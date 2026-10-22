use base64::prelude::*;
use p256::SecretKey;
use rand::RngCore;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tsproto_packets::packets::*;

use nano_ts3::command::Command;
use nano_ts3::crypto::*;
use nano_ts3::database::Database;
use nano_ts3::server::Server;

#[tokio::test]
async fn test_full_handshake_and_features() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();

    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");

    // Spawn server in background
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client_sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind failed");
    client_sock
        .connect(server_addr)
        .await
        .expect("client connect failed");

    // Step 1: Send Init0
    let mut r0 = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut r0);
    let init0 = OutC2SInit0::new(0, 0, r0);
    client_sock
        .send(&init0.into_vec())
        .await
        .expect("send init0 failed");

    // Receive Init1
    let mut buf = [0u8; 4096];
    let len = timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("timeout waiting for init1")
        .expect("recv failed");

    let in1 = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse init1");
    let s2c1 = in1.into_s2cinit().expect("into_s2cinit");
    let (r1, r0_rev) = match s2c1.data() {
        S2CInitData::Init1 { random1, random0_r } => (random1, random0_r),
        other => panic!("Expected Init1, got {:?}", other),
    };
    assert_eq!(**r0_rev, [r0[3], r0[2], r0[1], r0[0]]);

    // Step 2: Send Init2
    let init2 = OutC2SInit2::new(0, r1, **r0_rev);
    client_sock
        .send(&init2.into_vec())
        .await
        .expect("send init2 failed");

    // Receive Init3
    let len = timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("timeout waiting for init3")
        .expect("recv failed");

    let in3 = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse init3");
    let s2c3 = in3.into_s2cinit().expect("into_s2cinit");
    let (x, n, level, random2) = match s2c3.data() {
        S2CInitData::Init3 {
            x,
            n,
            level,
            random2,
        } => (*x, *n, *level, *random2),
        other => panic!("Expected Init3, got {:?}", other),
    };

    // Step 3: Solve RSA Puzzle: level modular squarings: y = x ^ (2 ^ level) % n
    let x_big = num_bigint::BigUint::from_bytes_be(x);
    let n_big = num_bigint::BigUint::from_bytes_be(n);
    let mut cur = x_big % &n_big;
    for _ in 0..level {
        cur = (&cur * &cur) % &n_big;
    }
    let y_digits = cur.to_bytes_be();
    let mut y = [0u8; 64];
    if y_digits.len() <= 64 {
        y[64 - y_digits.len()..].copy_from_slice(&y_digits);
    } else {
        y.copy_from_slice(&y_digits[..64]);
    }

    // Step 4: Generate Client ECC Key and Send Init4
    let mut client_key_bytes = [0u8; 32];
    let client_secret = loop {
        rand::thread_rng().fill_bytes(&mut client_key_bytes);
        if let Ok(sk) = SecretKey::from_slice(&client_key_bytes) {
            break sk;
        }
    };
    let client_der = encode_libtomcrypt_ecc_public(client_secret.public_key().as_affine());

    let mut alpha = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut alpha);

    let init4 = OutC2SInit4::new(0, x, n, level, random2, &y, &alpha, &client_der, "");
    client_sock
        .send(&init4.into_vec())
        .await
        .expect("send init4 failed");

    // Receive initivexpand2
    let len = timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("timeout waiting for initivexpand2")
        .expect("recv failed");

    let raw = &buf[..len];
    let in_expand = InPacket::try_new(Direction::S2C, raw).expect("parse initivexpand2");
    assert_eq!(in_expand.header().packet_type(), PacketType::Command);
    assert_eq!(in_expand.header().flags(), Flags::empty());

    let mac: [u8; 8] = raw[..8].try_into().unwrap();
    let mut ct = raw[11..].to_vec();
    decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &raw[8..11], &mac, &mut ct)
        .expect("decrypt initivexpand2");

    let expand_text = std::str::from_utf8(&ct).expect("utf8 initivexpand2");
    let expand_cmd = Command::parse(expand_text).expect("parse initivexpand2 cmd");
    assert_eq!(expand_cmd.name, "initivexpand2");

    let server_omega_b64 = expand_cmd.get("omega").expect("omega in initivexpand");
    let server_beta_b64 = expand_cmd.get("beta").expect("beta in initivexpand");

    let server_der = BASE64_STANDARD
        .decode(server_omega_b64)
        .expect("decode omega");
    let server_beta = BASE64_STANDARD
        .decode(server_beta_b64)
        .expect("decode beta");
    let _server_public = decode_libtomcrypt_ecc_public(&server_der).expect("decode server public");

    // Step 5: Send Encrypted `clientek` (Packet ID = 1)
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    let mut ek_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ek_seed);
    let client_ek_scalar = Scalar::from_bytes_mod_order(ek_seed);
    let client_ek_point = ED25519_BASEPOINT_POINT * client_ek_scalar;
    let client_ek_pub = client_ek_point.compress().0;
    let client_ek_b64 = BASE64_STANDARD.encode(&client_ek_pub);

    // Known derived public key of Anonymous license Block 1:
    let server_derived_pub: [u8; 32] = [
        0x2c, 0x39, 0xee, 0xda, 0x23, 0x12, 0xb2, 0x03, 0x7f, 0x51, 0xb2, 0x87, 0xd1, 0x1f, 0x53,
        0xba, 0x46, 0x84, 0x38, 0x25, 0xeb, 0x4c, 0xdb, 0x9e, 0x0b, 0xf9, 0x37, 0x4a, 0x32, 0x1d,
        0x62, 0x32,
    ];
    let s_pt = CompressedEdwardsY(server_derived_pub)
        .decompress()
        .expect("server pt");
    let shared_pt = s_pt * client_ek_scalar;
    let shared_secret = shared_pt.compress().0;

    let mut shared_iv = [0u8; 64];
    shared_iv.copy_from_slice(&Sha512::digest(&shared_secret));
    for (i, b) in alpha.iter().enumerate().take(10) {
        shared_iv[i] ^= *b;
    }
    for (i, b) in server_beta.iter().enumerate().take(54) {
        shared_iv[10 + i] ^= *b;
    }

    let mut clientek_cmd = Command::new("clientek");
    clientek_cmd.set("ek", &client_ek_b64);
    clientek_cmd.set("proof", "dummy_proof");
    let mut ek_payload = clientek_cmd.build().into_bytes();

    let ek_pid = 1u16;
    let mut ek_pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
    ek_pkt.packet_id(ek_pid);
    ek_pkt.client_id(0);

    let mut ek_aad = Vec::new();
    ek_aad.extend_from_slice(&ek_pid.to_be_bytes());
    ek_aad.extend_from_slice(&0u16.to_be_bytes());
    ek_aad.push(PacketType::Command as u8);

    let ek_mac = encrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &ek_aad, &mut ek_payload)
        .expect("encrypt clientek failed");
    ek_pkt.mac().copy_from_slice(&ek_mac);
    ek_pkt.data_mut().extend_from_slice(&ek_payload);

    client_sock
        .send(&ek_pkt.into_vec())
        .await
        .expect("send clientek failed");

    // Receive ACK for clientek
    let len = timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("timeout waiting for clientek ack")
        .expect("recv failed");
    let in_ack = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse clientek ack");
    assert_eq!(in_ack.header().packet_type(), PacketType::Ack);

    // Step 6: Send Encrypted `clientinit` (Packet ID = 2)
    let mut clientinit_cmd = Command::new("clientinit");
    clientinit_cmd.set("client_nickname", "TestUser");
    let wire_str = clientinit_cmd.build();
    let mut payload = wire_str.into_bytes();

    let p_id = 2u16;
    let (key, nonce) = derive_key_nonce(
        Direction::C2S,
        PacketType::Command as u8,
        0,
        p_id,
        &shared_iv,
    );

    let mut pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
    pkt.packet_id(p_id);
    pkt.client_id(1);

    let mut aad = Vec::new();
    aad.extend_from_slice(&p_id.to_be_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes()); // Client ID
    aad.push(PacketType::Command as u8);

    let mac = encrypt_eax(&key, &nonce, &aad, &mut payload).expect("encrypt clientinit failed");
    pkt.mac().copy_from_slice(&mac);
    pkt.data_mut().extend_from_slice(&payload);

    client_sock
        .send(&pkt.into_vec())
        .await
        .expect("send clientinit failed");

    // Step 7: Receive ACK and Server Responses (`initserver`, `channellist`, `channellistfinished`, `notifycliententerview`)
    let mut got_initserver = false;
    let mut got_channellist = false;
    let mut got_enterview = false;
    let mut s2c_frag_buf = Vec::new();

    for _ in 0..15 {
        let len = match timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await {
            Ok(Ok(l)) => l,
            _ => break,
        };

        let in_resp = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse resp");
        if in_resp.header().packet_type() == PacketType::Ack {
            continue;
        }

        if in_resp.header().packet_type() == PacketType::Command {
            let resp_id = in_resp.header().packet_id();
            let flags = in_resp.header().flags();
            let (s_key, s_nonce) = derive_key_nonce(
                Direction::S2C,
                PacketType::Command as u8,
                0,
                resp_id,
                &shared_iv,
            );
            let mac: [u8; 8] = buf[..8].try_into().unwrap();
            let aad = &buf[8..11];
            let mut text_buf = buf[11..len].to_vec();
            decrypt_eax(&s_key, &s_nonce, aad, &mac, &mut text_buf)
                .expect("decrypt server cmd failed");

            // First and last fragment carry FRAGMENTED; middle fragments do
            // not, so a flagged packet while buffering terminates the command.
            let cmd_text = if flags.contains(Flags::FRAGMENTED) {
                if s2c_frag_buf.is_empty() {
                    s2c_frag_buf.extend_from_slice(&text_buf);
                    continue;
                }
                s2c_frag_buf.extend_from_slice(&text_buf);
                let full = std::mem::take(&mut s2c_frag_buf);
                String::from_utf8(full).expect("utf8 cmd")
            } else if !s2c_frag_buf.is_empty() {
                s2c_frag_buf.extend_from_slice(&text_buf);
                continue;
            } else {
                String::from_utf8(text_buf).expect("utf8 cmd")
            };

            let cmd = Command::parse(&cmd_text).expect("parse cmd");

            match cmd.name.as_str() {
                "initserver" => got_initserver = true,
                "channellist" => got_channellist = true,
                "notifycliententerview" => got_enterview = true,
                "error" => {
                    if got_initserver && got_channellist && got_enterview {
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    assert!(got_initserver, "Should have received initserver");
    assert!(got_channellist, "Should have received channellist");
    assert!(got_enterview, "Should have received notifycliententerview");

    // Step 7: Test Privilege Key Redemption
    let mut priv_cmd = Command::new("privilegekeyuse");
    priv_cmd.set("token", &admin_token);
    let mut payload = priv_cmd.build().into_bytes();

    let p_id = 3u16;
    let (key, nonce) = derive_key_nonce(
        Direction::C2S,
        PacketType::Command as u8,
        0,
        p_id,
        &shared_iv,
    );
    let mut pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
    pkt.packet_id(p_id);
    pkt.client_id(1);

    let mut aad = Vec::new();
    aad.extend_from_slice(&p_id.to_be_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes());
    aad.push(PacketType::Command as u8);

    let mac = encrypt_eax(&key, &nonce, &aad, &mut payload).unwrap();
    pkt.mac().copy_from_slice(&mac);
    pkt.data_mut().extend_from_slice(&payload);
    client_sock
        .send(&pkt.into_vec())
        .await
        .expect("send privilegekeyuse failed");

    // Receive notifyclientupdated
    let mut got_admin_update = false;
    for i in 0..80 {
        let len = match timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => {
                println!("recv err: {:?}", e);
                break;
            }
            Err(_) => {
                println!("timeout on iter {}", i);
                break;
            }
        };

        let in_resp = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse resp");
        let p_type = in_resp.header().packet_type();
        let resp_id = in_resp.header().packet_id();
        println!(
            "Step 7 received packet #{}: type={:?}, id={}",
            i, p_type, resp_id
        );

        if p_type == PacketType::Command {
            let (s_key, s_nonce) = derive_key_nonce(
                Direction::S2C,
                PacketType::Command as u8,
                0,
                resp_id,
                &shared_iv,
            );
            let mac: [u8; 8] = buf[..8].try_into().unwrap();
            let aad = &buf[8..11];
            let mut text_buf = buf[11..len].to_vec();
            if let Ok(()) = decrypt_eax(&s_key, &s_nonce, aad, &mac, &mut text_buf) {
                let cmd_text = std::str::from_utf8(&text_buf).unwrap_or("<invalid utf8>");
                println!("  Decrypted cmd: {}", cmd_text);
                if let Some(cmd) = Command::parse(cmd_text) {
                    if cmd.name == "notifyclientupdated" {
                        got_admin_update = true;
                    }
                    if cmd.name == "error" && got_admin_update {
                        break;
                    }
                }
            } else {
                println!("  Failed to decrypt packet id {}", resp_id);
            }
        }
    }
    assert!(
        got_admin_update,
        "Should have received notifyclientupdated granting admin"
    );

    // Step 8: Create Channel
    let mut ch_create = Command::new("channelcreate");
    ch_create.set("channel_name", "Lounge");
    ch_create.set("channel_topic", "Chat");
    let mut payload = ch_create.build().into_bytes();

    let p_id = 4u16;
    let (key, nonce) = derive_key_nonce(
        Direction::C2S,
        PacketType::Command as u8,
        0,
        p_id,
        &shared_iv,
    );
    let mut pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
    pkt.packet_id(p_id);
    pkt.client_id(1);

    let mut aad = Vec::new();
    aad.extend_from_slice(&p_id.to_be_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes());
    aad.push(PacketType::Command as u8);

    let mac = encrypt_eax(&key, &nonce, &aad, &mut payload).unwrap();
    pkt.mac().copy_from_slice(&mac);
    pkt.data_mut().extend_from_slice(&payload);
    client_sock
        .send(&pkt.into_vec())
        .await
        .expect("send channelcreate failed");

    let mut got_channel_created = false;
    let mut ch_frag: Vec<u8> = Vec::new();
    for _ in 0..80 {
        let len = match timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await {
            Ok(Ok(l)) => l,
            _ => break,
        };

        let in_resp = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse resp");
        if in_resp.header().packet_type() == PacketType::Command {
            let resp_id = in_resp.header().packet_id();
            let flags = in_resp.header().flags();
            let (s_key, s_nonce) = derive_key_nonce(
                Direction::S2C,
                PacketType::Command as u8,
                0,
                resp_id,
                &shared_iv,
            );
            let mac: [u8; 8] = buf[..8].try_into().unwrap();
            let aad = &buf[8..11];
            let mut text_buf = buf[11..len].to_vec();
            if let Ok(()) = decrypt_eax(&s_key, &s_nonce, aad, &mac, &mut text_buf) {
                let cmd_text = if flags.contains(Flags::FRAGMENTED) {
                    if ch_frag.is_empty() {
                        ch_frag.extend_from_slice(&text_buf);
                        continue;
                    }
                    ch_frag.extend_from_slice(&text_buf);
                    String::from_utf8(std::mem::take(&mut ch_frag)).unwrap_or_default()
                } else if !ch_frag.is_empty() {
                    ch_frag.extend_from_slice(&text_buf);
                    continue;
                } else {
                    String::from_utf8(text_buf).unwrap_or_default()
                };
                if let Some(cmd) = Command::parse(&cmd_text) {
                    if cmd.name == "notifychannelcreated" {
                        assert_eq!(cmd.get("channel_name"), Some("Lounge"));
                        got_channel_created = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(
        got_channel_created,
        "Should have received notifychannelcreated"
    );

    // Step 9: Send Text Message
    let mut chat_cmd = Command::new("sendtextmessage");
    chat_cmd.set("targetmode", "2");
    chat_cmd.set("msg", "Hello\\sWorld!");
    let mut payload = chat_cmd.build().into_bytes();

    let p_id = 5u16;
    let (key, nonce) = derive_key_nonce(
        Direction::C2S,
        PacketType::Command as u8,
        0,
        p_id,
        &shared_iv,
    );
    let mut pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
    pkt.packet_id(p_id);
    pkt.client_id(1);

    let mut aad = Vec::new();
    aad.extend_from_slice(&p_id.to_be_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes());
    aad.push(PacketType::Command as u8);

    let mac = encrypt_eax(&key, &nonce, &aad, &mut payload).unwrap();
    pkt.mac().copy_from_slice(&mac);
    pkt.data_mut().extend_from_slice(&payload);
    client_sock
        .send(&pkt.into_vec())
        .await
        .expect("send text message failed");

    let mut got_chat = false;
    for _ in 0..80 {
        let len = match timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await {
            Ok(Ok(l)) => l,
            _ => break,
        };

        let in_resp = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse resp");
        if in_resp.header().packet_type() == PacketType::Command {
            let resp_id = in_resp.header().packet_id();
            if in_resp.header().flags().contains(Flags::FRAGMENTED) {
                continue;
            }
            let (s_key, s_nonce) = derive_key_nonce(
                Direction::S2C,
                PacketType::Command as u8,
                0,
                resp_id,
                &shared_iv,
            );
            let mac: [u8; 8] = buf[..8].try_into().unwrap();
            let aad = &buf[8..11];
            let mut text_buf = buf[11..len].to_vec();
            if let Ok(()) = decrypt_eax(&s_key, &s_nonce, aad, &mac, &mut text_buf) {
                let cmd_text = std::str::from_utf8(&text_buf).unwrap_or("");
                if let Some(cmd) = Command::parse(cmd_text) {
                    if cmd.name == "notifytextmessage" {
                        assert_eq!(cmd.get("msg"), Some("Hello\\sWorld!"));
                        got_chat = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(got_chat, "Should have received notifytextmessage broadcast");

    // Step 10: Client Move to New Channel
    let mut move_cmd = Command::new("clientmove");
    move_cmd.set("cid", "2");
    let mut payload = move_cmd.build().into_bytes();

    let p_id = 6u16;
    let (key, nonce) = derive_key_nonce(
        Direction::C2S,
        PacketType::Command as u8,
        0,
        p_id,
        &shared_iv,
    );
    let mut pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
    pkt.packet_id(p_id);
    pkt.client_id(1);

    let mut aad = Vec::new();
    aad.extend_from_slice(&p_id.to_be_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes());
    aad.push(PacketType::Command as u8);

    let mac = encrypt_eax(&key, &nonce, &aad, &mut payload).unwrap();
    pkt.mac().copy_from_slice(&mac);
    pkt.data_mut().extend_from_slice(&payload);
    client_sock
        .send(&pkt.into_vec())
        .await
        .expect("send clientmove failed");

    let mut got_move = false;
    for _ in 0..80 {
        let len = match timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await {
            Ok(Ok(l)) => l,
            _ => break,
        };

        let in_resp = InPacket::try_new(Direction::S2C, &buf[..len]).expect("parse resp");
        if in_resp.header().packet_type() == PacketType::Command {
            let resp_id = in_resp.header().packet_id();
            if in_resp.header().flags().contains(Flags::FRAGMENTED) {
                continue;
            }
            let (s_key, s_nonce) = derive_key_nonce(
                Direction::S2C,
                PacketType::Command as u8,
                0,
                resp_id,
                &shared_iv,
            );
            let mac: [u8; 8] = buf[..8].try_into().unwrap();
            let aad = &buf[8..11];
            let mut text_buf = buf[11..len].to_vec();
            if let Ok(()) = decrypt_eax(&s_key, &s_nonce, aad, &mac, &mut text_buf) {
                let cmd_text = std::str::from_utf8(&text_buf).unwrap_or("");
                if let Some(cmd) = Command::parse(cmd_text) {
                    if cmd.name == "notifyclientmoved" {
                        assert_eq!(cmd.get("ctid"), Some("2"));
                        got_move = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(got_move, "Should have received notifyclientmoved");

    server_handle.abort();
}
