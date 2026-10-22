use base64::prelude::*;
use p256::SecretKey;
use rand::RngCore;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tsproto_packets::packets::*;

use nano_ts3::crypto::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_sock = UdpSocket::bind("0.0.0.0:0").await?;
    let port = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "9988".to_string());
    let addr = format!("127.0.0.1:{}", port);
    client_sock.connect(&addr).await?;
    println!("Connecting to server at {}...", addr);

    // Step 1: Send Init0
    let mut r0 = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut r0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let ts_epoch = now.wrapping_sub(0x50e22700);
    // Note: OutC2SInit0 takes version as first param, which is actually timestamp!
    let init0 = OutC2SInit0::new(ts_epoch, ts_epoch, r0);
    client_sock.send(&init0.into_vec()).await?;
    println!("Sent Init0 with ts_epoch {}", ts_epoch);

    // Receive Init1
    let mut buf = [0u8; 4096];
    let len = timeout(Duration::from_secs(3), client_sock.recv(&mut buf)).await??;
    println!(
        "Received response to Init0! Len = {}, hex: {:02x?}",
        len,
        &buf[..len]
    );
    let in1 = InPacket::try_new(Direction::S2C, &buf[..len])?;
    let s2c1 = in1.into_s2cinit()?;
    let (r1, r0_rev) = match s2c1.data() {
        S2CInitData::Init1 { random1, random0_r } => (*random1, **random0_r),
        other => return Err(format!("Expected Init1, got {:?}", other).into()),
    };
    println!("Received Init1!");

    // Step 2: Send Init2
    let init2 = OutC2SInit2::new(ts_epoch, &r1, r0_rev);
    client_sock.send(&init2.into_vec()).await?;
    println!("Sent Init2");

    // Receive Init3
    let len = timeout(Duration::from_secs(3), client_sock.recv(&mut buf)).await??;
    let in3 = InPacket::try_new(Direction::S2C, &buf[..len])?;
    let s2c3 = in3.into_s2cinit()?;
    let (x, n, level, random2) = match s2c3.data() {
        S2CInitData::Init3 {
            x,
            n,
            level,
            random2,
        } => (*x, *n, *level, *random2),
        other => return Err(format!("Expected Init3, got {:?}", other).into()),
    };
    println!("Received Init3! level={}", level);

    // Step 3: Solve RSA puzzle: level squarings
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
    println!("Puzzle solved!");

    // Step 4: Send Init4
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

    let init4 = OutC2SInit4::new(ts_epoch, x, n, level, random2, &y, &alpha, &client_der, "");
    client_sock.send(&init4.into_vec()).await?;
    println!("Sent Init4!");

    // Step 5: Receive response!
    let len = timeout(Duration::from_secs(5), client_sock.recv(&mut buf)).await??;
    let raw = &buf[..len];
    println!("Received response from official server! Len = {}", len);

    let key = b"c:\\windows\\syste";
    let nonce = b"m\\firewall32.cpl";
    let mac: [u8; 8] = raw[..8].try_into().unwrap();

    // Decrypt initivexpand2 with fake key and nonce
    let mut ct1 = raw[11..].to_vec();
    decrypt_eax(key, nonce, &raw[8..11], &mac, &mut ct1)?;
    let expand_text = String::from_utf8(ct1)?;
    println!("DECRYPT SUCCESS!\n{}", expand_text);

    let expand_cmd = nano_ts3::command::Command::parse(&expand_text).unwrap();
    let server_beta_b64 = expand_cmd.get("beta").unwrap();
    let server_beta = BASE64_STANDARD.decode(server_beta_b64).unwrap();

    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use sha2::Digest;

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
    let s_pt = CompressedEdwardsY(server_derived_pub).decompress().unwrap();
    let shared_pt = s_pt * client_ek_scalar;
    let shared_secret = shared_pt.compress().0;

    let mut shared_iv = [0u8; 64];
    shared_iv.copy_from_slice(&sha2::Sha512::digest(&shared_secret));
    for (i, b) in alpha.iter().enumerate().take(10) {
        shared_iv[i] ^= *b;
    }
    for (i, b) in server_beta.iter().enumerate().take(54) {
        shared_iv[10 + i] ^= *b;
    }
    println!("Computed modern shared_iv on probe client!");

    // Send ACK for packet 0
    let ack = OutAck::new(Direction::C2S, PacketType::Command, 0);
    client_sock.send(&ack.into_vec()).await?;
    println!("Sent ACK for initivexpand2");

    // Send clientek command!
    let mut clientek = nano_ts3::command::Command::new("clientek");
    clientek.set("ek", &client_ek_b64);
    clientek.set("proof", "dummy_probe_proof");
    let ek_wire = clientek.build();
    let mut ek_bytes = ek_wire.into_bytes();

    let ek_pid = 1u16;
    let mut aad = [0u8; 5];
    aad[0..2].copy_from_slice(&ek_pid.to_be_bytes());
    aad[2..4].copy_from_slice(&0u16.to_be_bytes());
    aad[4] = PacketType::Command as u8;

    let ek_mac = encrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &aad, &mut ek_bytes)?;
    let mut ek_pkt = Vec::new();
    ek_pkt.extend_from_slice(&ek_mac);
    ek_pkt.extend_from_slice(&aad);
    ek_pkt.extend_from_slice(&ek_bytes);

    client_sock.send(&ek_pkt).await?;
    println!("Sent encrypted clientek!");

    // Receive server response to clientek!
    let len = timeout(Duration::from_secs(5), client_sock.recv(&mut buf)).await??;
    let resp = &buf[..len];
    println!(
        "Received response to clientek! Len = {}, hex: {:02x?}",
        len, resp
    );

    // Send encrypted clientinit (Packet ID = 2)
    let mut clientinit = nano_ts3::command::Command::new("clientinit");
    clientinit.set("client_nickname", "DanyalProbe");
    let init_wire = clientinit.build();
    let mut init_bytes = init_wire.into_bytes();

    let init_pid = 2u16;
    let (init_key, init_nonce) = derive_key_nonce(
        Direction::C2S,
        PacketType::Command as u8,
        0,
        init_pid,
        &shared_iv,
    );
    let mut aad = [0u8; 5];
    aad[0..2].copy_from_slice(&init_pid.to_be_bytes());
    aad[2..4].copy_from_slice(&0u16.to_be_bytes());
    aad[4] = PacketType::Command as u8;

    let init_mac = encrypt_eax(&init_key, &init_nonce, &aad, &mut init_bytes)?;
    let mut init_pkt = Vec::new();
    init_pkt.extend_from_slice(&init_mac);
    init_pkt.extend_from_slice(&aad);
    init_pkt.extend_from_slice(&init_bytes);

    client_sock.send(&init_pkt).await?;
    println!("Sent encrypted clientinit!");

    // Receive server initserver response!
    for _ in 0..5 {
        let len = timeout(Duration::from_secs(5), client_sock.recv(&mut buf)).await??;
        let resp = &buf[..len];
        println!("Received response from server! Len = {}", len);
        let in_resp = InPacket::try_new(Direction::S2C, resp)?;
        if in_resp.header().packet_type() == PacketType::Command {
            let mac: [u8; 8] = resp[..8].try_into().unwrap();
            let pid = u16::from_be_bytes(resp[8..10].try_into().unwrap());
            let mut ct = resp[11..].to_vec();
            let (s2c_key, s2c_nonce) = derive_key_nonce(
                Direction::S2C,
                PacketType::Command as u8,
                0,
                pid,
                &shared_iv,
            );
            decrypt_eax(&s2c_key, &s2c_nonce, &resp[8..11], &mac, &mut ct)?;
            let cmd_text = String::from_utf8_lossy(&ct);
            println!("DECRYPTED SERVER COMMAND:\n{}", cmd_text);
            break;
        }
    }

    Ok(())
}
