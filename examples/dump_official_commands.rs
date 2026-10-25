use base64::prelude::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use p256::SecretKey;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tsproto_packets::packets::*;

use nano_ts3::command::Command;
use nano_ts3::crypto::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_sock = UdpSocket::bind("127.0.0.1:0").await?;
    client_sock.connect("127.0.0.1:9987").await?;

    println!("Connected to 9987, starting handshake...");

    // Init0
    let mut r0 = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut r0);
    let init0 = OutC2SInit0::new(0, 0, r0);
    client_sock.send(&init0.into_vec()).await?;

    let mut buf = [0u8; 4096];
    let len = timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await??;
    let in1 = InPacket::try_new(Direction::S2C, &buf[..len])?;
    let s2c1 = in1.into_s2cinit()?;
    let (r1, r0_rev) = match s2c1.data() {
        S2CInitData::Init1 { random1, random0_r } => (*random1, **random0_r),
        _ => panic!("Expected Init1"),
    };

    // Init2
    let init2 = OutC2SInit2::new(0, &r1, r0_rev);
    client_sock.send(&init2.into_vec()).await?;

    let len = timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await??;
    let in3 = InPacket::try_new(Direction::S2C, &buf[..len])?;
    let s2c3 = in3.into_s2cinit()?;
    let (x, n, level, random2) = match s2c3.data() {
        S2CInitData::Init3 {
            x,
            n,
            level,
            random2,
        } => (*x, *n, *level, *random2),
        _ => panic!("Expected Init3"),
    };

    // Solve Puzzle
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

    // Init4
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

    let init4 = OutC2SInit4::new(0, &x, &n, level, &random2, &y, &alpha, &client_der, "");
    client_sock.send(&init4.into_vec()).await?;

    // initivexpand2
    let len = timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await??;
    let raw = &buf[..len];
    let mac: [u8; 8] = raw[..8].try_into().unwrap();
    let mut ct = raw[11..].to_vec();
    decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &raw[8..11], &mac, &mut ct)?;
    let expand_cmd = Command::parse(std::str::from_utf8(&ct)?).unwrap();

    let _server_omega_b64 = expand_cmd.get("omega").unwrap();
    let server_beta_b64 = expand_cmd.get("beta").unwrap();
    let server_beta = BASE64_STANDARD.decode(server_beta_b64)?;

    // clientek
    let mut ek_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ek_seed);
    let client_ek_scalar = Scalar::from_bytes_mod_order(ek_seed);
    let client_ek_point = ED25519_BASEPOINT_POINT * client_ek_scalar;
    let client_ek_pub = client_ek_point.compress().0;
    let client_ek_b64 = BASE64_STANDARD.encode(&client_ek_pub);

    let server_derived_pub: [u8; 32] = [
        0x2c, 0x39, 0xee, 0xda, 0x23, 0x12, 0xb2, 0x03, 0x7f, 0x51, 0xb2, 0x87, 0xd1, 0x1f, 0x53,
        0xba, 0x46, 0x84, 0x38, 0x25, 0xeb, 0x4c, 0xdb, 0x9e, 0x0b, 0xf9, 0x37, 0x4a, 0x32, 0x1d,
        0x62, 0x32,
    ];
    let s_pt = CompressedEdwardsY(server_derived_pub).decompress().unwrap();
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

    let ek_mac = encrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &ek_aad, &mut ek_payload)?;
    ek_pkt.mac().copy_from_slice(&ek_mac);
    ek_pkt.data_mut().extend_from_slice(&ek_payload);
    client_sock.send(&ek_pkt.into_vec()).await?;

    // Recv ACK
    let _ = timeout(Duration::from_secs(2), client_sock.recv(&mut buf)).await??;

    // Send clientinit
    let mut clientinit_cmd = Command::new("clientinit");
    clientinit_cmd.set("client_nickname", "TestUser");
    let mut payload = clientinit_cmd.build().into_bytes();

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
    aad.extend_from_slice(&1u16.to_be_bytes());
    aad.push(PacketType::Command as u8);

    let mac = encrypt_eax(&key, &nonce, &aad, &mut payload)?;
    pkt.mac().copy_from_slice(&mac);
    pkt.data_mut().extend_from_slice(&payload);
    client_sock.send(&pkt.into_vec()).await?;

    println!("\n=== SENT clientinit, LISTENING FOR S2C COMMANDS ===");

    let mut frag_buf = Vec::new();
    for _ in 0..30 {
        let len = match timeout(Duration::from_secs(3), client_sock.recv(&mut buf)).await {
            Ok(Ok(l)) => l,
            _ => break,
        };

        let in_pkt = match InPacket::try_new(Direction::S2C, &buf[..len]) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let p_type = in_pkt.header().packet_type();
        let p_id = in_pkt.header().packet_id();
        let flags = in_pkt.header().flags();

        if p_type == PacketType::Command {
            let (s_key, s_nonce) = derive_key_nonce(
                Direction::S2C,
                PacketType::Command as u8,
                0,
                p_id,
                &shared_iv,
            );
            let mac: [u8; 8] = buf[..8].try_into().unwrap();
            let aad = &buf[8..11];
            let mut text_buf = buf[11..len].to_vec();
            if let Ok(_) = decrypt_eax(&s_key, &s_nonce, aad, &mac, &mut text_buf) {
                if flags.contains(Flags::FRAGMENTED) {
                    frag_buf.extend_from_slice(&text_buf);
                    continue;
                } else if !frag_buf.is_empty() {
                    frag_buf.extend_from_slice(&text_buf);
                    let full = std::mem::take(&mut frag_buf);
                    let s = String::from_utf8_lossy(&full).to_string();
                    println!("[S2C CMD] (pid {}) {}", p_id, s);
                } else {
                    let s = String::from_utf8_lossy(&text_buf).to_string();
                    println!("[S2C CMD] (pid {}) {}", p_id, s);
                }
            }
        } else {
            println!("[S2C OTHER] type: {:?}, pid: {}", p_type, p_id);
        }
    }

    Ok(())
}
