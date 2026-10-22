//! Connect to an official TS3 server as a synthetic client and dump every
//! server-to-client command in order.
//!
//! Unlike our own server, the official server's SharedIV can only be derived
//! from the anonymous license blob it sends in `initivexpand2 l=...` (the blob
//! embeds the server's Ed25519 public key). We know our own ephemeral `ek`
//! scalar, so `shared = SHA512(server_pub * ek_scalar)`.
//!
//! Usage: cargo run --release --example official_dump -- <port> [nickname] [uid]

use std::time::{Duration, Instant};

use base64::prelude::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use p256::SecretKey;
use p256::ecdsa::signature::Signer;
use rand::RngCore;
use sha1::{Digest as _, Sha1};
use sha2::Sha512;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tsproto_packets::packets::*;

use nano_ts3::command::Command;
use nano_ts3::crypto::*;

const CLIENT_VERSION: u32 = 0x1428_98dd;

fn client_key_offset(omega: &str, required_level: u8) -> u64 {
    for offset in 0..u64::MAX {
        let digest = Sha1::digest(format!("{omega}{offset}").as_bytes());
        let mut level = 0;
        for byte in digest {
            if byte == 0 {
                level += 8;
            } else {
                level += byte.trailing_zeros() as u8;
                break;
            }
        }
        if level >= required_level {
            return offset;
        }
    }
    unreachable!("identity key offset space exhausted")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::args().nth(1).unwrap_or_else(|| "9987".into());
    let nickname = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "DumpClient".into());
    let uid_override = std::env::args().nth(3);

    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    sock.connect(format!("127.0.0.1:{}", port)).await?;
    let mut buf = [0u8; 8192];
    println!("connecting to 127.0.0.1:{}", port);

    // ---- Init0/1 ----
    let mut r0 = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut r0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let init0 = OutC2SInit0::new(CLIENT_VERSION, now, r0);
    sock.send(&init0.into_vec()).await?;
    let len = timeout(Duration::from_secs(3), sock.recv(&mut buf)).await??;
    let in1 = InPacket::try_new(Direction::S2C, &buf[..len])?;
    let s2c1 = in1.into_s2cinit()?;
    let (r1, r0_rev) = match s2c1.data() {
        S2CInitData::Init1 { random1, random0_r } => (*random1, **random0_r),
        other => return Err(format!("expected Init1, got {:?}", other).into()),
    };
    println!("Init1 ok");

    let mut ck = [0u8; 32];
    let client_secret = loop {
        rand::thread_rng().fill_bytes(&mut ck);
        if let Ok(sk) = SecretKey::from_slice(&ck) {
            break sk;
        }
    };
    let client_der = encode_libtomcrypt_ecc_public(client_secret.public_key().as_affine());
    let omega_b64 = BASE64_STANDARD.encode(&client_der);
    let key_offset = client_key_offset(&omega_b64, 8);
    // The official client UID is based on the omega field's base64 text, not
    // the DER bytes. Keep the generated probe identity consistent with its key.
    let derived_uid = BASE64_STANDARD.encode(Sha1::digest(omega_b64.as_bytes()));
    let uid = uid_override.unwrap_or_else(|| derived_uid.clone());
    if uid != derived_uid {
        println!("warning: supplied UID does not match this synthetic omega key");
    }
    println!("synthetic client UID: {}", uid);
    println!("synthetic client key offset: {key_offset} (security level >= 8)");
    let mut alpha = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut alpha);

    // Real 3.x clients also send clientinitiv as a bootstrap-encrypted command
    // (pid 0), in addition to the copy embedded in Init4.
    {
        let mut early = Command::new("clientinitiv");
        early.set("alpha", BASE64_STANDARD.encode(alpha));
        early.set("omega", &omega_b64);
        early.set("ot", "1");
        early.set("a", "1");
        early.set("ip", "");
        send_pre_shared(&sock, &early, 0).await?;
        println!("sent early clientinitiv");
    }

    // ---- Init2/3 ----
    let init2 = OutC2SInit2::new(CLIENT_VERSION, &r1, r0_rev);
    sock.send(&init2.into_vec()).await?;
    let len = timeout(Duration::from_secs(3), sock.recv(&mut buf)).await??;
    let in3 = InPacket::try_new(Direction::S2C, &buf[..len])?;
    let s2c3 = in3.into_s2cinit()?;
    let (x, n, level, random2) = match s2c3.data() {
        S2CInitData::Init3 {
            x,
            n,
            level,
            random2,
        } => (*x, *n, *level, *random2),
        other => return Err(format!("expected Init3, got {:?}", other).into()),
    };
    println!("Init3 level={}", level);
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

    // ---- Init4 ----
    let init4_cmd = format!(
        "clientinitiv alpha={} omega={} ot=1 a=1 ip c=0",
        BASE64_STANDARD.encode(alpha),
        omega_b64,
    );
    let mut init4 = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Init);
    init4.mac().copy_from_slice(b"TS3INIT1");
    init4.packet_id(0x65);
    {
        let d = init4.data_mut();
        d.extend_from_slice(&CLIENT_VERSION.to_be_bytes());
        d.push(4);
        d.extend_from_slice(x);
        d.extend_from_slice(n);
        d.extend_from_slice(&level.to_be_bytes());
        d.extend_from_slice(random2);
        d.extend_from_slice(&y);
        d.extend_from_slice(init4_cmd.as_bytes());
    }
    sock.send(&init4.into_vec()).await?;

    // ---- initivexpand2 (bootstrap encrypted) ----
    let len = timeout(Duration::from_secs(3), sock.recv(&mut buf)).await??;
    let raw = &buf[..len];
    let mac: [u8; 8] = raw[..8].try_into().unwrap();
    let mut ct = raw[11..].to_vec();
    decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &raw[8..11], &mac, &mut ct)?;
    let expand = Command::parse(std::str::from_utf8(&ct)?).ok_or("parse initivexpand2")?;
    println!("initivexpand2: {}", expand.raw);
    let beta = BASE64_STANDARD.decode(expand.get("beta").ok_or("beta")?)?;
    let lic = BASE64_STANDARD.decode(expand.get("l").ok_or("l")?)?;
    // Walk the license block chain. Each block's key is combined with a
    // hash-derived scalar and the previous key, starting at the TS3 root key.
    const ROOT_KEY: [u8; 32] = [
        0xcd, 0x0d, 0xe2, 0xae, 0xd4, 0x63, 0x45, 0x50, 0x9a, 0x7e, 0x3c, 0xfd, 0x8f, 0x68, 0xb3,
        0xdc, 0x75, 0x55, 0xb2, 0x9d, 0xcc, 0xec, 0x73, 0xcd, 0x18, 0x75, 0x0f, 0x99, 0x38, 0x12,
        0x40, 0x8a,
    ];
    let mut parent = CompressedEdwardsY(ROOT_KEY)
        .decompress()
        .ok_or("bad root key")?;
    let mut offset = 1usize;
    while offset < lic.len() {
        let block = &lic[offset..];
        let typ = block[33];
        let extra = match typ {
            // TS3 server block: 1 byte type + 4 byte max clients + issuer string.
            2 => {
                let rest = &block[42..];
                let issuer = rest[5..]
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or("unterminated issuer")?;
                6 + issuer
            }
            // Intermediate: 4 unknown bytes + issuer string.
            0 => {
                let rest = &block[42..];
                let issuer = rest[4..]
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or("unterminated issuer")?;
                5 + issuer
            }
            // Ephemeral / website / code blocks have no trailing data.
            32 | 1 | 3 => 0,
            other => return Err(format!("unsupported license block type {}", other).into()),
        };
        let block_len = 42 + extra;
        if offset + block_len > lic.len() {
            return Err("license block overrun".into());
        }
        let block = &lic[offset..offset + block_len];
        let block_pub = CompressedEdwardsY(
            block[1..33]
                .try_into()
                .map_err(|_| "bad block key length")?,
        )
        .decompress()
        .ok_or("invalid block key")?;
        let mut h = Sha512::digest(&block[1..]);
        h[0] &= 248;
        h[31] &= 63;
        h[31] |= 64;
        let hs = Scalar::from_bytes_mod_order(h[..32].try_into().unwrap());
        parent = block_pub * hs + parent;
        offset += block_len;
    }
    let server_pub = parent;
    println!("server_ek derived: {}", hex(&server_pub.compress().0));

    // ---- clientek ----
    let mut ek_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ek_seed);
    let ek_scalar = Scalar::from_bytes_mod_order(ek_seed);
    let ek_pub = (ED25519_BASEPOINT_POINT * ek_scalar).compress().0;
    let shared = (server_pub * ek_scalar).compress().0;
    let mut shared_iv = [0u8; 64];
    shared_iv.copy_from_slice(&Sha512::digest(shared));
    for (i, b) in alpha.iter().enumerate().take(10) {
        shared_iv[i] ^= *b;
    }
    for (i, b) in beta.iter().enumerate().take(54) {
        shared_iv[10 + i] ^= *b;
    }
    let shared_mac: [u8; 8] = Sha1::digest(shared_iv)[..8].try_into().unwrap();

    // ACK initivexpand2 (pid 0) before sending clientek.
    let mut expand_ack = OutAck::new(Direction::C2S, PacketType::Command, 0);
    expand_ack.flags(Flags::UNENCRYPTED);
    expand_ack.mac().copy_from_slice(&shared_mac);
    const _: () = ();
    let _ = sock.send(&expand_ack.into_vec()).await;

    // proof = ECDSA(ek || beta) with the same P-256 key that provided omega.
    let mut signed = Vec::with_capacity(32 + 54);
    signed.extend_from_slice(&ek_pub);
    signed.extend_from_slice(&beta);
    let signing_key =
        p256::ecdsa::SigningKey::from_slice(&client_secret.to_bytes()).expect("signing key");
    let sig: p256::ecdsa::DerSignature = signing_key.sign(&signed);
    let proof_b64 = BASE64_STANDARD.encode(sig.as_bytes());

    let mut clientek = Command::new("clientek");
    clientek.set("ek", BASE64_STANDARD.encode(ek_pub));
    clientek.set("proof", &proof_b64);
    send_pre_shared(&sock, &clientek, 1).await?;
    println!("sent clientek");

    // ---- clientinit ----
    let mut init = Command::new("clientinit");
    init.set("client_nickname", &nickname);
    init.set("client_version", "3.6.2 [Build: 1695203293]");
    init.set("client_platform", "Windows");
    init.set("client_input_hardware", "1");
    init.set("client_output_hardware", "1");
    init.set("client_default_channel", "");
    init.set("client_default_channel_password", "");
    init.set("client_server_password", "");
    init.set("client_meta_data", "");
    init.set(
        "client_version_sign",
        "4BdaZpdgUSMCuIs8qcloJPNxNlJ4o7QKnxMCRO60mSOTtJZyKjOrGLAmeAEtLIJjcjmdSpycMbQOIV92K2vXAw==",
    );
    init.set("client_key_offset", key_offset.to_string());
    init.set("client_nickname_phonetic", "");
    init.set("client_default_token", "");
    init.set("client_badges", "Overwolf=0");
    init.set("client_myteamspeak_id", "");
    init.set("client_user_tag", "");
    let mut hwid_a = [0u8; 16];
    let mut hwid_b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut hwid_a);
    rand::thread_rng().fill_bytes(&mut hwid_b);
    init.set("hwid", format!("{},{}", hex(&hwid_a), hex(&hwid_b)));
    let init_text = init.build();
    println!("C2S clientinit: {init_text}");
    let chunks: Vec<&[u8]> = init_text.as_bytes().chunks(480).collect();
    for (idx, chunk) in chunks.iter().enumerate() {
        let pid = 2u16.wrapping_add(idx as u16);
        let mut flags = Flags::NEWPROTOCOL;
        if chunks.len() > 1 && (idx == 0 || idx + 1 == chunks.len()) {
            flags |= Flags::FRAGMENTED;
        }
        let (key, nonce) = derive_key_nonce(
            Direction::C2S,
            PacketType::Command as u8,
            0,
            pid,
            &shared_iv,
        );
        let mut aad = Vec::with_capacity(5);
        aad.extend_from_slice(&pid.to_be_bytes());
        aad.extend_from_slice(&0u16.to_be_bytes());
        aad.push(flags.bits() | PacketType::Command as u8);
        let mut payload = chunk.to_vec();
        let mac = encrypt_eax(&key, &nonce, &aad, &mut payload)?;
        let mut pkt = OutPacket::new_with_dir(Direction::C2S, flags, PacketType::Command);
        pkt.packet_id(pid);
        pkt.client_id(0);
        pkt.mac().copy_from_slice(&mac);
        pkt.data_mut().extend_from_slice(&payload);
        sock.send(&pkt.into_vec()).await?;
        println!(
            "sent clientinit fragment {}/{} pid={} bytes={} flags=0x{:02x}",
            idx + 1,
            chunks.len(),
            pid,
            chunk.len(),
            flags.bits(),
        );
    }
    capture_server_packets(
        &sock,
        Duration::from_secs(6),
        "after clientinit",
        &shared_iv,
        &shared_mac,
    )
    .await?;
    Ok(())
}

async fn capture_server_packets(
    sock: &UdpSocket,
    duration: Duration,
    phase: &str,
    shared_iv: &[u8; 64],
    shared_mac: &[u8; 8],
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut buf = [0u8; 8192];
    let mut seq = 0;
    while start.elapsed() < duration {
        let len = match timeout(Duration::from_millis(300), sock.recv(&mut buf)).await {
            Ok(Ok(len)) => len,
            _ => continue,
        };
        let raw = &buf[..len];
        let in_pkt = match InPacket::try_new(Direction::S2C, raw) {
            Ok(packet) => packet,
            Err(error) => {
                println!("[{phase}] unparsed packet len={len}: {error}");
                continue;
            }
        };
        let packet_type = in_pkt.header().packet_type();
        let packet_id = in_pkt.header().packet_id();
        let flags = in_pkt.header().flags();
        seq += 1;
        println!(
            "[{phase} #{seq} +{}ms] p_type={} pid={} flags=0x{:02x} len={len}",
            start.elapsed().as_millis(),
            packet_type as u8,
            packet_id,
            flags.bits(),
        );
        if packet_type != PacketType::Command || len < 11 {
            continue;
        }

        let mut ack = OutAck::new(Direction::C2S, packet_type, packet_id);
        ack.flags(Flags::UNENCRYPTED);
        ack.mac().copy_from_slice(shared_mac);
        let _ = sock.send(&ack.into_vec()).await;

        let mac: [u8; 8] = raw[..8].try_into().unwrap();
        let encrypted = raw[11..].to_vec();
        let (key, nonce) = derive_key_nonce(
            Direction::S2C,
            PacketType::Command as u8,
            0,
            packet_id,
            shared_iv,
        );
        let mut plaintext = encrypted.clone();
        let mut key_name = "shared_iv";
        if decrypt_eax(&key, &nonce, &raw[8..11], &mac, &mut plaintext).is_err() {
            plaintext = encrypted;
            key_name = "bootstrap";
            if decrypt_eax(
                BOOTSTRAP_KEY,
                BOOTSTRAP_NONCE,
                &raw[8..11],
                &mac,
                &mut plaintext,
            )
            .is_err()
            {
                println!("[{phase}] decrypt failed pid={packet_id}");
                continue;
            }
        }
        println!(
            "[{phase}] decrypted with {key_name}: {}",
            String::from_utf8_lossy(&plaintext)
        );
    }
    Ok(())
}

async fn send_pre_shared(
    sock: &UdpSocket,
    cmd: &Command,
    pid: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = cmd.build().into_bytes();
    let flags = Flags::NEWPROTOCOL;
    let mut aad = Vec::new();
    aad.extend_from_slice(&pid.to_be_bytes());
    aad.extend_from_slice(&0u16.to_be_bytes());
    aad.push(flags.bits() | PacketType::Command as u8);
    let mac = encrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &aad, &mut payload)?;
    let mut pkt = OutPacket::new_with_dir(Direction::C2S, flags, PacketType::Command);
    pkt.packet_id(pid);
    pkt.client_id(0);
    pkt.mac().copy_from_slice(&mac);
    pkt.data_mut().extend_from_slice(&payload);
    sock.send(&pkt.into_vec()).await?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
