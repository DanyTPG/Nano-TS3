//! Oracle probe: connect to a TS3 server (official or nano-ts3), dump every
//! decrypted S2C command in arrival order, then exercise the admin flow.
//!
//! Usage: cargo run --release --example oracle_probe -- <port> [nickname] [uid] [token]
//!
//! The probe ACKs every command it receives so servers stop resending, which
//! keeps the captured ordering representative of a real client.

use base64::prelude::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use p256::SecretKey;
use rand::RngCore;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha512;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tsproto_packets::packets::*;

use nano_ts3::command::Command;
use nano_ts3::crypto::*;

const ANON_SERVER_DERIVED_PUB: [u8; 32] = [
    0x2c, 0x39, 0xee, 0xda, 0x23, 0x12, 0xb2, 0x03, 0x7f, 0x51, 0xb2, 0x87, 0xd1, 0x1f, 0x53, 0xba,
    0x46, 0x84, 0x38, 0x25, 0xeb, 0x4c, 0xdb, 0x9e, 0x0b, 0xf9, 0x37, 0x4a, 0x32, 0x1d, 0x62, 0x32,
];

struct Probe {
    sock: UdpSocket,
    shared_iv: [u8; 64],
    shared_mac: [u8; 8],
    clid: u16,
    next_c2s_pid: u16,
    frag: Vec<u8>,
    start: Instant,
    seq: usize,
}

impl Probe {
    async fn ack(&self, p_type: PacketType, p_id: u16) {
        if matches!(
            p_type,
            PacketType::Ack | PacketType::AckLow | PacketType::Pong
        ) {
            return;
        }
        let mut ack = OutAck::new(Direction::C2S, p_type, p_id);
        ack.flags(Flags::UNENCRYPTED);
        ack.mac().copy_from_slice(&self.shared_mac);
        let _ = self.sock.send(&ack.into_vec()).await;
    }

    /// Reads one S2C packet, ACKs it, and returns the reassembled command text.
    async fn recv_text(&mut self, dur: Duration) -> Option<(String, u16, Flags)> {
        let mut buf = [0u8; 4096];
        loop {
            let len = match timeout(dur, self.sock.recv(&mut buf)).await {
                Ok(Ok(l)) => l,
                _ => return None,
            };
            let raw = &buf[..len];
            let in_pkt = match InPacket::try_new(Direction::S2C, raw) {
                Ok(p) => p,
                Err(e) => {
                    println!("  [raw {:?} len={}] {:02x?}", e, len, &raw[..len.min(24)]);
                    continue;
                }
            };
            let p_type = in_pkt.header().packet_type();
            let p_id = in_pkt.header().packet_id();
            let flags = in_pkt.header().flags();

            if flags.contains(Flags::UNENCRYPTED) && !matches!(p_type, PacketType::Command) {
                self.ack(p_type, p_id).await;
                println!("  [pkt type={:?} pid={} flags={:?}]", p_type, p_id, flags);
                continue;
            }

            match p_type {
                PacketType::Command => {
                    self.ack(p_type, p_id).await;
                    if len < 11 {
                        continue;
                    }
                    let mac: [u8; 8] = raw[..8].try_into().unwrap();
                    let mut ct = raw[11..].to_vec();
                    let (key, nonce) = derive_key_nonce(
                        Direction::S2C,
                        PacketType::Command as u8,
                        0,
                        p_id,
                        &self.shared_iv,
                    );
                    if decrypt_eax(&key, &nonce, &raw[8..11], &mac, &mut ct).is_err() {
                        println!("  [FAILED DECRYPT pid={} len={}]", p_id, len);
                        continue;
                    }
                    let text = if flags.contains(Flags::FRAGMENTED) {
                        if self.frag.is_empty() {
                            self.frag.extend_from_slice(&ct);
                            continue;
                        }
                        self.frag.extend_from_slice(&ct);
                        String::from_utf8_lossy(&std::mem::take(&mut self.frag)).to_string()
                    } else if !self.frag.is_empty() {
                        self.frag.extend_from_slice(&ct);
                        continue;
                    } else {
                        String::from_utf8_lossy(&ct).to_string()
                    };
                    self.seq += 1;
                    println!(
                        "[{:>6.3}s] #{} (pid {} flags {:?}) {}",
                        self.start.elapsed().as_secs_f64(),
                        self.seq,
                        p_id,
                        flags,
                        text
                    );
                    return Some((text, p_id, flags));
                }
                _ => {
                    self.ack(p_type, p_id).await;
                }
            }
        }
    }

    async fn send_cmd(&mut self, cmd: &Command) {
        let p_id = self.next_c2s_pid;
        self.next_c2s_pid = self.next_c2s_pid.wrapping_add(1);
        let mut payload = cmd.build().into_bytes();
        let (key, nonce) = derive_key_nonce(
            Direction::C2S,
            PacketType::Command as u8,
            0,
            p_id,
            &self.shared_iv,
        );
        let mut pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
        pkt.packet_id(p_id);
        pkt.client_id(self.clid);
        let mut aad = Vec::new();
        aad.extend_from_slice(&p_id.to_be_bytes());
        aad.extend_from_slice(&self.clid.to_be_bytes());
        aad.push(PacketType::Command as u8);
        let mac = encrypt_eax(&key, &nonce, &aad, &mut payload).unwrap();
        pkt.mac().copy_from_slice(&mac);
        pkt.data_mut().extend_from_slice(&payload);
        println!("\n>>> C2S (pid {}): {}", p_id, cmd.build());
        self.sock.send(&pkt.into_vec()).await.unwrap();
    }

    /// Drain everything the server sends for `dur`, printing each command.
    async fn drain(&mut self, dur: Duration) -> Vec<String> {
        let mut got = Vec::new();
        let deadline = Instant::now() + dur;
        while Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(Instant::now());
            match self.recv_text(remain).await {
                Some((text, _, _)) => got.push(text),
                None => break,
            }
        }
        got
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "9987".to_string());
    let nickname = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "OracleProbe".to_string());
    let uid = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "oracle_probe_uid".to_string());
    let token = std::env::args().nth(4).unwrap_or_default();

    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    sock.connect(format!("127.0.0.1:{}", port)).await?;
    println!(
        "Connecting to 127.0.0.1:{} as {} (uid {})",
        port, nickname, uid
    );

    // Init0/1
    let mut r0 = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut r0);
    let init0 = OutC2SInit0::new(0, 0, r0);
    sock.send(&init0.into_vec()).await?;
    let mut buf = [0u8; 4096];
    let len = timeout(Duration::from_secs(3), sock.recv(&mut buf)).await??;
    println!("Init0 response raw len={} hex={:02x?}", len, &buf[..len]);
    let in1 = InPacket::try_new(Direction::S2C, &buf[..len])?;
    let s2c1 = in1.into_s2cinit()?;
    let (r1, r0_rev) = match s2c1.data() {
        S2CInitData::Init1 { random1, random0_r } => (*random1, **random0_r),
        _ => return Err("expected Init1".into()),
    };

    // Init2/3
    let init2 = OutC2SInit2::new(0, &r1, r0_rev);
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
        _ => return Err("expected Init3".into()),
    };
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
    let init4 = OutC2SInit4::new(0, x, n, level, random2, &y, &alpha, &client_der, "");
    sock.send(&init4.into_vec()).await?;

    // initivexpand2
    let len = timeout(Duration::from_secs(3), sock.recv(&mut buf)).await??;
    let raw = &buf[..len];
    let mac: [u8; 8] = raw[..8].try_into().unwrap();
    let mut ct = raw[11..].to_vec();
    decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &raw[8..11], &mac, &mut ct)?;
    let expand = Command::parse(std::str::from_utf8(&ct)?).ok_or("parse initivexpand2")?;
    println!("initivexpand2: {}", expand.raw);
    let server_beta = BASE64_STANDARD.decode(expand.get("beta").ok_or("beta")?)?;

    // clientek
    let mut ek_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ek_seed);
    let client_ek_scalar = Scalar::from_bytes_mod_order(ek_seed);
    let client_ek_pub = (ED25519_BASEPOINT_POINT * client_ek_scalar).compress().0;
    let client_ek_b64 = BASE64_STANDARD.encode(client_ek_pub);
    let shared_secret = (CompressedEdwardsY(ANON_SERVER_DERIVED_PUB)
        .decompress()
        .ok_or("server point")?
        * client_ek_scalar)
        .compress()
        .0;
    let mut shared_iv = [0u8; 64];
    shared_iv.copy_from_slice(&Sha512::digest(shared_secret));
    for (i, b) in alpha.iter().enumerate().take(10) {
        shared_iv[i] ^= *b;
    }
    for (i, b) in server_beta.iter().enumerate().take(54) {
        shared_iv[10 + i] ^= *b;
    }
    let shared_mac: [u8; 8] = Sha1::digest(shared_iv)[..8].try_into().unwrap();

    let mut probe = Probe {
        sock,
        shared_iv,
        shared_mac,
        clid: 1,
        next_c2s_pid: 2,
        frag: Vec::new(),
        start: Instant::now(),
        seq: 0,
    };

    // ACK initivexpand2 then clientek
    probe.ack(PacketType::Command, 0).await;
    let mut clientek = Command::new("clientek");
    clientek.set("ek", &client_ek_b64);
    clientek.set("proof", &BASE64_STANDARD.encode(b"oracle-probe"));
    let mut ek_payload = clientek.build().into_bytes();
    let ek_pid = 1u16;
    let mut ek_aad = Vec::new();
    ek_aad.extend_from_slice(&ek_pid.to_be_bytes());
    ek_aad.extend_from_slice(&0u16.to_be_bytes());
    ek_aad.push(PacketType::Command as u8);
    let ek_mac = encrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &ek_aad, &mut ek_payload)?;
    let mut ek_pkt = OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
    ek_pkt.packet_id(ek_pid);
    ek_pkt.client_id(0);
    ek_pkt.mac().copy_from_slice(&ek_mac);
    ek_pkt.data_mut().extend_from_slice(&ek_payload);
    probe.sock.send(&ek_pkt.into_vec()).await?;
    println!(">>> C2S clientek sent");
    probe.drain(Duration::from_millis(500)).await;

    // clientinit
    let mut clientinit = Command::new("clientinit");
    clientinit.set("client_nickname", &nickname);
    clientinit.set("client_unique_identifier", &uid);
    clientinit.set("cluid", &uid);
    clientinit.set("client_version", "3.6.2 [Build: 1695216578]");
    clientinit.set("client_platform", "Windows");
    clientinit.set("client_input_hardware", "1");
    clientinit.set("client_output_hardware", "1");
    clientinit.set("client_default_channel", "");
    clientinit.set("client_default_token", "");
    clientinit.set("client_meta_data", "");
    probe.send_cmd(&clientinit).await;

    println!("\n========== CLIENTINIT RESPONSE SEQUENCE ==========");
    let initial = probe.drain(Duration::from_millis(2500)).await;
    for text in &initial {
        if let Some(cmd) = Command::parse(text) {
            if cmd.name == "initserver" {
                probe.clid = cmd
                    .get("aclid")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(probe.clid);
                println!(">>> assigned clid = {}", probe.clid);
            }
        }
    }
    probe.clid = probe.clid.max(1);

    if !token.is_empty() {
        println!("\n========== PRIVILEGE KEY REDEMPTION ==========");
        let mut use_cmd = Command::new("privilegekeyuse");
        use_cmd.set("token", &token);
        probe.send_cmd(&use_cmd).await;
        probe.drain(Duration::from_millis(1500)).await;
    }

    println!("\n========== CHANNELCREATE ==========");
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "Oracle\\sChannel");
    create.set("channel_topic", "created by oracle probe");
    create.set("channel_flag_permanent", "1");
    create.set("channel_codec", "4");
    create.set("channel_codec_quality", "7");
    probe.send_cmd(&create).await;
    let created = probe.drain(Duration::from_millis(2000)).await;

    // A second channel with the same name to observe the duplicate-name error.
    println!("\n========== CHANNELCREATE DUPLICATE NAME ==========");
    let mut create2 = Command::new("channelcreate");
    create2.set("channel_name", "Oracle\\sChannel");
    create2.set("channel_flag_permanent", "1");
    probe.send_cmd(&create2).await;
    probe.drain(Duration::from_millis(1500)).await;

    println!("\n========== SERVERGROUPLIST / PERMISSION FLOW CHECK ==========");
    let sg = Command::new("servergrouplist");
    probe.send_cmd(&sg).await;
    probe.drain(Duration::from_millis(1000)).await;

    println!("\n========== DISCONNECT ==========");
    let mut dc = Command::new("clientdisconnect");
    dc.set("reasonid", "3");
    dc.set("reasonmsg", "oracle\\sprobe");
    probe.send_cmd(&dc).await;
    probe.drain(Duration::from_millis(1500)).await;
    println!("done");

    let _ = created;
    Ok(())
}
