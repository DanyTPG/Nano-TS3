use base64::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tsproto_packets::packets::*;

use nano_ts3::command::Command;
use nano_ts3::crypto::*;

#[derive(Default)]
struct Session {
    client_addr: Option<SocketAddr>,
    alpha: [u8; 10],
    beta: Vec<u8>,
    shared_iv: Option<[u8; 64]>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:9989").await?);
    let upstream_port = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "9987".to_string());
    let server_addr: SocketAddr = format!("127.0.0.1:{}", upstream_port).parse()?;
    let upstream_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    upstream_sock.connect(server_addr).await?;

    println!(
        "Proxy listening on 127.0.0.1:9989, forwarding to {}",
        server_addr
    );

    let session = Arc::new(Mutex::new(Session::default()));

    let proxy_c2s = proxy_sock.clone();
    let upstream_c2s = upstream_sock.clone();
    let sess_c2s = session.clone();

    // Task 1: C2S (Client -> Proxy -> Server)
    let t1 = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (len, peer) = match proxy_c2s.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("recv_from error: {}", e);
                    continue;
                }
            };

            let raw = &buf[..len];
            {
                let mut s = sess_c2s.lock().await;
                s.client_addr = Some(peer);
            }

            // Dump every init packet so the handshake fields can be studied.
            if raw.starts_with(b"TS3INIT1") && len >= 18 {
                println!(
                    "[PROXY C2S] Init pkt len={} step={} version={:02x?}",
                    len,
                    raw[17],
                    &raw[13..17]
                );
                // Init4 embeds the authoritative clientinitiv (alpha) after a
                // 301-byte fixed prefix; the server uses this alpha, not the
                // separately-sent bootstrap clientinitiv command.
                if raw[17] == 4 && len > 13 + 301 {
                    let embedded = String::from_utf8_lossy(&raw[314..]);
                    println!("[PROXY C2S] Init4 embedded: {}", embedded);
                    if let Some(cmd) = Command::parse(&embedded) {
                        if let Some(a_b64) = cmd.get("alpha") {
                            if let Ok(a_bytes) = BASE64_STANDARD.decode(a_b64) {
                                if a_bytes.len() == 10 {
                                    let mut s = sess_c2s.lock().await;
                                    s.alpha.copy_from_slice(&a_bytes);
                                    println!(
                                        "[PROXY C2S] Captured alpha from Init4: {:02x?}",
                                        s.alpha
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Check if Command packet
            if len >= 13 {
                let p_type = raw[12] & 0x0f;
                let p_id = u16::from_be_bytes([raw[8], raw[9]]);
                let p_flags = raw[12] & 0xf0;
                println!(
                    "[PROXY C2S] pkt len={}, p_type={}, pid={}, flags=0x{:02x}, mac={:02x?}",
                    len,
                    p_type,
                    p_id,
                    p_flags,
                    &raw[..8]
                );
                if p_type == PacketType::Command as u8 {
                    let mut s = sess_c2s.lock().await;
                    if s.shared_iv.is_none() {
                        // Pre-SharedIV command: clientinitiv or clientek
                        let mac: [u8; 8] = raw[..8].try_into().unwrap();
                        let aad = &raw[8..13];
                        let mut ct = raw[13..].to_vec();
                        if let Ok(()) =
                            decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, aad, &mac, &mut ct)
                        {
                            let text = String::from_utf8_lossy(&ct);
                            println!(
                                "[PROXY C2S (bootstrap)] Decrypted Command (pid={}): {}",
                                p_id, text
                            );
                            if let Some(cmd) = Command::parse(&text) {
                                if cmd.name == "clientinitiv" {
                                    if let Some(a_b64) = cmd.get("alpha") {
                                        if let Ok(a_bytes) = BASE64_STANDARD.decode(a_b64) {
                                            if a_bytes.len() == 10 {
                                                s.alpha.copy_from_slice(&a_bytes);
                                                println!(
                                                    "[PROXY C2S] Captured alpha from clientinitiv: {:02x?}",
                                                    s.alpha
                                                );
                                            }
                                        }
                                    }
                                } else if cmd.name == "clientek" {
                                    if let Some(ek_b64) = cmd.get("ek") {
                                        if let Ok(ek_bytes) = BASE64_STANDARD.decode(ek_b64) {
                                            if let Ok(ek_arr) = ek_bytes.as_slice().try_into() {
                                                if let Ok(siv) = compute_shared_iv_modern(
                                                    &ek_arr,
                                                    &SERVER_LICENSE_KEY_K,
                                                    &s.alpha,
                                                    &s.beta,
                                                ) {
                                                    s.shared_iv = Some(siv);
                                                    println!(
                                                        "[PROXY C2S] Established SharedIV from clientek!"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if let Some(siv) = s.shared_iv {
                        // Post-SharedIV command
                        let mac: [u8; 8] = raw[..8].try_into().unwrap();
                        let aad = &raw[8..13];
                        let mut ct = raw[13..].to_vec();
                        let (k, n) = derive_key_nonce(Direction::C2S, p_type, 0, p_id, &siv);
                        if let Ok(()) = decrypt_eax(&k, &n, aad, &mac, &mut ct) {
                            let text = String::from_utf8_lossy(&ct);
                            println!("[PROXY C2S] Decrypted Command (pid={}): {}", p_id, text);
                        } else {
                            println!("[PROXY C2S] Failed to decrypt command pid={}", p_id);
                        }
                    }
                }
            }

            let _ = upstream_c2s.send(raw).await;
        }
    });

    // Task 2: S2C (Server -> Upstream -> Proxy -> Client)
    let proxy_s2c = proxy_sock.clone();
    let upstream_s2c = upstream_sock.clone();
    let sess_s2c = session.clone();

    let t2 = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let len = match upstream_s2c.recv(&mut buf).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("upstream recv error: {}", e);
                    continue;
                }
            };

            let raw = &buf[..len];

            // Print every S2C packet info
            if len >= 11 {
                let p_type = raw[10] & 0x0f;
                let p_id = u16::from_be_bytes([raw[8], raw[9]]);
                let p_flags = raw[10] & 0xf0;
                println!(
                    "[PROXY S2C] pkt len={}, p_type={}, pid={}, flags=0x{:02x}, mac={:02x?}",
                    len,
                    p_type,
                    p_id,
                    p_flags,
                    &raw[..8]
                );

                if p_type == PacketType::Command as u8 {
                    let mut s = sess_s2c.lock().await;
                    if s.beta.is_empty() {
                        // initivexpand2
                        let mac: [u8; 8] = raw[..8].try_into().unwrap();
                        let aad = &raw[8..11];
                        let mut ct = raw[11..].to_vec();
                        if let Ok(()) =
                            decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, aad, &mac, &mut ct)
                        {
                            let text = String::from_utf8_lossy(&ct);
                            println!(
                                "[PROXY S2C (bootstrap)] Decrypted initivexpand2 (pid={}): {}",
                                p_id, text
                            );
                            if let Some(cmd) = Command::parse(&text) {
                                if let Some(beta_b64) = cmd.get("beta") {
                                    if let Ok(b) = BASE64_STANDARD.decode(beta_b64) {
                                        s.beta = b;
                                        println!(
                                            "[PROXY S2C] Captured beta (len={})",
                                            s.beta.len()
                                        );
                                    }
                                }
                            }
                        }
                    } else if let Some(siv) = s.shared_iv {
                        let mac: [u8; 8] = raw[..8].try_into().unwrap();
                        let aad = &raw[8..11];
                        let mut ct = raw[11..].to_vec();
                        let (k, n) = derive_key_nonce(Direction::S2C, p_type, 0, p_id, &siv);
                        if let Ok(()) = decrypt_eax(&k, &n, aad, &mac, &mut ct) {
                            let text = String::from_utf8_lossy(&ct);
                            println!("[PROXY S2C] Decrypted Command (pid={}): {}", p_id, text);
                        } else {
                            println!("[PROXY S2C] Failed to decrypt S2C command pid={}", p_id);
                        }
                    }
                }
            }

            let client_addr = {
                let s = sess_s2c.lock().await;
                s.client_addr
            };

            if let Some(caddr) = client_addr {
                let _ = proxy_s2c.send_to(raw, caddr).await;
            }
        }
    });

    let _ = tokio::join!(t1, t2);
    Ok(())
}
