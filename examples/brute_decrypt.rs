//! One-shot decryptor: tries every provided session IV against every C2S/S2C
//! command packet independently (no pid sequencing), printing decrypted
//! commands with their packet ids. Works on raw_proxy logs with interleaved
//! sessions.
//!
//! Usage: cargo run --release --example brute_decrypt -- <logfile> <iv1> [iv2] ...

use std::collections::BTreeMap;

use tsproto_packets::packets::{Direction, Flags, PacketType};

use nano_ts3::crypto::*;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let logfile = args.next().expect("logfile");
    let ivs: Vec<[u8; 64]> = args
        .map(|h| hex_to_bytes(&h).try_into().expect("64-byte iv hex"))
        .collect();

    let data = std::fs::read_to_string(&logfile).expect("log file");
    let mut out: BTreeMap<(u64, char, u16), String> = BTreeMap::new();

    for line in data.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        let dir = parts[0];
        let ts: u64 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let raw = match hex_to_bytes(parts[2].trim()).try_into() as Result<Vec<u8>, _> {
            Ok(v) => v,
            Err(_) => continue,
        };
        if raw.len() < 13 {
            continue;
        }
        let p_type = raw[12] & 0x0f;
        if p_type != PacketType::Command as u8 && p_type != PacketType::CommandLow as u8 {
            continue;
        }
        let direction = if dir == "c2s" { Direction::C2S } else { Direction::S2C };
        let pid = u16::from_be_bytes([raw[8], raw[9]]);
        let mut ciphertext = raw[13..].to_vec();
        let aad = &raw[8..13];

        for iv in &ivs {
            let (key, nonce) = derive_key_nonce(direction, p_type, 0, pid, iv);
            if decrypt_eax(&key, &nonce, aad, &raw[..8].try_into().unwrap(), &mut ciphertext)
                .is_ok()
            {
                if let Ok(text) = std::str::from_utf8(&ciphertext) {
                    let tag = if dir == "c2s" { 'C' } else { 'S' };
                    let pt = if p_type == PacketType::Command as u8 { 'H' } else { 'L' };
                    out.insert((ts, tag, pid), format!("[{:>8}ms {}{} pid={}] {}", ts, tag, pt, pid, text));
                }
                break;
            }
        }
    }

    for (_, v) in out {
        println!("{}", v);
    }
}
