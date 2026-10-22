//! Offline decryptor for raw_proxy logs. Given the session's 64-byte SharedIV
//! (e.g. recovered with scan_iv), decrypts and reassembles every Command /
//! CommandLow packet in wire order and prints a chronological transcript.
//!
//! Usage: cargo run --release --example decrypt_log -- <logfile> <shared_iv_hex>

use std::collections::BTreeMap;

use tsproto_packets::packets::{Direction, Flags, PacketType};

use nano_ts3::crypto::*;

#[derive(Default)]
struct Dir {
    pending: BTreeMap<u16, (Flags, Vec<u8>)>,
    expected: u16,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let logfile = args.next().expect("logfile");
    let iv_hex = args.next().expect("shared iv hex (128 hex chars)");
    let iv: [u8; 64] = hex_to_bytes(&iv_hex).try_into().expect("64 bytes");

    // clientek has pid 1; the first shared-encrypted C2S command is pid 2.
    // initivexpand2 has pid 0; the first shared-encrypted S2C command is pid 1.
    let mut c2s = Dir {
        pending: BTreeMap::new(),
        expected: 2,
    };
    let mut s2c = Dir {
        pending: BTreeMap::new(),
        expected: 1,
    };
    let (mut ok_enc, mut fail_enc) = (0usize, 0usize);

    for line in std::fs::read_to_string(&logfile).unwrap().lines() {
        let mut it = line.split_whitespace();
        let (Some(dir), Some(ts), Some(hexdata)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let raw = hex_to_bytes(hexdata);
        let is_c2s = dir == "c2s";
        let hdr = if is_c2s { 13 } else { 11 };
        if raw.len() < hdr {
            continue;
        }
        let pid = u16::from_be_bytes([raw[8], raw[9]]);
        let flag_type_byte = raw[hdr - 1];
        let p_type = flag_type_byte & 0x0f;
        let flags = Flags::from_bits_truncate(flag_type_byte & 0xf0);

        if p_type == PacketType::Init as u8 {
            if is_c2s && flag_type_byte & 0x0f == 8 {
                // C2S Init packets start with "TS3INIT1"; Init4 embeds the
                // authoritative clientinitiv as trailing text.
                if let Some(pos) = find_subslice(&raw, b"clientinitiv") {
                    println!(
                        "[{:>7}ms INIT C2S pid={}] {}",
                        ts,
                        pid,
                        String::from_utf8_lossy(&raw[pos..])
                    );
                }
            }
            continue;
        }
        if p_type != PacketType::Command as u8 && p_type != PacketType::CommandLow as u8 {
            continue;
        }

        let mac: [u8; 8] = raw[..8].try_into().unwrap();
        let aad = &raw[8..hdr];
        let mut ct = raw[hdr..].to_vec();

        // Bootstrap-encrypted packets: clientinitiv (pid 0) and clientek
        // (pid 1) from the client, initivexpand2 (pid 0) from the server.
        if pid <= 1 && decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, aad, &mac, &mut ct).is_ok() {
            println!(
                "[{:>7}ms BOOT {} pid={}] {}",
                ts,
                if is_c2s { "C2S" } else { "S2C" },
                pid,
                String::from_utf8_lossy(&ct)
            );
            continue;
        }
        ct = raw[hdr..].to_vec();

        let dir_enum = if is_c2s {
            Direction::C2S
        } else {
            Direction::S2C
        };
        let (key, nonce) = derive_key_nonce(dir_enum, p_type, 0, pid, &iv);
        if decrypt_eax(&key, &nonce, aad, &mac, &mut ct).is_err() {
            fail_enc += 1;
            if fail_enc <= 5 || fail_enc % 50 == 0 {
                println!(
                    "[{:>7}ms ???  {} pid={} flags={:?}] decrypt failed",
                    ts,
                    if is_c2s { "C2S" } else { "S2C" },
                    pid,
                    flags
                );
            }
            continue;
        }
        ok_enc += 1;

        let d = if is_c2s { &mut c2s } else { &mut s2c };
        d.pending.insert(pid, (flags, ct));
        while let Some((bytes, consumed)) = try_assemble_bytes(&d.pending, d.expected) {
            let first_pid = d.expected;
            let cmd_flags = d
                .pending
                .range(first_pid..first_pid.wrapping_add(consumed))
                .map(|(_, (f, _))| *f)
                .fold(Flags::empty(), |acc, f| acc | f);
            for id in first_pid..first_pid.wrapping_add(consumed) {
                d.pending.remove(&id);
            }
            d.expected = d.expected.wrapping_add(consumed);
            let compressed = cmd_flags.contains(Flags::COMPRESSED);
            let dump = format!(
                "scratch/asm/{}_p{}.bin",
                if is_c2s { "c2s" } else { "s2c" },
                first_pid
            );
            if let Some(parent) = std::path::Path::new(&dump).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&dump, &bytes);
            let text = String::from_utf8_lossy(&bytes);
            println!(
                "[{:>7}ms {} pids {}..{} flags={:?}{}] {}",
                ts,
                if is_c2s { "C2S" } else { "S2C" },
                first_pid,
                d.expected.wrapping_sub(1),
                cmd_flags,
                if compressed { " COMPRESSED" } else { "" },
                if compressed {
                    format!("<{} bytes, {}>", bytes.len(), dump)
                } else {
                    text.to_string()
                }
            );
        }
    }
    println!("--- {} decrypted packets, {} failures", ok_enc, fail_enc);
}

/// Same reassembly rule as the server: the first and last packet of a
/// fragmented command carry FRAGMENTED, middles carry no flag.
fn try_assemble_bytes(
    pending: &BTreeMap<u16, (Flags, Vec<u8>)>,
    expected: u16,
) -> Option<(Vec<u8>, u16)> {
    let (first_flags, first_bytes) = pending.get(&expected)?.clone();
    if !first_flags.contains(Flags::FRAGMENTED) {
        return Some((first_bytes, 1));
    }
    let mut ids = 1u16;
    let mut payload = first_bytes;
    let mut curr = expected;
    loop {
        let next = curr.wrapping_add(1);
        match pending.get(&next) {
            Some((flags, bytes)) => {
                ids += 1;
                payload.extend_from_slice(bytes);
                if flags.contains(Flags::FRAGMENTED) {
                    return Some((payload, ids));
                }
                curr = next;
            }
            None => return None,
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}
