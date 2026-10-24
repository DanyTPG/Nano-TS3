//! Scan a process's memory for a 64-byte window whose SHA1 prefix matches a
//! known shared MAC (the wire MAC field of unencrypted TS3 Ping/Ack packets is
//! sha1(shared_iv)[..8]). Prints every matching window as hex.
//!
//! Usage: cargo run --release --example scan_iv -- <pid> <oracle_mac_hex>

// This tool reads Windows process memory through kernel32 and cannot build
// on other hosts; gating it keeps `cargo test` green on Linux CI.
#[cfg(windows)]
use sha1::{Digest as _, Sha1};

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    region_type: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
    fn CloseHandle(handle: isize) -> i32;
    fn ReadProcessMemory(
        handle: isize,
        base_address: *const u8,
        buffer: *mut u8,
        size: usize,
        bytes_read: *mut usize,
    ) -> i32;
    fn VirtualQueryEx(
        handle: isize,
        address: *const u8,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
}

#[cfg(windows)]
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

#[cfg(windows)]
fn readable(protect: u32) -> bool {
    const GUARD: u32 = 0x100;
    if protect & GUARD != 0 {
        return false;
    }
    matches!(
        protect & 0xFF,
        0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80 // R, RW, WC, ER, ERW, EWC
    )
}

#[cfg(windows)]
fn main() {
    let mut args = std::env::args().skip(1);
    let pid: u32 = args.next().expect("pid").parse().expect("numeric pid");
    let oracle_hex = args.next().expect("oracle mac hex (16 hex chars)");
    let oracle = hex_to_bytes(&oracle_hex);
    let oracle: [u8; 8] = oracle.try_into().expect("8 bytes");

    unsafe {
        let proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        if proc == 0 {
            eprintln!(
                "OpenProcess failed (GetLastError {} in windbg terms)",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }

        let mut mbi = MemoryBasicInformation::default();
        let mut addr: usize = 0x10000;
        let mut regions = 0usize;
        let mut scanned = 0usize;
        let mut hits = 0usize;

        loop {
            let n = VirtualQueryEx(
                proc,
                addr as *const u8,
                &mut mbi,
                std::mem::size_of::<MemoryBasicInformation>(),
            );
            if n == 0 {
                break;
            }
            let next = mbi.base.checked_add(mbi.region_size).unwrap_or(usize::MAX);
            if mbi.state == 0x1000 && readable(mbi.protect) && mbi.region_size > 0 {
                regions += 1;
                // Read the region in chunks; skip unreadable tails.
                let mut chunk = vec![0u8; mbi.region_size.min(64 * 1024 * 1024)];
                let mut done = 0usize;
                while done < mbi.region_size {
                    let want = chunk.len().min(mbi.region_size - done);
                    let mut got = 0usize;
                    let ok = ReadProcessMemory(
                        proc,
                        (mbi.base + done) as *const u8,
                        chunk.as_mut_ptr(),
                        want,
                        &mut got,
                    );
                    if ok == 0 || got == 0 {
                        break;
                    }
                    scanned += got;
                    // Slide a 64-byte window; keep the last 63 bytes across
                    // chunk boundaries via an overlap copy.
                    let data = &chunk[..got];
                    let mut i = 0usize;
                    while i + 64 <= data.len() {
                        let digest = Sha1::digest(&data[i..i + 64]);
                        if digest[..8] == oracle {
                            let iv: [u8; 64] = data[i..i + 64].try_into().unwrap();
                            println!(
                                "HIT at 0x{:x}: {}",
                                mbi.base + done + i,
                                iv.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                            );
                            hits += 1;
                        }
                        i += 1;
                    }
                    done += got;
                }
            }
            if next <= addr || next == usize::MAX {
                break;
            }
            addr = next;
        }

        println!(
            "scanned {} regions, {} bytes, {} hits",
            regions, scanned, hits
        );
        CloseHandle(proc);
    }
}

#[cfg(windows)]
fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("scan_iv reads Windows process memory and only runs on Windows.");
}
