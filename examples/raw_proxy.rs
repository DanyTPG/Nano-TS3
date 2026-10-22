//! Transparent UDP proxy that records every packet (both directions) as hex
//! lines for offline decryption. One upstream socket per client address.
//!
//! Usage: cargo run --release --example raw_proxy -- <listen_port> <upstream_port> [logfile]

use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let listen_port: u16 = args.next().expect("listen port").parse()?;
    let upstream_port: u16 = args.next().expect("upstream port").parse()?;
    let logfile = args
        .next()
        .unwrap_or_else(|| format!("scratch/raw_{}.log", listen_port));

    let listener = Arc::new(UdpSocket::bind(("127.0.0.1", listen_port)).await?);
    let upstream_addr: SocketAddr = format!("127.0.0.1:{}", upstream_port).parse()?;
    let log = Arc::new(Mutex::new(std::io::BufWriter::new(std::fs::File::create(
        &logfile,
    )?)));
    let start = std::time::Instant::now();

    // client addr -> upstream socket
    let sessions: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    println!(
        "raw proxy 127.0.0.1:{} -> {}, logging to {}",
        listen_port, upstream_addr, logfile
    );

    fn log_packet(
        log: &Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
        start: &std::time::Instant,
        dir: &str,
        data: &[u8],
    ) {
        let mut line = format!("{} {:6} ", dir, start.elapsed().as_millis());
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in data {
            line.push(HEX[(b >> 4) as usize] as char);
            line.push(HEX[(b & 0xf) as usize] as char);
        }
        line.push('\n');
        let mut f = log.lock().unwrap();
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
    }

    let mut buf = [0u8; 8192];
    loop {
        let (len, peer) = listener.recv_from(&mut buf).await?;
        let raw = &buf[..len];

        let upstream = {
            let mut s = sessions.lock().unwrap();
            match s.get(&peer) {
                Some(sock) => sock.clone(),
                None => {
                    let sock = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
                    sock.connect(upstream_addr).await?;
                    s.insert(peer, sock.clone());

                    // Reader task: upstream -> client.
                    let listener2 = listener.clone();
                    let log2 = log.clone();
                    let start2 = start;
                    let peer2 = peer;
                    let task_sock = sock.clone();
                    tokio::spawn(async move {
                        let mut b = [0u8; 8192];
                        loop {
                            match task_sock.recv(&mut b).await {
                                Ok(n) => {
                                    log_packet(&log2, &start2, "s2c", &b[..n]);
                                    let _ = listener2.send_to(&b[..n], peer2).await;
                                }
                                Err(e) => {
                                    eprintln!("upstream recv error: {}", e);
                                }
                            }
                        }
                    });
                    sock
                }
            }
        };

        log_packet(&log, &start, "c2s", raw);
        let _ = upstream.send(raw).await;
    }
}
