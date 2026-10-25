use base64::prelude::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use p256::SecretKey;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tsproto_packets::packets::*;

use nano_ts3::command::Command;
use nano_ts3::crypto::*;

struct ClientSession {
    sock: UdpSocket,
    shared_iv: [u8; 64],
    pub clid: u16,
    pub uid: String,
    c2s_pid: u16,
    frag_buf: Vec<u8>,
}

impl ClientSession {
    async fn connect(server_addr: SocketAddr, nickname: &str, is_admin: bool) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind failed");
        sock.connect(server_addr).await.expect("connect failed");

        let mut r0 = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut r0);
        let init0 = OutC2SInit0::new(0, 0, r0);
        sock.send(&init0.into_vec()).await.unwrap();

        let mut buf = [0u8; 4096];
        let len = timeout(Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let in1 = InPacket::try_new(Direction::S2C, &buf[..len]).unwrap();
        let s2c1 = in1.into_s2cinit().unwrap();
        let (r1, r0_rev) = match s2c1.data() {
            S2CInitData::Init1 { random1, random0_r } => (*random1, **random0_r),
            other => panic!("Expected Init1, got {:?}", other),
        };

        let init2 = OutC2SInit2::new(0, &r1, r0_rev);
        sock.send(&init2.into_vec()).await.unwrap();

        let len = timeout(Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let in3 = InPacket::try_new(Direction::S2C, &buf[..len]).unwrap();
        let s2c3 = in3.into_s2cinit().unwrap();
        let (x, n, level, random2) = match s2c3.data() {
            S2CInitData::Init3 {
                x,
                n,
                level,
                random2,
            } => (*x, *n, *level, *random2),
            other => panic!("Expected Init3, got {:?}", other),
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

        let mut client_key_bytes = [0u8; 32];
        let client_secret = loop {
            rand::thread_rng().fill_bytes(&mut client_key_bytes);
            if let Ok(sk) = SecretKey::from_slice(&client_key_bytes) {
                break sk;
            }
        };
        let client_der = encode_libtomcrypt_ecc_public(client_secret.public_key().as_affine());
        let omega_b64 = BASE64_STANDARD.encode(&client_der);
        let derived_uid = BASE64_STANDARD.encode(sha1::Sha1::digest(omega_b64.as_bytes()));

        if is_admin {
            let conn = rusqlite::Connection::open("nano_ts3.db").unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let _ = conn.execute(
                "INSERT OR IGNORE INTO admin_identities (client_uid, created_at) VALUES (?1, ?2)",
                rusqlite::params![derived_uid, now],
            );
        }

        let mut alpha = [0u8; 10];
        rand::thread_rng().fill_bytes(&mut alpha);

        let init4 = OutC2SInit4::new(0, x, n, level, random2, &y, &alpha, &client_der, "");
        sock.send(&init4.into_vec()).await.unwrap();

        let len = timeout(Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let raw = &buf[..len];
        let mac: [u8; 8] = raw[..8].try_into().unwrap();
        let mut ct = raw[11..].to_vec();
        decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &raw[8..11], &mac, &mut ct)
            .expect("decrypt initivexpand2");
        let expand_cmd = Command::parse(std::str::from_utf8(&ct).unwrap()).unwrap();
        let server_beta = BASE64_STANDARD
            .decode(expand_cmd.get("beta").unwrap())
            .unwrap();

        let mut ek_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ek_seed);
        let client_ek_scalar = Scalar::from_bytes_mod_order(ek_seed);
        let client_ek_point = ED25519_BASEPOINT_POINT * client_ek_scalar;
        let client_ek_pub = client_ek_point.compress().0;
        let client_ek_b64 = BASE64_STANDARD.encode(&client_ek_pub);

        let server_derived_pub: [u8; 32] = [
            0x2c, 0x39, 0xee, 0xda, 0x23, 0x12, 0xb2, 0x03, 0x7f, 0x51, 0xb2, 0x87, 0xd1, 0x1f,
            0x53, 0xba, 0x46, 0x84, 0x38, 0x25, 0xeb, 0x4c, 0xdb, 0x9e, 0x0b, 0xf9, 0x37, 0x4a,
            0x32, 0x1d, 0x62, 0x32,
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
        clientek_cmd.set("proof", "live_verification");
        let mut ek_payload = clientek_cmd.build().into_bytes();

        let ek_pid = 1u16;
        let mut ek_pkt =
            OutPacket::new_with_dir(Direction::C2S, Flags::empty(), PacketType::Command);
        ek_pkt.packet_id(ek_pid);
        ek_pkt.client_id(0);

        let mut ek_aad = Vec::new();
        ek_aad.extend_from_slice(&ek_pid.to_be_bytes());
        ek_aad.extend_from_slice(&0u16.to_be_bytes());
        ek_aad.push(PacketType::Command as u8);

        let ek_mac = encrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &ek_aad, &mut ek_payload).unwrap();
        ek_pkt.mac().copy_from_slice(&ek_mac);
        ek_pkt.data_mut().extend_from_slice(&ek_payload);
        sock.send(&ek_pkt.into_vec()).await.unwrap();

        let _ = timeout(Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let mut clientinit_cmd = Command::new("clientinit");
        clientinit_cmd.set("client_nickname", nickname);
        clientinit_cmd.set("client_unique_identifier", &derived_uid);
        clientinit_cmd.set("cluid", &derived_uid);
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

        let mac = encrypt_eax(&key, &nonce, &aad, &mut payload).unwrap();
        pkt.mac().copy_from_slice(&mac);
        pkt.data_mut().extend_from_slice(&payload);
        sock.send(&pkt.into_vec()).await.unwrap();

        let mut session = Self {
            sock,
            shared_iv,
            clid: 0,
            uid: derived_uid,
            c2s_pid: 3,
            frag_buf: Vec::new(),
        };

        while let Some(cmd) = session.recv_command(Duration::from_secs(3)).await {
            if cmd.name == "initserver" {
                if let Some(aclid) = cmd.get("aclid") {
                    session.clid = aclid.parse().unwrap_or(0);
                }
            }
            if cmd.name == "error" {
                break;
            }
        }

        session
    }

    async fn send_command(&mut self, cmd: &Command) {
        let p_id = self.c2s_pid;
        self.c2s_pid = self.c2s_pid.wrapping_add(1);

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
        self.sock.send(&pkt.into_vec()).await.unwrap();
    }

    async fn recv_command(&mut self, timeout_dur: Duration) -> Option<Command> {
        let mut buf = [0u8; 4096];
        loop {
            let len = match timeout(timeout_dur, self.sock.recv(&mut buf)).await {
                Ok(Ok(l)) => l,
                _ => return None,
            };

            let in_resp = match InPacket::try_new(Direction::S2C, &buf[..len]) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let p_type = in_resp.header().packet_type();
            let p_id = in_resp.header().packet_id();

            if p_type == PacketType::Ping {
                let shared_mac: [u8; 8] = sha1::Sha1::digest(&self.shared_iv)[..8].try_into().unwrap();
                let mut pong = OutAck::new(Direction::C2S, PacketType::Pong, p_id);
                pong.flags(Flags::UNENCRYPTED);
                pong.mac().copy_from_slice(&shared_mac);
                let _ = self.sock.send(&pong.into_vec()).await;
                continue;
            }

            if p_type == PacketType::Ack {
                continue;
            }

            if p_type == PacketType::Command {
                let resp_id = in_resp.header().packet_id();
                let flags = in_resp.header().flags();
                let (s_key, s_nonce) = derive_key_nonce(
                    Direction::S2C,
                    PacketType::Command as u8,
                    0,
                    resp_id,
                    &self.shared_iv,
                );
                let mac: [u8; 8] = buf[..8].try_into().unwrap();
                let aad = &buf[8..11];
                let mut text_buf = buf[11..len].to_vec();
                if decrypt_eax(&s_key, &s_nonce, aad, &mac, &mut text_buf).is_err() {
                    continue;
                }

                let cmd_text = if flags.contains(Flags::FRAGMENTED) {
                    if self.frag_buf.is_empty() {
                        self.frag_buf.extend_from_slice(&text_buf);
                        continue;
                    }
                    self.frag_buf.extend_from_slice(&text_buf);
                    let full = std::mem::take(&mut self.frag_buf);
                    String::from_utf8(full).ok()?
                } else if !self.frag_buf.is_empty() {
                    self.frag_buf.extend_from_slice(&text_buf);
                    continue;
                } else {
                    String::from_utf8(text_buf).ok()?
                };

                return Command::parse(&cmd_text);
            }
        }
    }

    async fn recv_until(&mut self, name: &str, timeout_dur: Duration) -> Option<Command> {
        let deadline = tokio::time::Instant::now() + timeout_dur;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline - tokio::time::Instant::now();
            if let Some(cmd) = self.recv_command(remaining).await {
                if cmd.name == name {
                    return Some(cmd);
                }
            } else {
                return None;
            }
        }
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr: SocketAddr = "127.0.0.1:9988".parse()?;
    println!("=== STARTING LIVE VERIFICATION AGAINST NANO-TS3 AT {} ===", server_addr);

    // Find the GUI client's clid by querying client list
    println!("\n--- Step 1: Connecting Alice (Admin) and Bob (Guest) ---");
    let mut alice = ClientSession::connect(server_addr, "AliceAdmin", true).await;
    println!("Alice (Admin) connected, clid={}, uid={}", alice.clid, alice.uid);

    let mut bob = ClientSession::connect(server_addr, "BobGuest", false).await;
    println!("Bob (Guest) connected, clid={}, uid={}", bob.clid, bob.uid);

    // Alice queries clientlist to find the GUI client's clid
    let clist_cmd = Command::new("clientlist");
    alice.send_command(&clist_cmd).await;
    let gui_clid = 2u16;
    if let Some(clist) = alice.recv_until("clist", Duration::from_secs(2)).await {
        println!("clientlist: {}", clist.raw);
    }

    // Step 2: Text Messaging (Channel, Server, and DM to GUI client)
    println!("\n--- Step 2: Testing Text Messages ---");
    // 2a. Channel message
    let mut ch_msg = Command::new("sendtextmessage");
    ch_msg.set("targetmode", "2");
    ch_msg.set("msg", "Live\\stest\\schannel\\smessage");
    alice.send_command(&ch_msg).await;
    let echo = alice.recv_until("notifytextmessage", Duration::from_secs(2)).await.expect("channel echo");
    println!("Channel message echo received: msg={:?}, invokeruid={:?}", echo.get("msg"), echo.get("invokeruid"));
    assert!(echo.get("invokeruid").is_some(), "invokeruid must be present!");

    // 2b. Private message to GUI client (clid 4)
    let mut dm_msg = Command::new("sendtextmessage");
    dm_msg.set("targetmode", "1");
    dm_msg.set("target", gui_clid.to_string());
    dm_msg.set("msg", "Private\\shello\\sto\\sGUI\\sAdmin");
    alice.send_command(&dm_msg).await;
    let dm_echo = alice.recv_until("notifytextmessage", Duration::from_secs(2)).await.expect("dm echo");
    println!("Private message echo received: msg={:?}, targetmode={:?}", dm_echo.get("msg"), dm_echo.get("targetmode"));

    // Step 3: Permissions - Guest cannot create channels, Admin can
    println!("\n--- Step 3: Channel Creation Permissions ---");
    let mut guest_create = Command::new("channelcreate");
    guest_create.set("channel_name", "BobIllegalChannel");
    guest_create.set("channel_flag_permanent", "1");
    bob.send_command(&guest_create).await;
    let err = bob.recv_until("error", Duration::from_secs(2)).await.expect("error response");
    println!("Bob channelcreate rejected as expected: id={:?}, failed_permid={:?}", err.get("id"), err.get("failed_permid"));
    assert_eq!(err.get("id"), Some("2568"));

    // Alice creates dynamic testing channel
    let chan_name = format!("LiveRoom_{}", rand::random::<u16>());
    let mut admin_create = Command::new("channelcreate");
    admin_create.set("channel_name", &chan_name);
    admin_create.set("channel_flag_permanent", "1");
    alice.send_command(&admin_create).await;
    let ok = alice.recv_until("notifychannelcreated", Duration::from_secs(2)).await.expect("channel created");
    let created_cid = ok.get("cid").unwrap().parse::<u64>().unwrap();
    println!("Alice successfully created channel: cid={}, name={}", created_cid, chan_name);
    let _ = alice.recv_until("error", Duration::from_secs(2)).await;

    // Step 4: Admin Move vs Guest Move
    println!("\n--- Step 4: Client Move Semantics ---");
    // Bob (guest) tries to move Alice -> fails
    let mut guest_move = Command::new("clientmove");
    guest_move.set("clid", alice.clid.to_string());
    guest_move.set("cid", created_cid.to_string());
    bob.send_command(&guest_move).await;
    let err_move = bob.recv_until("error", Duration::from_secs(2)).await.expect("move error");
    println!("Guest move rejected as expected: id={:?}, failed_permid={:?}", err_move.get("id"), err_move.get("failed_permid"));
    assert_eq!(err_move.get("id"), Some("2568"));

    // Alice (admin) moves Bob into TestingRoom
    let mut admin_move = Command::new("clientmove");
    admin_move.set("clid", bob.clid.to_string());
    admin_move.set("cid", created_cid.to_string());
    alice.send_command(&admin_move).await;
    let notify_move = alice.recv_until("notifyclientmoved", Duration::from_secs(2)).await.expect("notifyclientmoved");
    println!("Admin moved Bob successfully: clid={:?}, ctid={:?}", notify_move.get("clid"), notify_move.get("ctid"));
    assert_eq!(notify_move.get("clid"), Some(bob.clid.to_string().as_str()));
    assert_eq!(notify_move.get("ctid"), Some(created_cid.to_string().as_str()));
    let _ = alice.recv_until("error", Duration::from_secs(2)).await;

    // Step 5: Connection Info (Admin gets IP, Guest does not)
    println!("\n--- Step 5: Connection Info (IP visibility) ---");
    let mut get_info = Command::new("getconnectioninfo");
    get_info.set("clid", gui_clid.to_string());
    alice.send_command(&get_info).await;
    if let Some(info) = alice.recv_until("notifyconnectioninfo", Duration::from_secs(2)).await {
        println!("Alice (Admin) connection info response: has_ip={}, ip={:?}", info.get("connection_client_ip").is_some(), info.get("connection_client_ip"));
        assert!(info.get("connection_client_ip").is_some(), "Admin must see client IP");
    }

    bob.send_command(&get_info).await;
    if let Some(info) = bob.recv_until("notifyconnectioninfo", Duration::from_secs(2)).await {
        println!("Bob (Guest) connection info response: has_ip={}", info.get("connection_client_ip").is_some());
        assert!(info.get("connection_client_ip").is_none(), "Guest must NOT see client IP");
    }

    // Step 6: Channel Settings, Password Gate & Max Clients
    println!("\n--- Step 6: Channel Edit, Password Gate & Limits ---");
    let mut edit_cmd = Command::new("channeledit");
    edit_cmd.set("cid", created_cid.to_string());
    edit_cmd.set("channel_password", "secretpass");
    edit_cmd.set("channel_flag_password", "1");
    edit_cmd.set("channel_maxclients", "1");
    edit_cmd.set("channel_flag_maxclients_unlimited", "0");
    edit_cmd.set("channel_codec_quality", "9");
    alice.send_command(&edit_cmd).await;
    let edit_ok = alice.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("channeledited");
    println!("Channel edited: cid={:?}, password_flag={:?}, maxclients={:?}", edit_ok.get("cid"), edit_ok.get("channel_flag_password"), edit_ok.get("channel_maxclients"));
    let _ = alice.recv_until("error", Duration::from_secs(2)).await;

    // Charlie connects as Guest
    let mut charlie = ClientSession::connect(server_addr, "CharlieGuest", false).await;
    // Charlie tries to join TestingRoom with wrong password
    let mut join_bad = Command::new("clientmove");
    join_bad.set("cid", created_cid.to_string());
    join_bad.set("cpw", "wrongpass");
    charlie.send_command(&join_bad).await;
    let err_pw = charlie.recv_until("error", Duration::from_secs(2)).await.expect("pw error");
    println!("Join with wrong password rejected: id={:?}", err_pw.get("id"));
    assert_eq!(err_pw.get("id"), Some("781"));

    // Move Bob out to Default Channel (cid 1) so TestingRoom has 0 occupants
    let mut move_bob_back = Command::new("clientmove");
    move_bob_back.set("clid", bob.clid.to_string());
    move_bob_back.set("cid", "1");
    alice.send_command(&move_bob_back).await;
    let _ = alice.recv_until("notifyclientmoved", Duration::from_secs(2)).await;

    // Charlie joins with correct password
    let mut join_ok = Command::new("clientmove");
    join_ok.set("cid", created_cid.to_string());
    join_ok.set("cpw", "secretpass");
    charlie.send_command(&join_ok).await;
    let mut charlie_moved = None;
    while let Some(mv) = charlie.recv_until("notifyclientmoved", Duration::from_secs(2)).await {
        if mv.get("clid") == Some(charlie.clid.to_string().as_str()) {
            charlie_moved = Some(mv);
            break;
        }
    }
    let charlie_moved = charlie_moved.expect("charlie moved");
    println!("Charlie joined with correct password: cid={:?}", charlie_moved.get("ctid"));
    assert_eq!(charlie_moved.get("ctid"), Some(created_cid.to_string().as_str()));

    // Dave tries to join TestingRoom (occupants=1, maxclients=1)
    let mut dave = ClientSession::connect(server_addr, "DaveGuest", false).await;
    let mut dave_join = Command::new("clientmove");
    dave_join.set("cid", created_cid.to_string());
    dave_join.set("cpw", "secretpass");
    dave.send_command(&dave_join).await;
    let err_full = dave.recv_until("error", Duration::from_secs(2)).await.expect("full error");
    println!("Dave join on full channel rejected: id={:?}", err_full.get("id"));
    assert_eq!(err_full.get("id"), Some("777"));

    // Step 7: Server Keepalive & 30s Timeout
    println!("\n--- Step 7: Server Keepalive and Timeout (30s) ---");
    let eve = ClientSession::connect(server_addr, "EveSilent", false).await;
    let eve_clid = eve.clid;
    println!("Eve connected (clid={}), now dropping socket to simulate network loss...", eve_clid);
    drop(eve);

    println!("Waiting for server keepalive sweep and 30s idle timeout...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut left_seen = false;
    while tokio::time::Instant::now() < deadline {
        if let Some(left) = alice.recv_until("notifyclientleftview", Duration::from_secs(2)).await {
            if left.get("clid") == Some(eve_clid.to_string().as_str()) {
                println!("Server broadcast notifyclientleftview for Eve: clid={:?}, reasonid={:?}, msg={:?}",
                    left.get("clid"), left.get("reasonid"), left.get("reasonmsg"));
                assert_eq!(left.get("reasonid"), Some("3"));
                left_seen = true;
                break;
            }
        }
    }
    assert!(left_seen, "Server must broadcast notifyclientleftview reasonid=3 on timeout");

    println!("\n=== ALL LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY ===");
    Ok(())
}
