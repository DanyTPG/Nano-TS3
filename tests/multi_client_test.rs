use base64::prelude::*;
use p256::SecretKey;
use rand::RngCore;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tsproto_packets::packets::*;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use nano_ts3::command::Command;
use nano_ts3::crypto::*;
use nano_ts3::database::Database;
use nano_ts3::server::Server;

struct ClientSession {
    sock: UdpSocket,
    shared_iv: [u8; 64],
    pub clid: u16,
    pub uid: String,
    pub ask_for_privilege_key: bool,
    pub server_groups: String,
    c2s_pid: u16,
    frag_buf: Vec<u8>,
}

impl ClientSession {
    async fn connect(server_addr: SocketAddr, nickname: &str) -> Self {
        Self::connect_with_secret(server_addr, nickname, None).await
    }

    /// Connects with a caller-supplied identity key so that reconnects keep the
    /// same server-derived UID.
    async fn connect_with_secret(
        server_addr: SocketAddr,
        nickname: &str,
        secret: Option<&SecretKey>,
    ) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind failed");
        sock.connect(server_addr).await.expect("connect failed");

        // Init0
        let mut r0 = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut r0);
        let init0 = OutC2SInit0::new(0, 0, r0);
        sock.send(&init0.into_vec()).await.unwrap();

        // Init1
        let mut buf = [0u8; 4096];
        let len = timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let in1 = InPacket::try_new(Direction::S2C, &buf[..len]).unwrap();
        let s2c1 = in1.into_s2cinit().unwrap();
        let (r1, r0_rev) = match s2c1.data() {
            S2CInitData::Init1 { random1, random0_r } => (*random1, **random0_r),
            other => panic!("Expected Init1, got {:?}", other),
        };

        // Init2
        let init2 = OutC2SInit2::new(0, &r1, r0_rev);
        sock.send(&init2.into_vec()).await.unwrap();

        // Init3
        let len = timeout(Duration::from_secs(2), sock.recv(&mut buf))
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

        // RSA puzzle
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

        // ECC Key & Init4
        let client_secret = match secret {
            Some(sk) => sk.clone(),
            None => {
                let mut client_key_bytes = [0u8; 32];
                loop {
                    rand::thread_rng().fill_bytes(&mut client_key_bytes);
                    if let Ok(sk) = SecretKey::from_slice(&client_key_bytes) {
                        break sk;
                    }
                }
            }
        };
        let client_der = encode_libtomcrypt_ecc_public(client_secret.public_key().as_affine());
        let mut alpha = [0u8; 10];
        rand::thread_rng().fill_bytes(&mut alpha);

        let init4 = OutC2SInit4::new(0, x, n, level, random2, &y, &alpha, &client_der, "");
        sock.send(&init4.into_vec()).await.unwrap();

        // initivexpand2
        let len = timeout(Duration::from_secs(2), sock.recv(&mut buf))
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

        // clientek
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
        clientek_cmd.set("proof", "dummy_proof");
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

        // ACK for clientek
        let _ = timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        // clientinit (PID 2)
        let mut clientinit_cmd = Command::new("clientinit");
        clientinit_cmd.set("client_nickname", nickname);
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
            uid: String::new(),
            ask_for_privilege_key: false,
            server_groups: String::new(),
            c2s_pid: 3,
            frag_buf: Vec::new(),
        };

        // Drain initial commands until error id=0 msg=ok, capturing the
        // assigned clid and the identity-derived UID.
        while let Some(cmd) = session.recv_command(Duration::from_secs(2)).await {
            if cmd.name == "initserver" {
                if let Some(aclid) = cmd.get("aclid") {
                    session.clid = aclid.parse().unwrap_or(0);
                }
                session.ask_for_privilege_key =
                    cmd.get("virtualserver_ask_for_privilegekey") == Some("1");
            }
            if cmd.name == "notifycliententerview"
                && cmd.get("clid") == Some(session.clid.to_string().as_str())
            {
                if let Some(uid) = cmd.get("client_unique_identifier") {
                    session.uid = uid.to_string();
                }
                if let Some(groups) = cmd.get("client_servergroups") {
                    session.server_groups = groups.to_string();
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

            if in_resp.header().packet_type() == PacketType::Ack {
                continue;
            }

            if in_resp.header().packet_type() == PacketType::Command {
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

                // TS3 fragmentation: the first and last packet of a
                // fragmented command carry FRAGMENTED; packets in between do
                // not. A FRAGMENTED packet while a fragment is already being
                // accumulated therefore terminates the command.
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

#[tokio::test]
async fn test_multi_client_interaction() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Client A (Alice) connects
    let mut alice = ClientSession::connect(server_addr, "Alice").await;
    assert_ne!(alice.clid, 0);

    // 2. Client B (Bob) connects
    let mut bob = ClientSession::connect(server_addr, "Bob").await;
    assert_ne!(bob.clid, 0);
    assert_ne!(alice.clid, bob.clid);

    // 3. Verify Alice sees Bob enter
    let bob_enter = alice
        .recv_until("notifycliententerview", Duration::from_secs(3))
        .await
        .expect("Alice should receive Bob's notifycliententerview");
    assert_eq!(bob_enter.get("clid"), Some(bob.clid.to_string().as_str()));
    assert_eq!(bob_enter.get("client_nickname"), Some("Bob"));

    // 4. Alice sends a text message to channel
    let mut chat = Command::new("sendtextmessage");
    chat.set("targetmode", "2");
    chat.set("msg", "Hello\\sBob!");
    alice.send_command(&chat).await;

    // 5. Bob receives the text message
    let bob_msg = bob
        .recv_until("notifytextmessage", Duration::from_secs(3))
        .await
        .expect("Bob should receive Alice's chat message");
    assert_eq!(bob_msg.get("msg"), Some("Hello\\sBob!"));
    assert_eq!(
        bob_msg.get("invokerid"),
        Some(alice.clid.to_string().as_str())
    );

    // 6. Bob disconnects gracefully
    let mut dc = Command::new("clientdisconnect");
    dc.set("reasonid", "3");
    dc.set("reasonmsg", "Leaving");
    bob.send_command(&dc).await;

    // Bob receives clean error id=0 msg=ok response
    let dc_resp = bob
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("Bob should receive disconnect ack error");
    assert_eq!(dc_resp.get("id"), Some("0"));

    // 7. Alice receives notifyclientleftview for Bob
    let left = alice
        .recv_until("notifyclientleftview", Duration::from_secs(3))
        .await
        .expect("Alice should receive Bob's left view notification");
    assert_eq!(left.get("clid"), Some(bob.clid.to_string().as_str()));
    assert_eq!(left.get("reasonid"), Some("3"));
    assert_eq!(left.get("reasonmsg"), Some("Leaving"));

    server_handle.abort();
}

#[tokio::test]
async fn test_channels_and_permissions_flow() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();

    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "AdminUser").await;
    let mut guest = ClientSession::connect(server_addr, "GuestUser").await;

    // 1. Admin redeems privilege key
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;

    let admin_update = admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("Admin should receive notifyclientupdated");
    assert_eq!(
        admin_update.get("clid"),
        Some(admin.clid.to_string().as_str())
    );
    assert_eq!(admin_update.get("client_servergroups"), Some("6"));

    // Guest also sees Admin's server group update
    let guest_sees_admin = guest
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("Guest should see Admin's group update");
    assert_eq!(
        guest_sees_admin.get("clid"),
        Some(admin.clid.to_string().as_str())
    );
    assert_eq!(guest_sees_admin.get("client_servergroups"), Some("6"));

    // 2. Guest requests permissionlist
    let perm_cmd = Command::new("permissionlist");
    guest.send_command(&perm_cmd).await;

    let perm_list = guest
        .recv_until("notifypermissionlist", Duration::from_secs(3))
        .await
        .expect("Guest should receive notifypermissionlist");
    // Verify permission definitions are present
    assert!(perm_list.raw.contains("b_channel_create_permanent"));

    // 3. Admin creates a new channel
    let mut ch_create = Command::new("channelcreate");
    ch_create.set("channel_name", "Game\\sLobby");
    ch_create.set("channel_topic", "General\\sDiscussion");
    admin.send_command(&ch_create).await;

    // Both Admin and Guest receive notifychannelcreated
    let admin_ch = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("Admin receives channel created");
    assert_eq!(admin_ch.get("channel_name"), Some("Game\\sLobby"));

    let guest_ch = guest
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("Guest receives channel created");
    assert_eq!(guest_ch.get("channel_name"), Some("Game\\sLobby"));
    let new_cid = guest_ch.get("cid").expect("cid").to_string();

    // 4. Admin moves to the new channel
    let mut ch_move = Command::new("clientmove");
    ch_move.set("cid", &new_cid);
    admin.send_command(&ch_move).await;

    let guest_move_notify = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("Guest receives client moved");
    assert_eq!(
        guest_move_notify.get("clid"),
        Some(admin.clid.to_string().as_str())
    );
    assert_eq!(guest_move_notify.get("ctid"), Some(new_cid.as_str()));

    server_handle.abort();
}

/// The server must derive a stable UID from the client's identity key
/// (`clientinitiv omega`), remember the UID after a privilege-key redemption,
/// and recognise the returning identity as Server Admin.
#[tokio::test]
async fn test_uid_derivation_and_admin_survives_reconnect() {
    use sha1::{Digest, Sha1};

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();

    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let secret = p256::SecretKey::from_slice(&[7u8; 32]).expect("valid secret");
    let der = encode_libtomcrypt_ecc_public(secret.public_key().as_affine());
    let expected_uid =
        BASE64_STANDARD.encode(Sha1::digest(BASE64_STANDARD.encode(&der).as_bytes()));

    let mut client = ClientSession::connect_with_secret(server_addr, "Dany", Some(&secret)).await;
    assert_eq!(client.uid, expected_uid, "UID must be sha1(omega base64)");
    assert!(
        client.ask_for_privilege_key,
        "fresh identity should be asked for a key"
    );
    assert_eq!(client.server_groups, "8");

    // Redeem the privilege key.
    let mut use_cmd = Command::new("privilegekeyuse");
    use_cmd.set("token", &admin_token);
    client.send_command(&use_cmd).await;
    let update = client
        .recv_until("notifyclientupdated", Duration::from_secs(3))
        .await
        .expect("notifyclientupdated after redemption");
    assert_eq!(update.get("client_servergroups"), Some("6"));
    // Drain the permission chunk burst plus the final error.
    let mut saw_ok = false;
    for _ in 0..120 {
        match client.recv_command(Duration::from_secs(2)).await {
            Some(cmd) => {
                if cmd.name == "error" && cmd.get("id") == Some("0") {
                    saw_ok = true;
                    break;
                }
            }
            None => break,
        }
    }
    assert!(saw_ok, "privilegekeyuse should finish with error id=0");

    // Graceful disconnect: the leaving client itself must be told it left.
    let mut dc = Command::new("clientdisconnect");
    dc.set("reasonid", "3");
    client.send_command(&dc).await;
    let mut got_own_left = false;
    for _ in 0..10 {
        match client.recv_command(Duration::from_secs(2)).await {
            Some(cmd) => {
                if cmd.name == "notifyclientleftview"
                    && cmd.get("clid") == Some(client.clid.to_string().as_str())
                {
                    assert_eq!(cmd.get("ctid"), Some("0"));
                    got_own_left = true;
                }
                if cmd.name == "error" && got_own_left {
                    break;
                }
            }
            None => break,
        }
    }
    assert!(
        got_own_left,
        "leaving client must receive its own notifyclientleftview"
    );

    // Reconnect with the same identity: no privilege-key prompt, admin group.
    let returning =
        ClientSession::connect_with_secret(server_addr, "Dany", Some(&secret)).await;
    assert_eq!(
        returning.uid, expected_uid,
        "UID must be stable across reconnects"
    );
    assert!(
        !returning.ask_for_privilege_key,
        "known Server Admin must not be asked for a privilege key again"
    );
    assert_eq!(returning.server_groups, "6");

    server_handle.abort();
}

/// channelcreate must return the new channel id in its error response, must
/// announce the invoker, and must reject duplicate names.
#[tokio::test]
async fn test_channelcreate_returns_cid_and_rejects_duplicates() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Creator").await;
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgrade notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await; // tokenuse ack

    let mut create = Command::new("channelcreate");
    create.set("channel_name", "Lounge");
    create.set("channel_topic", "Chat");
    create.set("channel_flag_permanent", "1");
    admin.send_command(&create).await;

    let mut created_cid = None;
    let mut notify_cid = None;
    let mut notify_invoker = None;
    for _ in 0..10 {
        match admin.recv_command(Duration::from_secs(2)).await {
            Some(cmd) => match cmd.name.as_str() {
                "notifychannelcreated" => {
                    notify_cid = cmd.get("cid").map(|v| v.to_string());
                    notify_invoker = cmd.get("invokerid").map(|v| v.to_string());
                }
                "error" => {
                    assert_eq!(cmd.get("id"), Some("0"));
                    created_cid = cmd.get("cid").map(|v| v.to_string());
                    break;
                }
                _ => {}
            },
            None => break,
        }
    }
    let cid = created_cid.expect("error response must include cid");
    assert_eq!(notify_cid.as_deref(), Some(cid.as_str()));
    assert_eq!(notify_invoker, Some(admin.clid.to_string()));

    // Exact duplicate and case-insensitive duplicate must both fail with 1024.
    for name in ["Lounge", "lounge"] {
        let mut dup = Command::new("channelcreate");
        dup.set("channel_name", name);
        admin.send_command(&dup).await;
        let mut error = None;
        for _ in 0..10 {
            match admin.recv_command(Duration::from_secs(2)).await {
                Some(cmd) => {
                    if cmd.name == "error" {
                        error = Some(cmd);
                        break;
                    }
                }
                None => break,
            }
        }
        let error = error.expect("duplicate channelcreate must answer with error");
        assert_eq!(
            error.get("id"),
            Some("1024"),
            "duplicate name must be rejected"
        );
    }

    server_handle.abort();
}

/// Guests must not be able to create channels; the server answers with the
/// official 2568 "insufficient client permissions" and a failed_permid.
#[tokio::test]
async fn test_channelcreate_requires_admin() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut guest = ClientSession::connect(server_addr, "Guest").await;
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "Sneaky");
    create.set("channel_flag_permanent", "1");
    guest.send_command(&create).await;

    let error = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("guest channelcreate must answer with an error");
    assert_eq!(error.get("id"), Some("2568"));
    assert_eq!(error.get("failed_permid"), Some("89"));

    // No channel was created either.
    let list = Command::new("channellist");
    guest.send_command(&list).await;
    let mut saw_sneaky = false;
    for _ in 0..10 {
        match guest.recv_command(Duration::from_secs(2)).await {
            Some(cmd) => {
                if cmd.name == "channellist" && cmd.get("channel_name") == Some("Sneaky") {
                    saw_sneaky = true;
                }
                if cmd.name == "channellistfinished" {
                    break;
                }
            }
            None => break,
        }
    }
    assert!(!saw_sneaky, "guest-created channel must not exist");

    server_handle.abort();
}

#[tokio::test]
async fn test_channel_edit_and_delete() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();

    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut guest = ClientSession::connect(server_addr, "Guest").await;

    // Redeem admin token
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    let _ = admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await;

    // 1. Admin creates channel
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "OriginalName");
    create.set("channel_topic", "OriginalTopic");
    create.set("channel_flag_permanent", "1");
    admin.send_command(&create).await;

    let ch_created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let test_cid = ch_created.get("cid").unwrap().to_string();

    // 2. Guest requests channelgetdescription
    let mut get_desc = Command::new("channelgetdescription");
    get_desc.set("cid", &test_cid);
    guest.send_command(&get_desc).await;

    let desc_cmd = guest
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("should receive notifychanneledited for description");
    assert_eq!(desc_cmd.get("cid"), Some(test_cid.as_str()));
    assert_eq!(desc_cmd.get("reasonid"), Some("9"));
    let desc_err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("desc error response");
    assert_eq!(desc_err.get("id"), Some("0"));

    // 3. Guest tries to edit channel -> rejected with 2563
    let mut guest_edit = Command::new("channeledit");
    guest_edit.set("cid", &test_cid);
    guest_edit.set("channel_name", "HackedName");
    guest.send_command(&guest_edit).await;

    let guest_err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("guest edit error");
    assert_eq!(guest_err.get("id"), Some("2568"));
    assert_eq!(guest_err.get("failed_permid"), Some("112"));

    // 4. Admin edits channel -> success and broadcast with reasonid=10
    let mut admin_edit = Command::new("channeledit");
    admin_edit.set("cid", &test_cid);
    admin_edit.set("channel_name", "EditedName");
    admin_edit.set("channel_topic", "EditedTopic");
    admin.send_command(&admin_edit).await;

    let guest_sees_edit = guest
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("guest receives notifychanneledited");
    assert_eq!(guest_sees_edit.get("cid"), Some(test_cid.as_str()));
    assert_eq!(guest_sees_edit.get("reasonid"), Some("10"));
    assert_eq!(guest_sees_edit.get("channel_name"), Some("EditedName"));
    assert_eq!(guest_sees_edit.get("channel_topic"), Some("EditedTopic"));

    let admin_edit_err = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("admin edit error");
    assert_eq!(admin_edit_err.get("id"), Some("0"));

    // 5. Guest moves into the channel
    let mut mv = Command::new("clientmove");
    mv.set("cid", &test_cid);
    guest.send_command(&mv).await;
    let _ = guest.recv_until("notifyclientmoved", Duration::from_secs(2)).await;
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;
    let _ = admin
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await;

    // 6. Admin attempts to delete occupied channel without force -> returns 770
    let mut del_no_force = Command::new("channeldelete");
    del_no_force.set("cid", &test_cid);
    del_no_force.set("force", "0");
    admin.send_command(&del_no_force).await;

    let del_err = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("delete error");
    assert_eq!(
        del_err.get("id"),
        Some("770"),
        "occupied channel without force must return error 770"
    );

    // 7. Admin deletes occupied channel with force=1 -> moves guest to default channel and deletes
    let mut del_force = Command::new("channeldelete");
    del_force.set("cid", &test_cid);
    del_force.set("force", "1");
    admin.send_command(&del_force).await;

    let guest_moved = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("guest moved to default channel");
    assert_eq!(
        guest_moved.get("clid"),
        Some(guest.clid.to_string().as_str())
    );
    assert_eq!(guest_moved.get("ctid"), Some("1"));

    let guest_ch_del = guest
        .recv_until("notifychanneldeleted", Duration::from_secs(2))
        .await
        .expect("guest receives notifychanneldeleted");
    assert_eq!(guest_ch_del.get("cid"), Some(test_cid.as_str()));

    let admin_del_ok = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("admin delete error");
    assert_eq!(admin_del_ok.get("id"), Some("0"));

    // 8. Admin attempts to delete default channel (cid=1) -> rejected with 771
    let mut del_def = Command::new("channeldelete");
    del_def.set("cid", "1");
    del_def.set("force", "1");
    admin.send_command(&del_def).await;

    let def_err = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("default channel delete error");
    assert_eq!(def_err.get("id"), Some("771"));

    server_handle.abort();
}

#[tokio::test]
async fn test_client_kick_and_ban() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();

    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut guest = ClientSession::connect(server_addr, "Guest").await;

    // Admin privileges
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    let _ = admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await;

    // Create a sub-channel
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "KickChannel");
    create.set("channel_flag_permanent", "1");
    admin.send_command(&create).await;
    let ch_created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let sub_cid = ch_created.get("cid").unwrap().to_string();

    // Guest moves to KickChannel
    let mut mv = Command::new("clientmove");
    mv.set("cid", &sub_cid);
    guest.send_command(&mv).await;
    let _ = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await;
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;
    let _ = admin
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await;

    // 1. Kick Guest from Channel (reasonid=4)
    let mut kick_ch = Command::new("clientkick");
    kick_ch.set("reasonid", "4");
    kick_ch.set("reasonmsg", "Out\\sof\\shere");
    kick_ch.set("clid", guest.clid.to_string());
    admin.send_command(&kick_ch).await;

    let guest_kicked_ch = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("guest receives kick moved");
    assert_eq!(
        guest_kicked_ch.get("clid"),
        Some(guest.clid.to_string().as_str())
    );
    assert_eq!(guest_kicked_ch.get("ctid"), Some("1"));
    assert_eq!(guest_kicked_ch.get("reasonid"), Some("4"));
    assert_eq!(guest_kicked_ch.get("reasonmsg"), Some("Out\\sof\\shere"));

    let admin_kick_ok = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("admin kick error");
    assert_eq!(admin_kick_ok.get("id"), Some("0"));

    // 2. Kick Guest from Server (reasonid=5)
    let mut kick_srv = Command::new("clientkick");
    kick_srv.set("reasonid", "5");
    kick_srv.set("reasonmsg", "Goodbye");
    kick_srv.set("clid", guest.clid.to_string());
    admin.send_command(&kick_srv).await;

    let guest_kicked_srv = guest
        .recv_until("notifyclientleftview", Duration::from_secs(2))
        .await
        .expect("guest receives server kick");
    assert_eq!(
        guest_kicked_srv.get("clid"),
        Some(guest.clid.to_string().as_str())
    );
    assert_eq!(guest_kicked_srv.get("reasonid"), Some("5"));
    assert_eq!(guest_kicked_srv.get("reasonmsg"), Some("Goodbye"));

    let admin_sees_left = admin
        .recv_until("notifyclientleftview", Duration::from_secs(2))
        .await
        .expect("admin sees guest left");
    assert_eq!(
        admin_sees_left.get("clid"),
        Some(guest.clid.to_string().as_str())
    );

    let admin_kick_srv_ok = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("admin server kick error");
    assert_eq!(admin_kick_srv_ok.get("id"), Some("0"));

    // 3. Guest connects again with a stable identity to test banning
    let secret_bob = p256::SecretKey::from_slice(&[42u8; 32]).expect("valid secret");
    let mut bob = ClientSession::connect_with_secret(server_addr, "Bob", Some(&secret_bob)).await;
    assert_ne!(bob.clid, 0);

    // 4. Admin bans Bob with banclient
    let mut ban_cmd = Command::new("banclient");
    ban_cmd.set("clid", bob.clid.to_string());
    ban_cmd.set("time", "3600");
    ban_cmd.set("banreason", "No\\sTrolling");
    admin.send_command(&ban_cmd).await;

    let bob_banned = bob
        .recv_until("notifyclientleftview", Duration::from_secs(2))
        .await
        .expect("bob receives ban leftview");
    assert_eq!(bob_banned.get("clid"), Some(bob.clid.to_string().as_str()));
    assert_eq!(bob_banned.get("reasonid"), Some("6"));
    assert_eq!(bob_banned.get("reasonmsg"), Some("No\\sTrolling"));

    let admin_ban_err = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("admin ban error");
    assert_eq!(admin_ban_err.get("id"), Some("0"));
    let ban_id = admin_ban_err
        .get("banid")
        .expect("banid in error response")
        .to_string();

    // 4b. Verify Bob is rejected on reconnect
    let bob_rejected =
        ClientSession::connect_with_secret(server_addr, "Bob", Some(&secret_bob)).await;
    assert_eq!(
        bob_rejected.clid, 0,
        "banned client must not be assigned a clid"
    );

    // 5. Admin lists bans
    let banlist_cmd = Command::new("banlist");
    admin.send_command(&banlist_cmd).await;
    let list_notify = admin
        .recv_until("notifybanlist", Duration::from_secs(2))
        .await
        .expect("admin receives notifybanlist");
    assert_eq!(list_notify.get("banid"), Some(ban_id.as_str()));
    assert_eq!(list_notify.get("reason"), Some("No\\sTrolling"));

    // 6. Admin deletes the ban
    let mut bandel_cmd = Command::new("bandel");
    bandel_cmd.set("banid", &ban_id);
    admin.send_command(&bandel_cmd).await;
    let del_ok = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("bandel response");
    assert_eq!(del_ok.get("id"), Some("0"));

    // 7. Verify Bob can reconnect successfully now that ban is removed
    let bob_reconnected =
        ClientSession::connect_with_secret(server_addr, "Bob", Some(&secret_bob)).await;
    assert_ne!(
        bob_reconnected.clid, 0,
        "unbanned client can now connect"
    );

    server_handle.abort();
}

/// Every notifytextmessage must carry invokeruid (its absence aborts the
/// official client with "parameter not found"), and targetmode=1 must be
/// routed to the `target` client plus an echo to the sender only.
#[tokio::test]
async fn test_text_message_targeting_and_invokeruid() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut alice = ClientSession::connect(server_addr, "Alice").await;
    let mut bob = ClientSession::connect(server_addr, "Bob").await;

    // Channel message (targetmode 2): both receive it with invokeruid.
    let mut ch_msg = Command::new("sendtextmessage");
    ch_msg.set("targetmode", "2");
    ch_msg.set("msg", "hello\\schannel");
    alice.send_command(&ch_msg).await;

    let alice_seen = alice
        .recv_until("notifytextmessage", Duration::from_secs(2))
        .await
        .expect("sender receives the channel message echo");
    assert_eq!(alice_seen.get("msg"), Some("hello\\schannel"));
    assert_eq!(alice_seen.get("invokerid"), Some(alice.clid.to_string().as_str()));
    assert_eq!(
        alice_seen.get("targetmode"),
        Some("2"),
        "channel messages use targetmode 2"
    );
    let uid = alice_seen
        .get("invokeruid")
        .expect("notifytextmessage must carry invokeruid")
        .to_string();
    assert!(!uid.is_empty(), "invokeruid must not be empty");

    let bob_seen = bob
        .recv_until("notifytextmessage", Duration::from_secs(2))
        .await
        .expect("channel member receives the channel message");
    assert_eq!(bob_seen.get("invokeruid"), Some(uid.as_str()));

    // Private message (targetmode 1): only the target and the sender get it.
    let mut dm = Command::new("sendtextmessage");
    dm.set("targetmode", "1");
    dm.set("target", bob.clid.to_string());
    dm.set("msg", "secret");
    alice.send_command(&dm).await;

    let dm_echo = alice
        .recv_until("notifytextmessage", Duration::from_secs(2))
        .await
        .expect("sender receives the private message echo");
    assert_eq!(dm_echo.get("msg"), Some("secret"));
    assert_eq!(dm_echo.get("targetmode"), Some("1"));
    assert_eq!(dm_echo.get("target"), Some(bob.clid.to_string().as_str()));

    let dm_target = bob
        .recv_until("notifytextmessage", Duration::from_secs(2))
        .await
        .expect("target receives the private message");
    assert_eq!(dm_target.get("msg"), Some("secret"));
    assert_eq!(dm_target.get("invokerid"), Some(alice.clid.to_string().as_str()));
    assert_eq!(dm_target.get("target"), Some(bob.clid.to_string().as_str()));

    let _ = alice.recv_until("error", Duration::from_secs(2)).await; // DM ack

    // Messaging a non-existent client must answer 512, not disconnect.
    let mut dm_bad = Command::new("sendtextmessage");
    dm_bad.set("targetmode", "1");
    dm_bad.set("target", "999");
    dm_bad.set("msg", "nobody");
    alice.send_command(&dm_bad).await;
    let err = alice
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("error response for unknown target");
    assert_eq!(err.get("id"), Some("512"));

    server_handle.abort();
}

/// An admin moving another user must relocate the target, not the admin.
/// ("Move client to channel" / "Move client to own channel" context actions.)
#[tokio::test]
async fn test_admin_moves_other_client() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut guest = ClientSession::connect(server_addr, "Guest").await;

    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgrade notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await; // tokenuse ack

    // Admin creates a channel and moves the GUEST into it while the admin
    // stays in the default channel.
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "Target");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let new_cid = created.get("cid").expect("cid").to_string();

    let mut move_cmd = Command::new("clientmove");
    move_cmd.set("clid", guest.clid.to_string());
    move_cmd.set("cid", &new_cid);
    admin.send_command(&move_cmd).await;

    // The moved guest receives notifyclientmoved with invoker fields.
    let guest_moved = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("moved client is notified");
    assert_eq!(guest_moved.get("clid"), Some(guest.clid.to_string().as_str()));
    assert_eq!(guest_moved.get("ctid"), Some(new_cid.as_str()));
    assert_eq!(
        guest_moved.get("invokerid"),
        Some(admin.clid.to_string().as_str()),
        "admin move carries invoker fields"
    );

    // The admin is NOT the one who moved: it stays in the default channel
    // (no notifyclientmoved about itself).
    let admin_self_moved = admin
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .filter(|cmd| cmd.get("clid") == Some(admin.clid.to_string().as_str()));
    assert!(
        admin_self_moved.is_none(),
        "admin must not be moved by its own clientmove of another user"
    );

    // A guest cannot move other clients.
    let mut guest_move = Command::new("clientmove");
    guest_move.set("clid", admin.clid.to_string());
    guest_move.set("cid", &new_cid);
    guest.send_command(&guest_move).await;
    let denied = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("guest moving another client must be denied");
    assert_eq!(denied.get("id"), Some("2568"));

    server_handle.abort();
}

/// Connection info: any client can read another client's stats, but
/// connection_client_ip is only included for admins.
#[tokio::test]
async fn test_connection_info_admin_only_ip() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut guest = ClientSession::connect(server_addr, "Guest").await;

    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgrade notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await; // tokenuse ack

    // The target publishes stats as the official client does after a
    // notifyconnectioninforequest.
    let mut stats = Command::new("setconnectioninfo");
    stats.set("connection_ping", "12");
    stats.set("connection_packetloss_total", "0.5");
    stats.set("connection_connected_time", "123456");
    guest.send_command(&stats).await;
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;

    // Admin query includes the IP.
    let mut ask = Command::new("getconnectioninfo");
    ask.set("clid", guest.clid.to_string());
    admin.send_command(&ask).await;
    let admin_info = admin
        .recv_until("notifyconnectioninfo", Duration::from_secs(2))
        .await
        .expect("admin receives connection info");
    assert_eq!(admin_info.get("clid"), Some(guest.clid.to_string().as_str()));
    assert_eq!(admin_info.get("connection_ping"), Some("12"));
    assert!(
        admin_info.get("connection_client_ip").is_some(),
        "admins see the target IP"
    );

    // Guest query for another client (Admin) has blank IP/port (required to prevent
    // official client disconnect with parameter not found) but still shows stats.
    let mut ask2 = Command::new("getconnectioninfo");
    ask2.set("clid", admin.clid.to_string());
    guest.send_command(&ask2).await;
    let guest_info = guest
        .recv_until("notifyconnectioninfo", Duration::from_secs(2))
        .await
        .expect("guest receives connection info");
    assert_eq!(
        guest_info.get("connection_client_ip"),
        Some(""),
        "guests must not see other clients' IPs"
    );
    assert_eq!(
        guest_info.get("connection_client_port"),
        Some("0"),
        "guests must not see other clients' ports"
    );

    // Guest querying itself sees its own IP and port (required by TS3 client).
    let mut ask_self = Command::new("getconnectioninfo");
    ask_self.set("clid", guest.clid.to_string());
    guest.send_command(&ask_self).await;
    let self_info = guest
        .recv_until("notifyconnectioninfo", Duration::from_secs(2))
        .await
        .expect("guest receives own connection info");
    assert!(
        self_info.get("connection_client_ip").is_some(),
        "clients can see their own IP"
    );

    server_handle.abort();
}

/// Joining a password-protected channel requires the matching `cpw`;
/// admins may move other clients into it without one.
#[tokio::test]
async fn test_channel_password_gate() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut guest = ClientSession::connect(server_addr, "Guest").await;

    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgrade notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await; // tokenuse ack

    let mut create = Command::new("channelcreate");
    create.set("channel_name", "Locked");
    create.set("channel_flag_password", "1");
    create.set("channel_password", "open sesame");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let cid = created.get("cid").expect("cid").to_string();
    assert_eq!(
        created.get("channel_flag_password"),
        Some("1"),
        "created channel is flagged as password-protected"
    );

    // Wrong password is rejected with the official error.
    let mut wrong = Command::new("clientmove");
    wrong.set("cid", &cid);
    wrong.set("cpw", "guess");
    guest.send_command(&wrong).await;
    let err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("wrong password rejected");
    assert_eq!(err.get("id"), Some("781"));

    // Missing password is rejected too.
    let mut missing = Command::new("clientmove");
    missing.set("cid", &cid);
    guest.send_command(&missing).await;
    let err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("missing password rejected");
    assert_eq!(err.get("id"), Some("781"));

    // The right password works.
    let mut right = Command::new("clientmove");
    right.set("cid", &cid);
    right.set("cpw", "open sesame");
    guest.send_command(&right).await;
    let moved = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("correct password joins the channel");
    assert_eq!(moved.get("ctid"), Some(cid.as_str()));
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;

    // The official TS3 GUI client sends `clid=0` when double-clicking a channel.
    // Moving back to passwordless channel with `clid=0`:
    let mut move_default = Command::new("clientmove");
    move_default.set("cid", "1");
    move_default.set("cpw", "");
    move_default.set("clid", "0");
    guest.send_command(&move_default).await;
    let moved_back = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("move back to default channel with clid=0 succeeds");
    assert_eq!(moved_back.get("ctid"), Some("1"));
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;

    // Official TS3 GUI double-click on password channel sends `cpw` empty with `clid=0`:
    let mut gui_double_click = Command::new("clientmove");
    gui_double_click.set("cid", &cid);
    gui_double_click.set("cpw", "");
    gui_double_click.set("clid", "0");
    guest.send_command(&gui_double_click).await;
    let err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("empty password on locked channel with clid=0 returns 781");
    assert_eq!(err.get("id"), Some("781"));

    // Official TS3 GUI dialog submit sends `cpw=password` with `clid=0`:
    let mut gui_submit_pw = Command::new("clientmove");
    gui_submit_pw.set("cid", &cid);
    gui_submit_pw.set("cpw", "open sesame");
    gui_submit_pw.set("clid", "0");
    guest.send_command(&gui_submit_pw).await;
    let moved_again = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("valid password with clid=0 succeeds");
    assert_eq!(moved_again.get("ctid"), Some(cid.as_str()));

    server_handle.abort();
}

/// A channel with a max-user limit stops admitting clients once full
/// (ERROR_channel_maxclients_reached = 777).
#[tokio::test]
async fn test_channel_max_clients_enforced() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut guest = ClientSession::connect(server_addr, "Guest").await;

    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgrade notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await; // tokenuse ack

    let mut create = Command::new("channelcreate");
    create.set("channel_name", "Tiny");
    create.set("channel_flag_maxclients_unlimited", "0");
    create.set("channel_maxclients", "1");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let cid = created.get("cid").expect("cid").to_string();

    // Admin fills the channel.
    let mut admin_move = Command::new("clientmove");
    admin_move.set("cid", &cid);
    admin.send_command(&admin_move).await;
    admin
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("admin joins");

    // Guest is rejected: the channel is full.
    let mut guest_move = Command::new("clientmove");
    guest_move.set("cid", &cid);
    guest.send_command(&guest_move).await;
    let err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("full channel rejects the join");
    assert_eq!(err.get("id"), Some("777"));

    server_handle.abort();
}

/// A channel edit changing codec, quality and max users at once must be
/// accepted and echoed back (the Audio/Advanced tabs of the Edit Channel
/// dialog).
#[tokio::test]
async fn test_channel_edit_audio_and_limits() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgrade notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await; // tokenuse ack

    let mut create = Command::new("channelcreate");
    create.set("channel_name", "AudioTest");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let cid = created.get("cid").expect("cid").to_string();

    let mut edit = Command::new("channeledit");
    edit.set("cid", &cid);
    edit.set("channel_codec", "5");
    edit.set("channel_codec_quality", "10");
    edit.set("channel_flag_maxclients_unlimited", "0");
    edit.set("channel_maxclients", "4");
    edit.set("channel_codec_is_unencrypted", "1");
    admin.send_command(&edit).await;

    let edited = admin
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("edit is broadcast");
    assert_eq!(edited.get("channel_codec"), Some("5"));
    assert_eq!(edited.get("channel_codec_quality"), Some("10"));
    assert_eq!(edited.get("channel_maxclients"), Some("4"));
    assert_eq!(
        edited.get("channel_codec_is_unencrypted"),
        Some("1"),
        "unencrypted flag is preserved"
    );

    let ok = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("channeledit response");
    assert_eq!(ok.get("id"), Some("0"));

    server_handle.abort();
}

/// Tests channel password changes (setting, removing, and broadcast of notifychannelpasswordchanged)
/// and connection info requests with default clid or non-admin view.
#[tokio::test]
async fn test_channel_password_edit_and_connection_info_default_clid() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    // Verify baseline needed permissions do NOT grant password bypass to clients:
    let needed_wire = nano_ts3::permissions::get_client_needed_permissions_wire();
    assert!(
        !needed_wire.contains("permid=137"),
        "b_channel_join_ignore_password (137) must not be broadcast in needed permissions"
    );
    assert!(
        !needed_wire.contains("permid=138"),
        "b_channel_join_ignore_maxclients (138) must not be broadcast in needed permissions"
    );
    assert!(
        !needed_wire.contains("permid=233"),
        "b_ft_ignore_password (233) must not be broadcast in needed permissions"
    );

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();

    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut guest = ClientSession::connect(server_addr, "Guest").await;

    // Redeem admin token
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    let _ = admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await;

    // 1. Admin creates an initially passwordless channel
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "PwTestChannel");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let cid = created.get("cid").expect("cid").to_string();
    assert_eq!(created.get("channel_flag_password"), Some("0"));

    // 2. Admin edits channel to set a password
    let mut edit_pw = Command::new("channeledit");
    edit_pw.set("cid", &cid);
    edit_pw.set("channel_password", "mysecret");
    admin.send_command(&edit_pw).await;

    // Admin receives notifychanneledited and notifychannelpasswordchanged
    let admin_edited = admin
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("admin receives notifychanneledited");
    assert_eq!(admin_edited.get("channel_flag_password"), Some("1"));
    let admin_pw_changed = admin
        .recv_until("notifychannelpasswordchanged", Duration::from_secs(2))
        .await
        .expect("admin receives notifychannelpasswordchanged");
    assert_eq!(admin_pw_changed.get("cid"), Some(cid.as_str()));

    // Guest also receives notifychanneledited and notifychannelpasswordchanged
    let guest_edited = guest
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("guest receives notifychanneledited");
    assert_eq!(guest_edited.get("channel_flag_password"), Some("1"));
    let guest_pw_changed = guest
        .recv_until("notifychannelpasswordchanged", Duration::from_secs(2))
        .await
        .expect("guest receives notifychannelpasswordchanged");
    assert_eq!(guest_pw_changed.get("cid"), Some(cid.as_str()));

    // 3. Guest tries to join without password -> error 781
    let mut guest_join_no_pw = Command::new("clientmove");
    guest_join_no_pw.set("cid", &cid);
    guest_join_no_pw.set("cpw", "");
    guest_join_no_pw.set("clid", "0");
    guest.send_command(&guest_join_no_pw).await;
    let err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("guest join rejected");
    assert_eq!(err.get("id"), Some("781"));

    // 4. Guest joins with correct password -> succeeds
    let mut guest_join_pw = Command::new("clientmove");
    guest_join_pw.set("cid", &cid);
    guest_join_pw.set("cpw", "mysecret");
    guest_join_pw.set("clid", "0");
    guest.send_command(&guest_join_pw).await;
    let moved = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("guest moved");
    assert_eq!(moved.get("ctid"), Some(cid.as_str()));

    // 5. Admin edits channel to clear the password (empty channel_password, no flag)
    let mut clear_pw = Command::new("channeledit");
    clear_pw.set("cid", &cid);
    clear_pw.set("channel_password", "");
    admin.send_command(&clear_pw).await;

    // Both clients receive notifychanneledited with flag=0 and notifychannelpasswordchanged
    let admin_cleared = admin
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("admin receives clear notifychanneledited");
    assert_eq!(admin_cleared.get("channel_flag_password"), Some("0"));
    let admin_pw_cleared = admin
        .recv_until("notifychannelpasswordchanged", Duration::from_secs(2))
        .await
        .expect("admin receives notifychannelpasswordchanged on clear");
    assert_eq!(admin_pw_cleared.get("cid"), Some(cid.as_str()));

    let guest_cleared = guest
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("guest receives clear notifychanneledited");
    assert_eq!(guest_cleared.get("channel_flag_password"), Some("0"));
    let guest_pw_cleared = guest
        .recv_until("notifychannelpasswordchanged", Duration::from_secs(2))
        .await
        .expect("guest receives notifychannelpasswordchanged on clear");
    assert_eq!(guest_pw_cleared.get("cid"), Some(cid.as_str()));

    // 6. Guest moves back to default channel, then joins PwTestChannel without password
    let mut move_back = Command::new("clientmove");
    move_back.set("cid", "1");
    guest.send_command(&move_back).await;
    let _ = guest.recv_until("notifyclientmoved", Duration::from_secs(2)).await;

    let mut move_again = Command::new("clientmove");
    move_again.set("cid", &cid);
    move_again.set("clid", "0");
    guest.send_command(&move_again).await;
    let moved_again = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("guest moved into cleared channel without password");
    assert_eq!(moved_again.get("ctid"), Some(cid.as_str()));

    // 7. Test getconnectioninfo without clid parameter (defaults to self)
    let info_no_clid = Command::new("getconnectioninfo");
    guest.send_command(&info_no_clid).await;
    let self_info = guest
        .recv_until("notifyconnectioninfo", Duration::from_secs(2))
        .await
        .expect("guest receives connection info for self when clid is omitted");
    assert_eq!(self_info.get("clid"), Some(guest.clid.to_string().as_str()));
    assert!(self_info.get("connection_client_ip").is_some());
    assert!(self_info.get("connection_client_port").is_some());

    server_handle.abort();
}

/// Tests the channel permissions tab:
/// - channelpermlist
/// - channeladdperm
/// - channeldelperm
/// - permoverview
/// - verifying clientmove gate enforced by channel permissions
#[tokio::test]
async fn test_channel_permissions_tab_and_permoverview() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Admin").await;
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgrade notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut guest = ClientSession::connect(server_addr, "Guest").await;
    let _ = guest
        .recv_until("notifycliententerview", Duration::from_secs(2))
        .await;

    // 1. Create SecuredArea channel
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "SecuredArea");
    create.set("channel_flag_permanent", "1");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let cid = created.get("cid").expect("cid").to_string();
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // 2. Query channel permissions list via channelpermlist (initially empty)
    let mut get_perms = Command::new("channelpermlist");
    get_perms.set("cid", &cid);
    admin.send_command(&get_perms).await;
    let empty_perms_err = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("channelpermlist response");
    assert_eq!(empty_perms_err.get("id"), Some("0"));

    // 3. Add channel permission: i_channel_needed_join_power = 75
    let mut add_perm = Command::new("channeladdperm");
    add_perm.set("cid", &cid);
    add_perm.set("permsid", "i_channel_needed_join_power");
    add_perm.set("permvalue", "75");
    admin.send_command(&add_perm).await;
    let add_err = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("channeladdperm ok");
    assert_eq!(add_err.get("id"), Some("0"));

    // 4. Query channelpermlist again, should return the added permission
    let mut get_perms2 = Command::new("channelpermlist");
    get_perms2.set("cid", &cid);
    admin.send_command(&get_perms2).await;
    let permlist_resp = admin
        .recv_until("notifychannelpermlist", Duration::from_secs(2))
        .await
        .expect("channelpermlist entry");
    assert_eq!(permlist_resp.get("cid"), Some(cid.as_str()));
    assert_eq!(permlist_resp.get("permid"), Some("140")); // i_channel_needed_join_power
    assert_eq!(permlist_resp.get("permvalue"), Some("75"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // 5. Guest tries to join SecuredArea -> fails with 2568 (insufficient client permissions)
    let mut guest_join = Command::new("clientmove");
    guest_join.set("cid", &cid);
    guest_join.set("clid", "0");
    guest.send_command(&guest_join).await;
    let join_err = guest
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("guest join error");
    assert_eq!(join_err.get("id"), Some("2568"));
    assert_eq!(join_err.get("failed_permid"), Some("140"));

    // 6. Admin CAN join because admin has join_power = 75 (Server Admin)
    let mut admin_join = Command::new("clientmove");
    admin_join.set("cid", &cid);
    admin_join.set("clid", "0");
    admin.send_command(&admin_join).await;
    let admin_moved = admin
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("admin moved successfully");
    assert_eq!(admin_moved.get("ctid"), Some(cid.as_str()));

    // 7. Delete channel permission via channeldelperm
    let mut del_perm = Command::new("channeldelperm");
    del_perm.set("cid", &cid);
    del_perm.set("permsid", "i_channel_needed_join_power");
    admin.send_command(&del_perm).await;
    let del_err = admin
        .recv_until("error", Duration::from_secs(2))
        .await
        .expect("channeldelperm ok");
    assert_eq!(del_err.get("id"), Some("0"));

    // 8. Now Guest can join SecuredArea
    let mut guest_join_again = Command::new("clientmove");
    guest_join_again.set("cid", &cid);
    guest_join_again.set("clid", "0");
    guest.send_command(&guest_join_again).await;
    let guest_moved = guest
        .recv_until("notifyclientmoved", Duration::from_secs(2))
        .await
        .expect("guest moved successfully after perm deleted");
    assert_eq!(guest_moved.get("ctid"), Some(cid.as_str()));

    // 9. Test permoverview command
    let mut perm_overview = Command::new("permoverview");
    perm_overview.set("cid", &cid);
    perm_overview.set("cldbid", "1");
    perm_overview.set("permsid", "b_channel_modify_make_permanent");
    admin.send_command(&perm_overview).await;
    let overview_reply = admin
        .recv_until("notifypermoverview", Duration::from_secs(2))
        .await
        .expect("permoverview notification");
    assert!(overview_reply.get("t").is_some());
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    server_handle.abort();
}

/// End-to-end test verifying all 4 tabs of the Channel Edit Dialog:
/// - Tab 1 (Standard): Name rename, phonetic name, password set/verify/clear, topic, description, icon ID
/// - Tab 2 (Audio): Codecs (Opus Voice, Opus Music), quality, latency factor, unencrypted voice toggle
/// - Tab 3 (Permissions): Talk power, subscribe power, permission checks, channeladdperm/channeldelperm/channelpermlist
/// - Tab 4 (Advanced): Permanence flags, default channel switch, channel ordering, client limits enforcement (777), family limits, delete delay
#[tokio::test]
async fn test_edit_channel_all_tabs_end_to_end() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Connect Admin and Guest
    let mut admin = ClientSession::connect(server_addr, "AdminUser").await;
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgraded");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut guest = ClientSession::connect(server_addr, "GuestUser").await;
    let _ = guest.recv_until("notifycliententerview", Duration::from_secs(2)).await;

    // 2. Create channel "TabsTestChannel"
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "TabsTestChannel");
    create.set("channel_flag_permanent", "1");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let cid = created.get("cid").expect("cid").to_string();
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // ==========================================
    // TAB 1: STANDARD TAB
    // ==========================================
    // A. channelgetdescription
    let mut get_desc = Command::new("channelgetdescription");
    get_desc.set("cid", &cid);
    admin.send_command(&get_desc).await;
    let init_desc = admin
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("channelgetdescription response");
    assert_eq!(init_desc.get("reasonid"), Some("9"));
    assert_eq!(init_desc.get("channel_description"), Some(""));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // B. Edit Standard tab fields: name, phonetic, password, topic, description, icon_id
    let mut edit_std = Command::new("channeledit");
    edit_std.set("cid", &cid);
    edit_std.set("channel_name", "StandardTabRenamed");
    edit_std.set("channel_name_phonetic", "StdPhonetic");
    edit_std.set("channel_password", "myChannelSecret");
    edit_std.set("channel_topic", "StandardTopicTest");
    edit_std.set("channel_description", "FullChannelDescriptionHere");
    edit_std.set("channel_icon_id", "67890");
    admin.send_command(&edit_std).await;

    let std_edited = admin
        .recv_until("notifychanneledited", Duration::from_secs(2))
        .await
        .expect("standard tab edit broadcast");
    assert_eq!(std_edited.get("reasonid"), Some("10"));
    assert_eq!(std_edited.get("channel_name"), Some("StandardTabRenamed"));
    assert_eq!(std_edited.get("channel_name_phonetic"), Some("StdPhonetic"));
    assert_eq!(std_edited.get("channel_flag_password"), Some("1"));
    assert_eq!(std_edited.get("channel_topic"), Some("StandardTopicTest"));
    assert_eq!(std_edited.get("channel_description"), Some("FullChannelDescriptionHere"));
    assert_eq!(std_edited.get("channel_icon_id"), Some("67890"));
    let _ = admin.recv_until("notifychannelpasswordchanged", Duration::from_secs(2)).await.expect("pw notification");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // C. Verify guest cannot join without password
    let mut move_no_pw = Command::new("clientmove");
    move_no_pw.set("cid", &cid);
    move_no_pw.set("clid", "0");
    guest.send_command(&move_no_pw).await;
    let pw_err = guest.recv_until("error", Duration::from_secs(2)).await.expect("err");
    assert_eq!(pw_err.get("id"), Some("781"), "channel_invalid_password");

    // D. Guest joins with correct password
    let mut move_with_pw = Command::new("clientmove");
    move_with_pw.set("cid", &cid);
    move_with_pw.set("clid", "0");
    move_with_pw.set("cpw", "myChannelSecret");
    guest.send_command(&move_with_pw).await;
    let guest_moved = guest.recv_until("notifyclientmoved", Duration::from_secs(2)).await.expect("moved");
    assert_eq!(guest_moved.get("ctid"), Some(cid.as_str()));
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;

    // E. Clear password via channel_flag_password=0
    let mut clear_pw = Command::new("channeledit");
    clear_pw.set("cid", &cid);
    clear_pw.set("channel_flag_password", "0");
    admin.send_command(&clear_pw).await;
    let cleared_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("cleared");
    assert_eq!(cleared_edited.get("channel_flag_password"), Some("0"));
    let _ = admin.recv_until("notifychannelpasswordchanged", Duration::from_secs(2)).await;
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // Move guest out and back in with no password
    let mut move_out = Command::new("clientmove");
    move_out.set("cid", "1");
    move_out.set("clid", "0");
    guest.send_command(&move_out).await;
    let _ = guest.recv_until("notifyclientmoved", Duration::from_secs(2)).await;
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;

    let mut move_in_free = Command::new("clientmove");
    move_in_free.set("cid", &cid);
    move_in_free.set("clid", "0");
    guest.send_command(&move_in_free).await;
    let free_moved = guest.recv_until("notifyclientmoved", Duration::from_secs(2)).await.expect("free moved");
    assert_eq!(free_moved.get("ctid"), Some(cid.as_str()));
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;

    // ==========================================
    // TAB 2: AUDIO TAB
    // ==========================================
    // Edit codec=4 (Opus Voice), quality=7, latency=2, unencrypted=1
    let mut edit_audio1 = Command::new("channeledit");
    edit_audio1.set("cid", &cid);
    edit_audio1.set("channel_codec", "4");
    edit_audio1.set("channel_codec_quality", "7");
    edit_audio1.set("channel_codec_latency_factor", "2");
    edit_audio1.set("channel_codec_is_unencrypted", "1");
    admin.send_command(&edit_audio1).await;

    let audio1_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("audio edit 1");
    assert_eq!(audio1_edited.get("channel_codec"), Some("4"));
    assert_eq!(audio1_edited.get("channel_codec_quality"), Some("7"));
    assert_eq!(audio1_edited.get("channel_codec_latency_factor"), Some("2"));
    assert_eq!(audio1_edited.get("channel_codec_is_unencrypted"), Some("1"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // Edit codec=5 (Opus Music), quality=10, latency=5, unencrypted=0
    let mut edit_audio2 = Command::new("channeledit");
    edit_audio2.set("cid", &cid);
    edit_audio2.set("channel_codec", "5");
    edit_audio2.set("channel_codec_quality", "10");
    edit_audio2.set("channel_codec_latency_factor", "5");
    edit_audio2.set("channel_codec_is_unencrypted", "0");
    admin.send_command(&edit_audio2).await;

    let audio2_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("audio edit 2");
    assert_eq!(audio2_edited.get("channel_codec"), Some("5"));
    assert_eq!(audio2_edited.get("channel_codec_quality"), Some("10"));
    assert_eq!(audio2_edited.get("channel_codec_latency_factor"), Some("5"));
    assert_eq!(audio2_edited.get("channel_codec_is_unencrypted"), Some("0"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // ==========================================
    // TAB 3: PERMISSIONS TAB
    // ==========================================
    // A. Powers in channeledit: needed_talk_power=30, needed_subscribe_power=15
    let mut edit_powers = Command::new("channeledit");
    edit_powers.set("cid", &cid);
    edit_powers.set("channel_needed_talk_power", "30");
    edit_powers.set("channel_needed_subscribe_power", "15");
    admin.send_command(&edit_powers).await;

    let powers_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("powers edit");
    assert_eq!(powers_edited.get("channel_needed_talk_power"), Some("30"));
    assert_eq!(powers_edited.get("channel_needed_subscribe_power"), Some("15"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // B. Guest attempts unauthorized channeledit -> rejected with 2568
    let mut guest_unauth = Command::new("channeledit");
    guest_unauth.set("cid", &cid);
    guest_unauth.set("channel_topic", "HackedTopic");
    guest.send_command(&guest_unauth).await;
    let unauth_err = guest.recv_until("error", Duration::from_secs(2)).await.expect("unauth error");
    assert_eq!(unauth_err.get("id"), Some("2568"));
    assert_eq!(unauth_err.get("failed_permid"), Some("113")); // b_channel_modify_topic

    // C. Advanced permissions via channeladdperm / channelpermlist / channeldelperm
    let mut add_perm = Command::new("channeladdperm");
    add_perm.set("cid", &cid);
    add_perm.set("permsid", "i_channel_needed_modify_power");
    add_perm.set("permvalue", "70");
    admin.send_command(&add_perm).await;
    let add_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("add ok");
    assert_eq!(add_ok.get("id"), Some("0"));

    let mut get_perms = Command::new("channelpermlist");
    get_perms.set("cid", &cid);
    admin.send_command(&get_perms).await;
    let perms_list = admin.recv_until("notifychannelpermlist", Duration::from_secs(2)).await.expect("permlist");
    assert_eq!(perms_list.get("cid"), Some(cid.as_str()));
    assert_eq!(perms_list.get("permid"), Some("125")); // i_channel_needed_modify_power
    assert_eq!(perms_list.get("permvalue"), Some("70"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut del_perm = Command::new("channeldelperm");
    del_perm.set("cid", &cid);
    del_perm.set("permsid", "i_channel_needed_modify_power");
    admin.send_command(&del_perm).await;
    let del_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("del ok");
    assert_eq!(del_ok.get("id"), Some("0"));

    // ==========================================
    // TAB 4: ADVANCED TAB
    // ==========================================
    // A. Permanence: change to semi-permanent
    let mut edit_perm = Command::new("channeledit");
    edit_perm.set("cid", &cid);
    edit_perm.set("channel_flag_semi_permanent", "1");
    admin.send_command(&edit_perm).await;
    let perm_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("semi-perm");
    assert_eq!(perm_edited.get("channel_flag_semi_permanent"), Some("1"));
    assert_eq!(perm_edited.get("channel_flag_permanent"), Some("0"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // B. Limits: maxclients=1, maxfamilyclients=2, delete_delay=45
    let mut edit_limits = Command::new("channeledit");
    edit_limits.set("cid", &cid);
    edit_limits.set("channel_flag_maxclients_unlimited", "0");
    edit_limits.set("channel_maxclients", "1");
    edit_limits.set("channel_flag_maxfamilyclients_unlimited", "0");
    edit_limits.set("channel_maxfamilyclients", "2");
    edit_limits.set("channel_delete_delay", "45");
    admin.send_command(&edit_limits).await;

    let limits_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("limits edit");
    assert_eq!(limits_edited.get("channel_flag_maxclients_unlimited"), Some("0"));
    assert_eq!(limits_edited.get("channel_maxclients"), Some("1"));
    assert_eq!(limits_edited.get("channel_flag_maxfamilyclients_unlimited"), Some("0"));
    assert_eq!(limits_edited.get("channel_maxfamilyclients"), Some("2"));
    assert_eq!(limits_edited.get("channel_delete_delay"), Some("45"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // Move guest to channel 1, admin joins channel (making it full: 1/1)
    let mut move_guest_1 = Command::new("clientmove");
    move_guest_1.set("cid", "1");
    move_guest_1.set("clid", "0");
    guest.send_command(&move_guest_1).await;
    let _ = guest.recv_until("notifyclientmoved", Duration::from_secs(2)).await;
    let _ = guest.recv_until("error", Duration::from_secs(2)).await;

    let mut admin_join = Command::new("clientmove");
    admin_join.set("cid", &cid);
    admin_join.set("clid", "0");
    admin.send_command(&admin_join).await;
    let _ = admin.recv_until("notifyclientmoved", Duration::from_secs(2)).await;
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // Guest tries to join full channel -> error 777
    let mut guest_join_full = Command::new("clientmove");
    guest_join_full.set("cid", &cid);
    guest_join_full.set("clid", "0");
    guest.send_command(&guest_join_full).await;
    let full_err = guest.recv_until("error", Duration::from_secs(2)).await.expect("full error");
    assert_eq!(full_err.get("id"), Some("777"), "channel maxclients reached");

    // C. Default channel toggle
    let mut create_def = Command::new("channelcreate");
    create_def.set("channel_name", "NewDefaultCandidate");
    create_def.set("channel_flag_permanent", "1");
    admin.send_command(&create_def).await;
    let def_created = admin.recv_until("notifychannelcreated", Duration::from_secs(2)).await.expect("def channel created");
    let def_cid = def_created.get("cid").expect("def cid").to_string();
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut make_default = Command::new("channeledit");
    make_default.set("cid", &def_cid);
    make_default.set("channel_flag_default", "1");
    admin.send_command(&make_default).await;
    let def_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("def edited");
    assert_eq!(def_edited.get("channel_flag_default"), Some("1"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // D. Channel ordering: reposition def_cid after channel 1
    let mut reorder = Command::new("channeledit");
    reorder.set("cid", &def_cid);
    reorder.set("channel_order", "1");
    admin.send_command(&reorder).await;
    let order_edited = admin.recv_until("notifychanneledited", Duration::from_secs(2)).await.expect("order edited");
    assert!(order_edited.get("channel_order").is_some());
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    server_handle.abort();
}

/// Tests that all 5 tiers of the TeamSpeak 3 permission engine support
/// full CRUD operations over the client wire protocol:
/// - Tier 1: Server Groups (servergroupaddperm, servergrouppermlist, servergroupdelperm, servergroupaddclient, servergroupdelclient)
/// - Tier 2: Client Permissions (clientaddperm, clientpermlist, clientdelperm)
/// - Tier 3: Channel Permissions (channeladdperm, channelpermlist, channeldelperm)
/// - Tier 4: Channel Groups (channelgroupaddperm, channelgrouppermlist, channelgroupdelperm, setclientchannelgroup)
/// - Tier 5: Channel-Client Permissions (channelclientaddperm, channelclientpermlist, channelclientdelperm)
#[tokio::test]
async fn test_all_five_tiers_wire_crud() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db = Database::in_memory().expect("failed to open in-memory db");
    let admin_token = db
        .get_or_create_initial_admin_token()
        .expect("token error")
        .unwrap();
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "AdminUser").await;
    let mut token_cmd = Command::new("privilegekeyuse");
    token_cmd.set("token", &admin_token);
    admin.send_command(&token_cmd).await;
    admin
        .recv_until("notifyclientupdated", Duration::from_secs(2))
        .await
        .expect("admin upgraded");
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut guest = ClientSession::connect(server_addr, "GuestUser").await;
    let _ = guest.recv_until("notifycliententerview", Duration::from_secs(2)).await;
    let guest_clid = guest.clid.to_string();

    // Create a channel for channel-scoped tiers
    let mut create = Command::new("channelcreate");
    create.set("channel_name", "TierChannel");
    create.set("channel_flag_permanent", "1");
    admin.send_command(&create).await;
    let created = admin
        .recv_until("notifychannelcreated", Duration::from_secs(2))
        .await
        .expect("channel created");
    let cid = created.get("cid").expect("cid").to_string();
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    // --- Tier 1: Server Groups ---
    let mut sg_add = Command::new("servergroupaddperm");
    sg_add.set("sgid", "7");
    sg_add.set("permsid", "b_channel_modify_name");
    sg_add.set("permvalue", "1");
    admin.send_command(&sg_add).await;
    let sg_add_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("sg add ok");
    assert_eq!(sg_add_ok.get("id"), Some("0"));

    let mut sg_list = Command::new("servergrouppermlist");
    sg_list.set("sgid", "7");
    sg_list.set("permsid", "1");
    admin.send_command(&sg_list).await;
    let sg_resp = admin.recv_until("notifyservergrouppermlist", Duration::from_secs(2)).await.expect("sg list");
    assert_eq!(sg_resp.get("sgid"), Some("7"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut sg_del = Command::new("servergroupdelperm");
    sg_del.set("sgid", "7");
    sg_del.set("permsid", "b_channel_modify_name");
    admin.send_command(&sg_del).await;
    let sg_del_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("sg del ok");
    assert_eq!(sg_del_ok.get("id"), Some("0"));

    // --- Tier 2: Client Specific Permissions ---
    let mut client_add = Command::new("clientaddperm");
    client_add.set("cldbid", &guest_clid);
    client_add.set("permsid", "i_channel_join_power");
    client_add.set("permvalue", "60");
    admin.send_command(&client_add).await;
    let client_add_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("client add ok");
    assert_eq!(client_add_ok.get("id"), Some("0"));

    let mut client_list = Command::new("clientpermlist");
    client_list.set("cldbid", &guest_clid);
    client_list.set("permsid", "1");
    admin.send_command(&client_list).await;
    let client_resp = admin.recv_until("notifyclientpermlist", Duration::from_secs(2)).await.expect("client list");
    assert_eq!(client_resp.get("cldbid"), Some(guest_clid.as_str()));
    assert_eq!(client_resp.get("permsid"), Some("i_channel_join_power"));
    assert_eq!(client_resp.get("permvalue"), Some("60"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut client_del = Command::new("clientdelperm");
    client_del.set("cldbid", &guest_clid);
    client_del.set("permsid", "i_channel_join_power");
    admin.send_command(&client_del).await;
    let client_del_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("client del ok");
    assert_eq!(client_del_ok.get("id"), Some("0"));

    // --- Tier 3: Channel Permissions ---
    let mut ch_add = Command::new("channeladdperm");
    ch_add.set("cid", &cid);
    ch_add.set("permsid", "i_channel_needed_join_power");
    ch_add.set("permvalue", "50");
    admin.send_command(&ch_add).await;
    let ch_add_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("ch add ok");
    assert_eq!(ch_add_ok.get("id"), Some("0"));

    let mut ch_list = Command::new("channelpermlist");
    ch_list.set("cid", &cid);
    admin.send_command(&ch_list).await;
    let ch_resp = admin.recv_until("notifychannelpermlist", Duration::from_secs(2)).await.expect("ch list");
    assert_eq!(ch_resp.get("cid"), Some(cid.as_str()));
    assert_eq!(ch_resp.get("permid"), Some("140"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut ch_del = Command::new("channeldelperm");
    ch_del.set("cid", &cid);
    ch_del.set("permsid", "i_channel_needed_join_power");
    admin.send_command(&ch_del).await;
    let ch_del_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("ch del ok");
    assert_eq!(ch_del_ok.get("id"), Some("0"));

    // --- Tier 4: Channel Groups ---
    let mut cg_add = Command::new("channelgroupaddperm");
    cg_add.set("cgid", "7");
    cg_add.set("permsid", "b_channel_modify_topic");
    cg_add.set("permvalue", "1");
    admin.send_command(&cg_add).await;
    let cg_add_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("cg add ok");
    assert_eq!(cg_add_ok.get("id"), Some("0"));

    let mut cg_list = Command::new("channelgrouppermlist");
    cg_list.set("cgid", "7");
    cg_list.set("permsid", "1");
    admin.send_command(&cg_list).await;
    let cg_resp = admin.recv_until("notifychannelgrouppermlist", Duration::from_secs(2)).await.expect("cg list");
    assert_eq!(cg_resp.get("cgid"), Some("7"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut cg_del = Command::new("channelgroupdelperm");
    cg_del.set("cgid", "7");
    cg_del.set("permsid", "b_channel_modify_topic");
    admin.send_command(&cg_del).await;
    let cg_del_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("cg del ok");
    assert_eq!(cg_del_ok.get("id"), Some("0"));

    let mut set_cg = Command::new("setclientchannelgroup");
    set_cg.set("cgid", "5"); // Channel Admin
    set_cg.set("cid", &cid);
    set_cg.set("cldbid", &guest_clid);
    admin.send_command(&set_cg).await;
    let set_cg_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("set cg ok");
    assert_eq!(set_cg_ok.get("id"), Some("0"));

    // --- Tier 5: Channel-Client Permissions ---
    let mut cc_add = Command::new("channelclientaddperm");
    cc_add.set("cid", &cid);
    cc_add.set("cldbid", &guest_clid);
    cc_add.set("permsid", "i_client_talk_power");
    cc_add.set("permvalue", "85");
    admin.send_command(&cc_add).await;
    let cc_add_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("cc add ok");
    assert_eq!(cc_add_ok.get("id"), Some("0"));

    let mut cc_list = Command::new("channelclientpermlist");
    cc_list.set("cid", &cid);
    cc_list.set("cldbid", &guest_clid);
    cc_list.set("permsid", "1");
    admin.send_command(&cc_list).await;
    let cc_resp = admin.recv_until("notifychannelclientpermlist", Duration::from_secs(2)).await.expect("cc list");
    assert_eq!(cc_resp.get("cid"), Some(cid.as_str()));
    assert_eq!(cc_resp.get("cldbid"), Some(guest_clid.as_str()));
    assert_eq!(cc_resp.get("permsid"), Some("i_client_talk_power"));
    assert_eq!(cc_resp.get("permvalue"), Some("85"));
    let _ = admin.recv_until("error", Duration::from_secs(2)).await;

    let mut cc_del = Command::new("channelclientdelperm");
    cc_del.set("cid", &cid);
    cc_del.set("cldbid", &guest_clid);
    cc_del.set("permsid", "i_client_talk_power");
    admin.send_command(&cc_del).await;
    let cc_del_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("cc del ok");
    assert_eq!(cc_del_ok.get("id"), Some("0"));

    // --- Server Group Client Assignment ---
    let mut sg_add_cl = Command::new("servergroupaddclient");
    sg_add_cl.set("sgid", "6");
    sg_add_cl.set("cldbid", &guest_clid);
    admin.send_command(&sg_add_cl).await;
    let sg_add_cl_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("sg add cl ok");
    assert_eq!(sg_add_cl_ok.get("id"), Some("0"));

    let mut sg_del_cl = Command::new("servergroupdelclient");
    sg_del_cl.set("sgid", "6");
    sg_del_cl.set("cldbid", &guest_clid);
    admin.send_command(&sg_del_cl).await;
    let sg_del_cl_ok = admin.recv_until("error", Duration::from_secs(2)).await.expect("sg del cl ok");
    assert_eq!(sg_del_cl_ok.get("id"), Some("0"));

    server_handle.abort();
}
