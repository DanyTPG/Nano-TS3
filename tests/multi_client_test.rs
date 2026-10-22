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
    let mut returning =
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
    let server = Server::bind("127.0.0.1:0", db).await.expect("bind failed");
    let server_addr = server.local_addr().expect("local addr failed");
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut admin = ClientSession::connect(server_addr, "Creator").await;

    let mut create = Command::new("channelcreate");
    create.set("channel_name", "Lounge");
    create.set("channel_topic", "Chat");
    create.set("channel_flag_permanent", "1");
    admin.send_command(&create).await;

    let mut created_cid = None;
    let mut notify_cid = None;
    let mut notify_invoker = None;
    let mut err_cid = None;
    for _ in 0..10 {
        match admin.recv_command(Duration::from_secs(2)).await {
            Some(cmd) => match cmd.name.as_str() {
                "notifychannelcreated" => {
                    notify_cid = cmd.get("cid").map(|v| v.to_string());
                    notify_invoker = cmd.get("invokerid").map(|v| v.to_string());
                }
                "error" => {
                    assert_eq!(cmd.get("id"), Some("0"));
                    err_cid = cmd.get("cid").map(|v| v.to_string());
                    created_cid = err_cid.clone();
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
