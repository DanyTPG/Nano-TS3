use base64::prelude::*;
use rand::Rng;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use sha1::{Digest, Sha1};
use tsproto_packets::packets::*;

use crate::command::Command;
use crate::crypto::*;
use crate::database::{BanRecord, ChannelEdit, ChannelRecord, Database};
use crate::permissions;
use crate::state::{ClientAudioState, HandshakePhase, ServerState};

pub struct Server {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<ServerState>>,
    db: Arc<Mutex<Database>>,
}

/// Builds a `notifycliententerview` command with every parameter the official
/// client's message parser marks as mandatory.
fn build_client_enter_view(
    reasonid: &str,
    clid: u16,
    uid: &str,
    nickname: &str,
    channel_id: u64,
    cfid: u64,
    is_admin: bool,
    audio: ClientAudioState,
) -> Command {
    let mut cmd = Command::new("notifycliententerview");
    cmd.set("reasonid", reasonid);
    cmd.set("reasonmsg", "");
    cmd.set("cfid", cfid.to_string());
    cmd.set("ctid", channel_id.to_string());
    cmd.set("clid", clid.to_string());
    cmd.set("client_database_id", clid.to_string());
    cmd.set("cldbid", clid.to_string());
    cmd.set("client_nickname", nickname);
    cmd.set("name", nickname);
    cmd.set("client_type", "0");
    cmd.set("client_unique_identifier", uid);
    cmd.set("cluid", uid);
    cmd.set("client_flag_avatar", "");
    cmd.set("client_description", "");
    cmd.set("client_icon_id", "0");
    cmd.set("client_input_muted", bool_wire(audio.input_muted));
    cmd.set("client_output_muted", bool_wire(audio.output_muted));
    cmd.set(
        "client_outputonly_muted",
        bool_wire(audio.output_only_muted),
    );
    cmd.set("client_input_hardware", bool_wire(audio.input_hardware));
    cmd.set("client_output_hardware", bool_wire(audio.output_hardware));
    cmd.set("client_meta_data", "");
    cmd.set("client_is_recording", "0");
    // Channel group 5 is Channel Admin, 8 is Guest.
    cmd.set("client_channel_group_id", if is_admin { "5" } else { "8" });
    cmd.set(
        "client_channel_group_inherited_channel_id",
        channel_id.to_string(),
    );
    cmd.set("client_servergroups", if is_admin { "6" } else { "8" });
    cmd.set("client_away", "0");
    cmd.set("client_away_message", "");
    cmd.set("client_talk_power", "0");
    cmd.set("client_talk_request", "0");
    cmd.set("client_talk_request_msg", "");
    cmd.set("client_is_talker", "0");
    cmd.set("client_is_priority_speaker", "0");
    cmd.set("client_unread_messages", "0");
    cmd.set("client_nickname_phonetic", "");
    cmd.set("client_needed_serverquery_view_power", "75");
    cmd.set("client_is_channel_commander", "0");
    cmd.set("client_country", "");
    cmd.set("client_badges", "");
    cmd.set("client_myteamspeak_id", "");
    cmd.set("client_integrations", "");
    cmd
}

fn parse_wire_bool(value: Option<&str>) -> Option<bool> {
    match value {
        Some("1") => Some(true),
        Some("0") => Some(false),
        _ => None,
    }
}

fn bool_wire(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn parse_channel_ids(cmd: &Command) -> Vec<u64> {
    let mut ids = Vec::new();
    for part in cmd.raw.split('|') {
        for token in part.split_whitespace() {
            if let Some(value) = token.strip_prefix("cid=") {
                if let Ok(cid) = value.parse::<u64>() {
                    ids.push(cid);
                }
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn build_channel_subscription_notification(name: &str, channel_ids: &[u64]) -> String {
    let entries = channel_ids
        .iter()
        .map(|cid| format!("cid={cid}"))
        .collect::<Vec<_>>()
        .join("|");
    format!("{name} {entries}")
}

fn parse_channel_number<T>(cmd: &Command, name: &str) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
{
    cmd.get(name)
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|_| format!("invalid value for {name}"))
        })
        .transpose()
}

fn parse_channel_edit(cmd: &Command) -> Result<ChannelEdit, String> {
    let mut edit = ChannelEdit {
        name: cmd.get("channel_name").map(str::to_owned),
        topic: cmd.get("channel_topic").map(str::to_owned),
        description: cmd.get("channel_description").map(str::to_owned),
        name_phonetic: cmd.get("channel_name_phonetic").map(str::to_owned),
        order_after: parse_channel_number(cmd, "channel_order")?,
        codec: parse_channel_number(cmd, "channel_codec")?,
        codec_quality: parse_channel_number(cmd, "channel_codec_quality")?,
        max_clients: parse_channel_number(cmd, "channel_maxclients")?,
        max_family_clients: parse_channel_number(cmd, "channel_maxfamilyclients")?,
        needed_talk_power: parse_channel_number(cmd, "channel_needed_talk_power")?,
        needed_subscribe_power: parse_channel_number(cmd, "channel_needed_subscribe_power")?,
        codec_latency_factor: parse_channel_number(cmd, "channel_codec_latency_factor")?,
        delete_delay: parse_channel_number(cmd, "channel_delete_delay")?,
        icon_id: parse_channel_number(cmd, "channel_icon_id")?,
        is_default: parse_wire_bool(cmd.get("channel_flag_default")),
        is_permanent: parse_wire_bool(cmd.get("channel_flag_permanent")),
        is_semi_permanent: parse_wire_bool(cmd.get("channel_flag_semi_permanent")),
        max_clients_unlimited: parse_wire_bool(cmd.get("channel_flag_maxclients_unlimited")),
        max_family_clients_unlimited: parse_wire_bool(
            cmd.get("channel_flag_maxfamilyclients_unlimited"),
        ),
        max_family_clients_inherited: parse_wire_bool(
            cmd.get("channel_flag_maxfamilyclients_inherited"),
        ),
        ..ChannelEdit::default()
    };

    // The relay supports plaintext Opus payloads only. Keep the channel
    // unencrypted even when the client includes this unchanged property.
    if cmd.get("channel_codec_is_unencrypted") == Some("0") {
        return Err("voice encryption is not supported".to_string());
    }
    if cmd
        .get("channel_password")
        .is_some_and(|password| !password.is_empty())
    {
        return Err("channel passwords are not supported".to_string());
    }
    if cmd.get("cpid").is_some_and(|parent| parent != "0") {
        return Err("subchannels are not supported".to_string());
    }
    if edit.codec.is_some_and(|codec| ![4, 5].contains(&codec)) {
        return Err("unsupported channel codec".to_string());
    }
    if edit
        .codec_quality
        .is_some_and(|quality| !(0..=10).contains(&quality))
    {
        return Err("channel codec quality must be between 0 and 10".to_string());
    }

    // A channel cannot be both permanent and semi-permanent. TeamSpeak sends
    // the selected flag, but tolerate clients that submit both as zero.
    if edit.is_permanent == Some(true) {
        edit.is_semi_permanent = Some(false);
    } else if edit.is_semi_permanent == Some(true) {
        edit.is_permanent = Some(false);
    }

    Ok(edit)
}

fn build_channel_notification(
    name: &str,
    channel: &ChannelRecord,
    invoker_id: u16,
    invoker_name: &str,
    invoker_uid: &str,
) -> Command {
    let mut notify = Command::new(name);
    notify.set("cid", channel.cid.to_string());
    notify.set("cpid", "0");
    notify.set("invokerid", invoker_id.to_string());
    notify.set("invokername", invoker_name);
    notify.set("invokeruid", invoker_uid);
    if name == "notifychanneledited" {
        // `reasonid=10` is the protocol's Channeledit reason. The 3.6.2
        // client requires it before applying an edit notification.
        notify.set("reasonid", "10");
    }
    notify.set("channel_name", &channel.name);
    notify.set("channel_topic", &channel.topic);
    notify.set("channel_description", &channel.description);
    notify.set("channel_codec", channel.codec.to_string());
    notify.set("channel_codec_quality", channel.codec_quality.to_string());
    notify.set("channel_order", channel.order_id.to_string());
    notify.set("channel_flag_permanent", bool_wire(channel.is_permanent));
    notify.set(
        "channel_flag_semi_permanent",
        bool_wire(channel.is_semi_permanent),
    );
    notify.set("channel_flag_default", bool_wire(channel.is_default));
    notify.set("channel_flag_password", "0");
    notify.set("channel_maxclients", channel.max_clients.to_string());
    notify.set(
        "channel_maxfamilyclients",
        channel.max_family_clients.to_string(),
    );
    notify.set(
        "channel_needed_talk_power",
        channel.needed_talk_power.to_string(),
    );
    notify.set(
        "channel_needed_subscribe_power",
        channel.needed_subscribe_power.to_string(),
    );
    notify.set("channel_icon_id", channel.icon_id.to_string());
    notify.set(
        "channel_codec_latency_factor",
        channel.codec_latency_factor.to_string(),
    );
    notify.set("channel_codec_is_unencrypted", "1");
    notify.set("channel_delete_delay", channel.delete_delay.to_string());
    notify.set(
        "channel_flag_maxclients_unlimited",
        bool_wire(channel.max_clients_unlimited),
    );
    notify.set(
        "channel_flag_maxfamilyclients_unlimited",
        bool_wire(channel.max_family_clients_unlimited),
    );
    notify.set(
        "channel_flag_maxfamilyclients_inherited",
        bool_wire(channel.max_family_clients_inherited),
    );
    notify.set("channel_name_phonetic", &channel.name_phonetic);
    notify
}

/// Reassembles the next complete command from the out-of-order packet buffer.
///
/// TS3 marks the first and the last packet of a fragmented command with
/// `Flags::FRAGMENTED`; packets in the middle carry no flags. A packet without
/// the flag while a fragment is being accumulated is a middle fragment, and a
/// flagged packet in that state terminates the command. A single-packet
/// command has no flag at all.
///
/// Returns the wire text and how many packets it consumed, or `None` if the
/// next fragment has not arrived yet.
fn try_assemble_next(
    pending: &mut std::collections::BTreeMap<u16, (Flags, Vec<u8>)>,
    expected: u16,
) -> Option<(String, u16)> {
    let (first_flags, first_bytes) = pending.get(&expected)?.clone();

    if !first_flags.contains(Flags::FRAGMENTED) {
        pending.remove(&expected);
        return Some((String::from_utf8_lossy(&first_bytes).to_string(), 1));
    }

    let mut ids = vec![expected];
    let mut payload = first_bytes;
    let mut curr = expected;

    loop {
        let next = curr.wrapping_add(1);
        match pending.get(&next) {
            Some((flags, bytes)) => {
                ids.push(next);
                payload.extend_from_slice(bytes);
                if flags.contains(Flags::FRAGMENTED) {
                    for id in &ids {
                        pending.remove(id);
                    }
                    return Some((
                        String::from_utf8_lossy(&payload).to_string(),
                        ids.len() as u16,
                    ));
                }
                curr = next;
            }
            None => return None,
        }
    }
}

/// Builds a fully populated `notifyserverupdated` command. The official client
/// rejects the message when any of these parameters is missing.
fn build_server_updated(ask_for_privilegekey: bool, port: u16) -> Command {
    let mut cmd = Command::new("notifyserverupdated");
    cmd.set(
        "virtualserver_welcomemessage",
        "Welcome to Nano-TS3 Server!",
    );
    cmd.set("virtualserver_maxclients", "32");
    // Nano-TS3 relays voice payloads without codec-level encryption. Advertise
    // the server-wide forced-off mode so clients send plaintext Opus frames.
    cmd.set("virtualserver_codec_encryption_mode", "1");
    cmd.set("virtualserver_clientsonline", "1");
    cmd.set("virtualserver_channelsonline", "1");
    cmd.set("virtualserver_uptime", "1000");
    cmd.set("virtualserver_hostmessage", "");
    cmd.set("virtualserver_hostmessage_mode", "0");
    cmd.set("virtualserver_flag_password", "0");
    cmd.set("virtualserver_default_channel_admin_group", "5");
    cmd.set(
        "virtualserver_max_download_total_bandwidth",
        "18446744073709551615",
    );
    cmd.set(
        "virtualserver_max_upload_total_bandwidth",
        "18446744073709551615",
    );
    cmd.set("virtualserver_complain_autoban_count", "5");
    cmd.set("virtualserver_complain_autoban_time", "1200");
    cmd.set("virtualserver_complain_remove_time", "3600");
    cmd.set(
        "virtualserver_min_clients_in_channel_before_forced_silence",
        "100",
    );
    cmd.set("virtualserver_antiflood_points_tick_reduce", "5");
    cmd.set("virtualserver_antiflood_points_needed_command_block", "150");
    cmd.set("virtualserver_antiflood_points_needed_ip_block", "250");
    cmd.set("virtualserver_client_connections", "0");
    cmd.set("virtualserver_query_client_connections", "0");
    cmd.set("virtualserver_queryclientsonline", "0");
    cmd.set("virtualserver_download_quota", "18446744073709551615");
    cmd.set("virtualserver_upload_quota", "18446744073709551615");
    cmd.set("virtualserver_month_bytes_downloaded", "0");
    cmd.set("virtualserver_month_bytes_uploaded", "0");
    cmd.set("virtualserver_total_bytes_downloaded", "0");
    cmd.set("virtualserver_total_bytes_uploaded", "0");
    cmd.set("virtualserver_port", port.to_string());
    cmd.set("virtualserver_autostart", "1");
    cmd.set("virtualserver_machine_id", "");
    cmd.set("virtualserver_needed_identity_security_level", "8");
    cmd.set("virtualserver_log_client", "1");
    cmd.set("virtualserver_log_query", "1");
    cmd.set("virtualserver_log_channel", "1");
    cmd.set("virtualserver_log_permissions", "1");
    cmd.set("virtualserver_log_server", "1");
    cmd.set("virtualserver_log_filetransfer", "1");
    cmd.set("virtualserver_min_client_version", "1560850141");
    cmd.set("virtualserver_reserved_slots", "0");
    cmd.set("virtualserver_total_packetloss_speech", "0");
    cmd.set("virtualserver_total_packetloss_keepalive", "0");
    cmd.set("virtualserver_total_packetloss_control", "0");
    cmd.set("virtualserver_total_packetloss_total", "0");
    cmd.set("virtualserver_total_ping", "0");
    cmd.set("virtualserver_weblist_enabled", "1");
    cmd.set("virtualserver_min_android_version", "1560850141");
    cmd.set("virtualserver_min_ios_version", "1560850141");
    cmd.set("virtualserver_antiflood_points_needed_plugin_block", "0");
    cmd.set(
        "virtualserver_ask_for_privilegekey",
        if ask_for_privilegekey { "1" } else { "0" },
    );
    cmd
}

impl Server {
    pub async fn bind(addr: &str, db: Database) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(addr).await?;
        info!("Nano-TS3 UDP server listening on {}", socket.local_addr()?);
        Ok(Self {
            socket: Arc::new(socket),
            state: Arc::new(Mutex::new(ServerState::new())),
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = [0u8; 4096];

        loop {
            let (len, peer) = match self.socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    if e.raw_os_error() != Some(10054) {
                        error!("UDP receive error: {:?}", e);
                    }
                    continue;
                }
            };

            let data = &buf[..len];
            if let Err(e) = self.handle_packet(peer, data).await {
                debug!("Handled packet from {} with info: {:?}", peer, e);
            }
        }
    }

    async fn handle_packet(&self, peer: SocketAddr, data: &[u8]) -> Result<(), String> {
        let in_pkt = match InPacket::try_new(Direction::C2S, data) {
            Ok(pkt) => pkt,
            Err(e) => return Err(format!("Invalid packet from {}: {:?}", peer, e)),
        };

        let p_type = in_pkt.header().packet_type();
        let p_id = in_pkt.header().packet_id();

        {
            let mut state = self.state.lock().await;
            state.cleanup_stale();
            if let Some(c) = state.get_client_mut(&peer) {
                c.last_activity = std::time::Instant::now();
            }
        }

        match p_type {
            PacketType::Init => {
                self.handle_init(peer, in_pkt).await?;
            }
            PacketType::Command | PacketType::CommandLow => {
                self.handle_command(peer, in_pkt, data).await?;
            }
            PacketType::Ping => {
                let shared_mac = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .and_then(|c| c.shared_iv)
                        .map(|siv| {
                            let sm: [u8; 8] = Sha1::digest(&siv)[..8].try_into().unwrap();
                            sm
                        })
                };
                if let Some(sm) = shared_mac {
                    let mut ack = OutAck::new(Direction::S2C, PacketType::Ping, p_id);
                    ack.flags(Flags::UNENCRYPTED);
                    ack.mac().copy_from_slice(&sm);
                    let _ = self.socket.send_to(&ack.into_vec(), peer).await;
                }
            }
            PacketType::Voice => {
                self.handle_voice(peer, data).await?;
            }
            PacketType::VoiceWhisper => {
                // In-channel voice is relayed by handle_voice. Whisper packets
                // carry their own target list and need a separate fan-out path.
                debug!("Ignoring unsupported voice-whisper packet from {}", peer);
            }
            PacketType::Ack | PacketType::AckLow | PacketType::Pong => {
                // Client acknowledged our command or ping
            }
        }

        Ok(())
    }

    async fn handle_init(&self, peer: SocketAddr, in_pkt: InPacket<'_>) -> Result<(), String> {
        let c2s_init = in_pkt.into_c2sinit().map_err(|e| format!("{:?}", e))?;
        let mut state = self.state.lock().await;

        match c2s_init.data() {
            C2SInitData::Init0 { random0, .. } => {
                info!("Handshake Init0 from {}", peer);
                let client = state.reset_or_create_client(peer);
                let r0_rev = [random0[3], random0[2], random0[1], random0[0]];
                let mut r1 = [0u8; 16];
                rand::thread_rng().fill(&mut r1[..]);

                client.r0_reversed = r0_rev;
                client.r1 = r1;
                client.handshake_phase = HandshakePhase::Init0Received;

                let resp = OutS2CInit1::new(&r1, r0_rev);
                let _ = self.socket.send_to(&resp.into_vec(), peer).await;
            }
            C2SInitData::Init2 { .. } => {
                info!("Handshake Init2 from {}", peer);
                let client = state.get_or_create_client(peer);
                let puzzle = RsaPuzzle::new();
                let resp = OutS2CInit3::new(&puzzle.x, &puzzle.n, puzzle.level, &puzzle.random2);
                client.puzzle = Some(puzzle);
                client.handshake_phase = HandshakePhase::Init2Received;

                let _ = self.socket.send_to(&resp.into_vec(), peer).await;
            }
            C2SInitData::Init4 { y, command, .. } => {
                info!("Handshake Init4 from {}", peer);
                let client = state.get_or_create_client(peer);
                if let Some(ref puzzle) = client.puzzle {
                    if !puzzle.verify(y) {
                        warn!("Puzzle solution verification failed from {}", peer);
                        return Err("Invalid puzzle verification".into());
                    }
                    info!("Puzzle solution verified successfully from {}", peer);
                }

                // Command contains "clientinitiv alpha=... omega=..."
                let cmd_str = std::str::from_utf8(command).map_err(|e| e.to_string())?;
                info!("Init4 command string: {}", cmd_str);
                let cmd = Command::parse(cmd_str)
                    .ok_or_else(|| "Failed to parse clientinitiv".to_string())?;

                let alpha_b64 = cmd
                    .get("alpha")
                    .ok_or_else(|| "Missing alpha in clientinitiv".to_string())?;
                let omega_b64 = cmd
                    .get("omega")
                    .ok_or_else(|| "Missing omega in clientinitiv".to_string())?;

                let alpha = BASE64_STANDARD
                    .decode(alpha_b64)
                    .map_err(|e| e.to_string())?;

                // A TS3 client never sends `client_unique_identifier` itself:
                // the server derives it from the identity public key in
                // `clientinitiv omega`. Verified against a real 3.6.2 client
                // and the official server's database: the UID is
                // base64(sha1(<omega base64 text>)).
                client.uid = BASE64_STANDARD.encode(Sha1::digest(omega_b64.as_bytes()));

                let mut beta = [0u8; 54];
                rand::thread_rng().fill(&mut beta[..]);

                client.alpha = alpha.clone();
                client.beta = beta.to_vec();
                client.shared_iv = None; // Modern SharedIV will be computed from clientek!
                client.handshake_phase = HandshakePhase::Init4Received;

                // Build initivexpand2 response
                let pk = client.server_secret.public_key();
                let server_der = encode_libtomcrypt_ecc_public(pk.as_affine());
                let server_omega = BASE64_STANDARD.encode(&server_der);
                let server_beta = BASE64_STANDARD.encode(&beta);

                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let proof = sign_license_proof();
                let mut expand_cmd = Command::new("initivexpand2");
                expand_cmd.set("l", ANONYMOUS_LICENSE);
                expand_cmd.set("beta", &server_beta);
                expand_cmd.set("omega", &server_omega);
                expand_cmd.set("ot", "1");
                expand_cmd.set("proof", &proof);
                expand_cmd.set("tvd", "");
                expand_cmd.set("time", &now_unix.to_string());

                let wire_str = expand_cmd.build();
                let mut payload = wire_str.into_bytes();
                let p_id = 0u16; // initivexpand2 MUST always have packet ID 0
                client.next_s2c_packet_id = 1;

                // Build S2C Command Packet encrypted with bootstrap key and nonce
                let mut aad = Vec::with_capacity(3);
                aad.extend_from_slice(&p_id.to_be_bytes());
                aad.push(PacketType::Command as u8);

                let mac = encrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, &aad, &mut payload)?;

                let mut pkt =
                    OutPacket::new_with_dir(Direction::S2C, Flags::empty(), PacketType::Command);
                pkt.packet_id(p_id);
                pkt.mac().copy_from_slice(&mac);
                pkt.data_mut().extend_from_slice(&payload);

                let _ = self.socket.send_to(&pkt.into_vec(), peer).await;
                info!(
                    "Sent encrypted initivexpand2 to {}, waiting for clientek!",
                    peer
                );
            }
        }

        Ok(())
    }

    async fn handle_command(
        &self,
        peer: SocketAddr,
        in_pkt: InPacket<'_>,
        raw: &[u8],
    ) -> Result<(), String> {
        let p_id = in_pkt.header().packet_id();
        let p_type = in_pkt.header().packet_type();

        let (has_siv, clid, alpha, beta) = {
            let mut state = self.state.lock().await;
            let client = match state.get_client_mut(&peer) {
                Some(c) => c,
                None => return Err("Client session not found".into()),
            };
            client.last_c2s_packet_id = p_id;
            (
                client.shared_iv.is_some(),
                client.clid,
                client.alpha.clone(),
                client.beta.clone(),
            )
        };

        if !has_siv {
            // First command from client MUST be `clientek` encrypted with BOOTSTRAP_KEY and BOOTSTRAP_NONCE!
            if raw.len() < 13 {
                return Err("clientek packet too short".into());
            }

            let mac: [u8; 8] = raw[..8].try_into().map_err(|_| "Invalid MAC")?;
            let aad = &raw[8..13]; // [PId (2)][CId (2)][PT (1)]
            let mut ciphertext = raw[13..].to_vec();

            decrypt_eax(BOOTSTRAP_KEY, BOOTSTRAP_NONCE, aad, &mac, &mut ciphertext)?;
            let cmd_text = std::str::from_utf8(&ciphertext).map_err(|e| e.to_string())?;
            info!("Received pre-shared_iv command: {}", cmd_text);

            let cmd =
                Command::parse(cmd_text).ok_or_else(|| "Failed to parse clientek".to_string())?;
            if cmd.name == "clientinitiv" {
                // TS3 3.x clients send clientinitiv twice: once as a
                // bootstrap-encrypted command right after Init0 and once
                // embedded in Init4. Only the Init4 copy is authoritative, but
                // the early one still needs an ACK so it is not retransmitted.
                let mut ack = OutAck::new(Direction::S2C, p_type, p_id);
                ack.flags(Flags::UNENCRYPTED);
                let _ = self.socket.send_to(&ack.into_vec(), peer).await;
                return Ok(());
            }
            if cmd.name == "clientek" {
                let ek_b64 = cmd
                    .get("ek")
                    .ok_or_else(|| "Missing ek in clientek".to_string())?;
                let ek_bytes = BASE64_STANDARD.decode(ek_b64).map_err(|e| e.to_string())?;
                let ek_fixed: [u8; 32] = ek_bytes.try_into().map_err(|_| "Invalid ek length")?;

                let shared_iv =
                    compute_shared_iv_modern(&ek_fixed, &SERVER_LICENSE_KEY_K, &alpha, &beta)?;
                let shared_mac = Sha1::digest(&shared_iv);

                {
                    let mut state = self.state.lock().await;
                    if let Some(c) = state.get_client_mut(&peer) {
                        c.shared_iv = Some(shared_iv);
                        c.handshake_phase = HandshakePhase::Connected;
                        c.expected_c2s_packet_id = 2; // Next command is clientinit (pid 2)
                    }
                }

                // Send ACK for clientek (packet ID 1) with shared_mac and UNENCRYPTED flag
                let mut ack = OutAck::new(Direction::S2C, p_type, p_id);
                ack.flags(Flags::UNENCRYPTED);
                ack.mac().copy_from_slice(&shared_mac[..8]);
                let _ = self.socket.send_to(&ack.into_vec(), peer).await;
                info!(
                    "Handshake completed! clientek processed, SharedIV established for client {}",
                    clid
                );
                return Ok(());
            } else {
                return Err(format!("Expected clientek, got {}", cmd.name));
            }
        }

        // We have SharedIV!
        let (shared_iv, shared_mac) = {
            let state = self.state.lock().await;
            let client = match state.get_client(&peer) {
                Some(c) => c,
                None => return Err("Client session not found".into()),
            };
            let siv = client
                .shared_iv
                .ok_or_else(|| "No shared IV established".to_string())?;
            let smac: [u8; 8] = Sha1::digest(&siv)[..8].try_into().unwrap();
            (siv, smac)
        };

        // Send ACK back
        let mut ack = OutAck::new(Direction::S2C, p_type, p_id);
        ack.flags(Flags::UNENCRYPTED);
        ack.mac().copy_from_slice(&shared_mac);
        let _ = self.socket.send_to(&ack.into_vec(), peer).await;

        let flags = in_pkt.header().flags();
        let decrypted_bytes = if flags.contains(Flags::UNENCRYPTED) {
            in_pkt.content().to_vec()
        } else {
            // Decrypt command packet
            // C2S header has 13 bytes: [MAC (8 bytes)][PId (2)][CId (2)][PT (1)]
            if raw.len() < 13 {
                return Err("Command packet too short".into());
            }

            let mac: [u8; 8] = raw[..8].try_into().map_err(|_| "Invalid MAC")?;
            let aad = &raw[8..13]; // Associated text: PId, CId, PT
            let mut ciphertext = raw[13..].to_vec();

            let (key, nonce) = derive_key_nonce(Direction::C2S, p_type as u8, 0, p_id, &shared_iv);
            decrypt_eax(&key, &nonce, aad, &mac, &mut ciphertext)?;
            ciphertext
        };

        let mut commands_to_dispatch: Vec<Command> = Vec::new();
        {
            let mut state = self.state.lock().await;
            let client = match state.get_client_mut(&peer) {
                Some(c) => c,
                None => return Err("Client session not found".into()),
            };

            // Detect duplicate retransmissions (older than expected_c2s_packet_id)
            let diff = p_id.wrapping_sub(client.expected_c2s_packet_id);
            if diff > 32768 {
                debug!(
                    "Ignoring retransmitted packet {} for clid {} (expected {})",
                    p_id, clid, client.expected_c2s_packet_id
                );
                return Ok(());
            }

            client
                .pending_packets
                .insert(p_id, (flags, decrypted_bytes));

            while let Some((cmd_text, consumed)) =
                try_assemble_next(&mut client.pending_packets, client.expected_c2s_packet_id)
            {
                client.expected_c2s_packet_id =
                    client.expected_c2s_packet_id.wrapping_add(consumed);
                if consumed == 1 {
                    info!(
                        "Received complete single-packet command from clid {}: {}",
                        clid, cmd_text
                    );
                } else {
                    info!(
                        "Received complete fragmented command from client {}: {}",
                        clid, cmd_text
                    );
                }
                if let Some(cmd) = Command::parse(&cmd_text) {
                    commands_to_dispatch.push(cmd);
                }
            }
        }

        for cmd in commands_to_dispatch {
            self.dispatch_command(peer, clid, cmd).await?;
        }

        Ok(())
    }

    async fn dispatch_command(
        &self,
        peer: SocketAddr,
        clid: u16,
        cmd: Command,
    ) -> Result<(), String> {
        info!("Dispatching command '{}' for clid {}", cmd.name, clid);
        match cmd.name.as_str() {
            "clientinit" => {
                let base_nickname = cmd.get("client_nickname").unwrap_or("User");
                let audio = ClientAudioState {
                    input_muted: parse_wire_bool(cmd.get("client_input_muted")).unwrap_or(false),
                    output_muted: parse_wire_bool(cmd.get("client_output_muted")).unwrap_or(false),
                    output_only_muted: parse_wire_bool(cmd.get("client_outputonly_muted"))
                        .unwrap_or(false),
                    input_hardware: parse_wire_bool(cmd.get("client_input_hardware"))
                        .unwrap_or(true),
                    output_hardware: parse_wire_bool(cmd.get("client_output_hardware"))
                        .unwrap_or(true),
                };
                let client_uid = cmd
                    .get("client_unique_identifier")
                    .or_else(|| cmd.get("cluid"))
                    .unwrap_or("");
                let uid = if !client_uid.is_empty() {
                    client_uid.to_string()
                } else {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| c.uid.clone())
                        .filter(|u| !u.is_empty())
                        .unwrap_or_else(|| format!("nano_uid_{}", clid))
                };

                // Deduplicate nicknames: the official client rejects a second
                // client whose nickname collides with one already in its tree.
                let nickname = {
                    let mut state = self.state.lock().await;
                    let mut chosen_nick = base_nickname.to_string();
                    let mut counter = 1;
                    while state.clients.values().any(|c| {
                        c.clid != clid
                            && c.handshake_phase == HandshakePhase::Connected
                            && c.nickname == chosen_nick
                    }) {
                        chosen_nick = format!("{}{}", base_nickname, counter);
                        counter += 1;
                    }
                    if let Some(c) = state.get_client_mut(&peer) {
                        c.nickname = chosen_nick.clone();
                        c.uid = uid.clone();
                        c.current_channel_id = 1;
                        c.audio = audio;
                    }
                    chosen_nick
                };

                // A UID that redeemed a privilege key before reconnects as admin.
                let is_admin = {
                    let db = self.db.lock().await;
                    db.is_admin_identity(&uid).unwrap_or(false)
                };
                {
                    let mut state = self.state.lock().await;
                    if let Some(c) = state.get_client_mut(&peer) {
                        c.is_admin = is_admin;
                    }
                }

                let client_ip = peer.ip().to_string();
                let ban_reason = {
                    let db = self.db.lock().await;
                    db.is_banned(&client_ip, &uid, base_nickname).unwrap_or(None)
                };
                if let Some(reason) = ban_reason {
                    info!(
                        "Banned client connection rejected: {} (uid: {}, ip: {}, reason: {})",
                        clid, uid, client_ip, reason
                    );
                    let mut err_resp = Command::new("error");
                    err_resp.set("id", "3329");
                    err_resp.set("msg", "connection failed, you are banned");
                    if !reason.is_empty() {
                        err_resp.set("extra_msg", &reason);
                    }
                    if let Some(rc) = cmd.get("return_code") {
                        err_resp.set("return_code", rc);
                    }
                    self.send_encrypted_command(peer, &err_resp).await?;
                    return Ok(());
                }

                // 1. initserver
                let mut initserver = Command::new("initserver");
                {
                    let db = self.db.lock().await;
                    let name = db
                        .get_property("virtualserver_name")
                        .unwrap_or(None)
                        .unwrap_or_else(|| "Nano-TS3 Minimal Server".into());
                    let welcome = db
                        .get_property("virtualserver_welcomemessage")
                        .unwrap_or(None)
                        .unwrap_or_else(|| "Welcome to Nano-TS3 Server!".into());
                    initserver.set("virtualserver_name", name);
                    initserver.set("virtualserver_welcomemessage", welcome);
                }
                initserver.set("virtualserver_platform", "Windows");
                initserver.set("virtualserver_version", "3.13.7 [Build: 1600000000]");
                initserver.set("virtualserver_maxclients", "32");
                initserver.set("virtualserver_created", "1600000000");
                // Voice relay currently forwards codec frames verbatim, so the
                // server must disable codec-level voice encryption.
                initserver.set("virtualserver_codec_encryption_mode", "1");
                initserver.set("virtualserver_hostmessage", "");
                initserver.set("virtualserver_hostmessage_mode", "0");
                initserver.set("virtualserver_default_server_group", "8");
                initserver.set("virtualserver_default_channel_group", "8");
                initserver.set("virtualserver_default_channel_admin_group", "5");
                initserver.set("virtualserver_id", "1");
                let ask_privilege = {
                    let db = self.db.lock().await;
                    !is_admin && db.has_unused_privilege_key().unwrap_or(false)
                };
                initserver.set("virtualserver_status", "online");
                initserver.set("virtualserver_ip", "127.0.0.1");
                initserver.set("virtualserver_nickname", "");
                initserver.set("virtualserver_capability_extensions", "");
                initserver.set("virtualserver_administrative_domain", "");
                initserver.set(
                    "virtualserver_ask_for_privilegekey",
                    if ask_privilege { "1" } else { "0" },
                );
                initserver.set("virtualserver_hostbanner_url", "");
                initserver.set("virtualserver_hostbanner_gfx_url", "");
                initserver.set("virtualserver_hostbanner_gfx_interval", "0");
                initserver.set(
                    "virtualserver_priority_speaker_dimm_modificator",
                    "-18.0000",
                );
                initserver.set("virtualserver_hostbutton_tooltip", "");
                initserver.set("virtualserver_hostbutton_url", "");
                initserver.set("virtualserver_hostbutton_gfx_url", "");
                initserver.set("virtualserver_name_phonetic", "");
                initserver.set("virtualserver_icon_id", "0");
                initserver.set("virtualserver_hostbanner_mode", "0");
                initserver.set("virtualserver_channel_temp_delete_delay_default", "0");
                initserver.set("virtualserver_unique_identifier", "nano_ts3_vserver_1");
                initserver.set("virtualserver_channelsonline", "1");
                initserver.set("virtualserver_clientsonline", "1");
                initserver.set("virtualserver_queryclientsonline", "0");
                initserver.set("virtualserver_query_client_connections", "0");
                initserver.set("virtualserver_client_connections", "0");
                initserver.set("virtualserver_uptime", "1000");
                initserver.set("virtualserver_antiflood_points_tick_reduce", "5");
                initserver.set("virtualserver_antiflood_points_needed_command_block", "150");
                initserver.set("virtualserver_antiflood_points_needed_ip_block", "250");
                initserver.set("virtualserver_antiflood_points_needed_plugin_block", "0");
                initserver.set("virtualserver_log_client", "1");
                initserver.set("virtualserver_log_query", "1");
                initserver.set("virtualserver_log_channel", "1");
                initserver.set("virtualserver_log_permissions", "1");
                initserver.set("virtualserver_log_server", "1");
                initserver.set("virtualserver_log_filetransfer", "1");
                initserver.set("virtualserver_min_client_version", "1560850141");
                initserver.set("acn", &nickname);
                initserver.set("aclid", clid.to_string());
                initserver.set("pv", "4");
                initserver.set("client_nickname", &nickname);
                initserver.set("client_version", "3.6.2 [Build: 1695203293]");
                initserver.set("client_platform", "Windows");
                initserver.set("client_input_muted", bool_wire(audio.input_muted));
                initserver.set("client_output_muted", bool_wire(audio.output_muted));
                initserver.set(
                    "client_outputonly_muted",
                    bool_wire(audio.output_only_muted),
                );
                initserver.set("client_input_hardware", bool_wire(audio.input_hardware));
                initserver.set("client_output_hardware", bool_wire(audio.output_hardware));
                initserver.set("client_default_channel", "");
                initserver.set("client_default_channel_password", "");
                initserver.set("client_server_password", "");
                initserver.set("client_meta_data", "");
                initserver.set("client_version_sign", "");
                initserver.set("client_security_hash", "");
                initserver.set("client_key_offset", "25207246");
                initserver.set("client_away", "0");
                initserver.set("client_away_message", "");
                initserver.set("client_nickname_phonetic", "");
                initserver.set("client_default_token", "");
                initserver.set("client_badges", "");
                initserver.set("client_integrations", "");
                initserver.set("client_talk_power", "0");
                initserver.set("client_myteamspeak_id", "");
                initserver.set("client_needed_serverquery_view_power", "75");
                self.send_encrypted_command(peer, &initserver).await?;

                // 2. Channel list entries. The own enter view has to follow
                // them (the client needs the default channel to exist) but has
                // to precede channellistfinished: the client's handler for
                // channellistfinished looks up its own client object and
                // aborts with `Assertion "client" failed` if it is missing.
                self.send_channel_entries(peer).await?;

                // reasonid=2 identifies this as the client's own entry; the client
                // treats 0 as "another client" and asserts in serverview.cpp.
                let own_view =
                    build_client_enter_view("2", clid, &uid, &nickname, 1, 0, is_admin, audio);
                self.send_encrypted_command(peer, &own_view).await?;

                self.send_channellist_finished(peer).await?;

                // Group names and membership are resolved only after the
                // client finished the channel list; sending them earlier (as
                // the previous order did) leaves %CLIENT_SERVER_GROUP_NAME%
                // placeholders in the UI.
                self.send_server_group_list(peer, true).await?;
                self.send_client_group_membership(peer, clid, is_admin)
                    .await?;

                // 3. Tell the newcomer about everybody who is already online.
                let existing_clients: Vec<(u16, String, String, u64, bool, ClientAudioState)> = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .filter(|c| {
                            c.clid != clid
                                && c.handshake_phase == HandshakePhase::Connected
                                && c.last_activity.elapsed() < std::time::Duration::from_secs(45)
                        })
                        .map(|c| {
                            (
                                c.clid,
                                c.uid.clone(),
                                c.nickname.clone(),
                                c.current_channel_id,
                                c.is_admin,
                                c.audio,
                            )
                        })
                        .collect()
                };

                for (other_clid, other_uid, other_nick, other_cid, other_admin, other_audio) in
                    &existing_clients
                {
                    let view = build_client_enter_view(
                        "0",
                        *other_clid,
                        other_uid,
                        other_nick,
                        *other_cid,
                        0,
                        *other_admin,
                        *other_audio,
                    );
                    self.send_encrypted_command(peer, &view).await?;
                }

                // 4. Announce the newcomer to all other connected clients.
                let newcomer_view =
                    build_client_enter_view("0", clid, &uid, &nickname, 1, 0, is_admin, audio);
                let other_endpoints: Vec<SocketAddr> = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .filter(|c| {
                            c.clid != clid
                                && c.handshake_phase == HandshakePhase::Connected
                                && c.last_activity.elapsed() < std::time::Duration::from_secs(45)
                        })
                        .map(|c| c.endpoint)
                        .collect()
                };
                for ep in other_endpoints {
                    let _ = self.send_encrypted_command(ep, &newcomer_view).await;
                }

                // 6. Publish channel-group names, followed by the baseline
                // permission requirements that the client uses for actions.
                self.send_channel_group_list(peer).await?;
                self.send_encrypted_raw(peer, permissions::get_client_needed_permissions_wire())
                    .await?;

                // 7. Send effective group permissions after the client knows
                // the permission names and required values.
                self.send_encrypted_raw(peer, permissions::get_guest_perms_wire())
                    .await?;
                if is_admin {
                    self.send_encrypted_raw(peer, permissions::get_server_admin_perms_wire())
                        .await?;
                }
                self.send_channel_group_perm_list(peer, 8).await?;
                if is_admin {
                    self.send_channel_group_perm_list(peer, 5).await?;
                }

                // 8. Success for the clientinit request itself.
                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;

                info!(
                    "Client {} ({}) successfully entered the server!",
                    clid, peer
                );
            }
            "clientupdate" => {
                let (notify, recipients) = {
                    let mut notify = Command::new("notifyclientupdated");
                    notify.set("clid", clid.to_string());

                    let mut state = self.state.lock().await;
                    if let Some(client) = state.get_client_mut(&peer) {
                        macro_rules! update_audio_flag {
                            ($wire_name:literal, $field:ident) => {
                                if let Some(value) = parse_wire_bool(cmd.get($wire_name)) {
                                    client.audio.$field = value;
                                    notify.set($wire_name, bool_wire(value));
                                }
                            };
                        }

                        update_audio_flag!("client_input_muted", input_muted);
                        update_audio_flag!("client_output_muted", output_muted);
                        update_audio_flag!("client_outputonly_muted", output_only_muted);
                        update_audio_flag!("client_input_hardware", input_hardware);
                        update_audio_flag!("client_output_hardware", output_hardware);
                    }

                    let recipients = if notify.params.len() > 1 {
                        state
                            .clients
                            .values()
                            .filter(|client| client.handshake_phase == HandshakePhase::Connected)
                            .map(|client| client.endpoint)
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    (notify, recipients)
                };

                for recipient in recipients {
                    self.send_encrypted_command(recipient, &notify).await?;
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelsubscribeall" | "channelunsubscribeall" => {
                let subscribe = cmd.name == "channelsubscribeall";
                let channel_ids = {
                    let db = self.db.lock().await;
                    db.get_channels()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|channel| channel.cid)
                        .collect::<Vec<_>>()
                };

                let (notification_name, notification_ids) = {
                    let mut state = self.state.lock().await;
                    match state.get_client_mut(&peer) {
                        Some(client) if subscribe => {
                            client
                                .subscribed_channels
                                .extend(channel_ids.iter().copied());
                            ("notifychannelsubscribed", channel_ids)
                        }
                        Some(client) => {
                            let current_channel = client.current_channel_id;
                            let unsubscribe_ids = client
                                .subscribed_channels
                                .iter()
                                .copied()
                                .filter(|cid| *cid != current_channel)
                                .collect::<Vec<_>>();
                            client.subscribed_channels.clear();
                            client.subscribed_channels.insert(current_channel);
                            ("notifychannelunsubscribed", unsubscribe_ids)
                        }
                        None => ("notifychannelunsubscribed", Vec::new()),
                    }
                };

                if !notification_ids.is_empty() {
                    let wire = build_channel_subscription_notification(
                        notification_name,
                        &notification_ids,
                    );
                    self.send_encrypted_raw(peer, &wire).await?;
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelsubscribe" | "channelunsubscribe" => {
                let subscribe = cmd.name == "channelsubscribe";
                let requested = parse_channel_ids(&cmd);
                let available = {
                    let db = self.db.lock().await;
                    db.get_channels()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|channel| channel.cid)
                        .collect::<std::collections::BTreeSet<_>>()
                };
                let requested = requested
                    .into_iter()
                    .filter(|cid| available.contains(cid))
                    .collect::<Vec<_>>();

                let (notification_name, notification_ids) = {
                    let mut state = self.state.lock().await;
                    match state.get_client_mut(&peer) {
                        Some(client) if subscribe => {
                            let mut newly_subscribed = Vec::new();
                            for cid in requested {
                                if client.subscribed_channels.insert(cid) {
                                    newly_subscribed.push(cid);
                                }
                            }
                            ("notifychannelsubscribed", newly_subscribed)
                        }
                        Some(client) => {
                            let current_channel = client.current_channel_id;
                            let mut unsubscribe_ids = Vec::new();
                            for cid in requested {
                                if cid != current_channel && client.subscribed_channels.remove(&cid)
                                {
                                    unsubscribe_ids.push(cid);
                                }
                            }
                            ("notifychannelunsubscribed", unsubscribe_ids)
                        }
                        None => ("notifychannelunsubscribed", Vec::new()),
                    }
                };

                if !notification_ids.is_empty() {
                    let wire = build_channel_subscription_notification(
                        notification_name,
                        &notification_ids,
                    );
                    self.send_encrypted_raw(peer, &wire).await?;
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "sendtextmessage" => {
                let target_mode = cmd.get("targetmode").unwrap_or("2");
                let msg = cmd.get("msg").unwrap_or("");
                let nickname = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| c.nickname.clone())
                        .unwrap_or_else(|| "User".into())
                };

                let mut notify = Command::new("notifytextmessage");
                notify.set("targetmode", target_mode);
                notify.set("msg", msg);
                notify.set("invokerid", clid.to_string());
                notify.set("invokername", &nickname);

                let endpoints: Vec<SocketAddr> = {
                    let state = self.state.lock().await;
                    if target_mode == "2" {
                        let cur_cid = state
                            .get_client(&peer)
                            .map(|c| c.current_channel_id)
                            .unwrap_or(1);
                        state
                            .clients_in_channel(cur_cid)
                            .iter()
                            .map(|c| c.endpoint)
                            .collect()
                    } else {
                        state.clients.values().map(|c| c.endpoint).collect()
                    }
                };

                for ep in endpoints {
                    let _ = self.send_encrypted_command(ep, &notify).await;
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await;
            }
            "clientmove" => {
                let new_cid: u64 = cmd.get("cid").and_then(|s| s.parse().ok()).unwrap_or(1);
                {
                    let mut state = self.state.lock().await;
                    if let Some(c) = state.get_client_mut(&peer) {
                        c.current_channel_id = new_cid;
                        c.subscribed_channels.insert(new_cid);
                    }
                }

                let mut notify = Command::new("notifyclientmoved");
                notify.set("ctid", new_cid.to_string());
                notify.set("reasonid", "0");
                notify.set("reasonmsg", "");
                notify.set("clid", clid.to_string());

                let all_peers: Vec<SocketAddr> = {
                    let state = self.state.lock().await;
                    state.clients.values().map(|c| c.endpoint).collect()
                };
                for ep in all_peers {
                    let _ = self.send_encrypted_command(ep, &notify).await;
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await;
            }
            "servergetvariables" => {
                let port = self.local_addr().map(|a| a.port()).unwrap_or(9988);
                let ask_for_privilege_key = {
                    let is_admin = {
                        let state = self.state.lock().await;
                        state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                    };
                    let has_key = {
                        let db = self.db.lock().await;
                        db.has_unused_privilege_key().unwrap_or(false)
                    };
                    !is_admin && has_key
                };
                let updated = build_server_updated(ask_for_privilege_key, port);
                self.send_encrypted_command(peer, &updated).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "clientgetvariables" => {
                let (nickname, _uid, admin) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.nickname.clone(), c.uid.clone(), c.is_admin),
                        None => ("User".to_string(), String::new(), false),
                    }
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let mut upd = Command::new("notifyclientupdated");
                upd.set("clid", clid.to_string());
                let _ = &nickname; // clientgetvariables must not rename
                upd.set("client_version", "3.6.2 [Build: 1695203293]");
                upd.set("client_platform", "Windows");
                upd.set("client_login_name", "");
                upd.set("client_created", "1600000000");
                upd.set("client_lastconnected", now.to_string());
                upd.set("client_totalconnections", "1");
                upd.set("client_month_bytes_uploaded", "0");
                upd.set("client_month_bytes_downloaded", "0");
                upd.set("client_total_bytes_uploaded", "0");
                upd.set("client_total_bytes_downloaded", "0");
                upd.set("client_servergroups", if admin { "6" } else { "8" });
                self.send_encrypted_command(peer, &upd).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channellist" => {
                self.send_channel_list(peer).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergrouplist" => {
                self.send_server_group_list(peer, false).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "permissionlist" => {
                // Send the complete notifypermissionlist wire string
                self.send_encrypted_raw(peer, permissions::get_notifypermissionlist_wire())
                    .await?;

                // Also proactively send the server group permissions for Admin (6) and Guest (8)
                self.send_encrypted_raw(peer, permissions::get_server_admin_perms_wire())
                    .await?;
                self.send_encrypted_raw(peer, permissions::get_guest_perms_wire())
                    .await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergrouppermlist" => {
                let sgid = cmd.get("sgid").unwrap_or("6");
                if sgid == "6" {
                    self.send_encrypted_raw(peer, permissions::get_server_admin_perms_wire())
                        .await?;
                } else {
                    self.send_encrypted_raw(peer, permissions::get_guest_perms_wire())
                        .await?;
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgrouplist" => {
                self.send_channel_group_list(peer).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgrouppermlist" => {
                let cgid: u16 = cmd.get("cgid").and_then(|v| v.parse().ok()).unwrap_or(8);
                self.send_channel_group_perm_list(peer, cgid).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergroupsbyclientid" => {
                let dbid: u16 = cmd
                    .get("cldbid")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(clid);
                let is_admin = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid == dbid)
                        .map(|c| c.is_admin)
                        .unwrap_or(false)
                };
                let mut resp = Command::new("notifyservergroupsbyclientid");
                resp.set("name", if is_admin { "Server Admin" } else { "Guest" });
                resp.set("sgid", if is_admin { "6" } else { "8" });
                resp.set("cldbid", dbid.to_string());
                self.send_encrypted_command(peer, &resp).await?;
                if is_admin {
                    let mut guest = Command::new("notifyservergroupsbyclientid");
                    guest.set("name", "Guest");
                    guest.set("sgid", "8");
                    guest.set("cldbid", dbid.to_string());
                    self.send_encrypted_command(peer, &guest).await?;
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgetdescription" => {
                let cid: u64 = cmd.get("cid").and_then(|s| s.parse().ok()).unwrap_or(1);
                let desc = {
                    let db = self.db.lock().await;
                    let channels = db.get_channels().unwrap_or_default();
                    channels
                        .into_iter()
                        .find(|ch| ch.cid == cid)
                        .map(|ch| ch.description)
                        .unwrap_or_default()
                };
                // The protocol answers `channelgetdescription` with the low
                // priority `notifychanneledited` update. A response named
                // `channelgetdescription` is ignored by the 3.6.2 client,
                // which leaves Edit Channel and Delete Channel without the
                // description snapshot their dialogs wait for.
                let mut resp = Command::new("notifychanneledited");
                resp.set("cid", cid.to_string());
                resp.set("reasonid", "9"); // Channelupdate
                resp.set("channel_description", &desc);
                self.send_encrypted_command(peer, &resp).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelcreate" => {
                let ch_name = cmd.get("channel_name").unwrap_or("New Channel");
                let ch_topic = cmd.get("channel_topic").unwrap_or("");

                let (nickname, invoker_uid) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.nickname.clone(), c.uid.clone()),
                        None => ("User".to_string(), String::new()),
                    }
                };

                // Channel names must be unique on the virtual server. The
                // incoming channel_order is the sibling this channel follows;
                // when omitted (or stale), append after the last channel.
                let cid = {
                    let db = self.db.lock().await;
                    let channels = db.get_channels().unwrap_or_default();
                    if channels
                        .iter()
                        .any(|c| c.name.eq_ignore_ascii_case(ch_name))
                    {
                        0
                    } else {
                        let requested_order =
                            cmd.get("channel_order").and_then(|s| s.parse::<u64>().ok());
                        let order_after = match requested_order {
                            Some(0) => 0,
                            Some(order) if channels.iter().any(|c| c.cid == order) => order,
                            _ => channels.last().map(|c| c.cid).unwrap_or(0),
                        };
                        db.create_channel_after(ch_name, ch_topic, order_after)
                            .unwrap_or(0)
                    }
                };

                if cid > 0 {
                    let db = self.db.lock().await;
                    if let Ok(mut edit) = parse_channel_edit(&cmd) {
                        // The order link was applied when the new row was
                        // inserted. Apply the remaining supplied properties.
                        edit.order_after = None;
                        if let Err(e) = db.edit_channel(cid, &edit) {
                            warn!(
                                "Failed to persist properties for new channel {}: {:?}",
                                cid, e
                            );
                        }
                    }
                }

                if cid > 0 {
                    let channel = {
                        let db = self.db.lock().await;
                        db.get_channels()
                            .unwrap_or_default()
                            .into_iter()
                            .find(|channel| channel.cid == cid)
                    };
                    let notify = channel.as_ref().map(|channel| {
                        build_channel_notification(
                            "notifychannelcreated",
                            channel,
                            clid,
                            &nickname,
                            &invoker_uid,
                        )
                    });

                    let all_peers: Vec<SocketAddr> = {
                        let state = self.state.lock().await;
                        state.clients.values().map(|c| c.endpoint).collect()
                    };
                    if let Some(notify) = notify {
                        for ep in all_peers {
                            let _ = self.send_encrypted_command(ep, &notify).await;
                        }
                    }
                }

                let mut err_resp = Command::new("error");
                if cid > 0 {
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                    // The official client needs the new channel id in this
                    // response to select the freshly created channel.
                    err_resp.set("cid", cid.to_string());
                } else {
                    err_resp.set("id", "1024");
                    err_resp.set("msg", "channel\\sname\\salready\\sin\\suse");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channeledit" => {
                let cid = cmd.get("cid").and_then(|value| value.parse::<u64>().ok());
                let (nickname, uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|client| {
                            (client.nickname.clone(), client.uid.clone(), client.is_admin)
                        })
                        .unwrap_or_else(|| ("User".to_string(), String::new(), false))
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else if let Some(cid) = cid {
                    match parse_channel_edit(&cmd) {
                        Err(reason) => {
                            err_resp.set("id", "1024");
                            err_resp.set("msg", reason);
                        }
                        Ok(edit) => {
                            let result = {
                                let db = self.db.lock().await;
                                db.edit_channel(cid, &edit)
                            };
                            match result {
                                Ok(Some(channel)) => {
                                    let notify = build_channel_notification(
                                        "notifychanneledited",
                                        &channel,
                                        clid,
                                        &nickname,
                                        &uid,
                                    );
                                    let recipients: Vec<SocketAddr> = {
                                        let state = self.state.lock().await;
                                        state
                                            .clients
                                            .values()
                                            .filter(|client| {
                                                client.handshake_phase == HandshakePhase::Connected
                                            })
                                            .map(|client| client.endpoint)
                                            .collect()
                                    };
                                    for recipient in recipients {
                                        let _ =
                                            self.send_encrypted_command(recipient, &notify).await;
                                    }
                                    err_resp.set("id", "0");
                                    err_resp.set("msg", "ok");
                                }
                                Ok(None) => {
                                    err_resp.set("id", "1024");
                                    err_resp.set("msg", "invalid channel");
                                }
                                Err(e) => {
                                    warn!("Failed to edit channel {}: {:?}", cid, e);
                                    err_resp.set("id", "1024");
                                    if cmd.get("channel_order").is_some() {
                                        err_resp.set("msg", "invalid channel order");
                                    } else if cmd.get("channel_name").is_some() {
                                        err_resp.set("msg", "channel name already in use");
                                    } else {
                                        err_resp.set("msg", "invalid channel configuration");
                                    }
                                }
                            }
                        }
                    }
                } else {
                    err_resp.set("id", "1024");
                    err_resp.set("msg", "invalid channel");
                }
                if err_resp.get("id") == Some("0") {
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channeldelete" => {
                let cid = cmd.get("cid").and_then(|value| value.parse::<u64>().ok());
                let force = cmd.get("force") == Some("1");
                let (nickname, uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|client| {
                            (client.nickname.clone(), client.uid.clone(), client.is_admin)
                        })
                        .unwrap_or_else(|| ("User".to_string(), String::new(), false))
                };
                let mut err_resp = Command::new("error");

                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else if let Some(cid) = cid {
                    let (channel_exists, is_default, default_cid) = {
                        let db = self.db.lock().await;
                        let channels = db.get_channels().unwrap_or_default();
                        (
                            channels.iter().any(|channel| channel.cid == cid),
                            channels
                                .iter()
                                .find(|channel| channel.cid == cid)
                                .is_some_and(|channel| channel.is_default),
                            channels
                                .iter()
                                .find(|channel| channel.is_default)
                                .map(|channel| channel.cid)
                                .unwrap_or(1),
                        )
                    };

                    let occupied_clients = {
                        let state = self.state.lock().await;
                        state
                            .clients
                            .values()
                            .filter(|client| {
                                client.current_channel_id == cid
                                    && client.handshake_phase == HandshakePhase::Connected
                            })
                            .map(|client| client.clid)
                            .collect::<Vec<_>>()
                    };

                    if !channel_exists || is_default {
                        err_resp.set("id", "771");
                        err_resp.set("msg", "invalid channel flags");
                    } else if !force && !occupied_clients.is_empty() {
                        err_resp.set("id", "770");
                        err_resp.set("msg", "channel is not empty");
                    } else {
                        let deleted = {
                            let db = self.db.lock().await;
                            db.delete_channel(cid).unwrap_or(false)
                        };
                        if !deleted {
                            err_resp.set("id", "1024");
                            err_resp.set("msg", "invalid channel");
                        } else {
                            let (move_clients, recipients) = {
                                let mut state = self.state.lock().await;
                                let mut move_clients = Vec::new();
                                for client in state.clients.values_mut() {
                                    client.subscribed_channels.remove(&cid);
                                    if force
                                        && client.current_channel_id == cid
                                        && client.handshake_phase == HandshakePhase::Connected
                                    {
                                        client.current_channel_id = default_cid;
                                        client.subscribed_channels.insert(default_cid);
                                        move_clients.push(client.clid);
                                    }
                                }
                                let recipients = state
                                    .clients
                                    .values()
                                    .filter(|client| {
                                        client.handshake_phase == HandshakePhase::Connected
                                    })
                                    .map(|client| client.endpoint)
                                    .collect::<Vec<_>>();
                                (move_clients, recipients)
                            };

                            for moved_clid in move_clients {
                                let mut moved = Command::new("notifyclientmoved");
                                moved.set("clid", moved_clid.to_string());
                                moved.set("cfid", cid.to_string());
                                moved.set("ctid", default_cid.to_string());
                                moved.set("reasonid", "0");
                                moved.set("reasonmsg", "channel deleted");
                                moved.set("invokerid", clid.to_string());
                                moved.set("invokername", &nickname);
                                moved.set("invokeruid", &uid);
                                for recipient in &recipients {
                                    let _ = self.send_encrypted_command(*recipient, &moved).await;
                                }
                            }

                            let mut deleted = Command::new("notifychanneldeleted");
                            deleted.set("cid", cid.to_string());
                            deleted.set("invokerid", clid.to_string());
                            deleted.set("invokername", &nickname);
                            deleted.set("invokeruid", &uid);
                            for recipient in recipients {
                                let _ = self.send_encrypted_command(recipient, &deleted).await;
                            }
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                        }
                    }
                } else {
                    err_resp.set("id", "1024");
                    err_resp.set("msg", "invalid channel");
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "tokenuse" | "privilegekeyuse" => {
                let token = cmd.get("token").or_else(|| cmd.get("key")).unwrap_or("");

                let (client_uid, nickname) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.uid.clone(), c.nickname.clone()),
                        None => (String::new(), "User".to_string()),
                    }
                };

                let redeemed = {
                    let db = self.db.lock().await;
                    db.redeem_privilege_key(token).unwrap_or(false)
                };

                if redeemed {
                    // Persist the identity so future reconnects are recognised
                    // as Server Admin without asking for a privilege key again.
                    if !client_uid.is_empty() {
                        let db = self.db.lock().await;
                        if let Err(e) = db.add_admin_identity(&client_uid) {
                            warn!("Failed to persist admin identity {}: {:?}", client_uid, e);
                        }
                    }

                    {
                        let mut state = self.state.lock().await;
                        if let Some(c) = state.get_client_mut(&peer) {
                            c.is_admin = true;
                        }
                    }
                    info!(
                        "Client {} redeemed privilege key and is now Server Admin!",
                        clid
                    );

                    let mut notify = Command::new("notifyclientupdated");
                    notify.set("clid", clid.to_string());
                    // Do NOT echo client_nickname here: the official client
                    // treats it as a rename request and rejects it with
                    // "nickname is already in use", dropping the connection.
                    let _ = &nickname;
                    notify.set("client_servergroups", "6");
                    notify.set("client_channel_group_id", "5");
                    notify.set("client_needed_serverquery_view_power", "75");

                    let all_endpoints: Vec<SocketAddr> = {
                        let state = self.state.lock().await;
                        state.clients.values().map(|c| c.endpoint).collect()
                    };
                    for ep in all_endpoints {
                        let _ = self.send_encrypted_command(ep, &notify).await;
                    }

                    // Push Server Admin and Channel Admin permissions immediately
                    let _ = self
                        .send_encrypted_raw(peer, permissions::get_server_admin_perms_wire())
                        .await;
                    let _ = self.send_channel_group_perm_list(peer, 5).await;

                    let port = self.local_addr().map(|a| a.port()).unwrap_or(9988);
                    let server_updated = build_server_updated(false, port);
                    let _ = self.send_encrypted_command(peer, &server_updated).await;
                }

                let mut err_resp = Command::new("error");
                if redeemed {
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                } else {
                    err_resp.set("id", "2564");
                    err_resp.set("msg", "invalid\\sprivilege\\stoken");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await;
            }
            "clientdisconnect" | "quit" => {
                let reason_id = cmd.get("reasonid").unwrap_or("3");
                let reason_msg = cmd.get("reasonmsg").unwrap_or("");

                let (cur_cid, other_peers) = {
                    let mut state = self.state.lock().await;
                    let cid = match state.get_client_mut(&peer) {
                        Some(c) => {
                            c.handshake_phase = HandshakePhase::Disconnected;
                            c.disconnect_time = Some(std::time::Instant::now());
                            c.current_channel_id
                        }
                        None => 1,
                    };
                    let others: Vec<SocketAddr> = state
                        .clients
                        .values()
                        .filter(|other| {
                            other.clid != clid && other.handshake_phase == HandshakePhase::Connected
                        })
                        .map(|other| other.endpoint)
                        .collect();
                    (cid, others)
                };

                // 1. Confirm the clientdisconnect command itself.
                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await;

                // 2. The leaving client must also receive its own left view
                //    (clid = own clid, ctid = 0) to transition immediately to
                //    the disconnected state instead of waiting for ACK
                //    timeouts.
                let mut notify = Command::new("notifyclientleftview");
                notify.set("clid", clid.to_string());
                notify.set("cfid", cur_cid.to_string());
                notify.set("ctid", "0");
                notify.set("reasonid", reason_id);
                notify.set("reasonmsg", reason_msg);
                let _ = self.send_encrypted_command(peer, &notify).await;

                for ep in other_peers {
                    let _ = self.send_encrypted_command(ep, &notify).await;
                }

                info!("Client {} disconnecting (reason {})", clid, reason_id);
            }
            "clientkick" => {
                let reason_id = cmd.get("reasonid").unwrap_or("4");
                let reason_msg = cmd.get("reasonmsg").unwrap_or("");
                let target_clid: Option<u16> = cmd.get("clid").and_then(|v| v.parse().ok());

                let (invoker_nickname, invoker_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.nickname.clone(), c.uid.clone(), c.is_admin))
                        .unwrap_or_else(|| ("User".to_string(), String::new(), false))
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else if let Some(target_clid) = target_clid {
                    let target_info = {
                        let state = self.state.lock().await;
                        state
                            .clients
                            .values()
                            .find(|c| {
                                c.clid == target_clid
                                    && c.handshake_phase == HandshakePhase::Connected
                            })
                            .map(|c| (c.endpoint, c.current_channel_id, c.nickname.clone()))
                    };

                    match target_info {
                        None => {
                            err_resp.set("id", "512");
                            err_resp.set("msg", "invalid clientID");
                        }
                        Some((target_ep, old_cid, target_nick)) => {
                            if reason_id == "4" {
                                // Channel Kick -> move to default channel
                                let default_cid = {
                                    let db = self.db.lock().await;
                                    let channels = db.get_channels().unwrap_or_default();
                                    channels
                                        .iter()
                                        .find(|ch| ch.is_default)
                                        .map(|ch| ch.cid)
                                        .unwrap_or(1)
                                };

                                if old_cid == default_cid {
                                    err_resp.set("id", "1024");
                                    err_resp.set("msg", "client is already in default channel");
                                } else {
                                    {
                                        let mut state = self.state.lock().await;
                                        if let Some(c) = state.clients.get_mut(&target_ep) {
                                            c.current_channel_id = default_cid;
                                            c.subscribed_channels.insert(default_cid);
                                        }
                                    }

                                    let mut moved = Command::new("notifyclientmoved");
                                    moved.set("clid", target_clid.to_string());
                                    moved.set("cfid", old_cid.to_string());
                                    moved.set("ctid", default_cid.to_string());
                                    moved.set("reasonid", "4");
                                    if !reason_msg.is_empty() {
                                        moved.set("reasonmsg", reason_msg);
                                    }
                                    moved.set("invokerid", clid.to_string());
                                    moved.set("invokername", &invoker_nickname);
                                    moved.set("invokeruid", &invoker_uid);

                                    let all_peers: Vec<SocketAddr> = {
                                        let state = self.state.lock().await;
                                        state
                                            .clients
                                            .values()
                                            .filter(|c| {
                                                c.handshake_phase == HandshakePhase::Connected
                                            })
                                            .map(|c| c.endpoint)
                                            .collect()
                                    };
                                    for ep in all_peers {
                                        let _ = self.send_encrypted_command(ep, &moved).await;
                                    }

                                    info!(
                                        "Client {} kicked {} ({}) from channel {} to default channel {}",
                                        clid, target_clid, target_nick, old_cid, default_cid
                                    );
                                    err_resp.set("id", "0");
                                    err_resp.set("msg", "ok");
                                }
                            } else if reason_id == "5" {
                                // Server Kick
                                let mut notify = Command::new("notifyclientleftview");
                                notify.set("clid", target_clid.to_string());
                                notify.set("cfid", old_cid.to_string());
                                notify.set("ctid", "0");
                                notify.set("reasonid", "5");
                                if !reason_msg.is_empty() {
                                    notify.set("reasonmsg", reason_msg);
                                }
                                notify.set("invokerid", clid.to_string());
                                notify.set("invokername", &invoker_nickname);
                                notify.set("invokeruid", &invoker_uid);

                                // Send to kicked client first
                                let _ = self.send_encrypted_command(target_ep, &notify).await;

                                let other_peers: Vec<SocketAddr> = {
                                    let mut state = self.state.lock().await;
                                    if let Some(c) = state.clients.get_mut(&target_ep) {
                                        c.handshake_phase = HandshakePhase::Disconnected;
                                        c.disconnect_time = Some(std::time::Instant::now());
                                    }
                                    state
                                        .clients
                                        .values()
                                        .filter(|c| {
                                            c.endpoint != target_ep
                                                && c.handshake_phase == HandshakePhase::Connected
                                        })
                                        .map(|c| c.endpoint)
                                        .collect()
                                };

                                for ep in other_peers {
                                    let _ = self.send_encrypted_command(ep, &notify).await;
                                }

                                info!(
                                    "Client {} kicked {} ({}) from server",
                                    clid, target_clid, target_nick
                                );
                                err_resp.set("id", "0");
                                err_resp.set("msg", "ok");
                            } else {
                                err_resp.set("id", "1024");
                                err_resp.set("msg", "invalid reasonid");
                            }
                        }
                    }
                } else {
                    err_resp.set("id", "512");
                    err_resp.set("msg", "invalid clientID");
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "banclient" => {
                let target_clid: Option<u16> = cmd.get("clid").and_then(|v| v.parse().ok());
                let duration: i64 = cmd.get("time").and_then(|v| v.parse().ok()).unwrap_or(0);
                let ban_reason = cmd.get("banreason").unwrap_or("");

                let (invoker_nickname, invoker_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.nickname.clone(), c.uid.clone(), c.is_admin))
                        .unwrap_or_else(|| ("User".to_string(), String::new(), false))
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else if let Some(target_clid) = target_clid {
                    let target_info = {
                        let state = self.state.lock().await;
                        state
                            .clients
                            .values()
                            .find(|c| {
                                c.clid == target_clid
                                    && c.handshake_phase == HandshakePhase::Connected
                            })
                            .map(|c| {
                                (
                                    c.endpoint,
                                    c.current_channel_id,
                                    c.nickname.clone(),
                                    c.uid.clone(),
                                )
                            })
                    };

                    match target_info {
                        None => {
                            err_resp.set("id", "512");
                            err_resp.set("msg", "invalid clientID");
                        }
                        Some((target_ep, old_cid, target_nick, target_uid)) => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64;

                            let target_ip = target_ep.ip().to_string();
                            let ban_record = BanRecord {
                                ip: target_ip,
                                name: target_nick.clone(),
                                uid: target_uid,
                                mytsid: String::new(),
                                lastnickname: target_nick.clone(),
                                created: now,
                                duration,
                                invokercldbid: clid as u64,
                                invokername: invoker_nickname.clone(),
                                invokeruid: invoker_uid.clone(),
                                reason: ban_reason.to_string(),
                                enforcements: 0,
                                ..Default::default()
                            };

                            let ban_id = {
                                let db = self.db.lock().await;
                                db.add_ban(&ban_record).unwrap_or(0)
                            };

                            // Disconnect target client with reasonid=6 (Banned)
                            let mut notify = Command::new("notifyclientleftview");
                            notify.set("clid", target_clid.to_string());
                            notify.set("cfid", old_cid.to_string());
                            notify.set("ctid", "0");
                            notify.set("reasonid", "6");
                            if !ban_reason.is_empty() {
                                notify.set("reasonmsg", ban_reason);
                            }
                            notify.set("invokerid", clid.to_string());
                            notify.set("invokername", &invoker_nickname);
                            notify.set("invokeruid", &invoker_uid);

                            // Send to banned client first
                            let _ = self.send_encrypted_command(target_ep, &notify).await;

                            let other_peers: Vec<SocketAddr> = {
                                let mut state = self.state.lock().await;
                                if let Some(c) = state.clients.get_mut(&target_ep) {
                                    c.handshake_phase = HandshakePhase::Disconnected;
                                    c.disconnect_time = Some(std::time::Instant::now());
                                }
                                state
                                    .clients
                                    .values()
                                    .filter(|c| {
                                        c.endpoint != target_ep
                                            && c.handshake_phase == HandshakePhase::Connected
                                    })
                                    .map(|c| c.endpoint)
                                    .collect()
                            };

                            for ep in other_peers {
                                let _ = self.send_encrypted_command(ep, &notify).await;
                            }

                            info!(
                                "Client {} banned {} ({}) ban_id={}",
                                clid, target_clid, target_nick, ban_id
                            );

                            let _ = self
                                .send_encrypted_raw(peer, &format!("banid={}", ban_id))
                                .await;

                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                            err_resp.set("banid", ban_id.to_string());
                        }
                    }
                } else {
                    err_resp.set("id", "512");
                    err_resp.set("msg", "invalid clientID");
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "banadd" => {
                let ip = cmd.get("ip").unwrap_or("");
                let uid_param = cmd.get("uid").unwrap_or("");
                let name_param = cmd.get("name").unwrap_or("");
                let duration: i64 = cmd.get("time").and_then(|v| v.parse().ok()).unwrap_or(0);
                let ban_reason = cmd.get("banreason").unwrap_or("");

                let (invoker_nickname, invoker_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.nickname.clone(), c.uid.clone(), c.is_admin))
                        .unwrap_or_else(|| ("User".to_string(), String::new(), false))
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else if ip.is_empty() && uid_param.is_empty() && name_param.is_empty() {
                    err_resp.set("id", "1024");
                    err_resp.set("msg", "parameter not found");
                } else {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    let ban_record = BanRecord {
                        ip: ip.to_string(),
                        name: name_param.to_string(),
                        uid: uid_param.to_string(),
                        mytsid: String::new(),
                        lastnickname: name_param.to_string(),
                        created: now,
                        duration,
                        invokercldbid: clid as u64,
                        invokername: invoker_nickname.clone(),
                        invokeruid: invoker_uid.clone(),
                        reason: ban_reason.to_string(),
                        enforcements: 0,
                        ..Default::default()
                    };

                    let ban_id = {
                        let db = self.db.lock().await;
                        db.add_ban(&ban_record).unwrap_or(0)
                    };

                    // Kick any currently connected clients that match this ban
                    let matching_clients: Vec<(SocketAddr, u16, u64)> = {
                        let state = self.state.lock().await;
                        state
                            .clients
                            .values()
                            .filter(|c| {
                                c.handshake_phase == HandshakePhase::Connected
                                    && ((!ip.is_empty() && c.endpoint.ip().to_string() == ip)
                                        || (!uid_param.is_empty() && c.uid == uid_param)
                                        || (!name_param.is_empty()
                                            && c.nickname.eq_ignore_ascii_case(name_param)))
                            })
                            .map(|c| (c.endpoint, c.clid, c.current_channel_id))
                            .collect()
                    };

                    for (target_ep, target_clid, old_cid) in matching_clients {
                        let mut notify = Command::new("notifyclientleftview");
                        notify.set("clid", target_clid.to_string());
                        notify.set("cfid", old_cid.to_string());
                        notify.set("ctid", "0");
                        notify.set("reasonid", "6");
                        if !ban_reason.is_empty() {
                            notify.set("reasonmsg", ban_reason);
                        }
                        notify.set("invokerid", clid.to_string());
                        notify.set("invokername", &invoker_nickname);
                        notify.set("invokeruid", &invoker_uid);

                        let _ = self.send_encrypted_command(target_ep, &notify).await;

                        let other_peers: Vec<SocketAddr> = {
                            let mut state = self.state.lock().await;
                            if let Some(c) = state.clients.get_mut(&target_ep) {
                                c.handshake_phase = HandshakePhase::Disconnected;
                                c.disconnect_time = Some(std::time::Instant::now());
                            }
                            state
                                .clients
                                .values()
                                .filter(|c| {
                                    c.endpoint != target_ep
                                        && c.handshake_phase == HandshakePhase::Connected
                                    })
                                .map(|c| c.endpoint)
                                .collect()
                        };

                        for ep in other_peers {
                            let _ = self.send_encrypted_command(ep, &notify).await;
                        }
                    }

                    let _ = self
                        .send_encrypted_raw(peer, &format!("banid={}", ban_id))
                        .await;

                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                    err_resp.set("banid", ban_id.to_string());
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "banlist" => {
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let bans = {
                        let db = self.db.lock().await;
                        db.get_bans().unwrap_or_default()
                    };

                    for ban in bans {
                        let mut ban_cmd = Command::new("notifybanlist");
                        ban_cmd.set("banid", ban.ban_id.to_string());
                        ban_cmd.set("ip", &ban.ip);
                        ban_cmd.set("name", &ban.name);
                        ban_cmd.set("uid", &ban.uid);
                        ban_cmd.set("mytsid", &ban.mytsid);
                        ban_cmd.set("lastnickname", &ban.lastnickname);
                        ban_cmd.set("created", ban.created.to_string());
                        ban_cmd.set("duration", ban.duration.to_string());
                        ban_cmd.set("invokercldbid", ban.invokercldbid.to_string());
                        ban_cmd.set("invokername", &ban.invokername);
                        ban_cmd.set("invokeruid", &ban.invokeruid);
                        ban_cmd.set("reason", &ban.reason);
                        ban_cmd.set("enforcements", ban.enforcements.to_string());
                        let _ = self.send_encrypted_command(peer, &ban_cmd).await;
                    }

                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "bandel" => {
                let ban_id: Option<u64> = cmd.get("banid").and_then(|v| v.parse().ok());
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else if let Some(ban_id) = ban_id {
                    let deleted = {
                        let db = self.db.lock().await;
                        db.delete_ban(ban_id).unwrap_or(false)
                    };
                    if deleted {
                        err_resp.set("id", "0");
                        err_resp.set("msg", "ok");
                    } else {
                        err_resp.set("id", "3328");
                        err_resp.set("msg", "invalid ban id");
                    }
                } else {
                    err_resp.set("id", "3328");
                    err_resp.set("msg", "invalid ban id");
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "bandelall" => {
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    let _ = db.delete_all_bans();
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            _ => {
                debug!("Unhandled command: {}", cmd.name);
                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await;
            }
        }

        Ok(())
    }

    async fn handle_voice(&self, peer: SocketAddr, packet: &[u8]) -> Result<(), String> {
        let (cid, clid) = {
            let state = self.state.lock().await;
            match state.get_client(&peer) {
                Some(c) => (c.current_channel_id, c.clid),
                None => return Ok(()),
            }
        };

        if packet.len() < 16 {
            return Ok(());
        }

        let seq_id = &packet[13..15];
        let codec = packet[15];
        let audio_data = &packet[16..];

        let recipients: Vec<SocketAddr> = {
            let state = self.state.lock().await;
            state
                .clients_in_channel(cid)
                .iter()
                .filter(|c| c.clid != clid)
                .map(|c| c.endpoint)
                .collect()
        };

        for recipient in recipients {
            let (p_id, shared_mac) = {
                let mut state = self.state.lock().await;
                let c = match state.get_client_mut(&recipient) {
                    Some(c) => c,
                    None => continue,
                };
                let id = c.next_s2c_voice_packet_id;
                c.next_s2c_voice_packet_id = c.next_s2c_voice_packet_id.wrapping_add(1);
                let sm: [u8; 8] = c
                    .shared_iv
                    .map(|siv| Sha1::digest(&siv)[..8].try_into().unwrap())
                    .unwrap_or([0u8; 8]);
                (id, sm)
            };

            let mut out = Vec::with_capacity(11 + 5 + audio_data.len());
            out.extend_from_slice(&shared_mac);
            out.extend_from_slice(&p_id.to_be_bytes());
            out.push(0x80); // Flags::UNENCRYPTED | PacketType::Voice (0)
            out.extend_from_slice(seq_id);
            out.extend_from_slice(&clid.to_be_bytes());
            out.push(codec);
            out.extend_from_slice(audio_data);
            let _ = self.socket.send_to(&out, recipient).await;
        }

        Ok(())
    }

    /// Sends one `channellist` entry per stored channel.
    async fn send_channel_entries(&self, peer: SocketAddr) -> Result<(), String> {
        let channels = {
            let db = self.db.lock().await;
            db.get_channels().unwrap_or_default()
        };

        for ch in channels {
            let mut ch_cmd = Command::new("channellist");
            ch_cmd.set("cid", ch.cid.to_string());
            ch_cmd.set("cpid", "0");
            ch_cmd.set("channel_name", ch.name);
            ch_cmd.set("channel_topic", ch.topic);
            ch_cmd.set("channel_codec", ch.codec.to_string());
            ch_cmd.set("channel_codec_quality", ch.codec_quality.to_string());
            ch_cmd.set("channel_maxclients", ch.max_clients.to_string());
            ch_cmd.set(
                "channel_maxfamilyclients",
                ch.max_family_clients.to_string(),
            );
            ch_cmd.set("channel_order", ch.order_id.to_string());
            ch_cmd.set("channel_flag_permanent", bool_wire(ch.is_permanent));
            ch_cmd.set(
                "channel_flag_semi_permanent",
                bool_wire(ch.is_semi_permanent),
            );
            ch_cmd.set("channel_flag_default", bool_wire(ch.is_default));
            ch_cmd.set("channel_flag_password", "0");
            ch_cmd.set(
                "channel_codec_latency_factor",
                ch.codec_latency_factor.to_string(),
            );
            ch_cmd.set("channel_codec_is_unencrypted", "1");
            ch_cmd.set("channel_delete_delay", ch.delete_delay.to_string());
            ch_cmd.set(
                "channel_flag_maxclients_unlimited",
                bool_wire(ch.max_clients_unlimited),
            );
            ch_cmd.set(
                "channel_flag_maxfamilyclients_unlimited",
                bool_wire(ch.max_family_clients_unlimited),
            );
            ch_cmd.set(
                "channel_flag_maxfamilyclients_inherited",
                bool_wire(ch.max_family_clients_inherited),
            );
            ch_cmd.set(
                "channel_needed_talk_power",
                ch.needed_talk_power.to_string(),
            );
            ch_cmd.set(
                "channel_needed_subscribe_power",
                ch.needed_subscribe_power.to_string(),
            );
            ch_cmd.set("channel_forced_silence", "0");
            ch_cmd.set("channel_name_phonetic", ch.name_phonetic);
            ch_cmd.set("channel_icon_id", ch.icon_id.to_string());
            self.send_encrypted_command(peer, &ch_cmd).await?;
        }

        Ok(())
    }

    /// Terminates the channel list. Must be sent after the client's own
    /// `notifycliententerview`.
    async fn send_channellist_finished(&self, peer: SocketAddr) -> Result<(), String> {
        let finished = Command::new("channellistfinished");
        self.send_encrypted_command(peer, &finished).await
    }

    /// Convenience combination used when the client itself requests
    /// `channellist`; by then its own client object already exists.
    async fn send_channel_list(&self, peer: SocketAddr) -> Result<(), String> {
        self.send_channel_entries(peer).await?;
        self.send_channellist_finished(peer).await
    }

    /// Announces the server groups a client belongs to. All groups are sent
    /// in a single multi-part command because the client replaces its cached
    /// membership list with every such command it receives.
    async fn send_client_group_membership(
        &self,
        peer: SocketAddr,
        clid: u16,
        is_admin: bool,
    ) -> Result<(), String> {
        let mut wire = String::from("notifyservergroupsbyclientid ");
        if is_admin {
            wire.push_str(&format!("name=Server\\sAdmin sgid=6 cldbid={}|", clid));
        }
        wire.push_str(&format!("name=Guest sgid=8 cldbid={}", clid));
        self.send_encrypted_raw(peer, &wire).await
    }

    /// Sends the channel groups the official client knows about (Guest and
    /// Channel Admin), all in one command for the same reason.
    async fn send_channel_group_list(&self, peer: SocketAddr) -> Result<(), String> {
        let wire = "notifychannelgrouplist cgid=5 name=Channel\\sAdmin type=1 iconid=100 savedb=1 sortid=0 namemode=0 n_modifyp=75 n_member_addp=50 n_member_removep=50|cgid=8 name=Guest type=1 iconid=0 savedb=0 sortid=0 namemode=0 n_modifyp=75 n_member_addp=0 n_member_removep=0";
        self.send_encrypted_raw(peer, wire).await
    }

    /// Channel group permissions as reported by an official 3.13.7 server.
    async fn send_channel_group_perm_list(
        &self,
        peer: SocketAddr,
        cgid: u16,
    ) -> Result<(), String> {
        let wire = match cgid {
            5 => {
                "notifychannelgrouppermlist cgid=5 permid=99 permvalue=1 permnegated=0 permskip=0|permid=111 permvalue=1 permnegated=0 permskip=0|permid=112 permvalue=1 permnegated=0 permskip=0|permid=113 permvalue=1 permnegated=0 permskip=0|permid=114 permvalue=1 permnegated=0 permskip=0|permid=115 permvalue=1 permnegated=0 permskip=0|permid=117 permvalue=1 permnegated=0 permskip=0|permid=118 permvalue=1 permnegated=0 permskip=0|permid=119 permvalue=1 permnegated=0 permskip=0|permid=120 permvalue=1 permnegated=0 permskip=0|permid=121 permvalue=1 permnegated=0 permskip=0|permid=123 permvalue=1 permnegated=0 permskip=0|permid=124 permvalue=50 permnegated=0 permskip=0|permid=125 permvalue=50 permnegated=0 permskip=0|permid=126 permvalue=1 permnegated=0 permskip=0|permid=128 permvalue=1 permnegated=0 permskip=0|permid=129 permvalue=1 permnegated=0 permskip=0|permid=130 permvalue=1 permnegated=0 permskip=0|permid=131 permvalue=1 permnegated=0 permskip=0|permid=132 permvalue=50 permnegated=0 permskip=0|permid=133 permvalue=50 permnegated=0 permskip=0|permid=143 permvalue=50 permnegated=0 permskip=0|permid=145 permvalue=100 permnegated=0 permskip=0|permid=148 permvalue=1 permnegated=0 permskip=0|permid=149 permvalue=40 permnegated=0 permskip=0|permid=165 permvalue=75 permnegated=0 permskip=0|permid=166 permvalue=50 permnegated=0 permskip=0|permid=167 permvalue=50 permnegated=0 permskip=0|permid=168 permvalue=50 permnegated=0 permskip=0|permid=169 permvalue=50 permnegated=0 permskip=0|permid=186 permvalue=1 permnegated=0 permskip=0|permid=200 permvalue=50 permnegated=0 permskip=0|permid=201 permvalue=50 permnegated=0 permskip=0|permid=204 permvalue=50 permnegated=0 permskip=0|permid=207 permvalue=25 permnegated=0 permskip=0|permid=221 permvalue=60 permnegated=0 permskip=0|permid=225 permvalue=1 permnegated=0 permskip=0"
            }
            _ => {
                "notifychannelgrouppermlist cgid=8 permid=149 permvalue=10 permnegated=0 permskip=0|permid=165 permvalue=75 permnegated=0 permskip=0"
            }
        };
        self.send_encrypted_raw(peer, wire).await
    }

    /// Sends the two server groups as one multi-part command. `notify`
    /// selects the unsolicited `notifyservergrouplist` form; the plain
    /// `servergrouplist` form is the response to a client query.
    async fn send_server_group_list(&self, peer: SocketAddr, notify: bool) -> Result<(), String> {
        let name = if notify {
            "notifyservergrouplist"
        } else {
            "servergrouplist"
        };
        let wire = format!(
            "{} sgid=6 name=Server\\sAdmin type=1 iconid=300 savedb=1 sortid=0 namemode=0 n_modifyp=75 n_member_addp=75 n_member_removep=75|sgid=8 name=Guest type=1 iconid=0 savedb=0 sortid=0 namemode=0 n_modifyp=75 n_member_addp=0 n_member_removep=0",
            name
        );
        self.send_encrypted_raw(peer, &wire).await
    }

    async fn send_encrypted_command(&self, peer: SocketAddr, cmd: &Command) -> Result<(), String> {
        let wire_str = cmd.build();
        self.send_encrypted_raw(peer, &wire_str).await
    }

    #[allow(dead_code)]
    async fn send_encrypted_low_command(
        &self,
        peer: SocketAddr,
        cmd: &Command,
    ) -> Result<(), String> {
        let wire_str = cmd.build();
        self.send_encrypted_raw_with_type(peer, &wire_str, PacketType::CommandLow)
            .await
    }

    async fn send_encrypted_raw(&self, peer: SocketAddr, wire_str: &str) -> Result<(), String> {
        self.send_encrypted_raw_with_type(peer, wire_str, PacketType::Command)
            .await
    }

    async fn send_encrypted_raw_with_type(
        &self,
        peer: SocketAddr,
        wire_str: &str,
        packet_type: PacketType,
    ) -> Result<(), String> {
        let shared_iv = {
            let state = self.state.lock().await;
            let client = match state.get_client(&peer) {
                Some(c) => c,
                None => return Err("Client not found for send".into()),
            };
            client.shared_iv.ok_or_else(|| "No shared IV".to_string())?
        };

        let wire_bytes = wire_str.as_bytes();
        let max_chunk_len = 480;

        if wire_bytes.len() <= max_chunk_len {
            let p_id = {
                let mut state = self.state.lock().await;
                let client = match state.get_client_mut(&peer) {
                    Some(c) => c,
                    None => return Err("Client not found for send".into()),
                };
                let id = match packet_type {
                    PacketType::CommandLow => {
                        let id = client.next_s2c_low_packet_id;
                        client.next_s2c_low_packet_id = id.wrapping_add(1);
                        id
                    }
                    _ => {
                        let id = client.next_s2c_packet_id;
                        client.next_s2c_packet_id = id.wrapping_add(1);
                        id
                    }
                };
                id
            };

            let flags = Flags::NEWPROTOCOL;
            let (key, nonce) =
                derive_key_nonce(Direction::S2C, packet_type as u8, 0, p_id, &shared_iv);

            let mut aad = [0u8; 3];
            aad[0..2].copy_from_slice(&p_id.to_be_bytes());
            aad[2] = flags.bits() | (packet_type as u8);

            let mut payload = wire_bytes.to_vec();
            let mac = encrypt_eax(&key, &nonce, &aad, &mut payload)?;

            let mut pkt = OutPacket::new_with_dir(Direction::S2C, flags, packet_type);
            pkt.packet_id(p_id);
            pkt.mac().copy_from_slice(&mac);
            pkt.data_mut().extend_from_slice(&payload);

            let res = self.socket.send_to(&pkt.into_vec(), peer).await;
            let cmd_name = wire_str.split_whitespace().next().unwrap_or("");
            info!(
                "Sent encrypted {:?} command '{}' (p_id: {}) to {}: {:?}",
                packet_type, cmd_name, p_id, peer, res
            );
        } else {
            let chunks: Vec<&[u8]> = wire_bytes.chunks(max_chunk_len).collect();
            let total_chunks = chunks.len();
            let cmd_name = wire_str.split_whitespace().next().unwrap_or("").to_string();

            for (idx, chunk) in chunks.into_iter().enumerate() {
                let p_id = {
                    let mut state = self.state.lock().await;
                    let client = match state.get_client_mut(&peer) {
                        Some(c) => c,
                        None => return Err("Client not found for send".into()),
                    };
                    let id = match packet_type {
                        PacketType::CommandLow => {
                            let id = client.next_s2c_low_packet_id;
                            client.next_s2c_low_packet_id = id.wrapping_add(1);
                            id
                        }
                        _ => {
                            let id = client.next_s2c_packet_id;
                            client.next_s2c_packet_id = id.wrapping_add(1);
                            id
                        }
                    };
                    id
                };

                // TS3 marks the first and the last packet of a fragmented
                // command with FRAGMENTED; packets in between do not set it.
                // Setting it on every chunk makes clients treat fragment #2 as
                // the end of the command, truncating large messages such as
                // initserver (which is why the official client reported
                // "parameter not found" and disconnected).
                let mut flags = Flags::NEWPROTOCOL;
                if total_chunks > 1 && (idx == 0 || idx + 1 == total_chunks) {
                    flags |= Flags::FRAGMENTED;
                }

                let (key, nonce) =
                    derive_key_nonce(Direction::S2C, packet_type as u8, 0, p_id, &shared_iv);

                let mut aad = [0u8; 3];
                aad[0..2].copy_from_slice(&p_id.to_be_bytes());
                aad[2] = flags.bits() | (packet_type as u8);

                let mut payload = chunk.to_vec();
                let mac = encrypt_eax(&key, &nonce, &aad, &mut payload)?;

                let mut pkt = OutPacket::new_with_dir(Direction::S2C, flags, packet_type);
                pkt.packet_id(p_id);
                pkt.mac().copy_from_slice(&mac);
                pkt.data_mut().extend_from_slice(&payload);

                let res = self.socket.send_to(&pkt.into_vec(), peer).await;
                info!(
                    "Sent fragment {}/{} of encrypted command '{}' (p_id: {}) to {}: {:?}",
                    idx + 1,
                    total_chunks,
                    cmd_name,
                    p_id,
                    peer,
                    res
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init1_packet_format() {
        let r1 = [1u8; 16];
        let r0 = [2u8; 4];
        let init1 = OutS2CInit1::new(&r1, r0);
        let bytes = init1.into_vec();
        assert_eq!(&bytes[0..8], b"TS3INIT1");
    }

    #[test]
    fn test_init3_packet_format() {
        let x = [1u8; 64];
        let n = [2u8; 64];
        let level = 1;
        let r2 = [3u8; 100];
        let init3 = OutS2CInit3::new(&x, &n, level, &r2);
        let bytes = init3.into_vec();
        assert_eq!(&bytes[0..8], b"TS3INIT1");
    }

    #[test]
    fn test_inspect_s2c_expand() {
        let mut pkt =
            OutPacket::new_with_dir(Direction::S2C, Flags::UNENCRYPTED, PacketType::Command);
        pkt.packet_id(0);
        pkt.data_mut().extend_from_slice(b"initivexpand alpha=123");
        let bytes = pkt.into_vec();
        println!("bytes len={}: {:02x?}", bytes.len(), &bytes[..20]);
    }

    #[test]
    fn test_inspect_c2s_init() {
        let init0 = OutC2SInit0::new(0, 0, [1, 2, 3, 4]);
        let bytes = init0.into_vec();
        println!("Init0 len: {}, hex: {:02x?}", bytes.len(), &bytes[..]);
        assert_eq!(bytes.len(), 13 + 21);
    }

    #[test]
    fn test_out_of_order_reassembly() {
        use std::collections::BTreeMap;

        // Two-fragment command (official client layout: both flagged).
        let mut pending: BTreeMap<u16, (Flags, Vec<u8>)> = BTreeMap::new();
        let chunk1 = vec![b'A'; 480];
        let chunk2 = b" msg=hello".to_vec();
        pending.insert(3, (Flags::FRAGMENTED, chunk2.clone()));
        assert!(try_assemble_next(&mut pending, 2).is_none());

        pending.insert(2, (Flags::FRAGMENTED, chunk1.clone()));
        let (text, consumed) = try_assemble_next(&mut pending, 2).expect("complete command");
        assert_eq!(consumed, 2);
        let mut expected = String::from_utf8(chunk1).unwrap();
        expected.push_str(&String::from_utf8(chunk2).unwrap());
        assert_eq!(text, expected);
        assert!(pending.is_empty());

        // Three-fragment command: first flag, unflagged middle, last flag.
        let mut pending: BTreeMap<u16, (Flags, Vec<u8>)> = BTreeMap::new();
        pending.insert(10, (Flags::FRAGMENTED, b"aaa".to_vec()));
        pending.insert(11, (Flags::NEWPROTOCOL, b"bbb".to_vec()));
        pending.insert(
            12,
            (Flags::NEWPROTOCOL | Flags::FRAGMENTED, b"ccc".to_vec()),
        );
        let (text, consumed) = try_assemble_next(&mut pending, 10).expect("complete command");
        assert_eq!(text, "aaabbbccc");
        assert_eq!(consumed, 3);
        assert!(pending.is_empty());

        // Single-packet command.
        let mut pending: BTreeMap<u16, (Flags, Vec<u8>)> = BTreeMap::new();
        pending.insert(20, (Flags::NEWPROTOCOL, b"ping".to_vec()));
        let (text, consumed) = try_assemble_next(&mut pending, 20).unwrap();
        assert_eq!(text, "ping");
        assert_eq!(consumed, 1);
        assert!(pending.is_empty());
    }
}
