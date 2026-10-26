use base64::prelude::*;
use rand::Rng;
use std::collections::HashMap;
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

/// Channel passwords are stored as SHA-256 hex digests; the wire value the
/// client supplies in `cpw` is hashed the same way before comparison.
fn hash_channel_password(password: &str) -> String {
    let digest = sha2::Sha256::digest(password.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
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
        codec_is_unencrypted: parse_wire_bool(cmd.get("channel_codec_is_unencrypted")),
        ..ChannelEdit::default()
    };

    // Channel passwords: `channel_flag_password=0` clears, a non-empty
    // `channel_password` sets a new one, and the flag alone on a passworded
    // channel keeps the stored password (the official client does not resend
    // it when the dialog is left unchanged).
    let password_flag = parse_wire_bool(cmd.get("channel_flag_password"));
    let supplied_password = cmd.get("channel_password");
    match (password_flag, supplied_password) {
        (Some(false), _) => edit.password = Some(String::new()),
        (_, Some(pw)) if pw.is_empty() => edit.password = Some(String::new()),
        (_, Some(password)) => {
            edit.password = Some(hash_channel_password(password));
        }
        (Some(true), None) => {
            // Keep whatever is stored; the official client does not resend
            // the password when the dialog field is left unchanged.
        }
        _ => {}
    }

    if cmd.get("cpid").is_some_and(|parent| parent != "0") {
        return Err("subchannels are not supported".to_string());
    }
    // The voice relay passes codec frames through unchanged, so any codec the
    // client offers (Speex, CELT, Opus) works; the quality range is 0-10.
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
    notify.set(
        "channel_flag_password",
        bool_wire(!channel.password_hash.is_empty()),
    );
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
    notify.set(
        "channel_codec_is_unencrypted",
        bool_wire(channel.codec_is_unencrypted),
    );
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

fn build_channel_edited_notification(
    channel: &ChannelRecord,
    edit: &ChannelEdit,
    invoker_id: u16,
    invoker_name: &str,
    invoker_uid: &str,
) -> Command {
    let mut notify = Command::new("notifychanneledited");
    notify.set("cid", channel.cid.to_string());
    // `reasonid=10` is the protocol's Channeledit reason. The 3.6.2
    // client requires it before applying an edit notification.
    notify.set("reasonid", "10");
    notify.set("invokerid", invoker_id.to_string());
    notify.set("invokername", invoker_name);
    notify.set("invokeruid", invoker_uid);

    // Only broadcast fields that actually changed. Crucially, sending
    // `channel_name` when the name was not renamed makes the official client
    // validate uniqueness against its own channel map, fail with
    // "Error from ChanClients: channel name is already in use", and abort.
    if let Some(ref name) = edit.name {
        notify.set("channel_name", name);
    }
    if let Some(ref topic) = edit.topic {
        notify.set("channel_topic", topic);
    }
    if let Some(ref desc) = edit.description {
        notify.set("channel_description", desc);
    }
    if let Some(codec) = edit.codec {
        notify.set("channel_codec", codec.to_string());
    }
    if let Some(quality) = edit.codec_quality {
        notify.set("channel_codec_quality", quality.to_string());
    }
    if edit.order_after.is_some() {
        notify.set("channel_order", channel.order_id.to_string());
    }
    if let Some(perm) = edit.is_permanent {
        notify.set("channel_flag_permanent", bool_wire(perm));
    }
    if let Some(semi) = edit.is_semi_permanent {
        notify.set("channel_flag_semi_permanent", bool_wire(semi));
    }
    if let Some(def) = edit.is_default {
        notify.set("channel_flag_default", bool_wire(def));
    }
    if edit.password.is_some() {
        notify.set(
            "channel_flag_password",
            bool_wire(!channel.password_hash.is_empty()),
        );
    }
    if let Some(max_c) = edit.max_clients {
        notify.set("channel_maxclients", max_c.to_string());
    }
    if let Some(max_f) = edit.max_family_clients {
        notify.set("channel_maxfamilyclients", max_f.to_string());
    }
    if let Some(ntp) = edit.needed_talk_power {
        notify.set("channel_needed_talk_power", ntp.to_string());
    }
    if let Some(nsp) = edit.needed_subscribe_power {
        notify.set("channel_needed_subscribe_power", nsp.to_string());
    }
    if let Some(clf) = edit.codec_latency_factor {
        notify.set("channel_codec_latency_factor", clf.to_string());
    }
    if let Some(unenc) = edit.codec_is_unencrypted {
        notify.set("channel_codec_is_unencrypted", bool_wire(unenc));
    }
    if let Some(delay) = edit.delete_delay {
        notify.set("channel_delete_delay", delay.to_string());
    }
    if let Some(max_u) = edit.max_clients_unlimited {
        notify.set("channel_flag_maxclients_unlimited", bool_wire(max_u));
    }
    if let Some(max_fu) = edit.max_family_clients_unlimited {
        notify.set("channel_flag_maxfamilyclients_unlimited", bool_wire(max_fu));
    }
    if let Some(max_fi) = edit.max_family_clients_inherited {
        notify.set("channel_flag_maxfamilyclients_inherited", bool_wire(max_fi));
    }
    if let Some(ref phon) = edit.name_phonetic {
        notify.set("channel_name_phonetic", phon);
    }
    if let Some(icon) = edit.icon_id {
        notify.set("channel_icon_id", icon.to_string());
    }
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
        let payload = if first_flags.contains(Flags::COMPRESSED) {
            let mut cur = std::io::Cursor::new(&first_bytes);
            match quicklz::decompress(&mut cur, 65536) {
                Ok(decompressed) => decompressed,
                Err(e) => {
                    warn!("Failed to decompress single-packet command with QuickLZ: {:?}", e);
                    first_bytes
                }
            }
        } else {
            first_bytes
        };
        return Some((String::from_utf8_lossy(&payload).to_string(), 1));
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
                    let decompressed = if first_flags.contains(Flags::COMPRESSED) {
                        let mut cur = std::io::Cursor::new(&payload);
                        match quicklz::decompress(&mut cur, 65536) {
                            Ok(dec) => dec,
                            Err(e) => {
                                warn!("Failed to decompress fragmented command with QuickLZ: {:?}", e);
                                payload
                            }
                        }
                    } else {
                        payload
                    };
                    return Some((
                        String::from_utf8_lossy(&decompressed).to_string(),
                        ids.len() as u16,
                    ));
                }
                curr = next;
            }
            None => return None,
        }
    }
}

/// Builds a `notifyconnectioninfo` command for the "Client connection info"
/// dialog. Missing stats are filled with neutral defaults so the client's
/// mandatory-field parser never rejects the command; `connection_client_ip`
/// is only included when the requesting user is an admin.
/// Builds a `notifyconnectioninfo` snapshot. Reverse engineered from the
/// official TS3 client handler at 0x102af00 (ff9b30, ff9dc0, fab810): the
/// client strictly asserts the presence of all packet loss fields, idle
/// time, server/client address and port. Missing parameters make the client
/// abort with "parameter not found" and disconnect immediately.
/// Remote IP and port are provided when `include_ip` is true (e.g. Server
/// Admin or checking one's own connection info).
fn build_connection_info(
    target_clid: u16,
    stats: &std::collections::BTreeMap<String, String>,
    target_ip: &str,
    target_port: u16,
    connected_time_secs: u64,
    idle_time_ms: u64,
    include_ip: bool,
) -> Command {
    let mut cmd = Command::new("notifyconnectioninfo");
    cmd.set("clid", target_clid.to_string());

    // Integer metrics
    for name in [
        "connection_packets_sent_speech",
        "connection_packets_sent_keepalive",
        "connection_packets_sent_control",
        "connection_packets_sent_total",
        "connection_bytes_sent_speech",
        "connection_bytes_sent_keepalive",
        "connection_bytes_sent_control",
        "connection_bytes_sent_total",
        "connection_packets_received_speech",
        "connection_packets_received_keepalive",
        "connection_packets_received_control",
        "connection_packets_received_total",
        "connection_bytes_received_speech",
        "connection_bytes_received_keepalive",
        "connection_bytes_received_control",
        "connection_bytes_received_total",
        "connection_bandwidth_sent_last_second_speech",
        "connection_bandwidth_sent_last_second_keepalive",
        "connection_bandwidth_sent_last_second_control",
        "connection_bandwidth_sent_last_second_total",
        "connection_bandwidth_sent_last_minute_speech",
        "connection_bandwidth_sent_last_minute_keepalive",
        "connection_bandwidth_sent_last_minute_control",
        "connection_bandwidth_sent_last_minute_total",
        "connection_bandwidth_received_last_second_speech",
        "connection_bandwidth_received_last_second_keepalive",
        "connection_bandwidth_received_last_second_control",
        "connection_bandwidth_received_last_second_total",
        "connection_bandwidth_received_last_minute_speech",
        "connection_bandwidth_received_last_minute_keepalive",
        "connection_bandwidth_received_last_minute_control",
        "connection_bandwidth_received_last_minute_total",
        "connection_filetransfer_bandwidth_sent",
        "connection_filetransfer_bandwidth_received",
        "connection_filetransfer_bytes_sent_total",
        "connection_filetransfer_bytes_received_total",
    ] {
        cmd.set(name, stats.get(name).map(|s| s.as_str()).unwrap_or("0"));
    }

    // Floating-point metrics and packet loss
    for name in [
        "connection_ping",
        "connection_ping_deviation",
        "connection_packetloss_speech",
        "connection_packetloss_keepalive",
        "connection_packetloss_control",
        "connection_packetloss_total",
        "connection_server2client_packetloss_speech",
        "connection_server2client_packetloss_keepalive",
        "connection_server2client_packetloss_control",
        "connection_server2client_packetloss_total",
        "connection_client2server_packetloss_speech",
        "connection_client2server_packetloss_keepalive",
        "connection_client2server_packetloss_control",
        "connection_client2server_packetloss_total",
    ] {
        cmd.set(name, stats.get(name).map(|s| s.as_str()).unwrap_or("0.0000"));
    }

    cmd.set(
        "connection_server_ip",
        stats
            .get("connection_server_ip")
            .map(|s| s.as_str())
            .unwrap_or("127.0.0.1"),
    );
    cmd.set(
        "connection_server_port",
        stats
            .get("connection_server_port")
            .map(|s| s.as_str())
            .unwrap_or("9988"),
    );
    cmd.set(
        "connection_connected_time",
        stats
            .get("connection_connected_time")
            .cloned()
            .unwrap_or_else(|| connected_time_secs.to_string()),
    );
    cmd.set(
        "connection_idle_time",
        stats
            .get("connection_idle_time")
            .cloned()
            .unwrap_or_else(|| idle_time_ms.to_string()),
    );

    if include_ip {
        cmd.set("connection_client_ip", target_ip);
        cmd.set("connection_client_port", target_port.to_string());
    } else {
        cmd.set("connection_client_ip", "");
        cmd.set("connection_client_port", "0");
    }

    cmd
}

/// Builds a `notifyserverupdated` command. The official client
/// Builds a `notifyserverupdated` command. The official client
/// rejects the message when any of these parameters is missing.
fn build_server_updated(
    ask_for_privilegekey: bool,
    port: u16,
    props: &HashMap<String, String>,
) -> Command {
    let mut cmd = Command::new("notifyserverupdated");
    cmd.set(
        "virtualserver_name",
        props
            .get("virtualserver_name")
            .map(|s| s.as_str())
            .unwrap_or("Nano-TS3 Minimal Server"),
    );
    cmd.set(
        "virtualserver_welcomemessage",
        props
            .get("virtualserver_welcomemessage")
            .map(|s| s.as_str())
            .unwrap_or("Welcome to Nano-TS3 Server!"),
    );
    cmd.set(
        "virtualserver_maxclients",
        props
            .get("virtualserver_maxclients")
            .map(|s| s.as_str())
            .unwrap_or("32"),
    );
    // Nano-TS3 relays both plaintext and EAX-encrypted codec payloads.
    // Mode 0 (individual) lets the client choose per channel via the
    // "Voice Data encrypted" toggle; mode 1 (forced off) greys it out.
    cmd.set(
        "virtualserver_codec_encryption_mode",
        props
            .get("virtualserver_codec_encryption_mode")
            .map(|s| s.as_str())
            .unwrap_or("0"),
    );
    cmd.set("virtualserver_clientsonline", "1");
    cmd.set("virtualserver_channelsonline", "1");
    cmd.set("virtualserver_uptime", "1000");
    cmd.set(
        "virtualserver_hostmessage",
        props
            .get("virtualserver_hostmessage")
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    cmd.set(
        "virtualserver_hostmessage_mode",
        props
            .get("virtualserver_hostmessage_mode")
            .map(|s| s.as_str())
            .unwrap_or("0"),
    );
    cmd.set(
        "virtualserver_flag_password",
        props
            .get("virtualserver_flag_password")
            .map(|s| s.as_str())
            .unwrap_or("0"),
    );
    cmd.set(
        "virtualserver_default_channel_admin_group",
        props
            .get("virtualserver_default_channel_admin_group")
            .map(|s| s.as_str())
            .unwrap_or("5"),
    );
    cmd.set(
        "virtualserver_default_server_group",
        props
            .get("virtualserver_default_server_group")
            .map(|s| s.as_str())
            .unwrap_or("8"),
    );
    cmd.set(
        "virtualserver_default_channel_group",
        props
            .get("virtualserver_default_channel_group")
            .map(|s| s.as_str())
            .unwrap_or("8"),
    );
    cmd.set(
        "virtualserver_hostbanner_url",
        props
            .get("virtualserver_hostbanner_url")
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    cmd.set(
        "virtualserver_hostbanner_gfx_url",
        props
            .get("virtualserver_hostbanner_gfx_url")
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    cmd.set(
        "virtualserver_hostbanner_gfx_interval",
        props
            .get("virtualserver_hostbanner_gfx_interval")
            .map(|s| s.as_str())
            .unwrap_or("0"),
    );
    cmd.set(
        "virtualserver_hostbanner_mode",
        props
            .get("virtualserver_hostbanner_mode")
            .map(|s| s.as_str())
            .unwrap_or("0"),
    );
    cmd.set(
        "virtualserver_hostbutton_tooltip",
        props
            .get("virtualserver_hostbutton_tooltip")
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    cmd.set(
        "virtualserver_hostbutton_url",
        props
            .get("virtualserver_hostbutton_url")
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    cmd.set(
        "virtualserver_hostbutton_gfx_url",
        props
            .get("virtualserver_hostbutton_gfx_url")
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    cmd.set(
        "virtualserver_icon_id",
        props
            .get("virtualserver_icon_id")
            .map(|s| s.as_str())
            .unwrap_or("0"),
    );
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
    cmd.set(
        "virtualserver_antiflood_points_tick_reduce",
        props
            .get("virtualserver_antiflood_points_tick_reduce")
            .map(|s| s.as_str())
            .unwrap_or("5"),
    );
    cmd.set(
        "virtualserver_antiflood_points_needed_command_block",
        props
            .get("virtualserver_antiflood_points_needed_command_block")
            .map(|s| s.as_str())
            .unwrap_or("150"),
    );
    cmd.set(
        "virtualserver_antiflood_points_needed_ip_block",
        props
            .get("virtualserver_antiflood_points_needed_ip_block")
            .map(|s| s.as_str())
            .unwrap_or("250"),
    );
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
    cmd.set(
        "virtualserver_needed_identity_security_level",
        props
            .get("virtualserver_needed_identity_security_level")
            .map(|s| s.as_str())
            .unwrap_or("8"),
    );
    cmd.set(
        "virtualserver_log_client",
        props
            .get("virtualserver_log_client")
            .map(|s| s.as_str())
            .unwrap_or("1"),
    );
    cmd.set(
        "virtualserver_log_query",
        props
            .get("virtualserver_log_query")
            .map(|s| s.as_str())
            .unwrap_or("1"),
    );
    cmd.set(
        "virtualserver_log_channel",
        props
            .get("virtualserver_log_channel")
            .map(|s| s.as_str())
            .unwrap_or("1"),
    );
    cmd.set(
        "virtualserver_log_permissions",
        props
            .get("virtualserver_log_permissions")
            .map(|s| s.as_str())
            .unwrap_or("1"),
    );
    cmd.set(
        "virtualserver_log_server",
        props
            .get("virtualserver_log_server")
            .map(|s| s.as_str())
            .unwrap_or("1"),
    );
    cmd.set(
        "virtualserver_log_filetransfer",
        props
            .get("virtualserver_log_filetransfer")
            .map(|s| s.as_str())
            .unwrap_or("1"),
    );
    cmd.set(
        "virtualserver_min_client_version",
        props
            .get("virtualserver_min_client_version")
            .map(|s| s.as_str())
            .unwrap_or("1560850141"),
    );
    cmd.set(
        "virtualserver_reserved_slots",
        props
            .get("virtualserver_reserved_slots")
            .map(|s| s.as_str())
            .unwrap_or("0"),
    );
    cmd.set("virtualserver_total_packetloss_speech", "0");
    cmd.set("virtualserver_total_packetloss_keepalive", "0");
    cmd.set("virtualserver_total_packetloss_control", "0");
    cmd.set("virtualserver_total_packetloss_total", "0");
    cmd.set("virtualserver_total_ping", "0");
    cmd.set(
        "virtualserver_weblist_enabled",
        props
            .get("virtualserver_weblist_enabled")
            .map(|s| s.as_str())
            .unwrap_or("1"),
    );
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
        info!("Nano-TS3 Server v{} UDP server listening on {}", env!("CARGO_PKG_VERSION"), socket.local_addr()?);
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
        // Periodic keepalive sweep: probe every connected client with a
        // server-side ping and drop sessions that have gone silent. Without
        // this, a hung or crashed client lingers in every other user's view
        // until it happens to be swept by unrelated incoming traffic.
        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(5));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buf) => {
                    let (len, peer) = match received {
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
                _ = keepalive.tick() => {
                    self.keepalive_sweep().await;
                }
            }
        }
    }

    /// Pings every connected client and times out sessions that have not sent
    /// anything for `IDLE_TIMEOUT`. Vanished connected clients are announced
    /// to the rest with the official `reasonid=3 connection lost` left view.
    async fn keepalive_sweep(&self) {
        // Probe: an unencrypted ping carrying the session's shared MAC, the
        // same shape the server already uses to answer client pings. Alive
        // clients respond (ack/pong), which refreshes their last_activity.
        let targets: Vec<(SocketAddr, u16, [u8; 8])> = {
            let state = self.state.lock().await;
            state
                .clients
                .values()
                .filter(|c| c.handshake_phase == HandshakePhase::Connected)
                .filter_map(|c| {
                    c.shared_iv.map(|siv| {
                        let mac: [u8; 8] = Sha1::digest(&siv)[..8].try_into().unwrap();
                        (c.endpoint, c.clid, mac)
                    })
                })
                .collect()
        };

        for (ep, _clid, mac) in targets {
            let p_id = {
                let mut state = self.state.lock().await;
                match state.get_client_mut(&ep) {
                    Some(c) => {
                        let id = c.next_s2c_ping_packet_id;
                        c.next_s2c_ping_packet_id = id.wrapping_add(1);
                        id
                    }
                    None => continue,
                }
            };
            let mut ping = OutAck::new(Direction::S2C, PacketType::Ping, p_id);
            ping.flags(Flags::UNENCRYPTED);
            ping.mac().copy_from_slice(&mac);
            let _ = self.socket.send_to(&ping.into_vec(), ep).await;
        }

        let disappeared = {
            let mut state = self.state.lock().await;
            state.cleanup_stale()
        };
        for (gone_clid, gone_cid) in disappeared {
            info!(
                "Client {} timed out (no packets received within idle timeout)",
                gone_clid
            );
            self.broadcast_client_left(gone_clid, gone_cid, "3", "connection lost")
                .await;
        }
    }

    /// Endpoints of connected clients that watch any of `cids` (through
    /// their channel subscriptions). Notifications that reference a client
    /// must only reach clients whose view can contain it, otherwise the
    /// official client aborts with "invalid clientID".
    async fn watching_recipients(
        &self,
        cids: &[u64],
        exclude: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let state = self.state.lock().await;
        state
            .clients
            .values()
            .filter(|c| {
                c.handshake_phase == HandshakePhase::Connected
                    && exclude.map_or(true, |ep| c.endpoint != ep)
                    && cids.iter().any(|cid| c.subscribed_channels.contains(cid))
            })
            .map(|c| c.endpoint)
            .collect()
    }

    /// Recipients for a channel switch `from_cid -> to_cid` of a client:
    /// watchers of `from_cid` already know the mover (they get the moved
    /// notification), watchers of only `to_cid` have never seen it (they get
    /// an enter view instead).
    async fn move_recipients(
        &self,
        from_cid: u64,
        to_cid: u64,
        exclude: SocketAddr,
    ) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
        let state = self.state.lock().await;
        let mut moved = Vec::new();
        let mut entered = Vec::new();
        for c in state.clients.values() {
            if c.endpoint == exclude || c.handshake_phase != HandshakePhase::Connected {
                continue;
            }
            if c.subscribed_channels.contains(&from_cid) {
                moved.push(c.endpoint);
            } else if c.subscribed_channels.contains(&to_cid) {
                entered.push(c.endpoint);
            }
        }
        (moved, entered)
    }

    /// Sends the subscriber fresh enter views (reasonid=2, Subscription) for
    /// every connected client in the given channels except the subscriber
    /// itself and clients the subscriber already has in view. The official
    /// client aborts with "Already known Client entering" if it receives a
    /// duplicate enter view for a client it already knows.
    async fn send_subscription_enter_views(&self, peer: SocketAddr, own_clid: u16, channels: &[u64]) {
        if channels.is_empty() {
            return;
        }
        let occupants: Vec<(u16, String, String, u64, bool, ClientAudioState)> = {
            let mut state = self.state.lock().await;
            let known = match state.get_client(&peer) {
                Some(c) => c.known_clients.clone(),
                None => return,
            };
            let mut to_send = Vec::new();
            for c in state.clients.values() {
                if c.handshake_phase == HandshakePhase::Connected
                    && c.clid != own_clid
                    && channels.contains(&c.current_channel_id)
                    && !known.contains(&c.clid)
                {
                    to_send.push((
                        c.clid,
                        c.uid.clone(),
                        c.nickname.clone(),
                        c.current_channel_id,
                        c.is_admin,
                        c.audio,
                    ));
                }
            }
            if let Some(c) = state.get_client_mut(&peer) {
                for (clid, ..) in &to_send {
                    c.known_clients.insert(*clid);
                }
            }
            to_send
        };
        for (clid, uid, nickname, cid, is_admin, audio) in occupants {
            let view = build_client_enter_view("2", clid, &uid, &nickname, cid, 0, is_admin, audio);
            let _ = self.send_encrypted_command(peer, &view).await;
        }
    }

    /// Tell every connected client that `gone_clid` left the server.
    /// Matches the official format captured for timeouts:
    /// `notifyclientleftview cfid=<cid> ctid=0 reasonid=3 reasonmsg=connection lost clid=<id>`.
    async fn broadcast_client_left(
        &self,
        gone_clid: u16,
        gone_cid: u64,
        reasonid: &str,
        reasonmsg: &str,
    ) {
        let recipients = self.watching_recipients(&[gone_cid], None).await;
        let mut notify = Command::new("notifyclientleftview");
        notify.set("clid", gone_clid.to_string());
        notify.set("cfid", gone_cid.to_string());
        notify.set("ctid", "0");
        notify.set("reasonid", reasonid);
        notify.set("reasonmsg", reasonmsg);
        for ep in &recipients {
            let _ = self.send_encrypted_command(*ep, &notify).await;
        }
        {
            let mut state = self.state.lock().await;
            for ep in &recipients {
                if let Some(c) = state.get_client_mut(ep) {
                    c.known_clients.remove(&gone_clid);
                }
            }
        }
        info!(
            "Broadcast left view for vanished client {} (reason {})",
            gone_clid, reasonid
        );
    }

    /// Tell every connected client that the server is going away so the
    /// official client disconnects immediately instead of waiting for its
    /// keepalive timeout. Captured from the official 3.13.7 server on
    /// `serverstop`: it sends each client its own left view with reasonid 11
    /// (`ClientdisconnectServerShutdown`) and reasonmsg "Server Shutdown!".
    /// (reasonid 7 is rejected by the 3.6.2 client with "invalid parameter".)
    pub async fn shutdown(&self) {
        let targets: Vec<(SocketAddr, u16, u64)> = {
            let mut state = self.state.lock().await;
            state
                .clients
                .values_mut()
                .filter(|c| c.handshake_phase == HandshakePhase::Connected)
                .map(|c| (c.endpoint, c.clid, c.current_channel_id))
                .collect()
        };

        for (ep, target_clid, cid) in targets {
            let mut notify = Command::new("notifyclientleftview");
            notify.set("clid", target_clid.to_string());
            notify.set("cfid", cid.to_string());
            notify.set("ctid", "0");
            notify.set("reasonid", "11");
            notify.set("reasonmsg", "Server Shutdown!");
            let _ = self.send_encrypted_command(ep, &notify).await;

            let mut state = self.state.lock().await;
            if let Some(c) = state.clients.get_mut(&ep) {
                c.handshake_phase = HandshakePhase::Disconnected;
                c.disconnect_time = Some(std::time::Instant::now());
            }
            info!("Notified client {} of server shutdown", target_clid);
        }

        // Give the final packets a moment to flush before the process exits.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    async fn handle_packet(&self, peer: SocketAddr, data: &[u8]) -> Result<(), String> {
        let in_pkt = match InPacket::try_new(Direction::C2S, data) {
            Ok(pkt) => pkt,
            Err(e) => return Err(format!("Invalid packet from {}: {:?}", peer, e)),
        };

        let p_type = in_pkt.header().packet_type();
        let p_id = in_pkt.header().packet_id();

        let disappeared = {
            let mut state = self.state.lock().await;
            let disappeared = state.cleanup_stale();
            if let Some(c) = state.get_client_mut(&peer) {
                c.last_activity = std::time::Instant::now();
            }
            disappeared
        };

        // Sessions that vanished without a disconnect must be announced as
        // gone, or every client still holding their clid in view will
        // reject later notifications about it ("invalid clientID").
        for (gone_clid, gone_cid) in disappeared {
            self.broadcast_client_left(gone_clid, gone_cid, "3", "connection lost")
                .await;
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
        let mut replaced_connected: Option<(u16, u64)> = None;

        match c2s_init.data() {
            C2SInitData::Init0 { random0, .. } => {
                info!("Handshake Init0 from {}", peer);
                // If this endpoint replaces a fully connected session (the
                // old connection died without a disconnect), remember it so
                // we can announce its departure after the handshake reply.
                if let Some(old) = state.get_client(&peer) {
                    if old.handshake_phase == HandshakePhase::Connected {
                        replaced_connected = Some((old.clid, old.current_channel_id));
                    }
                }
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

        drop(state);

        if let Some((old_clid, old_cid)) = replaced_connected {
            self.broadcast_client_left(old_clid, old_cid, "3", "connection lost")
                .await;
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

            // The Command and CommandLow packet types carry independent
            // packet-id sequences (the official client sends e.g. clientpoke
            // on CommandLow starting at pid 0). Track them separately;
            // sharing one tracker drops every low packet as a stale
            // "retransmission".
            let is_low = p_type == PacketType::CommandLow;
            let expected = if is_low {
                client.expected_c2s_low_packet_id
            } else {
                client.expected_c2s_packet_id
            };

            // Detect duplicate retransmissions (older than the expected id)
            let diff = p_id.wrapping_sub(expected);
            if diff > 32768 {
                debug!(
                    "Ignoring retransmitted {} packet {} for clid {} (expected {})",
                    if is_low { "low" } else { "command" },
                    p_id,
                    clid,
                    expected
                );
                return Ok(());
            }

            {
                let pending = if is_low {
                    &mut client.pending_low_packets
                } else {
                    &mut client.pending_packets
                };
                pending.insert(p_id, (flags, decrypted_bytes));
            }

            loop {
                let (cmd_text, consumed) = if is_low {
                    let expected_low = client.expected_c2s_low_packet_id;
                    match try_assemble_next(&mut client.pending_low_packets, expected_low) {
                        Some((text, consumed)) => {
                            client.expected_c2s_low_packet_id =
                                expected_low.wrapping_add(consumed);
                            (text, consumed)
                        }
                        None => break,
                    }
                } else {
                    let expected_cmd = client.expected_c2s_packet_id;
                    match try_assemble_next(&mut client.pending_packets, expected_cmd) {
                        Some((text, consumed)) => {
                            client.expected_c2s_packet_id =
                                expected_cmd.wrapping_add(consumed);
                            (text, consumed)
                        }
                        None => break,
                    }
                };
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

                let props = {
                    let db = self.db.lock().await;
                    db.get_all_properties().unwrap_or_default()
                };

                let flag_pw = props
                    .get("virtualserver_flag_password")
                    .map(|s| s.as_str())
                    .unwrap_or("0");
                let server_pw_hash = props
                    .get("virtualserver_password")
                    .map(|s| s.as_str())
                    .unwrap_or("");

                if flag_pw == "1" && !server_pw_hash.is_empty() {
                    let has_pw_bypass = is_admin || {
                        let db = self.db.lock().await;
                        permissions::has_permission(
                            &db,
                            &uid,
                            0,
                            "b_virtualserver_join_ignore_password",
                        )
                    };
                    if !has_pw_bypass {
                        let client_pw = cmd
                            .get("serverpassword")
                            .or_else(|| cmd.get("password"))
                            .unwrap_or("");
                        let mut hasher = Sha1::new();
                        hasher.update(client_pw.as_bytes());
                        let client_hash = BASE64_STANDARD.encode(hasher.finalize());
                        if client_hash != server_pw_hash && client_pw != server_pw_hash {
                            info!("Client {} failed server password verification", clid);
                            let mut err_resp = Command::new("error");
                            err_resp.set("id", "520");
                            err_resp.set("msg", "invalid server password");
                            if let Some(rc) = cmd.get("return_code") {
                                err_resp.set("return_code", rc);
                            }
                            self.send_encrypted_command(peer, &err_resp).await?;
                            return Ok(());
                        }
                    }
                }

                // 1. initserver
                let mut initserver = Command::new("initserver");
                initserver.set(
                    "virtualserver_name",
                    props
                        .get("virtualserver_name")
                        .map(|s| s.as_str())
                        .unwrap_or("Nano-TS3 Minimal Server"),
                );
                initserver.set(
                    "virtualserver_welcomemessage",
                    props
                        .get("virtualserver_welcomemessage")
                        .map(|s| s.as_str())
                        .unwrap_or("Welcome to Nano-TS3 Server!"),
                );
                initserver.set("virtualserver_platform", "Linux");
                initserver.set("virtualserver_version", "3.13.8 [Build: 1685172871]");
                initserver.set(
                    "virtualserver_maxclients",
                    props
                        .get("virtualserver_maxclients")
                        .map(|s| s.as_str())
                        .unwrap_or("32"),
                );
                initserver.set("virtualserver_created", "1600000000");
                initserver.set(
                    "virtualserver_codec_encryption_mode",
                    props
                        .get("virtualserver_codec_encryption_mode")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                initserver.set(
                    "virtualserver_hostmessage",
                    props
                        .get("virtualserver_hostmessage")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                initserver.set(
                    "virtualserver_hostmessage_mode",
                    props
                        .get("virtualserver_hostmessage_mode")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                initserver.set(
                    "virtualserver_default_server_group",
                    props
                        .get("virtualserver_default_server_group")
                        .map(|s| s.as_str())
                        .unwrap_or("8"),
                );
                initserver.set(
                    "virtualserver_default_channel_group",
                    props
                        .get("virtualserver_default_channel_group")
                        .map(|s| s.as_str())
                        .unwrap_or("8"),
                );
                initserver.set(
                    "virtualserver_default_channel_admin_group",
                    props
                        .get("virtualserver_default_channel_admin_group")
                        .map(|s| s.as_str())
                        .unwrap_or("5"),
                );
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
                initserver.set(
                    "virtualserver_flag_password",
                    flag_pw,
                );
                initserver.set(
                    "virtualserver_hostbanner_url",
                    props
                        .get("virtualserver_hostbanner_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                initserver.set(
                    "virtualserver_hostbanner_gfx_url",
                    props
                        .get("virtualserver_hostbanner_gfx_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                initserver.set(
                    "virtualserver_hostbanner_gfx_interval",
                    props
                        .get("virtualserver_hostbanner_gfx_interval")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                initserver.set(
                    "virtualserver_hostbanner_mode",
                    props
                        .get("virtualserver_hostbanner_mode")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                initserver.set(
                    "virtualserver_priority_speaker_dimm_modificator",
                    "-18.0000",
                );
                initserver.set(
                    "virtualserver_hostbutton_tooltip",
                    props
                        .get("virtualserver_hostbutton_tooltip")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                initserver.set(
                    "virtualserver_hostbutton_url",
                    props
                        .get("virtualserver_hostbutton_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                initserver.set(
                    "virtualserver_hostbutton_gfx_url",
                    props
                        .get("virtualserver_hostbutton_gfx_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                initserver.set(
                    "virtualserver_name_phonetic",
                    props
                        .get("virtualserver_name_phonetic")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                initserver.set(
                    "virtualserver_icon_id",
                    props
                        .get("virtualserver_icon_id")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
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
                // Official 3.13.7 sends protocol version 7 here (captured via
                // MITM); the client gates server-feature behavior on it.
                initserver.set("pv", "7");
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
                // The connect flow above hands the newcomer every existing
                // client's view, so mirror that in its own subscription
                // state: it is effectively subscribed to every channel until
                // it explicitly changes that.
                {
                    let all_cids = {
                        let db = self.db.lock().await;
                        db.get_channels()
                            .unwrap_or_default()
                            .into_iter()
                            .map(|ch| ch.cid)
                            .collect::<Vec<_>>()
                    };
                    let mut state = self.state.lock().await;
                    if let Some(c) = state.get_client_mut(&peer) {
                        c.subscribed_channels.extend(all_cids);
                    }
                }

                let newcomer_view =
                    build_client_enter_view("0", clid, &uid, &nickname, 1, 0, is_admin, audio);
                let other_endpoints = self.watching_recipients(&[1], Some(peer)).await;
                for ep in &other_endpoints {
                    let _ = self.send_encrypted_command(*ep, &newcomer_view).await;
                    let _ = self.send_encrypted_raw(*ep, &format!("notifyclientpermhints clid={} flags=65535", clid)).await;
                }

                {
                    let mut state = self.state.lock().await;
                    if let Some(c) = state.get_client_mut(&peer) {
                        c.known_clients.insert(clid);
                        for (other_clid, ..) in &existing_clients {
                            c.known_clients.insert(*other_clid);
                        }
                    }
                    for ep in &other_endpoints {
                        if let Some(c) = state.get_client_mut(ep) {
                            c.known_clients.insert(clid);
                        }
                    }
                }

                // 6. Publish channel-group names, followed by the baseline
                // permission requirements that the client uses for actions.
                self.send_channel_group_list(peer, true).await?;
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
                self.send_channel_group_perm_list(peer, 8, false).await?;
                if is_admin {
                    self.send_channel_group_perm_list(peer, 5, false).await?;
                }

                // Send channel and client permission hints to enable client
                // UI buttons (menu actions are gated on these; without them
                // even the Poke menu item does nothing).
                let channels = {
                    let db = self.db.lock().await;
                    db.get_channels().unwrap_or_default()
                };
                if !channels.is_empty() {
                    let mut ch_hints_wire = String::from("notifychannelpermhints ");
                    for (i, ch) in channels.iter().enumerate() {
                        if i > 0 {
                            ch_hints_wire.push('|');
                        }
                        let flags = if ch.is_default { "1027" } else { "65535" };
                        ch_hints_wire.push_str(&format!("cid={} flags={}", ch.cid, flags));
                    }
                    self.send_encrypted_raw(peer, &ch_hints_wire).await?;
                }

                let mut cl_hints_wire = String::from("notifyclientpermhints ");
                cl_hints_wire.push_str(&format!("clid={} flags=65535", clid));
                for (other_clid, ..) in &existing_clients {
                    cl_hints_wire.push_str(&format!("|clid={} flags=65535", other_clid));
                }
                self.send_encrypted_raw(peer, &cl_hints_wire).await?;

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

                let (notification_name, notification_ids, own_clid) = {
                    let mut state = self.state.lock().await;
                    match state.get_client_mut(&peer) {
                        Some(client) if subscribe => {
                            let own_clid = client.clid;
                            // Only channels that are genuinely new to this
                            // client's subscription get a notification and a
                            // re-announcement of their users; re-sending
                            // enter views for clients the receiver already
                            // knows aborts it ("Already known Client
                            // entering").
                            let newly: Vec<u64> = channel_ids
                                .iter()
                                .copied()
                                .filter(|cid| client.subscribed_channels.insert(*cid))
                                .collect();
                            ("notifychannelsubscribed", newly, Some(own_clid))
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
                            ("notifychannelunsubscribed", unsubscribe_ids, None)
                        }
                        None => ("notifychannelunsubscribed", Vec::new(), None),
                    }
                };

                if !notification_ids.is_empty() {
                    let wire = build_channel_subscription_notification(
                        notification_name,
                        &notification_ids,
                    );
                    self.send_encrypted_raw(peer, &wire).await?;
                }

                if subscribe {
                    if let Some(own_clid) = own_clid {
                        self.send_subscription_enter_views(peer, own_clid, &notification_ids)
                            .await;
                    }
                } else if !notification_ids.is_empty() {
                    let mut state = self.state.lock().await;
                    let to_remove: Vec<u16> = state
                        .clients
                        .values()
                        .filter(|c| c.endpoint != peer && notification_ids.contains(&c.current_channel_id))
                        .map(|c| c.clid)
                        .collect();
                    if let Some(client) = state.get_client_mut(&peer) {
                        for clid in to_remove {
                            client.known_clients.remove(&clid);
                        }
                    }
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

                let (notification_name, notification_ids, own_clid) = {
                    let mut state = self.state.lock().await;
                    match state.get_client_mut(&peer) {
                        Some(client) if subscribe => {
                            let own_clid = client.clid;
                            let mut newly_subscribed = Vec::new();
                            for cid in requested {
                                if client.subscribed_channels.insert(cid) {
                                    newly_subscribed.push(cid);
                                }
                            }
                            ("notifychannelsubscribed", newly_subscribed, Some(own_clid))
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
                            ("notifychannelunsubscribed", unsubscribe_ids, None)
                        }
                        None => ("notifychannelunsubscribed", Vec::new(), None),
                    }
                };

                if !notification_ids.is_empty() {
                    let wire = build_channel_subscription_notification(
                        notification_name,
                        &notification_ids,
                    );
                    self.send_encrypted_raw(peer, &wire).await?;
                }

                if subscribe {
                    if let Some(own_clid) = own_clid {
                        self.send_subscription_enter_views(peer, own_clid, &notification_ids)
                            .await;
                    }
                } else if !notification_ids.is_empty() {
                    let mut state = self.state.lock().await;
                    let to_remove: Vec<u16> = state
                        .clients
                        .values()
                        .filter(|c| c.endpoint != peer && notification_ids.contains(&c.current_channel_id))
                        .map(|c| c.clid)
                        .collect();
                    if let Some(client) = state.get_client_mut(&peer) {
                        for clid in to_remove {
                            client.known_clients.remove(&clid);
                        }
                    }
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
                // `invokeruid` is mandatory: the official client aborts the
                // connection with "parameter not found" when it is missing
                // (observed with 3.6.2 against every channel/private/server
                // message before the fix).
                let (nickname, invoker_uid) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.nickname.clone(), c.uid.clone()))
                        .unwrap_or_else(|| ("User".into(), String::new()))
                };

                let mut notify = Command::new("notifytextmessage");
                notify.set("targetmode", target_mode);
                notify.set("msg", msg);
                notify.set("invokerid", clid.to_string());
                notify.set("invokername", &nickname);
                notify.set("invokeruid", &invoker_uid);

                // targetmode 1 (private) goes to the `target` client(s) plus an
                // echo to the sender; 2 to the whole current channel; 3 to the
                // whole server.
                let mut err_resp = Command::new("error");
                if target_mode == "1" {
                    let targets: Vec<u16> = cmd
                        .get("target")
                        .map(|value| {
                            value
                                .split('|')
                                .filter_map(|part| part.parse::<u16>().ok())
                                .collect()
                        })
                        .unwrap_or_default();
                    let target_clients: Vec<(u16, SocketAddr)> = {
                        let state = self.state.lock().await;
                        targets
                            .iter()
                            .filter_map(|target| {
                                state
                                    .clients
                                    .values()
                                    .find(|c| {
                                        c.clid == *target
                                            && c.handshake_phase == HandshakePhase::Connected
                                    })
                                    .map(|c| (*target, c.endpoint))
                            })
                            .collect()
                    };
                    if target_clients.is_empty() {
                        err_resp.set("id", "512");
                        err_resp.set("msg", "invalid clientID");
                    } else {
                        for (target_clid, ep) in &target_clients {
                            let mut target_notify = notify.clone();
                            target_notify.set("target", target_clid.to_string());
                            let _ = self.send_encrypted_command(*ep, &target_notify).await;
                        }
                        // Sender echo
                        let mut echo_notify = notify.clone();
                        let target_str = cmd.get("target").unwrap_or("");
                        echo_notify.set("target", target_str);
                        let _ = self.send_encrypted_command(peer, &echo_notify).await;

                        err_resp.set("id", "0");
                        err_resp.set("msg", "ok");
                    }
                } else {
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
                            state
                                .clients
                                .values()
                                .filter(|c| c.handshake_phase == HandshakePhase::Connected)
                                .map(|c| c.endpoint)
                                .collect()
                        }
                    };

                    for ep in endpoints {
                        let _ = self.send_encrypted_command(ep, &notify).await;
                    }

                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await;
            }
            "clientmove" => {
                let new_cid: u64 = cmd.get("cid").and_then(|s| s.parse().ok()).unwrap_or(1);
                // The official client addresses the moved client with `clid`
                // (`clientmove clid=5|clid=6 cid=3`); when an admin moves
                // another user ("Move client to channel" / "Move client to own
                // channel"), the target must be honored instead of the sender.
                // A command without `clid` moves the sender itself (channel
                // double-click keeps this form).
                let mut target_clids: Vec<u16> = cmd
                    .get("clid")
                    .map(|value| {
                        value
                            .split('|')
                            .filter_map(|part| part.parse::<u16>().ok())
                            .map(|id| if id == 0 { clid } else { id })
                            .collect()
                    })
                    .unwrap_or_default();
                if target_clids.is_empty() {
                    target_clids.push(clid);
                }

                let (sender_nick, sender_uid, sender_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.nickname.clone(), c.uid.clone(), c.is_admin))
                        .unwrap_or_else(|| ("User".to_string(), String::new(), false))
                };

                // Moving another client requires move power.
                let moves_others = target_clids.iter().any(|t| *t != clid);
                let can_move = !moves_others || sender_admin || {
                    let db = self.db.lock().await;
                    let move_power = permissions::get_power(&db, &sender_uid, 0, "i_client_move_power");
                    move_power >= 50
                };
                let mut err_resp = Command::new("error");
                if !can_move {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "43"); // i_client_move_power
                } else {
                    // Channel properties for the join checks: password and
                    // max clients.
                    let (channel_password, max_clients, max_unlimited) = {
                        let db = self.db.lock().await;
                        match db
                            .get_channels()
                            .unwrap_or_default()
                            .into_iter()
                            .find(|ch| ch.cid == new_cid)
                        {
                            Some(ch) => (ch.password_hash, ch.max_clients, ch.max_clients_unlimited),
                            None => (String::new(), -1, true),
                        }
                    };

                    // Joining a password-protected channel requires the right
                    // `cpw` for self-moves. Admin-driven moves or b_channel_join_ignore_password bypass it.
                    let is_password_ok = if channel_password.is_empty() {
                        true
                    } else if {
                        let db = self.db.lock().await;
                        permissions::has_permission(&db, &sender_uid, new_cid, "b_channel_join_ignore_password")
                    } {
                        true
                    } else {
                        cmd.get("cpw")
                            .filter(|pw| !pw.is_empty())
                            .map(|pw| hash_channel_password(pw) == channel_password)
                            .unwrap_or(false)
                    };

                    let can_join_power = sender_admin || {
                        let db = self.db.lock().await;
                        let needed_join = permissions::get_power(&db, &sender_uid, new_cid, "i_channel_needed_join_power");
                        let join_power = permissions::get_power(&db, &sender_uid, new_cid, "i_channel_join_power");
                        join_power >= needed_join
                    };

                    if !can_join_power {
                        err_resp.set("id", "2568");
                        err_resp.set("msg", "insufficient client permissions");
                        err_resp.set("failed_permid", "140"); // i_channel_needed_join_power
                    } else if !is_password_ok {
                        // 781 = ERROR_channel_invalid_password
                        err_resp.set("id", "781");
                        err_resp.set("msg", "invalid channel password");
                    } else {
                        let (occupants, already_there) = {
                            let state = self.state.lock().await;
                            let occupants = state.clients_in_channel(new_cid).len() as i64;
                            let already_there = target_clids
                                .iter()
                                .filter(|t| {
                                    state.clients.values().any(|c| {
                                        c.clid == **t
                                            && c.handshake_phase == HandshakePhase::Connected
                                            && c.current_channel_id == new_cid
                                    })
                                })
                                .count() as i64;
                            (occupants, already_there)
                        };
                        let can_ignore_maxclients = sender_admin || {
                            let db = self.db.lock().await;
                            permissions::has_permission(&db, &sender_uid, new_cid, "b_channel_join_ignore_maxclients")
                        };
                        let arrivals = target_clids.len() as i64 - already_there;
                        if !max_unlimited
                            && max_clients >= 0
                            && occupants + arrivals > max_clients
                            && !can_ignore_maxclients
                        {
                            // 777 = ERROR_channel_maxclients_reached
                            err_resp.set("id", "777");
                            err_resp.set("msg", "channel maxclient reached");
                        } else {
                            for target in target_clids {
                                self.perform_move(
                                    clid,
                                    target,
                                    new_cid,
                                    &sender_nick,
                                    &sender_uid,
                                )
                                .await;
                            }
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                        }
                    }
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await?;
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
                let props = {
                    let db = self.db.lock().await;
                    db.get_all_properties().unwrap_or_default()
                };
                let updated = build_server_updated(ask_for_privilege_key, port, &props);
                self.send_encrypted_command(peer, &updated).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "serveredit" => {
                let (caller_uid, caller_name, is_admin) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.uid.clone(), c.nickname.clone(), c.is_admin),
                        None => (String::new(), "Admin".to_string(), false),
                    }
                };

                let edit_perms: &[(&str, &str)] = &[
                    ("virtualserver_name", "b_virtualserver_modify_name"),
                    ("virtualserver_name_phonetic", "b_virtualserver_modify_name"),
                    ("virtualserver_welcomemessage", "b_virtualserver_modify_welcomemessage"),
                    ("virtualserver_password", "b_virtualserver_modify_password"),
                    ("virtualserver_flag_password", "b_virtualserver_modify_password"),
                    ("virtualserver_icon_id", "b_virtualserver_modify_icon_id"),
                    ("virtualserver_maxclients", "b_virtualserver_modify_maxclients"),
                    ("virtualserver_reserved_slots", "b_virtualserver_modify_reserved_slots"),
                    ("virtualserver_weblist_enabled", "b_virtualserver_modify_weblist"),
                    ("virtualserver_hostmessage", "b_virtualserver_modify_hostmessage"),
                    ("virtualserver_hostmessage_mode", "b_virtualserver_modify_hostmessage"),
                    ("virtualserver_hostbanner_url", "b_virtualserver_modify_hostbanner"),
                    ("virtualserver_hostbanner_gfx_url", "b_virtualserver_modify_hostbanner"),
                    ("virtualserver_hostbanner_gfx_interval", "b_virtualserver_modify_hostbanner"),
                    ("virtualserver_hostbanner_mode", "b_virtualserver_modify_hostbanner"),
                    ("virtualserver_hostbutton_tooltip", "b_virtualserver_modify_hostbutton"),
                    ("virtualserver_hostbutton_url", "b_virtualserver_modify_hostbutton"),
                    ("virtualserver_hostbutton_gfx_url", "b_virtualserver_modify_hostbutton"),
                    ("virtualserver_codec_encryption_mode", "b_virtualserver_modify_codec_encryption_mode"),
                    ("virtualserver_needed_identity_security_level", "b_virtualserver_modify_needed_identity_security_level"),
                    ("virtualserver_default_server_group", "b_virtualserver_modify_default_servergroup"),
                    ("virtualserver_default_channel_group", "b_virtualserver_modify_default_channelgroup"),
                    ("virtualserver_default_channel_admin_group", "b_virtualserver_modify_default_channeladmingroup"),
                    ("virtualserver_channel_temp_delete_delay_default", "b_virtualserver_modify_channel_temp_delete_delay_default"),
                    ("virtualserver_min_client_version", "b_virtualserver_modify_min_client_version"),
                    ("virtualserver_antiflood_points_tick_reduce", "b_virtualserver_modify_antiflood"),
                    ("virtualserver_antiflood_points_needed_command_block", "b_virtualserver_modify_antiflood"),
                    ("virtualserver_antiflood_points_needed_ip_block", "b_virtualserver_modify_antiflood"),
                    ("virtualserver_antiflood_points_needed_plugin_block", "b_virtualserver_modify_antiflood"),
                    ("virtualserver_log_client", "b_virtualserver_modify_log_settings"),
                    ("virtualserver_log_query", "b_virtualserver_modify_log_settings"),
                    ("virtualserver_log_channel", "b_virtualserver_modify_log_settings"),
                    ("virtualserver_log_permissions", "b_virtualserver_modify_log_settings"),
                    ("virtualserver_log_server", "b_virtualserver_modify_log_settings"),
                    ("virtualserver_log_filetransfer", "b_virtualserver_modify_log_settings"),
                ];

                let mut err_resp = Command::new("error");
                let mut failure: Option<u32> = None;

                {
                    let db = self.db.lock().await;
                    for (prop, perm_name) in edit_perms {
                        if cmd.params.contains_key(*prop) {
                            if !is_admin && !permissions::has_permission(&db, &caller_uid, 0, perm_name) {
                                failure = Some(permissions::perm_name_to_id(perm_name).unwrap_or(0));
                                break;
                            }
                        }
                    }
                }

                if let Some(failed_id) = failure {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", failed_id.to_string());
                } else {
                    let mut changed = Vec::new();
                    {
                        let db = self.db.lock().await;
                        for (k, v) in &cmd.params {
                            if k.starts_with("virtualserver_") {
                                if k == "virtualserver_password" {
                                    if v.is_empty() {
                                        let _ = db.set_property("virtualserver_password", "");
                                        let _ = db.set_property("virtualserver_flag_password", "0");
                                        changed.push(("virtualserver_flag_password".to_string(), "0".to_string()));
                                    } else {
                                        let mut hasher = Sha1::new();
                                        hasher.update(v.as_bytes());
                                        let hash = BASE64_STANDARD.encode(hasher.finalize());
                                        let _ = db.set_property("virtualserver_password", &hash);
                                        let _ = db.set_property("virtualserver_flag_password", "1");
                                        changed.push(("virtualserver_flag_password".to_string(), "1".to_string()));
                                    }
                                } else {
                                    let _ = db.set_property(k, v);
                                    changed.push((k.clone(), v.clone()));
                                }
                            }
                        }
                    }

                    if !changed.is_empty() {
                        let mut notify = Command::new("notifyserveredited");
                        notify.set("reasonid", "11");
                        notify.set("invokerid", clid.to_string());
                        notify.set("invokername", &caller_name);
                        notify.set("invokeruid", &caller_uid);
                        for (k, v) in &changed {
                            notify.set(k, v);
                        }
                        let all_endpoints: Vec<SocketAddr> = {
                            let state = self.state.lock().await;
                            state.clients.values().map(|c| c.endpoint).collect()
                        };
                        for ep in all_endpoints {
                            let _ = self.send_encrypted_command(ep, &notify).await;
                        }
                    }

                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "serverinfo" => {
                let props = {
                    let db = self.db.lock().await;
                    db.get_all_properties().unwrap_or_default()
                };
                let port = self.local_addr().map(|a| a.port()).unwrap_or(9988);
                let (clients_online, channels_online) = {
                    let state = self.state.lock().await;
                    let db = self.db.lock().await;
                    let clients = state
                        .clients
                        .values()
                        .filter(|c| c.handshake_phase == HandshakePhase::Connected)
                        .count();
                    let channels = db.get_channels().map(|ch| ch.len()).unwrap_or(1);
                    (clients, channels)
                };

                let mut resp = Command::new("serverinfo");
                resp.set(
                    "virtualserver_name",
                    props
                        .get("virtualserver_name")
                        .map(|s| s.as_str())
                        .unwrap_or("Nano-TS3 Minimal Server"),
                );
                resp.set(
                    "virtualserver_welcomemessage",
                    props
                        .get("virtualserver_welcomemessage")
                        .map(|s| s.as_str())
                        .unwrap_or("Welcome to Nano-TS3 Server!"),
                );
                resp.set(
                    "virtualserver_maxclients",
                    props
                        .get("virtualserver_maxclients")
                        .map(|s| s.as_str())
                        .unwrap_or("32"),
                );
                resp.set("virtualserver_clientsonline", clients_online.to_string());
                resp.set("virtualserver_channelsonline", channels_online.to_string());
                resp.set("virtualserver_uptime", "1000");
                resp.set("virtualserver_status", "online");
                resp.set("virtualserver_port", port.to_string());
                resp.set(
                    "virtualserver_flag_password",
                    props
                        .get("virtualserver_flag_password")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                resp.set(
                    "virtualserver_default_server_group",
                    props
                        .get("virtualserver_default_server_group")
                        .map(|s| s.as_str())
                        .unwrap_or("8"),
                );
                resp.set(
                    "virtualserver_default_channel_group",
                    props
                        .get("virtualserver_default_channel_group")
                        .map(|s| s.as_str())
                        .unwrap_or("8"),
                );
                resp.set(
                    "virtualserver_default_channel_admin_group",
                    props
                        .get("virtualserver_default_channel_admin_group")
                        .map(|s| s.as_str())
                        .unwrap_or("5"),
                );
                resp.set(
                    "virtualserver_hostmessage",
                    props
                        .get("virtualserver_hostmessage")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                resp.set(
                    "virtualserver_hostmessage_mode",
                    props
                        .get("virtualserver_hostmessage_mode")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                resp.set(
                    "virtualserver_hostbanner_url",
                    props
                        .get("virtualserver_hostbanner_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                resp.set(
                    "virtualserver_hostbanner_gfx_url",
                    props
                        .get("virtualserver_hostbanner_gfx_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                resp.set(
                    "virtualserver_hostbanner_gfx_interval",
                    props
                        .get("virtualserver_hostbanner_gfx_interval")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                resp.set(
                    "virtualserver_hostbanner_mode",
                    props
                        .get("virtualserver_hostbanner_mode")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                resp.set(
                    "virtualserver_hostbutton_tooltip",
                    props
                        .get("virtualserver_hostbutton_tooltip")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                resp.set(
                    "virtualserver_hostbutton_url",
                    props
                        .get("virtualserver_hostbutton_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                resp.set(
                    "virtualserver_hostbutton_gfx_url",
                    props
                        .get("virtualserver_hostbutton_gfx_url")
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                );
                resp.set(
                    "virtualserver_icon_id",
                    props
                        .get("virtualserver_icon_id")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                resp.set(
                    "virtualserver_needed_identity_security_level",
                    props
                        .get("virtualserver_needed_identity_security_level")
                        .map(|s| s.as_str())
                        .unwrap_or("8"),
                );
                resp.set(
                    "virtualserver_codec_encryption_mode",
                    props
                        .get("virtualserver_codec_encryption_mode")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                resp.set(
                    "virtualserver_weblist_enabled",
                    props
                        .get("virtualserver_weblist_enabled")
                        .map(|s| s.as_str())
                        .unwrap_or("1"),
                );
                resp.set(
                    "virtualserver_reserved_slots",
                    props
                        .get("virtualserver_reserved_slots")
                        .map(|s| s.as_str())
                        .unwrap_or("0"),
                );
                resp.set("virtualserver_version", "3.13.8 [Build: 1685172871]");
                resp.set("virtualserver_platform", "Linux");
                self.send_encrypted_command(peer, &resp).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "clientgetvariables" => {
                let target_clid: u16 = cmd
                    .get("clid")
                    .and_then(|v| v.parse().ok())
                    .map(|id| if id == 0 { clid } else { id })
                    .unwrap_or(clid);
                let (nickname, is_admin, connected_secs) = {
                    let state = self.state.lock().await;
                    match state.clients.values().find(|c| {
                        c.clid == target_clid && c.handshake_phase == HandshakePhase::Connected
                    }) {
                        Some(c) => (
                            c.nickname.clone(),
                            c.is_admin,
                            c.connected_time.elapsed().as_secs(),
                        ),
                        None => ("User".to_string(), false, 0),
                    }
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let mut upd = Command::new("notifyclientupdated");
                upd.set("clid", target_clid.to_string());
                let _ = &nickname; // clientgetvariables must not rename
                upd.set("client_version", "3.6.2 [Build: 1695203293]");
                upd.set("client_platform", "Linux");
                upd.set("client_login_name", "");
                upd.set("client_created", "1600000000");
                upd.set(
                    "client_lastconnected",
                    (now.saturating_sub(connected_secs)).to_string(),
                );
                upd.set("client_totalconnections", "1");
                upd.set("client_month_bytes_uploaded", "0");
                upd.set("client_month_bytes_downloaded", "0");
                upd.set("client_total_bytes_uploaded", "0");
                upd.set("client_total_bytes_downloaded", "0");
                upd.set("client_servergroups", if is_admin { "6" } else { "8" });
                self.send_encrypted_command(peer, &upd).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "getconnectioninfo" => {
                // The official "Client connection info" dialog: the requester
                // asks for another client's stats, the server asks the target
                // (notifyconnectioninforequest) to publish fresh ones with
                // setconnectioninfo, and forwards them back as
                // notifyconnectioninfo. The IP and port are included for admins
                // and when checking one's own connection info.
                let target_clid: Option<u16> = match cmd.get("clid") {
                    Some(v) => v.parse().ok().map(|id| if id == 0 { clid } else { id }),
                    None => Some(clid),
                };
                let requester_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };

                match target_clid {
                    Some(target_clid) => {
                        let target_data = {
                            let mut state = self.state.lock().await;
                            let target = state
                                .clients
                                .values()
                                .find(|c| {
                                    c.clid == target_clid
                                        && c.handshake_phase == HandshakePhase::Connected
                                })
                                .map(|c| {
                                    (
                                        c.endpoint,
                                        c.connection_stats.clone(),
                                        c.endpoint.ip().to_string(),
                                        c.endpoint.port(),
                                        c.connected_time.elapsed().as_secs(),
                                        c.last_activity.elapsed().as_millis() as u64,
                                    )
                                });
                            if target.is_some() {
                                state
                                    .connection_watchers
                                    .entry(target_clid)
                                    .or_default()
                                    .insert(peer);
                            }
                            target
                        };

                        match target_data {
                            Some((
                                target_ep,
                                stats,
                                target_ip,
                                target_port,
                                connected_time,
                                idle_time,
                            )) => {
                                // Ask the target for a fresh report. The
                                // official client answers with
                                // `setconnectioninfo` while the dialog is open.
                                let _ = self
                                    .send_encrypted_raw(target_ep, "notifyconnectioninforequest")
                                    .await;

                                let is_self = target_clid == clid;
                                let notify = build_connection_info(
                                    target_clid,
                                    &stats,
                                    &target_ip,
                                    target_port,
                                    connected_time,
                                    idle_time,
                                    requester_admin || is_self,
                                );
                                self.send_encrypted_command(peer, &notify).await?;
                            }
                            None => {
                                let mut err_resp = Command::new("error");
                                err_resp.set("id", "512");
                                err_resp.set("msg", "invalid clientID");
                                if let Some(rc) = cmd.get("return_code") {
                                    err_resp.set("return_code", rc);
                                }
                                self.send_encrypted_command(peer, &err_resp).await?;
                                return Ok(());
                            }
                        }
                    }
                    None => {
                        let mut err_resp = Command::new("error");
                        err_resp.set("id", "1538");
                        err_resp.set("msg", "invalid parameter");
                        if let Some(rc) = cmd.get("return_code") {
                            err_resp.set("return_code", rc);
                        }
                        self.send_encrypted_command(peer, &err_resp).await?;
                        return Ok(());
                    }
                }

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "setconnectioninfo" | "connectioninfoautoupdate" => {
                // A client publishing its own connection statistics. The
                // official 3.6.2 client sends `connectioninfoautoupdate`
                // periodically (and after a connection-info request); both
                // names are accepted. Store them and forward to everyone
                // currently watching this client's connection info.
                let stats: std::collections::BTreeMap<String, String> = cmd
                    .params
                    .iter()
                    .filter(|(k, _)| k.starts_with("connection_"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let has_stats = !stats.is_empty();

                let (target_ip, target_port, connected_time, idle_time, recipients) = {
                    let mut state = self.state.lock().await;
                    if has_stats {
                        if let Some(c) = state.get_client_mut(&peer) {
                            c.connection_stats = stats.clone();
                        }
                    }
                    let (target_ip, target_port, connected_time, idle_time) = state
                        .get_client(&peer)
                        .map(|c| (
                            c.endpoint.ip().to_string(),
                            c.endpoint.port(),
                            c.connected_time.elapsed().as_secs(),
                            c.last_activity.elapsed().as_millis() as u64,
                        ))
                        .unwrap_or_else(|| ("127.0.0.1".to_string(), 0, 0, 0));

                    let watchers = state
                        .connection_watchers
                        .get(&clid)
                        .cloned()
                        .unwrap_or_default();
                    let recps: Vec<(SocketAddr, bool)> = watchers
                        .into_iter()
                        .filter_map(|ep| {
                            state
                                .clients
                                .get(&ep)
                                .filter(|c| c.handshake_phase == HandshakePhase::Connected)
                                .map(|c| (ep, c.is_admin))
                        })
                        .collect();
                    (target_ip, target_port, connected_time, idle_time, recps)
                };

                if has_stats {
                    for (ep, is_admin) in recipients {
                        let is_self = ep == peer;
                        let notify = build_connection_info(
                            clid,
                            &stats,
                            &target_ip,
                            target_port,
                            connected_time,
                            idle_time,
                            is_admin || is_self,
                        );
                        let _ = self.send_encrypted_command(ep, &notify).await;
                    }
                }

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
            "servergroupadd" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_servergroup_create")
                };

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "162");
                } else {
                    let name = cmd.get("name").unwrap_or("New Group");
                    let group_type: i32 = cmd.get("type").and_then(|v| v.parse().ok()).unwrap_or(1);
                    let db = self.db.lock().await;
                    match db.create_server_group(name, group_type) {
                        Ok(new_sgid) => {
                            let mut resp = Command::new("servergroupadd");
                            resp.set("sgid", new_sgid.to_string());
                            self.send_encrypted_command(peer, &resp).await?;
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                            drop(db);
                            self.broadcast_server_group_list().await;
                        }
                        Err(_) => {
                            err_resp.set("id", "1280");
                            err_resp.set("msg", "database error");
                        }
                    }
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergroupdel" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_servergroup_delete")
                };
                let sgid: u64 = cmd.get("sgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let force = cmd.get("force").map(|v| v == "1").unwrap_or(false);

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "172");
                } else if sgid == 6 || sgid == 7 || sgid == 8 {
                    err_resp.set("id", "2565");
                    err_resp.set("msg", "servergroup is not empty or is a default group");
                } else {
                    let db = self.db.lock().await;
                    match db.delete_server_group(sgid, force) {
                        Ok(true) => {
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                            drop(db);
                            self.broadcast_server_group_list().await;
                        }
                        Ok(false) => {
                            err_resp.set("id", "2565");
                            err_resp.set("msg", "servergroup is not empty");
                        }
                        Err(_) => {
                            err_resp.set("id", "1280");
                            err_resp.set("msg", "database error");
                        }
                    }
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergrouprename" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_servergroup_create")
                };
                let sgid: u64 = cmd.get("sgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let name = cmd.get("name").unwrap_or("");

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "162");
                } else if name.is_empty() {
                    err_resp.set("id", "1538");
                    err_resp.set("msg", "invalid parameter");
                } else {
                    let db = self.db.lock().await;
                    let _ = db.rename_server_group(sgid, name);
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                    drop(db);
                    self.broadcast_server_group_list().await;
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergroupcopy" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_servergroup_create")
                };
                let ssgid: u64 = cmd.get("ssgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let tsgid: u64 = cmd.get("tsgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let name = cmd.get("name").unwrap_or("Copy of Group");
                let group_type: i32 = cmd.get("type").and_then(|v| v.parse().ok()).unwrap_or(1);

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "162");
                } else {
                    let db = self.db.lock().await;
                    match db.copy_server_group(ssgid, tsgid, name, group_type) {
                        Ok(target_id) => {
                            let mut resp = Command::new("servergroupcopy");
                            resp.set("sgid", target_id.to_string());
                            self.send_encrypted_command(peer, &resp).await?;
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                            drop(db);
                            self.broadcast_server_group_list().await;
                        }
                        Err(_) => {
                            err_resp.set("id", "1280");
                            err_resp.set("msg", "database error");
                        }
                    }
                }
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
                let sgid: u64 = cmd.get("sgid").and_then(|v| v.parse().ok()).unwrap_or(6);
                let use_permsid = cmd.params.contains_key("permsid");
                self.send_server_group_perm_list(peer, sgid, use_permsid).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergroupaddperm" => {
                let sgid: u64 = cmd.get("sgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let param_sets = cmd.parse_piped_param_sets();
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        let val: i64 = pset
                            .get("permvalue")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let neg = pset.get("permnegated").map(|v| v == "1").unwrap_or(false);
                        let skip = pset.get("permskip").map(|v| v == "1").unwrap_or(false);

                        if let Some(pname) = perm_name {
                            let _ = db.set_server_group_perm(sgid, &pname, val, neg, skip);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergroupdelperm" => {
                let sgid: u64 = cmd.get("sgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let param_sets = cmd.parse_piped_param_sets();
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        if let Some(pname) = perm_name {
                            let _ = db.del_server_group_perm(sgid, &pname);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgroupadd" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_channelgroup_create")
                };

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "163");
                } else {
                    let name = cmd.get("name").unwrap_or("New Group");
                    let group_type: i32 = cmd.get("type").and_then(|v| v.parse().ok()).unwrap_or(1);
                    let db = self.db.lock().await;
                    match db.create_channel_group(name, group_type) {
                        Ok(new_cgid) => {
                            let mut resp = Command::new("channelgroupadd");
                            resp.set("cgid", new_cgid.to_string());
                            self.send_encrypted_command(peer, &resp).await?;
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                            drop(db);
                            self.broadcast_channel_group_list().await;
                        }
                        Err(_) => {
                            err_resp.set("id", "1280");
                            err_resp.set("msg", "database error");
                        }
                    }
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgroupdel" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_channelgroup_delete")
                };
                let cgid: u64 = cmd.get("cgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let force = cmd.get("force").map(|v| v == "1").unwrap_or(false);

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "173");
                } else if cgid == 5 || cgid == 6 || cgid == 7 || cgid == 8 {
                    err_resp.set("id", "2565");
                    err_resp.set("msg", "channelgroup is not empty or is a default group");
                } else {
                    let db = self.db.lock().await;
                    match db.delete_channel_group(cgid, force) {
                        Ok(true) => {
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                            drop(db);
                            self.broadcast_channel_group_list().await;
                        }
                        Ok(false) => {
                            err_resp.set("id", "2565");
                            err_resp.set("msg", "channelgroup is not empty");
                        }
                        Err(_) => {
                            err_resp.set("id", "1280");
                            err_resp.set("msg", "database error");
                        }
                    }
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgrouprename" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_channelgroup_create")
                };
                let cgid: u64 = cmd.get("cgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let name = cmd.get("name").unwrap_or("");

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "163");
                } else if name.is_empty() {
                    err_resp.set("id", "1538");
                    err_resp.set("msg", "invalid parameter");
                } else {
                    let db = self.db.lock().await;
                    let _ = db.rename_channel_group(cgid, name);
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                    drop(db);
                    self.broadcast_channel_group_list().await;
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgroupcopy" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_channelgroup_create")
                };
                let scgid: u64 = cmd.get("scgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let tcgid: u64 = cmd.get("tcgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let name = cmd.get("name").unwrap_or("Copy of Channel Group");
                let group_type: i32 = cmd.get("type").and_then(|v| v.parse().ok()).unwrap_or(1);

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "163");
                } else {
                    let db = self.db.lock().await;
                    match db.copy_channel_group(scgid, tcgid, name, group_type) {
                        Ok(target_id) => {
                            let mut resp = Command::new("channelgroupcopy");
                            resp.set("cgid", target_id.to_string());
                            self.send_encrypted_command(peer, &resp).await?;
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                            drop(db);
                            self.broadcast_channel_group_list().await;
                        }
                        Err(_) => {
                            err_resp.set("id", "1280");
                            err_resp.set("msg", "database error");
                        }
                    }
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgrouplist" => {
                self.send_channel_group_list(peer, false).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgrouppermlist" => {
                let cgid: u64 = cmd.get("cgid").and_then(|v| v.parse().ok()).unwrap_or(8);
                let use_permsid = cmd.params.contains_key("permsid");
                self.send_channel_group_perm_list(peer, cgid, use_permsid).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgroupaddperm" => {
                let cgid: u64 = cmd.get("cgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let param_sets = cmd.parse_piped_param_sets();
                let (uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };

                let mut err_resp = Command::new("error");
                let mut permission_ok = is_admin;
                if !permission_ok {
                    let db = self.db.lock().await;
                    let mod_power =
                        permissions::get_power(&db, &uid, 0, "i_group_modify_power");
                    permission_ok = mod_power >= 50;
                }
                if !permission_ok {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        let val: i64 = pset
                            .get("permvalue")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let neg = pset.get("permnegated").map(|v| v == "1").unwrap_or(false);
                        let skip = pset.get("permskip").map(|v| v == "1").unwrap_or(false);

                        if let Some(pname) = perm_name {
                            let _ = db.set_channel_group_perm(cgid, &pname, val, neg, skip);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelgroupdelperm" => {
                let cgid: u64 = cmd.get("cgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let param_sets = cmd.parse_piped_param_sets();
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        if let Some(pname) = perm_name {
                            let _ = db.del_channel_group_perm(cgid, &pname);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelpermlist" => {
                let cid: u64 = cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let use_permsid = cmd.params.contains_key("permsid");
                let (has_list_perm, is_admin) = {
                    let (uid, is_adm) = {
                        let state = self.state.lock().await;
                        state
                            .get_client(&peer)
                            .map(|c| (c.uid.clone(), c.is_admin))
                            .unwrap_or_default()
                    };
                    let db = self.db.lock().await;
                    let has_p = permissions::has_permission(
                        &db,
                        &uid,
                        cid,
                        "b_virtualserver_channel_permission_list",
                    );
                    (has_p, is_adm)
                };

                let mut err_resp = Command::new("error");
                if !is_admin && !has_list_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let wire = {
                        let db = self.db.lock().await;
                        permissions::build_channel_perm_list(&db, cid, use_permsid)
                    };
                    if wire != "notifychannelpermlist" {
                        self.send_encrypted_raw(peer, &wire).await?;
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channeladdperm" => {
                let (uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let param_sets = cmd.parse_piped_param_sets();
                let default_cid: u64 =
                    cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(0);

                let mut err_resp = Command::new("error");
                let mut permission_ok = is_admin;
                if !permission_ok {
                    let db = self.db.lock().await;
                    let mod_power = permissions::get_power(
                        &db,
                        &uid,
                        default_cid,
                        "i_channel_permission_modify_power",
                    );
                    let needed = permissions::get_power(
                        &db,
                        &uid,
                        default_cid,
                        "i_channel_needed_permission_modify_power",
                    );
                    permission_ok = mod_power >= needed && mod_power > 0;
                }

                if !permission_ok {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let cid = pset
                            .get("cid")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(default_cid);
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        let val: i64 = pset
                            .get("permvalue")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let neg = pset.get("permnegated").map(|v| v == "1").unwrap_or(false);
                        let skip = pset.get("permskip").map(|v| v == "1").unwrap_or(false);

                        if let Some(pname) = perm_name {
                            let _ = db.set_channel_perm(cid, &pname, val, neg, skip);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channeldelperm" => {
                let (uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };
                let param_sets = cmd.parse_piped_param_sets();
                let default_cid: u64 =
                    cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(0);

                let mut err_resp = Command::new("error");
                let mut permission_ok = is_admin;
                if !permission_ok {
                    let db = self.db.lock().await;
                    let mod_power = permissions::get_power(
                        &db,
                        &uid,
                        default_cid,
                        "i_channel_permission_modify_power",
                    );
                    let needed = permissions::get_power(
                        &db,
                        &uid,
                        default_cid,
                        "i_channel_needed_permission_modify_power",
                    );
                    permission_ok = mod_power >= needed && mod_power > 0;
                }

                if !permission_ok {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let cid = pset
                            .get("cid")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(default_cid);
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        if let Some(pname) = perm_name {
                            let _ = db.del_channel_perm(cid, &pname);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "permoverview" => {
                let cid: u64 = cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(1);
                let cldbid: u64 = cmd
                    .get("cldbid")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(clid as u64);
                let filter_permid: u32 = if let Some(sid) = cmd.get("permsid") {
                    permissions::perm_name_to_id(sid).unwrap_or(0)
                } else if let Some(pid_str) = cmd.get("permid") {
                    pid_str.parse().unwrap_or(0)
                } else {
                    0
                };

                let target_uid = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| c.uid.clone())
                        .unwrap_or_else(|| {
                            state
                                .get_client(&peer)
                                .map(|c| c.uid.clone())
                                .unwrap_or_default()
                        })
                };

                let wire = {
                    let db = self.db.lock().await;
                    permissions::build_permission_overview(
                        &db,
                        &target_uid,
                        cldbid,
                        cid,
                        filter_permid,
                    )
                };
                if wire != "notifypermoverview" {
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
            "setclientchannelgroup" => {
                let cgid: u64 = cmd.get("cgid").and_then(|v| v.parse().ok()).unwrap_or(8);
                let cid: u64 = cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(1);
                let cldbid: u64 = cmd
                    .get("cldbid")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(clid as u64);

                let (invoker_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.uid.clone(), c.is_admin))
                        .unwrap_or_default()
                };

                let (target_clid, target_uid) = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| (c.clid, c.uid.clone()))
                        .unwrap_or((cldbid as u16, String::new()))
                };

                let mut err_resp = Command::new("error");
                let can_set = is_admin || {
                    let db = self.db.lock().await;
                    permissions::check_power(
                        &db,
                        &invoker_uid,
                        cid,
                        "i_group_member_add_power",
                        50,
                    )
                };

                if !can_set {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    {
                        let db = self.db.lock().await;
                        let _ = db.set_client_channel_group(&target_uid, cid, cgid);
                    }

                    // Notify clients in channel
                    let mut notify = Command::new("notifyclientchannelgroupchanged");
                    notify.set("cgid", cgid.to_string());
                    notify.set("cid", cid.to_string());
                    notify.set("clid", target_clid.to_string());
                    notify.set("cgserverid", "0");

                    let recipients: Vec<SocketAddr> = {
                        let state = self.state.lock().await;
                        state
                            .clients
                            .values()
                            .filter(|c| c.handshake_phase == HandshakePhase::Connected)
                            .map(|c| c.endpoint)
                            .collect()
                    };
                    for r in recipients {
                        let _ = self.send_encrypted_command(r, &notify).await;
                    }

                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
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
            "clientpermlist" => {
                let cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(clid as u64);
                let use_permsid = cmd.params.contains_key("permsid");
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let target_uid = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| c.uid.clone())
                        .unwrap_or_default()
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let wire = {
                        let db = self.db.lock().await;
                        permissions::build_client_perm_list(&db, cldbid, &target_uid, use_permsid)
                    };
                    if !wire.is_empty() {
                        self.send_encrypted_raw(peer, &wire).await?;
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "clientaddperm" => {
                let cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(clid as u64);
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let target_uid = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| c.uid.clone())
                        .unwrap_or_default()
                };
                let param_sets = cmd.parse_piped_param_sets();

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        let val: i64 = pset
                            .get("permvalue")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let neg = pset.get("permnegated").map(|v| v == "1").unwrap_or(false);
                        let skip = pset.get("permskip").map(|v| v == "1").unwrap_or(false);

                        if let Some(pname) = perm_name {
                            let _ = db.set_client_perm(&target_uid, &pname, val, neg, skip);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "clientdelperm" => {
                let cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(clid as u64);
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let target_uid = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| c.uid.clone())
                        .unwrap_or_default()
                };
                let param_sets = cmd.parse_piped_param_sets();

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        if let Some(pname) = perm_name {
                            let _ = db.del_client_perm(&target_uid, &pname);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelclientpermlist" => {
                let cid: u64 = cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(1);
                let cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(clid as u64);
                let use_permsid = cmd.params.contains_key("permsid");
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let target_uid = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| c.uid.clone())
                        .unwrap_or_default()
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let wire = {
                        let db = self.db.lock().await;
                        permissions::build_channel_client_perm_list(&db, cid, cldbid, &target_uid, use_permsid)
                    };
                    if !wire.is_empty() {
                        self.send_encrypted_raw(peer, &wire).await?;
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelclientaddperm" => {
                let default_cid: u64 = cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(1);
                let default_cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(clid as u64);
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let param_sets = cmd.parse_piped_param_sets();

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let cid = pset.get("cid").and_then(|v| v.parse().ok()).unwrap_or(default_cid);
                        let cldbid = pset.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(default_cldbid);
                        let target_uid = {
                            let state = self.state.lock().await;
                            state
                                .clients
                                .values()
                                .find(|c| c.clid as u64 == cldbid)
                                .map(|c| c.uid.clone())
                                .unwrap_or_default()
                        };
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        let val: i64 = pset
                            .get("permvalue")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let neg = pset.get("permnegated").map(|v| v == "1").unwrap_or(false);
                        let skip = pset.get("permskip").map(|v| v == "1").unwrap_or(false);

                        if let Some(pname) = perm_name {
                            let _ = db.set_channel_client_perm(cid, &target_uid, &pname, val, neg, skip);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "channelclientdelperm" => {
                let default_cid: u64 = cmd.get("cid").and_then(|v| v.parse().ok()).unwrap_or(1);
                let default_cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(clid as u64);
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let param_sets = cmd.parse_piped_param_sets();

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    for pset in param_sets {
                        let cid = pset.get("cid").and_then(|v| v.parse().ok()).unwrap_or(default_cid);
                        let cldbid = pset.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(default_cldbid);
                        let target_uid = {
                            let state = self.state.lock().await;
                            state
                                .clients
                                .values()
                                .find(|c| c.clid as u64 == cldbid)
                                .map(|c| c.uid.clone())
                                .unwrap_or_default()
                        };
                        let perm_name = if let Some(sid) = pset.get("permsid") {
                            Some(sid.clone())
                        } else if let Some(pid_str) = pset.get("permid") {
                            pid_str
                                .parse::<u32>()
                                .ok()
                                .and_then(permissions::perm_id_to_name)
                                .map(str::to_string)
                        } else {
                            None
                        };
                        if let Some(pname) = perm_name {
                            let _ = db.del_channel_client_perm(cid, &target_uid, &pname);
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergroupaddclient" => {
                let sgid: u64 = cmd.get("sgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let (target_clid, target_uid) = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| (c.clid, c.uid.clone()))
                        .unwrap_or((cldbid as u16, String::new()))
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    let _ = db.add_client_to_server_group(&target_uid, sgid);
                    if sgid == 6 {
                        let mut state = self.state.lock().await;
                        if let Some(client) = state.clients.values_mut().find(|c| c.clid == target_clid) {
                            client.is_admin = true;
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "servergroupdelclient" => {
                let sgid: u64 = cmd.get("sgid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let cldbid: u64 = cmd.get("cldbid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let (target_clid, target_uid) = {
                    let state = self.state.lock().await;
                    state
                        .clients
                        .values()
                        .find(|c| c.clid as u64 == cldbid)
                        .map(|c| (c.clid, c.uid.clone()))
                        .unwrap_or((cldbid as u16, String::new()))
                };

                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                } else {
                    let db = self.db.lock().await;
                    let _ = db.remove_client_from_server_group(&target_uid, sgid);
                    if sgid == 6 {
                        let mut state = self.state.lock().await;
                        if let Some(client) = state.clients.values_mut().find(|c| c.clid == target_clid) {
                            client.is_admin = false;
                        }
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
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
                let (nickname, invoker_uid, is_admin) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.nickname.clone(), c.uid.clone(), c.is_admin))
                        .unwrap_or_else(|| ("User".to_string(), String::new(), false))
                };

                let mut err_resp = Command::new("error");
                let (perm_name, failed_permid) = if cmd.get("channel_flag_permanent") == Some("1") {
                    ("b_channel_create_permanent", "89")
                } else if cmd.get("channel_flag_semi_permanent") == Some("1") {
                    ("b_channel_create_semi_permanent", "90")
                } else if cmd.get("channel_flag_temporary") == Some("1") {
                    ("b_channel_create_temporary", "91")
                } else {
                    ("b_channel_create_permanent", "89")
                };
                let can_create = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &invoker_uid, 0, perm_name)
                };
                if !can_create {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", failed_permid);
                } else {
                    let ch_name = cmd.get("channel_name").unwrap_or("New Channel");
                    let ch_topic = cmd.get("channel_topic").unwrap_or("");

                    // Channel names must be unique on the virtual server. The
                    // incoming channel_order is the sibling this channel
                    // follows; when omitted (or stale), append after the last
                    // channel.
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
                        let _ = db.set_client_channel_group(&invoker_uid, cid, 5);
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
                            state
                                .clients
                                .values()
                                .filter(|c| c.handshake_phase == HandshakePhase::Connected)
                                .map(|c| c.endpoint)
                                .collect()
                        };
                        if let Some(notify) = notify {
                            for ep in &all_peers {
                                let _ = self.send_encrypted_command(*ep, &notify).await;
                            }
                            if channel.as_ref().is_some_and(|ch| !ch.password_hash.is_empty()) {
                                let mut pw_notify = Command::new("notifychannelpasswordchanged");
                                pw_notify.set("cid", cid.to_string());
                                for ep in &all_peers {
                                    let _ = self.send_encrypted_command(*ep, &pw_notify).await;
                                }
                            }
                        }
                    }

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
                if let Some(target_cid) = cid {
                    match parse_channel_edit(&cmd) {
                        Err(reason) => {
                            err_resp.set("id", "1024");
                            err_resp.set("msg", reason);
                        }
                        Ok(edit) => {
                            let (can_edit, failed_permid) = if is_admin {
                                (true, None)
                            } else {
                                let db = self.db.lock().await;
                                let mod_power = permissions::get_power(&db, &uid, target_cid, "i_channel_modify_power");
                                let needed = permissions::get_power(&db, &uid, target_cid, "i_channel_needed_modify_power");
                                if mod_power < needed {
                                    (false, Some("125")) // i_channel_needed_modify_power
                                } else if edit.name.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_name") {
                                    (false, Some("112"))
                                } else if edit.topic.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_topic") {
                                    (false, Some("113"))
                                } else if edit.description.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_description") {
                                    (false, Some("114"))
                                } else if edit.password.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_password") {
                                    (false, Some("115"))
                                } else if edit.codec.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_codec") {
                                    (false, Some("117"))
                                } else if edit.codec_quality.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_codec_quality") {
                                    (false, Some("118"))
                                } else if edit.codec_latency_factor.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_codec_latency_factor") {
                                    (false, Some("119"))
                                } else if (edit.max_clients.is_some() || edit.max_clients_unlimited.is_some()) && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_maxclients") {
                                    (false, Some("120"))
                                } else if (edit.max_family_clients.is_some() || edit.max_family_clients_unlimited.is_some() || edit.max_family_clients_inherited.is_some()) && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_maxfamilyclients") {
                                    (false, Some("121"))
                                } else if edit.order_after.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_sortorder") {
                                    (false, Some("122"))
                                } else if edit.needed_talk_power.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_needed_talk_power") {
                                    (false, Some("123"))
                                } else if edit.is_default.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_make_default") {
                                    (false, Some("108"))
                                } else if edit.is_permanent.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_make_permanent") {
                                    (false, Some("109"))
                                } else if edit.is_semi_permanent.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_make_semi_permanent") {
                                    (false, Some("110"))
                                } else if edit.codec_is_unencrypted.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_make_codec_encrypted") {
                                    (false, Some("126"))
                                } else if edit.delete_delay.is_some() && !permissions::has_permission(&db, &uid, target_cid, "b_channel_modify_temp_delete_delay") {
                                    (false, Some("127"))
                                } else {
                                    (true, None)
                                }
                            };

                            if !can_edit {
                                err_resp.set("id", "2568");
                                err_resp.set("msg", "insufficient client permissions");
                                if let Some(fpid) = failed_permid {
                                    err_resp.set("failed_permid", fpid);
                                }
                            } else {
                                let result = {
                                    let db = self.db.lock().await;
                                    db.edit_channel(target_cid, &edit)
                                };
                                match result {
                                    Ok(Some(channel)) => {
                                        let notify = build_channel_edited_notification(
                                            &channel,
                                            &edit,
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
                                        for recipient in &recipients {
                                            let _ =
                                                self.send_encrypted_command(*recipient, &notify).await;
                                        }
                                        if edit.password.is_some() {
                                            let mut pw_notify = Command::new("notifychannelpasswordchanged");
                                            pw_notify.set("cid", target_cid.to_string());
                                            for recipient in &recipients {
                                                let _ = self
                                                    .send_encrypted_command(*recipient, &pw_notify)
                                                    .await;
                                            }
                                        }
                                        err_resp.set("id", "0");
                                        err_resp.set("msg", "ok");
                                    }
                                    Ok(None) => {
                                        err_resp.set("id", "1024");
                                        err_resp.set("msg", "invalid channel");
                                    }
                                    Err(e) => {
                                        warn!("Failed to edit channel {}: {:?}", target_cid, e);
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
                let can_delete = is_admin || {
                    if let Some(target_cid) = cid {
                        let db = self.db.lock().await;
                        let del_power = permissions::get_power(&db, &uid, target_cid, "i_channel_delete_power");
                        let needed = permissions::get_power(&db, &uid, target_cid, "i_channel_needed_delete_power");
                        del_power >= needed && (
                            permissions::has_permission(&db, &uid, target_cid, "b_channel_delete_permanent")
                            || permissions::has_permission(&db, &uid, target_cid, "b_channel_delete_semi_permanent")
                            || permissions::has_permission(&db, &uid, target_cid, "b_channel_delete_temporary")
                        )
                    } else {
                        false
                    }
                };

                let mut err_resp = Command::new("error");
                if !can_delete {
                    err_resp.set("id", "2568");
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
                                        move_clients.push((
                                            client.clid,
                                            client.endpoint,
                                            client.uid.clone(),
                                            client.nickname.clone(),
                                            client.is_admin,
                                            client.audio,
                                        ));
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

                            for (moved_clid, moved_ep, moved_uid, moved_nick, moved_admin, moved_audio) in
                                move_clients
                            {
                                let mut moved = Command::new("notifyclientmoved");
                                moved.set("clid", moved_clid.to_string());
                                moved.set("cfid", cid.to_string());
                                moved.set("ctid", default_cid.to_string());
                                moved.set("reasonid", "0");
                                moved.set("reasonmsg", "channel deleted");
                                moved.set("invokerid", clid.to_string());
                                moved.set("invokername", &nickname);
                                moved.set("invokeruid", &uid);
                                // Watchers of the deleted channel know the
                                // moved client; watchers of only the default
                                // channel get an enter view instead.
                                let (mut moved_eps, enter_eps) =
                                    self.move_recipients(cid, default_cid, moved_ep).await;
                                moved_eps.push(moved_ep);
                                for recipient in &moved_eps {
                                    let _ = self.send_encrypted_command(*recipient, &moved).await;
                                }
                                for recipient in &enter_eps {
                                    let view = build_client_enter_view(
                                        "0",
                                        moved_clid,
                                        &moved_uid,
                                        &moved_nick,
                                        default_cid,
                                        cid,
                                        moved_admin,
                                        moved_audio,
                                    );
                                    let _ = self.send_encrypted_command(*recipient, &view).await;
                                }
                                {
                                    let mut state = self.state.lock().await;
                                    for recipient in &enter_eps {
                                        if let Some(c) = state.get_client_mut(recipient) {
                                            c.known_clients.insert(moved_clid);
                                        }
                                    }
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
            "tokenadd" | "privilegekeyadd" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.uid.clone(), c.is_admin),
                        None => (String::new(), false),
                    }
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_token_add")
                };

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "39");
                } else {
                    let tokentype: i32 = cmd
                        .get("tokentype")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let tokenid1: u64 = cmd
                        .get("tokenid1")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(if tokentype == 0 { 6 } else { 5 });
                    let tokenid2: u64 = cmd
                        .get("tokenid2")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let description = cmd
                        .get("tokendescription")
                        .or_else(|| cmd.get("description"))
                        .unwrap_or("");

                    let rand_token: String = rand::thread_rng()
                        .sample_iter(&rand::distributions::Alphanumeric)
                        .take(40)
                        .map(char::from)
                        .collect();

                    let db = self.db.lock().await;
                    match db.add_token(&rand_token, tokentype, tokenid1, tokenid2, description) {
                        Ok(()) => {
                            let resp_name = if cmd.name.starts_with("privilegekey") {
                                "privilegekeyadd"
                            } else {
                                "tokenadd"
                            };
                            let mut resp = Command::new(resp_name);
                            resp.set("token", &rand_token);
                            self.send_encrypted_command(peer, &resp).await?;
                            err_resp.set("id", "0");
                            err_resp.set("msg", "ok");
                        }
                        Err(_) => {
                            err_resp.set("id", "1280");
                            err_resp.set("msg", "database error");
                        }
                    }
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "tokenlist" | "privilegekeylist" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.uid.clone(), c.is_admin),
                        None => (String::new(), false),
                    }
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_token_list")
                };

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "38");
                } else {
                    let tokens = {
                        let db = self.db.lock().await;
                        db.list_tokens().unwrap_or_default()
                    };
                    if !tokens.is_empty() {
                        let parts: Vec<String> = tokens
                            .iter()
                            .map(|t| {
                                format!(
                                    "token={} token_type={} token_id1={} token_id2={} token_created={} token_description={}",
                                    t.token,
                                    t.token_type,
                                    t.token_id1,
                                    t.token_id2,
                                    t.created_at,
                                    crate::command::escape(&t.description),
                                )
                            })
                            .collect();
                        let resp_name = if cmd.name.starts_with("privilegekey") {
                            "privilegekeylist"
                        } else {
                            "tokenlist"
                        };
                        let wire = format!("{} {}", resp_name, parts.join("|"));
                        self.send_encrypted_raw(peer, &wire).await?;
                    }
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "tokendelete" | "privilegekeydelete" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.uid.clone(), c.is_admin),
                        None => (String::new(), false),
                    }
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_token_delete")
                };
                let token = cmd.get("token").or_else(|| cmd.get("key")).unwrap_or("");

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "41");
                } else if token.is_empty() {
                    err_resp.set("id", "1538");
                    err_resp.set("msg", "invalid parameter");
                } else {
                    let db = self.db.lock().await;
                    let _ = db.delete_token(token);
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
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

                let redeemed_tok = {
                    let db = self.db.lock().await;
                    db.redeem_token(token).unwrap_or(None)
                };

                let mut err_resp = Command::new("error");
                if let Some(tok) = redeemed_tok {
                    let db = self.db.lock().await;
                    if tok.token_type == 0 {
                        // Server Group Token
                        let _ = db.add_client_to_server_group(&client_uid, tok.token_id1);
                        if tok.token_id1 == 6 {
                            let _ = db.add_admin_identity(&client_uid);
                            drop(db);
                            {
                                let mut state = self.state.lock().await;
                                if let Some(c) = state.get_client_mut(&peer) {
                                    c.is_admin = true;
                                }
                            }
                            info!(
                                "Client {} redeemed Server Admin privilege key!",
                                clid
                            );

                            let mut notify = Command::new("notifyclientupdated");
                            notify.set("clid", clid.to_string());
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

                            let _ = self
                                .send_encrypted_raw(peer, permissions::get_server_admin_perms_wire())
                                .await;
                            let _ = self.send_channel_group_perm_list(peer, 5, false).await;

                            let port = self.local_addr().map(|a| a.port()).unwrap_or(9988);
                            let props = {
                                let db = self.db.lock().await;
                                db.get_all_properties().unwrap_or_default()
                            };
                            let server_updated = build_server_updated(false, port, &props);
                            let _ = self.send_encrypted_command(peer, &server_updated).await;
                        } else {
                            // Non-admin server group token
                            let groups = db.get_client_server_groups(&client_uid).unwrap_or_default();
                            drop(db);
                            let grp_str = groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(",");
                            let mut notify = Command::new("notifyclientupdated");
                            notify.set("clid", clid.to_string());
                            notify.set("client_servergroups", &grp_str);
                            let all_endpoints: Vec<SocketAddr> = {
                                let state = self.state.lock().await;
                                state.clients.values().map(|c| c.endpoint).collect()
                            };
                            for ep in all_endpoints {
                                let _ = self.send_encrypted_command(ep, &notify).await;
                            }
                        }
                    } else if tok.token_type == 1 {
                        // Channel Group Token
                        let cid = if tok.token_id2 > 0 { tok.token_id2 } else { 1 };
                        let _ = db.set_client_channel_group(&client_uid, cid, tok.token_id1);
                        drop(db);

                        let mut notify = Command::new("notifyclientchannelgroupchanged");
                        notify.set("cgid", tok.token_id1.to_string());
                        notify.set("cid", cid.to_string());
                        notify.set("clid", clid.to_string());
                        notify.set("cgserverid", "0");
                        let all_endpoints: Vec<SocketAddr> = {
                            let state = self.state.lock().await;
                            state.clients.values().map(|c| c.endpoint).collect()
                        };
                        for ep in all_endpoints {
                            let _ = self.send_encrypted_command(ep, &notify).await;
                        }
                    }

                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                } else {
                    err_resp.set("id", "2561");
                    err_resp.set("msg", "privilege key invalid");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                let _ = self.send_encrypted_command(peer, &err_resp).await;
            }
            "permfind" => {
                let (caller_uid, is_admin) = {
                    let state = self.state.lock().await;
                    match state.get_client(&peer) {
                        Some(c) => (c.uid.clone(), c.is_admin),
                        None => (String::new(), false),
                    }
                };
                let has_perm = is_admin || {
                    let db = self.db.lock().await;
                    permissions::has_permission(&db, &caller_uid, 0, "b_virtualserver_permission_find")
                };

                let mut err_resp = Command::new("error");
                if !has_perm {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "34");
                } else {
                    let perm_name = if let Some(sid) = cmd.get("permsid") {
                        sid.to_string()
                    } else if let Some(pid_str) = cmd.get("permid") {
                        pid_str
                            .parse::<u32>()
                            .ok()
                            .and_then(permissions::perm_id_to_name)
                            .map(str::to_string)
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };

                    let matches = {
                        let db = self.db.lock().await;
                        db.find_permissions(&perm_name).unwrap_or_default()
                    };
                    let parts: Vec<String> = matches
                        .iter()
                        .map(|m| {
                            let pid = permissions::perm_name_to_id(&m.perm_id).unwrap_or(0);
                            format!(
                                "t={} id1={} id2={} p={} v={} n={} s={}",
                                m.tier,
                                m.id1,
                                m.id2,
                                pid,
                                m.perm_value,
                                if m.perm_negated { 1 } else { 0 },
                                if m.perm_skip { 1 } else { 0 },
                            )
                        })
                        .collect();
                    let wire = if parts.is_empty() {
                        "permfind".to_string()
                    } else {
                        format!("permfind {}", parts.join("|"))
                    };
                    self.send_encrypted_raw(peer, &wire).await?;
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "permidgetbyname" => {
                let permsid = cmd.get("permsid").unwrap_or("");
                let mut err_resp = Command::new("error");
                if let Some(permid) = permissions::perm_name_to_id(permsid) {
                    let mut resp = Command::new("permidgetbyname");
                    resp.set("permsid", permsid);
                    resp.set("permid", permid.to_string());
                    self.send_encrypted_command(peer, &resp).await?;
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                } else {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "permission invalid");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "permnamebyid" => {
                let permid: u32 = cmd.get("permid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let mut err_resp = Command::new("error");
                if let Some(name) = permissions::perm_id_to_name(permid) {
                    let mut resp = Command::new("permnamebyid");
                    resp.set("permid", permid.to_string());
                    resp.set("permsid", name);
                    self.send_encrypted_command(peer, &resp).await?;
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                } else {
                    err_resp.set("id", "2563");
                    err_resp.set("msg", "permission invalid");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "permreset" => {
                let is_admin = {
                    let state = self.state.lock().await;
                    state.get_client(&peer).map(|c| c.is_admin).unwrap_or(false)
                };
                let mut err_resp = Command::new("error");
                if !is_admin {
                    err_resp.set("id", "2568");
                    err_resp.set("msg", "insufficient client permissions");
                    err_resp.set("failed_permid", "32800");
                } else {
                    err_resp.set("id", "0");
                    err_resp.set("msg", "ok");
                }
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "clientdisconnect" | "quit" => {
                let reason_id = cmd.get("reasonid").unwrap_or("3");
                let reason_msg = cmd.get("reasonmsg").unwrap_or("");

                let cur_cid = {
                    let mut state = self.state.lock().await;
                    match state.get_client_mut(&peer) {
                        Some(c) => {
                            c.handshake_phase = HandshakePhase::Disconnected;
                            c.disconnect_time = Some(std::time::Instant::now());
                            c.current_channel_id
                        }
                        None => 1,
                    }
                };
                let other_peers = self.watching_recipients(&[cur_cid], Some(peer)).await;

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

                for ep in &other_peers {
                    let _ = self.send_encrypted_command(*ep, &notify).await;
                }
                {
                    let mut state = self.state.lock().await;
                    for ep in &other_peers {
                        if let Some(c) = state.get_client_mut(ep) {
                            c.known_clients.remove(&clid);
                        }
                    }
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
                if let Some(target_clid) = target_clid {
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
                            let can_kick = is_admin || {
                                let db = self.db.lock().await;
                                if reason_id == "4" {
                                    permissions::check_target_power(
                                        &db,
                                        &invoker_uid,
                                        &target_uid,
                                        old_cid,
                                        "i_client_kick_from_channel_power",
                                        "i_client_needed_kick_from_channel_power",
                                    )
                                } else {
                                    permissions::check_target_power(
                                        &db,
                                        &invoker_uid,
                                        &target_uid,
                                        0,
                                        "i_client_kick_from_server_power",
                                        "i_client_needed_kick_from_server_power",
                                    )
                                }
                            };

                            if !can_kick {
                                err_resp.set("id", "2568");
                                err_resp.set("msg", "insufficient client permissions");
                            } else if reason_id == "4" {
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
                                    // The official server always includes
                                    // reasonmsg (possibly empty); without the
                                    // parameter the official client aborts
                                    // with "parameter not found".
                                    moved.set("reasonmsg", reason_msg);
                                    moved.set("invokerid", clid.to_string());
                                    moved.set("invokername", &invoker_nickname);
                                    moved.set("invokeruid", &invoker_uid);

                                    // Watchers of the old channel know the
                                    // target; watchers of only the default
                                    // channel need an enter view instead.
                                    let target_details = {
                                        let state = self.state.lock().await;
                                        state
                                            .clients
                                            .get(&target_ep)
                                            .map(|c| (c.uid.clone(), c.is_admin, c.audio))
                                    };
                                    let (mut moved_eps, enter_eps) = self
                                        .move_recipients(old_cid, default_cid, target_ep)
                                        .await;
                                    moved_eps.push(target_ep);
                                    for ep in &moved_eps {
                                        let _ = self.send_encrypted_command(*ep, &moved).await;
                                    }
                                    if let Some((t_uid, t_admin, t_audio)) = target_details {
                                        for ep in &enter_eps {
                                            let view = build_client_enter_view(
                                                "0",
                                                target_clid,
                                                &t_uid,
                                                &target_nick,
                                                default_cid,
                                                old_cid,
                                                t_admin,
                                                t_audio,
                                            );
                                            let _ = self.send_encrypted_command(*ep, &view).await;
                                        }
                                        {
                                            let mut state = self.state.lock().await;
                                            for ep in &enter_eps {
                                                if let Some(c) = state.get_client_mut(ep) {
                                                    c.known_clients.insert(target_clid);
                                                }
                                            }
                                        }
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
                                notify.set("reasonmsg", reason_msg);
                                notify.set("invokerid", clid.to_string());
                                notify.set("invokername", &invoker_nickname);
                                notify.set("invokeruid", &invoker_uid);

                                // Send to kicked client first
                                let _ = self.send_encrypted_command(target_ep, &notify).await;

                                {
                                    let mut state = self.state.lock().await;
                                    if let Some(c) = state.clients.get_mut(&target_ep) {
                                        c.handshake_phase = HandshakePhase::Disconnected;
                                        c.disconnect_time = Some(std::time::Instant::now());
                                    }
                                }
                                let other_peers = self
                                    .watching_recipients(&[old_cid], Some(target_ep))
                                    .await;

                                for ep in &other_peers {
                                    let _ = self.send_encrypted_command(*ep, &notify).await;
                                }
                                {
                                    let mut state = self.state.lock().await;
                                    for ep in &other_peers {
                                        if let Some(c) = state.get_client_mut(ep) {
                                            c.known_clients.remove(&target_clid);
                                        }
                                    }
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
            "clientpoke" => {
                let target_clid: Option<u16> = cmd.get("clid").and_then(|v| v.parse().ok());
                let poke_msg = cmd.get("msg").unwrap_or("").to_string();

                let (invoker_nickname, invoker_uid) = {
                    let state = self.state.lock().await;
                    state
                        .get_client(&peer)
                        .map(|c| (c.nickname.clone(), c.uid.clone()))
                        .unwrap_or_else(|| ("User".to_string(), String::new()))
                };

                let mut err_resp = Command::new("error");
                let target_ep = {
                    let state = self.state.lock().await;
                    target_clid.and_then(|target_clid| {
                        state
                            .clients
                            .values()
                            .find(|c| {
                                c.clid == target_clid
                                    && c.handshake_phase == HandshakePhase::Connected
                            })
                            .map(|c| c.endpoint)
                    })
                };

                match target_ep {
                    Some(target_ep) => {
                        let mut poke = Command::new("notifyclientpoke");
                        poke.set("invokerid", clid.to_string());
                        poke.set("invokername", &invoker_nickname);
                        poke.set("invokeruid", &invoker_uid);
                        poke.set("msg", &poke_msg);
                        let _ = self.send_encrypted_command(target_ep, &poke).await;

                        info!(
                            "Client {} ({}) poked client {} with message '{}'",
                            clid, invoker_nickname, target_clid.unwrap(), poke_msg
                        );
                        err_resp.set("id", "0");
                        err_resp.set("msg", "ok");
                    }
                    None => {
                        err_resp.set("id", "512");
                        err_resp.set("msg", "invalid clientID");
                    }
                }

                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "banclient" => {
                let target_clid: Option<u16> = cmd.get("clid").and_then(|v| v.parse().ok());
                let target_uid_param = cmd.get("uid").unwrap_or("");
                let target_cldbid: Option<u64> = cmd.get("cldbid").and_then(|v| v.parse().ok());
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
                } else {
                    let target_info = {
                        let state = self.state.lock().await;
                        state
                            .clients
                            .values()
                            .find(|c| {
                                c.handshake_phase == HandshakePhase::Connected
                                    && (
                                        target_clid.map_or(false, |clid| c.clid == clid)
                                            || (!target_uid_param.is_empty() && c.uid == target_uid_param)
                                            || target_cldbid.map_or(false, |cldbid| c.clid as u64 == cldbid)
                                    )
                            })
                            .map(|c| {
                                (
                                    c.clid,
                                    c.endpoint,
                                    c.current_channel_id,
                                    c.nickname.clone(),
                                    c.uid.clone(),
                                )
                            })
                    };

                    let (found_target, target_clid_opt, target_ep_opt, old_cid_opt, target_nick, target_uid, target_ip) =
                        if let Some((t_clid, t_ep, t_cid, t_nick, t_uid)) = target_info {
                            let ip = t_ep.ip().to_string();
                            (true, Some(t_clid), Some(t_ep), Some(t_cid), t_nick, t_uid, ip)
                        } else if !target_uid_param.is_empty() {
                            let name = cmd.get("name").unwrap_or("").to_string();
                            (true, None, None, None, name, target_uid_param.to_string(), String::new())
                        } else {
                            (false, None, None, None, String::new(), String::new(), String::new())
                        };

                    if !found_target {
                        err_resp.set("id", "512");
                        err_resp.set("msg", "invalid clientID");
                    } else {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;

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

                        if let (Some(target_clid), Some(target_ep), Some(old_cid)) = (target_clid_opt, target_ep_opt, old_cid_opt) {
                            // Disconnect target client with reasonid=6 (Banned)
                            let mut notify = Command::new("notifyclientleftview");
                            notify.set("clid", target_clid.to_string());
                            notify.set("cfid", old_cid.to_string());
                            notify.set("ctid", "0");
                            notify.set("reasonid", "6");
                            notify.set("bantime", duration.to_string());
                            notify.set("reasonmsg", ban_reason);
                            notify.set("invokerid", clid.to_string());
                            notify.set("invokername", &invoker_nickname);
                            notify.set("invokeruid", &invoker_uid);

                            // Send to banned client first
                            let _ = self.send_encrypted_command(target_ep, &notify).await;

                            {
                                let mut state = self.state.lock().await;
                                if let Some(c) = state.clients.get_mut(&target_ep) {
                                    c.handshake_phase = HandshakePhase::Disconnected;
                                    c.disconnect_time = Some(std::time::Instant::now());
                                }
                            }
                            let other_peers = self
                                .watching_recipients(&[old_cid], Some(target_ep))
                                .await;

                            for ep in &other_peers {
                                let _ = self.send_encrypted_command(*ep, &notify).await;
                            }
                            {
                                let mut state = self.state.lock().await;
                                for ep in &other_peers {
                                    if let Some(c) = state.get_client_mut(ep) {
                                        c.known_clients.remove(&target_clid);
                                    }
                                }
                            }

                            info!(
                                "Client {} banned {} ({}) ban_id={}",
                                clid, target_clid, target_nick, ban_id
                            );
                        } else {
                            info!(
                                "Client {} added ban for uid {} ban_id={}",
                                clid, target_uid_param, ban_id
                            );
                        }

                        err_resp.set("id", "0");
                        err_resp.set("msg", "ok");
                        err_resp.set("banid", ban_id.to_string());
                    }
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
                        notify.set("bantime", duration.to_string());
                        notify.set("reasonmsg", ban_reason);
                        notify.set("invokerid", clid.to_string());
                        notify.set("invokername", &invoker_nickname);
                        notify.set("invokeruid", &invoker_uid);

                        let _ = self.send_encrypted_command(target_ep, &notify).await;

                        {
                            let mut state = self.state.lock().await;
                            if let Some(c) = state.clients.get_mut(&target_ep) {
                                c.handshake_phase = HandshakePhase::Disconnected;
                                c.disconnect_time = Some(std::time::Instant::now());
                            }
                        }
                        let other_peers = self
                            .watching_recipients(&[old_cid], Some(target_ep))
                            .await;

                        for ep in other_peers {
                            let _ = self.send_encrypted_command(ep, &notify).await;
                        }
                    }

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
            "ftgetfilelist" => {
                // No file transfer support. The official 3.13.7 server answers
                // ftgetfilelist for an empty channel with no notifications and
                // this exact error (verified via a decrypted MITM capture):
                // the client's Delete Channel / File Browser flows treat it as
                // an empty listing and continue.
                let mut err_resp = Command::new("error");
                err_resp.set("id", "1281");
                err_resp.set("msg", "database empty result set");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "version" => {
                let mut ver_resp = Command::new("version");
                ver_resp.set("version", "3.13.8");
                ver_resp.set("build", "1685172871");
                ver_resp.set("platform", "Linux");
                self.send_encrypted_command(peer, &ver_resp).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
                if let Some(rc) = cmd.get("return_code") {
                    err_resp.set("return_code", rc);
                }
                self.send_encrypted_command(peer, &err_resp).await?;
            }
            "logview" => {
                let instance = cmd.get("instance").map(|v| v == "1").unwrap_or(false);
                let log_entry = if instance {
                    "2026-10-26 08:00:00.000000|INFO    |ServerLibPriv |   |TeamSpeak 3 Server 3.13.8 (2026-05-27 09:34:31)"
                } else {
                    "2026-10-26 08:00:00.000000|INFO    |VirtualServerBase|1  |listening on 0.0.0.0:9988"
                };
                let mut log_resp = Command::new("logview");
                log_resp.set("last_pos", log_entry.len().to_string());
                log_resp.set("file_size", log_entry.len().to_string());
                log_resp.set("l", log_entry);
                self.send_encrypted_command(peer, &log_resp).await?;

                let mut err_resp = Command::new("error");
                err_resp.set("id", "0");
                err_resp.set("msg", "ok");
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

    /// Moves one client (`target`) into `new_cid` and fans out the view
    /// updates. A same-channel move is a silent no-op: broadcasting a
    /// redundant notifyclientmoved makes the official client disconnect with
    /// "Invalid Client moving: already member of channel".
    ///
    /// `sender` is the client that issued the command; when it differs from
    /// the moved client (an admin moving another user), the moved
    /// notification carries invoker fields, mirroring the captured official
    /// kick/move format.
    async fn perform_move(
        &self,
        sender_clid: u16,
        target: u16,
        new_cid: u64,
        sender_nick: &str,
        sender_uid: &str,
    ) {
        let move_ctx = {
            let mut state = self.state.lock().await;
            match state
                .clients
                .values_mut()
                .find(|c| c.clid == target && c.handshake_phase == HandshakePhase::Connected)
            {
                Some(c) if c.current_channel_id != new_cid => {
                    let old = c.current_channel_id;
                    let was_watching = c.subscribed_channels.contains(&new_cid);
                    c.current_channel_id = new_cid;
                    c.subscribed_channels.insert(new_cid);
                    Some((
                        old,
                        was_watching,
                        c.endpoint,
                        c.uid.clone(),
                        c.nickname.clone(),
                        c.is_admin,
                        c.audio,
                    ))
                }
                _ => None,
            }
        };

        if let Some((old_cid, was_watching, target_ep, target_uid, target_nick, target_admin, target_audio)) =
            move_ctx
        {
            let mut notify = Command::new("notifyclientmoved");
            notify.set("clid", target.to_string());
            notify.set("cfid", old_cid.to_string());
            notify.set("ctid", new_cid.to_string());
            notify.set("reasonid", "0");
            if sender_clid != target {
                notify.set("invokerid", sender_clid.to_string());
                notify.set("invokername", sender_nick);
                notify.set("invokeruid", sender_uid);
            }

            // Watchers of the old channel know the target: they get the moved
            // notification. Watchers of only the new channel have never seen
            // it: they get an enter view instead, or the client aborts with
            // "invalid clientID".
            let (mut moved_eps, enter_eps) =
                self.move_recipients(old_cid, new_cid, target_ep).await;
            moved_eps.push(target_ep);
            for ep in &moved_eps {
                let _ = self.send_encrypted_command(*ep, &notify).await;
            }

            for ep in &enter_eps {
                let view = build_client_enter_view(
                    "0",
                    target,
                    &target_uid,
                    &target_nick,
                    new_cid,
                    old_cid,
                    target_admin,
                    target_audio,
                );
                let _ = self.send_encrypted_command(*ep, &view).await;
            }
            {
                let mut state = self.state.lock().await;
                for ep in &enter_eps {
                    if let Some(c) = state.get_client_mut(ep) {
                        c.known_clients.insert(target);
                    }
                }
            }

            // If the target was not watching the new channel before, it has
            // never seen that channel's occupants: deliver their enter views
            // so they become visible.
            if !was_watching {
                self.send_subscription_enter_views(target_ep, target, &[new_cid])
                    .await;
            }

            info!(
                "Client {} moved client {} ({}) from channel {} to {}",
                sender_clid, target, target_nick, old_cid, new_cid
            );
        }
    }

    async fn handle_voice(&self, peer: SocketAddr, packet: &[u8]) -> Result<(), String> {
        let (cid, clid, is_muted) = {
            let state = self.state.lock().await;
            match state.get_client(&peer) {
                Some(c) => (c.current_channel_id, c.clid, c.audio.input_muted),
                None => return Ok(()),
            }
        };

        if is_muted {
            return Ok(());
        }

        // C2S voice header: MAC(8) + packet id(2) + client id(2) + flags(1).
        if packet.len() < 16 {
            return Ok(());
        }
        let sender_pid = u16::from_be_bytes([packet[8], packet[9]]);
        let sender_flags = packet[12];
        let sender_encrypted = sender_flags & Flags::UNENCRYPTED.bits() == 0;

        let payload: Vec<u8> = if sender_encrypted {
            // Encrypted channel: the speaker's payload is EAX-encrypted with
            // the sender's c2s voice key for (generation, packet id). The
            // generation advances whenever the sender's 16-bit voice packet
            // id wraps around 65535 -> 0.
            let generation = {
                let mut state = self.state.lock().await;
                let voice_generation = match state.get_client_mut(&peer) {
                    Some(c) => {
                        let (wrapped, should_update_last) = match c.last_c2s_voice_pid {
                            Some(last) => {
                                if sender_pid < last && (last - sender_pid) > 32768 {
                                    (true, true)
                                } else if sender_pid >= last {
                                    (false, true)
                                } else {
                                    (false, false)
                                }
                            }
                            None => (false, true),
                        };
                        if wrapped {
                            c.c2s_voice_generation += 1;
                        }
                        if should_update_last {
                            c.last_c2s_voice_pid = Some(sender_pid);
                        }
                        c.c2s_voice_generation
                    }
                    None => return Ok(()),
                };
                voice_generation
            };
            let sender_shared_iv = {
                let state = self.state.lock().await;
                match state.get_client(&peer).and_then(|c| c.shared_iv) {
                    Some(iv) => iv,
                    None => return Ok(()),
                }
            };
            let (key, nonce) =
                derive_key_nonce(Direction::C2S, PacketType::Voice as u8, generation, sender_pid, &sender_shared_iv);
            let mac: [u8; 8] = packet[0..8].try_into().map_err(|_| "Invalid MAC")?;
            let mut ciphertext = packet[13..].to_vec();
            decrypt_eax(&key, &nonce, &packet[8..13], &mac, &mut ciphertext)?;
            ciphertext
        } else {
            packet[13..].to_vec()
        };

        // C2S Voice packet payload format:
        // [seq_id (2 bytes)][codec (1 byte)][audio_data (N bytes)]
        if payload.len() < 3 {
            return Ok(());
        }
        let seq_id = &payload[0..2];
        let codec = payload[2];
        let audio_data = &payload[3..];

        let recipients: Vec<SocketAddr> = {
            let state = self.state.lock().await;
            state
                .clients_in_channel(cid)
                .iter()
                .filter(|c| c.clid != clid)
                .map(|c| c.endpoint)
                .collect()
        };

        // Channels with channel_codec_is_unencrypted=0 carry EAX-encrypted
        // voice; the relay decrypts the speaker payload and re-encrypts it
        // per receiver with that receiver's s2c voice key.
        let channel_encrypted = {
            let db = self.db.lock().await;
            db.get_channels()
                .unwrap_or_default()
                .into_iter()
                .find(|ch| ch.cid == cid)
                .map(|ch| !ch.codec_is_unencrypted)
                .unwrap_or(false)
        };

        for recipient in recipients {
            let (p_id, shared_mac, shared_iv, s2c_generation) = {
                let mut state = self.state.lock().await;
                let c = match state.get_client_mut(&recipient) {
                    Some(c) => c,
                    None => continue,
                };
                let id = c.next_s2c_voice_packet_id;
                let generation = c.s2c_voice_generation;
                c.next_s2c_voice_packet_id = id.wrapping_add(1);
                if id == u16::MAX {
                    c.s2c_voice_generation += 1;
                }
                let sm: [u8; 8] = c
                    .shared_iv
                    .map(|siv| Sha1::digest(&siv)[..8].try_into().unwrap())
                    .unwrap_or([0u8; 8]);
                (id, sm, c.shared_iv, generation)
            };

            if channel_encrypted {
                let Some(receiver_iv) = shared_iv else {
                    continue;
                };
                let (key, nonce) = derive_key_nonce(
                    Direction::S2C,
                    PacketType::Voice as u8,
                    s2c_generation,
                    p_id,
                    &receiver_iv,
                );
                let mut body = Vec::with_capacity(5 + audio_data.len());
                body.extend_from_slice(seq_id);
                body.extend_from_slice(&clid.to_be_bytes());
                body.push(codec);
                body.extend_from_slice(audio_data);
                let mac = encrypt_eax(&key, &nonce, &{
                    let mut aad = Vec::with_capacity(3);
                    aad.extend_from_slice(&p_id.to_be_bytes());
                    aad.push(PacketType::Voice as u8);
                    aad
                }, &mut body)?;

                let mut out = Vec::with_capacity(11 + body.len());
                out.extend_from_slice(&mac);
                out.extend_from_slice(&p_id.to_be_bytes());
                out.push(PacketType::Voice as u8);
                out.extend_from_slice(&body);
                let _ = self.socket.send_to(&out, recipient).await;
            } else {
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
            ch_cmd.set(
                "channel_flag_password",
                bool_wire(!ch.password_hash.is_empty()),
            );
            ch_cmd.set(
                "channel_codec_latency_factor",
                ch.codec_latency_factor.to_string(),
            );
            ch_cmd.set(
                "channel_codec_is_unencrypted",
                bool_wire(ch.codec_is_unencrypted),
            );
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
        self.send_channellist_finished(peer).await?;
        let _ = {
            let db = self.db.lock().await;
            db.get_channels().unwrap_or_default()
        };
        Ok(())
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

    /// Sends the channel groups known to the server.
    async fn send_channel_group_list(&self, peer: SocketAddr, notify: bool) -> Result<(), String> {
        let name = if notify {
            "notifychannelgrouplist"
        } else {
            "channelgrouplist"
        };
        let groups = {
            let db = self.db.lock().await;
            db.get_channel_groups().unwrap_or_default()
        };
        let parts: Vec<String> = groups
            .into_iter()
            .map(|g| {
                format!(
                    "cgid={} name={} type={} iconid={} savedb={} sortid=0 namemode=0 n_modifyp=75 n_member_addp={} n_member_removep={}",
                    g.group_id,
                    crate::command::escape(&g.name),
                    g.group_type,
                    g.icon_id,
                    if g.save_db { 1 } else { 0 },
                    if g.group_id == 5 { 50 } else { 0 },
                    if g.group_id == 5 { 50 } else { 0 },
                )
            })
            .collect();
        let wire = format!("{} {}", name, parts.join("|"));
        self.send_encrypted_raw(peer, &wire).await
    }

    async fn broadcast_server_group_list(&self) {
        let all_endpoints: Vec<SocketAddr> = {
            let state = self.state.lock().await;
            state.clients.values().map(|c| c.endpoint).collect()
        };
        for ep in all_endpoints {
            let _ = self.send_server_group_list(ep, true).await;
        }
    }

    async fn broadcast_channel_group_list(&self) {
        let all_endpoints: Vec<SocketAddr> = {
            let state = self.state.lock().await;
            state.clients.values().map(|c| c.endpoint).collect()
        };
        for ep in all_endpoints {
            let _ = self.send_channel_group_list(ep, true).await;
        }
    }

    /// Channel group permissions from the database.
    async fn send_channel_group_perm_list(
        &self,
        peer: SocketAddr,
        cgid: u64,
        use_permsid: bool,
    ) -> Result<(), String> {
        let wire = {
            let db = self.db.lock().await;
            permissions::build_channel_group_perm_list(&db, cgid, use_permsid)
        };
        self.send_encrypted_raw(peer, &wire).await
    }

    /// Server group permissions from the database.
    async fn send_server_group_perm_list(
        &self,
        peer: SocketAddr,
        sgid: u64,
        use_permsid: bool,
    ) -> Result<(), String> {
        let wire = {
            let db = self.db.lock().await;
            permissions::build_server_group_perm_list(&db, sgid, use_permsid)
        };
        self.send_encrypted_raw(peer, &wire).await
    }

    /// Sends the server groups as one multi-part command. `notify`
    /// selects the unsolicited `notifyservergrouplist` form; the plain
    /// `servergrouplist` form is the response to a client query.
    async fn send_server_group_list(&self, peer: SocketAddr, notify: bool) -> Result<(), String> {
        let name = if notify {
            "notifyservergrouplist"
        } else {
            "servergrouplist"
        };
        let groups = {
            let db = self.db.lock().await;
            db.get_server_groups().unwrap_or_default()
        };
        let parts: Vec<String> = groups
            .into_iter()
            .map(|g| {
                format!(
                    "sgid={} name={} type={} iconid={} savedb={} sortid=0 namemode=0 n_modifyp=75 n_member_addp={} n_member_removep={}",
                    g.group_id,
                    crate::command::escape(&g.name),
                    g.group_type,
                    g.icon_id,
                    if g.save_db { 1 } else { 0 },
                    if g.group_id == 6 { 75 } else { 0 },
                    if g.group_id == 6 { 75 } else { 0 },
                )
            })
            .collect();
        let wire = format!("{} {}", name, parts.join("|"));
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

    #[test]
    fn test_quicklz_compressed_reassembly() {
        use std::collections::BTreeMap;
        let data = b"setconnectioninfo connection_ping=12.3456";
        let compressed = quicklz::compress(data, quicklz::CompressionLevel::Lvl1);

        let mut pending: BTreeMap<u16, (Flags, Vec<u8>)> = BTreeMap::new();
        pending.insert(1, (Flags::COMPRESSED, compressed));

        let (text, consumed) = try_assemble_next(&mut pending, 1).expect("complete command");
        assert_eq!(consumed, 1);
        assert_eq!(text, "setconnectioninfo connection_ping=12.3456");
    }
}
