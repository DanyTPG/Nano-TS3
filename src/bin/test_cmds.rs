use nano_ts3::command::Command;

fn main() {
    // 1. initserver
    let mut initserver = Command::new("initserver");
    initserver.set("virtualserver_name", "Nano-TS3 Clean Server");
    initserver.set("virtualserver_welcomemessage", "Welcome to Nano-TS3!");
    initserver.set("virtualserver_maxclients", "32");
    initserver.set("virtualserver_platform", "Windows");
    initserver.set("virtualserver_version", "3.13.7 [Build: 1600000000]");
    initserver.set("virtualserver_default_server_group", "8");
    initserver.set("virtualserver_default_channel_group", "8");
    initserver.set("virtualserver_default_channel_admin_group", "5");
    initserver.set("virtualserver_codec_encryption_mode", "1");
    initserver.set("virtualserver_hostmessage", "");
    initserver.set("virtualserver_hostmessage_mode", "0");
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
    initserver.set("acn", "Admin");
    initserver.set("aclid", "2");
    initserver.set("pv", "4");

    println!("=== INITSERVER ===\n{}", initserver.build());

    // 2. channellist
    let mut ch_cmd = Command::new("channellist");
    ch_cmd.set("cid", "1");
    ch_cmd.set("cpid", "0");
    ch_cmd.set("channel_name", "Default Channel");
    ch_cmd.set("channel_topic", "Welcome to Nano-TS3");
    ch_cmd.set("channel_codec", "4");
    ch_cmd.set("channel_codec_quality", "7");
    ch_cmd.set("channel_maxclients", "-1");
    ch_cmd.set("channel_maxfamilyclients", "-1");
    ch_cmd.set("channel_order", "0");
    ch_cmd.set("channel_flag_permanent", "1");
    ch_cmd.set("channel_flag_semi_permanent", "0");
    ch_cmd.set("channel_flag_default", "1");
    ch_cmd.set("channel_flag_password", "0");
    ch_cmd.set("channel_codec_latency_factor", "1");
    ch_cmd.set("channel_codec_is_unencrypted", "1");
    ch_cmd.set("channel_delete_delay", "0");
    ch_cmd.set("channel_flag_maxclients_unlimited", "1");
    ch_cmd.set("channel_flag_maxfamilyclients_unlimited", "1");
    ch_cmd.set("channel_flag_maxfamilyclients_inherited", "0");
    ch_cmd.set("channel_needed_talk_power", "0");
    ch_cmd.set("channel_forced_silence", "0");
    ch_cmd.set("channel_name_phonetic", "");
    ch_cmd.set("channel_icon_id", "0");

    println!("\n=== CHANNELLIST ===\n{}", ch_cmd.build());

    // 3. notifycliententerview
    let mut enter = Command::new("notifycliententerview");
    enter.set("reasonid", "2");
    enter.set("cfid", "0");
    enter.set("ctid", "1");
    enter.set("clid", "2");
    enter.set("client_database_id", "2");
    enter.set("cldbid", "2");
    enter.set("client_nickname", "Admin");
    enter.set("name", "Admin");
    enter.set("client_type", "0");
    enter.set("client_unique_identifier", "nano_uid_2");
    enter.set("cluid", "nano_uid_2");
    enter.set("client_flag_avatar", "");
    enter.set("client_description", "");
    enter.set("client_icon_id", "0");
    enter.set("client_input_muted", "0");
    enter.set("client_output_muted", "0");
    enter.set("client_outputonly_muted", "0");
    enter.set("client_input_hardware", "1");
    enter.set("client_output_hardware", "1");
    enter.set("client_meta_data", "");
    enter.set("client_is_recording", "0");
    enter.set("client_channel_group_id", "8");
    enter.set("client_channel_group_inherited_channel_id", "1");
    enter.set("client_servergroups", "6");
    enter.set("client_away", "0");
    enter.set("client_away_message", "");
    enter.set("client_talk_power", "0");
    enter.set("client_talk_request", "0");
    enter.set("client_talk_request_msg", "");
    enter.set("client_is_talker", "0");
    enter.set("client_is_priority_speaker", "0");
    enter.set("client_unread_messages", "0");
    enter.set("client_nickname_phonetic", "");
    enter.set("client_needed_serverquery_view_power", "75");
    enter.set("client_is_channel_commander", "0");
    enter.set("client_country", "");
    enter.set("client_badges", "");
    enter.set("client_myteamspeak_id", "");
    enter.set("client_integrations", "");

    println!("\n=== NOTIFYCLIENTENTERVIEW ===\n{}", enter.build());

    use tsproto_packets::packets::*;
    let mut ack = OutAck::new(Direction::S2C, PacketType::Command, 5);
    ack.flags(Flags::UNENCRYPTED);
    let bytes = ack.into_vec();
    println!("\n=== ACK ===\nlen={}: {:02x?}", bytes.len(), bytes);
}
