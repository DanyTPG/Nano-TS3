// Generated TeamSpeak 3 permissions data and helper functions
use std::sync::OnceLock;

static PERMISSION_LIST_WIRE: OnceLock<String> = OnceLock::new();

pub fn get_client_needed_permissions_wire() -> &'static str {
    concat!(
        "notifyclientneededpermissions ",
        "permid=178 permvalue=200000|permid=179 permvalue=-1|permid=170 permvalue=75|permid=164 permvalue=75|permid=154 permvalue=1|permid=159 permvalue=1|",
        "permid=157 permvalue=1|permid=161 permvalue=1|permid=158 permvalue=1|permid=192 permvalue=1|permid=211 permvalue=1|permid=208 permvalue=1|permid=44 permvalue=1|permid=232 permvalue=1|",
        "permid=26 permvalue=1|permid=228 permvalue=1|permid=218 permvalue=1|permid=219 permvalue=1|permid=166 permvalue=75|permid=168 permvalue=75|permid=243 permvalue=75|permid=65 permvalue=1|",
        "permid=63 permvalue=1|permid=57 permvalue=1|permid=58 permvalue=1|permid=59 permvalue=1|permid=66 permvalue=1|permid=60 permvalue=1|permid=70 permvalue=1|permid=52 permvalue=1|",
        "permid=53 permvalue=1|permid=54 permvalue=1|permid=56 permvalue=1|permid=61 permvalue=1|permid=62 permvalue=1|permid=64 permvalue=1|permid=67 permvalue=1|permid=69 permvalue=1|",
        "permid=68 permvalue=1|permid=72 permvalue=1|permid=71 permvalue=1|permid=80 permvalue=1|permid=81 permvalue=1|permid=112 permvalue=1|permid=115 permvalue=1|permid=113 permvalue=1|",
        "permid=114 permvalue=1|permid=117 permvalue=1|permid=118 permvalue=1|permid=109 permvalue=1|permid=110 permvalue=1|permid=111 permvalue=1|permid=108 permvalue=1|permid=116 permvalue=1|",
        "permid=120 permvalue=1|permid=121 permvalue=1|permid=122 permvalue=1|permid=123 permvalue=1|permid=88 permvalue=1|permid=89 permvalue=1|permid=91 permvalue=1|permid=92 permvalue=1|",
        "permid=93 permvalue=1|permid=94 permvalue=1|permid=95 permvalue=1|permid=100 permvalue=1|permid=101 permvalue=1|permid=102 permvalue=1|permid=103 permvalue=1|permid=96 permvalue=1|",
        "permid=97 permvalue=1|permid=98 permvalue=10|permid=195 permvalue=75|permid=90 permvalue=1|permid=160 permvalue=1|permid=128 permvalue=1|permid=129 permvalue=1|permid=130 permvalue=1|",
        "permid=131 permvalue=1|permid=225 permvalue=1|permid=104 permvalue=1|permid=38 permvalue=1|permid=39 permvalue=1|permid=40 permvalue=1|permid=41 permvalue=1|permid=42 permvalue=1|",
        "permid=43 permvalue=1|permid=212 permvalue=1|permid=153 permvalue=1|permid=155 permvalue=1|permid=156 permvalue=1|permid=215 permvalue=-1|permid=147 permvalue=1|permid=146 permvalue=8192|",
        "permid=74 permvalue=1|permid=229 permvalue=1|permid=220 permvalue=1|permid=31 permvalue=1|permid=55 permvalue=1|permid=99 permvalue=1|permid=119 permvalue=1|permid=126 permvalue=1|",
        "permid=76 permvalue=1|permid=186 permvalue=1|permid=162 permvalue=1|permid=163 permvalue=1|permid=193 permvalue=1|permid=248 permvalue=-1|permid=247 permvalue=-1|permid=75 permvalue=1|",
        "permid=173 permvalue=1|permid=172 permvalue=1|permid=214 permvalue=1|permid=213 permvalue=1|permid=77 permvalue=1|permid=187 permvalue=1|permid=188 permvalue=1|",
        "permid=79 permvalue=1|permid=106 permvalue=86400|permid=127 permvalue=1|permid=125 permvalue=1|permid=133 permvalue=1|permid=199 permvalue=1|permid=201 permvalue=1|permid=203 permvalue=1",
    )
}

pub fn get_notifypermissionlist_wire() -> &'static str {
    PERMISSION_LIST_WIRE.get_or_init(|| {
        r#"notifypermissionlist group_id_end=0|group_id_end=6|group_id_end=12|group_id_end=20|group_id_end=23|group_id_end=23|group_id_end=35|group_id_end=51|group_id_end=81|group_id_end=86|group_id_end=87|group_id_end=106|group_id_end=127|group_id_end=133|group_id_end=144|group_id_end=152|group_id_end=161|group_id_end=163|group_id_end=171|group_id_end=173|group_id_end=190|group_id_end=197|group_id_end=215|group_id_end=227|group_id_end=232|group_id_end=248|permname=b_serverinstance_help_view permdesc=Retrieve\sinformation\sabout\sServerQuery\scommands|permname=b_serverinstance_info_view permdesc=Retrieve\sglobal\sserver\sinformation|permname=b_serverinstance_virtualserver_list permdesc=List\svirtual\sservers\sstored\sin\sthe\sdatabase|permname=b_serverinstance_binding_list permdesc=List\sactive\sIP\sbindings\son\smulti-homed\smachines|permname=b_serverinstance_permission_list permdesc=List\spermissions\savailable\savailable\son\sthe\sserver\sinstance|permname=b_serverinstance_permission_find permdesc=Search\spermission\sassignments\sby\sname\sor\sID|permname=b_virtualserver_create permdesc=Create\svirtual\sservers|permname=b_virtualserver_delete permdesc=Delete\svirtual\sservers|permname=b_virtualserver_start_any permdesc=Start\sany\svirtual\sserver\sin\sthe\sserver\sinstance|permname=b_virtualserver_stop_any permdesc=Stop\sany\svirtual\sserver\sin\sthe\sserver\sinstance|permname=b_virtualserver_change_machine_id permdesc=Change\sa\svirtual\sservers\smachine\sID|permname=b_virtualserver_change_template permdesc=Edit\svirtual\sserver\sdefault\stemplate\svalues|permname=b_serverquery_login permdesc=Login\sto\sServerQuery|permname=b_serverquery_login_create permdesc=Create\sa\snew\sserver\squery\slogin|permname=b_serverquery_login_delete permdesc=Delete\sa\sserver\squery\slogin|permname=b_serverquery_login_list permdesc=List\sserver\squery\slogins|permname=b_serverinstance_textmessage_send permdesc=Send\stext\smessages\sto\sall\svirtual\sservers\sat\sonce|permname=b_serverinstance_log_view permdesc=Retrieve\sglobal\sserver\slog|permname=b_serverinstance_log_add permdesc=Write\sto\sglobal\sserver\slog|permname=b_serverinstance_stop permdesc=Shutdown\sthe\sserver\sprocess|permname=b_serverinstance_modify_settings permdesc=Edit\sglobal\ssettings|permname=b_serverinstance_modify_querygroup permdesc=Edit\sglobal\sServerQuery\sgroups|permname=b_serverinstance_modify_templates permdesc=Edit\sglobal\stemplate\sgroups|permname=b_virtualserver_select permdesc=Select\sa\svirtual\sserver|permname=b_virtualserver_info_view permdesc=Retrieve\svirtual\sserver\sinformation|permname=b_virtualserver_connectioninfo_view permdesc=Retrieve\svirtual\sserver\sconnection\sinformation|permname=b_virtualserver_channel_list permdesc=List\schannels\son\sa\svirtual\sserver|permname=b_virtualserver_channel_search permdesc=Search\sfor\schannels\son\sa\svirtual\sserver|permname=b_virtualserver_client_list permdesc=List\sclients\sonline\son\sa\svirtual\sserver|permname=b_virtualserver_client_search permdesc=Search\sfor\sclients\sonline\son\sa\svirtual\sserver|permname=b_virtualserver_client_dblist permdesc=List\sclient\sidentities\sknown\sby\sthe\svirtual\sserver|permname=b_virtualserver_client_dbsearch permdesc=Search\sfor\sclient\sidentities\sknown\sby\sthe\svirtual\sserver|permname=b_virtualserver_client_dbinfo permdesc=Retrieve\sclient\sinformation|permname=b_virtualserver_permission_find permdesc=Find\spermissions|permname=b_virtualserver_custom_search permdesc=Find\scustom\sfields|permname=b_virtualserver_start permdesc=Start\sown\svirtual\sserver|permname=b_virtualserver_stop permdesc=Stop\sown\svirtual\sserver|permname=b_virtualserver_token_list permdesc=List\sprivilege\skeys\savailable|permname=b_virtualserver_token_add permdesc=Create\snew\sprivilege\skeys|permname=b_virtualserver_token_use permdesc=Use\sa\sprivilege\skeys\sto\sgain\saccess\sto\sgroups|permname=b_virtualserver_token_delete permdesc=Delete\sa\sprivilege\skey|permname=b_virtualserver_apikey_add permdesc=Create\sa\snew\sAPI\skey|permname=b_virtualserver_apikey_manage permdesc=Manage\sexisting\sAPI\skeys|permname=b_virtualserver_log_view permdesc=Retrieve\svirtual\sserver\slog|permname=b_virtualserver_log_add permdesc=Write\sto\svirtual\sserver\slog|permname=b_virtualserver_join_ignore_password permdesc=Join\svirtual\sserver\signoring\sits\spassword|permname=b_virtualserver_notify_register permdesc=Register\sfor\sserver\snotifications|permname=b_virtualserver_notify_unregister permdesc=Unregister\sfrom\sserver\snotifications|permname=b_virtualserver_snapshot_create permdesc=Create\sserver\ssnapshots|permname=b_virtualserver_snapshot_deploy permdesc=Deploy\sserver\ssnapshots|permname=b_virtualserver_permission_reset permdesc=Reset\sthe\sserver\spermission\ssettings\sto\sdefault\svalues|permname=b_virtualserver_modify_name permdesc=Modify\sserver\sname|permname=b_virtualserver_modify_welcomemessage permdesc=Modify\swelcome\smessage|permname=b_virtualserver_modify_maxclients permdesc=Modify\sservers\smax\sclients|permname=b_virtualserver_modify_reserved_slots permdesc=Modify\sreserved\sslots|permname=b_virtualserver_modify_password permdesc=Modify\sserver\spassword|permname=b_virtualserver_modify_default_servergroup permdesc=Modify\sdefault\sServer\sGroup|permname=b_virtualserver_modify_default_channelgroup permdesc=Modify\sdefault\sChannel\sGroup|permname=b_virtualserver_modify_default_channeladmingroup permdesc=Modify\sdefault\sChannel\sAdmin\sGroup|permname=b_virtualserver_modify_channel_forced_silence permdesc=Modify\schannel\sforce\ssilence\svalue|permname=b_virtualserver_modify_complain permdesc=Modify\sindividual\scomplain\ssettings|permname=b_virtualserver_modify_antiflood permdesc=Modify\sindividual\santiflood\ssettings|permname=b_virtualserver_modify_ft_settings permdesc=Modify\sfile\stransfer\ssettings|permname=b_virtualserver_modify_ft_quotas permdesc=Modify\sfile\stransfer\squotas|permname=b_virtualserver_modify_hostmessage permdesc=Modify\sindividual\shostmessage\ssettings|permname=b_virtualserver_modify_hostbanner permdesc=Modify\sindividual\shostbanner\ssettings|permname=b_virtualserver_modify_hostbutton permdesc=Modify\sindividual\shostbutton\ssettings|permname=b_virtualserver_modify_port permdesc=Modify\sserver\sport|permname=b_virtualserver_modify_autostart permdesc=Modify\sserver\sautostart|permname=b_virtualserver_modify_needed_identity_security_level permdesc=Modify\srequired\sidentity\ssecurity\slevel|permname=b_virtualserver_modify_priority_speaker_dimm_modificator permdesc=Modify\spriority\sspeaker\sdimm\smodificator|permname=b_virtualserver_modify_log_settings permdesc=Modify\slog\ssettings|permname=b_virtualserver_modify_min_client_version permdesc=Modify\smin\sclient\sversion|permname=b_virtualserver_modify_icon_id permdesc=Modify\sserver\sicon|permname=b_virtualserver_modify_weblist permdesc=Modify\sweb\sserver\slist\sreporting\ssettings|permname=b_virtualserver_modify_codec_encryption_mode permdesc=Modify\scodec\sencryption\smode|permname=b_virtualserver_modify_temporary_passwords permdesc=Modify\stemporary\sserverpasswords|permname=b_virtualserver_modify_temporary_passwords_own permdesc=Modify\sown\stemporary\sserverpasswords|permname=b_virtualserver_modify_channel_temp_delete_delay_default permdesc=Modify\sdefault\stemporary\schannel\sdelete\sdelay|permname=b_virtualserver_modify_nickname permdesc=Modify\sserver\snicknames|permname=b_virtualserver_modify_integrations permdesc=Modify\sintegrations|permname=i_channel_min_depth permdesc=Min\schannel\screation\sdepth\sin\shierarchy|permname=i_channel_max_depth permdesc=Max\schannel\screation\sdepth\sin\shierarchy|permname=b_channel_group_inheritance_end permdesc=Stop\sinheritance\sof\schannel\sgroup\spermissions|permname=i_channel_permission_modify_power permdesc=Modify\schannel\spermission\spower|permname=i_channel_needed_permission_modify_power permdesc=Needed\smodify\schannel\spermission\spower|permname=b_channel_info_view permdesc=Retrieve\schannel\sinformation|permname=b_channel_create_child permdesc=Create\ssub-channels|permname=b_channel_create_permanent permdesc=Create\spermanent\schannels|permname=b_channel_create_semi_permanent permdesc=Create\ssemi-permanent\schannels|permname=b_channel_create_temporary permdesc=Create\stemporary\schannels|permname=b_channel_create_with_topic permdesc=Create\schannels\swith\sa\stopic|permname=b_channel_create_with_description permdesc=Create\schannels\swith\sa\sdescription|permname=b_channel_create_with_password permdesc=Create\spassword\sprotected\schannels|permname=b_channel_create_with_banner permdesc=Create\schannel\swith\sa\sbanner|permname=b_channel_create_modify_with_codec_opusvoice permdesc=Create\schannels\susing\sOPUS\s(voice)\scodec|permname=b_channel_create_modify_with_codec_opusmusic permdesc=Create\schannels\susing\sOPUS\s(music)\scodec|permname=i_channel_create_modify_with_codec_maxquality permdesc=Create\schannels\swith\scustom\scodec\squality|permname=i_channel_create_modify_with_codec_latency_factor_min permdesc=Create\schannels\swith\sminimal\scustom\scodec\slatency\sfactor|permname=b_channel_create_with_maxclients permdesc=Create\schannels\swith\scustom\smax\sclients|permname=b_channel_create_with_maxfamilyclients permdesc=Create\schannels\swith\scustom\smax\sfamily\sclients|permname=b_channel_create_with_sortorder permdesc=Create\schannels\swith\scustom\ssort\sorder|permname=b_channel_create_with_default permdesc=Create\sdefault\schannels|permname=b_channel_create_with_needed_talk_power permdesc=Create\schannels\swith\sneeded\stalk\spower|permname=b_channel_create_modify_with_force_password permdesc=Create\snew\schannels\sonly\swith\spassword|permname=i_channel_create_modify_with_temp_delete_delay permdesc=Max\sdelete\sdelay\sfor\stemporary\schannels|permname=b_channel_modify_parent permdesc=Move\schannels|permname=b_channel_modify_make_default permdesc=Make\schannel\sdefault|permname=b_channel_modify_make_permanent permdesc=Make\schannel\spermanent|permname=b_channel_modify_make_semi_permanent permdesc=Make\schannel\ssemi-permanent|permname=b_channel_modify_make_temporary permdesc=Make\schannel\stemporary|permname=b_channel_modify_name permdesc=Modify\schannel\sname|permname=b_channel_modify_topic permdesc=Modify\schannel\stopic|permname=b_channel_modify_description permdesc=Modify\schannel\sdescription|permname=b_channel_modify_password permdesc=Modify\schannel\spassword|permname=b_channel_modify_banner permdesc=Modify\schannel\sbanner|permname=b_channel_modify_codec permdesc=Modify\schannel\scodec|permname=b_channel_modify_codec_quality permdesc=Modify\schannel\scodec\squality|permname=b_channel_modify_codec_latency_factor permdesc=Modify\schannel\scodec\slatency\sfactor|permname=b_channel_modify_maxclients permdesc=Modify\schannels\smax\sclients|permname=b_channel_modify_maxfamilyclients permdesc=Modify\schannels\smax\sfamily\sclients|permname=b_channel_modify_sortorder permdesc=Modify\schannel\ssort\sorder|permname=b_channel_modify_needed_talk_power permdesc=Change\sneeded\schannel\stalk\spower|permname=i_channel_modify_power permdesc=Channel\smodify\spower|permname=i_channel_needed_modify_power permdesc=Needed\schannel\smodify\spower|permname=b_channel_modify_make_codec_encrypted permdesc=Make\schannel\scodec\sencrypted|permname=b_channel_modify_temp_delete_delay permdesc=Modify\stemporary\schannel\sdelete\sdelay|permname=b_channel_delete_permanent permdesc=Delete\spermanent\schannels|permname=b_channel_delete_semi_permanent permdesc=Delete\ssemi-permanent\schannels|permname=b_channel_delete_temporary permdesc=Delete\stemporary\schannels|permname=b_channel_delete_flag_force permdesc=Force\schannel\sdelete|permname=i_channel_delete_power permdesc=Delete\schannel\spower|permname=i_channel_needed_delete_power permdesc=Needed\sdelete\schannel\spower|permname=b_channel_join_permanent permdesc=Join\spermanent\schannels|permname=b_channel_join_semi_permanent permdesc=Join\ssemi-permanent\schannels|permname=b_channel_join_temporary permdesc=Join\stemporary\schannels|permname=b_channel_join_ignore_password permdesc=Join\schannel\signoring\sits\spassword|permname=b_channel_join_ignore_maxclients permdesc=Ignore\schannels\smax\sclients\slimit|permname=i_channel_join_power permdesc=Channel\sjoin\spower|permname=i_channel_needed_join_power permdesc=Needed\schannel\sjoin\spower|permname=i_channel_subscribe_power permdesc=Channel\ssubscribe\spower|permname=i_channel_needed_subscribe_power permdesc=Needed\schannel\ssubscribe\spower|permname=i_channel_description_view_power permdesc=Channel\sdescription\sview\spower|permname=i_channel_needed_description_view_power permdesc=Needed\schannel\sneeded\sdescription\sview\spower|permname=i_icon_id permdesc=Group\sicon\sidentifier|permname=i_max_icon_filesize permdesc=Max\sicon\sfilesize\sin\sbytes|permname=b_icon_manage permdesc=Enables\sicon\smanagement|permname=b_group_is_permanent permdesc=Group\sis\spermanent|permname=i_group_auto_update_type permdesc=Group\sauto-update\stype|permname=i_group_auto_update_max_value permdesc=Group\sauto-update\smax\svalue|permname=i_group_sort_id permdesc=Group\ssort\sid|permname=i_group_show_name_in_tree permdesc=Show\sgroup\sname\sin\stree\sdepending\son\sselected\smode|permname=b_virtualserver_servergroup_list permdesc=List\sserver\sgroups|permname=b_virtualserver_servergroup_permission_list permdesc=List\sserver\sgroup\spermissions|permname=b_virtualserver_servergroup_client_list permdesc=List\sclients\sfrom\sa\sserver\sgroup|permname=b_virtualserver_channelgroup_list permdesc=List\schannel\sgroups|permname=b_virtualserver_channelgroup_permission_list permdesc=List\schannel\sgroup\spermissions|permname=b_virtualserver_channelgroup_client_list permdesc=List\sclients\sfrom\sa\schannel\sgroup|permname=b_virtualserver_client_permission_list permdesc=List\sclient\spermissions|permname=b_virtualserver_channel_permission_list permdesc=List\schannel\spermissions|permname=b_virtualserver_channelclient_permission_list permdesc=List\schannel\sclient\spermissions|permname=b_virtualserver_servergroup_create permdesc=Create\sserver\sgroups|permname=b_virtualserver_channelgroup_create permdesc=Create\schannel\sgroups|permname=i_group_modify_power permdesc=Group\smodify\spower|permname=i_group_needed_modify_power permdesc=Needed\sgroup\smodify\spower|permname=i_group_member_add_power permdesc=Group\smember\sadd\spower|permname=i_group_needed_member_add_power permdesc=Needed\sgroup\smember\sadd\spower|permname=i_group_member_remove_power permdesc=Group\smember\sdelete\spower|permname=i_group_needed_member_remove_power permdesc=Needed\sgroup\smember\sdelete\spower|permname=i_permission_modify_power permdesc=Permission\smodify\spower|permname=b_permission_modify_power_ignore permdesc=Ignore\sneeded\spermission\smodify\spower|permname=b_virtualserver_servergroup_delete permdesc=Delete\sserver\sgroups|permname=b_virtualserver_channelgroup_delete permdesc=Delete\schannel\sgroups|permname=i_client_permission_modify_power permdesc=Client\spermission\smodify\spower|permname=i_client_needed_permission_modify_power permdesc=Needed\sclient\spermission\smodify\spower|permname=i_client_max_clones_uid permdesc=Max\sadditional\sconnections\sper\sclient\sidentity|permname=i_client_max_idletime permdesc=Max\sidle\stime\sin\sseconds|permname=i_client_max_avatar_filesize permdesc=Max\savatar\sfilesize\sin\sbytes|permname=i_client_max_channel_subscriptions permdesc=Max\schannel\ssubscriptions|permname=b_client_is_priority_speaker permdesc=Client\sis\spriority\sspeaker|permname=b_client_skip_channelgroup_permissions permdesc=Ignore\schannel\sgroup\spermissions|permname=b_client_force_push_to_talk permdesc=Force\sPush-To-Talk\scapture\smode|permname=b_client_ignore_bans permdesc=Ignore\sbans|permname=b_client_ignore_antiflood permdesc=Ignore\santiflood\smeasurements|permname=b_client_use_reserved_slot permdesc=Use\san\sreserved\sslot|permname=b_client_use_channel_commander permdesc=Use\schannel\scommander|permname=b_client_request_talker permdesc=Allow\sto\srequest\stalk\spower|permname=b_client_avatar_delete_other permdesc=Allow\sdeletion\sof\savatars\sfrom\sother\sclients|permname=b_client_is_sticky permdesc=Client\swill\sbe\ssticked\sto\scurrent\schannel|permname=b_client_ignore_sticky permdesc=Client\signores\ssticky\sflag|permname=b_client_info_view permdesc=Retrieve\sclient\sinformation|permname=b_client_permissionoverview_view permdesc=Retrieve\sclient\spermissions\soverview|permname=b_client_permissionoverview_own permdesc=Retrieve\sclients\sown\spermissions\soverview|permname=b_client_remoteaddress_view permdesc=View\sclient\sIP\saddress\sand\sport|permname=i_client_serverquery_view_power permdesc=ServerQuery\sview\spower|permname=i_client_needed_serverquery_view_power permdesc=Needed\sServerQuery\sview\spower|permname=b_client_custom_info_view permdesc=View\scustom\sfields|permname=i_client_kick_from_server_power permdesc=Client\skick\spower\sfrom\sserver|permname=i_client_needed_kick_from_server_power permdesc=Needed\sclient\skick\spower\sfrom\sserver|permname=i_client_kick_from_channel_power permdesc=Client\skick\spower\sfrom\schannel|permname=i_client_needed_kick_from_channel_power permdesc=Needed\sclient\skick\spower\sfrom\schannel|permname=i_client_ban_power permdesc=Client\sban\spower|permname=i_client_needed_ban_power permdesc=Needed\sclient\sban\spower|permname=i_client_move_power permdesc=Client\smove\spower|permname=i_client_needed_move_power permdesc=Needed\sclient\smove\spower|permname=i_client_complain_power permdesc=Complain\spower|permname=i_client_needed_complain_power permdesc=Needed\scomplain\spower|permname=b_client_complain_list permdesc=Show\scomplain\slist|permname=b_client_complain_delete_own permdesc=Delete\sown\scomplains|permname=b_client_complain_delete permdesc=Delete\scomplains|permname=b_client_ban_list permdesc=Show\sbanlist|permname=b_client_ban_create permdesc=Add\sa\sban|permname=b_client_ban_delete_own permdesc=Delete\sown\sbans|permname=b_client_ban_delete permdesc=Delete\sbans|permname=i_client_ban_max_bantime permdesc=Max\sbantime|permname=i_client_private_textmessage_power permdesc=Client\sprivate\smessage\spower|permname=i_client_needed_private_textmessage_power permdesc=Needed\sclient\sprivate\smessage\spower|permname=b_client_server_textmessage_send permdesc=Send\stext\smessages\sto\svirtual\sserver|permname=b_client_channel_textmessage_send permdesc=Send\stext\smessages\sto\schannel|permname=b_client_offline_textmessage_send permdesc=Send\soffline\smessages\sto\sclients|permname=i_client_talk_power permdesc=Client\stalk\spower|permname=i_client_needed_talk_power permdesc=Needed\sclient\stalk\spower|permname=i_client_poke_power permdesc=Client\spoke\spower|permname=i_client_needed_poke_power permdesc=Needed\sclient\spoke\spower|permname=b_client_set_flag_talker permdesc=Set\sthe\stalker\sflag\sfor\sclients\sand\sallow\sthem\sto\sspeak|permname=i_client_whisper_power permdesc=Client\swhisper\spower|permname=i_client_needed_whisper_power permdesc=Client\sneeded\swhisper\spower|permname=b_client_modify_description permdesc=Edit\sa\sclients\sdescription|permname=b_client_modify_own_description permdesc=Allow\sclient\sto\sedit\sown\sdescription|permname=b_client_modify_dbproperties permdesc=Edit\sa\sclients\sproperties\sin\sthe\sdatabase|permname=b_client_delete_dbproperties permdesc=Delete\sa\sclients\sproperties\sin\sthe\sdatabase|permname=b_client_create_modify_serverquery_login permdesc=Create\sor\smodify\sown\sServerQuery\saccount|permname=b_ft_ignore_password permdesc=Browse\sfiles\swithout\schannel\spassword|permname=b_ft_transfer_list permdesc=Retrieve\slist\sof\srunning\sfiletransfers|permname=i_ft_file_upload_power permdesc=File\supload\spower|permname=i_ft_needed_file_upload_power permdesc=Needed\sfile\supload\spower|permname=i_ft_file_download_power permdesc=File\sdownload\spower|permname=i_ft_needed_file_download_power permdesc=Needed\sfile\sdownload\spower|permname=i_ft_file_delete_power permdesc=File\sdelete\spower|permname=i_ft_needed_file_delete_power permdesc=Needed\sfile\sdelete\spower|permname=i_ft_file_rename_power permdesc=File\srename\spower|permname=i_ft_needed_file_rename_power permdesc=Needed\sfile\srename\spower|permname=i_ft_file_browse_power permdesc=File\sbrowse\spower|permname=i_ft_needed_file_browse_power permdesc=Needed\sfile\sbrowse\spower|permname=i_ft_directory_create_power permdesc=Create\sdirectory\spower|permname=i_ft_needed_directory_create_power permdesc=Needed\screate\sdirectory\spower|permname=i_ft_quota_mb_download_per_client permdesc=Download\squota\sper\sclient\sin\sMByte|permname=i_ft_quota_mb_upload_per_client permdesc=Upload\squota\sper\sclient\sin\sMByte"#.to_string()
    })
}

static SERVER_ADMIN_PERMS_WIRE: OnceLock<String> = OnceLock::new();
static GUEST_PERMS_WIRE: OnceLock<String> = OnceLock::new();

pub fn get_server_admin_perms_wire() -> &'static str {
    SERVER_ADMIN_PERMS_WIRE.get_or_init(|| {
        "notifyservergrouppermlist sgid=6 permid=25 permvalue=1 permnegated=0 permskip=0|permid=26 permvalue=1 permnegated=0 permskip=0|permid=27 permvalue=1 permnegated=0 permskip=0|permid=28 permvalue=1 permnegated=0 permskip=0|permid=29 permvalue=1 permnegated=0 permskip=0|permid=30 permvalue=1 permnegated=0 permskip=0|permid=31 permvalue=1 permnegated=0 permskip=0|permid=32 permvalue=1 permnegated=0 permskip=0|permid=33 permvalue=1 permnegated=0 permskip=0|permid=34 permvalue=1 permnegated=0 permskip=0|permid=35 permvalue=1 permnegated=0 permskip=0|permid=36 permvalue=1 permnegated=0 permskip=0|permid=37 permvalue=1 permnegated=0 permskip=0|permid=38 permvalue=1 permnegated=0 permskip=0|permid=39 permvalue=1 permnegated=0 permskip=0|permid=40 permvalue=1 permnegated=0 permskip=0|permid=41 permvalue=1 permnegated=0 permskip=0|permid=42 permvalue=1 permnegated=0 permskip=0|permid=43 permvalue=1 permnegated=0 permskip=0|permid=44 permvalue=1 permnegated=0 permskip=0|permid=45 permvalue=1 permnegated=0 permskip=0|permid=46 permvalue=1 permnegated=0 permskip=0|permid=47 permvalue=1 permnegated=0 permskip=0|permid=48 permvalue=1 permnegated=0 permskip=0|permid=52 permvalue=1 permnegated=0 permskip=0|permid=53 permvalue=1 permnegated=0 permskip=0|permid=54 permvalue=1 permnegated=0 permskip=0|permid=55 permvalue=1 permnegated=0 permskip=0|permid=56 permvalue=1 permnegated=0 permskip=0|permid=57 permvalue=1 permnegated=0 permskip=0|permid=58 permvalue=1 permnegated=0 permskip=0|permid=59 permvalue=1 permnegated=0 permskip=0|permid=60 permvalue=1 permnegated=0 permskip=0|permid=61 permvalue=1 permnegated=0 permskip=0|permid=62 permvalue=1 permnegated=0 permskip=0|permid=63 permvalue=1 permnegated=0 permskip=0|permid=64 permvalue=1 permnegated=0 permskip=0|permid=65 permvalue=1 permnegated=0 permskip=0|permid=66 permvalue=1 permnegated=0 permskip=0|permid=67 permvalue=1 permnegated=0 permskip=0|permid=68 permvalue=1 permnegated=0 permskip=0|permid=69 permvalue=1 permnegated=0 permskip=0|permid=70 permvalue=1 permnegated=0 permskip=0|permid=71 permvalue=1 permnegated=0 permskip=0|permid=72 permvalue=1 permnegated=0 permskip=0|permid=73 permvalue=1 permnegated=0 permskip=0|permid=74 permvalue=1 permnegated=0 permskip=0|permid=75 permvalue=1 permnegated=0 permskip=0|permid=76 permvalue=1 permnegated=0 permskip=0|permid=77 permvalue=1 permnegated=0 permskip=0|permid=79 permvalue=1 permnegated=0 permskip=0|permid=80 permvalue=1 permnegated=0 permskip=0|permid=81 permvalue=1 permnegated=0 permskip=0|permid=83 permvalue=10 permnegated=0 permskip=0|permid=85 permvalue=75 permnegated=0 permskip=0|permid=87 permvalue=1 permnegated=0 permskip=0|permid=88 permvalue=1 permnegated=0 permskip=0|permid=89 permvalue=1 permnegated=0 permskip=0|permid=90 permvalue=1 permnegated=0 permskip=0|permid=91 permvalue=1 permnegated=0 permskip=0|permid=92 permvalue=1 permnegated=0 permskip=0|permid=93 permvalue=1 permnegated=0 permskip=0|permid=94 permvalue=1 permnegated=0 permskip=0|permid=95 permvalue=1 permnegated=0 permskip=0|permid=96 permvalue=1 permnegated=0 permskip=0|permid=97 permvalue=1 permnegated=0 permskip=0|permid=98 permvalue=10 permnegated=0 permskip=0|permid=99 permvalue=1 permnegated=0 permskip=0|permid=100 permvalue=1 permnegated=0 permskip=0|permid=101 permvalue=1 permnegated=0 permskip=0|permid=102 permvalue=1 permnegated=0 permskip=0|permid=103 permvalue=1 permnegated=0 permskip=0|permid=104 permvalue=1 permnegated=0 permskip=0|permid=106 permvalue=86400 permnegated=0 permskip=0|permid=107 permvalue=1 permnegated=0 permskip=0|permid=108 permvalue=1 permnegated=0 permskip=0|permid=109 permvalue=1 permnegated=0 permskip=0|permid=110 permvalue=1 permnegated=0 permskip=0|permid=111 permvalue=1 permnegated=0 permskip=0|permid=112 permvalue=1 permnegated=0 permskip=0|permid=113 permvalue=1 permnegated=0 permskip=0|permid=114 permvalue=1 permnegated=0 permskip=0|permid=115 permvalue=1 permnegated=0 permskip=0|permid=116 permvalue=1 permnegated=0 permskip=0|permid=117 permvalue=1 permnegated=0 permskip=0|permid=118 permvalue=1 permnegated=0 permskip=0|permid=119 permvalue=1 permnegated=0 permskip=0|permid=120 permvalue=1 permnegated=0 permskip=0|permid=121 permvalue=1 permnegated=0 permskip=0|permid=122 permvalue=1 permnegated=0 permskip=0|permid=123 permvalue=1 permnegated=0 permskip=0|permid=124 permvalue=75 permnegated=0 permskip=0|permid=125 permvalue=75 permnegated=0 permskip=0|permid=126 permvalue=1 permnegated=0 permskip=0|permid=127 permvalue=1 permnegated=0 permskip=0|permid=128 permvalue=1 permnegated=0 permskip=0|permid=129 permvalue=1 permnegated=0 permskip=0|permid=130 permvalue=1 permnegated=0 permskip=0|permid=131 permvalue=1 permnegated=0 permskip=0|permid=132 permvalue=75 permnegated=0 permskip=0|permid=133 permvalue=75 permnegated=0 permskip=0|permid=134 permvalue=1 permnegated=0 permskip=0|permid=135 permvalue=1 permnegated=0 permskip=0|permid=136 permvalue=1 permnegated=0 permskip=0|permid=137 permvalue=1 permnegated=0 permskip=0|permid=138 permvalue=1 permnegated=0 permskip=0|permid=139 permvalue=75 permnegated=0 permskip=0|permid=141 permvalue=75 permnegated=0 permskip=0|permid=143 permvalue=75 permnegated=0 permskip=0|permid=145 permvalue=300 permnegated=0 permskip=0|permid=146 permvalue=8192 permnegated=0 permskip=0|permid=147 permvalue=1 permnegated=0 permskip=0|permid=148 permvalue=1 permnegated=0 permskip=0|permid=149 permvalue=45 permnegated=0 permskip=0|permid=150 permvalue=45 permnegated=0 permskip=0|permid=153 permvalue=1 permnegated=0 permskip=0|permid=154 permvalue=1 permnegated=0 permskip=0|permid=155 permvalue=1 permnegated=0 permskip=0|permid=156 permvalue=1 permnegated=0 permskip=0|permid=157 permvalue=1 permnegated=0 permskip=0|permid=158 permvalue=1 permnegated=0 permskip=0|permid=159 permvalue=1 permnegated=0 permskip=0|permid=160 permvalue=1 permnegated=0 permskip=0|permid=161 permvalue=1 permnegated=0 permskip=0|permid=162 permvalue=1 permnegated=0 permskip=0|permid=163 permvalue=1 permnegated=0 permskip=0|permid=164 permvalue=75 permnegated=0 permskip=0|permid=165 permvalue=75 permnegated=0 permskip=0|permid=166 permvalue=75 permnegated=0 permskip=0|permid=167 permvalue=75 permnegated=0 permskip=0|permid=168 permvalue=75 permnegated=0 permskip=0|permid=169 permvalue=75 permnegated=0 permskip=0|permid=170 permvalue=75 permnegated=0 permskip=0|permid=172 permvalue=1 permnegated=0 permskip=0|permid=173 permvalue=1 permnegated=0 permskip=0|permid=174 permvalue=75 permnegated=0 permskip=0|permid=175 permvalue=75 permnegated=0 permskip=0|permid=176 permvalue=10 permnegated=0 permskip=0|permid=178 permvalue=200000 permnegated=0 permskip=0|permid=179 permvalue=-1 permnegated=0 permskip=0|permid=181 permvalue=1 permnegated=0 permskip=0|permid=183 permvalue=1 permnegated=0 permskip=0|permid=184 permvalue=1 permnegated=0 permskip=0|permid=185 permvalue=1 permnegated=0 permskip=0|permid=186 permvalue=1 permnegated=0 permskip=0|permid=187 permvalue=1 permnegated=0 permskip=0|permid=188 permvalue=1 permnegated=0 permskip=0|permid=190 permvalue=1 permnegated=0 permskip=0|permid=191 permvalue=1 permnegated=0 permskip=0|permid=192 permvalue=1 permnegated=0 permskip=0|permid=193 permvalue=1 permnegated=0 permskip=0|permid=194 permvalue=1 permnegated=0 permskip=0|permid=195 permvalue=75 permnegated=0 permskip=0|permid=196 permvalue=75 permnegated=0 permskip=0|permid=197 permvalue=1 permnegated=0 permskip=0|permid=198 permvalue=75 permnegated=0 permskip=0|permid=199 permvalue=75 permnegated=0 permskip=0|permid=200 permvalue=75 permnegated=0 permskip=0|permid=201 permvalue=75 permnegated=0 permskip=0|permid=202 permvalue=75 permnegated=0 permskip=0|permid=203 permvalue=75 permnegated=0 permskip=0|permid=204 permvalue=75 permnegated=0 permskip=0|permid=205 permvalue=75 permnegated=0 permskip=0|permid=206 permvalue=75 permnegated=0 permskip=0|permid=207 permvalue=75 permnegated=0 permskip=0|permid=208 permvalue=1 permnegated=0 permskip=0|permid=209 permvalue=1 permnegated=0 permskip=0|permid=210 permvalue=1 permnegated=0 permskip=0|permid=211 permvalue=1 permnegated=0 permskip=0|permid=212 permvalue=1 permnegated=0 permskip=0|permid=213 permvalue=1 permnegated=0 permskip=0|permid=214 permvalue=1 permnegated=0 permskip=0|permid=215 permvalue=-1 permnegated=0 permskip=0|permid=216 permvalue=75 permnegated=0 permskip=0|permid=218 permvalue=1 permnegated=0 permskip=0|permid=219 permvalue=1 permnegated=0 permskip=0|permid=220 permvalue=1 permnegated=0 permskip=0|permid=221 permvalue=75 permnegated=0 permskip=0|permid=223 permvalue=75 permnegated=0 permskip=0|permid=225 permvalue=1 permnegated=0 permskip=0|permid=228 permvalue=1 permnegated=0 permskip=0|permid=229 permvalue=1 permnegated=0 permskip=0|permid=230 permvalue=1 permnegated=0 permskip=0|permid=231 permvalue=1 permnegated=0 permskip=0|permid=232 permvalue=1 permnegated=0 permskip=0|permid=233 permvalue=1 permnegated=0 permskip=0|permid=234 permvalue=1 permnegated=0 permskip=0|permid=235 permvalue=75 permnegated=0 permskip=0|permid=237 permvalue=75 permnegated=0 permskip=0|permid=239 permvalue=75 permnegated=0 permskip=0|permid=241 permvalue=75 permnegated=0 permskip=0|permid=243 permvalue=75 permnegated=0 permskip=0|permid=245 permvalue=75 permnegated=0 permskip=0|permid=247 permvalue=-1 permnegated=0 permskip=0|permid=248 permvalue=-1 permnegated=0 permskip=0|permid=32793 permvalue=75 permnegated=0 permskip=0|permid=32794 permvalue=75 permnegated=0 permskip=0|permid=32795 permvalue=75 permnegated=0 permskip=0|permid=32796 permvalue=75 permnegated=0 permskip=0|permid=32797 permvalue=75 permnegated=0 permskip=0|permid=32798 permvalue=75 permnegated=0 permskip=0|permid=32799 permvalue=75 permnegated=0 permskip=0|permid=32800 permvalue=75 permnegated=0 permskip=0|permid=32801 permvalue=75 permnegated=0 permskip=0|permid=32802 permvalue=75 permnegated=0 permskip=0|permid=32803 permvalue=75 permnegated=0 permskip=0|permid=32804 permvalue=75 permnegated=0 permskip=0|permid=32805 permvalue=75 permnegated=0 permskip=0|permid=32806 permvalue=75 permnegated=0 permskip=0|permid=32807 permvalue=75 permnegated=0 permskip=0|permid=32808 permvalue=75 permnegated=0 permskip=0|permid=32809 permvalue=75 permnegated=0 permskip=0|permid=32810 permvalue=75 permnegated=0 permskip=0|permid=32811 permvalue=75 permnegated=0 permskip=0|permid=32812 permvalue=75 permnegated=0 permskip=0|permid=32813 permvalue=75 permnegated=0 permskip=0|permid=32814 permvalue=75 permnegated=0 permskip=0|permid=32815 permvalue=75 permnegated=0 permskip=0|permid=32816 permvalue=75 permnegated=0 permskip=0|permid=32820 permvalue=75 permnegated=0 permskip=0|permid=32821 permvalue=75 permnegated=0 permskip=0|permid=32822 permvalue=75 permnegated=0 permskip=0|permid=32823 permvalue=75 permnegated=0 permskip=0|permid=32824 permvalue=75 permnegated=0 permskip=0|permid=32825 permvalue=75 permnegated=0 permskip=0|permid=32826 permvalue=75 permnegated=0 permskip=0|permid=32827 permvalue=75 permnegated=0 permskip=0|permid=32828 permvalue=75 permnegated=0 permskip=0|permid=32829 permvalue=75 permnegated=0 permskip=0|permid=32830 permvalue=75 permnegated=0 permskip=0|permid=32831 permvalue=75 permnegated=0 permskip=0|permid=32832 permvalue=75 permnegated=0 permskip=0|permid=32833 permvalue=75 permnegated=0 permskip=0|permid=32834 permvalue=75 permnegated=0 permskip=0|permid=32835 permvalue=75 permnegated=0 permskip=0|permid=32836 permvalue=75 permnegated=0 permskip=0|permid=32837 permvalue=75 permnegated=0 permskip=0|permid=32838 permvalue=75 permnegated=0 permskip=0|permid=32839 permvalue=75 permnegated=0 permskip=0|permid=32840 permvalue=75 permnegated=0 permskip=0|permid=32841 permvalue=75 permnegated=0 permskip=0|permid=32842 permvalue=75 permnegated=0 permskip=0|permid=32843 permvalue=75 permnegated=0 permskip=0|permid=32844 permvalue=75 permnegated=0 permskip=0|permid=32845 permvalue=75 permnegated=0 permskip=0|permid=32846 permvalue=75 permnegated=0 permskip=0|permid=32847 permvalue=75 permnegated=0 permskip=0|permid=32848 permvalue=75 permnegated=0 permskip=0|permid=32849 permvalue=75 permnegated=0 permskip=0|permid=32850 permvalue=75 permnegated=0 permskip=0|permid=32851 permvalue=75 permnegated=0 permskip=0|permid=32852 permvalue=75 permnegated=0 permskip=0|permid=32853 permvalue=75 permnegated=0 permskip=0|permid=32854 permvalue=75 permnegated=0 permskip=0|permid=32855 permvalue=75 permnegated=0 permskip=0|permid=32856 permvalue=75 permnegated=0 permskip=0|permid=32857 permvalue=75 permnegated=0 permskip=0|permid=32858 permvalue=75 permnegated=0 permskip=0|permid=32859 permvalue=75 permnegated=0 permskip=0|permid=32860 permvalue=75 permnegated=0 permskip=0|permid=32861 permvalue=75 permnegated=0 permskip=0|permid=32862 permvalue=75 permnegated=0 permskip=0|permid=32863 permvalue=75 permnegated=0 permskip=0|permid=32864 permvalue=75 permnegated=0 permskip=0|permid=32865 permvalue=75 permnegated=0 permskip=0|permid=32866 permvalue=75 permnegated=0 permskip=0|permid=32867 permvalue=75 permnegated=0 permskip=0|permid=32868 permvalue=75 permnegated=0 permskip=0|permid=32869 permvalue=75 permnegated=0 permskip=0|permid=32870 permvalue=75 permnegated=0 permskip=0|permid=32871 permvalue=75 permnegated=0 permskip=0|permid=32872 permvalue=75 permnegated=0 permskip=0|permid=32873 permvalue=75 permnegated=0 permskip=0|permid=32874 permvalue=75 permnegated=0 permskip=0|permid=32875 permvalue=75 permnegated=0 permskip=0|permid=32876 permvalue=75 permnegated=0 permskip=0|permid=32877 permvalue=75 permnegated=0 permskip=0|permid=32878 permvalue=75 permnegated=0 permskip=0|permid=32879 permvalue=75 permnegated=0 permskip=0|permid=32880 permvalue=75 permnegated=0 permskip=0|permid=32881 permvalue=75 permnegated=0 permskip=0|permid=32882 permvalue=75 permnegated=0 permskip=0|permid=32883 permvalue=75 permnegated=0 permskip=0|permid=32884 permvalue=75 permnegated=0 permskip=0|permid=32885 permvalue=75 permnegated=0 permskip=0|permid=32886 permvalue=75 permnegated=0 permskip=0|permid=32887 permvalue=75 permnegated=0 permskip=0|permid=32888 permvalue=75 permnegated=0 permskip=0|permid=32889 permvalue=75 permnegated=0 permskip=0|permid=32890 permvalue=75 permnegated=0 permskip=0|permid=32891 permvalue=75 permnegated=0 permskip=0|permid=32892 permvalue=75 permnegated=0 permskip=0|permid=32893 permvalue=75 permnegated=0 permskip=0|permid=32894 permvalue=75 permnegated=0 permskip=0|permid=32895 permvalue=75 permnegated=0 permskip=0|permid=32896 permvalue=75 permnegated=0 permskip=0|permid=32897 permvalue=75 permnegated=0 permskip=0|permid=32898 permvalue=75 permnegated=0 permskip=0|permid=32899 permvalue=75 permnegated=0 permskip=0|permid=32900 permvalue=75 permnegated=0 permskip=0|permid=32901 permvalue=75 permnegated=0 permskip=0|permid=32902 permvalue=75 permnegated=0 permskip=0|permid=32903 permvalue=75 permnegated=0 permskip=0|permid=32904 permvalue=75 permnegated=0 permskip=0|permid=32905 permvalue=75 permnegated=0 permskip=0|permid=32906 permvalue=75 permnegated=0 permskip=0|permid=32907 permvalue=75 permnegated=0 permskip=0|permid=32908 permvalue=75 permnegated=0 permskip=0|permid=32909 permvalue=75 permnegated=0 permskip=0|permid=32910 permvalue=75 permnegated=0 permskip=0|permid=32911 permvalue=75 permnegated=0 permskip=0|permid=32912 permvalue=75 permnegated=0 permskip=0|permid=32913 permvalue=75 permnegated=0 permskip=0|permid=32914 permvalue=75 permnegated=0 permskip=0|permid=32915 permvalue=75 permnegated=0 permskip=0|permid=32916 permvalue=75 permnegated=0 permskip=0|permid=32917 permvalue=75 permnegated=0 permskip=0|permid=32919 permvalue=75 permnegated=0 permskip=0|permid=32920 permvalue=75 permnegated=0 permskip=0|permid=32921 permvalue=75 permnegated=0 permskip=0|permid=32922 permvalue=75 permnegated=0 permskip=0|permid=32923 permvalue=75 permnegated=0 permskip=0|permid=32924 permvalue=75 permnegated=0 permskip=0|permid=32925 permvalue=75 permnegated=0 permskip=0|permid=32926 permvalue=75 permnegated=0 permskip=0|permid=32927 permvalue=75 permnegated=0 permskip=0|permid=32928 permvalue=75 permnegated=0 permskip=0|permid=32929 permvalue=75 permnegated=0 permskip=0|permid=32930 permvalue=75 permnegated=0 permskip=0|permid=32931 permvalue=75 permnegated=0 permskip=0|permid=32932 permvalue=75 permnegated=0 permskip=0|permid=32933 permvalue=75 permnegated=0 permskip=0|permid=32934 permvalue=75 permnegated=0 permskip=0|permid=32935 permvalue=75 permnegated=0 permskip=0|permid=32936 permvalue=75 permnegated=0 permskip=0|permid=32937 permvalue=75 permnegated=0 permskip=0|permid=32938 permvalue=75 permnegated=0 permskip=0|permid=32940 permvalue=75 permnegated=0 permskip=0|permid=32941 permvalue=75 permnegated=0 permskip=0|permid=32942 permvalue=75 permnegated=0 permskip=0|permid=32943 permvalue=75 permnegated=0 permskip=0|permid=32944 permvalue=75 permnegated=0 permskip=0|permid=32945 permvalue=75 permnegated=0 permskip=0|permid=32946 permvalue=75 permnegated=0 permskip=0|permid=32947 permvalue=75 permnegated=0 permskip=0|permid=32948 permvalue=75 permnegated=0 permskip=0|permid=32949 permvalue=75 permnegated=0 permskip=0|permid=32950 permvalue=75 permnegated=0 permskip=0|permid=32951 permvalue=75 permnegated=0 permskip=0|permid=32952 permvalue=75 permnegated=0 permskip=0|permid=32953 permvalue=75 permnegated=0 permskip=0|permid=32954 permvalue=75 permnegated=0 permskip=0|permid=32955 permvalue=75 permnegated=0 permskip=0|permid=32956 permvalue=75 permnegated=0 permskip=0|permid=32957 permvalue=75 permnegated=0 permskip=0|permid=32958 permvalue=75 permnegated=0 permskip=0|permid=32959 permvalue=75 permnegated=0 permskip=0|permid=32960 permvalue=75 permnegated=0 permskip=0|permid=32961 permvalue=75 permnegated=0 permskip=0|permid=32962 permvalue=75 permnegated=0 permskip=0|permid=32963 permvalue=75 permnegated=0 permskip=0|permid=32964 permvalue=75 permnegated=0 permskip=0|permid=32965 permvalue=75 permnegated=0 permskip=0|permid=32966 permvalue=75 permnegated=0 permskip=0|permid=32967 permvalue=75 permnegated=0 permskip=0|permid=32968 permvalue=75 permnegated=0 permskip=0|permid=32969 permvalue=75 permnegated=0 permskip=0|permid=32970 permvalue=75 permnegated=0 permskip=0|permid=32971 permvalue=75 permnegated=0 permskip=0|permid=32972 permvalue=75 permnegated=0 permskip=0|permid=32973 permvalue=75 permnegated=0 permskip=0|permid=32974 permvalue=75 permnegated=0 permskip=0|permid=32975 permvalue=75 permnegated=0 permskip=0|permid=32976 permvalue=75 permnegated=0 permskip=0|permid=32977 permvalue=75 permnegated=0 permskip=0|permid=32978 permvalue=75 permnegated=0 permskip=0|permid=32979 permvalue=75 permnegated=0 permskip=0|permid=32980 permvalue=75 permnegated=0 permskip=0|permid=32981 permvalue=75 permnegated=0 permskip=0|permid=32982 permvalue=75 permnegated=0 permskip=0|permid=32983 permvalue=75 permnegated=0 permskip=0|permid=32984 permvalue=75 permnegated=0 permskip=0|permid=32985 permvalue=75 permnegated=0 permskip=0|permid=32986 permvalue=75 permnegated=0 permskip=0|permid=32987 permvalue=75 permnegated=0 permskip=0|permid=32988 permvalue=75 permnegated=0 permskip=0|permid=32989 permvalue=75 permnegated=0 permskip=0|permid=32990 permvalue=75 permnegated=0 permskip=0|permid=32991 permvalue=75 permnegated=0 permskip=0|permid=32992 permvalue=75 permnegated=0 permskip=0|permid=32993 permvalue=75 permnegated=0 permskip=0|permid=32994 permvalue=75 permnegated=0 permskip=0|permid=32995 permvalue=75 permnegated=0 permskip=0|permid=32996 permvalue=75 permnegated=0 permskip=0|permid=32997 permvalue=75 permnegated=0 permskip=0|permid=32998 permvalue=75 permnegated=0 permskip=0|permid=32999 permvalue=75 permnegated=0 permskip=0|permid=33000 permvalue=75 permnegated=0 permskip=0|permid=33001 permvalue=75 permnegated=0 permskip=0|permid=33002 permvalue=75 permnegated=0 permskip=0|permid=33003 permvalue=75 permnegated=0 permskip=0|permid=33004 permvalue=75 permnegated=0 permskip=0|permid=33005 permvalue=75 permnegated=0 permskip=0|permid=33006 permvalue=75 permnegated=0 permskip=0|permid=33007 permvalue=75 permnegated=0 permskip=0|permid=33008 permvalue=75 permnegated=0 permskip=0|permid=33009 permvalue=75 permnegated=0 permskip=0|permid=33010 permvalue=75 permnegated=0 permskip=0|permid=33011 permvalue=75 permnegated=0 permskip=0|permid=33012 permvalue=75 permnegated=0 permskip=0|permid=33013 permvalue=75 permnegated=0 permskip=0|permid=33014 permvalue=75 permnegated=0 permskip=0|permid=33015 permvalue=75 permnegated=0 permskip=0|permid=33016 permvalue=75 permnegated=0 permskip=0".to_string()
    })
}

pub fn get_guest_perms_wire() -> &'static str {
    GUEST_PERMS_WIRE.get_or_init(|| {
        "notifyservergrouppermlist sgid=8 permid=40 permvalue=1 permnegated=0 permskip=0|permid=83 permvalue=0 permnegated=0 permskip=0|permid=87 permvalue=1 permnegated=0 permskip=0|permid=91 permvalue=1 permnegated=0 permskip=0|permid=92 permvalue=1 permnegated=0 permskip=0|permid=94 permvalue=1 permnegated=0 permskip=0|permid=96 permvalue=1 permnegated=0 permskip=0|permid=98 permvalue=7 permnegated=0 permskip=0|permid=99 permvalue=1 permnegated=0 permskip=0|permid=100 permvalue=1 permnegated=0 permskip=0|permid=104 permvalue=1 permnegated=0 permskip=0|permid=134 permvalue=1 permnegated=0 permskip=0|permid=135 permvalue=1 permnegated=0 permskip=0|permid=136 permvalue=1 permnegated=0 permskip=0|permid=149 permvalue=15 permnegated=0 permskip=0|permid=165 permvalue=75 permnegated=0 permskip=0|permid=176 permvalue=0 permnegated=0 permskip=0|permid=178 permvalue=200000 permnegated=0 permskip=0|permid=179 permvalue=-1 permnegated=0 permskip=0|permid=187 permvalue=1 permnegated=0 permskip=0|permid=191 permvalue=1 permnegated=0 permskip=0|permid=196 permvalue=75 permnegated=0 permskip=0|permid=199 permvalue=25 permnegated=0 permskip=0|permid=201 permvalue=25 permnegated=0 permskip=0|permid=203 permvalue=25 permnegated=0 permskip=0|permid=205 permvalue=25 permnegated=0 permskip=0|permid=219 permvalue=1 permnegated=0 permskip=0|permid=237 permvalue=25 permnegated=0 permskip=0|permid=243 permvalue=25 permnegated=0 permskip=0|permid=247 permvalue=-1 permnegated=0 permskip=0|permid=248 permvalue=-1 permnegated=0 permskip=0".to_string()
    })
}

use crate::database::Database;
pub use crate::permission_catalog::{perm_id_to_name, perm_name_to_id};

/// Evaluates a specific permission for a client in a given channel using the official 5-tier evaluation algorithm.
pub fn evaluate_permission(
    db: &Database,
    client_uid: &str,
    cid: u64,
    perm_name: &str,
) -> Option<i64> {
    // Tier 1: Server Groups
    let server_groups = db
        .get_client_server_groups(client_uid)
        .unwrap_or_else(|_| vec![8]);
    let mut t1_val: Option<i64> = None;
    let mut t1_has_negated = false;
    let mut t1_min_negated: i64 = i64::MAX;
    let mut t1_max_val: i64 = i64::MIN;
    let mut skip = false;

    for &sgid in &server_groups {
        if let Ok(perms) = db.get_server_group_perms(sgid) {
            for p in perms {
                if p.perm_id == perm_name {
                    if p.perm_skip {
                        skip = true;
                    }
                    if p.perm_negated {
                        t1_has_negated = true;
                        if p.perm_value < t1_min_negated {
                            t1_min_negated = p.perm_value;
                        }
                    } else if p.perm_value > t1_max_val {
                        t1_max_val = p.perm_value;
                    }
                }
            }
        }
    }

    if t1_has_negated {
        t1_val = Some(t1_min_negated);
    } else if t1_max_val != i64::MIN {
        t1_val = Some(t1_max_val);
    }

    // Check if b_client_skip_channelgroup_permissions is set in Tier 1
    if !skip {
        for &sgid in &server_groups {
            if let Ok(perms) = db.get_server_group_perms(sgid) {
                for p in perms {
                    if p.perm_id == "b_client_skip_channelgroup_permissions" && p.perm_value > 0 {
                        skip = true;
                    }
                }
            }
        }
    }

    let mut current_val = t1_val;

    // Tier 2: Client Specific Permissions
    if let Ok(client_perms) = db.get_client_perms(client_uid) {
        for p in client_perms {
            if p.perm_id == "b_client_skip_channelgroup_permissions" && p.perm_value > 0 {
                skip = true;
            }
            if p.perm_id == perm_name {
                current_val = Some(p.perm_value);
                if p.perm_skip {
                    skip = true;
                }
            }
        }
    }

    // Tier 3: Channel Specific Permissions (skipped if skip is true)
    if !skip && cid > 0 {
        if let Ok(ch_perms) = db.get_channel_perms(cid) {
            for p in ch_perms {
                if p.perm_id == perm_name {
                    current_val = Some(p.perm_value);
                }
            }
        }
    }

    // Tier 4: Channel Groups (skipped if skip is true)
    if !skip && cid > 0 {
        let cgid = db.get_client_channel_group(client_uid, cid).unwrap_or(8);
        if let Ok(cg_perms) = db.get_channel_group_perms(cgid) {
            for p in cg_perms {
                if p.perm_id == perm_name {
                    current_val = Some(p.perm_value);
                }
            }
        }
    }

    // Tier 5: Channel and Client Specific Permissions (always applied, ignores skip)
    if cid > 0 {
        if let Ok(cc_perms) = db.get_channel_client_perms(cid, client_uid) {
            for p in cc_perms {
                if p.perm_id == perm_name {
                    current_val = Some(p.perm_value);
                }
            }
        }
    }

    current_val
}

/// Checks if a boolean permission evaluates to true (> 0).
pub fn has_permission(db: &Database, client_uid: &str, cid: u64, perm_name: &str) -> bool {
    evaluate_permission(db, client_uid, cid, perm_name)
        .map(|v| v > 0)
        .unwrap_or(false)
}

/// Retrieves the effective integer value of a permission (or 0 if not set).
pub fn get_power(db: &Database, client_uid: &str, cid: u64, perm_name: &str) -> i64 {
    evaluate_permission(db, client_uid, cid, perm_name).unwrap_or(0)
}

/// Checks if the client's power permission is greater than or equal to the needed power.
pub fn check_power(
    db: &Database,
    client_uid: &str,
    cid: u64,
    power_perm: &str,
    needed_power: i64,
) -> bool {
    let power = get_power(db, client_uid, cid, power_perm);
    power >= needed_power
}

/// Checks if the invoker's power is sufficient against the target client's needed power.
pub fn check_target_power(
    db: &Database,
    invoker_uid: &str,
    target_uid: &str,
    cid: u64,
    power_perm: &str,
    needed_power_perm: &str,
) -> bool {
    let invoker_power = get_power(db, invoker_uid, cid, power_perm);
    let target_needed = get_power(db, target_uid, cid, needed_power_perm);
    invoker_power >= target_needed
}

/// Checks whether the invoker is permitted to add, modify, or delete a permission.
///
/// Returns `Ok(())` if allowed, or `Err(failed_permid)` if insufficient.
pub fn check_modify_permission(
    db: &Database,
    invoker_uid: &str,
    cid: u64,
    target_perm_name: &str,
    target_value: Option<i64>,
    is_grant: bool,
) -> Result<(), u32> {
    if invoker_uid.is_empty() {
        return Ok(());
    }

    // 1. Caller's permission modify power
    let invoker_modify_power = get_power(db, invoker_uid, cid, "i_permission_modify_power");

    // 2. Needed modify power
    let needed_perm_name = if is_grant || target_perm_name.starts_with("i_needed_modify_power_") {
        "i_needed_modify_power_permission_modify_power".to_string()
    } else {
        format!("i_needed_modify_power_{}", target_perm_name)
    };

    let needed_modify_power = evaluate_permission(db, invoker_uid, cid, &needed_perm_name)
        .unwrap_or(75);

    if invoker_modify_power < needed_modify_power {
        let failed_id = perm_name_to_id(&needed_perm_name)
            .or_else(|| perm_name_to_id(target_perm_name))
            .unwrap_or(32800);
        return Err(failed_id);
    }

    // 3. Delegation ceiling: caller cannot grant a value exceeding their own modify power
    // (except boolean 0/1 values and negative values)
    if let Some(val) = target_value {
        if val > 1 && val > invoker_modify_power {
            let failed_id = perm_name_to_id(target_perm_name).unwrap_or(32800);
            return Err(failed_id);
        }
    }

    Ok(())
}

/// Builds the `notifyservergrouppermlist` wire payload for a server group.
pub fn build_server_group_perm_list(db: &Database, sgid: u64, use_permsid: bool) -> String {
    let perms = db.get_server_group_perms(sgid).unwrap_or_default();
    if perms.is_empty() {
        return format!("notifyservergrouppermlist sgid={}", sgid);
    }
    let parts: Vec<String> = perms
        .into_iter()
        .map(|p| {
            let id_part = if use_permsid {
                format!("permsid={}", p.perm_id)
            } else {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                format!("permid={}", pid)
            };
            format!(
                "sgid={} {} permvalue={} permnegated={} permskip={}",
                sgid,
                id_part,
                p.perm_value,
                if p.perm_negated { 1 } else { 0 },
                if p.perm_skip { 1 } else { 0 },
            )
        })
        .collect();
    format!("notifyservergrouppermlist {}", parts.join("|"))
}

/// Builds the `notifychannelgrouppermlist` wire payload for a channel group.
pub fn build_channel_group_perm_list(db: &Database, cgid: u64, use_permsid: bool) -> String {
    let perms = db.get_channel_group_perms(cgid).unwrap_or_default();
    if perms.is_empty() {
        return format!("notifychannelgrouppermlist cgid={}", cgid);
    }
    let parts: Vec<String> = perms
        .into_iter()
        .map(|p| {
            let id_part = if use_permsid {
                format!("permsid={}", p.perm_id)
            } else {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                format!("permid={}", pid)
            };
            format!(
                "cgid={} {} permvalue={} permnegated={} permskip={}",
                cgid,
                id_part,
                p.perm_value,
                if p.perm_negated { 1 } else { 0 },
                if p.perm_skip { 1 } else { 0 },
            )
        })
        .collect();
    format!("notifychannelgrouppermlist {}", parts.join("|"))
}

/// Builds the `notifychannelpermlist` wire payload for a channel.
pub fn build_channel_perm_list(db: &Database, cid: u64, use_permsid: bool) -> String {
    let perms = db.get_channel_perms(cid).unwrap_or_default();
    if perms.is_empty() {
        return "notifychannelpermlist".to_string();
    }
    let parts: Vec<String> = perms
        .into_iter()
        .map(|p| {
            let id_part = if use_permsid {
                format!("permsid={}", p.perm_id)
            } else {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                format!("permid={}", pid)
            };
            format!(
                "cid={} {} permvalue={} permnegated={} permskip={}",
                cid,
                id_part,
                p.perm_value,
                if p.perm_negated { 1 } else { 0 },
                if p.perm_skip { 1 } else { 0 },
            )
        })
        .collect();
    format!("notifychannelpermlist {}", parts.join("|"))
}

/// Builds the `notifyclientpermlist` wire payload for a client.
pub fn build_client_perm_list(
    db: &Database,
    cldbid: u64,
    client_uid: &str,
    use_permsid: bool,
) -> String {
    let perms = db.get_client_perms(client_uid).unwrap_or_default();
    if perms.is_empty() {
        return format!("notifyclientpermlist cldbid={}", cldbid);
    }
    let parts: Vec<String> = perms
        .into_iter()
        .map(|p| {
            let id_part = if use_permsid {
                format!("permsid={}", p.perm_id)
            } else {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                format!("permid={}", pid)
            };
            format!(
                "cldbid={} {} permvalue={} permnegated={} permskip={}",
                cldbid,
                id_part,
                p.perm_value,
                if p.perm_negated { 1 } else { 0 },
                if p.perm_skip { 1 } else { 0 },
            )
        })
        .collect();
    format!("notifyclientpermlist {}", parts.join("|"))
}

/// Builds the `notifychannelclientpermlist` wire payload for a client in a channel.
pub fn build_channel_client_perm_list(
    db: &Database,
    cid: u64,
    cldbid: u64,
    client_uid: &str,
    use_permsid: bool,
) -> String {
    let perms = db.get_channel_client_perms(cid, client_uid).unwrap_or_default();
    if perms.is_empty() {
        return format!("notifychannelclientpermlist cid={} cldbid={}", cid, cldbid);
    }
    let parts: Vec<String> = perms
        .into_iter()
        .map(|p| {
            let id_part = if use_permsid {
                format!("permsid={}", p.perm_id)
            } else {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                format!("permid={}", pid)
            };
            format!(
                "cid={} cldbid={} {} permvalue={} permnegated={} permskip={}",
                cid,
                cldbid,
                id_part,
                p.perm_value,
                if p.perm_negated { 1 } else { 0 },
                if p.perm_skip { 1 } else { 0 },
            )
        })
        .collect();
    format!("notifychannelclientpermlist {}", parts.join("|"))
}

/// Builds the `notifypermoverview` wire payload across all 5 tiers.
pub fn build_permission_overview(
    db: &Database,
    client_uid: &str,
    cldbid: u64,
    cid: u64,
    filter_permid: u32,
) -> String {
    let mut rows: Vec<String> = Vec::new();

    // Tier 1: Server groups (t=0, id1=sgid, id2=0)
    let sgs = db
        .get_client_server_groups(client_uid)
        .unwrap_or_else(|_| vec![8]);
    for sgid in sgs {
        if let Ok(perms) = db.get_server_group_perms(sgid) {
            for p in perms {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                if filter_permid == 0 || filter_permid == pid {
                    rows.push(format!(
                        "t=0 id1={} id2=0 p={} v={} n={} s={}",
                        sgid,
                        pid,
                        p.perm_value,
                        if p.perm_negated { 1 } else { 0 },
                        if p.perm_skip { 1 } else { 0 },
                    ));
                }
            }
        }
    }

    // Tier 2: Client perms (t=1, id1=cldbid, id2=0)
    if let Ok(perms) = db.get_client_perms(client_uid) {
        for p in perms {
            let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
            if filter_permid == 0 || filter_permid == pid {
                rows.push(format!(
                    "t=1 id1={} id2=0 p={} v={} n={} s={}",
                    cldbid,
                    pid,
                    p.perm_value,
                    if p.perm_negated { 1 } else { 0 },
                    if p.perm_skip { 1 } else { 0 },
                ));
            }
        }
    }

    // Tier 3: Channel perms (t=2, id1=cid, id2=0)
    if cid > 0 {
        if let Ok(perms) = db.get_channel_perms(cid) {
            for p in perms {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                if filter_permid == 0 || filter_permid == pid {
                    rows.push(format!(
                        "t=2 id1={} id2=0 p={} v={} n={} s={}",
                        cid,
                        pid,
                        p.perm_value,
                        if p.perm_negated { 1 } else { 0 },
                        if p.perm_skip { 1 } else { 0 },
                    ));
                }
            }
        }
    }

    // Tier 4: Channel group (t=3, id1=cgid, id2=0)
    if cid > 0 {
        let cgid = db.get_client_channel_group(client_uid, cid).unwrap_or(8);
        if let Ok(perms) = db.get_channel_group_perms(cgid) {
            for p in perms {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                if filter_permid == 0 || filter_permid == pid {
                    rows.push(format!(
                        "t=3 id1={} id2=0 p={} v={} n={} s={}",
                        cgid,
                        pid,
                        p.perm_value,
                        if p.perm_negated { 1 } else { 0 },
                        if p.perm_skip { 1 } else { 0 },
                    ));
                }
            }
        }
    }

    // Tier 5: Channel-client perms (t=4, id1=cid, id2=cldbid)
    if cid > 0 {
        if let Ok(perms) = db.get_channel_client_perms(cid, client_uid) {
            for p in perms {
                let pid = perm_name_to_id(&p.perm_id).unwrap_or(0);
                if filter_permid == 0 || filter_permid == pid {
                    rows.push(format!(
                        "t=4 id1={} id2={} p={} v={} n={} s={}",
                        cid,
                        cldbid,
                        pid,
                        p.perm_value,
                        if p.perm_negated { 1 } else { 0 },
                        if p.perm_skip { 1 } else { 0 },
                    ));
                }
            }
        }
    }

    if rows.is_empty() {
        "notifypermoverview".to_string()
    } else {
        format!("notifypermoverview {}", rows.join("|"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_five_tier_permission_evaluation() {
        let db = Database::in_memory().expect("in-memory db");

        let uid = "test_user_eval";
        let cid = 1;

        // Default: Guest (server group 8)
        assert_eq!(
            evaluate_permission(&db, uid, cid, "b_channel_modify_name"),
            None
        );
        assert!(!has_permission(&db, uid, cid, "b_channel_modify_name"));
        assert_eq!(get_power(&db, uid, cid, "i_channel_modify_power"), 0);

        // Tier 4: Give user Channel Admin in channel 1
        db.set_client_channel_group(uid, cid, 5).unwrap();
        assert_eq!(
            evaluate_permission(&db, uid, cid, "b_channel_modify_name"),
            Some(1)
        );
        assert!(has_permission(&db, uid, cid, "b_channel_modify_name"));
        assert_eq!(get_power(&db, uid, cid, "i_channel_delete_power"), 50);

        // In channel 2, user should still be Guest
        assert_eq!(
            evaluate_permission(&db, uid, 2, "b_channel_modify_name"),
            None
        );

        // Tier 3: Channel permission for a perm not in Channel Group (e.g. i_channel_needed_join_power)
        db.set_channel_perm(cid, "i_channel_needed_join_power", 25, false, false).unwrap();
        assert_eq!(get_power(&db, uid, cid, "i_channel_needed_join_power"), 25);

        // Tier 5: Channel-Client permission overrides Channel Group (Tier 4)
        db.set_channel_client_perm(cid, uid, "i_channel_delete_power", 80, false, false).unwrap();
        assert_eq!(get_power(&db, uid, cid, "i_channel_delete_power"), 80);

        // Power comparison
        assert!(check_power(&db, uid, cid, "i_channel_delete_power", 75));
        assert!(!check_power(&db, uid, cid, "i_channel_delete_power", 90));
    }

    #[test]
    fn test_server_admin_skip_channelgroup() {
        let db = Database::in_memory().expect("in-memory db");
        let uid = "admin_user";
        db.add_client_to_server_group(uid, 6).unwrap();

        let cid = 1;
        // Server admin has power 75
        assert_eq!(get_power(&db, uid, cid, "i_channel_modify_power"), 75);

        // Channel group 8 (Guest) has 0, but because Server Admin skips channel group perms,
        // it stays 75!
        db.set_client_channel_group(uid, cid, 8).unwrap();
        assert_eq!(get_power(&db, uid, cid, "i_channel_modify_power"), 75);
    }

    #[test]
    fn test_check_modify_permission() {
        let db = Database::in_memory().expect("in-memory db");
        let admin_uid = "admin_user";
        db.add_client_to_server_group(admin_uid, 6).unwrap();

        let guest_uid = "guest_user"; // defaults to group 8

        let cid = 1;

        // Admin (power 75) modifying b_channel_modify_name (needed 75) -> Ok
        assert!(check_modify_permission(&db, admin_uid, cid, "b_channel_modify_name", Some(1), false).is_ok());

        // Admin granting power 50 -> Ok
        assert!(check_modify_permission(&db, admin_uid, cid, "i_channel_modify_power", Some(50), false).is_ok());

        // Admin granting power 100 (exceeds admin's 75 power) -> Err
        assert!(check_modify_permission(&db, admin_uid, cid, "i_channel_modify_power", Some(100), false).is_err());

        // Guest (power 0) modifying b_channel_modify_name (needed 75) -> Err
        assert!(check_modify_permission(&db, guest_uid, cid, "b_channel_modify_name", Some(1), false).is_err());
    }
}
