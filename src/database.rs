use rand::{Rng, distributions::Alphanumeric};
use rusqlite::{Connection, Result, params};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ChannelRecord {
    pub cid: u64,
    pub name: String,
    pub topic: String,
    pub description: String,
    /// TeamSpeak `channel_order`: the preceding sibling's ID, or zero first.
    pub order_id: u64,
    pub is_default: bool,
    pub is_permanent: bool,
    pub is_semi_permanent: bool,
    pub codec: i64,
    pub codec_quality: i64,
    pub max_clients: i64,
    pub max_family_clients: i64,
    pub needed_talk_power: i64,
    pub needed_subscribe_power: i64,
    pub codec_latency_factor: i64,
    pub delete_delay: i64,
    pub max_clients_unlimited: bool,
    pub max_family_clients_unlimited: bool,
    pub max_family_clients_inherited: bool,
    pub name_phonetic: String,
    pub icon_id: i64,
    /// SHA-256 hex digest of the channel password; empty means no password.
    pub password_hash: String,
    /// TeamSpeak `channel_codec_is_unencrypted`. False means clients send
    /// EAX-encrypted voice payloads in this channel.
    pub codec_is_unencrypted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ChannelEdit {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub description: Option<String>,
    pub order_after: Option<u64>,
    pub is_default: Option<bool>,
    pub is_permanent: Option<bool>,
    pub is_semi_permanent: Option<bool>,
    pub codec: Option<i64>,
    pub codec_quality: Option<i64>,
    pub max_clients: Option<i64>,
    pub max_family_clients: Option<i64>,
    pub needed_talk_power: Option<i64>,
    pub needed_subscribe_power: Option<i64>,
    pub codec_latency_factor: Option<i64>,
    pub delete_delay: Option<i64>,
    pub max_clients_unlimited: Option<bool>,
    pub max_family_clients_unlimited: Option<bool>,
    pub max_family_clients_inherited: Option<bool>,
    pub name_phonetic: Option<String>,
    pub icon_id: Option<i64>,
    /// New channel password as a SHA-256 hex digest. `Some("")` clears the
    /// password; `None` leaves it untouched (the official client omits
    /// `channel_password` when editing a passworded channel without retyping
    /// it).
    pub password: Option<String>,
    pub codec_is_unencrypted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BanRecord {
    pub ban_id: u64,
    pub ip: String,
    pub name: String,
    pub uid: String,
    pub mytsid: String,
    pub lastnickname: String,
    pub created: i64,
    pub duration: i64,
    pub invokercldbid: u64,
    pub invokername: String,
    pub invokeruid: String,
    pub reason: String,
    pub enforcements: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub group_id: u64,
    pub name: String,
    pub group_type: i64,
    pub icon_id: i64,
    pub save_db: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermRecord {
    pub perm_id: String,
    pub perm_value: i64,
    pub perm_negated: bool,
    pub perm_skip: bool,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Opens or creates the SQLite database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Creates an in-memory database (useful for testing).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS server_properties (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channels (
                cid INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                topic TEXT NOT NULL DEFAULT '',
                order_id INTEGER NOT NULL DEFAULT 0,
                is_default INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL DEFAULT '',
                is_permanent INTEGER NOT NULL DEFAULT 1,
                is_semi_permanent INTEGER NOT NULL DEFAULT 0,
                codec INTEGER NOT NULL DEFAULT 4,
                codec_quality INTEGER NOT NULL DEFAULT 7,
                max_clients INTEGER NOT NULL DEFAULT -1,
                max_family_clients INTEGER NOT NULL DEFAULT -1,
                needed_talk_power INTEGER NOT NULL DEFAULT 0,
                needed_subscribe_power INTEGER NOT NULL DEFAULT 0,
                codec_latency_factor INTEGER NOT NULL DEFAULT 1,
                delete_delay INTEGER NOT NULL DEFAULT 0,
                max_clients_unlimited INTEGER NOT NULL DEFAULT 1,
                max_family_clients_unlimited INTEGER NOT NULL DEFAULT 1,
                max_family_clients_inherited INTEGER NOT NULL DEFAULT 0,
                name_phonetic TEXT NOT NULL DEFAULT '',
                icon_id INTEGER NOT NULL DEFAULT 0,
                password_hash TEXT NOT NULL DEFAULT '',
                codec_is_unencrypted INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS privilege_keys (
                token TEXT PRIMARY KEY,
                is_used INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_identities (
                client_uid TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bans (
                ban_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                uid TEXT NOT NULL DEFAULT '',
                mytsid TEXT NOT NULL DEFAULT '',
                lastnickname TEXT NOT NULL DEFAULT '',
                created INTEGER NOT NULL,
                duration INTEGER NOT NULL DEFAULT 0,
                invokercldbid INTEGER NOT NULL DEFAULT 0,
                invokername TEXT NOT NULL DEFAULT '',
                invokeruid TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                enforcements INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS groups_server (
                group_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                type INTEGER NOT NULL DEFAULT 1,
                icon_id INTEGER NOT NULL DEFAULT 0,
                save_db INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS groups_channel (
                group_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                type INTEGER NOT NULL DEFAULT 1,
                icon_id INTEGER NOT NULL DEFAULT 0,
                save_db INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS group_server_to_client (
                group_id INTEGER NOT NULL,
                client_uid TEXT NOT NULL,
                PRIMARY KEY(group_id, client_uid)
            );

            CREATE TABLE IF NOT EXISTS group_channel_to_client (
                group_id INTEGER NOT NULL,
                cid INTEGER NOT NULL,
                client_uid TEXT NOT NULL,
                PRIMARY KEY(cid, client_uid)
            );

            CREATE TABLE IF NOT EXISTS perm_server_group (
                group_id INTEGER NOT NULL,
                perm_id TEXT NOT NULL,
                perm_value INTEGER NOT NULL,
                perm_negated INTEGER NOT NULL DEFAULT 0,
                perm_skip INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(group_id, perm_id)
            );

            CREATE TABLE IF NOT EXISTS perm_channel_groups (
                group_id INTEGER NOT NULL,
                perm_id TEXT NOT NULL,
                perm_value INTEGER NOT NULL,
                perm_negated INTEGER NOT NULL DEFAULT 0,
                perm_skip INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(group_id, perm_id)
            );

            CREATE TABLE IF NOT EXISTS perm_channel (
                cid INTEGER NOT NULL,
                perm_id TEXT NOT NULL,
                perm_value INTEGER NOT NULL,
                perm_negated INTEGER NOT NULL DEFAULT 0,
                perm_skip INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(cid, perm_id)
            );

            CREATE TABLE IF NOT EXISTS perm_client (
                client_uid TEXT NOT NULL,
                perm_id TEXT NOT NULL,
                perm_value INTEGER NOT NULL,
                perm_negated INTEGER NOT NULL DEFAULT 0,
                perm_skip INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(client_uid, perm_id)
            );

            CREATE TABLE IF NOT EXISTS perm_channel_clients (
                cid INTEGER NOT NULL,
                client_uid TEXT NOT NULL,
                perm_id TEXT NOT NULL,
                perm_value INTEGER NOT NULL,
                perm_negated INTEGER NOT NULL DEFAULT 0,
                perm_skip INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(cid, client_uid, perm_id)
            );
            ",
        )?;

        // Add channel properties to databases created by older builds.
        // SQLite cannot add several columns through one ALTER TABLE, so keep
        // the migration list explicit and only apply missing columns.
        let existing_columns = {
            let mut stmt = self.conn.prepare("PRAGMA table_info(channels)")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
            rows.collect::<Result<HashSet<_>, _>>()?
        };
        for (name, declaration) in [
            ("description", "TEXT NOT NULL DEFAULT ''"),
            ("is_permanent", "INTEGER NOT NULL DEFAULT 1"),
            ("is_semi_permanent", "INTEGER NOT NULL DEFAULT 0"),
            ("codec", "INTEGER NOT NULL DEFAULT 4"),
            ("codec_quality", "INTEGER NOT NULL DEFAULT 7"),
            ("max_clients", "INTEGER NOT NULL DEFAULT -1"),
            ("max_family_clients", "INTEGER NOT NULL DEFAULT -1"),
            ("needed_talk_power", "INTEGER NOT NULL DEFAULT 0"),
            ("needed_subscribe_power", "INTEGER NOT NULL DEFAULT 0"),
            ("codec_latency_factor", "INTEGER NOT NULL DEFAULT 1"),
            ("delete_delay", "INTEGER NOT NULL DEFAULT 0"),
            ("max_clients_unlimited", "INTEGER NOT NULL DEFAULT 1"),
            ("max_family_clients_unlimited", "INTEGER NOT NULL DEFAULT 1"),
            ("max_family_clients_inherited", "INTEGER NOT NULL DEFAULT 0"),
            ("name_phonetic", "TEXT NOT NULL DEFAULT ''"),
            ("icon_id", "INTEGER NOT NULL DEFAULT 0"),
            ("password_hash", "TEXT NOT NULL DEFAULT ''"),
            ("codec_is_unencrypted", "INTEGER NOT NULL DEFAULT 1"),
        ] {
            if !existing_columns.contains(name) {
                self.conn.execute_batch(&format!(
                    "ALTER TABLE channels ADD COLUMN {name} {declaration}"
                ))?;
            }
        }

        // Ensure default channel exists
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))?;

        if count == 0 {
            self.conn.execute(
                "INSERT INTO channels (name, topic, order_id, is_default) VALUES (?1, ?2, ?3, ?4)",
                params!["Default Channel", "Welcome to Nano-TS3", 0, 1],
            )?;
        }

        // Older databases could contain channels with duplicate names (the
        // create path did not validate them). A TeamSpeak client rejects a
        // channel tree containing duplicate names, so collapse duplicates
        // before enforcing uniqueness.
        self.conn.execute(
            "DELETE FROM channels WHERE cid NOT IN (
                 SELECT MIN(cid) FROM channels GROUP BY name COLLATE NOCASE
             )",
            [],
        )?;
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_name_nocase
             ON channels(name COLLATE NOCASE)",
            [],
        )?;

        // `order_id` stores TeamSpeak's `channel_order` link: the channel ID
        // this channel follows (zero for the first channel). Older builds
        // wrote zero for every new channel, so rebuild a valid sibling chain
        // while preserving any order that can already be followed.
        self.normalize_channel_order()?;

        // Ensure server properties exist
        self.conn.execute(
            "INSERT OR IGNORE INTO server_properties (key, value) VALUES (?1, ?2)",
            params!["virtualserver_name", "Nano-TS3 Minimal Server"],
        )?;
        self.conn.execute(
            "INSERT OR IGNORE INTO server_properties (key, value) VALUES (?1, ?2)",
            params![
                "virtualserver_welcomemessage",
                "Welcome to Nano-TS3 Server!"
            ],
        )?;

        // Seed default server groups
        let sg_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM groups_server", [], |row| row.get(0))?;
        if sg_count == 0 {
            let mut stmt = self.conn.prepare(
                "INSERT INTO groups_server (group_id, name, type, icon_id, save_db) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for grp in crate::default_permissions::DEFAULT_SERVER_GROUPS {
                let icon_id = match grp.id {
                    6 => 300,
                    _ => 0,
                };
                let save_db = if grp.id == 8 { 0 } else { 1 };
                stmt.execute(params![grp.id, grp.name, grp.group_type, icon_id, save_db])?;
            }
        }

        // Seed default server group perms
        let sg_perm_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM perm_server_group", [], |row| row.get(0))?;
        if sg_perm_count == 0 {
            let mut stmt = self.conn.prepare(
                "INSERT INTO perm_server_group (group_id, perm_id, perm_value, perm_negated, perm_skip) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for p in crate::default_permissions::DEFAULT_SERVER_GROUP_PERMS {
                stmt.execute(params![
                    p.group_id,
                    p.perm_id,
                    p.value,
                    p.negated as i64,
                    p.skip as i64
                ])?;
            }
        }

        // Seed default channel groups
        let cg_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM groups_channel", [], |row| row.get(0))?;
        if cg_count == 0 {
            let mut stmt = self.conn.prepare(
                "INSERT INTO groups_channel (group_id, name, type, icon_id, save_db) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for grp in crate::default_permissions::DEFAULT_CHANNEL_GROUPS {
                let icon_id = match grp.id {
                    5 => 100,
                    6 => 200,
                    7 => 600,
                    _ => 0,
                };
                let save_db = if grp.id == 8 { 0 } else { 1 };
                stmt.execute(params![grp.id, grp.name, grp.group_type, icon_id, save_db])?;
            }
        }

        // Seed default channel group perms
        let cg_perm_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM perm_channel_groups", [], |row| row.get(0))?;
        if cg_perm_count == 0 {
            let mut stmt = self.conn.prepare(
                "INSERT INTO perm_channel_groups (group_id, perm_id, perm_value, perm_negated, perm_skip) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for p in crate::default_permissions::DEFAULT_CHANNEL_GROUP_PERMS {
                stmt.execute(params![
                    p.group_id,
                    p.perm_id,
                    p.value,
                    p.negated as i64,
                    p.skip as i64
                ])?;
            }
        }

        // Migrate any existing admin identities into group_server_to_client (Server Admin)
        self.conn.execute(
            "INSERT OR IGNORE INTO group_server_to_client (group_id, client_uid)
             SELECT 6, client_uid FROM admin_identities",
            [],
        )?;

        Ok(())
    }

    /// Generates and stores a one-time Server Admin privilege key if none exists.
    /// Returns Some(token) if a fresh token was created.
    pub fn get_or_create_initial_admin_token(&self) -> Result<Option<String>> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM privilege_keys", [], |row| row.get(0))?;

        if count == 0 {
            let rand_string: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            let token = format!("nano_ts3_admin_{}", rand_string);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            self.conn.execute(
                "INSERT INTO privilege_keys (token, is_used, created_at) VALUES (?1, ?2, ?3)",
                params![token, 0, now],
            )?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Redeems an admin privilege token. Returns true if valid and unused.
    pub fn redeem_privilege_key(&self, token: &str) -> Result<bool> {
        let token = token.trim();
        let mut stmt = self
            .conn
            .prepare("SELECT is_used FROM privilege_keys WHERE token = ?1")?;
        let is_used: Option<i64> = stmt.query_row(params![token], |row| row.get(0)).ok();

        if let Some(0) = is_used {
            self.conn.execute(
                "UPDATE privilege_keys SET is_used = 1 WHERE token = ?1",
                params![token],
            )?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Checks if there is any unused privilege key.
    pub fn has_unused_privilege_key(&self) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM privilege_keys WHERE is_used = 0")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Checks if a client UID is a known Server Admin.
    pub fn is_admin_identity(&self, uid: &str) -> Result<bool> {
        let in_group: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM group_server_to_client WHERE client_uid = ?1 AND group_id = 6",
            params![uid],
            |row| row.get(0),
        )?;
        if in_group > 0 {
            return Ok(true);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM admin_identities WHERE client_uid = ?1")?;
        let count: i64 = stmt.query_row(params![uid], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Adds a client UID as a persistent Server Admin.
    pub fn add_admin_identity(&self, uid: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn.execute(
            "INSERT OR IGNORE INTO admin_identities (client_uid, created_at) VALUES (?1, ?2)",
            params![uid, now],
        )?;
        let _ = self.add_client_to_server_group(uid, 6);
        Ok(())
    }

    // --- Group & Permission accessors ---

    pub fn get_client_server_groups(&self, uid: &str) -> Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id FROM group_server_to_client WHERE client_uid = ?1 ORDER BY group_id",
        )?;
        let rows = stmt.query_map(params![uid], |row| row.get::<_, u64>(0))?;
        let groups = rows.collect::<Result<Vec<_>, _>>()?;
        if groups.is_empty() {
            // Default server group is 8 (Guest)
            Ok(vec![8])
        } else {
            Ok(groups)
        }
    }

    pub fn set_client_server_groups(&self, uid: &str, groups: &[u64]) -> Result<()> {
        self.conn.execute(
            "DELETE FROM group_server_to_client WHERE client_uid = ?1",
            params![uid],
        )?;
        for &gid in groups {
            self.conn.execute(
                "INSERT OR IGNORE INTO group_server_to_client (group_id, client_uid) VALUES (?1, ?2)",
                params![gid, uid],
            )?;
        }
        Ok(())
    }

    pub fn add_client_to_server_group(&self, uid: &str, group_id: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO group_server_to_client (group_id, client_uid) VALUES (?1, ?2)",
            params![group_id, uid],
        )?;
        // If adding to a non-guest group, remove from Guest group (8)
        if group_id != 8 {
            self.conn.execute(
                "DELETE FROM group_server_to_client WHERE client_uid = ?1 AND group_id = 8",
                params![uid],
            )?;
        }
        Ok(())
    }

    pub fn remove_client_from_server_group(&self, uid: &str, group_id: u64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM group_server_to_client WHERE client_uid = ?1 AND group_id = ?2",
            params![uid, group_id],
        )?;
        // If no server groups left, assign Guest group (8)
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM group_server_to_client WHERE client_uid = ?1",
            params![uid],
            |row| row.get(0),
        )?;
        if count == 0 {
            self.conn.execute(
                "INSERT OR IGNORE INTO group_server_to_client (group_id, client_uid) VALUES (8, ?1)",
                params![uid],
            )?;
        }
        Ok(())
    }

    pub fn get_client_channel_group(&self, uid: &str, cid: u64) -> Result<u64> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id FROM group_channel_to_client WHERE cid = ?1 AND client_uid = ?2",
        )?;
        let res = stmt.query_row(params![cid, uid], |row| row.get::<_, u64>(0));
        match res {
            Ok(cgid) => Ok(cgid),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(8), // Guest
            Err(e) => Err(e),
        }
    }

    pub fn set_client_channel_group(&self, uid: &str, cid: u64, group_id: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO group_channel_to_client (group_id, cid, client_uid) VALUES (?1, ?2, ?3)
             ON CONFLICT(cid, client_uid) DO UPDATE SET group_id = excluded.group_id",
            params![group_id, cid, uid],
        )?;
        Ok(())
    }

    pub fn get_server_groups(&self) -> Result<Vec<GroupRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, name, type, icon_id, save_db FROM groups_server ORDER BY group_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(GroupRecord {
                group_id: row.get(0)?,
                name: row.get(1)?,
                group_type: row.get(2)?,
                icon_id: row.get(3)?,
                save_db: row.get::<_, i64>(4)? == 1,
            })
        })?;
        rows.collect()
    }

    pub fn get_channel_groups(&self) -> Result<Vec<GroupRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, name, type, icon_id, save_db FROM groups_channel ORDER BY group_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(GroupRecord {
                group_id: row.get(0)?,
                name: row.get(1)?,
                group_type: row.get(2)?,
                icon_id: row.get(3)?,
                save_db: row.get::<_, i64>(4)? == 1,
            })
        })?;
        rows.collect()
    }

    pub fn get_server_group_perms(&self, group_id: u64) -> Result<Vec<PermRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT perm_id, perm_value, perm_negated, perm_skip FROM perm_server_group WHERE group_id = ?1 ORDER BY perm_id",
        )?;
        let rows = stmt.query_map(params![group_id], |row| {
            Ok(PermRecord {
                perm_id: row.get(0)?,
                perm_value: row.get(1)?,
                perm_negated: row.get::<_, i64>(2)? == 1,
                perm_skip: row.get::<_, i64>(3)? == 1,
            })
        })?;
        rows.collect()
    }

    pub fn set_server_group_perm(
        &self,
        group_id: u64,
        perm_id: &str,
        value: i64,
        negated: bool,
        skip: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO perm_server_group (group_id, perm_id, perm_value, perm_negated, perm_skip)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id, perm_id) DO UPDATE SET
                 perm_value = excluded.perm_value,
                 perm_negated = excluded.perm_negated,
                 perm_skip = excluded.perm_skip",
            params![group_id, perm_id, value, negated as i64, skip as i64],
        )?;
        Ok(())
    }

    pub fn del_server_group_perm(&self, group_id: u64, perm_id: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM perm_server_group WHERE group_id = ?1 AND perm_id = ?2",
            params![group_id, perm_id],
        )?;
        Ok(count > 0)
    }

    pub fn get_channel_group_perms(&self, group_id: u64) -> Result<Vec<PermRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT perm_id, perm_value, perm_negated, perm_skip FROM perm_channel_groups WHERE group_id = ?1 ORDER BY perm_id",
        )?;
        let rows = stmt.query_map(params![group_id], |row| {
            Ok(PermRecord {
                perm_id: row.get(0)?,
                perm_value: row.get(1)?,
                perm_negated: row.get::<_, i64>(2)? == 1,
                perm_skip: row.get::<_, i64>(3)? == 1,
            })
        })?;
        rows.collect()
    }

    pub fn set_channel_group_perm(
        &self,
        group_id: u64,
        perm_id: &str,
        value: i64,
        negated: bool,
        skip: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO perm_channel_groups (group_id, perm_id, perm_value, perm_negated, perm_skip)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id, perm_id) DO UPDATE SET
                 perm_value = excluded.perm_value,
                 perm_negated = excluded.perm_negated,
                 perm_skip = excluded.perm_skip",
            params![group_id, perm_id, value, negated as i64, skip as i64],
        )?;
        Ok(())
    }

    pub fn del_channel_group_perm(&self, group_id: u64, perm_id: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM perm_channel_groups WHERE group_id = ?1 AND perm_id = ?2",
            params![group_id, perm_id],
        )?;
        Ok(count > 0)
    }

    pub fn get_channel_perms(&self, cid: u64) -> Result<Vec<PermRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT perm_id, perm_value, perm_negated, perm_skip FROM perm_channel WHERE cid = ?1 ORDER BY perm_id",
        )?;
        let rows = stmt.query_map(params![cid], |row| {
            Ok(PermRecord {
                perm_id: row.get(0)?,
                perm_value: row.get(1)?,
                perm_negated: row.get::<_, i64>(2)? == 1,
                perm_skip: row.get::<_, i64>(3)? == 1,
            })
        })?;
        rows.collect()
    }

    pub fn set_channel_perm(
        &self,
        cid: u64,
        perm_id: &str,
        value: i64,
        negated: bool,
        skip: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO perm_channel (cid, perm_id, perm_value, perm_negated, perm_skip)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(cid, perm_id) DO UPDATE SET
                 perm_value = excluded.perm_value,
                 perm_negated = excluded.perm_negated,
                 perm_skip = excluded.perm_skip",
            params![cid, perm_id, value, negated as i64, skip as i64],
        )?;
        Ok(())
    }

    pub fn del_channel_perm(&self, cid: u64, perm_id: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM perm_channel WHERE cid = ?1 AND perm_id = ?2",
            params![cid, perm_id],
        )?;
        Ok(count > 0)
    }

    pub fn get_client_perms(&self, uid: &str) -> Result<Vec<PermRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT perm_id, perm_value, perm_negated, perm_skip FROM perm_client WHERE client_uid = ?1 ORDER BY perm_id",
        )?;
        let rows = stmt.query_map(params![uid], |row| {
            Ok(PermRecord {
                perm_id: row.get(0)?,
                perm_value: row.get(1)?,
                perm_negated: row.get::<_, i64>(2)? == 1,
                perm_skip: row.get::<_, i64>(3)? == 1,
            })
        })?;
        rows.collect()
    }

    pub fn set_client_perm(
        &self,
        uid: &str,
        perm_id: &str,
        value: i64,
        negated: bool,
        skip: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO perm_client (client_uid, perm_id, perm_value, perm_negated, perm_skip)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(client_uid, perm_id) DO UPDATE SET
                 perm_value = excluded.perm_value,
                 perm_negated = excluded.perm_negated,
                 perm_skip = excluded.perm_skip",
            params![uid, perm_id, value, negated as i64, skip as i64],
        )?;
        Ok(())
    }

    pub fn del_client_perm(&self, uid: &str, perm_id: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM perm_client WHERE client_uid = ?1 AND perm_id = ?2",
            params![uid, perm_id],
        )?;
        Ok(count > 0)
    }

    pub fn get_channel_client_perms(&self, cid: u64, uid: &str) -> Result<Vec<PermRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT perm_id, perm_value, perm_negated, perm_skip FROM perm_channel_clients WHERE cid = ?1 AND client_uid = ?2 ORDER BY perm_id",
        )?;
        let rows = stmt.query_map(params![cid, uid], |row| {
            Ok(PermRecord {
                perm_id: row.get(0)?,
                perm_value: row.get(1)?,
                perm_negated: row.get::<_, i64>(2)? == 1,
                perm_skip: row.get::<_, i64>(3)? == 1,
            })
        })?;
        rows.collect()
    }

    pub fn set_channel_client_perm(
        &self,
        cid: u64,
        uid: &str,
        perm_id: &str,
        value: i64,
        negated: bool,
        skip: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO perm_channel_clients (cid, client_uid, perm_id, perm_value, perm_negated, perm_skip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(cid, client_uid, perm_id) DO UPDATE SET
                 perm_value = excluded.perm_value,
                 perm_negated = excluded.perm_negated,
                 perm_skip = excluded.perm_skip",
            params![cid, uid, perm_id, value, negated as i64, skip as i64],
        )?;
        Ok(())
    }

    pub fn del_channel_client_perm(&self, cid: u64, uid: &str, perm_id: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM perm_channel_clients WHERE cid = ?1 AND client_uid = ?2 AND perm_id = ?3",
            params![cid, uid, perm_id],
        )?;
        Ok(count > 0)
    }

    /// Fetches all channels from the database.
    pub fn get_channels(&self) -> Result<Vec<ChannelRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT cid, name, topic, order_id, is_default, description, \
                 is_permanent, is_semi_permanent, codec, codec_quality, max_clients, \
                 max_family_clients, needed_talk_power, needed_subscribe_power, \
                 codec_latency_factor, delete_delay, max_clients_unlimited, \
                 max_family_clients_unlimited, max_family_clients_inherited, \
                 name_phonetic, icon_id, password_hash, codec_is_unencrypted FROM channels",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ChannelRecord {
                cid: row.get(0)?,
                name: row.get(1)?,
                topic: row.get(2)?,
                order_id: row.get(3)?,
                is_default: row.get::<_, i64>(4)? == 1,
                description: row.get(5)?,
                is_permanent: row.get::<_, i64>(6)? == 1,
                is_semi_permanent: row.get::<_, i64>(7)? == 1,
                codec: row.get(8)?,
                codec_quality: row.get(9)?,
                max_clients: row.get(10)?,
                max_family_clients: row.get(11)?,
                needed_talk_power: row.get(12)?,
                needed_subscribe_power: row.get(13)?,
                codec_latency_factor: row.get(14)?,
                delete_delay: row.get(15)?,
                max_clients_unlimited: row.get::<_, i64>(16)? == 1,
                max_family_clients_unlimited: row.get::<_, i64>(17)? == 1,
                max_family_clients_inherited: row.get::<_, i64>(18)? == 1,
                name_phonetic: row.get(19)?,
                icon_id: row.get(20)?,
                password_hash: row.get(21)?,
                codec_is_unencrypted: row.get::<_, i64>(22)? == 1,
            })
        })?;

        let mut channels = Vec::new();
        for r in rows {
            channels.push(r?);
        }

        // `channel_order` is a predecessor link, not a numeric sort key.
        // Walk that chain so insertion and subsequent list responses use the
        // same visible order as the client. Prefer the default channel and
        // then the lower channel ID when repairing ambiguous old data.
        channels.sort_by_key(|ch| (!ch.is_default, ch.cid));
        let mut successors: HashMap<u64, Vec<ChannelRecord>> = HashMap::new();
        for ch in &channels {
            successors.entry(ch.order_id).or_default().push(ch.clone());
        }
        for list in successors.values_mut() {
            list.sort_by_key(|ch| (!ch.is_default, ch.cid));
        }

        let mut pending = successors.remove(&0).unwrap_or_default();
        pending.reverse();
        let mut ordered = Vec::with_capacity(channels.len());
        let mut visited = HashSet::with_capacity(channels.len());

        while let Some(ch) = pending.pop() {
            if !visited.insert(ch.cid) {
                continue;
            }
            if let Some(mut next) = successors.remove(&ch.cid) {
                next.reverse();
                pending.extend(next);
            }
            ordered.push(ch);
        }

        // Cycles and orphaned links have no reachable first channel. Append
        // them deterministically; normalize_channel_order will make the
        // resulting order persistent.
        for ch in channels {
            if visited.contains(&ch.cid) {
                continue;
            }
            pending.push(ch);
            while let Some(next_ch) = pending.pop() {
                if !visited.insert(next_ch.cid) {
                    continue;
                }
                if let Some(mut next) = successors.remove(&next_ch.cid) {
                    next.reverse();
                    pending.extend(next);
                }
                ordered.push(next_ch);
            }
        }

        Ok(ordered)
    }

    /// Creates a new channel.
    pub fn create_channel(&self, name: &str, topic: &str) -> Result<u64> {
        let order_after = self.get_channels()?.last().map(|ch| ch.cid).unwrap_or(0);
        self.create_channel_after(name, topic, order_after)
    }

    /// Creates a channel after the specified sibling, updating the next
    /// sibling's predecessor link when inserting in the middle of the list.
    pub fn create_channel_after(&self, name: &str, topic: &str, order_after: u64) -> Result<u64> {
        let channels = self.get_channels()?;
        let valid_order_after = order_after == 0 || channels.iter().any(|ch| ch.cid == order_after);
        let order_after = if valid_order_after {
            order_after
        } else {
            channels.last().map(|ch| ch.cid).unwrap_or(0)
        };
        let successor = channels
            .iter()
            .find(|ch| ch.order_id == order_after)
            .map(|ch| ch.cid);

        self.conn.execute(
            "INSERT INTO channels (name, topic, order_id, is_default) VALUES (?1, ?2, ?3, ?4)",
            params![name, topic, order_after as i64, 0],
        )?;
        let cid = self.conn.last_insert_rowid() as u64;

        if let Some(successor) = successor {
            self.conn.execute(
                "UPDATE channels SET order_id = ?1 WHERE cid = ?2",
                params![cid as i64, successor as i64],
            )?;
        }

        Ok(cid)
    }

    /// Applies channel edits and keeps the stored order links consistent.
    /// Returns None if the channel ID does not exist.
    pub fn edit_channel(&self, cid: u64, edit: &ChannelEdit) -> Result<Option<ChannelRecord>> {
        let mut channels = self.get_channels()?;
        let Some(index) = channels.iter().position(|channel| channel.cid == cid) else {
            return Ok(None);
        };

        if edit.name.as_deref().is_some_and(str::is_empty) {
            return Err(rusqlite::Error::InvalidParameterName(
                "channel_name must not be empty".into(),
            ));
        }
        if let Some(name) = edit.name.as_deref() {
            if channels
                .iter()
                .any(|channel| channel.cid != cid && channel.name.eq_ignore_ascii_case(name))
            {
                return Err(rusqlite::Error::InvalidParameterName(
                    "duplicate channel_name".into(),
                ));
            }
        }

        if let Some(order_after) = edit.order_after {
            if order_after == cid
                || (order_after != 0 && !channels.iter().any(|channel| channel.cid == order_after))
            {
                return Err(rusqlite::Error::InvalidParameterName(
                    "invalid channel_order".into(),
                ));
            }

            let channel = channels.remove(index);
            let insert_at = if order_after == 0 {
                0
            } else {
                channels
                    .iter()
                    .position(|candidate| candidate.cid == order_after)
                    .map(|position| position + 1)
                    .ok_or_else(|| {
                        rusqlite::Error::InvalidParameterName("invalid channel_order".into())
                    })?
            };
            channels.insert(insert_at, channel);

            let mut predecessor = 0;
            for channel in &mut channels {
                channel.order_id = predecessor;
                self.conn.execute(
                    "UPDATE channels SET order_id = ?1 WHERE cid = ?2",
                    params![predecessor as i64, channel.cid as i64],
                )?;
                predecessor = channel.cid;
            }
        }

        let channel_index = channels
            .iter()
            .position(|channel| channel.cid == cid)
            .expect("channel was found before editing");
        {
            let channel = &mut channels[channel_index];
            if let Some(value) = &edit.name {
                channel.name = value.clone();
            }
            if let Some(value) = &edit.topic {
                channel.topic = value.clone();
            }
            if let Some(value) = &edit.description {
                channel.description = value.clone();
            }
            if let Some(value) = edit.is_permanent {
                channel.is_permanent = value;
                if value {
                    channel.is_semi_permanent = false;
                }
            }
            if let Some(value) = edit.is_semi_permanent {
                channel.is_semi_permanent = value;
                if value {
                    channel.is_permanent = false;
                }
            }
            if let Some(value) = edit.codec {
                channel.codec = value;
            }
            if let Some(value) = edit.codec_quality {
                channel.codec_quality = value;
            }
            if let Some(value) = edit.max_clients {
                channel.max_clients = value;
            }
            if let Some(value) = edit.max_family_clients {
                channel.max_family_clients = value;
            }
            if let Some(value) = edit.needed_talk_power {
                channel.needed_talk_power = value;
            }
            if let Some(value) = edit.needed_subscribe_power {
                channel.needed_subscribe_power = value;
            }
            if let Some(value) = edit.codec_latency_factor {
                channel.codec_latency_factor = value;
            }
            if let Some(value) = edit.delete_delay {
                channel.delete_delay = value;
            }
            if let Some(value) = edit.max_clients_unlimited {
                channel.max_clients_unlimited = value;
            }
            if let Some(value) = edit.max_family_clients_unlimited {
                channel.max_family_clients_unlimited = value;
            }
            if let Some(value) = edit.max_family_clients_inherited {
                channel.max_family_clients_inherited = value;
            }
            if let Some(value) = &edit.name_phonetic {
                channel.name_phonetic = value.clone();
            }
            if let Some(value) = edit.icon_id {
                channel.icon_id = value;
            }
            if let Some(value) = &edit.password {
                // Empty digest clears the password, matching
                // channel_flag_password=0 edits.
                channel.password_hash = value.clone();
            }
            if let Some(value) = edit.codec_is_unencrypted {
                channel.codec_is_unencrypted = value;
            }
        }

        let current_default_cid = channels
            .iter()
            .find(|candidate| candidate.is_default)
            .map(|candidate| candidate.cid);
        let updated_default_cid = match edit.is_default {
            Some(true) => Some(cid),
            Some(false) if current_default_cid == Some(cid) => channels
                .iter()
                .find(|candidate| candidate.cid != cid)
                .map(|candidate| candidate.cid)
                .or(Some(cid)),
            Some(false) => current_default_cid,
            None => current_default_cid,
        };
        if edit.is_default.is_some() {
            for candidate in &mut channels {
                candidate.is_default = Some(candidate.cid) == updated_default_cid;
            }
        }

        let channel = &channels[channel_index];

        self.conn.execute(
            "UPDATE channels SET name=?1, topic=?2, description=?3, order_id=?4, \
             is_default=?5, is_permanent=?6, is_semi_permanent=?7, codec=?8, \
             codec_quality=?9, max_clients=?10, max_family_clients=?11, \
             needed_talk_power=?12, needed_subscribe_power=?13, codec_latency_factor=?14, \
             delete_delay=?15, max_clients_unlimited=?16, \
             max_family_clients_unlimited=?17, max_family_clients_inherited=?18, \
             name_phonetic=?19, icon_id=?20, password_hash=?21, codec_is_unencrypted=?22 \
             WHERE cid=?23",
            params![
                channel.name,
                channel.topic,
                channel.description,
                channel.order_id as i64,
                channel.is_default as i64,
                channel.is_permanent as i64,
                channel.is_semi_permanent as i64,
                channel.codec,
                channel.codec_quality,
                channel.max_clients,
                channel.max_family_clients,
                channel.needed_talk_power,
                channel.needed_subscribe_power,
                channel.codec_latency_factor,
                channel.delete_delay,
                channel.max_clients_unlimited as i64,
                channel.max_family_clients_unlimited as i64,
                channel.max_family_clients_inherited as i64,
                channel.name_phonetic,
                channel.icon_id,
                channel.password_hash,
                channel.codec_is_unencrypted as i64,
                cid as i64,
            ],
        )?;

        if edit.is_default.is_some() {
            if let Some(default_cid) = updated_default_cid {
                self.conn.execute(
                    "UPDATE channels SET is_default = CASE WHEN cid = ?1 THEN 1 ELSE 0 END",
                    params![default_cid as i64],
                )?;
            }
        }

        Ok(self
            .get_channels()?
            .into_iter()
            .find(|channel| channel.cid == cid))
    }

    fn normalize_channel_order(&self) -> Result<()> {
        let channels = self.get_channels()?;
        let mut previous = 0;
        for ch in channels {
            if ch.order_id != previous {
                self.conn.execute(
                    "UPDATE channels SET order_id = ?1 WHERE cid = ?2",
                    params![previous as i64, ch.cid as i64],
                )?;
            }
            previous = ch.cid;
        }
        Ok(())
    }

    /// Deletes a non-default channel and reconnects the predecessor chain.
    pub fn delete_channel(&self, cid: u64) -> Result<bool> {
        let channels = self.get_channels()?;
        let Some(target) = channels.iter().find(|channel| channel.cid == cid) else {
            return Ok(false);
        };
        if target.is_default {
            return Ok(false);
        }

        let rows_affected = self.conn.execute(
            "DELETE FROM channels WHERE cid = ?1 AND is_default = 0",
            params![cid as i64],
        )?;
        if rows_affected == 0 {
            return Ok(false);
        }

        let remaining = channels
            .into_iter()
            .filter(|channel| channel.cid != cid)
            .collect::<Vec<_>>();
        for (position, channel) in remaining.iter().enumerate() {
            let predecessor = position
                .checked_sub(1)
                .map(|previous| remaining[previous].cid)
                .unwrap_or(0);
            self.conn.execute(
                "UPDATE channels SET order_id = ?1 WHERE cid = ?2",
                params![predecessor as i64, channel.cid as i64],
            )?;
        }
        Ok(true)
    }

    /// Fetches a server property value.
    pub fn get_property(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM server_properties WHERE key = ?1")?;
        stmt.query_row(params![key], |row| row.get(0))
            .ok()
            .map(Ok)
            .transpose()
    }

    /// Adds a ban record and returns the allocated `ban_id`.
    pub fn add_ban(&self, ban: &BanRecord) -> Result<u64> {
        self.conn.execute(
            "INSERT INTO bans (ip, name, uid, mytsid, lastnickname, created, duration, invokercldbid, invokername, invokeruid, reason, enforcements) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                ban.ip,
                ban.name,
                ban.uid,
                ban.mytsid,
                ban.lastnickname,
                ban.created,
                ban.duration,
                ban.invokercldbid as i64,
                ban.invokername,
                ban.invokeruid,
                ban.reason,
                ban.enforcements as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid() as u64)
    }

    /// Deletes a ban rule by ID. Returns true if a row was deleted.
    pub fn delete_ban(&self, ban_id: u64) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM bans WHERE ban_id = ?1",
            params![ban_id as i64],
        )?;
        Ok(rows > 0)
    }

    /// Deletes all active ban rules.
    pub fn delete_all_bans(&self) -> Result<()> {
        self.conn.execute("DELETE FROM bans", [])?;
        Ok(())
    }

    /// Fetches all bans.
    pub fn get_bans(&self) -> Result<Vec<BanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT ban_id, ip, name, uid, mytsid, lastnickname, created, duration, \
             invokercldbid, invokername, invokeruid, reason, enforcements FROM bans ORDER BY ban_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BanRecord {
                ban_id: row.get::<_, i64>(0)? as u64,
                ip: row.get(1)?,
                name: row.get(2)?,
                uid: row.get(3)?,
                mytsid: row.get(4)?,
                lastnickname: row.get(5)?,
                created: row.get(6)?,
                duration: row.get(7)?,
                invokercldbid: row.get::<_, i64>(8)? as u64,
                invokername: row.get(9)?,
                invokeruid: row.get(10)?,
                reason: row.get(11)?,
                enforcements: row.get::<_, i64>(12)? as u64,
            })
        })?;
        let mut bans = Vec::new();
        for r in rows {
            bans.push(r?);
        }
        Ok(bans)
    }

    /// Checks if a client is banned by IP, UID, or nickname.
    /// If banned, increments enforcement count and returns the ban reason.
    pub fn is_banned(&self, ip: &str, uid: &str, name: &str) -> Result<Option<String>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let bans = self.get_bans()?;
        for ban in bans {
            // Check expiry: duration == 0 means permanent
            if ban.duration > 0 && ban.created + ban.duration <= now {
                continue;
            }

            let ip_matches = !ban.ip.is_empty() && !ip.is_empty() && ban.ip == ip;
            let uid_matches = !ban.uid.is_empty() && !uid.is_empty() && ban.uid == uid;
            let name_matches =
                !ban.name.is_empty() && !name.is_empty() && ban.name.eq_ignore_ascii_case(name);

            if ip_matches || uid_matches || name_matches {
                let _ = self.conn.execute(
                    "UPDATE bans SET enforcements = enforcements + 1 WHERE ban_id = ?1",
                    params![ban.ban_id as i64],
                );
                return Ok(Some(ban.reason));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_init_and_channels() {
        let db = Database::in_memory().expect("failed to open in-memory db");
        let channels = db.get_channels().expect("failed to fetch channels");
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "Default Channel");
        assert!(channels[0].is_default);

        let new_cid = db
            .create_channel("Gaming Lounge", "Talk about games")
            .expect("failed to create channel");
        let channels_after = db.get_channels().expect("failed to fetch channels");
        assert_eq!(channels_after.len(), 2);
        assert_eq!(channels_after[1].cid, new_cid);
        assert_eq!(channels_after[1].name, "Gaming Lounge");
    }

    #[test]
    fn test_permissions_seeding_and_crud() {
        let db = Database::in_memory().expect("failed to open in-memory db");

        // Server groups check
        let sg = db.get_server_groups().expect("failed to get server groups");
        assert_eq!(sg.len(), 3);
        assert!(sg.iter().any(|g| g.group_id == 6 && g.name == "Server Admin"));
        assert!(sg.iter().any(|g| g.group_id == 7 && g.name == "Normal"));
        assert!(sg.iter().any(|g| g.group_id == 8 && g.name == "Guest"));

        // Channel groups check
        let cg = db.get_channel_groups().expect("failed to get channel groups");
        assert_eq!(cg.len(), 4);
        assert!(cg.iter().any(|g| g.group_id == 5 && g.name == "Channel Admin"));
        assert!(cg.iter().any(|g| g.group_id == 6 && g.name == "Operator"));
        assert!(cg.iter().any(|g| g.group_id == 7 && g.name == "Voice"));
        assert!(cg.iter().any(|g| g.group_id == 8 && g.name == "Guest"));

        // Verify seeded perms count
        let sa_perms = db.get_server_group_perms(6).expect("sa perms");
        assert_eq!(sa_perms.len(), 413);
        let guest_perms = db.get_server_group_perms(8).expect("guest perms");
        assert_eq!(guest_perms.len(), 31);
        let ca_perms = db.get_channel_group_perms(5).expect("ca perms");
        assert_eq!(ca_perms.len(), 33);

        // Client group assignment
        assert_eq!(db.get_client_server_groups("user_1").unwrap(), vec![8]);
        db.add_client_to_server_group("user_1", 6).unwrap();
        assert_eq!(db.get_client_server_groups("user_1").unwrap(), vec![6]);

        // Channel group assignment
        assert_eq!(db.get_client_channel_group("user_1", 1).unwrap(), 8);
        db.set_client_channel_group("user_1", 1, 5).unwrap();
        assert_eq!(db.get_client_channel_group("user_1", 1).unwrap(), 5);

        // Channel perms CRUD
        assert_eq!(db.get_channel_perms(1).unwrap().len(), 0);
        db.set_channel_perm(1, "i_channel_needed_join_power", 25, false, false).unwrap();
        let cp = db.get_channel_perms(1).unwrap();
        assert_eq!(cp.len(), 1);
        assert_eq!(cp[0].perm_id, "i_channel_needed_join_power");
        assert_eq!(cp[0].perm_value, 25);
        assert!(db.del_channel_perm(1, "i_channel_needed_join_power").unwrap());
        assert_eq!(db.get_channel_perms(1).unwrap().len(), 0);
    }

    #[test]
    fn test_privilege_key_lifecycle() {
        let db = Database::in_memory().expect("failed to open in-memory db");
        let token = db
            .get_or_create_initial_admin_token()
            .expect("failed to get token");
        assert!(token.is_some());
        let token_str = token.unwrap();

        // Second call returns None because token already exists
        let second_call = db
            .get_or_create_initial_admin_token()
            .expect("failed second call");
        assert!(second_call.is_none());

        // Redeem valid token
        assert!(db.redeem_privilege_key(&token_str).unwrap());
        // Cannot redeem twice
        assert!(!db.redeem_privilege_key(&token_str).unwrap());
        // Cannot redeem fake token
        assert!(!db.redeem_privilege_key("nonexistent").unwrap());
    }

    #[test]
    fn test_admin_identity_persistence() {
        let db = Database::in_memory().expect("failed to open in-memory db");
        assert!(!db.is_admin_identity("test_uid_1").unwrap());
        db.add_admin_identity("test_uid_1").unwrap();
        assert!(db.is_admin_identity("test_uid_1").unwrap());
        // Duplicate add should not fail
        db.add_admin_identity("test_uid_1").unwrap();
        assert!(db.is_admin_identity("test_uid_1").unwrap());
    }

    #[test]
    fn test_ban_lifecycle_and_matching() {
        let db = Database::in_memory().expect("failed to open in-memory db");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Permanent ban by UID
        let ban_uid = BanRecord {
            ip: String::new(),
            name: String::new(),
            uid: "banned_uid_1".to_string(),
            mytsid: String::new(),
            lastnickname: "Troll".to_string(),
            created: now,
            duration: 0,
            invokercldbid: 1,
            invokername: "Admin".to_string(),
            invokeruid: "admin_uid".to_string(),
            reason: "Trolling in lobby".to_string(),
            enforcements: 0,
            ..Default::default()
        };
        let ban_id1 = db.add_ban(&ban_uid).expect("failed to add ban");
        assert!(ban_id1 > 0);

        // Ban by IP with 3600s duration
        let ban_ip = BanRecord {
            ip: "192.168.1.100".to_string(),
            name: String::new(),
            uid: String::new(),
            mytsid: String::new(),
            lastnickname: "Flooder".to_string(),
            created: now,
            duration: 3600,
            invokercldbid: 1,
            invokername: "Admin".to_string(),
            invokeruid: "admin_uid".to_string(),
            reason: "Flooding".to_string(),
            enforcements: 0,
            ..Default::default()
        };
        let ban_id2 = db.add_ban(&ban_ip).expect("failed to add ban");
        assert!(ban_id2 > 0);

        // Expired ban
        let ban_expired = BanRecord {
            ip: "10.0.0.5".to_string(),
            name: String::new(),
            uid: "expired_uid".to_string(),
            mytsid: String::new(),
            lastnickname: "OldBanned".to_string(),
            created: now - 100,
            duration: 50, // expired 50 seconds ago
            invokercldbid: 1,
            invokername: "Admin".to_string(),
            invokeruid: "admin_uid".to_string(),
            reason: "Temporary".to_string(),
            enforcements: 0,
            ..Default::default()
        };
        let _ = db.add_ban(&ban_expired).expect("failed to add ban");

        // Verify is_banned matching
        assert_eq!(
            db.is_banned("1.2.3.4", "banned_uid_1", "User").unwrap(),
            Some("Trolling in lobby".to_string())
        );
        assert_eq!(
            db.is_banned("192.168.1.100", "innocent_uid", "User").unwrap(),
            Some("Flooding".to_string())
        );
        // Expired ban should not match
        assert_eq!(
            db.is_banned("10.0.0.5", "expired_uid", "OldBanned").unwrap(),
            None
        );
        // Clean user should not match
        assert_eq!(
            db.is_banned("1.2.3.4", "clean_uid", "GoodUser").unwrap(),
            None
        );

        // Verify enforcement counter incremented
        let bans = db.get_bans().expect("failed to get bans");
        assert_eq!(bans.len(), 3);
        let b1 = bans.iter().find(|b| b.ban_id == ban_id1).unwrap();
        assert_eq!(b1.enforcements, 1);

        // Delete ban 1
        assert!(db.delete_ban(ban_id1).unwrap());
        assert!(!db.delete_ban(ban_id1).unwrap());
        assert_eq!(
            db.is_banned("1.2.3.4", "banned_uid_1", "User").unwrap(),
            None
        );

        // Delete all bans
        db.delete_all_bans().expect("failed to delete all");
        assert_eq!(db.get_bans().unwrap().len(), 0);
    }
}
