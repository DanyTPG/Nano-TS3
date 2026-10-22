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
                icon_id INTEGER NOT NULL DEFAULT 0
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
        Ok(())
    }

    /// Fetches all channels from the database.
    pub fn get_channels(&self) -> Result<Vec<ChannelRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT cid, name, topic, order_id, is_default, description, \
                 is_permanent, is_semi_permanent, codec, codec_quality, max_clients, \
                 max_family_clients, needed_talk_power, needed_subscribe_power, \
                 codec_latency_factor, delete_delay, max_clients_unlimited, \
                 max_family_clients_unlimited, max_family_clients_inherited, \
                 name_phonetic, icon_id FROM channels",
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
             name_phonetic=?19, icon_id=?20 WHERE cid=?21",
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
}
