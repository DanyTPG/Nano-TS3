use crate::crypto::{RsaPuzzle, SERVER_KEY_K};
use p256::SecretKey;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use tsproto_packets::packets::Flags;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakePhase {
    Init0Received,
    Init2Received,
    Init4Received,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAudioState {
    pub input_muted: bool,
    pub output_muted: bool,
    pub output_only_muted: bool,
    pub input_hardware: bool,
    pub output_hardware: bool,
}

impl Default for ClientAudioState {
    fn default() -> Self {
        Self {
            input_muted: false,
            output_muted: false,
            output_only_muted: false,
            input_hardware: true,
            output_hardware: true,
        }
    }
}

pub struct ClientSession {
    pub clid: u16,
    pub endpoint: SocketAddr,
    pub nickname: String,
    pub current_channel_id: u64,
    pub audio: ClientAudioState,
    pub subscribed_channels: BTreeSet<u64>,
    pub known_clients: BTreeSet<u16>,
    pub is_admin: bool,
    pub uid: String,
    pub disconnect_time: Option<std::time::Instant>,
    pub connected_time: std::time::Instant,

    // Handshake & Cryptography state
    pub handshake_phase: HandshakePhase,
    pub server_secret: SecretKey,
    pub r0_reversed: [u8; 4],
    pub r1: [u8; 16],
    pub puzzle: Option<RsaPuzzle>,
    pub alpha: Vec<u8>,
    pub beta: Vec<u8>,
    pub shared_iv: Option<[u8; 64]>,

    // Packet sequencing
    pub next_s2c_packet_id: u16,
    pub next_s2c_low_packet_id: u16,
    pub next_s2c_voice_packet_id: u16,
    pub next_s2c_ping_packet_id: u16,
    pub last_c2s_packet_id: u16,
    pub expected_c2s_packet_id: u16,

    // Voice encryption bookkeeping. The EAX key/nonce for a voice packet
    // changes whenever the 16-bit packet id wraps around (generation++), so
    // both directions have to track the current generation. c2s follows the
    // sender's wrap; s2c is fully under our control.
    pub c2s_voice_generation: u32,
    pub last_c2s_voice_pid: Option<u16>,
    pub s2c_voice_generation: u32,

    // Connection statistics the client published with `setconnectioninfo`,
    // keyed by the raw `connection_*` parameter name. Served to other clients
    // through `getconnectioninfo` / `notifyconnectioninfo`.
    pub connection_stats: std::collections::BTreeMap<String, String>,

    // Inbound command reordering and defragmentation
    pub pending_packets: BTreeMap<u16, (Flags, Vec<u8>)>,

    // The CommandLow stream (p_type 3) has its own packet-id sequence,
    // independent of the Command stream. The official client sends e.g.
    // clientpoke on it, starting at pid 0 (captured from a real 3.6.2
    // client). Sharing one tracker drops every low packet as a stale
    // "retransmission".
    pub expected_c2s_low_packet_id: u16,
    pub pending_low_packets: BTreeMap<u16, (Flags, Vec<u8>)>,
    pub last_activity: std::time::Instant,
}

impl ClientSession {
    pub fn new(clid: u16, endpoint: SocketAddr) -> Self {
        let server_secret = SecretKey::from_slice(&SERVER_KEY_K).expect("valid server secret");

        Self {
            clid,
            endpoint,
            nickname: format!("Client_{}", clid),
            uid: format!("nano_uid_{}", clid),
            disconnect_time: None,
            current_channel_id: 1, // Default channel
            audio: ClientAudioState::default(),
            subscribed_channels: BTreeSet::from([1]),
            known_clients: BTreeSet::new(),
            is_admin: false,
            handshake_phase: HandshakePhase::Init0Received,
            server_secret,
            r0_reversed: [0u8; 4],
            r1: [0u8; 16],
            puzzle: None,
            alpha: Vec::new(),
            beta: Vec::new(),
            shared_iv: None,
            next_s2c_packet_id: 0,
            next_s2c_low_packet_id: 0,
            next_s2c_voice_packet_id: 0,
            next_s2c_ping_packet_id: 0,
            last_c2s_packet_id: 0,
            expected_c2s_packet_id: 1, // First command is clientek (pid 1)
            expected_c2s_low_packet_id: 0, // First CommandLow command is pid 0
            pending_low_packets: BTreeMap::new(),
            pending_packets: BTreeMap::new(),
            c2s_voice_generation: 0,
            last_c2s_voice_pid: None,
            s2c_voice_generation: 0,
            connection_stats: std::collections::BTreeMap::new(),
            connected_time: std::time::Instant::now(),
            last_activity: std::time::Instant::now(),
        }
    }
}

pub struct ServerState {
    pub clients: HashMap<SocketAddr, ClientSession>,
    /// Which endpoints are watching another client's connection info
    /// (target clid -> watchers). Populated by `getconnectioninfo` and
    /// pruned whenever sessions disappear.
    pub connection_watchers: HashMap<u16, BTreeSet<SocketAddr>>,
    next_clid: u16,
}

/// A connected client that has not sent a single packet (command, ping, pong,
/// voice — anything) for this long is considered dead and is dropped. The
/// official client keeps the connection alive with a ping every ~2 seconds,
/// so 30 s means ~15 consecutive keepalives were missed.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl ServerState {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
            connection_watchers: HashMap::new(),
            next_clid: 2,
        }
    }

    pub fn reset_or_create_client(&mut self, endpoint: SocketAddr) -> &mut ClientSession {
        let clid = if let Some(old) = self.clients.get(&endpoint) {
            old.clid
        } else {
            let id = self.next_clid;
            Self::advance_clid(&mut self.next_clid);
            id
        };
        self.clients
            .insert(endpoint, ClientSession::new(clid, endpoint));
        self.clients.get_mut(&endpoint).unwrap()
    }

    pub fn get_or_create_client(&mut self, endpoint: SocketAddr) -> &mut ClientSession {
        let clid = self.next_clid;
        self.clients.entry(endpoint).or_insert_with(|| {
            Self::advance_clid(&mut self.next_clid);
            ClientSession::new(clid, endpoint)
        })
    }

    pub fn get_client(&self, endpoint: &SocketAddr) -> Option<&ClientSession> {
        self.clients.get(endpoint)
    }

    pub fn get_client_mut(&mut self, endpoint: &SocketAddr) -> Option<&mut ClientSession> {
        self.clients.get_mut(endpoint)
    }

    pub fn remove_client(&mut self, endpoint: &SocketAddr) -> Option<ClientSession> {
        self.clients.remove(endpoint)
    }

    /// Drops stale sessions (timed-out idle clients and disconnected ones
    /// kept briefly for endpoint replacement). Returns the (clid, channel) of
    /// sessions that were fully connected when they vanished: those were never
    /// announced as leaving, so the caller must broadcast a left view for them
    /// or clients still holding that clid in view will treat later
    /// notifications about it as a protocol error ("invalid clientID").
    pub fn cleanup_stale(&mut self) -> Vec<(u16, u64)> {
        let now = std::time::Instant::now();
        let mut disappeared = Vec::new();
        self.clients.retain(|_, c| {
            let keep = if let Some(disc_time) = c.disconnect_time {
                now.duration_since(disc_time).as_secs() < 5
            } else {
                now.duration_since(c.last_activity) < IDLE_TIMEOUT
            };
            if !keep && c.handshake_phase == HandshakePhase::Connected {
                disappeared.push((c.clid, c.current_channel_id));
            }
            keep
        });
        if !disappeared.is_empty() {
            // Watchers of vanished clients can never receive further updates.
            let gone: BTreeSet<u16> = disappeared.iter().map(|(clid, _)| *clid).collect();
            self.connection_watchers.retain(|clid, watchers| {
                if gone.contains(clid) {
                    return false;
                }
                watchers.retain(|ep| self.clients.contains_key(ep));
                !watchers.is_empty()
            });
        }
        disappeared
    }

    pub fn clients_in_channel(&self, cid: u64) -> Vec<&ClientSession> {
        self.clients
            .values()
            .filter(|c| {
                c.current_channel_id == cid
                    && c.handshake_phase == HandshakePhase::Connected
                    && c.last_activity.elapsed() < std::time::Duration::from_secs(45)
            })
            .collect()
    }

    fn advance_clid(next: &mut u16) {
        *next = next.wrapping_add(1);
        if *next == 0 {
            *next = 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cleanup_stale_times_out_idle_connected_clients() {
        let mut state = ServerState::new();
        let ep: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let mut client = ClientSession::new(2, ep);
        client.handshake_phase = HandshakePhase::Connected;
        client.last_activity = std::time::Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1);
        state.clients.insert(ep, client);

        // A watcher entry for the vanished client must be pruned too.
        let watcher: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        state
            .connection_watchers
            .entry(2)
            .or_default()
            .insert(watcher);

        let gone = state.cleanup_stale();
        assert_eq!(gone, vec![(2, 1)]);
        assert!(state.clients.is_empty());
        assert!(state.connection_watchers.is_empty());
    }

    #[test]
    fn cleanup_stale_keeps_active_clients() {
        let mut state = ServerState::new();
        let ep: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let mut client = ClientSession::new(2, ep);
        client.handshake_phase = HandshakePhase::Connected;
        client.last_activity = std::time::Instant::now() - Duration::from_secs(2);
        state.clients.insert(ep, client);

        assert!(state.cleanup_stale().is_empty());
        assert_eq!(state.clients.len(), 1);
    }

    #[test]
    fn cleanup_stale_times_out_stuck_handshakes() {
        let mut state = ServerState::new();
        let ep: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let mut client = ClientSession::new(2, ep);
        // Still in the handshake phase: dropped without a left-view broadcast.
        client.last_activity = std::time::Instant::now() - IDLE_TIMEOUT - Duration::from_secs(5);
        state.clients.insert(ep, client);

        let gone = state.cleanup_stale();
        assert!(gone.is_empty());
        assert!(state.clients.is_empty());
    }
}
