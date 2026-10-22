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
    pub is_admin: bool,
    pub uid: String,
    pub disconnect_time: Option<std::time::Instant>,

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
    pub last_c2s_packet_id: u16,
    pub expected_c2s_packet_id: u16,

    // Inbound command reordering and defragmentation
    pub pending_packets: BTreeMap<u16, (Flags, Vec<u8>)>,
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
            last_c2s_packet_id: 0,
            expected_c2s_packet_id: 1, // First command is clientek (pid 1)
            pending_packets: BTreeMap::new(),
            last_activity: std::time::Instant::now(),
        }
    }
}

pub struct ServerState {
    pub clients: HashMap<SocketAddr, ClientSession>,
    next_clid: u16,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
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

    pub fn cleanup_stale(&mut self) {
        let now = std::time::Instant::now();
        self.clients.retain(|_, c| {
            if let Some(disc_time) = c.disconnect_time {
                now.duration_since(disc_time).as_secs() < 5
            } else {
                now.duration_since(c.last_activity).as_secs() < 120
            }
        });
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
