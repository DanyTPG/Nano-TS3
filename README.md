# Nano-TS3: Minimal TeamSpeak 3 Compatible Server

**Nano-TS3** is a lightweight, clean-room, minimal TeamSpeak 3 compatible server
written in asynchronous **Rust** (Tokio). It implements the core TeamSpeak 3 UDP
transport protocol, full cryptographic handshakes (Init0–Init4), AES-128 EAX
stream encryption, channel hierarchy management, Opus voice packet forwarding,
text messaging, and single-use Server Admin privilege token generation and
redemption.

---

## Status (verified with the official client 3.6.2)

| Capability | Status |
| --- | --- |
| Handshake Init0 → Init1 → Init2 → Init3 → Init4 → initivexpand2 → clientek → SharedIV | Working with the official client |
| Encrypted command transport, fragmentation, out-of-order reassembly | Working |
| `initserver`, channel list, own/other `notifycliententerview` | Working |
| Multiple official clients in one channel, nickname de-duplication | Working (three simultaneous clients were visible to each other) |
| Server group / channel group names and admin icon | Working (`Server Admin`, `Channel Admin`) |
| Privilege key redemption from the official client popup | Working; the identity is persisted and recognized as Server Admin on reconnect |
| Text chat (`sendtextmessage` / `notifytextmessage`) | Working |
| In-channel voice relay (Opus, unencrypted) | Payloads relay without codec encryption; live audio verification is pending |
| `channelcreate` protocol handler (new `cid`, broadcast, duplicate rejection) | Working (covered by integration tests) |
| `channeledit` / `channeldelete` (incl. the client's Delete Channel dialog) | Working with TS3 3.6.2; deletion broadcasts `notifychanneldeleted` and persists |
| Channel creation from the official client's context menu | Working; sort-order fix implemented |
| Kick from channel / from server (client context menu) | Working; `notifyclientmoved reasonid=4` / `notifyclientleftview reasonid=5` with invoker fields |
| Ban client (`banclient`, bans persisted and enforced at connect) | Working; target disconnected with `reasonid=6` |
| Poke client (`clientpoke` → `notifyclientpoke` popup) | Working (requires separate CommandLow packet-id tracking) |
| Graceful server shutdown (Ctrl+C / console close) | Working; per-client `notifyclientleftview reasonid=11` per the official server; clients disconnect instantly with auto-reconnect |
| Multi-user view consistency (subscribe toggle, join occupied channel, ghost sessions) | Working; enter-views re-sent on (re)subscribe; subscription-filtered fan-outs |
| Graceful disconnect (`notifyclientleftview` to the leaving client itself) | Working (covered by tests) |

### Known limitation

Channel order is stored as a predecessor link. Create and edit operations now
apply the requested predecessor and repair the following links; delete repairs
the remaining chain. Channel edits persist the name, topic, description, codec,
quality, ordering, and supported limits and flags. Forced deletion moves clients
to the default channel. The current channel model is flat, so subchannels and
channel passwords are not supported. Details are in
[docs/PROTOCOL_NOTES.md](docs/PROTOCOL_NOTES.md#channel-edits-and-deletes).

Voice whisper routing is not implemented. In-channel voice is relayed as raw
Opus frames, so nano-ts3 advertises codec encryption as forced off; encrypted
voice channels are unsupported. The relay has a separate S2C voice packet
sequence. Live audio verification is pending.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   Official TS3 Client(s)    |
                      +--------------+--------------+
                                     |
                          UDP Port 9988 (Packets)
                                     |
                                     v
+-------------------------------------------------------------------------+
|                                Nano-TS3                                 |
|                                                                         |
|  +--------------------+   +---------------------+   +----------------+  |
|  |  UDP Packet Demux  |-->| Crypto & Handshake  |-->| Command Parser |  |
|  | (tsproto-packets)  |   | (EAX / P256 / RSA)  |   |   & Escaping   |  |
|  +--------------------+   +---------------------+   +----------------+  |
|            |                                                |           |
|            v                                                v           |
|  +--------------------+                           +------------------+  |
|  |    Voice Relay     |                           | Server Dispatch  |  |
|  | (In-Channel Relay) |                           | & Session State  |  |
|  +--------------------+                           +------------------+  |
|                                                             |           |
|                                                             v           |
|                                                   +------------------+  |
|                                                   |  SQLite Database |  |
|                                                   |  (nano_ts3.db)   |  |
|                                                   +------------------+  |
+-------------------------------------------------------------------------+
```

### Module Structure

- [`src/main.rs`](src/main.rs): CLI entrypoint, server initialization, privilege key banner display.
- [`src/server.rs`](src/server.rs): UDP listener, packet routing (Init, Command, Voice, Ping/Ack), TS3 command handling, defragmentation and the client-visible message ordering.
- [`src/state.rs`](src/state.rs): Ephemeral in-memory session manager, tracking client IDs (`clid`), channels, encryption keys and stale-session cleanup.
- [`src/crypto.rs`](src/crypto.rs): AES-128 EAX encryption/decryption, LibTomCrypt ASN.1 DER P-256 public key encoding/decoding, ECDH SharedIV computation, and RSA puzzle generation/verification.
- [`src/command.rs`](src/command.rs): TS3 wire command serialization and deserialization with TeamSpeak-style escaping (`\s`, `\/`, `\p`, etc.).
- [`src/database.rs`](src/database.rs): SQLite schema, channel CRUD (with case-insensitive unique names), privilege token management and persistent admin identities.
- [`src/permissions.rs`](src/permissions.rs): 248-entry permission catalog, official Server Admin group permission list, Guest and channel group permission wires.
- [`docs/PROTOCOL_NOTES.md`](docs/PROTOCOL_NOTES.md): reverse-engineering findings and the exact message ordering the official client requires.
- [`tests/integration_test.rs`](tests/integration_test.rs), [`tests/multi_client_test.rs`](tests/multi_client_test.rs): end-to-end protocol tests.
- [`examples/`](examples): diagnostic clients and a decrypting UDP proxy.

---

## Building and Running

### Prerequisites

- Rust toolchain (Rust 2024 Edition / 1.85+)
- Windows, Linux, or macOS

### Running the Server

```bash
cargo build --release
./target/release/nano-ts3 9988
```

The server binds `0.0.0.0:9988` by default; pass another port as the first
argument to override it. On first startup it generates an initial Server Admin
privilege token:

```
=======================================================
             Nano-TS3 Minimal Server v0.1.0
=======================================================

*******************************************************
       SERVER ADMIN PRIVILEGE KEY GENERATED
*******************************************************
Token: nano_ts3_admin_...

Redeem in TeamSpeak 3 Client: Permissions -> Use Privilege Key
*******************************************************

Ready for TeamSpeak 3 clients on udp://127.0.0.1:9988
```

### Connecting with TeamSpeak 3 Client

1. Open the **TeamSpeak 3 Client**.
2. Click **Connections** → **Connect** (`Ctrl+S`).
3. Enter `127.0.0.1:9988` into **Server Nickname or Address**.
4. Choose any nickname and click **Connect**.
5. Redeem the token in the automatically shown **Use Privilege Key** popup (or
   via **Permissions** → **Use Privilege Key**). The identity's UID is persisted,
   so later reconnects are recognized as Server Admin without asking again.

---

## Running Automated Tests

```bash
cargo test --lib
cargo test --test integration_test
cargo test --test multi_client_test
```

Coverage includes:

- Command serialization and character escaping round-trips.
- AES-128 EAX encryption/decryption and tag verification.
- ASN.1 DER P-256 public key encoding/decoding.
- RSA puzzle generation and solution verification.
- SQLite schema, channel CRUD, privilege-key lifecycle, admin identity persistence.
- Fragment reassembly (first/last `FRAGMENTED` semantics, out-of-order input).
- UID derivation from the client's omega value, privilege-key redemption and
  admin recognition across reconnects.
- Channel creation returning `cid`, duplicate-name rejection, graceful
  disconnect notifications, multi-client visibility and chat.
