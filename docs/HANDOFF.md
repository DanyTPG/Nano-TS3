# nano-ts3 Hand-Off

Date: 2026-10-24
Repository: `C:\Projects\Nano-TS3`
Target: official TeamSpeak 3 Client 3.6.2 (`C:\Program Files\TeamSpeak 3 Client\ts3client_win64.exe`)
Server: `nano-ts3`, UDP 9988, pure Rust.

---

## 1. Mission status

The official client 3.6.2 now exercises the full admin workflow against
nano-ts3: connect, chat, redeem/hold admin, create/edit/**delete** channels
(GUI, with confirmation dialog), **kick from channel and from server**,
**ban**, **poke**, and it disconnects **gracefully on server shutdown**
(auto-reconnect armed). Multi-user view consistency is fixed.

| Goal | State | Evidence |
| --- | --- | --- |
| Handshake Init0-4, encrypted commands, fragmentation, reassembly | works | tests + real client |
| Multiple clients, groups, privilege keys, chat | works | tests + live sessions |
| Channel create / edit / **delete (GUI confirm dialog)** | works | `channeldelete` received, `notifychanneldeleted` broadcast, DB row removed, live tree update |
| **Kick from channel / from server (GUI)** | works | `notifyclientmoved reasonid=4` / `notifyclientleftview reasonid=5` with invoker fields |
| **Ban (GUI + wire)** | works | `notifyclientleftview reasonid=6 bantime=...`, bans row stored, enforced at `clientinit` |
| **Poke (GUI and wire)** | works | CommandLow fix; "X poked you" popup delivered to the official client |
| **Graceful server shutdown** | works | Ctrl+C/Break/console-close → per-client left-view `reasonid=11 reasonmsg=Server Shutdown!` (official format); client disconnects in ~10 ms, autoreconnect armed |
| **View consistency** (subscribe toggle, join occupied channel, ghost sessions) | works | enter-views resent on (re)subscribe; subscription-filtered fan-outs; vanished sessions announced `reasonid=3` |
| `permissionlist` catalog | works | full 496-entry official capture (src/permission_catalog.rs) |
| Voice relay | implemented | relay path only, live mic test pending |

All automated tests pass: `cargo test --release` → 21 ok. Protocol findings
live in [PROTOCOL_NOTES.md](PROTOCOL_NOTES.md) — read it before touching the
wire format; nearly every constant there was captured from real official
traffic.

---

## 2. Environment (as of hand-off)

* `nano-ts3` on UDP 9988. Start: `python scratch/run_nano.py 9988 start`;
  graceful stop: `python scratch/send_ctrl_c.py` (sends CTRL_BREAK to the
  server console so clients disconnect cleanly). Plain `taskkill` also works
  but clients hang until timeout.
* Official 3.13.7 server copies: `scratch/ts3official` (use query port 10022;
  10011 is blocked by a Windows reserved-port range) and the user's own at
  `C:\Softwares	eamspeak3-server_win64` (default ports). ServerQuery login:
  `serveradmin` / `5J6TGS8q`.
* **TS3 client automation**: the Program Files client manifest has
  `uiAccess="true"` — Windows silently launches it elevated and UI
  automation (UIA/cua-driver) is blocked. Always launch the copy at
  `scratch/ts3medium/ts3client_win64.exe` (medium integrity, fully drivable;
  a Program Files instance must be closed manually first — single-instance
  forwarding). Qt context menus respond reliably to keyboard navigation
  (right-click + N×Down + Enter); synthetic mouse clicks into menus are
  flaky; UIA can enumerate the main window but not menu popups.
* Wire-level test client: `cargo run --release --example admin_console --
  9988 Nick [admin_uid]` — interactive command console over the TS3
  protocol; self-registers its derived UID into `admin_identities` when no
  uid argument is passed (pass `iMD9uDe3y38CY2TNKHZ8LHCQuH4=` to act as the
  user's admin identity).
* Debugging arsenal in `scratch/` (gitignored):
  * `run_nano.py` / `run_official.py` / `send_ctrl_c.py` — process control.
  * `poke_watch3.py` — armed live watcher: triggers on a server-log event and
    repeatedly scans the client process for a string; `mem_scan.py` — one-shot
    process string scan (UTF-16 + ASCII). These distinguish "dialog never
    fired" vs "command built but held in queue" vs "sent".
  * `poke_xref.py` / `poke_disasm.py` — capstone RE helpers for
    ts3client_win64.exe (image base 0x140000000).
  * MITM pipeline: `examples/raw_proxy` (capture), `examples/scan_iv`
    (recover session IV from client memory via ping MAC), `examples/decrypt_log`
    (per-session transcript), `examples/brute_decrypt` (per-packet IV brute
    force — required when several sessions interleave in one capture).
* Client identity UID `iMD9uDe3y38CY2TNKHZ8LHCQuH4=`; DB
  `nano_ts3.db` (channels, `admin_identities`, `privilege_keys`, `bans`).
* Client logs: `%APPDATA%\TS3Client\logs	s3client_*.log`.

---

## 3. Key reverse-engineering findings (already implemented)

All are documented in [`docs/PROTOCOL_NOTES.md`](PROTOCOL_NOTES.md); the most
important ones:

1. **Fragment flags**: a multi-fragment command flags only the **first and last**
   packet with `FRAGMENTED (0x10)`; middle packets are unflagged. Old nano-ts3
   flagged every chunk, truncating `initserver` and producing
   `Error while parsing packet: parameter not found` (client disconnect).
   Implemented in `try_assemble_next` ([`src/server.rs:95`](../src/server.rs#L95))
   and the outbound loop in `send_encrypted_raw`.
2. **Own enter view before `channellistfinished`**: the client's
   `channellistfinished` handler (`0x14061e350`, registered at `0x1406084e1`)
   looks up its own client and asserts `"client"` (serverconnectionhandler.cpp:4115).
3. **UID derivation**: UID = `base64(sha1(<omega base64 text exactly as sent>))`,
   not the DER bytes. Verified with the real client and the official DB.
   (`handle_init` in `src/server.rs`.)
4. **Never echo `client_nickname` in `notifyclientupdated`** — the client treats
   it as a rename and disconnects with "nickname is already in use".
5. **`servergetvariables`** must answer with a full `notifyserverupdated` and
   must **not** set `virtualserver_ask_for_privilegekey=0` while an unused key
   exists; otherwise "Use Privilege Key" is greyed out.
6. **Group lists are one multi-part command** (`a=…|b=…`). Sending one command
   per group makes the client replace its cache and keep only the last group,
   producing `%CLIENT_SERVER_GROUP_NAME%` placeholders and hiding admin perms.
7. **Permission ids** (verified via ServerQuery against 3.13.7):
   `b_virtualserver_token_use=40`, `b_channel_create_child=88`,
   `b_channel_create_permanent=89`, `b_channel_create_semi_permanent=90`,
   `b_channel_create_temporary=91`. Guest must have 40. The official Server
   Admin `sgid=6` list has 412 entries incl. 33000-series needed-power perms and
   is embedded in `src/permissions.rs`.
8. **Message order accepted by the client**:
   `initserver` → `channellist` (entries) → own `notifycliententerview`
   (`reasonid=2`) → `channellistfinished` → server group list → client group
   membership → channel group list → other clients' enter views → store to
   others → server group permissions → channel group permissions → `error ok`.
   `reasonid=0` for the own enter view crashes the client
   (`serverview.cpp:6714`, `clientID != m_clientID`).
9. **Setup**: official 3.13.7's `virtualserver_keypair` in the DB is exactly
   nano-ts3's `SERVER_KEY_K`; the anonymous license chain derivation was
   reproduced exactly (see §6) — `license_check` proves it.

---

## 4. What changed in the code

### Session 2026-10-23/24 (channel mgmt GUI, kick/ban/poke, shutdown, view consistency, CommandLow)

* `src/server.rs`
  * `clientpoke` handler; `ftgetfilelist` answers official-style
    `error id=1281 database empty result set` (unblocks the Delete Channel
    dialog); `permissionlist` answers with the full official catalog
    (`src/permission_catalog.rs`).
  * Kick/ban notifications always carry `reasonmsg` (possibly empty) — its
    absence aborted every receiving client ("parameter not found") and was
    the cause of "kick kicks BOTH clients".
  * Graceful shutdown: `Server::shutdown()` sends each client its own
    `notifyclientleftview reasonid=11 reasonmsg=Server Shutdown!` (captured
    official format; reasonid 7 is rejected by the client).
    `src/main.rs` listens on ctrl_c/ctrl_break/ctrl_close (unix: SIGTERM/SIGINT).
  * View consistency: subscribe-all resends enter-views (reasonid 2) for newly
    subscribed channels only; `clientmove` delivers occupant enter-views to
    the mover; all enter/moved/left-view fan-outs are subscription-filtered
    (`watching_recipients`, `move_recipients`); vanished sessions (idle sweep,
    endpoint replacement) broadcast `reasonid=3 connection lost`
    (`cleanup_stale` now returns the disappeared).
  * Same-channel `clientmove` is a silent no-op (redundant moved-broadcast
    disconnects the official client).
  * `pv=7` in initserver (official value).
  * **CommandLow stream separation** — Command (p_type 2) and CommandLow
    (p_type 3) have independent packet-id sequences; the client sends
    `clientpoke` on CommandLow starting at pid 0. The old single shared
    expected-pid tracker dropped every poke as a "retransmission" while the
    client held it forever. `ClientSession` now has
    `expected_c2s_low_packet_id` + `pending_low_packets`.
* `src/state.rs`: low-stream fields; `cleanup_stale` returns disappeared
  connected sessions.
* New examples: `admin_console` (interactive wire client), `brute_decrypt`,
  `ftlist_probe`; `src/permission_catalog.rs` (generated via
  `scratch/gen_catalog.py` from the official capture).
* Tests: 21 pass (`cargo test --release`).


* `src/server.rs`
  * `try_assemble_next` + corrected outbound fragment flags.
  * `build_client_enter_view` / `build_server_updated` helpers (all mandatory
    fields for the client's parser).
  * `clientinit`: ordering above, real UID, group names/membership, channel
    groups, guest/admin perms, optional `client_*` mirror fields in `initserver`.
  * `tokenuse`/`privilegekeyuse`: accepts `token` or `key`, persists the UID via
    `db.add_admin_identity`, broadcasts `notifyclientupdated` (no nickname),
    pushes admin perms + full `notifyserverupdated` (ask=0).
* `channelcreate`: case-insensitive duplicate check, stores the requested
    `channel_order` predecessor (or appends), updates the following sibling,
    broadcasts `notifychannelcreated` with that predecessor, and returns
    `cid`/`1024` in `error`.
  * `clientdisconnect`/`quit`: marks `HandshakePhase::Disconnected`, keeps the
    session 5 s (`cleanup_stale`), sends `error ok` + `notifyclientleftview` to
    the leaving client and to everybody else.
  * `servergetvariables`, `clientgetvariables`, `channellist`,
    `servergrouplist`, `channelgrouplist`, `channelgrouppermlist`,
    `servergroupsbyclientid`, `permissionlist` handlers.
  * `send_channel_list`, `send_client_group_membership`,
    `send_channel_group_list`, `send_channel_group_perm_list`,
    `send_server_group_list`.
* `src/database.rs`: `admin_identities` table + helpers; channel name de-dup
  migration + `UNIQUE INDEX ... COLLATE NOCASE`; channel-order chain migration.
* `src/permissions.rs`: official Guest list, official 412-entry Server Admin
  list, catalog unchanged (248 entries, matches official 3.13.7).
* `src/state.rs`: `HandshakePhase::Disconnected`, `uid`, `disconnect_time`,
  `cleanup_stale`.
* Tests: fragment semantics, UID derivation + admin persistence over reconnect,
  channelcreate `cid` + duplicate rejection, graceful disconnect self-notify.
* Docs: `README.md` rewritten with status/limitations; `docs/PROTOCOL_NOTES.md`.

---

## 5. Channel creation order

The official 3.6.2 client now enables **Create Channel / Create Sub-Channel**
for Server Admin on nano-ts3 (confirmed by the user after adding the captured
`notifyclientneededpermissions` login notification). Creating a channel with
**Sort This Channel After** then disconnected with `invalid channel order` and
the channel appeared first after reconnect.

The server had been announcing `channel_order` as the new channel's own `cid`
and storing all new channels with order zero. TS3 uses `channel_order` as the
preceding sibling's ID. The handler now takes the client's requested
predecessor, falls back to appending after the last channel when absent or
stale, and announces the same value. Mid-list insertion rewrites the next
sibling link; startup also rebuilds a valid chain from legacy order-zero rows.
A live-client retest of this fix is pending.

Earlier menu investigations that did **not** resolve the disabled action:

* exact official 412-entry `sgid=6` permission list;
* assigning admin to channel group 5 (Channel Admin) and pushing cgid 5 perms —
  reverted, because the official server leaves admins in channel group 8;
* multi-part group/membership/channel-group lists (fixed names/icon but not
  create);
* `notifychannelpermhints` / `notifyclientpermhints` with all bits — caused an
  assertion (`serverconnectionhandler.cpp:6205`, expression `client`) and was
  removed (do not re-add without checking which clids are materialised);
* own enter view `reasonid=0` — crashes (`serverview.cpp:6714`);
* mirroring the client's `client_*` fields in `initserver` (kept; harmless);
* `permissions.rs` guest/admin/channel-group wires match official data.

### Historical static-analysis leads (client exe, image base `0x140000000`, `.text` RVA `0x1000`)

* `"&Create Channel"` QAction created at `0x140286bae` (menu builder; description
  `"Create a new channel"` at `0x140286ca9`), stored at `[rsi+0x2f0]`.
  `C&reate Sub-Channel` created at `0x140286d8a`.
* The immediate enable call is at `0x140286cda`:

  ```
  cmp byte ptr [rip + 0x131325a], 0
  sete dl
  mov rcx, qword ptr [rsi + 0x2f0]
  call qword ptr [rip + 0xc6389f]      ; QAction::setEnabled(bool)
  ```

  RIP target = `0x141599f3b` (verify with capstone). That global has **104
  RIP-relative READERS** across the menu builder (Overwolf, URL catcher, file
  transfer, friend/foe, …); no direct writer was found with a naive RIP scan, so
  it is likely written through a pointer or is a member of a global UI object.
  Identify the writer (function-by-function disassembly via `.pdata`; capstone is
  installed in the bundled Python) and find the later permission-based
  re-evaluation that disables the action after creation.
* The client asserts at `serverconnectionhandler.cpp:4115` (`"client"`) when
  `channellistfinished` arrives before the own client exists — already fixed.
* `serverconnectionhandler.cpp:6205` (`"client"`) fires for
  `notifyclientpermhints` referencing an unknown clid.
* `serverview.cpp:6714` (`"clientID != m_clientID"`) fires for `reasonid=0` self
  enter view.

### Next step

Reconnect the official client, create a channel after the last root channel,
and confirm it stays connected and the new channel appears last both immediately
and after reconnect.

---

## 6. Diagnostic tools (in `examples/`, all build with the crate)

| Tool | What it does |
| --- | --- |
| `cargo run --release --example oracle_probe -- 9988 Name uid` | Connects to nano-ts3, prints every decrypted S2C command in order, then tests `privilegekeyuse`, `channelcreate`, `channelcreate` duplicate, `servergrouplist`, `clientdisconnect`. |
| `cargo run --release --example proxy_9989 -- 9988` | UDP proxy 9989→upstream, decrypts both directions for nano sessions. |
| `cargo run --release --example official_dump -- 9987 Name uid` | Synthetic client for an official server. Implements the full license-chain key derivation and dumps decrypted S2C. Currently rejected with `error id=1`. |
| `cargo run --release --example license_check` | Proves the license-chain derivation matches nano-ts3's `SERVER_LICENSE_KEY_K` (`2c39eeda…`). |

Static-analysis helpers are Python scripts in `scratch/` (capstone installed in
the bundled Python): `find_assert_line.py`, `disasm_func.py`,
`find_create_channel.py`, `find_global_xrefs.py`, `find_perm_group.py`,
`scan_strings.py`, etc. Re-run them if offsets move (client is fixed 3.6.2).

---

## 7. Build / run / test

```powershell
cd C:\Projects\Nano-TS3
cargo build --release
.\target\release\nano-ts3.exe 9988

cargo test --lib
cargo test --test multi_client_test
cargo test --test integration_test
```

* Launch the official client (from an elevated task if preferred):
  `schtasks /run /tn "RunTS3"` (that batch uses
  `ts3server://127.0.0.1?port=9988`) or
  `& "C:\Program Files\TeamSpeak 3 Client\ts3client_win64.exe" "ts3server://127.0.0.1?port=9988" -multiple`.
* Fresh state: stop server, delete `nano_ts3.db`, restart; note the printed
  admin token.

---

## 8. Environment / editing gotchas

* **Do not commit `scratch/`**, it contains a copy of the official
  TeamSpeak server binaries used only as a protocol oracle. It is gitignored;
  keep it that way (clean-room constraint: nano-ts3 itself has no TS3 binaries
  or FFI).
* The repository has **no commits yet** (`git status` shows everything
  untracked); create the initial commit when appropriate.
* PowerShell mangles inner quotes in `python -c` one-liners. Write a small `.py`
  file in `scratch/` and run it instead (the previous agent hit this repeatedly).
  Use the bundled Python:
  `C:\Users\Dan\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe`.
* `src/server.rs` was CRLF with an earlier `\r\r\n` corruption; it is plain LF
  now. Use the `edit` tool normally. Do not convert line endings blindly.
* The client started by `RunTS3` runs **elevated**; a medium shell cannot kill it
  or inject input. For UI automation, launch it from a medium process (close the
  elevated instance first) — synthetic input then works (mouse/keyboard), though
  in the previous agent's DSH session `SetCursorPos` was still denied, so UI
  steps were ultimately performed by the user.
* Official server query usage (local copy):
  `login serveradmin 5J6TGS8q`, `use port=9987`, then e.g.
  `servergrouppermlist sgid=6`, `channelgrouppermlist cgid=8`,
  `permissionlist`, `clientdblist`, `servergroupaddclient sgid=6 cldbid=3`.
* The official server's writeable copy is `scratch\ts3official`; start it with
  `.\ts3server.exe` (defaults: voice 9987, query 10011). Its fresh-install admin
  token is in `scratch\official_stdout.txt`.

---

## 9. File map (most relevant)

* [`src/server.rs`](../src/server.rs) — protocol dispatch, handshake, ordering,
  defragmentation, all connect/privilege/channel/disconnect handlers.
  Key lines: `build_client_enter_view` 27, `try_assemble_next` 95,
  `build_server_updated` 134, `cleanup_stale` call 241,
  `clientinit` 548, `servergetvariables` 866, `clientgetvariables` 890,
  `channelcreate` 1059, `tokenuse` 1142, `clientdisconnect` 1224,
  `send_channel_list` 1396, group senders 1404–1470.
* [`src/database.rs`](../src/database.rs) — schema, channel de-dup/unique index,
  privilege keys, admin identities.
* [`src/permissions.rs`](../src/permissions.rs) — catalog + group wires.
* [`src/state.rs`](../src/state.rs) — sessions, disconnected cleanup.
* [`src/crypto.rs`](../src/crypto.rs) — EAX, ECDH, RSA puzzle, license proof.
* [`docs/PROTOCOL_NOTES.md`](PROTOCOL_NOTES.md) — detailed findings.
* [`README.md`](../README.md) — status, build/run, tests.
* [`tests/multi_client_test.rs`](../tests/multi_client_test.rs) — protocol
  client; includes UID/admin-reconnect and channelcreate tests.
* [`tests/integration_test.rs`](../tests/integration_test.rs) — single-client
  end-to-end flow.
* [`examples/`](../examples) — probes listed in §6.
