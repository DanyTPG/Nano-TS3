# nano-ts3 Protocol Notes

Clean-room findings collected while making the official TeamSpeak 3 Client 3.6.2
connect to nano-ts3. Everything here was derived from observed traffic and
static analysis of the client; no TeamSpeak code was copied.

## Tools used during the investigation

| File | Purpose |
| --- | --- |
| `examples/oracle_probe.rs` | Connects to nano-ts3, dumps every decrypted S2C command in order, exercises privilege keys, channel creation, duplicate names and disconnect. |
| `examples/proxy_9989.rs` | UDP proxy that decrypts and prints both directions of a nano-ts3 session. |
| `examples/official_dump.rs` | Synthetic client for an official server: derives the server's ephemeral key from the license chain and dumps the official connectivity sequence. |
| `examples/license_check.rs` | Validates the license-chain key derivation against nano-ts3's fixed anonymous license. |

## Transport

* S2C header is 11 bytes: MAC(8) + packet id(2) + flags/type(1).
* C2S header is 13 bytes: MAC(8) + packet id(2) + client id(2) + flags/type(1).
* AES-128-EAX key/nonce are derived from `SHA256(dir || type || generation ||
  shared_iv)` (see `crypto::derive_key_nonce`).
* Command flags seen from real clients: `NEWPROTOCOL (0x20)`, sometimes
  `FRAGMENTED (0x10)`. The flag byte is part of the EAX associated data, so it
  must match the packet header exactly.

## Fragmentation (critical)

TS3 does **not** mark every fragment. A multi-fragment command marks the **first
and the last** packet with `FRAGMENTED`; packets in between have no flags. A
single-packet command has no flag at all.

Receiver rule (matches tsproto's codec and the official client):

* flagged packet with no fragment buffered -> start of a command;
* unflagged packet while buffering -> middle fragment, append and continue;
* flagged packet while buffering -> final fragment, append and dispatch.

Marking every chunk (the original nano-ts3 behaviour) makes a 4-fragment
`initserver` complete after fragment 2, so the client parses a truncated command
and disconnects with `parameter not found`. This was the root cause of the
client failing during the handshake after Init4.

## Handshake observations

* Real clients send `clientinitiv` twice: once as a bootstrap-encrypted command
  with packet id 0 and once embedded in Init4. Both copies are identical; ACK
  the early one and use the Init4 copy.
* Init0/Init2/Init4 carry a 32-bit "version" that the official 3.6.2 client
  sends as `0x142898dd`; the Init0 timestamp is the current Unix time.
* `client_key_offset` is an identity-specific hashcash counter: the security
  level is the number of trailing zero bits in
  `SHA1(omega_text + decimal_offset)`. Reusing the captured client's offset
  with a newly generated omega fails identity validation; `official_dump.rs`
  now computes a level-8 offset for its own key.
* `initivexpand2` is encrypted with the bootstrap key/nonce and always uses
  packet id 0. `ot=1` is required; a server that omits it is treated as
  outdated.
* The client UID is **not** sent by the client. The official server derives it
  as `base64(sha1(<the omega value exactly as it appears in clientinitiv>))`.
  For example `MEwDAgcAAgEgAiB1n5Zg...` yields
  `iMD9uDe3y38CY2TNKHZ8LHCQuH4=`. This was verified against a real client and
  the official server's `clients` table.
* `clientek` carries an Ed25519 ephemeral key and an ECDSA proof over
  `ek || beta` signed with the client's P-256 identity key (the same key that
  produced `omega`).

### License chain (for synthetic clients / tooling)

The `l` parameter of `initivexpand2` is a chain of license blocks. The server's
ECDH key is derived from the TeamSpeak root key and every block:

```
key = ROOT_KEY(point)
for block in blocks:
    hash = clamp(SHA512(block[1..]))
    key = block_pub * hash + key
```

Block layout is 42 bytes fixed: `0x00`, 32-byte public key, type byte,
not-before u32, not-after u32, then type-specific data. Anonymous licenses
contain a Server block (`type=2`, with 1-byte license type, 4-byte max clients
and a NUL-terminated issuer string) followed by an Ephemeral block (`type=32`).
`examples/license_check.rs` proves the derivation reproduces nano-ts3's
`SERVER_LICENSE_KEY_K`.

## Connect sequence that the official client accepts

Observed from the official client against nano-ts3:

1. `initserver` (client can be fragmented; mandatory fields per the TS3
   declarations must all be present).
2. `channellist` entries (one command per channel).
3. The client's **own** `notifycliententerview` with `reasonid=2`. Static
   analysis shows the client's `channellistfinished` handler looks up its own
   client object and asserts `client` if it is missing, so the own enter view
   must precede `channellistfinished`.
4. `channellistfinished`.
5. Server group names (`notifyservergrouplist`), client group membership
   (`notifyservergroupsbyclientid`) and channel group names
   (`notifychannelgrouplist`) — each **as a single multi-part command**.
   The client replaces its cached list with every such command, so sending one
   command per group leaves only the last group (visible as
   `%CLIENT_SERVER_GROUP_NAME%` placeholders and missing admin permissions).
6. Enter views for clients that were already online, then the broadcast of the
   newcomer to everybody else.
7. Server group permissions (`notifyservergrouppermlist`), channel group
   permissions (`notifychannelgrouppermlist`).
8. `error id=0 msg=ok` for `clientinit`.

The captured official 3.13.7 login also sends one 123-entry
`notifyclientneededpermissions` command after the group lists. Nano-ts3 omitted
this notification; it is now included in the same part of the login sequence.
The user confirmed that this enables Create Channel in official client 3.6.2.

`servergetvariables` must answer with a fully populated `notifyserverupdated`
and must keep `virtualserver_ask_for_privilegekey=1` for a guest while an unused
privilege key exists. Answering with `0` clears the client's flag and greys out
"Use Privilege Key".

## Permission ids

Verified against an official 3.13.7 server via ServerQuery:

* `b_virtualserver_token_use` = 40 (must be granted to Guest so the privilege
  key menu/popup is usable).
* `b_channel_create_permanent` = 89, `b_channel_create_child` = 88,
  `b_channel_create_semi_permanent` = 90, `b_channel_create_temporary` = 91.
* The official Server Admin group (`sgid=6`) list contains 412 entries,
  including the 33000-series `i_needed_modify_power_*` permissions; using that
  list is more faithful than granting only 1..248.

`notifyclientupdated` must not echo `client_nickname`: the official client
treats it as a rename request and disconnects with "nickname is already in use".

## Channel creation order

The official 3.6.2 client now enables **Create Channel / Create Sub-Channel**
for a Server Admin connected to nano-ts3. The missing 123-entry
`notifyclientneededpermissions` notification was identified in the official
capture and added to login; the user confirmed the menu is enabled.

A real create using **Sort This Channel After** then disconnected with
`Disconnected from server (invalid channel order)`. The cause was two related
ordering bugs: `notifychannelcreated` set `channel_order` to the new channel's
own `cid`, and the database stored every new channel with order zero. In TS3,
`channel_order` is the ID of the preceding sibling (zero means first). The
create handler now honors a valid requested predecessor, appends after the last
channel when the request omits or supplies a stale ID, and broadcasts that same
predecessor. The database updates the next sibling link for middle insertions
and normalizes legacy root-channel order links at startup. A live-client retest
of this fix is still needed.

## Channel edits and deletes

Before opening channel action dialogs, the 3.6.2 client requests
`channelgetdescription cid=...`. The protocol response is the low-priority
`notifychanneledited` form with `cid`, `reasonid=9` (`Channelupdate`), and
`channel_description`, followed by the matching `error ok`. Replying with a
command named `channelgetdescription` leaves the client waiting, so Edit Channel
does not open. The server now returns the expected notification; the Edit
Channel dialog was verified in the official client.

The client sends `channeledit cid=...` and `channeldelete cid=... force=...`.
The server now persists channel edits, broadcasts a complete
`notifychanneledited` snapshot, and replies to the request with its `return_code`.
Full edit notifications include `reasonid=10` (`Channeledit`).
Editable persisted fields include name, topic, description, predecessor order,
codec, codec quality, client limits, channel lifetime flags, needed powers,
latency factor, icon ID, and phonetic name. Reordering rewrites the full
predecessor chain so there are no dangling links or duplicate predecessors.

Deletion protects the default channel. `force=0` rejects a channel with
connected clients; `force=1` moves those clients to the default channel,
broadcasts `notifyclientmoved` and `notifychanneldeleted`, then removes the row
and repairs the remaining order chain. This implementation currently supports
root channels only. Channel passwords and encrypted voice channels are not
supported. The delete confirmation flow has not been separately exercised in
the client.

## Channel subscriptions and client audio state

The client sends `channelsubscribeall` after login and sends individual
`channelsubscribe cid=...` / `channelunsubscribe cid=...` commands when the user
changes channel subscriptions. These commands need both an `error id=0 msg=ok`
reply and the matching `notifychannelsubscribed` or
`notifychannelunsubscribed` notification, with channel IDs encoded as
`cid=...|cid=...`. A client also sends an individual subscribe for a newly
created channel. Keep subscription state per connected client so duplicate
requests do not generate duplicate notifications; always retain the client's
current channel as subscribed.

Microphone and headphone indicators come from the client's `clientupdate`
fields: `client_input_muted`, `client_output_muted`,
`client_outputonly_muted`, `client_input_hardware`, and
`client_output_hardware`. Store the partial update and broadcast a
`notifyclientupdated` containing the changed fields and `clid`. Include the
current audio flags in `notifycliententerview` for clients who join later.

## Voice relay packet sequencing

S2C packet IDs are tracked independently by packet type. In-channel `Voice`
packets must use their own counter rather than `next_s2c_packet_id`, which is
used for `Command` packets; a voice packet with the command counter's current
ID falls outside the client's voice receive window. The in-channel relay now
uses `next_s2c_voice_packet_id` per receiving client while preserving the
speaker's voice sequence, client ID, codec, and Opus payload. The relay passes
codec frames through unchanged, so `initserver` advertises
`virtualserver_codec_encryption_mode=1` (forced off) and channel entries set
`channel_codec_is_unencrypted=1`. Leaving encryption enabled made clients send
encrypted voice payloads, which the relay forwarded as if they were Opus frames
and produced noise. Encrypted voice channels are unsupported. `VoiceWhisper`
target routing is not implemented.

Earlier investigations into the greyed menu item included:

Investigated without success:

* granting the exact official `sgid=6` permission list (412 entries);
* assigning the admin to channel group 5 (Channel Admin) and pushing its
  permissions (the official server actually leaves admins in Guest, so this was
  reverted);
* multi-part group/membership/channel-group lists (this fixed group name
  resolution and the admin icon);
* `notifychannelpermhints` / `notifyclientpermhints` (the client asserts in
  `serverconnectionhandler.cpp` for clients that are not yet materialised, so
  they were removed);
* using `reasonid=0` for the own enter view (the client asserts
  `clientID != m_clientID` in `serverview.cpp`);
* mirroring the client fields in `initserver`.

