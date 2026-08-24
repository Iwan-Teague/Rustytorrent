# RustyTorrent — Task & Sprint Breakdown

> Granular tasks per roadmap phase. Estimates are in hours for a solo developer.
> Mark tasks with [x] as you complete them.

## Current Status

Phases 1–6 implemented and verified, plus the MSE/PE encrypted-handshake and
BEP-5 DHT slices of Phase 7. The build is clean (`cargo clippy -D warnings`
and `cargo fmt --check` both pass), and **500+** unit + integration tests run
green across 17 suites.

Status addendum (2026-08 security & anonymity passes): martian-filter
strictness is derived from session anonymity at every peer/DHT/tracker
ingestion site; BEP 6 REJECT_REQUESTs are range- and ownership-validated
(remote-panic + cross-peer-poison fix); the MSE SKEY match is
constant-time; SOCKS5 refuses hostname hops under `--anonymous`;
anonymous-mode UDP-tracker refusal is proven at the kernel socket level;
µTP has bounded send/receive/delivery memory with property coverage.
See docs/TODO.md §1–2 for details.

End-to-end download is verified by:

- **Plain path, localhost**: 32 MiB single-file torrent between two `rustytorrent`
  instances completes in ~1 s with byte-identical MD5.
- **MSE path, localhost** (`--encrypt`): same torrent, ~2 s, MD5 byte-identical.
- **Real public swarm via tracker** (Debian 13.5 amd64-netinst.iso, 755 MiB):
  14 % downloaded in 60 s at ~1.9 MB/s; the plain-then-MSE-fallback heuristic
  catches MSE-only peers automatically.
- **Real public swarm via DHT alone** (`--no-tracker --dht`, same torrent):
  32 % downloaded in 90 s at ~2.8 MB/s; bootstraps from `router.bittorrent.com`
  & co., then iterative `get_peers` against 78 routing-table contacts surfaces
  229 candidate peers.
- **DHT persistence**: routing table written to
  `~/.config/rustytorrent/dht_state` every 5 minutes and on graceful shutdown;
  warm-load on next start (~80 contacts) skips the cold-bootstrap RTT.
- **Upload-side optimization**: an LRU cache of whole pieces (default 32 ×
  256 KiB ≈ 8 MiB) collapses 16 disk reads per piece down to 1 when leechers
  pull all blocks of the same piece sequentially.

Outstanding gaps:

- **µTP (BEP 29)** — TCP only today; a UDP path would unlock the
  UDP-only slice of the swarm.

---

## How to Use This Doc

- Work top-to-bottom within each phase
- Items marked ⚠️ are blockers — don't skip them
- Estimates assume familiarity with Rust but not the underlying protocol
- Each phase should be fully working before starting the next

---

## Phase 1 — Parse & Inspect  ✅

**Total estimate: ~12h**

### Bencode Parser (`src/metainfo/bencode.rs`)
- [x] ⚠️ Define `BencodeValue` enum: `Int(i64)`, `Bytes(Vec<u8>)`, `List(Vec<BencodeValue>)`, `Dict(BTreeMap<Vec<u8>, BencodeValue>)`
- [x] ⚠️ Implement recursive descent parser from `&[u8]`
- [x] Write unit tests: integers, byte strings, lists, nested dicts, empty values
- [x] Handle parse errors gracefully (no panics)

### Torrent File (`src/metainfo/torrent.rs`)
- [x] ⚠️ Define `TorrentFile`, `Info`, `FileEntry` structs
- [x] ⚠️ Deserialize from `BencodeValue` tree
- [x] ⚠️ Compute `info_hash`: extract raw bencoded `info` bytes, SHA1 hash them — verified vs. independent Python SHA1 on Debian .torrent
- [x] Parse `pieces` bytes into `Vec<[u8; 20]>` piece hashes
- [x] Handle both single-file and multi-file `info` layouts
- [x] Parse `announce-list` (list of lists)
- [x] Unit test against synthetic torrents; integration-tested on real Debian + Ubuntu + Big Buck Bunny .torrent files

### CLI (`src/main.rs`)
- [x] Set up `clap` with subcommand structure
- [x] Implement `rustytorrent info <file>` subcommand

### Setup
- [x] ⚠️ Initialize `Cargo.toml` with all Phase 1 dependencies (`sha1`, `clap`, `thiserror`, `tracing`, `tracing-subscriber`)
- [x] Set up `error.rs` with unified `Error` enum and `Result` alias

---

## Phase 2 — Tracker Communication  ✅

**Total estimate: ~14h**

### HTTP Tracker (`src/tracker/http.rs`)
- [x] ⚠️ Define `AnnounceRequest` and `AnnounceResponse` structs (`tracker/mod.rs`)
- [x] ⚠️ Build announce URL with correct percent-encoded `info_hash` and `peer_id` (per RFC 3986 unreserved-only)
- [x] ⚠️ Parse compact peer list (6 bytes per peer: 4 IP + 2 port big-endian); also supports dict-form peers and `peers6`
- [x] Parse `failure reason` and surface as error
- [x] Schedule re-announce respecting `interval` (engine's `tracker_timer`)
- [x] Add `reqwest` (rustls-tls feature) to dependencies

### UDP Tracker (`src/tracker/udp.rs`)
- [x] ⚠️ Implement connect request (magic `protocol_id = 0x41727101980` per BEP 15)
- [x] ⚠️ Implement announce request with connect response `connection_id`; 98-byte packet layout verified by test
- [x] Parse announce response: peers, interval, seeders, leechers
- [x] Retry with exponential backoff (15s × 2^n, max 4 attempts — tunable from doc's 8)
- [x] Random `transaction_id` generation and echo-check

### Peer ID & Config
- [x] Generate `peer_id` in Azureus style: `-RT0100-` + 12 random printable bytes (`src/peer_id.rs`)
- [x] Add `rand` to dependencies

### Tracker Trait & Manager
- [x] `tracker::announce` dispatches on URL scheme (`http://`, `https://`, `udp://`)
- [x] `tracker::announce_with_fallback` tries each tier in announce-list, falls back to `announce`

### CLI
- [x] Implement `rustytorrent peers <file>` subcommand — verified live against Debian tracker (returned 50 peers)
- [x] Add `tracing` log output to all tracker operations

### Tests
- [x] Unit test compact peer parsing (v4 and v6)
- [x] Unit test UDP packet serialization (98-byte layout) and response parsing

---

## Phase 3 — Peer Handshake & Messaging  ✅

**Total estimate: ~18h**

### Handshake (`src/peer/handshake.rs`)
- [x] ⚠️ Implement outgoing handshake: preamble + 8 reserved bytes + info_hash + peer_id — 68-byte total per BEP 3
- [x] ⚠️ Read and validate incoming handshake (info_hash mismatch closes connection)
- [x] Handle both outgoing and incoming flows via `perform_outgoing` / `perform_incoming`; in-memory duplex roundtrip test

### Wire Protocol Messages (`src/peer/message.rs`)
- [x] ⚠️ Define `Message` enum for all standard message types (IDs 0–8)
- [x] ⚠️ Implement message framing: 4-byte big-endian length prefix (`read_frame` / `write_frame`)
- [x] Implement `encode(&self) -> Vec<u8>` and `decode(payload: &[u8]) -> Result<Message>` — every variant roundtrips in tests
- [x] Handle keep-alive (length = 0)
- [x] Strict bitfield decoding: spare bits past `num_pieces` must be zero per BEP 3

### Peer Connection (`src/peer/connection.rs`)
- [x] ⚠️ Spawn per-peer `tokio::task` with `TcpStream`
- [x] ⚠️ Async read/write loop using `tokio::select!`; events flow up via `mpsc::Sender<PeerEvent>`
- [x] Async write path: receive `PeerCommand` from `mpsc::Receiver`, encode, send
- [x] State tracked in engine: `peer_choking_us`, `am_interested`, `inflight` per addr
- [x] Send keep-alive every 2 minutes (`KEEPALIVE_INTERVAL`); drop peer if idle 180 s
- [x] Handle clean disconnect and propagate `Disconnected` event to engine

### Peer Manager (`src/peer/manager.rs`)
- [x] ⚠️ Maintain `HashMap<SocketAddr, PeerSlot>` (handle + JoinHandle)
- [x] Cap at 50 total connections (configurable)
- [x] Connect to new peers from tracker list (`try_connect_many`)
- [x] Disconnect path: forget address on `PeerEvent::Disconnected`

### Engine (`src/engine.rs`)
- [x] ⚠️ Set up central `select!` loop receiving from peer events, storage events, tracker tick, choke tick, progress tick, incoming connections
- [x] Handle `PeerEvent::Bitfield`, `Have`, `Choke`, `Unchoke`, `Block`, `Request`, `Cancel`

---

## Phase 4 — Core Downloading  ✅

**Total estimate: ~20h**

### Piece Manager (`src/piece/manager.rs`)
- [x] ⚠️ Piece state: `Missing`, `InProgress`, `Complete` (block bitmaps held separately)
- [x] ⚠️ Track which blocks within a piece have arrived (16 KiB `BLOCK_SIZE`); last block of last piece may be shorter
- [x] Maintain local bitfield (`BitVec<u8, Msb0>`) for sending to peers
- [x] `received_block` returns the assembled buffer when all blocks are in
- [x] `bitvec` already in dependencies

### Piece Picker (`src/piece/picker.rs`)
- [x] ⚠️ Picker chooses by rarest-first (Phase 5 graduation) over peer's bitfield
- [x] Always request 16384-byte blocks (size determined by `block_length` for last block edge case)
- [x] Pipeline depth: 5 outstanding `Request` messages per peer (`PIPELINE_DEPTH` in engine)

### SHA1 Verifier (`src/piece/verifier.rs`)
- [x] ⚠️ Hash assembled piece bytes with `sha1` crate; verified against `SHA1("abc")` known answer
- [x] ⚠️ Compare against expected hash from `TorrentFile.info.piece_hashes[index]`
- [x] On mismatch: reset piece to `Missing`, ban the contributing peer

### Disk Storage (`src/storage/disk.rs`)
- [x] ⚠️ Pre-allocate output files on startup using `set_len`
- [x] ⚠️ Async write of piece data at correct file offset; flushes after every piece
- [x] Run storage in dedicated task, receive via `mpsc` channel
- [x] `StorageEvent::Written` returned to engine after flush

### Engine Wiring
- [x] ⚠️ On `PeerEvent::Unchoke`: start requesting blocks (Interested was sent earlier on bitfield/have)
- [x] ⚠️ On `PeerEvent::Block`: forward block to PieceManager
- [x] On full piece + verify pass: dispatch `StorageCommand::Write`
- [x] On `StorageEvent::Written`: broadcast `Have(index)` to all peers and re-pump their request queues
- [x] On `StorageEvent::Written`: update local bitfield via `mark_complete`
- [x] Periodic progress log (configurable, default every 2 s)

### CLI
- [x] Periodic progress log to download subcommand
- [x] Implement `rustytorrent download <file.torrent> --output <dir> [--port N] [--peer host:port…] [--no-tracker]`

---

## Phase 5 — Multi-file & Correctness  ✅

**Total estimate: ~16h**

### Multi-file Storage (`src/storage/layout.rs`)
- [x] ⚠️ Virtual offset map: piece index + byte offset → file path + file offset
- [x] ⚠️ Pieces that span multiple files split into N writes; 3-way span tested
- [x] Pre-allocate all files on startup (single-file and multi-file)

### Rarest-First Picker (`src/piece/picker.rs`)
- [x] ⚠️ Track `availability: Vec<u32>` (count of peers that have each piece)
- [x] Update counts on `PeerEvent::Bitfield` and `PeerEvent::Have`
- [x] Picker sorts candidates by availability ascending, shuffles ties for fairness; sticky per-peer assignment to avoid thrash

### Endgame Mode
- [x] Detect endgame: fewer than 5 incomplete pieces remain (`ENDGAME_REMAINING`)
- [x] In endgame: re-request unfinished blocks from any unchoked peer that has the piece
- [x] Send `Cancel` to peers when a block arrives from someone else (via `endgame_requests` map)

### Choke / Unchoke (`src/scheduler/choke.rs`)
- [x] ⚠️ Run choking loop every 10 seconds (`CHOKE_INTERVAL`)
- [x] ⚠️ Track download rate from each peer over 20-second rolling window (`RATE_WINDOW`)
- [x] ⚠️ Unchoke top 3 peers by rate (`REGULAR_UNCHOKE_SLOTS`)
- [x] ⚠️ 1 optimistic unchoke slot: rotate every 30 s (`OPTIMISTIC_INTERVAL`)
- [x] Anti-snubbing: peer flagged snubbed if no block in 60 s, demoted in selection

### Upload / Seeding
- [x] Respond to `Request` messages from unchoked peers (engine queues `StorageCommand::Read`)
- [x] Read piece from disk and send `Piece` message
- [x] Whole-piece LRU upload cache — first block of a piece reads from disk, subsequent blocks served from RAM ([`storage/cache.rs`](../src/storage/cache.rs))

---

## Phase 6 — Hardening & Resume  ✅

**Total estimate: ~16h**

### Resume Support (`src/storage/disk.rs::scan_resume`)
- [x] ⚠️ On startup: for each piece, SHA1-check existing file bytes; verified via partial-then-resume self-test
- [x] ⚠️ Rebuild local bitfield from verification results
- [x] Skip already-verified pieces in the picker; if fully complete on startup, run as seeder (don't exit)

### Peer Banning
- [x] Maintain `HashSet<IpAddr>` of banned peers (`PeerManager::banned`)
- [x] Ban peer on hash mismatch (in engine's Block handler)
- [x] Ban peer on repeated protocol violations — per-IP rolling-window counter (3 strikes in 60 s) covers bad pstr, info_hash mismatch, oversized frame, malformed message, bitfield spare-bit violations; benign network errors (EOF, timeout, reset) don't count
- [x] Skip banned peers when connecting (and accepting)

### Incoming Connections (`src/engine.rs`)
- [x] ⚠️ Open `TcpListener` on configured port (non-fatal if port busy)
- [x] Accept incoming connections and hand off to `PeerManager::accept_incoming`
- [x] Respect max connection cap and ban list for incoming peers

### Graceful Shutdown
- [x] Trap `SIGINT` (ctrl-c) in `main.rs::cmd_download`
- [x] Flush all pending disk writes on shutdown (storage task receives `Shutdown` command)
- [x] Send tracker `stopped` event on shutdown (when tracker is enabled)
- [x] Listener task aborted on engine exit

### Stability & Polish
- [x] Stable `peer_id`: persisted to `$XDG_CONFIG_HOME/rustytorrent/peer_id` (or `~/.config/rustytorrent/peer_id`); regenerated on missing/bad file
- [x] Rate limiter: configurable max download/upload speed — `--max-down`
      / `--max-up` (KiB/s) feed engine-wide token buckets (2 s burst);
      download gated at Request issuance, upload at `serve_request`
      (over-quota requests dropped silently; peers re-request).
- [x] Bandwidth stats: bytes downloaded/uploaded per torrent (engine `downloaded` / `uploaded` counters; logged at progress tick)
- [x] Audit all code paths for `unwrap()` / `expect()` — non-test code has zero `unwrap()`s; `clippy -D warnings` is clean
- [x] Integration test: self-test (seeder ↔ leecher over localhost) downloads 32 MiB torrent end-to-end with MD5 verified vs source

---

## Phase 7 — Protocol Extensions

**Total estimate: ~40h** (rough, extensions are research-heavy)

### MSE / PE — Message Stream Encryption (BEP 8)  ✅
- [x] RC4 stream cipher with key-schedule + 1024-byte discard helper ([`peer/mse/rc4.rs`](../src/peer/mse/rc4.rs))
- [x] 768-bit Diffie-Hellman with Oakley Group 1 prime, generator 2 ([`peer/mse/dh.rs`](../src/peer/mse/dh.rs))
- [x] Initiator handshake: Ya+PadA, sync on encrypted VC, exchange crypto_provide/crypto_select ([`peer/mse/handshake.rs::perform_outgoing`](../src/peer/mse/handshake.rs))
- [x] Receiver handshake: Yb+PadB, locate `HASH(req1,S)` in stream, resolve SKEY against torrent's info_hash ([`peer/mse/handshake.rs::perform_incoming`](../src/peer/mse/handshake.rs))
- [x] `Rc4Reader` / `Rc4Writer` `AsyncRead`/`AsyncWrite` wrappers so the post-handshake loop is identical to plain BT
- [x] Outgoing dispatch: plain first, then MSE fallback on signature failures; `--encrypt` for MSE-only
- [x] Incoming dispatch: peek first byte; `\x13` → plain, anything else → MSE
- [x] Integration verified against real Debian swarm (14 % of 755 MiB in 60 s at ~1.9 MB/s)

### Extension Protocol (BEP 10)  ✅
- [x] Set reserved bytes in handshake to signal support (byte 5 = 0x10) ([`peer/handshake.rs`](../src/peer/handshake.rs))
- [x] `extended` message (id 20) framing in the wire codec ([`peer/message.rs`](../src/peer/message.rs))
- [x] Exchange extension handshake with `m` dict of supported extensions ([`peer/extension.rs`](../src/peer/extension.rs))

### Peer Exchange / PEX (BEP 11)  ✅
- [x] `ut_pex` payload parser (IPv4 `added` + IPv6 `added6`, drops zero-port entries) ([`peer/extension.rs`](../src/peer/extension.rs))
- [x] Post-BT-handshake extension-handshake exchange so peers know our `ut_pex` id ([`peer/connection.rs`](../src/peer/connection.rs) `post_handshake_loop`)
- [x] Engine handles `PeerEvent::Pex` and forwards to `PeerManager::try_connect_many` ([`engine.rs`](../src/engine.rs))
- [x] Outgoing PEX — every 60 s the engine builds added/dropped deltas per peer (tracking last snapshot, capped at 50 entries/direction) and ships via `PeerCommand::Extension`. Skipped under `--anonymous`.

### ut_metadata (BEP 9)  ✅
- [x] `ut_metadata` request/data/reject codec ([`peer/extension.rs`](../src/peer/extension.rs))
- [x] Reassemble + SHA-1 verify metadata against magnet info_hash ([`peer/metadata_fetch.rs`](../src/peer/metadata_fetch.rs))

### Magnet Links  ✅
- [x] Parse magnet URI (`xt=urn:btih:` hex/base32, `tr=`, `dn=`) ([`magnet.rs`](../src/magnet.rs))
- [x] Bootstrap from trackers in magnet URI ([`main.rs` `cmd_magnet`](../src/main.rs))
- [x] Bootstrap from DHT for trackerless magnets
- [x] Fetch metadata via ut_metadata before handing off to the engine

### DHT (BEP 5)  ✅
- [x] 160-bit `NodeId` + XOR distance + bucket index ([`dht/node_id.rs`](../src/dht/node_id.rs))
- [x] Kademlia k-bucket routing table (K=8, 160 buckets, LRU within bucket) ([`dht/routing.rs`](../src/dht/routing.rs))
- [x] KRPC bencode codec for ping / find_node / get_peers / announce_peer ([`dht/krpc.rs`](../src/dht/krpc.rs))
- [x] UDP server: answers inbound queries; correlates outbound queries by transaction id ([`dht/server.rs`](../src/dht/server.rs))
- [x] Iterative `get_peers` with α=3 parallel and a 15 s soft budget
- [x] Bootstrap from `router.bittorrent.com`, `dht.transmissionbt.com`, etc.
- [x] Routing-table persistence to `~/.config/rustytorrent/dht_state` with warm-load on startup ([`dht/persist.rs`](../src/dht/persist.rs))
- [x] Engine integration: spawn DHT on `--dht`, supplemental peer discovery when connected-peer count drops below half the cap, periodic 5-minute lookups
- [x] Verified end-to-end against the real public DHT (Debian torrent: 229 peers discovered, 32 % downloaded in 90 s without tracker)

---

## Phase 8 — Web UI

**Total estimate: ~24h**

> **Status note (2026-08):** a monitoring API + minimal UI shipped with
> somewhat different endpoints than the spec below: `GET /api/status`,
> `GET /api/peers`, `GET /api/files`, `GET /metrics` (Prometheus),
> `POST /api/pause|resume|shutdown`, daemon-scoped `POST /api/add`,
> `POST /api/add_magnet`, plus loopback-only binding, Host-header and
> CSRF checks. The per-torrent REST surface below remains future work.

### REST API (`src/api/`)
- [ ] Add `axum` to dependencies — 15m
- [ ] `GET /api/torrents` — list all active torrents with status — 2h
- [ ] `POST /api/torrents` — add torrent by file upload or magnet — 2h
- [ ] `DELETE /api/torrents/:id` — remove torrent — 1h
- [ ] `POST /api/torrents/:id/pause` and `/resume` — 1h
- [ ] `GET /api/torrents/:id/peers` — peer list with stats — 1h
- [ ] `GET /metrics` — Prometheus-format metrics — 2h

### Frontend
- [ ] Static file serving via axum — 30m
- [ ] Torrent list view with progress bars — 4h
- [ ] Peer list table — 2h
- [ ] Speed graph (upload / download over time) — 3h
- [ ] Add torrent dialog (file drag-and-drop or magnet paste) — 2h

---

## Ongoing / Cross-cutting

These tasks apply across all phases:

- [ ] Keep `CHANGELOG.md` updated as features land
- [ ] Add `tracing` spans to all major async boundaries
- [x] Run `clippy` with `--deny warnings` in CI (.github/workflows/ci.yml)
- [x] Run `cargo fmt` check in CI (.github/workflows/ci.yml)
- [ ] Keep dependency count lean — evaluate each new crate
