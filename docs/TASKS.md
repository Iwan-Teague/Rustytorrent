# RustyTorrent — Task & Sprint Breakdown

> Granular tasks per roadmap phase. Estimates are in hours for a solo developer.
> Mark tasks with [x] as you complete them.

---

## How to Use This Doc

- Work top-to-bottom within each phase
- Items marked ⚠️ are blockers — don't skip them
- Estimates assume familiarity with Rust but not BitTorrent internals
- Each phase should be fully working before starting the next

---

## Phase 1 — Parse & Inspect

**Total estimate: ~12h**

### Bencode Parser (`src/metainfo/bencode.rs`)
- [ ] ⚠️ Define `BencodeValue` enum: `Int(i64)`, `Bytes(Vec<u8>)`, `List(Vec<BencodeValue>)`, `Dict(BTreeMap<Vec<u8>, BencodeValue>)` — 1h
- [ ] ⚠️ Implement recursive descent parser from `&[u8]` — 2h
- [ ] Write unit tests: integers, byte strings, lists, nested dicts, empty values — 1h
- [ ] Handle parse errors gracefully (no panics) — 30m

### Torrent File (`src/metainfo/torrent.rs`)
- [ ] ⚠️ Define `TorrentFile`, `Info`, `FileEntry` structs — 1h
- [ ] ⚠️ Deserialize from `BencodeValue` tree — 1h
- [ ] ⚠️ Compute `info_hash`: extract raw bencoded `info` bytes, SHA1 hash them — 1h
- [ ] Parse `pieces` bytes into `Vec<[u8; 20]>` piece hashes — 30m
- [ ] Handle both single-file and multi-file `info` layouts — 1h
- [ ] Parse `announce-list` (list of lists) — 30m
- [ ] Unit test against 2–3 real `.torrent` files — 1h

### CLI (`src/main.rs`)
- [ ] Set up `clap` with subcommand structure — 30m
- [ ] Implement `rustytorrent info <file>` subcommand — 30m

### Setup
- [ ] ⚠️ Initialize `Cargo.toml` with all Phase 1 dependencies (`sha1`, `clap`, `thiserror`, `tracing`, `tracing-subscriber`) — 30m
- [ ] Set up `error.rs` with unified `Error` enum and `Result` alias — 30m

---

## Phase 2 — Tracker Communication

**Total estimate: ~14h**

### HTTP Tracker (`src/tracker/http.rs`)
- [ ] ⚠️ Define `TrackerRequest` and `TrackerResponse` structs — 30m
- [ ] ⚠️ Build announce URL with correct URL-encoded `info_hash` and `peer_id` — 1h
- [ ] ⚠️ Parse compact peer list (6 bytes per peer: 4 IP + 2 port big-endian) — 1h
- [ ] Parse `failure reason` and surface as error — 30m
- [ ] Schedule re-announce respecting `interval` using `tokio::time::sleep` — 1h
- [ ] Add `reqwest` (rustls-tls feature) to dependencies — 15m

### UDP Tracker (`src/tracker/udp.rs`)
- [ ] ⚠️ Implement connect request (magic `connection_id = 0x41727101980`) — 1h
- [ ] ⚠️ Implement announce request with connect response `connection_id` — 1h
- [ ] Parse announce response: peers, interval, seeders, leechers — 1h
- [ ] Implement retry with exponential backoff (15s → 30s → 60s… up to 8 tries) — 1h
- [ ] Random `transaction_id` generation and echo-check — 30m

### Peer ID & Config
- [ ] Generate `peer_id` in Azureus style: `-RT0100-` + 12 random bytes — 30m
- [ ] Add `rand` to dependencies — 15m

### Tracker Trait & Manager
- [ ] Define `Tracker` trait with `announce()` method — 30m
- [ ] Implement tracker selection logic (try announce-list in order) — 1h

### CLI
- [ ] Implement `rustytorrent peers <file>` subcommand — 30m
- [ ] Add `tracing` log output to all tracker operations — 30m

### Tests
- [ ] Unit test compact peer parsing — 30m
- [ ] Unit test UDP packet serialization/deserialization — 1h

---

## Phase 3 — Peer Handshake & Messaging

**Total estimate: ~18h**

### Handshake (`src/peer/handshake.rs`)
- [ ] ⚠️ Implement outgoing handshake: preamble + 8 reserved bytes + info_hash + peer_id — 1h
- [ ] ⚠️ Read and validate incoming handshake — 1h
- [ ] Handle both outgoing (we connect) and incoming (they connect) flows — 1h

### Wire Protocol Messages (`src/peer/message.rs`)
- [ ] ⚠️ Define `Message` enum for all standard message types (IDs 0–9) — 1h
- [ ] ⚠️ Implement message framing: 4-byte big-endian length prefix — 1h
- [ ] Implement `encode(&self) -> Vec<u8>` for each message type — 1h
- [ ] Implement `decode(id: u8, payload: &[u8]) -> Result<Message>` — 1h
- [ ] Handle keep-alive (length = 0) — 30m

### Peer Connection (`src/peer/connection.rs`)
- [ ] ⚠️ Spawn per-peer `tokio::task` with `TcpStream` — 1h
- [ ] ⚠️ Async read loop: frame → decode → send over `mpsc::Sender<PeerEvent>` — 2h
- [ ] Async write path: receive `PeerCommand` from `mpsc::Receiver`, encode, send — 1h
- [ ] Track connection state flags: `am_choking`, `am_interested`, `peer_choking`, `peer_interested` — 30m
- [ ] Send keep-alive every 2 minutes — 30m
- [ ] Handle clean disconnect and propagate to PeerManager — 30m

### Peer Manager (`src/peer/manager.rs`)
- [ ] ⚠️ Maintain `HashMap<PeerId, PeerHandle>` — 1h
- [ ] Cap at 50 total connections — 30m
- [ ] Connect to new peers from tracker list — 1h
- [ ] Reconnect with backoff on disconnect — 1h

### Engine (`src/engine.rs`)
- [ ] ⚠️ Set up central `select!` loop receiving from all channel endpoints — 2h
- [ ] Handle `PeerEvent::Bitfield` and log it — 30m

---

## Phase 4 — Core Downloading

**Total estimate: ~20h**

### Piece Manager (`src/piece/manager.rs`)
- [ ] ⚠️ Define piece state: `Missing`, `Requested { blocks: BitVec }`, `Complete` — 1h
- [ ] ⚠️ Track which blocks within a piece have arrived (16 KiB blocks) — 1h
- [ ] Maintain local bitfield (`BitVec<u8, Msb0>`) for sending to peers — 1h
- [ ] Fire `PieceComplete` event when all blocks received — 30m
- [ ] Add `bitvec` to dependencies — 15m

### Piece Picker (`src/piece/picker.rs`)
- [ ] ⚠️ Sequential picker (pick lowest missing piece index first) — 1h
- [ ] Always request 16 KiB blocks (16384 bytes) — note in code — 15m
- [ ] Pipeline: maintain 5 outstanding block requests per peer — 1h

### SHA1 Verifier (`src/piece/verifier.rs`)
- [ ] ⚠️ Hash assembled piece bytes with `sha1` crate — 30m
- [ ] ⚠️ Compare against expected hash from `TorrentFile.piece_hashes[index]` — 30m
- [ ] On mismatch: reset piece to `Missing`, log which peer sent the bad blocks — 30m

### Disk Storage (`src/storage/disk.rs`)
- [ ] ⚠️ Pre-allocate output file on startup using `set_len` — 30m
- [ ] ⚠️ Async write of piece data at correct file offset — 1h
- [ ] Run storage in dedicated task, receive via `mpsc` channel — 1h
- [ ] Return `WriteComplete` event to engine after flush — 30m

### Engine Wiring
- [ ] ⚠️ On `PeerEvent::Unchoke`: send `Interested`, start requesting blocks — 1h
- [ ] ⚠️ On `PeerEvent::Piece`: forward block to PieceManager — 1h
- [ ] On `PieceComplete` + `VerifyPass`: dispatch to StorageTask — 30m
- [ ] On `PieceComplete`: broadcast `Have(index)` to all peers — 30m
- [ ] On `PieceComplete`: update local bitfield — 15m
- [ ] Track overall download progress, log % complete — 30m

### CLI
- [ ] Add progress bar or periodic progress log to download subcommand — 1h
- [ ] Implement `rustytorrent download <file.torrent>` — 1h

---

## Phase 5 — Multi-file & Correctness

**Total estimate: ~16h**

### Multi-file Storage
- [ ] ⚠️ Build virtual offset map: piece index + byte offset → file path + file offset — 2h
- [ ] ⚠️ Handle pieces that span multiple files — 1h
- [ ] Pre-allocate all files in multi-file torrent on startup — 1h

### Rarest-First Picker
- [ ] ⚠️ Track `availability: Vec<u32>` (count of peers that have each piece) — 1h
- [ ] Update counts on `PeerEvent::Bitfield` and `PeerEvent::Have` — 1h
- [ ] Replace sequential picker with rarest-first (shuffle ties for fairness) — 1h

### Endgame Mode
- [ ] Detect endgame: fewer than 5 incomplete pieces remain — 30m
- [ ] In endgame: request every missing block from all peers — 1h
- [ ] Send `Cancel` to peers when a block arrives from someone else — 1h

### Choke / Unchoke (`src/scheduler/choke.rs`)
- [ ] ⚠️ Run choking loop every 10 seconds — 30m
- [ ] ⚠️ Track download rate from each peer over 20-second rolling window — 1h
- [ ] ⚠️ Unchoke top 3 peers by rate — 30m
- [ ] ⚠️ 1 optimistic unchoke slot: rotate every 30s — 1h
- [ ] Anti-snubbing: flag peer if no block received in 60s — 30m

### Upload / Seeding
- [ ] Respond to `Request` messages from unchoked peers — 1h
- [ ] Read piece from disk (or LRU cache) and send `Piece` message — 1h
- [ ] Add small `LruCache` for recently-read pieces — 30m

---

## Phase 6 — Hardening & Resume

**Total estimate: ~16h**

### Resume Support
- [ ] ⚠️ On startup: for each piece, SHA1-check existing file bytes — 2h
- [ ] ⚠️ Rebuild local bitfield from verification results — 1h
- [ ] Skip already-verified pieces in the picker — 30m

### Peer Banning
- [ ] Maintain `HashSet<IpAddr>` of banned peers — 30m
- [ ] Ban peer on hash mismatch — 30m
- [ ] Ban peer on repeated protocol violations — 30m
- [ ] Skip banned peers when connecting — 15m

### Incoming Connections
- [ ] ⚠️ Open `TcpListener` on configured port — 30m
- [ ] Accept incoming connections and hand off to PeerManager — 1h
- [ ] Respect max connection cap for incoming peers — 30m

### Graceful Shutdown
- [ ] Trap `SIGINT`/`SIGTERM` with `tokio::signal` — 30m
- [ ] Flush all pending disk writes on shutdown — 30m
- [ ] Send tracker `stopped` event on shutdown — 30m
- [ ] Join all peer tasks cleanly — 30m

### Stability & Polish
- [ ] Stable `peer_id`: generate once, persist to `~/.config/rustytorrent/peer_id` — 30m
- [ ] Rate limiter: configurable max download/upload speed — 2h
- [ ] Bandwidth stats: bytes downloaded/uploaded per torrent — 1h
- [ ] Audit all code paths for `unwrap()` / `expect()` — replace with proper errors — 1h
- [ ] Integration test: download a small public-domain torrent end-to-end in CI — 2h

---

## Phase 7 — Protocol Extensions

**Total estimate: ~40h** (rough, extensions are research-heavy)

### Extension Protocol (BEP 10)
- [ ] Set reserved bytes in handshake to signal support — 30m
- [ ] Implement `extended` message (ID 20) framing — 2h
- [ ] Exchange extension handshake with `m` dict of supported extensions — 2h

### Peer Exchange / PEX (BEP 11)
- [ ] Implement `ut_pex` extension message — 3h
- [ ] Integrate new peers from PEX into PeerManager — 1h

### ut_metadata (BEP 9)
- [ ] Implement `ut_metadata` extension: `request`, `data`, `reject` messages — 4h
- [ ] Reassemble and verify metadata from peers — 2h

### Magnet Links
- [ ] Parse magnet URI (`xt=urn:btih:...`, `tr=...`, `dn=...`) — 1h
- [ ] Bootstrap from trackers in magnet URI — 1h
- [ ] Fetch metadata via ut_metadata before starting download — 1h

### DHT (BEP 5)
- [ ] Kademlia routing table (k-buckets, node ID space) — 8h
- [ ] UDP-based RPC: `ping`, `find_node`, `get_peers`, `announce_peer` — 8h
- [ ] Bootstrap from known DHT nodes — 2h
- [ ] Integrate DHT peers into PeerManager — 1h

---

## Phase 8 — Web UI

**Total estimate: ~24h**

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
- [ ] Run `clippy` with `--deny warnings` in CI
- [ ] Run `cargo fmt` check in CI
- [ ] Keep dependency count lean — evaluate each new crate
