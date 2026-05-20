# RustyTorrent — Architecture Overview

---

## Design Principles

1. **Everything is a task.** Each major subsystem (tracker, each peer, disk I/O) runs in its own `tokio::spawn`'d task. They never call each other directly.
2. **Communicate through channels.** All cross-task coordination uses `tokio::sync::mpsc` channels. The engine is the hub; modules are spokes.
3. **No shared mutable state at top level.** Shared state is isolated behind `Arc<RwLock<>>` only where unavoidable (e.g. the piece availability table that all peer tasks read from).
4. **Fail loudly in tests, fail gracefully in production.** No `unwrap()` outside tests. Every error propagates through the typed `Error` enum.

---

## High-Level Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI (clap)                             │
│              rustytorrent [info|peers|download] …               │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                       TorrentEngine                             │
│                    (central select! loop)                       │
│                                                                 │
│   ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌────────────┐  │
│   │ Tracker  │  │  Peer    │  │   Piece    │  │  Storage   │  │
│   │ Manager  │  │ Manager  │  │  Manager   │  │   Task     │  │
│   └────┬─────┘  └────┬─────┘  └─────┬──────┘  └─────┬──────┘  │
│        │              │              │                │         │
│   mpsc channels flow up to engine, commands flow down          │
└─────────────────────────────────────────────────────────────────┘
                               │
                     ┌─────────┴────────┐
                     │                  │
               ┌─────▼──────┐    ┌──────▼─────┐
               │  Tracker   │    │  Peer conn  │
               │  HTTP/UDP  │    │  tasks (N)  │
               └────────────┘    └─────────────┘
```

---

## Module Reference

### `engine.rs` — TorrentEngine

The session coordinator. Owns all channel endpoints and runs a central `tokio::select!` loop that dispatches events.

**Inputs (receives from):**
- `TrackerEvent` — new peer list from tracker
- `PeerEvent` — messages from individual peer tasks (Bitfield, Piece, Have, Choke, etc.)
- `VerifyResult` — pass/fail from the piece verifier
- `StorageEvent` — write confirmed

**Outputs (sends to):**
- `TrackerCommand` — re-announce, stop
- `PeerCommand` — Request, Cancel, Have, Choke/Unchoke
- `StorageCommand` — write piece to disk
- `SchedulerTick` — trigger choke recalculation

The engine should never do heavy computation — it routes events and updates lightweight state.

---

### `metainfo/` — Torrent File Parsing

**`bencode.rs`**
Pure parser. Input: `&[u8]`. Output: `BencodeValue` tree. No I/O.

```
BencodeValue
  ├── Int(i64)
  ├── Bytes(Vec<u8>)
  ├── List(Vec<BencodeValue>)
  └── Dict(BTreeMap<Vec<u8>, BencodeValue>)
```

**`torrent.rs`**
Deserialization layer on top of bencode. Key types:

```rust
pub struct TorrentFile {
    pub info_hash: [u8; 20],
    pub announce: Option<String>,
    pub announce_list: Vec<Vec<String>>,
    pub info: Info,
}

pub struct Info {
    pub name: String,
    pub piece_length: u64,
    pub piece_hashes: Vec<[u8; 20]>,   // parsed from raw `pieces` bytes
    pub files: TorrentFiles,
}

pub enum TorrentFiles {
    Single { length: u64 },
    Multi { files: Vec<FileEntry> },
}
```

**Critical:** `info_hash` is SHA1 of the *raw bencoded bytes* of the `info` key. These must be captured during parsing before any deserialization.

---

### `tracker/` — Announce

**`http.rs`** — HTTP tracker (BEP 3)

Announce URL format:
```
GET /announce
  ?info_hash=<20-byte SHA1 URL-encoded>
  &peer_id=<20 bytes>
  &port=6881
  &uploaded=0
  &downloaded=0
  &left=<total bytes>
  &compact=1
  &event=started
  &numwant=50
```

Compact peer response: consecutive 6-byte chunks. Bytes 0–3 = IPv4 (big-endian), bytes 4–5 = port (big-endian).

**`udp.rs`** — UDP tracker (BEP 15)

```
Step 1: Connect
  Send: [0x41727101980 (8B), action=0 (4B), transaction_id (4B)]
  Recv: [action=0 (4B), transaction_id (4B), connection_id (8B)]

Step 2: Announce
  Send: [connection_id (8B), action=1 (4B), transaction_id (4B),
         info_hash (20B), peer_id (20B), downloaded (8B), left (8B),
         uploaded (8B), event (4B), ip=0 (4B), key (4B),
         num_want=-1 (4B), port (2B)]
  Recv: [action=1 (4B), transaction_id (4B), interval (4B),
         leechers (4B), seeders (4B), peers[] (6B each)]
```

Retry on timeout: 15s × 2^n, max 8 attempts.

---

### `peer/` — Wire Protocol

**`handshake.rs`**

```
Outgoing:
  [0x13]                        ← length of "BitTorrent protocol"
  "BitTorrent protocol"         ← 19 bytes
  [0x00 × 8]                   ← reserved (set bits for extensions)
  info_hash                     ← 20 bytes
  peer_id                       ← 20 bytes

Incoming: same structure, verify info_hash matches
```

Reserved byte conventions (set if supported):
- Byte 5, bit 4: DHT (BEP 5)
- Byte 7, bit 0: Extension Protocol (BEP 10)

**`message.rs`** — Wire message types

| Length | ID | Name | Payload |
|--------|----|------|---------|
| 0 | — | KeepAlive | — |
| 1 | 0 | Choke | — |
| 1 | 1 | Unchoke | — |
| 1 | 2 | Interested | — |
| 1 | 3 | NotInterested | — |
| 5 | 4 | Have | piece_index (4B) |
| 1+N | 5 | Bitfield | bitfield bytes |
| 13 | 6 | Request | index (4B), begin (4B), length (4B) |
| 9+N | 7 | Piece | index (4B), begin (4B), block data |
| 13 | 8 | Cancel | index (4B), begin (4B), length (4B) |

Frame format: `[length: u32 BE][id: u8][payload…]`

**`connection.rs`** — Per-peer async task

Each peer connection is **two** independent tasks sharing a `oneshot` for
shutdown signalling:

```
let (reader, writer) = stream.into_split();
let (read_done_tx, read_done_rx) = oneshot::channel();

// Read-only task.
tokio::spawn(async move {
    let res = loop {
        let frame = read_frame(&mut reader).await?;
        let msg = Message::decode(&frame)?;
        event_tx.send(msg_to_event(addr, msg)).await?;
    };
    let _ = read_done_tx.send(res);
});

// Write-only loop (runs in run_with_stream's stack).
loop {
    select! {
        cmd = cmd_rx.recv() => write_frame(&mut writer, cmd.encode()).await?,
        _   = sleep(until_next_keepalive) => write_frame(&mut writer, &[]).await?,
        res = &mut read_done_rx => return res,
    }
}
```

**Why split**: a naive single-task `select!` between `read_frame` and
`cmd_rx.recv()` is a footgun. `read_frame` calls `AsyncReadExt::read_exact`,
which is **not** cancel-safe. If `select!` drops a half-completed read (e.g.
two of four length-prefix bytes already pulled), those bytes are lost, the
next read restarts at a wrong offset, and a payload byte gets interpreted as
a length prefix. The symptom is a `frame too large: 1398791722` log right
after the seeder starts streaming Piece messages, and the connection dies.
Running reader and writer on independent tasks sidesteps the cancellation
entirely — neither future ever gets dropped mid-await.

**`manager.rs`** — Connection pool

- `HashMap<PeerId, PeerHandle>` where `PeerHandle = mpsc::Sender<PeerCommand>`
- Caps at 50 total connections
- Maintains half-open connection throttle (don't open 50 simultaneously)
- Reconnect with exponential backoff

---

### `piece/` — Piece State Machine

**State transitions:**

```
Missing
  └─→ Requested { blocks_pending: BitVec }
        ├─→ Missing          (on verify fail or peer disconnect before complete)
        └─→ Verifying
              ├─→ Missing    (on SHA1 mismatch)
              └─→ Complete   (on SHA1 match)
```

**`manager.rs`**

Owns the full piece state table. Answers questions like:
- "Which pieces do I need?" → feed to picker
- "Which blocks of piece X are still missing?" → feed to request logic
- "Is piece X complete?" → trigger verification

**`picker.rs`** — Piece selection

Strategies (in order of activation):
1. **Random** — for first 4 pieces (get *something* as fast as possible for seeding)
2. **Rarest-first** — default; requires `availability: Vec<u32>` updated from Bitfield/Have
3. **Endgame** — when <5 incomplete pieces remain: request all missing blocks from all peers

Within equal-rarity groups, always shuffle to avoid thundering herd on the same piece.

**Block pipelining:** always maintain 5 outstanding `Request` messages per unchoked peer. Waiting for one block at a time per peer gives ~1/5th the throughput.

**`verifier.rs`**

```rust
pub fn verify(index: usize, data: &[u8], expected: &[u8; 20]) -> bool {
    sha1::Sha1::digest(data).as_slice() == expected
}
```

Called after all blocks of a piece have arrived. On failure: reset piece to `Missing`, log the contributing peer IDs.

---

### `storage/` — Disk I/O

**`disk.rs`**

Virtual offset mapping for multi-file torrents:

```
piece_index, byte_offset_within_piece
    │
    ▼
global_offset = piece_index × piece_length + byte_offset
    │
    ▼
find file where file.start_offset ≤ global_offset < file.end_offset
    │
    ▼
file_offset = global_offset - file.start_offset
```

A single piece can span multiple files. The write path must split the block across file boundaries.

Pre-allocate all files on startup using `File::set_len` — this prevents fragmentation and lets the OS reserve the space up front.

Runs as a dedicated task to avoid blocking the async runtime on disk syscalls. Uses `tokio::fs`.

LRU cache for recently-read pieces (used for upload). Start with size 32 pieces.

---

### `scheduler/` — Choke Algorithm

**Runs every 10 seconds.**

**Leeching mode** (we still have pieces to download):
1. Rank all currently-unchoked-by-them peers by download rate from them over the last 20 seconds
2. Unchoke the top 3
3. Every 30 seconds, rotate the **optimistic unchoke** slot to a randomly-selected currently-choked peer

**Seeding mode** (we have 100% of pieces):
1. Rank peers by upload rate *to* them
2. Unchoke the top 3 (rewarding peers that are downloading from us)
3. Keep 1 optimistic unchoke slot rotating every 30 seconds

**Anti-snubbing:** if a peer has been unchoked by us for >60 seconds without sending us a single block, mark them as snubbed and replace them with the next optimistic unchoke candidate.

---

## Data Flow: Block Received → Written to Disk

```
[1] Peer TCP stream
      └─ read_frame() in peer task

[2] PeerConnection task
      └─ decode Message::Piece { index, begin, data }
      └─ send PeerEvent::Block { peer_id, index, begin, data }
             over mpsc channel

[3] TorrentEngine (select! loop)
      └─ receive PeerEvent::Block
      └─ forward to PieceManager

[4] PieceManager
      └─ mark block (index, begin) as received
      └─ if all blocks for piece `index` received:
           └─ emit PieceAssembled { index, data }

[5] Verifier (called inline or as subtask)
      └─ SHA1(data) == piece_hashes[index]?
      └─ yes → emit VerifyResult::Pass { index, data }
      └─ no  → emit VerifyResult::Fail { index }
               → PieceManager resets piece to Missing

[6] Engine receives VerifyResult::Pass
      └─ send StorageCommand::Write { index, data } to StorageTask

[7] StorageTask
      └─ map piece to file offset(s)
      └─ tokio::fs write
      └─ send StorageEvent::Written { index }

[8] Engine receives StorageEvent::Written
      └─ update local bitfield
      └─ send PeerCommand::Have(index) to ALL peers via PeerManager
      └─ update piece availability counts
      └─ update progress stats
```

---

## Configuration (`config.toml`)

```toml
[network]
listen_port = 6881
max_peers = 50
max_half_open = 10

[transfer]
max_download_rate = 0    # 0 = unlimited (bytes/sec)
max_upload_rate = 0

[storage]
download_dir = "~/Downloads"
piece_cache_size = 32    # pieces

[identity]
peer_id_file = "~/.config/rustytorrent/peer_id"
```

---

## Error Handling Strategy

```rust
// src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bencode parse error: {0}")]
    Bencode(String),
    #[error("tracker error: {0}")]
    Tracker(String),
    #[error("peer handshake failed: {0}")]
    Handshake(String),
    #[error("piece verification failed for index {index}")]
    VerifyFailed { index: usize },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    // …
}

pub type Result<T> = std::result::Result<T, Error>;
```

Use `thiserror` throughout the library. Use `anyhow` only in `main.rs` for top-level reporting.

---

## Dependency Summary

Every BitTorrent-specific behavior in this crate is hand-written. The
dependencies are domain-agnostic foundations only — none of them know what
a torrent is.

```toml
[dependencies]
tokio        = { version = "1", features = ["full"] }       # async runtime
reqwest      = { version = "0.12", features = ["rustls-tls"], default-features = false }  # HTTP GET for HTTP-tracker only
sha1         = "0.10"                                        # RustCrypto SHA-1 primitive
bitvec       = "1"                                           # generic bit-vector
clap         = { version = "4", features = ["derive"] }      # CLI parser
thiserror    = "1"                                           # derive macro for the Error enum
anyhow       = "1"                                           # only used in main.rs
tracing      = "0.1"                                         # structured logging
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rand         = "0.8"                                         # peer_id, transaction_id, picker shuffle
num-bigint   = "0.4"                                         # 768-bit DH for MSE/PE
num-traits   = "0.2"                                         # Zero/One traits for num-bigint
lru          = "0.12"                                        # generic LRU container for the upload cache
```

What is hand-written (not pulled in from any crate):

| Concern | Module | Notes |
|---|---|---|
| Bencode decode | [`metainfo/bencode.rs`](../src/metainfo/bencode.rs) | Recursive-descent parser. Hand-written because `info_hash` requires the raw byte span of the `info` dict, awkward via serde. |
| `.torrent` deserialization | [`metainfo/torrent.rs`](../src/metainfo/torrent.rs) | Walks the bencode tree into typed structs; manual raw-byte scan finds the `info` value span and SHA1s it. |
| Percent encoding for trackers | [`tracker/http.rs::percent_encode`](../src/tracker/http.rs) | RFC 3986 unreserved-only encoder for raw 20-byte `info_hash` / `peer_id`. |
| HTTP tracker request + response | [`tracker/http.rs`](../src/tracker/http.rs) | URL built by hand; response parsed by our own bencode parser. |
| UDP tracker protocol (BEP 15) | [`tracker/udp.rs`](../src/tracker/udp.rs) | 16-byte connect / 98-byte announce packet hand-laid; retry/timeout per spec. |
| Peer-ID generation | [`peer_id.rs`](../src/peer_id.rs) | Azureus-style `-RT0100-` + 12 random printable bytes. |
| BitTorrent handshake | [`peer/handshake.rs`](../src/peer/handshake.rs) | 68-byte buffer encode/decode; `perform_outgoing` / `perform_incoming`. |
| Wire-message codec | [`peer/message.rs`](../src/peer/message.rs) | Encode/decode for IDs 0–8, 4-byte BE length prefix framing, strict bitfield (spare bits must be zero). |
| Per-peer task | [`peer/connection.rs`](../src/peer/connection.rs) | `tokio::select!` between socket reads, command channel, and keep-alive timer. No library wraps this. |
| Peer pool | [`peer/manager.rs`](../src/peer/manager.rs) | `HashMap<SocketAddr, PeerSlot>`, cap + ban list, outgoing dial + incoming accept. |
| Piece + block state machine | [`piece/manager.rs`](../src/piece/manager.rs) | Per-piece `Missing` / `InProgress` / `Complete`; per-block `requested` + `received` bitmaps. |
| Rarest-first picker + endgame | [`piece/picker.rs`](../src/piece/picker.rs) | Availability table from `Bitfield` + `Have`, tie-shuffle, sticky per-peer assignment. |
| SHA-1 piece verifier | [`piece/verifier.rs`](../src/piece/verifier.rs) | Thin wrapper around the `sha1` primitive — the only "library" call. |
| File layout / piece↔file map | [`storage/layout.rs`](../src/storage/layout.rs) | Virtual offset map; one piece → many `(file, offset, count)` slices. |
| Disk task (write / read / resume scan) | [`storage/disk.rs`](../src/storage/disk.rs) | `tokio::fs` for I/O; everything around it (pre-allocate, write fan-out across files, SHA1 rescan) is our own. |
| Choke algorithm (BEP 3) | [`scheduler/choke.rs`](../src/scheduler/choke.rs) | 3 regular + 1 optimistic unchoke slots; 20-s rolling rate window per peer; anti-snubbing. |
| Central engine | [`engine.rs`](../src/engine.rs) | `tokio::select!` hub for all channels; pipelining at depth 5; tracker re-announce; broadcast `Have` after writes; ctrl-c shutdown. |
| RC4 stream cipher | [`peer/mse/rc4.rs`](../src/peer/mse/rc4.rs) | 256-byte S-box, key schedule, PRGA, 1024-byte discard helper. Includes known-answer test against the classic `"Key"` / `"Plaintext"` vector. |
| 768-bit Diffie-Hellman | [`peer/mse/dh.rs`](../src/peer/mse/dh.rs) | RFC 2409 Oakley Group 1 prime + generator 2; mod-exp delegated to `num-bigint`. |
| MSE/PE handshake | [`peer/mse/handshake.rs`](../src/peer/mse/handshake.rs) | Initiator and receiver flows including `HASH(req1,S)` / `HASH(req2,SKEY) XOR HASH(req3,S)` sync, encrypted VC alignment, `crypto_provide`/`crypto_select` negotiation, PadA/B/C/D handling. |
| RC4 stream wrappers | [`peer/mse/stream.rs`](../src/peer/mse/stream.rs) | `EncryptedStream`, `Rc4Reader`, `Rc4Writer` implementing `AsyncRead` / `AsyncWrite` over an inner socket and a per-direction `Rc4` keystream. |
| Plain-vs-MSE dispatch | [`peer/connection.rs`](../src/peer/connection.rs) | Outgoing: tries plain first, falls back to MSE on the signature failures of MSE-only peers. Incoming: peeks first byte; `\x13` → plain, anything else → MSE. `--encrypt` forces MSE-only for outgoing. |
| 160-bit NodeId + XOR distance | [`dht/node_id.rs`](../src/dht/node_id.rs) | Kademlia ID space; bucket index = highest differing bit. |
| K-bucket routing table | [`dht/routing.rs`](../src/dht/routing.rs) | 160 buckets × K=8 contacts; LRU within each bucket; "good" contacts (seen <15 min) win against stale ones. |
| KRPC bencode codec | [`dht/krpc.rs`](../src/dht/krpc.rs) | Encode/decode for ping / find_node / get_peers / announce_peer queries + their three response shapes + error. Verified against the BEP 5 sample-ping wire bytes. |
| DHT UDP server | [`dht/server.rs`](../src/dht/server.rs) | Owns the socket, transaction-id table, peer store, and token salt; answers inbound queries; runs iterative `get_peers` with α=3 parallel and a 15-second budget. |
| DHT persistence | [`dht/persist.rs`](../src/dht/persist.rs) | `node_id` + routing-table snapshot saved every 5 minutes (and on graceful shutdown) to `$XDG_CONFIG_HOME/rustytorrent/dht_state`; trivial inspect-with-xxd binary format. |
| LRU upload cache | [`storage/cache.rs`](../src/storage/cache.rs) | Whole-piece cache for the upload path. First Request triggers a disk read of the full piece; subsequent blocks for the same piece are served from RAM. Default 32 pieces (~8 MiB upper bound). |
| SOCKS5 client (RFC 1928 + RFC 1929) | [`socks5.rs`](../src/socks5.rs) | Hand-rolled outgoing CONNECT through a SOCKS5 proxy, with optional username/password auth. Used by every peer dial and (transitively, via `reqwest`'s socks feature) by HTTP-tracker requests. |
| Anonymous-mode bundle | [`engine.rs`](../src/engine.rs) | When `--anonymous` is set: refuse to start without a proxy, suppress the inbound TCP listener, force DHT off, force `port=0` in tracker announces, and use an ephemeral non-persisted peer_id. Documented in [docs/ANONYMITY.md](ANONYMITY.md). |

---

## Implemented CLI

```
rustytorrent info <file>                       # Phase 1: parse + display
rustytorrent peers <file> [--port N] [--numwant N]   # Phase 2: live tracker query
rustytorrent download <file>                   # Phase 4+: full client
    [--output DIR]
    [--port N]
    [--peer host:port]      (repeatable — direct-dial in addition to/instead of tracker)
    [--no-tracker]          (skip tracker, use --peer / --dht exclusively)
    [--encrypt]             (force outgoing MSE/PE; skip the plain attempt)
    [--dht]                 (enable BEP 5 DHT for trackerless peer discovery)
    [--socks5 host:port]    (route peer + tracker traffic through SOCKS5)
    [--socks5-user U]       (optional RFC 1929 username; requires --socks5)
    [--socks5-pass P]       (optional RFC 1929 password; requires --socks5-user)
    [--anonymous]           (strict bundle: requires --socks5; DHT off, listener off,
                            ephemeral peer_id, port=0 in announces)
```
