# RustyTorrent — Agent Build Guide

> A step-by-step guide for an AI coding agent to build this project autonomously.
> Read `docs/ARCHITECTURE.md` and `docs/ROADMAP.md` first before starting any work.

---

## Before You Start

**Read these files in order:**
1. `docs/ROADMAP.md` — understand the phases and what "done" looks like at each one
2. `docs/ARCHITECTURE.md` — understand the module layout and data flow
3. `docs/TASKS.md` — your granular checklist; tick items as you complete them
4. `Cargo.toml` — understand what dependencies are already declared

**Never skip a phase.** Each phase's milestone must pass before starting the next. The project is designed to be runnable and testable at every stage.

**Run `cargo check` after every non-trivial change.** Do not accumulate compilation errors. Fix them immediately.

---

## Working Rules

- **One module at a time.** Don't start implementing `tracker/` while `metainfo/` has failing tests.
- **Write the test before marking a task complete.** If a task says "implement X", it's not done until there's at least one test that exercises X.
- **No `unwrap()` in non-test code.** Use `?` and the typed `Error` enum in `src/error.rs`.
- **Add a `tracing::debug!` or `tracing::info!` call to every function that does I/O or async work.** Future debugging depends on it.
- **Keep `docs/TASKS.md` updated.** Mark `[x]` on tasks as you complete them.

---

## Phase 1 — Parse & Inspect

**Goal:** Parse a `.torrent` file and print its contents. No network, no disk I/O beyond reading the file.

### Step 1: Create the bencode module

```
src/metainfo/mod.rs
src/metainfo/bencode.rs
src/metainfo/torrent.rs
```

Uncomment `pub mod metainfo;` in `src/lib.rs`.

**`bencode.rs` — implement this first:**

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum BencodeValue {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<BencodeValue>),
    Dict(std::collections::BTreeMap<Vec<u8>, BencodeValue>),
}

impl BencodeValue {
    pub fn parse(input: &[u8]) -> Result<(BencodeValue, &[u8])> { … }
}
```

The parser is recursive descent over `&[u8]`. Entry point checks the first byte:
- `i` → integer (read until `e`)
- `0-9` → byte string (read length, then colon, then N bytes)
- `l` → list (recurse until `e`)
- `d` → dict (recurse pairs until `e`, keys must be byte strings)

**Write tests before moving on:**
```rust
#[test]
fn test_integer() { assert_eq!(parse(b"i42e"), BencodeValue::Int(42)); }
#[test]
fn test_string() { assert_eq!(parse(b"4:spam"), BencodeValue::Bytes(b"spam".to_vec())); }
#[test]
fn test_nested() { /* test a dict containing a list */ }
```

### Step 2: info_hash — the most critical detail

When parsing the top-level bencode dict, before deserializing the `info` key's value, capture the **raw bytes** of that key's value from the original input slice. SHA1 those raw bytes. That's the `info_hash`. Do not re-serialize — the hash must match the original encoding exactly.

```rust
// Find where "info" value starts and ends in the raw input
// Compute: sha1::Sha1::digest(&raw_info_bytes)
```

### Step 3: TorrentFile structs

Map the parsed bencode into typed structs. Handle both single-file (`info.length`) and multi-file (`info.files`) layouts. Return a clear error if a required field is missing.

### Step 4: Wire up CLI

```
$ cargo run -- info ubuntu.torrent
Name:        ubuntu-22.04-desktop-amd64.iso  
Info hash:   3b4a...f9a  
Piece length: 512 KiB  
Pieces:      2271  
Total size:  3.6 GiB  
Trackers:    udp://tracker.example.com:6969
```

**Phase 1 is complete when:** `cargo test` passes and the above command works on a real `.torrent` file.

---

## Phase 2 — Tracker Communication

**Goal:** Retrieve a peer list from real trackers.

### Step 1: HTTP Tracker

Create `src/tracker/http.rs`. Key things to get right:

- **URL-encode `info_hash` correctly.** It's 20 raw bytes, not hex. Use `urlencoding` or percent-encode each byte manually. Test this — many implementations get it wrong.
- **Compact peer format:** response `peers` is a byte string of 6-byte chunks: `[ip0, ip1, ip2, ip3, port_hi, port_lo]`. Port is big-endian u16.
- **Send `numwant=50`.** Default is often 20, which limits peer discovery.
- **Always send `compact=1`.** Non-compact is deprecated.

### Step 2: UDP Tracker

Create `src/tracker/udp.rs`. Use `tokio::net::UdpSocket`.

The protocol is two round-trips:
1. Connect (get `connection_id`)
2. Announce (send `connection_id`, get peers)

All multi-byte fields are big-endian. Parse with `u64::from_be_bytes([…])` etc. — no external binary parsing library needed.

Implement retry: wait 15s, then 30s, then 60s (multiply by 2 each time), give up after 8 attempts.

### Step 3: Tracker selection

Try the first tracker in `announce-list`. If it fails, try the next. Move successful trackers to the front of their tier (this is the standard behavior from BEP 12).

### Step 4: CLI

```
$ cargo run -- peers ubuntu.torrent
Found 50 peers:
  203.0.113.1:6881
  198.51.100.44:51413
  …
```

**Phase 2 is complete when:** you can retrieve real peers from both an HTTP and a UDP tracker.

---

## Phase 3 — Peer Handshake & Messaging

**Goal:** Connect to peers and exchange bitfields. No downloading.

### Step 1: Set up the async task architecture

This is the most important structural decision in the project. Get it right now.

The pattern for every peer task:

```rust
// In src/peer/connection.rs
pub async fn run_peer(
    stream: TcpStream,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    event_tx: mpsc::Sender<PeerEvent>,     // sends events TO engine
    mut cmd_rx: mpsc::Receiver<PeerCommand>, // receives commands FROM engine
) -> Result<()> {
    // 1. Handshake
    // 2. select! loop: read from stream OR receive from cmd_rx
}
```

The engine owns a `HashMap<PeerId, mpsc::Sender<PeerCommand>>` to send commands to specific peers.

### Step 2: Handshake

Send then receive (outgoing) or receive then send (incoming). Verify `info_hash` matches. If it doesn't, close the connection — this is a security check.

### Step 3: Message framing

```rust
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 { return Ok(vec![]); } // keep-alive
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}
```

### Step 4: Engine setup

Create `src/engine.rs` with the central `select!` loop. For Phase 3, it just needs to:
- Accept `PeerEvent::Bitfield` and log it
- Accept `PeerEvent::Have` and log it

Add the `TorrentEngine::run()` method and call it from `main.rs`.

**Phase 3 is complete when:** you connect to 10 real peers, complete handshakes, and log their bitfields without crashing.

---

## Phase 4 — Core Downloading

**Goal:** Download a real single-file torrent end-to-end.

### Step 1: PieceManager

The state machine for pieces. Critical correctness requirement: a piece is only written to disk after SHA1 verification passes. Never write unverified data.

Track at block granularity (16384 bytes). A piece of length `piece_length` has `ceil(piece_length / 16384)` blocks. The last block of the last piece may be smaller.

### Step 2: Pipelining

**This is the single biggest performance lever.** Always keep 5 block requests outstanding per unchoked peer. The moment you receive a block, send the next request immediately to refill the pipeline.

```rust
// After receiving Piece(index, begin, data):
piece_manager.received_block(index, begin, &data);
send_next_request_if_needed(&peer_handle, &mut piece_manager);
```

Without pipelining you'll get ~1/5th the achievable speed.

### Step 3: Disk storage

Pre-allocate the file on startup. Write blocks as they arrive from the verifier (not before). Use a dedicated tokio task so disk I/O doesn't block the async runtime.

### Step 4: Wire it together in the engine

The engine's select! loop needs to handle:
- `PeerEvent::Unchoke` → send `Interested` + start requesting blocks
- `PeerEvent::Piece` → forward to PieceManager → if piece complete, verify → if pass, write to disk
- `StorageEvent::Written` → broadcast `Have(index)` to all peers, update bitfield

### Step 5: Testing

Download a small, well-seeded, public domain torrent (e.g., an old Linux ISO or a Project Gutenberg ebook collection). Verify the downloaded file's SHA1 matches the expected value.

**Phase 4 is complete when:** a single-file torrent downloads completely and the file is valid.

---

## Phase 5 — Multi-file & Correctness

### Multi-file virtual offset map

Build this once and cache it. The map converts `(piece_index, byte_offset_in_piece)` to `Vec<(file_path, file_offset, byte_count)>` — a single piece can map to multiple files.

```rust
fn map_piece_to_files(
    piece_index: usize,
    piece_length: u64,
    files: &[FileEntry],
) -> Vec<FileWrite> { … }
```

### Rarest-first picker

Maintain `availability: Vec<u32>` initialized to zeros. Increment on `Bitfield` (for each set bit) and `Have` messages. Decrement on `Have` from yourself (you don't need what you have).

For selection: collect all `Missing` pieces, sort by `availability[i]` ascending, shuffle within equal groups, return the first.

### Endgame mode

Trigger when: `pieces_remaining < 5` (tune this). In endgame, for each missing block, send `Request` to every peer that has that piece. Track which peers got which requests so you can send `Cancel` messages when the block arrives from the first responder.

### Choke/Unchoke

Run on a `tokio::time::interval` every 10 seconds. Keep a rolling 20-second window of bytes received per peer (use a `VecDeque<(Instant, u64)>` per peer). Sort, unchoke top 3, rotate optimistic slot every 30 seconds.

**Phase 5 is complete when:** multi-file torrents download correctly and speed is reasonable (>1 MB/s on a well-seeded torrent on a fast connection).

---

## Phase 6 — Hardening

### Resume support

On startup (before connecting to any peers), iterate over every piece and SHA1-verify its bytes from the existing file. This is slow — log progress. Build the bitfield from results. Tell the tracker `downloaded = verified_bytes`.

### Graceful shutdown

```rust
tokio::select! {
    _ = tokio::signal::ctrl_c() => {
        tracing::info!("Shutting down");
        // send stopped to tracker
        // flush storage
        // drop all peer tasks
    }
}
```

### Peer banning

```rust
struct BanList(HashSet<IpAddr>);
```

Ban on: SHA1 mismatch (they sent us corrupt data), repeated protocol violations, sending invalid message formats.

**Phase 6 is complete when:** the client can be interrupted and resumed, and runs stably for multi-hour downloads.

---

## Lessons from Other Clients

These are findings from studying libtorrent, Transmission, cratetorrent, and aria2:

**Connection limits (Transmission defaults):** 60 peers per torrent, 240 global. Start here; tune later. Too many connections hurts performance on most systems due to router/NAT limits.

**Disk I/O (libtorrent approach):** Use a store-buffer — accumulate blocks in memory until all blocks of a piece arrive, then flush the entire piece in one write (using `writev` if available). This is more efficient than writing each 16 KiB block individually. Implement this in Phase 4 or 5.

**Rarest-first (libtorrent):** operates at the *block* level, not the *piece* level. It tracks partially-downloaded pieces and prefers to finish them before starting new ones. Implement piece-level rarest-first first, then upgrade if performance demands it.

**Endgame trigger (libtorrent):** triggers when the number of outstanding requests exceeds the number of missing blocks — i.e., when every missing block is already requested. This is more precise than a fixed piece count threshold. Consider implementing this in Phase 5.

**Choke algorithm:** all major clients use exactly 3 regular + 1 optimistic unchoke. No production client has meaningfully deviated from this. Don't reinvent it.

**Cratetorrent (Rust) — slow-start congestion control:** increment the request queue size by 1 per block received; back off if throughput gain < 10 KB/s. This avoids flooding slow peers with requests. Consider adding this on top of the fixed-5-pipeline approach in Phase 5.

---

## Common Mistakes to Avoid

| Mistake | Consequence | Fix |
|---|---|---|
| Re-encoding `info` dict for `info_hash` | Hash mismatch, no peers connect | Capture raw bytes during parse |
| URL-encoding `info_hash` as hex | Tracker rejects announce | Percent-encode raw 20 bytes |
| Requesting blocks larger than 16 KiB | Peers close connection | Always use exactly 16384 |
| No block pipelining | ~5x slower than achievable | Always keep 5 requests in flight |
| Writing before SHA1 verification | Corrupt downloads that pass | Verify, then write |
| `unwrap()` in peer read loop | Single bad peer crashes client | Propagate errors, disconnect peer |
| Regenerating `peer_id` each run | Poor citizen, some trackers may ban | Persist to config dir |

---

## Verification Checklist (run before calling a phase complete)

- [ ] `cargo test` passes with zero failures
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] The phase's milestone command works on a real `.torrent` file
- [ ] No `unwrap()` or `expect()` in non-test code (search: `grep -r "\.unwrap()" src/`)
- [ ] All new public functions have a `tracing` call
- [ ] `docs/TASKS.md` tasks for this phase are marked `[x]`
