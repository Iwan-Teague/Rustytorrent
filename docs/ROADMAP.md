# RustyTorrent — Roadmap

> A BitTorrent client built in Rust. Fast, correct, and a joy to hack on.

---

## Vision

RustyTorrent aims to be a fully-featured, production-quality BitTorrent client written in idiomatic Rust. The long-term goal is spec compliance with the core BEP suite, a clean async architecture, and an optional web UI — built incrementally in phases so the project is usable at every stage.

---

## Status

| Phase | Name | Status |
|-------|------|--------|
| 1 | Parse & Inspect | 🔲 Not started |
| 2 | Tracker Communication | 🔲 Not started |
| 3 | Peer Handshake & Messaging | 🔲 Not started |
| 4 | Core Downloading | 🔲 Not started |
| 5 | Multi-file & Correctness | 🔲 Not started |
| 6 | Hardening & Resume | 🔲 Not started |
| 7 | Extensions | 🔲 Not started |
| 8 | Web UI | 🔲 Not started |

---

## Phase 1 — Parse & Inspect
**Target: Week 1**

The foundation. Every other component depends on being able to read a `.torrent` file correctly.

### Goals
- Implement a bencode parser (`BencodeValue` enum: integer, byte string, list, dict)
- Deserialize `TorrentFile` and `Info` structs from parsed bencode
- Compute the `info_hash` (SHA1 of the raw bencoded `info` dict bytes)
- Build the first CLI subcommand: `rustytorrent info <file.torrent>`

### Milestone
```
$ rustytorrent info ubuntu-22.04.torrent
Name:        ubuntu-22.04-desktop-amd64.iso
Info hash:   3b4…f9a
Pieces:      2271 × 512 KiB
Total size:  3.6 GiB
Files:       1
Trackers:    2
```

### Out of scope
Network I/O of any kind.

---

## Phase 2 — Tracker Communication
**Target: Week 1–2**

Get a peer list from real trackers.

### Goals
- HTTP tracker: `GET /announce` with correct query params, parse compact peer response
- UDP tracker: connect → announce sequence with retry/backoff
- Respect `interval` and `min interval` for re-announces
- CLI subcommand: `rustytorrent peers <file.torrent>`

### Milestone
```
$ rustytorrent peers ubuntu-22.04.torrent
192.168.1.10:6881
203.0.113.44:51413
[... 48 more peers]
```

### Out of scope
Connecting to any of those peers.

---

## Phase 3 — Peer Handshake & Messaging
**Target: Week 2–3**

Speak the BitTorrent wire protocol. No downloading yet.

### Goals
- BitTorrent handshake (19-byte preamble, reserved bytes, info_hash, peer_id)
- All standard wire messages: Choke, Unchoke, Interested, NotInterested, Have, Bitfield, Request, Piece, Cancel
- Async per-peer task with mpsc channel back to engine
- PeerManager: connect to up to 50 peers, handle disconnects
- Log peer bitfields to understand what they have

### Milestone
Connect to 10+ peers and exchange bitfields without crashing.

### Out of scope
Requesting or writing any blocks.

---

## Phase 4 — Core Downloading
**Target: Week 3–4**

Download a real file end-to-end.

### Goals
- PieceManager: track piece and block state
- Sequential piece picker (rarest-first comes in Phase 5)
- Block requests pipelined (5 outstanding per peer)
- SHA1 piece verification
- Async disk writes with pre-allocated file
- Broadcast `Have` to all peers on piece completion
- Progress display in CLI

### Milestone
Download a small single-file torrent (e.g., a Linux ISO) completely and correctly.

### Out of scope
Multi-file torrents, uploading/seeding.

---

## Phase 5 — Multi-file & Correctness
**Target: Week 4–5**

Make the client correct, not just functional.

### Goals
- Multi-file torrent support (virtual offset mapping across files)
- Rarest-first piece selection
- Endgame mode (request missing blocks from all peers simultaneously)
- Full choke/unchoke algorithm (3 regular + 1 optimistic unchoke slot)
- Upload / seeding to peers
- Anti-snubbing (peer hasn't sent a block in 60s → optimistic unchoke elsewhere)

### Milestone
Download a multi-file torrent at reasonable speed and seed back to peers.

---

## Phase 6 — Hardening & Resume
**Target: Week 5–6**

Make the client reliable enough to leave running unattended.

### Goals
- Peer banning (hash mismatch, protocol violations)
- Incoming connection listener (be connectable, not just outbound)
- Resume support: on startup, SHA1-scan existing files and rebuild bitfield
- Graceful shutdown: flush disk writes, send `stopped` event to tracker
- Rate limiting and per-torrent bandwidth stats
- Stable `peer_id` persisted to `~/.config/rustytorrent/peer_id`
- Comprehensive error handling — no panics or unwraps in non-test code

### Milestone
The client is usable for real, multi-hour downloads. It can be interrupted and resumed.

---

## Phase 7 — Protocol Extensions
**Target: Month 2–3**

Stretch goals that make RustyTorrent a first-class citizen in the BitTorrent ecosystem.

### Goals (in priority order)
1. **Extension Protocol (BEP 10)** — prerequisite handshake extension for all below
2. **Peer Exchange / PEX (BEP 11)** — peers share peer lists, reduces tracker dependency
3. **ut_metadata (BEP 9)** — fetch torrent metadata from peers
4. **Magnet links** — depends on DHT + ut_metadata
5. **DHT (BEP 5)** — Kademlia distributed hash table for trackerless operation

---

## Phase 8 — Web UI
**Target: Month 3+**

A browser-based interface for monitoring and controlling downloads.

### Goals
- `axum`-based JSON REST API
- Endpoints: list torrents, add torrent (file or magnet), remove, pause/resume, peer list, stats
- Small SPA frontend (vanilla JS or minimal framework)
- Speed graphs, piece progress visualization
- Prometheus metrics endpoint (`/metrics`)

---

## Stretch Goals (no timeline)

- IPv6 support
- Selective file download within multi-file torrents
- i2p / Tor transport support
- Plugin system for custom piece pickers

---

## Principles

- **Usable at every phase** — each milestone ships something that works
- **No unsafe** — the whole client should be achievable in safe Rust
- **No panics in production paths** — every `?` should propagate a typed error
- **Test at the boundaries** — bencode, SHA1 verification, and piece state are pure functions and should have thorough unit tests
