# RustyTorrent — Roadmap

> A peer-to-peer file transfer client built in Rust. Fast, correct, and a joy to hack on.

---

## Vision

RustyTorrent aims to be a fully-featured, production-quality peer-to-peer file transfer client written in idiomatic Rust. The long-term goal is spec compliance with the core BEP suite, a clean async architecture, and an optional web UI — built incrementally in phases so the project is usable at every stage.

---

## Status

| Phase | Name | Status |
|-------|------|--------|
| 1 | Parse & Inspect | ✅ Done |
| 2 | Tracker Communication | ✅ Done |
| 3 | Peer Handshake & Messaging | ✅ Done |
| 4 | Core Downloading | ✅ Done |
| 5 | Multi-file & Correctness | ✅ Done |
| 6 | Hardening & Resume | ✅ Done |
| 7 | Extensions | ✅ MSE/PE + DHT + BEP 9/10/11 + magnet + µTP (BEP 29, SACK + LEDBAT) |
| 8 | Web UI | 🟡 `--web`: status page (progress, sparkline, per-file, peers) + JSON + Prometheus + **pause/resume**; multi-torrent add/remove still needs a daemon |

**Anonymity / security**:
- Built-in SOCKS5 client (RFC 1928 + RFC 1929 auth) for outgoing peer
  dials and HTTP-tracker requests.
- `--anonymous` bundle: requires `--socks5`, disables the inbound TCP
  listener, disables DHT, randomizes peer_id per session, zeroes `port` in
  tracker announces. See [docs/ANONYMITY.md](ANONYMITY.md) for the threat model.
- MSE/PE wire encryption (BEP 8) for transport obfuscation; pair with
  `--encrypt` to force MSE on every outbound dial.

**Last verified:**
- Localhost self-test (seeder ↔ leecher) — plain path: 32 MiB single-file
  torrent in ~1 s, MD5 byte-identical.
- Localhost self-test with `--encrypt` (forces outgoing MSE/PE) — same torrent
  in ~2 s, MD5 byte-identical.
- Real public swarm via **tracker** (Debian 13.5 amd64-netinst.iso, 755 MiB) —
  427/3020 pieces (~109 MiB, 14 %) downloaded in 60 s at ~1.9 MB/s. Plain →
  MSE fallback catches MSE-only peers automatically.
- Real public swarm via **DHT** alone (`--no-tracker --dht`, same torrent) —
  985/3020 pieces (~253 MiB, 32 %) downloaded in 90 s at ~2.8 MB/s. Bootstrap
  → 78 contacts → 229 discovered peers → 50 connected.
- DHT routing table persists to `~/.config/rustytorrent/dht_state` (~2 KB,
  ~80 contacts) and warm-loads on next start.
- Resume scan correctly skips already-verified pieces on restart.
- SOCKS5 + anonymous-mode self-test: 32 MiB single-file torrent through a
  local Python SOCKS5 proxy in ~1 s, MD5 byte-identical. `--anonymous`
  rejects start when `--socks5` is missing.
- 132 unit tests pass.

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

Speak the peer wire protocol. No downloading yet.

### Goals
- Peer handshake (19-byte preamble, reserved bytes, info_hash, peer_id)
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

Stretch goals that make RustyTorrent a first-class citizen in the wider peer-to-peer ecosystem.

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
- ✅ `axum`-based HTTP server (`--web PORT`, loopback-bound)
- ✅ `GET /api/status` + `/api/peers` + `/api/files` (JSON), `GET /metrics` (Prometheus), `GET /` (self-contained status page: progress bar, download-rate sparkline, instantaneous rates, per-file progress, peer list)
- ✅ `POST /api/pause` / `/api/resume` — pause/resume the running download (button on the status page)
- 🔲 add torrent (file or magnet) / remove — need a multi-torrent daemon (today's engine is one-torrent-per-process)
- 🔲 multi-torrent list view

### Status
Monitoring + single-torrent control have landed: a running download
serves rich live stats over loopback HTTP and can be paused/resumed. The
remaining control plane — adding and removing torrents at runtime — is
gated on refactoring the one-torrent-per-process engine into a
multi-torrent daemon with a shared session manager, tracked separately.

---

## Stretch Goals (no timeline)

- ✅ IPv6 support (dual-stack listener + IPv6 compact peers / PEX)
- ✅ Selective file download within multi-file torrents (`--select SUBSTR`)
- Tor transport supported via `--socks5` + `--anonymous`; native i2p not done
- Plugin system for custom piece pickers

---

## Principles

- **Usable at every phase** — each milestone ships something that works
- **No unsafe** — the whole client should be achievable in safe Rust
- **No panics in production paths** — every `?` should propagate a typed error
- **Test at the boundaries** — bencode, SHA1 verification, and piece state are pure functions and should have thorough unit tests
