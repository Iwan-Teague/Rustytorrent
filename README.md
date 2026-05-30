# RustyTorrent

A fully-functional peer-to-peer file transfer client written from scratch
in Rust. The protocol-specific bits — bencode, info-hash, the peer wire
protocol, HTTP/UDP trackers, MSE/PE encryption, the BEP 5 DHT, the piece
state machine, the rarest-first picker, the choke algorithm, the engine —
are all written from first principles in this repo; the dependency list is
entirely generic infrastructure (async runtime, HTTP client, hash
primitives, bit-vectors, big-int math for DH, CLI parser).

Cross-platform: Linux, macOS (Intel + Apple Silicon), and Windows.

## What works

| Capability | Status |
|---|---|
| Bencode parser + `.torrent` decoder with raw-bytes `info_hash` | ✅ |
| HTTP trackers (BEP 3) and UDP trackers (BEP 15) with retry + connection-id refresh | ✅ |
| Peer wire protocol (handshake + all 9 messages, BEP 3) | ✅ |
| MSE / Protocol Encryption (BEP 8): RC4, 768-bit DH, full handshake | ✅ |
| BEP 5 DHT: KRPC, k-bucket routing table, iterative `get_peers`, persistent state | ✅ |
| Piece state machine with block-level pipelining (depth 5) | ✅ |
| Rarest-first picker + endgame mode + SHA-1 verifier | ✅ |
| Multi-file storage with virtual offset map across files | ✅ |
| Choke algorithm (BEP 3: 3 regular + 1 optimistic, 20 s rolling window) | ✅ |
| Resume scan on startup + DHT routing-table persistence | ✅ |
| LRU upload-cache (32 pieces) to keep popular pieces in RAM | ✅ |
| SOCKS5 outgoing proxy (RFC 1928 + RFC 1929 auth); repeatable for multi-hop chains | ✅ |
| `--anonymous` bundle: DHT off, listener off, ephemeral peer_id, `port=0` | ✅ |
| BEP 10 extension protocol + BEP 9 ut_metadata + magnet links | ✅ |
| BEP 11 PEX — bidirectional: receive incoming peer lists + send delta updates every 60 s | ✅ |
| Engine-wide bandwidth limiter (`--max-down`, `--max-up`) | ✅ |
| µTP transport (BEP 29) — `--utp`: TCP+µTP dial race, inbound µTP, SACK + LEDBAT | ✅ |
| Private torrents (BEP 27) — DHT + PEX disabled when `private` is set | ✅ |
| Web monitoring UI — `--web PORT`: status page + JSON + Prometheus `/metrics` (loopback) | ✅ |
| Web UI control plane (add/pause/remove, multi-torrent) | ❌ — needs a daemon refactor |

## Quick start

### Build

```sh
cargo build --release
```

### Inspect a torrent

```sh
./target/release/rustytorrent info path/to/file.torrent
```

### Download

```sh
# Tracker + DHT, normal mode
./target/release/rustytorrent download file.torrent --output ~/Downloads --dht

# Trackerless (DHT only)
./target/release/rustytorrent download file.torrent --output ~/Downloads \
    --no-tracker --dht

# Direct peer, no network discovery (good for self-tests)
./target/release/rustytorrent download file.torrent --output ~/Downloads \
    --no-tracker --peer 1.2.3.4:6881
```

### Magnet links

```sh
# Magnet URI — fetches metadata from peers via DHT + ut_metadata, then
# downloads as usual. DHT defaults to on for magnets.
./target/release/rustytorrent magnet \
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=demo&tr=udp://tracker.example:6969" \
    --output ~/Downloads
```

### Anonymity

```sh
# Route through your VPN's local SOCKS5
./target/release/rustytorrent download file.torrent --output ~/Downloads \
    --socks5 127.0.0.1:1080 --anonymous

# Route through Tor (no DHT, no UDP trackers — both incompatible with Tor)
./target/release/rustytorrent download file.torrent --output ~/Downloads \
    --socks5 127.0.0.1:9050 --anonymous
```

See [docs/ANONYMITY.md](docs/ANONYMITY.md) for the threat model — what
`--anonymous` does and doesn't protect against.

### Full CLI

```
rustytorrent download <file> [OPTIONS]

  --output DIR              destination directory (default: ".")
  --port N                  listen port (default: 6881)
  --peer host:port          extra peer to dial directly (repeatable)
  --no-tracker              skip the .torrent's tracker list
  --dht                     enable BEP 5 DHT
  --encrypt                 force outgoing MSE/PE (skip plain attempt)
  --socks5 host:port        route through SOCKS5; repeat to chain hops
                            (first = entry, last = exit; last hop sees creds)
  --socks5-user U           SOCKS5 username for the LAST hop (requires --socks5)
  --socks5-pass P           SOCKS5 password for the LAST hop (requires --socks5-user)
  --anonymous               strict bundle (requires --socks5; DHT/listener off)
  --bind-iface IFACE        VPN kill switch — bind outgoing sockets to IFACE
  --tor-isolation           per-peer SOCKS5 username so each dial gets its own Tor circuit
  --paranoid                write encrypted spool only; plaintext never on disk
  --memory-only             keep pieces in RAM, never write to disk (Linux/macOS/BSD)
  --sandbox                 OS sandbox (Linux seccomp / macOS sandbox_init) before download loop
  --passphrase P            passphrase for --paranoid (or RUSTYTORRENT_PASSPHRASE env)
  --spool PATH              override the spool file path
  --max-down N              cap inbound bandwidth, KiB/s (engine-wide)
  --max-up N                cap outbound bandwidth, KiB/s (engine-wide)
  --utp                     enable µTP (BEP 29): race TCP+µTP on each dial,
                            accept inbound µTP. Auto-off under --anonymous /
                            --socks5 / --bind-iface (UDP can't ride SOCKS5)
  --web PORT                serve a read-only monitoring UI on 127.0.0.1:PORT
                            (status page + /api/status JSON + /metrics)

rustytorrent decrypt <file> [OPTIONS]      # extract a --paranoid spool afterwards

  --output DIR              destination directory (default: ".")
  --spool PATH              encrypted spool to read
  --passphrase P            same passphrase used to produce the spool

rustytorrent magnet <URI> [OPTIONS]        # download from a magnet link

  --output DIR              destination directory (default: ".")
  --port N                  listen port (default: 6881)
  --peer host:port          extra bootstrap peer (repeatable)
  --dht                     enable DHT (default: true for magnets)
  --encrypt                 force outgoing MSE/PE post-bootstrap
  --socks5 …                same SOCKS5 / anonymity flags as `download`
  --paranoid / --passphrase / --spool   same encrypted-spool flags as `download`
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — module map, data flow, dependencies
- [docs/ANONYMITY.md](docs/ANONYMITY.md) — threat model + verification
- [docs/ROADMAP.md](docs/ROADMAP.md) — phase plan, current status
- [docs/TASKS.md](docs/TASKS.md) — granular task checklist per phase
- [docs/AGENT_BUILD_GUIDE.md](docs/AGENT_BUILD_GUIDE.md) — original build-from-scratch guide

## Development

```sh
cargo test                            # 241 unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

CI runs the test matrix on Linux + macOS + Windows on every push.

## License

MIT.
