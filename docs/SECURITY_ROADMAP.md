# RustyTorrent — Security & Anonymity Roadmap

A living list of hardening work, grouped by effort × value. Each item links
to its tracking issue (when filed) and updates as work lands.

Companion doc: [docs/ANONYMITY.md](ANONYMITY.md) covers the current threat
model that `--socks5 --anonymous` protects against today. This file covers
what's left and why.

---

## A-tier — cheap & high-value (next up)

These are small (≤100 lines each), no large new dependencies, and close
real holes. Bundled into one focused pass.

| # | Item | What it gets you | Cost |
|---|------|------------------|------|
| A1 | **DH parameter validation in MSE handshake** | Currently we accept whatever `Yb` (or `Ya`) the peer sends. A malicious peer could send `0`, `1`, or `p-1` to force a degenerate shared secret. Reject `Y ≤ 1` and `Y ≥ p-1`. | ~20 lines, no deps |
| A2 | **`zeroize` for crypto secrets** | Wipe RC4 internal state, DH private key, peer_id, info_hash buffers on `Drop` so they don't survive in heap-snapshot core dumps or freed-page reuse. | ~30 lines + `zeroize` crate (generic) |
| A3 | **Constant-time hash / peer_id comparison** | Use the `subtle` crate's `ConstantTimeEq` for SHA-1 piece-verify and peer_id equality. Defends against timing side-channels in case a future change accidentally introduces an early-exit comparison. | ~10 lines + `subtle` crate (generic) |
| A4 | **`--encrypt-only` mode** | Never try plain handshake first. Today's plain-then-MSE fallback briefly sends `\x13BitTorrent…` over the wire, which is a DPI fingerprint even if the eventual MSE handshake hides everything after it. | ~10 lines |
| A5 | **Bind-to-interface (`--bind-iface`)** | VPN kill switch. Bind every outbound socket to a specific interface (e.g. `utun0`); if the tunnel drops, sockets fail closed instead of falling back to the default route. Cross-platform: `IP_BOUND_IF` (macOS), `SO_BINDTODEVICE` (Linux), `IP_UNICAST_IF` (Windows). | ~80 lines + `socket2` crate |
| A6 | **Tor stream isolation** | Pass per-peer SOCKS5 credentials (random nonce as the username field) so each outbound peer rides its own Tor circuit. Tor's SOCKS server treats distinct credentials as distinct streams. Defeats correlation by any single exit node. | ~30 lines |

**Total estimate**: ~200 lines, 2 generic deps, one focused PR.

---

## B-tier — moderate effort, high value

These need their own focused effort but each unlocks a category of
protection that A-tier doesn't touch.

| # | Item | What it gets you | Cost |
|---|------|------------------|------|
| B1 | **AES-GCM on-disk encryption for in-progress pieces** | The seized-laptop scenario: in-progress files on disk are the smoking gun even if every network bit was anonymous. Encrypt at the storage layer with a per-session key derived from a passphrase (Argon2). Decrypt on read; rewrite plaintext only when complete, or never with `--paranoid`. | ~150 lines + `aes-gcm` + `argon2` |
| ~~B2~~ | ~~**`--memory-only` downloads**~~ — landed. Pieces live in a heap `Vec<Option<Vec<u8>>>`; nothing on disk. Linux/macOS/BSD only — Windows refused at startup. Mutex with `--paranoid`. | done |
| B3 | **Per-peer Request rate limit** | Token-bucket on inbound `Request` so a single peer can't DoS the disk by spamming requests faster than we can read. | ~50 lines, no deps |
| B4 | **Per-IP connection-rate limit on the listener** | Cap inbound connection attempts per source IP per minute. Reject the rest. Cheap protection against SYN-flood style abuse. | ~40 lines |
| B5 | **MSE/PE reserved-bit fingerprint reduction** | The reserved-bytes pattern in handshake leaks client identity. Randomize the unused bits we don't need to set, or match libtorrent's pattern to blend in. | ~20 lines |

---

## C-tier — bigger / experimental

| # | Item | What it gets you | Cost |
|---|------|------------------|------|
| ~~C1~~ | ~~**Multi-hop proxy chaining**~~ — landed. `--socks5` is now repeatable; the chain runs nested SOCKS5 CONNECTs on a single TCP stream. Credentials and Tor stream isolation attach to the last hop. Tracker HTTP still rides the first hop only (reqwest limit). | done |
| ~~C2 (Linux + macOS)~~ | ~~**OS-level sandboxing**~~ — Linux seccomp + macOS `sandbox_init` SBPL profile landed. Windows AppContainer remains open. | mostly done |
| ~~C3~~ | ~~**µTP (BEP 29) over UDP**~~ — landed. Packet codec, state machine, UDP socket runtime, AsyncRead/AsyncWrite bridge, engine integration (`--utp`: parallel TCP+µTP dial race + inbound listener), selective-ack (emit + prune + fast retransmit), LEDBAT delay-based congestion control (with fixed-window fallback), and inbound-flood / spoof defenses. Gated off under anonymous/SOCKS5/bind-iface. **Polish now also landed (commit c63fc05): wrap-correct reorder buffer (16-bit seq wraparound), randomized receiver-seq accept token (blind-spoof resistance), LEDBAT per-minute base-delay history, and a shared-`Arc<[u8]>` send buffer (no per-chunk alloc).** | done |
| C4 | **I2P transport** | Native anonymity overlay; tiny swarms but no Tor-style exit-node trust issues. Substantial work — different transport entirely. | ~1000+ lines |
| ~~C5~~ | ~~**Anonymous-mode peer_id rotation**~~ — landed. At every reannounce in anonymous mode the engine regenerates the peer_id (libtorrent-style prefix); existing TCP connections keep their handshaken id but every new outgoing dial uses the fresh one. Defeats the "same client signature across unrelated swarms" correlation. | done |
| ~~C6~~ | ~~**Tracker-frequency jitter**~~ — landed. Reannounce interval is jittered upward (+0-5% normal, +5-50% anonymous) so two clients on the same tracker don't share an identical cadence fingerprint. | done |

---

## Out-of-scope / won't do

| Item | Why not |
|---|---|
| Replace RC4 with ChaCha20 in MSE | MSE/PE the spec says RC4. Replacing it makes us non-interoperable. |
| Roll our own bignum for DH | `num-bigint` is a generic primitive; not BitTorrent-specific. Implementing constant-time 768-bit mod-exp from scratch is enormous and error-prone. |
| End-to-end peer encryption beyond MSE | The protocol doesn't define a per-peer authenticated channel. Would require a non-standard extension that no other client speaks. |
| Anti-fingerprinting via packet padding to constant-rate | Too aggressive for a portfolio project; meaningful bandwidth overhead. |

---

## Status

Last updated: 2026-06-01. **C3 µTP polish fully landed (commit c63fc05):
randomized receiver-seq accept token (blind-spoof resistance), wrap-correct
reorder buffer, LEDBAT per-minute base-delay history, shared-`Arc<[u8]>`
send buffer. Alongside: proptest fuzz harness for the bencode/message/KRPC
parsers, actionable error messages, and a CLI shared-args refactor — see
docs/TODO.md.**

Last updated: 2026-05-29. **Untrusted-input hardening pass + SOCKS5
auth-downgrade fix landed (see "Hardening pass" below).**

Last updated: 2026-05-23. **A-tier complete; B1+B3+B4+B5 landed; most of
C-tier (C5+C6) landed; full Phase 7 (BEP 10/11/9 + magnet) landed; bandwidth
limiter, DHT announce_peer, dual-stack IPv6 listener, MSE on magnet
bootstrap landed.** Anonymity-fingerprint pass (Stage 1) landed: the BEP 10
extension handshake, peer_id prefix, and tracker User-Agent now blend in
as libtorrent 2.0.9 under `--anonymous`, and cleartext `http://` trackers
are rejected up front in that mode.

### Hardening pass (2026-05-29)

Audit of every untrusted-input parser (bencode, peer wire, KRPC,
ut_metadata/ut_pex, UDP tracker, handshake). Found and fixed two real
remote-DoS holes and one privacy downgrade; the rest were already
well-defended (length-checked, bounded allocations, kernel-filtered
UDP source, constant-time hash compares).

- ✅ **bencode recursion cap** — `parse_value` recursed with no depth
  bound; a deeply nested payload (`llll…`/`dddd…`) overflowed the
  stack and crashed the process. Untrusted bencode arrives from DHT
  nodes, trackers, and peer extension/ut_metadata messages, so the
  nesting is attacker-controlled. Now capped at depth 100.
- ✅ **µTP reorder-buffer cap** — the per-connection `pending_in`
  out-of-order buffer was unbounded; a peer that withholds one seq_nr
  and floods higher ones forced unbounded memory growth (remote OOM).
  Capped at `MAX_PENDING_IN`; excess is dropped and re-requested via
  the cumulative ack.
- ✅ **SOCKS5 auth-downgrade fix** — when credentials were present we
  offered `[NO_AUTH, USERPASS]`, letting the proxy pick NO_AUTH and
  silently ignore the credentials. With `--tor-isolation` that means
  the per-dial random username never reaches Tor and every dial rides
  one circuit — the correlation defense silently lost. Now offer
  USER/PASS only when creds are set; fail closed otherwise.
- ✅ **µTP state-machine off-by-one** (correctness, found during socket
  work) — the initiator treated the receiver's first DATA as a
  duplicate (STATE seq_nr names the peer's *next* seq, not a delivered
  one), silently dropping it. Fixed and regression-tested.
- ✅ **path traversal via `name`** — multi-file path *segments* were
  sanitized but the torrent `name` field was not, and `storage::Layout`
  joins it onto the output root (`root/name`, `root/name/seg`). A
  hostile `.torrent` (or magnet metadata from untrusted peers) with
  `name = "../../.bashrc"` or `/etc/cron.d/evil` escaped the download
  dir → arbitrary file write. Now rejects empty / `.` / `..` /
  separators on both `name` and segments.
- ✅ **piece length bound** — `piece_length` came straight from the
  torrent (only negative-checked). Zero is degenerate; an enormous
  value overflows `piece_index * piece_length` (debug panic / release
  wrap) and drives huge allocations. Capped at 1 GiB, reject 0.
- ✅ **µTP connection cap** — UDP sources are spoofable, so a forged-SYN
  flood created unbounded receiver-side connection state (B4's per-IP
  limit can't help). Driver caps total connections at `MAX_CONNS`.
- ✅ **PeerManager violation-map GC** — the per-IP protocol-violation
  map shed stale timestamps only for IPs that re-offended; an IP that
  violated once and vanished kept its entry forever. Engine now sweeps
  it on a 60 s tick. (`banned` is intentionally permanent — proven
  malicious; growth self-limiting.)
- ✅ **DHT peer-store bound + expiry** — the store capped each
  info_hash's peer list (256) but never bounded the *number* of
  info_hashes and never expired entries. Added a 5 min TTL GC
  (`ANNOUNCE_TTL` 30 min) + an insert-time cap of `MAX_INFO_HASHES`.
- ✅ **DHT anti-reflection** — a KRPC reply is larger than the query, so
  the public DHT node could be used to reflect amplified traffic at a
  spoofed-source victim. Per-source-IP token bucket (20 burst, 5/s) on
  inbound query answers caps reflection at any single target.
- Panic audit: every `unwrap`/`expect`/`unreachable` in non-test code is
  guarded by a real invariant — the "no panics in production" principle
  holds; no changes needed.

### A-tier landed
- ✅ A1: DH parameter validation in MSE handshake — rejects degenerate Y values.
- ✅ A2: `zeroize` on drop for RC4 state + DH private key.
- ✅ A3: Constant-time compare (`subtle`) for piece-hash verify + info_hash.
- ✅ A4: `--anonymous` implies MSE-only outgoing (no plain pstr emitted).
- ✅ A5: `--bind-iface IFACE` for VPN kill switch (macOS / Linux / Windows).
- ✅ A6: `--tor-isolation` for per-peer Tor circuits.

### B-tier landed
- ✅ B1: `--paranoid` mode — AES-256-GCM encrypted spool with Argon2id-derived
  key; plaintext never persisted during the session. Companion `decrypt`
  subcommand extracts the spool into the real file layout afterwards.
- ✅ B3: per-peer token-bucket rate limit on inbound `Request` messages
  (default 200 req/s, burst 50) — caps a single peer's disk-read pressure.
- ✅ B5: handshake reserved-bytes fingerprint reduction — set the DHT bit
  (BEP 5, byte 7 = 0x01) when DHT is enabled instead of always emitting
  the all-zero "I support nothing" pattern.

### B-tier remaining
_None — B2 landed alongside the multi-hop chain work._

### C2 — OS-level sandboxing
- ✅ Linux x86_64: `--sandbox` installs a hand-rolled BPF whitelist
  via `prctl(PR_SET_NO_NEW_PRIVS)` +
  `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC)`. The filter rejects
  32-bit syscall numbers (audit-arch check), then whitelists ~75
  syscalls covering tokio's runtime, rustls, and our
  network/storage code. Anything outside the list terminates the
  process via SIGSYS.
- ✅ macOS: `--sandbox` installs a deny-default SBPL profile via
  `sandbox_init(3)`. Allows file-read/file-write, network*,
  signal, mach-lookup, sysctl-read/write, ipc-posix-*. The
  default-deny tail still includes `process-exec`, `process-fork`,
  `system-mount`, `system-kext-*`, and the rest of the privileged
  primitives we'd otherwise be exposed to.
- Both backends share one entry point (`crate::sandbox::engage()`)
  invoked late in engine startup, post-listener, post-tracker,
  post-DH; the main download loop runs entirely under the chosen
  sandbox.
- Windows AppContainer remains open.

### C3 — µTP (partial)
- ✅ Packet codec ([`src/peer/utp/packet.rs`](../src/peer/utp/packet.rs)):
  full BEP 29 wire format including the extension chain. Tests
  cover roundtrip, every packet-type nibble, selective-ack
  extension, and rejection paths (short buffer, unknown type,
  wrong version, truncated/overflowing extensions).
- ✅ Per-connection state machine ([`src/peer/utp/connection.rs`](../src/peer/utp/connection.rs)):
  SYN/STATE/DATA/FIN/RESET transitions, BEP 29 connection_id
  allocation (initiator picks recv_id; send_id = recv_id + 1;
  each side's send_id == other's recv_id), cumulative acks,
  retransmit-on-RTO with exponential backoff, receive-side
  reordering, and clean FIN-driven close. Pure logic — no I/O —
  so tests drive two connections back-to-back over a perfect
  in-memory channel.
- ✅ UDP socket runtime ([`src/peer/utp/socket.rs`](../src/peer/utp/socket.rs)):
  one `UtpSocket` owns a single UDP socket and a driver task that
  demuxes datagrams by `(peer, connection_id)` and multiplexes every
  connection over it. `UtpStream` implements `AsyncRead`/`AsyncWrite`,
  so the existing BT-handshake / MSE / wire-message code runs over µTP
  unchanged. `connect` (outbound) and `accept` (inbound) both work;
  loopback tests cover small + 20 KB multi-packet transfers and the
  dead-peer dial timeout. Fixing this exposed a state-machine bug: the
  initiator was treating the receiver's first DATA as a duplicate
  (STATE seq_nr off-by-one) — now fixed and regression-tested.
- ✅ Engine integration (`--utp`): a `Transport` enum
  ([`src/peer/transport.rs`](../src/peer/transport.rs)) unifies TCP and
  µTP behind `AsyncRead`/`AsyncWrite`. Each outbound dial races TCP and
  µTP and takes whichever connects first; an inbound µTP listener funnels
  accepted streams through the same capped/ban-checked accept path as
  TCP. **Gated off under `--anonymous`, an active SOCKS5 chain, or
  `--bind-iface`** — UDP can't ride a SOCKS5 CONNECT and the µTP socket
  isn't interface-bound, so allowing it there would leak past the proxy
  / kill switch. End-to-end smoke test: two peers complete a real BT
  handshake over µTP loopback.
- ✅ Inbound µTP DoS bound: the driver caps total connections at
  `MAX_CONNS` and drops new inbound SYNs past it. UDP sources are
  spoofable (so B4's per-IP limit can't help), and the driver created
  a connection entry per forged SYN — an unbounded remote OOM. The cap
  bounds steady-state memory regardless of flood rate; half-open forged
  entries reap at `HARD_TIMEOUT`.
- ✅ Anti-spoofing accept: an inbound µTP connection is no longer
  surfaced to `accept()` on the SYN alone — the driver holds it until
  the peer sends a non-SYN packet (proving it received our STATE, i.e.
  a responsive return path). A spoofed-source SYN flood therefore never
  occupies a peer slot; the half-open entries just reap at
  `HARD_TIMEOUT`. (Residual: a blind spoofer who also forges a DATA
  packet could still surface one, since our receiver's initial seq_nr
  is fixed; randomizing it as an unguessable accept token would close
  that too — noted for later.)
- ✅ Selective-ack (BEP 29): receiver emits a SACK bitmask; sender
  prunes selectively-acked packets and fast-retransmits the gap on a
  >=3-past-gap SACK (TCP-style dup-ack loss signal).
- ✅ LEDBAT congestion control: a delay-based AIMD controller
  ([`Ledbat`](../src/peer/utp/connection.rs)) sizes the send window from
  the peer's echoed `timestamp_diff` (the driver echoes ours back too),
  targeting ~100 ms standing queue. Falls back to the fixed window with
  a 2-packet floor until a usable sample arrives, so it can't regress or
  stall. The math is unit-tested; the emergent dynamics still want
  validation against a real µTP peer on a latency'd link.
- ✅ Polish landed (commit c63fc05): **randomized receiver seq_nr as an
  accept token** — `new_receiver` draws the initial seq from the CSPRNG and
  the driver only confirms the return path (and surfaces the conn to
  `accept()`) when a non-SYN packet acks that token within a bounded window,
  closing the residual blind SYN+DATA spoof; **16-bit seq wraparound** — the
  reorder buffer is re-keyed to an absolute non-wrapping logical sequence so
  ordering/draining/SACK stay correct past 65535→0; **LEDBAT per-minute
  base-delay history** — a rolling ~13-slot minute-minima window lets the
  base delay recover after a route change instead of pinning low. (Also
  perf: outgoing payloads now share one `Arc<[u8]>` allocation instead of a
  `Vec` per packet.)

### B2 — `--memory-only` storage
- ✅ In-RAM piece store; nothing persisted to disk for the lifetime of
  the process. Mutually exclusive with `--paranoid`. Engine startup
  picker prefers memory-only > paranoid > plain disk. Unsupported on
  Windows (clear error at startup rather than silent disk fallback).
  Pairs well with `--anonymous` for the strongest "leave-no-trace"
  posture available.

### B-tier additional
- ✅ B4: per-source-IP rate limit on inbound listener (10-burst, 1/sec
  sustained, lazy GC). Cheap SYN-flood defence on the public listener
  for non-anonymous sessions.

### C-tier landed
- ✅ C5: anonymous-mode peer_id rotation. At every reannounce in
  anonymous mode the engine regenerates its peer_id; existing TCP
  connections keep their already-handshaken id, but every new
  outgoing dial after that point uses the fresh one — defeats the
  "same 20-byte client signature across unrelated swarms" correlation.
- ✅ C6: tracker-announce interval jitter (upward only, larger window
  in anonymous mode) so two clients sharing a tracker don't share an
  identical cadence fingerprint.

### Cross-cutting
- ✅ Engine-wide bandwidth limiter (`--max-down` / `--max-up`) — token
  bucket on Request issuance and `serve_request`. Not a security item
  per se but lands alongside the C-tier work.

### C1 — Multi-hop SOCKS5 chaining
- ✅ `--socks5` is repeatable; the chain runs nested SOCKS5 CONNECTs
  on a single TCP stream (RFC 1928 nests cleanly). The first
  `--socks5` is the entry hop, the last is the exit. Credentials and
  `--tor-isolation` attach to the last hop only (typically the one
  that actually enforces auth or where circuit isolation is
  meaningful). Tracker HTTP rides only the first hop because
  reqwest's SOCKS5 support is single-hop. Length-1 chains behave
  identically to the previous single-proxy code path.

### `--bind-iface` + `--socks5` combination
- ✅ Previously refused at engine startup. Now supported: the TCP
  dial to the first SOCKS5 hop itself rides netbind, so the kernel
  route to the proxy is forced onto the bound interface (the VPN
  kill-switch invariant: if the tunnel drops, dials fail closed
  instead of falling back to the default route). Intermediate hops
  in a multi-hop chain inherit the binding for free because they
  ride the same TCP stream.

### Anonymity-fingerprint pass (Stage 1)
- ✅ BEP 10 extension handshake: under `--anonymous`, drop the `v`
  (client version) and `reqq` (request queue depth) keys that
  uniquely identify us as rustytorrent. Only the `m` dict is sent.
- ✅ peer_id prefix: anonymous mode uses `-LT2090-` (libtorrent 2.0.9)
  instead of the default `-RT0100-`. Applies to the initial id, the
  magnet-bootstrap dial, and the mid-session reannounce rotation.
- ✅ Tracker HTTP `User-Agent`: anonymous mode sends
  `libtorrent/2.0.9` instead of the default `rustytorrent/<ver>`
  per-announce, without rebuilding the cached HTTP client.
- ✅ Cleartext `http://` trackers rejected up front under
  `--anonymous` (an observer between us and the proxy can read the
  HTTP body even when the dial itself is masked). `https://` and
  `udp://` are unaffected (`udp://` is already blocked separately
  because UDP can't ride SOCKS5 CONNECT).
