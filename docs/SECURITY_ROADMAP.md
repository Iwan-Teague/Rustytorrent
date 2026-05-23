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
| ~~C2 (Linux part)~~ | ~~**OS-level sandboxing**~~ — Linux seccomp landed. App-sandbox profile (macOS) and AppContainer (Windows) remain open. | partly done |
| C3 | **µTP (BEP 29) over UDP** | Connect to peers that only speak µTP. Today we only do TCP, so a slice of the swarm is unreachable. Adds a UDP path that needs its own proxy story (or hard-off in anonymous mode, like DHT). | ~600 lines |
| C4 | **I2P transport** | Native anonymity overlay; tiny swarms but no Tor-style exit-node trust issues. Substantial work — different transport entirely. | ~1000+ lines |
| C5 | **Custom MSE reserved-byte fingerprint matching** | Per-peer Tor circuit + matching the *exact* handshake byte pattern of (say) qBittorrent so traffic analysis can't distinguish us by client. | ~50 lines (depends on B5) |
| ~~C6~~ | ~~**Tracker-frequency jitter**~~ — landed. Reannounce interval is jittered upward (+0-5% normal, +5-50% anonymous) so two clients on the same tracker don't share an identical cadence fingerprint. peer_id mid-session rotation is still open. | done |

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

Last updated: 2026-05-23. **A-tier complete; B1+B3+B4+B5 landed; most of
C-tier (C5+C6) landed; full Phase 7 (BEP 10/11/9 + magnet) landed; bandwidth
limiter, DHT announce_peer, dual-stack IPv6 listener, MSE on magnet
bootstrap landed.** Anonymity-fingerprint pass (Stage 1) landed: the BEP 10
extension handshake, peer_id prefix, and tracker User-Agent now blend in
as libtorrent 2.0.9 under `--anonymous`, and cleartext `http://` trackers
are rejected up front in that mode.

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

### C2 — Linux seccomp sandbox
- ✅ `--sandbox` engages a hand-rolled BPF whitelist installed via
  `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SECCOMP_SET_MODE_FILTER,
  TSYNC)`. The filter rejects 32-bit syscall numbers on a 64-bit
  kernel (audit-arch check), then whitelists ~75 syscalls covering
  tokio's runtime, rustls, and our network/storage code. Anything
  outside the list terminates the process via SIGSYS — no
  privilege-escalation primitives (`ptrace`, `init_module`,
  `kexec_load`, `mount`, `swapon`, `pivot_root`, …) are reachable
  from the address space even if an exploit lands there. Filter
  installs late in engine startup (post-listener, post-tracker,
  post-DH); the main download loop runs entirely under the sandbox.
  Linux x86_64 only; other platforms refused at startup. App-sandbox
  (macOS) and AppContainer (Windows) remain open.

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
