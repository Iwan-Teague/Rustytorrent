# Changelog

All notable changes to rustytorrent are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning targets
[SemVer](https://semver.org/) post-1.0.

## [Unreleased]

Security, anonymity, and robustness hardening across the peer/tracker/DHT/
µTP/SOCKS5 surface, plus the µTP flow-control implementation and its
verification suite.

### Security & Anonymity

- **Anonymous-mode egress is fail-closed at every layer**: direct TCP dials,
  UDP tracker announces, DHT spawning, inbound listeners, and clearnet
  tracker URLs are all refused — not merely discouraged — under
  `--anonymous` or a SOCKS5 chain; each gate carries a behavioral test
  (kernel-socket-level proofs included).
- **Martian/SSRF screening derived from session anonymity** at every peer
  ingestion site (tracker responses, DHT lookups, PEX) *and* re-checked at
  the dial syscall itself (`is_safe_dial_target`), so a hostile address
  reaching a dial through any future unfiltered path is still refused;
  loopback remains exempt for local multi-instance peering.
- **BEP 6 REJECT_REQUEST validation**: out-of-range indices no longer reach
  unchecked piece indexing (remote panic), and rejects may only clear
  request state for requests actually sent to the rejecting peer (closing
  a cross-peer stall vector).
- **Constant-time MSE SKEY matching**: candidate info-hash comparison uses
  `subtle::ConstantTimeEq` with no early exit; timing can no longer reveal
  which hosted torrent a prober's SKEY guess hit.
- **SOCKS5 hardening**: hostname proxy hops are refused under `--anonymous`
  (startup clearnet-DNS leak closed); no-downgrade method negotiation when
  credentials are present; malformed/hostile proxy replies (bad versions,
  unoffered methods, unknown ATYP, oversized domain bind addresses,
  truncation) fail fast without hangs.
- **Peer-id and User-Agent hygiene in anonymous mode**: ephemeral
  libtorrent-lookalike peer ids (`-LT2090-`, rotated per reannounce) and a
  libtorrent-style User-Agent replace every fingerprintable default.
- **Credential hygiene**: proxy passwords never appear in `Debug` output or
  error surfaces; passkeys are scrubbed from all tracker URL logging;
  control characters are stripped from tracker-supplied text.
- **Owner-only permissions** for on-disk state: peer id, daemon store, DHT
  routing table, download data, spool, and created `.torrent` output.
- **Release builds enable `overflow-checks`**: arithmetic overflow panics
  instead of wrapping silently in optimized builds.

### Fixed

- **µTP memory bounds (three coordinated fixes)**: outbound writes are
  gated by a per-connection credit ledger (256 KiB cap); inbound acceptance
  enforces the advertised receive window (frontier pins like TCP zero-
  window); the driver→stream delivery queue is bounded, with bytes left in
  the receive buffer until the application reads. Undelivered/deliverable
  memory per connection is now bounded regardless of either side's
  behavior.
- **µTP shutdown semantics**: local `shutdown()` terminates pending and
  future writes (`BrokenPipe`, the TCP EPIPE analogue) instead of leaving
  writers parked or silently discarding queued bytes; a peer RESET unblocks
  parked writers promptly.
- **`--port 0` resolves before announcing**, on both the single-torrent and
  daemon paths: announces advertise the real OS-assigned port instead of
  the "no listener" placeholder (passive discovery was silently broken).
- **`--max-down` / `--max-up` edge cases**: sub-8 KiB/s caps no longer
  stall transfers permanently (bucket capacity floored at one block), and
  an explicit `0` means unlimited as the help text always claimed.
- **SIGTERM now triggers graceful shutdown** alongside Ctrl+C — process
  managers (systemd, Docker) can stop the binary without losing in-flight
  writes, tracker stopped-announces, or DHT routing-table state.
- **`create` refuses zero-length inputs** (empty file, or directory of only
  empty files) instead of writing metainfo with zero piece hashes that no
  client can load.
- Tracker announce response bodies are size-bounded (remote
  memory-exhaustion DoS); interval values clamped; cross-host redirects
  never followed; IPv6-literal detection corrected.
- `--select ""` (or whitespace-only patterns) are rejected with an error
  instead of silently matching every file.

### Performance

- Pipeline resume scan overlaps SHA-1 hashing with disk reads across all
  cores; picker per-request sorting replaced with a linear min pass;
  wire-frame reads reuse buffers (zero steady-state allocation on the
  download path); upload path reduced to a single copy per served block;
  µTP outgoing data shares one allocation per application write.

### Tests

- Property suites for bencode/KRPC/wire decoders, multi-file layout
  tiling, metainfo semantic bounds, and the µTP flow-control core
  (stream-integrity-under-chaos, no-drain flood bounding, SendGate ledger).
- End-to-end adversarial tests: connect floods, request floods, poisoned
  blocks (verify-fail → ban → disconnect), forged REJECT storms, anonymous-
  mode socket audits via `/proc`, scripted hostile SOCKS5 proxies, and
  kernel-level proofs that anonymous engines own zero UDP/listening
  sockets. Security-critical fixes are mutation-checked against their
  tests. Also pins the sandbox-smoke engage-once race (concurrent tests
  racing PR_SET_NO_NEW_PRIVS against an installed filter) via a strace
  root-cause.

### Added

- **BEP 6 fast extensions**: HAVE_ALL / HAVE_NONE / REJECT_REQUEST /
  SUGGEST / ALLOWED_FAST on the wire, reserved-bit advertisement, and the
  associated engine handling — closing the libtorrent reserved-byte
  fingerprint gap.
- `RUSTYTORRENT_SOCKS5_USER` / `RUSTYTORRENT_SOCKS5_PASS` environment
  fallbacks so proxy credentials need not sit in argv.
- `--sandbox` support wired into the daemon subcommand (seccomp whitelist).
- CI enforcement: cargo-deny supply-chain job (RustSec advisories, license
  policy, source restrictions), a linux-only release-profile test pass
  exercising overflow-checks, and rustdoc link hygiene via
  `RUSTDOCFLAGS=-D warnings`.
