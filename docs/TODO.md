# RustyTorrent — Improvement Backlog

A whole-project sweep (2026-05-30) for everything worth doing: security,
privacy/anonymity, performance, correctness, UX, features, testing, and
tech debt. Findings were grep/agent-surfaced and then spot-verified
against the code — items marked **[verified]** were confirmed by reading
the cited lines; items marked **[claim]** are plausible but not yet
re-checked. Line numbers drift; treat them as starting points.

Priorities: **P0** = correctness/security bug or real user pain ·
**P1** = clear win, bounded · **P2** = nice-to-have / polish.

---

## Correctness & security audit (2026-06-02)

An adversarial read-only audit of the IO/stream layer, the download path,
storage, and DHT/tracker/peer-manager (prompted by the MSE keystream-desync
bug fixed in commit `181c175`). Fixed:

- [x] **P1 — hostile HTTP tracker `interval` → engine panic.** A malicious or
  MITM'd `http://` tracker returning a huge `interval` (up to `i64::MAX`)
  overflowed `Duration` in the announce-jitter step (`base * pct`) → panic
  (the whole process in standalone mode; one session in the daemon), even on
  the first announce. Fixed: clamp the parsed `interval`/`min interval` to
  24 h in `tracker/http.rs::parse_response`, and made `jittered_interval` use
  saturating `Duration` math. Both tested.
- [x] **P2 — `--select` resumed nothing on restart.** Regression from the
  selective-allocation skip: `scan_resume` bailed to empty on the first
  missing file, but selective downloads deliberately never create unwanted
  files. Fixed: `scan_resume` now tolerates missing files
  (`Vec<Option<File>>`), skipping only the pieces that read from an absent
  file, so it resumes every fully-present piece. Also improves normal
  multi-file partial resume. Regression-tested.
- [x] **P2 — DHT replies correlated by txid only.** A 16-bit transaction id is
  guessable, so an off-path attacker could inject (or evict) an in-flight
  lookup's reply. Fixed: bind each `PendingQuery` to the queried `SocketAddr`
  and accept a reply only from that exact address (peek-then-remove, so a
  forged packet can't evict the genuine pending entry either).
- [x] **P2 — `serve_request` upload accounting before bounds check.** A peer
  could inflate our `uploaded` counter / drain upload tokens with a valid
  `length` but an out-of-range `begin` that ships zero bytes. Fixed: validate
  the window against the piece length before charging accounting.

Deferred (real, but larger or lower-value — left for a focused pass):

- [ ] **P1 — hash-fail bans the *completing* peer, not the *poisoning* one;
  unsolicited blocks are accepted.** `received_block` stores any well-formed
  block regardless of whether we requested it from that peer, with no
  per-block source tracking, so on a SHA-1 failure the engine bans whoever
  delivered the *last* block (often an honest peer, permanently by IP) while a
  peer that injected an earlier bad block stays connected and re-poisons. Fix
  needs per-block source attribution and/or rejecting blocks not currently
  outstanding to the sending peer (requires per-peer outstanding-request
  tracking).
- [ ] **P1 — an idle (non-choking, non-disconnecting) peer parks its assigned
  piece indefinitely.** No per-request timeout / stale-inflight reaper exists;
  a peer that accepts a `Request` then goes silent holds its `inflight` slots
  and the piece's `requested` bits until endgame (`missing < 5`) finally
  re-requests it — below endgame the torrent can stall. Fix: a request-deadline
  reaper that releases inflight + the sticky assignment.
- [ ] **P2 — µTP `UtpStream::poll_write` has no backpressure.** It hands every
  write to the driver over an unbounded channel and always reports the whole
  buffer accepted, so an app writing faster than the LEDBAT window drains
  grows driver-side memory unbounded. Low severity (the upload path is
  rate-limited and bounded by peer-count × pipeline depth in practice). Bound
  the in-flight send buffer and return `Pending` when full.
- [ ] **P2 — `num_pieces` vs `total_length` never reconciled.** A malformed /
  hostile `.torrent` whose piece-hash count disagrees with
  `ceil(total/piece_length)` parses fine but then hangs the download silently
  (pieces past real file coverage produce empty write slices and never verify)
  — no corruption, just no diagnostic. Add a parse-time check (deferred:
  several synthetic-torrent tests build inconsistent counts and would need
  updating first).
- [ ] **P3 — `decrypt_all_pieces` silently creates an empty spool** if pointed
  at a missing/wrong path (no `try_exists` guard, unlike `scan_spool_resume`),
  reporting "Recovered 0 pieces". Cleanliness.

Audit also verified clean (no bug): the multi-file virtual offset map, the
selective-skip `None`-slot path (errors, never panics/corrupts), AES-256-GCM
nonce uniqueness + auth-tag verification, the reused spool scratch buffer,
`scan_resume` mis-verification resistance, upload-cache coherency, the
global/per-session connection cap + RAII slot release, the permanent ban set,
DHT reflection / store-pollution defenses + token handling, the k-bucket /
XOR-distance routing math, and the `Transport`/`UtpStream` `poll_*` impls.

---

## 1. Security & hardening

- [x] **P1 — Daemon `POST /api/add` path read is unconstrained.** [verified]
  `web.rs daemon_add` does `tokio::fs::read(body.trim())` on any
  server-side path. DONE: added `resolve_under(dir, requested)` which
  canonicalizes both (following symlinks, collapsing `..`) and requires
  the resolved path to live under a configured torrent dir, else 403.
  Wired a `--torrent-dir` daemon flag (defaults to cwd) into
  `DaemonState.torrent_dir`. Containment is checked *before* any
  `fs::read`, so an out-of-tree path is never even stat'd. Startup
  positional torrents bypass the check (trusted CLI input). Unit-tested
  inside/escape/absolute/nonexistent cases.
- [x] **P2 — DH private-key wipe is best-effort.** [verified]
  `peer/mse/dh.rs` `Drop` overwrites the `BigUint` with `0` but doesn't
  scrub the freed limb allocation; not constant-time. DONE: rewrote the
  `Drop` comment to state plainly that this deallocates rather than
  scrubs, that num-bigint has no safe in-place zeroing and the crate
  forbids `unsafe`, and that it's acceptable because MSE is
  obfuscation-only with ephemeral keys (the derived RC4 state IS
  `ZeroizeOnDrop`). No longer overstates the guarantee.
- [x] **P2 — bencode `parse_bytes` defensive bound.** [verified]
  `metainfo/bencode.rs` guards `rest.len() < len` before `split_at(len)`,
  so it's safe today. DONE: added an explicit comment noting `len` is
  attacker-controlled and that `split_at` panics if unbounded, plus a
  `debug_assert!(len <= rest.len())` immediately before the split to pin
  the invariant against a future refactor.
- [x] **P2 — ut_metadata per-session memory budget.** [verified cap]
  `peer/extension.rs` caps a single `metadata_size` at 100 MB, but a peer
  flood across many connections could each allocate up to that. DONE:
  added a process-wide `GLOBAL_METADATA_BUDGET` (256 MB) with an RAII
  `MetadataReservation` guard (CAS against an `AtomicUsize`). Each fetch
  reserves `total_size` before allocating the assembly buffer and is
  refused if it would exceed the ceiling; the guard releases on drop
  (success/error/abort), so 16 × 100 MB × N-magnets can no longer blow up
  memory. Unit-tested bound + release + overflow.
- [ ] **P2 — Windows AppContainer sandbox.** `sandbox.rs` supports Linux
  seccomp + macOS SBPL; Windows `--sandbox` is refused. Implement
  AppContainer (roadmap C2 remainder).
- [x] **P2 — no-echo TTY passphrase prompt** for `--paranoid`. Today the
  passphrase comes from `--passphrase` (warned: leaks in `ps`/history) or
  `RUSTYTORRENT_PASSPHRASE`. DONE: added `rpassword` and a third fallback
  in `resolve_passphrase` — when both stdin and stderr are TTYs and no
  flag/env is set, prompt with hidden input (`rpassword::prompt_password`).
  Gated on `IsTerminal` for both streams so pipes/CI fall through to the
  hard error instead of blocking. Most-private source (never in argv,
  env, or shell history). Benefits both `download --paranoid` and
  `decrypt`. rpassword wraps the termios/Win32 `unsafe`, keeping our code
  unsafe-free.
- [x] **P2 — randomized µTP receiver seq as an accept token.** DONE
  (commit c63fc05): `new_receiver` now draws its initial seq_nr from the
  CSPRNG (same source as the connection_ids) as an unguessable accept
  token. The driver marks the return path confirmed — and only then
  surfaces the connection to `accept()` — when an incoming non-SYN packet's
  cumulative ack lands in a bounded window anchored at that token (a SYN
  never confirms; a half-space `seq_le` would have accepted ~50% of random
  forgeries, so the window is exact). Closes the residual blind SYN+DATA
  spoof. Unit-tested (legit ack confirms; forged ack doesn't; seq is
  randomized).

## 2. Privacy & anonymity

- [x] **P1 — verify `--anonymous` covers ALL egress, end to end.** Spot
  checks pass (listener off, DHT off, MSE forced, UDP trackers rejected,
  cleartext `http://` trackers rejected, port=0, ephemeral peer_id
  [verified]). DONE: audited every egress path and updated
  `docs/ANONYMITY.md`. Findings: (1) tracker HTTP always uses the proxied
  reqwest client with `socks5h://` when a proxy is set — remote DNS, no
  fallback to the default route; (2) anonymous refuses to start without a
  proxy (`engine.rs`), so there's no clearnet dial path; (3) `--web` and
  the daemon UI are loopback-only and never dial out *except* the daemon's
  runtime magnet bootstrap (clearnet — daemon doesn't support anonymous,
  now documented); (4) proxy-host DNS is resolved once at startup on the
  host (unavoidable; use an IP literal to avoid). Also FIXED two stale
  claims the audit caught in ANONYMITY.md: it said µTP "isn't implemented"
  and "is force-disabled under --bind-iface" — both untrue after the µTP
  work; corrected to: µTP is implemented, hard-off under anonymous/socks5,
  interface-bound under --bind-iface.
- [x] **P1 — interface-bind the µTP socket** so `--utp` can coexist with
  `--bind-iface` (was force-disabled there). DONE: added
  `UtpSocket::from_udp(UdpSocket)` so a caller can hand it a pre-bound
  socket; the engine now builds the µTP datagram socket via
  `netbind::bind_udp_to_interface` when `--bind-iface` is set, pinning it
  to the same interface as the TCP path. Still gated off under
  `--anonymous`/`--socks5` (UDP can't ride SOCKS5). CLI help + gating
  comments updated.
- [ ] **P2 — tracker HTTP is not interface-bindable** (reqwest
  limitation) — documented residual of `--bind-iface`. Investigate a
  reqwest connector that binds to the interface, or route the tracker
  through the SOCKS5 path uniformly.
- [ ] **P2 — MSE reserved-byte fingerprint** (roadmap B5 partially done):
  audit the exact reserved-bytes pattern vs libtorrent to minimize the
  DPI fingerprint surface under `--anonymous`.
- [ ] **P2 — i2p transport** (roadmap C4) — native anonymity overlay; big.

## 3. Performance & speed

- [x] **P0 — `scan_resume` hashes every piece inline on the async
  runtime.** [DONE] `storage/disk.rs` now offloads each piece's SHA-1 to
  `spawn_blocking` so the resume scan no longer freezes the reactor.
  Further win available: pipeline reads + hashing across cores (still P2).
- [x] **P1 — `picker.pick_for` rebuilds + sorts a candidates `Vec` every
  call.** [verified] `piece/picker.rs` did O(n log n) per block request.
  DONE (partial — the low-risk half): replaced the `collect + sort_by_key`
  with a single O(n) min-availability pass that keeps only the
  current-best tie group, and made sequential mode early-exit at the first
  usable (lowest-index) piece instead of collecting + `min`-ing. Removes
  the sort and the full-candidate allocation; behavior (rarest-first with
  tie-shuffle) is identical, all picker tests green. The fully incremental
  availability-bucket structure remains a possible future step but wasn't
  needed to kill the sort — left as a note, not a blocker.
- [x] **P1 — `file_progress` + peer-list scan every progress tick.**
  [verified] `engine.rs` `file_progress` iterated all pieces × all files
  each ~2 s. DONE: (1) the scan was already gated behind a connected web
  watcher (`web_tx.is_some()`), so it never runs headless; (2) added a
  memo keyed on `pm.complete_count()` (a cheap popcount) — completed
  pieces only grow, so an unchanged count means byte-identical fractions
  and the O(pieces × files) rescan is skipped, reused from cache. The
  per-tick peer-address `collect()` is left as-is: it's O(connected
  peers) (≤ the peer cap, a few dozen), negligible vs the piece scan.
- [x] **P1 — `read_frame` allocates a fresh `Vec` per wire frame.**
  [verified] `peer/message.rs:211` `vec![0u8; len]` per frame (per 16 KiB
  block on the download path). DONE: added `read_frame_into(reader,
  max_len, &mut buf)` reading into a per-peer reusable `Vec` (capacity
  retained across frames); the read loop in `connection.rs` now allocates
  nothing in steady state. Safe because `Message::decode` copies every
  variable-length field into an owned `Vec`, so the borrow ends before the
  next read. (The `Message::Piece { data: p[8..].to_vec() }` decode copy
  is unavoidable here — the piece data must outlive the reused buffer to
  reach the storage writer.)
- [x] **P1 — block data is cloned on the upload path.** [verified]
  `engine.rs:~1302` / `storage/memspool.rs` clone `Vec<u8>` per served
  block. DONE (the cheap, high-value copies): the cache-hit serve path
  went from **three** 16 KiB copies per block to **two**.
  (1) `write_message` gained a single-pass `Piece` branch, but the main
  upload loop in `connection.rs` was still calling `Message::Piece.encode()`
  + `write_all` — `encode()` copies the block *twice* (payload scratch +
  `tag()`). The Piece send now routes through `write_message`, so that's
  one copy instead of two. (2) Earlier work already cut the wire-build to
  a single pass. The one remaining copy is the cache-`Arc`→`Vec` slice in
  `serve_request`. Eliminating it would need `PeerCommand::Piece.data`,
  `Message::Piece.data`, `PeerEvent::Block.data`, and `StorageCommand`
  to all become `bytes::Bytes` in lockstep — otherwise the incoming
  decode→`Block` path gains a *new* `Bytes`→`Vec` copy on the download
  side. That wide core-path change isn't justified by one remaining
  memcpy in a security-first codebase, so it's deliberately deferred.
- [x] **P2 — spool write pads/allocates per write.** `storage/spool.rs`
  DONE: `write_piece` now reuses a `write_scratch` buffer instead of
  `data.to_vec()` + `resize` per call, and `read_range` returns the
  decrypted buffer directly on a full-piece read (the upload-cache
  pattern) instead of cloning a sub-slice. Short-last-piece + full-piece
  roundtrips still green.
- [x] **P2 — disk `flush()` per piece recomputes `slices_for_piece`.**
  `storage/disk.rs` — DONE: `write_piece` called `slices_for_piece` twice
  (write loop + flush loop). Now it records the touched file indices
  during the write (slices are in file order, so a last-element check
  dedups) and flushes exactly those, dropping the redundant recompute.
  Verified by the multi-file disk test + the multi-file download e2e.
- [x] **P2 — µTP `Send` command allocates `Vec<u8>` per chunk.** DONE
  (commit c63fc05): a new `Payload` type is a slice into a shared
  `Arc<[u8]>`; outgoing data is buffered as whole `Arc<[u8]>` blocks and
  sliced into packets that share one allocation, so a block split into N
  packets allocates once, and a retransmit clone is just a refcount bump.
  `Command::Send` carries `Arc<[u8]>`; the `AsyncWrite` impl still takes
  `&[u8]`.
- [x] **P2 — bitfield byte→bits expansion is a manual per-bit loop.**
  `message.rs bitfield_from_bytes` — DONE: replaced the per-bit
  shift/branch loop with a bulk `BitVec::<u8, Msb0>::from_slice(bytes)` +
  `truncate(num_pieces)`. `Msb0` ordering is exactly the wire layout, so
  it's byte-for-byte equivalent (all bitfield tests green) without
  per-bit work.

## 4. Correctness & robustness

- [x] **P0 — `complete_count()` can exceed `wanted_count()` under
  `--select` after a resume.** [DONE] Added
  `PieceManager::wanted_complete_count()` (counts `wanted & local`) and
  switched `build_stats` + `log_progress` to it, so the displayed
  progress is wanted-relative and can't exceed 100%. Unit-tested.
- [x] **P1 — daemon shutdown race window.** [DONE] `shutdown_all` now
  joins each engine task against a shared 8 s deadline (`select!` task vs
  `sleep_until`), force-aborting only a straggler past it — so a slow
  storage flush / tracker-stopped isn't truncated by the old fixed
  500 ms. (`remove()`'s detached 10 s reaper is left: it self-completes,
  so it's bounded, not a real leak.)
- [x] **P1 — production panic audit.** [DONE — clean] Scanned the hot
  files' non-test code: there are NO production `.unwrap()`s (the agent's
  `main.rs send().unwrap()` claim was a false positive). The only
  `.expect()`s left (`engine.rs` passphrase/dht, `dht/server.rs` persist)
  are all locally invariant-guarded with comments ("checked above",
  "guarded by `if`") — acceptable assertions, not input-panics. The "no
  panics in production paths" principle already holds.
- [x] **P2 — 16-bit µTP seq_nr wraparound.** DONE (commit c63fc05): the
  reorder buffer is re-keyed from raw `u16` to an absolute non-wrapping
  `u64` logical sequence (a `peer_logical_acked` counter), so ordering and
  the next-expected drain stay monotonic across the 65535→0 wrap; the SACK
  bit offsets derive from the logical distance too, so they're wrap-immune.
  Unit-tested across the boundary (in-order drain + duplicate-before-frontier).
- [x] **P2 — LEDBAT base-delay uses a running min, not the 13-slot
  per-minute history.** DONE (commit c63fc05): added the rolling ~13-slot
  one-minute-minima window; base = max(min-over-history, fixed floor) so it
  recovers upward after a route change while keeping the fail-safe fixed
  floor + 2-packet floor. Unit-tested (recovers after the window expires;
  holds the min within a slot).
- [x] **P2 — engine dropped-`ctl_tx` when `--web` is off** means the
  control select-arm is permanently inert by design — fine, but document
  it so it's not mistaken for a bug. DONE: added an explicit comment at
  the `ctl_rx.recv()` select-arm explaining that the closed channel
  disables the arm by design (no controller without web/daemon), not a bug.

## 5. User experience & CLI

- [x] **P0/P1 — terminal progress line.** [DONE] (Correction: a
  `[progress]` line already existed, but used the session-*average* rate
  with no ETA/peers.) `log_progress` now prints instantaneous ↓/↑ rates,
  connected-peer count, and an ETA every progress tick — wanted-relative,
  so it reads correctly under `--select`/paused.
- [x] **P1 — `--verbose` / `--quiet` flags.** [DONE] Global `-v` (debug),
  `-vv` (trace), `-q` (warn) set the default tracing filter; `RUST_LOG`
  still overrides. No more env-var-only verbosity control.
- [x] **P1 — magnet `add` to the daemon.** [verified gap] Daemon
  `POST /api/add` only took a `.torrent` path. DONE: added
  `POST /api/add_magnet` accepting a `magnet:?xt=urn:btih:…` URI. Because
  the metadata fetch can take many seconds, the handler parses +
  dup-checks synchronously then spawns a background task (tracker
  bootstrap → `fetch_metadata` → `from_info_dict_bytes` → `mgr.add`),
  returning `202 Accepted` with the info-hash hex immediately; the
  session appears in `/api/status` once metadata lands. Daemon v1 is
  tracker-only, so a magnet without `tr=` trackers is rejected up front.
  Added `SessionManager::contains` for the cheap pre-check, wired the
  daemon UI's add box to route `magnet:` links to the new endpoint, and
  covered parse-error / no-tracker / accepted cases in the smoke test.
- [x] **P1 — torrent-creation command (`create`).** [verified gap] No way
  to make a `.torrent` from a file/dir; users needed `mktorrent`. DONE:
  added `src/create.rs` (`create_torrent`) + a `create` subcommand:
  `rustytorrent create <path> [--tracker URL]... [--piece-length N]
  [--name NAME] [-o OUT] [--private]`. Streams the input in piece-length
  chunks (single file or recursively-walked dir, symlinks skipped),
  builds the canonical info dict via the existing `BencodeValue::to_bytes`
  (BTreeMap ⇒ sorted keys), computes the info-hash, and writes the
  metainfo (`announce` + BEP 12 `announce-list`, optional BEP 27
  `private`). Hashing runs on `spawn_blocking`. Verified the output
  re-parses through our own loader AND that an independent Python bencode
  parser computes the identical info-hash (interop). Unit tests cover
  single-file, multi-file, private, and zero-piece-length rejection.
- [ ] **P2 — single-download queue / resume-list.** Without the daemon,
  one torrent per process and no persisted queue. Either document "use
  `daemon`" or add a simple resume-list the daemon restores on startup.
- [x] **P2 — print the selected files after `--select` resolves.**
  DONE: added `Layout::selected_paths(selectors)` and the engine now
  prints each matched file (relative to the torrent root) after the piece
  summary, plus a loud warning when a `--select` pattern matched nothing
  (previously a typo silently downloaded zero bytes with no explanation).
  Unit-tested match/empty cases. (Originally flagged [verified] —
  especially useful for magnet, where metadata arrives async, so the user
  sees `--select` took effect.)
- [x] **P2 — actionable error messages.** DONE (commit 8d93997): every
  `Error` Display string now carries remediation guidance derived from the
  real construction sites — tracker (down/unreachable → check network/proxy;
  DHT/PEX can still find peers), network (dial/timeout → connectivity,
  `--socks5`, `--bind-iface`), handshake (incompatible / encryption-only
  swarm), crypto (wrong/missing `--passphrase` or tampered spool), I/O
  (path/space/perms), bencode (malformed/truncated). The `{0}`/`{index}`
  detail is preserved; per-variant maintainer doc comments added.

## 6. Features (roadmap follow-ups)

- [x] **P1 — daemon: one shared inbound listener** demuxing by info_hash
  instead of one port per session (see `docs/DAEMON.md`). DONE: new
  `src/acceptor.rs` owns one TCP (+ optional µTP) listener; for each
  connection it drives the handshake far enough to learn the info_hash
  (plain: read the 68-byte handshake; MSE: `mse::perform_incoming` with
  the current candidate set), looks the session up in a shared
  `Registry`, and forwards the already-handshaken connection via
  `Inbound::Handshaken`. Engine gained a `set_managed_inbound` seam
  (skips binding its own listener); the single-torrent `download`/`magnet`
  path is byte-identical (it emits `Inbound::Raw` and handshakes itself).
  Integration-tested end to end (`tests/daemon_shared.rs`): inbound routes
  to the right session, unknown info_hash is dropped, and removal stops
  routing.
- [x] **P1 — daemon: one shared DHT** instead of DHT-off-per-session.
  DONE: `cmd_daemon` spawns one `Dht` (unless `--no-dht`) and
  `SessionManager` hands each eligible session a clone via the engine's
  `set_managed_dht` seam. The engine never shuts down a shared DHT
  (`owns_dht`); the manager shuts it down once on daemon exit so the
  routing-table state persists cleanly. Per-torrent gating still applies
  (anonymous/private sessions get no handle).
- [x] **P2 — daemon persistence:** save/restore the hosted torrent set
  across restarts. DONE: new `src/daemon_store.rs` (`DaemonStore`) stores
  each hosted torrent as `<ih>.torrent` (verbatim metainfo — info-hash
  preserved) + a `<ih>.json` sidecar (output dir, DHT intent).
  `SessionManager::add_persistent` saves on add; `remove` forgets; daemon
  shutdown deliberately keeps the set so the next start restores it.
  `cmd_daemon` restores on startup; both web add paths persist (magnet
  via `assemble_torrent_bytes`, which splices the info dict verbatim).
  Unit + integration tested (info-hash preservation, save/forget,
  shutdown-keeps-set).
- [x] **P2 — selective download: skip allocating unwanted files.** DONE
  (commit 0638591): `Layout::wanted_files(selectors)` computes the set of
  files holding ≥1 byte of a wanted piece — boundary/straddle files stay
  wanted-for-allocation because they receive spillover writes — and the
  plain-disk backend skips `create`/`set_len` for files outside that set
  (kept as `None` slots, with a defensive error, not a panic, if a skipped
  slot is ever referenced). The engine passes the mask only to the disk
  backend; memory-only/paranoid are unaffected. Fail-safe: allocate when
  unsure. An e2e test asserts an unwanted, non-boundary file is never
  created on disk while the selected file downloads byte-complete.
- [ ] **P2 — plugin system for custom piece pickers** (roadmap stretch).
- [x] **P2 — IPv6: confirm dual-stack dialing.** DONE (commit 73fa060):
  added `tests/ipv6_dial.rs`, a seeder↔leecher loopback e2e conducted
  entirely over `::1` (free port via binding `[::1]:0`; the dialed address
  is asserted `is_ipv6() && is_loopback()` so a silent v4 downgrade fails
  the test). Verified end to end with NO code change needed — the engine
  already binds a dual-stack listener (`bind_dual_stack_listener`: a
  `socket2` IPv6 socket with `set_only_v6(false)` on `[::]`) and the
  outbound dial uses family-agnostic `TcpStream::connect`, so an IPv6
  `SocketAddr` flows through the dial path untouched.

## 7. Testing

- [x] **P0 — end-to-end seeder↔leecher download test.** [DONE]
  `tests/download_e2e.rs`: a seeder engine (started complete) serves a
  leecher over loopback (no tracker, direct `--peer`); asserts
  byte-identical output. Exercises the whole download path — handshake,
  bitfield, rarest-first picker, pipelining, SHA-1 verify, disk writes,
  completion — in ~0.5 s.
- [x] **P1 — multi-file write-offset correctness test.** [DONE] Second
  test in `download_e2e.rs`: a 2-file torrent whose boundary falls inside
  a piece; asserts each file is written byte-identical (the virtual
  offset map splits the straddling piece correctly).
- [x] **P1 — resume/restart test.** [DONE] `resume_from_partial_download`
  in `download_e2e.rs`: pre-populates the leecher's output with the first
  two pieces correct + the rest zeroed; asserts `scan_resume` verifies
  them so only the last piece is fetched and the final file is
  byte-identical.
- [x] **P1 — `--select` end-to-end engine test.** [DONE]
  `selective_download_fetches_only_wanted_file` in `download_e2e.rs`:
  selects one file of a 2-file torrent, asserts the leecher completes
  (wanted-relative) and writes the selected file in full without fetching
  the other file's exclusive piece. Validates the selective-download +
  completion path end to end.
- [x] **P2 — choke scheduler under load.** DONE (commit 830b0b2): 7 tests
  drive `ChokeScheduler` with many competing peers — regular slots go to
  the top-3 by rate (`REGULAR_UNCHOKE_SLOTS`), the optimistic slot lands
  outside that set, seeding mode ranks by upload rate (the snub filter is
  bypassed when seeding), and the edge cases hold (empty / fewer-than-slots
  candidates, `forget`, no tick-to-tick fibrillation). The time-gated
  behavior (60 s snub threshold, 30 s optimistic rotation) reads
  `Instant::now()` with no injection seam, so it's left untested rather than
  adding a production-only time seam — noted as a limitation.
- [x] **P2 — property/fuzz the bencode + KRPC + message parsers** on
  random/adversarial input. DONE (commit 8323562): added `proptest`
  (dev-dep) and `tests/parser_props.rs` — 9 property tests asserting the
  three untrusted-input decoders never panic on arbitrary bytes and that
  valid values round-trip (`decode∘encode == id`). bencode uses a recursive
  depth-bounded value strategy; message covers all variants (stripping the
  4-byte length prefix that `encode` adds but `decode` doesn't expect); krpc
  is fuzzed on both arbitrary bytes and valid-bencode-but-invalid-krpc.
  Extended (commit c7aed6f) with `tests/wire_props.rs` — 23 more props
  covering the rest of the untrusted-input wire surface: peer handshake,
  UDP-tracker announce response, the BEP 10 extension / ut_metadata / ut_pex
  payloads, and the DHT compact node/peer decoders (never-panic + roundtrip
  where an encoder exists). Extended again (commit 56c449f) with
  `tests/metainfo_props.rs` — 8 props on the *semantic* layer above bencode
  (`TorrentFile::from_bytes`, `from_info_dict_bytes`, `MagnetLink::parse`)
  fed arbitrary + structured-hostile input, proving the path-traversal
  rejection and the `1..=1 GiB` piece_length bound can't be bypassed by any
  crafted-but-valid bencode. And `tests/layout_props.rs` (commit f81c634)
  property-tests the multi-file virtual offset map: across 2000 random
  layouts (incl. 0-length files + short final pieces) `slices_for_piece`
  exactly tiles every file `[0,len)` with no gaps/overlaps and correct
  byte totals — the multi-file write-correctness invariant. Both held, no
  bug found. (cargo-fuzz continuous fuzzing remains a possible future add;
  proptest covers the never-panic + roundtrip invariants in-suite.)

## 8. Code quality / tech debt

- [x] **P1 — `hex` duplication.** [DONE] New `src/util.rs` with
  `hex(&[u8]) -> String` and `info_hash_from_hex(&str) -> Option<[u8;20]>`
  (unit-tested). Replaced the encode copies in `main.rs`/`engine.rs`/
  `session.rs`/`web.rs` and the web `parse_info_hash` decode. (`magnet.rs`
  keeps its own nibble parser — it also handles base32 btih, so it's not
  the same function.)
- [x] **P1 — CLI arg duplication between `download` and `magnet`.** DONE
  (commit 3b9c2ba): the 21 verbatim-shared flags are now a
  `#[derive(clap::Args)] SharedDownloadArgs` `#[command(flatten)]`'d into
  both variants (all `requires`/`conflicts_with` relations preserved).
  Per-variant differences stay on the enum: `--dht` (default `false` for
  download, `true` for magnet), `--no-tracker` (download only), and the
  `file`/`uri` positionals. `cmd_download`/`cmd_magnet` now take the struct
  (destructured at the call site so `EngineConfig` is still built in
  `main.rs`); both `#[allow(clippy::too_many_arguments)]` were removed.
- [ ] **P2 — `engine.rs run()` is ~500 lines of one `select!`.** Extract
  per-event handlers (tracker tick, choke tick, dht tick, peer event,
  control) to shrink the loop body.
- [x] **P2 — remove/justify `#[allow(dead_code)]`** in
  `metadata_fetch.rs` (×2), `dht/server.rs`, `storage/memspool.rs`. DONE:
  removed the two `metadata_fetch.rs` `const _ = CONST` import-keeper
  hacks (and the now-unused `HANDSHAKE_LEN`/`BLOCK_SIZE` imports); removed
  the genuinely-unused `memspool::diagnostic_backing_path` (+ its
  `PathBuf` import) as YAGNI. Kept `dht/server.rs KrpcReply::Error` — it
  IS constructed, its fields are intentionally captured-but-unread for
  future error tracing, and the comment already justifies it.
- [x] **P2 — document magic constants** (`ENDGAME_REMAINING = 5`,
  `INITIAL_WINDOW_PACKETS`, choke slot counts) with the rationale. DONE:
  expanded the doc comments on `ENDGAME_REMAINING` + `PIPELINE_DEPTH`
  (engine), `INITIAL_WINDOW_PACKETS` (µTP), and all five choke constants
  (`CHOKE_INTERVAL`, `OPTIMISTIC_INTERVAL`, `RATE_WINDOW`,
  `SNUB_THRESHOLD`, `REGULAR_UNCHOKE_SLOTS`) explaining the value chosen
  and why.
- [ ] **P2 — split large modules** (`peer/connection.rs` ~1k lines,
  `main.rs` ~1.1k) along natural seams.

---

### Notes / verified non-issues (don't re-open)

- AES-GCM nonce uniqueness (random 96-bit), Argon2id params, RC4
  `ZeroizeOnDrop`, bencode depth cap, `read_frame` max-len bound,
  ut_metadata/piece-length caps, KRPC bounds, UDP-tracker source filter,
  loopback-only web bind, seccomp/SBPL profiles, anonymous-mode peer_id
  ephemerality (`generate_libtorrent_lookalike` [verified]), and the
  live-download verify on `spawn_blocking` — all reviewed and OK.
