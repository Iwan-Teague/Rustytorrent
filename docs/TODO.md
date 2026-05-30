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

## 1. Security & hardening

- [ ] **P1 — Daemon `POST /api/add` path read is unconstrained.** [verified]
  `web.rs daemon_add` does `tokio::fs::read(body.trim())` on any
  server-side path. Loopback-only so low exposure, but a co-hosted XSS /
  container-localhost foothold could read any file the process can.
  Fix: `canonicalize()` and require the path to live under a configured
  torrent dir (or accept an uploaded `.torrent` body instead of a path).
- [ ] **P2 — DH private-key wipe is best-effort.** [verified]
  `peer/mse/dh.rs` `Drop` overwrites the `BigUint` with `0` but doesn't
  scrub the freed limb allocation; not constant-time. Acceptable (MSE is
  obfuscation, keys are per-connection ephemeral), but either wrap in a
  zeroizing type or downgrade the comment from "wipe" to "best-effort,
  obfuscation-only" so the security claim isn't overstated. The derived
  RC4 state IS properly `ZeroizeOnDrop` — good.
- [ ] **P2 — bencode `parse_bytes` defensive bound.** [verified]
  `metainfo/bencode.rs` guards `rest.len() < len` before `split_at(len)`,
  so it's safe today, but add an explicit pre-check comment / assert so a
  future refactor can't reintroduce a panic path.
- [ ] **P2 — ut_metadata per-session memory budget.** [verified cap]
  `peer/extension.rs` caps a single `metadata_size` at 100 MB, but a peer
  flood across many connections could each allocate up to that. Add a
  global/per-session metadata budget for `MAX_CONCURRENT_FETCH` dials.
- [ ] **P2 — Windows AppContainer sandbox.** `sandbox.rs` supports Linux
  seccomp + macOS SBPL; Windows `--sandbox` is refused. Implement
  AppContainer (roadmap C2 remainder).
- [ ] **P2 — no-echo TTY passphrase prompt** for `--paranoid`. Today the
  passphrase comes from `--passphrase` (warned: leaks in `ps`/history) or
  `RUSTYTORRENT_PASSPHRASE`. Add an interactive no-echo prompt when stdin
  is a TTY and neither is set (needs `rpassword` or termios FFI; test per
  OS).
- [ ] **P2 — randomized µTP receiver seq as an accept token** to close
  the residual blind-spoof (a forged SYN+DATA can still surface one
  inbound connection). `utp/connection.rs new_receiver` uses a fixed
  initial seq; randomize it and only surface to `accept()` once a packet
  acks it. Low impact (the forged conn can't complete the BT handshake;
  bounded by `MAX_CONNS` + handshake timeout) — hence P2.

## 2. Privacy & anonymity

- [ ] **P1 — verify `--anonymous` covers ALL egress, end to end.** Spot
  checks pass (listener off, DHT off, MSE forced, UDP trackers rejected,
  cleartext `http://` trackers rejected, port=0, ephemeral peer_id
  [verified]). Remaining audit: confirm the daemon path and `--web`
  never dial out; confirm `reqwest`'s connection to the SOCKS5 proxy
  itself can't fall back to the default route; confirm no DNS leak for
  the proxy host (it's resolved once at startup → ok). Write it up in
  `docs/ANONYMITY.md` as a coverage matrix.
- [ ] **P1 — interface-bind the µTP socket** so `--utp` can coexist with
  `--bind-iface` (today µTP is force-disabled there). Same `socket2`
  device-bind already used for TCP (`netbind::bind_udp_to_interface`
  exists for DHT — reuse it).
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
- [ ] **P1 — `picker.pick_for` rebuilds + sorts a candidates `Vec` every
  call.** [verified] `piece/picker.rs` does O(n log n) per block request
  over all pieces. For large torrents this is a hot path. Maintain an
  incrementally-updated rarest-piece structure (bucket by availability),
  or cache candidates and invalidate on bitfield/Have changes. Also skip
  the `sort_by_key` entirely in sequential mode (it computes `min`
  separately already). [verified]
- [ ] **P1 — `file_progress` + peer-list scan every progress tick.**
  [verified] `engine.rs` `file_progress` iterates all pieces × all files
  each ~2 s, and `build_stats` re-collects connected-peer addresses every
  tick. Update per-file completion incrementally on piece-complete events
  and cache the peer list, updating on connect/disconnect.
- [ ] **P1 — `read_frame` allocates a fresh `Vec` per wire frame.**
  [verified] `peer/message.rs:211` `vec![0u8; len]` per frame (per 16 KiB
  block on the download path). Reuse a per-peer buffer or adopt
  `bytes::BytesMut`. Same for `Message::Piece { data: p[8..].to_vec() }`
  decode copy.
- [ ] **P1 — block data is cloned on the upload path.** [verified]
  `engine.rs:~1302` / `storage/memspool.rs` clone `Vec<u8>` per served
  block. Share read-only pieces as `Arc<[u8]>` / `Arc<Vec<u8>>` so the
  LRU cache and per-peer serves don't copy.
- [ ] **P2 — spool write pads/allocates per write.** `storage/spool.rs`
  `padded.resize()` allocates a full piece buffer each write; reuse a
  scratch buffer. `plaintext[..].to_vec()` on read clones — return a slice
  where possible.
- [ ] **P2 — disk `flush()` per piece recomputes `slices_for_piece`.**
  `storage/disk.rs` — cache the slice mapping; consider batching flushes.
- [ ] **P2 — µTP `Send` command allocates `Vec<u8>` per chunk.**
  `utp/socket.rs` — a block split into N packets allocates N times;
  consider `Arc<[u8]>` or a ring buffer.
- [ ] **P2 — bitfield byte→bits expansion is a manual per-bit loop.**
  `peer/connection.rs` / `message.rs bitfield_from_bytes` — use a
  bytewise/`bitvec` fast path or a 256-entry lookup table.

## 4. Correctness & robustness

- [x] **P0 — `complete_count()` can exceed `wanted_count()` under
  `--select` after a resume.** [DONE] Added
  `PieceManager::wanted_complete_count()` (counts `wanted & local`) and
  switched `build_stats` + `log_progress` to it, so the displayed
  progress is wanted-relative and can't exceed 100%. Unit-tested.
- [ ] **P1 — daemon shutdown race / abort window.** [verified]
  `session.rs shutdown_all` sleeps 500 ms then `abort()`s — too short if
  a session is mid storage-flush / tracker-stopped. `remove()` spawns a
  detached 10 s-then-abort task that's never tracked. Use
  `tokio::time::timeout` joining the task with a 5–10 s bound; track or
  await the reaper.
- [ ] **P1 — storage-task channel sends `.unwrap()` in production.**
  [claim] `main.rs` storage `cmd_tx.send(..).unwrap()` will panic if the
  storage task died first. Audit all production `.send().unwrap()` /
  `.unwrap()` against the "no panics in production paths" principle and
  convert to graceful handling.
- [ ] **P2 — 16-bit µTP seq_nr wraparound.** [verified, documented]
  `utp/connection.rs` `pending_in: BTreeMap<u16,...>` orders by raw u16,
  which breaks across a 65535→0 wrap (a >65k-packet, ~80 MB single µTP
  connection). `seq_le` is mod-2^16 but the BTreeMap isn't. Practical risk
  low (hard timeout reaps long flows) but it's a real gap. Fix: key the
  reorder buffer by a wrap-aware offset from `peer_seq_nr_acked`.
- [ ] **P2 — LEDBAT base-delay uses a running min, not the 13-slot
  per-minute history.** [verified, documented] Fails safe (over-
  conservative) but can get stuck low after a route change. Add the
  rolling-minute base-delay window per BEP 29 / libtorrent.
- [ ] **P2 — engine dropped-`ctl_tx` when `--web` is off** means the
  control select-arm is permanently inert by design — fine, but document
  it so it's not mistaken for a bug.

## 5. User experience & CLI

- [x] **P0/P1 — terminal progress line.** [DONE] (Correction: a
  `[progress]` line already existed, but used the session-*average* rate
  with no ETA/peers.) `log_progress` now prints instantaneous ↓/↑ rates,
  connected-peer count, and an ETA every progress tick — wanted-relative,
  so it reads correctly under `--select`/paused.
- [ ] **P1 — `--verbose` / `--quiet` flags.** [verified] Verbosity is
  only via `RUST_LOG`. Add flags that set the tracing filter so users
  don't need the env var.
- [ ] **P1 — magnet `add` to the daemon.** [verified gap] Daemon
  `POST /api/add` only takes a `.torrent` path; magnet URIs need the
  metadata-fetch flow wired into the add path (`fetch_metadata` →
  `from_info_dict_bytes` → `mgr.add`).
- [ ] **P1 — torrent-creation command (`create`).** [verified gap] No way
  to make a `.torrent` from a file/dir; users need `mktorrent`. Add
  `rustytorrent create <path> [--tracker URL]` (piece hashing → info dict
  → info_hash).
- [ ] **P2 — single-download queue / resume-list.** Without the daemon,
  one torrent per process and no persisted queue. Either document "use
  `daemon`" or add a simple resume-list the daemon restores on startup.
- [ ] **P2 — print the selected files after `--select` resolves.**
  [verified] Especially for magnet (metadata arrives async); surface what
  matched so the user knows `--select` took effect.
- [ ] **P2 — actionable error messages.** Audit `Error::Network`/`Tracker`
  strings for "what do I do" guidance (e.g. tracker timeouts, MSE-only
  swarms, bind failures).

## 6. Features (roadmap follow-ups)

- [ ] **P1 — daemon: one shared inbound listener** demuxing by info_hash
  instead of one port per session (see `docs/DAEMON.md`). The BT
  handshake carries info_hash; MSE's `perform_incoming` already matches a
  *set* of info_hashes, so routing is feasible.
- [ ] **P1 — daemon: one shared DHT** instead of DHT-off-per-session.
  `Dht` is already `Clone`; thread one instance through all sessions
  (avoids the persisted-state race that forced DHT-off in v1).
- [ ] **P2 — daemon persistence:** save/restore the hosted torrent set
  across restarts.
- [ ] **P2 — selective download: skip allocating unwanted files** (today
  the full layout is created; boundary pieces still write into unwanted
  files — acceptable, but a `--no-pad` could trim).
- [ ] **P2 — plugin system for custom piece pickers** (roadmap stretch).
- [ ] **P2 — IPv6: confirm dual-stack dialing** (listener + compact-peer
  parsing done; verify outbound IPv6 peer dials work end to end).

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
- [ ] **P1 — resume/restart test:** partial download persists and resumes
  correctly (scan_resume rebuilds the bitfield). (The e2e harness now
  makes this easy to add.)
- [x] **P1 — `--select` end-to-end engine test.** [DONE]
  `selective_download_fetches_only_wanted_file` in `download_e2e.rs`:
  selects one file of a 2-file torrent, asserts the leecher completes
  (wanted-relative) and writes the selected file in full without fetching
  the other file's exclusive piece. Validates the selective-download +
  completion path end to end.
- [ ] **P2 — choke scheduler under load** (many peers competing for the
  3+1 unchoke slots; fairness + anti-snubbing).
- [ ] **P2 — property/fuzz the bencode + KRPC + message parsers** on
  random/adversarial input (cargo-fuzz) — they're the untrusted-input
  attack surface.

## 8. Code quality / tech debt

- [ ] **P1 — `hex` is defined 5 times.** [verified] `main.rs hex`,
  `engine.rs hex_lower`, `session.rs hex_lower`, `web.rs hex_lower`,
  `magnet.rs hex_nibble`. Extract one `util::hex` (and a `from_hex`).
- [ ] **P1 — CLI arg duplication between `download` and `magnet`** (~17
  identical flags, twice). [verified] Factor a `#[derive(Args)]
  SharedDownloadArgs` `#[command(flatten)]`'d into both, and a shared
  `EngineConfig` builder so `cmd_download`/`cmd_magnet` stop taking 20+
  positional params (`#[allow(clippy::too_many_arguments)]`).
- [ ] **P2 — `engine.rs run()` is ~500 lines of one `select!`.** Extract
  per-event handlers (tracker tick, choke tick, dht tick, peer event,
  control) to shrink the loop body.
- [ ] **P2 — remove/justify `#[allow(dead_code)]`** in
  `metadata_fetch.rs` (×2), `dht/server.rs`, `storage/memspool.rs`.
- [ ] **P2 — document magic constants** (`ENDGAME_REMAINING = 5`,
  `INITIAL_WINDOW_PACKETS`, choke slot counts) with the rationale.
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
