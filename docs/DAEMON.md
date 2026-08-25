# RustyTorrent — Multi-Torrent Daemon (design)

The last open Phase 8 item is runtime **add / remove** of torrents and a
**multi-torrent** view. Today the client is one-torrent-per-process:
`TorrentEngine::run(self)` consumes `self`, binds a listener + (optional)
DHT + (optional) web server, runs one torrent to completion, and exits.

This document is the plan to turn that into a long-running **daemon**
hosting N torrents behind one control surface, without regressing the
existing single-torrent CLI. It exists so the refactor can be executed
in small, individually-shippable, test-backed steps rather than one big
risky change.

---

## Goals

- `rustytorrent daemon --web PORT [torrents...]` — a process that hosts
  zero or more torrents and serves one web UI/API for all of them.
- `POST /api/add` (a `.torrent` path or a magnet URI) → start a torrent.
- `POST /api/remove` (info_hash) → stop + drop a torrent.
- `GET /api/status` → an **array** of per-torrent stats; existing
  per-torrent endpoints become `/api/torrent/{info_hash}/...`.
- The existing `download` / `magnet` subcommands keep working **exactly**
  as today (single torrent, runs to completion, exits).

## Non-goals (for the first cut)

- ~~Persisting the torrent set across restarts (resume list).~~ **Done**:
  DaemonStore persists each hosted torrent + sidecar; restore on startup.
- Auth on the control API — it stays **loopback-only**, same as now.
- Scheduling / queueing / per-torrent rate caps. Follow-up.

---

## The hard decisions

### 1. Inbound listener — one shared, demux by info_hash

Each torrent currently binds its own TCP (and µTP/UDP) listener on
`listen_port`. N torrents cannot each own the same port, and allocating a
port per torrent is ugly and firewall-hostile.

**Decision:** the daemon binds **one** inbound TCP listener (and one µTP
`UtpSocket`) on a single port. The BitTorrent handshake carries the
`info_hash` in its first 48 bytes, so the daemon peeks/reads the
handshake, looks up the matching session by `info_hash`, and hands the
connection to that session's `PeerManager::accept_incoming`. Unknown
info_hash → drop.

This means the per-connection accept path moves up from the engine to a
shared **acceptor** that owns the listener and a `HashMap<InfoHash,
SessionHandle>`. The existing `run_incoming_dispatch` (plain-vs-MSE peek)
already reads the handshake; it needs to additionally route by info_hash.
MSE complicates this: the info_hash isn't in cleartext for an MSE dial —
but MSE's `req2 = HASH('req2', info_hash)` is matched against the set of
known info_hashes (see `mse::perform_incoming`, which already takes a
*slice* of candidate info_hashes). So the shared acceptor passes **all**
active info_hashes to `perform_incoming`, which returns the matched one.
That's already supported — `perform_incoming` was built for exactly this.

### 2. DHT — one shared instance

DHT is global (a single Kademlia routing table), not per-torrent. Today
each engine spawns its own `Dht`. In the daemon, spawn **one** `Dht` and
have every session call `get_peers(info_hash)` / `announce_peer` against
it. `Dht` is already `Clone` (cheap handle over an mpsc), so sessions
share a clone. Anonymous/private/bind-iface gating stays per-torrent for
*announce/use*, but the socket is shared.

### 3. The session abstraction

Extract the per-torrent run loop into a `Session` that does **not** own
the listener, DHT, or web server. A `SessionManager` owns those shared
resources and a `HashMap<InfoHash, Session>`.

```
SessionManager
├── shared TCP listener + UtpSocket   (acceptor task, routes by info_hash)
├── shared Dht                        (Option)
├── web server (one, aggregates)
└── sessions: HashMap<InfoHash, SessionHandle>
        SessionHandle {
            name, info_hash,
            stats_rx: watch::Receiver<EngineStats>,  // engine → manager
            ctl_tx:  mpsc::Sender<EngineControl>,     // manager → engine
            inbound_tx: mpsc::Sender<(Transport, SocketAddr)>, // acceptor → engine
            task: JoinHandle<()>,
        }
```

The engine already exposes the right seams from the Phase 8 work:
`EngineStats` (watch) and `EngineControl` (pause/resume mpsc). Extend
`EngineControl` with `Remove`/`Shutdown` so the manager can stop a
session cleanly (graceful: tracker `stopped`, storage flush).

### 4. Decoupling step (behavior-preserving)

`run(self)` becomes a thin wrapper that creates the channels + binds its
own listener/DHT/web (today's behavior) and calls a new
`run_inner(self, deps)` where `deps` carries the listener/DHT/web/control
handles. The daemon calls `run_inner` with **shared** deps instead. This
is the one large mechanical move; it must land with the full test suite
green and a localhost self-test confirming the single-torrent path is
byte-identical.

### 5. Web layer — aggregate

`WebState` gains a handle to the `SessionManager`. `GET /api/status`
returns `Vec<EngineStats>` (one per session). Per-torrent control becomes
`POST /api/torrent/{info_hash}/pause|resume|remove`. The status page
becomes a list with a row per torrent (reusing the existing single-torrent
rendering per row). `POST /api/add` takes a body of either a magnet URI
or a path/uploaded `.torrent`.

---

## Incremental plan (each step ships + tests independently)

1. **[DONE] Engine inbound seam** — rather than the originally-planned
   `run_inner(deps)` split, the engine gained a narrower
   `set_managed_inbound` seam: all inbound connections flow through one
   `mpsc<Inbound>` channel, and in managed mode the engine reads it
   instead of binding its own listener. Single-torrent `download`/`magnet`
   is byte-identical (it emits `Inbound::Raw` and handshakes itself).
2. **[DONE] Shared acceptor** — `src/acceptor.rs` owns one listener and a
   `Registry` (info_hash → session inbound channel), handshakes each
   connection (plain + MSE), and routes by info_hash. Unit tests cover
   plain routing, the MSE candidate match, and the unknown-hash drop.
3. **[DONE] SessionManager + `daemon` subcommand** — `with_shared` owns the
   registry, the shared DHT, and the acceptor task; `cmd_daemon` binds one
   listener on `--port`, spawns one DHT (unless `--no-dht`), and hosts all
   torrents on it. `GET /api/status` already returns an array.
   `tests/daemon_shared.rs` exercises the routing end to end.
4. **[DONE] `POST /api/add` / per-torrent control** — runtime add (path +
   magnet) and pause/resume/remove via the web layer.
5. **Persistence (follow-up)** — save/restore the torrent set.

Steps 1–3 landed behavior-preserving for the single-torrent path and are
covered by the full test suite.

---

## Risks / watch-items

- **MSE inbound routing**: confirmed feasible — `mse::perform_incoming`
  already matches against a set of info_hashes. The shared acceptor must
  pass the *current* active set (it changes as torrents are added/removed).
- **Graceful per-session shutdown**: `EngineControl::Remove` must run the
  same teardown `run` does on completion (tracker `stopped`, storage
  flush, DHT state save is now shared so only saved on daemon exit).
- **Port/firewall**: one listen port for the daemon — document that the
  user maps a single port, same as a normal client.
- **Resource caps**: [DONE] a daemon with many torrents now has a global
  peer cap (`--max-peers-total`, default 500) shared across all sessions
  via `peer::manager::GlobalPeerCap`, on top of per-torrent `max_peers`.
  Each peer holds an RAII guard released on disconnect/ban/forget.
