//! Multi-torrent daemon — a [`SessionManager`] hosting many
//! [`TorrentEngine`]s behind one shared web/control surface, each driven
//! through the engine's `set_managed*` seams.
//!
//! ## Shared resources
//!
//! When constructed with [`SessionManager::with_shared`] the manager owns
//! the daemon-wide resources and threads them into every session it
//! starts:
//!
//! - **One inbound listener.** A single [`crate::acceptor`] owns the TCP
//!   (and optional µTP) listener and routes each connection to the right
//!   session by info_hash. Sessions register their inbound channel in the
//!   shared [`crate::acceptor::Registry`] on add and unregister on remove,
//!   so the daemon opens just one port instead of one per torrent.
//! - **One DHT.** A single [`crate::dht::Dht`] is shared by clone; the
//!   manager shuts it down once on daemon exit so its routing-table state
//!   persists cleanly (per-session DHTs would race on the state file).
//!
//! A `SessionManager::new()` (no shared resources) keeps the standalone
//! behaviour where each engine binds its own listener — used by tests.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;

use crate::engine::{EngineConfig, EngineControl, TorrentEngine};
use crate::metainfo::TorrentFile;
use crate::peer_id::PeerId;
use crate::web::EngineStats;

/// 20-byte info-hash, the per-session key.
pub type InfoHash = [u8; 20];

struct Session {
    /// Latest stats published by the engine.
    stats_rx: watch::Receiver<EngineStats>,
    /// Control channel into the engine (pause/resume/shutdown).
    ctl_tx: mpsc::Sender<EngineControl>,
    /// The engine's run task. Reaped on remove.
    task: JoinHandle<()>,
}

/// Daemon-wide resources shared across every session.
struct Shared {
    /// info_hash → session inbound channel, read by the shared acceptor.
    registry: crate::acceptor::Registry,
    /// The shared DHT, if enabled. Shut down once on daemon exit.
    dht: Option<crate::dht::Dht>,
    /// The single port the shared listener is bound to. Threaded into each
    /// session's config so its tracker/DHT announces advertise the right
    /// (reachable) port even though the session binds nothing itself.
    listen_port: u16,
    /// The acceptor's accept-loop task; aborted on daemon shutdown.
    acceptor_task: JoinHandle<()>,
}

/// Owns the running sessions. Cheap to clone (shared behind `Arc`s), so
/// the web handlers and the CLI can both hold one.
#[derive(Clone, Default)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<InfoHash, Session>>>,
    shared: Option<Arc<Shared>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a manager that hosts sessions behind one shared acceptor
    /// (registry + listener task) and an optional shared DHT, all bound to
    /// `listen_port`. The caller (the `daemon` command) binds the listener,
    /// spawns the acceptor with `registry`, and optionally spawns the DHT.
    pub fn with_shared(
        registry: crate::acceptor::Registry,
        dht: Option<crate::dht::Dht>,
        listen_port: u16,
        acceptor_task: JoinHandle<()>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            shared: Some(Arc::new(Shared {
                registry,
                dht,
                listen_port,
                acceptor_task,
            })),
        }
    }

    /// Start hosting `torrent`. Builds an engine driven by managed
    /// channels (no per-engine web server), spawns its run loop, and
    /// records the session. Returns the info-hash key, or `None` if a
    /// session with that info-hash is already running (idempotent add).
    pub async fn add(
        &self,
        torrent: TorrentFile,
        peer_id: PeerId,
        mut cfg: EngineConfig,
    ) -> Option<InfoHash> {
        let info_hash = torrent.info_hash;
        let mut map = self.inner.lock().await;
        if map.contains_key(&info_hash) {
            return None;
        }

        let initial = EngineStats::placeholder(
            torrent.info.name.clone(),
            crate::util::hex(&info_hash),
            torrent.total_length(),
            torrent.num_pieces(),
        );
        let (stats_tx, stats_rx) = watch::channel(initial);
        let (ctl_tx, ctl_rx) = mpsc::channel::<EngineControl>(8);

        // Shared-mode wiring: register an inbound channel with the shared
        // acceptor (so it can route by info_hash) and feed the engine the
        // shared DHT + the shared listen port instead of letting it bind
        // its own listener / spawn its own DHT.
        let (inbound_rx, shared_dht) = if let Some(shared) = &self.shared {
            cfg.listen_port = shared.listen_port;
            // Use the shared DHT only when the session is DHT-eligible
            // (caller asked for it). If we have no shared DHT, force
            // enable_dht off so the engine doesn't spawn its own and race
            // on the persisted-state file.
            let dht = if cfg.enable_dht {
                shared.dht.clone()
            } else {
                None
            };
            if dht.is_none() {
                cfg.enable_dht = false;
            }
            let (tx, rx) = mpsc::channel::<crate::peer::inbound::Inbound>(32);
            shared.registry.lock().await.insert(info_hash, tx);
            (Some(rx), dht)
        } else {
            (None, None)
        };

        let mut engine = TorrentEngine::new(torrent, peer_id, cfg);
        engine.set_managed(stats_tx, ctl_rx);
        if let Some(rx) = inbound_rx {
            engine.set_managed_inbound(rx);
        }
        if let Some(dht) = shared_dht {
            engine.set_managed_dht(dht);
        }
        let task = tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                tracing::warn!(target: "session", error = %e, "session engine ended with error");
            }
        });

        map.insert(
            info_hash,
            Session {
                stats_rx,
                ctl_tx,
                task,
            },
        );
        Some(info_hash)
    }

    /// Drop a session's entry from the shared acceptor registry (no-op in
    /// standalone mode). Called on remove + shutdown so the acceptor stops
    /// routing to a session that's going away.
    async fn unregister(&self, info_hash: &InfoHash) {
        if let Some(shared) = &self.shared {
            shared.registry.lock().await.remove(info_hash);
        }
    }

    /// Snapshot of every session's latest stats.
    pub async fn snapshot(&self) -> Vec<EngineStats> {
        self.inner
            .lock()
            .await
            .values()
            .map(|s| s.stats_rx.borrow().clone())
            .collect()
    }

    /// Number of hosted sessions.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Whether a session with this info-hash is already hosted. A cheap
    /// pre-check before an expensive add path (e.g. a magnet metadata
    /// fetch); [`add`](Self::add) still re-checks atomically at insert
    /// time, so this is only an optimization, not a correctness guard.
    pub async fn contains(&self, info_hash: &InfoHash) -> bool {
        self.inner.lock().await.contains_key(info_hash)
    }

    /// Gracefully stop every session (tracker `stopped`, storage flush)
    /// and clear the map. Used on daemon shutdown. Each engine is given
    /// until a shared deadline to finish its teardown; only a straggler
    /// past the deadline is force-aborted, so a slow storage flush isn't
    /// cut off (the old fixed 500 ms could truncate it).
    pub async fn shutdown_all(&self) {
        let drained: Vec<(InfoHash, Session)> = self.inner.lock().await.drain().collect();
        for (_, s) in &drained {
            let _ = s.ctl_tx.send(EngineControl::Shutdown).await;
        }
        // Shared deadline: total wait is bounded to ~GRACE regardless of
        // session count (later sessions inherit the same absolute instant,
        // and once it's passed sleep_until returns immediately).
        const GRACE: std::time::Duration = std::time::Duration::from_secs(8);
        let deadline = tokio::time::Instant::now() + GRACE;
        for (ih, s) in drained {
            self.unregister(&ih).await;
            let mut task = s.task;
            tokio::select! {
                _ = &mut task => {} // exited gracefully
                _ = tokio::time::sleep_until(deadline) => { task.abort(); }
            }
        }
        // Tear down shared resources once the sessions are gone: stop the
        // acceptor and let the DHT persist + close cleanly.
        if let Some(shared) = &self.shared {
            shared.acceptor_task.abort();
            if let Some(d) = &shared.dht {
                d.shutdown().await;
            }
        }
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Send a control command to one session. Returns false if there's
    /// no such session (or its engine has already exited).
    pub async fn control(&self, info_hash: &InfoHash, cmd: EngineControl) -> bool {
        match self.inner.lock().await.get(info_hash) {
            Some(s) => s.ctl_tx.send(cmd).await.is_ok(),
            None => false,
        }
    }

    /// Remove a session: ask its engine to stop gracefully (tracker
    /// `stopped`, storage flush), drop it from the map, and abort the
    /// task as a backstop if it doesn't exit promptly. Returns false if
    /// there was no such session.
    pub async fn remove(&self, info_hash: &InfoHash) -> bool {
        let session = self.inner.lock().await.remove(info_hash);
        match session {
            Some(s) => {
                // Stop the acceptor routing new connections to this session.
                self.unregister(info_hash).await;
                let _ = s.ctl_tx.send(EngineControl::Shutdown).await;
                // Give the graceful teardown a moment, then ensure the
                // task is gone so we never leak it.
                let task = s.task;
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    task.abort();
                });
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_snapshot_remove_roundtrip() {
        // A minimal valid single-file torrent (no tracker, no DHT — the
        // engine binds a listener and idles since there are no peers).
        let mut buf = Vec::new();
        buf.extend_from_slice(
            b"d4:infod6:lengthi16384e4:name5:t.bin12:piece lengthi16384e6:pieces20:",
        );
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(b"ee");
        let torrent = TorrentFile::from_bytes(&buf).unwrap();
        let ih = torrent.info_hash;

        let mgr = SessionManager::new();
        let mut cfg = EngineConfig {
            no_tracker: true,
            ..Default::default()
        };
        // Use an ephemeral-ish high port unlikely to collide in CI.
        cfg.listen_port = 0; // 0 → OS picks a free port for the listener
        cfg.output_dir = std::env::temp_dir();

        let added = mgr.add(torrent, [9u8; 20], cfg).await;
        assert_eq!(added, Some(ih));
        assert_eq!(mgr.len().await, 1);

        // The placeholder snapshot is available immediately.
        let snap = mgr.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].total_pieces, 1);
        assert_eq!(snap[0].name, "t.bin");

        // Adding the same info-hash again is a no-op.
        // (Rebuild the torrent since `add` consumed the previous one.)
        let mut buf2 = Vec::new();
        buf2.extend_from_slice(
            b"d4:infod6:lengthi16384e4:name5:t.bin12:piece lengthi16384e6:pieces20:",
        );
        buf2.extend_from_slice(&[0u8; 20]);
        buf2.extend_from_slice(b"ee");
        let dup = TorrentFile::from_bytes(&buf2).unwrap();
        assert_eq!(mgr.add(dup, [9u8; 20], EngineConfig::default()).await, None);

        // Control + remove.
        assert!(mgr.control(&ih, EngineControl::Pause).await);
        assert!(mgr.remove(&ih).await);
        assert!(mgr.is_empty().await);
        // Control on a removed session fails.
        assert!(!mgr.control(&ih, EngineControl::Resume).await);
    }
}
