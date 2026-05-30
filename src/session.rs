//! Multi-torrent daemon — a [`SessionManager`] hosting many
//! [`TorrentEngine`]s behind one shared web/control surface, each driven
//! through the engine's `set_managed` seam.
//!
//! ## First-cut scope (see docs/DAEMON.md)
//!
//! This is the v1 daemon. To reuse every line of the existing engine
//! unchanged it takes two deliberate shortcuts vs the eventual design:
//!
//! - **Per-session listener port.** Each session binds its own listener
//!   on `base_port + index` rather than sharing one listener that
//!   demuxes by info_hash. Means the daemon opens several ports; the
//!   shared-listener routing is the documented follow-up.
//! - **DHT disabled.** Each engine would otherwise spawn its own `Dht`
//!   and they'd race on the same persisted-state file. Until a single
//!   shared `Dht` is wired through, daemon sessions are tracker-only.
//!
//! Both are noted so a contributor knows they're intentional, not bugs.

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

/// Owns the running sessions. Cheap to clone (shared behind an `Arc`),
/// so the web handlers and the CLI can both hold one.
#[derive(Clone, Default)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<InfoHash, Session>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start hosting `torrent`. Builds an engine driven by managed
    /// channels (no per-engine web server), spawns its run loop, and
    /// records the session. Returns the info-hash key, or `None` if a
    /// session with that info-hash is already running (idempotent add).
    pub async fn add(
        &self,
        torrent: TorrentFile,
        peer_id: PeerId,
        cfg: EngineConfig,
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

        let mut engine = TorrentEngine::new(torrent, peer_id, cfg);
        engine.set_managed(stats_tx, ctl_rx);
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
        let sessions: Vec<Session> = self.inner.lock().await.drain().map(|(_, s)| s).collect();
        for s in &sessions {
            let _ = s.ctl_tx.send(EngineControl::Shutdown).await;
        }
        // Shared deadline: total wait is bounded to ~GRACE regardless of
        // session count (later sessions inherit the same absolute instant,
        // and once it's passed sleep_until returns immediately).
        const GRACE: std::time::Duration = std::time::Duration::from_secs(8);
        let deadline = tokio::time::Instant::now() + GRACE;
        for s in sessions {
            let mut task = s.task;
            tokio::select! {
                _ = &mut task => {} // exited gracefully
                _ = tokio::time::sleep_until(deadline) => { task.abort(); }
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
