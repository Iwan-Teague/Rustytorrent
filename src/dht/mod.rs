//! Kademlia DHT (BEP 5) — distributed peer discovery without a tracker.
//!
//! The DHT uses 160-bit node IDs in the same space as BitTorrent info-hashes.
//! Distance between IDs is XOR; nodes maintain a routing table of "k-buckets"
//! organized by prefix length to each contact's ID.
//!
//! Public API: spawn a `Dht`, then call [`Dht::get_peers`] to find peers for
//! an info-hash. The DHT task runs forever in the background; drop the `Dht`
//! (or call [`Dht::shutdown`]) to stop it.
//!
//! Wire format: KRPC messages are bencoded dicts sent over UDP. See
//! <https://www.bittorrent.org/beps/bep_0005.html>.

use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};

pub mod krpc;
pub mod node_id;
pub mod persist;
pub mod routing;
pub mod server;

pub use node_id::NodeId;
pub use routing::RoutingTable;

/// Well-known DHT bootstrap nodes. The BEP discourages auto-adding them to
/// `.torrent` files; using them to seed an empty routing table is the
/// universal convention across qBittorrent / Transmission / libtorrent.
pub const DEFAULT_BOOTSTRAP_NODES: &[&str] = &[
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
];

#[derive(Debug)]
pub(crate) enum DhtCommand {
    GetPeers {
        info_hash: [u8; 20],
        reply: oneshot::Sender<Vec<SocketAddr>>,
    },
    Announce {
        info_hash: [u8; 20],
        port: u16,
    },
    RoutingTableSize {
        reply: oneshot::Sender<usize>,
    },
    Shutdown,
}

/// Handle to a running DHT task. Cheap to clone — clones share the same
/// underlying task.
#[derive(Clone)]
pub struct Dht {
    cmd_tx: mpsc::Sender<DhtCommand>,
}

impl Dht {
    /// Spawn a DHT background task listening on `listen_port` and bootstrapping
    /// from `bootstrap`. Returns a handle; the task lives until the handle is
    /// dropped or [`Dht::shutdown`] is called.
    ///
    /// `persist_path` is where the routing table is loaded from on startup
    /// (if present) and saved to every 5 minutes. Pass `None` to disable
    /// persistence — the DHT will re-bootstrap from scratch each run.
    pub async fn spawn(
        listen_port: u16,
        bootstrap: Vec<String>,
        persist_path: Option<PathBuf>,
    ) -> Result<Self, std::io::Error> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        // Try loading previously-persisted state. Failure → empty start.
        let (node_id, warm_contacts) = match persist_path.as_deref().and_then(persist::load) {
            Some((id, c)) => {
                tracing::info!(
                    target: "dht",
                    contacts = c.len(),
                    "loaded persisted dht state"
                );
                (Some(id), c)
            }
            None => (None, Vec::new()),
        };
        server::spawn(
            listen_port,
            bootstrap,
            node_id,
            warm_contacts,
            persist_path,
            cmd_rx,
        )
        .await?;
        Ok(Self { cmd_tx })
    }

    /// Ask the DHT for peers carrying `info_hash`. Returns whatever the
    /// lookup turned up before a soft timeout; an empty list means we
    /// couldn't find any.
    pub async fn get_peers(&self, info_hash: [u8; 20]) -> Vec<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(DhtCommand::GetPeers {
                info_hash,
                reply: tx,
            })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Tell the DHT we have `info_hash` on `port`. Best-effort — failures are
    /// logged but not surfaced.
    pub async fn announce(&self, info_hash: [u8; 20], port: u16) {
        let _ = self
            .cmd_tx
            .send(DhtCommand::Announce { info_hash, port })
            .await;
    }

    /// Approximate number of contacts in our routing table — useful as a
    /// readiness signal before running expensive lookups.
    pub async fn routing_table_size(&self) -> usize {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(DhtCommand::RoutingTableSize { reply: tx })
            .await
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(DhtCommand::Shutdown).await;
    }
}
