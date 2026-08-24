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

/// Screen contacts restored from the persist file through the same martian
/// filter applied to live wire input (`util::is_dialable_peer_addr`): a
/// tampered or stale state file must not be able to aim our startup DHT
/// probes at loopback, link-local or NAT64 targets. Strictness is DERIVED
/// AT SPAWN TIME (`anonymous || proxied`) and passed in — never hardcoded
/// here — so if DHT gating ever loosens, this filter re-tightens with it.
fn dialable_warm_contacts(
    contacts: Vec<routing::Contact>,
    strict_martians: bool,
) -> Vec<routing::Contact> {
    let before = contacts.len();
    let kept: Vec<routing::Contact> = contacts
        .into_iter()
        .filter(|c| crate::util::is_dialable_peer_addr(&c.addr, strict_martians))
        .collect();
    let dropped = before - kept.len();
    if dropped > 0 {
        tracing::warn!(
            target: "dht",
            dropped,
            "dropped martian contacts from persisted dht state"
        );
    }
    kept
}

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
    ///
    /// `bind_iface` pins the DHT's UDP socket to a network interface (the
    /// VPN kill switch): `Some("utun0")` makes DHT traffic fail closed if
    /// the tunnel drops, just like the TCP peer dials. `None` binds the
    /// default route.
    pub async fn spawn(
        listen_port: u16,
        bootstrap: Vec<String>,
        persist_path: Option<PathBuf>,
        bind_iface: Option<String>,
        // `anonymous || proxied`, derived by the CALLER (engine /
        // magnet bootstrap / daemon) so the martian filter tightens
        // exactly when the DHT would be running behind an anonymity
        // tunnel. Never hardcode `false` here.
        strict_martians: bool,
    ) -> Result<Self, std::io::Error> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        // Try loading previously-persisted state. Failure → empty start.
        let (node_id, warm_contacts) = match persist_path.as_deref().and_then(persist::load) {
            Some((id, c)) => {
                let kept = dialable_warm_contacts(c, strict_martians);
                tracing::info!(
                    target: "dht",
                    contacts = kept.len(),
                    "loaded persisted dht state"
                );
                (Some(id), kept)
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
            bind_iface,
            strict_martians,
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

#[cfg(test)]
mod warm_contacts_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn contact(ip: [u8; 4], port: u16) -> routing::Contact {
        routing::Contact::new(
            NodeId([9u8; 20]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port),
        )
    }

    #[test]
    fn persisted_martian_contacts_are_dropped_before_warming() {
        let contacts = vec![
            contact([93, 184, 215, 14], 6881), // public — kept
            contact([127, 0, 0, 1], 6881),     // loopback — dropped
            contact([169, 254, 169, 254], 80), // link-local metadata — dropped
            contact([192, 168, 1, 50], 51413), // site-local — allowed (clearnet DHT)
        ];
        let kept = dialable_warm_contacts(contacts, false);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].addr.to_string(), "93.184.215.14:6881");
        assert_eq!(kept[1].addr.to_string(), "192.168.1.50:51413");
    }

    /// The coupling pin: under anonymity (strict = true) LAN/ULA targets
    /// from a tampered persist file must ALSO be refused — an anonymous
    /// client probing RFC1918 through its tunnel is exactly the SSRF the
    /// martian filter exists to prevent. The non-strict control case
    /// above makes any future divergence obvious.
    #[test]
    fn persisted_martian_filter_is_strict_when_anonymous_or_proxied() {
        let public = contact([93, 184, 215, 14], 6881);
        let lan: Vec<routing::Contact> = [[192, 168, 1, 50], [10, 0, 0, 7], [172, 16, 5, 5]]
            .iter()
            .map(|ip| contact(*ip, 6881))
            .collect();

        // Control: without anonymity, LAN hops stay allowed.
        let mut list_nonstrict = vec![public.clone()];
        list_nonstrict.extend(lan.clone());
        let kept_nonstrict = dialable_warm_contacts(list_nonstrict, false);
        assert_eq!(kept_nonstrict.len(), 4);

        // Strict: every LAN hop dropped, public kept.
        let mut list_strict = vec![public];
        list_strict.extend(lan);
        let kept_strict = dialable_warm_contacts(list_strict, true);
        assert_eq!(kept_strict.len(), 1);
        assert_eq!(kept_strict[0].addr.to_string(), "93.184.215.14:6881");

        // ULA (fd00::/8) must also be refused under strict.
        let ula = routing::Contact::new(
            NodeId([7u8; 20]),
            "[fd00::1]:6881".parse::<std::net::SocketAddr>().unwrap(),
        );
        assert!(dialable_warm_contacts(vec![ula], true).is_empty());
    }
}
