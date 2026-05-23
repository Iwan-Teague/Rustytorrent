use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::peer::connection::{run_outgoing, run_outgoing_mse_only, PeerEvent, PeerHandle};
use crate::peer_id::PeerId;
use crate::socks5::ProxyConfig;

pub const DEFAULT_MAX_PEERS: usize = 50;
pub const PER_PEER_CMD_BUFFER: usize = 64;

/// Pool of active peer connections. The engine owns one of these and
/// uses `handle()` to send commands to specific peers.
pub struct PeerManager {
    info_hash: [u8; 20],
    our_peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    peers: HashMap<SocketAddr, PeerSlot>,
    banned: HashSet<std::net::IpAddr>,
    max_peers: usize,
    force_outgoing_mse: bool,
    proxy: Option<ProxyConfig>,
    bind_iface: Option<String>,
    /// Anonymous-mode flag passed through to each peer task so the
    /// BEP 10 extension handshake omits the `v` (client version) and
    /// `reqq` fields that uniquely fingerprint us as rustytorrent.
    anonymous: bool,
}

struct PeerSlot {
    handle: PeerHandle,
    task: JoinHandle<()>,
}

impl PeerManager {
    pub fn new(
        info_hash: [u8; 20],
        our_peer_id: PeerId,
        event_tx: mpsc::Sender<PeerEvent>,
    ) -> Self {
        Self {
            info_hash,
            our_peer_id,
            event_tx,
            peers: HashMap::new(),
            banned: HashSet::new(),
            max_peers: DEFAULT_MAX_PEERS,
            force_outgoing_mse: false,
            proxy: None,
            bind_iface: None,
            anonymous: false,
        }
    }

    pub fn set_max_peers(&mut self, n: usize) {
        self.max_peers = n;
    }

    pub fn set_force_outgoing_mse(&mut self, on: bool) {
        self.force_outgoing_mse = on;
    }

    pub fn set_proxy(&mut self, proxy: Option<ProxyConfig>) {
        self.proxy = proxy;
    }

    pub fn set_bind_iface(&mut self, iface: Option<String>) {
        self.bind_iface = iface;
    }

    pub fn set_anonymous(&mut self, anonymous: bool) {
        self.anonymous = anonymous;
    }

    /// Replace the peer_id used on every *future* outgoing dial. Already-
    /// established connections retain whichever id was negotiated at
    /// their handshake. Used by anonymous mode to rotate the id between
    /// reannounces (C5) so a long-lived session can't be correlated by
    /// the same 20-byte client identifier appearing in unrelated swarms.
    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        self.our_peer_id = peer_id;
    }

    pub fn connected_count(&self) -> usize {
        self.peers.len()
    }

    pub fn handle(&self, addr: &SocketAddr) -> Option<&PeerHandle> {
        self.peers.get(addr).map(|s| &s.handle)
    }

    pub fn addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.peers.keys()
    }

    pub fn ban(&mut self, ip: std::net::IpAddr) {
        tracing::info!(target: "peer::manager", %ip, "banning peer");
        self.banned.insert(ip);
        let to_drop: Vec<SocketAddr> = self
            .peers
            .keys()
            .filter(|a| a.ip() == ip)
            .copied()
            .collect();
        for a in to_drop {
            self.drop_peer(&a);
        }
    }

    pub fn is_banned(&self, ip: &std::net::IpAddr) -> bool {
        self.banned.contains(ip)
    }

    pub fn drop_peer(&mut self, addr: &SocketAddr) {
        if let Some(slot) = self.peers.remove(addr) {
            // Dropping `slot.handle` closes the cmd channel; combined with abort
            // this guarantees the peer task stops promptly. We deliberately skip
            // sending a Shutdown command — it would race with abort and adds no value.
            slot.task.abort();
        }
    }

    /// Try to add new peer addresses. Skips already-connected, banned,
    /// and over-cap.
    pub fn try_connect_many(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> usize {
        let mut started = 0;
        for addr in addrs {
            if self.peers.len() >= self.max_peers {
                break;
            }
            if self.peers.contains_key(&addr) {
                continue;
            }
            if self.banned.contains(&addr.ip()) {
                continue;
            }
            self.spawn_outgoing(addr);
            started += 1;
        }
        started
    }

    fn spawn_outgoing(&mut self, addr: SocketAddr) {
        let (cmd_tx, cmd_rx) = mpsc::channel(PER_PEER_CMD_BUFFER);
        let info_hash = self.info_hash;
        let peer_id = self.our_peer_id;
        let event_tx = self.event_tx.clone();
        let force_mse = self.force_outgoing_mse;
        let proxy = self.proxy.clone();
        let bind_iface = self.bind_iface.clone();
        let anonymous = self.anonymous;
        let task = tokio::spawn(async move {
            let res = if force_mse {
                run_outgoing_mse_only(
                    addr, info_hash, peer_id, event_tx, cmd_rx, proxy, bind_iface, anonymous,
                )
                .await
            } else {
                run_outgoing(
                    addr, info_hash, peer_id, event_tx, cmd_rx, proxy, bind_iface, anonymous,
                )
                .await
            };
            if let Err(e) = res {
                tracing::debug!(target: "peer", %addr, error = %e, "peer task ended");
            }
        });
        self.peers.insert(
            addr,
            PeerSlot {
                handle: cmd_tx,
                task,
            },
        );
    }

    /// Accept an inbound TCP connection from a peer and spawn its task.
    /// Honors max-peer cap and ban list; returns false if rejected.
    pub fn accept_incoming(&mut self, stream: tokio::net::TcpStream, addr: SocketAddr) -> bool {
        if self.peers.len() >= self.max_peers || self.peers.contains_key(&addr) {
            return false;
        }
        if self.banned.contains(&addr.ip()) {
            return false;
        }
        let (cmd_tx, cmd_rx) = mpsc::channel(PER_PEER_CMD_BUFFER);
        let info_hash = self.info_hash;
        let peer_id = self.our_peer_id;
        let event_tx = self.event_tx.clone();
        let anonymous = self.anonymous;
        let task = tokio::spawn(async move {
            if let Err(e) = crate::peer::connection::run_with_stream(
                stream, addr, info_hash, peer_id, event_tx, cmd_rx, false, anonymous,
            )
            .await
            {
                tracing::debug!(target: "peer", %addr, error = %e, "incoming peer task ended");
            }
        });
        self.peers.insert(
            addr,
            PeerSlot {
                handle: cmd_tx,
                task,
            },
        );
        true
    }

    /// Mark a peer slot freed because the engine observed `Disconnected`.
    pub fn forget(&mut self, addr: &SocketAddr) {
        if let Some(slot) = self.peers.remove(addr) {
            slot.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ban_drops_existing_peer() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        let addr: SocketAddr = "10.0.0.1:6881".parse().unwrap();
        m.spawn_outgoing(addr);
        assert_eq!(m.connected_count(), 1);
        m.ban(addr.ip());
        assert_eq!(m.connected_count(), 0);
        assert!(m.is_banned(&addr.ip()));
    }

    #[tokio::test]
    async fn try_connect_respects_cap() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        m.set_max_peers(2);
        let started = m.try_connect_many(vec![
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:1".parse().unwrap(),
            "10.0.0.3:1".parse().unwrap(),
        ]);
        assert_eq!(started, 2);
        assert_eq!(m.connected_count(), 2);
    }
}
