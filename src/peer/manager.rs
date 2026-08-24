use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::peer::connection::{run_outgoing, run_outgoing_mse_only, PeerEvent, PeerHandle};
use crate::peer::transport::Transport;
use crate::peer::utp::UtpSocket;
use crate::peer_id::PeerId;
use crate::socks5::ProxyConfig;

pub const DEFAULT_MAX_PEERS: usize = 50;
pub const PER_PEER_CMD_BUFFER: usize = 64;

use std::sync::atomic::{AtomicUsize, Ordering};

/// A process-wide cap on total concurrent peer connections, shared across
/// every session in the daemon. It bounds the aggregate connection count
/// regardless of how many torrents are hosted — defense against a
/// many-torrent daemon (or one very popular swarm) exhausting file
/// descriptors / memory — and stacks on top of each session's per-torrent
/// `max_peers`. Cheap to clone (an `Arc<AtomicUsize>` + the limit).
#[derive(Clone)]
pub struct GlobalPeerCap {
    count: Arc<AtomicUsize>,
    max: usize,
}

impl GlobalPeerCap {
    pub fn new(max: usize) -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// Try to claim one global slot. Returns a guard that releases it on
    /// drop, or `None` if the cap is already reached. Lock-free CAS so
    /// concurrent sessions can't oversubscribe past `max`.
    fn try_acquire(&self) -> Option<GlobalPeerGuard> {
        let mut cur = self.count.load(Ordering::Relaxed);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.count.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(GlobalPeerGuard(self.count.clone())),
                Err(observed) => cur = observed,
            }
        }
    }
}

/// RAII release of one global peer slot. Held inside the [`PeerSlot`], so
/// the slot's removal from the map (disconnect, ban, drop) frees the
/// global count automatically — no manual decrement to forget.
struct GlobalPeerGuard(Arc<AtomicUsize>);

impl Drop for GlobalPeerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Per-IP protocol-violation counter window. After this many
/// violations within `VIOLATION_WINDOW` the IP is banned.
pub const VIOLATION_BAN_THRESHOLD: u32 = 3;
/// Rolling window for the violation counter. Violations older than
/// this contribute nothing — long-running sessions don't accumulate
/// stale strikes against peers that only had a single transient bug.
pub const VIOLATION_WINDOW: Duration = Duration::from_secs(60);

/// Pool of active peer connections. The engine owns one of these and
/// uses `handle()` to send commands to specific peers.
pub struct PeerManager {
    info_hash: [u8; 20],
    our_peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    peers: HashMap<SocketAddr, PeerSlot>,
    banned: HashSet<IpAddr>,
    max_peers: usize,
    force_outgoing_mse: bool,
    /// SOCKS5 chain for outgoing peer dials. Empty = direct (clearnet).
    /// Length 1 = single hop. Length 2+ = nested SOCKS5 CONNECTs.
    proxies: Vec<ProxyConfig>,
    bind_iface: Option<String>,
    /// Anonymous-mode flag passed through to each peer task so the
    /// BEP 10 extension handshake omits the `v` (client version) and
    /// `reqq` fields that uniquely fingerprint us as rustytorrent.
    anonymous: bool,
    /// Per-IP protocol-violation timestamps within the rolling
    /// `VIOLATION_WINDOW`. When the count reaches
    /// `VIOLATION_BAN_THRESHOLD` the IP joins the ban set. The map
    /// only grows for IPs that have actually violated; clean peers
    /// never appear here. Entries are pruned lazily on insert and by
    /// `gc_violations` on a periodic tick.
    violations: HashMap<IpAddr, Vec<Instant>>,
    /// Shared µTP socket for outgoing dials. `Some` only when µTP is
    /// enabled on a clearnet direct path (the engine withholds it under
    /// `--anonymous`, an active SOCKS5 chain, or `--bind-iface`). When
    /// set, each outgoing dial races TCP and µTP.
    utp: Option<Arc<UtpSocket>>,
    /// Optional process-wide connection cap (the daemon's shared cap).
    /// `None` for a standalone single-torrent engine (only `max_peers`
    /// applies then).
    global_cap: Option<GlobalPeerCap>,
}

struct PeerSlot {
    handle: PeerHandle,
    task: JoinHandle<()>,
    /// Holds this peer's global-cap reservation, if any. Dropped with the
    /// slot, releasing the global slot on disconnect/ban/forget.
    _global: Option<GlobalPeerGuard>,
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
            proxies: Vec::new(),
            bind_iface: None,
            anonymous: false,
            violations: HashMap::new(),
            utp: None,
            global_cap: None,
        }
    }

    pub fn set_utp(&mut self, utp: Option<Arc<UtpSocket>>) {
        self.utp = utp;
    }

    /// Install a process-wide connection cap (the daemon shares one across
    /// all sessions). Standalone engines leave this unset.
    pub fn set_global_cap(&mut self, cap: GlobalPeerCap) {
        self.global_cap = Some(cap);
    }

    /// Claim a global-cap slot for a new peer. `Ok(None)` means no cap is
    /// configured (always allowed); `Ok(Some(guard))` reserved a slot;
    /// `Err(())` means the global cap is full and the peer must be
    /// rejected.
    fn acquire_global(&self) -> std::result::Result<Option<GlobalPeerGuard>, ()> {
        match &self.global_cap {
            None => Ok(None),
            Some(cap) => cap.try_acquire().map(Some).ok_or(()),
        }
    }

    pub fn set_max_peers(&mut self, n: usize) {
        self.max_peers = n;
    }

    pub fn set_force_outgoing_mse(&mut self, on: bool) {
        self.force_outgoing_mse = on;
    }

    pub fn set_proxies(&mut self, proxies: Vec<ProxyConfig>) {
        self.proxies = proxies;
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

    /// Record a BEP 3 protocol violation observed from `ip` (bad
    /// pstr, frame too large, malformed message, etc.). If the
    /// rolling-window count reaches `VIOLATION_BAN_THRESHOLD`, ban
    /// the IP immediately and drop any active connections from it.
    ///
    /// Returns `true` when the call resulted in a ban (so the
    /// caller can log it once). Idempotent: subsequent violations
    /// from an already-banned IP still get counted but the return
    /// value is false.
    pub fn record_violation(&mut self, ip: IpAddr) -> bool {
        if self.banned.contains(&ip) {
            // Already banned — keep counting (cheap) but don't fire
            // again. Cleanup happens at the GC tick below.
            return false;
        }
        let now = Instant::now();
        let entry = self.violations.entry(ip).or_default();
        entry.retain(|t| now.duration_since(*t) <= VIOLATION_WINDOW);
        entry.push(now);
        let count = entry.len() as u32;
        if count >= VIOLATION_BAN_THRESHOLD {
            tracing::warn!(
                target: "peer::manager",
                %ip,
                violations = count,
                "protocol violations exceeded threshold; banning IP"
            );
            self.ban(ip);
            return true;
        }
        tracing::debug!(
            target: "peer::manager",
            %ip,
            count,
            threshold = VIOLATION_BAN_THRESHOLD,
            "protocol violation recorded"
        );
        false
    }

    pub fn ban(&mut self, ip: IpAddr) {
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

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.banned.contains(ip)
    }

    /// Drop violation entries whose timestamps have all aged out of
    /// `VIOLATION_WINDOW`. `record_violation` prunes stale timestamps
    /// only for the IP it's touching, so an IP that violates once and
    /// never reconnects would otherwise keep its entry forever — an
    /// attacker with many real source IPs (each committing a single
    /// sub-threshold violation) could grow the map without bound. The
    /// engine calls this on a periodic tick to bound that growth.
    ///
    /// The `banned` set is deliberately NOT swept here: an entry only
    /// lands there after a peer crossed `VIOLATION_BAN_THRESHOLD`
    /// genuine protocol violations, i.e. proved itself malicious, so
    /// retaining the ban for the process lifetime is the safer policy.
    /// Its growth is bounded by the number of distinct IPs that managed
    /// to earn a ban, which is self-limiting in practice.
    pub fn gc_violations(&mut self) {
        let now = Instant::now();
        self.violations.retain(|_ip, times| {
            times.retain(|t| now.duration_since(*t) <= VIOLATION_WINDOW);
            !times.is_empty()
        });
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
            // Stop if the process-wide cap is reached — no point scanning
            // more addresses we can't dial.
            if !self.spawn_outgoing(addr) {
                break;
            }
            started += 1;
        }
        started
    }

    /// Returns false if the global cap blocked the dial (no slot spawned).
    fn spawn_outgoing(&mut self, addr: SocketAddr) -> bool {
        let global = match self.acquire_global() {
            Ok(g) => g,
            Err(()) => {
                tracing::debug!(target: "peer", %addr, "global peer cap reached; not dialing");
                return false;
            }
        };
        let (cmd_tx, cmd_rx) = mpsc::channel(PER_PEER_CMD_BUFFER);
        let info_hash = self.info_hash;
        let peer_id = self.our_peer_id;
        let event_tx = self.event_tx.clone();
        let force_mse = self.force_outgoing_mse;
        let proxies = self.proxies.clone();
        let bind_iface = self.bind_iface.clone();
        let anonymous = self.anonymous;
        let utp = self.utp.clone();
        let task = tokio::spawn(async move {
            let res = if force_mse {
                run_outgoing_mse_only(
                    addr, info_hash, peer_id, event_tx, cmd_rx, proxies, bind_iface, anonymous, utp,
                )
                .await
            } else {
                run_outgoing(
                    addr, info_hash, peer_id, event_tx, cmd_rx, proxies, bind_iface, anonymous, utp,
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
                _global: global,
            },
        );
        true
    }

    /// Accept an inbound connection (TCP or µTP) from a peer and spawn
    /// its task. Honors max-peer cap, the global cap, and the ban list;
    /// returns false if rejected.
    pub fn accept_incoming(&mut self, stream: Transport, addr: SocketAddr) -> bool {
        if self.peers.len() >= self.max_peers || self.peers.contains_key(&addr) {
            return false;
        }
        if self.banned.contains(&addr.ip()) {
            return false;
        }
        let global = match self.acquire_global() {
            Ok(g) => g,
            Err(()) => return false,
        };
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
                _global: global,
            },
        );
        true
    }

    /// Accept a connection the shared acceptor already handshook (daemon
    /// path). Honors the same max-peer cap, global cap, and ban list as
    /// [`accept_incoming`](Self::accept_incoming); returns false if
    /// rejected. The acceptor verified the info_hash during the handshake,
    /// so by the time we get here the peer is known to be in our swarm.
    pub fn accept_handshaken(&mut self, peer: crate::peer::inbound::HandshakenPeer) -> bool {
        let addr = peer.addr;
        if self.peers.len() >= self.max_peers || self.peers.contains_key(&addr) {
            return false;
        }
        if self.banned.contains(&addr.ip()) {
            return false;
        }
        let global = match self.acquire_global() {
            Ok(g) => g,
            Err(()) => return false,
        };
        let (cmd_tx, cmd_rx) = mpsc::channel(PER_PEER_CMD_BUFFER);
        let event_tx = self.event_tx.clone();
        let anonymous = self.anonymous;
        let task = tokio::spawn(async move {
            if let Err(e) =
                crate::peer::connection::run_handshaken(peer, event_tx, cmd_rx, anonymous).await
            {
                tracing::debug!(target: "peer", %addr, error = %e, "handshaken peer task ended");
            }
        });
        self.peers.insert(
            addr,
            PeerSlot {
                handle: cmd_tx,
                task,
                _global: global,
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

    /// Ban must also gate FUTURE dials: try_connect_many silently skips
    /// addresses whose IP is on the ban list (a banned peer that reconnects
    /// would otherwise be re-admitted). Mutation-checked: disabling the
    /// ban-list check in try_connect_many fails this test.
    #[test]
    fn banned_ip_is_skipped_by_try_connect_many() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        let addr: SocketAddr = "10.0.0.9:6881".parse().unwrap();
        m.ban(addr.ip());
        let started = m.try_connect_many([addr]);
        assert_eq!(started, 0, "banned IP must be skipped");
        assert_eq!(m.connected_count(), 0);
    }

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

    #[test]
    fn global_cap_bounds_and_releases() {
        let cap = GlobalPeerCap::new(2);
        let g1 = cap.try_acquire().expect("first slot");
        let _g2 = cap.try_acquire().expect("second slot");
        assert!(cap.try_acquire().is_none(), "cap of 2 is full");
        drop(g1);
        assert!(cap.try_acquire().is_some(), "dropping a guard frees a slot");
    }

    #[tokio::test]
    async fn global_cap_rejects_over_limit_and_frees_on_forget() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        m.set_global_cap(GlobalPeerCap::new(1));
        let a: SocketAddr = "10.0.0.1:6881".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:6881".parse().unwrap();
        // First dial claims the only global slot; the second is rejected.
        assert!(m.spawn_outgoing(a));
        assert!(!m.spawn_outgoing(b), "global cap of 1 must reject the 2nd");
        assert_eq!(m.connected_count(), 1);
        // Forgetting the first drops its slot (and the global guard),
        // freeing a slot for a new dial.
        m.forget(&a);
        assert!(m.spawn_outgoing(b), "slot freed after forget");
        assert_eq!(m.connected_count(), 1);
    }

    #[tokio::test]
    async fn one_violation_does_not_ban() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        let ip: IpAddr = "10.0.0.42".parse().unwrap();
        let banned_now = m.record_violation(ip);
        assert!(!banned_now);
        assert!(!m.is_banned(&ip));
    }

    #[tokio::test]
    async fn threshold_violations_ban_ip() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        let ip: IpAddr = "10.0.0.42".parse().unwrap();
        for _ in 0..VIOLATION_BAN_THRESHOLD - 1 {
            assert!(!m.record_violation(ip));
        }
        // Final strike crosses the threshold.
        assert!(m.record_violation(ip));
        assert!(m.is_banned(&ip));
    }

    #[tokio::test]
    async fn violation_drops_existing_connection() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        let addr: SocketAddr = "10.0.0.42:6881".parse().unwrap();
        m.spawn_outgoing(addr);
        assert_eq!(m.connected_count(), 1);
        for _ in 0..VIOLATION_BAN_THRESHOLD {
            m.record_violation(addr.ip());
        }
        // After ban, the existing connection should be torn down.
        assert!(m.is_banned(&addr.ip()));
        assert_eq!(m.connected_count(), 0);
    }

    #[tokio::test]
    async fn gc_drops_fully_aged_violation_entries() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        // Insert a single stale timestamp directly (older than the window).
        m.violations.insert(
            ip,
            vec![Instant::now() - VIOLATION_WINDOW - Duration::from_secs(5)],
        );
        assert!(m.violations.contains_key(&ip));
        m.gc_violations();
        assert!(
            !m.violations.contains_key(&ip),
            "fully-aged-out IP entry must be removed"
        );
    }

    #[tokio::test]
    async fn gc_retains_recent_violation_entries() {
        let (tx, _rx) = mpsc::channel(16);
        let mut m = PeerManager::new([0u8; 20], [0u8; 20], tx);
        let ip: IpAddr = "10.0.0.8".parse().unwrap();
        m.record_violation(ip); // one fresh strike, below threshold
        assert!(m.violations.contains_key(&ip));
        m.gc_violations();
        assert!(
            m.violations.contains_key(&ip),
            "a recent sub-threshold violation must be retained"
        );
        assert!(!m.is_banned(&ip));
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
