//! The DHT background task: owns the UDP socket, the routing table, and a
//! map of in-flight transactions. Receives [`DhtCommand`]s from clients
//! and inbound KRPC packets from the network.
//!
//! Outgoing queries are correlated with responses by a per-request
//! 2-byte transaction id; responses without a known txid are dropped.
//!
//! Inbound queries are answered immediately (ping → pong, find_node →
//! closest nodes, get_peers → closest nodes + token, announce_peer →
//! token check + store).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;

use super::krpc::{Message, Query, Response};
use super::node_id::NodeId;
use super::routing::{Contact, RoutingTable, K};
use super::DhtCommand;
use crate::ratelimit::TokenBucket;

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const LOOKUP_BUDGET: Duration = Duration::from_secs(15);
/// Parallel α queries per lookup round, per Kademlia paper.
const ALPHA: usize = 3;
/// Token rotation: tokens we issue stay valid for this long.
const TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_DATAGRAM: usize = 1500;

/// How long an announced peer stays in the store before being pruned.
/// BEP 5 clients re-announce roughly every 15 min; 30 min gives a 2×
/// margin so a still-active peer isn't dropped between its announces.
const ANNOUNCE_TTL: Duration = Duration::from_secs(30 * 60);
/// Hard cap on the number of distinct info_hashes we'll hold peers for.
/// Each announce needs a valid token (a get_peers round-trip from a real
/// IP), but a real attacker — or just organic DHT load on a long-running
/// node — would otherwise grow the key set without bound. Once at the
/// cap we stop accepting announces for *new* info_hashes (existing ones
/// still update). Periodic TTL pruning keeps us below it in practice.
const MAX_INFO_HASHES: usize = 16_384;
/// How often we sweep the peer store for TTL-expired entries.
const PEER_STORE_GC_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Per-source-IP inbound-query rate limit. A KRPC response is larger
/// than the query, so a public DHT node is a reflection/amplification
/// vector: an attacker spoofs a victim's IP as the source of many
/// `get_peers` queries and we send the amplified replies *to the
/// victim*. Because every forged query shares the victim's source IP,
/// a per-IP token bucket caps how much traffic we can be made to
/// reflect at any single target — removing the amplification gain.
/// Generous enough that real nodes (which query us only occasionally,
/// even mid-lookup) never hit it.
const QUERY_BURST: f64 = 20.0;
const QUERY_RATE_PER_SEC: f64 = 5.0;
/// Soft cap on the per-IP query-limiter map; idle (refilled) buckets
/// are GC'd lazily once we exceed it so the map can't grow without
/// bound under a distributed (many distinct source IPs) flood.
const MAX_QUERY_LIMIT_IPS: usize = 4096;

/// `info_hash → list of (peer-addr, when-we-learned)`. Used by the
/// inbound get_peers handler to return values we've seen via prior
/// announce_peer queries.
type PeerStore = HashMap<[u8; 20], Vec<(SocketAddr, Instant)>>;

#[allow(clippy::too_many_arguments)] // each arg is a distinct spawn-time knob
pub(super) async fn spawn(
    listen_port: u16,
    bootstrap: Vec<String>,
    node_id: Option<NodeId>,
    warm_contacts: Vec<Contact>,
    persist_path: Option<std::path::PathBuf>,
    cmd_rx: mpsc::Receiver<DhtCommand>,
    bind_iface: Option<String>,
) -> Result<(), std::io::Error> {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port);
    // With a kill-switch interface set, pin the DHT's UDP socket to it so
    // its traffic fails closed if the tunnel drops — matching the TCP peer
    // dials. Without it, a normal unbound bind.
    let sock = match bind_iface.as_deref() {
        Some(iface) => crate::netbind::bind_udp_to_interface(bind, iface)?,
        None => UdpSocket::bind(bind).await?,
    };
    let sock = Arc::new(sock);
    let local_id = node_id.unwrap_or_else(NodeId::random);
    let state = Arc::new(SharedState::new(local_id));
    // Pre-load warm contacts from disk so the first lookup doesn't have to
    // wait on bootstrap RTT.
    if !warm_contacts.is_empty() {
        let mut rt = state.routing.lock().await;
        for c in warm_contacts {
            rt.insert(c);
        }
    }
    // Compute the table size before the macro: holding the lock guard's
    // borrow across the await inside the tracing args makes the enclosing
    // future non-Send, which breaks `tokio::spawn(engine.run())` in the
    // daemon (the single-torrent path runs un-spawned and never noticed).
    let warm_contacts = state.routing.lock().await.len();
    tracing::info!(
        target: "dht",
        port = listen_port,
        node_id = %local_id,
        warm_contacts,
        "dht listening"
    );
    tokio::spawn(run(sock, state, bootstrap, persist_path, cmd_rx));
    Ok(())
}

/// State shared between the receiving task, the command-handler task, and
/// transient per-lookup tasks.
struct SharedState {
    local_id: NodeId,
    routing: Mutex<RoutingTable>,
    /// Outstanding queries we sent: transaction id → reply channel.
    pending: Mutex<HashMap<Vec<u8>, PendingQuery>>,
    /// `info_hash → (peers we've seen, last update)`. Used to answer
    /// inbound `get_peers`.
    peer_store: Mutex<PeerStore>,
    /// Secret salt for issuing get_peers tokens. Rotated every TOKEN_TTL.
    token_state: Mutex<TokenState>,
    /// Per-source-IP token buckets gating how fast we answer inbound
    /// queries — anti-reflection (see `QUERY_BURST`).
    query_limits: Mutex<HashMap<IpAddr, TokenBucket>>,
}

struct PendingQuery {
    reply: oneshot::Sender<KrpcReply>,
}

struct TokenState {
    current: [u8; 8],
    previous: [u8; 8],
    last_rotated: Instant,
}

/// What the receiver task reports back to a pending query. We only act on
/// `Response`; `Error` is captured for diagnostics in case we ever want to
/// surface it.
#[derive(Debug)]
enum KrpcReply {
    Response(Response),
    #[allow(dead_code)] // captured-but-unused for now; kept for future error tracing
    Error(i64, String),
}

impl SharedState {
    fn new(local_id: NodeId) -> Self {
        let mut current = [0u8; 8];
        let mut previous = [0u8; 8];
        rand::thread_rng().fill(&mut current);
        rand::thread_rng().fill(&mut previous);
        Self {
            local_id,
            routing: Mutex::new(RoutingTable::new(local_id)),
            pending: Mutex::new(HashMap::new()),
            peer_store: Mutex::new(HashMap::new()),
            token_state: Mutex::new(TokenState {
                current,
                previous,
                last_rotated: Instant::now(),
            }),
            query_limits: Mutex::new(HashMap::new()),
        }
    }

    /// Per-source-IP rate gate for inbound queries (anti-reflection).
    /// Returns `true` if we should answer. Lazily GCs idle buckets once
    /// the map grows past `MAX_QUERY_LIMIT_IPS` so a distributed flood
    /// can't grow it without bound.
    async fn allow_query_from(&self, ip: IpAddr) -> bool {
        let mut limits = self.query_limits.lock().await;
        if limits.len() > MAX_QUERY_LIMIT_IPS {
            // Drop buckets that have refilled (idle sources); keeps the
            // map bounded without forgetting actively-limited IPs.
            limits.retain(|_, b| b.available() < QUERY_BURST - 1.0);
        }
        limits
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(QUERY_BURST, QUERY_RATE_PER_SEC))
            .try_consume(1.0)
    }

    /// Issue a token for `addr` derived from our current secret + their IP.
    /// Tokens are 8 bytes; we accept both `current` and `previous` salts so
    /// peers don't have to query us immediately before announcing.
    async fn issue_token(&self, addr: SocketAddr) -> Vec<u8> {
        let mut ts = self.token_state.lock().await;
        if ts.last_rotated.elapsed() >= TOKEN_TTL {
            ts.previous = ts.current;
            rand::thread_rng().fill(&mut ts.current);
            ts.last_rotated = Instant::now();
        }
        token_for(addr, &ts.current)
    }

    async fn verify_token(&self, addr: SocketAddr, token: &[u8]) -> bool {
        let ts = self.token_state.lock().await;
        let t_now = token_for(addr, &ts.current);
        let t_prev = token_for(addr, &ts.previous);
        token == t_now.as_slice() || token == t_prev.as_slice()
    }

    /// Drop announced peers older than `ANNOUNCE_TTL` and any info_hash
    /// whose list is then empty, bounding the peer store's memory on a
    /// long-running node (and limiting how long a flood of distinct-hash
    /// announces can occupy it).
    async fn prune_peer_store(&self) {
        let now = Instant::now();
        let mut store = self.peer_store.lock().await;
        store.retain(|_hash, entries| {
            entries.retain(|(_, t)| now.duration_since(*t) <= ANNOUNCE_TTL);
            !entries.is_empty()
        });
    }
}

fn token_for(addr: SocketAddr, salt: &[u8; 8]) -> Vec<u8> {
    // Cheap, non-cryptographic: SHA1(salt || ip_bytes). Plenty for spam control.
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(salt);
    match addr.ip() {
        IpAddr::V4(v4) => h.update(v4.octets()),
        IpAddr::V6(v6) => h.update(v6.octets()),
    }
    h.finalize()[..8].to_vec()
}

async fn run(
    sock: Arc<UdpSocket>,
    state: Arc<SharedState>,
    bootstrap: Vec<String>,
    persist_path: Option<std::path::PathBuf>,
    mut cmd_rx: mpsc::Receiver<DhtCommand>,
) {
    // Receive loop on its own task — UDP recv is not cancel-safe-friendly
    // when other branches in a select! own state we're updating.
    let recv_state = state.clone();
    let recv_sock = sock.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, from) = match recv_sock.recv_from(&mut buf).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(target: "dht", error = %e, "recv");
                    continue;
                }
            };
            handle_datagram(&recv_state, &recv_sock, from, &buf[..n]).await;
        }
    });

    // Bootstrap: resolve each known router address and find_node our own ID.
    let bootstrap_addrs = resolve_bootstrap(&bootstrap).await;
    if !bootstrap_addrs.is_empty() {
        bootstrap_routing_table(&sock, state.clone(), &bootstrap_addrs).await;
    } else {
        tracing::warn!(target: "dht", "no bootstrap nodes resolved");
    }

    let mut persist_timer = tokio::time::interval(Duration::from_secs(300));
    persist_timer.tick().await; // discard immediate first tick

    let mut peer_store_gc_timer = tokio::time::interval(PEER_STORE_GC_INTERVAL);
    peer_store_gc_timer.tick().await; // discard immediate first tick

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break; };
                match cmd {
                    DhtCommand::Shutdown => break,
                    DhtCommand::GetPeers { info_hash, reply } => {
                        let sock = sock.clone();
                        let state = state.clone();
                        tokio::spawn(async move {
                            let peers = lookup_get_peers(&sock, &state, info_hash).await;
                            let _ = reply.send(peers);
                        });
                    }
                    DhtCommand::Announce { info_hash, port } => {
                        let sock = sock.clone();
                        let state = state.clone();
                        tokio::spawn(async move {
                            announce_peer(&sock, &state, info_hash, port).await;
                        });
                    }
                    DhtCommand::RoutingTableSize { reply } => {
                        let n = state.routing.lock().await.len();
                        let _ = reply.send(n);
                    }
                }
            }
            _ = persist_timer.tick(), if persist_path.is_some() => {
                let table = state.routing.lock().await.clone();
                let id = state.local_id;
                let path = persist_path.clone().expect("guarded by `if`");
                let count = table.len();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = super::persist::save(&path, id, &table) {
                        tracing::debug!(target: "dht", error = %e, "persist save");
                    } else {
                        tracing::debug!(target: "dht", contacts = count, "persisted dht state");
                    }
                });
            }
            _ = peer_store_gc_timer.tick() => {
                state.prune_peer_store().await;
            }
        }
    }

    // Final save on shutdown.
    if let Some(p) = persist_path.as_deref() {
        let table = state.routing.lock().await.clone();
        let _ = super::persist::save(p, state.local_id, &table);
    }
}

async fn resolve_bootstrap(hosts: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for h in hosts {
        match tokio::net::lookup_host(h.as_str()).await {
            Ok(iter) => {
                for addr in iter {
                    if addr.is_ipv4() {
                        out.push(addr);
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::debug!(target: "dht", host = %h, error = %e, "bootstrap resolve");
            }
        }
    }
    out
}

async fn bootstrap_routing_table(
    sock: &Arc<UdpSocket>,
    state: Arc<SharedState>,
    bootstrap: &[SocketAddr],
) {
    // Send a find_node for our own id to each bootstrap router; that prompts
    // them to return their closest contacts, which we insert into our table.
    let target = state.local_id;
    for addr in bootstrap {
        let q = Query::FindNode {
            id: state.local_id,
            target,
        };
        if let Some(resp) = send_query(sock, &state, *addr, q).await {
            ingest_nodes_from(&state, &resp).await;
        }
    }
    let bootstrap_contacts = state.routing.lock().await.len();
    tracing::info!(target: "dht", contacts = bootstrap_contacts, "bootstrap complete");
    // Kick off a self-find to flesh out our buckets.
    let _ = lookup_find_node(sock, &state, state.local_id).await;
    let self_find_contacts = state.routing.lock().await.len();
    tracing::info!(target: "dht", contacts = self_find_contacts, "self-find complete");
}

async fn ingest_nodes_from(state: &Arc<SharedState>, resp: &Response) {
    let nodes = match resp {
        Response::Nodes { nodes, .. } | Response::PeersNodes { nodes, .. } => Some(nodes),
        _ => None,
    };
    if let Some(nodes) = nodes {
        let mut rt = state.routing.lock().await;
        for c in nodes {
            rt.insert(c.clone());
        }
    }
}

fn next_txid() -> Vec<u8> {
    let mut buf = [0u8; 2];
    rand::thread_rng().fill(&mut buf);
    buf.to_vec()
}

async fn handle_datagram(state: &SharedState, sock: &UdpSocket, from: SocketAddr, bytes: &[u8]) {
    let msg = match Message::decode(bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::trace!(target: "dht", %from, error = %e, "decode");
            return;
        }
    };
    match msg {
        Message::Query {
            transaction_id,
            query,
        } => {
            // Anti-reflection: rate-limit answers per source IP. Forged
            // queries spoofing a victim's IP all share that IP's bucket,
            // capping how much we can be made to reflect at the victim.
            if !state.allow_query_from(from.ip()).await {
                tracing::trace!(target: "dht", %from, "inbound query rate limit; dropping");
                return;
            }
            answer_query(state, sock, from, transaction_id, query).await
        }
        Message::Response {
            transaction_id,
            response,
        } => {
            // Refresh sender's contact and route the response to the waiting caller.
            if let Some(id) = response_id(&response) {
                let mut rt = state.routing.lock().await;
                rt.insert(Contact::new(id, from));
            }
            let waiting = state.pending.lock().await.remove(&transaction_id);
            if let Some(p) = waiting {
                let _ = p.reply.send(KrpcReply::Response(response));
            }
        }
        Message::Error {
            transaction_id,
            code,
            message,
        } => {
            let waiting = state.pending.lock().await.remove(&transaction_id);
            if let Some(p) = waiting {
                let _ = p.reply.send(KrpcReply::Error(code, message));
            }
        }
    }
}

fn response_id(r: &Response) -> Option<NodeId> {
    match r {
        Response::Id { id }
        | Response::Nodes { id, .. }
        | Response::Peers { id, .. }
        | Response::PeersNodes { id, .. } => Some(*id),
    }
}

async fn answer_query(
    state: &SharedState,
    sock: &UdpSocket,
    from: SocketAddr,
    transaction_id: Vec<u8>,
    query: Query,
) {
    // Whoever is talking to us is a candidate contact.
    let sender_id = match &query {
        Query::Ping { id }
        | Query::FindNode { id, .. }
        | Query::GetPeers { id, .. }
        | Query::AnnouncePeer { id, .. } => *id,
    };
    {
        let mut rt = state.routing.lock().await;
        rt.insert(Contact::new(sender_id, from));
    }

    let response = match query {
        Query::Ping { .. } => Response::Id { id: state.local_id },
        Query::FindNode { target, .. } => {
            let nodes = state.routing.lock().await.closest(&target, K);
            Response::Nodes {
                id: state.local_id,
                nodes,
            }
        }
        Query::GetPeers { info_hash, .. } => {
            let token = state.issue_token(from).await;
            let peers: Vec<SocketAddr> = state
                .peer_store
                .lock()
                .await
                .get(&info_hash)
                .map(|entries| entries.iter().map(|(a, _)| *a).collect())
                .unwrap_or_default();
            if !peers.is_empty() {
                Response::Peers {
                    id: state.local_id,
                    token,
                    values: peers,
                }
            } else {
                let target = NodeId(info_hash);
                let nodes = state.routing.lock().await.closest(&target, K);
                Response::PeersNodes {
                    id: state.local_id,
                    token,
                    nodes,
                }
            }
        }
        Query::AnnouncePeer {
            info_hash,
            port,
            token,
            implied_port,
            ..
        } => {
            if !state.verify_token(from, &token).await {
                let err = Message::Error {
                    transaction_id,
                    code: 203,
                    message: "bad token".into(),
                };
                let _ = sock.send_to(&err.encode(), from).await;
                return;
            }
            let advertised_port = if implied_port { from.port() } else { port };
            let peer_addr = SocketAddr::new(from.ip(), advertised_port);
            let mut store = state.peer_store.lock().await;
            // Bound the number of distinct info_hashes: once at the cap we
            // still update hashes we already track, but refuse to create a
            // new key. Prevents a flood of random-info_hash announces from
            // growing the map without bound between GC sweeps. Either way
            // we reply with our id (a normal announce_peer ack).
            if store.len() < MAX_INFO_HASHES || store.contains_key(&info_hash) {
                let entry = store.entry(info_hash).or_default();
                entry.retain(|(a, _)| *a != peer_addr);
                entry.push((peer_addr, Instant::now()));
                // Trim per-hash list to avoid unbounded growth.
                if entry.len() > 256 {
                    entry.drain(..entry.len() - 256);
                }
            }
            Response::Id { id: state.local_id }
        }
    };
    let reply = Message::Response {
        transaction_id,
        response,
    };
    let _ = sock.send_to(&reply.encode(), from).await;
}

/// Send a query to `addr` and wait for the matching response.
async fn send_query(
    sock: &Arc<UdpSocket>,
    state: &Arc<SharedState>,
    addr: SocketAddr,
    query: Query,
) -> Option<Response> {
    let txid = next_txid();
    let msg = Message::Query {
        transaction_id: txid.clone(),
        query,
    };
    let (tx, rx) = oneshot::channel();
    state
        .pending
        .lock()
        .await
        .insert(txid.clone(), PendingQuery { reply: tx });
    if sock.send_to(&msg.encode(), addr).await.is_err() {
        state.pending.lock().await.remove(&txid);
        return None;
    }
    match timeout(QUERY_TIMEOUT, rx).await {
        Ok(Ok(KrpcReply::Response(resp))) => Some(resp),
        _ => {
            state.pending.lock().await.remove(&txid);
            None
        }
    }
}

/// Iteratively find the K closest nodes to `target`. Used during bootstrap
/// and as a maintenance op.
async fn lookup_find_node(
    sock: &Arc<UdpSocket>,
    state: &Arc<SharedState>,
    target: NodeId,
) -> Vec<Contact> {
    let started = Instant::now();
    let mut shortlist = state.routing.lock().await.closest(&target, K * 2);
    let mut queried: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    while started.elapsed() < LOOKUP_BUDGET {
        // Pick up to ALPHA unqueried closest contacts.
        let next: Vec<Contact> = shortlist
            .iter()
            .filter(|c| !queried.contains(&c.id))
            .take(ALPHA)
            .cloned()
            .collect();
        if next.is_empty() {
            break;
        }
        let mut tasks = Vec::new();
        for c in next {
            queried.insert(c.id);
            let sock = sock.clone();
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let q = Query::FindNode {
                    id: state.local_id,
                    target,
                };
                send_query(&sock, &state, c.addr, q).await
            }));
        }
        for t in tasks {
            if let Ok(Some(resp)) = t.await {
                ingest_nodes_from(state, &resp).await;
                if let Response::Nodes { nodes, .. } = resp {
                    shortlist.extend(nodes);
                }
            }
        }
        shortlist.sort_by_key(|c| c.id.distance(&target));
        shortlist.dedup_by_key(|c| c.id);
        shortlist.truncate(K * 4);
    }
    shortlist.truncate(K);
    shortlist
}

/// Iterative `get_peers` lookup — returns whatever peers we found before
/// the lookup budget elapsed.
async fn lookup_get_peers(
    sock: &Arc<UdpSocket>,
    state: &Arc<SharedState>,
    info_hash: [u8; 20],
) -> Vec<SocketAddr> {
    let started = Instant::now();
    let target = NodeId(info_hash);
    let mut shortlist = state.routing.lock().await.closest(&target, K * 2);
    let mut queried: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut tokens: HashMap<NodeId, (Vec<u8>, SocketAddr)> = HashMap::new();

    while started.elapsed() < LOOKUP_BUDGET {
        let next: Vec<Contact> = shortlist
            .iter()
            .filter(|c| !queried.contains(&c.id))
            .take(ALPHA)
            .cloned()
            .collect();
        if next.is_empty() {
            break;
        }
        let mut tasks = Vec::new();
        for c in next {
            queried.insert(c.id);
            let sock = sock.clone();
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let q = Query::GetPeers {
                    id: state.local_id,
                    info_hash,
                };
                let resp = send_query(&sock, &state, c.addr, q).await;
                (c, resp)
            }));
        }
        for t in tasks {
            if let Ok((c, Some(resp))) = t.await {
                match resp {
                    Response::Peers {
                        ref token,
                        ref values,
                        ..
                    } => {
                        tokens.insert(c.id, (token.clone(), c.addr));
                        for v in values {
                            if !peers.contains(v) {
                                peers.push(*v);
                            }
                        }
                    }
                    Response::PeersNodes {
                        ref token,
                        ref nodes,
                        ..
                    } => {
                        tokens.insert(c.id, (token.clone(), c.addr));
                        shortlist.extend(nodes.clone());
                    }
                    _ => {}
                }
                ingest_nodes_from(state, &resp).await;
            }
        }
        shortlist.sort_by_key(|c| c.id.distance(&target));
        shortlist.dedup_by_key(|c| c.id);
        shortlist.truncate(K * 4);

        // Soft stop: if we already have a fistful of peers, return early.
        if peers.len() >= 20 {
            break;
        }
    }
    tracing::debug!(
        target: "dht",
        peers = peers.len(),
        queried = queried.len(),
        "get_peers complete"
    );
    peers
}

async fn announce_peer(
    sock: &Arc<UdpSocket>,
    state: &Arc<SharedState>,
    info_hash: [u8; 20],
    port: u16,
) {
    // We need tokens from the K closest nodes — do a get_peers first so we
    // collect tokens along the way, then send announce_peer to each closest.
    let target = NodeId(info_hash);
    let started = Instant::now();
    let mut shortlist = state.routing.lock().await.closest(&target, K * 2);
    let mut queried: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    let mut tokens: HashMap<NodeId, (Vec<u8>, SocketAddr)> = HashMap::new();
    while started.elapsed() < LOOKUP_BUDGET {
        let next: Vec<Contact> = shortlist
            .iter()
            .filter(|c| !queried.contains(&c.id))
            .take(ALPHA)
            .cloned()
            .collect();
        if next.is_empty() {
            break;
        }
        let mut tasks = Vec::new();
        for c in next {
            queried.insert(c.id);
            let sock = sock.clone();
            let state = state.clone();
            let addr = c.addr;
            tasks.push(tokio::spawn(async move {
                let q = Query::GetPeers {
                    id: state.local_id,
                    info_hash,
                };
                (c, send_query(&sock, &state, addr, q).await)
            }));
        }
        for t in tasks {
            if let Ok((c, Some(resp))) = t.await {
                match resp {
                    Response::Peers { ref token, .. } | Response::PeersNodes { ref token, .. } => {
                        tokens.insert(c.id, (token.clone(), c.addr));
                    }
                    _ => {}
                }
                if let Response::PeersNodes { ref nodes, .. } = resp {
                    shortlist.extend(nodes.clone());
                }
                ingest_nodes_from(state, &resp).await;
            }
        }
        shortlist.sort_by_key(|c| c.id.distance(&target));
        shortlist.dedup_by_key(|c| c.id);
        shortlist.truncate(K * 4);
    }
    // Send announce_peer to the K closest contacts we got tokens from.
    let mut closest: Vec<(NodeId, Vec<u8>, SocketAddr)> = tokens
        .into_iter()
        .map(|(id, (tok, addr))| (id, tok, addr))
        .collect();
    closest.sort_by_key(|(id, _, _)| id.distance(&target));
    closest.truncate(K);
    for (_id, token, addr) in closest {
        let q = Query::AnnouncePeer {
            id: state.local_id,
            info_hash,
            port,
            token,
            implied_port: false,
        };
        let _ = send_query(sock, state, addr, q).await;
    }
    tracing::debug!(target: "dht", "announce_peer complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prune_drops_stale_and_keeps_fresh() {
        let state = SharedState::new(NodeId([0u8; 20]));
        let fresh_hash = [1u8; 20];
        let stale_hash = [2u8; 20];
        let peer: SocketAddr = "1.2.3.4:6881".parse().unwrap();
        {
            let mut store = state.peer_store.lock().await;
            store.insert(fresh_hash, vec![(peer, Instant::now())]);
            // A stale entry, older than the TTL.
            store.insert(
                stale_hash,
                vec![(peer, Instant::now() - ANNOUNCE_TTL - Duration::from_secs(1))],
            );
        }
        state.prune_peer_store().await;
        let store = state.peer_store.lock().await;
        assert!(store.contains_key(&fresh_hash), "fresh entry must survive");
        assert!(
            !store.contains_key(&stale_hash),
            "fully-stale info_hash must be removed entirely"
        );
    }

    #[tokio::test]
    async fn query_rate_limit_caps_burst_from_one_ip() {
        let state = SharedState::new(NodeId([0u8; 20]));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        // The first QUERY_BURST queries are allowed; beyond that, within
        // the same instant (no refill), further queries are dropped.
        let mut allowed = 0;
        for _ in 0..(QUERY_BURST as usize + 50) {
            if state.allow_query_from(ip).await {
                allowed += 1;
            }
        }
        assert!(
            allowed <= QUERY_BURST as usize,
            "allowed {allowed} > burst {QUERY_BURST}"
        );
        assert!(allowed >= 1, "the burst must permit at least some queries");
    }
}
