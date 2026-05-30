//! Shared inbound acceptor for the multi-torrent daemon.
//!
//! A single TCP listener (and optional µTP socket) serves every hosted
//! torrent. For each inbound connection the acceptor drives the handshake
//! far enough to learn the peer's `info_hash`, looks up the matching
//! session in a shared [`Registry`], and hands the already-handshaken
//! connection to that session via [`Inbound::Handshaken`]. Connections for
//! an unknown info_hash are dropped.
//!
//! ## Why the acceptor owns the handshake
//!
//! - **Plain BT:** the 20-byte info_hash sits in the fixed 68-byte
//!   handshake, so we read it, match, and reply with our own handshake for
//!   that torrent.
//! - **MSE/PE:** the info_hash is *not* in cleartext — it's only recovered
//!   by the DH exchange + `req2 = HASH('req2', info_hash)` match. So the
//!   acceptor calls [`mse::perform_incoming`] with the **current** set of
//!   active info_hashes; it returns the matched one. There's no way to
//!   peek-and-forward a raw MSE stream, which is exactly why a single
//!   shared listener (rather than a port per torrent) needs the acceptor
//!   to own the handshake.
//!
//! The daemon's per-session peer_id is shared (all sessions answer with
//! the same id), matching how the daemon already announces.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

use crate::peer::handshake::{supports_extension_protocol, Handshake, HANDSHAKE_LEN, PSTRLEN};
use crate::peer::inbound::{HandshakenPeer, Inbound};
use crate::peer::mse;
use crate::peer::transport::Transport;
use crate::peer::utp::UtpSocket;
use crate::peer_id::PeerId;
use crate::ratelimit::TokenBucket;

/// 20-byte info-hash key.
pub type InfoHash = [u8; 20];

/// Active sessions: `info_hash → that session's inbound channel`. The
/// `SessionManager` inserts on add and removes on remove; the acceptor
/// snapshots it to route each connection and to build the MSE candidate
/// set. Behind an `Arc<Mutex<…>>` so both sides share one map.
pub type Registry = Arc<Mutex<HashMap<InfoHash, mpsc::Sender<Inbound>>>>;

/// Build an empty registry handle.
pub fn new_registry() -> Registry {
    Arc::new(Mutex::new(HashMap::new()))
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Spawn the shared acceptor: a TCP accept loop (with the same per-source
/// IP connect rate-limit the single-torrent listener uses) plus an
/// optional µTP accept loop. Each accepted connection is handshaked and
/// routed on its own task so a slow peer can't stall the accept loop.
/// Returns the join handle for the TCP loop (the daemon aborts it on
/// shutdown).
pub fn spawn(
    tcp: TcpListener,
    utp: Option<Arc<UtpSocket>>,
    registry: Registry,
    peer_id: PeerId,
) -> JoinHandle<()> {
    // µTP accept loop (if a shared µTP socket was provided).
    if let Some(u) = utp {
        let reg = registry.clone();
        tokio::spawn(async move {
            while let Ok((stream, addr)) = u.accept().await {
                let reg = reg.clone();
                tokio::spawn(async move {
                    route_one(Transport::Utp(stream), addr, &reg, peer_id).await;
                });
            }
        });
    }

    tokio::spawn(async move {
        // B4 — per-source-IP connect rate limit, mirroring the
        // single-torrent listener. Lazily-created buckets, GC'd to keep
        // the map bounded on a long-lived daemon.
        let mut buckets: HashMap<IpAddr, TokenBucket> = HashMap::new();
        let mut last_gc = Instant::now();
        loop {
            match tcp.accept().await {
                Ok((s, addr)) => {
                    let ip = addr.ip();
                    let bucket = buckets
                        .entry(ip)
                        .or_insert_with(|| TokenBucket::new(10.0, 1.0));
                    if !bucket.try_consume(1.0) {
                        tracing::debug!(target: "acceptor", %addr, "per-IP connect rate limit; dropping");
                        drop(s);
                        continue;
                    }
                    if last_gc.elapsed() > Duration::from_secs(300) {
                        buckets.retain(|_, b| b.available() < 9.0);
                        last_gc = Instant::now();
                    }
                    let reg = registry.clone();
                    tokio::spawn(async move {
                        route_one(Transport::Tcp(s), addr, &reg, peer_id).await;
                    });
                }
                Err(e) => {
                    tracing::debug!(target: "acceptor", error = %e, "accept");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
}

/// Handshake one inbound connection and route it to the matching session.
/// Returns `true` if it was handed to a session, `false` if dropped
/// (unknown info_hash, malformed handshake, timeout, or the session went
/// away mid-handshake). Never propagates errors — a bad inbound peer must
/// not be able to crash the acceptor.
pub async fn route_one(
    mut stream: Transport,
    addr: SocketAddr,
    registry: &Registry,
    peer_id: PeerId,
) -> bool {
    stream.set_nodelay();
    let peeked = match timeout(HANDSHAKE_TIMEOUT, stream.peek_first_byte()).await {
        Ok(Ok(Some(b))) => b,
        _ => return false,
    };
    if peeked == PSTRLEN {
        route_plain(stream, addr, registry, peer_id).await
    } else {
        // Anything else → assume MSE/PE; the peeked byte starts `Ya`.
        route_mse(stream, addr, registry, peer_id).await
    }
}

/// Plain BT: read the 68-byte handshake (the peek did not consume it),
/// match its info_hash against the registry, reply, and forward.
async fn route_plain(
    mut stream: Transport,
    addr: SocketAddr,
    registry: &Registry,
    peer_id: PeerId,
) -> bool {
    let mut buf = [0u8; HANDSHAKE_LEN];
    match timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        _ => return false,
    }
    let theirs = match Handshake::decode(&buf) {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(target: "acceptor", %addr, error = %e, "plain handshake decode failed");
            return false;
        }
    };
    // Look up the session for the claimed info_hash.
    let tx = match registry.lock().await.get(&theirs.info_hash) {
        Some(tx) => tx.clone(),
        None => {
            tracing::debug!(target: "acceptor", %addr, "plain: no session for info_hash; dropping");
            return false;
        }
    };
    // Reply with our handshake for that torrent.
    let ours = Handshake::new(theirs.info_hash, peer_id);
    if timeout(HANDSHAKE_TIMEOUT, stream.write_all(&ours.encode()))
        .await
        .map(|r| r.is_ok())
        != Ok(true)
    {
        return false;
    }
    let supports_ext = supports_extension_protocol(&theirs.reserved);
    let (reader, writer) = split(stream);
    let peer = HandshakenPeer {
        info_hash: theirs.info_hash,
        addr,
        peer_id: theirs.peer_id,
        supports_ext,
        reader: Box::new(reader),
        writer: Box::new(writer),
    };
    tx.send(Inbound::Handshaken(peer)).await.is_ok()
}

/// MSE/PE: run the DH exchange against the current candidate set, then the
/// BT handshake over the encrypted stream, then forward.
async fn route_mse(
    stream: Transport,
    addr: SocketAddr,
    registry: &Registry,
    peer_id: PeerId,
) -> bool {
    // Snapshot the current active info_hashes for the req2 match. If the
    // set is empty there's nothing this connection could belong to.
    let candidates: Vec<InfoHash> = { registry.lock().await.keys().copied().collect() };
    if candidates.is_empty() {
        return false;
    }
    let (mut enc, matched) = match timeout(
        HANDSHAKE_TIMEOUT,
        mse::perform_incoming(stream, &candidates, &[]),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::debug!(target: "acceptor", %addr, error = %e, "mse incoming failed");
            return false;
        }
        Err(_) => return false,
    };
    // BT handshake over the encrypted stream (we're the receiver). This
    // also validates the peer's info_hash equals `matched`.
    let theirs = match timeout(
        HANDSHAKE_TIMEOUT,
        Handshake::perform_incoming(&mut enc, matched, peer_id),
    )
    .await
    {
        Ok(Ok(h)) => h,
        _ => return false,
    };
    // Re-look-up after the (slow) handshake in case the session was
    // removed in the meantime.
    let tx = match registry.lock().await.get(&matched) {
        Some(tx) => tx.clone(),
        None => return false,
    };
    let supports_ext = supports_extension_protocol(&theirs.reserved);
    let (raw, in_cipher, out_cipher) = enc.into_parts();
    let (read_half, write_half) = split(raw);
    let reader = mse::Rc4Reader::new(read_half, in_cipher);
    let writer = mse::Rc4Writer::new(write_half, out_cipher);
    let peer = HandshakenPeer {
        info_hash: matched,
        addr,
        peer_id: theirs.peer_id,
        supports_ext,
        reader: Box::new(reader),
        writer: Box::new(writer),
    };
    tx.send(Inbound::Handshaken(peer)).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    /// Connect a loopback TCP pair and return (server_transport,
    /// client_stream).
    async fn tcp_pair() -> (Transport, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr);
        let server = l.accept();
        let (client, server) = tokio::join!(client, server);
        let (server, _) = server.unwrap();
        (Transport::Tcp(server), client.unwrap())
    }

    fn registry_with(ih: InfoHash) -> (Registry, mpsc::Receiver<Inbound>) {
        let (tx, rx) = mpsc::channel(4);
        let reg = new_registry();
        reg.try_lock().unwrap().insert(ih, tx);
        (reg, rx)
    }

    #[tokio::test]
    async fn routes_plain_handshake_to_matching_session() {
        let ih = [0xAB; 20];
        let (reg, mut rx) = registry_with(ih);
        let (server, mut client) = tcp_pair().await;
        let daemon_peer_id = [9u8; 20];
        let client_peer_id = [7u8; 20];

        // Acceptor side.
        let reg2 = reg.clone();
        let acc = tokio::spawn(async move {
            route_one(server, "1.2.3.4:5".parse().unwrap(), &reg2, daemon_peer_id).await
        });

        // Client: send a plain handshake, read the reply.
        client
            .write_all(&Handshake::new(ih, client_peer_id).encode())
            .await
            .unwrap();
        let mut reply = [0u8; HANDSHAKE_LEN];
        client.read_exact(&mut reply).await.unwrap();
        let reply = Handshake::decode(&reply).unwrap();
        assert_eq!(reply.info_hash, ih);
        assert_eq!(reply.peer_id, daemon_peer_id);

        assert!(acc.await.unwrap(), "route_one should report success");
        // The session received a handshaken peer for the right torrent.
        match rx.try_recv().unwrap() {
            Inbound::Handshaken(p) => {
                assert_eq!(p.info_hash, ih);
                assert_eq!(p.peer_id, client_peer_id);
            }
            _ => panic!("expected Handshaken"),
        }
    }

    #[tokio::test]
    async fn drops_unknown_info_hash() {
        let ih = [0xAB; 20];
        let other = [0xCD; 20];
        let (reg, mut rx) = registry_with(ih);
        let (server, mut client) = tcp_pair().await;
        let reg2 = reg.clone();
        let acc = tokio::spawn(async move {
            route_one(server, "1.2.3.4:5".parse().unwrap(), &reg2, [9u8; 20]).await
        });
        // Handshake for a torrent we don't host.
        client
            .write_all(&Handshake::new(other, [7u8; 20]).encode())
            .await
            .unwrap();
        assert!(!acc.await.unwrap(), "unknown info_hash must be dropped");
        assert!(rx.try_recv().is_err(), "no session should be notified");
    }

    #[tokio::test]
    async fn routes_mse_handshake_via_candidate_match() {
        let ih = [0x5A; 20];
        let (reg, mut rx) = registry_with(ih);
        let (server, client) = tcp_pair().await;
        let daemon_peer_id = [9u8; 20];
        let client_peer_id = [7u8; 20];

        let reg2 = reg.clone();
        let acc = tokio::spawn(async move {
            route_one(server, "9.9.9.9:9".parse().unwrap(), &reg2, daemon_peer_id).await
        });

        // Client drives the MSE outgoing handshake, then BT-over-MSE.
        let client_task = tokio::spawn(async move {
            let mut enc = mse::perform_outgoing(client, ih).await.unwrap();
            let theirs = Handshake::perform_outgoing(&mut enc, ih, client_peer_id)
                .await
                .unwrap();
            theirs.peer_id
        });

        let routed = acc.await.unwrap();
        assert!(routed, "MSE connection should route to the matched session");
        let their_reply_id = client_task.await.unwrap();
        assert_eq!(their_reply_id, daemon_peer_id);

        match rx.try_recv().unwrap() {
            Inbound::Handshaken(p) => {
                assert_eq!(p.info_hash, ih, "matched the candidate info_hash");
                assert_eq!(p.peer_id, client_peer_id);
            }
            _ => panic!("expected Handshaken"),
        }
    }
}
