//! Integration test for the daemon's shared inbound listener (DAEMON.md
//! steps 1–3): one acceptor on one port routes an inbound connection to
//! the right hosted session by info_hash, and removing a session stops
//! the acceptor from routing to it.

use std::time::Duration;

use rustytorrent::acceptor;
use rustytorrent::daemon_store::DaemonStore;
use rustytorrent::engine::{bind_dual_stack_listener, EngineConfig};
use rustytorrent::metainfo::TorrentFile;
use rustytorrent::peer::handshake::{Handshake, HANDSHAKE_LEN};
use rustytorrent::session::SessionManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Minimal valid single-file `.torrent` bytes; first pieces-hash byte =
/// `tag` so distinct tags yield distinct info-hashes.
fn torrent_bytes(name: &str, tag: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"d4:infod6:lengthi16384e4:name");
    buf.extend_from_slice(format!("{}:{}", name.len(), name).as_bytes());
    buf.extend_from_slice(b"12:piece lengthi16384e6:pieces20:");
    let mut hash = [0u8; 20];
    hash[0] = tag;
    buf.extend_from_slice(&hash);
    buf.extend_from_slice(b"ee");
    buf
}

fn torrent(name: &str, tag: u8) -> TorrentFile {
    TorrentFile::from_bytes(&torrent_bytes(name, tag)).unwrap()
}

fn scratch_dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rt_daemon_persist_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Dial `port`, send a plain BT handshake for `info_hash`, and return the
/// peer's handshake reply if one arrives within a short window. `None`
/// means the connection was dropped without a reply (no matching session).
async fn try_handshake(port: u16, info_hash: [u8; 20]) -> Option<Handshake> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    s.write_all(&Handshake::new(info_hash, [0x33; 20]).encode())
        .await
        .ok()?;
    let mut reply = [0u8; HANDSHAKE_LEN];
    match timeout(Duration::from_secs(2), s.read_exact(&mut reply)).await {
        Ok(Ok(_)) => Handshake::decode(&reply).ok(),
        _ => None,
    }
}

#[tokio::test]
async fn shared_listener_routes_inbound_by_info_hash() {
    let daemon_peer_id = [0x9A; 20];

    // One shared listener + acceptor on an OS-assigned port.
    let listener = bind_dual_stack_listener(0).expect("bind shared listener");
    let port = listener.local_addr().unwrap().port();
    let registry = acceptor::new_registry();
    let acceptor_task = acceptor::spawn(listener, None, registry.clone(), daemon_peer_id);

    let mgr = SessionManager::with_shared(registry, None, port, acceptor_task, None);

    let t = torrent("alpha", 0xA1);
    let ih = t.info_hash;
    let cfg = EngineConfig {
        no_tracker: true,
        enable_dht: false,
        output_dir: std::env::temp_dir(),
        ..Default::default()
    };
    assert_eq!(mgr.add(t, daemon_peer_id, cfg).await, Some(ih));

    // Give the session a beat to register + its engine to start.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A handshake for the hosted torrent is answered by the daemon's
    // peer_id — proving the acceptor matched and routed to the session.
    let reply = try_handshake(port, ih)
        .await
        .expect("hosted info_hash should get a handshake reply");
    assert_eq!(reply.info_hash, ih);
    assert_eq!(reply.peer_id, daemon_peer_id);

    // A handshake for an unknown torrent is dropped (no reply).
    let unknown = [0xEE; 20];
    assert!(
        try_handshake(port, unknown).await.is_none(),
        "unknown info_hash must not be routed/answered"
    );

    // After removing the session, the acceptor must stop routing to it.
    assert!(mgr.remove(&ih).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        try_handshake(port, ih).await.is_none(),
        "removed session's info_hash must no longer be answered"
    );

    mgr.shutdown_all().await;
}

#[tokio::test]
async fn add_persistent_saves_and_remove_forgets() {
    let state_dir = scratch_dir();
    let daemon_peer_id = [0x9B; 20];

    let listener = bind_dual_stack_listener(0).expect("bind shared listener");
    let port = listener.local_addr().unwrap().port();
    let registry = acceptor::new_registry();
    let acceptor_task = acceptor::spawn(listener, None, registry.clone(), daemon_peer_id);
    let store = DaemonStore::open(state_dir.clone()).unwrap();
    let mgr = SessionManager::with_shared(registry, None, port, acceptor_task, Some(store));

    let raw = torrent_bytes("persisted", 0x42);
    let t = TorrentFile::from_bytes(&raw).unwrap();
    let ih = t.info_hash;
    let cfg = EngineConfig {
        no_tracker: true,
        enable_dht: false,
        output_dir: std::env::temp_dir(),
        ..Default::default()
    };
    assert_eq!(
        mgr.add_persistent(t, daemon_peer_id, cfg, &raw).await,
        Some(ih)
    );

    // A separate handle to the same dir sees the persisted torrent.
    let inspect = DaemonStore::open(state_dir.clone()).unwrap();
    let saved = inspect.load_all();
    assert_eq!(saved.len(), 1, "torrent should be persisted on add");
    assert_eq!(saved[0].torrent_bytes, raw);

    // Explicit remove erases it from the store.
    assert!(mgr.remove(&ih).await);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        inspect.load_all().is_empty(),
        "remove must forget the persisted torrent"
    );

    // Shutdown must NOT erase persistence (so a restart can resume).
    let raw2 = torrent_bytes("survives", 0x77);
    let t2 = TorrentFile::from_bytes(&raw2).unwrap();
    let cfg2 = EngineConfig {
        no_tracker: true,
        enable_dht: false,
        output_dir: std::env::temp_dir(),
        ..Default::default()
    };
    mgr.add_persistent(t2, daemon_peer_id, cfg2, &raw2).await;
    mgr.shutdown_all().await;
    assert_eq!(
        inspect.load_all().len(),
        1,
        "shutdown must leave the set on disk for restart"
    );

    std::fs::remove_dir_all(&state_dir).ok();
}
