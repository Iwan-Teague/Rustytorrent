//! B4 — per-source-IP inbound CONNECT rate limit, wired end to end.
//!
//! The engine's accept loop drops connections without engaging the
//! handshake once a source IP's token bucket (burst 10, refill 1/s) runs
//! dry. The bucket mechanics are unit-tested elsewhere; THIS test pins
//! the wiring: a real engine, a real listener, a flood of real
//! connections from one address.
//!
//! Assertions:
//! - early connections DO get a handshake reply (the burst admits them),
//! - total successful handshakes stay bounded near the burst size,
//! - nothing crashes and the engine keeps serving afterwards.

use std::time::Duration;

use rustytorrent::engine::{EngineConfig, TorrentEngine};
use rustytorrent::metainfo::{Info, TorrentFile, TorrentFiles};
use sha1::{Digest, Sha1};

const PIECE_LEN: u64 = 16384;

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}

fn make_torrent(name: &str, data: &[u8]) -> TorrentFile {
    let piece_hashes: Vec<[u8; 20]> = data.chunks(PIECE_LEN as usize).map(sha1).collect();
    TorrentFile {
        info_hash: sha1(data),
        announce: None,
        announce_list: vec![],
        info: Info {
            name: name.to_string(),
            piece_length: PIECE_LEN,
            piece_hashes,
            files: TorrentFiles::Single {
                length: data.len() as u64,
            },
            private: false,
        },
    }
}

/// One probe: connect, speak a valid plain BT handshake, wait briefly
/// for the engine's 68-byte handshake reply. Returns true if replied.
async fn probe(addr: std::net::SocketAddr, info_hash: [u8; 20]) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock =
        match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
            .await
        {
            Ok(Ok(s)) => s,
            _ => return false,
        };

    let mut hs = Vec::with_capacity(68);
    hs.push(19u8);
    hs.extend_from_slice(b"BitTorrent protocol");
    hs.extend_from_slice(&[0u8; 8]); // reserved
    hs.extend_from_slice(&info_hash);
    hs.extend_from_slice(&[0x77u8; 20]);
    if sock.write_all(&hs).await.is_err() {
        return false;
    }

    let mut reply = vec![0u8; 68];
    matches!(
        tokio::time::timeout(Duration::from_millis(400), sock.read_exact(&mut reply)).await,
        Ok(Ok(_))
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_connect_flood_is_capped_per_ip() {
    let data = vec![0xCDu8; 4096];
    let torrent = make_torrent("flood.bin", &data);

    let tmp = std::env::temp_dir().join(format!("rt_flood_{}", std::process::id()));
    tokio::fs::create_dir_all(&tmp).await.unwrap();

    // Find a free port, then bind the engine there.
    let probe_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe_l.local_addr().unwrap().port();
    drop(probe_l);

    let cfg = EngineConfig {
        output_dir: tmp.clone(),
        listen_port: port,
        no_tracker: true,
        ..Default::default()
    };
    let engine = TorrentEngine::new(torrent.clone(), [3u8; 20], cfg);
    let task = tokio::spawn(async move {
        let _ = engine.run().await;
    });

    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // Wait for the listener.
    let mut bound = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(listen_addr).await.is_ok() {
            bound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(bound, "listener never came up");

    // Flood: 16 rapid handshakes from this IP. Bucket = burst 10, 1/s.
    const ATTEMPTS: usize = 16;
    let mut replied = 0usize;
    for _ in 0..ATTEMPTS {
        if probe(listen_addr, torrent.info_hash).await {
            replied += 1;
        }
    }

    assert!(
        replied >= (ATTEMPTS / 2),
        "too few handshakes answered ({replied}) — throttle over-fires"
    );
    assert!(
        replied < ATTEMPTS,
        "all {ATTEMPTS} attempts answered — per-IP connect limit not enforced"
    );

    // Sanity: the engine survived the flood.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!task.is_finished(), "engine task died during connect flood");

    task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
