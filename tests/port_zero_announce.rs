//! `--port 0` must resolve to the ACTUAL bound ephemeral port before any
//! tracker announce.
//!
//! Regression: the listener bound an OS-assigned port but nothing wrote
//! it back into the session config, so announces advertised `port=0` —
//! the protocol's "I have no listener" placeholder — while a live seeder
//! socket actually existed. Passive discovery silently broke for anyone
//! using the standard "pick a random port for me" convention.
//!
//! Proof: a scripted HTTP tracker captures the announced `port=` from
//! the query string and asserts it is non-zero AND reachable (a full BT
//! handshake round-trip succeeds against exactly that port).

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
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

fn make_torrent_with_announce(name: &str, announce: String) -> TorrentFile {
    let data = vec![0xCDu8; 4096];
    TorrentFile {
        info_hash: sha1(&data),
        announce: Some(announce),
        announce_list: vec![],
        info: Info {
            name: name.to_string(),
            piece_length: PIECE_LEN,
            piece_hashes: vec![sha1(&data)],
            files: TorrentFiles::Single {
                length: data.len() as u64,
            },
            private: false,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn port_zero_resolves_before_announcing() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Fake HTTP tracker: capture announced port=, reply valid empty compact.
    let tracker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tracker_addr = tracker.local_addr().unwrap();

    let captured = Arc::new(AtomicU16::new(0));
    let cap2 = captured.clone();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = tracker.accept().await {
            let mut req = vec![0u8; 4096];
            let n = sock.read(&mut req).await.unwrap_or(0);
            let text = String::from_utf8_lossy(&req[..n]).to_string();
            if let Some(idx) = text.find("port=") {
                let rest = &text[idx + 5..];
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(p) = digits.parse::<u16>() {
                    cap2.store(p, Ordering::Relaxed);
                }
            }
            let body = b"d8:completei0e10:incompletei0e8:intervali1800e5:peers0:e";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(body).await;
        }
    });

    // Bind the fake tracker first so we can bake its URL into the torrent.
    let torrent = make_torrent_with_announce("p0.bin", format!("http://{tracker_addr}/announce"));

    let tmp = std::env::temp_dir().join(format!("rt_p0_{}", std::process::id()));
    tokio::fs::create_dir_all(&tmp).await.unwrap();

    let cfg = EngineConfig {
        output_dir: tmp.clone(),
        listen_port: 0, // THE point under test
        no_tracker: false,
        ..Default::default()
    };
    let engine = TorrentEngine::new(torrent.clone(), [5u8; 20], cfg);
    let task = tokio::spawn(async move {
        let _ = engine.run().await;
    });

    // Initial announce fires near the top of run().
    tokio::time::sleep(Duration::from_millis(800)).await;
    let advertised = captured.load(Ordering::Relaxed);
    assert_ne!(
        advertised, 0,
        "announce advertised port=0 while a live listener exists"
    );

    // The advertised port must be REACHABLE: a full BT handshake
    // round-trip succeeds against exactly that port.
    let dial_addr: std::net::SocketAddr = format!("127.0.0.1:{advertised}").parse().unwrap();
    let mut sock = tokio::net::TcpStream::connect(dial_addr).await.unwrap();
    let mut hs = Vec::with_capacity(68);
    hs.push(19u8);
    hs.extend_from_slice(b"BitTorrent protocol");
    hs.extend_from_slice(&[0u8; 8]);
    hs.extend_from_slice(&torrent.info_hash);
    hs.extend_from_slice(&[0x88u8; 20]);
    sock.write_all(&hs).await.unwrap();
    let mut reply = vec![0u8; 68];
    tokio::time::timeout(Duration::from_secs(3), sock.read_exact(&mut reply))
        .await
        .expect("handshake reply within 3s")
        .expect("reply complete");
    // reply[0] is the protocol-string length byte (19).
    assert_eq!(reply[0], 19);
    assert_eq!(&reply[1..20], b"BitTorrent protocol");

    task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
