//! B3 — per-peer inbound Request rate limit, wired end to end.
//!
//! The read loop consults a token bucket (burst 50, refill 200/s) before
//! forwarding Request events; over-quota requests are silently dropped
//! so a hostile peer can't turn our upload side into unlimited disk-read
//! pressure. This test pins the WIRING against a real seeder: after the
//! BT handshake + interest/unchoke dance, a flood of 300 valid Requests
//! must yield far fewer Piece replies than the flood size (the burst
//! cap), while still being served at all (honest peers aren't starved).

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_flood_is_rate_limited_but_served() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let data: Vec<u8> = (0..40_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let torrent = Arc::new(make_torrent("b3.bin", &data));

    let tmp = std::env::temp_dir().join(format!("rt_b3_{}", std::process::id()));
    tokio::fs::create_dir_all(&tmp).await.unwrap();
    tokio::fs::write(tmp.join("b3.bin"), &data).await.unwrap();

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let cfg = EngineConfig {
        output_dir: tmp.clone(),
        listen_port: port,
        no_tracker: true,
        ..Default::default()
    };
    let engine = TorrentEngine::new((*torrent).clone(), [4u8; 20], cfg);
    let task = tokio::spawn(async move {
        let _ = engine.run().await;
    });

    // Listener up?
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(listen_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Handshake.
    let mut sock = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
    let mut hs = Vec::with_capacity(68);
    hs.push(19u8);
    hs.extend_from_slice(b"BitTorrent protocol");
    hs.extend_from_slice(&[0, 0, 0, 0, 0, 0x10, 0, 0x04]); // BEP10 + BEP6
    hs.extend_from_slice(&torrent.info_hash);
    hs.extend_from_slice(&[0x99u8; 20]);
    sock.write_all(&hs).await.unwrap();
    let mut reply = vec![0u8; 68];
    sock.read_exact(&mut reply)
        .await
        .expect("seeder handshakes back");

    // Express interest; wait for Unchoke (choke tick fires immediately,
    // and we are the only candidate peer).
    sock.write_all(&1u32.to_be_bytes()).await.unwrap();
    sock.write_all(&[3u8]).await.expect("interested sent");

    let mut unchoked = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut acc: Vec<u8> = Vec::new();
    let mut rbuf = vec![0u8; 4096];
    while !unchoked && std::time::Instant::now() < deadline {
        let n = match tokio::time::timeout(Duration::from_millis(500), sock.read(&mut rbuf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        acc.extend_from_slice(&rbuf[..n]);
        // Properly framed scan: a naive byte search would false-positive
        // on id-like bytes inside the BITFIELD payload.
        loop {
            if acc.len() < 5 {
                break;
            }
            let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
            if len == 0 {
                acc.drain(..4);
                continue;
            }
            if acc.len() < 4 + len {
                break;
            }
            if acc[4] == 1 {
                unchoked = true;
            }
            acc.drain(..4 + len);
        }
    }
    assert!(unchoked, "seeder never unchoked the only interested peer");
    assert!(
        acc.is_empty(),
        "unparsed bytes left over — frame parser desynced"
    );

    // Phase A: ONE request must produce exactly one Piece reply.
    {
        let mut one = Vec::with_capacity(17);
        one.extend_from_slice(&13u32.to_be_bytes());
        one.push(6u8);
        one.extend_from_slice(&0u32.to_be_bytes());
        one.extend_from_slice(&0u32.to_be_bytes());
        one.extend_from_slice(&16384u32.to_be_bytes());
        sock.write_all(&one).await.expect("single request write");
        let mut buf = vec![0u8; 70_000];
        let mut got_piece = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut acc: Vec<u8> = Vec::new();
        while std::time::Instant::now() < deadline && !got_piece {
            match tokio::time::timeout(Duration::from_millis(200), sock.read(&mut buf)).await {
                Ok(Ok(0)) => panic!("server closed after single request"),
                Ok(Ok(n)) => acc.extend_from_slice(&buf[..n]),
                _ => {}
            }
            loop {
                if acc.len() < 5 {
                    break;
                }
                let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
                if len == 0 {
                    acc.drain(..4);
                    continue;
                }
                if acc.len() < 4 + len {
                    break;
                }
                if acc[4] == 7 {
                    got_piece = true;
                }
                acc.drain(..4 + len);
            }
        }
        assert!(got_piece, "single valid request was not served");
    }

    // Flood: 300 identical valid Requests for piece 0 / block 0, written
    // back-to-back so they land well inside one refill window.
    const FLOOD: usize = 300;
    let mut frame = Vec::with_capacity(17);
    frame.extend_from_slice(&13u32.to_be_bytes());
    frame.push(6u8); // REQUEST
    frame.extend_from_slice(&0u32.to_be_bytes()); // index 0
    frame.extend_from_slice(&0u32.to_be_bytes()); // begin 0
    frame.extend_from_slice(&16384u32.to_be_bytes()); // length = full piece
    let flood_frame = frame.clone();

    // Drain reader concurrently while writing the flood.
    let (mut r_half, mut w_half) = tokio::io::split(sock);
    let writer = tokio::spawn(async move {
        for _ in 0..FLOOD {
            if w_half.write_all(&flood_frame).await.is_err() {
                break;
            }
        }
        let _ = w_half.flush().await;
    });

    let mut piece_replies = 0usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    // Frame-aware reader: accumulate into `acc` and only consume whole
    // frames (4-byte BE length prefix + payload), keeping any trailing
    // partial frame for the next read.
    let mut acc: Vec<u8> = Vec::new();
    let mut rbuf = vec![0u8; 70_000];
    while std::time::Instant::now() < deadline {
        let n = match tokio::time::timeout(Duration::from_millis(200), r_half.read(&mut rbuf)).await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };
        acc.extend_from_slice(&rbuf[..n]);
        loop {
            if acc.len() < 5 {
                break;
            }
            let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
            if len == 0 {
                acc.drain(..4); // keep-alive
                continue;
            }
            if acc.len() < 4 + len {
                break;
            }
            if acc[4] == 7 {
                piece_replies += 1;
            }
            acc.drain(..4 + len);
        }
    }
    let _ = writer.await;

    assert!(piece_replies > 0, "valid requests must still be served");
    assert!(
        piece_replies < FLOOD / 2,
        "rate limit not engaged: {piece_replies}/{FLOOD} requests answered"
    );

    task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
