//! Hostile BEP 6 REJECT_REQUEST injection against a live engine.
//!
//! A connected peer can send REJECT_REQUEST naming any (index, begin).
//! Two invariants must hold:
//!
//! 1. **No crash**: an out-of-range `index` must not reach PieceManager's
//!    unchecked `states[index]` indexing. Before the guard existed, ONE
//!    forged reject with index = 0xFFFFFFFF panicked the engine task.
//! 2. **No cross-peer poisoning**: a reject may only clear request state
//!    for requests we sent to the rejecting peer itself. Otherwise a
//!    malicious peer could erase another peer's outstanding entry and
//!    that peer's honest block would be dropped as "unsolicited".
//!
//! The deterministic, end-to-end proof of both: while an honest seeder
//! serves the leecher, a hostile inbound peer spams forged REJECTs (huge
//! indices AND valid-looking ones). The leecher must still finish
//! byte-identical within the normal budget.

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

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Speak enough BT protocol to be accepted as an inbound peer, then fire
/// `n` forged REJECT_REQUEST frames (BEP 6, id 16) mixing huge and
/// small-but-fake indices.
async fn hostile_reject_flood(addr: std::net::SocketAddr, info_hash: [u8; 20], n: u32) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock =
        tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
            .await
            .expect("attacker dials")
            .expect("attacker connected");

    // Handshake: protocol string + reserved + info_hash + peer_id.
    let mut hs = Vec::with_capacity(68);
    hs.push(19u8);
    hs.extend_from_slice(b"BitTorrent protocol");
    // Reserved: BEP 10 ext bit (byte5=0x10) + BEP 6 bit (byte7=0x04) so
    // our REJECT frames are semantically plausible.
    hs.extend_from_slice(&[0, 0, 0, 0, 0, 0x10, 0, 0x04]);
    hs.extend_from_slice(&info_hash);
    hs.extend_from_slice(&[0x66u8; 20]); // attacker peer id
    sock.write_all(&hs).await.unwrap();

    // Read the engine's handshake reply (68 bytes) so it isn't blocked on
    // write; ignore contents.
    let mut echo = vec![0u8; 68];
    sock.read_exact(&mut echo).await.unwrap();

    for i in 0..n {
        let (index, begin) = if i % 2 == 0 {
            (u32::MAX - i, 0) // wildly out of range
        } else {
            (i % 3, (i % 4) * 16384) // plausible but never requested from us
        };
        let mut frame = Vec::with_capacity(13);
        frame.extend_from_slice(&13u32.to_be_bytes());
        frame.push(16u8); // REJECT_REQUEST
        frame.extend_from_slice(&index.to_be_bytes());
        frame.extend_from_slice(&begin.to_be_bytes());
        sock.write_all(&frame).await.unwrap();
    }

    // Linger briefly so the frames are definitely processed mid-download.
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Dropping the socket ends our side cleanly.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_reject_requests_do_not_crash_or_poison_the_download() {
    let data: Vec<u8> = (0..40_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let name = "reject.bin";
    let torrent = Arc::new(make_torrent(name, &data));

    let tmp = std::env::temp_dir().join(format!("rt_reject_{}", std::process::id()));
    let seed_dir = tmp.join("seed");
    let leech_dir = tmp.join("leech");
    tokio::fs::create_dir_all(&seed_dir).await.unwrap();
    tokio::fs::create_dir_all(&leech_dir).await.unwrap();
    tokio::fs::write(seed_dir.join(name), &data).await.unwrap();

    let seeder_port = free_port().await;

    let seed_cfg = EngineConfig {
        output_dir: seed_dir.clone(),
        listen_port: seeder_port,
        no_tracker: true,
        ..Default::default()
    };
    let seeder = TorrentEngine::new((*torrent).clone(), [1u8; 20], seed_cfg);
    let seeder_task = tokio::spawn(async move {
        let _ = seeder.run().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let leech_port = free_port().await;
    let leech_cfg = EngineConfig {
        output_dir: leech_dir.clone(),
        listen_port: leech_port,
        no_tracker: true,
        seed_peers: vec![format!("127.0.0.1:{seeder_port}").parse().unwrap()],
        ..Default::default()
    };

    // Attacker connects BEFORE the leecher starts so at least one flood
    // lands around the request traffic; keep flooding in the background
    // across the whole transfer.
    let attacker_info_hash = torrent.info_hash;
    let attacker_addr: std::net::SocketAddr = format!("127.0.0.1:{leech_port}").parse().unwrap();
    tokio::spawn(async move {
        // Wait for the listener, then run several waves.
        for wave in 0..3 {
            tokio::time::sleep(Duration::from_millis(250 * wave)).await;
            hostile_reject_flood(attacker_addr, attacker_info_hash, 40).await;
        }
    });

    let leecher = TorrentEngine::new((*torrent).clone(), [2u8; 20], leech_cfg);
    let result = tokio::time::timeout(Duration::from_secs(30), leecher.run()).await;
    assert!(
        result.is_ok(),
        "download did not finish — forged rejects broke it"
    );
    result.unwrap().expect("leecher run returned error");

    let got = tokio::fs::read(leech_dir.join(name)).await.unwrap();
    assert_eq!(got.len(), data.len(), "size mismatch");
    assert_eq!(got, data, "bytes differ from the seed");

    seeder_task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
