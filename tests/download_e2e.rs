//! End-to-end download test: a seeder engine that already has the data
//! serves it to a leecher engine over loopback (no tracker, direct peer),
//! and we assert the leecher writes byte-identical output.
//!
//! This is the gold-standard integration test — it exercises the real
//! download path end to end: handshake, bitfield exchange, the rarest-
//! first picker, block pipelining, SHA-1 piece verification, multi-slice
//! disk writes, the choke algorithm, and completion. None of the other
//! integration tests cover an actual transfer.

use std::sync::Arc;
use std::time::Duration;

use rustytorrent::engine::{EngineConfig, TorrentEngine};
use rustytorrent::metainfo::{FileEntry, Info, TorrentFile, TorrentFiles};
use sha1::{Digest, Sha1};

const PIECE_LEN: u64 = 16384;

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}

/// Build a single-file `TorrentFile` describing `data` with correct
/// per-piece SHA-1 hashes. The `info_hash` is arbitrary-but-consistent —
/// the transfer only needs both ends to agree on it and on the piece
/// hashes; it isn't re-derived from the info dict here.
fn make_torrent(name: &str, data: &[u8]) -> TorrentFile {
    let piece_hashes: Vec<[u8; 20]> = data.chunks(PIECE_LEN as usize).map(sha1).collect();
    TorrentFile {
        info_hash: sha1(data), // unique per data; both ends use the same value
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

/// Bind-and-drop to discover a free localhost TCP port.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seeder_serves_leecher_full_download() {
    // ~40 KB → 3 pieces (two full + one short). Distinct bytes so piece
    // verification is meaningful (not all-zero).
    let data: Vec<u8> = (0..40_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let name = "e2e.bin";
    let torrent = Arc::new(make_torrent(name, &data));

    let tmp = std::env::temp_dir().join(format!("rt_e2e_{}", std::process::id()));
    let seed_dir = tmp.join("seed");
    let leech_dir = tmp.join("leech");
    tokio::fs::create_dir_all(&seed_dir).await.unwrap();
    tokio::fs::create_dir_all(&leech_dir).await.unwrap();

    // Seeder already has the complete file on disk → its resume scan
    // marks every piece verified, so it starts as a seed.
    tokio::fs::write(seed_dir.join(name), &data).await.unwrap();

    let port = free_port().await;

    // Spawn the seeder; it idles + serves (started complete → never exits).
    let seed_cfg = EngineConfig {
        output_dir: seed_dir.clone(),
        listen_port: port,
        no_tracker: true,
        ..Default::default()
    };
    let seeder = TorrentEngine::new((*torrent).clone(), [1u8; 20], seed_cfg);
    let seeder_task = tokio::spawn(async move {
        let _ = seeder.run().await;
    });

    // Give the seeder a moment to bind its listener before the leecher
    // dials (the leecher only has this one peer and won't re-discover).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Leecher: no tracker, dial the seeder directly. run() returns once
    // every piece is downloaded + written.
    let leech_cfg = EngineConfig {
        output_dir: leech_dir.clone(),
        listen_port: free_port().await,
        no_tracker: true,
        seed_peers: vec![format!("127.0.0.1:{port}").parse().unwrap()],
        ..Default::default()
    };
    let leecher = TorrentEngine::new((*torrent).clone(), [2u8; 20], leech_cfg);

    let result = tokio::time::timeout(Duration::from_secs(30), leecher.run()).await;
    assert!(result.is_ok(), "leecher did not finish within 30s");
    assert!(result.unwrap().is_ok(), "leecher run() returned an error");

    // The downloaded file must be byte-identical to the seeded data.
    let got = tokio::fs::read(leech_dir.join(name)).await.unwrap();
    assert_eq!(got.len(), data.len(), "downloaded size mismatch");
    assert_eq!(got, data, "downloaded bytes differ from the seed");

    seeder_task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_file_download_writes_correct_offsets() {
    // Two files whose boundary falls inside a piece, so the picker /
    // storage must split a downloaded piece across both files (virtual
    // offset map). a.bin = 25000 bytes, b.bin = 15000 → 40000 total,
    // piece 1 (16384..32768) straddles the 25000 boundary.
    let a: Vec<u8> = (0..25_000u32)
        .map(|i| (i.wrapping_mul(40503) >> 7) as u8)
        .collect();
    let b: Vec<u8> = (0..15_000u32)
        .map(|i| (i.wrapping_mul(2246822519) >> 11) as u8)
        .collect();
    let mut data = a.clone();
    data.extend_from_slice(&b);

    let dir = "pkg";
    let piece_hashes: Vec<[u8; 20]> = data.chunks(PIECE_LEN as usize).map(sha1).collect();
    let torrent = TorrentFile {
        info_hash: sha1(&data),
        announce: None,
        announce_list: vec![],
        info: Info {
            name: dir.to_string(),
            piece_length: PIECE_LEN,
            piece_hashes,
            files: TorrentFiles::Multi {
                files: vec![
                    FileEntry {
                        length: a.len() as u64,
                        path: "a.bin".into(),
                    },
                    FileEntry {
                        length: b.len() as u64,
                        path: "b.bin".into(),
                    },
                ],
            },
            private: false,
        },
    };

    let tmp = std::env::temp_dir().join(format!("rt_e2e_mf_{}", std::process::id()));
    let seed_dir = tmp.join("seed");
    let leech_dir = tmp.join("leech");
    tokio::fs::create_dir_all(seed_dir.join(dir)).await.unwrap();
    tokio::fs::create_dir_all(&leech_dir).await.unwrap();
    // Seed both files in the torrent's directory.
    tokio::fs::write(seed_dir.join(dir).join("a.bin"), &a)
        .await
        .unwrap();
    tokio::fs::write(seed_dir.join(dir).join("b.bin"), &b)
        .await
        .unwrap();

    let port = free_port().await;
    let seeder = TorrentEngine::new(
        torrent.clone(),
        [3u8; 20],
        EngineConfig {
            output_dir: seed_dir.clone(),
            listen_port: port,
            no_tracker: true,
            ..Default::default()
        },
    );
    let seeder_task = tokio::spawn(async move {
        let _ = seeder.run().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let leecher = TorrentEngine::new(
        torrent,
        [4u8; 20],
        EngineConfig {
            output_dir: leech_dir.clone(),
            listen_port: free_port().await,
            no_tracker: true,
            seed_peers: vec![format!("127.0.0.1:{port}").parse().unwrap()],
            ..Default::default()
        },
    );
    let result = tokio::time::timeout(Duration::from_secs(30), leecher.run()).await;
    assert!(result.is_ok(), "leecher timed out");
    assert!(result.unwrap().is_ok());

    // Each file must be written to its own region, byte-identical.
    let got_a = tokio::fs::read(leech_dir.join(dir).join("a.bin"))
        .await
        .unwrap();
    let got_b = tokio::fs::read(leech_dir.join(dir).join("b.bin"))
        .await
        .unwrap();
    assert_eq!(got_a, a, "a.bin mismatch (wrong piece→file mapping?)");
    assert_eq!(got_b, b, "b.bin mismatch");

    seeder_task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selective_download_fetches_only_wanted_file() {
    // Same 2-file torrent. Select only "a.bin": the leecher fetches the
    // pieces overlapping a.bin (0 and the boundary piece 1), completes
    // (wanted-relative), and writes a.bin in full — without fetching
    // piece 2 (entirely inside b.bin).
    let a: Vec<u8> = (0..25_000u32)
        .map(|i| (i.wrapping_mul(40503) >> 7) as u8)
        .collect();
    let b: Vec<u8> = (0..15_000u32)
        .map(|i| (i.wrapping_mul(2246822519) >> 11) as u8)
        .collect();
    let mut data = a.clone();
    data.extend_from_slice(&b);

    let dir = "pkg";
    let piece_hashes: Vec<[u8; 20]> = data.chunks(PIECE_LEN as usize).map(sha1).collect();
    let torrent = TorrentFile {
        info_hash: sha1(&data),
        announce: None,
        announce_list: vec![],
        info: Info {
            name: dir.to_string(),
            piece_length: PIECE_LEN,
            piece_hashes,
            files: TorrentFiles::Multi {
                files: vec![
                    FileEntry {
                        length: a.len() as u64,
                        path: "a.bin".into(),
                    },
                    FileEntry {
                        length: b.len() as u64,
                        path: "b.bin".into(),
                    },
                ],
            },
            private: false,
        },
    };

    let tmp = std::env::temp_dir().join(format!("rt_e2e_sel_{}", std::process::id()));
    let seed_dir = tmp.join("seed");
    let leech_dir = tmp.join("leech");
    tokio::fs::create_dir_all(seed_dir.join(dir)).await.unwrap();
    tokio::fs::create_dir_all(&leech_dir).await.unwrap();
    tokio::fs::write(seed_dir.join(dir).join("a.bin"), &a)
        .await
        .unwrap();
    tokio::fs::write(seed_dir.join(dir).join("b.bin"), &b)
        .await
        .unwrap();

    let port = free_port().await;
    let seeder = TorrentEngine::new(
        torrent.clone(),
        [5u8; 20],
        EngineConfig {
            output_dir: seed_dir.clone(),
            listen_port: port,
            no_tracker: true,
            ..Default::default()
        },
    );
    let seeder_task = tokio::spawn(async move {
        let _ = seeder.run().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let leecher = TorrentEngine::new(
        torrent,
        [6u8; 20],
        EngineConfig {
            output_dir: leech_dir.clone(),
            listen_port: free_port().await,
            no_tracker: true,
            seed_peers: vec![format!("127.0.0.1:{port}").parse().unwrap()],
            selected_files: vec!["a.bin".to_string()],
            ..Default::default()
        },
    );
    let result = tokio::time::timeout(Duration::from_secs(30), leecher.run()).await;
    assert!(result.is_ok(), "selective leecher timed out");
    assert!(result.unwrap().is_ok());

    let got_a = tokio::fs::read(leech_dir.join(dir).join("a.bin"))
        .await
        .unwrap();
    assert_eq!(got_a, a, "selected file a.bin must be complete");

    seeder_task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
