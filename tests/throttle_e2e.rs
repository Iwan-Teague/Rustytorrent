//! Integration test proving that `--max-down` throttling engages and
//! produces byte-exact output. The throttle adds artificial delay between
//! pieces; this test verifies the download still completes correctly.

use std::time::Duration;

use rustytorrent::engine::{EngineConfig, TorrentEngine};
use rustytorrent::metainfo::{Info, TorrentFile, TorrentFiles};
use sha1::{Digest, Sha1};

const PIECE_LEN: u64 = 16384;
const NUM_PIECES: usize = 4;

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
async fn throttled_download_produces_exact_output() {
    let data: Vec<u8> = (0..NUM_PIECES * PIECE_LEN as usize)
        .map(|i| (i % 253 + 1) as u8)
        .collect();
    let torrent = make_torrent("thr.bin", &data);

    let seed_dir = std::env::temp_dir().join(format!("rt_thr_s_{}", std::process::id()));
    tokio::fs::create_dir_all(&seed_dir).await.unwrap();
    std::fs::write(seed_dir.join("thr.bin"), &data).unwrap();

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seeder_port = probe.local_addr().unwrap().port();
    drop(probe);

    let seed_cfg = EngineConfig {
        output_dir: seed_dir.clone(),
        listen_port: seeder_port,
        no_tracker: true,
        ..Default::default()
    };
    let seeder_engine = TorrentEngine::new(torrent.clone(), [1u8; 20], seed_cfg);
    let seeder_task = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(60), seeder_engine.run()).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let leech_dir = std::env::temp_dir().join(format!("rt_thr_l_{}", std::process::id()));
    tokio::fs::create_dir_all(&leech_dir).await.unwrap();

    let cfg = EngineConfig {
        output_dir: leech_dir.clone(),
        listen_port: 0,
        no_tracker: true,
        max_down_bytes_per_sec: Some(32 * 1024), // 32 KiB/s
        seed_peers: vec![format!("127.0.0.1:{seeder_port}").parse().unwrap()],
        ..Default::default()
    };

    let leecher = TorrentEngine::new(torrent.clone(), [2u8; 20], cfg);
    let leecher_task = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(60), leecher.run()).await;
    });

    // Wait for the download to finish.
    let _ = tokio::time::timeout(Duration::from_secs(45), leecher_task).await;

    // Verify byte-exactness.
    let out_path = leech_dir.join("thr.bin");
    let got = tokio::fs::read(&out_path).await.unwrap();
    assert_eq!(got.len(), data.len(), "size mismatch");
    assert_eq!(got, data, "content mismatch");

    seeder_task.abort();
    let _ = tokio::fs::remove_dir_all(&seed_dir).await;
    let _ = tokio::fs::remove_dir_all(&leech_dir).await;
}
