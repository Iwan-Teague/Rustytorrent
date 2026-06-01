//! End-to-end proof that outbound dialing works over **IPv6 loopback**.
//!
//! The roadmap lists IPv6 support (dual-stack listener + IPv6 compact
//! peers) as done but flags "confirm dual-stack *dialing* works end to
//! end" as unverified. This is that confirmation, made permanent.
//!
//! It mirrors `seeder_serves_leecher_full_download` in `download_e2e.rs`
//! exactly in spirit — a complete seeder serves a leecher over a direct
//! peer link with no tracker — except the leecher reaches the seeder at an
//! `::1` (IPv6 loopback) `SocketAddr` rather than `127.0.0.1`. The seeder's
//! inbound listener binds dual-stack on `[::]` (see
//! `engine::bind_dual_stack_listener`), so the `::1` dial lands on it.
//!
//! The test asserts up front that the address it dials is genuinely an
//! IPv6 loopback `SocketAddr` (not a v4 fallback), and the free port is
//! discovered by binding `[::1]:0` — the same family the seeder accepts on
//! — so there is no silent downgrade to `127.0.0.1`.

use std::net::SocketAddr;
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

/// Build a single-file `TorrentFile` describing `data` with correct
/// per-piece SHA-1 hashes. Identical to the helper in `download_e2e.rs`:
/// the `info_hash` is arbitrary-but-consistent — both ends just have to
/// agree on it and on the piece hashes.
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

/// Bind-and-drop on `[::1]:0` to discover a free **IPv6 loopback** TCP
/// port. The v6 mirror of `download_e2e::free_port`. Binding on `::1`
/// (rather than `127.0.0.1:0`) keeps the discovered port in the same
/// address family the dual-stack listener will own, so the seeder is
/// actually reachable there.
async fn free_v6_port() -> u16 {
    let l = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seeder_serves_leecher_over_ipv6_loopback() {
    // ~40 KB → 3 pieces (two full + one short). Distinct bytes so piece
    // verification is meaningful (not all-zero). Same data shape as the
    // v4 e2e so the transfer mechanics are identical and only the address
    // family under test differs.
    let data: Vec<u8> = (0..40_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let name = "e2e_v6.bin";
    let torrent = Arc::new(make_torrent(name, &data));

    let tmp = std::env::temp_dir().join(format!("rt_e2e_v6_{}", std::process::id()));
    let seed_dir = tmp.join("seed");
    let leech_dir = tmp.join("leech");
    tokio::fs::create_dir_all(&seed_dir).await.unwrap();
    tokio::fs::create_dir_all(&leech_dir).await.unwrap();

    // Seeder already has the complete file on disk → its resume scan
    // marks every piece verified, so it starts as a seed.
    tokio::fs::write(seed_dir.join(name), &data).await.unwrap();

    let port = free_v6_port().await;

    // The address the leecher will dial. Assert it is GENUINELY an IPv6
    // loopback socket — this is what makes the test prove v6 dialing and
    // not silently fall back to 127.0.0.1.
    let seed_addr: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    assert!(
        seed_addr.is_ipv6(),
        "seed peer address must be IPv6, got {seed_addr}"
    );
    assert!(
        seed_addr.ip().is_loopback(),
        "seed peer address must be IPv6 loopback (::1), got {seed_addr}"
    );

    // Spawn the seeder; it idles + serves (started complete → never exits).
    // Its inbound listener binds dual-stack on [::], so the ::1 dial below
    // reaches it.
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

    // Leecher: no tracker, dial the seeder directly over ::1. run()
    // returns once every piece is downloaded + written.
    let leech_cfg = EngineConfig {
        output_dir: leech_dir.clone(),
        listen_port: free_v6_port().await,
        no_tracker: true,
        seed_peers: vec![seed_addr],
        ..Default::default()
    };
    let leecher = TorrentEngine::new((*torrent).clone(), [2u8; 20], leech_cfg);

    let result = tokio::time::timeout(Duration::from_secs(30), leecher.run()).await;
    assert!(result.is_ok(), "leecher did not finish within 30s over ::1");
    assert!(result.unwrap().is_ok(), "leecher run() returned an error");

    // The downloaded file must be byte-identical to the seeded data.
    let got = tokio::fs::read(leech_dir.join(name)).await.unwrap();
    assert_eq!(got.len(), data.len(), "downloaded size mismatch");
    assert_eq!(got, data, "downloaded bytes differ from the seed");

    seeder_task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
