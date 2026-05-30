//! End-to-end smoke test for the multi-torrent daemon web layer: add two
//! torrents to a SessionManager, then drive the daemon router over real
//! HTTP — the status array, a per-info_hash pause, and a remove.

use rustytorrent::engine::EngineConfig;
use rustytorrent::metainfo::TorrentFile;
use rustytorrent::session::SessionManager;
use rustytorrent::web::daemon_router;

/// Build a minimal valid single-file torrent whose `name` is `name` and
/// whose first pieces-hash byte is `tag` (so the two torrents get
/// distinct info-hashes).
fn torrent(name: &str, tag: u8) -> TorrentFile {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"d4:infod6:lengthi16384e4:name");
    buf.extend_from_slice(format!("{}:{}", name.len(), name).as_bytes());
    buf.extend_from_slice(b"12:piece lengthi16384e6:pieces20:");
    let mut hash = [0u8; 20];
    hash[0] = tag;
    buf.extend_from_slice(&hash);
    buf.extend_from_slice(b"ee");
    TorrentFile::from_bytes(&buf).unwrap()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[tokio::test]
async fn daemon_hosts_lists_and_controls_torrents() {
    let mgr = SessionManager::new();
    let cfg = || EngineConfig {
        no_tracker: true,
        listen_port: 0, // OS picks a free port per session
        output_dir: std::env::temp_dir(),
        ..Default::default()
    };
    let ih_a = mgr
        .add(torrent("alpha", 0xA1), [1u8; 20], cfg())
        .await
        .unwrap();
    let _ih_b = mgr
        .add(torrent("beta", 0xB2), [1u8; 20], cfg())
        .await
        .unwrap();
    assert_eq!(mgr.len().await, 2);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, daemon_router(mgr.clone())).await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // /api/status is an array of two torrents.
    let list: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/api/status"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let names: Vec<&str> = arr.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"alpha") && names.contains(&"beta"));

    // Pause torrent A by info_hash.
    let resp = client
        .post(format!("{base}/api/torrent/{}/pause", hex(&ih_a)))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // A bogus info_hash is a 404.
    let resp = client
        .post(format!("{base}/api/torrent/{}/pause", "00".repeat(20)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    // Remove torrent A → status array drops to one.
    let resp = client
        .post(format!("{base}/api/torrent/{}/remove", hex(&ih_a)))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let list: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/api/status"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
}
