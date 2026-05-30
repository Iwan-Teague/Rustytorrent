//! End-to-end smoke test for the Phase 8 monitoring server: bind the
//! router on an ephemeral loopback port, then hit each route over real
//! HTTP and check the responses reflect the published stats.

use rustytorrent::engine::EngineControl;
use rustytorrent::web::{router, EngineStats, WebState};
use tokio::sync::{mpsc, watch};

fn sample() -> EngineStats {
    EngineStats {
        name: "demo".into(),
        info_hash: "abc123".into(),
        complete_pieces: 3,
        total_pieces: 10,
        downloaded_bytes: 300,
        uploaded_bytes: 0,
        total_bytes: 1000,
        peers_connected: 4,
        elapsed_secs: 5,
        down_rate_bps: 60,
        up_rate_bps: 10,
        complete: false,
        paused: false,
        remaining_bytes: 700,
        peers: vec!["10.0.0.1:6881".into(), "10.0.0.2:6881".into()],
        files: vec![rustytorrent::web::FileProgress {
            path: "movie.mkv".into(),
            length: 1000,
            fraction: 0.3,
            wanted: true,
        }],
    }
}

#[tokio::test]
async fn serves_status_metrics_and_index() {
    let (tx, rx) = watch::channel(sample());
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<EngineControl>(8);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(WebState { rx, ctl: ctl_tx })).await;
    });

    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // JSON status reflects the published snapshot.
    let body = client
        .get(format!("{base}/api/status"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["complete_pieces"], 3);
    assert_eq!(v["total_pieces"], 10);
    assert_eq!(v["peers_connected"], 4);
    assert_eq!(v["name"], "demo");

    // Peer list endpoint returns the connected addresses.
    let peers: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/api/peers"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(peers.as_array().unwrap().len(), 2);
    assert_eq!(peers[0], "10.0.0.1:6881");

    // Per-file progress endpoint.
    let files: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/api/files"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(files[0]["path"], "movie.mkv");
    assert_eq!(files[0]["wanted"], true);

    // Prometheus endpoint exposes the series with the info_hash label.
    let metrics = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("rustytorrent_complete_pieces{info_hash=\"abc123\"} 3"));
    assert!(metrics.contains("# TYPE rustytorrent_peers_connected gauge"));

    // Index page is HTML.
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let html = resp.text().await.unwrap();
    assert!(ct.contains("text/html"), "content-type was {ct}");
    assert!(html.contains("<title>RustyTorrent</title>"));

    // A live update propagates to subsequent requests.
    let mut updated = sample();
    updated.complete_pieces = 10;
    updated.complete = true;
    tx.send(updated).unwrap();
    let body = client
        .get(format!("{base}/api/status"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["complete_pieces"], 10);
    assert_eq!(v["complete"], true);

    // POST /api/pause forwards a control command into the engine channel.
    let resp = client
        .post(format!("{base}/api/pause"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), ctl_rx.recv())
        .await
        .expect("control command should arrive")
        .expect("channel open");
    assert!(matches!(cmd, EngineControl::Pause));
}
