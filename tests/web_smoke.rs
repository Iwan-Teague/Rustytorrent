//! End-to-end smoke test for the Phase 8 monitoring server: bind the
//! router on an ephemeral loopback port, then hit each route over real
//! HTTP and check the responses reflect the published stats.

use rustytorrent::web::{router, EngineStats};
use tokio::sync::watch;

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
        complete: false,
    }
}

#[tokio::test]
async fn serves_status_metrics_and_index() {
    let (tx, rx) = watch::channel(sample());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(rx)).await;
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
}
