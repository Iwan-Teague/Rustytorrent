//! End-to-end smoke test for the multi-torrent daemon web layer: add two
//! torrents to a SessionManager, then drive the daemon router over real
//! HTTP — the status array, a per-info_hash pause, and a remove.

use rustytorrent::engine::EngineConfig;
use rustytorrent::metainfo::TorrentFile;
use rustytorrent::session::SessionManager;
use rustytorrent::web::{daemon_router, DaemonState};

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
    let state = DaemonState {
        mgr: mgr.clone(),
        output: std::env::temp_dir(),
        peer_id: [7u8; 20],
        base_port: 0,
        no_dht: true,
        torrent_dir: std::env::temp_dir(),
        magnet_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(
            rustytorrent::web::MAX_CONCURRENT_MAGNET_ADDS,
        )),
    };
    tokio::spawn(async move {
        let _ = axum::serve(listener, daemon_router(state)).await;
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

    // POST /api/add with a path to a .torrent on disk → array grows.
    let mut tpath = std::env::temp_dir();
    tpath.push(format!("rt_daemon_add_{}.torrent", std::process::id()));
    // Reconstruct gamma's bytes and write them out.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"d4:infod6:lengthi16384e4:name5:gamma12:piece lengthi16384e6:pieces20:");
    let mut h = [0u8; 20];
    h[0] = 0xCC;
    buf.extend_from_slice(&h);
    buf.extend_from_slice(b"ee");
    tokio::fs::write(&tpath, &buf).await.unwrap();

    let resp = client
        .post(format!("{base}/api/add"))
        .body(tpath.to_string_lossy().into_owned())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "add failed: {}", resp.status());

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
    assert_eq!(
        list.as_array().unwrap().len(),
        2,
        "added torrent should appear"
    );
    let _ = tokio::fs::remove_file(&tpath).await;

    // POST /api/add_magnet:
    // - a garbage body is a 400 (parse failure)
    let resp = client
        .post(format!("{base}/api/add_magnet"))
        .body("not a magnet")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // - a valid magnet WITHOUT trackers is a 400 (daemon v1 can't
    //   bootstrap peers without DHT)
    let no_tr = format!("magnet:?xt=urn:btih:{}", "ab".repeat(20));
    let resp = client
        .post(format!("{base}/api/add_magnet"))
        .body(no_tr)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // - a valid magnet WITH a tracker is accepted (202) and echoes the
    //   info-hash hex. The background fetch will fail against the dead
    //   tracker, but the synchronous accept is what we assert here.
    let ih_hex = "cd".repeat(20);
    let magnet = format!("magnet:?xt=urn:btih:{ih_hex}&tr=http://127.0.0.1:1/announce&dn=test");
    let resp = client
        .post(format!("{base}/api/add_magnet"))
        .body(magnet)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(resp.text().await.unwrap(), ih_hex);
}

/// The `String` extractors have no default body limit; without the
/// DefaultBodyLimit layer any local process could POST an unbounded
/// body at /api/add_magnet and OOM the daemon. Oversized bodies must be
/// refused with 413 BEFORE the handler runs.
#[tokio::test]
async fn oversized_request_body_is_refused_with_413() {
    let mgr = SessionManager::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = DaemonState {
        mgr,
        output: std::env::temp_dir(),
        peer_id: [7u8; 20],
        base_port: 0,
        no_dht: true,
        torrent_dir: std::env::temp_dir(),
        magnet_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(
            rustytorrent::web::MAX_CONCURRENT_MAGNET_ADDS,
        )),
    };
    tokio::spawn(async move {
        let _ = axum::serve(listener, daemon_router(state)).await;
    });
    let client = reqwest::Client::new();

    let huge = "x".repeat(64 * 1024 + 1);
    let resp = client
        .post(format!("http://{addr}/api/add_magnet"))
        .body(huge)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "unbounded body was buffered instead of refused"
    );

    // A legal-sized (under-cap) garbage magnet still reaches the handler:
    // it must be the LIMIT that rejects, not the layer breaking routing.
    let under = format!(
        "magnet:?xt=urn:btih:{}&tr=http://127.0.0.1:9/a",
        "ef".repeat(20)
    );
    let pad = "y".repeat(16 * 1024); // dn-style padding keeps us well under cap
    let resp = client
        .post(format!("http://{addr}/api/add_magnet"))
        .body(format!("{under}&dn={pad}"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "under-cap request must not trip the body limit"
    );
}

/// The magnet_gate semaphore must actually bound concurrent bootstrap
/// pipelines: MAX_CONCURRENT_MAGNET_ADDS+1 adds pointed at a hanging
/// tracker produce exactly MAX_CONCURRENT_MAGNET_ADDS dials — the extra
/// add queues on the permit instead of stacking another dial chain.
#[tokio::test]
async fn magnet_bootstrap_gate_caps_concurrent_pipelines() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let accepts = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Hanging tracker: count accepted connections and HOLD them open
    // (never respond) so no announce completes and releases a permit
    // mid-test. The task dies with the test runtime.
    let acc = accepts.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            if let Ok((s, _)) = listener.accept().await {
                acc.fetch_add(1, Ordering::SeqCst);
                held.push(s);
            }
        }
    });

    let state = DaemonState {
        mgr: SessionManager::new(),
        output: std::env::temp_dir(),
        peer_id: [7u8; 20],
        base_port: 0,
        no_dht: true,
        torrent_dir: std::env::temp_dir(),
        magnet_gate: Arc::new(tokio::sync::Semaphore::new(
            rustytorrent::web::MAX_CONCURRENT_MAGNET_ADDS,
        )),
    };

    // One distinct magnet per add (different info-hash → no dup-check hit).
    let mk_magnet = |ih_byte: u8| {
        rustytorrent::magnet::MagnetLink::parse(&format!(
            "magnet:?xt=urn:btih:{}&tr=http%3A%2F%2F{}%2Fa",
            [ih_byte; 20]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            addr
        ))
        .unwrap()
    };

    let limit = rustytorrent::web::MAX_CONCURRENT_MAGNET_ADDS;
    for i in 0..limit + 1 {
        let st = state.clone();
        let m = mk_magnet(0xE0 + i as u8);
        tokio::spawn(rustytorrent::web::magnet_bootstrap(st, m));
    }

    // Wait for the gated steady state: exactly `limit` dials up.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let n = accepts.load(Ordering::SeqCst);
        if n >= limit {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "gate starved the pipelines: only {n} dials up"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    // Settle window: the queued (limit+1)th pipeline must NOT dial.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        limit,
        "gate failed to cap concurrent magnet-add pipelines"
    );
}

/// Queue-depth bound: once all gate permits are held, further
/// /api/add_magnet POSTs must be refused with 429 INSTEAD of spawning
/// another parked task (each parked task pins a whole MagnetLink body).
/// Sequential POSTs with an observed-dial wait between them make the
/// permit-holding deterministic — no sleep-and-hope races.
#[tokio::test]
async fn saturated_magnet_gate_returns_429_instead_of_queueing() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let accepts = Arc::new(AtomicUsize::new(0));
    let tracker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taddr = tracker.local_addr().unwrap();
    let acc = accepts.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            if let Ok((s, _)) = tracker.accept().await {
                acc.fetch_add(1, Ordering::SeqCst);
                held.push(s);
            }
        }
    });

    let mgr = SessionManager::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let daddr = listener.local_addr().unwrap();
    let state = DaemonState {
        mgr,
        output: std::env::temp_dir(),
        peer_id: [7u8; 20],
        base_port: 0,
        no_dht: true,
        torrent_dir: std::env::temp_dir(),
        magnet_gate: Arc::new(tokio::sync::Semaphore::new(
            rustytorrent::web::MAX_CONCURRENT_MAGNET_ADDS,
        )),
    };
    tokio::spawn(async move {
        let _ = axum::serve(listener, daemon_router(state)).await;
    });
    let client = reqwest::Client::new();

    let mk_uri = |ih_byte: u8| {
        format!(
            "magnet:?xt=urn:btih:{}&tr=http%3A%2F%2F{taddr}%2Fa",
            [ih_byte; 20]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    };

    // Fill the gate one POST at a time, observing the dial before the
    // next request: each accepted connection proves its permit is held.
    for i in 0..rustytorrent::web::MAX_CONCURRENT_MAGNET_ADDS {
        let resp = client
            .post(format!("http://{daddr}/api/add_magnet"))
            .body(mk_uri(0xF0 + i as u8))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::ACCEPTED,
            "add {i} while gate open must be admitted"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while accepts.load(Ordering::SeqCst) < i + 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "pipeline {i} never dialed"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    // Gate full: this add must be refused without queueing.
    let resp = client
        .post(format!("http://{daddr}/api/add_magnet"))
        .body(mk_uri(0xFE))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "saturated gate must return 429, not spawn a parked pipeline"
    );
}
