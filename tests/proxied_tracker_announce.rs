//! The proxied tracker announce must ride ONLY the configured SOCKS5 chain.
//!
//! Two invariants, proven against real sockets:
//!
//! 1. POSITIVE PATH: an announce through a `ProxyConfig` reaches a fake
//!    SOCKS5 server (CONNECT handshake), is relayed to a fake HTTP tracker,
//!    and the bencoded response round-trips back into a parsed
//!    `AnnounceResponse`. Nothing else in the repo proves this happy path
//!    on every platform — the anonymous-engine socket audits are
//!    Linux-only and prove REFUSALS, not successful proxied announces.
//!
//! 2. NO AMBIENT INTERCEPTION: with hostile proxy environment variables
//!    pointing at a LIVE decoy listener we control, neither announce may
//!    touch it. reqwest consults HTTP_PROXY/HTTPS_PROXY/ALL_PROXY by
//!    default; the proxied client must be pinned to its explicit chain.
//!
//! Both phases share one test fn (env vars are process-global; cargo runs
//! test fns concurrently within one binary).
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use rustytorrent::socks5::ProxyConfig;
use rustytorrent::tracker::{announce_with_proxy_anon, AnnounceRequest};

const EVENT_NONE: rustytorrent::tracker::Event = rustytorrent::tracker::Event::None;

fn announce_req() -> AnnounceRequest {
    AnnounceRequest {
        info_hash: [0x42u8; 20],
        peer_id: [0x24u8; 20],
        port: 51413,
        uploaded: 0,
        downloaded: 0,
        left: 1,
        event: EVENT_NONE,
        num_want: 50,
    }
}

/// Minimal bencoded announce success the client's parser accepts.
const TRACKER_BODY: &[u8] = b"d8:completei1e10:incompletei2e8:intervali60e5:peers0:e";

/// Fake HTTP tracker: answers any request line with the bencode body.
async fn spawn_fake_tracker() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            // Drain the request headers (ignore contents), then answer.
            let mut buf = [0u8; 2048];
            let _ = tokio::time::timeout(Duration::from_secs(2), sock.readable()).await;
            let _ = sock.try_read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                TRACKER_BODY.len()
            );
            let mut out = resp.into_bytes();
            out.extend_from_slice(TRACKER_BODY);
            let _ = sock.write_all(&out).await;
            let _ = sock.shutdown().await;
        }
    });
    (port, hits)
}

/// Decoy "system proxy": records connections, never speaks HTTP usefully.
/// If ambient env-proxy interception ever happens, its hit counter moves.
async fn spawn_decoy_proxy() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 512];
            let _ = tokio::time::timeout(Duration::from_secs(1), sock.readable()).await;
            let _ = sock.try_read(&mut buf);
            let _ = sock
                .write_all(b"HTTP/1.1 503 nope\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = sock.shutdown().await;
        }
    });
    (port, hits)
}

/// Fake SOCKS5 server: no-auth greeting, CONNECT to loopback target, then
/// blind byte-pipe between client and target. Returns its port and the
/// number of CONNECT requests it served.
async fn spawn_fake_socks() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connects = Arc::new(AtomicUsize::new(0));
    let connects_clone = connects.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let connects_inner = connects_clone.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Greeting: VER NMETHODS METHODS...
                let mut head = [0u8; 2];
                if client.read_exact(&mut head).await.is_err() || head[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if client.write_all(&[0x05, 0x00]).await.is_err() {
                    return; // no-auth chosen
                }
                // Request: VER CMD RSV ATYP ...
                let mut req_head = [0u8; 4];
                if client.read_exact(&mut req_head).await.is_err() || req_head[1] != 0x01 {
                    return;
                }
                let target = match req_head[3] {
                    0x01 => {
                        let mut a = [0u8; 4];
                        if client.read_exact(&mut a).await.is_err() {
                            return;
                        }
                        let mut p = [0u8; 2];
                        if client.read_exact(&mut p).await.is_err() {
                            return;
                        }
                        format!("{}:{}", std::net::Ipv4Addr::from(a), u16::from_be_bytes(p))
                    }
                    0x03 => {
                        let mut l = [0u8; 1];
                        if client.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        let mut host = vec![0u8; l[0] as usize];
                        if client.read_exact(&mut host).await.is_err() {
                            return;
                        }
                        let mut p = [0u8; 2];
                        if client.read_exact(&mut p).await.is_err() {
                            return;
                        }
                        format!(
                            "{}:{}",
                            String::from_utf8_lossy(&host),
                            u16::from_be_bytes(p)
                        )
                    }
                    _ => return,
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(&target).await else {
                    let _ = client
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                connects_inner.fetch_add(1, Ordering::SeqCst);
                let _ = client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (port, connects)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxied_announce_rides_socks_chain_and_ignores_ambient_proxy_env() {
    // Hostile ambient configuration: a LIVE decoy that would corrupt or
    // observe any intercepted announce, set BEFORE either client is built
    // (reqwest captures system proxies at build time).
    let (decoy_port, decoy_hits) = spawn_decoy_proxy().await;
    std::env::set_var("HTTP_PROXY", format!("http://127.0.0.1:{decoy_port}"));
    std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{decoy_port}"));
    std::env::set_var("ALL_PROXY", format!("socks5://127.0.0.1:{decoy_port}"));

    let (tracker_port, tracker_hits) = spawn_fake_tracker().await;
    let (socks_port, socks_connects) = spawn_fake_socks().await;

    let url = format!("http://127.0.0.1:{tracker_port}/announce");
    let proxy = ProxyConfig {
        addr: format!("127.0.0.1:{socks_port}").parse().unwrap(),
        credentials: None,
        isolation: false,
    };

    let resp = announce_with_proxy_anon(&url, &announce_req(), Some(&proxy), false, None)
        .await
        .expect("proxied announce must succeed through the SOCKS chain");

    assert_eq!(resp.interval, Duration::from_secs(60));
    assert_eq!(resp.seeders, Some(1));
    assert_eq!(resp.leechers, Some(2));

    // The chain actually carried it...
    assert_eq!(
        socks_connects.load(Ordering::SeqCst),
        1,
        "SOCKS5 server must have relayed exactly one CONNECT"
    );
    assert_eq!(
        tracker_hits.load(Ordering::SeqCst),
        1,
        "fake tracker must have answered exactly one announce"
    );
    // ...and the ambient decoy saw NOTHING.
    assert_eq!(
        decoy_hits.load(Ordering::SeqCst),
        0,
        "ambient env proxy must never intercept an explicit-chain announce"
    );
}
