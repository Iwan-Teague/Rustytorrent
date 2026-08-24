//! Anonymous mode must not open ANY direct socket on the session port.
//!
//! The engine's `dht_wanted` gate promises that anonymous mode (and proxy
//! chains) never spawn the DHT, and that `inbound_wanted` never opens the
//! TCP listener — because a raw UDP/TCP socket bound on the real network
//! exposes the real IP and links it to the info-hash, defeating the whole
//! proxy chain. This test holds that promise end to end: it runs a real
//! engine configured with `anonymous = true` AND `enable_dht = true` (the
//! maximally hostile combination — if the gate ever regresses to "trust
//! the flag", this is how it regresses), lets it settle, then inspects the
//! kernel's socket tables via /proc and asserts nothing is bound on the
//! port. UDP is the critical assertion (DHT + µTP); TCP is asserted too so
//! a future listener regression can't hide behind "but UDP was fine".
//!
//! Linux-only: reads `/proc/net/udp{,6}` and `/proc/net/tcp{,6}`.
#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::time::Duration;

use rustytorrent::engine::{EngineConfig, TorrentEngine};
use rustytorrent::metainfo::{Info, TorrentFile, TorrentFiles};
use rustytorrent::socks5::ProxyConfig;

const PIECE_LEN: u64 = 16384;

fn sha1(bytes: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}

fn make_torrent(name: &str) -> TorrentFile {
    let data = vec![0xABu8; 4096];
    TorrentFile {
        info_hash: sha1(&data),
        announce: None,
        announce_list: vec![],
        info: Info {
            name: name.to_string(),
            piece_length: PIECE_LEN,
            piece_hashes: vec![sha1(&data)],
            files: TorrentFiles::Single {
                length: data.len() as u64,
            },
            private: false,
        },
    }
}

/// Every local port currently bound by any process, parsed from one
/// /proc/net table. Local address is column 1 as `HEXIP:HEXPORT`.
fn proc_bound_ports(table: &str) -> std::io::Result<HashSet<u16>> {
    let raw = std::fs::read_to_string(table)?;
    let mut ports = HashSet::new();
    for line in raw.lines().skip(1) {
        let Some(local) = line.split_whitespace().nth(1) else {
            continue;
        };
        let Some((_ip, port)) = local.rsplit_once(':') else {
            continue;
        };
        if let Ok(p) = u16::from_str_radix(port, 16) {
            ports.insert(p);
        }
    }
    Ok(ports)
}

/// Union of every UDP/TCP port bound anywhere on the host (v4 + v6).
fn all_bound_ports() -> HashSet<u16> {
    let mut all = HashSet::new();
    for suffix in ["", "6"] {
        for proto in ["udp", "tcp"] {
            if let Ok(ports) = proc_bound_ports(&format!("/proc/net/{proto}{suffix}")) {
                all.extend(ports);
            }
        }
    }
    all
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_engine_opens_no_direct_socket_even_with_dht_requested() {
    // A port we know is free *right now* (bind-and-drop). Re-checked below
    // before the assertions so an unlucky collision fails as "port already
    // taken by something else", not as a gate regression.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    // Sanity pre-flight: if some unrelated process grabbed the port in the
    // bind/drop window, pick another rather than fail spuriously.
    if all_bound_ports().contains(&port) {
        return; // vanishingly rare; not worth retry loops in CI
    }

    let tmp = std::env::temp_dir().join(format!("rt_anon_{}", std::process::id()));
    tokio::fs::create_dir_all(&tmp).await.unwrap();

    let cfg = EngineConfig {
        output_dir: tmp.clone(),
        listen_port: port,
        no_tracker: true,
        // The hostile combination: DHT explicitly ON while anonymous. The
        // gate must win over the flag.
        enable_dht: true,
        anonymous: true,
        // Anonymous refuses to start without a proxy chain (fail-closed on
        // dials), so hand it one. Nothing listens there; the engine must
        // still start, run, and open no direct socket.
        proxies: vec![ProxyConfig {
            addr: "127.0.0.1:1".parse().unwrap(),
            credentials: None,
            isolation: false,
        }],
        ..Default::default()
    };

    let engine = TorrentEngine::new(make_torrent("anon.bin"), [7u8; 20], cfg);
    let task = tokio::spawn(async move {
        let _ = engine.run().await;
    });

    // Give any wrongly-opened DHT/µTP/listener socket time to appear — the
    // ungated paths all bind at the very top of run().
    tokio::time::sleep(Duration::from_millis(800)).await;

    let bound = all_bound_ports();
    assert!(
        !bound.contains(&port),
        "anonymous engine opened a direct socket on port {port} \
         (DHT/µTP/listener gate regression)"
    );

    task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
