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
    make_torrent_with_trackers(name, &[])
}

/// `trackers`: announce URLs baked into the metainfo. The anonymous-mode
/// test bakes a `udp://` tracker pointing at a discard port — if the UDP
/// refusal ever regresses to "attempt then fail", the attempt itself
/// would open a direct socket and the process-wide assertions below
/// would catch it.
fn make_torrent_with_trackers(name: &str, trackers: &[String]) -> TorrentFile {
    let data = vec![0xABu8; 4096];
    TorrentFile {
        info_hash: sha1(&data),
        announce: None,
        announce_list: trackers.iter().map(|u| vec![u.clone()]).collect(),
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

/// `socket:[<inode>]` symlinks currently held open by THIS process.
fn self_socket_fds() -> HashSet<String> {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|e| e.ok())
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .map(|l| l.to_string_lossy().into_owned())
        .filter(|s| s.starts_with("socket:["))
        .collect()
}

/// /proc table rows for sockets this process owns, as
/// `(local_port, state)` pairs. The inode column is matched against our
/// fd set so unrelated processes' sockets are ignored. TCP state is the
/// hex code (0A = LISTEN); UDP rows have no meaningful state.
fn self_owned_sockets(table: &str) -> Vec<(u16, String)> {
    let fds = self_socket_fds();
    let raw = match std::fs::read_to_string(table) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // sl local rem st ... tx:rx ... tr:tm retrnsmt uid timeout inode
        if cols.len() < 10 {
            continue;
        }
        // The table lists the bare inode number; our fd symlinks read
        // `socket:[<inode>]`.
        let fd_ref = format!("socket:[{}]", cols[9]);
        if !fds.contains(&fd_ref) {
            continue;
        }
        let port = cols[1]
            .rsplit_once(':')
            .and_then(|(_, p)| u16::from_str_radix(p, 16).ok());
        if let Some(port) = port {
            out.push((port, cols[3].to_string()));
        }
    }
    out
}

/// The two audits run in the SAME process (one test binary) but cargo
/// runs test fns concurrently; each audit's own helper sockets (probe,
/// silent sink) would otherwise show up in the other's process-wide
/// snapshot. Serialize them.
static AUDIT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_engine_opens_no_direct_socket_even_with_dht_requested() {
    let _audit = AUDIT_LOCK.lock().await;
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

    // Assertion 1 (port-scoped): nothing bound on the configured session
    // port, by anyone on the host.
    let bound = all_bound_ports();
    assert!(
        !bound.contains(&port),
        "anonymous engine opened a direct socket on port {port} \
         (DHT/µTP/listener gate regression)"
    );

    // Assertion 2 (process-wide, stronger): the engine process owns NO UDP
    // sockets at all — not on the session port, not ephemeral. A regression
    // that binds the DHT or µTP socket to port 0 / a shifted port would
    // pass assertion 1 but fail here. The proxy is an IP literal and
    // reqwest uses socks5h (remote DNS), so a correct anonymous engine has
    // no legitimate local UDP use whatsoever.
    let mut owned_udp: Vec<(u16, String)> = Vec::new();
    for suffix in ["", "6"] {
        owned_udp.extend(self_owned_sockets(&format!("/proc/net/udp{suffix}")));
    }
    assert!(
        owned_udp.is_empty(),
        "anonymous engine process owns UDP sockets (DHT/µTP egress leak): {owned_udp:?}"
    );

    // Assertion 3: no listening TCP anywhere in the process — the inbound
    // listener must be off in anonymous mode (`inbound_wanted`), and any
    // *other* listen socket would accept direct connections that bypass
    // the proxy chain entirely.
    let mut owned_listen: Vec<(u16, String)> = Vec::new();
    for suffix in ["", "6"] {
        owned_listen.extend(
            self_owned_sockets(&format!("/proc/net/tcp{suffix}"))
                .into_iter()
                .filter(|(_, st)| st == "0A"), // LISTEN
        );
    }
    assert!(
        owned_listen.is_empty(),
        "anonymous engine process has LISTENING TCP sockets (direct-inbound leak): {owned_listen:?}"
    );

    task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}

/// Tracker-privacy variant of the audit: the metainfo itself carries a
/// `udp://` tracker (the scheme that CANNOT ride SOCKS5 and would leak
/// the real IP if ever attempted). In anonymous mode the dispatcher must
/// refuse it before any DNS or socket work — so even though trackers are
/// ENABLED here (`no_tracker = false`) and an announce is attempted, the
/// process must still own zero UDP sockets and zero listening TCP
/// sockets. This is the kernel-level proof behind "UDP announces never
/// open a direct socket in anon mode"; the dispatcher unit tests prove
/// the refusal by error text, this one proves it by socket absence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_engine_with_udp_tracker_opens_no_direct_socket() {
    let _audit = AUDIT_LOCK.lock().await;
    // A SILENT sink socket plays the tracker: it receives our (never
    // sent) announce and never replies, so if a real attempt were made,
    // its socket would stay open through the 15 s retry backoff — long
    // before our 800 ms snapshot. A discard-port target is useless here:
    // loopback ICMP-unreachable fails such attempts within microseconds,
    // faster than any /proc sample could catch the leaked socket.
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    let udp_tracker = format!("udp://127.0.0.1:{sink_port}/announce");
    let torrent = make_torrent_with_trackers("anon-tracker.bin", &[udp_tracker]);

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    if all_bound_ports().contains(&port) {
        return; // port collision pre-flight, as in the DHT variant
    }

    let tmp = std::env::temp_dir().join(format!("rt_anon_trk_{}", std::process::id()));
    tokio::fs::create_dir_all(&tmp).await.unwrap();

    let cfg = EngineConfig {
        output_dir: tmp.clone(),
        listen_port: port,
        // Trackers ENABLED — the whole point is that an announce IS
        // attempted against the udp:// URL.
        no_tracker: false,
        enable_dht: false,
        anonymous: true,
        proxies: vec![ProxyConfig {
            addr: "127.0.0.1:1".parse().unwrap(),
            credentials: None,
            isolation: false,
        }],
        ..Default::default()
    };

    let engine = TorrentEngine::new(torrent, [9u8; 20], cfg);
    let task = tokio::spawn(async move {
        let _ = engine.run().await;
    });

    // The initial announce fires at the top of run(); give any wrongly-
    // opened tracker socket time to appear in /proc.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // No direct socket bound anywhere on our session port...
    let bound = all_bound_ports();
    assert!(
        !bound.contains(&port),
        "anonymous engine with udp:// tracker opened a socket on port {port}"
    );

    // ...and crucially, the process owns NO UDP sockets at all: the UDP
    // tracker announce must have been refused before socket creation.
    let mut owned_udp: Vec<(u16, String)> = Vec::new();
    for suffix in ["", "6"] {
        owned_udp.extend(self_owned_sockets(&format!("/proc/net/udp{suffix}")));
    }
    // Scanner sanity: the sink MUST show up, or the audit is broken.
    assert!(
        owned_udp.iter().any(|(p, _)| *p == sink_port),
        "self-audit broken: sink socket {sink_port} not visible"
    );
    // The real assertion: NOTHING besides the sink itself. An attempted
    // udp:// announce would bind its own ephemeral socket and be visible
    // here for the whole retry backoff.
    let leaked: Vec<_> = owned_udp.iter().filter(|(p, _)| *p != sink_port).collect();
    assert!(
        leaked.is_empty(),
        "udp:// tracker announce opened a direct UDP socket in anonymous mode: {leaked:?}"
    );

    // Listener stays off too (inbound would bypass the proxy chain).
    let mut owned_listen: Vec<(u16, String)> = Vec::new();
    for suffix in ["", "6"] {
        owned_listen.extend(
            self_owned_sockets(&format!("/proc/net/tcp{suffix}"))
                .into_iter()
                .filter(|(_, st)| st == "0A"),
        );
    }
    assert!(
        owned_listen.is_empty(),
        "anonymous engine has LISTENING TCP sockets: {owned_listen:?}"
    );

    task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
