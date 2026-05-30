use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use rustytorrent::metainfo::TorrentFile;
use rustytorrent::tracker;

#[derive(Parser)]
#[command(name = "rustytorrent", about = "A BitTorrent client built in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show info about a .torrent file
    Info { file: PathBuf },
    /// List peers from a .torrent file's trackers
    Peers {
        file: PathBuf,
        #[arg(long, default_value_t = 6881)]
        port: u16,
        #[arg(long, default_value_t = 50)]
        numwant: i32,
    },
    /// Download a torrent
    Download {
        file: PathBuf,
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        #[arg(long, default_value_t = 6881)]
        port: u16,
        /// Skip the tracker and dial these peers directly (host:port). Useful for local tests.
        #[arg(long)]
        peer: Vec<String>,
        /// Don't query the tracker. Implies --peer is the entire swarm.
        #[arg(long, default_value_t = false)]
        no_tracker: bool,
        /// Skip the plain-BitTorrent attempt and dial every peer via MSE/PE directly.
        /// Useful for testing the encrypted path against MSE-only peers.
        #[arg(long, default_value_t = false)]
        encrypt: bool,
        /// Enable the BEP 5 DHT for trackerless peer discovery.
        #[arg(long, default_value_t = false)]
        dht: bool,
        /// SOCKS5 proxy address (host:port). Repeat to build a chain
        /// `client → proxy1 → proxy2 → … → target` for multi-hop
        /// anonymity (C1) — each hop runs nested SOCKS5 CONNECTs on a
        /// single TCP stream. Use `127.0.0.1:9050` for Tor's local
        /// SOCKS port, or your VPN's loopback SOCKS endpoint. First
        /// `--socks5` is closest to us; last is closest to the
        /// destination.
        #[arg(long)]
        socks5: Vec<String>,
        /// Optional SOCKS5 username. Applied to the LAST hop only
        /// (typically the Tor / VPN endpoint that actually validates
        /// auth). Paired with --socks5-pass for RFC 1929 auth.
        #[arg(long, requires = "socks5")]
        socks5_user: Option<String>,
        /// Optional SOCKS5 password. Required if --socks5-user is set.
        #[arg(long, requires = "socks5_user")]
        socks5_pass: Option<String>,
        /// "Anonymous mode" bundle. Requires --socks5. Disables the inbound
        /// TCP listener and the DHT (both leak the real IP), randomizes the
        /// peer_id (no on-disk persistence), and zeroes the port in tracker
        /// announces. With --socks5 alone you get IP-masking; with
        /// --anonymous you also close the side-channels that would
        /// otherwise undo it.
        #[arg(long, default_value_t = false, requires = "socks5")]
        anonymous: bool,
        /// Bind every outgoing socket to this network interface (VPN kill
        /// switch). If the interface goes away — VPN tunnel drops, Wi-Fi
        /// reconnects — outbound dials fail closed instead of leaking via
        /// the default route. Interface name on Unix (e.g. `utun0`,
        /// `tun0`, `en0`), numeric interface index on Windows.
        #[arg(long)]
        bind_iface: Option<String>,
        /// Tor stream isolation: every outgoing peer dial uses a randomly
        /// generated SOCKS5 username so Tor routes it over its own circuit,
        /// defeating correlation by a single exit node. Requires --socks5.
        /// Harmless on non-Tor SOCKS5 proxies that ignore credentials;
        /// avoid on commercial VPNs that require real auth.
        #[arg(long, default_value_t = false, requires = "socks5")]
        tor_isolation: bool,
        /// Paranoid storage: write every piece into an AES-256-GCM encrypted
        /// spool file under a passphrase-derived key. Plaintext never
        /// touches disk during the session. Run `rustytorrent decrypt`
        /// afterwards with the same passphrase to extract.
        #[arg(long, default_value_t = false)]
        paranoid: bool,
        /// Memory-only storage: keep every piece in RAM, never write to
        /// disk. Strongest "leave no trace" posture; pairs well with
        /// --anonymous. Mutually exclusive with --paranoid. Unsupported
        /// on Windows.
        #[arg(long, default_value_t = false, conflicts_with = "paranoid")]
        memory_only: bool,
        /// Defense-in-depth: install an OS sandbox just before
        /// entering the download loop. Linux x86_64 → seccomp BPF
        /// whitelist; macOS → `sandbox_init` SBPL deny-default
        /// profile. Either way an exploit in our address space
        /// can't reach `ptrace`, `mount`, `process-exec`, kernel
        /// module load, etc. Windows refused at startup.
        #[arg(long, default_value_t = false)]
        sandbox: bool,
        /// Passphrase for paranoid mode. Required when --paranoid is set.
        /// Prefer the `RUSTYTORRENT_PASSPHRASE` environment variable:
        /// passing it here exposes it in the process list and shell
        /// history.
        #[arg(long)]
        passphrase: Option<String>,
        /// Override the spool file path. Defaults to
        /// `<output>/<torrent-name>.rustytorrent-spool`.
        #[arg(long)]
        spool: Option<PathBuf>,
        /// Cap download rate at this many KiB/s, engine-wide across
        /// all peers. Unset = unthrottled. Gated at Request issuance.
        #[arg(long)]
        max_down: Option<u64>,
        /// Cap upload rate at this many KiB/s. Unset = unthrottled.
        /// Gated at `serve_request`; over-quota peer requests are
        /// silently dropped (peer re-requests later).
        #[arg(long)]
        max_up: Option<u64>,
        /// Enable µTP (BEP 29): bind a UDP socket on the listen port,
        /// accept inbound µTP peers, and race TCP+µTP on every dial.
        /// Auto-disabled under --anonymous / --socks5 / --bind-iface
        /// (UDP can't ride SOCKS5 and isn't interface-bound here).
        #[arg(long, default_value_t = false)]
        utp: bool,
        /// Serve a read-only web monitoring UI (status page + JSON +
        /// Prometheus /metrics) on 127.0.0.1:PORT. Loopback only.
        #[arg(long, value_name = "PORT")]
        web: Option<u16>,
        /// Selective download: only fetch files whose path contains this
        /// substring (repeatable). Multi-file torrents only; omit to get
        /// everything.
        #[arg(long = "select", value_name = "SUBSTR")]
        select: Vec<String>,
        /// Sequential download: fetch pieces in order (for streaming a
        /// media file while it downloads) instead of rarest-first.
        #[arg(long, default_value_t = false)]
        sequential: bool,
    },
    /// Download from a magnet URI (BEP 9 + BEP 10 + BEP 53). Bootstraps a
    /// peer pool via DHT and the magnet's own trackers, fetches the info
    /// dict via ut_metadata, hash-verifies against the magnet's
    /// info_hash, then runs the regular download engine.
    Magnet {
        /// `magnet:?xt=urn:btih:…&tr=…` URI.
        uri: String,
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        #[arg(long, default_value_t = 6881)]
        port: u16,
        /// Extra peer to dial directly (host:port). Useful when the
        /// magnet's trackers are dead and DHT is slow to find peers.
        #[arg(long)]
        peer: Vec<String>,
        /// Force MSE/PE on outgoing dials after the metadata is fetched.
        /// The bootstrap itself currently only attempts plain.
        #[arg(long, default_value_t = false)]
        encrypt: bool,
        /// Enable DHT. Defaults to ON for magnets — without trackers in
        /// the URI and no DHT, there are no peers to bootstrap from.
        #[arg(long, default_value_t = true)]
        dht: bool,
        #[arg(long)]
        socks5: Vec<String>,
        #[arg(long, requires = "socks5")]
        socks5_user: Option<String>,
        #[arg(long, requires = "socks5_user")]
        socks5_pass: Option<String>,
        /// Anonymous bundle. Requires --socks5. Magnet bootstrap then
        /// relies on the magnet's `tr=` trackers (DHT is off in
        /// anonymous mode); if there are none, bootstrap fails.
        #[arg(long, default_value_t = false, requires = "socks5")]
        anonymous: bool,
        #[arg(long)]
        bind_iface: Option<String>,
        #[arg(long, default_value_t = false, requires = "socks5")]
        tor_isolation: bool,
        #[arg(long, default_value_t = false)]
        paranoid: bool,
        /// Memory-only storage. Same semantics as `download --memory-only`.
        #[arg(long, default_value_t = false, conflicts_with = "paranoid")]
        memory_only: bool,
        /// seccomp sandbox. Same semantics as `download --sandbox`.
        #[arg(long, default_value_t = false)]
        sandbox: bool,
        /// Passphrase for paranoid mode. Prefer `RUSTYTORRENT_PASSPHRASE`
        /// — passing it here exposes it in the process list and shell
        /// history.
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        spool: Option<PathBuf>,
        /// Cap download rate, KiB/s. Same semantics as `download`.
        #[arg(long)]
        max_down: Option<u64>,
        /// Cap upload rate, KiB/s.
        #[arg(long)]
        max_up: Option<u64>,
        /// Enable µTP (BEP 29). Same semantics as `download --utp`.
        #[arg(long, default_value_t = false)]
        utp: bool,
        /// Serve a read-only web monitoring UI on 127.0.0.1:PORT.
        #[arg(long, value_name = "PORT")]
        web: Option<u16>,
        /// Selective download: only fetch files whose path contains this
        /// substring (repeatable). Applies once magnet metadata arrives.
        #[arg(long = "select", value_name = "SUBSTR")]
        select: Vec<String>,
        /// Sequential download (in-order pieces for streaming).
        #[arg(long, default_value_t = false)]
        sequential: bool,
    },
    /// Decrypt a `--paranoid` spool into the real file layout using the
    /// same passphrase that produced it. Pieces that don't hash-match
    /// (e.g. half-written or under a different key) are skipped.
    Decrypt {
        /// The `.torrent` that the spool was produced from. Provides
        /// piece hashes, piece length, and the file layout to write into.
        file: PathBuf,
        /// Destination directory for the decrypted files (created if
        /// missing).
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Path to the encrypted spool. Defaults to
        /// `<output>/<torrent-name>.rustytorrent-spool`.
        #[arg(long)]
        spool: Option<PathBuf>,
        /// Passphrase. Prefer `RUSTYTORRENT_PASSPHRASE` — passing it here
        /// exposes it in the process list and shell history.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Run as a multi-torrent daemon: host several torrents behind one
    /// loopback web UI (status array + per-torrent pause/resume/remove).
    /// First cut — tracker-only (DHT off) and one listen port per torrent;
    /// see docs/DAEMON.md.
    Daemon {
        /// `.torrent` files to load at startup.
        torrents: Vec<PathBuf>,
        /// Destination directory for all torrents.
        #[arg(long, default_value = ".")]
        output: PathBuf,
        /// Web UI port (bound to 127.0.0.1).
        #[arg(long, default_value_t = 8080)]
        web: u16,
        /// Base listen port; torrent `i` uses `base + i`.
        #[arg(long, default_value_t = 6881)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Info { file } => cmd_info(file).await,
        Commands::Peers {
            file,
            port,
            numwant,
        } => cmd_peers(file, port, numwant).await,
        Commands::Download {
            file,
            output,
            port,
            peer,
            no_tracker,
            encrypt,
            dht,
            socks5,
            socks5_user,
            socks5_pass,
            anonymous,
            bind_iface,
            tor_isolation,
            paranoid,
            memory_only,
            sandbox,
            passphrase,
            spool,
            max_down,
            max_up,
            utp,
            web,
            select,
            sequential,
        } => {
            cmd_download(
                file,
                output,
                port,
                peer,
                no_tracker,
                encrypt,
                dht,
                socks5,
                socks5_user,
                socks5_pass,
                anonymous,
                bind_iface,
                tor_isolation,
                paranoid,
                memory_only,
                sandbox,
                passphrase,
                spool,
                max_down,
                max_up,
                utp,
                web,
                select,
                sequential,
            )
            .await
        }
        Commands::Decrypt {
            file,
            output,
            spool,
            passphrase,
        } => cmd_decrypt(file, output, spool, passphrase).await,
        Commands::Daemon {
            torrents,
            output,
            web,
            port,
        } => cmd_daemon(torrents, output, web, port).await,
        Commands::Magnet {
            uri,
            output,
            port,
            peer,
            encrypt,
            dht,
            socks5,
            socks5_user,
            socks5_pass,
            anonymous,
            bind_iface,
            tor_isolation,
            paranoid,
            memory_only,
            sandbox,
            passphrase,
            spool,
            max_down,
            max_up,
            utp,
            web,
            select,
            sequential,
        } => {
            cmd_magnet(
                uri,
                output,
                port,
                peer,
                encrypt,
                dht,
                socks5,
                socks5_user,
                socks5_pass,
                anonymous,
                bind_iface,
                tor_isolation,
                paranoid,
                memory_only,
                sandbox,
                passphrase,
                spool,
                max_down,
                max_up,
                utp,
                web,
                select,
                sequential,
            )
            .await
        }
    }
}

fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0usize;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.2} {}", UNITS[unit])
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

async fn cmd_info(path: PathBuf) -> Result<()> {
    let raw = tokio::fs::read(&path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    let t = TorrentFile::from_bytes(&raw)?;
    println!("Name:         {}", t.info.name);
    println!("Info hash:    {}", hex(&t.info_hash));
    println!(
        "Piece length: {} ({})",
        t.info.piece_length,
        format_size(t.info.piece_length)
    );
    println!("Pieces:       {}", t.num_pieces());
    println!(
        "Total size:   {} ({})",
        t.total_length(),
        format_size(t.total_length())
    );
    match &t.info.files {
        rustytorrent::metainfo::TorrentFiles::Single { length } => {
            println!("Files:        1 ({})", format_size(*length));
        }
        rustytorrent::metainfo::TorrentFiles::Multi { files } => {
            println!("Files:        {}", files.len());
            for f in files {
                println!("  {:>10}  {}", format_size(f.length), f.path.display());
            }
        }
    }
    println!("Private:      {}", t.info.private);
    let trackers = t.trackers();
    println!("Trackers:     {}", trackers.len());
    for tr in &trackers {
        println!("  {tr}");
    }
    Ok(())
}

async fn cmd_peers(path: PathBuf, port: u16, numwant: i32) -> Result<()> {
    let raw = tokio::fs::read(&path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    let t = TorrentFile::from_bytes(&raw)?;
    let peer_id = rustytorrent::peer_id::load_or_generate(&rustytorrent::peer_id::default_path());
    let req = tracker::AnnounceRequest {
        info_hash: t.info_hash,
        peer_id,
        port,
        uploaded: 0,
        downloaded: 0,
        left: t.total_length(),
        event: tracker::Event::Started,
        num_want: numwant,
    };
    let (used, resp) =
        tracker::announce_with_fallback(&t.announce_list, t.announce.as_deref(), &req, None)
            .await?;
    println!("Tracker:  {used}");
    println!("Interval: {}s", resp.interval.as_secs());
    if let Some(s) = resp.seeders {
        println!("Seeders:  {s}");
    }
    if let Some(l) = resp.leechers {
        println!("Leechers: {l}");
    }
    println!("Found {} peers:", resp.peers.len());
    for p in &resp.peers {
        println!("  {p}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // CLI flag plumbing — each arg is one user-facing knob
async fn cmd_download(
    path: PathBuf,
    output: PathBuf,
    port: u16,
    extra_peers: Vec<String>,
    no_tracker: bool,
    encrypt: bool,
    dht: bool,
    socks5: Vec<String>,
    socks5_user: Option<String>,
    socks5_pass: Option<String>,
    anonymous: bool,
    bind_iface: Option<String>,
    tor_isolation: bool,
    paranoid: bool,
    memory_only: bool,
    sandbox: bool,
    passphrase: Option<String>,
    spool: Option<PathBuf>,
    max_down: Option<u64>,
    max_up: Option<u64>,
    utp: bool,
    web: Option<u16>,
    select: Vec<String>,
    sequential: bool,
) -> Result<()> {
    let raw = tokio::fs::read(&path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    let t = TorrentFile::from_bytes(&raw)?;
    println!(
        "Downloading {} ({})",
        t.info.name,
        format_size(t.total_length())
    );
    println!("Info hash:  {}", hex(&t.info_hash));
    println!("Output dir: {}", output.display());

    let mut parsed_peers = Vec::new();
    for s in &extra_peers {
        let addr: std::net::SocketAddr = s
            .parse()
            .with_context(|| format!("invalid peer address: {s}"))?;
        parsed_peers.push(addr);
    }

    // Resolve the SOCKS5 chain. Each --socks5 becomes one hop; the first
    // is closest to us, the last is closest to the destination. We
    // resolve the hosts once at startup so we don't emit DNS queries on
    // the clearnet for every dial.
    let proxies = resolve_proxy_chain(socks5, socks5_user, socks5_pass, tor_isolation).await?;

    // Anonymous mode insists on a fresh, non-persisted peer_id every run —
    // a stable id across sessions would let observers correlate. The
    // libtorrent-style prefix masks the rustytorrent identity that the
    // default `-RT0100-` prefix would otherwise leak in every announce
    // and handshake.
    let peer_id = if anonymous {
        rustytorrent::peer_id::generate_libtorrent_lookalike()
    } else {
        rustytorrent::peer_id::load_or_generate(&rustytorrent::peer_id::default_path())
    };

    if anonymous {
        println!("Anonymous:  on (DHT off, listener off, peer_id ephemeral, port=0 in announces)");
    }

    if let Some(iface) = &bind_iface {
        println!("Bound to:   {iface} (VPN kill switch)");
        println!("            note: peer dials and the DHT socket are bound to {iface},");
        println!("            but tracker HTTP (reqwest) can't be interface-bound — pair");
        println!("            with --socks5 for a tracker that also rides the tunnel.");
    }

    let resolved_passphrase = if paranoid {
        Some(resolve_passphrase(passphrase)?)
    } else {
        None
    };
    if paranoid {
        println!("Paranoid:   on (encrypted spool, plaintext never written)");
    }
    if memory_only {
        println!("Memory:     on (RAM-only spool, nothing persisted)");
    }
    if sandbox {
        println!("Sandbox:    on (OS-level whitelist installed before download loop)");
    }

    if let Some(d) = max_down {
        println!("Max down:   {d} KiB/s");
    }
    if let Some(u) = max_up {
        println!("Max up:     {u} KiB/s");
    }

    let cfg = rustytorrent::engine::EngineConfig {
        output_dir: output,
        listen_port: port,
        seed_peers: parsed_peers,
        no_tracker,
        force_outgoing_mse: encrypt,
        enable_dht: dht,
        proxies,
        anonymous,
        bind_iface,
        paranoid,
        memory_only,
        sandbox,
        passphrase: resolved_passphrase,
        spool_path: spool,
        max_down_bytes_per_sec: max_down.map(|k| k * 1024),
        max_up_bytes_per_sec: max_up.map(|k| k * 1024),
        utp_enabled: utp,
        web_port: web,
        selected_files: select,
        sequential,
        ..Default::default()
    };
    if let Some(p) = web {
        println!("Web UI:     http://127.0.0.1:{p}/ (loopback only)");
    }
    let engine = rustytorrent::engine::TorrentEngine::new(t, peer_id, cfg);

    // The engine handles ctrl-c internally and performs an orderly shutdown
    // (tracker stopped event, storage flush, DHT routing-table save).
    engine.run().await?;
    println!("Done.");
    Ok(())
}

/// Resolve the paranoid-mode passphrase from CLI flag → env var → error.
/// We never log it; just pass it to the engine to derive the spool key.
///
/// Order is deliberate: the `--passphrase` flag wins for scripting, but
/// it is the *least* private source — a CLI argument is visible to every
/// other process on the machine via the process table
/// (`ps auxww` / `/proc/<pid>/cmdline`) and is typically saved to shell
/// history. For a feature whose whole point is the seized-laptop /
/// hostile-local-observer threat model, that's a real leak, so we warn
/// loudly and point at the env var. `RUSTYTORRENT_PASSPHRASE` is not
/// perfect either (readable via `/proc/<pid>/environ` by the same user
/// or root) but it stays out of the process argument list and shell
/// history, which is the common-case exposure.
fn resolve_passphrase(flag: Option<String>) -> Result<String> {
    if let Some(p) = flag {
        eprintln!(
            "warning: passing the passphrase via --passphrase exposes it in the process \
             list (ps/proc) and shell history. Prefer the RUSTYTORRENT_PASSPHRASE \
             environment variable."
        );
        return Ok(p);
    }
    if let Ok(p) = std::env::var("RUSTYTORRENT_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    anyhow::bail!("--paranoid requires --passphrase or RUSTYTORRENT_PASSPHRASE (non-empty)")
}

async fn cmd_daemon(
    torrents: Vec<PathBuf>,
    output: PathBuf,
    web: u16,
    base_port: u16,
) -> Result<()> {
    use rustytorrent::session::SessionManager;

    let mgr = SessionManager::new();
    let peer_id = rustytorrent::peer_id::load_or_generate(&rustytorrent::peer_id::default_path());

    for (i, path) in torrents.iter().enumerate() {
        let raw = match tokio::fs::read(path).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: {e}", path.display());
                continue;
            }
        };
        let t = match TorrentFile::from_bytes(&raw) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("skip {}: {e}", path.display());
                continue;
            }
        };
        let cfg = rustytorrent::engine::EngineConfig {
            output_dir: output.clone(),
            // One listen port per torrent (v1 — see docs/DAEMON.md).
            listen_port: base_port.wrapping_add(i as u16),
            // Tracker-only for now: a shared DHT is the documented
            // follow-up; per-session DHTs would race on the state file.
            enable_dht: false,
            ..Default::default()
        };
        match mgr.add(t, peer_id, cfg).await {
            Some(ih) => println!("added {} [{}]", path.display(), hex(&ih)),
            None => println!("skip {} (already running)", path.display()),
        }
    }

    println!(
        "Daemon:     {} torrent(s); UI at http://127.0.0.1:{web}/ (loopback)",
        mgr.len().await
    );

    // Serve until ctrl-c, then stop every session gracefully.
    tokio::select! {
        _ = rustytorrent::web::serve_daemon(web, mgr.clone()) => {}
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down daemon...");
        }
    }
    mgr.shutdown_all().await;
    println!("Done.");
    Ok(())
}

async fn cmd_decrypt(
    torrent_path: PathBuf,
    output: PathBuf,
    spool: Option<PathBuf>,
    passphrase: Option<String>,
) -> Result<()> {
    let raw = tokio::fs::read(&torrent_path)
        .await
        .with_context(|| format!("read {}", torrent_path.display()))?;
    let t = TorrentFile::from_bytes(&raw)?;
    let layout = rustytorrent::storage::Layout::from_torrent(output.clone(), &t);
    let spool_path = spool.unwrap_or_else(|| {
        let mut p = output.clone();
        p.push(format!("{}.rustytorrent-spool", t.info.name));
        p
    });
    let passphrase = resolve_passphrase(passphrase)?;
    println!("Decrypting: {}", spool_path.display());
    println!("Into:       {}", output.display());

    let pieces = rustytorrent::storage::decrypt_all_pieces(
        &spool_path,
        &passphrase,
        &layout,
        &t.info.piece_hashes,
    )
    .await?;
    println!("Recovered:  {} / {} pieces", pieces.len(), t.num_pieces());

    // Write the recovered pieces into the real file layout via the regular
    // storage task — reuses all the multi-file offset math.
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel(64);
    let handle = rustytorrent::storage::spawn_storage_task(layout, cmd_rx, ev_tx);

    let total_written = pieces.len();
    for (index, data) in pieces {
        cmd_tx
            .send(rustytorrent::storage::StorageCommand::Write { index, data })
            .await
            .context("send Write to storage task")?;
    }
    // Drain confirmations so we wait for every write to flush.
    let mut acked = 0usize;
    while acked < total_written {
        match ev_rx.recv().await {
            Some(rustytorrent::storage::StorageEvent::Written { .. }) => acked += 1,
            Some(rustytorrent::storage::StorageEvent::Error { index, msg }) => {
                anyhow::bail!("storage error on piece {index:?}: {msg}");
            }
            None => break,
        }
    }
    cmd_tx
        .send(rustytorrent::storage::StorageCommand::Shutdown)
        .await
        .ok();
    let _ = handle.await;

    println!("Done.");
    Ok(())
}

/// Resolve a list of `--socks5` flag values to a SOCKS5 chain. The
/// chain is the dial path from us to the destination: hop 0 dials hop
/// 1, hop 1 dials hop 2, … hop N-1 dials the actual target. Empty
/// input → empty chain (direct dial). Shared by `cmd_download` and
/// `cmd_magnet`.
///
/// Credentials and Tor stream isolation are applied to the LAST hop
/// only — typically the Tor / VPN endpoint that actually enforces
/// auth or where circuit isolation is meaningful. Earlier hops are
/// usually just transit (e.g. a corporate VPN) that doesn't need auth.
async fn resolve_proxy_chain(
    socks5: Vec<String>,
    socks5_user: Option<String>,
    socks5_pass: Option<String>,
    tor_isolation: bool,
) -> Result<Vec<rustytorrent::socks5::ProxyConfig>> {
    if socks5.is_empty() {
        if socks5_user.is_some() || socks5_pass.is_some() || tor_isolation {
            anyhow::bail!("--socks5-user / --socks5-pass / --tor-isolation require --socks5");
        }
        return Ok(Vec::new());
    }
    let credentials = match (socks5_user, socks5_pass) {
        (Some(u), Some(p)) => Some(rustytorrent::socks5::Credentials {
            username: u,
            password: p,
        }),
        (None, None) => None,
        _ => anyhow::bail!("--socks5-user and --socks5-pass must be set together"),
    };
    let last_idx = socks5.len() - 1;
    let mut chain = Vec::with_capacity(socks5.len());
    for (i, spec) in socks5.iter().enumerate() {
        let addr = tokio::net::lookup_host(spec.as_str())
            .await
            .with_context(|| format!("resolving SOCKS5 proxy {spec}"))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("SOCKS5 proxy {spec} did not resolve"))?;
        let is_last = i == last_idx;
        let creds = if is_last { credentials.clone() } else { None };
        let iso = if is_last { tor_isolation } else { false };
        let role = if last_idx == 0 {
            "SOCKS5"
        } else if i == 0 {
            "SOCKS5 hop 1 (entry)"
        } else if is_last {
            "SOCKS5 last hop (exit)"
        } else {
            "SOCKS5 mid hop"
        };
        if iso {
            println!("Proxy:      {addr} ({role}, Tor stream isolation on)");
        } else {
            println!("Proxy:      {addr} ({role})");
        }
        chain.push(rustytorrent::socks5::ProxyConfig {
            addr,
            credentials: creds,
            isolation: iso,
        });
    }
    Ok(chain)
}

#[allow(clippy::too_many_arguments)]
async fn cmd_magnet(
    uri: String,
    output: PathBuf,
    port: u16,
    extra_peers: Vec<String>,
    encrypt: bool,
    dht: bool,
    socks5: Vec<String>,
    socks5_user: Option<String>,
    socks5_pass: Option<String>,
    anonymous: bool,
    bind_iface: Option<String>,
    tor_isolation: bool,
    paranoid: bool,
    memory_only: bool,
    sandbox: bool,
    passphrase: Option<String>,
    spool: Option<PathBuf>,
    max_down: Option<u64>,
    max_up: Option<u64>,
    utp: bool,
    web: Option<u16>,
    select: Vec<String>,
    sequential: bool,
) -> Result<()> {
    let magnet = rustytorrent::magnet::MagnetLink::parse(&uri)?;
    println!(
        "Magnet:     {} ({} trackers)",
        magnet
            .display_name
            .as_deref()
            .unwrap_or("(no display name)"),
        magnet.trackers.len()
    );
    println!("Info hash:  {}", hex(&magnet.info_hash));

    // Pre-advertise BEP 10 so the bootstrap dials send the right
    // reserved bits before the engine has a chance to install them.
    // OnceLock makes the engine's later call a no-op.
    rustytorrent::peer::handshake::set_extension_bytes(
        rustytorrent::peer::handshake::extension_bytes_from(dht && !anonymous, true),
    );

    let proxies = resolve_proxy_chain(socks5, socks5_user, socks5_pass, tor_isolation).await?;

    let peer_id = if anonymous {
        rustytorrent::peer_id::generate_libtorrent_lookalike()
    } else {
        rustytorrent::peer_id::load_or_generate(&rustytorrent::peer_id::default_path())
    };

    // Build the bootstrap peer pool: --peer args, magnet trackers,
    // and DHT lookups (when DHT is permitted).
    let mut pool: Vec<std::net::SocketAddr> = Vec::new();
    for s in &extra_peers {
        let addr: std::net::SocketAddr = s
            .parse()
            .with_context(|| format!("invalid peer address: {s}"))?;
        pool.push(addr);
    }

    // Tracker bootstrap: each `tr=` URL gets one announce. We bail
    // peer-by-peer rather than fail the whole thing on a dead tracker.
    if !magnet.trackers.is_empty() {
        println!("Bootstrap:  querying {} tracker(s)", magnet.trackers.len());
        let req = rustytorrent::tracker::AnnounceRequest {
            info_hash: magnet.info_hash,
            peer_id,
            // BEP 27 hint: port=0 in anonymous mode so we don't
            // advertise a listen socket we aren't running.
            port: if anonymous { 0 } else { port },
            uploaded: 0,
            downloaded: 0,
            // We don't know `left` yet — magnet stage. Use 0 (the
            // common convention for "metadata not yet known").
            left: 0,
            event: rustytorrent::tracker::Event::Started,
            num_want: 50,
        };
        for url in &magnet.trackers {
            match rustytorrent::tracker::announce_with_proxy_anon(
                url,
                &req,
                proxies.first(),
                anonymous,
            )
            .await
            {
                Ok(resp) => {
                    tracing::info!(
                        target: "magnet",
                        tracker = %url,
                        peers = resp.peers.len(),
                        "tracker bootstrap"
                    );
                    pool.extend(resp.peers);
                }
                Err(e) => {
                    tracing::warn!(target: "magnet", tracker = %url, error = %e, "tracker failed");
                }
            }
        }
    }

    // DHT bootstrap. Skipped under --anonymous (UDP can't ride SOCKS5
    // and would leak our IP) and when the caller explicitly turned it
    // off. We spawn a temporary DHT just for the bootstrap; the
    // engine spawns its own DHT later when it takes over.
    let dht_handle = if dht && !anonymous {
        println!("Bootstrap:  warming up DHT (allow ~10s)");
        let bootstrap = vec![
            "router.bittorrent.com:6881".to_string(),
            "router.utorrent.com:6881".to_string(),
            "dht.transmissionbt.com:6881".to_string(),
        ];
        match rustytorrent::dht::Dht::spawn(port, bootstrap, None, None).await {
            Ok(d) => {
                // Brief warm-up so get_peers has something to work
                // with. Engine's persistent table would be better
                // but we don't want to fight it for the same UDP
                // port across two spawns.
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let dht_peers = d.get_peers(magnet.info_hash).await;
                tracing::info!(
                    target: "magnet",
                    peers = dht_peers.len(),
                    "dht bootstrap"
                );
                pool.extend(dht_peers);
                Some(d)
            }
            Err(e) => {
                tracing::warn!(target: "magnet", error = %e, "dht spawn failed");
                None
            }
        }
    } else {
        None
    };

    pool.sort();
    pool.dedup();
    println!("Bootstrap:  {} candidate peer(s)", pool.len());

    let info_bytes = rustytorrent::peer::metadata_fetch::fetch_metadata(
        magnet.info_hash,
        pool,
        proxies.clone(),
        anonymous,
    )
    .await
    .map_err(|e| anyhow::anyhow!("magnet bootstrap: {e}"))?;
    println!("Fetched:    {} bytes of info dict", info_bytes.len());

    // Shut down the bootstrap DHT before the engine spawns its own on
    // the same port.
    if let Some(d) = dht_handle {
        d.shutdown().await;
    }

    let t = rustytorrent::metainfo::TorrentFile::from_info_dict_bytes(
        &info_bytes,
        magnet.info_hash,
        magnet.trackers,
    )?;
    println!(
        "Downloading {} ({})",
        t.info.name,
        format_size(t.total_length())
    );
    println!("Output dir: {}", output.display());

    if anonymous {
        println!("Anonymous:  on (DHT off, listener off, peer_id ephemeral, port=0 in announces)");
    }
    if let Some(iface) = &bind_iface {
        println!("Bound to:   {iface} (VPN kill switch)");
        println!("            note: peer dials and the DHT socket are bound to {iface},");
        println!("            but tracker HTTP (reqwest) can't be interface-bound — pair");
        println!("            with --socks5 for a tracker that also rides the tunnel.");
    }
    let resolved_passphrase = if paranoid {
        Some(resolve_passphrase(passphrase)?)
    } else {
        None
    };
    if paranoid {
        println!("Paranoid:   on (encrypted spool, plaintext never written)");
    }
    if memory_only {
        println!("Memory:     on (RAM-only spool, nothing persisted)");
    }
    if sandbox {
        println!("Sandbox:    on (OS-level whitelist installed before download loop)");
    }

    if let Some(d) = max_down {
        println!("Max down:   {d} KiB/s");
    }
    if let Some(u) = max_up {
        println!("Max up:     {u} KiB/s");
    }

    let cfg = rustytorrent::engine::EngineConfig {
        output_dir: output,
        listen_port: port,
        // No --no-tracker for magnet: announce-list came from the URI
        // and is the user's only way to influence the tracker set.
        no_tracker: false,
        force_outgoing_mse: encrypt,
        enable_dht: dht,
        proxies,
        anonymous,
        bind_iface,
        paranoid,
        memory_only,
        sandbox,
        passphrase: resolved_passphrase,
        spool_path: spool,
        max_down_bytes_per_sec: max_down.map(|k| k * 1024),
        max_up_bytes_per_sec: max_up.map(|k| k * 1024),
        utp_enabled: utp,
        web_port: web,
        selected_files: select,
        sequential,
        ..Default::default()
    };
    if let Some(p) = web {
        println!("Web UI:     http://127.0.0.1:{p}/ (loopback only)");
    }
    let engine = rustytorrent::engine::TorrentEngine::new(t, peer_id, cfg);
    engine.run().await?;
    println!("Done.");
    Ok(())
}
