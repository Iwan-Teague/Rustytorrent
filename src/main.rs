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
        /// SOCKS5 proxy address (host:port). All outgoing peer dials and HTTP-tracker
        /// requests will be routed through it. Use `127.0.0.1:9050` for Tor's
        /// local SOCKS port, or your VPN's loopback SOCKS endpoint.
        #[arg(long)]
        socks5: Option<String>,
        /// Optional SOCKS5 username (paired with --socks5-pass for RFC 1929 auth).
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
        /// Passphrase for paranoid mode. If unset, read from the
        /// `RUSTYTORRENT_PASSPHRASE` environment variable. Required
        /// when --paranoid is set.
        #[arg(long)]
        passphrase: Option<String>,
        /// Override the spool file path. Defaults to
        /// `<output>/<torrent-name>.rustytorrent-spool`.
        #[arg(long)]
        spool: Option<PathBuf>,
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
        /// Passphrase. If unset, read from `RUSTYTORRENT_PASSPHRASE`.
        #[arg(long)]
        passphrase: Option<String>,
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
            passphrase,
            spool,
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
                passphrase,
                spool,
            )
            .await
        }
        Commands::Decrypt {
            file,
            output,
            spool,
            passphrase,
        } => cmd_decrypt(file, output, spool, passphrase).await,
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
    socks5: Option<String>,
    socks5_user: Option<String>,
    socks5_pass: Option<String>,
    anonymous: bool,
    bind_iface: Option<String>,
    tor_isolation: bool,
    paranoid: bool,
    passphrase: Option<String>,
    spool: Option<PathBuf>,
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

    // Resolve the SOCKS5 proxy if requested. We resolve the host once at
    // startup so we don't emit DNS queries on the clearnet for every dial.
    let proxy = match socks5 {
        None => None,
        Some(spec) => {
            // Accept either "host:port" or "ip:port".
            let addr = tokio::net::lookup_host(spec.as_str())
                .await
                .with_context(|| format!("resolving SOCKS5 proxy {spec}"))?
                .next()
                .ok_or_else(|| anyhow::anyhow!("SOCKS5 proxy {spec} did not resolve"))?;
            let credentials = match (socks5_user, socks5_pass) {
                (Some(u), Some(p)) => Some(rustytorrent::socks5::Credentials {
                    username: u,
                    password: p,
                }),
                (None, None) => None,
                _ => anyhow::bail!("--socks5-user and --socks5-pass must be set together"),
            };
            if tor_isolation {
                println!("Proxy:      {addr} (SOCKS5, Tor stream isolation on)");
            } else {
                println!("Proxy:      {addr} (SOCKS5)");
            }
            Some(rustytorrent::socks5::ProxyConfig {
                addr,
                credentials,
                isolation: tor_isolation,
            })
        }
    };

    // Anonymous mode insists on a fresh, non-persisted peer_id every run —
    // a stable id across sessions would let observers correlate.
    let peer_id = if anonymous {
        rustytorrent::peer_id::generate()
    } else {
        rustytorrent::peer_id::load_or_generate(&rustytorrent::peer_id::default_path())
    };

    if anonymous {
        println!("Anonymous:  on (DHT off, listener off, peer_id ephemeral, port=0 in announces)");
    }

    if let Some(iface) = &bind_iface {
        println!("Bound to:   {iface} (VPN kill switch)");
    }

    let resolved_passphrase = if paranoid {
        Some(resolve_passphrase(passphrase)?)
    } else {
        None
    };
    if paranoid {
        println!("Paranoid:   on (encrypted spool, plaintext never written)");
    }

    let cfg = rustytorrent::engine::EngineConfig {
        output_dir: output,
        listen_port: port,
        seed_peers: parsed_peers,
        no_tracker,
        force_outgoing_mse: encrypt,
        enable_dht: dht,
        proxy,
        anonymous,
        bind_iface,
        paranoid,
        passphrase: resolved_passphrase,
        spool_path: spool,
        ..Default::default()
    };
    let engine = rustytorrent::engine::TorrentEngine::new(t, peer_id, cfg);

    // The engine handles ctrl-c internally and performs an orderly shutdown
    // (tracker stopped event, storage flush, DHT routing-table save).
    engine.run().await?;
    println!("Done.");
    Ok(())
}

/// Resolve the paranoid-mode passphrase from CLI flag → env var → error.
/// We never log it; just pass it to the engine to derive the spool key.
fn resolve_passphrase(flag: Option<String>) -> Result<String> {
    if let Some(p) = flag {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("RUSTYTORRENT_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    anyhow::bail!("--paranoid requires --passphrase or RUSTYTORRENT_PASSPHRASE (non-empty)")
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
