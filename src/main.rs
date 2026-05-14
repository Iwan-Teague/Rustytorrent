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
    /// Download a torrent (Phase 4)
    Download { file: PathBuf },
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
        Commands::Peers { file, port, numwant } => cmd_peers(file, port, numwant).await,
        Commands::Download { .. } => anyhow::bail!("download: Phase 4"),
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
    if unit == 0 { format!("{bytes} B") } else { format!("{v:.2} {}", UNITS[unit]) }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{b:02x}")); }
    s
}

async fn cmd_info(path: PathBuf) -> Result<()> {
    let raw = tokio::fs::read(&path).await.with_context(|| format!("read {}", path.display()))?;
    let t = TorrentFile::from_bytes(&raw)?;
    println!("Name:         {}", t.info.name);
    println!("Info hash:    {}", hex(&t.info_hash));
    println!("Piece length: {} ({})", t.info.piece_length, format_size(t.info.piece_length));
    println!("Pieces:       {}", t.num_pieces());
    println!("Total size:   {} ({})", t.total_length(), format_size(t.total_length()));
    match &t.info.files {
        rustytorrent::metainfo::TorrentFiles::Single { length } => {
            println!("Files:        1 ({})", format_size(*length));
        }
        rustytorrent::metainfo::TorrentFiles::Multi { files } => {
            println!("Files:        {}", files.len());
            for f in files { println!("  {:>10}  {}", format_size(f.length), f.path.display()); }
        }
    }
    println!("Private:      {}", t.info.private);
    let trackers = t.trackers();
    println!("Trackers:     {}", trackers.len());
    for tr in &trackers { println!("  {tr}"); }
    Ok(())
}

async fn cmd_peers(path: PathBuf, port: u16, numwant: i32) -> Result<()> {
    let raw = tokio::fs::read(&path).await.with_context(|| format!("read {}", path.display()))?;
    let t = TorrentFile::from_bytes(&raw)?;
    let peer_id = rustytorrent::peer_id::generate();
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
    let (used, resp) = tracker::announce_with_fallback(&t.announce_list, t.announce.as_deref(), &req, None).await?;
    println!("Tracker:  {used}");
    println!("Interval: {}s", resp.interval.as_secs());
    if let Some(s) = resp.seeders { println!("Seeders:  {s}"); }
    if let Some(l) = resp.leechers { println!("Leechers: {l}"); }
    println!("Found {} peers:", resp.peers.len());
    for p in &resp.peers { println!("  {p}"); }
    Ok(())
}
