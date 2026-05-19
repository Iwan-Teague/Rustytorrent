use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rustytorrent", about = "A BitTorrent client built in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show info about a .torrent file
    Info {
        file: std::path::PathBuf,
    },
    /// List peers from a .torrent file's tracker
    Peers {
        file: std::path::PathBuf,
    },
    /// Download a torrent
    Download {
        file: std::path::PathBuf,
        #[arg(short, long, default_value = ".")]
        output: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Info { file } => {
            println!("Info: {:?}", file);
            todo!("Phase 1")
        }
        Commands::Peers { file } => {
            println!("Peers: {:?}", file);
            todo!("Phase 2")
        }
        Commands::Download { file, output } => {
            println!("Download {:?} → {:?}", file, output);
            todo!("Phase 4")
        }
    }
}
