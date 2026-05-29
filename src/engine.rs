use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::interval;

use crate::error::{Error, Result};
use crate::metainfo::TorrentFile;
use crate::peer::connection::{PeerCommand, PeerEvent};
use crate::peer::manager::PeerManager;
use crate::peer::message::{bitfield_to_bytes, BLOCK_SIZE};
use crate::peer::transport::Transport;
use crate::peer::utp::UtpSocket;
use crate::peer_id::PeerId;
use crate::piece::{verify_piece, BlockOutcome, Picker, PieceManager};
use crate::ratelimit::TokenBucket;
use crate::scheduler::ChokeScheduler;
use crate::storage::{
    spawn_encrypted_storage_task, spawn_storage_task, Layout, PieceCache, StorageCommand,
    StorageEvent,
};
use crate::tracker::{self, AnnounceRequest, Event};

/// Outstanding block requests per unchoked peer.
pub const PIPELINE_DEPTH: usize = 5;

/// Threshold of remaining pieces below which we enable endgame.
pub const ENDGAME_REMAINING: usize = 5;

pub struct EngineConfig {
    pub output_dir: PathBuf,
    pub listen_port: u16,
    pub max_peers: usize,
    pub progress_every: Duration,
    pub reannounce_min: Duration,
    /// Peers to dial in addition to (or instead of) tracker results.
    pub seed_peers: Vec<SocketAddr>,
    /// If true, never contact the tracker (use seed_peers exclusively).
    pub no_tracker: bool,
    /// If true, every outgoing dial goes straight to MSE/PE (skip the plain
    /// attempt). Useful for testing the encrypted path on localhost or for
    /// swarms known to be entirely MSE-only.
    pub force_outgoing_mse: bool,
    /// Enable BEP 5 DHT for trackerless peer discovery + supplemental peers.
    /// When on, the engine spawns a DHT task on `listen_port`, bootstraps
    /// against the well-known router nodes, and asks for peers periodically
    /// (especially when the connected-peer count is low).
    pub enable_dht: bool,
    /// DHT bootstrap addresses (host:port). Empty → use built-in defaults.
    pub dht_bootstrap: Vec<String>,
    /// SOCKS5 proxy chain for all outgoing peer dials. Empty → direct
    /// connections (clearnet). Length 1 → single-hop proxy (the typical
    /// `--socks5 host:port` case). Length 2+ → multi-hop chain: bytes
    /// flow client → proxies[0] → proxies[1] → … → target via nested
    /// SOCKS5 CONNECTs on a single TCP stream. Defeats single-proxy
    /// compromise (C1).
    ///
    /// Tracker HTTP traffic uses only `proxies[0]` (reqwest's SOCKS5
    /// support is single-hop). Peer dials use the full chain.
    pub proxies: Vec<crate::socks5::ProxyConfig>,
    /// Bind every outbound socket to this network interface (e.g. `utun0`,
    /// `tun0`). Acts as a VPN kill switch — if the interface goes away,
    /// dials fail closed instead of falling back to the default route.
    pub bind_iface: Option<String>,
    /// "Anonymous mode" bundle: require a proxy, disable the inbound TCP
    /// listener (no incoming connections — they'd land on our real IP),
    /// disable DHT (UDP-only, can't go through SOCKS5 CONNECT, and would
    /// leak our IP to the wider network), and zero the `port` field in
    /// tracker announces so we don't advertise a listen socket we aren't
    /// running. The engine refuses to start in this mode without `proxy`.
    pub anonymous: bool,
    /// **Paranoid storage** (B1): write every piece to an AES-256-GCM
    /// encrypted spool file instead of the real file layout, keyed off a
    /// passphrase via Argon2id. Plaintext never touches disk during the
    /// session. The user later runs `rustytorrent decrypt` with the
    /// same passphrase to extract.
    pub paranoid: bool,
    /// **Sandbox** (C2): just before entering the main event loop,
    /// install a deny-default OS sandbox. Linux x86_64 → seccomp
    /// BPF whitelist; macOS → `sandbox_init` SBPL profile. Other
    /// platforms refused at startup. Defense-in-depth: even if an
    /// exploit lands in our address space, kernel primitives like
    /// `ptrace` / `mount` / `process-exec` are unreachable.
    pub sandbox: bool,
    /// **Memory-only storage** (B2): keep every piece in heap RAM only.
    /// Nothing is persisted to disk — when the process exits the
    /// download is gone. Mutually exclusive with `paranoid` (the two
    /// solve overlapping threats with different storage backends).
    /// Unsupported on Windows; the engine refuses to start there.
    pub memory_only: bool,
    /// Passphrase used when `paranoid` is true. Required in that mode.
    pub passphrase: Option<String>,
    /// Where to place the encrypted spool file. Defaults to
    /// `<output_dir>/<torrent-name>.rustytorrent-spool` when unset.
    pub spool_path: Option<PathBuf>,
    /// Cap inbound bandwidth at this many bytes/sec (engine-wide,
    /// summed across all peers). `None` = unthrottled. Enforced by
    /// gating outgoing `Request` issuance — when the bucket is dry we
    /// stop asking for new blocks, so peers naturally back off.
    pub max_down_bytes_per_sec: Option<u64>,
    /// Cap outbound bandwidth at this many bytes/sec, engine-wide.
    /// `None` = unthrottled. Enforced at `serve_request` — over-quota
    /// requests are silently dropped (peer re-requests later) rather
    /// than queued, which keeps the engine memory-bounded under bursty
    /// load.
    pub max_up_bytes_per_sec: Option<u64>,
    /// **µTP** (BEP 29) transport. When on, the engine binds a µTP
    /// socket on `listen_port` (UDP), accepts inbound µTP peers, and
    /// races TCP+µTP on every outgoing dial. Gated off automatically
    /// under `anonymous`, an active SOCKS5 chain, or `bind_iface` —
    /// UDP can't ride SOCKS5 and our µTP socket isn't interface-bound,
    /// so allowing it there would leak past the proxy / kill switch.
    pub utp_enabled: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("."),
            listen_port: 6881,
            max_peers: 50,
            progress_every: Duration::from_secs(2),
            reannounce_min: Duration::from_secs(60),
            seed_peers: Vec::new(),
            no_tracker: false,
            force_outgoing_mse: false,
            enable_dht: false,
            dht_bootstrap: Vec::new(),
            proxies: Vec::new(),
            anonymous: false,
            bind_iface: None,
            paranoid: false,
            memory_only: false,
            sandbox: false,
            passphrase: None,
            spool_path: None,
            max_down_bytes_per_sec: None,
            max_up_bytes_per_sec: None,
            utp_enabled: false,
        }
    }
}

pub struct TorrentEngine {
    torrent: Arc<TorrentFile>,
    peer_id: PeerId,
    cfg: EngineConfig,
    pm: PieceManager,
    picker: Picker,
    choker: ChokeScheduler,
    peer_choking_us: HashMap<SocketAddr, bool>,
    am_interested: HashMap<SocketAddr, bool>,
    /// Whether we've sent Unchoke to the peer and not followed it with Choke.
    /// Used to gate upload-side `Request` handling.
    we_unchoked: HashMap<SocketAddr, bool>,
    inflight: HashMap<SocketAddr, usize>,
    /// For endgame: which peers have an outstanding request for (piece, block).
    endgame_requests: HashMap<(u32, u32), Vec<SocketAddr>>,
    uploaded: u64,
    downloaded: u64,
    start_time: Instant,
    last_progress: Instant,
    /// In-memory LRU of whole pieces, populated on each upload-side miss.
    /// Lets us serve all blocks of a popular piece from RAM after the first
    /// read instead of going back to disk per-block.
    upload_cache: PieceCache,
    /// Engine-wide download throttle. Token bucket sized at 2 seconds
    /// of burst over the configured rate; gated at Request-issue time
    /// so peers naturally back off when we stop asking for blocks.
    download_bucket: Option<TokenBucket>,
    /// Engine-wide upload throttle. Gated at `serve_request`; over-quota
    /// peer requests are dropped silently rather than queued so memory
    /// stays bounded under bursty load.
    upload_bucket: Option<TokenBucket>,
    /// BEP 11 — for each peer that advertised a `ut_pex` id in their
    /// extension handshake, the id we should use when sending them
    /// outgoing PEX. Populated on `PeerEvent::ExtensionHandshake`.
    peer_pex_ids: HashMap<SocketAddr, u8>,
    /// BEP 11 — last set of peer addresses we shared with each peer via
    /// PEX. Used to compute `added`/`dropped` deltas on the next send so
    /// we never duplicate information that's already in flight.
    peer_pex_snapshot: HashMap<SocketAddr, std::collections::HashSet<SocketAddr>>,
}

impl TorrentEngine {
    pub fn new(torrent: TorrentFile, peer_id: PeerId, cfg: EngineConfig) -> Self {
        let pm = PieceManager::new(
            torrent.info.piece_length,
            torrent.total_length(),
            torrent.num_pieces(),
        );
        let picker = Picker::new(torrent.num_pieces());
        let download_bucket = cfg.max_down_bytes_per_sec.map(|r| {
            let rate = r as f64;
            // 2 s of burst headroom so the picker can refill the pipeline
            // after a brief stall without the cap kicking in.
            TokenBucket::new(rate * 2.0, rate)
        });
        let upload_bucket = cfg.max_up_bytes_per_sec.map(|r| {
            let rate = r as f64;
            TokenBucket::new(rate * 2.0, rate)
        });
        Self {
            torrent: Arc::new(torrent),
            peer_id,
            cfg,
            pm,
            picker,
            choker: ChokeScheduler::new(),
            peer_choking_us: HashMap::new(),
            am_interested: HashMap::new(),
            we_unchoked: HashMap::new(),
            inflight: HashMap::new(),
            endgame_requests: HashMap::new(),
            uploaded: 0,
            downloaded: 0,
            start_time: Instant::now(),
            last_progress: Instant::now(),
            upload_cache: PieceCache::default(),
            download_bucket,
            upload_bucket,
            peer_pex_ids: HashMap::new(),
            peer_pex_snapshot: HashMap::new(),
        }
    }

    pub async fn run(mut self) -> Result<()> {
        // Anonymous mode is strict: without a proxy we'd leak the real IP on
        // every dial. Refuse to start rather than silently downgrade.
        if self.cfg.anonymous && self.cfg.proxies.is_empty() {
            return Err(Error::Network(
                "anonymous mode requires --socks5; refusing to dial clearnet".into(),
            ));
        }
        // Anonymous mode refuses cleartext `http://` trackers — a passive
        // observer between us and the proxy would see the announce body
        // even when the dial itself is masked. https:// is encrypted in
        // transport; udp:// is already implicitly rejected because it
        // can't ride SOCKS5 CONNECT. We check every URL we'd ever try
        // (announce-list tiers + the single `announce` fallback) up
        // front rather than per-tier so the user gets one clear error
        // instead of a quiet skip-of-all-trackers later.
        if self.cfg.anonymous {
            if let Some(msg) = check_anonymous_tracker_urls(
                &self.torrent.announce_list,
                self.torrent.announce.as_deref(),
            ) {
                return Err(Error::Network(msg));
            }
        }
        // Paranoid mode needs a passphrase to derive the spool key. Fail
        // closed here rather than later inside the storage task spawn.
        if self.cfg.paranoid && self.cfg.passphrase.is_none() {
            return Err(Error::Crypto(
                "paranoid mode requires --passphrase (or RUSTYTORRENT_PASSPHRASE env)".into(),
            ));
        }
        // --memory-only and --paranoid are different storage backends
        // (in-RAM vs encrypted-on-disk). Both at once would require
        // picking one to drive the storage task; refuse rather than
        // silently choose.
        if self.cfg.memory_only && self.cfg.paranoid {
            return Err(Error::Network(
                "--memory-only and --paranoid are mutually exclusive".into(),
            ));
        }
        // --memory-only is Linux/macOS/BSD today; on Windows we'd have
        // to either fall back to disk or implement an mmap variant.
        // Bail explicitly so the user knows.
        if self.cfg.memory_only && !crate::storage::MEMSPOOL_SUPPORTED {
            return Err(Error::Network(
                "--memory-only is not supported on this platform (Linux/macOS/BSD only)".into(),
            ));
        }
        // --sandbox supports Linux x86_64 (seccomp) and macOS
        // (sandbox_init SBPL profile). Other platforms fail fast
        // rather than silently no-op (the user asked for a sandbox;
        // they should know if they didn't get one).
        if self.cfg.sandbox && !crate::sandbox::SUPPORTED {
            return Err(Error::Network(
                "--sandbox is not supported on this platform (Linux x86_64 and macOS only)".into(),
            ));
        }
        // In anonymous mode we never want to emit a plain `\x13BitTorrent...`
        // handshake — it's a DPI fingerprint even if the eventual MSE fallback
        // hides everything after it. Force MSE-only outgoing dials.
        if self.cfg.anonymous && !self.cfg.force_outgoing_mse {
            self.cfg.force_outgoing_mse = true;
        }
        if self.cfg.anonymous {
            tracing::info!(
                target: "engine",
                "anonymous mode: DHT off, listener off, port=0 in announces, MSE-only outgoing"
            );
        }
        if !self.cfg.proxies.is_empty() {
            let hops: Vec<String> = self
                .cfg
                .proxies
                .iter()
                .map(|p| p.addr.to_string())
                .collect();
            tracing::info!(
                target: "engine",
                hops = ?hops,
                "routing peer traffic through SOCKS5 chain ({} hop(s))",
                self.cfg.proxies.len()
            );
            if self.cfg.proxies.len() > 1 {
                tracing::info!(
                    target: "engine",
                    "tracker HTTP uses only the first hop (reqwest is single-hop SOCKS5)"
                );
            }
        }

        // BEP 27 — a private torrent must not use peer-discovery
        // mechanisms outside the tracker (DHT, PEX, LSD): doing so leaks
        // peer addresses to the wider network and gets users banned from
        // private trackers. We force DHT and PEX off whenever the info
        // dict's `private` flag is set, regardless of CLI flags.
        let private = self.torrent.info.private;
        if private && self.cfg.enable_dht {
            tracing::info!(target: "engine", "private torrent (BEP 27): DHT disabled despite --dht");
        }
        // VPN kill switch: --bind-iface forces every outbound socket
        // onto the bound interface so traffic fails closed if the tunnel
        // drops. DHT runs over a UDP socket we don't (yet) interface-bind,
        // so it would leak the real IP on the default route — disable it
        // when a bind interface is set, the same fail-closed stance
        // anonymous mode takes.
        let bound_iface = self.cfg.bind_iface.is_some();
        if bound_iface && self.cfg.enable_dht {
            tracing::info!(target: "engine", "--bind-iface set: DHT disabled (its UDP socket isn't interface-bound; would leak past the kill switch)");
        }

        // B5 — advertise the extensions we actually implement in the
        // handshake reserved bytes. Anonymous mode never enables DHT, so
        // we honor that here too. BEP 10 (extension protocol) is always
        // on — it's how we accept ut_metadata/ut_pex without breaking
        // peers that expect us to opt in.
        let dht_enabled = self.cfg.enable_dht && !self.cfg.anonymous && !private && !bound_iface;
        crate::peer::handshake::set_extension_bytes(crate::peer::handshake::extension_bytes_from(
            dht_enabled,
            true,
        ));

        let (peer_event_tx, mut peer_event_rx) = mpsc::channel::<PeerEvent>(1024);
        let mut peers = PeerManager::new(self.torrent.info_hash, self.peer_id, peer_event_tx);
        peers.set_max_peers(self.cfg.max_peers);
        peers.set_force_outgoing_mse(self.cfg.force_outgoing_mse);
        peers.set_proxies(self.cfg.proxies.clone());
        peers.set_bind_iface(self.cfg.bind_iface.clone());
        peers.set_anonymous(self.cfg.anonymous);

        // µTP transport (BEP 29): bind a UDP socket on the listen port
        // when enabled on a clearnet direct path. Gated off under
        // anonymous / SOCKS5 / bind-iface — UDP can't ride a SOCKS5
        // CONNECT and our µTP socket isn't interface-bound, so allowing
        // it there would leak past the proxy / kill switch.
        let utp_socket: Option<Arc<UtpSocket>> = if self.cfg.utp_enabled
            && !self.cfg.anonymous
            && self.cfg.proxies.is_empty()
            && self.cfg.bind_iface.is_none()
        {
            let bind: SocketAddr = (std::net::Ipv4Addr::UNSPECIFIED, self.cfg.listen_port).into();
            match UtpSocket::bind(bind).await {
                Ok(s) => {
                    tracing::info!(target: "engine", port = self.cfg.listen_port, "µTP transport enabled (TCP+µTP dial race)");
                    Some(Arc::new(s))
                }
                Err(e) => {
                    tracing::warn!(target: "engine", error = %e, "µTP bind failed; continuing TCP-only");
                    None
                }
            }
        } else {
            None
        };
        peers.set_utp(utp_socket.clone());

        // Incoming connections (TCP and/or µTP) funnel through one
        // channel as `Transport` values so the accept path is uniform.
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<(Transport, SocketAddr)>(32);

        // µTP inbound accept loop. The per-peer cap + ban list are still
        // enforced in `accept_incoming`. Skipped under anonymous mode
        // (no inbound at all then) since `utp_socket` is already None.
        if let Some(utp) = utp_socket.clone() {
            let tx = incoming_tx.clone();
            tokio::spawn(async move {
                while let Ok((stream, addr)) = utp.accept().await {
                    if tx.send((Transport::Utp(stream), addr)).await.is_err() {
                        break; // engine gone
                    }
                }
            });
        }
        let listener_handle = if self.cfg.anonymous {
            drop(incoming_tx);
            None
        } else {
            match bind_dual_stack_listener(self.cfg.listen_port) {
                Ok(l) => {
                    tracing::info!(
                        target: "engine",
                        port = self.cfg.listen_port,
                        "listening for incoming peers"
                    );
                    Some(tokio::spawn(async move {
                        // B4 — per-source-IP rate limit on inbound
                        // connection attempts. A token bucket per IP
                        // (lazily created on first sight, GC'd to keep
                        // the map bounded) caps how fast any single
                        // source can hammer us. We *accept* the TCP
                        // connection (we have to, to read the source
                        // IP) and then drop it without engaging the
                        // handshake when the bucket's dry.
                        let mut buckets: HashMap<std::net::IpAddr, TokenBucket> = HashMap::new();
                        let mut last_gc = Instant::now();
                        loop {
                            match l.accept().await {
                                Ok((s, addr)) => {
                                    let ip = addr.ip();
                                    let bucket = buckets.entry(ip).or_insert_with(|| {
                                        // 10 attempts in the first second,
                                        // then 1/sec sustained — comfortably
                                        // above any honest peer-discovery
                                        // pattern, well below the rate a
                                        // SYN-flood-style probe would use.
                                        TokenBucket::new(10.0, 1.0)
                                    });
                                    if !bucket.try_consume(1.0) {
                                        tracing::debug!(
                                            target: "engine",
                                            %addr,
                                            "per-IP connect rate limit; dropping"
                                        );
                                        drop(s);
                                        continue;
                                    }
                                    // Cheap GC: every 5 minutes drop
                                    // bucket entries that look full
                                    // (no recent activity → idle, safe
                                    // to forget). Keeps the map from
                                    // growing without bound on a
                                    // long-lived seeding session.
                                    if last_gc.elapsed() > Duration::from_secs(300) {
                                        buckets.retain(|_, b| b.available() < 9.0);
                                        last_gc = Instant::now();
                                    }
                                    if incoming_tx.send((Transport::Tcp(s), addr)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(target: "engine", error = %e, "accept");
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        }
                    }))
                }
                Err(e) => {
                    tracing::warn!(target: "engine", error = %e, "listener bind failed");
                    drop(incoming_tx);
                    None
                }
            }
        };

        let layout = Layout::from_torrent(self.cfg.output_dir.clone(), &self.torrent);
        let (storage_cmd_tx, storage_cmd_rx) = mpsc::channel::<StorageCommand>(64);
        let (storage_event_tx, mut storage_event_rx) = mpsc::channel::<StorageEvent>(64);

        // Resolve the spool path up front so resume + storage spawn agree.
        let spool_path = self.cfg.spool_path.clone().unwrap_or_else(|| {
            let mut p = self.cfg.output_dir.clone();
            p.push(format!("{}.rustytorrent-spool", self.torrent.info.name));
            p
        });

        // Storage backend selection: memory-only > paranoid > plain disk.
        // memory-only is the strongest "leave no trace" posture; paranoid
        // is encrypted-at-rest; plain disk is the default.
        let storage_handle = if self.cfg.memory_only {
            tracing::info!(
                target: "engine",
                "memory-only storage: pieces live in RAM, nothing persisted to disk"
            );
            crate::storage::spawn_memspool_storage_task(
                layout.clone(),
                storage_cmd_rx,
                storage_event_tx,
            )
        } else if self.cfg.paranoid {
            let passphrase = self
                .cfg
                .passphrase
                .clone()
                .expect("passphrase presence checked above");
            tracing::info!(
                target: "engine",
                spool = %spool_path.display(),
                "paranoid storage: every piece encrypted at rest, plaintext never persisted"
            );
            spawn_encrypted_storage_task(
                spool_path.clone(),
                passphrase,
                layout.clone(),
                storage_cmd_rx,
                storage_event_tx,
            )
        } else {
            spawn_storage_task(layout.clone(), storage_cmd_rx, storage_event_tx)
        };

        // Resume scan: hash-verify existing pieces (on-disk plaintext for
        // the normal path, decrypted spool slots for paranoid). Memory-only
        // has nothing to resume from — RAM doesn't survive process exit.
        tracing::info!(target: "engine", "resume scan starting");
        let already = if self.cfg.memory_only {
            Vec::new()
        } else if self.cfg.paranoid {
            let passphrase = self
                .cfg
                .passphrase
                .as_deref()
                .expect("passphrase presence checked above");
            crate::storage::scan_spool_resume(
                &spool_path,
                passphrase,
                &layout,
                &self.torrent.info.piece_hashes,
            )
            .await?
        } else {
            crate::storage::disk::scan_resume(&layout, &self.torrent.info.piece_hashes).await?
        };
        for i in &already {
            self.pm.mark_complete_verified(*i);
        }
        if !already.is_empty() {
            tracing::info!(target: "engine", verified = already.len(), "resume scan complete");
        }
        // If we resumed into a fully-complete state, run as a seeder (don't exit on first event).
        let started_complete = self.pm.is_complete();
        if started_complete {
            self.choker.set_seeding(true);
            tracing::info!(target: "engine", "fully seeded; running in seed mode");
        }

        // Always dial any explicitly configured peers.
        if !self.cfg.seed_peers.is_empty() {
            let n = peers.try_connect_many(self.cfg.seed_peers.clone());
            tracing::info!(target: "engine", peers = n, "dialing configured seed peers");
        }

        // Initial announce — unless explicitly disabled.
        let initial_interval = if self.cfg.no_tracker {
            tracing::info!(target: "engine", "tracker disabled by config");
            Duration::from_secs(900)
        } else {
            let req = self.announce_request(Event::Started);
            match tracker::announce_with_fallback_anon(
                &self.torrent.announce_list,
                self.torrent.announce.as_deref(),
                &req,
                self.cfg.proxies.first(),
                self.cfg.anonymous,
            )
            .await
            {
                Ok((used_url, resp)) => {
                    tracing::info!(target: "engine", tracker = %used_url, peers = resp.peers.len(), "first announce");
                    peers.try_connect_many(resp.peers.clone());
                    resp.interval
                }
                Err(e) => {
                    tracing::warn!(target: "engine", error = %e, "initial announce failed");
                    Duration::from_secs(900)
                }
            }
        };

        // C6 — jitter the reannounce cadence so two clients sharing the
        // same tracker don't produce identical timing fingerprints. We
        // never go below the tracker's stated min (or our floor),
        // because trackers ban for re-announcing too fast.
        let mut tracker_timer = interval(jittered_interval(
            initial_interval.max(self.cfg.reannounce_min),
            self.cfg.anonymous,
        ));
        tracker_timer.tick().await; // first tick is immediate

        let mut choke_timer = interval(crate::scheduler::choke::CHOKE_INTERVAL);
        choke_timer.tick().await;

        let mut progress_timer = interval(self.cfg.progress_every);
        progress_timer.tick().await;

        // DHT setup. We bind on listen_port (same as the BT listener — UDP
        // and TCP coexist on that number) and bootstrap against the
        // configured routers; failures are non-fatal — DHT is supplemental.
        // DHT cannot ride through SOCKS5 CONNECT (it's UDP), and announcing
        // ourselves onto the DHT leaks the real IP. Anonymous mode forces
        // it off regardless of `enable_dht`.
        let dht_wanted = self.cfg.enable_dht && !self.cfg.anonymous && !private && !bound_iface;
        if self.cfg.enable_dht && self.cfg.anonymous {
            tracing::info!(target: "engine", "anonymous mode: ignoring --dht request");
        }
        let dht = if dht_wanted {
            let bootstrap = if self.cfg.dht_bootstrap.is_empty() {
                crate::dht::DEFAULT_BOOTSTRAP_NODES
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                self.cfg.dht_bootstrap.clone()
            };
            let persist = Some(crate::dht::persist::default_path());
            match crate::dht::Dht::spawn(self.cfg.listen_port, bootstrap, persist).await {
                Ok(d) => Some(d),
                Err(e) => {
                    tracing::warn!(target: "engine", error = %e, "dht spawn failed");
                    None
                }
            }
        } else {
            None
        };
        // First DHT lookup fires after a short delay (let bootstrap settle),
        // then every 5 minutes thereafter. Also triggered ad-hoc when we
        // run low on connected peers.
        let mut dht_timer = interval(Duration::from_secs(20));
        dht_timer.tick().await;
        let mut dht_full_period = false;

        // BEP 11 outgoing PEX cadence — every 60 s we broadcast
        // added/dropped diffs to peers that advertised a ut_pex id.
        // Anonymous mode never populates `peer_pex_ids`, so the tick
        // is a no-op there.
        let mut pex_timer = interval(Duration::from_secs(60));
        pex_timer.tick().await;

        // BEP 5 announce_peer — tell the DHT we're carrying this
        // info_hash so other DHT-using clients can find us via
        // `get_peers`. We only announce when our public listener is
        // actually up (otherwise peers would dial a closed port and
        // give up on us). Cadence matches the DHT spec's 30-minute
        // recommendation; the first announce happens shortly after the
        // DHT has had a moment to settle so the routing table isn't
        // empty when we publish.
        let mut dht_announce_timer = interval(Duration::from_secs(60));
        dht_announce_timer.tick().await;
        let mut dht_announce_long_period = false;

        // Periodic GC of the per-IP protocol-violation map so a churn of
        // many one-off offenders can't grow it without bound (defense in
        // depth — see PeerManager::gc_violations).
        let mut violation_gc_timer = interval(Duration::from_secs(60));
        violation_gc_timer.tick().await;

        // C2 — engage the seccomp sandbox last in startup. By now the
        // listener is bound, the storage task is alive, the initial
        // tracker announce (which needs DNS) has gone out, and the
        // DHT has bootstrapped. Everything from here on rides the
        // syscall whitelist; an exploit that lands during the main
        // download loop can't pivot via syscalls outside it.
        if self.cfg.sandbox {
            crate::sandbox::engage()?;
        }

        let result: Result<()> = loop {
            tokio::select! {
                Some(ev) = peer_event_rx.recv() => {
                    if let Err(e) = self.handle_peer_event(ev, &mut peers, &storage_cmd_tx).await {
                        tracing::warn!(target: "engine", error = %e, "peer event handler error");
                    }
                    if self.pm.is_complete() && !started_complete {
                        tracing::info!(target: "engine", "all pieces downloaded");
                        break Ok(());
                    }
                }
                Some(ev) = storage_event_rx.recv() => {
                    self.handle_storage_event(ev, &mut peers).await;
                    if self.pm.is_complete() {
                        tracing::info!(target: "engine", "all pieces written");
                        break Ok(());
                    }
                }
                _ = tracker_timer.tick(), if !self.cfg.no_tracker => {
                    // C5 — in anonymous mode, rotate the peer_id at
                    // every reannounce. Existing TCP connections keep
                    // their negotiated id (handshake already happened),
                    // but every NEW dial after this point will use the
                    // fresh id. Defeats the "same client signature
                    // across unrelated swarms" correlation.
                    if self.cfg.anonymous {
                        // Use the libtorrent-style prefix so the
                        // rotation doesn't expose us as rustytorrent
                        // via the Azureus prefix on every reannounce.
                        self.peer_id = crate::peer_id::generate_libtorrent_lookalike();
                        peers.set_peer_id(self.peer_id);
                        tracing::debug!(target: "engine", "anonymous mode: rotated peer_id for new dials");
                    }
                    let req = self.announce_request(Event::None);
                    let res = tracker::announce_with_fallback_anon(
                        &self.torrent.announce_list,
                        self.torrent.announce.as_deref(),
                        &req,
                        self.cfg.proxies.first(),
                        self.cfg.anonymous,
                    ).await;
                    match res {
                        Ok((_, resp)) => {
                            tracker_timer = interval(jittered_interval(
                                resp.interval.max(self.cfg.reannounce_min),
                                self.cfg.anonymous,
                            ));
                            tracker_timer.tick().await;
                            let started = peers.try_connect_many(resp.peers);
                            if started > 0 {
                                tracing::debug!(target: "engine", started, "added peers from reannounce");
                            }
                        }
                        Err(e) => tracing::warn!(target: "engine", error = %e, "reannounce failed"),
                    }
                }
                _ = choke_timer.tick() => {
                    let candidates: Vec<SocketAddr> = peers.addrs().copied().collect();
                    let dec = self.choker.tick(&candidates);
                    for a in dec.to_unchoke {
                        if let Some(h) = peers.handle(&a) {
                            if h.try_send(PeerCommand::Unchoke).is_ok() {
                                self.we_unchoked.insert(a, true);
                            }
                        }
                    }
                    for a in dec.to_choke {
                        if let Some(h) = peers.handle(&a) {
                            if h.try_send(PeerCommand::Choke).is_ok() {
                                self.we_unchoked.insert(a, false);
                            }
                        }
                    }
                }
                _ = progress_timer.tick() => {
                    self.log_progress();
                }
                _ = violation_gc_timer.tick() => {
                    peers.gc_violations();
                }
                Some((stream, addr)) = incoming_rx.recv() => {
                    if !peers.accept_incoming(stream, addr) {
                        tracing::debug!(target: "engine", %addr, "incoming peer rejected");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!(target: "engine", "ctrl-c — beginning graceful shutdown");
                    break Ok(());
                }
                _ = dht_timer.tick(), if dht.is_some() => {
                    let dht = dht.as_ref().expect("guarded by `if`").clone();
                    let info_hash = self.torrent.info_hash;
                    let connected = peers.connected_count();
                    let max_peers = self.cfg.max_peers;
                    // Skip lookups while we're comfortably full.
                    if connected < max_peers / 2 {
                        let routing = dht.routing_table_size().await;
                        tracing::debug!(target: "engine", routing, connected, "running DHT get_peers");
                        let new_peers = dht.get_peers(info_hash).await;
                        if !new_peers.is_empty() {
                            let started = peers.try_connect_many(new_peers.iter().copied());
                            tracing::info!(
                                target: "engine",
                                discovered = new_peers.len(),
                                connected = started,
                                "added peers from DHT"
                            );
                        }
                    }
                    // After the first tick, fall back to the long-poll cadence.
                    if !dht_full_period {
                        dht_full_period = true;
                        dht_timer = interval(Duration::from_secs(300));
                        dht_timer.tick().await;
                    }
                }
                _ = pex_timer.tick(), if !self.peer_pex_ids.is_empty() => {
                    self.send_pex_to_all(&peers).await;
                }
                _ = dht_announce_timer.tick(), if dht.is_some() && listener_handle.is_some() => {
                    let dht_ref = dht.as_ref().expect("guarded by `if`");
                    let info_hash = self.torrent.info_hash;
                    let port = self.cfg.listen_port;
                    dht_ref.announce(info_hash, port).await;
                    // First announce uses the short cadence (60 s) to
                    // get us on the DHT quickly; subsequent ones drop to
                    // the spec-recommended 30-minute interval.
                    if !dht_announce_long_period {
                        dht_announce_long_period = true;
                        dht_announce_timer = interval(Duration::from_secs(1800));
                        dht_announce_timer.tick().await;
                    }
                }
                else => break Ok(()),
            }
        };

        // Final stopped event.
        if !self.cfg.no_tracker {
            let req = self.announce_request(Event::Stopped);
            let _ = tracker::announce_with_fallback_anon(
                &self.torrent.announce_list,
                self.torrent.announce.as_deref(),
                &req,
                self.cfg.proxies.first(),
                self.cfg.anonymous,
            )
            .await;
        }
        // Flush storage.
        let _ = storage_cmd_tx.send(StorageCommand::Shutdown).await;
        let _ = storage_handle.await;
        if let Some(h) = listener_handle {
            h.abort();
        }
        if let Some(d) = dht {
            d.shutdown().await;
        }
        result
    }

    fn announce_request(&self, event: Event) -> AnnounceRequest {
        let downloaded = self.downloaded;
        let left = self.torrent.total_length().saturating_sub(downloaded);
        // Anonymous mode advertises port=0: we don't run a public listener,
        // so promising a port we won't honor is both a lie and a fingerprint.
        let port = if self.cfg.anonymous {
            0
        } else {
            self.cfg.listen_port
        };
        AnnounceRequest {
            info_hash: self.torrent.info_hash,
            peer_id: self.peer_id,
            port,
            uploaded: self.uploaded,
            downloaded,
            left,
            event,
            num_want: 50,
        }
    }

    async fn handle_peer_event(
        &mut self,
        ev: PeerEvent,
        peers: &mut PeerManager,
        storage_cmd_tx: &mpsc::Sender<StorageCommand>,
    ) -> Result<()> {
        match ev {
            PeerEvent::Connected { addr, peer_id: _ } => {
                self.peer_choking_us.insert(addr, true);
                self.am_interested.insert(addr, false);
                self.we_unchoked.insert(addr, false);
                self.inflight.insert(addr, 0);
                if self.pm.complete_count() > 0 {
                    if let Some(h) = peers.handle(&addr) {
                        let bf = bitfield_to_bytes(self.pm.local_bitfield());
                        let _ = h.try_send(PeerCommand::Bitfield(bf));
                    }
                }
            }
            PeerEvent::Disconnected {
                addr,
                reason,
                violation,
            } => {
                tracing::debug!(target: "engine", %addr, reason, violation, "peer disconnected");
                if violation {
                    // Record under the IP, not the SocketAddr — a peer
                    // that reconnects from a fresh source port keeps
                    // its strike history against us.
                    peers.record_violation(addr.ip());
                }
                self.cleanup_disconnected_peer(addr);
                peers.forget(&addr);
            }
            PeerEvent::Bitfield { addr, bits } => {
                self.picker.set_peer_bitfield(addr, bits);
                self.maybe_express_interest(addr, peers);
                self.maybe_request_blocks(addr, peers);
            }
            PeerEvent::Have { addr, index } => {
                self.picker.add_have(addr, index as usize);
                self.maybe_express_interest(addr, peers);
                self.maybe_request_blocks(addr, peers);
            }
            PeerEvent::Choke { addr } => {
                self.peer_choking_us.insert(addr, true);
                self.inflight.insert(addr, 0);
                // Release in-flight blocks for the assigned piece so another peer can pick them up.
                if let Some(idx) = self.picker.assignment(&addr) {
                    self.pm.release_piece_inflight(idx);
                    self.picker.release_assignment(&addr);
                }
            }
            PeerEvent::Unchoke { addr } => {
                self.peer_choking_us.insert(addr, false);
                self.maybe_request_blocks(addr, peers);
            }
            PeerEvent::Interested { addr } => {
                // Fast-path for seeders: if we're fully seeded and have free
                // slots, unchoke immediately rather than waiting up to 10 s
                // for the next choke tick. This dramatically cuts startup
                // latency for new leechers.
                if self.pm.is_complete() && !self.we_unchoked.get(&addr).copied().unwrap_or(false) {
                    if let Some(h) = peers.handle(&addr) {
                        if h.try_send(PeerCommand::Unchoke).is_ok() {
                            self.we_unchoked.insert(addr, true);
                        }
                    }
                }
            }
            PeerEvent::NotInterested { addr: _ } => {}
            PeerEvent::Block {
                addr,
                index,
                begin,
                data,
            } => {
                let data_len = data.len() as u64;
                // The block counts toward our pipeline regardless of dup/error —
                // a Piece message did come back so an in-flight slot is freed.
                if let Some(c) = self.inflight.get_mut(&addr) {
                    *c = c.saturating_sub(1);
                }

                let outcome = match self.pm.received_block(index as usize, begin, &data) {
                    Ok(o) => o,
                    Err(e) => {
                        // Protocol violation (bad offset, wrong size, out-of-range piece).
                        // Drop the peer rather than letting them keep us spinning.
                        tracing::warn!(target: "engine", %addr, error = %e, "bad block from peer");
                        peers.ban(addr.ip());
                        self.cleanup_disconnected_peer(addr);
                        return Ok(());
                    }
                };

                // Only credit `downloaded` for blocks that actually advanced state.
                // Duplicates and ignored blocks don't count toward the tracker's
                // `downloaded` field, otherwise we'd inflate it.
                if outcome != BlockOutcome::Duplicate {
                    self.choker.record_download(addr, data_len);
                    self.downloaded = self.downloaded.saturating_add(data_len);
                }

                // Endgame: now that the block is in, tell every other peer that's
                // also working on this block to cancel their copy of the request.
                if let Some(peers_list) = self.endgame_requests.remove(&(index, begin)) {
                    for other in peers_list {
                        if other != addr {
                            if let Some(h) = peers.handle(&other) {
                                let _ = h.try_send(PeerCommand::Cancel {
                                    index,
                                    begin,
                                    length: data_len as u32,
                                });
                            }
                        }
                    }
                }

                if let BlockOutcome::Completed(buf) = outcome {
                    // SHA-1 is CPU-bound; large pieces (8 MiB) take >10 ms on
                    // a fast laptop. Offload so the engine's select! loop can
                    // keep dispatching other events.
                    let expected = self.torrent.info.piece_hashes[index as usize];
                    let join: std::result::Result<(bool, Vec<u8>), tokio::task::JoinError> =
                        tokio::task::spawn_blocking(move || {
                            let ok = verify_piece(&buf, &expected);
                            (ok, buf)
                        })
                        .await;
                    let (ok, buf) = match join {
                        Ok(pair) => pair,
                        Err(e) => return Err(Error::Io(std::io::Error::other(e.to_string()))),
                    };
                    if ok {
                        storage_cmd_tx
                            .send(StorageCommand::Write { index, data: buf })
                            .await
                            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
                    } else {
                        tracing::warn!(target: "engine", index, %addr, "piece SHA1 mismatch — banning peer");
                        self.pm.reset_piece(index as usize);
                        self.upload_cache.invalidate(index).await;
                        peers.ban(addr.ip());
                        self.picker.clear_assignment_if(&addr, index as usize);
                    }
                }
                self.maybe_request_blocks(addr, peers);
            }
            PeerEvent::Request {
                addr,
                index,
                begin,
                length,
            } => {
                self.serve_request(addr, index, begin, length, peers, storage_cmd_tx)
                    .await;
            }
            PeerEvent::Cancel { .. } => {
                // We fire-and-forget upload tasks; cancel arriving after we've
                // already dispatched the read is a no-op. If the peer disconnects
                // before our Piece send completes, the send simply fails.
            }
            PeerEvent::ExtensionHandshake {
                addr,
                their_ut_pex_id,
            } => {
                // Track the peer's ut_pex id so the periodic PEX timer
                // knows where to address outgoing peer-exchange
                // messages. Anonymous mode skips this entirely — we
                // never want to broadcast our peer set in that posture.
                // Private torrents (BEP 27) skip it too: PEX would leak
                // peers outside the tracker.
                if !self.cfg.anonymous && !self.torrent.info.private {
                    if let Some(id) = their_ut_pex_id {
                        self.peer_pex_ids.insert(addr, id);
                    }
                }
            }
            PeerEvent::Pex {
                addr,
                peers: pex_peers,
            } => {
                // BEP 11 — supplemental peer discovery. Drop self and
                // already-connected addresses; PeerManager handles
                // dedupe + max-peers cap. In anonymous mode we ignore
                // PEX entirely: peers shared via PEX could be honeypot
                // entries trying to enumerate the swarm. Private torrents
                // (BEP 27) ignore PEX too — only tracker peers are allowed.
                if self.cfg.anonymous || self.torrent.info.private {
                    tracing::debug!(
                        target: "engine",
                        from = %addr,
                        n = pex_peers.len(),
                        "ignoring PEX (anonymous or private torrent)"
                    );
                } else {
                    let started = peers.try_connect_many(pex_peers);
                    if started > 0 {
                        tracing::debug!(
                            target: "engine",
                            from = %addr,
                            started,
                            "added peers from PEX"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Serve a single `Request` from `addr`. Fires off a task that does the
    /// disk read + Piece send, so the engine doesn't block on disk I/O while
    /// many peers are downloading from us.
    async fn serve_request(
        &mut self,
        addr: SocketAddr,
        index: u32,
        begin: u32,
        length: u32,
        peers: &PeerManager,
        storage_cmd_tx: &mpsc::Sender<StorageCommand>,
    ) {
        // BEP 3: a peer should not Request while choked. Defend against it
        // anyway — some clients spam Request to dodge unchoke logic.
        if !*self.we_unchoked.get(&addr).unwrap_or(&false) {
            return;
        }
        // Standard block size is 16 KiB. Allow shorter (last block of last
        // piece) but never larger; libtorrent/Transmission drop the
        // connection on >16 KiB.
        if length == 0 || length > BLOCK_SIZE {
            return;
        }
        if index as usize >= self.pm.num_pieces() {
            return;
        }
        if !self.pm.local_bitfield()[index as usize] {
            return;
        }

        let Some(peer_handle) = peers.handle(&addr).cloned() else {
            return;
        };
        // Upload throttle: if the bucket can't cover this block, drop
        // the request silently. Peers re-request on timeout, so the
        // user-visible effect is just a smoother cap on outbound rate.
        if let Some(b) = &mut self.upload_bucket {
            if !b.try_consume(length as f64) {
                return;
            }
        }
        // Optimistic accounting — the actual TCP send may fail, but the
        // approximation is good enough for choker rate tracking.
        self.uploaded = self.uploaded.saturating_add(length as u64);
        self.choker.record_upload(addr, length as u64);

        // Fast path: cache hit. Slice the requested range out of the cached
        // piece and ship it without touching disk. Typical hit pattern:
        // a leecher pulls all 16 blocks of a 256 KiB piece sequentially;
        // only the first triggers a read.
        if let Some(piece_arc) = self.upload_cache.get(index).await {
            let end = (begin as usize).saturating_add(length as usize);
            if end <= piece_arc.len() {
                let data = piece_arc[begin as usize..end].to_vec();
                tokio::spawn(async move {
                    let _ = peer_handle
                        .send(PeerCommand::Piece { index, begin, data })
                        .await;
                });
                return;
            }
        }

        // Cache miss: read the WHOLE piece so the next block from the same
        // peer hits the cache. `piece_size` accounts for the short final
        // piece, if any.
        let piece_size = self.pm.piece_size(index as usize) as u32;
        let storage_tx = storage_cmd_tx.clone();
        let cache = self.upload_cache.clone();
        tokio::spawn(async move {
            let (reply_tx, mut reply_rx) = mpsc::channel(1);
            if storage_tx
                .send(StorageCommand::Read {
                    index,
                    begin: 0,
                    length: piece_size,
                    reply: reply_tx,
                })
                .await
                .is_err()
            {
                return;
            }
            let Some(Ok(piece_bytes)) = reply_rx.recv().await else {
                return;
            };
            let end = (begin as usize).saturating_add(length as usize);
            if end > piece_bytes.len() {
                return;
            }
            let block = piece_bytes[begin as usize..end].to_vec();
            let piece_arc = std::sync::Arc::new(piece_bytes);
            cache.insert(index, piece_arc).await;
            let _ = peer_handle
                .send(PeerCommand::Piece {
                    index,
                    begin,
                    data: block,
                })
                .await;
        });
    }

    /// Clean up engine-side state for a peer that has gone away (disconnected,
    /// banned, or kicked for a protocol violation). Used by the Disconnected
    /// handler and the bad-block path.
    /// Push BEP 11 PEX updates to every peer that advertised a ut_pex
    /// id. The payload for each peer is the delta vs the snapshot we
    /// last sent them: `added` is the currently-connected set minus
    /// what they already knew, `dropped` is what they knew but is no
    /// longer connected. We never include the recipient in their own
    /// PEX list. Empty deltas skip the send.
    async fn send_pex_to_all(&mut self, peers: &PeerManager) {
        use std::collections::HashSet;
        let current: HashSet<SocketAddr> = peers.addrs().copied().collect();
        // Snapshot the (addr, id) pairs so we can mutate self.peer_pex_snapshot
        // inside the loop without aliasing.
        let targets: Vec<(SocketAddr, u8)> =
            self.peer_pex_ids.iter().map(|(a, id)| (*a, *id)).collect();
        for (addr, ext_id) in targets {
            // Don't tell a peer about themselves.
            let visible: HashSet<SocketAddr> =
                current.iter().copied().filter(|a| *a != addr).collect();
            let last = self
                .peer_pex_snapshot
                .get(&addr)
                .cloned()
                .unwrap_or_default();

            let mut added: Vec<SocketAddr> = visible.difference(&last).copied().collect();
            let mut dropped: Vec<SocketAddr> = last.difference(&visible).copied().collect();
            if added.is_empty() && dropped.is_empty() {
                continue;
            }
            added.truncate(crate::peer::extension::PEX_MAX_ENTRIES_PER_DIRECTION);
            dropped.truncate(crate::peer::extension::PEX_MAX_ENTRIES_PER_DIRECTION);
            let payload = crate::peer::extension::build_pex_payload(&added, &dropped);

            if let Some(handle) = peers.handle(&addr) {
                if handle
                    .try_send(PeerCommand::Extension { ext_id, payload })
                    .is_err()
                {
                    // Channel full / closed — drop the snapshot update
                    // too so the next tick recomputes from scratch.
                    continue;
                }
            }
            // Record what we just shared so the next tick's diff is
            // accurate even when peers connect/disconnect mid-cycle.
            self.peer_pex_snapshot.insert(addr, visible);
        }
    }

    fn cleanup_disconnected_peer(&mut self, addr: SocketAddr) {
        self.peer_choking_us.remove(&addr);
        self.am_interested.remove(&addr);
        self.we_unchoked.remove(&addr);
        self.inflight.remove(&addr);
        if let Some(idx) = self.picker.assignment(&addr) {
            self.picker.release_assignment(&addr);
            self.pm.release_piece_inflight(idx);
        }
        self.picker.forget_peer(&addr);
        self.choker.forget(&addr);
        // BEP 11 — drop PEX bookkeeping for the departing peer so the
        // map doesn't grow unbounded over a long-lived seeding session.
        self.peer_pex_ids.remove(&addr);
        self.peer_pex_snapshot.remove(&addr);
    }

    async fn handle_storage_event(&mut self, ev: StorageEvent, peers: &mut PeerManager) {
        match ev {
            StorageEvent::Written { index } => {
                self.pm.mark_complete(index as usize);
                if self.pm.is_complete() {
                    self.choker.set_seeding(true);
                }
                // Broadcast Have to all peers.
                let addrs: Vec<SocketAddr> = peers.addrs().copied().collect();
                for a in &addrs {
                    if let Some(h) = peers.handle(a) {
                        let _ = h.try_send(PeerCommand::Have(index));
                    }
                }
                // Any peer that was assigned to this piece now needs a new one;
                // restart its request pump so it picks up other missing pieces.
                for a in addrs {
                    self.picker.clear_assignment_if(&a, index as usize);
                    self.maybe_request_blocks(a, peers);
                }
            }
            StorageEvent::Error { index, msg } => {
                tracing::error!(target: "engine", ?index, msg, "storage error");
                if let Some(i) = index {
                    self.pm.reset_piece(i as usize);
                }
            }
        }
    }

    fn maybe_express_interest(&mut self, addr: SocketAddr, peers: &PeerManager) {
        let already = *self.am_interested.get(&addr).unwrap_or(&false);
        let useful = self
            .pm
            .missing_pieces()
            .any(|i| self.picker.peer_has(&addr, i));
        if useful && !already {
            if let Some(h) = peers.handle(&addr) {
                let _ = h.try_send(PeerCommand::Interested);
                self.am_interested.insert(addr, true);
            }
        } else if !useful && already {
            if let Some(h) = peers.handle(&addr) {
                let _ = h.try_send(PeerCommand::NotInterested);
                self.am_interested.insert(addr, false);
            }
        }
    }

    fn maybe_request_blocks(&mut self, addr: SocketAddr, peers: &PeerManager) {
        if *self.peer_choking_us.get(&addr).unwrap_or(&true) {
            return;
        }
        let endgame = self.pm.missing_count() < ENDGAME_REMAINING && self.pm.missing_count() > 0;
        // Pieces this peer ran out of blocks on this round; skip them and
        // avoid an infinite pick_for loop when picker keeps returning a
        // sticky piece with no reservable blocks.
        let mut exhausted: std::collections::HashSet<usize> = std::collections::HashSet::new();
        loop {
            let cur = self.inflight.get(&addr).copied().unwrap_or(0);
            if cur >= PIPELINE_DEPTH {
                break;
            }
            let piece_idx = match self.picker.pick_for(&addr, &self.pm, endgame) {
                Some(p) => p,
                None => break,
            };
            if exhausted.contains(&piece_idx) {
                // Picker keeps suggesting the same piece even after we cleared the sticky.
                break;
            }
            let block_opt = if endgame {
                // In endgame: re-request any block we haven't received yet, even if marked requested.
                self.pm
                    .unfinished_blocks(piece_idx)
                    .into_iter()
                    .find(|(b, _)| {
                        !self
                            .endgame_requests
                            .get(&(piece_idx as u32, *b))
                            .map(|v| v.contains(&addr))
                            .unwrap_or(false)
                    })
            } else {
                self.pm.reserve_block(piece_idx)
            };
            let block = match block_opt {
                Some(bl) => bl,
                None => {
                    // No more blocks to reserve on this piece — move on.
                    exhausted.insert(piece_idx);
                    self.picker.clear_assignment_if(&addr, piece_idx);
                    continue;
                }
            };
            // Download throttle: gate at the actual request site so we
            // don't burn budget on iterations the picker bails out of.
            // We charge `block.1` (the real block length, which is
            // BLOCK_SIZE for everything except possibly the last block).
            if let Some(b) = &mut self.download_bucket {
                if !b.try_consume(block.1 as f64) {
                    if !endgame {
                        self.pm.release_block(piece_idx, block.0);
                    }
                    break;
                }
            }
            if let Some(h) = peers.handle(&addr) {
                if h.try_send(PeerCommand::Request {
                    index: piece_idx as u32,
                    begin: block.0,
                    length: block.1,
                })
                .is_ok()
                {
                    *self.inflight.entry(addr).or_insert(0) += 1;
                    if endgame {
                        self.endgame_requests
                            .entry((piece_idx as u32, block.0))
                            .or_default()
                            .push(addr);
                    }
                } else {
                    if !endgame {
                        self.pm.release_block(piece_idx, block.0);
                    }
                    break;
                }
            } else {
                if !endgame {
                    self.pm.release_block(piece_idx, block.0);
                }
                break;
            }
        }
    }

    fn log_progress(&mut self) {
        self.last_progress = Instant::now();
        let done = self.pm.complete_count();
        let total = self.pm.num_pieces();
        let pct = (done as f64) / (total as f64) * 100.0;
        let secs = self.start_time.elapsed().as_secs_f64().max(0.001);
        let rate = (self.downloaded as f64) / secs;
        tracing::info!(
            target: "engine",
            pct = format!("{pct:.1}%"),
            pieces = format!("{}/{}", done, total),
            down_bytes = self.downloaded,
            rate_kbps = format!("{:.0}", rate / 1024.0),
            "progress"
        );
        println!(
            "[progress] {done:>5}/{total} pieces  {pct:>5.1}%  down {:>7.1} KiB  {:>7.1} KiB/s",
            self.downloaded as f64 / 1024.0,
            rate / 1024.0,
        );
    }
}

/// Bind the inbound peer listener as a dual-stack socket so both IPv4
/// and IPv6 peers can reach us on the same port.
///
/// Why not just `tokio::net::TcpListener::bind("[::]:port")`? On Linux
/// that already accepts both families by default, but macOS / *BSD
/// usually set `IPV6_V6ONLY=1` and Windows always does, so a naive
/// `[::]` bind silently rejects IPv4 peers. We use `socket2` to flip
/// `set_only_v6(false)` explicitly before binding, which is the
/// portable recipe.
///
/// Falls back to an IPv4-only listener on `0.0.0.0` if the IPv6 bind
/// fails — the most common failure is a host without IPv6 configured
/// at all, in which case losing IPv6 reach is preferable to losing
/// the listener entirely.
fn bind_dual_stack_listener(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    let try_v6 = || -> std::io::Result<tokio::net::TcpListener> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        sock.set_only_v6(false)?;
        sock.set_reuse_address(true)?;
        let addr: std::net::SocketAddr = (std::net::Ipv6Addr::UNSPECIFIED, port).into();
        sock.bind(&addr.into())?;
        sock.listen(128)?;
        sock.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(sock.into())
    };
    match try_v6() {
        Ok(l) => Ok(l),
        Err(e) => {
            tracing::debug!(
                target: "engine",
                error = %e,
                "IPv6 dual-stack bind failed; falling back to IPv4-only"
            );
            let sock = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            sock.set_reuse_address(true)?;
            let addr: std::net::SocketAddr = (std::net::Ipv4Addr::UNSPECIFIED, port).into();
            sock.bind(&addr.into())?;
            sock.listen(128)?;
            sock.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(sock.into())
        }
    }
}

/// Return an error message if the torrent's tracker URLs include any
/// cleartext `http://` entries — anonymous mode refuses those because
/// the announce body is observable inside the proxied TCP stream.
/// Returns `None` when every URL is safe (`https://` or `udp://`,
/// which the higher layer handles separately).
fn check_anonymous_tracker_urls(
    announce_list: &[Vec<String>],
    announce: Option<&str>,
) -> Option<String> {
    let mut bad: Vec<&str> = Vec::new();
    for tier in announce_list {
        for url in tier {
            if url.starts_with("http://") {
                bad.push(url.as_str());
            }
        }
    }
    if let Some(u) = announce {
        if u.starts_with("http://") {
            bad.push(u);
        }
    }
    if bad.is_empty() {
        None
    } else {
        Some(format!(
            "anonymous mode refuses cleartext http:// trackers: {}",
            bad.join(", ")
        ))
    }
}

/// Compute a jittered re-announce interval (C6).
///
/// We always jitter **upward** — going below the tracker's stated
/// interval is the fastest path to a ban. In normal mode the
/// adjustment is tiny (+0..5 %), just enough to defeat the trivial
/// "same client announces every N seconds on the dot" timing
/// fingerprint. In anonymous mode the window opens up to +5..50 %
/// since the cost of an extra few minutes between announces is much
/// cheaper than letting timing analysis link two of the user's
/// torrents to the same machine.
fn jittered_interval(base: Duration, anonymous: bool) -> Duration {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let pct: u32 = if anonymous {
        rng.gen_range(5..=50)
    } else {
        rng.gen_range(0..=5)
    };
    base + base * pct / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_is_always_at_least_base() {
        let base = Duration::from_secs(600);
        for _ in 0..100 {
            assert!(jittered_interval(base, false) >= base);
            assert!(jittered_interval(base, true) >= base);
        }
    }

    #[test]
    fn memspool_platform_gate_matches_cfg() {
        // Just a sanity assert that the platform gate is wired
        // through — on the platforms we run CI on (Linux, macOS,
        // Windows) this matches the cfg outcome we expect. Clippy
        // warns about asserting a constant, but the constant is
        // cfg-derived so its value is genuinely different across
        // build targets.
        #[allow(clippy::assertions_on_constants)]
        {
            #[cfg(not(windows))]
            assert!(crate::storage::MEMSPOOL_SUPPORTED);
            #[cfg(windows)]
            assert!(!crate::storage::MEMSPOOL_SUPPORTED);
        }
    }

    #[test]
    fn anonymous_tracker_check_accepts_https_and_udp() {
        let tiers = vec![
            vec!["https://t.example/announce".into()],
            vec!["udp://t.example:6969".into()],
        ];
        assert!(check_anonymous_tracker_urls(&tiers, None).is_none());
    }

    #[test]
    fn anonymous_tracker_check_rejects_http() {
        let tiers = vec![vec!["http://insecure.example/announce".into()]];
        let msg = check_anonymous_tracker_urls(&tiers, None).expect("expected refusal");
        assert!(msg.contains("http://insecure.example/announce"));
    }

    #[test]
    fn anonymous_tracker_check_rejects_http_in_announce_fallback() {
        let tiers: Vec<Vec<String>> = Vec::new();
        let single = "http://fallback.example/announce";
        let msg = check_anonymous_tracker_urls(&tiers, Some(single)).expect("expected refusal");
        assert!(msg.contains(single));
    }

    #[test]
    fn anonymous_jitter_is_bigger_on_average() {
        let base = Duration::from_secs(600);
        let n = 200;
        let avg_normal: u128 = (0..n)
            .map(|_| jittered_interval(base, false).as_millis())
            .sum::<u128>()
            / n as u128;
        let avg_anon: u128 = (0..n)
            .map(|_| jittered_interval(base, true).as_millis())
            .sum::<u128>()
            / n as u128;
        assert!(
            avg_anon > avg_normal,
            "expected anonymous avg ({avg_anon}ms) > normal avg ({avg_normal}ms)"
        );
    }
}
