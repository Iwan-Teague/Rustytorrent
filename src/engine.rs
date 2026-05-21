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
use crate::peer_id::PeerId;
use crate::piece::{verify_piece, BlockOutcome, Picker, PieceManager};
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
    /// SOCKS5 proxy for all outgoing peer dials and tracker HTTP. `None` →
    /// direct connections (clearnet). When set, the swarm only sees the
    /// proxy's IP; pair with `anonymous = true` to also close DHT/listener
    /// side-channels that would otherwise leak the real IP.
    pub proxy: Option<crate::socks5::ProxyConfig>,
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
    /// Passphrase used when `paranoid` is true. Required in that mode.
    pub passphrase: Option<String>,
    /// Where to place the encrypted spool file. Defaults to
    /// `<output_dir>/<torrent-name>.rustytorrent-spool` when unset.
    pub spool_path: Option<PathBuf>,
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
            proxy: None,
            anonymous: false,
            bind_iface: None,
            paranoid: false,
            passphrase: None,
            spool_path: None,
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
}

impl TorrentEngine {
    pub fn new(torrent: TorrentFile, peer_id: PeerId, cfg: EngineConfig) -> Self {
        let pm = PieceManager::new(
            torrent.info.piece_length,
            torrent.total_length(),
            torrent.num_pieces(),
        );
        let picker = Picker::new(torrent.num_pieces());
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
        }
    }

    pub async fn run(mut self) -> Result<()> {
        // Anonymous mode is strict: without a proxy we'd leak the real IP on
        // every dial. Refuse to start rather than silently downgrade.
        if self.cfg.anonymous && self.cfg.proxy.is_none() {
            return Err(Error::Network(
                "anonymous mode requires --socks5; refusing to dial clearnet".into(),
            ));
        }
        // Paranoid mode needs a passphrase to derive the spool key. Fail
        // closed here rather than later inside the storage task spawn.
        if self.cfg.paranoid && self.cfg.passphrase.is_none() {
            return Err(Error::Crypto(
                "paranoid mode requires --passphrase (or RUSTYTORRENT_PASSPHRASE env)".into(),
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
        if let Some(p) = &self.cfg.proxy {
            tracing::info!(target: "engine", proxy = %p.addr, "routing peer + tracker traffic through SOCKS5");
        }

        // B5 — advertise the extensions we actually implement in the
        // handshake reserved bytes. Anonymous mode never enables DHT, so
        // we honor that here too. BEP 10 (extension protocol) is always
        // on — it's how we accept ut_metadata/ut_pex without breaking
        // peers that expect us to opt in.
        let dht_enabled = self.cfg.enable_dht && !self.cfg.anonymous;
        crate::peer::handshake::set_extension_bytes(crate::peer::handshake::extension_bytes_from(
            dht_enabled,
            true,
        ));

        let (peer_event_tx, mut peer_event_rx) = mpsc::channel::<PeerEvent>(1024);
        let mut peers = PeerManager::new(self.torrent.info_hash, self.peer_id, peer_event_tx);
        peers.set_max_peers(self.cfg.max_peers);
        peers.set_force_outgoing_mse(self.cfg.force_outgoing_mse);
        peers.set_proxy(self.cfg.proxy.clone());
        peers.set_bind_iface(self.cfg.bind_iface.clone());

        // Bind incoming-connection listener — unless anonymous mode (the
        // listener would expose our real IP on the configured port).
        let (incoming_tx, mut incoming_rx) =
            mpsc::channel::<(tokio::net::TcpStream, SocketAddr)>(32);
        let listener_handle = if self.cfg.anonymous {
            drop(incoming_tx);
            None
        } else {
            match tokio::net::TcpListener::bind(("0.0.0.0", self.cfg.listen_port)).await {
                Ok(l) => {
                    tracing::info!(
                        target: "engine",
                        port = self.cfg.listen_port,
                        "listening for incoming peers"
                    );
                    Some(tokio::spawn(async move {
                        loop {
                            match l.accept().await {
                                Ok((s, addr)) => {
                                    if incoming_tx.send((s, addr)).await.is_err() {
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

        let storage_handle = if self.cfg.paranoid {
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
        // the normal path, decrypted spool slots for paranoid) before
        // talking to anyone.
        tracing::info!(target: "engine", "resume scan starting");
        let already = if self.cfg.paranoid {
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
            match tracker::announce_with_fallback(
                &self.torrent.announce_list,
                self.torrent.announce.as_deref(),
                &req,
                self.cfg.proxy.as_ref(),
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

        let mut tracker_timer = interval(initial_interval.max(self.cfg.reannounce_min));
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
        let dht_wanted = self.cfg.enable_dht && !self.cfg.anonymous;
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
                    let req = self.announce_request(Event::None);
                    let res = tracker::announce_with_fallback(
                        &self.torrent.announce_list,
                        self.torrent.announce.as_deref(),
                        &req,
                        self.cfg.proxy.as_ref(),
                    ).await;
                    match res {
                        Ok((_, resp)) => {
                            tracker_timer = interval(resp.interval.max(self.cfg.reannounce_min));
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
                else => break Ok(()),
            }
        };

        // Final stopped event.
        if !self.cfg.no_tracker {
            let req = self.announce_request(Event::Stopped);
            let _ = tracker::announce_with_fallback(
                &self.torrent.announce_list,
                self.torrent.announce.as_deref(),
                &req,
                self.cfg.proxy.as_ref(),
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
            PeerEvent::Disconnected { addr, reason } => {
                tracing::debug!(target: "engine", %addr, reason, "peer disconnected");
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
