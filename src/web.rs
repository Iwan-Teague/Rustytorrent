//! Phase 8 — read-only web monitoring server.
//!
//! An `axum` server, bound to **loopback only** (`127.0.0.1`), exposing
//! the live state of the running download:
//!
//! - `GET /`            — a tiny self-contained HTML page that polls the
//!   JSON endpoint and renders a progress bar.
//! - `GET /api/status`  — the current [`EngineStats`] as JSON.
//! - `GET /metrics`     — Prometheus text exposition of the same numbers.
//!
//! The engine pushes a fresh [`EngineStats`] into a `watch` channel on
//! every progress tick; handlers just read the latest value, so serving
//! a request never touches the engine's hot path.
//!
//! ## Why loopback only
//!
//! This is a monitoring/control surface. Binding it to `0.0.0.0` would
//! expose a stranger on the network to your download's metadata (and, in
//! a future version, control). We bind `127.0.0.1` unconditionally; a
//! user who wants remote access can front it with their own
//! authenticated reverse proxy / SSH tunnel.

use std::net::{Ipv4Addr, SocketAddr};

use axum::extract::{Path, Request, State};
use axum::http::header::{HOST, ORIGIN};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;
use tokio::sync::{mpsc, watch};

use crate::engine::EngineControl;
use crate::session::SessionManager;

/// Shared state for the web handlers: the latest stats (read) plus a
/// control channel back into the engine (pause/resume).
#[derive(Clone)]
pub struct WebState {
    pub rx: watch::Receiver<EngineStats>,
    pub ctl: mpsc::Sender<EngineControl>,
}

/// A snapshot of a running download, published to the web layer each
/// progress tick. Cheap to clone; carries only scalars + the torrent
/// name.
#[derive(Debug, Clone, Serialize)]
pub struct EngineStats {
    /// Torrent display name.
    pub name: String,
    /// Lowercase hex of the info-hash.
    pub info_hash: String,
    /// Pieces verified-and-written so far.
    pub complete_pieces: usize,
    /// Total pieces in the torrent.
    pub total_pieces: usize,
    /// Bytes downloaded (payload that advanced piece state).
    pub downloaded_bytes: u64,
    /// Bytes uploaded to peers.
    pub uploaded_bytes: u64,
    /// Total size of the torrent in bytes.
    pub total_bytes: u64,
    /// Currently-connected peers.
    pub peers_connected: usize,
    /// Seconds since the engine started.
    pub elapsed_secs: u64,
    /// Instantaneous download rate (over the last progress interval),
    /// bytes/sec.
    pub down_rate_bps: u64,
    /// Instantaneous upload rate (over the last progress interval),
    /// bytes/sec.
    pub up_rate_bps: u64,
    /// True once every piece is downloaded.
    pub complete: bool,
    /// True when the download is paused via the control API.
    pub paused: bool,
    /// Approximate bytes still to download (wanted pieces not yet
    /// complete). Drives the ETA estimate; 0 when complete.
    pub remaining_bytes: u64,
    /// Addresses of the currently-connected peers (`ip:port`). Loopback-
    /// only endpoint, so listing the swarm we're talking to is fine.
    pub peers: Vec<String>,
    /// Per-file download progress (multi-file torrents). Empty for a
    /// single-file torrent.
    pub files: Vec<FileProgress>,
}

/// Per-file progress for the status UI.
#[derive(Debug, Clone, Serialize)]
pub struct FileProgress {
    /// File path within the torrent (relative).
    pub path: String,
    /// File length in bytes.
    pub length: u64,
    /// Fraction of the file's bytes that live in completed pieces,
    /// `[0.0, 1.0]`.
    pub fraction: f64,
    /// Whether this file is part of the selective-download set (always
    /// true when no `--select` is given).
    pub wanted: bool,
}

impl EngineStats {
    /// A zeroed snapshot for a freshly-added session, before the engine
    /// publishes its first real one. Used by the daemon's `watch`
    /// channel initial value.
    pub fn placeholder(
        name: String,
        info_hash: String,
        total_bytes: u64,
        total_pieces: usize,
    ) -> Self {
        Self {
            name,
            info_hash,
            complete_pieces: 0,
            total_pieces,
            downloaded_bytes: 0,
            uploaded_bytes: 0,
            total_bytes,
            peers_connected: 0,
            elapsed_secs: 0,
            down_rate_bps: 0,
            up_rate_bps: 0,
            complete: false,
            paused: false,
            remaining_bytes: total_bytes,
            peers: Vec::new(),
            files: Vec::new(),
        }
    }

    /// Fraction complete in `[0.0, 1.0]`. Zero-piece torrents read as 1.0
    /// (nothing to download) rather than NaN.
    pub fn fraction(&self) -> f64 {
        if self.total_pieces == 0 {
            return 1.0;
        }
        self.complete_pieces as f64 / self.total_pieces as f64
    }

    /// Render the Prometheus text exposition format for these stats. All
    /// series carry an `info_hash` label so a scraper monitoring several
    /// instances can disambiguate.
    pub fn render_prometheus(&self) -> String {
        let ih = &self.info_hash;
        let mut out = String::new();
        let mut metric = |name: &str, help: &str, ty: &str, value: String| {
            out.push_str(&format!("# HELP rustytorrent_{name} {help}\n"));
            out.push_str(&format!("# TYPE rustytorrent_{name} {ty}\n"));
            out.push_str(&format!(
                "rustytorrent_{name}{{info_hash=\"{ih}\"}} {value}\n"
            ));
        };
        metric(
            "complete_pieces",
            "Pieces verified and written",
            "gauge",
            self.complete_pieces.to_string(),
        );
        metric(
            "total_pieces",
            "Total pieces in the torrent",
            "gauge",
            self.total_pieces.to_string(),
        );
        metric(
            "downloaded_bytes",
            "Payload bytes downloaded",
            "counter",
            self.downloaded_bytes.to_string(),
        );
        metric(
            "uploaded_bytes",
            "Payload bytes uploaded",
            "counter",
            self.uploaded_bytes.to_string(),
        );
        metric(
            "total_bytes",
            "Total torrent size in bytes",
            "gauge",
            self.total_bytes.to_string(),
        );
        metric(
            "peers_connected",
            "Currently connected peers",
            "gauge",
            self.peers_connected.to_string(),
        );
        metric(
            "down_rate_bps",
            "Instantaneous download rate, bytes/sec",
            "gauge",
            self.down_rate_bps.to_string(),
        );
        metric(
            "up_rate_bps",
            "Instantaneous upload rate, bytes/sec",
            "gauge",
            self.up_rate_bps.to_string(),
        );
        metric(
            "complete",
            "1 if the download is complete, else 0",
            "gauge",
            if self.complete { "1" } else { "0" }.to_string(),
        );
        out
    }
}

/// Host part of a `Host` or `Origin` header value: strips any scheme,
/// path and port. IPv6 literals keep their brackets (`[::1]:8317` →
/// `[::1]`); compare via [`is_loopback_host`] which tolerates them.
fn host_part(value: &str) -> Option<&str> {
    let rest = value.split_once("://").map(|(_, r)| r).unwrap_or(value);
    let authority = rest.split(['/', '?', '#']).next()?;
    if let Some(end) = authority.rfind(']') {
        return Some(&authority[..=end]);
    }
    Some(
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority),
    )
}

/// True for the loopback names a legitimate local client sends in
/// `Host`/`Origin`. Anything else — a rebound public hostname, a LAN
/// name, an attacker's origin — is rejected by [`csrf_guard`].
fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.trim_matches(['[', ']']),
        "127.0.0.1" | "::1" | "localhost"
    )
}

/// Loopback-only request guard applied to both web routers.
///
/// The servers bind `127.0.0.1`, but that alone does not stop a browser:
///
/// 1. DNS rebinding — a page at `https://evil.example` re-resolves its
///    own name to `127.0.0.1`; the browser happily talks to our port
///    while sending `Host: evil.example`. Rejecting non-loopback Host
///    headers kills the whole class (including read endpoints).
/// 2. Drive-by CSRF — any web page can issue cross-site POSTs to
///    `http://127.0.0.1:<port>/api/...`; browsers attach an `Origin`
///    header to such fetches even though CORS blocks reading the
///    response. A mutating POST carrying a non-loopback Origin is
///    refused; header-less clients (curl, scripts) pass.
async fn csrf_guard(req: Request, next: Next) -> Response {
    let host_ok = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(host_part)
        .map(is_loopback_host)
        .unwrap_or(false);
    if !host_ok {
        return (StatusCode::FORBIDDEN, "foreign Host header").into_response();
    }
    if req.method() == Method::POST {
        let origin_ok = req
            .headers()
            .get(ORIGIN)
            .and_then(|o| o.to_str().ok())
            .and_then(host_part)
            .map(is_loopback_host)
            .unwrap_or(true); // no Origin → not a browser fetch
        if !origin_ok {
            return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
        }
    }
    next.run(req).await
}

/// Build the monitoring + control router. Split out from [`serve`] so
/// tests can drive it over an ephemeral listener.
pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status_json))
        .route("/api/peers", get(peers_json))
        .route("/api/files", get(files_json))
        .route("/api/pause", post(pause))
        .route("/api/resume", post(resume))
        .route("/api/shutdown", post(shutdown))
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn(csrf_guard))
        .with_state(state)
}

/// Spawn the monitoring server on `127.0.0.1:port`, reading the latest
/// stats from `rx` and forwarding pause/resume to `ctl`. Runs until the
/// process exits (or the bind fails, in which case it logs and returns —
/// monitoring is non-essential and must never take down a download).
pub async fn serve(port: u16, rx: watch::Receiver<EngineStats>, ctl: mpsc::Sender<EngineControl>) {
    let app = router(WebState { rx, ctl });
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(target: "web", %addr, error = %e, "web server bind failed; monitoring disabled");
            return;
        }
    };
    tracing::info!(target: "web", %addr, "monitoring UI at http://{addr}/");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::warn!(target: "web", error = %e, "web server stopped");
    }
}

async fn status_json(State(st): State<WebState>) -> impl IntoResponse {
    let stats = st.rx.borrow().clone();
    // Hand to axum's Json so the name field is correctly escaped.
    axum::Json(stats)
}

async fn peers_json(State(st): State<WebState>) -> impl IntoResponse {
    let peers = st.rx.borrow().peers.clone();
    axum::Json(peers)
}

async fn files_json(State(st): State<WebState>) -> impl IntoResponse {
    let files = st.rx.borrow().files.clone();
    axum::Json(files)
}

async fn metrics(State(st): State<WebState>) -> impl IntoResponse {
    let body = st.rx.borrow().render_prometheus();
    ([("content-type", "text/plain; version=0.0.4")], body)
}

async fn pause(State(st): State<WebState>) -> impl IntoResponse {
    control(&st, EngineControl::Pause).await
}

async fn resume(State(st): State<WebState>) -> impl IntoResponse {
    control(&st, EngineControl::Resume).await
}

async fn shutdown(State(st): State<WebState>) -> impl IntoResponse {
    control(&st, EngineControl::Shutdown).await
}

async fn control(st: &WebState, cmd: EngineControl) -> impl IntoResponse {
    match st.ctl.send(cmd).await {
        Ok(()) => (StatusCode::OK, "ok"),
        // The engine loop is gone (shutting down) — report it rather
        // than pretend success.
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "engine unavailable"),
    }
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

// ---- Multi-torrent daemon router ----

/// Everything the daemon web handlers need: the session map plus the
/// template for building a config when a torrent is added at runtime.
#[derive(Clone)]
pub struct DaemonState {
    pub mgr: SessionManager,
    pub output: std::path::PathBuf,
    pub peer_id: crate::peer_id::PeerId,
    /// The shared listen port (all sessions share one acceptor on it).
    pub base_port: u16,
    /// Whether the daemon's shared DHT is disabled. Runtime-added
    /// torrents opt into the DHT unless this is set; the `SessionManager`
    /// downgrades the request to off when there's no shared DHT.
    pub no_dht: bool,
    /// Directory the runtime `POST /api/add` path must live under. The
    /// request body path is canonicalized and rejected unless it resolves
    /// inside this dir — so a loopback foothold (co-hosted XSS, a
    /// container sharing localhost) can't coerce the daemon into reading
    /// arbitrary host files. Startup positional torrents bypass this;
    /// they're trusted CLI input.
    pub torrent_dir: std::path::PathBuf,
}

/// Resolve `requested` and require it to live under `dir`. Both are
/// canonicalized (following symlinks, collapsing `..`) so a path like
/// `dir/../../etc/passwd` or a symlink escape is caught. Returns the
/// canonical path on success, or an error string for the 403 body.
/// `dir` itself is canonicalized per call — cheap (one stat) and keeps
/// the check correct if the dir is created/replaced after startup.
fn resolve_under(
    dir: &std::path::Path,
    requested: &str,
) -> std::result::Result<std::path::PathBuf, String> {
    let base = dir
        .canonicalize()
        .map_err(|e| format!("torrent dir {}: {e}", dir.display()))?;
    let full = std::path::Path::new(requested)
        .canonicalize()
        .map_err(|e| format!("resolve {requested}: {e}"))?;
    if full.starts_with(&base) {
        Ok(full)
    } else {
        Err(format!(
            "path {requested} is outside the permitted torrent dir"
        ))
    }
}

/// Build the daemon router. `GET /api/status` returns an *array* of
/// per-session stats; control is per info-hash; `POST /api/add` takes a
/// server-side `.torrent` path and starts hosting it.
pub fn daemon_router(state: DaemonState) -> Router {
    Router::new()
        .route("/", get(daemon_index))
        .route("/api/status", get(daemon_status))
        .route("/api/add", post(daemon_add))
        .route("/api/add_magnet", post(daemon_add_magnet))
        .route("/api/torrent/:ih/pause", post(daemon_pause))
        .route("/api/torrent/:ih/resume", post(daemon_resume))
        .route("/api/torrent/:ih/remove", post(daemon_remove))
        .layer(middleware::from_fn(csrf_guard))
        .with_state(state)
}

/// Serve the daemon UI/API on `127.0.0.1:port` (loopback only, same as
/// the single-torrent server).
pub async fn serve_daemon(port: u16, state: DaemonState) {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(target: "web", %addr, error = %e, "daemon web bind failed");
            return;
        }
    };
    tracing::info!(target: "web", %addr, "daemon UI at http://{addr}/");
    if let Err(e) = axum::serve(listener, daemon_router(state)).await {
        tracing::warn!(target: "web", error = %e, "daemon web server stopped");
    }
}

async fn daemon_status(State(st): State<DaemonState>) -> impl IntoResponse {
    axum::Json(st.mgr.snapshot().await)
}

/// Add a torrent at runtime. The (loopback) request body is a path to a
/// `.torrent` file on the daemon host. Returns the info-hash hex on
/// success. Magnet add is a follow-up (needs the metadata-fetch flow).
async fn daemon_add(State(st): State<DaemonState>, body: String) -> impl IntoResponse {
    let path = body.trim();
    if path.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty path".to_string());
    }
    // Containment check first — never touch a path outside the permitted
    // dir, not even to stat it via fs::read's error.
    let safe = match resolve_under(&st.torrent_dir, path) {
        Ok(p) => p,
        Err(e) => return (StatusCode::FORBIDDEN, e),
    };
    let raw = match tokio::fs::read(&safe).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("read {path}: {e}")),
    };
    let torrent = match crate::metainfo::TorrentFile::from_bytes(&raw) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("parse {path}: {e}")),
    };
    let cfg = crate::engine::EngineConfig {
        output_dir: st.output.clone(),
        // The SessionManager routes inbound through the shared acceptor and
        // overrides this with the shared port; it's only the announce port.
        listen_port: st.base_port,
        // Opt into the shared DHT; the manager downgrades to off when the
        // daemon ran --no-dht (or the torrent is private).
        enable_dht: !st.no_dht,
        ..Default::default()
    };
    match st.mgr.add_persistent(torrent, st.peer_id, cfg, &raw).await {
        Some(ih) => (StatusCode::OK, crate::util::hex(&ih)),
        None => (StatusCode::CONFLICT, "already running".to_string()),
    }
}

/// Build `.torrent` bytes from a (verified) raw info-dict and a tracker
/// list. The info dict is spliced in **verbatim**, so the info-hash is
/// preserved exactly — we must never re-encode it (key reordering would
/// change the hash). Top-level keys are emitted in bencode-canonical
/// order: `announce` < `announce-list` < `info`. Used to persist a
/// magnet-added torrent so the daemon can resume it after a restart.
fn assemble_torrent_bytes(info_bytes: &[u8], trackers: &[String]) -> Vec<u8> {
    fn push_bstr(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(s.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(s);
    }
    let mut out = Vec::with_capacity(info_bytes.len() + 64);
    out.push(b'd');
    if let Some(first) = trackers.first() {
        push_bstr(&mut out, b"announce");
        push_bstr(&mut out, first.as_bytes());
    }
    if !trackers.is_empty() {
        push_bstr(&mut out, b"announce-list");
        out.push(b'l');
        for t in trackers {
            out.push(b'l');
            push_bstr(&mut out, t.as_bytes());
            out.push(b'e');
        }
        out.push(b'e');
    }
    push_bstr(&mut out, b"info");
    out.extend_from_slice(info_bytes); // verbatim — preserves info_hash
    out.push(b'e');
    out
}

/// Add a torrent from a `magnet:?xt=urn:btih:…` URI at runtime.
///
/// Metadata fetch can take many seconds (tracker bootstrap + BEP 9
/// `ut_metadata` from peers), so we do NOT block the request: parse and
/// dup-check synchronously, then spawn a background task that bootstraps
/// peers, fetches the info dict, and registers the session once it
/// lands. Returns `202 Accepted` with the info-hash hex immediately —
/// the caller polls `/api/status` for the session to appear.
///
/// Daemon v1 is tracker-only (DHT off), so the peer pool comes solely
/// from the magnet's `tr=` trackers; a magnet without trackers can't be
/// bootstrapped here and is rejected up front.
async fn daemon_add_magnet(State(st): State<DaemonState>, body: String) -> impl IntoResponse {
    let magnet = match crate::magnet::MagnetLink::parse(body.trim()) {
        Ok(m) => m,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("parse magnet: {e}")),
    };
    let info_hash = magnet.info_hash;
    // Cheap early dup check so we don't kick off an expensive fetch for a
    // torrent we already host. `add` re-checks atomically at insert.
    if st.mgr.contains(&info_hash).await {
        return (StatusCode::CONFLICT, "already running".to_string());
    }
    if magnet.trackers.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "magnet has no trackers; daemon v1 is tracker-only (DHT off) and can't \
             bootstrap peers without them"
                .to_string(),
        );
    }

    let ih_hex = crate::util::hex(&info_hash);
    tokio::spawn(async move {
        // Tracker bootstrap. No proxy / non-anonymous in daemon v1.
        let req = crate::tracker::AnnounceRequest {
            info_hash,
            peer_id: st.peer_id,
            port: st.base_port,
            uploaded: 0,
            downloaded: 0,
            left: 0, // metadata unknown at the magnet stage
            event: crate::tracker::Event::Started,
            num_want: 50,
        };
        let mut pool: Vec<SocketAddr> = Vec::new();
        for url in &magnet.trackers {
            match crate::tracker::announce_with_proxy_anon(url, &req, None, false, None).await {
                Ok(resp) => {
                    // Daemon runs clearnet-only (no anonymous/proxy knobs),
                    // so the non-strict half applies TODAY: refuse the
                    // martians a tracker can hand us (loopback, link-local
                    // metadata endpoint, multicast, ...). The constant makes
                    // the implicit coupling explicit and greppable: if the
                    // daemon ever gains anonymity knobs, replace with
                    // strict = anonymous || proxied like the engine does.
                    const DAEMON_MARTIANS_STRICT: bool = false;
                    pool.extend(
                        resp.peers.into_iter().filter(|a| {
                            crate::util::is_dialable_peer_addr(a, DAEMON_MARTIANS_STRICT)
                        }),
                    );
                }
                Err(e) => {
                    tracing::debug!(target: "web", tracker = %crate::tracker::redact_url_query(url), error = %e, "magnet tracker bootstrap failed")
                }
            }
        }
        pool.sort();
        pool.dedup();
        if pool.is_empty() {
            tracing::warn!(target: "web", info_hash = %crate::util::hex(&info_hash), "magnet add: no peers from trackers; giving up");
            return;
        }

        let info_bytes = match crate::peer::metadata_fetch::fetch_metadata(
            info_hash,
            pool,
            Vec::new(),
            false,
            None,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(target: "web", info_hash = %crate::util::hex(&info_hash), error = %e, "magnet add: metadata fetch failed");
                return;
            }
        };
        let torrent = match crate::metainfo::TorrentFile::from_info_dict_bytes(
            &info_bytes,
            info_hash,
            magnet.trackers.clone(),
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(target: "web", error = %e, "magnet add: info dict parse/verify failed");
                return;
            }
        };
        // Assemble `.torrent` bytes (info dict verbatim → info_hash
        // preserved) so the daemon can persist + resume this magnet add.
        let raw_torrent = assemble_torrent_bytes(&info_bytes, &magnet.trackers);
        let cfg = crate::engine::EngineConfig {
            output_dir: st.output.clone(),
            listen_port: st.base_port,
            enable_dht: !st.no_dht,
            ..Default::default()
        };
        match st
            .mgr
            .add_persistent(torrent, st.peer_id, cfg, &raw_torrent)
            .await
        {
            Some(ih) => {
                tracing::info!(target: "web", info_hash = %crate::util::hex(&ih), "magnet add: session started")
            }
            None => {
                tracing::info!(target: "web", info_hash = %crate::util::hex(&info_hash), "magnet add: already running (raced)")
            }
        }
    });

    (StatusCode::ACCEPTED, ih_hex)
}

async fn daemon_pause(State(st): State<DaemonState>, Path(ih): Path<String>) -> impl IntoResponse {
    daemon_ctl(&st.mgr, &ih, EngineControl::Pause).await
}
async fn daemon_resume(State(st): State<DaemonState>, Path(ih): Path<String>) -> impl IntoResponse {
    daemon_ctl(&st.mgr, &ih, EngineControl::Resume).await
}
async fn daemon_remove(State(st): State<DaemonState>, Path(ih): Path<String>) -> impl IntoResponse {
    let Some(h) = crate::util::info_hash_from_hex(&ih) else {
        return (StatusCode::BAD_REQUEST, "bad info_hash");
    };
    if st.mgr.remove(&h).await {
        (StatusCode::OK, "removed")
    } else {
        (StatusCode::NOT_FOUND, "no such torrent")
    }
}

async fn daemon_ctl(
    mgr: &SessionManager,
    ih: &str,
    cmd: EngineControl,
) -> (StatusCode, &'static str) {
    let Some(h) = crate::util::info_hash_from_hex(ih) else {
        return (StatusCode::BAD_REQUEST, "bad info_hash");
    };
    if mgr.control(&h, cmd).await {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::NOT_FOUND, "no such torrent")
    }
}

async fn daemon_index() -> Html<&'static str> {
    Html(DAEMON_HTML)
}

/// Multi-torrent dashboard: a row per torrent with a progress bar and
/// pause/resume/remove actions. Polls the array endpoint once a second.
const DAEMON_HTML: &str = r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RustyTorrent — daemon</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.25rem; }
  .t { border: 1px solid #eee; border-radius: 6px; padding: .75rem 1rem; margin: .75rem 0; }
  .row { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; }
  .name { font-weight: 600; word-break: break-all; }
  .bar { height: 1rem; background: #eee; border-radius: 4px; overflow: hidden; margin: .4rem 0; }
  .fill { height: 100%; background: #2d7; width: 0; transition: width .3s; }
  .done .fill { background: #29f; }
  .meta { color: #666; font-size: 13px; }
  button { font: inherit; padding: .1rem .5rem; cursor: pointer; margin-left: .25rem; }
  .empty { color: #999; }
</style></head><body>
<h1>RustyTorrent <span class="meta" id="count"></span></h1>
<form id="addform" style="margin:.5rem 0">
  <input id="addpath" type="text" placeholder="path to a .torrent on the daemon host, or a magnet: link" style="width:70%;font:inherit;padding:.2rem .4rem">
  <button type="submit">Add</button>
  <span class="meta" id="addmsg"></span>
</form>
<div id="list"><p class="empty">Loading…</p></div>
<script>
const fmtBytes = b => { const u=["B","KiB","MiB","GiB","TiB"]; let i=0; b=Number(b); while(b>=1024&&i<u.length-1){b/=1024;i++;} return b.toFixed(i?1:0)+" "+u[i]; };
document.getElementById("addform").addEventListener("submit", async (e) => {
  e.preventDefault();
  const path = document.getElementById("addpath").value.trim();
  if (!path) return;
  const msg = document.getElementById("addmsg");
  // Route magnet links to the async add_magnet endpoint; everything else
  // is treated as a server-side .torrent path.
  const isMagnet = path.toLowerCase().startsWith("magnet:");
  const url = isMagnet ? "/api/add_magnet" : "/api/add";
  try {
    const r = await fetch(url, { method:"POST", body: path });
    if (r.ok) {
      msg.textContent = isMagnet ? "fetching metadata…" : "added";
      document.getElementById("addpath").value = "";
    } else {
      msg.textContent = "error: " + (await r.text());
    }
    await tick();
  } catch (err) { msg.textContent = "error"; }
});
async function act(ih, action) { try { await fetch(`/api/torrent/${ih}/${action}`, {method:"POST"}); await tick(); } catch(e){} }
async function tick() {
  let list;
  try { list = await (await fetch("/api/status")).json(); } catch(e){ return; }
  document.getElementById("count").textContent = list.length ? `(${list.length})` : "";
  const root = document.getElementById("list");
  if (!list.length) { root.innerHTML = '<p class="empty">No torrents.</p>'; return; }
  root.innerHTML = "";
  for (const s of list) {
    const frac = s.total_pieces ? s.complete_pieces/s.total_pieces : 1;
    const div = document.createElement("div");
    div.className = "t" + (s.complete ? " done" : "");
    const head = document.createElement("div"); head.className = "row";
    const name = document.createElement("span"); name.className = "name"; name.textContent = s.name;
    const pct = document.createElement("span"); pct.className = "meta";
    pct.textContent = (frac*100).toFixed(1) + "%" + (s.complete?" ✓":s.paused?" (paused)":"");
    head.append(name, pct);
    const bar = document.createElement("div"); bar.className = "bar";
    const fill = document.createElement("div"); fill.className = "fill"; fill.style.width=(frac*100).toFixed(1)+"%";
    bar.appendChild(fill);
    const meta = document.createElement("div"); meta.className = "row meta";
    const stat = document.createElement("span");
    stat.textContent = `${fmtBytes(s.downloaded_bytes)} / ${fmtBytes(s.total_bytes)} · ↓${fmtBytes(s.down_rate_bps)}/s · ${s.peers_connected} peers`;
    const actions = document.createElement("span");
    const pause = document.createElement("button");
    pause.textContent = s.paused ? "Resume" : "Pause";
    pause.onclick = () => act(s.info_hash, s.paused ? "resume" : "pause");
    const rm = document.createElement("button"); rm.textContent = "Remove";
    rm.onclick = () => { if (confirm("Remove " + s.name + "?")) act(s.info_hash, "remove"); };
    actions.append(pause, rm);
    meta.append(stat, actions);
    div.append(head, bar, meta);
    root.appendChild(div);
  }
}
tick(); setInterval(tick, 1000);
</script></body></html>
"##;

/// Self-contained status page — no external assets, polls `/api/status`
/// once a second and redraws a progress bar + counters.
const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RustyTorrent</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.25rem; }
  .bar { height: 1.25rem; background: #eee; border-radius: 4px; overflow: hidden; }
  .fill { height: 100%; background: #2d7; width: 0; transition: width .3s; }
  .grid { display: grid; grid-template-columns: auto 1fr; gap: .25rem 1rem; margin-top: 1rem; }
  .k { color: #666; }
  .mono { font-family: ui-monospace, monospace; }
  .done .fill { background: #29f; }
</style>
</head>
<body>
  <h1 id="name">RustyTorrent <button id="stop" style="float:right;font:inherit;padding:.15rem .6rem;cursor:pointer;margin-left:.4rem">Stop</button><button id="pause" style="float:right;font:inherit;padding:.15rem .6rem;cursor:pointer">Pause</button></h1>
  <div class="bar"><div class="fill" id="fill"></div></div>
  <canvas id="spark" width="608" height="56" style="width:100%;height:56px;margin-top:1rem;background:#fafafa;border-radius:4px"></canvas>
  <div class="k" style="text-align:right;font-size:12px" id="sparkmax">—</div>
  <div class="grid">
    <span class="k">Progress</span><span id="pct">—</span>
    <span class="k">Pieces</span><span id="pieces">—</span>
    <span class="k">Downloaded</span><span id="down">—</span>
    <span class="k">Uploaded</span><span id="up">—</span>
    <span class="k">Down rate</span><span id="rate">—</span>
    <span class="k">Up rate</span><span id="urate">—</span>
    <span class="k">Peers</span><span id="peers">—</span>
    <span class="k">ETA</span><span id="eta">—</span>
    <span class="k">Elapsed</span><span id="elapsed">—</span>
    <span class="k">Info hash</span><span class="mono" id="ih">—</span>
  </div>
  <details id="filesbox" style="margin-top:1rem" hidden>
    <summary class="k">Files (<span id="fcount">0</span>)</summary>
    <table id="files" style="width:100%;border-collapse:collapse;margin-top:.5rem;font-size:13px"></table>
  </details>
  <details style="margin-top:1rem">
    <summary class="k">Connected peers (<span id="pcount">0</span>)</summary>
    <ul class="mono" id="peers" style="margin:.5rem 0 0; padding-left:1.25rem"></ul>
  </details>
<script>
const fmtBytes = b => {
  const u = ["B","KiB","MiB","GiB","TiB"]; let i = 0; b = Number(b);
  while (b >= 1024 && i < u.length-1) { b /= 1024; i++; }
  return b.toFixed(i ? 1 : 0) + " " + u[i];
};
const fmtDur = s => {
  s = Number(s); const h = Math.floor(s/3600), m = Math.floor(s%3600/60), sec = s%60;
  return (h?h+"h ":"") + (m||h?m+"m ":"") + sec + "s";
};
// Rolling download-rate history for the sparkline (last ~2 minutes at 1s).
const HIST = 120;
const rates = [];
function drawSpark() {
  const c = document.getElementById("spark"), ctx = c.getContext("2d");
  const w = c.width, h = c.height;
  ctx.clearRect(0, 0, w, h);
  if (rates.length < 2) return;
  const max = Math.max(1, ...rates);
  document.getElementById("sparkmax").textContent = "peak " + fmtBytes(max) + "/s";
  ctx.beginPath();
  rates.forEach((r, i) => {
    const x = (i / (HIST - 1)) * w;
    const y = h - (r / max) * (h - 4) - 2;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.strokeStyle = "#2d7"; ctx.lineWidth = 1.5; ctx.stroke();
  ctx.lineTo((rates.length - 1) / (HIST - 1) * w, h);
  ctx.lineTo(0, h); ctx.closePath();
  ctx.fillStyle = "rgba(34,221,119,.12)"; ctx.fill();
}
async function tick() {
  try {
    const s = await (await fetch("/api/status")).json();
    const frac = s.total_pieces ? s.complete_pieces / s.total_pieces : 1;
    document.getElementById("name").textContent = s.name || "RustyTorrent";
    document.title = (s.complete ? "✓ " : Math.round(frac*100)+"% ") + (s.name||"RustyTorrent");
    document.getElementById("fill").style.width = (frac*100).toFixed(1) + "%";
    document.body.classList.toggle("done", !!s.complete);
    document.getElementById("pct").textContent = (frac*100).toFixed(1) + "%" + (s.complete ? " (complete)" : "");
    document.getElementById("pieces").textContent = s.complete_pieces + " / " + s.total_pieces;
    document.getElementById("down").textContent = fmtBytes(s.downloaded_bytes) + " / " + fmtBytes(s.total_bytes);
    document.getElementById("up").textContent = fmtBytes(s.uploaded_bytes);
    document.getElementById("rate").textContent = fmtBytes(s.down_rate_bps) + "/s";
    document.getElementById("urate").textContent = fmtBytes(s.up_rate_bps) + "/s";
    rates.push(Number(s.down_rate_bps) || 0);
    if (rates.length > HIST) rates.shift();
    drawSpark();
    document.getElementById("peers").textContent = s.peers_connected;
    let eta = "—";
    if (s.complete) eta = "done";
    else if (s.paused) eta = "paused";
    else if (s.down_rate_bps > 0 && s.remaining_bytes > 0)
      eta = fmtDur(Math.round(s.remaining_bytes / s.down_rate_bps));
    document.getElementById("eta").textContent = eta;
    document.getElementById("elapsed").textContent = fmtDur(s.elapsed_secs);
    document.getElementById("ih").textContent = s.info_hash;
    const btn = document.getElementById("pause");
    btn.textContent = s.paused ? "Resume" : "Pause";
    btn.dataset.action = s.paused ? "resume" : "pause";
    const peers = s.peers || [];
    document.getElementById("pcount").textContent = peers.length;
    const ul = document.getElementById("peers");
    ul.innerHTML = "";
    for (const p of peers) {
      const li = document.createElement("li");
      li.textContent = p; // textContent — never innerHTML, so a hostile
                          // peer address can't inject markup
      ul.appendChild(li);
    }
    const files = s.files || [];
    document.getElementById("filesbox").hidden = files.length === 0;
    document.getElementById("fcount").textContent = files.length;
    const tbl = document.getElementById("files");
    tbl.innerHTML = "";
    for (const f of files) {
      const tr = document.createElement("tr");
      tr.style.opacity = f.wanted ? "1" : "0.5";
      const name = document.createElement("td");
      name.textContent = f.path; // textContent — paths come from the torrent
      name.style.cssText = "padding:1px 8px 1px 0;font-family:ui-monospace,monospace;word-break:break-all";
      const pct = document.createElement("td");
      pct.textContent = (f.wanted ? "" : "(skipped) ") + Math.round((f.fraction||0)*100) + "%";
      pct.style.cssText = "text-align:right;white-space:nowrap;color:#666";
      const sz = document.createElement("td");
      sz.textContent = fmtBytes(f.length);
      sz.style.cssText = "text-align:right;white-space:nowrap;color:#999;padding-left:8px";
      tr.append(name, pct, sz);
      tbl.appendChild(tr);
    }
  } catch (e) { /* engine gone or starting — keep last values */ }
}
document.getElementById("pause").addEventListener("click", async (e) => {
  const action = e.target.dataset.action || "pause";
  try { await fetch("/api/" + action, { method: "POST" }); await tick(); }
  catch (err) { /* engine gone */ }
});
document.getElementById("stop").addEventListener("click", async () => {
  if (!confirm("Stop the download and exit? (graceful shutdown)")) return;
  try { await fetch("/api/shutdown", { method: "POST" }); } catch (err) {}
});
tick(); setInterval(tick, 1000);
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EngineStats {
        EngineStats {
            name: "ubuntu \"24.04\".iso".into(), // embedded quotes → JSON-escape check
            info_hash: "0123456789abcdef0123456789abcdef01234567".into(),
            complete_pieces: 50,
            total_pieces: 200,
            downloaded_bytes: 1024 * 1024,
            uploaded_bytes: 4096,
            total_bytes: 4 * 1024 * 1024,
            peers_connected: 7,
            elapsed_secs: 90,
            down_rate_bps: 11_000,
            up_rate_bps: 2_000,
            complete: false,
            paused: false,
            remaining_bytes: 3 * 1024 * 1024,
            peers: vec!["1.2.3.4:6881".into(), "[::1]:51413".into()],
            files: vec![FileProgress {
                path: "a/b.txt".into(),
                length: 1234,
                fraction: 0.5,
                wanted: true,
            }],
        }
    }

    #[test]
    fn fraction_is_ratio_and_handles_empty() {
        assert!((sample().fraction() - 0.25).abs() < 1e-9);
        let mut s = sample();
        s.total_pieces = 0;
        assert_eq!(s.fraction(), 1.0, "zero-piece torrent reads as complete");
    }

    #[test]
    fn json_escapes_name() {
        let json = serde_json::to_string(&sample()).unwrap();
        // serde_json must escape the embedded quotes — a hand-rolled
        // encoder is exactly what this guards against.
        assert!(
            json.contains(r#""name":"ubuntu \"24.04\".iso""#),
            "got: {json}"
        );
        assert!(json.contains(r#""peers_connected":7"#));
        assert!(json.contains(r#""complete":false"#));
    }

    #[test]
    fn prometheus_has_expected_series() {
        let p = sample().render_prometheus();
        assert!(p.contains(
            "rustytorrent_complete_pieces{info_hash=\"0123456789abcdef0123456789abcdef01234567\"} 50"
        ));
        assert!(p.contains("rustytorrent_peers_connected{info_hash=\"0123456789abcdef0123456789abcdef01234567\"} 7"));
        assert!(p.contains(
            "rustytorrent_complete{info_hash=\"0123456789abcdef0123456789abcdef01234567\"} 0"
        ));
        assert!(p.contains(
            "rustytorrent_up_rate_bps{info_hash=\"0123456789abcdef0123456789abcdef01234567\"} 2000"
        ));
        // Every metric must carry HELP + TYPE lines.
        assert_eq!(p.matches("# HELP ").count(), p.matches("# TYPE ").count());
        assert!(p.matches("# TYPE ").count() >= 9);
    }

    #[test]
    fn resolve_under_accepts_inside_rejects_escape() {
        // Unique scratch dir under the system temp, no external crates.
        let base = std::env::temp_dir().join(format!("rt_resolve_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();

        // A real file inside the dir resolves and passes.
        let inside = base.join("a.torrent");
        std::fs::write(&inside, b"x").unwrap();
        let ok = resolve_under(&base, inside.to_str().unwrap()).unwrap();
        assert!(ok.starts_with(base.canonicalize().unwrap()));

        // A traversal escape is rejected (doesn't resolve inside).
        let escape = format!("{}/../../etc/hosts", base.display());
        assert!(resolve_under(&base, &escape).is_err());

        // An absolute path to a well-known outside file exists but is
        // outside the dir → Err (not a resolve failure).
        let outside = resolve_under(&base, "/etc/hosts");
        if let Ok(p) = &outside {
            assert!(!p.starts_with(base.canonicalize().unwrap()));
        }
        assert!(outside.is_err());

        // A nonexistent path inside the dir fails to canonicalize → Err,
        // so we never hand a missing path to fs::read.
        assert!(resolve_under(&base, base.join("nope.torrent").to_str().unwrap()).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn assemble_torrent_bytes_preserves_info_hash() {
        use crate::metainfo::TorrentFile;
        use sha1::{Digest, Sha1};
        // A minimal valid info dict; its SHA-1 is the info-hash.
        let mut info = Vec::new();
        info.extend_from_slice(b"d6:lengthi16384e4:name5:t.bin12:piece lengthi16384e6:pieces20:");
        info.extend_from_slice(&[0u8; 20]);
        info.push(b'e');

        let trackers = vec![
            "http://a.example/announce".to_string(),
            "http://b.example/announce".to_string(),
        ];
        let bytes = assemble_torrent_bytes(&info, &trackers);

        // Round-trips through the parser, and the info-hash equals the
        // SHA-1 of the verbatim info dict — proving we didn't re-encode it.
        let t = TorrentFile::from_bytes(&bytes).unwrap();
        let mut h = Sha1::new();
        h.update(&info);
        let expected: [u8; 20] = h.finalize().into();
        assert_eq!(t.info_hash, expected);
        assert_eq!(t.info.name, "t.bin");
        assert_eq!(t.announce.as_deref(), Some("http://a.example/announce"));
        assert_eq!(t.announce_list.len(), 2);
    }

    #[test]
    fn assemble_torrent_bytes_no_trackers_is_valid() {
        use crate::metainfo::TorrentFile;
        let mut info = Vec::new();
        info.extend_from_slice(b"d6:lengthi16384e4:name5:t.bin12:piece lengthi16384e6:pieces20:");
        info.extend_from_slice(&[0u8; 20]);
        info.push(b'e');
        let bytes = assemble_torrent_bytes(&info, &[]);
        let t = TorrentFile::from_bytes(&bytes).unwrap();
        assert_eq!(t.info.name, "t.bin");
        assert!(t.announce.is_none());
    }

    #[test]
    fn host_part_parses_authority_forms() {
        assert_eq!(host_part("127.0.0.1:8317"), Some("127.0.0.1"));
        assert_eq!(host_part("localhost"), Some("localhost"));
        assert_eq!(host_part("[::1]:9000"), Some("[::1]"));
        // Origin form: scheme + optional path.
        assert_eq!(host_part("https://evil.example/x?y"), Some("evil.example"));
        assert_eq!(host_part("http://127.0.0.1:8317"), Some("127.0.0.1"));
        // Garbage still yields something parseable or None — never panic.
        assert_eq!(host_part(""), Some(""));
    }

    #[test]
    fn loopback_host_accepts_only_loopback_names() {
        for ok in ["127.0.0.1", "::1", "[::1]", "localhost"] {
            assert!(is_loopback_host(ok), "{ok} should be loopback");
        }
        for bad in ["", "evil.example", "[fe80::1]", "127.0.0.2"] {
            assert!(!is_loopback_host(bad), "{bad} must NOT be loopback");
        }
    }

    // ---- csrf_guard integration through the real router ----

    mod guard {
        use super::*;
        use axum::body::Body;
        use tower::ServiceExt;

        fn app() -> (axum::Router, mpsc::Receiver<EngineControl>) {
            let (_tx, rx) = tokio::sync::watch::channel(sample());
            let (ctl, ctl_rx) = mpsc::channel::<EngineControl>(4);
            (
                router(WebState { rx, ctl }),
                // The caller must keep this alive: dropping it makes every
                // control POST legitimately answer 503.
                ctl_rx,
            )
        }

        async fn respond(
            method: &str,
            uri: &str,
            host: Option<&str>,
            origin: Option<&str>,
        ) -> StatusCode {
            let (a, _ctl_rx) = app();
            let mut b = axum::http::Request::builder().method(method).uri(uri);
            if let Some(h) = host {
                b = b.header("host", h);
            }
            if let Some(o) = origin {
                b = b.header("origin", o);
            }
            let resp = a.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
            resp.status()
        }

        #[tokio::test]
        async fn rebound_or_missing_host_is_rejected_everywhere() {
            assert_eq!(
                respond("GET", "/api/status", Some("evil.example"), None).await,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                respond("GET", "/api/status", None, None).await,
                StatusCode::FORBIDDEN
            );
        }

        #[tokio::test]
        async fn loopback_hosts_are_served() {
            assert_eq!(
                respond("GET", "/api/status", Some("127.0.0.1:8317"), None).await,
                StatusCode::OK
            );
            assert_eq!(
                respond("GET", "/metrics", Some("localhost:8317"), None).await,
                StatusCode::OK
            );
        }

        #[tokio::test]
        async fn cross_origin_post_is_rejected() {
            // Drive-by CSRF: a page at evil.example POSTing to loopback.
            assert_eq!(
                respond(
                    "POST",
                    "/api/pause",
                    Some("127.0.0.1:8317"),
                    Some("https://evil.example")
                )
                .await,
                StatusCode::FORBIDDEN
            );
        }

        #[tokio::test]
        async fn headerless_client_post_passes() {
            // curl / scripts send no Origin — the trusted local case.
            assert_eq!(
                respond("POST", "/api/pause", Some("127.0.0.1:8317"), None).await,
                StatusCode::OK
            );
        }

        #[tokio::test]
        async fn same_origin_browser_post_passes() {
            // The bundled UI's own fetches carry a loopback Origin.
            assert_eq!(
                respond(
                    "POST",
                    "/api/pause",
                    Some("127.0.0.1:8317"),
                    Some("http://127.0.0.1:8317")
                )
                .await,
                StatusCode::OK
            );
        }
    }
}
