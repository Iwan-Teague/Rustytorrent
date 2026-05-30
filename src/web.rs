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

use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use tokio::sync::watch;

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
    /// Addresses of the currently-connected peers (`ip:port`). Loopback-
    /// only endpoint, so listing the swarm we're talking to is fine.
    pub peers: Vec<String>,
}

impl EngineStats {
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

/// Build the monitoring router over a stats `watch` receiver. Split out
/// from [`serve`] so tests can drive it over an ephemeral listener.
pub fn router(rx: watch::Receiver<EngineStats>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status_json))
        .route("/api/peers", get(peers_json))
        .route("/metrics", get(metrics))
        .with_state(rx)
}

/// Spawn the monitoring server on `127.0.0.1:port`, reading the latest
/// stats from `rx`. Runs until the process exits (or the bind fails, in
/// which case it logs and returns — monitoring is non-essential and must
/// never take down a download).
pub async fn serve(port: u16, rx: watch::Receiver<EngineStats>) {
    let app = router(rx);
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

async fn status_json(State(rx): State<watch::Receiver<EngineStats>>) -> impl IntoResponse {
    let stats = rx.borrow().clone();
    // Hand to axum's Json so the name field is correctly escaped.
    axum::Json(stats)
}

async fn peers_json(State(rx): State<watch::Receiver<EngineStats>>) -> impl IntoResponse {
    let peers = rx.borrow().peers.clone();
    axum::Json(peers)
}

async fn metrics(State(rx): State<watch::Receiver<EngineStats>>) -> impl IntoResponse {
    let body = rx.borrow().render_prometheus();
    ([("content-type", "text/plain; version=0.0.4")], body)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

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
  <h1 id="name">RustyTorrent</h1>
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
    <span class="k">Elapsed</span><span id="elapsed">—</span>
    <span class="k">Info hash</span><span class="mono" id="ih">—</span>
  </div>
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
    document.getElementById("elapsed").textContent = fmtDur(s.elapsed_secs);
    document.getElementById("ih").textContent = s.info_hash;
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
  } catch (e) { /* engine gone or starting — keep last values */ }
}
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
            peers: vec!["1.2.3.4:6881".into(), "[::1]:51413".into()],
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
}
