use std::net::SocketAddr;
use std::time::Duration;

use crate::error::Result;
use crate::peer_id::PeerId;

pub mod http;
pub mod udp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    None,
    Started,
    Completed,
    Stopped,
}

impl Event {
    pub fn as_udp_code(self) -> u32 {
        match self {
            Event::None => 0,
            Event::Completed => 1,
            Event::Started => 2,
            Event::Stopped => 3,
        }
    }

    pub fn as_http_param(self) -> Option<&'static str> {
        match self {
            Event::None => None,
            Event::Started => Some("started"),
            Event::Completed => Some("completed"),
            Event::Stopped => Some("stopped"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub info_hash: [u8; 20],
    pub peer_id: PeerId,
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: Event,
    pub num_want: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceResponse {
    pub interval: Duration,
    pub min_interval: Option<Duration>,
    pub seeders: Option<u32>,
    pub leechers: Option<u32>,
    pub peers: Vec<SocketAddr>,
}

/// Announce against a tracker URL, dispatching to HTTP or UDP
/// based on scheme. Returns the parsed response.
pub async fn announce(url: &str, req: &AnnounceRequest) -> Result<AnnounceResponse> {
    announce_with_proxy(url, req, None).await
}

/// Announce against `url`, routing HTTP traffic through `proxy` if set.
/// UDP trackers are skipped entirely when a proxy is configured — UDP can't
/// ride through SOCKS5 CONNECT and would leak the real IP.
pub async fn announce_with_proxy(
    url: &str,
    req: &AnnounceRequest,
    proxy: Option<&crate::socks5::ProxyConfig>,
) -> Result<AnnounceResponse> {
    announce_with_proxy_anon(url, req, proxy, false).await
}

/// As `announce_with_proxy`, but when `anonymous` is true the HTTP
/// announce sends a libtorrent-style User-Agent instead of the
/// default `rustytorrent/<ver>` — the default UA is otherwise a
/// trivially-distinctive fingerprint at the tracker.
pub async fn announce_with_proxy_anon(
    url: &str,
    req: &AnnounceRequest,
    proxy: Option<&crate::socks5::ProxyConfig>,
    anonymous: bool,
) -> Result<AnnounceResponse> {
    if url.starts_with("udp://") {
        if proxy.is_some() {
            return Err(crate::error::Error::Tracker(format!(
                "skipping UDP tracker while proxy is configured: {url}"
            )));
        }
        udp::announce(url, req).await
    } else if url.starts_with("http://") || url.starts_with("https://") {
        http::announce_with_proxy_anon(url, req, proxy, anonymous).await
    } else {
        Err(crate::error::Error::Tracker(format!(
            "unsupported tracker scheme: {url}"
        )))
    }
}

/// Walk announce-list tiers (BEP 12). Returns the first successful response
/// and reports which URL worked, so the caller can move it to the front of
/// its tier for next announce.
pub async fn announce_with_fallback(
    tiers: &[Vec<String>],
    fallback_single: Option<&str>,
    req: &AnnounceRequest,
    proxy: Option<&crate::socks5::ProxyConfig>,
) -> Result<(String, AnnounceResponse)> {
    announce_with_fallback_anon(tiers, fallback_single, req, proxy, false).await
}

/// Anonymous-aware variant of `announce_with_fallback`: forwards the
/// `anonymous` flag down to the per-URL announce so HTTP requests
/// adopt the libtorrent-style User-Agent when set.
pub async fn announce_with_fallback_anon(
    tiers: &[Vec<String>],
    fallback_single: Option<&str>,
    req: &AnnounceRequest,
    proxy: Option<&crate::socks5::ProxyConfig>,
    anonymous: bool,
) -> Result<(String, AnnounceResponse)> {
    let mut last_err: Option<crate::error::Error> = None;
    for tier in tiers {
        for url in tier {
            match announce_with_proxy_anon(url, req, proxy, anonymous).await {
                Ok(r) => return Ok((url.clone(), r)),
                Err(e) => {
                    tracing::warn!(url = %url, error = %e, "tracker announce failed");
                    last_err = Some(e);
                }
            }
        }
    }
    if let Some(url) = fallback_single {
        match announce_with_proxy_anon(url, req, proxy, anonymous).await {
            Ok(r) => return Ok((url.to_string(), r)),
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "tracker announce failed");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| crate::error::Error::Tracker("no trackers configured".into())))
}
