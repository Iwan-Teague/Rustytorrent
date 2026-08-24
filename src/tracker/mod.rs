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
        if anonymous || proxy.is_some() {
            // Fail closed: UDP cannot ride the SOCKS5 CONNECT path, so
            // under anonymous mode a udp:// announce would egress the
            // real interface and leak our IP. Refuse outright — even
            // when no proxy is configured (an upstream gate could be
            // bypassed; this is the last line of defense).
            return Err(crate::error::Error::Tracker(format!(
                "skipping UDP tracker while proxy is configured or anonymous mode is on: {url}"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> AnnounceRequest {
        AnnounceRequest {
            info_hash: [7u8; 20],
            peer_id: crate::peer_id::generate(),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            event: Event::Started,
            num_want: 50,
        }
    }

    #[tokio::test]
    async fn udp_announce_refused_in_anonymous_mode_even_without_proxy() {
        // Host is deliberately unresolvable (.invalid TLD): the guard
        // must fire BEFORE any DNS or socket work, so the error is the
        // anonymity refusal — not a dns failure.
        let err = announce_with_proxy_anon("udp://anon-guard-test.invalid:80", &req(), None, true)
            .await
            .expect_err("anonymous UDP announce must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("skipping UDP tracker") && msg.contains("anonymous"),
            "expected anonymity refusal, got: {msg}"
        );
    }

    #[tokio::test]
    async fn udp_announce_guard_does_not_fire_without_anon_or_proxy() {
        // Mutation-sensitivity control: identical call with anonymous
        // OFF must get PAST the guard (it then fails on the bogus host
        // with some other error). If the guard ever widens to refuse
        // all UDP announces, this test catches it.
        let err =
            announce_with_proxy_anon("udp://anon-guard-test.invalid:80", &req(), None, false)
                .await
                .expect_err("bogus host should fail somehow");
        let msg = format!("{err}");
        assert!(
            !msg.contains("skipping UDP tracker"),
            "guard fired without anon/proxy: {msg}"
        );
    }
}
