use std::net::SocketAddr;
use std::time::Duration;

use crate::error::Result;
use crate::peer_id::PeerId;

pub mod http;
pub mod udp;

/// Strip the query string and fragment from a tracker URL for display in
/// logs and error messages. Private-tracker announce URLs carry the user's
/// passkey/key as query parameters; echoing the full URL into an error or
/// tracing line would leak exactly the credential anonymous mode exists to
/// protect. `scheme://host/path` keeps enough to identify the tracker.
pub fn redact_url_query(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or(url).to_string()
}

/// Remove any occurrence of `url` (e.g. one embedded by reqwest's error
/// Display, which prints "… for url (https://host/a?passkey=…)") from a
/// rendered error string, replacing it with its redacted form.
pub fn scrub_url_from_message(msg: &str, url: &str) -> String {
    if msg.is_empty() || url.is_empty() {
        return msg.to_string();
    }
    let redacted = redact_url_query(url);
    if redacted == url {
        return msg.to_string();
    }
    msg.replace(url, &redacted)
}

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
    announce_with_proxy_anon(url, req, proxy, false, None).await
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
    bind_iface: Option<&str>,
) -> Result<AnnounceResponse> {
    if anonymous && proxy.is_none() {
        // Fail closed: without a proxy an http(s):// announce rides the
        // real interface (and resolves DNS locally), leaking our IP.
        // Anonymous mode guarantees a SOCKS5 chain upstream; refuse
        // outright if a caller ever violates that.
        return Err(crate::error::Error::Tracker(format!(
            "anonymous mode requires a SOCKS5 proxy; refusing direct tracker announce: {}", redact_url_query(url)
        )));
    }
    if url.starts_with("udp://") {
        if anonymous || proxy.is_some() {
            // Fail closed: UDP cannot ride the SOCKS5 CONNECT path, so
            // under anonymous mode a udp:// announce would egress the
            // real interface and leak our IP. Refuse outright — even
            // when no proxy is configured (an upstream gate could be
            // bypassed; this is the last line of defense).
            return Err(crate::error::Error::Tracker(format!(
                "skipping UDP tracker while proxy is configured or anonymous mode is on: {}", redact_url_query(url)
            )));
        }
        udp::announce(url, req, bind_iface).await
    } else if url.starts_with("http://") || url.starts_with("https://") {
        http::announce_with_proxy_anon(url, req, proxy, anonymous, bind_iface).await
    } else {
        Err(crate::error::Error::Tracker(format!(
            "unsupported tracker scheme: {}", redact_url_query(url)
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
    announce_with_fallback_anon(tiers, fallback_single, req, proxy, false, None).await
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
    bind_iface: Option<&str>,
) -> Result<(String, AnnounceResponse)> {
    let mut last_err: Option<crate::error::Error> = None;
    for tier in tiers {
        for url in tier {
            match announce_with_proxy_anon(url, req, proxy, anonymous, bind_iface).await {
                Ok(r) => return Ok((url.clone(), r)),
                Err(e) => {
                    tracing::warn!(url = %url, error = %e, "tracker announce failed");
                    last_err = Some(e);
                }
            }
        }
    }
    if let Some(url) = fallback_single {
        match announce_with_proxy_anon(url, req, proxy, anonymous, bind_iface).await {
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
        let err = announce_with_proxy_anon("udp://anon-guard-test.invalid:80", &req(), None, true, None)
            .await
            .expect_err("anonymous UDP announce must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("refusing direct tracker announce") && msg.contains("anonymous"),
            "expected anonymity refusal, got: {msg}"
        );
    }

    #[tokio::test]
    async fn udp_announce_refused_while_proxy_configured_even_without_anon() {
        // UDP cannot ride a SOCKS5 CONNECT: with a proxy configured the
        // announce would either leak direct or fail — refuse explicitly
        // (independent of the anonymity guard).
        let cfg = crate::socks5::ProxyConfig {
            addr: "127.0.0.1:1".parse().unwrap(),
            credentials: None,
            isolation: false,
        };
        let err = announce_with_proxy_anon(
            "udp://proxy-guard-test.invalid:80",
            &req(),
            Some(&cfg),
            false,
            None,
        )
        .await
        .expect_err("proxied UDP announce must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("skipping UDP tracker"),
            "expected UDP-over-proxy refusal, got: {msg}"
        );
    }

    #[tokio::test]
    async fn http_announce_refused_in_anonymous_mode_without_proxy() {
        // Same fail-closed contract for http(s):// trackers: no proxy +
        // anonymous must refuse before any request/DNS work.
        let err = announce_with_proxy_anon(
            "https://anon-guard-test.invalid/announce",
            &req(),
            None,
            true,
            None,
        )
        .await
        .expect_err("anonymous HTTP announce without proxy must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("refusing direct tracker announce") && msg.contains("anonymous"),
            "expected anonymity refusal, got: {msg}"
        );

        // With a proxy configured the guard passes (request proceeds and
        // fails on the bogus host instead of being refused). A proxied
        // client would try to reach the proxy itself; either way it must
        // NOT be the anonymity refusal.
        let cfg = crate::socks5::ProxyConfig {
            addr: "127.0.0.1:1".parse().unwrap(),
            credentials: None,
            isolation: false,
        };
        let err = announce_with_proxy_anon(
            "https://anon-guard-test.invalid/announce",
            &req(),
            Some(&cfg),
            true,
            None,
        )
        .await
        .expect_err("bogus host via dead proxy should fail somehow");
        let msg = format!("{err}");
        assert!(
            !msg.contains("refusing direct tracker announce"),
            "guard over-fired with proxy present: {msg}"
        );
    }

    #[tokio::test]
    async fn udp_announce_guard_does_not_fire_without_anon_or_proxy() {
        // Mutation-sensitivity control: identical call with anonymous
        // OFF must get PAST the guard (it then fails on the bogus host
        // with some other error). If the guard ever widens to refuse
        // all UDP announces, this test catches it.
        let err = announce_with_proxy_anon(
            "udp://anon-guard-test.invalid:80",
            &req(),
            None,
            false,
            None,
        )
        .await
        .expect_err("bogus host should fail somehow");
        let msg = format!("{err}");
        assert!(
            !msg.contains("skipping UDP tracker"),
            "guard fired without anon/proxy: {msg}"
        );
    }

    /// Kill-switch invariant end-to-end: with `--bind-iface` set, a UDP
    /// announce must bind its socket to that interface — a missing one
    /// fails closed naming the iface, never silently riding the default
    /// route. Loopback host: DNS resolves, so the ONLY way this errors
    /// is the interface bind.
    #[tokio::test]
    async fn udp_announce_honors_bind_iface_fail_closed() {
        let err =
            announce_with_proxy_anon("udp://127.0.0.1:9/announce", &req(), None, false, Some("rt_nonexistent_iface_xyz123"))
                .await
                .expect_err("missing bind iface must fail closed");
        let msg = format!("{err}");
        assert!(
            msg.contains("udp bind via rt_nonexistent_iface_xyz123"),
            "error must name the bound interface, got: {msg}"
        );
    }

    #[test]
    fn redact_url_query_strips_query_and_fragment() {
        assert_eq!(
            redact_url_query("https://t.example/a.php?passkey=SECRET&k=X"),
            "https://t.example/a.php"
        );
        assert_eq!(redact_url_query("http://t.example/an#frag"), "http://t.example/an");
        // No query/fragment: unchanged.
        assert_eq!(redact_url_query("udp://t.example:6969/announce"), "udp://t.example:6969/announce");
    }

    #[test]
    fn scrub_url_from_message_redacts_embedded_url() {
        let url = "https://t.example/a.php?passkey=SECRET";
        let msg = format!("http send: error sending request for url ({url})");
        let scrubbed = scrub_url_from_message(&msg, url);
        assert!(scrubbed.contains("https://t.example/a.php"));
        assert!(!scrubbed.contains("SECRET"), "passkey survived scrub: {scrubbed}");
        // URL without query: nothing to scrub, message unchanged.
        let plain = "http://x.example/a";
        assert_eq!(scrub_url_from_message("boom", plain), "boom");
    }
}
