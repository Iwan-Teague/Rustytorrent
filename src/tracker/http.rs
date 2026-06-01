use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::metainfo::BencodeValue;
use crate::socks5::ProxyConfig;
use crate::tracker::{AnnounceRequest, AnnounceResponse};

/// Process-wide HTTP client cache. We keep:
/// - One "direct" client for non-proxied use.
/// - One client per distinct proxy URL (rare — usually just one in a session).
///
/// `reqwest::Client` is cheap to clone and pools TCP/TLS connections internally,
/// so we keep exactly one per (proxy?) and reuse it for every tracker announce.
/// Building a fresh client per announce throws away the connection pool and
/// forces a new TLS handshake each time.
fn direct_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("rustytorrent/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("build static reqwest client with default config")
    })
}

fn proxied_client(proxy_url: &str) -> reqwest::Client {
    static CACHE: OnceLock<Mutex<HashMap<String, reqwest::Client>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().expect("proxy client cache mutex poisoned");
    if let Some(c) = guard.get(proxy_url) {
        return c.clone();
    }
    // `socks5h://` forces remote DNS resolution — no clearnet DNS leak.
    let proxy =
        reqwest::Proxy::all(proxy_url).expect("malformed SOCKS5 proxy URL — validated upstream");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("rustytorrent/", env!("CARGO_PKG_VERSION")))
        .proxy(proxy)
        .build()
        .expect("build proxied reqwest client");
    guard.insert(proxy_url.to_string(), client.clone());
    client
}

/// Percent-encode every byte that isn't an unreserved character per RFC 3986.
/// Critical for `info_hash` and `peer_id` since they're arbitrary 20-byte values,
/// not printable strings.
fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

fn build_url(base: &str, req: &AnnounceRequest) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut url = format!(
        "{base}{sep}info_hash={ih}&peer_id={pid}&port={port}&uploaded={up}&downloaded={dn}&left={left}&compact=1&numwant={nw}",
        ih = percent_encode(&req.info_hash),
        pid = percent_encode(&req.peer_id),
        port = req.port,
        up = req.uploaded,
        dn = req.downloaded,
        left = req.left,
        nw = req.num_want,
    );
    if let Some(e) = req.event.as_http_param() {
        url.push_str(&format!("&event={e}"));
    }
    url
}

pub async fn announce(base_url: &str, req: &AnnounceRequest) -> Result<AnnounceResponse> {
    announce_with_proxy(base_url, req, None).await
}

pub async fn announce_with_proxy(
    base_url: &str,
    req: &AnnounceRequest,
    proxy: Option<&ProxyConfig>,
) -> Result<AnnounceResponse> {
    announce_inner(base_url, req, proxy, None).await
}

/// User-Agent string we send when anonymized: matches libtorrent 2.0.9
/// so a tracker (or any HTTP observer that sees the request) can't
/// pick us out by UA alone. Real libtorrent emits exactly this string,
/// so blending in here costs us nothing functionally.
const LIBTORRENT_LOOKALIKE_UA: &str = "libtorrent/2.0.9";

/// As `announce_with_proxy`, but additionally overrides the User-Agent
/// header on the outbound request. Used by the engine in anonymous
/// mode to avoid leaking the `rustytorrent/<ver>` UA we'd otherwise
/// emit by default.
pub async fn announce_with_proxy_anon(
    base_url: &str,
    req: &AnnounceRequest,
    proxy: Option<&ProxyConfig>,
    anonymous: bool,
) -> Result<AnnounceResponse> {
    let ua_override = if anonymous {
        Some(LIBTORRENT_LOOKALIKE_UA)
    } else {
        None
    };
    announce_inner(base_url, req, proxy, ua_override).await
}

async fn announce_inner(
    base_url: &str,
    req: &AnnounceRequest,
    proxy: Option<&ProxyConfig>,
    ua_override: Option<&str>,
) -> Result<AnnounceResponse> {
    let url = build_url(base_url, req);
    tracing::debug!(
        target: "tracker::http",
        url = %base_url,
        via_proxy = proxy.is_some(),
        ua_override = ua_override.is_some(),
        "announcing"
    );
    let client_owned;
    let client: &reqwest::Client = match proxy {
        Some(p) => {
            client_owned = proxied_client(&p.as_socks5h_url());
            &client_owned
        }
        None => direct_client(),
    };
    let mut builder = client.get(&url);
    if let Some(ua) = ua_override {
        // Per-request header takes precedence over the client's default
        // user_agent setting, so we don't have to rebuild the client.
        builder = builder.header(reqwest::header::USER_AGENT, ua);
    }
    let bytes = builder
        .send()
        .await
        .map_err(|e| Error::Tracker(format!("http send: {e}")))?
        .bytes()
        .await
        .map_err(|e| Error::Tracker(format!("http recv: {e}")))?;
    parse_response(&bytes)
}

/// Clamp tracker-supplied announce intervals to a sane ceiling (24 h). A
/// hostile or MITM'd `http://` tracker can otherwise return an enormous
/// `interval` (up to `i64::MAX`), which both parks reannounces effectively
/// forever and overflows the `Duration` arithmetic in the engine's jitter
/// step (`base * pct`) — a remote panic. The lower bound is enforced
/// separately by `reannounce_min`.
const MAX_INTERVAL_SECS: u64 = 86_400;

pub fn parse_response(body: &[u8]) -> Result<AnnounceResponse> {
    let v = BencodeValue::parse_all(body).map_err(|e| Error::Tracker(format!("bencode: {e}")))?;
    let d = v
        .as_dict()
        .map_err(|e| Error::Tracker(format!("response: {e}")))?;
    if let Some(reason) = d.get(&b"failure reason".to_vec()) {
        let msg = reason.as_str().unwrap_or("<non-utf8>").to_string();
        return Err(Error::Tracker(format!("failure: {msg}")));
    }
    let interval = d
        .get(&b"interval".to_vec())
        .ok_or_else(|| Error::Tracker("response missing interval".into()))?
        .as_int()
        .map_err(|e| Error::Tracker(format!("interval: {e}")))?;
    let min_interval = d
        .get(&b"min interval".to_vec())
        .and_then(|v| v.as_int().ok())
        .map(|n| Duration::from_secs((n.max(0) as u64).min(MAX_INTERVAL_SECS)));
    let seeders = d
        .get(&b"complete".to_vec())
        .and_then(|v| v.as_int().ok())
        .and_then(|n| u32::try_from(n).ok());
    let leechers = d
        .get(&b"incomplete".to_vec())
        .and_then(|v| v.as_int().ok())
        .and_then(|n| u32::try_from(n).ok());

    let mut peers: Vec<SocketAddr> = Vec::new();
    if let Some(p) = d.get(&b"peers".to_vec()) {
        match p {
            BencodeValue::Bytes(b) => peers.extend(parse_compact_v4(b)?),
            BencodeValue::List(list) => {
                for entry in list {
                    let dd = entry
                        .as_dict()
                        .map_err(|e| Error::Tracker(format!("peer entry: {e}")))?;
                    let ip = dd
                        .get(&b"ip".to_vec())
                        .ok_or_else(|| Error::Tracker("peer missing ip".into()))?
                        .as_str()
                        .map_err(|e| Error::Tracker(format!("peer ip: {e}")))?;
                    let port = dd
                        .get(&b"port".to_vec())
                        .ok_or_else(|| Error::Tracker("peer missing port".into()))?
                        .as_int()
                        .map_err(|e| Error::Tracker(format!("peer port: {e}")))?;
                    let port_u16 = u16::try_from(port)
                        .map_err(|_| Error::Tracker("peer port out of range".into()))?;
                    let addr: IpAddr = ip
                        .parse()
                        .map_err(|e| Error::Tracker(format!("peer ip parse: {e}")))?;
                    peers.push(SocketAddr::new(addr, port_u16));
                }
            }
            _ => return Err(Error::Tracker("peers field has unexpected type".into())),
        }
    }
    if let Some(BencodeValue::Bytes(b)) = d.get(&b"peers6".to_vec()) {
        peers.extend(parse_compact_v6(b)?);
    }

    Ok(AnnounceResponse {
        interval: Duration::from_secs((interval.max(0) as u64).min(MAX_INTERVAL_SECS)),
        min_interval,
        seeders,
        leechers,
        peers,
    })
}

fn parse_compact_v4(b: &[u8]) -> Result<Vec<SocketAddr>> {
    if !b.len().is_multiple_of(6) {
        return Err(Error::Tracker(format!(
            "compact v4 peers length {} not multiple of 6",
            b.len()
        )));
    }
    let mut out = Vec::with_capacity(b.len() / 6);
    for c in b.chunks_exact(6) {
        let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
        let port = u16::from_be_bytes([c[4], c[5]]);
        out.push(SocketAddr::new(IpAddr::V4(ip), port));
    }
    Ok(out)
}

fn parse_compact_v6(b: &[u8]) -> Result<Vec<SocketAddr>> {
    if !b.len().is_multiple_of(18) {
        return Err(Error::Tracker(format!(
            "compact v6 peers length {} not multiple of 18",
            b.len()
        )));
    }
    let mut out = Vec::with_capacity(b.len() / 18);
    for c in b.chunks_exact(18) {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&c[..16]);
        let ip = Ipv6Addr::from(octets);
        let port = u16::from_be_bytes([c[16], c[17]]);
        out.push(SocketAddr::new(IpAddr::V6(ip), port));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_unreserved_passes_through() {
        assert_eq!(percent_encode(b"Aa0-_.~"), "Aa0-_.~");
    }

    #[test]
    fn percent_encode_binary() {
        // BEP 3 example bytes — must round-trip as %XX uppercase hex.
        assert_eq!(percent_encode(&[0x00, 0x10, 0xff]), "%00%10%FF");
    }

    #[test]
    fn percent_encode_full_info_hash() {
        let h = [0u8; 20];
        assert_eq!(percent_encode(&h).len(), 60);
        assert!(percent_encode(&h).starts_with("%00%00"));
    }

    #[test]
    fn url_has_required_params() {
        let req = AnnounceRequest {
            info_hash: [0xAB; 20],
            peer_id: *b"-RT0100-aaaaaaaaaaaa",
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 1000,
            event: crate::tracker::Event::Started,
            num_want: 50,
        };
        let url = build_url("http://t.example/announce", &req);
        assert!(url.contains("info_hash="));
        assert!(url.contains("peer_id="));
        assert!(url.contains("port=6881"));
        assert!(url.contains("left=1000"));
        assert!(url.contains("compact=1"));
        assert!(url.contains("numwant=50"));
        assert!(url.contains("event=started"));
    }

    #[test]
    fn url_handles_query_in_base() {
        let req = AnnounceRequest {
            info_hash: [0; 20],
            peer_id: [0; 20],
            port: 0,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            event: crate::tracker::Event::None,
            num_want: 1,
        };
        let url = build_url("http://t.example/announce?key=abc", &req);
        // Should append with '&', not '?'.
        assert!(url.starts_with("http://t.example/announce?key=abc&info_hash="));
    }

    #[test]
    fn parse_compact_v4_peers() {
        // Two peers: 1.2.3.4:6881 and 10.20.30.40:51413
        let bytes = [1, 2, 3, 4, 0x1A, 0xE1, 10, 20, 30, 40, 0xC8, 0xD5];
        let peers = parse_compact_v4(&bytes).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].to_string(), "1.2.3.4:6881");
        assert_eq!(peers[1].to_string(), "10.20.30.40:51413");
    }

    #[test]
    fn parse_compact_v4_rejects_short() {
        assert!(parse_compact_v4(&[1, 2, 3, 4]).is_err());
    }

    #[test]
    fn parse_response_compact() {
        // d8:intervali900e5:peers6:\x01\x02\x03\x04\x1a\xe1e
        let mut body = Vec::new();
        body.extend_from_slice(b"d8:intervali900e5:peers6:");
        body.extend_from_slice(&[1, 2, 3, 4, 0x1A, 0xE1]);
        body.push(b'e');
        let r = parse_response(&body).unwrap();
        assert_eq!(r.interval, Duration::from_secs(900));
        assert_eq!(r.peers.len(), 1);
        assert_eq!(r.peers[0].to_string(), "1.2.3.4:6881");
    }

    #[test]
    fn parse_response_failure_reason() {
        let body = b"d14:failure reason13:not authorizede";
        assert!(parse_response(body).is_err());
    }

    #[test]
    fn parse_response_clamps_hostile_interval() {
        // A hostile tracker returning i64::MAX must not yield an unbounded
        // Duration (which would later overflow the jitter math and panic).
        let body = b"d8:intervali9223372036854775807e12:min intervali9223372036854775807ee";
        let r = parse_response(body).unwrap();
        assert_eq!(r.interval, Duration::from_secs(MAX_INTERVAL_SECS));
        assert_eq!(r.min_interval, Some(Duration::from_secs(MAX_INTERVAL_SECS)));
    }

    #[test]
    fn parse_response_dict_peers() {
        // Non-compact: peers is a list of dicts.
        let body = b"d8:intervali600e5:peersld2:ip9:127.0.0.14:porti6881eeee";
        let r = parse_response(body).unwrap();
        assert_eq!(r.peers.len(), 1);
        assert_eq!(r.peers[0].to_string(), "127.0.0.1:6881");
    }

    /// Spin a tiny "HTTP server" that reads the request, captures the
    /// User-Agent header, and replies with a minimal valid tracker
    /// response. Returns the captured UA via a oneshot.
    async fn spawn_ua_capture() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            // Headers are case-insensitive; reqwest sends "User-Agent: ".
            let ua = req
                .lines()
                .find_map(|l| {
                    l.strip_prefix("user-agent: ")
                        .or(l.strip_prefix("User-Agent: "))
                })
                .unwrap_or("")
                .to_string();
            let _ = tx.send(ua);
            // Minimal bencoded response: interval only, empty peer list.
            let body = b"d8:intervali900e5:peers0:e";
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        });
        (addr, rx)
    }

    fn dummy_req() -> AnnounceRequest {
        AnnounceRequest {
            info_hash: [0; 20],
            peer_id: [0; 20],
            port: 0,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            event: crate::tracker::Event::None,
            num_want: 1,
        }
    }

    #[tokio::test]
    async fn anonymous_uses_libtorrent_ua() {
        let (addr, rx) = spawn_ua_capture().await;
        let url = format!("http://{addr}/announce");
        let _ = announce_with_proxy_anon(&url, &dummy_req(), None, true)
            .await
            .unwrap();
        let ua = rx.await.unwrap();
        assert_eq!(ua, LIBTORRENT_LOOKALIKE_UA);
    }

    #[tokio::test]
    async fn non_anonymous_uses_default_ua() {
        let (addr, rx) = spawn_ua_capture().await;
        let url = format!("http://{addr}/announce");
        let _ = announce_with_proxy_anon(&url, &dummy_req(), None, false)
            .await
            .unwrap();
        let ua = rx.await.unwrap();
        assert!(
            ua.starts_with("rustytorrent/"),
            "expected default rustytorrent UA, got {ua:?}"
        );
    }
}
