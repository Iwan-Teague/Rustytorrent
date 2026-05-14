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
    let url = build_url(base_url, req);
    tracing::debug!(
        target: "tracker::http",
        url = %base_url,
        via_proxy = proxy.is_some(),
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
    let bytes = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Tracker(format!("http send: {e}")))?
        .bytes()
        .await
        .map_err(|e| Error::Tracker(format!("http recv: {e}")))?;
    parse_response(&bytes)
}

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
        .map(|n| Duration::from_secs(n.max(0) as u64));
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
        interval: Duration::from_secs(interval.max(0) as u64),
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
    fn parse_response_dict_peers() {
        // Non-compact: peers is a list of dicts.
        let body = b"d8:intervali600e5:peersld2:ip9:127.0.0.14:porti6881eeee";
        let r = parse_response(body).unwrap();
        assert_eq!(r.peers.len(), 1);
        assert_eq!(r.peers[0].to_string(), "127.0.0.1:6881");
    }
}
