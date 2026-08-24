//! Minimal SOCKS5 client for outgoing TCP through a proxy
//! ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928) + USER/PASS auth
//! [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929)).
//!
//! Used by the peer-connection layer when the engine is configured with a
//! proxy: every outbound TCP dial goes `client → proxy → target` instead of
//! `client → target`, so the swarm only ever sees the proxy's IP.
//!
//! Scope: CONNECT only (the cmd we need for peer connections). UDP
//! ASSOCIATE (needed for DHT-over-proxy) is intentionally out of scope —
//! the `--anonymous` engine mode disables DHT entirely.

use std::net::{IpAddr, SocketAddr};

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Connection budget for proxy handshake (TCP connect → method negotiation
/// → optional auth → CONNECT request → reply). Generous, since some
/// commercial proxies are slow.
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// SOCKS5 version byte ("VER").
const VER_SOCKS5: u8 = 0x05;
/// Authentication subnegotiation version byte for username/password
/// ("VER" in RFC 1929 — note this is *not* the SOCKS5 version, just the
/// version of the auth subprotocol).
const VER_USERPASS: u8 = 0x01;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCEEDED: u8 = 0x00;

/// Proxy configuration shared across all outgoing peer dials in a session.
/// Cheaply cloneable.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Where the SOCKS5 server listens. Resolved IP, not a host name; if the
    /// user supplied a hostname we resolve it once at startup so we don't
    /// emit clearnet DNS queries every connection.
    pub addr: SocketAddr,
    /// Optional `(username, password)` for RFC 1929 auth.
    pub credentials: Option<Credentials>,
    /// **Tor stream isolation.** When `true`, every outgoing dial uses a
    /// freshly-randomized SOCKS5 username; Tor's SOCKS server treats
    /// distinct usernames as distinct streams and routes each over its own
    /// circuit. Defeats correlation by any single exit node.
    ///
    /// On non-Tor SOCKS5 proxies that ignore credentials this is harmless;
    /// on proxies that *enforce* real USER/PASS auth this will break dials,
    /// so leave it off for commercial VPNs that require real creds.
    pub isolation: bool,
}

impl ProxyConfig {
    /// Materialize the per-dial effective config. When `isolation` is on,
    /// generate a fresh random username for each call so Tor puts it on a
    /// new circuit.
    pub fn for_dial(&self) -> ProxyConfig {
        if !self.isolation {
            return self.clone();
        }
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let username = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let creds = Credentials {
            username,
            // Tor doesn't actually check the password; any non-empty value works.
            password: "x".into(),
        };
        ProxyConfig {
            addr: self.addr,
            credentials: Some(creds),
            isolation: false, // already applied
        }
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

// Manual `Debug` impls: the derived forms would print proxy passwords in
// cleartext anywhere a `{:?}` lands — tracing lines, panic messages, error
// context. Credentials are opaque ("Credentials { .. }"); `ProxyConfig`
// keeps only its non-secret fields readable so dial debugging still works.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials { .. }")
    }
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("addr", &self.addr)
            .field("credentials", &self.credentials)
            .field("isolation", &self.isolation)
            .finish()
    }
}

impl ProxyConfig {
    /// Build the equivalent SOCKS5 URL string for passing to libraries that
    /// expect one (e.g. `reqwest::Proxy::all`). Uses `socks5h://` so the
    /// remote end resolves hostnames — no clearnet DNS leak.
    pub fn as_socks5h_url(&self) -> String {
        match &self.credentials {
            Some(creds) => format!(
                "socks5h://{}:{}@{}",
                urlencode(&creds.username),
                urlencode(&creds.password),
                self.addr
            ),
            None => format!("socks5h://{}", self.addr),
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("proxy protocol error: {0}")]
    Protocol(String),
    #[error("proxy auth failed")]
    AuthFailed,
    #[error("proxy refused CONNECT (REP={0}): {1}")]
    Refused(u8, &'static str),
    #[error("proxy handshake timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Socks5Error>;

/// Dial `target` through `proxy`. Returns the underlying TCP stream which
/// is, post-handshake, a transparent byte-pipe to `target`.
pub async fn connect(proxy: &ProxyConfig, target: SocketAddr) -> Result<TcpStream> {
    connect_chain(std::slice::from_ref(proxy), target, None).await
}

/// Dial `target` through a *chain* of SOCKS5 proxies. The client opens
/// one TCP stream to `chain[0]` and then issues nested SOCKS5
/// handshakes on that same stream: the first hop CONNECTs to
/// `chain[1].addr`, the second hop (visible through the first hop's
/// tunnel) CONNECTs to `chain[2].addr`, and so on, until the last hop
/// CONNECTs to `target`. RFC 1928 nests cleanly — each hop sees
/// nothing but bytes flowing toward the next hop's address.
///
/// When `bind_iface` is set the TCP socket to the FIRST hop is bound
/// to that network interface (the VPN kill switch). Intermediate
/// hops ride the same TCP stream and don't need their own binding —
/// the bind affects which kernel route the bytes take to the first
/// hop, which is the only thing observable to a non-tunnel link.
///
/// Chains of length 1 behave identically to the single-proxy `connect`.
/// Chains of length 0 are rejected — that's a programming error.
pub async fn connect_chain(
    chain: &[ProxyConfig],
    target: SocketAddr,
    bind_iface: Option<&str>,
) -> Result<TcpStream> {
    if chain.is_empty() {
        return Err(Socks5Error::Protocol(
            "connect_chain called with empty chain".into(),
        ));
    }
    // Scale the timeout with hop count so a 3-hop chain doesn't fail on
    // the cumulative handshake budget. Each hop gets the same per-hop
    // budget as a single proxy would have.
    let total = PROXY_HANDSHAKE_TIMEOUT
        .checked_mul(chain.len() as u32)
        .unwrap_or(PROXY_HANDSHAKE_TIMEOUT);
    match timeout(total, do_connect_chain(chain, target, bind_iface)).await {
        Ok(r) => r,
        Err(_) => Err(Socks5Error::Timeout),
    }
}

async fn do_connect_chain(
    chain: &[ProxyConfig],
    target: SocketAddr,
    bind_iface: Option<&str>,
) -> Result<TcpStream> {
    // Open the TCP socket to the first proxy. Every subsequent hop's
    // bytes flow through this same stream. With --bind-iface set, the
    // first-hop dial goes via netbind so the kernel route to the
    // proxy is forced onto the bound interface (fails closed if it
    // goes away — the VPN kill switch invariant).
    let mut stream = match bind_iface {
        Some(iface) => crate::netbind::connect_via_interface(chain[0].addr, iface)
            .await
            .map_err(Socks5Error::Io)?,
        None => TcpStream::connect(chain[0].addr).await?,
    };
    let _ = stream.set_nodelay(true);

    // For hop i, the SOCKS5 CONNECT target is hop i+1's address; the
    // final hop's CONNECT target is the actual destination.
    for (i, hop) in chain.iter().enumerate() {
        let hop_target = if i + 1 < chain.len() {
            chain[i + 1].addr
        } else {
            target
        };
        do_handshake_on_stream(&mut stream, hop, hop_target).await?;
    }
    Ok(stream)
}

/// Drive one SOCKS5 handshake (method negotiation + optional
/// USER/PASS + CONNECT) over an already-open stream. The stream may
/// be a raw TCP socket (first hop) or the tunneled byte-pipe from a
/// previous hop's CONNECT (subsequent hops in a chain) — the
/// handshake is wire-identical either way.
async fn do_handshake_on_stream(
    stream: &mut TcpStream,
    proxy: &ProxyConfig,
    target: SocketAddr,
) -> Result<()> {
    // Step 1 — method negotiation.
    //
    // When we have credentials we offer ONLY USER/PASS — never NO_AUTH
    // alongside it. Offering both lets the proxy downgrade to NO_AUTH and
    // silently ignore our credentials, which is a privacy hole: with
    // --tor-isolation each dial carries a fresh random SOCKS5 username
    // that Tor uses to assign a distinct circuit (see
    // `ProxyConfig::for_dial`). If the proxy picks NO_AUTH that username
    // never reaches Tor, every dial rides the same circuit, and the
    // correlation defense the user asked for is gone — with no error. So
    // when creds are set we force USER/PASS and fail closed if the proxy
    // won't take it. When we have no creds we offer NO_AUTH only.
    let methods: &[u8] = if proxy.credentials.is_some() {
        &[METHOD_USERPASS]
    } else {
        &[METHOD_NO_AUTH]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(VER_SOCKS5);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;

    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    if method_reply[0] != VER_SOCKS5 {
        return Err(Socks5Error::Protocol(format!(
            "method reply ver = 0x{:02x}, expected 0x05",
            method_reply[0]
        )));
    }
    match method_reply[1] {
        METHOD_NO_AUTH => { /* nothing to do */ }
        METHOD_USERPASS => {
            let creds = proxy.credentials.as_ref().ok_or_else(|| {
                Socks5Error::Protocol("proxy demanded USER/PASS but none provided".into())
            })?;
            do_userpass_auth(stream, creds).await?;
        }
        METHOD_NONE_ACCEPTABLE => return Err(Socks5Error::AuthFailed),
        other => {
            return Err(Socks5Error::Protocol(format!(
                "proxy chose unsupported method 0x{other:02x}"
            )))
        }
    }

    // Step 2 — CONNECT request.
    let request = build_connect_request(target);
    stream.write_all(&request).await?;

    // Step 3 — read reply: VER, REP, RSV, ATYP, BIND.ADDR, BIND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER_SOCKS5 {
        return Err(Socks5Error::Protocol(format!(
            "connect reply ver = 0x{:02x}",
            head[0]
        )));
    }
    if head[1] != REP_SUCCEEDED {
        return Err(Socks5Error::Refused(head[1], rep_meaning(head[1])));
    }
    // Drain BIND.ADDR + BIND.PORT according to ATYP — we don't actually use
    // these values, but we need to consume them so the stream is byte-aligned
    // for application traffic.
    drain_bind_addr_port(stream, head[3]).await?;
    Ok(())
}

async fn do_userpass_auth(stream: &mut TcpStream, creds: &Credentials) -> Result<()> {
    let u = creds.username.as_bytes();
    let p = creds.password.as_bytes();
    if u.len() > 255 || p.len() > 255 {
        return Err(Socks5Error::Protocol(
            "username/password must each be ≤255 bytes".into(),
        ));
    }
    let mut req = Vec::with_capacity(3 + u.len() + p.len());
    req.push(VER_USERPASS);
    req.push(u.len() as u8);
    req.extend_from_slice(u);
    req.push(p.len() as u8);
    req.extend_from_slice(p);
    stream.write_all(&req).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != VER_USERPASS {
        return Err(Socks5Error::Protocol(format!(
            "auth reply ver = 0x{:02x}, expected 0x01",
            reply[0]
        )));
    }
    if reply[1] != 0x00 {
        return Err(Socks5Error::AuthFailed);
    }
    Ok(())
}

fn build_connect_request(target: SocketAddr) -> Vec<u8> {
    let mut req = Vec::with_capacity(22);
    req.push(VER_SOCKS5);
    req.push(CMD_CONNECT);
    req.push(0x00); // RSV
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    req
}

async fn drain_bind_addr_port(stream: &mut TcpStream, atyp: u8) -> Result<()> {
    let bind_len = match atyp {
        ATYP_IPV4 => 4 + 2,
        ATYP_IPV6 => 16 + 2,
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            len_buf[0] as usize + 2
        }
        other => {
            return Err(Socks5Error::Protocol(format!(
                "unsupported ATYP 0x{other:02x} in connect reply"
            )))
        }
    };
    let mut drain = vec![0u8; bind_len];
    stream.read_exact(&mut drain).await?;
    Ok(())
}

fn rep_meaning(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused by destination",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown REP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn connect_request_layout_ipv4() {
        let target: SocketAddr = "1.2.3.4:6881".parse().unwrap();
        let req = build_connect_request(target);
        assert_eq!(req, vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x1A, 0xE1]);
    }

    #[test]
    fn connect_request_layout_ipv6() {
        let target: SocketAddr = "[::1]:80".parse().unwrap();
        let req = build_connect_request(target);
        assert_eq!(req[0..4], [0x05, 0x01, 0x00, 0x04]);
        // ::1 is 15 zero bytes then 0x01.
        assert_eq!(&req[4..19], &[0u8; 15]);
        assert_eq!(req[19], 0x01);
        assert_eq!(&req[20..22], &80u16.to_be_bytes());
    }

    #[test]
    fn rep_meaning_known_codes() {
        assert_eq!(rep_meaning(0x01), "general SOCKS server failure");
        assert_eq!(rep_meaning(0x05), "connection refused by destination");
        assert_eq!(rep_meaning(0xAB), "unknown REP");
    }

    #[test]
    fn urlencode_unreserved() {
        assert_eq!(urlencode("AaZz09-_.~"), "AaZz09-_.~");
    }

    #[test]
    fn urlencode_special() {
        assert_eq!(urlencode("a:b@c/d"), "a%3Ab%40c%2Fd");
    }

    #[test]
    fn proxy_url_no_creds() {
        let p = ProxyConfig {
            addr: "127.0.0.1:9050".parse().unwrap(),
            credentials: None,
            isolation: false,
        };
        assert_eq!(p.as_socks5h_url(), "socks5h://127.0.0.1:9050");
    }

    #[test]
    fn proxy_url_with_creds() {
        let p = ProxyConfig {
            addr: "10.0.0.1:1080".parse().unwrap(),
            credentials: Some(Credentials {
                username: "user@host".into(),
                password: "p:ss".into(),
            }),
            isolation: false,
        };
        assert_eq!(
            p.as_socks5h_url(),
            "socks5h://user%40host:p%3Ass@10.0.0.1:1080"
        );
    }

    #[test]
    fn for_dial_with_isolation_off_clones() {
        let p = ProxyConfig {
            addr: "127.0.0.1:9050".parse().unwrap(),
            credentials: None,
            isolation: false,
        };
        let d = p.for_dial();
        assert_eq!(d.addr, p.addr);
        assert!(d.credentials.is_none());
    }

    #[test]
    fn for_dial_with_isolation_generates_unique_username() {
        let p = ProxyConfig {
            addr: "127.0.0.1:9050".parse().unwrap(),
            credentials: None,
            isolation: true,
        };
        let a = p.for_dial();
        let b = p.for_dial();
        // Two consecutive isolated dials should get distinct usernames so
        // Tor puts them on separate circuits.
        let ua = a.credentials.unwrap().username;
        let ub = b.credentials.unwrap().username;
        assert_ne!(ua, ub, "isolated dials must get fresh usernames");
        // After applying isolation, the per-dial config has isolation=false
        // so the SOCKS5 layer doesn't try to randomize again.
        assert!(!a.isolation);
        assert!(!b.isolation);
    }

    /// Spawn a tiny in-memory "SOCKS5 server" that does the protocol
    /// dance and reports its observations. Used to verify `connect()`
    /// without a real proxy.
    async fn spawn_mock_socks5(
        require_auth: bool,
        target_check: SocketAddr,
    ) -> (SocketAddr, tokio::task::JoinHandle<MockResult>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], VER_SOCKS5);
            let nmethods = greeting[1] as usize;
            let mut methods = vec![0u8; nmethods];
            sock.read_exact(&mut methods).await.unwrap();

            let chosen = if require_auth && methods.contains(&METHOD_USERPASS) {
                METHOD_USERPASS
            } else if methods.contains(&METHOD_NO_AUTH) {
                METHOD_NO_AUTH
            } else {
                METHOD_NONE_ACCEPTABLE
            };
            sock.write_all(&[VER_SOCKS5, chosen]).await.unwrap();

            let mut got_creds = None;
            if chosen == METHOD_USERPASS {
                let mut head = [0u8; 2];
                sock.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0], VER_USERPASS);
                let ulen = head[1] as usize;
                let mut u = vec![0u8; ulen];
                sock.read_exact(&mut u).await.unwrap();
                let mut plen_buf = [0u8; 1];
                sock.read_exact(&mut plen_buf).await.unwrap();
                let mut p = vec![0u8; plen_buf[0] as usize];
                sock.read_exact(&mut p).await.unwrap();
                got_creds = Some((String::from_utf8(u).unwrap(), String::from_utf8(p).unwrap()));
                sock.write_all(&[VER_USERPASS, 0x00]).await.unwrap();
            }

            // CONNECT request: VER, CMD, RSV, ATYP, ADDR, PORT
            let mut req_head = [0u8; 4];
            sock.read_exact(&mut req_head).await.unwrap();
            assert_eq!(req_head[0], VER_SOCKS5);
            assert_eq!(req_head[1], CMD_CONNECT);
            assert_eq!(req_head[3], ATYP_IPV4);
            let mut addr_buf = [0u8; 6];
            sock.read_exact(&mut addr_buf).await.unwrap();
            let target_seen = SocketAddr::from((
                [addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]],
                u16::from_be_bytes([addr_buf[4], addr_buf[5]]),
            ));
            assert_eq!(target_seen, target_check);

            // Reply success with our bind addr 0.0.0.0:0.
            sock.write_all(&[VER_SOCKS5, REP_SUCCEEDED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            // Echo whatever the client sends after handshake (to prove the
            // post-handshake stream is byte-aligned).
            let mut buf = [0u8; 5];
            let _ = sock.read_exact(&mut buf).await;
            let _ = sock.write_all(&buf).await;
            MockResult {
                creds: got_creds,
                trailing: buf.to_vec(),
            }
        });
        (addr, handle)
    }

    struct MockResult {
        creds: Option<(String, String)>,
        trailing: Vec<u8>,
    }

    #[tokio::test]
    async fn handshake_no_auth_succeeds() {
        let target: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let (proxy_addr, server) = spawn_mock_socks5(false, target).await;
        let mut stream = connect(
            &ProxyConfig {
                addr: proxy_addr,
                credentials: None,
                isolation: false,
            },
            target,
        )
        .await
        .unwrap();
        // Post-handshake the tunnel is transparent — write/read should round-trip.
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        let res = server.await.unwrap();
        assert!(res.creds.is_none());
        assert_eq!(res.trailing, b"hello");
    }

    #[tokio::test]
    async fn handshake_with_userpass_succeeds() {
        let target: SocketAddr = "9.9.9.9:6881".parse().unwrap();
        let (proxy_addr, server) = spawn_mock_socks5(true, target).await;
        let mut stream = connect(
            &ProxyConfig {
                addr: proxy_addr,
                credentials: Some(Credentials {
                    username: "alice".into(),
                    password: "s3cret".into(),
                }),
                isolation: false,
            },
            target,
        )
        .await
        .unwrap();
        stream.write_all(b"world").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        let res = server.await.unwrap();
        assert_eq!(res.creds, Some(("alice".into(), "s3cret".into())));
    }

    /// Privacy regression: when credentials are present we must offer
    /// ONLY USER/PASS, so the proxy can't downgrade to NO_AUTH and
    /// silently drop the per-dial isolation username. The mock asserts
    /// the offered method set and that it actually receives the creds.
    #[tokio::test]
    async fn creds_present_offers_only_userpass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let target: SocketAddr = "9.9.9.9:6881".parse().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.unwrap();
            let nmethods = greeting[1] as usize;
            let mut methods = vec![0u8; nmethods];
            sock.read_exact(&mut methods).await.unwrap();
            // The whole point: NO_AUTH must NOT be on offer.
            assert!(
                !methods.contains(&METHOD_NO_AUTH),
                "NO_AUTH must not be offered when creds are set (downgrade hole)"
            );
            assert!(methods.contains(&METHOD_USERPASS));
            sock.write_all(&[VER_SOCKS5, METHOD_USERPASS])
                .await
                .unwrap();
            // Consume the USER/PASS auth and confirm the username arrives.
            let mut head = [0u8; 2];
            sock.read_exact(&mut head).await.unwrap();
            let mut u = vec![0u8; head[1] as usize];
            sock.read_exact(&mut u).await.unwrap();
            let mut plen = [0u8; 1];
            sock.read_exact(&mut plen).await.unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            sock.read_exact(&mut p).await.unwrap();
            sock.write_all(&[VER_USERPASS, 0x00]).await.unwrap();
            // CONNECT + success reply.
            let mut req = [0u8; 10];
            sock.read_exact(&mut req).await.unwrap();
            sock.write_all(&[VER_SOCKS5, REP_SUCCEEDED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            String::from_utf8(u).unwrap()
        });
        let _stream = connect(
            &ProxyConfig {
                addr: proxy_addr,
                credentials: Some(Credentials {
                    username: "isolation-nonce".into(),
                    password: "x".into(),
                }),
                isolation: false,
            },
            target,
        )
        .await
        .unwrap();
        let got_user = server.await.unwrap();
        assert_eq!(got_user, "isolation-nonce");
    }

    /// A NO_AUTH-only proxy must make a creds-bearing dial fail closed,
    /// not silently succeed with the credentials ignored.
    #[tokio::test]
    async fn creds_present_fails_closed_on_no_auth_only_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            sock.read_exact(&mut methods).await.unwrap();
            // Proxy supports only NO_AUTH; client offered only USERPASS →
            // nothing in common.
            sock.write_all(&[VER_SOCKS5, METHOD_NONE_ACCEPTABLE])
                .await
                .unwrap();
        });
        let res = connect(
            &ProxyConfig {
                addr: proxy_addr,
                credentials: Some(Credentials {
                    username: "u".into(),
                    password: "p".into(),
                }),
                isolation: false,
            },
            "1.1.1.1:80".parse().unwrap(),
        )
        .await;
        assert!(
            matches!(res, Err(Socks5Error::AuthFailed)),
            "creds + NO_AUTH-only proxy must fail closed, got {res:?}"
        );
        server.await.unwrap();
    }

    /// Verify the "no acceptable methods" path: proxy demands auth, client
    /// offered none.
    #[tokio::test]
    async fn handshake_no_methods_returns_auth_failed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            sock.read_exact(&mut methods).await.unwrap();
            sock.write_all(&[VER_SOCKS5, METHOD_NONE_ACCEPTABLE])
                .await
                .unwrap();
        });
        let res = connect(
            &ProxyConfig {
                addr: proxy_addr,
                credentials: None,
                isolation: false,
            },
            "1.1.1.1:80".parse().unwrap(),
        )
        .await;
        assert!(matches!(res, Err(Socks5Error::AuthFailed)));
        server.await.unwrap();
    }

    /// Spawn a SOCKS5 mock that, after a successful CONNECT, opens a
    /// TCP connection to whatever address the client asked for and
    /// proxies bytes bidirectionally. Lets us chain real mocks: the
    /// middle hop genuinely forwards to the next hop's address, which
    /// is what makes a multi-hop chain test meaningful.
    async fn spawn_forwarding_mock_socks5() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            // Method negotiation.
            let mut greeting = [0u8; 2];
            client.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
            client
                .write_all(&[VER_SOCKS5, METHOD_NO_AUTH])
                .await
                .unwrap();
            // CONNECT request.
            let mut req_head = [0u8; 4];
            client.read_exact(&mut req_head).await.unwrap();
            let mut addr_buf = [0u8; 6];
            client.read_exact(&mut addr_buf).await.unwrap();
            let next: SocketAddr = SocketAddr::from((
                [addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]],
                u16::from_be_bytes([addr_buf[4], addr_buf[5]]),
            ));
            // Reply success.
            client
                .write_all(&[VER_SOCKS5, REP_SUCCEEDED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // Open the upstream connection and bidirectionally copy.
            let upstream = TcpStream::connect(next).await.unwrap();
            let (mut cr, mut cw) = client.into_split();
            let (mut ur, mut uw) = upstream.into_split();
            let a = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut cr, &mut uw).await;
            });
            let b = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut ur, &mut cw).await;
            });
            let _ = a.await;
            let _ = b.await;
        });
        (addr, handle)
    }

    /// Two-hop chain end-to-end: client → hop A (forwarding) → hop B →
    /// target. Hop A actually relays the next hop's bytes; hop B is
    /// the terminating mock and captures the application-level
    /// trailing bytes the client sends through both hops.
    #[tokio::test]
    async fn connect_chain_two_hops() {
        // Final target the client wants to reach.
        let final_target: SocketAddr = "9.9.9.9:6881".parse().unwrap();
        // Hop B sits at the end and must be told its target is the final.
        let (hop_b_addr, hop_b) = spawn_mock_socks5(false, final_target).await;
        // Hop A is the first hop — it forwards to hop B.
        let (hop_a_addr, _hop_a) = spawn_forwarding_mock_socks5().await;

        let chain = vec![
            ProxyConfig {
                addr: hop_a_addr,
                credentials: None,
                isolation: false,
            },
            ProxyConfig {
                addr: hop_b_addr,
                credentials: None,
                isolation: false,
            },
        ];
        let mut stream = connect_chain(&chain, final_target, None).await.unwrap();
        // Post-chain the tunnel is transparent — the bytes we write
        // should appear at hop B's "trailing" buffer.
        stream.write_all(b"chain").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"chain");
        let b_result = hop_b.await.unwrap();
        assert_eq!(b_result.trailing, b"chain");
    }

    #[tokio::test]
    async fn connect_chain_rejects_empty_chain() {
        let target: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let res = connect_chain(&[], target, None).await;
        assert!(matches!(res, Err(Socks5Error::Protocol(_))));
    }

    /// Verify the bind-iface plumbing reaches netbind: passing a
    /// nonsense interface name fails the first-hop TCP dial with an
    /// Io error from the netbind layer rather than silently falling
    /// back to the default route. Cross-platform: every platform
    /// either reports "iface not found" (Linux/macOS/BSD) or
    /// "Unsupported" (Windows), and we just need *some* IO error.
    #[tokio::test]
    async fn connect_chain_with_unknown_bind_iface_errors() {
        let target: SocketAddr = "1.1.1.1:80".parse().unwrap();
        // Use a SOCKS5 hop address that would succeed if we ever
        // reached it — the bind failure must short-circuit before
        // we get there.
        let chain = vec![ProxyConfig {
            addr: "127.0.0.1:1".parse().unwrap(),
            credentials: None,
            isolation: false,
        }];
        let res = connect_chain(&chain, target, Some("rt_nonexistent_iface_xyz123")).await;
        assert!(
            matches!(res, Err(Socks5Error::Io(_))),
            "expected Io error from netbind, got {res:?}"
        );
    }

    /// Proxy returns a non-success REP — caller surfaces it.
    #[tokio::test]
    async fn handshake_refused_returns_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            sock.read_exact(&mut methods).await.unwrap();
            sock.write_all(&[VER_SOCKS5, METHOD_NO_AUTH]).await.unwrap();
            let mut req = [0u8; 10];
            sock.read_exact(&mut req).await.unwrap();
            // REP=0x05 = connection refused by destination.
            sock.write_all(&[VER_SOCKS5, 0x05, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let res = connect(
            &ProxyConfig {
                addr: proxy_addr,
                credentials: None,
                isolation: false,
            },
            "1.1.1.1:80".parse().unwrap(),
        )
        .await;
        match res {
            Err(Socks5Error::Refused(0x05, _)) => {}
            other => panic!("expected Refused(0x05), got {other:?}"),
        }
        server.await.unwrap();
    }

    #[test]
    fn debug_output_never_contains_credentials() {
        let secret_user = "alice-secret-account".to_string();
        let secret_pass = "hunter2-super-secret".to_string();
        let cfg = ProxyConfig {
            addr: "10.0.0.1:1080".parse().unwrap(),
            credentials: Some(Credentials {
                username: secret_user.clone(),
                password: secret_pass.clone(),
            }),
            isolation: true,
        };

        let cfg_dbg = format!("{cfg:?}");
        assert!(!cfg_dbg.contains(&secret_pass), "password leaked: {cfg_dbg}");
        assert!(
            !cfg_dbg.contains(&secret_user),
            "username leaked: {cfg_dbg}"
        );
        // Non-secret fields stay readable for dial debugging.
        assert!(cfg_dbg.contains("10.0.0.1:1080"));
        assert!(cfg_dbg.contains("isolation: true"));

        let creds_dbg = format!("{:?}", cfg.credentials.as_ref().unwrap());
        assert!(!creds_dbg.contains(&secret_pass));
        assert!(!creds_dbg.contains(&secret_user));

        // The URL form is intentionally credential-bearing (reqwest needs
        // it); just pin its shape so a future refactor can't silently
        // change the scheme away from socks5h remote-DNS.
        let url = cfg.as_socks5h_url();
        assert!(url.starts_with("socks5h://") && url.ends_with("@10.0.0.1:1080"));
    }
}
