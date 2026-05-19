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
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Where the SOCKS5 server listens. Resolved IP, not a host name; if the
    /// user supplied a hostname we resolve it once at startup so we don't
    /// emit clearnet DNS queries every connection.
    pub addr: SocketAddr,
    /// Optional `(username, password)` for RFC 1929 auth.
    pub credentials: Option<Credentials>,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
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
    match timeout(PROXY_HANDSHAKE_TIMEOUT, do_connect(proxy, target)).await {
        Ok(r) => r,
        Err(_) => Err(Socks5Error::Timeout),
    }
}

async fn do_connect(proxy: &ProxyConfig, target: SocketAddr) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy.addr).await?;
    let _ = stream.set_nodelay(true);

    // Step 1 — method negotiation.
    // We always offer NO_AUTH (cheap fallback for proxies that ignore creds).
    // If we have creds, we additionally offer USER/PASS; the proxy picks one.
    let methods: &[u8] = if proxy.credentials.is_some() {
        &[METHOD_NO_AUTH, METHOD_USERPASS]
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
            do_userpass_auth(&mut stream, creds).await?;
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
    drain_bind_addr_port(&mut stream, head[3]).await?;
    Ok(stream)
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
        };
        assert_eq!(
            p.as_socks5h_url(),
            "socks5h://user%40host:p%3Ass@10.0.0.1:1080"
        );
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
            },
            "1.1.1.1:80".parse().unwrap(),
        )
        .await;
        assert!(matches!(res, Err(Socks5Error::AuthFailed)));
        server.await.unwrap();
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
}
