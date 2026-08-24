use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::tracker::{AnnounceRequest, AnnounceResponse};

const PROTOCOL_ID: u64 = 0x41727101980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const ACTION_ERROR: u32 = 3;

const MAX_RETRIES: u32 = 4; // 15 * 2^n: 15s, 30s, 60s, 120s
const BASE_TIMEOUT_SECS: u64 = 15;

/// Per BEP 15 the tracker may discard a `connection_id` 60 s after it was
/// issued; clients are advised to refresh well before that. We treat ids
/// older than 45 s as stale and re-do the connect step before announcing.
const CONNECTION_ID_MAX_AGE: Duration = Duration::from_secs(45);

pub async fn announce(url: &str, req: &AnnounceRequest, bind_iface: Option<&str>) -> Result<AnnounceResponse> {
    let host_port = url
        .strip_prefix("udp://")
        .ok_or_else(|| Error::Tracker(format!("not a udp URL: {url}")))?;
    // strip optional /path or /announce
    let host_port = host_port.split('/').next().unwrap_or(host_port);
    let addr: SocketAddr = tokio::net::lookup_host(host_port)
        .await
        .map_err(|e| Error::Tracker(format!("dns: {e}")))?
        .next()
        .ok_or_else(|| Error::Tracker("dns: no addrs".into()))?;
    tracing::debug!(target: "tracker::udp", %addr, "announcing");

    let bind_addr: SocketAddr = if addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    };
    // With --bind-iface (the VPN kill switch) the announce socket must be
    // pinned to that interface: if the tunnel drops we fail closed instead
    // of egressing the default route with our real IP.
    let sock = match bind_iface {
        Some(iface) => crate::netbind::bind_udp_to_interface(bind_addr, iface)
            .map_err(|e| Error::Tracker(format!("udp bind via {iface}: {e}")))?,
        None => UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| Error::Tracker(format!("udp bind: {e}")))?,
    };
    sock.connect(addr)
        .await
        .map_err(|e| Error::Tracker(format!("udp connect: {e}")))?;

    let (connection_id, connect_time) = connect(&sock).await?;
    do_announce(&sock, connection_id, connect_time, req).await
}

async fn connect(sock: &UdpSocket) -> Result<(u64, Instant)> {
    for attempt in 0..MAX_RETRIES {
        let mut transaction_id_buf = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut transaction_id_buf);
        let transaction_id = u32::from_be_bytes(transaction_id_buf);

        let mut packet = [0u8; 16];
        packet[..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
        packet[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
        packet[12..16].copy_from_slice(&transaction_id.to_be_bytes());

        sock.send(&packet)
            .await
            .map_err(|e| Error::Tracker(format!("udp send connect: {e}")))?;

        let mut buf = [0u8; 1500];
        let wait = Duration::from_secs(BASE_TIMEOUT_SECS << attempt);
        match timeout(wait, sock.recv(&mut buf)).await {
            Err(_) => {
                tracing::debug!(
                    target: "tracker::udp",
                    attempt,
                    waited = ?wait,
                    "connect timeout, retrying"
                );
                continue;
            }
            Ok(Err(e)) => return Err(Error::Tracker(format!("udp recv connect: {e}"))),
            Ok(Ok(n)) => {
                if n < 16 {
                    return Err(Error::Tracker(format!("connect resp too short: {n}")));
                }
                let action = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let txid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                if txid != transaction_id {
                    tracing::warn!(target: "tracker::udp", "transaction id mismatch");
                    continue;
                }
                if action == ACTION_ERROR {
                    let msg = std::str::from_utf8(&buf[8..n]).unwrap_or("<non-utf8>");
                    return Err(Error::Tracker(format!("connect error: {msg}")));
                }
                if action != ACTION_CONNECT {
                    return Err(Error::Tracker(format!("connect bad action {action}")));
                }
                let cid = u64::from_be_bytes([
                    buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ]);
                return Ok((cid, Instant::now()));
            }
        }
    }
    Err(Error::Tracker("connect retries exhausted".into()))
}

async fn do_announce(
    sock: &UdpSocket,
    mut connection_id: u64,
    mut connect_time: Instant,
    req: &AnnounceRequest,
) -> Result<AnnounceResponse> {
    for attempt in 0..MAX_RETRIES {
        // Refresh the connection_id if it's about to expire (BEP 15: trackers
        // accept ids for 60 s after issue; we re-handshake at 45 s).
        if connect_time.elapsed() >= CONNECTION_ID_MAX_AGE {
            tracing::debug!(target: "tracker::udp", "connection_id stale; reconnecting");
            let (new_id, new_time) = connect(sock).await?;
            connection_id = new_id;
            connect_time = new_time;
        }

        let mut transaction_id_buf = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut transaction_id_buf);
        let transaction_id = u32::from_be_bytes(transaction_id_buf);

        let mut key_buf = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut key_buf);
        let key = u32::from_be_bytes(key_buf);

        let packet = build_announce_packet(connection_id, transaction_id, key, req);
        sock.send(&packet)
            .await
            .map_err(|e| Error::Tracker(format!("udp send announce: {e}")))?;

        let mut buf = vec![0u8; 65535];
        let wait = Duration::from_secs(BASE_TIMEOUT_SECS << attempt);
        match timeout(wait, sock.recv(&mut buf)).await {
            Err(_) => {
                tracing::debug!(
                    target: "tracker::udp",
                    attempt,
                    waited = ?wait,
                    "announce timeout, retrying"
                );
                continue;
            }
            Ok(Err(e)) => return Err(Error::Tracker(format!("udp recv announce: {e}"))),
            Ok(Ok(n)) => {
                if n < 8 {
                    return Err(Error::Tracker("announce resp too short".into()));
                }
                let action = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let txid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                if txid != transaction_id {
                    tracing::warn!(target: "tracker::udp", "txn mismatch on announce");
                    continue;
                }
                if action == ACTION_ERROR {
                    let msg = std::str::from_utf8(&buf[8..n]).unwrap_or("<non-utf8>");
                    // Trackers commonly respond with "Connection ID missmatch"
                    // (sic) when the id was retired early (clock drift, restart).
                    // Force a fresh connect on the next iteration rather than
                    // failing the whole announce.
                    tracing::debug!(
                        target: "tracker::udp",
                        attempt,
                        error = msg,
                        "tracker error response; reconnecting"
                    );
                    connect_time = Instant::now() - CONNECTION_ID_MAX_AGE;
                    continue;
                }
                if action != ACTION_ANNOUNCE {
                    return Err(Error::Tracker(format!("announce bad action {action}")));
                }
                return parse_announce_response(&buf[..n]);
            }
        }
    }
    Err(Error::Tracker("announce retries exhausted".into()))
}

fn build_announce_packet(
    connection_id: u64,
    transaction_id: u32,
    key: u32,
    req: &AnnounceRequest,
) -> [u8; 98] {
    let mut p = [0u8; 98];
    p[0..8].copy_from_slice(&connection_id.to_be_bytes());
    p[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    p[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    p[16..36].copy_from_slice(&req.info_hash);
    p[36..56].copy_from_slice(&req.peer_id);
    p[56..64].copy_from_slice(&req.downloaded.to_be_bytes());
    p[64..72].copy_from_slice(&req.left.to_be_bytes());
    p[72..80].copy_from_slice(&req.uploaded.to_be_bytes());
    p[80..84].copy_from_slice(&req.event.as_udp_code().to_be_bytes());
    p[84..88].copy_from_slice(&0u32.to_be_bytes()); // ip = 0 (use sender)
    p[88..92].copy_from_slice(&key.to_be_bytes());
    p[92..96].copy_from_slice(&req.num_want.to_be_bytes());
    p[96..98].copy_from_slice(&req.port.to_be_bytes());
    p
}

pub fn parse_announce_response(buf: &[u8]) -> Result<AnnounceResponse> {
    if buf.len() < 20 {
        return Err(Error::Tracker("announce resp header < 20 bytes".into()));
    }
    let interval = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let leechers = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let seeders = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let peers_bytes = &buf[20..];
    if !peers_bytes.len().is_multiple_of(6) {
        return Err(Error::Tracker(format!(
            "peer payload {} not multiple of 6",
            peers_bytes.len()
        )));
    }
    let mut peers = Vec::with_capacity(peers_bytes.len() / 6);
    for c in peers_bytes.chunks_exact(6) {
        let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
        let port = u16::from_be_bytes([c[4], c[5]]);
        peers.push(SocketAddr::new(IpAddr::V4(ip), port));
    }
    Ok(AnnounceResponse {
        interval: Duration::from_secs(interval as u64),
        min_interval: None,
        seeders: Some(seeders),
        leechers: Some(leechers),
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_packet_layout() {
        let req = AnnounceRequest {
            info_hash: [0xAB; 20],
            peer_id: [0xCD; 20],
            port: 6881,
            uploaded: 1,
            downloaded: 2,
            left: 3,
            event: crate::tracker::Event::Started,
            num_want: 50,
        };
        let p = build_announce_packet(0xDEADBEEF_DEADBEEFu64, 0x12345678, 0x55555555, &req);
        assert_eq!(p.len(), 98);
        assert_eq!(&p[0..8], &0xDEADBEEF_DEADBEEFu64.to_be_bytes());
        assert_eq!(&p[8..12], &1u32.to_be_bytes()); // action=announce
        assert_eq!(&p[12..16], &0x12345678u32.to_be_bytes());
        assert_eq!(&p[16..36], &[0xAB; 20]);
        assert_eq!(&p[36..56], &[0xCD; 20]);
        assert_eq!(&p[56..64], &2u64.to_be_bytes());
        assert_eq!(&p[64..72], &3u64.to_be_bytes());
        assert_eq!(&p[72..80], &1u64.to_be_bytes());
        assert_eq!(&p[80..84], &2u32.to_be_bytes()); // event=started
        assert_eq!(&p[84..88], &0u32.to_be_bytes());
        assert_eq!(&p[88..92], &0x55555555u32.to_be_bytes());
        assert_eq!(&p[92..96], &50i32.to_be_bytes());
        assert_eq!(&p[96..98], &6881u16.to_be_bytes());
    }

    #[test]
    fn protocol_id_magic() {
        // Per BEP 15.
        assert_eq!(PROTOCOL_ID, 0x0000_0417_2710_1980);
    }

    #[test]
    fn parse_announce_response_minimal() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // action
        buf.extend_from_slice(&0xABCD_1234u32.to_be_bytes()); // txid
        buf.extend_from_slice(&900u32.to_be_bytes()); // interval
        buf.extend_from_slice(&5u32.to_be_bytes()); // leechers
        buf.extend_from_slice(&10u32.to_be_bytes()); // seeders
        buf.extend_from_slice(&[1, 2, 3, 4, 0x1A, 0xE1]);
        let r = parse_announce_response(&buf).unwrap();
        assert_eq!(r.interval, Duration::from_secs(900));
        assert_eq!(r.seeders, Some(10));
        assert_eq!(r.leechers, Some(5));
        assert_eq!(r.peers.len(), 1);
        assert_eq!(r.peers[0].to_string(), "1.2.3.4:6881");
    }

    #[test]
    fn parse_announce_response_short() {
        assert!(parse_announce_response(&[0u8; 8]).is_err());
    }
}
