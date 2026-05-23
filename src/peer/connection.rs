use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};

use crate::error::{Error, Result};
use crate::peer::handshake::Handshake;
use crate::peer::message::{read_frame, write_frame, Message, BLOCK_SIZE};
use crate::peer::mse;
use crate::peer_id::PeerId;
use crate::ratelimit::TokenBucket;
use crate::socks5::{self, ProxyConfig};

pub const MAX_FRAME_LEN: u32 = (BLOCK_SIZE + 1024) * 2; // covers a 16 KiB piece + headroom
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);

/// B3 — per-peer rate limit on inbound `Request` messages. A misbehaving peer
/// can otherwise hammer us with Requests faster than we can read pieces off
/// disk, turning into a cheap DoS against the upload side. We replenish at
/// `REQUEST_TOKENS_PER_SEC` per second with a hard ceiling of
/// `REQUEST_BURST_TOKENS` — anything over is silently dropped from the event
/// stream (we don't disconnect: a brief burst from a real fast peer is
/// indistinguishable from abuse, and the peer will just re-request later).
///
/// Default sized for honest fast peers: 200 req/s sustained, 50 burst. At
/// 16 KiB block size that caps a single peer's read pressure on the disk
/// task to ~3 MiB/s steady-state — well above any real seed rate.
pub const REQUEST_TOKENS_PER_SEC: f64 = 200.0;
pub const REQUEST_BURST_TOKENS: f64 = 50.0;

/// Events emitted by a peer task to the engine.
#[derive(Debug)]
pub enum PeerEvent {
    Connected {
        addr: SocketAddr,
        peer_id: PeerId,
    },
    Disconnected {
        addr: SocketAddr,
        reason: String,
    },
    Bitfield {
        addr: SocketAddr,
        bits: bitvec::vec::BitVec<u8, bitvec::order::Msb0>,
    },
    Have {
        addr: SocketAddr,
        index: u32,
    },
    Choke {
        addr: SocketAddr,
    },
    Unchoke {
        addr: SocketAddr,
    },
    Interested {
        addr: SocketAddr,
    },
    NotInterested {
        addr: SocketAddr,
    },
    Block {
        addr: SocketAddr,
        index: u32,
        begin: u32,
        data: Vec<u8>,
    },
    Request {
        addr: SocketAddr,
        index: u32,
        begin: u32,
        length: u32,
    },
    Cancel {
        addr: SocketAddr,
        index: u32,
        begin: u32,
        length: u32,
    },
    /// BEP 11 PEX — peer is sharing additional peer addresses with us.
    /// The engine adds them to the connection pool, deduplicated.
    Pex {
        addr: SocketAddr,
        peers: Vec<SocketAddr>,
    },
    /// BEP 10 extension handshake parsed out of an Extended { ext_id: 0 }
    /// frame. Lets the engine learn which numeric IDs this peer wants us
    /// to use when we send them extension messages (specifically:
    /// `ut_pex` for outgoing PEX).
    ExtensionHandshake {
        addr: SocketAddr,
        their_ut_pex_id: Option<u8>,
    },
}

/// Commands the engine sends to a single peer task.
#[derive(Debug)]
pub enum PeerCommand {
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Have(u32),
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Piece {
        index: u32,
        begin: u32,
        data: Vec<u8>,
    },
    Bitfield(Vec<u8>),
    /// BEP 10 — engine wants this peer to receive a generic extension
    /// message. Used today for outgoing BEP 11 PEX; the `ext_id` is
    /// the peer's advertised id for the extension in question.
    Extension {
        ext_id: u8,
        payload: Vec<u8>,
    },
}

/// Outbound side of a peer task — the engine keeps one of these per peer.
pub type PeerHandle = mpsc::Sender<PeerCommand>;

/// Run an outgoing peer connection. The caller already chose the address
/// and provided shared `info_hash` + our `peer_id`.
///
/// Tries plain BitTorrent first (preserves compatibility with peers that
/// only speak plain — e.g. localhost self-tests, simple OSS clients). On
/// the signature failure of an MSE-only peer (we send `\x13BitTorrent…`,
/// they immediately drop the connection) the caller is silently retried
/// over MSE/PE.
#[allow(clippy::too_many_arguments)] // each arg is a distinct dial-time knob
pub async fn run_outgoing(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    proxies: Vec<ProxyConfig>,
    bind_iface: Option<String>,
    anonymous: bool,
) -> Result<()> {
    tracing::debug!(target: "peer", %addr, hops = proxies.len(), bind = ?bind_iface, "dialing (plain)");
    let iface = bind_iface.as_deref();
    let outcome = match plain_handshake(addr, info_hash, peer_id, &proxies, iface).await {
        Ok((reader, writer, theirs)) => {
            let supports_ext =
                crate::peer::handshake::supports_extension_protocol(&theirs.reserved);
            let _ = event_tx
                .send(PeerEvent::Connected {
                    addr,
                    peer_id: theirs.peer_id,
                })
                .await;
            post_handshake_loop(
                reader,
                writer,
                addr,
                event_tx.clone(),
                cmd_rx,
                supports_ext,
                anonymous,
            )
            .await
        }
        Err(e) if is_likely_mse_signal(&e) => {
            tracing::debug!(target: "peer", %addr, reason = %e, "plain failed, retrying with MSE");
            match mse_handshake_outgoing(addr, info_hash, peer_id, &proxies, iface).await {
                Ok((reader, writer, theirs)) => {
                    let supports_ext =
                        crate::peer::handshake::supports_extension_protocol(&theirs.reserved);
                    let _ = event_tx
                        .send(PeerEvent::Connected {
                            addr,
                            peer_id: theirs.peer_id,
                        })
                        .await;
                    post_handshake_loop(
                        reader,
                        writer,
                        addr,
                        event_tx.clone(),
                        cmd_rx,
                        supports_ext,
                        anonymous,
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    };

    let reason = outcome
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "closed".to_string());
    let _ = event_tx
        .send(PeerEvent::Disconnected { addr, reason })
        .await;
    outcome
}

/// Run an outgoing peer connection forcing MSE/PE — no plain attempt.
/// Useful when the swarm is known to be MSE-only, or to drive the
/// encrypted path in self-tests.
#[allow(clippy::too_many_arguments)] // each arg is a distinct dial-time knob
pub async fn run_outgoing_mse_only(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    proxies: Vec<ProxyConfig>,
    bind_iface: Option<String>,
    anonymous: bool,
) -> Result<()> {
    tracing::debug!(target: "peer", %addr, hops = proxies.len(), bind = ?bind_iface, "dialing (MSE-only)");
    let outcome =
        match mse_handshake_outgoing(addr, info_hash, peer_id, &proxies, bind_iface.as_deref())
            .await
        {
            Ok((reader, writer, theirs)) => {
                let supports_ext =
                    crate::peer::handshake::supports_extension_protocol(&theirs.reserved);
                let _ = event_tx
                    .send(PeerEvent::Connected {
                        addr,
                        peer_id: theirs.peer_id,
                    })
                    .await;
                post_handshake_loop(
                    reader,
                    writer,
                    addr,
                    event_tx.clone(),
                    cmd_rx,
                    supports_ext,
                    anonymous,
                )
                .await
            }
            Err(e) => Err(e),
        };
    let reason = outcome
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "closed".to_string());
    let _ = event_tx
        .send(PeerEvent::Disconnected { addr, reason })
        .await;
    outcome
}

/// Heuristic: if a plain handshake failed in any of these specific ways,
/// the most likely explanation is that the peer is MSE-only.
fn is_likely_mse_signal(e: &Error) -> bool {
    match e {
        Error::Handshake(s) => {
            s.contains("early eof")
                || s.contains("bad pstrlen")
                || s.contains("bad protocol string")
                || s.contains("read: unexpected end of file")
        }
        // Network "Connection reset by peer" immediately after our bytes
        // is the third common signature of an MSE-only peer dropping us.
        Error::Network(s) => s.contains("Connection reset"),
        _ => false,
    }
}

/// Open a TCP connection (direct or via SOCKS5 chain), perform the plain
/// BitTorrent handshake, return the split read/write halves.
async fn plain_handshake(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    proxies: &[ProxyConfig],
    bind_iface: Option<&str>,
) -> Result<(OwnedReadHalf, OwnedWriteHalf, Handshake)> {
    let mut stream = dial(addr, proxies, bind_iface).await?;
    let _ = stream.set_nodelay(true);
    let theirs = match timeout(
        HANDSHAKE_TIMEOUT,
        Handshake::perform_outgoing(&mut stream, info_hash, peer_id),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(Error::Handshake("timeout".into())),
    };
    let (read_half, write_half) = stream.into_split();
    Ok((read_half, write_half, theirs))
}

/// Open a TCP connection to `addr`, going through the SOCKS5 chain if
/// any is configured. Empty `proxies` → direct dial. Length-1 chain →
/// single-hop SOCKS5. Length-N chain → nested SOCKS5 CONNECTs on one
/// TCP stream (C1: defeats single-proxy compromise). The returned
/// `TcpStream` is, post-handshake, a transparent byte-pipe to `addr`.
async fn dial(
    addr: SocketAddr,
    proxies: &[ProxyConfig],
    bind_iface: Option<&str>,
) -> Result<TcpStream> {
    if !proxies.is_empty() {
        // Through a SOCKS5 chain: we connect to the first hop's IP, not
        // the peer's. The bind-iface decision applies to the FIRST hop's
        // TCP connection only (intermediate hops ride that single
        // stream). socks5::connect_chain does its own TcpStream::connect
        // under the hood — to enforce the bound iface we'd need to wire
        // it through socks5. For now, refuse the combination loudly
        // rather than silently leak via the default route.
        if bind_iface.is_some() {
            return Err(Error::Network(
                "--bind-iface + --socks5 not yet supported together".into(),
            ));
        }
        // Materialize the per-dial config for each hop: when stream
        // isolation is on this generates a fresh random SOCKS5
        // username on that hop so Tor puts this dial on its own
        // circuit. Hops without isolation are cloned as-is.
        let effective: Vec<ProxyConfig> = proxies.iter().map(|p| p.for_dial()).collect();
        return socks5::connect_chain(&effective, addr)
            .await
            .map_err(|e| Error::Network(format!("socks5 dial {addr}: {e}")));
    }
    match bind_iface {
        Some(iface) => {
            match timeout(
                Duration::from_secs(10),
                crate::netbind::connect_via_interface(addr, iface),
            )
            .await
            {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(Error::Network(format!("connect {addr} via {iface}: {e}"))),
                Err(_) => Err(Error::Network(format!(
                    "connect {addr} via {iface}: timeout"
                ))),
            }
        }
        None => match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(Error::Network(format!("connect {addr}: {e}"))),
            Err(_) => Err(Error::Network(format!("connect {addr}: timeout"))),
        },
    }
}

/// Open a fresh TCP connection (direct or via SOCKS5), drive the MSE
/// handshake, then the BT handshake over the encrypted stream. Return the
/// split RC4-wrapped halves.
async fn mse_handshake_outgoing(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    proxies: &[ProxyConfig],
    bind_iface: Option<&str>,
) -> Result<(
    mse::Rc4Reader<OwnedReadHalf>,
    mse::Rc4Writer<OwnedWriteHalf>,
    Handshake,
)> {
    let stream = dial(addr, proxies, bind_iface).await?;
    let _ = stream.set_nodelay(true);

    // MSE handshake first. After this, all reads/writes through `enc` are
    // RC4'd transparently.
    let mut enc = match timeout(HANDSHAKE_TIMEOUT, mse::perform_outgoing(stream, info_hash)).await {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return Err(Error::Handshake(format!("mse: {e}"))),
        Err(_) => return Err(Error::Handshake("mse timeout".into())),
    };

    // Standard BT handshake — its bytes flow through the encryption.
    let theirs = match timeout(
        HANDSHAKE_TIMEOUT,
        Handshake::perform_outgoing(&mut enc, info_hash, peer_id),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(Error::Handshake("bt-over-mse timeout".into())),
    };

    // Pull out the raw socket + ciphers (now advanced past the BT
    // handshake) and split into per-direction wrappers.
    let (raw_stream, in_cipher, out_cipher) = enc.into_parts();
    let (read_half, write_half) = raw_stream.into_split();
    Ok((
        mse::Rc4Reader::new(read_half, in_cipher),
        mse::Rc4Writer::new(write_half, out_cipher),
        theirs,
    ))
}

/// Run a peer task on an already-connected stream from an inbound TCP
/// accept. Peeks the first byte to decide between plain BT (0x13) and MSE
/// (anything else — the start of `Ya`), then dispatches.
#[allow(clippy::too_many_arguments)] // each arg is a distinct dial-time knob
pub async fn run_with_stream(
    stream: TcpStream,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    outgoing: bool,
    anonymous: bool,
) -> Result<()> {
    let outcome = if outgoing {
        // Outgoing-on-existing-stream is only used by tests today; keep it
        // plain-only since the caller already chose this path.
        run_plain_on_stream(
            stream,
            addr,
            info_hash,
            peer_id,
            event_tx.clone(),
            cmd_rx,
            true,
            anonymous,
        )
        .await
    } else {
        run_incoming_dispatch(
            stream,
            addr,
            info_hash,
            peer_id,
            event_tx.clone(),
            cmd_rx,
            anonymous,
        )
        .await
    };

    let reason = outcome
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "closed".to_string());
    let _ = event_tx
        .send(PeerEvent::Disconnected { addr, reason })
        .await;
    outcome
}

/// Plain BT handshake on an already-connected stream, then the standard
/// post-handshake loop.
#[allow(clippy::too_many_arguments)] // each arg is a distinct dial-time knob
async fn run_plain_on_stream(
    mut stream: TcpStream,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    outgoing: bool,
    anonymous: bool,
) -> Result<()> {
    let theirs = match timeout(HANDSHAKE_TIMEOUT, async {
        if outgoing {
            Handshake::perform_outgoing(&mut stream, info_hash, peer_id).await
        } else {
            Handshake::perform_incoming(&mut stream, info_hash, peer_id).await
        }
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(Error::Handshake("timeout".into())),
    };
    let supports_ext = crate::peer::handshake::supports_extension_protocol(&theirs.reserved);
    let _ = event_tx
        .send(PeerEvent::Connected {
            addr,
            peer_id: theirs.peer_id,
        })
        .await;
    let (reader, writer) = stream.into_split();
    post_handshake_loop(
        reader,
        writer,
        addr,
        event_tx,
        cmd_rx,
        supports_ext,
        anonymous,
    )
    .await
}

/// Inbound connection dispatcher: peek the first byte and pick the right path.
async fn run_incoming_dispatch(
    stream: TcpStream,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    anonymous: bool,
) -> Result<()> {
    // MSG_PEEK lets us inspect the byte without consuming it. tokio's
    // `TcpStream::peek` returns the number of bytes copied; 0 means EOF.
    let mut peek_buf = [0u8; 1];
    let peeked = match timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut peek_buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(Error::Network(format!("peek: {e}"))),
        Err(_) => return Err(Error::Handshake("peek timeout".into())),
    };
    if peeked == 0 {
        return Err(Error::Network("peer closed before handshake".into()));
    }
    if peek_buf[0] == crate::peer::handshake::PSTRLEN {
        // 0x13 → plain BT.
        run_plain_on_stream(
            stream, addr, info_hash, peer_id, event_tx, cmd_rx, false, anonymous,
        )
        .await
    } else {
        // Anything else → assume MSE/PE; the peeked byte is the first byte of Ya.
        run_mse_on_stream(
            stream, addr, info_hash, peer_id, event_tx, cmd_rx, anonymous,
        )
        .await
    }
}

/// MSE-over-stream incoming flow. The peek above did NOT consume the byte
/// (MSG_PEEK), so the inner MSE handshake reads `Ya` from the start.
async fn run_mse_on_stream(
    stream: TcpStream,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    anonymous: bool,
) -> Result<()> {
    let info_hashes = [info_hash];
    let (mut enc, _matched) = match timeout(
        HANDSHAKE_TIMEOUT,
        mse::perform_incoming(stream, &info_hashes, &[]),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(Error::Handshake(format!("mse incoming: {e}"))),
        Err(_) => return Err(Error::Handshake("mse incoming timeout".into())),
    };

    // BT handshake over the encrypted stream — we're the receiver here.
    let theirs = match timeout(
        HANDSHAKE_TIMEOUT,
        Handshake::perform_incoming(&mut enc, info_hash, peer_id),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(Error::Handshake("bt-over-mse incoming timeout".into())),
    };
    let supports_ext = crate::peer::handshake::supports_extension_protocol(&theirs.reserved);
    let _ = event_tx
        .send(PeerEvent::Connected {
            addr,
            peer_id: theirs.peer_id,
        })
        .await;

    let (raw, in_cipher, out_cipher) = enc.into_parts();
    let (read_half, write_half) = raw.into_split();
    let reader = mse::Rc4Reader::new(read_half, in_cipher);
    let writer = mse::Rc4Writer::new(write_half, out_cipher);
    post_handshake_loop(
        reader,
        writer,
        addr,
        event_tx,
        cmd_rx,
        supports_ext,
        anonymous,
    )
    .await
}

/// The generic post-handshake event loop. The read side runs on its own
/// task (so `read_exact` is never dropped mid-read by a `select!`); the
/// write side multiplexes `cmd_rx`, a keep-alive timer, and a oneshot
/// shutdown signal from the read task.
///
/// Generic over the reader/writer types so the same loop serves:
/// - plain peers: `OwnedReadHalf` / `OwnedWriteHalf` of a `TcpStream`
/// - MSE peers: `Rc4Reader<OwnedReadHalf>` / `Rc4Writer<OwnedWriteHalf>`
async fn post_handshake_loop<R, W>(
    mut reader: R,
    mut writer: W,
    addr: SocketAddr,
    event_tx: mpsc::Sender<PeerEvent>,
    mut cmd_rx: mpsc::Receiver<PeerCommand>,
    peer_supports_extension: bool,
    anonymous: bool,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    // BEP 10 — if the peer set the extension-protocol reserved bit,
    // reciprocate by sending our `m` dict so they know which ext_id
    // to use when forwarding us PEX (and ut_metadata, which we
    // silently ignore today). Peers that didn't advertise BEP 10 may
    // close the connection on an unknown id=20 frame, so we gate.
    // Anonymous mode strips the `v` and `reqq` fields from the payload
    // — those uniquely fingerprint us as rustytorrent.
    if peer_supports_extension {
        let payload = crate::peer::extension::build_handshake_payload(anonymous);
        let msg = Message::Extended {
            ext_id: crate::peer::extension::EXT_HANDSHAKE_ID,
            payload,
        };
        if let Err(e) = crate::peer::message::write_message(&mut writer, &msg).await {
            // Non-fatal — log and proceed; the peer still gets the
            // regular BT message stream, just without PEX.
            tracing::debug!(target: "peer", %addr, error = %e, "ext handshake send failed");
        }
    }
    let read_event_tx = event_tx.clone();
    let (read_done_tx, mut read_done_rx) = tokio::sync::oneshot::channel::<Result<()>>();
    let read_task = tokio::spawn(async move {
        let res: Result<()> = async {
            let mut request_bucket = TokenBucket::new(REQUEST_BURST_TOKENS, REQUEST_TOKENS_PER_SEC);
            loop {
                let frame = read_frame(&mut reader, MAX_FRAME_LEN).await?;
                let msg = Message::decode(&frame)?;
                // B3 — throttle inbound Request messages per peer. Drop the
                // event when the bucket's dry; the peer will re-request
                // and we'll catch up on the next refill window. We don't
                // disconnect here so honest fast peers aren't punished
                // for short bursts that happen to land hot.
                if matches!(msg, Message::Request { .. }) && !request_bucket.try_consume(1.0) {
                    tracing::debug!(
                        target: "peer",
                        %addr,
                        "request rate-limit hit; dropping Request frame"
                    );
                    continue;
                }
                // BEP 10 / 11 — the extension protocol envelope. We
                // care about two specific ext_ids:
                //   - 0: the peer's extension handshake, which tells us
                //     which numeric id THEY want us to use when sending
                //     them ut_pex. We bubble that up so the engine can
                //     start sending outgoing PEX.
                //   - OUR_UT_PEX_ID: incoming PEX peer-list updates,
                //     which we parse + forward to the engine for
                //     `PeerManager::try_connect_many`.
                // Anything else (ut_metadata requests we don't serve,
                // unknown extensions) is silently dropped per the spec.
                if let Message::Extended { ext_id, payload } = &msg {
                    if *ext_id == crate::peer::extension::EXT_HANDSHAKE_ID {
                        match crate::peer::extension::parse_handshake_payload(payload) {
                            Ok(info) => {
                                let ev = PeerEvent::ExtensionHandshake {
                                    addr,
                                    their_ut_pex_id: info.their_ut_pex_id,
                                };
                                if read_event_tx.send(ev).await.is_err() {
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                tracing::debug!(target: "peer", %addr, error = %e, "ext handshake parse");
                            }
                        }
                        continue;
                    }
                    if *ext_id == crate::peer::extension::OUR_UT_PEX_ID {
                        match crate::peer::extension::parse_pex(payload) {
                            Ok(pex) if !pex.added.is_empty() => {
                                let ev = PeerEvent::Pex {
                                    addr,
                                    peers: pex.added,
                                };
                                if read_event_tx.send(ev).await.is_err() {
                                    return Ok(());
                                }
                            }
                            Ok(_) => {} // empty payload, nothing to do
                            Err(e) => {
                                tracing::debug!(target: "peer", %addr, error = %e, "ut_pex parse");
                            }
                        }
                        continue;
                    }
                }
                if let Some(ev) = msg_to_event(addr, msg) {
                    if read_event_tx.send(ev).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
        .await;
        let _ = read_done_tx.send(res);
    });

    let result: Result<()> = async {
        let mut last_send = Instant::now();
        loop {
            let until_next_keepalive = KEEPALIVE_INTERVAL
                .checked_sub(last_send.elapsed())
                .unwrap_or_else(|| Duration::from_secs(1));

            tokio::select! {
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { return Ok(()); };
                    let bytes = match cmd {
                        PeerCommand::Request { index, begin, length } =>
                            Message::Request { index, begin, length }.encode(),
                        PeerCommand::Cancel { index, begin, length } =>
                            Message::Cancel { index, begin, length }.encode(),
                        PeerCommand::Have(i) => Message::Have(i).encode(),
                        PeerCommand::Choke => Message::Choke.encode(),
                        PeerCommand::Unchoke => Message::Unchoke.encode(),
                        PeerCommand::Interested => Message::Interested.encode(),
                        PeerCommand::NotInterested => Message::NotInterested.encode(),
                        PeerCommand::Piece { index, begin, data } =>
                            Message::Piece { index, begin, data }.encode(),
                        PeerCommand::Bitfield(b) => Message::Bitfield(b).encode(),
                        PeerCommand::Extension { ext_id, payload } =>
                            Message::Extended { ext_id, payload }.encode(),
                    };
                    writer.write_all(&bytes).await
                        .map_err(|e| Error::Network(format!("write: {e}")))?;
                    last_send = Instant::now();
                }
                _ = tokio::time::sleep(until_next_keepalive) => {
                    write_frame(&mut writer, &[]).await?;
                    last_send = Instant::now();
                }
                read_result = &mut read_done_rx => {
                    return match read_result {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(e),
                        Err(_) => Ok(()),
                    };
                }
            }
        }
    }
    .await;
    read_task.abort();
    result
}

fn msg_to_event(addr: SocketAddr, msg: Message) -> Option<PeerEvent> {
    match msg {
        Message::KeepAlive => None,
        Message::Choke => Some(PeerEvent::Choke { addr }),
        Message::Unchoke => Some(PeerEvent::Unchoke { addr }),
        Message::Interested => Some(PeerEvent::Interested { addr }),
        Message::NotInterested => Some(PeerEvent::NotInterested { addr }),
        Message::Have(index) => Some(PeerEvent::Have { addr, index }),
        Message::Bitfield(bytes) => {
            // The peer-task layer doesn't know `num_pieces` (that lives with the
            // engine that owns the .torrent), so we expand the raw bytes as
            // `bytes.len() * 8` MSb0 bits and let the engine ignore tail bits
            // past its known piece count when it calls `set_peer_bitfield`.
            let mut bv: bitvec::vec::BitVec<u8, bitvec::order::Msb0> =
                bitvec::vec::BitVec::repeat(false, bytes.len() * 8);
            for (i, b) in bytes.iter().enumerate() {
                for j in 0..8 {
                    if (b >> (7 - j)) & 1 == 1 {
                        bv.set(i * 8 + j, true);
                    }
                }
            }
            Some(PeerEvent::Bitfield { addr, bits: bv })
        }
        Message::Request {
            index,
            begin,
            length,
        } => Some(PeerEvent::Request {
            addr,
            index,
            begin,
            length,
        }),
        Message::Piece { index, begin, data } => Some(PeerEvent::Block {
            addr,
            index,
            begin,
            data,
        }),
        Message::Cancel {
            index,
            begin,
            length,
        } => Some(PeerEvent::Cancel {
            addr,
            index,
            begin,
            length,
        }),
        // BEP 10 extension messages aren't handled by the engine loop —
        // ut_metadata is consumed by the dedicated magnet-bootstrap
        // fetcher, and ut_pex isn't wired in yet. Silently drop so peers
        // that advertise these extensions don't blow up the connection
        // by sending them. BEP 10 spec explicitly permits ignoring
        // extension messages we don't understand.
        Message::Extended { .. } => None,
    }
}
