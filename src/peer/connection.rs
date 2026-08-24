use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{split, AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};

use crate::error::{Error, Result};
use crate::peer::handshake::Handshake;
use crate::peer::message::{read_frame_into, write_frame, Message, BLOCK_SIZE};
use crate::peer::mse;
use crate::peer::transport::Transport;
use crate::peer::utp::UtpSocket;
use crate::peer_id::PeerId;
use crate::ratelimit::TokenBucket;
use crate::socks5::{self, ProxyConfig};

pub const MAX_FRAME_LEN: u32 = (BLOCK_SIZE + 1024) * 2; // covers a 16 KiB piece + headroom
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);
/// Liveness bound on the READ side. We send keepalives when the write
/// side goes idle, but nothing forced us to notice a peer that simply
/// never speaks again — such peers would hold their `MAX_PEERS` slots
/// forever and a few dozen of them could stall connectivity entirely.
/// BEP 3 keepalive convention is ~2 minutes; 5 minutes of total silence
/// means the peer (or its NAT mapping) is gone.
pub const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Liveness bound on the WRITE side. A peer that stops reading (full TCP
/// receive window) blocks every write forever; if it keeps OUR read side
/// fed with periodic keepalives, neither the read-idle timeout nor our
/// own keepalive timer can fire and the slot is occupied permanently.
/// Bound each individual write so a stalled peer is disconnected instead.
pub const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(120);

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
        /// Full 8-byte reserved field from the peer's BT handshake. The
        /// engine uses this to decide which capability-specific initial
        /// messages to send (e.g. BEP 6 `HaveAll`/`HaveNone`).
        peer_reserved: [u8; 8],
    },
    Disconnected {
        addr: SocketAddr,
        reason: String,
        /// True when the disconnect was caused by a clear BEP 3
        /// protocol violation — bad pstr, wrong info_hash, oversized
        /// frame, malformed message — rather than a benign network
        /// event (EOF mid-read, timeout, reset). Drives the
        /// per-IP "ban on repeated protocol violations" escalation
        /// in [`crate::peer::manager::PeerManager`].
        violation: bool,
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
    /// BEP 6 fast extensions — peer has every piece (seeder). The engine
    /// should treat this the same as a full `Bitfield`.
    HaveAll {
        addr: SocketAddr,
    },
    /// BEP 6 fast extensions — peer rejected our `Request` (e.g. they
    /// chopped the upload queue). We release the block for re-request.
    RejectRequest {
        addr: SocketAddr,
        index: u32,
        begin: u32,
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
    /// BEP 6 — send `HaveAll` to a peer that supports fast extensions
    /// instead of a full Bitfield (seeder shorthand).
    HaveAll,
    /// BEP 6 — send `HaveNone` to a peer that supports fast extensions
    /// instead of an empty Bitfield (new-leecher shorthand).
    HaveNone,
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
    utp: Option<Arc<UtpSocket>>,
) -> Result<()> {
    tracing::debug!(target: "peer", %addr, hops = proxies.len(), bind = ?bind_iface, utp = utp.is_some(), "dialing (plain)");
    let iface = bind_iface.as_deref();
    let outcome = async {
        // Establish a transport (TCP, or a TCP+µTP race when µTP is
        // enabled on a clearnet direct path), then try plain BT.
        let transport = connect_transport(addr, utp.as_ref(), &proxies, iface, anonymous).await?;
        match plain_handshake_outgoing(transport, info_hash, peer_id).await {
            Ok((reader, writer, theirs)) => {
                run_after_handshake(reader, writer, addr, &theirs, event_tx.clone(), cmd_rx, anonymous)
                    .await
            }
            Err(e) if is_likely_mse_signal(&e) => {
                tracing::debug!(target: "peer", %addr, reason = %e, "plain failed, retrying with MSE");
                // Redial (racing again if µTP is on) and force MSE.
                let transport = connect_transport(addr, utp.as_ref(), &proxies, iface, anonymous).await?;
                let (reader, writer, theirs) =
                    mse_handshake_outgoing(transport, info_hash, peer_id).await?;
                run_after_handshake(reader, writer, addr, &theirs, event_tx.clone(), cmd_rx, anonymous)
                    .await
            }
            Err(e) => Err(e),
        }
    }
    .await;

    let (reason, violation) = classify_outcome(&outcome);
    let _ = event_tx
        .send(PeerEvent::Disconnected {
            addr,
            reason,
            violation,
        })
        .await;
    outcome
}

/// Emit the `Connected` event and run the post-handshake loop. Shared
/// by the plain and MSE outgoing paths so the connected-event + loop
/// boilerplate lives in one place.
async fn run_after_handshake<R, W>(
    reader: R,
    writer: W,
    addr: SocketAddr,
    theirs: &Handshake,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    anonymous: bool,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let supports_ext = crate::peer::handshake::supports_extension_protocol(&theirs.reserved);
    let _ = event_tx
        .send(PeerEvent::Connected {
            addr,
            peer_id: theirs.peer_id,
            peer_reserved: theirs.reserved,
        })
        .await;
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

/// Build the `(reason, violation)` pair for a `PeerEvent::Disconnected`
/// event from the per-peer task's final Result. Wraps the duplicated
/// `outcome.as_ref().err().map(...)` pattern at every Disconnected
/// emission site so the violation classification stays in one place.
fn classify_outcome(outcome: &Result<()>) -> (String, bool) {
    match outcome.as_ref().err() {
        Some(e) => (e.to_string(), is_protocol_violation(e)),
        None => ("closed".to_string(), false),
    }
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
    utp: Option<Arc<UtpSocket>>,
) -> Result<()> {
    tracing::debug!(target: "peer", %addr, hops = proxies.len(), bind = ?bind_iface, utp = utp.is_some(), "dialing (MSE-only)");
    let iface = bind_iface.as_deref();
    let outcome = async {
        let transport = connect_transport(addr, utp.as_ref(), &proxies, iface, anonymous).await?;
        let (reader, writer, theirs) =
            mse_handshake_outgoing(transport, info_hash, peer_id).await?;
        run_after_handshake(
            reader,
            writer,
            addr,
            &theirs,
            event_tx.clone(),
            cmd_rx,
            anonymous,
        )
        .await
    }
    .await;
    let (reason, violation) = classify_outcome(&outcome);
    let _ = event_tx
        .send(PeerEvent::Disconnected {
            addr,
            reason,
            violation,
        })
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

/// Read one peer-wire frame, but give up when the peer goes silent for
/// `idle`. The write side sends keepalives when IT goes idle; without a
/// read-side bound a connected-but-silent peer would hold its
/// `MAX_PEERS` slot forever. The resulting error text deliberately
/// matches nothing in `is_protocol_violation`, so the disconnect is
/// treated as benign.
async fn read_frame_with_idle<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: u32,
    buf: &mut Vec<u8>,
    idle: Duration,
) -> Result<()> {
    match timeout(idle, read_frame_into(reader, max_len, buf)).await {
        Ok(res) => res,
        Err(_) => Err(Error::Network(format!(
            "peer idle: no message within {}s",
            idle.as_secs()
        ))),
    }
}

/// The error for a write that made no progress within
/// [`WRITE_STALL_TIMEOUT`]. Like the read-idle error, the text matches
/// nothing in `is_protocol_violation` — a stalled peer gets disconnected,
/// not banned.
fn write_stall_error() -> Error {
    Error::Network(format!(
        "peer write stalled: no progress within {}s",
        WRITE_STALL_TIMEOUT.as_secs()
    ))
}

/// Classify a disconnect cause as a BEP 3 protocol violation that
/// merits the per-IP ban-on-repeats escalation, vs a benign network
/// event we shouldn't punish the peer for.
///
/// We deliberately only flag *unambiguous* violations:
/// - `bad pstrlen` / `bad protocol string`: incoming connection
///   sent a malformed handshake preamble (or wrong protocol byte).
/// - `info_hash mismatch`: peer claims to be in a different swarm
///   on a stream that has already passed the pstrlen check.
/// - `frame too large`: peer sent a length-prefix beyond
///   `MAX_FRAME_LEN`; the spec caps blocks at 16 KiB so this is
///   either a bug or an attempt to OOM us.
/// - `decode:` / `bad bitfield`: malformed message body — message
///   IDs out of range, bitfield with spare bits set, etc.
///
/// We pointedly do NOT flag: timeouts, `early eof`, "connection
/// reset" — all common with MSE-only peers and network instability.
fn is_protocol_violation(e: &Error) -> bool {
    let s = match e {
        Error::Handshake(s) => s.as_str(),
        Error::Network(s) => s.as_str(),
        _ => return false,
    };
    // Handshake-layer violations.
    s.contains("bad pstrlen")
        || s.contains("bad protocol string")
        || s.contains("info_hash mismatch")
        // Wire-codec violations from `peer/message.rs`.
        || s.contains("frame too large")
        || s.contains("unknown message id")
        || s.contains("bitfield spare bits not zero")
        || s.contains("have payload")
        || s.contains("piece short")
        || s.contains("extended payload empty")
}

/// Establish a peer transport. On a clearnet direct path with µTP
/// enabled, race a TCP dial and a µTP dial and take whichever connects
/// first (the other is aborted); otherwise dial TCP only. µTP is gated
/// off whenever a SOCKS5 chain or `--bind-iface` is set — UDP can't
/// ride a SOCKS5 CONNECT and our µTP socket isn't interface-bound, so
/// either would leak past the proxy / kill switch. nodelay is applied
/// before returning.
async fn connect_transport(
    addr: SocketAddr,
    utp: Option<&Arc<UtpSocket>>,
    proxies: &[ProxyConfig],
    bind_iface: Option<&str>,
    anonymous: bool,
) -> Result<Transport> {
    let use_utp = should_use_utp(proxies.is_empty(), bind_iface.is_some(), anonymous);
    let transport = match (use_utp, utp) {
        (true, Some(utp)) => race_tcp_utp(addr, utp, proxies, bind_iface, anonymous).await?,
        _ => Transport::Tcp(dial_tcp(addr, proxies, bind_iface, anonymous).await?),
    };
    transport.set_nodelay();
    Ok(transport)
}

/// Whether the uTP leg may race the TCP dial. µTP is raw UDP: it can't
/// ride a SOCKS5 CONNECT, and anonymous mode forbids UDP egress entirely.
/// A `--bind-iface` pin also keeps the race off — the engine still binds
/// an interface-pinned µTP socket for INBOUND peers in that case, but
/// outgoing dials stay TCP-only. `anonymous` is checked here — not just
/// at engine socket creation — so this stays true even if a future caller
/// hands us a µTP socket while anonymous.
fn should_use_utp(proxies_empty: bool, bind_iface_set: bool, anonymous: bool) -> bool {
    proxies_empty && !bind_iface_set && !anonymous
}

/// Race a TCP dial against a µTP dial. Returns the first transport to
/// connect; if one fails we wait for the other rather than failing the
/// whole dial (a peer may have only one of the two reachable). Returns
/// the last error only if BOTH fail.
async fn race_tcp_utp(
    addr: SocketAddr,
    utp: &Arc<UtpSocket>,
    proxies: &[ProxyConfig],
    bind_iface: Option<&str>,
    anonymous: bool,
) -> Result<Transport> {
    let tcp_fut = dial_tcp(addr, proxies, bind_iface, anonymous);
    let utp_fut = utp.connect(addr);
    tokio::pin!(tcp_fut);
    tokio::pin!(utp_fut);
    let mut tcp_done = false;
    let mut utp_done = false;
    let mut last_err: Option<Error> = None;
    loop {
        tokio::select! {
            r = &mut tcp_fut, if !tcp_done => match r {
                Ok(s) => return Ok(Transport::Tcp(s)),
                Err(e) => { tcp_done = true; last_err = Some(e); }
            },
            r = &mut utp_fut, if !utp_done => match r {
                Ok(s) => return Ok(Transport::Utp(s)),
                Err(e) => { utp_done = true; last_err = Some(Error::Network(format!("utp connect {addr}: {e}"))); }
            },
            else => break,
        }
        if tcp_done && utp_done {
            break;
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Network(format!("connect {addr}: no transport"))))
}

/// Perform the plain BT handshake over an already-connected transport,
/// then return the split read/write halves.
async fn plain_handshake_outgoing(
    mut transport: Transport,
    info_hash: [u8; 20],
    peer_id: PeerId,
) -> Result<(ReadHalf<Transport>, WriteHalf<Transport>, Handshake)> {
    let theirs = match timeout(
        HANDSHAKE_TIMEOUT,
        Handshake::perform_outgoing(&mut transport, info_hash, peer_id),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(Error::Handshake("timeout".into())),
    };
    let (read_half, write_half) = split(transport);
    Ok((read_half, write_half, theirs))
}

/// Open a TCP connection to `addr`, going through the SOCKS5 chain if
/// any is configured. Empty `proxies` → direct dial. Length-1 chain →
/// single-hop SOCKS5. Length-N chain → nested SOCKS5 CONNECTs on one
/// TCP stream (C1: defeats single-proxy compromise). The returned
/// `TcpStream` is, post-handshake, a transparent byte-pipe to `addr`.
async fn dial_tcp(
    addr: SocketAddr,
    proxies: &[ProxyConfig],
    bind_iface: Option<&str>,
    anonymous: bool,
) -> Result<TcpStream> {
    if anonymous && proxies.is_empty() {
        // Fail closed: a direct dial here would put the real IP on the
        // wire. Anonymous mode must never fall back to clearnet, even
        // if an upstream config gate is bypassed.
        return Err(Error::Network(
            "anonymous mode requires a SOCKS5 proxy; refusing direct dial".into(),
        ));
    }
    if !proxies.is_empty() {
        // Through a SOCKS5 chain: we connect to the first hop's IP, not
        // the peer's. With --bind-iface set, the FIRST hop's TCP dial
        // rides netbind so the kernel route to the proxy is forced
        // onto the bound interface (intermediate hops ride that
        // single TCP stream, so they inherit the binding for free).
        //
        // Materialize the per-dial config for each hop: when stream
        // isolation is on this generates a fresh random SOCKS5
        // username on that hop so Tor puts this dial on its own
        // circuit. Hops without isolation are cloned as-is.
        let effective: Vec<ProxyConfig> = proxies.iter().map(|p| p.for_dial()).collect();
        return socks5::connect_chain(&effective, addr, bind_iface)
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

/// Drive the MSE handshake over an already-connected transport, then
/// the BT handshake over the encrypted stream. Return the split
/// RC4-wrapped halves.
async fn mse_handshake_outgoing(
    transport: Transport,
    info_hash: [u8; 20],
    peer_id: PeerId,
) -> Result<(
    mse::Rc4Reader<ReadHalf<Transport>>,
    mse::Rc4Writer<WriteHalf<Transport>>,
    Handshake,
)> {
    // MSE handshake first. After this, all reads/writes through `enc` are
    // RC4'd transparently.
    let mut enc = match timeout(
        HANDSHAKE_TIMEOUT,
        mse::perform_outgoing(transport, info_hash),
    )
    .await
    {
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

    // Pull out the raw transport + ciphers (now advanced past the BT
    // handshake) and split into per-direction wrappers.
    let (raw_stream, in_cipher, out_cipher) = enc.into_parts();
    let (read_half, write_half) = split(raw_stream);
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
    stream: Transport,
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

    let (reason, violation) = classify_outcome(&outcome);
    let _ = event_tx
        .send(PeerEvent::Disconnected {
            addr,
            reason,
            violation,
        })
        .await;
    outcome
}

/// Run a peer task for a connection the *shared acceptor* already drove
/// through the full handshake (plain or MSE). The acceptor owns the
/// handshake because an MSE peer's info_hash is only knowable after the
/// DH exchange; here we just emit `Connected`, run the post-handshake
/// loop on the supplied (type-erased) reader/writer, and emit
/// `Disconnected` on exit — mirroring [`run_with_stream`] so the engine
/// sees the same event lifecycle regardless of which path accepted the
/// peer.
pub async fn run_handshaken(
    peer: crate::peer::inbound::HandshakenPeer,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    anonymous: bool,
) -> Result<()> {
    let crate::peer::inbound::HandshakenPeer {
        addr,
        peer_id,
        supports_ext,
        peer_reserved,
        reader,
        writer,
        ..
    } = peer;
    let _ = event_tx
        .send(PeerEvent::Connected {
            addr,
            peer_id,
            peer_reserved,
        })
        .await;
    let outcome = post_handshake_loop(
        reader,
        writer,
        addr,
        event_tx.clone(),
        cmd_rx,
        supports_ext,
        anonymous,
    )
    .await;
    let (reason, violation) = classify_outcome(&outcome);
    let _ = event_tx
        .send(PeerEvent::Disconnected {
            addr,
            reason,
            violation,
        })
        .await;
    outcome
}

/// Plain BT handshake on an already-connected stream, then the standard
/// post-handshake loop.
#[allow(clippy::too_many_arguments)] // each arg is a distinct dial-time knob
async fn run_plain_on_stream(
    mut stream: Transport,
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
            peer_reserved: theirs.reserved,
        })
        .await;
    let (reader, writer) = split(stream);
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
    mut stream: Transport,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: PeerId,
    event_tx: mpsc::Sender<PeerEvent>,
    cmd_rx: mpsc::Receiver<PeerCommand>,
    anonymous: bool,
) -> Result<()> {
    // Peek the first byte without consuming it (MSG_PEEK on TCP; a
    // buffered non-consuming read on µTP). `None` means EOF.
    let peeked = match timeout(HANDSHAKE_TIMEOUT, stream.peek_first_byte()).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Err(Error::Network(format!("peek: {e}"))),
        Err(_) => return Err(Error::Handshake("peek timeout".into())),
    };
    let Some(first) = peeked else {
        return Err(Error::Network("peer closed before handshake".into()));
    };
    if first == crate::peer::handshake::PSTRLEN {
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

/// MSE-over-stream incoming flow. The peek above did NOT consume the byte,
/// so the inner MSE handshake reads `Ya` from the start.
async fn run_mse_on_stream(
    stream: Transport,
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
            peer_reserved: theirs.reserved,
        })
        .await;

    let (raw, in_cipher, out_cipher) = enc.into_parts();
    let (read_half, write_half) = split(raw);
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
            // Reused across frames so the steady-state read path allocates
            // nothing once it's grown to the largest frame seen.
            let mut frame = Vec::new();
            loop {
                read_frame_with_idle(&mut reader, MAX_FRAME_LEN, &mut frame, READ_IDLE_TIMEOUT)
                    .await?;
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
                    match cmd {
                        // Upload-hot path: route Piece through write_message,
                        // whose specialized branch builds the wire frame in a
                        // single pass. Going via encode() here would copy the
                        // (up to 16 KiB) block twice (payload scratch + tag).
                        PeerCommand::Piece { index, begin, data } => {
                            timeout(
                                WRITE_STALL_TIMEOUT,
                                crate::peer::message::write_message(
                                    &mut writer,
                                    &Message::Piece { index, begin, data },
                                ),
                            )
                            .await
                            .map_err(|_| write_stall_error())??;
                        }
                        other => {
                            let bytes = match other {
                                PeerCommand::Request { index, begin, length } =>
                                    Message::Request { index, begin, length }.encode(),
                                PeerCommand::Cancel { index, begin, length } =>
                                    Message::Cancel { index, begin, length }.encode(),
                                PeerCommand::Have(i) => Message::Have(i).encode(),
                                PeerCommand::Choke => Message::Choke.encode(),
                                PeerCommand::Unchoke => Message::Unchoke.encode(),
                                PeerCommand::Interested => Message::Interested.encode(),
                                PeerCommand::NotInterested => Message::NotInterested.encode(),
                                PeerCommand::Piece { .. } => unreachable!("handled above"),
                                PeerCommand::Bitfield(b) => Message::Bitfield(b).encode(),
                                PeerCommand::Extension { ext_id, payload } =>
                                    Message::Extended { ext_id, payload }.encode(),
                                // BEP 6 fast-extension shorthands.
                                PeerCommand::HaveAll => Message::HaveAll.encode(),
                                PeerCommand::HaveNone => Message::HaveNone.encode(),
                            };
                            timeout(WRITE_STALL_TIMEOUT, writer.write_all(&bytes))
                                .await
                                .map_err(|_| write_stall_error())?
                                .map_err(|e| Error::Network(format!("write: {e}")))?;
                        }
                    }
                    last_send = Instant::now();
                }
                _ = tokio::time::sleep(until_next_keepalive) => {
                    timeout(WRITE_STALL_TIMEOUT, write_frame(&mut writer, &[]))
                        .await
                        .map_err(|_| write_stall_error())??;
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
        // BEP 6 fast-extension messages.
        Message::HaveAll => Some(PeerEvent::HaveAll { addr }),
        // HaveNone = peer has no pieces; same as an empty Bitfield — no action.
        Message::HaveNone => None,
        Message::RejectRequest { index, begin, .. } => {
            Some(PeerEvent::RejectRequest { addr, index, begin })
        }
        // AllowedFast and SuggestPiece are advisory hints we don't currently act
        // on (we don't track an allow-fast set or re-prioritize on suggestions).
        // Decode silently so connections with BEP 6 peers stay open.
        Message::AllowedFast(_) | Message::SuggestPiece(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_handshake_violations() {
        assert!(is_protocol_violation(&Error::Handshake(
            "bad pstrlen: 0".into()
        )));
        assert!(is_protocol_violation(&Error::Handshake(
            "bad protocol string".into()
        )));
        assert!(is_protocol_violation(&Error::Handshake(
            "info_hash mismatch".into()
        )));
    }

    #[test]
    fn classifies_wire_codec_violations() {
        assert!(is_protocol_violation(&Error::Network(
            "frame too large: 999999".into()
        )));
        assert!(is_protocol_violation(&Error::Network(
            "unknown message id 99".into()
        )));
        assert!(is_protocol_violation(&Error::Network(
            "bitfield spare bits not zero".into()
        )));
        assert!(is_protocol_violation(&Error::Network(
            "have payload 3 != 4".into()
        )));
        assert!(is_protocol_violation(&Error::Network(
            "piece short: 6".into()
        )));
    }

    #[test]
    fn benign_errors_are_not_violations() {
        // These are network instability or MSE-only-peer signals,
        // not deliberate misbehavior. Banning on these would
        // punish honest peers.
        assert!(!is_protocol_violation(&Error::Handshake("timeout".into())));
        assert!(!is_protocol_violation(&Error::Handshake(
            "read: early eof".into()
        )));
        assert!(!is_protocol_violation(&Error::Network(
            "connect 1.2.3.4:6881: Connection reset by peer".into()
        )));
        assert!(!is_protocol_violation(&Error::Network(
            "frame body: io error".into()
        )));
    }

    #[test]
    fn idle_read_disconnect_is_benign_not_violation() {
        // The read-idle bound is a liveness cleanup, not an accusation:
        // NAT timeouts and dead mobile peers are the normal case, so the
        // escalation path must never see this error as a violation.
        assert!(!is_protocol_violation(&Error::Network(format!(
            "peer idle: no message within {}s",
            READ_IDLE_TIMEOUT.as_secs()
        ))));
    }

    #[tokio::test]
    async fn silent_peer_read_times_out_as_idle_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _server = listener.accept().unwrap(); // accepted but never writes
        let mut buf = Vec::new();
        let started = std::time::Instant::now();
        let res = read_frame_with_idle(
            &mut client,
            MAX_FRAME_LEN,
            &mut buf,
            Duration::from_millis(80),
        )
        .await;
        assert!(res.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "idle bound must fire promptly, took {:?}",
            started.elapsed()
        );
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("peer idle"), "unexpected error: {msg}");
    }

    #[test]
    fn stalled_peer_write_is_benign_not_violation() {
        let e = write_stall_error();
        assert!(e.to_string().contains("stalled"));
        assert!(!is_protocol_violation(&e));
    }

    #[tokio::test]
    async fn write_to_unread_socket_times_out() {
        // 64-byte buffer: writing more than that to an unread duplex
        // half stalls the writer, exactly like a peer that stops reading.
        let (mut client, _reader) = tokio::io::duplex(64);
        let started = std::time::Instant::now();
        let res: Result<()> = timeout(
            Duration::from_millis(80),
            client.write_all(&vec![0u8; 4096]),
        )
        .await
        .map_err(|_| write_stall_error())
        .and_then(|r| r.map_err(|e| Error::Network(format!("write: {e}"))));
        assert!(res.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stall bound must fire promptly, took {:?}",
            started.elapsed()
        );
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("stalled"), "unexpected error: {msg}");
    }

    #[test]
    fn classify_outcome_flags_violations() {
        let outcome: Result<()> = Err(Error::Network("frame too large: 99".into()));
        let (reason, violation) = classify_outcome(&outcome);
        assert!(violation);
        assert!(reason.contains("frame too large"));
    }

    #[test]
    fn classify_outcome_clean_close_is_not_violation() {
        let outcome: Result<()> = Ok(());
        let (reason, violation) = classify_outcome(&outcome);
        assert!(!violation);
        assert_eq!(reason, "closed");
    }

    #[tokio::test]
    async fn dial_tcp_refuses_direct_socket_when_anonymous_without_proxies() {
        // A live listener proves the target is connectable — the only
        // reason `dial_tcp` may not reach it is the anonymous fail-closed
        // guard, not an unreachable peer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let err = dial_tcp(addr, &[], None, true)
            .await
            .expect_err("anonymous dial without proxies must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("refusing direct dial") && msg.contains("anonymous"),
            "unexpected refusal message: {msg}"
        );

        // Control: without anonymous mode the same dial connects. If a
        // regression removes the anon guard, the first assertion above
        // fails instead of silently passing.
        let _stream = dial_tcp(addr, &[], None, false).await.unwrap();
    }

    #[test]
    fn should_use_utp_covers_anonymous() {
        // Truth table: µTP (raw UDP, no proxy support, no iface binding)
        // is only allowed with no proxy chain, no --bind-iface, and
        // anonymous mode OFF. Any single condition forbids it.
        assert!(!should_use_utp(true, false, true), "anonymous forbids uTP");
        assert!(should_use_utp(true, false, false));
        assert!(!should_use_utp(false, false, false), "proxies forbid uTP");
        assert!(!should_use_utp(true, true, false), "bind-iface forbids uTP");
    }
}
