//! Magnet-link bootstrap: fetch a torrent's info dict via BEP 9
//! (ut_metadata) from any peer that supports BEP 10 (extension
//! protocol).
//!
//! ## Flow
//!
//! 1. Caller supplies the info_hash (from `magnet:?xt=urn:btih:…`),
//!    a pool of candidate peer addresses (typically from DHT
//!    `get_peers` + the magnet's `tr=` trackers), and optional proxy.
//! 2. We dial up to `MAX_CONCURRENT_FETCH` peers in parallel. Each
//!    attempt does a plain BT handshake, an extension handshake, and a
//!    loop of `ut_metadata` requests for piece 0..N until the full
//!    info dict is reassembled.
//! 3. First peer to deliver a complete dict that SHA1-hashes to the
//!    expected info_hash wins; the rest are cancelled.
//!
//! ## Why this is its own module
//!
//! It deliberately doesn't touch `PeerManager` or the regular
//! `post_handshake_loop`. The bootstrap is a one-shot — the
//! connections we open here are torn down after we have the metadata.
//! Mixing the regular engine flow (rarest-first picker, choker,
//! storage task, etc.) with a single-message bootstrap loop would
//! force a lot of awkward conditional state. Self-contained is cheaper.
//!
//! ## MSE on bootstrap
//!
//! For now we only attempt the plain handshake — if a peer is
//! MSE-only we just skip them and try the next. The magnet pool is
//! typically large enough that this isn't blocking. Layering MSE on
//! the bootstrap path is a small follow-up.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::peer::extension::{
    build_handshake_payload, build_metadata_request, parse_handshake_payload,
    parse_metadata_response, MetadataResponse, EXT_HANDSHAKE_ID, METADATA_PIECE_SIZE,
    OUR_UT_METADATA_ID,
};
use crate::peer::handshake::{supports_extension_protocol, Handshake};
use crate::peer::message::{read_frame, write_message, Message};
use crate::peer_id::PeerId;
use crate::socks5::{self, ProxyConfig};

/// Cap parallel dials during bootstrap. Higher = faster on average but
/// more connections opened that we'll just drop after the first success.
const MAX_CONCURRENT_FETCH: usize = 16;

/// Process-wide ceiling on metadata-assembly memory in flight. The
/// per-peer cap (`MAX_METADATA_SIZE`, 100 MB in extension.rs) bounds one
/// dial, but `MAX_CONCURRENT_FETCH` of them — across every concurrent
/// magnet — could each allocate up to that (16 × 100 MB = 1.6 GB per
/// magnet, more with several magnets). This shared budget bounds the
/// total: a fetch must reserve its `total_size` here before allocating
/// the assembly buffer, and is refused if that would exceed the ceiling.
/// 256 MB comfortably fits any real torrent's info dict (normally
/// <100 KB; even a multi-TB torrent's piece-hash string is tens of MB)
/// while capping a flood. The common case never comes near it.
const GLOBAL_METADATA_BUDGET: usize = 256 * 1024 * 1024;
static METADATA_BYTES_IN_FLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// RAII reservation against [`GLOBAL_METADATA_BUDGET`]. Releases the
/// bytes on drop (whether the fetch succeeded, errored, or was aborted),
/// so a panicking or timed-out dial can't leak budget.
struct MetadataReservation(usize);

impl MetadataReservation {
    /// Try to reserve `bytes`. Returns `None` if it would exceed the
    /// global budget, leaving the counter unchanged.
    fn try_acquire(bytes: usize) -> Option<Self> {
        use std::sync::atomic::Ordering;
        let mut cur = METADATA_BYTES_IN_FLIGHT.load(Ordering::Relaxed);
        loop {
            let next = cur.checked_add(bytes)?;
            if next > GLOBAL_METADATA_BUDGET {
                return None;
            }
            match METADATA_BYTES_IN_FLIGHT.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self(bytes)),
                Err(observed) => cur = observed,
            }
        }
    }
}

impl Drop for MetadataReservation {
    fn drop(&mut self) {
        METADATA_BYTES_IN_FLIGHT.fetch_sub(self.0, std::sync::atomic::Ordering::AcqRel);
    }
}
/// Per-peer step timeouts. Generous because peers behind slow links
/// genuinely take seconds to respond to ut_metadata requests.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const EXT_STEP_TIMEOUT: Duration = Duration::from_secs(20);
/// Whole-pool timeout. If we can't get the metadata from any peer in
/// this window, give up — the swarm probably can't serve it (rare).
const OVERALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Max frame size we'll accept from the peer during bootstrap. The
/// largest legitimate frame is a `Data` ut_metadata response carrying
/// one 16 KiB metadata piece plus its bencode envelope — give a little
/// headroom for the dict.
const FETCH_MAX_FRAME_LEN: u32 = (METADATA_PIECE_SIZE as u32) + 1024;

/// Frame budgets for one bootstrap exchange (MED-1, wave3 B10). Each
/// read is individually time-boxed by `EXT_STEP_TIMEOUT`, but the skip
/// loops in `read_extension_handshake` / `read_metadata_response` had
/// no bound on HOW MANY frames they would read, so a malicious peer
/// could keep the attempt alive indefinitely (and hold its metadata
/// budget reservation) by dribbling valid-but-irrelevant frames —
/// keep-alives, stray Bitfields, re-sent handshakes — just under each
/// step timeout. A real peer sends a handful of noise frames at most,
/// and a legitimate exchange needs exactly `num_pieces` ut_metadata
/// `Data` frames. We allow `EXT_HANDSHAKE_MAX_FRAMES` before the peer's
/// extension handshake resolves, then widen the budget to cover
/// `num_pieces` data frames plus `EXT_NOISE_FRAME_SLACK` noise. Each
/// frame is additionally capped at `FETCH_MAX_FRAME_LEN`, so this
/// bounds both the frame count and the total bytes a peer can make us
/// read.
const EXT_HANDSHAKE_MAX_FRAMES: usize = 64;
const EXT_NOISE_FRAME_SLACK: usize = 64;

/// Fail-closed counter behind the [`EXT_HANDSHAKE_MAX_FRAMES`] /
/// [`EXT_NOISE_FRAME_SLACK`] budgets: every frame read during a
/// bootstrap exchange is spent against this budget, and exhausting it
/// aborts the attempt with [`Error::Protocol`].
struct FrameBudget {
    remaining: usize,
}

impl FrameBudget {
    fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    /// Account one frame. Returns `Err` once the budget is exhausted;
    /// the caller must treat that as the end of the attempt.
    fn spend(&mut self) -> Result<()> {
        if self.remaining == 0 {
            return Err(Error::Protocol(
                "ut_metadata bootstrap: peer frame budget exhausted \
                 (too many non-advancing frames)"
                    .into(),
            ));
        }
        self.remaining -= 1;
        Ok(())
    }

    /// Widen the budget once `num_pieces` is known (see the constants'
    /// docs): the exchange legitimately needs one `Data` frame per
    /// piece, plus slack for noise frames.
    fn widen(&mut self, data_frames: usize) {
        self.remaining = self
            .remaining
            .saturating_add(data_frames + EXT_NOISE_FRAME_SLACK);
    }
}

/// Fetch the info dict bytes for `info_hash` from any peer in
/// `peer_pool`. Returns the raw bencoded info dict (which the caller
/// is responsible for verifying — we already SHA1-checked it here,
/// but the caller still needs to parse it into a `TorrentFile`).
///
/// Errors:
/// - `Network` if every peer attempt failed within the overall
///   timeout. This is the magnet equivalent of "DHT returned nothing
///   useful + tracker had no peers".
pub async fn fetch_metadata(
    info_hash: [u8; 20],
    peer_pool: Vec<SocketAddr>,
    proxies: Vec<ProxyConfig>,
    anonymous: bool,
    bind_iface: Option<String>,
) -> Result<Vec<u8>> {
    if peer_pool.is_empty() {
        return Err(Error::Network(
            "magnet bootstrap: no candidate peers (DHT + trackers returned nothing)".into(),
        ));
    }

    // Anonymous bootstrap: use a libtorrent-style peer_id so the prefix
    // doesn't immediately leak the client name even before the engine
    // takes over.
    let our_peer_id = if anonymous {
        crate::peer_id::generate_libtorrent_lookalike()
    } else {
        crate::peer_id::generate()
    };
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_FETCH));
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);

    let mut handles = Vec::with_capacity(peer_pool.len());
    for addr in peer_pool {
        let sem = sem.clone();
        let tx = tx.clone();
        let proxies = proxies.clone();
        let bind_iface = bind_iface.clone();
        let handle = tokio::spawn(async move {
            let permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };
            match try_fetch_from(
                addr,
                info_hash,
                our_peer_id,
                &proxies,
                anonymous,
                bind_iface.as_deref(),
            )
            .await
            {
                Ok(bytes) => {
                    // tx is bounded(1) — first sender wins; subsequent
                    // sends short-circuit because the receiver has
                    // already taken the value and the channel closes.
                    let _ = tx.send(bytes).await;
                }
                Err(e) => {
                    tracing::debug!(
                        target: "magnet",
                        peer = %crate::util::redact_peer(&addr),
                        error = %e,
                        "ut_metadata fetch attempt failed"
                    );
                }
            }
            drop(permit);
        });
        handles.push(handle);
    }
    drop(tx);

    let outcome = match timeout(OVERALL_TIMEOUT, rx.recv()).await {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(Error::Network(
            "magnet bootstrap: every peer attempt failed".into(),
        )),
        Err(_) => Err(Error::Network(format!(
            "magnet bootstrap: timed out after {}s",
            OVERALL_TIMEOUT.as_secs()
        ))),
    };
    // Cancel any still-in-flight attempts — we have what we needed (or gave up).
    for h in handles {
        h.abort();
    }
    outcome
}

/// Orchestrate a single peer attempt: dial, run plain BT handshake; if
/// that fails in a way that looks like the peer is MSE-only, redial and
/// run the MSE handshake before retrying BT. Either way, hand the
/// resulting stream (plain `TcpStream` or `EncryptedStream`) to the
/// generic `exchange_metadata` function, which does the BEP 10 + 9
/// protocol over any AsyncRead+AsyncWrite.
async fn try_fetch_from(
    addr: SocketAddr,
    info_hash: [u8; 20],
    our_peer_id: PeerId,
    proxies: &[ProxyConfig],
    anonymous: bool,
    bind_iface: Option<&str>,
) -> Result<Vec<u8>> {
    // Attempt 1: plain BT handshake on a fresh TcpStream.
    let plain_result = async {
        let mut stream = dial(addr, proxies, anonymous, bind_iface).await?;
        let _ = stream.set_nodelay(true);
        let theirs = match timeout(
            HANDSHAKE_TIMEOUT,
            Handshake::perform_outgoing(&mut stream, info_hash, our_peer_id),
        )
        .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(Error::Handshake("bt handshake timeout".into())),
        };
        if !supports_extension_protocol(&theirs.reserved) {
            return Err(Error::Network(
                "peer lacks BEP 10 extension protocol".into(),
            ));
        }
        exchange_metadata(&mut stream, info_hash, addr, anonymous).await
    }
    .await;

    match plain_result {
        Ok(v) => return Ok(v),
        Err(e) if !looks_like_mse_signal(&e) => return Err(e),
        Err(_) => {
            tracing::debug!(target: "magnet", peer = %crate::util::redact_peer(&addr), "plain BT failed; retrying with MSE");
        }
    }

    // Attempt 2: MSE handshake on a fresh TcpStream. The first TCP
    // attempt is now in some intermediate state (we sent the plain pstr
    // and got a reject or EOF), so we redial cleanly.
    let stream = dial(addr, proxies, anonymous, bind_iface).await?;
    let _ = stream.set_nodelay(true);
    let mut enc = match timeout(
        HANDSHAKE_TIMEOUT,
        crate::peer::mse::perform_outgoing(stream, info_hash),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Error::Handshake(format!("mse handshake: {e}"))),
        Err(_) => return Err(Error::Handshake("mse handshake timeout".into())),
    };
    let theirs = match timeout(
        HANDSHAKE_TIMEOUT,
        Handshake::perform_outgoing(&mut enc, info_hash, our_peer_id),
    )
    .await
    {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return Err(Error::Network(format!("bt-over-mse handshake: {e}"))),
        Err(_) => return Err(Error::Network("bt-over-mse handshake timeout".into())),
    };
    if !supports_extension_protocol(&theirs.reserved) {
        return Err(Error::Network(
            "peer (over MSE) lacks BEP 10 extension protocol".into(),
        ));
    }
    exchange_metadata(&mut enc, info_hash, addr, anonymous).await
}

/// Heuristic: did the plain BT handshake fail in a way that suggests the
/// peer is MSE-only? Mirrors `peer::connection::is_likely_mse_signal`,
/// but inlined here so the bootstrap module doesn't need to expose the
/// helper crate-wide.
fn looks_like_mse_signal(e: &Error) -> bool {
    match e {
        Error::Handshake(s) => {
            s.contains("early eof")
                || s.contains("bad pstrlen")
                || s.contains("bad protocol string")
                || s.contains("read: unexpected end of file")
        }
        Error::Network(s) => s.contains("Connection reset"),
        _ => false,
    }
}

/// Run the BEP 10 extension handshake + BEP 9 ut_metadata exchange over
/// any AsyncRead+AsyncWrite stream (plain or MSE-encrypted). Returns
/// the assembled, hash-verified info dict.
async fn exchange_metadata<S>(
    stream: &mut S,
    info_hash: [u8; 20],
    addr: SocketAddr,
    anonymous: bool,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Extension handshake exchange. Send ours; read theirs from the
    // post-handshake message stream (filtering out unrelated Bitfield/
    // Have/etc. that legitimately also appear early).
    let our_ext = Message::Extended {
        ext_id: EXT_HANDSHAKE_ID,
        payload: build_handshake_payload(anonymous),
    };
    write_message(stream, &our_ext)
        .await
        .map_err(|e| Error::Network(format!("ext handshake write: {e}")))?;

    let mut budget = FrameBudget::new(EXT_HANDSHAKE_MAX_FRAMES);
    let peer_info = read_extension_handshake(stream, &mut budget).await?;
    let their_id = peer_info.their_ut_metadata_id.ok_or_else(|| {
        Error::Network("peer doesn't advertise ut_metadata in extension handshake".into())
    })?;
    let total_size = peer_info.metadata_size.ok_or_else(|| {
        Error::Network("peer doesn't advertise metadata_size — can't bootstrap".into())
    })?;

    // Reserve the assembly memory against the process-wide budget BEFORE
    // allocating. Held for the duration of this fetch; released on drop
    // (success, error, or abort) by the RAII guard.
    let _budget = MetadataReservation::try_acquire(total_size as usize).ok_or_else(|| {
        Error::Network(format!(
            "metadata fetch refused: {total_size} bytes would exceed the global budget"
        ))
    })?;

    // Request pieces 0..ceil(total_size / METADATA_PIECE_SIZE), assemble.
    let num_pieces = (total_size as usize).div_ceil(METADATA_PIECE_SIZE);
    // The exchange now legitimately needs one `Data` frame per piece;
    // widen the budget accordingly (see `EXT_NOISE_FRAME_SLACK`).
    budget.widen(num_pieces);
    let mut assembled = vec![0u8; total_size as usize];
    let mut received = vec![false; num_pieces];

    while received.iter().any(|&got| !got) {
        let next = received
            .iter()
            .position(|&got| !got)
            .expect("loop guard says at least one is missing");
        let req = Message::Extended {
            ext_id: their_id,
            payload: build_metadata_request(next as u32),
        };
        write_message(stream, &req)
            .await
            .map_err(|e| Error::Network(format!("ut_metadata request: {e}")))?;

        let resp = read_metadata_response(stream, &mut budget).await?;
        match resp {
            MetadataResponse::Data {
                piece,
                total_size: peer_total,
                data,
            } => {
                if peer_total != total_size {
                    return Err(Error::Network(format!(
                        "peer total_size changed mid-fetch: was {total_size}, now {peer_total}"
                    )));
                }
                let idx = piece as usize;
                if idx >= num_pieces {
                    return Err(Error::Network(format!(
                        "piece {idx} out of range (have {num_pieces})"
                    )));
                }
                let expected_len = piece_expected_len(idx, num_pieces, total_size);
                if data.len() != expected_len {
                    return Err(Error::Network(format!(
                        "piece {idx} length {} != expected {expected_len}",
                        data.len()
                    )));
                }
                let off = idx * METADATA_PIECE_SIZE;
                assembled[off..off + expected_len].copy_from_slice(&data);
                received[idx] = true;
            }
            MetadataResponse::Reject { piece } => {
                return Err(Error::Network(format!(
                    "peer rejected ut_metadata piece {piece}"
                )));
            }
            MetadataResponse::Other => {
                // Some other ut_metadata message variant — keep waiting.
                continue;
            }
        }
    }

    // Hash-verify against the magnet's info_hash. This is the whole
    // point — anyone can ship bytes, but only a peer who actually has
    // the right metadata can produce something that hashes correctly.
    let mut hasher = Sha1::new();
    hasher.update(&assembled);
    let got: [u8; 20] = hasher.finalize().into();
    if got != info_hash {
        return Err(Error::Network(format!(
            "fetched metadata hash mismatch: peer {} sent garbage that didn't verify",
            crate::util::redact_peer(&addr)
        )));
    }
    Ok(assembled)
}

fn piece_expected_len(piece_idx: usize, num_pieces: usize, total_size: u32) -> usize {
    if piece_idx + 1 == num_pieces {
        let r = (total_size as usize) % METADATA_PIECE_SIZE;
        if r == 0 {
            METADATA_PIECE_SIZE
        } else {
            r
        }
    } else {
        METADATA_PIECE_SIZE
    }
}

/// Read messages from the post-handshake stream until we get the
/// peer's extension handshake (`Extended { ext_id: 0 }`). Bitfield /
/// Have / KeepAlive / etc. are common before the ext handshake and
/// must be skipped, not errored on. Every frame read — including the
/// skipped ones — is spent against `budget`; exhausting it fails
/// closed so a dribbling peer can't hold the attempt open forever.
async fn read_extension_handshake<S>(
    stream: &mut S,
    budget: &mut FrameBudget,
) -> Result<crate::peer::extension::PeerExtensionInfo>
where
    S: AsyncRead + Unpin,
{
    loop {
        let frame = timeout(EXT_STEP_TIMEOUT, read_frame(stream, FETCH_MAX_FRAME_LEN))
            .await
            .map_err(|_| Error::Network("ext handshake read timeout".into()))?
            .map_err(|e| Error::Network(format!("ext handshake frame: {e}")))?;
        budget.spend()?;
        if frame.is_empty() {
            continue; // keep-alive
        }
        let msg = Message::decode(&frame)?;
        if let Message::Extended { ext_id, payload } = msg {
            if ext_id == EXT_HANDSHAKE_ID {
                return parse_handshake_payload(&payload);
            }
            // An ut_metadata data response showing up before the
            // handshake would be a protocol violation; tolerate by
            // continuing to wait.
            continue;
        }
        // Bitfield, Have, KeepAlive, Choke, etc. — irrelevant to us
        // during the bootstrap. Drop and loop.
    }
}

/// Wait for the next ut_metadata response on the stream. Same
/// filtering discipline as `read_extension_handshake` — non-Extended
/// frames are skipped — and every frame read is spent against
/// `budget` so a dribbling peer can't stall the piece loop.
async fn read_metadata_response<S>(
    stream: &mut S,
    budget: &mut FrameBudget,
) -> Result<MetadataResponse>
where
    S: AsyncRead + Unpin,
{
    loop {
        let frame = timeout(EXT_STEP_TIMEOUT, read_frame(stream, FETCH_MAX_FRAME_LEN))
            .await
            .map_err(|_| Error::Network("ut_metadata read timeout".into()))?
            .map_err(|e| Error::Network(format!("ut_metadata frame: {e}")))?;
        budget.spend()?;
        if frame.is_empty() {
            continue;
        }
        let msg = Message::decode(&frame)?;
        if let Message::Extended { ext_id, payload } = msg {
            if ext_id == OUR_UT_METADATA_ID {
                return parse_metadata_response(&payload);
            }
            // A second extension handshake (some clients send a fresh
            // one on every connection event) or an ext_id we didn't
            // assign — ignore.
            continue;
        }
        // Other BT messages aren't relevant; keep waiting.
    }
}

async fn dial(
    addr: SocketAddr,
    proxies: &[ProxyConfig],
    anonymous: bool,
    bind_iface: Option<&str>,
) -> Result<TcpStream> {
    if anonymous && proxies.is_empty() {
        // Fail closed: a direct dial here would put the real IP on the
        // wire. Anonymous mode without proxies must never fall back.
        return Err(Error::Network(
            "magnet bootstrap: anonymous mode requires --socks5; refusing direct dial".into(),
        ));
    }
    // Same belt-and-braces martian screen as the engine's dial_tcp:
    // ingestion filters per-source; this is the last line at the syscall.
    let martian_strict = crate::engine::dht_martian_strict(anonymous, !proxies.is_empty());
    if !crate::util::is_safe_dial_target(&addr, martian_strict) {
        return Err(Error::Network(format!(
            "refusing martian dial target {} (strict={martian_strict})",
            crate::util::redact_peer(&addr)
        )));
    }
    if !proxies.is_empty() {
        // Per-hop materialization so Tor stream isolation refreshes the
        // SOCKS5 username for this dial; non-isolated hops are cloned
        // as-is. The chain can be a single proxy (length 1) or many.
        // With a kill-switch interface set, the FIRST hop's dial rides
        // netbind so the TCP connection to the proxy itself can't
        // escape onto the default route if the tunnel drops — same
        // contract as the engine's peer dials.
        let effective: Vec<ProxyConfig> = proxies.iter().map(|p| p.for_dial()).collect();
        return timeout(
            DIAL_TIMEOUT,
            socks5::connect_chain(&effective, addr, bind_iface),
        )
        .await
        .map_err(|_| {
            Error::Network(format!(
                "socks5 dial {}: timeout",
                crate::util::redact_peer(&addr)
            ))
        })?
        .map_err(|e| {
            Error::Network(format!(
                "socks5 dial {}: {e}",
                crate::util::redact_peer(&addr)
            ))
        });
    }
    match bind_iface {
        Some(iface) => timeout(
            DIAL_TIMEOUT,
            crate::netbind::connect_via_interface(addr, iface),
        )
        .await
        .map_err(|_| {
            Error::Network(format!(
                "connect {} via {iface}: timeout",
                crate::util::redact_peer(&addr)
            ))
        })?
        .map_err(|e| {
            Error::Network(format!(
                "connect {} via {iface}: {e}",
                crate::util::redact_peer(&addr)
            ))
        }),
        None => timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                Error::Network(format!(
                    "connect {}: timeout",
                    crate::util::redact_peer(&addr)
                ))
            })?
            .map_err(|e| {
                Error::Network(format!("connect {}: {e}", crate::util::redact_peer(&addr)))
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn metadata_reservation_bounds_and_releases() {
        let base = METADATA_BYTES_IN_FLIGHT.load(Ordering::Relaxed);

        // A small reservation within budget succeeds and bumps the counter.
        let r = MetadataReservation::try_acquire(1024).unwrap();
        assert_eq!(
            METADATA_BYTES_IN_FLIGHT.load(Ordering::Relaxed),
            base + 1024
        );

        // A reservation that would exceed the global ceiling is refused
        // and leaves the counter untouched.
        assert!(MetadataReservation::try_acquire(GLOBAL_METADATA_BUDGET).is_none());
        assert_eq!(
            METADATA_BYTES_IN_FLIGHT.load(Ordering::Relaxed),
            base + 1024
        );

        // Dropping the guard releases the bytes.
        drop(r);
        assert_eq!(METADATA_BYTES_IN_FLIGHT.load(Ordering::Relaxed), base);
    }

    #[test]
    fn metadata_reservation_rejects_overflow() {
        // checked_add guards against usize overflow in the ceiling math.
        assert!(MetadataReservation::try_acquire(usize::MAX).is_none());
    }

    #[tokio::test]
    async fn dial_refuses_direct_socket_when_anonymous_without_proxies() {
        // A live listener proves the target is connectable — the only
        // reason `dial` may not reach it is the anonymous fail-closed
        // guard, not an unreachable peer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let err = dial(addr, &[], true, None)
            .await
            .expect_err("anonymous dial without proxies must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("refusing direct dial") && msg.contains("anonymous"),
            "unexpected refusal message: {msg}"
        );

        // Control: without anonymous mode the same dial connects. If a
        // regression removes the anon guard, this pair of assertions
        // fails on the first one instead of silently passing.
        let _stream = dial(addr, &[], false, None).await.unwrap();
    }

    #[tokio::test]
    async fn dial_honors_bind_iface_on_direct_path() {
        // Non-anon, no proxy, bogus interface name: dial must take the
        // netbind path (error names the iface) rather than silently
        // falling through to a plain clearnet connect that would
        // succeed against the listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let err = dial(addr, &[], false, Some("rn-no-such-iface-0"))
            .await
            .expect_err("bogus iface must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("via rn-no-such-iface-0"),
            "expected netbind-path error naming the iface, got: {msg}"
        );
        // Same log path: the peer IP must be tokenized in dial errors.
        assert!(
            !msg.contains(&addr.ip().to_string()),
            "raw addr leaked: {msg}"
        );
    }

    #[tokio::test]
    async fn fetch_metadata_anonymous_without_proxies_never_dials_direct() {
        // End-to-end fail-closed proof: a live listener as the sole
        // candidate peer, anonymous mode, no proxy. Every per-peer
        // attempt must refuse at the dial — none may reach the
        // listener — so the whole fetch errors out.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let res = fetch_metadata([9u8; 20], vec![addr], Vec::new(), true, None).await;
        let err = res.expect_err("anonymous fetch without proxies must fail closed");
        let msg = format!("{err}");
        assert!(
            msg.contains("failed"),
            "expected exhausted-attempts error, got: {msg}"
        );
    }
    #[tokio::test]
    async fn metadata_dial_refuses_martian_target() {
        // Belt-and-braces screen on the magnet bootstrap dial: the
        // link-local metadata endpoint is refused before any socket work,
        // clearnet or not.
        let addr: SocketAddr = "169.254.169.254:80".parse().unwrap();
        let err = dial(addr, &[], false, None)
            .await
            .expect_err("martian target must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("refusing martian dial target"),
            "expected martian refusal, got: {msg}"
        );
        // The refusal reaches web magnet-add logs via error=%e — the raw
        // address must never ride along in the message body.
        assert!(!msg.contains("169.254"), "raw addr leaked: {msg}");
        assert!(msg.contains("peer:"), "expected redacted token: {msg}");

        // Loopback exemption still holds for local bootstrap setups.
        let ok = dial("127.0.0.1:1".parse().unwrap(), &[], false, None)
            .await
            .unwrap_err();
        let msg2 = format!("{ok}");
        assert!(
            msg2.contains("connect peer:") && msg2.contains("Connection refused"),
            "loopback must pass the screen and fail at connect instead, got: {msg2}"
        );
    }

    // ---- MED-1 frame-budget tests (wave3 B10 / AQ-65) ----
    //
    // These drive `exchange_metadata` over an in-memory duplex stream so
    // the peer side is fully attacker-controlled with no real sockets.
    use tokio::io::AsyncWriteExt;

    /// Write one `Extended { ext_id, payload }` wire frame to the peer
    /// side via the production encoder (message id 20 + ext id + body).
    async fn peer_write_extended<W>(w: &mut W, ext_id: u8, payload: Vec<u8>)
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        write_message(w, &Message::Extended { ext_id, payload })
            .await
            .unwrap();
    }

    /// A valid keep-alive frame is just a zero length prefix.
    const KEEPALIVE: [u8; 4] = 0u32.to_be_bytes();

    /// Bencoded extension handshake advertising `ut_metadata` under
    /// `ext_id` and the given `metadata_size`.
    fn peer_ext_handshake(metadata_size: u32, ext_id: u8) -> Vec<u8> {
        use crate::metainfo::bencode::BencodeValue;
        let mut m = std::collections::BTreeMap::new();
        m.insert(b"ut_metadata".to_vec(), BencodeValue::Int(ext_id as i64));
        let mut root = std::collections::BTreeMap::new();
        root.insert(b"m".to_vec(), BencodeValue::Dict(m));
        root.insert(
            b"metadata_size".to_vec(),
            BencodeValue::Int(metadata_size as i64),
        );
        BencodeValue::Dict(root).to_bytes()
    }

    /// Bencoded ut_metadata `data` response for `piece` with `data`
    /// appended verbatim after the dict (BEP 9 wire format).
    fn peer_metadata_data(piece: u32, total_size: u32, data: &[u8]) -> Vec<u8> {
        use crate::metainfo::bencode::BencodeValue;
        let mut d = std::collections::BTreeMap::new();
        d.insert(b"msg_type".to_vec(), BencodeValue::Int(1));
        d.insert(b"piece".to_vec(), BencodeValue::Int(piece as i64));
        d.insert(b"total_size".to_vec(), BencodeValue::Int(total_size as i64));
        let mut payload = BencodeValue::Dict(d).to_bytes();
        payload.extend_from_slice(data);
        payload
    }

    #[test]
    fn frame_budget_spends_and_fails_closed() {
        let mut b = FrameBudget::new(2);
        assert!(b.spend().is_ok());
        assert!(b.spend().is_ok());
        let err = b.spend().expect_err("exhausted budget must fail closed");
        assert!(matches!(err, Error::Protocol(_)), "got: {err}");
        // Widening revives it: 1 data frame + 64 slack.
        b.widen(1);
        assert!(b.spend().is_ok());
        assert_eq!(b.remaining, 64);
    }

    #[tokio::test]
    async fn frame_budget_rejects_dribbling_peer_before_ext_handshake() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            // Dribble thousands of valid keep-alive frames — more than
            // EXT_HANDSHAKE_MAX_FRAMES — never sending a real handshake.
            for _ in 0..4096 {
                if server.write_all(&KEEPALIVE).await.is_err() {
                    break;
                }
            }
        });
        // Bound the call so a regression (no budget → infinite skip
        // loop, since instant frames never trip EXT_STEP_TIMEOUT) fails
        // this test instead of hanging the suite.
        let res = timeout(
            Duration::from_secs(30),
            exchange_metadata(
                &mut client,
                [7u8; 20],
                "127.0.0.1:1".parse().unwrap(),
                false,
            ),
        )
        .await;
        writer.abort();
        let err = res
            .expect("budget must end the attempt long before this bound")
            .expect_err("dribbler before handshake must be rejected");
        let msg = format!("{err}");
        assert!(
            matches!(err, Error::Protocol(_)) && msg.contains("frame budget"),
            "expected typed frame-budget error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn frame_budget_rejects_dribbling_peer_during_metadata_phase() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            // Honest handshake first (metadata_size = one piece), then
            // endless keep-alives instead of the requested Data frame.
            peer_write_extended(
                &mut server,
                2,
                peer_ext_handshake(METADATA_PIECE_SIZE as u32, 2),
            )
            .await;
            for _ in 0..4096 {
                if server.write_all(&KEEPALIVE).await.is_err() {
                    break;
                }
            }
        });
        let res = timeout(
            Duration::from_secs(30),
            exchange_metadata(
                &mut client,
                [7u8; 20],
                "127.0.0.1:1".parse().unwrap(),
                false,
            ),
        )
        .await;
        writer.abort();
        let err = res
            .expect("budget must end the attempt long before this bound")
            .expect_err("dribbler during exchange must be rejected");
        let msg = format!("{err}");
        assert!(
            matches!(err, Error::Protocol(_)) && msg.contains("frame budget"),
            "expected typed frame-budget error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn exchange_metadata_succeeds_against_honest_peer() {
        // Control for the two dribble tests: a peer that answers every
        // request with the right Data frames must still complete, so
        // the budget can't have been set tighter than legitimate use.
        let payload: Vec<u8> = (0..48u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut hasher = Sha1::new();
        hasher.update(&payload);
        let info_hash: [u8; 20] = hasher.finalize().into();

        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let peer_payload = payload.clone();
        let writer = tokio::spawn(async move {
            peer_write_extended(
                &mut server,
                EXT_HANDSHAKE_ID,
                peer_ext_handshake(peer_payload.len() as u32, 2),
            )
            .await;
            // Responses ride OUR advertised ut_metadata id, not theirs.
            peer_write_extended(
                &mut server,
                OUR_UT_METADATA_ID,
                peer_metadata_data(0, peer_payload.len() as u32, &peer_payload),
            )
            .await;
            // Park WITHOUT dropping our half: dropping it would discard
            // any unread buffered frames and EOF the exchange.
            std::future::pending::<()>().await;
        });
        let got = timeout(
            Duration::from_secs(30),
            exchange_metadata(
                &mut client,
                info_hash,
                "127.0.0.1:1".parse().unwrap(),
                false,
            ),
        )
        .await
        .expect("honest exchange must finish long before this bound")
        .expect("honest peer must verify and assemble");
        writer.abort();
        assert_eq!(got, payload);
    }
}
