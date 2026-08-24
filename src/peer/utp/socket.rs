//! µTP socket runtime — the I/O layer that turns the pure-logic
//! [`Connection`] state machine into a real transport over a shared
//! UDP socket.
//!
//! ## Shape
//!
//! - [`UtpSocket::bind`] opens one UDP socket and spawns a single
//!   *driver* task that owns it. All connections multiplexed over that
//!   socket share the driver — there is no socket-per-connection.
//! - The driver demuxes inbound datagrams by `(peer, connection_id)`,
//!   feeds each into the matching `Connection`, and puts the packets
//!   the state machine produces back on the wire.
//! - [`UtpStream`] is the application handle. It implements
//!   `AsyncRead`/`AsyncWrite`, so the existing peer code (the BT
//!   handshake, MSE, the wire-message loop) runs on top of µTP
//!   unchanged — exactly as it does over a `TcpStream`.
//!
//! Streams talk to the driver over an unbounded command channel
//! (writes/closes) and receive delivered bytes over a per-connection
//! unbounded channel. The driver is the single owner of every
//! `Connection`, so the state machine never needs locking.
//!
//! ## Write backpressure
//!
//! The command channel is unbounded, so backpressure is enforced one
//! level up, at [`UtpStream::poll_write`], via a per-connection
//! [`SendGate`] credit ledger shared between the stream and the
//! driver. A write first reserves `min(len, available)` bytes of
//! credit; if none is available it parks the caller's waker and
//! returns `Poll::Pending`. The driver releases credit exactly when
//! bytes *leave* the connection — acked by the peer (dropped from
//! `out_blocks`/`in_flight`), or dropped wholesale when the connection
//! closes/reaps — and wakes the parked writer. Total driver-held
//! outbound memory per connection is therefore bounded at
//! [`SEND_BUF_CAP_BYTES`] regardless of how fast the application
//! writes.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::interval;

use super::connection::{Connection, State};
use super::packet::{Packet, PacketType};

/// How often the driver runs the timer pass (retransmits, FIN/RTO
/// progress, window draining when no acks are arriving).
const TICK_INTERVAL: Duration = Duration::from_millis(50);

/// How long [`UtpSocket::connect`] waits for the handshake to complete
/// before giving up. The state machine's own `HARD_TIMEOUT` is longer;
/// this bounds the caller's wait so a dead peer doesn't hang a dial.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest UDP datagram we'll read. µTP packets are far smaller
/// (header + ≤1200 payload), but size for the theoretical max so a
/// jumbo/garbage datagram is truncated rather than mis-parsed.
const RECV_BUF: usize = 65_535;

/// Hard cap on the number of connections the driver will hold at once.
/// UDP source addresses are spoofable, so a flood of forged SYNs —
/// each from a distinct `(addr, connection_id)` — would otherwise
/// create an unbounded number of receiver-side connection entries
/// (and queued accepts), a cheap remote OOM that the per-source-IP
/// TCP rate limit (B4) can't defend because the sources are forged.
/// Once we're at the cap we drop new *inbound* SYNs; outbound dials
/// (engine-initiated, already bounded by the peer cap) are unaffected
/// because they're created via the command channel, not here. A
/// half-open forged entry is reaped at `HARD_TIMEOUT`, so the cap
/// bounds steady-state memory regardless of flood rate. Sized well
/// above any legitimate peer set + in-flight dial races.
const MAX_CONNS: usize = 1024;

/// Per-connection cap, in bytes, on outbound data the driver holds for
/// the peer — the unsent queue plus every sent-but-unacked packet
/// (`Connection::outstanding_send_bytes`). [`UtpStream::poll_write`]
/// refuses to enqueue past this: it accepts a partial write up to the
/// remaining credit and returns `Poll::Pending` when none is left,
/// parking the writer until the driver releases acked bytes.
///
/// Sizing: the engine's upload path is paced by peer `Request`s at
/// `PIPELINE_DEPTH` × 16 KiB ≈ 80 KiB per peer in flight, so 256 KiB is
/// ~3× legitimate headroom — a well-behaved upload never blocks. The
/// bound turns the previously unbounded app→driver queue into a fixed
/// worst case of cap × live connections (≈ 12 MiB at the engine's 50-peer
/// cap; the forged-SYN `MAX_CONNS` ceiling can't reach it because remote
/// peers can't make *us* write). Chosen over tokio's bounded-channel
/// backpressure because one shared bounded channel would couple unrelated
/// streams' writers together.
const SEND_BUF_CAP_BYTES: usize = 256 * 1024;

/// Shared write-side credit ledger for one connection: how many bytes
/// the stream side has reserved against [`SEND_BUF_CAP_BYTES`], and the
/// waker of any writer currently blocked on full credit.
///
/// The stream reserves atomically before enqueueing a `Send`; the driver
/// releases exactly what leaves the connection and wakes the parked
/// writer. Single-reserver (one `poll_write` at a time per stream, &mut),
/// single-releaser (the driver), so plain atomics + one waker slot are
/// sufficient — no unbounded waiter queues.
struct SendGate {
    /// Bytes currently reserved by the stream (mirrors what the driver
    /// holds once the `Send` command lands; transiently over-counts
    /// while the command is still in the channel, which is the safe
    /// direction).
    used: AtomicUsize,
    closed: AtomicBool,
    /// Waker of the writer blocked in `poll_write`, if any. Taken and
    /// woken on release/close.
    waiter: SyncMutex<Option<Waker>>,
}

impl SendGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            waiter: SyncMutex::new(None),
        })
    }

    fn available(&self) -> usize {
        SEND_BUF_CAP_BYTES.saturating_sub(self.used.load(Ordering::SeqCst))
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Reserve up to `want` bytes. Returns what was actually reserved
    /// (≥ 1 whenever `available() > 0`).
    fn reserve(&self, want: usize) -> usize {
        let n = want.min(self.available());
        if n > 0 {
            self.used.fetch_add(n, Ordering::SeqCst);
        }
        n
    }

    /// Give back `n` reserved bytes and wake a blocked writer, if any.
    fn release(&self, n: usize) {
        if n == 0 {
            return;
        }
        // Saturating CAS loop: a concurrent reserve may bump `used`
        // between our load and the swap; retry until one subtraction
        // lands. Never goes below zero.
        loop {
            let cur = self.used.load(Ordering::SeqCst);
            let next = cur.saturating_sub(n);
            match self
                .used
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        self.wake();
    }

    /// Mark the connection dead: blocked (and all future) writes fail
    /// with `BrokenPipe` instead of waiting forever.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.wake();
    }

    fn wake(&self) {
        if let Some(w) = self.waiter.lock().expect("waiter mutex").take() {
            w.wake();
        }
    }
}

/// `(peer address, our recv_id)` — the key every connection is stored
/// under. Inbound packets for an established connection always carry
/// our `recv_id` as their `connection_id`, so this is also the lookup
/// key for routing a datagram.
type ConnKey = (SocketAddr, u16);

/// The error surfaced to a writer when its connection died while it was
/// blocked on (or holding) send credit.
fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "utp connection closed")
}

/// An in-flight outgoing dial: the responder that hands the finished
/// stream back to `connect`, paired with the receive half the stream
/// reads delivered bytes from.
type PendingDial = (
    oneshot::Sender<io::Result<UtpStream>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
);

/// Messages from a [`UtpStream`] to the owning driver.
enum Command {
    /// Open an outgoing connection; the finished stream (or the dial
    /// error) comes back over `resp` once the handshake settles.
    Connect {
        peer: SocketAddr,
        resp: oneshot::Sender<io::Result<UtpStream>>,
    },
    /// Application bytes to send on `key`. Carried as a shared
    /// `Arc<[u8]>` block so the driver can hand it to the connection
    /// without a copy, and so splitting it into N packets shares the one
    /// allocation (see `Connection::enqueue_send_block`). The writer's
    /// `gate` rides along so credit is released even when the connection
    /// has already been reaped (or refuses the block because it's
    /// closing) — otherwise a raced write would strand its reservation
    /// and eventually wedge every writer at the cap.
    Send {
        key: ConnKey,
        data: Arc<[u8]>,
        gate: Arc<SendGate>,
    },
    /// Application requested a clean close of `key`.
    Close { key: ConnKey },
}

/// One driver-owned connection plus its plumbing to the stream half.
struct Entry {
    conn: Connection,
    /// Write-credit ledger shared with the stream half. The driver
    /// releases acked/dropped bytes against it and closes it when the
    /// connection is reaped, so a blocked writer never waits on a dead
    /// connection.
    gate: Arc<SendGate>,
    /// Last value of `conn.outstanding_send_bytes()` the driver has
    /// accounted for. Each sync releases `last_outstanding - current`
    /// back to the gate — exactly the bytes that left the connection
    /// (acked or pruned) since the previous event.
    last_outstanding: usize,
    /// Driver → stream: in-order application bytes. Dropping this
    /// sender signals EOF to the stream's `AsyncRead`.
    deliver: mpsc::UnboundedSender<Vec<u8>>,
    /// For an outgoing dial: the responder that delivers the finished
    /// `UtpStream` once we reach `Connected`, paired with the receive
    /// half the stream will read from. `None` for inbound connections.
    pending: Option<PendingDial>,
    /// For an *inbound* connection: the stream + peer addr we'll hand to
    /// `accept()` — but only once the connection's `return_path_confirmed`
    /// flips, i.e. the peer acked the randomized initial seq_nr (accept
    /// token) we sent in our STATE, proving it actually received that
    /// STATE on the real return path. Holding off until then means a
    /// spoofed-source SYN(+DATA) flood never surfaces to `accept()` /
    /// occupies a peer slot; the half-open entries just reap at
    /// `HARD_TIMEOUT`. `None` once surfaced (or for outbound connections).
    pending_accept: Option<(UtpStream, SocketAddr)>,
    /// Most recent one-way delay measurement for this connection:
    /// `local_recv_micros - peer_timestamp_micros` on the last packet we
    /// received. Echoed back as `timestamp_diff_micros` on our outgoing
    /// packets so the peer's LEDBAT controller (and ours, against another
    /// rustytorrent) has a delay signal to work from.
    last_timestamp_diff: u32,
}

/// A connected µTP stream. Implements `AsyncRead` + `AsyncWrite` so it
/// is a drop-in for `TcpStream` in the peer code.
pub struct UtpStream {
    key: ConnKey,
    cmd: mpsc::UnboundedSender<Command>,
    /// Write-credit ledger shared with the driver (see [`SendGate`]).
    gate: Arc<SendGate>,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Leftover bytes from a delivered chunk that didn't fit the last
    /// read's buffer.
    read_rem: Vec<u8>,
    read_pos: usize,
    shutdown_sent: bool,
}

impl UtpStream {
    fn new(
        key: ConnKey,
        cmd: mpsc::UnboundedSender<Command>,
        incoming: mpsc::UnboundedReceiver<Vec<u8>>,
        gate: Arc<SendGate>,
    ) -> Self {
        Self {
            key,
            cmd,
            gate,
            incoming,
            read_rem: Vec::new(),
            read_pos: 0,
            shutdown_sent: false,
        }
    }

    /// The peer this stream is connected to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.key.0
    }

    /// Peek the first not-yet-consumed byte without removing it from the
    /// stream — the inbound dispatcher uses this to choose plain BT vs
    /// MSE. `Ok(None)` means clean EOF before any byte arrived. The byte
    /// stays buffered, so the subsequent handshake read still sees it
    /// (mirrors `TcpStream::peek` / MSG_PEEK semantics for the caller).
    pub async fn peek_first_byte(&mut self) -> io::Result<Option<u8>> {
        if self.read_pos < self.read_rem.len() {
            return Ok(Some(self.read_rem[self.read_pos]));
        }
        match self.incoming.recv().await {
            Some(bytes) => {
                self.read_rem = bytes;
                self.read_pos = 0;
                Ok(self.read_rem.first().copied())
            }
            None => Ok(None),
        }
    }
}

impl AsyncRead for UtpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // Serve any leftover from the previously delivered chunk first.
        if me.read_pos < me.read_rem.len() {
            let n = (me.read_rem.len() - me.read_pos).min(buf.remaining());
            buf.put_slice(&me.read_rem[me.read_pos..me.read_pos + n]);
            me.read_pos += n;
            return Poll::Ready(Ok(()));
        }
        match me.incoming.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                me.read_rem = bytes;
                me.read_pos = 0;
                let n = me.read_rem.len().min(buf.remaining());
                buf.put_slice(&me.read_rem[..n]);
                me.read_pos = n;
                Poll::Ready(Ok(()))
            }
            // Sender dropped → connection closed/reaped → clean EOF.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UtpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.gate.closed() {
            return Poll::Ready(Err(broken_pipe()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            // Reserve credit up front so concurrent writes can never
            // overshoot SEND_BUF_CAP_BYTES, then hand the bytes to the
            // driver. Partial acceptance keeps the accounting exact: a
            // write larger than the remaining credit is split across
            // polls (write_all callers handle this transparently).
            let n = me.gate.reserve(buf.len());
            if n > 0 {
                // One allocation per accepted chunk: the connection
                // slices this shared block into packet payloads that
                // all reference it (no per-packet copies).
                match me.cmd.send(Command::Send {
                    key: me.key,
                    data: Arc::from(&buf[..n]),
                    gate: Arc::clone(&me.gate),
                }) {
                    Ok(()) => return Poll::Ready(Ok(n)),
                    Err(_) => {
                        me.gate.release(n);
                        return Poll::Ready(Err(broken_pipe()));
                    }
                }
            }
            // Credit exhausted — park until the driver releases acked
            // bytes or closes the connection. Register the waker FIRST,
            // then re-check availability: a release that raced us
            // between the check above and registration would otherwise
            // strand us with no future notification. Spurious wakeups
            // just re-run the loop.
            *me.gate.waiter.lock().expect("send-gate waiter mutex") = Some(cx.waker().clone());
            if me.gate.closed() {
                return Poll::Ready(Err(broken_pipe()));
            }
            if me.gate.available() > 0 {
                continue; // credit freed while we registered — retry now
            }
            return Poll::Pending;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Writes are handed to the driver synchronously; there is no
        // userspace buffer in the stream to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.shutdown_sent {
            let _ = me.cmd.send(Command::Close { key: me.key });
            me.shutdown_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for UtpStream {
    fn drop(&mut self) {
        // Best-effort clean close so the peer sees a FIN even if the
        // caller never called shutdown().
        if !self.shutdown_sent {
            let _ = self.cmd.send(Command::Close { key: self.key });
        }
    }
}

/// A bound µTP endpoint. Cheap to clone-free share via `Arc` if needed;
/// holds only channel handles — the real work lives in the driver task.
pub struct UtpSocket {
    cmd: mpsc::UnboundedSender<Command>,
    accept_rx: Mutex<mpsc::UnboundedReceiver<(UtpStream, SocketAddr)>>,
    local_addr: SocketAddr,
}

impl UtpSocket {
    /// Bind a UDP socket and start the driver task.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Self::from_udp(socket)
    }

    /// Build a µTP socket from an already-bound `UdpSocket`. Used when the
    /// caller needs to pin the underlying datagram socket to a specific
    /// interface first (the `--bind-iface` VPN kill switch) via
    /// `netbind::bind_udp_to_interface`, which `UtpSocket::bind` can't do
    /// because the device-bind setsockopt must run before `bind`.
    pub fn from_udp(socket: UdpSocket) -> io::Result<Self> {
        let socket = Arc::new(socket);
        let local_addr = socket.local_addr()?;
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let driver = Driver {
            socket,
            conns: HashMap::new(),
            cmd_rx,
            cmd_tx: cmd_tx.clone(),
            accept_tx,
            start: Instant::now(),
        };
        tokio::spawn(driver.run());
        Ok(Self {
            cmd: cmd_tx,
            accept_rx: Mutex::new(accept_rx),
            local_addr,
        })
    }

    /// The local UDP address (useful when bound to port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Dial a peer. Resolves once the µTP handshake completes, or errors
    /// on timeout / reset.
    pub async fn connect(&self, peer: SocketAddr) -> io::Result<UtpStream> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd
            .send(Command::Connect {
                peer,
                resp: resp_tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "utp driver gone"))?;
        match tokio::time::timeout(CONNECT_TIMEOUT, resp_rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "utp driver dropped dial",
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "utp handshake timed out",
            )),
        }
    }

    /// Accept the next inbound µTP connection.
    pub async fn accept(&self) -> io::Result<(UtpStream, SocketAddr)> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "utp driver gone"))
    }
}

/// The single task that owns the UDP socket and every `Connection`.
struct Driver {
    socket: Arc<UdpSocket>,
    conns: HashMap<ConnKey, Entry>,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    accept_tx: mpsc::UnboundedSender<(UtpStream, SocketAddr)>,
    start: Instant,
}

impl Driver {
    async fn run(mut self) {
        let mut buf = vec![0u8; RECV_BUF];
        let mut tick = interval(TICK_INTERVAL);
        loop {
            tokio::select! {
                r = self.socket.recv_from(&mut buf) => {
                    if let Ok((n, peer)) = r {
                        self.on_datagram(&buf[..n], peer).await;
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => self.on_command(c).await,
                        // All command senders dropped (socket + every
                        // stream gone) → nothing left to drive.
                        None => break,
                    }
                }
                _ = tick.tick() => self.on_tick().await,
            }
        }
    }

    fn now_micros(&self) -> u32 {
        self.start.elapsed().as_micros() as u32
    }

    /// Encode and send a batch of packets to one peer, stamping the
    /// send timestamp and the echoed delay measurement on each.
    async fn flush(&self, peer: SocketAddr, diff: u32, packets: Vec<Packet>) {
        for mut p in packets {
            p.timestamp_micros = self.now_micros();
            p.timestamp_diff_micros = diff;
            let _ = self.socket.send_to(&p.encode(), peer).await;
        }
    }

    async fn on_datagram(&mut self, data: &[u8], peer: SocketAddr) {
        let pkt = match Packet::decode(data) {
            Ok(p) => p,
            Err(_) => return, // garbage / non-µTP datagram — ignore.
        };
        let now = Instant::now();
        // One-way delay of this packet (peer clock vs ours, offset and
        // all — LEDBAT only uses relative changes / the running min).
        // Echoed on our outgoing packets so the peer can run LEDBAT.
        let recv_diff = self.now_micros().wrapping_sub(pkt.timestamp_micros);
        let key: ConnKey = (peer, pkt.connection_id);
        let mut outgoing = Vec::new();

        if self.conns.contains_key(&key) {
            if let Some(entry) = self.conns.get_mut(&key) {
                entry.last_timestamp_diff = recv_diff;
                if let Some(resp) = entry.conn.handle_incoming(&pkt, now) {
                    outgoing.push(resp);
                }
            }
            self.collect_after(&key, now, &mut outgoing);
            // Return-path validation: surface the held inbound stream to
            // accept() only once the connection confirms the peer acked
            // the randomized initial seq_nr (accept token) we sent in our
            // STATE. A blind spoofer that forges SYN+DATA from a victim
            // address never receives that token, so it can't make this
            // true — its forged packets leave the connection unconfirmed
            // and the half-open entry reaps at HARD_TIMEOUT. (Checking the
            // token, not merely "any non-SYN packet", closes the residual
            // where a forged DATA with a guessed/zero ack would otherwise
            // surface a connection.)
            if self
                .conns
                .get(&key)
                .is_some_and(|e| e.conn.return_path_confirmed())
            {
                let surfaced = self
                    .conns
                    .get_mut(&key)
                    .and_then(|e| e.pending_accept.take());
                if let Some((stream, paddr)) = surfaced {
                    let _ = self.accept_tx.send((stream, paddr));
                }
            }
        } else if pkt.packet_type == PacketType::Syn {
            // A SYN's connection_id is the initiator's recv_id; our
            // recv_id for the receiver side is that + 1.
            let recv_key: ConnKey = (peer, pkt.connection_id.wrapping_add(1));
            if self.conns.contains_key(&recv_key) {
                // Duplicate SYN (our STATE was lost) — re-ack via the
                // existing connection.
                if let Some(entry) = self.conns.get_mut(&recv_key) {
                    entry.last_timestamp_diff = recv_diff;
                    if let Some(resp) = entry.conn.handle_incoming(&pkt, now) {
                        outgoing.push(resp);
                    }
                }
                self.collect_after(&recv_key, now, &mut outgoing);
            } else if self.conns.len() >= MAX_CONNS {
                // At the connection cap — drop this inbound SYN rather
                // than let a forged-source flood grow state without
                // bound. The peer (if real) will retransmit; by then a
                // half-open entry may have been reaped.
                tracing::debug!(target: "utp", %peer, "connection cap reached; dropping inbound SYN");
            } else if let Some((conn, state)) = Connection::new_receiver(&pkt, now) {
                let (dtx, drx) = mpsc::unbounded_channel();
                let gate = SendGate::new();
                let stream = UtpStream::new(recv_key, self.cmd_tx.clone(), drx, Arc::clone(&gate));
                self.conns.insert(
                    recv_key,
                    Entry {
                        conn,
                        gate,
                        last_outstanding: 0,
                        deliver: dtx,
                        pending: None,
                        // Hold the stream until the peer's first non-SYN
                        // packet confirms the return path (anti-spoofing);
                        // only then is it handed to accept().
                        pending_accept: Some((stream, peer)),
                        last_timestamp_diff: recv_diff,
                    },
                );
                outgoing.push(state);
            }
        }
        // Non-SYN packets with no matching connection are ignored.

        self.flush(peer, recv_diff, outgoing).await;
    }

    async fn on_command(&mut self, cmd: Command) {
        let now = Instant::now();
        match cmd {
            Command::Connect { peer, resp } => {
                let recv_id = self.free_recv_id(peer);
                let key: ConnKey = (peer, recv_id);
                let (conn, syn) = Connection::new_initiator(recv_id, now);
                let (dtx, drx) = mpsc::unbounded_channel();
                let gate = SendGate::new();
                self.conns.insert(
                    key,
                    Entry {
                        conn,
                        gate,
                        last_outstanding: 0,
                        deliver: dtx,
                        pending: Some((resp, drx)),
                        pending_accept: None,
                        last_timestamp_diff: 0,
                    },
                );
                // No packet received yet → no delay measurement to echo.
                self.flush(peer, 0, vec![syn]).await;
            }
            Command::Send { key, data, gate } => {
                let len = data.len();
                let accepted = match self.conns.get_mut(&key) {
                    // Hand over the shared block with no copy. `false`
                    // means the connection is closing and dropped the
                    // block — the writer's reservation must be returned.
                    Some(entry) => entry.conn.enqueue_send_block(data),
                    None => false,
                };
                if !accepted {
                    gate.release(len);
                }
                let mut outgoing = Vec::new();
                self.collect_after(&key, now, &mut outgoing);
                let diff = self.diff_for(&key);
                self.flush(key.0, diff, outgoing).await;
            }
            Command::Close { key } => {
                if let Some(entry) = self.conns.get_mut(&key) {
                    entry.conn.close();
                    // Local shutdown is terminal for writers — the TCP
                    // EPIPE analogue. Close the gate so a write issued
                    // after `shutdown()` fails fast instead of being
                    // silently refused by the closing connection (which
                    // would report `Ok` while dropping the bytes), and
                    // so a writer parked on credit is unblocked now
                    // rather than at the HARD_TIMEOUT reap.
                    entry.gate.close();
                }
                let mut outgoing = Vec::new();
                self.collect_after(&key, now, &mut outgoing);
                let diff = self.diff_for(&key);
                self.flush(key.0, diff, outgoing).await;
            }
        }
    }

    /// The last delay measurement to echo on packets we send for `key`
    /// outside the receive path (timer-driven retransmits, app writes).
    /// 0 if the connection is gone or hasn't received anything yet.
    fn diff_for(&self, key: &ConnKey) -> u32 {
        self.conns.get(key).map_or(0, |e| e.last_timestamp_diff)
    }

    async fn on_tick(&mut self) {
        let now = Instant::now();
        let keys: Vec<ConnKey> = self.conns.keys().copied().collect();
        for key in keys {
            let mut outgoing = Vec::new();
            if let Some(entry) = self.conns.get_mut(&key) {
                outgoing.extend(entry.conn.tick(now));
            }
            self.collect_after(&key, now, &mut outgoing);
            let diff = self.diff_for(&key);
            self.flush(key.0, diff, outgoing).await;
        }
    }

    /// After any state-machine input, do the common follow-up for one
    /// connection: deliver received bytes upward, collect newly-sendable
    /// packets into `outgoing`, fire the connect notification on
    /// `Connected`, and reap the entry if it has closed.
    fn collect_after(&mut self, key: &ConnKey, now: Instant, outgoing: &mut Vec<Packet>) {
        let entry = match self.conns.get_mut(key) {
            Some(e) => e,
            None => return,
        };

        let received = entry.conn.take_received(usize::MAX);
        if !received.is_empty() {
            let _ = entry.deliver.send(received);
        }

        outgoing.extend(entry.conn.pending_send_packets(now));

        // Write-credit accounting: whatever left the connection since the
        // last event — DATA payloads the peer acked (or selectively
        // acked), pruned from `in_flight` — is released back to the gate,
        // waking a parked writer if one exists. Packetization itself
        // (queue → in-flight) only moves bytes between the two counters,
        // leaving their sum unchanged, so it never triggers a release.
        let outstanding = entry.conn.outstanding_send_bytes();
        if outstanding < entry.last_outstanding {
            let freed = entry.last_outstanding - outstanding;
            entry.gate.release(freed);
            entry.last_outstanding = outstanding;
        } else {
            entry.last_outstanding = outstanding;
        }

        if entry.conn.state() == State::Connected {
            if let Some((resp, drx)) = entry.pending.take() {
                let stream =
                    UtpStream::new(*key, self.cmd_tx.clone(), drx, Arc::clone(&entry.gate));
                let _ = resp.send(Ok(stream));
            }
        }

        if entry.conn.is_closed() || entry.conn.fin_complete() {
            // Surface a dial failure if the handshake never completed.
            if let Some((resp, _)) = entry.pending.take() {
                let _ = resp.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "utp connection reset before handshake completed",
                )));
            }
            // Return any remaining credit (the buffers just dropped with
            // the connection) and mark the gate closed so a writer parked
            // on it errors instead of waiting forever. Writes already in
            // the command channel are handled by their miss path.
            let remaining = entry.conn.outstanding_send_bytes();
            if remaining > 0 {
                entry.gate.release(remaining);
            }
            entry.gate.close();
            // Dropping the entry drops `deliver` → stream sees EOF.
            self.conns.remove(key);
        }
    }

    /// Pick a recv_id not already in use for `peer`. Also keeps `id+1`
    /// clear so a future inbound SYN can't collide with the send_id
    /// half of an existing outgoing connection.
    fn free_recv_id(&self, peer: SocketAddr) -> u16 {
        loop {
            let id: u16 = rand::random();
            if !self.conns.contains_key(&(peer, id))
                && !self.conns.contains_key(&(peer, id.wrapping_add(1)))
            {
                return id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (UtpSocket, UtpSocket, SocketAddr) {
        let server = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let saddr = server.local_addr();
        let client = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        (server, client, saddr)
    }

    #[tokio::test]
    async fn loopback_small_roundtrip() {
        let (server, client, saddr) = pair().await;
        let srv = tokio::spawn(async move {
            let (mut s, _peer) = server.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            s.write_all(b"world!!").await.unwrap();
            // Hold the stream open long enough for the client to read.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut c = client.connect(saddr).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 7];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world!!");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn loopback_multi_packet_transfer() {
        let (server, client, saddr) = pair().await;
        // 20 000 bytes forces multiple DATA packets and at least one
        // window-slide driven by incoming acks.
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let srv = tokio::spawn(async move {
            let (mut s, _peer) = server.accept().await.unwrap();
            let mut got = vec![0u8; expected.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
        });

        let mut c = client.connect(saddr).await.unwrap();
        c.write_all(&payload).await.unwrap();
        c.flush().await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn inbound_syn_flood_is_capped() {
        use super::super::packet::{Packet, PacketType};
        let server = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let saddr = server.local_addr();

        // One raw UDP socket fires many forged SYNs, each with a
        // distinct connection_id (so each looks like a brand-new
        // inbound connection to the driver).
        let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let n = (MAX_CONNS as u32) + 300;
        for cid in 0..n {
            let syn = Packet::new(PacketType::Syn, cid as u16, 1, 0);
            let _ = attacker.send_to(&syn.encode(), saddr).await;
            // connection_id is u16, so reuse wraps — but distinct cids
            // within 0..65536 are plenty to exceed the cap.
            if cid >= 65000 {
                break;
            }
        }

        // Pure SYNs with no follow-up packet must NEVER surface to
        // accept(): return-path validation holds the connection until a
        // non-SYN packet confirms the source is responsive. A spoofed
        // SYN flood therefore can't occupy a single peer slot. (The
        // driver still bounds its internal half-open state at MAX_CONNS;
        // those entries reap at HARD_TIMEOUT.)
        let mut accepted = 0usize;
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(200), server.accept()).await
        {
            accepted += 1;
            if accepted > 8 {
                break; // any surfaced connection here is already a bug
            }
        }
        assert_eq!(
            accepted, 0,
            "pure-SYN flood must not surface any accepted connection"
        );
    }

    #[tokio::test]
    async fn connect_to_dead_peer_times_out_or_resets() {
        let client = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        // 127.0.0.1:1 — nothing listening; ICMP-unreachable or silence.
        // Either path must surface an error, not hang forever. Use a
        // short outer timeout so the test itself can't wedge.
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let res = tokio::time::timeout(Duration::from_secs(12), client.connect(dead)).await;
        match res {
            Ok(inner) => assert!(inner.is_err(), "dial to dead peer must error"),
            Err(_) => panic!("connect() did not honour its own timeout"),
        }
    }

    // ---- SendGate units ----

    #[test]
    fn send_gate_reserve_release_roundtrip() {
        let g = SendGate::new();
        assert_eq!(g.available(), SEND_BUF_CAP_BYTES);
        assert_eq!(g.reserve(1000), 1000);
        assert_eq!(g.available(), SEND_BUF_CAP_BYTES - 1000);
        // Over-reserve is capped at the remaining credit.
        assert_eq!(g.reserve(SEND_BUF_CAP_BYTES), SEND_BUF_CAP_BYTES - 1000);
        assert_eq!(g.available(), 0);
        // Zero credit reserves nothing — the caller must park.
        assert_eq!(g.reserve(1), 0);
        g.release(400);
        assert_eq!(g.available(), 400);
        // Partial writes: reserve less than asked when partially free.
        assert_eq!(g.reserve(4000), 400);
    }

    #[test]
    fn send_gate_release_saturates_at_zero() {
        let g = SendGate::new();
        // Releasing more than ever reserved must not wrap `used` into a
        // huge value (which would permanently wedge all writers).
        g.release(SEND_BUF_CAP_BYTES + 5);
        assert_eq!(g.available(), SEND_BUF_CAP_BYTES);
    }

    #[test]
    fn send_gate_close_sets_flag() {
        let g = SendGate::new();
        assert!(!g.closed());
        g.close();
        assert!(g.closed());
    }

    /// Mirrors `poll_write`'s registration order exactly (register waker,
    /// then re-check) so the test proves the race-free ordering wakes.
    #[tokio::test]
    async fn send_gate_wakes_registered_waiter_on_release() {
        let g = SendGate::new();
        assert_eq!(g.reserve(SEND_BUF_CAP_BYTES), SEND_BUF_CAP_BYTES);
        let g2 = Arc::clone(&g);
        let waiter = tokio::spawn(async move {
            std::future::poll_fn(|cx| {
                loop {
                    if g2.closed() || g2.available() > 0 {
                        return Poll::Ready(g2.available());
                    }
                    *g2.waiter.lock().expect("waiter mutex") = Some(cx.waker().clone());
                    if g2.available() > 0 {
                        continue; // release raced us before registration
                    }
                    return Poll::Pending;
                }
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        g.release(1234);
        let avail = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("release must wake the registered waiter")
            .expect("task ok");
        assert_eq!(avail, 1234);
    }

    #[tokio::test]
    async fn send_gate_close_wakes_waiter_with_closed_flag() {
        let g = SendGate::new();
        assert_eq!(g.reserve(SEND_BUF_CAP_BYTES), SEND_BUF_CAP_BYTES);
        let g2 = Arc::clone(&g);
        let waiter = tokio::spawn(async move {
            std::future::poll_fn(|cx| {
                if g2.closed() {
                    return Poll::Ready(true);
                }
                *g2.waiter.lock().expect("waiter mutex") = Some(cx.waker().clone());
                Poll::Pending
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        g.release(SEND_BUF_CAP_BYTES); // credit alone must NOT satisfy close-waiters
        assert!(!g.closed());
        g.close();
        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("close must wake the registered waiter")
            .expect("task ok");
    }

    // ---- End-to-end backpressure against a scripted peer ----

    /// A raw-UDP fake peer that completes the µTP handshake and then
    /// follows a script: stay silent (no acks) until told to start acking
    /// everything it receives. This gives deterministic control of the
    /// sender's credit — silence pins `in_flight`, acks release it.
    ///
    /// Proves both halves of the backpressure contract:
    /// 1. `write_all` beyond `SEND_BUF_CAP_BYTES` stalls while unacked,
    /// 2. it completes once the peer acks, with every byte on the wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_write_blocks_at_cap_until_peer_acks() {
        use super::super::packet::PacketType as PT;

        let fake = tokio::net::UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let client_sock = UtpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let fake_addr = fake.local_addr().unwrap();

        // Handshake: connect() sends the SYN; we answer STATE so the dial
        // resolves and the stream enters Connected (DATA may flow).
        let dial = tokio::spawn(async move { client_sock.connect(fake_addr).await });
        let mut buf = vec![0u8; 2048];
        let (n, client_addr) = fake.recv_from(&mut buf).await.unwrap();
        let syn = Packet::decode(&buf[..n]).expect("SYN decodes");
        assert_eq!(syn.packet_type, PT::Syn);
        // Receiver STATE per BEP 29: connection_id = SYN's id (our send
        // id), seq_nr = our initial (arbitrary), ack_nr = the SYN's seq.
        let state = Packet::new(PT::State, syn.connection_id, 7, syn.seq_nr);
        fake.send_to(&state.encode(), client_addr).await.unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(3), dial)
            .await
            .expect("handshake within 3s")
            .expect("dial task ok")
            .expect("handshake succeeds");

        // Writer: CAP + 40 KiB. The extra 40 KiB can only leave after
        // credits free up via acks — proof the writer actually blocked.
        const TOTAL: usize = SEND_BUF_CAP_BYTES + 40_000;
        let payload = vec![0x5Au8; TOTAL];
        let (done_tx, mut done_rx) = mpsc::channel::<usize>(1);
        let writer = tokio::spawn(async move {
            stream
                .write_all(&payload)
                .await
                .expect("write_all succeeds once acks resume");
            let _ = done_tx.send(TOTAL).await;
            stream
        });

        // Phase 1 — silence. Collect the initial window's DATA (a few
        // packets arrive immediately) but ack NOTHING. The writer must
        // stall with its remaining ~CAP bytes queued.
        let mut seen: HashSet<u16> = HashSet::new();
        let mut received = 0usize;
        let quiet_end = Instant::now() + Duration::from_millis(300);
        while Instant::now() < quiet_end {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(50), fake.recv_from(&mut buf)).await
            {
                if let Ok(p) = Packet::decode(&buf[..n]) {
                    if p.packet_type == PT::Data && seen.insert(p.seq_nr) {
                        received += p.payload.len();
                    }
                }
            }
        }
        assert!(received > 0, "initial-window DATA never reached the wire");
        match tokio::time::timeout(Duration::from_millis(500), done_rx.recv()).await {
            Err(_) => {} // still blocked — correct
            Ok(_) => panic!("write_all finished although the peer acked nothing"),
        }

        // Phase 2 — cumulative acks. Ack only the *contiguous* frontier:
        // a lost packet keeps the ack pinned and forces an RTO retransmit,
        // which our dedup set counts once. DATA seqs start right after
        // the SYN's.
        let mut contiguous = syn.seq_nr;
        while seen.contains(&contiguous.wrapping_add(1)) {
            contiguous = contiguous.wrapping_add(1);
        }
        let ack_deadline = Instant::now() + Duration::from_secs(15);
        while received < TOTAL {
            if Instant::now() > ack_deadline {
                panic!("ack phase stalled: {received}/{TOTAL} bytes delivered");
            }
            let pkt =
                match tokio::time::timeout(Duration::from_millis(500), fake.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((n, _))) => Packet::decode(&buf[..n]).ok(),
                    _ => {
                        // Idle stretch — re-ack current frontier in case ours
                        // was lost, then keep waiting.
                        let ack = Packet::new(PT::State, syn.connection_id, 7, contiguous);
                        fake.send_to(&ack.encode(), client_addr).await.unwrap();
                        continue;
                    }
                };
            let Some(pkt) = pkt else { continue };
            if pkt.packet_type != PT::Data {
                continue;
            }
            let seq = pkt.seq_nr;
            if seen.insert(seq) {
                received += pkt.payload.len();
            }
            if seq == contiguous.wrapping_add(1) {
                contiguous = seq;
                while seen.contains(&contiguous.wrapping_add(1)) {
                    contiguous = contiguous.wrapping_add(1);
                }
            }
            let ack = Packet::new(PT::State, syn.connection_id, 7, contiguous);
            fake.send_to(&ack.encode(), client_addr).await.unwrap();
        }
        assert_eq!(received, TOTAL, "every byte must reach the wire");

        // The writer finishes only because acks freed its credit.
        let written = tokio::time::timeout(Duration::from_secs(3), done_rx.recv())
            .await
            .expect("writer completes after acks resume")
            .expect("done channel open");
        assert_eq!(written, TOTAL);
        writer.abort();
    }

    /// A peer RESET must unblock a writer parked on full credit: the
    /// reaped connection closes its gate, so `write_all` surfaces
    /// `BrokenPipe` promptly instead of hanging until the 60 s
    /// HARD_TIMEOUT reap would (never) free the credit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_reset_unblocks_parked_writer() {
        use super::super::packet::PacketType as PT;

        let fake = tokio::net::UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let client_sock = UtpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let fake_addr = fake.local_addr().unwrap();

        let dial = tokio::spawn(async move { client_sock.connect(fake_addr).await });
        let mut buf = vec![0u8; 2048];
        let (n, client_addr) = fake.recv_from(&mut buf).await.unwrap();
        let syn = Packet::decode(&buf[..n]).expect("SYN decodes");
        let state = Packet::new(PT::State, syn.connection_id, 7, syn.seq_nr);
        fake.send_to(&state.encode(), client_addr).await.unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(3), dial)
            .await
            .expect("handshake within 3s")
            .expect("dial task ok")
            .expect("handshake succeeds");

        // Park a writer beyond the cap against a silent peer.
        const TOTAL: usize = SEND_BUF_CAP_BYTES + 40_000;
        let payload = vec![0x5Au8; TOTAL];
        let writer = tokio::spawn(async move { stream.write_all(&payload).await });

        // Let it enqueue and stall.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !writer.is_finished(),
            "writer should be parked while the peer is silent"
        );

        // RESET from the peer — same connection_id our incoming packets
        // carry (the initiator's recv_id, i.e. the SYN's).
        let rst = Packet::new(PT::Reset, syn.connection_id, 9, 0);
        fake.send_to(&rst.encode(), client_addr).await.unwrap();

        let res = tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .expect("reset must unblock the parked writer quickly")
            .expect("writer task ok");
        match res {
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::BrokenPipe,
                "parked write must fail with BrokenPipe after reset"
            ),
            Ok(()) => panic!("write_all completed after peer reset"),
        }
    }

    /// A local `shutdown()` is terminal for writers (the TCP EPIPE
    /// analogue): writes issued afterwards must error promptly instead of
    /// being silently refused by the closing connection while reporting
    /// `Ok`. Polls until the driver has processed the Close, so the test
    /// is scheduling-independent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_shutdown_makes_subsequent_writes_fail() {
        use super::super::packet::PacketType as PT;

        let fake = tokio::net::UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let client_sock = UtpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let fake_addr = fake.local_addr().unwrap();

        let dial = tokio::spawn(async move { client_sock.connect(fake_addr).await });
        let mut buf = vec![0u8; 2048];
        let (n, _client_addr) = fake.recv_from(&mut buf).await.unwrap();
        let syn = Packet::decode(&buf[..n]).expect("SYN decodes");
        let state = Packet::new(PT::State, syn.connection_id, 7, syn.seq_nr);
        fake.send_to(&state.encode(), _client_addr).await.unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(3), dial)
            .await
            .expect("handshake within 3s")
            .expect("dial task ok")
            .expect("handshake succeeds");

        stream.shutdown().await.expect("shutdown ok");

        // The gate closes when the driver processes the Close command —
        // retry briefly so channel scheduling can't flake the test.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match stream.write_all(b"post-shutdown").await {
                Err(e) => {
                    assert_eq!(
                        e.kind(),
                        io::ErrorKind::BrokenPipe,
                        "post-shutdown write must be BrokenPipe"
                    );
                    break;
                }
                Ok(_) => {
                    assert!(
                        Instant::now() < deadline,
                        "writes still succeeding 2s after shutdown — \
                         Close did not terminate the send gate"
                    );
                }
            }
        }
    }
}
