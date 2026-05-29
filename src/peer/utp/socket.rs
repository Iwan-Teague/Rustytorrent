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
//! ## Deliberate gaps (carried over from the state machine)
//!
//! - Fixed send window, no LEDBAT — see [`Connection`].
//! - Selective-ack is parsed by the codec but not acted on.
//! - The application→driver data path is unbounded: a producer that
//!   writes far faster than the network drains will grow the driver's
//!   per-connection `out_buf`. BitTorrent block exchange is naturally
//!   paced by the request/piece protocol, so this isn't a problem in
//!   practice, but it is not a general-purpose backpressured stream.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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

/// `(peer address, our recv_id)` — the key every connection is stored
/// under. Inbound packets for an established connection always carry
/// our `recv_id` as their `connection_id`, so this is also the lookup
/// key for routing a datagram.
type ConnKey = (SocketAddr, u16);

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
    /// Application bytes to send on `key`.
    Send { key: ConnKey, data: Vec<u8> },
    /// Application requested a clean close of `key`.
    Close { key: ConnKey },
}

/// One driver-owned connection plus its plumbing to the stream half.
struct Entry {
    conn: Connection,
    /// Driver → stream: in-order application bytes. Dropping this
    /// sender signals EOF to the stream's `AsyncRead`.
    deliver: mpsc::UnboundedSender<Vec<u8>>,
    /// For an outgoing dial: the responder that delivers the finished
    /// `UtpStream` once we reach `Connected`, paired with the receive
    /// half the stream will read from. `None` for inbound connections
    /// (their stream is built and handed to `accept` immediately).
    pending: Option<PendingDial>,
}

/// A connected µTP stream. Implements `AsyncRead` + `AsyncWrite` so it
/// is a drop-in for `TcpStream` in the peer code.
pub struct UtpStream {
    key: ConnKey,
    cmd: mpsc::UnboundedSender<Command>,
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
    ) -> Self {
        Self {
            key,
            cmd,
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
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match me.cmd.send(Command::Send {
            key: me.key,
            data: buf.to_vec(),
        }) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "utp driver gone",
            ))),
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
        let socket = Arc::new(UdpSocket::bind(addr).await?);
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
    /// send timestamp on each.
    async fn flush(&self, peer: SocketAddr, packets: Vec<Packet>) {
        for mut p in packets {
            p.timestamp_micros = self.now_micros();
            let _ = self.socket.send_to(&p.encode(), peer).await;
        }
    }

    async fn on_datagram(&mut self, data: &[u8], peer: SocketAddr) {
        let pkt = match Packet::decode(data) {
            Ok(p) => p,
            Err(_) => return, // garbage / non-µTP datagram — ignore.
        };
        let now = Instant::now();
        let key: ConnKey = (peer, pkt.connection_id);
        let mut outgoing = Vec::new();

        if self.conns.contains_key(&key) {
            if let Some(entry) = self.conns.get_mut(&key) {
                if let Some(resp) = entry.conn.handle_incoming(&pkt, now) {
                    outgoing.push(resp);
                }
            }
            self.collect_after(&key, now, &mut outgoing);
        } else if pkt.packet_type == PacketType::Syn {
            // A SYN's connection_id is the initiator's recv_id; our
            // recv_id for the receiver side is that + 1.
            let recv_key: ConnKey = (peer, pkt.connection_id.wrapping_add(1));
            if self.conns.contains_key(&recv_key) {
                // Duplicate SYN (our STATE was lost) — re-ack via the
                // existing connection.
                if let Some(entry) = self.conns.get_mut(&recv_key) {
                    if let Some(resp) = entry.conn.handle_incoming(&pkt, now) {
                        outgoing.push(resp);
                    }
                }
                self.collect_after(&recv_key, now, &mut outgoing);
            } else if let Some((conn, state)) = Connection::new_receiver(&pkt, now) {
                let (dtx, drx) = mpsc::unbounded_channel();
                let stream = UtpStream::new(recv_key, self.cmd_tx.clone(), drx);
                self.conns.insert(
                    recv_key,
                    Entry {
                        conn,
                        deliver: dtx,
                        pending: None,
                    },
                );
                outgoing.push(state);
                // If nobody is accepting, the stream is dropped, which
                // sends a Close → the half-open conn is reaped.
                let _ = self.accept_tx.send((stream, peer));
            }
        }
        // Non-SYN packets with no matching connection are ignored.

        self.flush(peer, outgoing).await;
    }

    async fn on_command(&mut self, cmd: Command) {
        let now = Instant::now();
        match cmd {
            Command::Connect { peer, resp } => {
                let recv_id = self.free_recv_id(peer);
                let key: ConnKey = (peer, recv_id);
                let (conn, syn) = Connection::new_initiator(recv_id, now);
                let (dtx, drx) = mpsc::unbounded_channel();
                self.conns.insert(
                    key,
                    Entry {
                        conn,
                        deliver: dtx,
                        pending: Some((resp, drx)),
                    },
                );
                self.flush(peer, vec![syn]).await;
            }
            Command::Send { key, data } => {
                if let Some(entry) = self.conns.get_mut(&key) {
                    entry.conn.enqueue_send(&data);
                }
                let mut outgoing = Vec::new();
                self.collect_after(&key, now, &mut outgoing);
                self.flush(key.0, outgoing).await;
            }
            Command::Close { key } => {
                if let Some(entry) = self.conns.get_mut(&key) {
                    entry.conn.close();
                }
                let mut outgoing = Vec::new();
                self.collect_after(&key, now, &mut outgoing);
                self.flush(key.0, outgoing).await;
            }
        }
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
            self.flush(key.0, outgoing).await;
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

        if entry.conn.state() == State::Connected {
            if let Some((resp, drx)) = entry.pending.take() {
                let stream = UtpStream::new(*key, self.cmd_tx.clone(), drx);
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
}
