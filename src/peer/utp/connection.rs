//! Per-connection µTP state machine.
//!
//! `Connection` is pure logic — no I/O, no timers, no socket
//! handling. The owning driver (in `socket`) drives it by calling
//! `handle_incoming(packet, now)`, `enqueue_send(bytes)`, and
//! `tick(now)`. The state machine returns the list of outgoing
//! packets the driver should put on the wire.
//!
//! Keeping the state machine I/O-free makes it unit-testable: tests
//! drive a pair of `Connection`s back-to-back and assert correctness
//! without spinning a real tokio runtime or UDP socket.
//!
//! ## What is and isn't implemented
//!
//! - **Implemented**: SYN/STATE/DATA/FIN/RESET state transitions,
//!   cumulative-ack sequencing, fixed-window send pacing, retransmit
//!   on RTO (with exponential backoff), receive-side reordering that
//!   is correct across the 16-bit seq_nr wrap (the reorder buffer is
//!   keyed by an absolute logical sequence — see `pending_in`),
//!   clean FIN-driven close.
//! - **Selective ack (BEP 29)**: a receiver holding out-of-order
//!   packets attaches a SACK bitmask to its acks (`build_sack`); a
//!   sender prunes selectively-acked packets from its retransmit queue
//!   (`process_sack`). When a SACK reports >= 3 packets past the gap
//!   (TCP-style duplicate-ack loss signal) the sender fast-retransmits
//!   the gap immediately instead of waiting out its RTO.
//! - **LEDBAT (BEP 29)**: a delay-based controller ([`Ledbat`]) sizes
//!   the send window from one-way-delay samples (the peer's echoed
//!   `timestamp_diff`), yielding to other traffic as queuing delay
//!   builds. Falls back to the fixed `INITIAL_WINDOW_PACKETS` until a
//!   usable sample arrives, with a 2-packet floor so it can't stall.
//! - **Anti-spoof accept token (receiver side)**: the receiver's
//!   initial seq_nr is drawn from the CSPRNG and doubles as an
//!   unguessable accept token. The return path is confirmed only once
//!   an incoming non-SYN packet acks a seq_nr we actually sent within
//!   a bounded window anchored at that token (see
//!   `return_path_confirmed`), so a blind spoofer that forges SYN+DATA
//!   from a victim address — and never receives our STATE — cannot
//!   surface an inbound connection to `accept()`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::packet::{Extension, Packet, PacketType, Payload, EXT_SELECTIVE_ACK};

/// Initial retransmission timeout — first re-send of an unacked
/// packet fires this long after the original send. The RTO doubles
/// on every subsequent retransmit of the same packet (capped at
/// `MAX_RTO`).
pub const INITIAL_RTO: Duration = Duration::from_millis(1000);
/// Cap on the per-packet RTO. Real LEDBAT scales this off measured
/// RTT; we keep it fixed for simplicity.
pub const MAX_RTO: Duration = Duration::from_secs(15);
/// Give up on a connection if a single packet's RTO has doubled
/// past this. Catches stuck peers without leaking state forever.
pub const HARD_TIMEOUT: Duration = Duration::from_secs(60);
/// Initial congestion window, in unacked DATA packets, before LEDBAT
/// has enough delay samples to size the window dynamically. 8 packets
/// (~12 KB at `MAX_DATA_PAYLOAD`) is a common µTP/TCP initial-window
/// choice: large enough to get throughput off the ground within the
/// first RTT, small enough not to swamp a thin/buffered link before the
/// delay-based controller can react. The LEDBAT controller grows or
/// shrinks from here; this value is also the floor we fall back to if it
/// has no estimate yet.
pub const INITIAL_WINDOW_PACKETS: usize = 8;
/// Maximum payload bytes per DATA packet. Sized to fit comfortably
/// under the typical ~1400-byte Ethernet MTU minus IP/UDP/µTP
/// headers (~48 bytes of stack overhead).
pub const MAX_DATA_PAYLOAD: usize = 1200;
/// Receive window we advertise to the peer (bytes). Plenty for any
/// real BitTorrent block-exchange flow; sized to make wnd_size
/// effectively non-throttling. This is also the hard bound on undelivered
/// receive-side bytes per connection (`in_buf` + stashed out-of-order
/// payloads): incoming DATA past it is refused unacked until the
/// application drains, so even a hostile peer that ignores wnd_size can
/// overshoot by at most one packet instead of buffering without limit.
pub const RECV_WINDOW_BYTES: u32 = 1024 * 1024;
/// Hard cap on out-of-order DATA packets we'll buffer while waiting
/// for the gap-filling packet to arrive. Without this, a malicious
/// peer can withhold one seq_nr and then stream packets at
/// ever-higher seq_nrs, forcing us to buffer every payload in memory
/// indefinitely (a cheap remote OOM). Sized to comfortably cover the
/// advertised receive window (`RECV_WINDOW_BYTES / MAX_DATA_PAYLOAD`,
/// rounded up) — a well-behaved peer never exceeds it; a flooding
/// peer just gets its excess out-of-order packets dropped and must
/// retransmit them in order.
pub const MAX_PENDING_IN: usize = RECV_WINDOW_BYTES as usize / MAX_DATA_PAYLOAD + 1;

/// LEDBAT (BEP 29) delay-based congestion controller. Pure logic: fed
/// one-way-delay samples + bytes acked, it sizes the send window in
/// bytes so the connection yields to other traffic once it detects
/// queuing delay building past `TARGET_MICROS`.
///
/// ## Base-delay tracking
///
/// Per BEP 29 / libtorrent the base delay is the minimum over a rolling
/// history of per-minute minima (≈13 one-minute slots), NOT a single
/// running min over all time. The history matters when the path's true
/// base delay *rises* — e.g. a route change adds 20 ms of propagation:
/// with a single all-time min we'd stay pinned to the old low forever,
/// reading the new floor as 20 ms of standing queue and needlessly
/// throttling. The rolling window lets stale low samples age out (the
/// slot holding them is eventually retired) so the base can recover
/// upward.
///
/// We keep both: the rolling per-minute history ([`base_history`]) and a
/// `fixed_floor` running min that is *never* retired. The reported base
/// is the higher of (a) the min over retained history slots and (b) the
/// fixed floor — so the history can only ever *raise* the base above the
/// all-time min, never drop it below. That keeps the original fail-safe
/// (a too-low base over-shrinks the window → we under-utilise rather than
/// congest) while still letting the base climb after a genuine route
/// change. With no samples yet the caller uses the fixed window.
#[derive(Debug, Clone)]
struct Ledbat {
    /// Current congestion window, in bytes.
    cwnd_bytes: f64,
    /// Running minimum over *all* samples ever seen (micros). Never
    /// retired, so it pins the absolute floor the reported base can take
    /// — the rolling history can only raise the base above this, never
    /// below it. Preserves the original fail-safe behaviour.
    fixed_floor: Option<u32>,
    /// Rolling history of per-minute delay minima (micros), newest at the
    /// back. A new slot is pushed each minute; the oldest is dropped once
    /// the window is full, so a stale low sample ages out and the base can
    /// recover after a route change. The reported base is the min over
    /// these slots (combined with `fixed_floor`).
    base_history: VecDeque<u32>,
    /// When the current (newest) history slot started. Once a sample
    /// arrives `BASE_DELAY_SLOT` or more after this, the slot is sealed
    /// and a fresh one opened. `None` until the first usable sample.
    cur_slot_start: Option<Instant>,
    /// True once we've fed at least one usable sample. Until then the
    /// caller falls back to the fixed window — our own µTP↔µTP loopback
    /// and any peer that doesn't echo `timestamp_diff` leave samples at
    /// zero, and we must not let that stall the transfer.
    has_sample: bool,
}

/// Target one-way queuing delay (micros). LEDBAT aims to keep the
/// standing queue at ~100 ms and backs off above it.
const LEDBAT_TARGET_MICROS: f64 = 100_000.0;
/// Cap on how fast the window grows, in bytes per RTT. One MSS/RTT —
/// deliberately gentler than libtorrent's 3000 so we ramp conservatively.
const LEDBAT_MAX_CWND_INCREASE: f64 = MAX_DATA_PAYLOAD as f64;
/// Window floor so the controller can never stall the connection.
const LEDBAT_MIN_WINDOW: f64 = (2 * MAX_DATA_PAYLOAD) as f64;
/// Window ceiling — matches our advertised receive window; plenty for
/// any BitTorrent block-exchange flow and bounds runaway growth.
const LEDBAT_MAX_WINDOW: f64 = RECV_WINDOW_BYTES as f64;
/// Length of one base-delay history slot. libtorrent buckets the
/// base-delay history into one-minute minima; we match that.
const BASE_DELAY_SLOT: Duration = Duration::from_secs(60);
/// Number of per-minute slots retained in the base-delay history. ≈13
/// minutes of memory, per libtorrent — long enough that a transient
/// low sample (e.g. a momentarily empty queue) still influences the
/// base for a while, short enough that the base recovers within minutes
/// of a genuine upward route change.
const BASE_DELAY_SLOTS: usize = 13;

impl Ledbat {
    fn new() -> Self {
        Self {
            // Start at the fixed window so behaviour matches the legacy
            // pacing until the first real sample arrives.
            cwnd_bytes: (INITIAL_WINDOW_PACKETS * MAX_DATA_PAYLOAD) as f64,
            fixed_floor: None,
            base_history: VecDeque::new(),
            cur_slot_start: None,
            has_sample: false,
        }
    }

    /// Fold one delay sample into the rolling per-minute base-delay
    /// history and return the current base estimate. Advances to a fresh
    /// slot when the current one is `BASE_DELAY_SLOT` old (retiring the
    /// oldest once the window is full), updates the newest slot's running
    /// minimum, and keeps the never-retired `fixed_floor`. The returned
    /// base is `max(min-over-history, fixed_floor)` so the history can
    /// only raise the base above the all-time min, never below it.
    fn update_base(&mut self, delay_sample: u32, now: Instant) -> u32 {
        // Never-retired running min: the absolute floor on the base.
        let floor = self
            .fixed_floor
            .map_or(delay_sample, |f| f.min(delay_sample));
        self.fixed_floor = Some(floor);

        match self.cur_slot_start {
            None => {
                // First usable sample — open the first slot.
                self.base_history.push_back(delay_sample);
                self.cur_slot_start = Some(now);
            }
            Some(start) => {
                if now.duration_since(start) >= BASE_DELAY_SLOT {
                    // Seal the current slot, open a new one. Advance by
                    // whole slots so a long idle gap (multiple minutes
                    // with no sample) doesn't leave the window full of
                    // stale slots — it ages them out as it should.
                    let elapsed = now.duration_since(start);
                    let slots_passed =
                        (elapsed.as_secs() / BASE_DELAY_SLOT.as_secs()).max(1) as usize;
                    for _ in 0..slots_passed {
                        self.base_history.push_back(delay_sample);
                        if self.base_history.len() > BASE_DELAY_SLOTS {
                            self.base_history.pop_front();
                        }
                    }
                    // Anchor the new slot's start on a slot boundary so
                    // slot length stays ~1 minute regardless of sample
                    // jitter.
                    self.cur_slot_start = Some(start + BASE_DELAY_SLOT * (slots_passed as u32));
                } else if let Some(cur) = self.base_history.back_mut() {
                    // Same slot — fold into its running minimum.
                    *cur = (*cur).min(delay_sample);
                } else {
                    self.base_history.push_back(delay_sample);
                }
            }
        }

        let hist_min = self.base_history.iter().copied().min().unwrap_or(floor);
        hist_min.max(floor)
    }

    /// Fold one ack into the window. `delay_sample` is the peer's
    /// `timestamp_diff` (their measurement of our send→their-recv delay);
    /// `bytes_acked` is how many payload bytes this ack freed;
    /// `peer_wnd` is the peer's advertised receive window (0 = unknown);
    /// `now` drives the per-minute base-delay slot advance.
    fn on_ack(&mut self, delay_sample: u32, bytes_acked: usize, peer_wnd: u32, now: Instant) {
        if delay_sample == 0 || bytes_acked == 0 {
            return; // not a usable sample — keep the fixed-window fallback
        }
        self.has_sample = true;
        let base = self.update_base(delay_sample, now);

        let queuing = delay_sample.saturating_sub(base) as f64;
        let off_target = (LEDBAT_TARGET_MICROS - queuing) / LEDBAT_TARGET_MICROS;
        let window_factor = bytes_acked as f64 / self.cwnd_bytes;
        let gain = LEDBAT_MAX_CWND_INCREASE * off_target * window_factor;
        self.cwnd_bytes = (self.cwnd_bytes + gain).clamp(LEDBAT_MIN_WINDOW, LEDBAT_MAX_WINDOW);

        // Never send past what the peer says it can buffer.
        if peer_wnd > 0 {
            self.cwnd_bytes = self.cwnd_bytes.min(peer_wnd as f64).max(LEDBAT_MIN_WINDOW);
        }
    }

    /// The current base-delay estimate (micros), or `None` before any
    /// usable sample. Exposed for tests asserting the rolling-minute
    /// recovery behaviour.
    #[cfg(test)]
    fn base_delay(&self) -> Option<u32> {
        if !self.has_sample {
            return None;
        }
        let floor = self.fixed_floor?;
        Some(
            self.base_history
                .iter()
                .copied()
                .min()
                .unwrap_or(floor)
                .max(floor),
        )
    }

    /// The send window in packets, or `None` if no sample has arrived yet
    /// (caller uses the fixed window). Always at least 2 packets.
    fn window_packets(&self) -> Option<usize> {
        if !self.has_sample {
            return None;
        }
        Some(((self.cwnd_bytes / MAX_DATA_PAYLOAD as f64) as usize).max(2))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initiator: SYN sent, awaiting peer's STATE response.
    SynSent,
    /// Receiver: SYN received, STATE response queued.
    SynReceived,
    /// Both sides agreed on connection IDs; data flows.
    Connected,
    /// Local side requested close; FIN queued/in-flight.
    FinSent,
    /// Peer closed; we've drained their buffered data.
    Closed,
    /// Hard reset; the connection is dead with no clean-close path.
    Reset,
}

/// One unacked packet sitting in our retransmit queue.
struct InFlight {
    seq_nr: u16,
    send_time: Instant,
    rto: Duration,
    /// The decoded packet to re-send. Re-encoded on each transmit so
    /// the latest seq_nr / ack_nr / timestamp can be embedded.
    packet: Packet,
}

/// Per-conversation µTP state. One of these per peer connection.
pub struct Connection {
    pub state: State,
    /// connection_id used on outgoing packets ("send id"). For the
    /// initiator this is the original SYN id; for the receiver it's
    /// `syn_id + 1`.
    send_id: u16,
    /// connection_id we expect on incoming packets ("recv id").
    /// Mirror of the peer's send_id.
    recv_id: u16,
    /// Next seq_nr we'll assign to an outgoing SYN/DATA/FIN packet.
    /// STATE packets reuse the current seq_nr (per BEP 29: pure acks
    /// do not advance the sender's sequence).
    next_seq_nr: u16,
    /// Highest seq_nr from the peer we've delivered to the
    /// application. ack_nr we report in outgoing packets.
    peer_seq_nr_acked: u16,
    /// Outgoing application data the caller has handed us, waiting to be
    /// packetized — held as a queue of whole *blocks* (one per `write`),
    /// each a shared `Arc<[u8]>`. Packetization slices each block into
    /// DATA-packet payloads that *share* the block's single allocation
    /// (see [`Payload`]), instead of copying each ~1200-byte chunk into a
    /// fresh `Vec`. `out_head` is how many bytes of the front block have
    /// already been packetized; `out_len` is the total unsent bytes
    /// across all blocks (kept so emptiness / length checks stay O(1)).
    out_blocks: VecDeque<Arc<[u8]>>,
    out_head: usize,
    out_len: usize,
    /// Application bytes the peer sent that we've delivered into the
    /// in-order stream. Pulled by `take_received`.
    in_buf: VecDeque<u8>,
    /// Absolute (non-wrapping) logical position of the delivery
    /// frontier: how many in-order DATA packets we've delivered from the
    /// peer since the connection opened. Tracks `peer_seq_nr_acked` but
    /// as a `u64` that never wraps, so it can key `pending_in` with a
    /// total order that survives the 16-bit seq_nr wrap.
    peer_logical_acked: u64,
    /// Out-of-order DATA packets we've received, waiting for the gap
    /// before them to close.
    ///
    /// Keyed by an *absolute logical sequence* (`u64`), NOT by the raw
    /// `seq_nr`. A raw-`u16` key orders incorrectly across the 65535→0
    /// wrap: on a long-lived connection (one µTP stream past ~80 MB /
    /// 65 536 packets) the seq_nr wraps, and a `BTreeMap<u16, _>` would
    /// then sort a freshly-wrapped seq (0, 1, 2…) as *less than* the
    /// still-buffered pre-wrap seqs (…65534, 65535) — scrambling both the
    /// delivery order and the "lowest pending" view. The logical key is
    /// `peer_logical_acked` plus the wrap-aware distance the packet sits
    /// ahead of the frontier (`seq_nr.wrapping_sub(peer_seq_nr_acked)`),
    /// so it increases monotonically with delivery order no matter where
    /// the raw seq_nr lands in the 16-bit space, and never needs
    /// rebasing across the wrap.
    ///
    /// Values are `Payload` (a shared-Arc slice), so buffering an
    /// out-of-order packet and later draining it never copies the bytes —
    /// the stash holds a refcount on the decoded datagram's payload.
    pending_in: BTreeMap<u64, Payload>,
    /// Outgoing packets we've sent but the peer hasn't acked.
    /// Sorted by seq_nr ascending (we push to the back as we send).
    in_flight: VecDeque<InFlight>,
    /// Anti-spoof accept token for the *receiver* side: the random
    /// initial seq_nr we embedded in our STATE response to an inbound
    /// SYN.
    ///
    /// A blind spoofer who forges `SYN`+`DATA` from a victim address
    /// never sees our STATE, so it cannot learn this value. A genuine
    /// peer, having received our STATE, echoes it back as the `ack_nr`
    /// on its next packet. Until we observe a non-SYN packet acking a
    /// seq anchored at this token the return path is unproven and the
    /// driver must NOT surface the connection to `accept()` (see
    /// `return_path_confirmed`). `None` on the initiator side, which
    /// uses the SYN/STATE exchange it started as its own liveness proof.
    accept_token: Option<u16>,
    /// Set once an incoming non-SYN packet's cumulative `ack_nr` lands in
    /// the bounded window anchored at `accept_token`, proving the peer
    /// received our STATE on the real return path. Always `true` for the
    /// initiator (no token to confirm). Read by the driver to gate
    /// `accept()`.
    return_path_confirmed: bool,
    /// When the connection should be hard-killed if we still haven't
    /// reached `Closed` or `Reset`.
    deadline: Instant,
    /// SACK-driven fast retransmit: when a selective ack reveals enough
    /// packets received past the gap, the gap's seq_nr is parked here
    /// and re-sent on the next `pending_send_packets` — beating the
    /// gap packet's RTO by ~one round trip.
    fast_rtx_seq: Option<u16>,
    /// The last gap seq_nr we fast-retransmitted, so a run of SACKs for
    /// the same gap triggers exactly one fast retransmit (further
    /// recovery falls to the normal RTO). Cleared implicitly when the
    /// gap advances to a new seq_nr.
    last_fast_rtx_seq: Option<u16>,
    /// LEDBAT congestion controller sizing the send window. Falls back
    /// to the fixed window until the first usable delay sample arrives.
    cc: Ledbat,
}

impl Connection {
    /// Create the initiator side of a new connection. `recv_id` is
    /// our chosen connection ID — incoming packets from the peer
    /// will carry this value. Outgoing packets go out on
    /// `recv_id + 1` per BEP 29. The driver is expected to put the
    /// returned SYN packet on the wire immediately.
    pub fn new_initiator(recv_id: u16, now: Instant) -> (Self, Packet) {
        // BEP 29: initiator picks `recv_id` randomly; SYN's
        // connection_id == recv_id. Initiator's send_id = recv_id + 1.
        // The peer's recv_id ends up equal to our send_id, and the
        // peer's send_id ends up equal to our recv_id — i.e. each
        // side's send_id matches the other side's recv_id.
        let send_id = recv_id.wrapping_add(1);
        let mut conn = Self {
            state: State::SynSent,
            send_id,
            recv_id,
            next_seq_nr: 1,
            peer_seq_nr_acked: 0,
            peer_logical_acked: 0,
            out_blocks: VecDeque::new(),
            out_head: 0,
            out_len: 0,
            in_buf: VecDeque::new(),
            pending_in: BTreeMap::new(),
            in_flight: VecDeque::new(),
            // Initiator has no accept token — it proves liveness by
            // completing the SYN/STATE handshake it started.
            accept_token: None,
            return_path_confirmed: true,
            deadline: now + HARD_TIMEOUT,
            fast_rtx_seq: None,
            last_fast_rtx_seq: None,
            cc: Ledbat::new(),
        };
        // The SYN packet uses our recv_id as its connection_id; the
        // peer will read this as its OWN send_id and use it on its
        // STATE / DATA / etc. responses.
        let syn = Packet::new(PacketType::Syn, conn.recv_id, conn.next_seq_nr, 0);
        conn.next_seq_nr = conn.next_seq_nr.wrapping_add(1);
        conn.in_flight.push_back(InFlight {
            seq_nr: 1,
            send_time: now,
            rto: INITIAL_RTO,
            packet: syn.clone(),
        });
        (conn, syn)
    }

    /// Create the receiver side from an incoming SYN. The driver
    /// is expected to put the returned STATE packet on the wire
    /// immediately to complete the handshake.
    ///
    /// The receiver's initial seq_nr is drawn from the CSPRNG and serves
    /// as a blind-spoof accept token: the driver must hold the connection
    /// back from `accept()` until `return_path_confirmed()` reports the
    /// peer echoed that value back as an `ack_nr` (see `accept_token`).
    pub fn new_receiver(syn: &Packet, now: Instant) -> Option<(Self, Packet)> {
        // `rand::random` draws from the thread-local CSPRNG — the same
        // source the driver uses for connection_ids — so the token a
        // blind spoofer would have to guess is unpredictable.
        Self::new_receiver_with_seq(syn, now, rand::random::<u16>())
    }

    /// Receiver constructor taking the initial seq_nr explicitly.
    /// `new_receiver` calls this with a CSPRNG draw; tests call it with a
    /// fixed value for determinism.
    fn new_receiver_with_seq(syn: &Packet, now: Instant, init_seq: u16) -> Option<(Self, Packet)> {
        if syn.packet_type != PacketType::Syn {
            return None;
        }
        // BEP 29: receiver's send_id = SYN's connection_id (this
        // matches the initiator's recv_id). Receiver's recv_id =
        // SYN's connection_id + 1 (which matches the initiator's
        // send_id). Each side's send_id == other side's recv_id.
        let send_id = syn.connection_id;
        let recv_id = syn.connection_id.wrapping_add(1);
        let mut conn = Self {
            state: State::SynReceived,
            send_id,
            recv_id,
            // Our randomized initial seq_nr, which doubles as the accept
            // token. STATE reuses it without advancing (per spec), so the
            // first DATA we send also carries this seq.
            next_seq_nr: init_seq,
            peer_seq_nr_acked: syn.seq_nr,
            peer_logical_acked: 0,
            out_blocks: VecDeque::new(),
            out_head: 0,
            out_len: 0,
            in_buf: VecDeque::new(),
            pending_in: BTreeMap::new(),
            in_flight: VecDeque::new(),
            accept_token: Some(init_seq),
            return_path_confirmed: false,
            deadline: now + HARD_TIMEOUT,
            fast_rtx_seq: None,
            last_fast_rtx_seq: None,
            cc: Ledbat::new(),
        };
        // STATE acks the SYN. seq_nr is our chosen initial; ack_nr
        // is the SYN's seq_nr.
        let state = Packet {
            packet_type: PacketType::State,
            connection_id: conn.send_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: conn.recv_window(),
            seq_nr: conn.next_seq_nr,
            ack_nr: syn.seq_nr,
            extensions: Vec::new(),
            payload: Payload::empty(),
        };
        // STATE doesn't increment our seq_nr (per spec), so
        // `next_seq_nr` stays at the randomized initial value for the
        // first DATA.
        conn.state = State::Connected;
        Some((conn, state))
    }

    /// Whether the peer has proven it owns the return path by acking our
    /// randomized initial seq_nr (the accept token). The driver gates
    /// `accept()` on this so a blind spoofer that forges `SYN`+`DATA`
    /// from a victim address — but never receives our STATE — cannot
    /// surface an inbound connection. Always `true` on the initiator
    /// side (it has no token to confirm).
    pub fn return_path_confirmed(&self) -> bool {
        self.return_path_confirmed
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed | State::Reset)
    }

    /// True once a locally-initiated FIN has been fully acknowledged by
    /// the peer (in `FinSent` with nothing left in-flight). Lets the
    /// driver reap the connection immediately instead of waiting out
    /// `HARD_TIMEOUT` — the `State` ack of our FIN never advances us out
    /// of `FinSent` on its own.
    pub fn fin_complete(&self) -> bool {
        self.state == State::FinSent && self.in_flight.is_empty()
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Application has bytes to send. Buffer them as one block;
    /// `pending_send_packets` will packetize as the window allows. This
    /// `&[u8]` entry point copies once into a fresh `Arc<[u8]>` block;
    /// the driver's hot path uses [`enqueue_send_block`] to hand over an
    /// already-shared block with no copy.
    ///
    /// [`enqueue_send_block`]: Self::enqueue_send_block
    pub fn enqueue_send(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.enqueue_send_block(Arc::from(bytes));
    }

    /// Buffer an already-shared outgoing block (no copy). The block is
    /// later sliced into packet payloads that share its single
    /// allocation. An empty block is ignored so it can't wedge the
    /// front-of-queue cursor.
    ///
    /// Returns `true` if the block was buffered, `false` if it was
    /// refused (connection already closing/closed, or an empty block).
    /// The driver's send-credit accounting ([`SendGate`] in `socket`)
    /// relies on this to release the writer's reservation for refused
    /// blocks instead of stranding the credit forever.
    ///
    /// [`SendGate`]: super::socket
    pub fn enqueue_send_block(&mut self, block: Arc<[u8]>) -> bool {
        if matches!(self.state, State::FinSent | State::Closed | State::Reset) {
            return false;
        }
        if block.is_empty() {
            return false;
        }
        self.out_len += block.len();
        self.out_blocks.push_back(block);
        true
    }

    /// Total application bytes this connection holds on the sender's
    /// behalf but the peer hasn't acked yet: unsent queue (`out_len`)
    /// plus every in-flight (sent, unacked) DATA payload. The driver's
    /// send-credit gate tracks exactly this quantity so a blocked
    /// [`UtpStream`] writer resumes when bytes actually leave the
    /// connection — either because they were acked, or because the
    /// connection was reaped and its buffers dropped.
    ///
    /// O(in_flight); called once per driver event for the affected
    /// connection, and `in_flight` is window-bounded, so this stays
    /// cheap.
    pub fn outstanding_send_bytes(&self) -> usize {
        let inflight: usize = self.in_flight.iter().map(|e| e.packet.payload.len()).sum();
        self.out_len + inflight
    }

    /// Pull whatever the application can read right now.
    pub fn take_received(&mut self, max: usize) -> Vec<u8> {
        let n = self.in_buf.len().min(max);
        self.in_buf.drain(..n).collect()
    }

    /// Application requests connection close. Generates a FIN once
    /// the send queue is empty (or now, if the queue is empty).
    pub fn close(&mut self) {
        if matches!(
            self.state,
            State::FinSent | State::Closed | State::Reset | State::SynSent
        ) {
            return;
        }
        self.state = State::FinSent;
    }

    /// Returns true if a packet matches this connection (i.e. came
    /// from the right peer on the right connection_id). The driver
    /// pre-filters by peer SocketAddr; this checks the connection_id.
    ///
    /// Normal incoming packets carry our `recv_id`. A duplicate SYN
    /// (peer's STATE response was lost) carries the original
    /// connection_id — which is our `send_id` on the receiver side.
    /// We match either so the duplicate is delivered to
    /// `handle_incoming` for the re-ack path.
    pub fn matches_incoming(&self, packet: &Packet) -> bool {
        packet.connection_id == self.recv_id
            || (packet.packet_type == PacketType::Syn && packet.connection_id == self.send_id)
    }

    /// Process an incoming packet from the peer. Returns the
    /// outgoing packet (if any) the driver should send immediately
    /// in response — typically a STATE ack. Time-driven outgoing
    /// (window pacing, retransmit) comes out of `pending_send_packets()`
    /// and `tick()`.
    pub fn handle_incoming(&mut self, packet: &Packet, now: Instant) -> Option<Packet> {
        if !self.matches_incoming(packet) {
            return None;
        }
        // RESET is terminal regardless of state.
        if packet.packet_type == PacketType::Reset {
            self.state = State::Reset;
            return None;
        }
        // Free in-flight packets whose seq_nr the peer has acked
        // (cumulative). The peer's ack_nr names the highest seq_nr
        // they've delivered in order.
        let acked_through = packet.ack_nr;
        let mut bytes_acked = 0usize;
        while let Some(front) = self.in_flight.front() {
            if seq_le(front.seq_nr, acked_through) {
                let entry = self.in_flight.pop_front().expect("front just checked");
                bytes_acked += entry.packet.payload.len();
            } else {
                break;
            }
        }
        // Anti-spoof accept gate (receiver side): confirm the return path
        // only when a *non-SYN* packet's cumulative ack lands in the
        // bounded window anchored at our randomized accept token, proving
        // the peer received the STATE we sent (whose seq_nr == token).
        //
        // A legit peer that processed our STATE reports cumulative ack
        // `token - 1` *before* it has received any of our DATA (its "ready
        // for token" baseline), then `token`, `token + 1`, … as our DATA
        // arrives. So the valid closed range is
        // `[token - 1, next_seq_nr - 1]`: `lo = token - 1` (the baseline),
        // `hi = next_seq_nr - 1` (the highest seq we've put on the wire;
        // equals `token - 1` too while no DATA has been sent, since STATE
        // doesn't advance next_seq_nr). Using a *bounded* window — not a
        // bare `seq_le(token, ack)`, which would accept ~half the 16-bit
        // space — means a blind spoofer must land `ack_nr` exactly on one
        // of the handful of seqs anchored at the unguessable random token,
        // not merely in the right half-space. A SYN's ack_nr is
        // attacker-chosen and meaningless, so SYNs never confirm.
        // Confirmation latches once set.
        if !self.return_path_confirmed && packet.packet_type != PacketType::Syn {
            if let Some(token) = self.accept_token {
                let lo = token.wrapping_sub(1);
                let hi = self.next_seq_nr.wrapping_sub(1);
                if seq_le(lo, acked_through) && seq_le(acked_through, hi) {
                    self.return_path_confirmed = true;
                }
            }
        }
        // Selective ack (BEP 29): if the peer reported receiving packets
        // *beyond* the cumulative gap, drop those from the retransmit
        // queue so a future RTO resends only the genuinely-missing
        // packet(s) instead of the whole window.
        if let Some(sack) = packet
            .extensions
            .iter()
            .find(|e| e.kind == EXT_SELECTIVE_ACK)
        {
            bytes_acked += self.process_sack(acked_through, &sack.data);
        }
        // LEDBAT: fold this ack's freshly-acked bytes and the peer's
        // delay measurement (its `timestamp_diff`) into the send window.
        // A zero diff (peer doesn't echo, or our own loopback) is ignored
        // by the controller, which keeps the fixed-window fallback.
        if bytes_acked > 0 {
            self.cc.on_ack(
                packet.timestamp_diff_micros,
                bytes_acked,
                packet.wnd_size,
                now,
            );
        }
        match packet.packet_type {
            PacketType::Syn => {
                // We're already the receiver of this SYN; a
                // duplicate SYN re-arrives because our STATE got
                // lost. Re-ack.
                Some(self.build_state_ack())
            }
            PacketType::State => {
                // Pure ack — no payload, no new seq_nr to advance.
                // SynSent → Connected once we see the peer's STATE.
                if self.state == State::SynSent {
                    self.state = State::Connected;
                    // The STATE's seq_nr is the peer's *next* seq — its
                    // first DATA will reuse this exact value (a STATE
                    // doesn't advance the sender's seq). So we expect
                    // `packet.seq_nr` next, i.e. we've "acked through"
                    // one before it. Setting `peer_seq_nr_acked` to
                    // `packet.seq_nr` itself would make that first DATA
                    // look like a duplicate and silently drop it.
                    self.peer_seq_nr_acked = packet.seq_nr.wrapping_sub(1);
                }
                None
            }
            PacketType::Data => {
                let payload_seq = packet.seq_nr;
                if seq_le(payload_seq, self.peer_seq_nr_acked) {
                    // Duplicate — already delivered (this includes a stale
                    // retransmit sitting *behind* the frontier across the
                    // wrap, which `seq_le` classifies correctly). Re-ack.
                    return Some(self.build_state_ack());
                }
                // Distance ahead of the delivery frontier. 1 == the next
                // expected packet; >1 == a future packet with a gap before
                // it. Wrap-aware via `wrapping_sub`, so it is correct
                // across the 65535→0 seq_nr wrap.
                let dist = payload_seq.wrapping_sub(self.peer_seq_nr_acked);
                if dist == 1 {
                    // Receive-window enforcement: if the application
                    // hasn't drained what we already delivered, REFUSE
                    // the packet — do not buffer it, do not advance the
                    // frontier. The cumulative ack stays where it was,
                    // so a conforming peer stalls (and retransmits at
                    // its RTO) exactly like TCP with a zero window.
                    // Without this, a hostile peer that ignores our
                    // advertised wnd_size could grow `in_buf` (and the
                    // driver→stream queue) without bound while the app
                    // reads slowly or not at all — a remote OOM. With
                    // it, undelivered receive-side memory per
                    // connection is hard-bounded at RECV_WINDOW_BYTES
                    // (+ one stashed-packet allowance via MAX_PENDING_IN
                    // for the out-of-order case).
                    if self.in_buf.len() >= RECV_WINDOW_BYTES as usize {
                        return Some(self.build_state_ack());
                    }
                    // In-order delivery. Push to in_buf, then drain any
                    // buffered packets that now close the gap.
                    self.in_buf.extend(packet.payload.iter().copied());
                    self.peer_seq_nr_acked = payload_seq;
                    self.peer_logical_acked = self.peer_logical_acked.wrapping_add(1);
                    self.drain_pending_in();
                } else {
                    // Out-of-order; stash keyed by *absolute logical
                    // sequence* so ordering and draining survive the wrap.
                    // The logical key is the frontier's logical position
                    // plus the wrap-aware distance ahead of it.
                    let logical = self.peer_logical_acked + dist as u64;
                    // Re-stashing a key we already hold is free (overwrite).
                    // Only grow the buffer up to MAX_PENDING_IN — beyond
                    // that we drop the excess (see the const's rationale):
                    // the peer retransmits once our cumulative ack_nr
                    // advances.
                    if self.pending_in.contains_key(&logical)
                        || self.pending_in.len() < MAX_PENDING_IN
                    {
                        self.pending_in.insert(logical, packet.payload.clone());
                    }
                }
                // Always cumulative-ack our real in-order position, even
                // when we dropped this packet — that tells a flooding
                // peer exactly which seq we're still stuck on.
                Some(self.build_state_ack())
            }
            PacketType::Fin => {
                // Peer is closing. Ack their FIN, deliver any final
                // bytes, transition to Closed once our outgoing is
                // drained.
                self.peer_seq_nr_acked = packet.seq_nr;
                let ack = self.build_state_ack();
                if self.out_len == 0 && self.in_flight.is_empty() {
                    self.state = State::Closed;
                }
                Some(ack)
            }
            PacketType::Reset => unreachable!("handled at top of fn"),
        }
    }

    /// Deliver any buffered out-of-order packets that now sit directly
    /// behind the freshly-advanced delivery frontier.
    ///
    /// `pending_in` is keyed by absolute logical sequence, so the next
    /// contiguous packet is always at `peer_logical_acked + 1`. We pop it,
    /// advance both the wrapping `peer_seq_nr_acked` and the non-wrapping
    /// `peer_logical_acked`, and repeat until the gap reopens. No key
    /// rebasing is needed — absolute keys stay valid across the 16-bit
    /// seq_nr wrap.
    fn drain_pending_in(&mut self) {
        // Same window bound as the in-order accept path: stashed packets
        // draining behind a closed gap must not overflow `in_buf` either
        // (to within one packet — each append is checked before it runs).
        // Whatever doesn't fit stays stashed and drains on a later call
        // once the application has consumed some bytes.
        while self.in_buf.len() < RECV_WINDOW_BYTES as usize {
            let Some(buf) = self.pending_in.remove(&(self.peer_logical_acked + 1)) else {
                break;
            };
            self.in_buf.extend(buf.iter().copied());
            self.peer_seq_nr_acked = self.peer_seq_nr_acked.wrapping_add(1);
            self.peer_logical_acked += 1;
        }
    }

    /// The receive window we advertise: total buffer minus what the
    /// application hasn't taken yet. Advertising the honest remaining
    /// space lets a conforming peer pause *before* we have to drop, and
    /// keeps our advertised value from being a lie that invites the
    /// refusal path above.
    fn recv_window(&self) -> u32 {
        RECV_WINDOW_BYTES.saturating_sub(self.in_buf.len() as u32)
    }

    /// Produce outgoing DATA / FIN packets up to the send window.
    /// The driver puts each on the wire and adds it to the
    /// in-flight retransmit queue (which we already track here).
    pub fn pending_send_packets(&mut self, now: Instant) -> Vec<Packet> {
        let mut out = Vec::new();
        if self.is_closed() {
            return out;
        }
        // Don't send DATA before the SYN handshake completes.
        if self.state == State::SynSent || self.state == State::SynReceived {
            return out;
        }
        // SACK-driven fast retransmit: a selective ack revealed the gap
        // packet was lost (enough later packets arrived), so resend it
        // now rather than waiting out its RTO. Refresh ack_nr and reset
        // its send timer so `tick` doesn't double-send it.
        if let Some(seq) = self.fast_rtx_seq.take() {
            if let Some(entry) = self.in_flight.iter_mut().find(|e| e.seq_nr == seq) {
                entry.packet.ack_nr = self.peer_seq_nr_acked;
                entry.send_time = now;
                out.push(entry.packet.clone());
            }
        }
        // Packetize as much of the send buffer as the window allows.
        // LEDBAT sizes the window once delay samples arrive; until then
        // (loopback / non-echoing peers) we use the fixed window.
        //
        // Each DATA payload is a `Payload` *slice* of the front block's
        // shared `Arc<[u8]>`, so the N packets carved out of one
        // application write share that write's single allocation — no
        // per-chunk `Vec` copy, and the `pkt.clone()` into the retransmit
        // queue below is a refcount bump rather than a byte copy.
        let window = self.cc.window_packets().unwrap_or(INITIAL_WINDOW_PACKETS);
        while self.out_len > 0 && self.in_flight.len() < window {
            // Clone the front block's Arc (refcount bump) and read its
            // length, then release the borrow so we can mutate the cursor.
            let block = match self.out_blocks.front() {
                Some(b) => Arc::clone(b),
                None => break, // out_len > 0 with no block is unreachable
            };
            let block_len = block.len();
            let take = (block_len - self.out_head).min(MAX_DATA_PAYLOAD);
            let payload = Payload::slice(block, self.out_head, take);
            self.out_head += take;
            self.out_len -= take;
            // Front block fully packetized — drop it and reset the cursor.
            if self.out_head >= block_len {
                self.out_blocks.pop_front();
                self.out_head = 0;
            }
            let pkt = Packet {
                packet_type: PacketType::Data,
                connection_id: self.send_id,
                timestamp_micros: 0,
                timestamp_diff_micros: 0,
                wnd_size: self.recv_window(),
                seq_nr: self.next_seq_nr,
                ack_nr: self.peer_seq_nr_acked,
                extensions: Vec::new(),
                payload,
            };
            self.in_flight.push_back(InFlight {
                seq_nr: self.next_seq_nr,
                send_time: now,
                rto: INITIAL_RTO,
                packet: pkt.clone(),
            });
            self.next_seq_nr = self.next_seq_nr.wrapping_add(1);
            out.push(pkt);
        }
        // If close was requested and the send buffer's drained,
        // queue a FIN once.
        if self.state == State::FinSent
            && self.out_len == 0
            && !self
                .in_flight
                .iter()
                .any(|p| p.packet.packet_type == PacketType::Fin)
        {
            let pkt = Packet {
                packet_type: PacketType::Fin,
                connection_id: self.send_id,
                timestamp_micros: 0,
                timestamp_diff_micros: 0,
                wnd_size: self.recv_window(),
                seq_nr: self.next_seq_nr,
                ack_nr: self.peer_seq_nr_acked,
                extensions: Vec::new(),
                payload: Payload::empty(),
            };
            self.in_flight.push_back(InFlight {
                seq_nr: self.next_seq_nr,
                send_time: now,
                rto: INITIAL_RTO,
                packet: pkt.clone(),
            });
            self.next_seq_nr = self.next_seq_nr.wrapping_add(1);
            out.push(pkt);
        }
        out
    }

    /// Drive timers. Returns retransmits the driver must send.
    /// Also transitions to Reset if the hard timeout has fired.
    pub fn tick(&mut self, now: Instant) -> Vec<Packet> {
        if self.is_closed() {
            return Vec::new();
        }
        if now >= self.deadline {
            self.state = State::Reset;
            return Vec::new();
        }
        let mut out = Vec::new();
        for entry in self.in_flight.iter_mut() {
            if now.duration_since(entry.send_time) >= entry.rto {
                // Refresh ack_nr / timestamp on the resend so the
                // packet reflects our latest received state.
                entry.packet.ack_nr = self.peer_seq_nr_acked;
                entry.send_time = now;
                // Exponential backoff up to MAX_RTO.
                entry.rto = (entry.rto * 2).min(MAX_RTO);
                out.push(entry.packet.clone());
            }
        }
        out
    }

    fn build_state_ack(&self) -> Packet {
        Packet {
            packet_type: PacketType::State,
            connection_id: self.send_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: self.recv_window(),
            // STATE packets reuse the current seq_nr — they don't
            // advance it.
            seq_nr: self.next_seq_nr,
            ack_nr: self.peer_seq_nr_acked,
            // Attach a selective-ack bitmask when we're holding
            // out-of-order packets, so the sender can fast-recover the
            // single missing packet rather than the whole window.
            extensions: self.build_sack().into_iter().collect(),
            payload: Payload::empty(),
        }
    }

    /// Build the BEP 29 selective-ack extension from the out-of-order
    /// receive buffer, or `None` if there's nothing buffered. The
    /// bitmask's bit `n` (LSB-first within each byte, matching
    /// libtorrent) represents `ack_nr + 2 + n`; `ack_nr + 1` is the gap
    /// we're waiting on and is never represented. Length is a multiple
    /// of 4 bytes per spec, capped so a sparse far-future packet can't
    /// inflate it.
    fn build_sack(&self) -> Option<Extension> {
        if self.pending_in.is_empty() {
            return None;
        }
        /// 64 bytes = 512 packets of SACK range — vastly more than our
        /// send window; anything past it just waits for RTO.
        const MAX_SACK_BYTES: usize = 64;
        // `pending_in` is keyed by absolute logical sequence, so a key's
        // distance ahead of the frontier is `logical - peer_logical_acked`.
        // The SACK base sits at `ack_nr + 2` (frontier + 2; the gap at
        // frontier + 1 is never represented), so the bit offset is that
        // distance minus 2. Working in logical space keeps this wrap-immune.
        let mut mask: Vec<u8> = vec![0u8; 4];
        for &logical in self.pending_in.keys() {
            // Distance ahead of the frontier (≥ 2 for any buffered packet,
            // since frontier+1 is the open gap and never buffered).
            let dist = logical.saturating_sub(self.peer_logical_acked);
            let offset = match dist.checked_sub(2) {
                Some(o) => o as usize,
                None => continue,
            };
            let byte = offset / 8;
            if byte >= MAX_SACK_BYTES {
                continue;
            }
            if byte >= mask.len() {
                // Grow to the next multiple of 4 bytes that covers `byte`.
                let new_len = (((byte / 4) + 1) * 4).min(MAX_SACK_BYTES);
                mask.resize(new_len, 0);
                if byte >= mask.len() {
                    continue;
                }
            }
            mask[byte] |= 1 << (offset % 8);
        }
        if mask.iter().all(|&b| b == 0) {
            return None;
        }
        Some(Extension {
            kind: EXT_SELECTIVE_ACK,
            data: mask,
        })
    }

    /// Drop in-flight packets the peer selectively acknowledged.
    /// `ack_nr` is the packet's cumulative ack; bit `n` of `mask`
    /// (LSB-first) marks `ack_nr + 2 + n` as received. Packets at or
    /// below the cumulative gap (`ack_nr + 1`) are never represented, so
    /// their `wrapping_sub(base)` lands outside the mask and they're
    /// correctly retained for retransmit.
    /// Returns the number of payload bytes pruned (selectively acked),
    /// which the caller folds into the LEDBAT window.
    fn process_sack(&mut self, ack_nr: u16, mask: &[u8]) -> usize {
        let base = ack_nr.wrapping_add(2);
        let mut pruned_bytes = 0usize;
        let mut kept: VecDeque<InFlight> = VecDeque::with_capacity(self.in_flight.len());
        while let Some(entry) = self.in_flight.pop_front() {
            let offset = entry.seq_nr.wrapping_sub(base) as usize;
            let byte = offset / 8;
            let sacked = byte < mask.len() && (mask[byte] >> (offset % 8)) & 1 == 1;
            if sacked {
                pruned_bytes += entry.packet.payload.len();
            } else {
                kept.push_back(entry);
            }
        }
        self.in_flight = kept;
        // Fast retransmit: a SACK reporting >= 3 packets received past
        // the gap is the µTP analogue of TCP's three-duplicate-ack loss
        // signal (the threshold tolerates mild reordering). Schedule one
        // immediate retransmit of the lowest still-unacked packet — the
        // gap — and remember it so a burst of SACKs for the same gap
        // doesn't trigger repeated resends (the RTO covers the rest).
        let sacked_count: u32 = mask.iter().map(|b| b.count_ones()).sum();
        if sacked_count >= 3 {
            if let Some(front) = self.in_flight.front() {
                let gap = front.seq_nr;
                if self.last_fast_rtx_seq != Some(gap) {
                    self.fast_rtx_seq = Some(gap);
                    self.last_fast_rtx_seq = Some(gap);
                }
            }
        }
        pruned_bytes
    }
}

/// 16-bit sequence-number comparison. Treats numbers in the
/// "rear half" of the wrap as before, the "front half" as after.
/// Identical to TCP's sequence-comparison rule scaled to 16 bits.
fn seq_le(a: u16, b: u16) -> bool {
    // Equivalent to: a == b || a < b (mod 2^16, near b)
    let diff = b.wrapping_sub(a) as i32;
    (0..=32768).contains(&diff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn initiator_emits_syn_on_recv_id() {
        let (conn, syn) = Connection::new_initiator(100, now());
        assert_eq!(conn.state, State::SynSent);
        assert_eq!(syn.packet_type, PacketType::Syn);
        // BEP 29: SYN's connection_id == initiator's recv_id.
        assert_eq!(syn.connection_id, 100);
        // And initiator's send_id is recv_id + 1.
        assert_eq!(conn.send_id, 101);
    }

    #[test]
    fn receiver_acks_syn_with_state_on_send_id() {
        let t = now();
        let (_init, syn) = Connection::new_initiator(100, t);
        let (recv, state) = Connection::new_receiver(&syn, t).unwrap();
        assert_eq!(recv.state, State::Connected);
        assert_eq!(state.packet_type, PacketType::State);
        // Receiver's send_id = SYN.connection_id = 100.
        assert_eq!(state.connection_id, 100);
        // Receiver's recv_id = SYN.connection_id + 1 = 101.
        assert_eq!(recv.recv_id, 101);
        assert_eq!(state.ack_nr, syn.seq_nr);
    }

    #[test]
    fn syn_then_state_advances_initiator_to_connected() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(100, t);
        let (_recv, state) = Connection::new_receiver(&syn, t).unwrap();
        // STATE from peer carries connection_id = peer's send_id =
        // initiator's recv_id. matches_incoming must accept it.
        assert!(init.matches_incoming(&state));
        let reply = init.handle_incoming(&state, t);
        assert!(
            reply.is_none(),
            "STATE in SynSent should not require a reply"
        );
        assert_eq!(init.state, State::Connected);
    }

    /// Drive two connections back-to-back with a perfect channel
    /// (no loss, no reorder). Send some bytes, expect them to
    /// arrive at the peer.
    #[test]
    fn loopback_data_transfer() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(200, t);
        let (mut recv, state) = Connection::new_receiver(&syn, t).unwrap();
        // Complete handshake initiator-side.
        let _ = init.handle_incoming(&state, t);
        assert_eq!(init.state, State::Connected);

        init.enqueue_send(b"hello, mu-tp!");
        // Drive the initiator: produce DATA packets, hand to recv.
        let out = init.pending_send_packets(t);
        assert_eq!(out.len(), 1);
        let reply = recv
            .handle_incoming(&out[0], t)
            .expect("recv must ack DATA");
        assert_eq!(reply.packet_type, PacketType::State);
        // Receiver delivers the bytes to the application layer.
        let got = recv.take_received(64);
        assert_eq!(got, b"hello, mu-tp!");
        // Initiator processes the ack and clears in-flight.
        let _ = init.handle_incoming(&reply, t);
        assert!(init.in_flight.is_empty());
    }

    /// Receiver-initiated DATA must be delivered to the initiator. The
    /// receiver's first DATA reuses the seq_nr it announced in its STATE
    /// (a STATE doesn't advance the sender's seq), so a naive initiator
    /// would treat it as a duplicate and drop it. Regression test for
    /// that off-by-one.
    #[test]
    fn receiver_initiated_data_reaches_initiator() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(700, t);
        let (mut recv, state) = Connection::new_receiver(&syn, t).unwrap();
        // Complete the handshake on the initiator side.
        let _ = init.handle_incoming(&state, t);
        assert_eq!(init.state, State::Connected);

        // Receiver sends the first application bytes.
        recv.enqueue_send(b"from-the-receiver");
        let out = recv.pending_send_packets(t);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].packet_type, PacketType::Data);

        let _ = init.handle_incoming(&out[0], t);
        let got = init.take_received(64);
        assert_eq!(got, b"from-the-receiver");
    }

    /// FIN from one side closes the other once everything's drained.
    #[test]
    fn fin_closes_connection() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(300, t);
        let (mut recv, state) = Connection::new_receiver(&syn, t).unwrap();
        let _ = init.handle_incoming(&state, t);
        // Initiator closes.
        init.close();
        let out = init.pending_send_packets(t);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].packet_type, PacketType::Fin);
        // Receiver sees FIN, acks, transitions to Closed.
        let ack = recv.handle_incoming(&out[0], t).unwrap();
        assert_eq!(ack.packet_type, PacketType::State);
        assert_eq!(recv.state, State::Closed);
    }

    /// Re-send fires after the RTO has elapsed.
    #[test]
    fn rto_triggers_retransmit() {
        let t0 = now();
        let (mut init, _syn) = Connection::new_initiator(400, t0);
        // Before RTO: tick should not retransmit.
        let immediate = init.tick(t0);
        assert!(immediate.is_empty(), "no retransmit before RTO has elapsed");
        // Simulate time passing past INITIAL_RTO.
        let t1 = t0 + INITIAL_RTO + Duration::from_millis(50);
        let retx = init.tick(t1);
        assert_eq!(retx.len(), 1);
        assert_eq!(retx[0].packet_type, PacketType::Syn);
    }

    /// Hard timeout: a connection that never acks gets killed.
    #[test]
    fn hard_timeout_marks_reset() {
        let t0 = now();
        let (mut init, _syn) = Connection::new_initiator(500, t0);
        let later = t0 + HARD_TIMEOUT + Duration::from_secs(1);
        let _ = init.tick(later);
        assert_eq!(init.state, State::Reset);
        assert!(init.is_closed());
    }

    /// Out-of-order DATA arrivals get buffered and delivered when
    /// the gap closes.
    #[test]
    fn out_of_order_data_eventually_delivered_in_order() {
        let t = now();
        let (init, syn) = Connection::new_initiator(600, t);
        let (mut recv, _state) = Connection::new_receiver(&syn, t).unwrap();
        // Hand the receiver seq 3 (out of order) then 2 then expect
        // delivery once the gap closes.
        let recv_id = recv.recv_id;
        let mk = |seq: u16, payload: &[u8]| Packet {
            packet_type: PacketType::Data,
            connection_id: recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: seq,
            ack_nr: 0,
            extensions: Vec::new(),
            payload: payload.to_vec().into(),
        };
        // SYN seq was 1, so the next-expected is 2. Hand 3 first.
        let _ = recv.handle_incoming(&mk(3, b"WORLD"), t);
        assert!(
            recv.take_received(64).is_empty(),
            "seq 3 buffered, gap at 2"
        );
        // Now hand seq 2 → both 2 and 3 should drain.
        let _ = recv.handle_incoming(&mk(2, b"hello,"), t);
        let got = recv.take_received(64);
        assert_eq!(got, b"hello,WORLD");
        // Suppress unused-variable warning on `init` — kept to make
        // the handshake context obvious.
        let _ = init;
    }

    /// A peer that withholds the gap-filler and floods ever-higher
    /// out-of-order seq_nrs must not grow our reorder buffer without
    /// bound. Excess packets are dropped; the buffer stays capped.
    #[test]
    fn out_of_order_flood_is_bounded() {
        let t = now();
        let (init, syn) = Connection::new_initiator(900, t);
        let (mut recv, _state) = Connection::new_receiver(&syn, t).unwrap();
        let recv_id = recv.recv_id;
        let mk = |seq: u16| Packet {
            packet_type: PacketType::Data,
            connection_id: recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: seq,
            ack_nr: 0,
            extensions: Vec::new(),
            payload: vec![0u8; MAX_DATA_PAYLOAD].into(),
        };
        // next-expected is 2 (SYN seq was 1). Never send 2 — flood
        // 3..=N with N far past the cap, all out of order.
        for seq in 3..(3 + MAX_PENDING_IN as u32 + 5_000) {
            let _ = recv.handle_incoming(&mk(seq as u16), t);
        }
        assert!(
            recv.pending_in.len() <= MAX_PENDING_IN,
            "reorder buffer must stay capped at {MAX_PENDING_IN}, got {}",
            recv.pending_in.len()
        );
        // Nothing was delivered in order (the gap at seq 2 is still open).
        assert!(recv.take_received(usize::MAX).is_empty());
        let _ = init;
    }

    /// When the receiver holds an out-of-order packet, its ack must
    /// carry a SACK extension with the bit for the buffered seq set.
    #[test]
    fn receiver_emits_sack_for_out_of_order() {
        let t = now();
        let (_init, syn) = Connection::new_initiator(800, t);
        let (mut recv, _state) = Connection::new_receiver(&syn, t).unwrap();
        let recv_id = recv.recv_id;
        // SYN seq was 1 → next expected is 2. Deliver seq 4 (gap at 2,3).
        let pkt = Packet {
            packet_type: PacketType::Data,
            connection_id: recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: 4,
            ack_nr: 0,
            extensions: Vec::new(),
            payload: b"x".to_vec().into(),
        };
        let ack = recv.handle_incoming(&pkt, t).expect("ack expected");
        let sack = ack
            .extensions
            .iter()
            .find(|e| e.kind == EXT_SELECTIVE_ACK)
            .expect("ack must carry a SACK when holding out-of-order data");
        // base = ack_nr(1) + 2 = 3. seq 4 → offset 1 → byte 0, bit 1.
        assert_eq!(ack.ack_nr, 1, "cumulative ack still stuck at the gap");
        assert_eq!(sack.data[0] & 0b0000_0010, 0b0000_0010, "bit for seq 4 set");
        assert_eq!(sack.data[0] & 0b0000_0001, 0, "seq 3 (the gap) not set");
    }

    /// The sender, on receiving a SACK, drops the selectively-acked
    /// packets from its retransmit queue but keeps the genuine gap.
    #[test]
    fn sender_prunes_inflight_on_sack() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(810, t);
        let (_recv, state) = Connection::new_receiver(&syn, t).unwrap();
        let _ = init.handle_incoming(&state, t);
        // Queue 4 DATA packets (seqs 2,3,4,5 — SYN took seq 1).
        init.enqueue_send(&vec![0u8; MAX_DATA_PAYLOAD * 4]);
        let sent = init.pending_send_packets(t);
        assert_eq!(sent.len(), 4);
        assert_eq!(init.in_flight.len(), 4);

        // Peer cumulatively acks through seq 1 (nothing new) but SACKs
        // seqs 3,4,5 as received — only seq 2 is the real gap.
        // base = ack_nr(1)+2 = 3. seqs 3,4,5 → offsets 0,1,2 → bits 0,1,2.
        let sack = Extension {
            kind: EXT_SELECTIVE_ACK,
            data: vec![0b0000_0111, 0, 0, 0],
        };
        let ack = Packet {
            packet_type: PacketType::State,
            connection_id: init.recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: 1,
            ack_nr: 1,
            extensions: vec![sack],
            payload: Payload::empty(),
        };
        let _ = init.handle_incoming(&ack, t);
        // seqs 3,4,5 pruned; only seq 2 (the gap) remains for retransmit.
        assert_eq!(init.in_flight.len(), 1);
        assert_eq!(init.in_flight.front().unwrap().seq_nr, 2);
    }

    /// A SACK reporting >= 3 packets past the gap triggers an immediate
    /// fast retransmit of the gap (no RTO wait), exactly once per gap.
    #[test]
    fn sack_triggers_fast_retransmit() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(820, t);
        let (_recv, state) = Connection::new_receiver(&syn, t).unwrap();
        let _ = init.handle_incoming(&state, t);
        // Send 4 DATA packets (seqs 2,3,4,5).
        init.enqueue_send(&vec![0u8; MAX_DATA_PAYLOAD * 4]);
        let sent = init.pending_send_packets(t);
        assert_eq!(sent.len(), 4);
        // Nothing more to send and no fast-rtx yet.
        assert!(init.pending_send_packets(t).is_empty());

        // SACK marks seqs 3,4,5 received (3 packets past the gap at 2).
        let recv_id = init.recv_id;
        let mk_ack = || Packet {
            packet_type: PacketType::State,
            connection_id: recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: 1,
            ack_nr: 1,
            extensions: vec![Extension {
                kind: EXT_SELECTIVE_ACK,
                data: vec![0b0000_0111, 0, 0, 0],
            }],
            payload: Payload::empty(),
        };
        let _ = init.handle_incoming(&mk_ack(), t);
        // The gap (seq 2) is fast-retransmitted right now.
        let rtx = init.pending_send_packets(t);
        assert_eq!(rtx.len(), 1);
        assert_eq!(rtx[0].seq_nr, 2);
        assert_eq!(rtx[0].packet_type, PacketType::Data);

        // A second identical SACK for the same gap must NOT retransmit
        // again (dedup) — recovery for repeated loss falls to the RTO.
        let _ = init.handle_incoming(&mk_ack(), t);
        assert!(
            init.pending_send_packets(t).is_empty(),
            "same-gap SACK must fast-retransmit only once"
        );
    }

    // ---- LEDBAT controller ----

    #[test]
    fn ledbat_starts_in_fixed_window_fallback() {
        let cc = Ledbat::new();
        assert_eq!(
            cc.window_packets(),
            None,
            "no sample yet → caller uses fixed window"
        );
    }

    #[test]
    fn ledbat_grows_when_below_target() {
        let t = now();
        let mut cc = Ledbat::new();
        let before = cc.cwnd_bytes;
        // First sample sets base; queuing 0 → off_target 1 → grow.
        cc.on_ack(1000, MAX_DATA_PAYLOAD * INITIAL_WINDOW_PACKETS, 0, t);
        assert!(cc.cwnd_bytes > before);
        assert!(cc.window_packets().unwrap() >= INITIAL_WINDOW_PACKETS);
    }

    #[test]
    fn ledbat_shrinks_when_above_target() {
        let t = now();
        let mut cc = Ledbat::new();
        cc.on_ack(1000, MAX_DATA_PAYLOAD, 0, t); // establish base = 1000
        let grown = cc.cwnd_bytes;
        // A sample 300 ms above base → queuing 300ms >> 100ms target → shrink.
        cc.on_ack(1000 + 300_000, MAX_DATA_PAYLOAD, 0, t);
        assert!(cc.cwnd_bytes < grown);
    }

    #[test]
    fn ledbat_never_drops_below_floor() {
        let t = now();
        let mut cc = Ledbat::new();
        cc.on_ack(1000, MAX_DATA_PAYLOAD, 0, t);
        for _ in 0..200 {
            cc.on_ack(1000 + 5_000_000, MAX_DATA_PAYLOAD * 8, 0, t); // massive queuing
        }
        assert!(cc.cwnd_bytes >= LEDBAT_MIN_WINDOW);
        assert!(cc.window_packets().unwrap() >= 2);
    }

    #[test]
    fn ledbat_base_delay_tracks_min() {
        let t = now();
        let mut cc = Ledbat::new();
        cc.on_ack(5000, MAX_DATA_PAYLOAD, 0, t);
        cc.on_ack(1000, MAX_DATA_PAYLOAD, 0, t);
        cc.on_ack(8000, MAX_DATA_PAYLOAD, 0, t);
        assert_eq!(cc.base_delay(), Some(1000));
    }

    #[test]
    fn ledbat_ignores_unusable_samples() {
        let t = now();
        let mut cc = Ledbat::new();
        cc.on_ack(0, MAX_DATA_PAYLOAD, 0, t); // zero delay (peer doesn't echo)
        cc.on_ack(1000, 0, 0, t); // zero bytes acked
        assert_eq!(
            cc.window_packets(),
            None,
            "no usable sample → still fallback"
        );
    }

    #[test]
    fn ledbat_respects_peer_receive_window() {
        let t = now();
        let mut cc = Ledbat::new();
        cc.on_ack(1000, MAX_DATA_PAYLOAD * 8, 3 * MAX_DATA_PAYLOAD as u32, t);
        assert!(cc.cwnd_bytes <= 3.0 * MAX_DATA_PAYLOAD as f64);
        assert!(cc.cwnd_bytes >= LEDBAT_MIN_WINDOW);
    }

    /// The rolling per-minute base-delay history must let the base
    /// *recover upward* after a route change: a one-off low sample only
    /// influences the base while its minute slot is retained; once enough
    /// minutes of higher samples have shifted it out of the window, the
    /// base climbs to the new floor instead of staying pinned to the old
    /// low forever (which a single all-time running min would do).
    #[test]
    fn ledbat_base_recovers_after_slot_window_expires() {
        let t0 = now();
        let mut cc = Ledbat::new();
        // Minute 0: a very low base sample (e.g. momentarily empty queue).
        cc.on_ack(1000, MAX_DATA_PAYLOAD, 0, t0);
        assert_eq!(cc.base_delay(), Some(1000), "low sample sets the base");

        // Route change: the true floor is now ~50 ms higher. Feed one
        // higher sample per minute for more than the full slot window so
        // the slot holding the old 1000 ages out of the history.
        let higher = 51_000;
        for i in 1..=(BASE_DELAY_SLOTS as u32 + 1) {
            let t = t0 + BASE_DELAY_SLOT * i;
            cc.on_ack(higher, MAX_DATA_PAYLOAD, 0, t);
        }
        // The old low has been retired; the base recovered to the new
        // floor (within the retained slots, all == higher).
        assert_eq!(
            cc.base_delay(),
            Some(higher),
            "base must recover upward once the stale low slot ages out"
        );
    }

    /// Within a single minute slot, repeated samples fold into that
    /// slot's running minimum and the base tracks the slot min — it does
    /// not advance a slot per sample.
    #[test]
    fn ledbat_base_holds_min_within_one_slot() {
        let t0 = now();
        let mut cc = Ledbat::new();
        cc.on_ack(8000, MAX_DATA_PAYLOAD, 0, t0);
        // A few seconds later (same minute slot), a lower sample.
        cc.on_ack(3000, MAX_DATA_PAYLOAD, 0, t0 + Duration::from_secs(5));
        // Still the same slot: base is the slot minimum.
        assert_eq!(cc.base_delay(), Some(3000));
        // Only one slot has been opened.
        assert_eq!(cc.base_history.len(), 1);
    }

    /// Low-delay acks must open the connection's effective send window
    /// past the fixed INITIAL_WINDOW_PACKETS.
    #[test]
    fn ledbat_window_opens_with_low_delay_acks() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(830, t);
        let (_recv, state) = Connection::new_receiver(&syn, t).unwrap();
        let _ = init.handle_incoming(&state, t);
        init.enqueue_send(&vec![0u8; MAX_DATA_PAYLOAD * 20]);

        // First batch is the fixed window (no delay sample yet).
        let first = init.pending_send_packets(t);
        assert_eq!(first.len(), INITIAL_WINDOW_PACKETS);

        // Peer acks all of them with a low one-way delay → window opens.
        let last_seq = first.last().unwrap().seq_nr;
        let ack = Packet {
            packet_type: PacketType::State,
            connection_id: init.recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 1000,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: 1,
            ack_nr: last_seq,
            extensions: Vec::new(),
            payload: Payload::empty(),
        };
        let _ = init.handle_incoming(&ack, t);
        let second = init.pending_send_packets(t);
        assert!(
            second.len() > INITIAL_WINDOW_PACKETS,
            "window should open past {INITIAL_WINDOW_PACKETS}, sent {}",
            second.len()
        );
    }

    #[test]
    fn seq_le_wraps_correctly_near_zero() {
        // 65000 is "before" 100 (the gap is < 32768).
        assert!(seq_le(65000, 100));
        assert!(!seq_le(100, 65000));
        // Equality counts as "before or equal".
        assert!(seq_le(42, 42));
        // Adjacent values.
        assert!(seq_le(50, 51));
        assert!(!seq_le(51, 50));
    }

    // ---- shared-allocation send path (item 4) ----

    /// One application write spanning several packets must split into
    /// payloads whose concatenation is exactly the input, with full-MTU
    /// chunks and a smaller tail — and (white-box) all of a block's
    /// packet payloads must share that block's single backing allocation,
    /// not be N independent copies.
    #[test]
    fn one_block_splits_into_shared_payload_slices() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(840, t);
        let (_recv, state) = Connection::new_receiver(&syn, t).unwrap();
        let _ = init.handle_incoming(&state, t);

        // 2.5 packets' worth of data in a single write → one block.
        let total = MAX_DATA_PAYLOAD * 2 + 500;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        init.enqueue_send(&data);

        // Open the window wide enough to drain it all at once.
        init.cc.cwnd_bytes = LEDBAT_MAX_WINDOW;
        init.cc.has_sample = true;
        let pkts = init.pending_send_packets(t);
        assert_eq!(pkts.len(), 3, "2.5 MTUs → 3 DATA packets");
        assert_eq!(pkts[0].payload.len(), MAX_DATA_PAYLOAD);
        assert_eq!(pkts[1].payload.len(), MAX_DATA_PAYLOAD);
        assert_eq!(pkts[2].payload.len(), 500, "tail packet is the remainder");

        // Reassembled payloads equal the original write, in order.
        let mut reassembled = Vec::new();
        for p in &pkts {
            reassembled.extend_from_slice(&p.payload);
        }
        assert_eq!(reassembled, data, "split must be loss/duplication-free");

        // White-box: the three payloads are slices of ONE shared Arc. The
        // block's strong count reflects the in-flight retransmit copies +
        // the returned packets, all sharing the single allocation — proof
        // the split did not allocate per packet. (A `Vec`-per-chunk
        // implementation could not make these point at the same buffer.)
        let p0 = pkts[0].payload.as_slice().as_ptr();
        // The slices are contiguous within the same backing buffer.
        assert_eq!(
            pkts[1].payload.as_slice().as_ptr() as usize,
            p0 as usize + MAX_DATA_PAYLOAD,
            "packet 1 payload is contiguous with packet 0 in the same block"
        );
        assert_eq!(
            pkts[2].payload.as_slice().as_ptr() as usize,
            p0 as usize + 2 * MAX_DATA_PAYLOAD,
            "packet 2 payload is contiguous with packet 1 in the same block"
        );
    }

    /// A second, separately-buffered write keeps its own block boundary:
    /// a packet payload never straddles two distinct writes. The receiver
    /// still reassembles the full in-order byte stream regardless.
    #[test]
    fn separate_writes_do_not_merge_into_one_packet() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(850, t);
        let (mut recv, state) = Connection::new_receiver(&syn, t).unwrap();
        let _ = init.handle_incoming(&state, t);

        // Two small writes, each well under one MTU.
        init.enqueue_send(b"first-write");
        init.enqueue_send(b"second-write");
        let pkts = init.pending_send_packets(t);
        // Each write becomes its own packet (no cross-write merge), so the
        // first payload is exactly the first write.
        assert_eq!(pkts.len(), 2);
        assert_eq!(&*pkts[0].payload, b"first-write");
        assert_eq!(&*pkts[1].payload, b"second-write");

        // End-to-end the receiver still sees the concatenated stream.
        for p in &pkts {
            let _ = recv.handle_incoming(p, t);
        }
        assert_eq!(recv.take_received(usize::MAX), b"first-writesecond-write");
    }

    // ---- 16-bit seq_nr wraparound in the reorder buffer (item 1) ----

    /// Build a receiver whose delivery frontier is parked just below the
    /// 16-bit seq_nr wrap, so subsequent DATA crosses 65535→0. A SYN with
    /// `seq` as its seq_nr makes the receiver's initial
    /// `peer_seq_nr_acked == seq`, i.e. the next expected DATA is
    /// `seq + 1`.
    fn receiver_parked_at(seq: u16, t: Instant) -> Connection {
        let syn = Packet::new(PacketType::Syn, 700, seq, 0);
        let (recv, _state) = Connection::new_receiver(&syn, t).unwrap();
        recv
    }

    /// Out-of-order reorder + in-order drain must stay correct across the
    /// 65535→0 seq_nr wrap. A raw-`u16`-keyed BTreeMap would sort the
    /// post-wrap seq 0/1 *below* the buffered pre-wrap seq 65535 and
    /// scramble delivery; the absolute-logical key keeps it monotonic.
    #[test]
    fn reorder_drains_in_order_across_seq_wrap() {
        let t = now();
        // Frontier at 65534 → next expected is 65535, then 0, then 1.
        let mut recv = receiver_parked_at(65534, t);
        let recv_id = recv.recv_id;
        let mk = |seq: u16, payload: &[u8]| Packet {
            packet_type: PacketType::Data,
            connection_id: recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: seq,
            ack_nr: 0,
            extensions: Vec::new(),
            payload: payload.to_vec().into(),
        };

        // Deliver the packets that straddle the wrap fully out of order:
        // first the post-wrap seq 1, then the wrap point 0, leaving a gap
        // at the pre-wrap 65535 that blocks delivery.
        let _ = recv.handle_incoming(&mk(1, b"C"), t);
        let _ = recv.handle_incoming(&mk(0, b"B"), t);
        assert!(
            recv.take_received(64).is_empty(),
            "nothing delivers while the gap at 65535 is open, even though \
             post-wrap seq 0 and 1 arrived"
        );
        assert_eq!(recv.pending_in.len(), 2, "two packets buffered ahead");

        // Close the gap with the pre-wrap seq 65535. All three must drain
        // in seq order 65535, 0, 1 → "ABC".
        let _ = recv.handle_incoming(&mk(65535, b"A"), t);
        let got = recv.take_received(64);
        assert_eq!(got, b"ABC", "drain order must follow seq across the wrap");
        assert!(recv.pending_in.is_empty(), "buffer fully drained");
        assert_eq!(recv.peer_seq_nr_acked, 1, "frontier advanced past the wrap");

        // A later in-order packet (seq 2) delivers immediately.
        let _ = recv.handle_incoming(&mk(2, b"D"), t);
        assert_eq!(recv.take_received(64), b"D");
        assert_eq!(recv.peer_seq_nr_acked, 2);
    }

    /// A duplicate DATA whose seq_nr sits just *behind* the frontier
    /// across the wrap must be treated as already-delivered (re-ack), not
    /// buffered as a far-future packet.
    #[test]
    fn duplicate_before_frontier_across_wrap_is_reacked() {
        let t = now();
        // Frontier starts at 65535 → next expected is 0, then 1.
        let mut recv = receiver_parked_at(65535, t);
        let recv_id = recv.recv_id;
        let mk = |seq: u16, payload: &[u8]| Packet {
            packet_type: PacketType::Data,
            connection_id: recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: seq,
            ack_nr: 0,
            extensions: Vec::new(),
            payload: payload.to_vec().into(),
        };
        // Deliver seq 0 then 1 in order → frontier at 1 (post-wrap).
        let _ = recv.handle_incoming(&mk(0, b"X"), t);
        let _ = recv.handle_incoming(&mk(1, b"Y"), t);
        assert_eq!(recv.take_received(64), b"XY");
        assert_eq!(recv.peer_seq_nr_acked, 1);

        // A stale retransmit of the pre-wrap seq 65535 (now *behind* the
        // frontier) must re-ack, not get buffered as a future packet.
        let reply = recv.handle_incoming(&mk(65535, b"stale"), t);
        assert_eq!(reply.unwrap().packet_type, PacketType::State);
        assert!(recv.pending_in.is_empty(), "stale dup must not buffer");
        assert!(recv.take_received(64).is_empty(), "no spurious delivery");
    }

    // ---- randomized accept token / return-path confirm (item 2) ----

    /// The receiver's initial seq_nr is randomized (the accept token) and
    /// embedded in its STATE response; until the peer acks it the return
    /// path is unconfirmed.
    #[test]
    fn receiver_initial_seq_is_randomized_accept_token() {
        let t = now();
        let syn = Packet::new(PacketType::Syn, 800, 1, 0);
        let (recv, state) = Connection::new_receiver_with_seq(&syn, t, 0x4242).unwrap();
        // STATE carries our chosen token as its seq_nr.
        assert_eq!(state.seq_nr, 0x4242);
        assert_eq!(recv.accept_token, Some(0x4242));
        assert!(!recv.return_path_confirmed(), "unconfirmed before any ack");

        // Production path draws from the CSPRNG: over many constructions
        // the initial seq must not be a fixed constant. A statistical
        // check — if it were fixed (e.g. always 1) every draw would
        // collide; seeing >1 distinct value across a modest sample proves
        // it is randomized.
        let mut seqs = std::collections::HashSet::new();
        for _ in 0..64 {
            let (_r, s) = Connection::new_receiver(&syn, t).unwrap();
            seqs.insert(s.seq_nr);
        }
        assert!(
            seqs.len() > 1,
            "receiver initial seq_nr must be randomized, got a single value"
        );
    }

    /// A legitimate peer that received our STATE echoes the random token
    /// back as ack_nr; that confirms the return path so the driver may
    /// surface the connection to accept().
    #[test]
    fn legit_peer_ack_confirms_return_path() {
        let t = now();
        // Initiator picks recv_id 900; its SYN seq is 1.
        let (mut init, syn) = Connection::new_initiator(900, t);
        let token = 0x9001;
        let (mut recv, state) = Connection::new_receiver_with_seq(&syn, t, token).unwrap();
        assert!(!recv.return_path_confirmed(), "unconfirmed before any ack");

        // Initiator processes our STATE → records our token as the seq it
        // will ack and advances to Connected.
        let _ = init.handle_incoming(&state, t);
        assert_eq!(init.state, State::Connected);

        // Initiator now sends DATA. Having processed our STATE (seq ==
        // token) but received none of our DATA yet, its cumulative ack
        // baseline is `token - 1` — the unguessable value anchored at our
        // random token that proves it saw our STATE.
        init.enqueue_send(b"payload");
        let out = init.pending_send_packets(t);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].ack_nr,
            token.wrapping_sub(1),
            "legit peer's baseline ack is anchored at our random token"
        );

        // Receiver sees it → return path confirmed (and latches).
        let _ = recv.handle_incoming(&out[0], t);
        assert!(
            recv.return_path_confirmed(),
            "ack anchored at the token must confirm the return path"
        );
    }

    /// A blind spoofer forges SYN+DATA from a victim address but never
    /// receives our STATE, so it cannot learn the random token. Its wrong
    /// ack_nr must NOT confirm the return path — including a rear-half
    /// guess that a naive `seq_le(token, ack)` check would have accepted,
    /// and a SYN carrying even a correct-looking ack.
    #[test]
    fn blind_spoofer_wrong_ack_does_not_confirm() {
        let t = now();
        let syn = Packet::new(PacketType::Syn, 1000, 1, 0);
        let token = 0xBEEF;
        let (mut recv, _state) = Connection::new_receiver_with_seq(&syn, t, token).unwrap();
        let recv_id = recv.recv_id;

        // Forged DATA with a guessed ack_nr deliberately in the front half
        // above the token — a bare `seq_le(token, ack)` would accept it,
        // but the bounded `[token, hi]` window (hi == token here, since we
        // have sent no DATA) rejects it.
        let forged = Packet {
            packet_type: PacketType::Data,
            connection_id: recv_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: 2,
            ack_nr: token.wrapping_add(5000),
            extensions: Vec::new(),
            payload: b"spoof".to_vec().into(),
        };
        let _ = recv.handle_incoming(&forged, t);
        assert!(
            !recv.return_path_confirmed(),
            "a front-half wrong ack must never confirm"
        );

        // A forged ack *behind* the token (rear-half) must also be rejected.
        let forged2 = Packet {
            ack_nr: token.wrapping_sub(3),
            ..forged.clone()
        };
        let _ = recv.handle_incoming(&forged2, t);
        assert!(
            !recv.return_path_confirmed(),
            "rear-half ack must not confirm"
        );

        // A duplicate SYN never confirms, even with a correct-looking ack.
        let dup_syn = Packet {
            packet_type: PacketType::Syn,
            connection_id: 1000,
            ack_nr: token,
            ..forged.clone()
        };
        let _ = recv.handle_incoming(&dup_syn, t);
        assert!(
            !recv.return_path_confirmed(),
            "a SYN must never confirm the accept token"
        );

        // Finally, the genuine baseline ack (`token - 1`, what a peer that
        // saw our STATE reports before any of our DATA) DOES confirm —
        // proving the gate is closed to spoofers, open to the real peer.
        let good = Packet {
            packet_type: PacketType::State,
            ack_nr: token.wrapping_sub(1),
            ..forged
        };
        let _ = recv.handle_incoming(&good, t);
        assert!(recv.return_path_confirmed());
    }

    // ---- Receive-window enforcement (flow control / OOM defense) ----

    /// Hand-craft a DATA packet as the receiver would send it: the
    /// connection_id the initiator expects (`syn.connection_id`), an
    /// explicit seq_nr, and an exact payload. Lets tests script precise
    /// sequences instead of routing through `pending_send_packets`.
    fn raw_data(conn_id: u16, seq: u16, ack: u16, payload: &[u8]) -> Packet {
        let mut p = Packet::new(PacketType::Data, conn_id, seq, ack);
        p.payload = Payload::slice(Arc::from(payload), 0, payload.len());
        p
    }

    /// A peer that ignores our advertised window must not be able to grow
    /// our receive buffer without bound: once `in_buf` holds a full
    /// window of undelivered bytes, further in-order packets are refused
    /// (frontier does NOT advance - the ack pins the peer) until the
    /// application drains. The refused seq becomes deliverable again
    /// after the drain.
    #[test]
    fn receive_window_refuses_in_order_data_when_app_is_not_reading() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(700, t);
        let (_recv, state) = Connection::new_receiver_with_seq(&syn, t, 100).unwrap();
        let _ = init.handle_incoming(&state, t);

        let cid = syn.connection_id; // expected on incoming packets
        let pkt_len = MAX_DATA_PAYLOAD;
        let payload = vec![0x11u8; pkt_len];

        // Feed strictly in-order DATA while the app reads NOTHING, until
        // the window refuses. With the guard in place this happens within
        // ~one window of buffered bytes; without it acceptance is
        // unbounded and no refusal ever occurs.
        let mut seq = 100u16;
        let mut fed = 0usize;
        for _ in 0..((RECV_WINDOW_BYTES as usize / pkt_len) * 3) {
            let reply = init
                .handle_incoming(&raw_data(cid, seq, 0, &payload), t)
                .unwrap();
            if reply.ack_nr != seq {
                // Refused: the cumulative ack stayed pinned at seq-1.
                assert_eq!(reply.ack_nr, seq.wrapping_sub(1));
                // Overshoot is bounded by one partial-window packet
                // (check-before-append).
                assert!(
                    fed <= RECV_WINDOW_BYTES as usize + pkt_len,
                    "accepted {fed} bytes - window not enforced"
                );
                // Recovery: once the application drains, the SAME seq
                // delivers (the peer's retransmit would).
                let got = init.take_received(usize::MAX);
                assert_eq!(got.len(), fed, "drain returns everything accepted");
                let _ = init
                    .handle_incoming(&raw_data(cid, seq, 0, &payload), t)
                    .unwrap();
                let got = init.take_received(usize::MAX);
                assert_eq!(got.len(), pkt_len, "refused seq delivers after drain");
                return;
            }
            fed += pkt_len;
            seq = seq.wrapping_add(1);
        }
        panic!("window never refused - guard missing");
    }

    /// The out-of-order drain path obeys the same bound: stashed packets
    /// released behind a closing gap stop filling `in_buf` at the window
    /// and stay stashed for a later drain, instead of overflowing.
    #[test]
    fn receive_window_bounds_drain_of_stashed_packets() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(701, t);
        let (_recv, state) = Connection::new_receiver_with_seq(&syn, t, 200).unwrap();
        let _ = init.handle_incoming(&state, t);

        let cid = syn.connection_id;
        let pkt_len = MAX_DATA_PAYLOAD;
        let payload = vec![0x22u8; pkt_len];

        // Stash a run starting one past the frontier (gap at 200).
        let stash_count = RECV_WINDOW_BYTES as usize / pkt_len + 50;
        for i in 1..=stash_count {
            let seq = 200u16.wrapping_add(i as u16);
            let _ = init
                .handle_incoming(&raw_data(cid, seq, 0, &payload), t)
                .unwrap();
        }

        // Close the gap with seq 200 - triggers the drain, which must
        // stop at the window bound rather than emptying the stash.
        let reply = init
            .handle_incoming(&raw_data(cid, 200, 0, &payload), t)
            .unwrap();
        let drained = init.take_received(usize::MAX).len();
        assert!(drained > 0, "gap close must deliver");
        // Bound is window + at most one packet (the drain checks before
        // each append, so the last append may straddle the line).
        assert!(
            drained <= RECV_WINDOW_BYTES as usize + pkt_len,
            "drain overflowed the receive buffer: {drained}"
        );
        // Frontier advanced only through what was actually delivered:
        // `drained` covers the gap-closing packet AND the stashed run,
        // and the pre-handshake frontier was seq 199.
        assert_eq!(
            reply.ack_nr,
            199u16.wrapping_add((drained / pkt_len) as u16),
            "ack must reflect exactly the delivered prefix"
        );

        // Delivery resumes from the frontier once space is free again.
        let next = reply.ack_nr.wrapping_add(1);
        let r2 = init
            .handle_incoming(&raw_data(cid, next, 0, &payload), t)
            .unwrap();
        assert_eq!(r2.ack_nr, next, "delivery resumes after drain");
    }

    /// Outgoing packets advertise honest remaining space, so a conforming
    /// peer throttles BEFORE we reach the refusal path.
    #[test]
    fn advertised_wnd_size_reflects_undrained_bytes() {
        let t = now();
        let (mut init, syn) = Connection::new_initiator(702, t);
        let (_recv, state) = Connection::new_receiver_with_seq(&syn, t, 300).unwrap();
        let _ = init.handle_incoming(&state, t);

        let cid = syn.connection_id;
        let payload = vec![0x33u8; 10_000];
        let _ = init
            .handle_incoming(&raw_data(cid, 300, 0, &payload), t)
            .unwrap();

        let ack = init.build_state_ack();
        assert_eq!(
            ack.wnd_size,
            RECV_WINDOW_BYTES - 10_000,
            "wnd_size must shrink by undelivered bytes"
        );
    }
}
