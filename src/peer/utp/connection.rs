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
//!   on RTO (with exponential backoff), receive-side reordering,
//!   clean FIN-driven close.
//! - **Selective ack (BEP 29)**: a receiver holding out-of-order
//!   packets attaches a SACK bitmask to its acks (`build_sack`); a
//!   sender prunes selectively-acked packets from its retransmit queue
//!   (`process_sack`). When a SACK reports >= 3 packets past the gap
//!   (TCP-style duplicate-ack loss signal) the sender fast-retransmits
//!   the gap immediately instead of waiting out its RTO.
//! - **Not implemented**: LEDBAT congestion control (we use a fixed
//!   send window of `INITIAL_WINDOW_PACKETS`); sequence-number
//!   wraparound (16-bit seq_nr wraps after 65 536 packets — a real
//!   long-lived connection would need to handle it, the typical
//!   BitTorrent block-exchange session won't).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use super::packet::{Extension, Packet, PacketType, EXT_SELECTIVE_ACK};

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
/// Maximum number of unacked DATA packets we'll have outstanding
/// before pausing the application's send. A real implementation
/// would dynamically size this from LEDBAT's delay estimate; we
/// hold a fixed window.
pub const INITIAL_WINDOW_PACKETS: usize = 8;
/// Maximum payload bytes per DATA packet. Sized to fit comfortably
/// under the typical ~1400-byte Ethernet MTU minus IP/UDP/µTP
/// headers (~48 bytes of stack overhead).
pub const MAX_DATA_PAYLOAD: usize = 1200;
/// Receive window we advertise to the peer (bytes). Plenty for any
/// real BitTorrent block-exchange flow; sized to make wnd_size
/// effectively non-throttling.
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
    /// Outgoing application bytes the caller has handed us, waiting
    /// to be packetized.
    out_buf: VecDeque<u8>,
    /// Application bytes the peer sent that we've delivered into the
    /// in-order stream. Pulled by `take_received`.
    in_buf: VecDeque<u8>,
    /// Out-of-order DATA packets we've received, keyed by seq_nr.
    /// Delivered to `in_buf` as the gap closes.
    pending_in: BTreeMap<u16, Vec<u8>>,
    /// Outgoing packets we've sent but the peer hasn't acked.
    /// Sorted by seq_nr ascending (we push to the back as we send).
    in_flight: VecDeque<InFlight>,
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
            out_buf: VecDeque::new(),
            in_buf: VecDeque::new(),
            pending_in: BTreeMap::new(),
            in_flight: VecDeque::new(),
            deadline: now + HARD_TIMEOUT,
            fast_rtx_seq: None,
            last_fast_rtx_seq: None,
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
    pub fn new_receiver(syn: &Packet, now: Instant) -> Option<(Self, Packet)> {
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
            // Pick our own initial seq_nr. BEP 29 leaves this to the
            // implementation — 1 is safe and matches what most
            // clients do.
            next_seq_nr: 1,
            peer_seq_nr_acked: syn.seq_nr,
            out_buf: VecDeque::new(),
            in_buf: VecDeque::new(),
            pending_in: BTreeMap::new(),
            in_flight: VecDeque::new(),
            deadline: now + HARD_TIMEOUT,
            fast_rtx_seq: None,
            last_fast_rtx_seq: None,
        };
        // STATE acks the SYN. seq_nr is our chosen initial; ack_nr
        // is the SYN's seq_nr.
        let state = Packet {
            packet_type: PacketType::State,
            connection_id: conn.send_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: RECV_WINDOW_BYTES,
            seq_nr: conn.next_seq_nr,
            ack_nr: syn.seq_nr,
            extensions: Vec::new(),
            payload: Vec::new(),
        };
        // STATE doesn't increment our seq_nr (per spec), so
        // `next_seq_nr` stays at 1 for the first DATA.
        conn.state = State::Connected;
        Some((conn, state))
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

    /// Application has bytes to send. Buffer them; `pending_send_packets`
    /// will packetize as window allows.
    pub fn enqueue_send(&mut self, bytes: &[u8]) {
        if matches!(self.state, State::FinSent | State::Closed | State::Reset) {
            return;
        }
        self.out_buf.extend(bytes.iter().copied());
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
    pub fn handle_incoming(&mut self, packet: &Packet, _now: Instant) -> Option<Packet> {
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
        while let Some(front) = self.in_flight.front() {
            if seq_le(front.seq_nr, acked_through) {
                self.in_flight.pop_front();
            } else {
                break;
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
            self.process_sack(acked_through, &sack.data);
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
                    // Duplicate — already delivered. Re-ack.
                    return Some(self.build_state_ack());
                }
                let next_expected = self.peer_seq_nr_acked.wrapping_add(1);
                if payload_seq == next_expected {
                    // In-order delivery. Push to in_buf, then drain
                    // any pending_in that closes the gap.
                    self.in_buf.extend(packet.payload.iter().copied());
                    self.peer_seq_nr_acked = payload_seq;
                    while let Some(buf) = self
                        .pending_in
                        .remove(&self.peer_seq_nr_acked.wrapping_add(1))
                    {
                        self.in_buf.extend(buf.iter().copied());
                        self.peer_seq_nr_acked = self.peer_seq_nr_acked.wrapping_add(1);
                    }
                } else if self.pending_in.contains_key(&payload_seq)
                    || self.pending_in.len() < MAX_PENDING_IN
                {
                    // Out-of-order; stash for later. Re-stashing a seq we
                    // already hold is free (overwrite). Only grow the
                    // buffer up to MAX_PENDING_IN — beyond that we drop
                    // the excess (see the const's rationale): the peer
                    // will retransmit once our cumulative ack_nr advances.
                    self.pending_in.insert(payload_seq, packet.payload.clone());
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
                if self.out_buf.is_empty() && self.in_flight.is_empty() {
                    self.state = State::Closed;
                }
                Some(ack)
            }
            PacketType::Reset => unreachable!("handled at top of fn"),
        }
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
        while !self.out_buf.is_empty() && self.in_flight.len() < INITIAL_WINDOW_PACKETS {
            let chunk_len = self.out_buf.len().min(MAX_DATA_PAYLOAD);
            let payload: Vec<u8> = self.out_buf.drain(..chunk_len).collect();
            let pkt = Packet {
                packet_type: PacketType::Data,
                connection_id: self.send_id,
                timestamp_micros: 0,
                timestamp_diff_micros: 0,
                wnd_size: RECV_WINDOW_BYTES,
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
            && self.out_buf.is_empty()
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
                wnd_size: RECV_WINDOW_BYTES,
                seq_nr: self.next_seq_nr,
                ack_nr: self.peer_seq_nr_acked,
                extensions: Vec::new(),
                payload: Vec::new(),
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
            wnd_size: RECV_WINDOW_BYTES,
            // STATE packets reuse the current seq_nr — they don't
            // advance it.
            seq_nr: self.next_seq_nr,
            ack_nr: self.peer_seq_nr_acked,
            // Attach a selective-ack bitmask when we're holding
            // out-of-order packets, so the sender can fast-recover the
            // single missing packet rather than the whole window.
            extensions: self.build_sack().into_iter().collect(),
            payload: Vec::new(),
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
        let base = self.peer_seq_nr_acked.wrapping_add(2);
        let mut mask: Vec<u8> = vec![0u8; 4];
        for &seq in self.pending_in.keys() {
            let offset = seq.wrapping_sub(base) as usize;
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
    fn process_sack(&mut self, ack_nr: u16, mask: &[u8]) {
        let base = ack_nr.wrapping_add(2);
        self.in_flight.retain(|entry| {
            let offset = entry.seq_nr.wrapping_sub(base) as usize;
            let byte = offset / 8;
            let sacked = byte < mask.len() && (mask[byte] >> (offset % 8)) & 1 == 1;
            !sacked
        });
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
            payload: payload.to_vec(),
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
            payload: vec![0u8; MAX_DATA_PAYLOAD],
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
            payload: b"x".to_vec(),
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
            payload: Vec::new(),
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
            payload: Vec::new(),
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
}
