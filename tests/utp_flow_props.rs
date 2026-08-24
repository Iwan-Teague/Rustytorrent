//! Property tests for the µTP flow-control core (receive-window
//! enforcement + reorder buffer).
//!
//! Invariants hammered here beyond what the targeted unit tests sample:
//!
//! 1. **Stream integrity under arbitrary arrival patterns** — any mix of
//!    in-order, duplicate, and gap-opening DATA delivers the sender's
//!    byte stream exactly: an in-order, duplicate-free prefix.
//!
//! 2. **Undelivered-byte bound without an application drain** — feeding
//!    strictly in-order data while nobody reads must stop accepting at
//!    the window (frontier pinned, acks stable) and never exceed
//!    `RECV_WINDOW_BYTES` + one packet, for ANY packet size split.

use std::sync::Arc;
use std::time::Instant;

use proptest::prelude::*;

use rustytorrent::peer::utp::connection::{Connection, MAX_PENDING_IN, RECV_WINDOW_BYTES};
use rustytorrent::peer::utp::packet::{Packet, PacketType, Payload};

const MAX_DATA_PAYLOAD: usize = 1200;

/// xorshift64* — deterministic chaos derived from the proptest seed so
/// shrinking replays faithfully.
struct Xs(u64);

impl Xs {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, end: u64) -> u64 {
        self.next_u64() % end
    }
}

/// Receiver side with fixed ids: SYN claims connection_id 7 with seq 1,
/// so the first expected DATA seq is 2. Returns `(conn, inbound_cid)`.
fn receiver_under_test(t: Instant) -> (Connection, u16) {
    let syn = Packet::new(PacketType::Syn, 7, 1, 0);
    let (recv, _state) = Connection::new_receiver(&syn, t).unwrap();
    // Packets FROM the peer carry OUR recv_id == syn.connection_id + 1.
    (recv, 7u16.wrapping_add(1))
}

fn data_pkt(cid: u16, seq: u16, payload: &[u8]) -> Packet {
    let mut pkt = Packet::new(PacketType::Data, cid, seq, 0);
    pkt.payload = Payload::slice(Arc::from(payload.to_vec()), 0, payload.len());
    pkt
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// Any interleaving of in-order / duplicate / gap-opening DATA must
    /// deliver an exact prefix of the sender's byte stream.
    #[test]
    fn receive_stream_is_exact_prefix_under_chaos(
        seed in any::<u64>(),
        steps in 8usize..250,
        pkt_len in 1usize..=MAX_DATA_PAYLOAD,
    ) {
        let mut xs = Xs::new(seed);
        let t = Instant::now();
        let (mut recv, cid) = receiver_under_test(t);

        // Sender model: the byte stream it wants to deliver, cut into
        // pkt_len chunks numbered from seq 2.
        let total_bytes = steps.saturating_mul(pkt_len);
        let sent: Vec<u8> = (0..total_bytes).map(|i| (i % 253 + 1) as u8).collect();
        let mut next_seq: u16 = 2;
        let mut delivered: Vec<u8> = Vec::new();

        for _ in 0..steps {
            if (next_seq as usize - 2).saturating_mul(pkt_len) >= total_bytes {
                break; // modeled stream exhausted
            }
            let roll = xs.below(100);
            let seq: u16 = if roll < 60 {
                let s = next_seq; // next in order
                next_seq = next_seq.wrapping_add(1);
                s
            } else if roll < 80 && next_seq > 2 {
                // retransmit something already seen (accepted or refused)
                (2 + xs.below(next_seq as u64 - 1)) as u16
            } else {
                // open a gap: jump ahead by 1..3
                let s = next_seq;
                next_seq = next_seq.wrapping_add(1 + xs.below(3) as u16);
                s
            };

            let idx = (seq as usize).saturating_sub(2).saturating_mul(pkt_len);
            if idx >= sent.len() {
                continue; // jumped past the modeled stream entirely
            }
            let end = (idx + pkt_len).min(sent.len());
            let pkt = data_pkt(cid, seq, &sent[idx..end]);

            let reply = recv
                .handle_incoming(&pkt, t)
                .expect("DATA on a matched connection is always acked");
            prop_assert!(reply.packet_type == PacketType::State);

            delivered.extend_from_slice(&recv.take_received(usize::MAX));
        }

        prop_assert!(
            delivered.len() <= sent.len(),
            "delivered {} bytes > sent {}",
            delivered.len(),
            sent.len()
        );
        prop_assert_eq!(
            &delivered[..],
            &sent[..delivered.len()],
            "delivered stream diverged from sender's stream"
        );
    }
}

// Heavier per-case work (tens of thousands of packets); fewer cases keep
// the suite fast while still covering every packet-size regime.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]


    /// No-drain stress: strictly in-order arrival with NO application
    /// reads. Model-correct expectations: the frontier advances by exactly
    /// one per in-order accept until the window fills; afterwards the
    /// frontier HOLDS (in-order packets are refused, later seqs are
    /// stashed up to MAX_PENDING_IN) and undelivered bytes stay within
    /// window + stash bounds. A retransmit of frontier+1 after a drain
    /// must resume delivery intact.
    #[test]
    fn no_drain_flood_is_bounded_and_recovers_exactly(
        // Small floors keep the run inside one 16-bit seq cycle: filling
        // two windows must not wrap past delivered sequences (which would
        // be genuine duplicates rather than flow-control outcomes).
        pkt_len in 64usize..=MAX_DATA_PAYLOAD,
    ) {
        let t = Instant::now();
        let (mut recv, cid) = receiver_under_test(t);

        // Enough packets to overfill the window twice plus slack, capped
        // to stay inside one seq cycle.
        let pkts = (RECV_WINDOW_BYTES as usize / pkt_len * 2 + 50).min(60_000);
        let stream: Vec<u8> = (0..pkts * pkt_len).map(|i| (i % 249 + 1) as u8).collect();

        // NOTE: no draining inside this loop — the application is
        // "not reading"; sampling only.
        let mut delivered: Vec<u8> = Vec::new();
        let mut seq = 2u16;
        let mut pinned_at: Option<u16> = None;

        for i in 0..pkts {
            let chunk = &stream[i * pkt_len..(i + 1) * pkt_len];
            let reply = recv.handle_incoming(&data_pkt(cid, seq, chunk), t).unwrap();

            match pinned_at {
                None => {
                    if reply.ack_nr != seq {
                        // First non-advance pins the frontier. It may sit
                        // more than one behind a just-refused seq once
                        // future seqs start being stashed; the invariant
                        // is that it freezes HERE and never regresses or
                        // skips without an accept.
                        pinned_at = Some(reply.ack_nr);
                    }
                }
                Some(p) => prop_assert_eq!(reply.ack_nr, p, "frontier moved while pinned"),
            }

            // Undelivered = in_buf (< window, +<=1 overshoot packet) plus
            // the count-bounded out-of-order stash.
            prop_assert!(
                recv.undelivered_receive_bytes()
                    <= RECV_WINDOW_BYTES as usize
                        + MAX_DATA_PAYLOAD
                        + MAX_PENDING_IN * MAX_DATA_PAYLOAD,
                "undelivered {} exceeds window+stash bound",
                recv.undelivered_receive_bytes()
            );
            seq = seq.wrapping_add(1);
        }

        let f = pinned_at.expect("window never filled");

        // The app finally reads: everything accepted so far comes out as
        // an exact prefix covering seqs 2..=f, i.e. (f - 1) full packets.
        delivered.extend_from_slice(&recv.take_received(usize::MAX));
        prop_assert_eq!(delivered.len(), (f as usize - 1) * pkt_len, "prefix length");

        // Recovery: the peer retransmits frontier+1 (its RTO would); the
        // gap closes and the stash cascades into the drained buffer.
        let off = (f + 1 - 2) as usize * pkt_len;
        let _ = recv.handle_incoming(
            &data_pkt(cid, f.wrapping_add(1), &stream[off..off + pkt_len]),
            t,
        );
        delivered.extend_from_slice(&recv.take_received(usize::MAX));
        prop_assert!(
            delivered.len() > (f as usize - 1) * pkt_len,
            "retransmit must unlock delivery past the old frontier"
        );
        prop_assert_eq!(
            &delivered[..],
            &stream[..delivered.len()],
            "delivered stream diverged from sender's stream"
        );
    }
}
