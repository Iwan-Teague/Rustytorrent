use std::collections::HashMap;
use std::net::SocketAddr;

use bitvec::prelude::*;
use rand::seq::SliceRandom;

use crate::piece::manager::{PieceManager, PieceState};

/// Tracks which pieces each peer has and picks the next piece for a peer
/// using either sequential (Phase 4) or rarest-first (Phase 5) strategy.
pub struct Picker {
    num_pieces: usize,
    /// Per-peer bitfield (Msb0): which pieces they advertise.
    peer_bitfields: HashMap<SocketAddr, BitVec<u8, Msb0>>,
    /// Availability count per piece — how many peers have it.
    availability: Vec<u32>,
    /// Pieces a peer is currently assigned to fetch (sticky).
    assigned: HashMap<SocketAddr, usize>,
    /// Sequential mode: pick the lowest-index needed piece instead of
    /// the rarest. Trades swarm-health (rarest-first) for in-order
    /// delivery — useful for streaming a media file while it downloads.
    sequential: bool,
}

impl Picker {
    pub fn new(num_pieces: usize) -> Self {
        Self {
            num_pieces,
            peer_bitfields: HashMap::new(),
            availability: vec![0u32; num_pieces],
            assigned: HashMap::new(),
            sequential: false,
        }
    }

    /// Enable in-order piece selection (for streaming). Off by default
    /// (rarest-first), which is healthier for the swarm.
    pub fn set_sequential(&mut self, on: bool) {
        self.sequential = on;
    }

    pub fn set_peer_bitfield(&mut self, addr: SocketAddr, bf: BitVec<u8, Msb0>) {
        // Remove old contributions if any.
        if let Some(old) = self.peer_bitfields.remove(&addr) {
            for i in 0..self.num_pieces.min(old.len()) {
                if old[i] {
                    self.availability[i] = self.availability[i].saturating_sub(1);
                }
            }
        }
        // Add new contributions.
        for i in 0..self.num_pieces.min(bf.len()) {
            if bf[i] {
                self.availability[i] = self.availability[i].saturating_add(1);
            }
        }
        self.peer_bitfields.insert(addr, bf);
    }

    pub fn peer_has(&self, addr: &SocketAddr, index: usize) -> bool {
        match self.peer_bitfields.get(addr) {
            Some(bf) if index < bf.len() => bf[index],
            _ => false,
        }
    }

    pub fn add_have(&mut self, addr: SocketAddr, index: usize) {
        if index >= self.num_pieces {
            return;
        }
        let bf = self
            .peer_bitfields
            .entry(addr)
            .or_insert_with(|| BitVec::repeat(false, self.num_pieces));
        if bf.len() < self.num_pieces {
            bf.resize(self.num_pieces, false);
        }
        if !bf[index] {
            bf.set(index, true);
            self.availability[index] = self.availability[index].saturating_add(1);
        }
    }

    pub fn forget_peer(&mut self, addr: &SocketAddr) {
        if let Some(bf) = self.peer_bitfields.remove(addr) {
            for i in 0..self.num_pieces.min(bf.len()) {
                if bf[i] {
                    self.availability[i] = self.availability[i].saturating_sub(1);
                }
            }
        }
        self.assigned.remove(addr);
    }

    pub fn assignment(&self, addr: &SocketAddr) -> Option<usize> {
        self.assigned.get(addr).copied()
    }

    pub fn release_assignment(&mut self, addr: &SocketAddr) {
        self.assigned.remove(addr);
    }

    pub fn clear_assignment_if(&mut self, addr: &SocketAddr, index: usize) {
        if let Some(&cur) = self.assigned.get(addr) {
            if cur == index {
                self.assigned.remove(addr);
            }
        }
    }

    pub fn availability(&self) -> &[u32] {
        &self.availability
    }

    /// Pick a new piece for `addr` that:
    /// - peer has it
    /// - is not Complete
    /// - is not currently assigned to another peer (unless in endgame)
    ///
    /// Sort by `availability` ascending; shuffle ties.
    pub fn pick_for(
        &mut self,
        addr: &SocketAddr,
        pm: &PieceManager,
        endgame: bool,
    ) -> Option<usize> {
        if let Some(i) = self.assigned.get(addr) {
            if pm.state(*i) != &PieceState::Complete && pm.is_wanted(*i) {
                return Some(*i);
            }
        }
        let bf = self.peer_bitfields.get(addr)?;
        let in_use: std::collections::HashSet<usize> = self.assigned.values().copied().collect();
        let usable = |i: usize| -> bool {
            i < bf.len()
                && bf[i]
                && pm.state(i) != &PieceState::Complete
                && pm.is_wanted(i)
                && (endgame || !in_use.contains(&i))
        };

        let chosen = if self.sequential {
            // Lowest-index needed piece → in-order delivery for streaming.
            // The first match in ascending order IS the lowest index, so
            // break immediately rather than scanning + min-ing the rest.
            (0..self.num_pieces).find(|&i| usable(i))?
        } else {
            // Rarest-first in a single O(n) pass: track the minimum
            // availability seen and the set of pieces tied at it, instead
            // of building + sorting a full candidate Vec (was O(n log n)).
            // `ties` only ever holds the current-best group.
            let mut min_av = u32::MAX;
            let mut ties: Vec<usize> = Vec::new();
            for i in 0..self.num_pieces {
                if !usable(i) {
                    continue;
                }
                let av = self.availability[i];
                if av < min_av {
                    min_av = av;
                    ties.clear();
                    ties.push(i);
                } else if av == min_av {
                    ties.push(i);
                }
            }
            // Shuffle within the lowest-availability group for fairness,
            // then take one. Empty ⇒ no usable piece for this peer.
            ties.shuffle(&mut rand::thread_rng());
            *ties.first()?
        };
        self.assigned.insert(*addr, chosen);
        Some(chosen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkbf(bits: &[bool]) -> BitVec<u8, Msb0> {
        let mut bv: BitVec<u8, Msb0> = BitVec::repeat(false, bits.len());
        for (i, b) in bits.iter().enumerate() {
            bv.set(i, *b);
        }
        bv
    }

    #[test]
    fn availability_tracks_peers() {
        let mut p = Picker::new(4);
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2".parse().unwrap();
        p.set_peer_bitfield(a, mkbf(&[true, false, true, false]));
        p.set_peer_bitfield(b, mkbf(&[true, true, false, false]));
        assert_eq!(p.availability(), &[2, 1, 1, 0]);
    }

    #[test]
    fn add_have_updates_availability() {
        let mut p = Picker::new(3);
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        p.set_peer_bitfield(a, mkbf(&[false, false, false]));
        p.add_have(a, 1);
        assert_eq!(p.availability(), &[0, 1, 0]);
        // Re-adding same Have is idempotent.
        p.add_have(a, 1);
        assert_eq!(p.availability(), &[0, 1, 0]);
    }

    #[test]
    fn forget_peer_drops_availability() {
        let mut p = Picker::new(2);
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        p.set_peer_bitfield(a, mkbf(&[true, true]));
        assert_eq!(p.availability(), &[1, 1]);
        p.forget_peer(&a);
        assert_eq!(p.availability(), &[0, 0]);
    }

    #[test]
    fn pick_avoids_complete_pieces() {
        let mut pm = PieceManager::new(16384, 32768, 2);
        pm.mark_complete(0);
        let mut p = Picker::new(2);
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        p.set_peer_bitfield(a, mkbf(&[true, true]));
        assert_eq!(p.pick_for(&a, &pm, false), Some(1));
    }

    #[test]
    fn pick_prefers_rarer_piece() {
        let pm = PieceManager::new(16384, 49152, 3);
        let mut p = Picker::new(3);
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2".parse().unwrap();
        let c: SocketAddr = "3.3.3.3:3".parse().unwrap();
        // Piece 0: all three have. Piece 1: only b. Piece 2: a + b.
        p.set_peer_bitfield(a, mkbf(&[true, false, true]));
        p.set_peer_bitfield(b, mkbf(&[true, true, true]));
        p.set_peer_bitfield(c, mkbf(&[true, false, false]));
        // Picking for b → rarest piece b has is piece 1 (availability=1).
        assert_eq!(p.pick_for(&b, &pm, false), Some(1));
    }

    #[test]
    fn sequential_picks_lowest_index_not_rarest() {
        let pm = PieceManager::new(16384, 49152, 3);
        let mut p = Picker::new(3);
        p.set_sequential(true);
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2".parse().unwrap();
        let c: SocketAddr = "3.3.3.3:3".parse().unwrap();
        // Make piece 2 the rarest (only b has it), piece 0 the commonest.
        p.set_peer_bitfield(a, mkbf(&[true, false, true]));
        p.set_peer_bitfield(b, mkbf(&[true, true, true]));
        p.set_peer_bitfield(c, mkbf(&[true, false, false]));
        // Rarest-first would pick 1 or 2 for b; sequential must pick 0
        // (lowest index b has and we need), for in-order delivery.
        assert_eq!(p.pick_for(&b, &pm, false), Some(0));
    }
}
