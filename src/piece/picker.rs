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
}

impl Picker {
    pub fn new(num_pieces: usize) -> Self {
        Self {
            num_pieces,
            peer_bitfields: HashMap::new(),
            availability: vec![0u32; num_pieces],
            assigned: HashMap::new(),
        }
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
        let mut candidates: Vec<usize> = (0..self.num_pieces)
            .filter(|i| {
                i < &bf.len()
                    && bf[*i]
                    && pm.state(*i) != &PieceState::Complete
                    && pm.is_wanted(*i)
                    && (endgame || !in_use.contains(i))
            })
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by_key(|i| self.availability[*i]);
        // Shuffle within the lowest-availability group for fairness.
        let min_av = self.availability[candidates[0]];
        let tie_end = candidates
            .iter()
            .position(|i| self.availability[*i] != min_av)
            .unwrap_or(candidates.len());
        candidates[..tie_end].shuffle(&mut rand::thread_rng());
        let chosen = candidates[0];
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
}
