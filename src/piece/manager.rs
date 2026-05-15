use bitvec::prelude::*;

use crate::error::{Error, Result};
use crate::peer::message::BLOCK_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceState {
    Missing,
    InProgress,
    Complete,
}

/// Outcome of feeding a single block into the manager. The engine uses this
/// to distinguish "credit `downloaded`" from "ignore", and to know when a
/// piece is ready for SHA-1 verification.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockOutcome {
    /// We already had this block, or the piece is already Complete.
    /// Do not credit `downloaded` for it.
    Duplicate,
    /// Block accepted; the piece still has more blocks pending.
    Stored,
    /// Block accepted and completed the piece; assembled bytes returned for verify.
    Completed(Vec<u8>),
}

/// Block-level piece state machine.
/// - Tracks which blocks of which pieces have been requested vs received.
/// - Owns the in-memory assembly buffer until a piece passes verification.
pub struct PieceManager {
    piece_length: u64,
    total_length: u64,
    num_pieces: usize,
    states: Vec<PieceState>,
    requested: Vec<BitVec<u8, Msb0>>,
    received: Vec<BitVec<u8, Msb0>>,
    buffers: Vec<Option<Vec<u8>>>,
    local: BitVec<u8, Msb0>,
}

impl PieceManager {
    pub fn new(piece_length: u64, total_length: u64, num_pieces: usize) -> Self {
        assert!(num_pieces > 0);
        let mut states = Vec::with_capacity(num_pieces);
        let mut requested = Vec::with_capacity(num_pieces);
        let mut received = Vec::with_capacity(num_pieces);
        let mut buffers = Vec::with_capacity(num_pieces);
        for i in 0..num_pieces {
            let nb = num_blocks_for_piece(i, piece_length, total_length, num_pieces);
            states.push(PieceState::Missing);
            requested.push(BitVec::repeat(false, nb));
            received.push(BitVec::repeat(false, nb));
            buffers.push(None);
        }
        let local = BitVec::repeat(false, num_pieces);
        Self {
            piece_length,
            total_length,
            num_pieces,
            states,
            requested,
            received,
            buffers,
            local,
        }
    }

    pub fn piece_length(&self) -> u64 {
        self.piece_length
    }

    pub fn total_length(&self) -> u64 {
        self.total_length
    }

    pub fn num_pieces(&self) -> usize {
        self.num_pieces
    }

    pub fn piece_size(&self, index: usize) -> u64 {
        piece_size_for(index, self.piece_length, self.total_length, self.num_pieces)
    }

    pub fn num_blocks(&self, index: usize) -> usize {
        num_blocks_for_piece(index, self.piece_length, self.total_length, self.num_pieces)
    }

    pub fn block_length(&self, index: usize, block_index: usize) -> u32 {
        let piece_size = self.piece_size(index);
        let begin = (block_index as u64) * (BLOCK_SIZE as u64);
        let remain = piece_size.saturating_sub(begin);
        remain.min(BLOCK_SIZE as u64) as u32
    }

    pub fn state(&self, index: usize) -> &PieceState {
        &self.states[index]
    }

    pub fn local_bitfield(&self) -> &BitSlice<u8, Msb0> {
        &self.local
    }

    pub fn is_complete(&self) -> bool {
        self.local.all()
    }

    pub fn complete_count(&self) -> usize {
        self.local.count_ones()
    }

    pub fn missing_count(&self) -> usize {
        self.num_pieces - self.complete_count()
    }

    /// Mark a piece as already verified — used by the resume scanner.
    pub fn mark_complete_verified(&mut self, index: usize) {
        self.states[index] = PieceState::Complete;
        self.local.set(index, true);
        self.buffers[index] = None;
    }

    /// Iterator of pieces that still need work.
    pub fn missing_pieces(&self) -> impl Iterator<Item = usize> + '_ {
        self.states
            .iter()
            .enumerate()
            .filter(|(_, s)| **s != PieceState::Complete)
            .map(|(i, _)| i)
    }

    /// Reserve the next pending block of `index` for a request.
    /// Returns `(begin, length)` if found, or `None` if all blocks of
    /// this piece are already requested or received.
    pub fn reserve_block(&mut self, index: usize) -> Option<(u32, u32)> {
        if self.states[index] == PieceState::Complete {
            return None;
        }
        if self.states[index] == PieceState::Missing {
            self.states[index] = PieceState::InProgress;
            let size = self.piece_size(index) as usize;
            self.buffers[index] = Some(vec![0u8; size]);
        }
        let nb = self.num_blocks(index);
        for b in 0..nb {
            if !self.requested[index][b] && !self.received[index][b] {
                self.requested[index].set(b, true);
                let begin = (b as u32) * BLOCK_SIZE;
                let length = self.block_length(index, b);
                return Some((begin, length));
            }
        }
        None
    }

    /// All not-yet-received blocks of a piece — for endgame requests.
    pub fn unfinished_blocks(&self, index: usize) -> Vec<(u32, u32)> {
        let nb = self.num_blocks(index);
        let mut out = Vec::new();
        for b in 0..nb {
            if !self.received[index][b] {
                let begin = (b as u32) * BLOCK_SIZE;
                let length = self.block_length(index, b);
                out.push((begin, length));
            }
        }
        out
    }

    /// Cancel the in-flight bit for a block — call when a peer disconnects
    /// or after a `Cancel` is sent in endgame. Lets another peer pick it up.
    pub fn release_block(&mut self, index: usize, begin: u32) {
        if self.states[index] == PieceState::Complete {
            return;
        }
        if begin.is_multiple_of(BLOCK_SIZE) {
            let b = (begin / BLOCK_SIZE) as usize;
            if b < self.requested[index].len() {
                self.requested[index].set(b, false);
            }
        }
    }

    /// Release every requested-but-not-received block in a piece.
    pub fn release_piece_inflight(&mut self, index: usize) {
        if self.states[index] == PieceState::Complete {
            return;
        }
        let nb = self.num_blocks(index);
        for b in 0..nb {
            if !self.received[index][b] {
                self.requested[index].set(b, false);
            }
        }
    }

    /// A block arrived. Writes into the assembly buffer.
    /// Returns `BlockOutcome::Completed(buf)` when the final block lands.
    /// Returns `Err` on protocol violations (wrong size, bad offset, out-of-range
    /// piece) — the engine should disconnect the sender.
    pub fn received_block(
        &mut self,
        index: usize,
        begin: u32,
        data: &[u8],
    ) -> Result<BlockOutcome> {
        if index >= self.num_pieces {
            return Err(Error::Network(format!("block for invalid piece {index}")));
        }
        if self.states[index] == PieceState::Complete {
            return Ok(BlockOutcome::Duplicate);
        }
        if !begin.is_multiple_of(BLOCK_SIZE) {
            return Err(Error::Network(format!(
                "block begin {} not multiple of {}",
                begin, BLOCK_SIZE
            )));
        }
        let block_index = (begin / BLOCK_SIZE) as usize;
        let nb = self.num_blocks(index);
        if block_index >= nb {
            return Err(Error::Network(format!(
                "block {block_index} out of range for piece {index}"
            )));
        }
        let expected_len = self.block_length(index, block_index) as usize;
        if data.len() != expected_len {
            return Err(Error::Network(format!(
                "block size {} != expected {}",
                data.len(),
                expected_len
            )));
        }
        if self.states[index] == PieceState::Missing {
            self.states[index] = PieceState::InProgress;
            self.buffers[index] = Some(vec![0u8; self.piece_size(index) as usize]);
        }
        if self.received[index][block_index] {
            return Ok(BlockOutcome::Duplicate);
        }
        let buf = self.buffers[index]
            .as_mut()
            .ok_or_else(|| Error::Network("buffer missing".into()))?;
        let begin_u = begin as usize;
        buf[begin_u..begin_u + expected_len].copy_from_slice(data);
        self.received[index].set(block_index, true);
        self.requested[index].set(block_index, true);
        if self.received[index].all() {
            let bytes = self.buffers[index]
                .take()
                .ok_or_else(|| Error::Network("piece buffer vanished".into()))?;
            return Ok(BlockOutcome::Completed(bytes));
        }
        Ok(BlockOutcome::Stored)
    }

    /// Reset a piece to Missing — called after a SHA1 verify failure.
    pub fn reset_piece(&mut self, index: usize) {
        self.states[index] = PieceState::Missing;
        self.buffers[index] = None;
        let nb = self.num_blocks(index);
        for b in 0..nb {
            self.requested[index].set(b, false);
            self.received[index].set(b, false);
        }
    }

    /// Mark a piece complete after successful verification.
    pub fn mark_complete(&mut self, index: usize) {
        self.states[index] = PieceState::Complete;
        self.local.set(index, true);
        self.buffers[index] = None;
    }
}

fn piece_size_for(index: usize, piece_length: u64, total_length: u64, num_pieces: usize) -> u64 {
    if index + 1 == num_pieces {
        let r = total_length % piece_length;
        if r == 0 {
            piece_length
        } else {
            r
        }
    } else {
        piece_length
    }
}

fn num_blocks_for_piece(
    index: usize,
    piece_length: u64,
    total_length: u64,
    num_pieces: usize,
) -> usize {
    let ps = piece_size_for(index, piece_length, total_length, num_pieces);
    ps.div_ceil(BLOCK_SIZE as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_layout_full_pieces() {
        // 2 pieces of 32 KiB → 2 blocks of 16 KiB each.
        let pm = PieceManager::new(32768, 65536, 2);
        assert_eq!(pm.piece_size(0), 32768);
        assert_eq!(pm.piece_size(1), 32768);
        assert_eq!(pm.num_blocks(0), 2);
        assert_eq!(pm.block_length(0, 0), 16384);
        assert_eq!(pm.block_length(0, 1), 16384);
    }

    #[test]
    fn block_layout_last_short_piece() {
        // Total 40 KiB, piece length 32 KiB → last piece is 8 KiB → 1 block of 8 KiB.
        let pm = PieceManager::new(32768, 40960, 2);
        assert_eq!(pm.piece_size(1), 8192);
        assert_eq!(pm.num_blocks(1), 1);
        assert_eq!(pm.block_length(1, 0), 8192);
    }

    #[test]
    fn block_layout_last_partial_block() {
        // 20000-byte single piece → 2 blocks: 16384 + 3616.
        let pm = PieceManager::new(20000, 20000, 1);
        assert_eq!(pm.num_blocks(0), 2);
        assert_eq!(pm.block_length(0, 0), 16384);
        assert_eq!(pm.block_length(0, 1), 3616);
    }

    #[test]
    fn reserve_and_receive_completes_piece() {
        // Single piece 24 KiB → 2 blocks (16 KiB, 8 KiB).
        let mut pm = PieceManager::new(24576, 24576, 1);
        let (b0, l0) = pm.reserve_block(0).unwrap();
        assert_eq!((b0, l0), (0, 16384));
        let (b1, l1) = pm.reserve_block(0).unwrap();
        assert_eq!((b1, l1), (16384, 8192));
        assert!(pm.reserve_block(0).is_none());

        // Receive first block — stored, piece not yet complete.
        assert_eq!(
            pm.received_block(0, 0, &vec![1u8; 16384]).unwrap(),
            BlockOutcome::Stored
        );
        // Receive second block — completes the piece.
        let bytes = match pm.received_block(0, 16384, &vec![2u8; 8192]).unwrap() {
            BlockOutcome::Completed(b) => b,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(bytes.len(), 24576);
        assert_eq!(&bytes[..16384], &[1u8; 16384][..]);
        assert_eq!(&bytes[16384..], &[2u8; 8192][..]);
    }

    #[test]
    fn duplicate_block_ignored() {
        let mut pm = PieceManager::new(16384, 16384, 1);
        let _ = pm.reserve_block(0);
        // First receive completes the piece (single block).
        assert!(matches!(
            pm.received_block(0, 0, &vec![1u8; 16384]).unwrap(),
            BlockOutcome::Completed(_)
        ));
        pm.mark_complete(0);
        // Second receive for the same block now hits the Complete short-circuit.
        assert_eq!(
            pm.received_block(0, 0, &vec![1u8; 16384]).unwrap(),
            BlockOutcome::Duplicate
        );
    }

    #[test]
    fn duplicate_in_progress_block_returns_duplicate() {
        // Two blocks: receive the first twice; second receive is Duplicate.
        let mut pm = PieceManager::new(32768, 32768, 1);
        let _ = pm.reserve_block(0);
        assert_eq!(
            pm.received_block(0, 0, &vec![1u8; 16384]).unwrap(),
            BlockOutcome::Stored
        );
        assert_eq!(
            pm.received_block(0, 0, &vec![1u8; 16384]).unwrap(),
            BlockOutcome::Duplicate
        );
    }

    #[test]
    fn rejects_misaligned_block() {
        let mut pm = PieceManager::new(32768, 32768, 1);
        assert!(pm.received_block(0, 100, &vec![0; 16384]).is_err());
    }

    #[test]
    fn rejects_wrong_size_block() {
        let mut pm = PieceManager::new(32768, 32768, 1);
        assert!(pm.received_block(0, 0, &vec![0; 1000]).is_err());
    }

    #[test]
    fn reset_piece_clears_state() {
        let mut pm = PieceManager::new(16384, 16384, 1);
        let _ = pm.reserve_block(0);
        pm.received_block(0, 0, &vec![9u8; 16384]).unwrap();
        pm.reset_piece(0);
        assert_eq!(pm.state(0), &PieceState::Missing);
        let r = pm.reserve_block(0);
        assert!(r.is_some());
    }

    #[test]
    fn release_block_allows_re_reserve() {
        let mut pm = PieceManager::new(32768, 32768, 1);
        pm.reserve_block(0).unwrap();
        pm.reserve_block(0).unwrap();
        assert!(pm.reserve_block(0).is_none());
        pm.release_block(0, 0);
        assert_eq!(pm.reserve_block(0), Some((0, 16384)));
    }

    #[test]
    fn mark_complete_updates_bitfield() {
        let mut pm = PieceManager::new(16384, 32768, 2);
        assert!(!pm.is_complete());
        pm.mark_complete(0);
        assert!(!pm.is_complete());
        pm.mark_complete(1);
        assert!(pm.is_complete());
    }
}
