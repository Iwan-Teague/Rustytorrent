use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;

pub const CHOKE_INTERVAL: Duration = Duration::from_secs(10);
pub const OPTIMISTIC_INTERVAL: Duration = Duration::from_secs(30);
pub const RATE_WINDOW: Duration = Duration::from_secs(20);
pub const SNUB_THRESHOLD: Duration = Duration::from_secs(60);
pub const REGULAR_UNCHOKE_SLOTS: usize = 3;

/// Standard BitTorrent choke algorithm: 3 regular unchoke slots + 1 optimistic.
///
/// Reference: BEP 3 §"Choking and Optimistic Unchoking" — 3 regular + 1 optimistic
/// is the universal default across major clients (libtorrent, Transmission, qBittorrent).
pub struct ChokeScheduler {
    /// Per-peer rolling window of `(timestamp, bytes_received)` samples.
    samples: HashMap<SocketAddr, VecDeque<(Instant, u64)>>,
    /// Per-peer timestamp of the last block received (for snub detection).
    last_block: HashMap<SocketAddr, Instant>,
    /// Whether the local end has unchoked the peer.
    unchoked: HashMap<SocketAddr, bool>,
    optimistic: Option<SocketAddr>,
    last_optimistic_tick: Instant,
    seeding: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChokeDecision {
    pub to_unchoke: Vec<SocketAddr>,
    pub to_choke: Vec<SocketAddr>,
    pub optimistic: Option<SocketAddr>,
}

impl ChokeScheduler {
    pub fn new() -> Self {
        Self {
            samples: HashMap::new(),
            last_block: HashMap::new(),
            unchoked: HashMap::new(),
            optimistic: None,
            last_optimistic_tick: Instant::now(),
            seeding: false,
        }
    }

    pub fn set_seeding(&mut self, seeding: bool) {
        self.seeding = seeding;
    }

    pub fn record_download(&mut self, addr: SocketAddr, bytes: u64) {
        let now = Instant::now();
        let q = self.samples.entry(addr).or_default();
        q.push_back((now, bytes));
        let cutoff = now - RATE_WINDOW;
        while let Some(&(t, _)) = q.front() {
            if t < cutoff {
                q.pop_front();
            } else {
                break;
            }
        }
        self.last_block.insert(addr, now);
    }

    pub fn record_upload(&mut self, addr: SocketAddr, bytes: u64) {
        let now = Instant::now();
        let q = self.samples.entry(addr).or_default();
        q.push_back((now, bytes));
        let cutoff = now - RATE_WINDOW;
        while let Some(&(t, _)) = q.front() {
            if t < cutoff {
                q.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn forget(&mut self, addr: &SocketAddr) {
        self.samples.remove(addr);
        self.last_block.remove(addr);
        self.unchoked.remove(addr);
        if self.optimistic == Some(*addr) {
            self.optimistic = None;
        }
    }

    fn rate_for(&self, addr: &SocketAddr) -> u64 {
        match self.samples.get(addr) {
            Some(q) => q.iter().map(|(_, b)| *b).sum(),
            None => 0,
        }
    }

    pub fn is_snubbed(&self, addr: &SocketAddr) -> bool {
        match self.last_block.get(addr) {
            Some(t) => t.elapsed() > SNUB_THRESHOLD,
            None => true, // no blocks ever received
        }
    }

    /// Compute the unchoke decision. `candidates` is every connected peer.
    /// Should be called every `CHOKE_INTERVAL`.
    pub fn tick(&mut self, candidates: &[SocketAddr]) -> ChokeDecision {
        let now = Instant::now();

        // Rotate optimistic slot every 30s.
        if now.duration_since(self.last_optimistic_tick) >= OPTIMISTIC_INTERVAL
            || self.optimistic.is_none()
        {
            self.last_optimistic_tick = now;
            let pool: Vec<SocketAddr> = candidates.to_vec();
            if let Some(pick) = pool.choose(&mut rand::thread_rng()) {
                self.optimistic = Some(*pick);
            }
        }

        // Rank candidates by relevant rate.
        let mut ranked: Vec<(SocketAddr, u64)> = candidates
            .iter()
            .filter(|a| !self.is_snubbed(a) || self.seeding) // snubbed peers de-prioritized in leech mode
            .map(|a| (*a, self.rate_for(a)))
            .collect();
        ranked.sort_by_key(|entry| std::cmp::Reverse(entry.1));

        let mut chosen: Vec<SocketAddr> = ranked
            .into_iter()
            .take(REGULAR_UNCHOKE_SLOTS)
            .map(|(a, _)| a)
            .collect();
        if let Some(opt) = self.optimistic {
            if !chosen.contains(&opt) {
                chosen.push(opt);
            }
        }

        let mut to_unchoke = Vec::new();
        let mut to_choke = Vec::new();
        for addr in candidates {
            let want = chosen.contains(addr);
            let have = *self.unchoked.get(addr).unwrap_or(&false);
            if want && !have {
                to_unchoke.push(*addr);
                self.unchoked.insert(*addr, true);
            } else if !want && have {
                to_choke.push(*addr);
                self.unchoked.insert(*addr, false);
            }
        }
        ChokeDecision {
            to_unchoke,
            to_choke,
            optimistic: self.optimistic,
        }
    }
}

impl Default for ChokeScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchokes_top_three_by_rate() {
        let mut s = ChokeScheduler::new();
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:1".parse().unwrap();
        let c: SocketAddr = "3.3.3.3:1".parse().unwrap();
        let d: SocketAddr = "4.4.4.4:1".parse().unwrap();
        s.record_download(a, 100);
        s.record_download(b, 50);
        s.record_download(c, 200);
        s.record_download(d, 10);
        let dec = s.tick(&[a, b, c, d]);
        // top 3 by rate = c (200), a (100), b (50)
        assert!(dec.to_unchoke.contains(&a));
        assert!(dec.to_unchoke.contains(&b));
        assert!(dec.to_unchoke.contains(&c));
    }

    #[test]
    fn forget_removes_peer_state() {
        let mut s = ChokeScheduler::new();
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        s.record_download(a, 100);
        s.forget(&a);
        assert_eq!(s.rate_for(&a), 0);
    }
}
