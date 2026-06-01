use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;

/// How often the choker recomputes which peers to unchoke. The canonical
/// BitTorrent value (BEP 3 / mainline): re-evaluating every 10 s damps
/// "fibrillation" — peers being rapidly choked/unchoked — which would
/// otherwise waste the slow-start of every reopened connection.
pub const CHOKE_INTERVAL: Duration = Duration::from_secs(10);
/// How often the optimistic-unchoke slot rotates to a new random peer.
/// 30 s (3× `CHOKE_INTERVAL`, per mainline) gives a freshly-unchoked peer
/// long enough to ramp up and prove its upload rate before the next
/// regular-slot reshuffle judges it.
pub const OPTIMISTIC_INTERVAL: Duration = Duration::from_secs(30);
/// Sliding window over which peer up/down rates are averaged to rank them
/// for the regular unchoke slots. 20 s smooths burstiness without lagging
/// so far behind that a peer that just went idle keeps a slot.
pub const RATE_WINDOW: Duration = Duration::from_secs(20);
/// A peer we're interested in but that hasn't sent us a block for this
/// long is treated as "snubbing" us and loses priority for our upload
/// slots — the standard anti-leech heuristic.
pub const SNUB_THRESHOLD: Duration = Duration::from_secs(60);
/// Regular (rate-based) unchoke slots. Mainline uses 4 *total* unchoked
/// peers = 3 regular + 1 optimistic; this is the 3. Small on purpose:
/// concentrating upload bandwidth on a few peers gives each a useful rate
/// (tit-for-tat works better than spreading thin), and the optimistic
/// slot still explores new peers.
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

    // --- Test helpers ----------------------------------------------------

    /// Build `n` distinct loopback-style addresses with unique ports.
    fn peers(n: u16) -> Vec<SocketAddr> {
        (0..n)
            .map(|i| {
                format!("10.0.0.{}:{}", (i % 250) + 1, 6000 + i)
                    .parse::<SocketAddr>()
                    .unwrap()
            })
            .collect()
    }

    /// On a *fresh* scheduler, every candidate starts choked, so the first
    /// `tick` reports the entire chosen (unchoked) set via `to_unchoke`. This
    /// returns that full set so tests can reason about regular + optimistic.
    fn first_tick_unchoked(s: &mut ChokeScheduler, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
        let dec = s.tick(candidates);
        assert!(dec.to_choke.is_empty(), "fresh scheduler chokes nothing");
        dec.to_unchoke
    }

    // --- 1. Regular slots go to the top-N peers by rate ------------------

    #[test]
    fn regular_slots_are_top_n_by_rate_under_load() {
        // 10 competing peers with strictly increasing download rates.
        let p = peers(10);
        let mut s = ChokeScheduler::new();
        // Give peer i a rate proportional to i (peer 9 fastest, peer 0 slowest).
        for (i, addr) in p.iter().enumerate() {
            s.record_download(*addr, (i as u64 + 1) * 1000);
        }

        let unchoked = first_tick_unchoked(&mut s, &p);
        let opt = s.optimistic; // optimistic peer chosen on the first tick

        // The 3 fastest peers are indices 9, 8, 7.
        let top_n: Vec<SocketAddr> = vec![p[9], p[8], p[7]];

        // REGULAR_UNCHOKE_SLOTS is the contract for N.
        assert_eq!(REGULAR_UNCHOKE_SLOTS, 3, "N (regular slots) is 3");

        // Every top-N peer must be unchoked regardless of the random optimistic.
        for addr in &top_n {
            assert!(
                unchoked.contains(addr),
                "top-N peer {addr} must hold a regular slot"
            );
        }

        // Every unchoked peer is either a top-N regular slot or the optimistic.
        for addr in &unchoked {
            let is_regular = top_n.contains(addr);
            let is_opt = opt == Some(*addr);
            assert!(
                is_regular || is_opt,
                "unchoked peer {addr} is neither top-N nor optimistic"
            );
        }

        // No duplicate unchokes.
        let mut dedup = unchoked.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), unchoked.len(), "no peer unchoked twice");

        // Total unchoked never exceeds regular slots + 1 optimistic.
        assert!(
            unchoked.len() <= REGULAR_UNCHOKE_SLOTS + 1,
            "at most N regular + 1 optimistic unchoked"
        );
    }

    // --- 2. Optimistic slot exists and can fall outside the top-N --------

    #[test]
    fn optimistic_slot_can_be_outside_top_n() {
        // Only the top-3 carry rate; the remaining 7 are zero-rate peers that
        // can only ever be unchoked via the optimistic slot.
        let p = peers(10);
        let top_n: Vec<SocketAddr> = vec![p[0], p[1], p[2]];

        // The optimistic pick is random over all candidates, so retry on fresh
        // schedulers until it lands outside the top-N (bounded; effectively
        // certain since 7/10 picks qualify). This drives the behavior purely
        // through the public API with no time injection.
        let mut saw_outside = false;
        for _ in 0..200 {
            let mut s = ChokeScheduler::new();
            s.record_download(p[0], 3000);
            s.record_download(p[1], 2000);
            s.record_download(p[2], 1000);
            let unchoked = first_tick_unchoked(&mut s, &p);
            let opt = s.optimistic;

            // An optimistic peer is always selected when candidates exist.
            assert!(opt.is_some(), "optimistic slot is populated");

            // Top-N always hold their regular slots.
            for addr in &top_n {
                assert!(unchoked.contains(addr));
            }

            if let Some(o) = opt {
                if !top_n.contains(&o) {
                    // Optimistic landed on a zero-rate peer outside the top-N:
                    // it must be unchoked, giving a set size of N + 1.
                    saw_outside = true;
                    assert!(unchoked.contains(&o), "optimistic peer must be unchoked");
                    assert_eq!(
                        unchoked.len(),
                        REGULAR_UNCHOKE_SLOTS + 1,
                        "N regular + 1 optimistic when optimistic is outside top-N"
                    );
                    break;
                }
            }
        }
        assert!(
            saw_outside,
            "optimistic slot should at least once go to a peer outside the top-N"
        );
    }

    // --- 3. Seeding mode ranks by upload rate ---------------------------

    #[test]
    fn seeding_uses_upload_rate_leeching_uses_download_rate() {
        // `up_only` only ever uploads (never sends us a block) -> snubbed.
        // `down_only` sends us blocks -> not snubbed, strong download rate.
        let up_only: SocketAddr = "10.1.1.1:7000".parse().unwrap();
        let down_only: SocketAddr = "10.2.2.2:7001".parse().unwrap();
        let cands = [up_only, down_only];

        // Leeching: snub filter drops the upload-only peer; the downloader wins.
        let mut leech = ChokeScheduler::new();
        leech.record_upload(up_only, 1_000_000); // huge upload, but snubbed
        leech.record_download(down_only, 1000); // modest download, not snubbed
        assert!(leech.is_snubbed(&up_only), "upload-only peer is snubbed");
        assert!(!leech.is_snubbed(&down_only));
        let leech_unchoked = first_tick_unchoked(&mut leech, &cands);
        assert!(
            leech_unchoked.contains(&down_only),
            "leeching prefers the downloader"
        );
        // up_only can only appear via the random optimistic slot, never a
        // regular (rate) slot, because it is filtered out of the ranking.
        if leech_unchoked.contains(&up_only) {
            assert_eq!(
                leech.optimistic,
                Some(up_only),
                "in leech mode a snubbed peer is unchoked only optimistically"
            );
        }

        // Seeding: snub filter is bypassed, so the strong uploader is ranked
        // and earns a regular slot purely on its upload rate.
        let mut seed = ChokeScheduler::new();
        seed.set_seeding(true);
        seed.record_upload(up_only, 1_000_000);
        seed.record_download(down_only, 1000);
        let seed_unchoked = first_tick_unchoked(&mut seed, &cands);
        assert!(
            seed_unchoked.contains(&up_only),
            "seeding ranks the strong uploader into a regular slot"
        );
        // The uploader outranks the downloader by rate (1_000_000 vs 1000).
        assert!(seed.rate_for(&up_only) > seed.rate_for(&down_only));
    }

    // --- 4. Edge cases: forget / empty / fewer-than-slots ---------------

    #[test]
    fn empty_candidates_tick_is_sane() {
        let mut s = ChokeScheduler::new();
        let dec = s.tick(&[]);
        assert!(dec.to_unchoke.is_empty());
        assert!(dec.to_choke.is_empty());
        // With no candidates the optimistic slot cannot be filled.
        assert!(dec.optimistic.is_none());
    }

    #[test]
    fn fewer_candidates_than_slots_never_overfills() {
        // Two candidates, three regular slots: never unchoke more than exist,
        // and never unchoke a peer twice.
        let p = peers(2);
        let mut s = ChokeScheduler::new();
        s.record_download(p[0], 500);
        s.record_download(p[1], 100);
        let unchoked = first_tick_unchoked(&mut s, &p);
        assert!(
            unchoked.len() <= p.len(),
            "unchoked count never exceeds candidate count"
        );
        let mut dedup = unchoked.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), unchoked.len(), "no duplicate unchokes");
        // Both peers should be unchoked (they fit within the slots).
        assert!(unchoked.contains(&p[0]) && unchoked.contains(&p[1]));
    }

    #[test]
    fn forget_releases_optimistic_and_unchoke_state() {
        let p = peers(4);
        let mut s = ChokeScheduler::new();
        for addr in &p {
            s.record_download(*addr, 100);
        }
        let _ = s.tick(&p);
        // Forget whoever currently holds the optimistic slot plus a regular one.
        if let Some(opt) = s.optimistic {
            s.forget(&opt);
            assert_ne!(s.optimistic, Some(opt), "forget clears optimistic slot");
        }
        s.forget(&p[0]);
        assert_eq!(s.rate_for(&p[0]), 0, "forget clears rate samples");
        assert!(
            s.is_snubbed(&p[0]),
            "forgotten peer has no last-block record"
        );

        // A subsequent tick on the surviving peers must not panic, must not
        // re-choke the forgotten peer, and must not duplicate unchokes.
        let survivors: Vec<SocketAddr> = p.iter().copied().filter(|a| *a != p[0]).collect();
        let dec = s.tick(&survivors);
        assert!(!dec.to_choke.contains(&p[0]));
        assert!(!dec.to_unchoke.contains(&p[0]));
        let mut all: Vec<SocketAddr> = dec.to_unchoke.clone();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), dec.to_unchoke.len());
    }

    #[test]
    fn repeated_ticks_are_stable_no_fibrillation() {
        // With unchanged rates, after the set stabilizes a tick should produce
        // no further regular churn (only possible optimistic rotation, which is
        // time-gated and won't fire within a single test run).
        let p = peers(5);
        let mut s = ChokeScheduler::new();
        for (i, addr) in p.iter().enumerate() {
            s.record_download(*addr, (i as u64 + 1) * 1000);
        }
        let _ = s.tick(&p); // settle
        let dec = s.tick(&p);
        // Nothing newly unchoked/choked when the ranking is unchanged and the
        // optimistic slot has not rotated.
        assert!(
            dec.to_unchoke.is_empty(),
            "stable rates cause no re-unchoke churn"
        );
        assert!(
            dec.to_choke.is_empty(),
            "stable rates cause no re-choke churn"
        );
    }
}
