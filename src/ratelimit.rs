//! Minimal token-bucket rate limiter.
//!
//! Used for two distinct purposes today:
//! - Per-peer cap on inbound `Request` messages (B3 — drop the message
//!   when the bucket is dry so a single peer can't DoS the disk).
//! - Engine-wide cap on download / upload bandwidth (the `--max-down`
//!   and `--max-up` flags — gate Request issuance and Piece send when
//!   the byte-bucket is dry).
//!
//! No background refill task — the bucket is lazily refilled at the
//! moment of `try_consume`, which keeps it allocation-free and lock-free
//! when wrapped in a `Mutex` for cross-task access.

use std::time::Instant;

/// Token bucket that refills at `rate_per_sec` up to a hard ceiling of
/// `capacity`. `try_consume(n)` returns `true` iff `n` tokens were
/// available; on `false` the bucket state is unchanged.
pub struct TokenBucket {
    capacity: f64,
    rate_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, rate_per_sec: f64) -> Self {
        Self {
            capacity,
            rate_per_sec,
            // Start full so a brief opening burst doesn't get throttled.
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, n: f64) -> bool {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// How many tokens are currently available, after a lazy refill.
    /// Useful for capacity-based caller decisions (e.g. "drain as many
    /// blocks as the bucket allows in this loop iteration") without
    /// committing them yet.
    pub fn available(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
            self.last_refill = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn starts_full() {
        let mut b = TokenBucket::new(10.0, 1.0);
        for _ in 0..10 {
            assert!(b.try_consume(1.0));
        }
        assert!(!b.try_consume(1.0));
    }

    #[test]
    fn refills_over_time() {
        let mut b = TokenBucket::new(5.0, 1000.0);
        for _ in 0..5 {
            assert!(b.try_consume(1.0));
        }
        assert!(!b.try_consume(1.0));
        std::thread::sleep(Duration::from_millis(20));
        // 1000 t/s × 20 ms = 20 tokens, capped at capacity 5.
        assert!(b.try_consume(5.0));
    }

    #[test]
    fn caps_at_capacity() {
        let mut b = TokenBucket::new(3.0, 1000.0);
        std::thread::sleep(Duration::from_millis(50));
        assert!(b.try_consume(3.0));
        assert!(!b.try_consume(0.1));
    }

    #[test]
    fn try_consume_failure_preserves_state() {
        let mut b = TokenBucket::new(2.0, 0.0); // no refill
                                                // Drain one.
        assert!(b.try_consume(1.0));
        // Request more than remaining — must fail and not deduct.
        assert!(!b.try_consume(5.0));
        // The remaining 1 token is still there.
        assert!(b.try_consume(1.0));
    }
}
