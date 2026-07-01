//! Minimal in-memory per-key token-bucket rate limiter.
//!
//! Used to throttle abuse-prone public POSTs (registration, password reset) per client IP.
//! There is no existing limiter in Keystone, so this is a small, dependency-free one: a
//! `Mutex<HashMap<key, Bucket>>` of token buckets that refill continuously at `refill_per_sec`
//! up to `capacity`. `check(key)` costs one token and returns whether the call is allowed.
//!
//! This is best-effort and process-local (per replica) — exactly the right weight for slowing
//! down bursts from a single source without a datastore. Keys are bounded by opportunistic GC:
//! a fully-refilled bucket is pruned on access so the map cannot grow without bound.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::now_secs;

/// A continuously-refilling token bucket. `tokens` is fractional so sub-second refills accrue.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: u64,
}

/// Per-key token-bucket limiter. Cheap to share behind an `Arc`.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// A limiter allowing bursts up to `capacity`, refilling `capacity` tokens every `per_secs`.
    pub fn new(capacity: u32, per_secs: u64) -> Self {
        let per_secs = per_secs.max(1);
        RateLimiter {
            capacity: capacity as f64,
            refill_per_sec: capacity as f64 / per_secs as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Spend one token for `key`. Returns `true` when allowed, `false` when the bucket is empty.
    pub fn check(&self, key: &str) -> bool {
        let now = now_secs();
        let mut buckets = self.buckets.lock().expect("ratelimit lock poisoned");
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        // Refill for elapsed time (guard against clock going backwards).
        let elapsed = now.saturating_sub(bucket.last) as f64;
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;

        let allowed = if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        };

        // Opportunistic GC: a bucket back at full capacity carries no state worth keeping.
        if bucket.tokens >= self.capacity {
            buckets.remove(key);
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_denied() {
        // 3 tokens, slow refill: the 4th immediate call is denied.
        let rl = RateLimiter::new(3, 3600);
        assert!(rl.check("1.2.3.4"));
        assert!(rl.check("1.2.3.4"));
        assert!(rl.check("1.2.3.4"));
        assert!(!rl.check("1.2.3.4"), "4th call over capacity is denied");
        // A different key has its own bucket.
        assert!(rl.check("5.6.7.8"));
    }
}
