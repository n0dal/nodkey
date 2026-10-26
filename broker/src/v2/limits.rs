//! Per-workload token buckets (spec §2.5), driven by the broker clock (whole seconds). The key
//! set is the configured workloads, so memory is bounded by configuration, not by requests.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    per_sec: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// `per_min` tokens per minute, at most `burst` at once.
    pub fn new<'a>(per_min: u32, burst: u32, keys: impl Iterator<Item = &'a str>) -> Self {
        let buckets = keys
            .map(|k| {
                (
                    k.to_owned(),
                    Bucket {
                        tokens: f64::from(burst),
                        last: 0,
                    },
                )
            })
            .collect();
        RateLimiter {
            capacity: f64::from(burst),
            per_sec: f64::from(per_min) / 60.0,
            buckets: Mutex::new(buckets),
        }
    }

    /// Takes one token for `key` at `now` (Unix seconds). Unknown keys and a poisoned lock are
    /// refused (fail closed). A clock that moves backwards refills nothing.
    pub fn try_take(&self, key: &str, now: u64) -> bool {
        let Ok(mut m) = self.buckets.lock() else {
            return false;
        };
        let Some(b) = m.get_mut(key) else {
            return false;
        };
        if b.last == 0 {
            b.last = now;
        }
        let dt = now.saturating_sub(b.last) as f64;
        b.tokens = (b.tokens + dt * self.per_sec).min(self.capacity);
        b.last = b.last.max(now);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill_and_isolation() {
        let r = RateLimiter::new(10, 10, ["a", "b"].into_iter());
        let t0 = 1_000;
        for _ in 0..10 {
            assert!(r.try_take("a", t0));
        }
        assert!(!r.try_take("a", t0));
        // Another workload is unaffected (T23).
        assert!(r.try_take("b", t0));
        // 6 s later exactly one token is back (10/min).
        assert!(r.try_take("a", t0 + 6));
        assert!(!r.try_take("a", t0 + 6));
        // Clock going backwards refills nothing.
        assert!(!r.try_take("a", t0));
        assert!(!r.try_take("unknown", t0));
    }
}

/// Per-workload bound on concurrent database use (BR-01): a workload can hold at most `n`
/// connections of the workload lane at once, whatever its request mix. Keys are the configured
/// workloads; unknown keys are refused.
#[derive(Debug)]
pub struct ConcurrencyGate {
    per_key: HashMap<String, std::sync::Arc<tokio::sync::Semaphore>>,
}

impl ConcurrencyGate {
    pub fn new<'a>(n: usize, keys: impl Iterator<Item = &'a str>) -> Self {
        ConcurrencyGate {
            per_key: keys
                .map(|k| {
                    (
                        k.to_owned(),
                        std::sync::Arc::new(tokio::sync::Semaphore::new(n)),
                    )
                })
                .collect(),
        }
    }

    /// Waits at most `wait` for a slot. `None` on timeout or for an unknown key (fail closed).
    pub async fn acquire(
        &self,
        key: &str,
        wait: std::time::Duration,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let s = self.per_key.get(key)?.clone();
        tokio::time::timeout(wait, s.acquire_owned())
            .await
            .ok()?
            .ok()
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn one_workload_cannot_take_anothers_slots() {
        let g = ConcurrencyGate::new(2, ["a", "b"].into_iter());
        let w = Duration::from_millis(20);
        let p1 = g.acquire("a", w).await.unwrap();
        let _p2 = g.acquire("a", w).await.unwrap();
        assert!(g.acquire("a", w).await.is_none(), "third slot for a");
        assert!(g.acquire("b", w).await.is_some(), "b unaffected");
        assert!(g.acquire("unknown", w).await.is_none());
        drop(p1);
        assert!(g.acquire("a", w).await.is_some());
    }
}
