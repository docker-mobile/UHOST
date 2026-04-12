//! Simple token bucket used for API and control-plane throttling.

use std::sync::Mutex;
use std::time::Duration;

use time::OffsetDateTime;

/// Result of a rate-limit check.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_second: f64,
    state: std::sync::Arc<Mutex<TokenBucketState>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct TokenBucketState {
    tokens: f64,
    last_refill: OffsetDateTime,
}

impl TokenBucket {
    /// Build a new token bucket.
    pub fn new(capacity: u32, refill_per_second: u32) -> Self {
        Self {
            capacity: f64::from(capacity),
            refill_per_second: f64::from(refill_per_second),
            state: std::sync::Arc::new(Mutex::new(TokenBucketState {
                tokens: f64::from(capacity),
                last_refill: OffsetDateTime::now_utc(),
            })),
        }
    }

    /// Try to consume tokens from the bucket.
    pub fn try_consume(&self, amount: u32) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return false;
        };

        let now = OffsetDateTime::now_utc();
        let elapsed = (now - guard.last_refill)
            .try_into()
            .unwrap_or_else(|_| Duration::from_secs(0));
        let refill = elapsed.as_secs_f64() * self.refill_per_second;
        guard.tokens = (guard.tokens + refill).min(self.capacity);
        guard.last_refill = now;

        if guard.tokens < f64::from(amount) {
            return false;
        }

        guard.tokens -= f64::from(amount);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::TokenBucket;

    #[test]
    fn bucket_blocks_when_empty() {
        let bucket = TokenBucket::new(1, 0);
        assert!(bucket.try_consume(1));
        assert!(!bucket.try_consume(1));
    }
}
