//! Retry helpers with jittered backoff.

use std::future::Future;
use std::time::Duration;

use crate::error::{PlatformError, Result};

/// Whether a failure should be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDisposition {
    /// Retry the operation.
    Retryable,
    /// Return the error immediately.
    Permanent,
}

/// Retry policy with capped exponential backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum number of attempts including the first call.
    pub max_attempts: u32,
    /// Initial delay before the second attempt.
    pub base_delay: Duration,
    /// Maximum delay.
    pub max_delay: Duration,
    /// Upper bound for random jitter in milliseconds.
    pub jitter_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
            jitter_ms: 100,
        }
    }
}

impl RetryPolicy {
    /// Execute a fallible async operation with retries.
    pub async fn run<F, Fut, T, C>(&self, mut call: F, classify: C) -> Result<T>
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = Result<T>>,
        C: Fn(&PlatformError) -> RetryDisposition,
    {
        let mut attempt = 1_u32;
        let mut delay = self.base_delay;

        loop {
            match call(attempt).await {
                Ok(value) => return Ok(value),
                Err(error) if attempt < self.max_attempts => {
                    if classify(&error) == RetryDisposition::Permanent {
                        return Err(error);
                    }

                    let jitter = self.next_jitter().unwrap_or_default();
                    let sleep_for = delay
                        .saturating_add(Duration::from_millis(jitter))
                        .min(self.max_delay);
                    tokio::time::sleep(sleep_for).await;
                    delay = delay.saturating_mul(2).min(self.max_delay);
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn next_jitter(&self) -> Result<u64> {
        if self.jitter_ms == 0 {
            return Ok(0);
        }

        let bytes = crate::crypto::random_bytes(8)?;
        let mut array = [0_u8; 8];
        array.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(array) % self.jitter_ms)
    }
}
