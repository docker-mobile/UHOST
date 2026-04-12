//! Clock abstraction used to keep time-dependent code testable.

use std::sync::{Arc, Mutex};

use time::OffsetDateTime;

/// Time source abstraction.
pub trait Clock: Send + Sync {
    /// Return the current UTC timestamp.
    fn now(&self) -> OffsetDateTime;
}

/// Real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Mutable clock used by tests and deterministic simulations.
#[derive(Debug, Clone)]
pub struct ManualClock {
    inner: Arc<Mutex<OffsetDateTime>>,
}

impl ManualClock {
    /// Construct a manual clock pinned to a known time.
    pub fn new(initial: OffsetDateTime) -> Self {
        Self {
            inner: Arc::new(Mutex::new(initial)),
        }
    }

    /// Advance the manual clock.
    pub fn advance_by(&self, duration: time::Duration) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard += duration;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        self.inner
            .lock()
            .map(|value| *value)
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
    }
}
