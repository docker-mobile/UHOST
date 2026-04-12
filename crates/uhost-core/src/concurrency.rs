//! Concurrency utilities shared by services.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Cooperative cancellation flag.
#[derive(Debug, Clone, Default)]
pub struct CancellationFlag(Arc<AtomicBool>);

impl CancellationFlag {
    /// Trigger cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Check whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Bounded concurrency gate used to keep queues and fan-out work finite.
#[derive(Debug, Clone)]
pub struct BoundedGate {
    semaphore: Arc<Semaphore>,
}

impl BoundedGate {
    /// Create a new gate with a fixed permit count.
    pub fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }

    /// Acquire one permit.
    pub async fn acquire(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        self.semaphore.clone().acquire_owned().await
    }
}
