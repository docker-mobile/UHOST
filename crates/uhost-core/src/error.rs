//! Shared error model.
//!
//! The platform uses one structured error shape so operators receive consistent
//! diagnostics regardless of which service emitted the failure.

use core::fmt;

use serde::{Deserialize, Serialize};

/// High-level error classes that remain stable over the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Input validation failed.
    InvalidInput,
    /// Requested resource was not found.
    NotFound,
    /// Caller is not authenticated.
    Unauthorized,
    /// Caller is authenticated but not permitted to act.
    Forbidden,
    /// A concurrency precondition failed.
    Conflict,
    /// Rate limiting prevented the request from being served.
    RateLimited,
    /// A dependency timed out.
    Timeout,
    /// A dependency is temporarily unavailable.
    Unavailable,
    /// Storage bytes or integrity metadata were found to be corrupted.
    StorageCorruption,
    /// The platform hit an unexpected internal failure.
    Internal,
}

/// Platform-wide structured error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformError {
    /// Stable machine-readable error code.
    pub code: ErrorCode,
    /// Human-readable message suitable for operators and API consumers.
    pub message: String,
    /// Optional detail string for debugging without exposing secrets.
    pub detail: Option<String>,
    /// Optional correlation identifier propagated across services.
    pub correlation_id: Option<String>,
}

impl PlatformError {
    /// Create a new error with the given code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
            correlation_id: None,
        }
    }

    /// Attach a non-secret detail string.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach a correlation identifier.
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Convenience helper for invalid input failures.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }

    /// Convenience helper for not-found failures.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// Convenience helper for conflicts.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }

    /// Convenience helper for forbidden actions.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }

    /// Convenience helper for temporary dependency failures.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unavailable, message)
    }

    /// Convenience helper for storage integrity or corruption failures.
    pub fn storage_corruption(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::StorageCorruption, message)
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PlatformError {}

/// Shared result alias.
pub type Result<T> = std::result::Result<T, PlatformError>;
