//! Secret wrappers that avoid accidental logging.

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Heap-allocated secret bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Build a new secret byte wrapper.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the wrapped bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(REDACTED)")
    }
}

/// Heap-allocated secret string.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Build a new secret string wrapper.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the secret string.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(REDACTED)")
    }
}
