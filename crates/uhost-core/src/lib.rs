//! Core platform primitives shared across services.
//!
//! This crate deliberately contains the boring, reliability-heavy pieces that
//! every service needs: typed errors, configuration loading, request context,
//! structured logging, metrics primitives, retries, rate limiting, secret
//! wrappers, crypto helpers, and validation utilities.

pub mod clock;
pub mod concurrency;
pub mod config;
pub mod context;
pub mod crypto;
pub mod error;
pub mod extension;
pub mod feature;
pub mod logging;
pub mod metrics;
pub mod migrations;
pub mod rate_limit;
pub mod retry;
pub mod secret;
pub mod validation;

// This `pub use` block is the curated public surface for shared platform
// primitives, not a blanket prelude of every symbol declared in the modules
// above.
pub use clock::{Clock, ManualClock, SystemClock};
pub use concurrency::{BoundedGate, CancellationFlag};
pub use config::{ConfigLoader, ConfigSchema, LoadableConfig, ReloadableConfig};
pub use context::RequestContext;
pub use crypto::{
    base64url_decode, base64url_encode, hash_password, hmac_sha256, random_bytes, seal_secret,
    sha256_hex, unseal_secret, verify_password,
};
pub use error::{ErrorCode, PlatformError, Result};
pub use extension::{
    BackgroundTaskContract, CompatibilityPolicy, DeliveryMode, DeprecationNotice,
    EventSubscription, PluginManifest, validate_manifest_against_policy,
};
pub use feature::FeatureFlags;
pub use logging::{JsonLogger, LogField, LogLevel};
pub use metrics::{HistogramSnapshot, MetricRegistry, MetricSnapshot};
pub use migrations::{
    MigrationManifest, find_migration_manifest, load_migration_manifests,
    validate_migration_manifest_chain,
};
pub use rate_limit::TokenBucket;
pub use retry::{RetryDisposition, RetryPolicy};
pub use secret::{SecretBytes, SecretString};
pub use uhost_types::{PrincipalIdentity, PrincipalKind};
pub use validation::{
    canonicalize_hostname, normalize_label_key, validate_domain_name, validate_email,
    validate_label_value, validate_slug,
};
