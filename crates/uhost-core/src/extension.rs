//! Stable extension system contracts.
//!
//! These types define the minimum compatibility surface for plugin-style
//! extensions. Service code can evolve quickly while still preserving explicit
//! version and deprecation policy guarantees for plugin authors.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Stable plugin manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin identifier. This is expected to stay stable for the plugin's
    /// lifecycle and is used for trust and policy mapping.
    pub plugin_id: String,
    /// Human-readable plugin name.
    pub name: String,
    /// Plugin implementation version (semver-like string).
    pub version: String,
    /// Minimum platform extension API version required.
    pub min_api_version: u16,
    /// Maximum platform extension API version tested by the plugin.
    pub max_api_version: u16,
    /// Event subscriptions declared by the plugin.
    pub subscriptions: Vec<EventSubscription>,
    /// Background task handlers exposed by the plugin.
    pub background_tasks: Vec<BackgroundTaskContract>,
}

/// Versioned event subscription contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSubscription {
    /// Topic pattern. This should include schema version suffixes, such as
    /// `mail.message.*.v1`.
    pub topic: String,
    /// Delivery mode.
    pub delivery_mode: DeliveryMode,
    /// Whether at-least-once retries are enabled.
    pub retries_enabled: bool,
}

/// Background task handler contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundTaskContract {
    /// Stable task identifier.
    pub task: String,
    /// Maximum runtime before cancellation.
    pub timeout_seconds: u32,
    /// Maximum concurrent executions.
    pub max_concurrency: u16,
}

/// Delivery semantics for extension event callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// Single delivery attempt per event.
    BestEffort,
    /// Retry until success or operator cancellation.
    AtLeastOnce,
}

/// Compatibility policy published by the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityPolicy {
    /// Current extension API major version.
    pub current_api_version: u16,
    /// Oldest supported extension API version.
    pub minimum_supported_api_version: u16,
    /// Date when the minimum supported version changes.
    pub effective_at: OffsetDateTime,
}

/// Deprecation notice for extension API contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecationNotice {
    /// Feature or topic being deprecated.
    pub feature: String,
    /// Optional replacement feature.
    pub replacement: Option<String>,
    /// Date after which the feature may be removed.
    pub removal_not_before: OffsetDateTime,
    /// Migration guidance.
    pub guidance: String,
}

/// Validate whether a plugin manifest is compatible with policy.
pub fn validate_manifest_against_policy(
    manifest: &PluginManifest,
    policy: &CompatibilityPolicy,
) -> bool {
    manifest.min_api_version <= policy.current_api_version
        && manifest.max_api_version >= policy.current_api_version
        && manifest.max_api_version >= policy.minimum_supported_api_version
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{CompatibilityPolicy, PluginManifest, validate_manifest_against_policy};

    #[test]
    fn manifest_compatibility_check_works_for_version_ranges() {
        let manifest = PluginManifest {
            plugin_id: String::from("plg_demo"),
            name: String::from("demo"),
            version: String::from("1.2.3"),
            min_api_version: 1,
            max_api_version: 3,
            subscriptions: Vec::new(),
            background_tasks: Vec::new(),
        };
        let policy = CompatibilityPolicy {
            current_api_version: 2,
            minimum_supported_api_version: 1,
            effective_at: OffsetDateTime::now_utc(),
        };
        assert!(validate_manifest_against_policy(&manifest, &policy));
    }
}
