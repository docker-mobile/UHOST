//! Feature flag helpers.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Small feature-flag map.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlags {
    flags: BTreeMap<String, bool>,
}

impl FeatureFlags {
    /// Enable or disable a named flag.
    pub fn set(&mut self, name: impl Into<String>, enabled: bool) {
        self.flags.insert(name.into(), enabled);
    }

    /// Test whether a flag is enabled.
    pub fn enabled(&self, name: &str) -> bool {
        self.flags.get(name).copied().unwrap_or(false)
    }

    /// Return the enabled flag names.
    pub fn enabled_names(&self) -> BTreeSet<String> {
        self.flags
            .iter()
            .filter(|(_, enabled)| **enabled)
            .map(|(name, _)| name.clone())
            .collect()
    }
}
