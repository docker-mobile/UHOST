//! Configuration loading and environment overlays.

use std::env;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::error::{PlatformError, Result};
use uhost_types::ServiceMode;

/// Top-level schema header shared by config files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSchema {
    /// Schema version for explicit migrations.
    pub schema_version: u16,
    /// Runtime mode.
    pub mode: ServiceMode,
    /// Immutable bootstrap identity for the current node.
    pub node_name: String,
}

/// Trait for config sections that can self-validate before service start.
pub trait LoadableConfig: DeserializeOwned + Send + Sync {
    /// Validate semantic invariants after deserialization.
    fn validate(&self) -> Result<()>;
}

/// Marker trait for config that may be reloaded safely at runtime.
pub trait ReloadableConfig: LoadableConfig {}

/// Loader for TOML config files with environment overlays.
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    env_prefix: String,
}

impl ConfigLoader {
    /// Create a new loader using the provided environment variable prefix.
    pub fn new(env_prefix: impl Into<String>) -> Self {
        Self {
            env_prefix: env_prefix.into(),
        }
    }

    /// Load a configuration file and merge environment overrides.
    pub async fn load<T>(&self, path: impl AsRef<Path>) -> Result<T>
    where
        T: LoadableConfig,
    {
        let raw = fs::read_to_string(path.as_ref()).await.map_err(|error| {
            PlatformError::unavailable("failed to read config file").with_detail(error.to_string())
        })?;

        let mut value = toml::from_str::<toml::Value>(&raw).map_err(|error| {
            PlatformError::invalid("failed to parse config file").with_detail(error.to_string())
        })?;
        self.apply_environment_overrides(&mut value)?;
        let config: T = value.try_into().map_err(|error| {
            PlatformError::invalid("failed to decode config structure")
                .with_detail(error.to_string())
        })?;
        config.validate()?;
        Ok(config)
    }

    fn apply_environment_overrides(&self, root: &mut toml::Value) -> Result<()> {
        self.apply_environment_overrides_from_iter(root, env::vars())
    }

    fn apply_environment_overrides_from_iter<I, K, V>(
        &self,
        root: &mut toml::Value,
        vars: I,
    ) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<String>,
    {
        for (key, value) in vars {
            let key = key.as_ref();
            if !key.starts_with(&self.env_prefix) {
                continue;
            }

            let path = key[self.env_prefix.len()..]
                .trim_start_matches('_')
                .split("__")
                .filter(|segment| !segment.is_empty())
                .map(|segment| segment.to_ascii_lowercase())
                .collect::<Vec<_>>();

            if path.is_empty() {
                continue;
            }

            merge_toml_path(root, &path, toml::Value::String(value.into()))?;
        }

        Ok(())
    }
}

fn merge_toml_path(current: &mut toml::Value, path: &[String], value: toml::Value) -> Result<()> {
    if path.is_empty() {
        *current = value;
        return Ok(());
    }

    let Some((head, tail)) = path.split_first() else {
        return Ok(());
    };

    if !current.is_table() {
        return Err(PlatformError::invalid(
            "config path collides with a non-table value",
        ));
    }

    let table = current
        .as_table_mut()
        .ok_or_else(|| PlatformError::invalid("config path does not point to a table"))?;

    if tail.is_empty() {
        table.insert(head.clone(), value);
        return Ok(());
    }

    let next = table
        .entry(head.clone())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));

    if !next.is_table() {
        return Err(PlatformError::invalid(
            "config path collides with a non-table value",
        ));
    }

    merge_toml_path(next, tail, value)
}

#[cfg(test)]
mod tests {
    use super::{ConfigLoader, ConfigSchema, LoadableConfig};
    use crate::error::Result;
    use tempfile::tempdir;
    use uhost_types::ServiceMode;

    #[derive(Debug, serde::Deserialize)]
    struct ExampleConfig {
        schema: ConfigSchema,
        listen: String,
    }

    impl LoadableConfig for ExampleConfig {
        fn validate(&self) -> Result<()> {
            if self.listen.is_empty() {
                return Err(crate::error::PlatformError::invalid("listen is empty"));
            }

            if self.schema.node_name.is_empty() {
                return Err(crate::error::PlatformError::invalid("node_name is empty"));
            }

            Ok(())
        }
    }

    #[tokio::test]
    async fn load_toml_config() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("config.toml");
        tokio::fs::write(
            &path,
            br#"listen = "127.0.0.1:9080"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "dev-node"
"#,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let config: ExampleConfig = ConfigLoader::new("UHOST")
            .load(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.schema.mode, ServiceMode::AllInOne);
    }

    #[test]
    fn env_overrides_fail_when_they_try_to_descend_into_a_scalar() {
        let loader = ConfigLoader::new("UHOST");
        let mut table = toml::map::Map::new();
        table.insert(
            String::from("listen"),
            toml::Value::String(String::from("127.0.0.1:8080")),
        );
        let mut value = toml::Value::Table(table);

        let error = loader
            .apply_environment_overrides_from_iter(&mut value, [("UHOST_LISTEN__PORT", "9090")])
            .expect_err("expected scalar path collision to fail");

        assert_eq!(error.code, crate::error::ErrorCode::InvalidInput);
    }
}
