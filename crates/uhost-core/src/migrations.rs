//! Manifest-backed migration helpers shared by the lifecycle service and CLI.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

use crate::{PlatformError, Result, sha256_hex};

/// One migration manifest loaded from disk.
#[derive(Debug, Clone, PartialEq)]
pub struct MigrationManifest {
    /// Source file that defined the manifest.
    pub source: PathBuf,
    /// Stable migration name.
    pub name: String,
    /// Scope key such as `schema` or `config`.
    pub scope: String,
    /// Source version.
    pub from_version: u32,
    /// Target version.
    pub to_version: u32,
    /// Published canonical checksum.
    pub checksum: String,
    /// Optional compatibility window in days.
    pub compatibility_window_days: Option<u32>,
    /// Optional structured transform hints.
    pub changes: toml::Table,
    canonical_document: Value,
}

impl MigrationManifest {
    /// Compute the canonical checksum for this manifest.
    pub fn canonical_checksum(&self) -> Result<String> {
        let mut fields = BTreeMap::<String, String>::new();
        flatten_manifest_value(String::new(), &self.canonical_document, &mut fields)?;
        let payload = fields
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(sha256_hex(payload.as_bytes()))
    }

    /// Ensure the published checksum matches the canonical manifest payload.
    pub fn validate_canonical_checksum(&self) -> Result<()> {
        let computed = self.canonical_checksum()?;
        if computed == self.checksum {
            return Ok(());
        }

        Err(
            PlatformError::invalid("migration manifest checksum mismatch").with_detail(format!(
                "{} expected {} but computed {}",
                self.source.display(),
                self.checksum,
                computed
            )),
        )
    }
}

/// Load migration manifests from one bundle root without validating the chain.
pub fn load_migration_manifests(bundle_root: &Path) -> Result<Vec<MigrationManifest>> {
    if !bundle_root.exists() {
        return Err(PlatformError::not_found(format!(
            "migration bundle root {} does not exist",
            bundle_root.display()
        )));
    }

    let mut files = Vec::new();
    collect_toml_files(bundle_root, &mut files)?;
    files.sort();

    let mut manifests = Vec::new();
    for file in files {
        let content =
            fs::read_to_string(&file).map_err(|error| {
                PlatformError::unavailable("failed to read migration manifest")
                    .with_detail(format!("{}: {}", file.display(), error))
            })?;
        let value: Value = toml::from_str(&content).map_err(|error| {
            PlatformError::invalid("failed to decode migration manifest").with_detail(format!(
                "{}: {}",
                file.display(),
                error
            ))
        })?;

        let name = toml_required_string(&value, "name", &file)?;
        let scope = toml_required_string(&value, "scope", &file)?.to_ascii_lowercase();
        let from_version = toml_required_u32(&value, "from_version", &file)?;
        let to_version = toml_required_u32(&value, "to_version", &file)?;
        let checksum = toml_required_string(&value, "checksum", &file)?;
        let compatibility_window_days = value
            .get("compatibility")
            .and_then(|compatibility| compatibility.get("window_days"))
            .and_then(Value::as_integer)
            .and_then(|days| u32::try_from(days).ok());
        let changes = value
            .get("changes")
            .and_then(Value::as_table)
            .cloned()
            .unwrap_or_default();
        let mut canonical_document = value.clone();
        let canonical_table = canonical_document.as_table_mut().ok_or_else(|| {
            PlatformError::invalid("migration manifest root must be a table")
                .with_detail(file.display().to_string())
        })?;
        canonical_table.remove("checksum");

        manifests.push(MigrationManifest {
            source: file,
            name,
            scope,
            from_version,
            to_version,
            checksum,
            compatibility_window_days,
            changes,
            canonical_document,
        });
    }

    manifests.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.from_version.cmp(&right.from_version))
            .then(left.to_version.cmp(&right.to_version))
            .then(left.name.cmp(&right.name))
    });

    Ok(manifests)
}

/// Validate manifest checksums and enforce one contiguous chain per scope.
pub fn validate_migration_manifest_chain(manifests: &[MigrationManifest]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for manifest in manifests {
        manifest.validate_canonical_checksum()?;
        if manifest.to_version <= manifest.from_version {
            return Err(PlatformError::invalid(
                "migration manifest to_version must be greater than from_version",
            )
            .with_detail(manifest.source.display().to_string()));
        }
        let identity = (
            manifest.scope.clone(),
            manifest.from_version,
            manifest.to_version,
            manifest.name.clone(),
        );
        if !seen.insert(identity) {
            return Err(
                PlatformError::invalid("duplicate migration manifest definition")
                    .with_detail(manifest.source.display().to_string()),
            );
        }
    }

    let scopes = manifests
        .iter()
        .map(|manifest| manifest.scope.clone())
        .collect::<BTreeSet<_>>();
    for scope in scopes {
        let mut scoped = manifests
            .iter()
            .filter(|manifest| manifest.scope == scope)
            .collect::<Vec<_>>();
        scoped.sort_by(|left, right| {
            left.from_version
                .cmp(&right.from_version)
                .then(left.to_version.cmp(&right.to_version))
                .then(left.name.cmp(&right.name))
        });

        let mut previous = None::<&MigrationManifest>;
        for manifest in scoped {
            if let Some(previous) = previous
                && manifest.from_version != previous.to_version
            {
                return Err(
                    PlatformError::invalid("migration manifest chain is not contiguous")
                        .with_detail(format!(
                            "scope {} expected from_version {} but found {} in {}",
                            scope,
                            previous.to_version,
                            manifest.from_version,
                            manifest.source.display()
                        )),
                );
            }
            previous = Some(manifest);
        }
    }

    Ok(())
}

/// Find one manifest by stable identity.
pub fn find_migration_manifest<'a>(
    manifests: &'a [MigrationManifest],
    scope: &str,
    from_version: u32,
    to_version: u32,
    name: &str,
) -> Option<&'a MigrationManifest> {
    let scope = scope.trim().to_ascii_lowercase();
    manifests.iter().find(|manifest| {
        manifest.scope == scope
            && manifest.from_version == from_version
            && manifest.to_version == to_version
            && manifest.name == name
    })
}

fn collect_toml_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(root).map_err(|error| {
        PlatformError::unavailable("failed to read migration directory").with_detail(format!(
            "{}: {}",
            root.display(),
            error
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            PlatformError::unavailable("failed to enumerate migration directory")
                .with_detail(error.to_string())
        })?;
        let path = entry.path();
        let file_type =
            entry.file_type().map_err(|error| {
                PlatformError::unavailable("failed to read migration path type")
                    .with_detail(format!("{}: {}", path.display(), error))
            })?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_toml_files(&path, output)?;
            continue;
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            output.push(path);
        }
    }

    Ok(())
}

fn toml_required_string(value: &Value, key: &str, source: &Path) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            PlatformError::invalid(format!("missing or invalid `{key}` in migration manifest"))
                .with_detail(source.display().to_string())
        })
}

fn toml_required_u32(value: &Value, key: &str, source: &Path) -> Result<u32> {
    value
        .get(key)
        .and_then(Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            PlatformError::invalid(format!("missing or invalid `{key}` in migration manifest"))
                .with_detail(source.display().to_string())
        })
}

fn flatten_manifest_value(
    prefix: String,
    value: &Value,
    output: &mut BTreeMap<String, String>,
) -> Result<()> {
    match value {
        Value::Table(table) => {
            let keys = table.keys().cloned().collect::<BTreeSet<_>>();
            for key in keys {
                let next = table.get(&key).ok_or_else(|| {
                    PlatformError::invalid("migration manifest table entry disappeared")
                })?;
                let next_prefix = if prefix.is_empty() {
                    key
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_manifest_value(next_prefix, next, output)?;
            }
            Ok(())
        }
        _ => {
            if prefix.is_empty() {
                return Err(PlatformError::invalid(
                    "migration manifest checksum payload cannot be scalar",
                ));
            }
            let encoded = serde_json::to_string(value).map_err(|error| {
                PlatformError::invalid("failed to encode canonical migration manifest value")
                    .with_detail(error.to_string())
            })?;
            output.insert(prefix, encoded);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{load_migration_manifests, validate_migration_manifest_chain};

    #[test]
    fn manifest_chain_validation_rejects_gaps() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let schema = temp.path().join("schema");
        fs::create_dir_all(&schema).unwrap_or_else(|error| panic!("{error}"));
        fs::write(
            schema.join("0001.toml"),
            r#"name = "s1"
scope = "schema"
from_version = 1
to_version = 2
checksum = "05f942c78ad3be4ce6ee649067f8482847f920f4abe51f1ad33133b6b8fccb9c"
"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        fs::write(
            schema.join("0002.toml"),
            r#"name = "s3"
scope = "schema"
from_version = 3
to_version = 4
checksum = "83815b73bf3388a0b9dfcf4eb10558ea4670590c3cec87e781a2d8371c6852a3"
"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let manifests =
            load_migration_manifests(temp.path()).unwrap_or_else(|error| panic!("{error}"));
        let error = validate_migration_manifest_chain(&manifests)
            .expect_err("expected non-contiguous migration chain to fail");
        assert!(
            error
                .detail
                .unwrap_or_default()
                .contains("expected from_version 2 but found 3")
        );
    }
}
