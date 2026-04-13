//! Append-only audit log.

use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use serde::Serialize;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use uhost_core::{PlatformError, Result};

/// Append-only JSON-lines audit log.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    write_guard: Arc<Mutex<()>>,
}

impl AuditLog {
    /// Open or create an audit log file.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to create audit log directory")
                    .with_detail(error.to_string())
            })?;
            secure_directory_permissions(parent).await?;
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let _ = options.open(&path).await.map_err(|error| {
            PlatformError::unavailable("failed to initialize audit log")
                .with_detail(error.to_string())
        })?;

        let path = fs::canonicalize(&path).await.map_err(|error| {
            PlatformError::unavailable("failed to canonicalize audit log path")
                .with_detail(error.to_string())
        })?;
        if let Some(parent) = path.parent() {
            secure_directory_permissions(parent).await?;
        }
        secure_file_permissions(&path).await?;
        sync_parent_dir(&path).await?;

        Ok(Self {
            write_guard: shared_write_guard(&path),
            path,
        })
    }

    /// Append one record to the audit log.
    pub async fn append<T>(&self, record: &T) -> Result<()>
    where
        T: Serialize,
    {
        let _guard = self.write_guard.lock().await;
        let encoded = serde_json::to_vec(record).map_err(|error| {
            PlatformError::unavailable("failed to encode audit record")
                .with_detail(error.to_string())
        })?;
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options.open(&self.path).await.map_err(|error| {
            PlatformError::unavailable("failed to open audit log").with_detail(error.to_string())
        })?;
        file.write_all(&encoded).await.map_err(|error| {
            PlatformError::unavailable("failed to append audit record")
                .with_detail(error.to_string())
        })?;
        file.write_all(b"\n").await.map_err(|error| {
            PlatformError::unavailable("failed to finalize audit record")
                .with_detail(error.to_string())
        })?;
        file.flush().await.map_err(|error| {
            PlatformError::unavailable("failed to flush audit log").with_detail(error.to_string())
        })?;
        file.sync_all().await.map_err(|error| {
            PlatformError::unavailable("failed to sync audit log").with_detail(error.to_string())
        })?;
        secure_file_permissions(&self.path).await
    }
}

fn shared_write_guard(path: &Path) -> Arc<Mutex<()>> {
    static REGISTRY: OnceLock<StdMutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    registry
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

async fn secure_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;

    #[cfg(unix)]
    {
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| {
                PlatformError::unavailable("failed to harden audit log directory permissions")
                    .with_detail(error.to_string())
            })?;
    }
    Ok(())
}

async fn secure_file_permissions(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;

    #[cfg(unix)]
    {
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|error| {
                PlatformError::unavailable("failed to harden audit log file permissions")
                    .with_detail(error.to_string())
            })?;
    }
    Ok(())
}

async fn sync_parent_dir(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;

    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            let dir = fs::File::open(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to open audit directory for sync")
                    .with_detail(error.to_string())
            })?;
            dir.sync_all().await.map_err(|error| {
                PlatformError::unavailable("failed to sync audit directory")
                    .with_detail(error.to_string())
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::AuditLog;

    #[cfg(unix)]
    #[tokio::test]
    async fn open_hardens_audit_log_file_and_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("audit").join("audit.log");

        let log = AuditLog::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        log.append(&json!({ "event": "created" }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let file_mode = std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("{error}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);

        let parent = path.parent().unwrap_or_else(|| panic!("missing parent"));
        let directory_mode = std::fs::metadata(parent)
            .unwrap_or_else(|error| panic!("{error}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
    }
}
