//! Shared test helpers.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tempfile::{TempDir, tempdir};

use uhost_core::{PlatformError, Result};

/// Temporary state directory used by integration tests.
#[derive(Debug)]
pub struct TempState {
    root: TempDir,
}

impl TempState {
    /// Allocate a new temp state directory.
    pub fn new() -> Result<Self> {
        tempdir().map(|root| Self { root }).map_err(|error| {
            PlatformError::unavailable("failed to create temp test directory")
                .with_detail(error.to_string())
        })
    }

    /// Borrow the root path.
    pub fn path(&self) -> &Path {
        self.root.path()
    }

    /// Build a child path under the temporary root.
    pub fn join(&self, child: impl AsRef<Path>) -> PathBuf {
        self.root.path().join(child)
    }

    /// Build a normalized child path under the temporary root.
    ///
    /// Rejects absolute paths and parent-directory traversal so tests stay
    /// confined to the temporary root.
    pub fn checked_join(&self, child: impl AsRef<Path>) -> Result<PathBuf> {
        let child = normalize_relative_path(child.as_ref())?;
        Ok(self.root.path().join(child))
    }

    /// Create a directory tree under the temporary root.
    pub fn create_dir_all(&self, child: impl AsRef<Path>) -> Result<PathBuf> {
        let path = self.checked_join(child)?;
        fs::create_dir_all(&path)
            .map_err(|error| io_error("failed to create temp directory", error))?;
        Ok(path)
    }

    /// Write a file under the temporary root, creating parent directories when needed.
    pub fn write(&self, child: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<PathBuf> {
        let path = self.checked_join(child)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| io_error("failed to create temp file parent directory", error))?;
        }
        fs::write(&path, contents).map_err(|error| io_error("failed to write temp file", error))?;
        Ok(path)
    }
}

impl AsRef<Path> for TempState {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

fn io_error(message: &str, error: io::Error) -> PlatformError {
    PlatformError::unavailable(message).with_detail(error.to_string())
}

fn normalize_relative_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(
                    PlatformError::unavailable("invalid temp path").with_detail(format!(
                        "parent-directory traversal is not allowed: {path:?}"
                    )),
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(PlatformError::unavailable("invalid temp path")
                    .with_detail(format!("absolute paths are not allowed: {path:?}")));
            }
        }
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::TempState;
    use std::path::PathBuf;

    #[test]
    fn creates_directories_under_the_temp_root() {
        let state = TempState::new().expect("temp state");

        let path = state.create_dir_all("nested/dir").expect("create dir");

        assert!(path.is_dir());
        assert_eq!(path, state.join("nested/dir"));
        assert!(path.starts_with(state.path()));
    }

    #[test]
    fn writes_files_and_creates_parents() {
        let state = TempState::new().expect("temp state");

        let path = state
            .write("nested/file.txt", b"hello")
            .expect("write file");

        assert_eq!(std::fs::read(&path).expect("read file"), b"hello");
        assert_eq!(path, state.join("nested/file.txt"));
        assert!(path.starts_with(state.path()));
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let state = TempState::new().expect("temp state");

        let error = state
            .checked_join(PathBuf::from("../escape"))
            .expect_err("parent traversal should fail");

        let message = error.to_string();
        assert!(message.contains("invalid temp path"));
    }
}
