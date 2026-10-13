//! Local file storage.

use std::ffi::OsStr;
use std::io::SeekFrom;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::fs::{self, File};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncSeekExt};

use super::{Download, RemoteFile, StorageBackend};
use crate::error::{ErrorKind, ServerError, ServerResult};

#[derive(Debug)]
pub struct LocalBackend {
    config: LocalStorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalStorageConfig {
    /// The directory to store all files under.
    path: PathBuf,
}

/// Reference to a file in local storage.
///
/// We still call it "remote file" for consistency :)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRemoteFile {
    /// Name of the file.
    pub name: String,
}

async fn read_version(storage_path: &Path) -> ServerResult<u32> {
    let version_path = storage_path.join("VERSION");
    let v = match fs::read_to_string(&version_path).await {
        Ok(version) => version
            .trim()
            .parse()
            .map_err(|_| ErrorKind::StorageError(anyhow::anyhow!("Invalid version file")))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => {
            return Err(ErrorKind::StorageError(anyhow::anyhow!(
                "Failed to read version file: {}",
                e
            ))
            .into());
        }
    };
    Ok(v)
}

async fn write_version(storage_path: &Path, version: u32) -> ServerResult<()> {
    let version_path = storage_path.join("VERSION");
    fs::write(&version_path, format!("{}", version))
        .await
        .map_err(ServerError::storage_error)?;
    Ok(())
}

async fn upgrade_0_to_1(storage_path: &Path) -> ServerResult<()> {
    let mut files = fs::read_dir(storage_path)
        .await
        .map_err(ServerError::storage_error)?;
    // move all files to subdirectory using the first two characters of the filename
    while let Some(file) = files
        .next_entry()
        .await
        .map_err(ServerError::storage_error)?
    {
        if file
            .file_type()
            .await
            .map_err(ServerError::storage_error)?
            .is_file()
        {
            let name = file.file_name();
            let name_bytes = name.as_os_str().as_bytes();
            let parents = storage_path
                .join(OsStr::from_bytes(&name_bytes[0..1]))
                .join(OsStr::from_bytes(&name_bytes[0..2]));
            let new_path = parents.join(name);
            fs::create_dir_all(&parents).await.map_err(|e| {
                ErrorKind::StorageError(anyhow::anyhow!("Failed to create directory {}", e))
            })?;
            fs::rename(&file.path(), &new_path).await.map_err(|e| {
                ErrorKind::StorageError(anyhow::anyhow!(
                    "Failed to move file {} to {}: {}",
                    file.path().display(),
                    new_path.display(),
                    e
                ))
            })?;
        }
    }

    Ok(())
}

impl LocalBackend {
    pub async fn new(config: LocalStorageConfig) -> ServerResult<Self> {
        fs::create_dir_all(&config.path).await.map_err(|e| {
            ErrorKind::StorageError(anyhow::anyhow!(
                "Failed to create storage directory {}: {}",
                config.path.display(),
                e
            ))
        })?;

        let version = read_version(&config.path).await?;
        if version == 0 {
            upgrade_0_to_1(&config.path).await?;
        }
        write_version(&config.path, 1).await?;

        Ok(Self { config })
    }

    fn get_path(&self, p: &str) -> PathBuf {
        // Validate: p must be at least 2 chars for the sharding scheme.
        // Short or empty names are a client error, not a panic.
        let level1 = p.get(0..1).unwrap_or("");
        let level2 = p.get(0..2).unwrap_or(level1);
        self.config.path.join(level1).join(level2).join(p)
    }
}

#[async_trait]
impl StorageBackend for LocalBackend {
    async fn upload_file(
        &self,
        name: String,
        mut stream: &mut (dyn AsyncRead + Unpin + Send),
    ) -> ServerResult<RemoteFile> {
        let path = self.get_path(&name);
        let parent = path.parent().ok_or_else(|| {
            ErrorKind::StorageError(anyhow::anyhow!("Storage path has no parent: {}", path.display()))
        })?;
        fs::create_dir_all(parent).await.map_err(|e| {
            ErrorKind::StorageError(anyhow::anyhow!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
        let mut file = File::create(self.get_path(&name)).await.map_err(|e| {
            ErrorKind::StorageError(anyhow::anyhow!(
                "Failed to create file {}: {}",
                self.get_path(&name).display(),
                e
            ))
        })?;

        io::copy(&mut stream, &mut file)
            .await
            .map_err(ServerError::storage_error)?;

        Ok(RemoteFile::Local(LocalRemoteFile { name }))
    }

    async fn delete_file(&self, name: String) -> ServerResult<()> {
        fs::remove_file(self.get_path(&name))
            .await
            .map_err(ServerError::storage_error)?;

        Ok(())
    }

    async fn delete_file_db(&self, file: &RemoteFile) -> ServerResult<()> {
        let file = if let RemoteFile::Local(file) = file {
            file
        } else {
            return Err(ErrorKind::StorageError(anyhow::anyhow!(
                "Does not understand the remote file reference"
            ))
            .into());
        };

        fs::remove_file(self.get_path(&file.name))
            .await
            .map_err(ServerError::storage_error)?;

        Ok(())
    }

    async fn download_file(&self, name: String, _prefer_stream: bool) -> ServerResult<Download> {
        let file = File::open(self.get_path(&name))
            .await
            .map_err(ServerError::storage_error)?;

        Ok(Download::AsyncRead(Box::new(file)))
    }

    async fn download_file_db(
        &self,
        file: &RemoteFile,
        _prefer_stream: bool,
    ) -> ServerResult<Download> {
        let file = if let RemoteFile::Local(file) = file {
            file
        } else {
            return Err(ErrorKind::StorageError(anyhow::anyhow!(
                "Does not understand the remote file reference"
            ))
            .into());
        };

        let file = File::open(self.get_path(&file.name))
            .await
            .map_err(ServerError::storage_error)?;

        Ok(Download::AsyncRead(Box::new(file)))
    }

    async fn get_range(&self, name: String, offset: u64, len: u64) -> ServerResult<Bytes> {
        // A zero-length read is empty at any offset; don't even
        // touch the filesystem for it.
        if len == 0 {
            return Ok(Bytes::new());
        }

        let mut file = File::open(self.get_path(&name))
            .await
            .map_err(ServerError::storage_error)?;

        let file_len = file
            .metadata()
            .await
            .map_err(ServerError::storage_error)?
            .len();

        if offset > file_len {
            return Err(ErrorKind::StorageError(anyhow::anyhow!(
                "Range offset {} is past the end of the file ({} bytes)",
                offset,
                file_len
            ))
            .into());
        }

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(ServerError::storage_error)?;

        // The buffer grows only with bytes actually read, never
        // with the caller-supplied `len`, so a huge `len` cannot
        // force a huge allocation. `take` clamps the read at the
        // end of the file.
        let mut buf = Vec::new();
        file.take(len)
            .read_to_end(&mut buf)
            .await
            .map_err(ServerError::storage_error)?;

        Ok(Bytes::from(buf))
    }

    async fn make_db_reference(&self, name: String) -> ServerResult<RemoteFile> {
        Ok(RemoteFile::Local(LocalRemoteFile { name }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_backend() -> LocalBackend {
        LocalBackend {
            config: LocalStorageConfig {
                path: PathBuf::from("/tmp/test-storage"),
            },
        }
    }

    #[test]
    fn get_path_handles_empty_name() {
        // Adversarial: empty name must not panic on indexing
        let backend = test_backend();
        let path = backend.get_path("");
        // Should produce a valid path, not panic
        assert!(path.to_str().is_some());
    }

    #[test]
    fn get_path_handles_single_char_name() {
        // Adversarial: single char name must not panic on [0..2] indexing
        let backend = test_backend();
        let path = backend.get_path("a");
        assert!(path.to_str().is_some());
    }

    #[test]
    fn get_path_shards_normal_names() {
        // Validation: normal names are sharded correctly
        let backend = test_backend();
        let path = backend.get_path("abcdef123456");
        assert_eq!(path, PathBuf::from("/tmp/test-storage/a/ab/abcdef123456"));
    }

    /// Creates a backend rooted at a fresh temporary directory and
    /// uploads `data` under `name` through the real upload path.
    async fn backend_with_file(name: &str, data: &[u8]) -> (LocalBackend, PathBuf) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let root = std::env::temp_dir().join(format!(
            "bunker-local-range-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let backend = LocalBackend {
            config: LocalStorageConfig { path: root.clone() },
        };

        let mut stream: &[u8] = data;
        backend
            .upload_file(name.to_owned(), &mut stream)
            .await
            .unwrap();

        (backend, root)
    }

    #[tokio::test]
    async fn get_range_reads_exact_windows() {
        let data = b"0123456789";
        let (backend, root) = backend_with_file("rangefixture", data).await;

        // Validation: windows from the start, middle and end return
        // exactly the requested bytes.
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 0, 4)
                .await
                .unwrap(),
            Bytes::from_static(b"0123")
        );
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 2, 3)
                .await
                .unwrap(),
            Bytes::from_static(b"234")
        );
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 9, 1)
                .await
                .unwrap(),
            Bytes::from_static(b"9")
        );
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 0, 10)
                .await
                .unwrap(),
            Bytes::from_static(b"0123456789")
        );

        fs::remove_dir_all(root).await.ok();
    }

    #[tokio::test]
    async fn get_range_clamps_len_past_end() {
        let data = b"0123456789";
        let (backend, root) = backend_with_file("rangefixture", data).await;

        // Validation: a length running past the end of the file is
        // clamped to the bytes that remain.
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 8, 100)
                .await
                .unwrap(),
            Bytes::from_static(b"89")
        );

        // Adversarial: a huge length is clamped the same way and
        // must not drive a huge allocation.
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 0, u64::MAX)
                .await
                .unwrap(),
            Bytes::from_static(b"0123456789")
        );

        fs::remove_dir_all(root).await.ok();
    }

    #[tokio::test]
    async fn get_range_at_and_past_eof() {
        let data = b"0123456789";
        let (backend, root) = backend_with_file("rangefixture", data).await;

        // Validation: an offset exactly at the end of the file is
        // an empty read, and a zero length is empty at any offset.
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 10, 5)
                .await
                .unwrap(),
            Bytes::new()
        );
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 3, 0)
                .await
                .unwrap(),
            Bytes::new()
        );
        assert_eq!(
            backend
                .get_range("rangefixture".to_owned(), 0, 0)
                .await
                .unwrap(),
            Bytes::new()
        );

        // Adversarial: an offset past the end of the file is an
        // error, including the largest representable offset.
        assert!(backend
            .get_range("rangefixture".to_owned(), 11, 5)
            .await
            .is_err());
        assert!(backend
            .get_range("rangefixture".to_owned(), u64::MAX, 5)
            .await
            .is_err());

        fs::remove_dir_all(root).await.ok();
    }

    #[tokio::test]
    async fn get_range_missing_file_is_an_error() {
        // Adversarial: ranging over a file that does not exist is
        // an error, not an empty read or a panic.
        let backend = test_backend();
        assert!(backend
            .get_range("doesnotexist".to_owned(), 0, 4)
            .await
            .is_err());
    }
}
