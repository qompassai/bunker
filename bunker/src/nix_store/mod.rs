#[cfg(feature = "nix_store")]
#[allow(unsafe_code)]
mod bindings;
#[cfg(feature = "nix_store")]
mod nix_store;
use crate::error::{BunkerError, BunkerResult};
use crate::hash::Hash;
use lazy_static::lazy_static;
#[cfg(feature = "nix_store")]
pub use nix_store::NixStore;
use regex::Regex;
use serde::{Deserialize, Serialize, de};
use std::ffi::OsStr;
#[cfg(target_family = "unix")]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[cfg(test)]
pub mod tests;
pub const STORE_PATH_HASH_LEN: usize = 32;
pub const STORE_PATH_HASH_REGEX_FRAGMENT: &str = "[0123456789abcdfghijklmnpqrsvwxyz]{32}";

lazy_static! {
    static ref STORE_PATH_HASH_REGEX: Regex = {
        Regex::new(&format!("^{}$", STORE_PATH_HASH_REGEX_FRAGMENT)).unwrap()
    };

    /// Regex for a valid store base name.
    ///
    /// A base name consists of two parts: A hash and a human-readable
    /// label/name. The format of the hash is described in `StorePathHash`.
    ///
    /// The human-readable name can only contain the following characters:
    ///
    /// - A-Za-z0-9
    /// - `+-._?=`
    ///
    /// See the Nix implementation in `src/libstore/path.cc`.
    static ref STORE_BASE_NAME_REGEX: Regex = {
        Regex::new(r"^[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+-._?=]+$").unwrap()
    };
}

/// A path in a Nix store.
///
/// This must be a direct child of the store. This path may or
/// may not actually exist.
///
/// This guarantees that the base name is of valid format.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct StorePath {
    /// Base name of the store path.
    ///
    /// For example, for `/nix/store/ia70ss13m22znbl8khrf2hq72qmh5drr-ruby-2.7.5`,
    /// this would be `ia70ss13m22znbl8khrf2hq72qmh5drr-ruby-2.7.5`.
    base_name: PathBuf,
}

/// A fixed-length store path hash.
///
/// For example, for `/nix/store/ia70ss13m22znbl8khrf2hq72qmh5drr-ruby-2.7.5`,
/// this would be `ia70ss13m22znbl8khrf2hq72qmh5drr`.
///
/// It must contain exactly 32 "base-32 characters". Nix's special scheme
/// include the following valid characters: "0123456789abcdfghijklmnpqrsvwxyz"
/// ('e', 'o', 'u', 't' are banned).
///
/// Examples of invalid store path hashes:
///
/// - "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
/// - "IA70SS13M22ZNBL8KHRF2HQ72QMH5DRR"
/// - "whatevenisthisthing"
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize)]
pub struct StorePathHash(String);

/// Information on a valid store path.
#[derive(Debug)]
pub struct ValidPathInfo {
    /// The store path.
    pub path: StorePath,

    /// Hash of the NAR.
    pub nar_hash: Hash,

    /// Size of the NAR.
    pub nar_size: u64,

    /// References.
    ///
    /// This list only contains base names of the paths.
    pub references: Vec<PathBuf>,

    /// Signatures.
    pub sigs: Vec<String>,

    /// Content Address.
    pub ca: Option<String>,
}

#[cfg_attr(not(feature = "nix_store"), allow(dead_code))]
impl StorePath {
    /// Creates a StorePath with a base name.
    fn from_base_name(base_name: PathBuf) -> BunkerResult<Self> {
        let s =
            base_name
                .as_os_str()
                .to_str()
                .ok_or_else(|| BunkerError::InvalidStorePathName {
                    base_name: base_name.clone(),
                    reason: "Name contains non-UTF-8 characters",
                })?;

        if !STORE_BASE_NAME_REGEX.is_match(s) {
            return Err(BunkerError::InvalidStorePathName {
                base_name,
                reason: "Name is of invalid format",
            });
        }

        Ok(Self { base_name })
    }

    /// Creates a StorePath with a known valid base name.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the name is of a valid format (refer
    /// to the documentations for `STORE_BASE_NAME_REGEX`). Other operations
    /// with this object will assume it's valid.
    #[allow(unsafe_code)]
    unsafe fn from_base_name_unchecked(base_name: PathBuf) -> Self {
        Self { base_name }
    }

    /// Gets the hash portion of the store path.
    #[cfg(target_family = "unix")]
    pub fn to_hash(&self) -> StorePathHash {
        // Safety: We have already validated the format of the base name,
        // including the hash part. The name is guaranteed valid UTF-8.
        #[allow(unsafe_code)]
        unsafe {
            let s = std::str::from_utf8_unchecked(self.base_name.as_os_str().as_bytes());
            let hash = s[..STORE_PATH_HASH_LEN].to_string();
            StorePathHash::new_unchecked(hash)
        }
    }

    /// Returns the human-readable name.
    #[cfg(target_family = "unix")]
    pub fn name(&self) -> String {
        // Safety: Already checked
        #[allow(unsafe_code)]
        unsafe {
            let s = std::str::from_utf8_unchecked(self.base_name.as_os_str().as_bytes());
            s[STORE_PATH_HASH_LEN + 1..].to_string()
        }
    }

    pub fn as_os_str(&self) -> &OsStr {
        self.base_name.as_os_str()
    }

    #[cfg_attr(not(feature = "nix_store"), allow(dead_code))]
    #[cfg(target_family = "unix")]
    fn as_base_name_bytes(&self) -> &[u8] {
        self.base_name.as_os_str().as_bytes()
    }
}

impl StorePathHash {
    /// Creates a store path hash from a string.
    pub fn new(hash: String) -> BunkerResult<Self> {
        if hash.as_bytes().len() != STORE_PATH_HASH_LEN {
            return Err(BunkerError::InvalidStorePathHash {
                hash,
                reason: "Hash is of invalid length",
            });
        }

        if !STORE_PATH_HASH_REGEX.is_match(&hash) {
            return Err(BunkerError::InvalidStorePathHash {
                hash,
                reason: "Hash is of invalid format",
            });
        }

        Ok(Self(hash))
    }

    /// Creates a store path hash from a string, without checking its validity.
    ///
    /// # Safety
    ///
    /// The caller must make sure that it is of expected length and format.
    #[allow(unsafe_code)]
    pub unsafe fn new_unchecked(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for StorePathHash {
    /// Deserializes a potentially-invalid store path hash.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use de::Error;
        String::deserialize(deserializer)
            .and_then(|s| Self::new(s).map_err(|e| Error::custom(e.to_string())))
    }
}

#[cfg_attr(not(feature = "nix_store"), allow(dead_code))]
fn to_base_name(store_dir: &Path, path: &Path) -> BunkerResult<PathBuf> {
    if let Ok(remaining) = path.strip_prefix(store_dir) {
        let first = remaining
            .iter()
            .next()
            .ok_or_else(|| BunkerError::InvalidStorePath {
                path: path.to_owned(),
                reason: "Path is store directory itself",
            })?;

        if first.len() < STORE_PATH_HASH_LEN {
            Err(BunkerError::InvalidStorePath {
                path: path.to_owned(),
                reason: "Path is too short",
            })
        } else {
            Ok(PathBuf::from(first))
        }
    } else {
        Err(BunkerError::InvalidStorePath {
            path: path.to_owned(),
            reason: "Path is not in store directory",
        })
    }
}
