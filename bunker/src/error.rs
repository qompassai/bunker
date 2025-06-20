//! Error handling.

use std::error::Error as StdError;
use std::io;
use std::path::PathBuf;

use displaydoc::Display;

pub type BunkerResult<T> = Result<T, BunkerError>;

/// An error.
#[derive(Debug, Display)]
pub enum BunkerError {
    /// Invalid store path {path:?}: {reason}
    InvalidStorePath { path: PathBuf, reason: &'static str },

    /// Invalid store path base name {base_name:?}: {reason}
    InvalidStorePathName {
        base_name: PathBuf,
        reason: &'static str,
    },

    /// Invalid store path hash "{hash}": {reason}
    InvalidStorePathHash { hash: String, reason: &'static str },

    /// Invalid cache name "{name}"
    InvalidCacheName { name: String },

    /// Signing error: {0}
    SigningError(super::signing::Error),

    /// Hashing error: {0}
    HashError(super::hash::Error),

    /// I/O error: {error}.
    IoError { error: io::Error },

    /// Unknown C++ exception: {exception}.
    CxxError { exception: String },
}

impl BunkerError {
    pub fn name(&self) -> &'static str {
        match self {
            Self::InvalidStorePath { .. } => "InvalidStorePath",
            Self::InvalidStorePathName { .. } => "InvalidStorePathName",
            Self::InvalidStorePathHash { .. } => "InvalidStorePathHash",
            Self::InvalidCacheName { .. } => "InvalidCacheName",
            Self::SigningError(_) => "SigningError",
            Self::HashError(_) => "HashError",
            Self::IoError { .. } => "IoError",
            Self::CxxError { .. } => "CxxError",
        }
    }
}

impl StdError for BunkerError {}

#[cfg(feature = "nix_store")]
impl From<cxx::Exception> for BunkerError {
    fn from(exception: cxx::Exception) -> Self {
        Self::CxxError {
            exception: exception.what().to_string(),
        }
    }
}

impl From<io::Error> for BunkerError {
    fn from(error: io::Error) -> Self {
        Self::IoError { error }
    }
}

impl From<super::signing::Error> for BunkerError {
    fn from(error: super::signing::Error) -> Self {
        Self::SigningError(error)
    }
}

impl From<super::hash::Error> for BunkerError {
    fn from(error: super::hash::Error) -> Self {
        Self::HashError(error)
    }
}
