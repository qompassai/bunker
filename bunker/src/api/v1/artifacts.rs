//! Artifact upload API.
//!
//! Artifacts are opaque release binaries (tarballs, installers,
//! disk images) stored next to the Nix binary cache, addressed by
//! the SHA-256 digest of their contents. They share the cache's
//! JWT authorization model but none of the Nix protocol machinery.

use serde::{Deserialize, Serialize};

use crate::cache::CacheName;

/// Header carrying the JSON-encoded [`ArtifactUploadRequest`].
///
/// This mirrors the `X-Bunker-Nar-Info` header of the NAR upload
/// endpoint: metadata travels in a header so the request body can
/// be the raw artifact bytes, streamed end to end.
pub const BUNKER_ARTIFACT_INFO: &str = "X-Bunker-Artifact-Info";

/// Header carrying the hex-encoded SHA-256 digest the client
/// computed for the artifact it is uploading.
///
/// Optional. When present, the server verifies the digest of the
/// bytes it actually received against this value and rejects the
/// upload on mismatch.
pub const BUNKER_ARTIFACT_SHA256: &str = "X-Bunker-Artifact-Sha256";

/// Header carrying the size, in bytes, of the artifact the client
/// is uploading.
///
/// Optional. When present, the server verifies the number of bytes
/// it actually received against this value and rejects the upload
/// on mismatch.
pub const BUNKER_ARTIFACT_SIZE: &str = "X-Bunker-Artifact-Size";

/// Metadata of an artifact upload.
///
/// The artifact bytes themselves are the request body; everything
/// else the server needs travels in the
/// [`BUNKER_ARTIFACT_INFO`] header as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactUploadRequest {
    /// The cache the artifact belongs to.
    pub cache: CacheName,

    /// Name of the artifact (e.g. `light-show`).
    ///
    /// Together with `cache`, this is the identity the `latest`
    /// pointer is tracked for.
    pub name: String,

    /// Version of the artifact (e.g. `1.4.2`).
    pub version: String,

    /// Bare file name of the artifact (e.g.
    /// `light-show_1.4.2_linux-x86_64.tar.gz`).
    ///
    /// This is a display and download name only. It never becomes
    /// part of a storage path; objects are stored under a key
    /// derived from their content digest.
    pub filename: String,
}

/// The server's record of a completed artifact upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactUploadResponse {
    /// The cache the artifact was uploaded to.
    pub cache: CacheName,

    /// Name of the artifact.
    pub name: String,

    /// Version of the artifact.
    pub version: String,

    /// Bare file name of the artifact.
    pub filename: String,

    /// Hex-encoded SHA-256 digest of the artifact's contents,
    /// computed by the server from the bytes it received.
    pub sha256: String,

    /// Size of the artifact in bytes, counted by the server from
    /// the bytes it received.
    pub size: u64,
}
