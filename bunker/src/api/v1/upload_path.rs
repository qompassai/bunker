use serde::{Deserialize, Serialize};
use serde_with::{DefaultOnError, serde_as};

use crate::cache::CacheName;
use crate::hash::Hash;
use crate::nix_store::StorePathHash;

pub const BUNKER_NAR_INFO: &str = "X-Bunker-Nar-Info";
pub const BUNKER_NAR_INFO_PREAMBLE_SIZE: &str = "X-Bunker-Nar-Info-Preamble-Size";
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadPathNarInfo {
    pub cache: CacheName,
    pub store_path_hash: StorePathHash,
    pub store_path: String,
    pub references: Vec<String>,
    pub system: Option<String>,
    pub deriver: Option<String>,
    pub sigs: Vec<String>,
    pub ca: Option<String>,
    pub nar_hash: Hash,
    pub nar_size: usize,
}
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadPathResult {
    #[serde_as(deserialize_as = "DefaultOnError")]
    pub kind: UploadPathResultKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<usize>,
    pub frac_deduplicated: Option<f64>,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum UploadPathResultKind {
    Uploaded,
    Deduplicated,
}
impl Default for UploadPathResultKind {
    fn default() -> Self {
        Self::Uploaded
    }
}
