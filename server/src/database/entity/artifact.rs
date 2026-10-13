//! A named release artifact in a binary cache.
//!
//! An artifact is a single whole file (a release binary, tarball,
//! package, ...) identified within its cache by the validated
//! `(name, version, filename)` triple. The file's bytes live in the
//! storage backend under a server-generated key derived from the
//! cache ID and the SHA-256 digest (see
//! `crate::storage::artifact_key`); the user-facing name, version
//! and filename exist only in this row, never in a storage key.
//!
//! Partial uploads are never represented here: an artifact row is
//! only created once the upload's bytes have been received and
//! verified. In-flight upload state lives in
//! [`super::artifact_upload`].

use sea_orm::entity::prelude::*;

pub type ArtifactModel = Model;

/// A named release artifact in a binary cache.
#[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "artifact")]
pub struct Model {
    /// Unique numeric ID of the artifact.
    #[sea_orm(primary_key)]
    pub id: i64,

    /// The cache this artifact belongs to.
    ///
    /// Deleting the cache deletes its artifacts
    /// (`ON DELETE CASCADE`).
    #[sea_orm(indexed)]
    pub cache_id: i64,

    /// Artifact name (validated token, e.g. `light-show`).
    #[sea_orm(column_type = "String(Some(50))")]
    pub name: String,

    /// Artifact version (validated token, e.g. `1.2.0`).
    ///
    /// Never the reserved token `latest`; that alias is resolved
    /// through [`super::artifact_latest`].
    #[sea_orm(column_type = "String(Some(64))")]
    pub version: String,

    /// The file's name (validated token, e.g.
    /// `light-show_1.2.0_linux-x86_64.tar.gz`).
    ///
    /// Data only: it is never used as a filesystem path or storage
    /// key.
    #[sea_orm(column_type = "String(Some(128))")]
    pub filename: String,

    /// Size of the file in bytes, verified against the received
    /// bytes at upload time.
    pub size: i64,

    /// SHA-256 digest of the file's bytes, in its binary form:
    /// exactly the 32 raw digest bytes, not a hex encoding.
    pub sha256: Vec<u8>,

    /// Content type of the file, derived from the filename
    /// extension at upload time.
    #[sea_orm(column_type = "String(Some(128))")]
    pub content_type: String,

    /// Timestamp when the artifact was created.
    pub created_at: ChronoDateTimeUtc,

    /// Timestamp when the artifact was last updated.
    pub updated_at: ChronoDateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::cache::Entity",
        from = "Column::CacheId",
        to = "super::cache::Column::Id",
        on_delete = "Cascade"
    )]
    Cache,
}

impl Related<super::cache::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cache.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
