//! An in-flight (partial) artifact upload.
//!
//! Upload state lives only in this table, never as an
//! [`super::artifact`] row: an artifact row exists only once its
//! bytes have been fully received and verified. A row here records
//! what an uploader declared up front (optionally the expected
//! digest and size), the upload's state as free text (e.g.
//! `receiving`), and when the attempt expires so abandoned uploads
//! can be reaped. Finishing or abandoning an upload deletes its row
//! here; finalizing creates the artifact row.

use sea_orm::entity::prelude::*;

pub type ArtifactUploadModel = Model;

/// An in-flight (partial) artifact upload.
#[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "artifact_upload")]
pub struct Model {
    /// Unique numeric ID of the upload.
    #[sea_orm(primary_key)]
    pub id: i64,

    /// The cache the artifact is being uploaded to.
    ///
    /// Deleting the cache deletes its in-flight uploads
    /// (`ON DELETE CASCADE`).
    #[sea_orm(indexed)]
    pub cache_id: i64,

    /// Artifact name (validated token).
    #[sea_orm(column_type = "String(Some(50))")]
    pub name: String,

    /// Artifact version (validated token, never `latest`).
    #[sea_orm(column_type = "String(Some(64))")]
    pub version: String,

    /// The file's name (validated token). Data only; never a
    /// filesystem path or storage key.
    #[sea_orm(column_type = "String(Some(128))")]
    pub filename: String,

    /// SHA-256 digest the uploader declared for the file, in its
    /// binary form (exactly 32 raw digest bytes), if one was
    /// declared. A claim to be verified against the received
    /// bytes, never trusted.
    pub expected_sha256: Option<Vec<u8>>,

    /// Size in bytes the uploader declared for the file, if one
    /// was declared. A claim to be verified, never trusted.
    pub expected_size: Option<i64>,

    /// State of the upload, as text (e.g. `receiving`).
    pub state: String,

    /// Timestamp when the upload was created.
    pub created_at: ChronoDateTimeUtc,

    /// Timestamp when the upload attempt expires and may be
    /// reaped.
    pub expires_at: ChronoDateTimeUtc,
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
