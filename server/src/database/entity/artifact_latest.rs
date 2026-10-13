//! The `latest` pointer for an artifact name in a cache.
//!
//! There is at most one row per `(cache_id, name)`: it names the
//! artifact a `latest` request resolves to. The pointer is the only
//! source of truth for `latest` — there is no "newest by upload
//! time" guessing — and it moves only when an upload is finalized.
//! Deleting the cache, or the artifact it points at, deletes the
//! pointer (`ON DELETE CASCADE`); `latest` then resolves to
//! nothing until the next finalized upload.

use sea_orm::entity::prelude::*;

pub type ArtifactLatestModel = Model;

/// The `latest` pointer for an artifact name in a cache.
#[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "artifact_latest")]
pub struct Model {
    /// The cache the pointer belongs to. Part of the primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub cache_id: i64,

    /// Artifact name (validated token). Part of the primary key.
    #[sea_orm(primary_key, auto_increment = false, column_type = "String(Some(50))")]
    pub name: String,

    /// The artifact `latest` currently resolves to for
    /// `(cache_id, name)`.
    pub latest_artifact_id: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::artifact::Entity",
        from = "Column::LatestArtifactId",
        to = "super::artifact::Column::Id",
        on_delete = "Cascade"
    )]
    Artifact,

    #[sea_orm(
        belongs_to = "super::cache::Entity",
        from = "Column::CacheId",
        to = "super::cache::Column::Id",
        on_delete = "Cascade"
    )]
    Cache,
}

impl Related<super::artifact::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Artifact.def()
    }
}

impl Related<super::cache::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cache.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
