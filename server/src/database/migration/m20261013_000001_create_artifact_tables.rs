//! Creates the artifact-serving tables: `artifact`,
//! `artifact_upload` and `artifact_latest`.
//!
//! Artifacts are per-cache. Every foreign key to `cache` is
//! `ON DELETE CASCADE`, so destroying a cache destroys its
//! artifacts, its in-flight uploads and its `latest` pointers.
//! `artifact_latest.latest_artifact_id` cascades as well, so a
//! pointer never outlives the artifact it names.

use sea_orm_migration::prelude::*;

use crate::database::entity::artifact;
use crate::database::entity::artifact_latest;
use crate::database::entity::artifact_upload;
use crate::database::entity::cache;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261013_000001_create_artifact_tables"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // artifact
        manager
            .create_table(
                Table::create()
                    .table(artifact::Entity)
                    .col(
                        ColumnDef::new(artifact::Column::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::CacheId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::Name)
                            .string_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::Version)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::Filename)
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::Size)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::Sha256)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::ContentType)
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact::Column::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk_artifact_cache")
                            .from_tbl(artifact::Entity)
                            .from_col(artifact::Column::CacheId)
                            .to_tbl(cache::Entity)
                            .to_col(cache::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-artifact-cache-id")
                    .table(artifact::Entity)
                    .col(artifact::Column::CacheId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uniq-artifact-cache-name-version-filename")
                    .table(artifact::Entity)
                    .col(artifact::Column::CacheId)
                    .col(artifact::Column::Name)
                    .col(artifact::Column::Version)
                    .col(artifact::Column::Filename)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // artifact_upload
        manager
            .create_table(
                Table::create()
                    .table(artifact_upload::Entity)
                    .col(
                        ColumnDef::new(artifact_upload::Column::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::CacheId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::Name)
                            .string_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::Version)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::Filename)
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::ExpectedSha256)
                            .binary_len(32)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::ExpectedSize)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::State)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_upload::Column::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk_artifact_upload_cache")
                            .from_tbl(artifact_upload::Entity)
                            .from_col(artifact_upload::Column::CacheId)
                            .to_tbl(cache::Entity)
                            .to_col(cache::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-artifact-upload-cache-id")
                    .table(artifact_upload::Entity)
                    .col(artifact_upload::Column::CacheId)
                    .to_owned(),
            )
            .await?;

        // artifact_latest
        manager
            .create_table(
                Table::create()
                    .table(artifact_latest::Entity)
                    .col(
                        ColumnDef::new(artifact_latest::Column::CacheId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_latest::Column::Name)
                            .string_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(artifact_latest::Column::LatestArtifactId)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-artifact-latest")
                            .col(artifact_latest::Column::CacheId)
                            .col(artifact_latest::Column::Name),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk_artifact_latest_cache")
                            .from_tbl(artifact_latest::Entity)
                            .from_col(artifact_latest::Column::CacheId)
                            .to_tbl(cache::Entity)
                            .to_col(cache::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk_artifact_latest_artifact")
                            .from_tbl(artifact_latest::Entity)
                            .from_col(artifact_latest::Column::LatestArtifactId)
                            .to_tbl(artifact::Entity)
                            .to_col(artifact::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse creation order: dependents first.
        manager
            .drop_table(Table::drop().table(artifact_latest::Entity).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(artifact_upload::Entity).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(artifact::Entity).to_owned())
            .await
    }
}
