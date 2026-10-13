// /qompassai/bunker/server/src/gc.rs
// Qompass AI Bunker Server Garbage Collection
// Copyright (C) 2025 Qompass AI, All rights reserved
/////////////////////////////////////////////////////
//! Garbage collection.
use std::sync::Arc;
use std::time::Duration;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::future::join_all;
use sea_orm::entity::prelude::*;
use sea_orm::query::QuerySelect;
use sea_orm::sea_query::{LockBehavior, LockType, Query};
use sea_orm::{ConnectionTrait, DatabaseConnection, FromQueryResult, QueryOrder};
use tokio::sync::Semaphore;
use tokio::time;
use tracing::instrument;
use super::{State, StateInner};
use crate::config::Config;
use crate::database::entity::artifact_upload::{self, Entity as ArtifactUpload};
use crate::database::entity::cache::{self, Entity as Cache};
use crate::database::entity::chunk::{self, ChunkState, Entity as Chunk};
use crate::database::entity::chunkref::{self, Entity as ChunkRef};
use crate::database::entity::nar::{self, Entity as Nar, NarState};
use crate::database::entity::object::{self, Entity as Object};
use crate::storage::{artifact_upload_key, delete_file_if_present, StorageBackend};
#[derive(Debug, FromQueryResult)]
struct CacheIdAndRetentionPeriod {
    id: i64,
    name: String,
    retention_period: i32,
}

/// Runs garbage collection periodically.
pub async fn run_garbage_collection(config: Config) {
    let interval = config.garbage_collection.interval;

    if interval == Duration::ZERO {
        // disabled
        return;
    }

    loop {
        // We don't stop even if it errors
        if let Err(e) = run_garbage_collection_once(config.clone()).await {
            tracing::warn!("Garbage collection failed: {}", e);
        }

        time::sleep(interval).await;
    }
}

/// Runs garbage collection once.
#[instrument(skip_all)]
pub async fn run_garbage_collection_once(config: Config) -> Result<()> {
    tracing::info!("Running garbage collection...");

    let state = StateInner::new(config).await;
    run_time_based_garbage_collection(&state).await?;
    run_reap_orphan_nars(&state).await?;
    run_reap_orphan_chunks(&state).await?;
    run_reap_expired_artifact_uploads(&state).await?;

    Ok(())
}

#[instrument(skip_all)]
async fn run_time_based_garbage_collection(state: &State) -> Result<()> {
    let db = state.database().await?;
    let now = Utc::now();

    let default_retention_period = state.config.garbage_collection.default_retention_period;
    let retention_period =
        cache::Column::RetentionPeriod.if_null(default_retention_period.as_secs() as i32);

    // Find caches with retention periods set
    let caches = Cache::find()
        .select_only()
        .column(cache::Column::Id)
        .column(cache::Column::Name)
        .column_as(retention_period.clone(), "retention_period")
        .filter(retention_period.ne(0))
        .into_model::<CacheIdAndRetentionPeriod>()
        .all(db)
        .await?;

    tracing::info!(
        "Found {} caches subject to time-based garbage collection",
        caches.len()
    );

    let mut objects_deleted = 0;

    for cache in caches {
        let period = ChronoDuration::seconds(cache.retention_period.into());
        let cutoff = now.checked_sub_signed(period).ok_or_else(|| {
            anyhow!(
                "Somehow subtracting retention period for cache {} underflowed",
                cache.name
            )
        })?;

        let deletion = Object::delete_many()
            .filter(object::Column::CacheId.eq(cache.id))
            .filter(object::Column::CreatedAt.lt(cutoff))
            .filter(
                object::Column::LastAccessedAt
                    .is_null()
                    .or(object::Column::LastAccessedAt.lt(cutoff)),
            )
            .exec(db)
            .await?;
        tracing::info!(
            "Deleted {} objects from {} (ID {})",
            deletion.rows_affected,
            cache.name,
            cache.id
        );
        objects_deleted += deletion.rows_affected;
    }

    tracing::info!("Deleted {} objects in total", objects_deleted);

    Ok(())
}
#[instrument(skip_all)]
async fn run_reap_orphan_nars(state: &State) -> Result<()> {
    let db = state.database().await?;
    // find all orphan NARs...
    let orphan_nar_ids = Query::select()
        .from(Nar)
        .expr(nar::Column::Id.into_expr())
        .left_join(
            Object,
            object::Column::NarId
                .into_expr()
                .eq(nar::Column::Id.into_expr()),
        )
        .and_where(object::Column::Id.is_null())
        .and_where(nar::Column::State.eq(NarState::Valid))
        .and_where(nar::Column::HoldersCount.eq(0))
        .lock_with_tables_behavior(LockType::Update, [Nar], LockBehavior::SkipLocked)
        .to_owned();
    // ... and simply delete them
    let deletion = Nar::delete_many()
        .filter(nar::Column::Id.in_subquery(orphan_nar_ids))
        .exec(db)
        .await?;
    tracing::info!("Deleted {} orphan NARs", deletion.rows_affected,);
    Ok(())
}
#[instrument(skip_all)]
async fn run_reap_orphan_chunks(state: &State) -> Result<()> {
    let db = state.database().await?;
    let storage = state.storage().await?;

    let orphan_chunk_limit = match db.get_database_backend() {
        // Arbitrarily chosen sensible value since there's no good default to choose from for MySQL
        sea_orm::DatabaseBackend::MySql => 1000,
        // Panic limit set by sqlx for postgresql: https://github.com/launchbadge/sqlx/issues/671#issuecomment-687043510
        sea_orm::DatabaseBackend::Postgres => u64::from(u16::MAX),
        // Default statement limit imposed by sqlite: https://www.sqlite.org/limits.html#max_variable_number
        sea_orm::DatabaseBackend::Sqlite => 500,
    };

    // find all orphan chunks...
    let orphan_chunk_ids = Query::select()
        .from(Chunk)
        .expr(chunk::Column::Id.into_expr())
        .left_join(
            ChunkRef,
            chunkref::Column::ChunkId
                .into_expr()
                .eq(chunk::Column::Id.into_expr()),
        )
        .and_where(chunkref::Column::Id.is_null())
        .and_where(chunk::Column::State.eq(ChunkState::Valid))
        .and_where(chunk::Column::HoldersCount.eq(0))
        .lock_with_tables_behavior(LockType::Update, [Chunk], LockBehavior::SkipLocked)
        .to_owned();

    // ... and transition their state to Deleted
    //
    // Deleted chunks are essentially invisible from our normal queries
    let transition_statement = {
        let change_state = Query::update()
            .table(Chunk)
            .value(chunk::Column::State, ChunkState::Deleted)
            .and_where(chunk::Column::Id.in_subquery(orphan_chunk_ids))
            .to_owned();
        db.get_database_backend().build(&change_state)
    };

    db.execute(transition_statement).await?;

    let orphan_chunks: Vec<chunk::Model> = Chunk::find()
        .filter(chunk::Column::State.eq(ChunkState::Deleted))
        .limit(orphan_chunk_limit)
        .all(db)
        .await?;

    if orphan_chunks.is_empty() {
        return Ok(());
    }

    // Delete the chunks from remote storage
    let delete_limit = Arc::new(Semaphore::new(20)); // TODO: Make this configurable
    let futures: Vec<_> = orphan_chunks
        .into_iter()
        .map(|chunk| {
            let delete_limit = delete_limit.clone();
            async move {
                let permit = delete_limit.acquire().await?;
                storage.delete_file_db(&chunk.remote_file.0).await?;
                drop(permit);
                Result::<_, anyhow::Error>::Ok(chunk.id)
            }
        })
        .collect();

    // Deletions can result in spurious failures, tolerate them
    //
    // Chunks that failed to be deleted from the remote storage will
    // just be stuck in Deleted state.
    //
    // TODO: Maybe have an interactive command to retry deletions?
    let deleted_chunk_ids: Vec<_> = join_all(futures)
        .await
        .into_iter()
        .filter(|r| {
            if let Err(e) = r {
                tracing::warn!("Deletion failed: {}", e);
            }

            r.is_ok()
        })
        .map(|r| r.unwrap())
        .collect();

    // Finally, delete them from the database
    let deletion = Chunk::delete_many()
        .filter(chunk::Column::Id.is_in(deleted_chunk_ids))
        .exec(db)
        .await?;

    tracing::info!("Deleted {} orphan chunks", deletion.rows_affected);

    Ok(())
}

#[instrument(skip_all)]
async fn run_reap_expired_artifact_uploads(state: &State) -> Result<()> {
    let db = state.database().await?;
    let storage = state.storage().await?;

    let batch_limit = match db.get_database_backend() {
        // The same per-backend bounds as the orphan-chunk reap
        // above: MySQL gets an arbitrarily chosen sensible
        // value, Postgres the sqlx panic limit, SQLite the
        // statement variable limit. The limit bounds the
        // `is_in` deletion below as well as the scan.
        sea_orm::DatabaseBackend::MySql => 1000,
        sea_orm::DatabaseBackend::Postgres => u64::from(u16::MAX),
        sea_orm::DatabaseBackend::Sqlite => 500,
    };

    reap_expired_artifact_uploads(db, storage.as_ref().as_ref(), Utc::now(), batch_limit).await?;

    Ok(())
}

/// Reaps expired artifact uploads: rows whose `expires_at`
/// has passed, together with the temp object each one names.
///
/// An upload row is bookkeeping with an expiry written at
/// creation, 24 hours out (see `crate::api::v1::artifacts`).
/// The upload handler deletes temp objects on every failure
/// path it controls, so a temp object that survives its row
/// means the server died mid-upload; the row is the only
/// record of the temp key, which is derived from the row's ID.
/// A row past its expiry is abandoned by definition — an
/// upload still `receiving` after its full TTL is a dead
/// upload, not a slow one — so the reap never races a live
/// upload inside the lifetime the protocol allows.
///
/// The discipline mirrors the orphan-chunk reap: a bounded
/// batch per pass, oldest first; storage before rows; and a
/// row is deleted only when its temp object is confirmed gone,
/// so a failed storage delete leaves the row for the next
/// pass instead of orphaning the object.
///
/// Returns the number of rows reaped.
async fn reap_expired_artifact_uploads(
    db: &DatabaseConnection,
    storage: &dyn StorageBackend,
    now: DateTime<Utc>,
    batch_limit: u64,
) -> Result<usize> {
    let expired = ArtifactUpload::find()
        .filter(artifact_upload::Column::ExpiresAt.lt(now))
        .order_by_asc(artifact_upload::Column::Id)
        .limit(batch_limit)
        .all(db)
        .await?;

    if expired.is_empty() {
        return Ok(0);
    }

    let mut reaped_ids: Vec<i64> = Vec::new();

    for upload in &expired {
        match delete_file_if_present(storage, &artifact_upload_key(upload.id)).await {
            Ok(_) => reaped_ids.push(upload.id),
            Err(e) => {
                tracing::warn!(
                    "Failed to delete the temp object of expired upload {}: {}",
                    upload.id,
                    e
                );
            }
        }
    }

    if reaped_ids.is_empty() {
        return Ok(0);
    }

    let deletion = ArtifactUpload::delete_many()
        .filter(artifact_upload::Column::Id.is_in(reaped_ids))
        .exec(db)
        .await?;

    tracing::info!("Reaped {} expired artifact uploads", deletion.rows_affected);

    Ok(deletion.rows_affected as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use sea_orm::ActiveValue::Set;
    use sea_orm::Database;

    use crate::database::entity::Json as DbJson;
    use crate::database::migration::{Migrator, MigratorTrait};
    use crate::storage::{LocalBackend, LocalStorageConfig};

    /// Everything one test needs: a migrated database, a local
    /// storage backend in a temp dir, and one cache row.
    struct Rig {
        db: DatabaseConnection,
        storage: LocalBackend,
        root: PathBuf,
        cache_id: i64,
    }

    async fn rig(test: &str) -> Rig {
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let root = std::env::temp_dir().join(format!(
            "bunker-gc-artifact-test-{}-{}-{}",
            test,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        tokio::fs::create_dir_all(&root).await.unwrap();

        let url = format!("sqlite://{}/test.db?mode=rwc", root.display());
        let db = Database::connect(&url).await.unwrap();
        Migrator::up(&db, None).await.unwrap();

        let storage_config: LocalStorageConfig =
            serde_json::from_value(serde_json::json!({ "path": root.join("storage") })).unwrap();
        let storage = LocalBackend::new(storage_config).await.unwrap();

        let now = Utc::now();
        let cache = cache::ActiveModel {
            name: Set("gc-cache".to_owned()),
            keypair: Set("test-keypair".to_owned()),
            is_public: Set(false),
            store_dir: Set("/nix/store".to_owned()),
            priority: Set(40),
            upstream_cache_key_names: Set(DbJson(Vec::new())),
            created_at: Set(now),
            deleted_at: Set(None),
            retention_period: Set(None),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        Rig {
            db,
            storage,
            root,
            cache_id: cache.id,
        }
    }

    /// Inserts one upload row in the given state, expiring at
    /// the given time, and returns its ID.
    async fn insert_upload(rig: &Rig, state: &str, expires_at: DateTime<Utc>) -> i64 {
        artifact_upload::ActiveModel {
            cache_id: Set(rig.cache_id),
            name: Set("widget".to_owned()),
            version: Set("1.0.0".to_owned()),
            filename: Set("widget_1.0.0.tar.gz".to_owned()),
            expected_sha256: Set(None),
            expected_size: Set(None),
            state: Set(state.to_owned()),
            created_at: Set(expires_at - ChronoDuration::hours(25)),
            expires_at: Set(expires_at),
            ..Default::default()
        }
        .insert(&rig.db)
        .await
        .unwrap()
        .id
    }

    /// Places a temp object for an upload row, as an upload
    /// that died mid-receive would have left behind.
    async fn place_temp_object(rig: &Rig, upload_id: i64) {
        let mut bytes: &[u8] = b"partial bytes";
        rig.storage
            .upload_file(artifact_upload_key(upload_id), &mut bytes)
            .await
            .unwrap();
    }

    async fn upload_row_ids(rig: &Rig) -> Vec<i64> {
        let mut ids: Vec<i64> = ArtifactUpload::find()
            .all(&rig.db)
            .await
            .unwrap()
            .iter()
            .map(|upload| upload.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Counts files under the storage root, excluding the
    /// backend's VERSION marker — i.e. counts stored objects.
    fn stored_object_count(root: &Path) -> usize {
        fn walk(dir: &Path) -> usize {
            let mut count = 0;
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        count += walk(&path);
                    } else if entry.file_name() != "VERSION" {
                        count += 1;
                    }
                }
            }
            count
        }

        walk(&root.join("storage"))
    }

    #[tokio::test]
    async fn reaper_collects_expired_uploads_and_their_temp_objects() {
        let rig = rig("expired").await;
        let now = Utc::now();

        // An abandoned upload: expired, still `receiving`, its
        // temp object left behind.
        let abandoned = insert_upload(&rig, "receiving", now - ChronoDuration::hours(1)).await;
        place_temp_object(&rig, abandoned).await;

        // A completed upload whose bookkeeping row has also
        // expired. Its temp object is long gone (it was moved
        // to the artifact's final key at completion).
        let completed = insert_upload(&rig, "completed", now - ChronoDuration::hours(2)).await;

        // A live upload inside its TTL: row and temp object
        // must both survive the pass untouched.
        let fresh = insert_upload(&rig, "receiving", now + ChronoDuration::hours(23)).await;
        place_temp_object(&rig, fresh).await;

        assert_eq!(stored_object_count(&rig.root), 2);

        let reaped = reap_expired_artifact_uploads(&rig.db, &rig.storage, now, 500)
            .await
            .unwrap();
        assert_eq!(reaped, 2);

        // Only the fresh row remains, with its temp object.
        let remaining = upload_row_ids(&rig).await;
        assert_eq!(remaining, vec![fresh]);
        assert!(!remaining.contains(&abandoned));
        assert!(!remaining.contains(&completed));
        assert_eq!(stored_object_count(&rig.root), 1);
        let bytes = rig
            .storage
            .get_range(artifact_upload_key(fresh), 0, 13)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"partial bytes");

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn reaper_respects_the_batch_bound() {
        let rig = rig("bounded").await;
        let now = Utc::now();

        for _ in 0..3 {
            insert_upload(&rig, "failed", now - ChronoDuration::hours(1)).await;
        }

        // A pass is bounded: two of three expired rows go.
        let reaped = reap_expired_artifact_uploads(&rig.db, &rig.storage, now, 2)
            .await
            .unwrap();
        assert_eq!(reaped, 2);
        assert_eq!(upload_row_ids(&rig).await.len(), 1);

        // The next pass finishes the backlog.
        let reaped = reap_expired_artifact_uploads(&rig.db, &rig.storage, now, 2)
            .await
            .unwrap();
        assert_eq!(reaped, 1);
        assert_eq!(upload_row_ids(&rig).await.len(), 0);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }
}
