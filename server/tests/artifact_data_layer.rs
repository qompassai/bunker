//! Data-layer tests for artifact serving (M1).
//!
//! These tests exercise the `artifact`, `artifact_upload` and
//! `artifact_latest` tables against a real migrated SQLite
//! database — the same backend the golden-corpus server runs on —
//! plus the GC-blindness invariant: a full garbage-collection pass
//! must never touch artifact rows.
//!
//! Roughly half the tests are validation (the data layer does what
//! it promises) and half are adversarial (constraints and cascades
//! actually reject or remove what they must).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use bunker_server::config::Config;
use bunker_server::database::entity::{
    artifact, artifact_latest, artifact_upload, cache, nar, object, Json,
};
use bunker_server::database::migration::{Migrator, MigratorTrait, SchemaManager};
use bunker_server::database::BunkerDatabase;
use bunker_server::gc::run_garbage_collection_once;
use chrono::{DateTime, Duration, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::ActiveValue::Set;
use sea_orm::{Database, DatabaseConnection, Statement};

/// Creates a fresh, fully migrated SQLite database in a unique
/// temporary directory. Returns the connection and the directory
/// (the caller removes it when done).
async fn fresh_db(test: &str) -> (DatabaseConnection, PathBuf) {
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let dir = std::env::temp_dir().join(format!(
        "bunker-artifact-db-test-{}-{}-{}",
        test,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let url = format!("sqlite://{}/test.db?mode=rwc", dir.display());
    let db = Database::connect(&url).await.unwrap();
    Migrator::up(&db, None).await.unwrap();

    (db, dir)
}

/// Current time truncated to whole seconds, so timestamps compare
/// equal after a database round trip on every backend.
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
}

async fn table_names(db: &DatabaseConnection) -> Vec<String> {
    db.query_all(Statement::from_string(
        sea_orm::DatabaseBackend::Sqlite,
        "SELECT name FROM sqlite_master WHERE type = 'table'".to_owned(),
    ))
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.try_get::<String>("", "name").unwrap())
    .collect()
}

async fn insert_cache(db: &DatabaseConnection, name: &str) -> i64 {
    insert_cache_with_retention(db, name, None).await
}

async fn insert_cache_with_retention(
    db: &DatabaseConnection,
    name: &str,
    retention_period: Option<i32>,
) -> i64 {
    let model = cache::ActiveModel {
        name: Set(name.to_owned()),
        keypair: Set("test-keypair".to_owned()),
        is_public: Set(true),
        store_dir: Set("/nix/store".to_owned()),
        priority: Set(40),
        upstream_cache_key_names: Set(Json(Vec::new())),
        created_at: Set(now()),
        deleted_at: Set(None),
        retention_period: Set(retention_period),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();

    model.id
}

async fn insert_artifact(
    db: &DatabaseConnection,
    cache_id: i64,
    name: &str,
    version: &str,
    filename: &str,
    digest_byte: u8,
) -> artifact::Model {
    let now = now();
    artifact::ActiveModel {
        cache_id: Set(cache_id),
        name: Set(name.to_owned()),
        version: Set(version.to_owned()),
        filename: Set(filename.to_owned()),
        size: Set(1234),
        sha256: Set(vec![digest_byte; 32]),
        content_type: Set("application/gzip".to_owned()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap()
}

async fn insert_upload(
    db: &DatabaseConnection,
    cache_id: i64,
    expected_sha256: Option<Vec<u8>>,
    expected_size: Option<i64>,
) -> artifact_upload::Model {
    let now = now();
    artifact_upload::ActiveModel {
        cache_id: Set(cache_id),
        name: Set("widget".to_owned()),
        version: Set("1.0.0".to_owned()),
        filename: Set("widget_1.0.0_linux-x86_64.tar.gz".to_owned()),
        expected_sha256: Set(expected_sha256),
        expected_size: Set(expected_size),
        state: Set("receiving".to_owned()),
        created_at: Set(now),
        expires_at: Set(now + Duration::hours(1)),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap()
}

// ----------------------------------------------------------------
// Validation
// ----------------------------------------------------------------

#[tokio::test]
async fn migration_up_down_round_trip() {
    let (db, dir) = fresh_db("roundtrip").await;

    // Up: all three artifact tables exist alongside the old ones.
    let names = table_names(&db).await;
    for table in ["artifact", "artifact_latest", "artifact_upload", "cache"] {
        assert!(names.iter().any(|n| n == table), "missing table {table}");
    }

    // Down: rolling back the artifact migration drops exactly its
    // three tables and leaves the pre-existing schema alone.
    let migrations = Migrator::migrations();
    let migration = migrations.last().unwrap();
    assert_eq!(migration.name(), "m20261013_000001_create_artifact_tables");

    let manager = SchemaManager::new(&db);
    migration.down(&manager).await.unwrap();

    let names = table_names(&db).await;
    for table in ["artifact", "artifact_latest", "artifact_upload"] {
        assert!(
            !names.iter().any(|n| n == table),
            "table {table} survived down"
        );
    }
    assert!(names.iter().any(|n| n == "cache"));

    // Up again: the tables come back and accept rows.
    migration.up(&manager).await.unwrap();
    let names = table_names(&db).await;
    for table in ["artifact", "artifact_latest", "artifact_upload"] {
        assert!(
            names.iter().any(|n| n == table),
            "missing table {table} after re-up"
        );
    }
    let cache_id = insert_cache(&db, "roundtrip").await;
    insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.tar.gz", 0x11).await;

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn artifact_crud_round_trip() {
    let (db, dir) = fresh_db("crud").await;
    let cache_id = insert_cache(&db, "crud").await;

    let created = insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.tar.gz", 0xab).await;

    // Read back: every column survives, including the digest in its
    // binary form (32 raw bytes, not hex text).
    let found = artifact::Entity::find_by_id(created.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found, created);
    assert_eq!(found.sha256, vec![0xabu8; 32]);
    assert_eq!(found.size, 1234);
    assert_eq!(found.content_type, "application/gzip");

    // Update.
    let updated_at = now();
    artifact::ActiveModel {
        id: Set(created.id),
        content_type: Set("application/zip".to_owned()),
        updated_at: Set(updated_at),
        ..Default::default()
    }
    .update(&db)
    .await
    .unwrap();

    let found = artifact::Entity::find_by_id(created.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.content_type, "application/zip");
    assert_eq!(found.updated_at, updated_at);

    // Delete.
    artifact::Entity::delete_by_id(created.id)
        .exec(&db)
        .await
        .unwrap();
    assert!(artifact::Entity::find_by_id(created.id)
        .one(&db)
        .await
        .unwrap()
        .is_none());

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn artifact_upload_records_partial_state_only() {
    let (db, dir) = fresh_db("upload").await;
    let cache_id = insert_cache(&db, "upload").await;

    // An upload with declared expectations.
    let upload = insert_upload(&db, cache_id, Some(vec![0x42; 32]), Some(1234)).await;
    let found = artifact_upload::Entity::find_by_id(upload.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.expected_sha256, Some(vec![0x42; 32]));
    assert_eq!(found.expected_size, Some(1234));
    assert_eq!(found.state, "receiving");
    assert!(found.expires_at > found.created_at);

    // An upload with nothing declared: both expectation columns
    // are nullable.
    let bare = insert_upload(&db, cache_id, None, None).await;
    let found = artifact_upload::Entity::find_by_id(bare.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.expected_sha256, None);
    assert_eq!(found.expected_size, None);

    // Invariant: partial uploads never appear as artifact rows.
    let artifacts = artifact::Entity::find()
        .filter(artifact::Column::CacheId.eq(cache_id))
        .count(&db)
        .await
        .unwrap();
    assert_eq!(artifacts, 0);

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn latest_pointer_insert_overwrite_read() {
    let (db, dir) = fresh_db("latest").await;
    let cache_id = insert_cache(&db, "latest").await;

    // No pointer yet: resolution is `None`, never a guess.
    assert!(db
        .find_artifact_latest(cache_id, "widget")
        .await
        .unwrap()
        .is_none());

    let v1 = insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.tar.gz", 0x01).await;
    db.set_artifact_latest(cache_id, "widget", v1.id)
        .await
        .unwrap();
    let resolved = db
        .find_artifact_latest(cache_id, "widget")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved.id, v1.id);

    // Overwrite: the pointer moves to the newer artifact and there
    // is still exactly one pointer row for (cache, name).
    let v2 = insert_artifact(&db, cache_id, "widget", "1.1.0", "widget.tar.gz", 0x02).await;
    db.set_artifact_latest(cache_id, "widget", v2.id)
        .await
        .unwrap();
    let resolved = db
        .find_artifact_latest(cache_id, "widget")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved.id, v2.id);
    assert_eq!(resolved.version, "1.1.0");

    let pointer = artifact_latest::Entity::find_by_id((cache_id, "widget".to_owned()))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pointer.latest_artifact_id, v2.id);

    // A different name in the same cache is an independent pointer.
    assert!(db
        .find_artifact_latest(cache_id, "gadget")
        .await
        .unwrap()
        .is_none());

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

// ----------------------------------------------------------------
// Adversarial: constraints and cascades must actually bite
// ----------------------------------------------------------------

#[tokio::test]
async fn artifact_unique_constraint_rejects_duplicate_tuple() {
    let (db, dir) = fresh_db("unique").await;
    let cache_id = insert_cache(&db, "unique").await;
    let other_cache_id = insert_cache(&db, "unique-other").await;

    insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.tar.gz", 0x01).await;

    // Same (cache, name, version, filename) — even with different
    // bytes — is rejected by the UNIQUE constraint.
    let now = now();
    let duplicate = artifact::ActiveModel {
        cache_id: Set(cache_id),
        name: Set("widget".to_owned()),
        version: Set("1.0.0".to_owned()),
        filename: Set("widget.tar.gz".to_owned()),
        size: Set(9999),
        sha256: Set(vec![0x02; 32]),
        content_type: Set("application/gzip".to_owned()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await;
    assert!(
        duplicate.is_err(),
        "duplicate tuple was accepted: {duplicate:?}"
    );

    // The same tuple in a different cache, and a different
    // filename in the same cache, are both fine.
    insert_artifact(
        &db,
        other_cache_id,
        "widget",
        "1.0.0",
        "widget.tar.gz",
        0x01,
    )
    .await;
    insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.zip", 0x01).await;

    let count = artifact::Entity::find().count(&db).await.unwrap();
    assert_eq!(count, 3);

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn foreign_keys_reject_dangling_references() {
    let (db, dir) = fresh_db("fk").await;
    let cache_id = insert_cache(&db, "fk").await;
    let artifact = insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.tar.gz", 0x01).await;

    // An artifact pointing at a cache that does not exist.
    let now = now();
    let orphan_artifact = artifact::ActiveModel {
        cache_id: Set(999_999),
        name: Set("widget".to_owned()),
        version: Set("1.0.0".to_owned()),
        filename: Set("widget.tar.gz".to_owned()),
        size: Set(1),
        sha256: Set(vec![0x03; 32]),
        content_type: Set("application/gzip".to_owned()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&db)
    .await;
    assert!(orphan_artifact.is_err());

    // A latest pointer naming an artifact that does not exist.
    let orphan_pointer = artifact_latest::ActiveModel {
        cache_id: Set(cache_id),
        name: Set("widget".to_owned()),
        latest_artifact_id: Set(999_999),
    }
    .insert(&db)
    .await;
    assert!(orphan_pointer.is_err());

    // The real pointer works, and a second raw insert for the same
    // (cache, name) primary key is rejected (overwrite must go
    // through the upsert accessor).
    db.set_artifact_latest(cache_id, "widget", artifact.id)
        .await
        .unwrap();
    let duplicate_pointer = artifact_latest::ActiveModel {
        cache_id: Set(cache_id),
        name: Set("widget".to_owned()),
        latest_artifact_id: Set(artifact.id),
    }
    .insert(&db)
    .await;
    assert!(duplicate_pointer.is_err());

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn deleting_cache_cascades_to_artifacts_uploads_and_latest() {
    let (db, dir) = fresh_db("cascade-cache").await;
    let doomed = insert_cache(&db, "doomed").await;
    let spared = insert_cache(&db, "spared").await;

    let doomed_artifact =
        insert_artifact(&db, doomed, "widget", "1.0.0", "widget.tar.gz", 0x01).await;
    insert_upload(&db, doomed, None, None).await;
    db.set_artifact_latest(doomed, "widget", doomed_artifact.id)
        .await
        .unwrap();

    let spared_artifact =
        insert_artifact(&db, spared, "widget", "1.0.0", "widget.tar.gz", 0x02).await;
    db.set_artifact_latest(spared, "widget", spared_artifact.id)
        .await
        .unwrap();

    cache::Entity::delete_by_id(doomed).exec(&db).await.unwrap();

    // Everything belonging to the destroyed cache is gone.
    assert_eq!(
        artifact::Entity::find()
            .filter(artifact::Column::CacheId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        artifact_upload::Entity::find()
            .filter(artifact_upload::Column::CacheId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        artifact_latest::Entity::find()
            .filter(artifact_latest::Column::CacheId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0
    );

    // The other cache's artifact and pointer are untouched.
    assert!(artifact::Entity::find_by_id(spared_artifact.id)
        .one(&db)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        db.find_artifact_latest(spared, "widget")
            .await
            .unwrap()
            .unwrap()
            .id,
        spared_artifact.id
    );

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn deleting_artifact_cascades_to_latest_pointer() {
    let (db, dir) = fresh_db("cascade-artifact").await;
    let cache_id = insert_cache(&db, "cascade-artifact").await;
    let artifact = insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.tar.gz", 0x01).await;
    db.set_artifact_latest(cache_id, "widget", artifact.id)
        .await
        .unwrap();

    artifact::Entity::delete_by_id(artifact.id)
        .exec(&db)
        .await
        .unwrap();

    // The pointer must not outlive the artifact it names.
    assert_eq!(artifact_latest::Entity::find().count(&db).await.unwrap(), 0);
    assert!(db
        .find_artifact_latest(cache_id, "widget")
        .await
        .unwrap()
        .is_none());

    // The cache itself survives.
    assert!(cache::Entity::find_by_id(cache_id)
        .one(&db)
        .await
        .unwrap()
        .is_some());

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}

// ----------------------------------------------------------------
// GC blindness (design invariant)
// ----------------------------------------------------------------

/// The JWT signing fixture already published in
/// `server/src/config.rs` tests. Test-only.
const TEST_TOKEN_ED25519_SECRET_BASE64: &str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUxpdlM2bDZvYzZTeWZYcnk1YUpsZmtYZEVnblZCQnVjOFg1K3VTWEFiMmUKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=";

#[tokio::test]
async fn garbage_collection_never_touches_artifacts() {
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let dir = std::env::temp_dir().join(format!(
        "bunker-artifact-gc-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let storage_dir = dir.join("storage");
    std::fs::create_dir_all(&storage_dir).unwrap();
    let db_path = dir.join("gc.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    // Seed: a cache with a 60-second retention period holding an
    // expired Nix object (which GC *should* reap, along with its
    // orphaned NAR) plus an artifact, an in-flight upload and a
    // latest pointer (which GC must never touch, regardless of the
    // cache's retention period).
    let (cache_id, artifact_id) = {
        let db = Database::connect(&db_url).await.unwrap();
        Migrator::up(&db, None).await.unwrap();

        let cache_id = insert_cache_with_retention(&db, "gc", Some(60)).await;
        let old = now() - Duration::days(1);

        let nar = nar::ActiveModel {
            state: Set(nar::NarState::Valid),
            nar_hash: Set(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
            ),
            nar_size: Set(10),
            compression: Set("none".to_owned()),
            num_chunks: Set(0),
            completeness_hint: Set(true),
            holders_count: Set(0),
            created_at: Set(old),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        object::ActiveModel {
            cache_id: Set(cache_id),
            nar_id: Set(nar.id),
            store_path_hash: Set("00000000000000000000000000000000".to_owned()),
            store_path: Set("/nix/store/00000000000000000000000000000000-gc".to_owned()),
            references: Set(Json(Vec::new())),
            system: Set(None),
            deriver: Set(None),
            sigs: Set(Json(Vec::new())),
            ca: Set(None),
            created_at: Set(old),
            last_accessed_at: Set(None),
            created_by: Set(None),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let artifact =
            insert_artifact(&db, cache_id, "widget", "1.0.0", "widget.tar.gz", 0x09).await;
        insert_upload(&db, cache_id, None, None).await;
        db.set_artifact_latest(cache_id, "widget", artifact.id)
            .await
            .unwrap();

        db.close().await.unwrap();
        (cache_id, artifact.id)
    };

    let config_toml = format!(
        r#"
[database]
url = "{db_url}"

[storage]
type = "local"
path = "{storage}"

[chunking]
nar-size-threshold = 1
min-size = 1024
avg-size = 2048
max-size = 4096

[jwt.signing]
token-ed25519-secret-base64 = "{TEST_TOKEN_ED25519_SECRET_BASE64}"
"#,
        storage = storage_dir.display(),
    );
    let config: Config = toml::from_str(&config_toml).unwrap();

    run_garbage_collection_once(config).await.unwrap();

    // The GC pass demonstrably ran: the expired object and its
    // orphaned NAR are gone.
    let db = Database::connect(&db_url).await.unwrap();
    assert_eq!(object::Entity::find().count(&db).await.unwrap(), 0);
    assert_eq!(nar::Entity::find().count(&db).await.unwrap(), 0);

    // And it was blind to artifacts: rows and pointer all survive.
    assert_eq!(
        artifact::Entity::find_by_id(artifact_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .filename,
        "widget.tar.gz"
    );
    assert_eq!(
        artifact_upload::Entity::find()
            .filter(artifact_upload::Column::CacheId.eq(cache_id))
            .count(&db)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        db.find_artifact_latest(cache_id, "widget")
            .await
            .unwrap()
            .unwrap()
            .id,
        artifact_id
    );

    db.close().await.unwrap();
    std::fs::remove_dir_all(dir).ok();
}
