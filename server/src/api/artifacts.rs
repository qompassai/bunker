//! Artifact download endpoint.
//!
//! `GET /:cache/artifacts/:name/:version/:file` serves one
//! release artifact (a tarball, an installer, a disk image)
//! stored by the upload endpoint in `crate::api::v1::artifacts`.
//! Artifacts live entirely outside the Nix protocol: no narinfo
//! is read, no NAR is reassembled, and garbage collection never
//! sees these objects.
//!
//! The version segment may be the literal token `latest`, which
//! resolves through the `artifact_latest` pointer for the name.
//! The pointer is the only source of truth for `latest`; there
//! is no "newest by upload time" fallback.
//!
//! Authorization is the binary cache's read posture, unchanged:
//! the caller's JWT (already decoded by the `apply_auth`
//! middleware into the request's [`AuthState`]) must grant the
//! `pull` permission on the cache, and public caches grant
//! anonymous pull. The response for a **private** cache is always
//! streamed through this server — it is never a redirect to a
//! presigned storage URL, because a presigned URL is a bearer
//! capability that would outlive the authorization check. Public
//! caches may redirect, exactly like single-chunk NAR downloads.
//!
//! Objects are fetched from storage by their digest key alone
//! (see `crate::storage::artifact_key`); the name, version and
//! filename in the URL are validated with the upload endpoint's
//! discipline and then used only as a database lookup key — they
//! never become part of a storage path.

use axum::body::Body;
use axum::extract::{Extension, Path};
use axum::http::header::{self, HeaderName};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use futures::TryStreamExt as _;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio_util::io::ReaderStream;
use tracing::instrument;

use bunker::cache::CacheName;

use crate::access::http::AuthState;
use crate::api::v1::artifacts::validate_artifact_tokens;
use crate::database::entity::artifact::{self, ArtifactModel, Entity as Artifact};
use crate::database::entity::cache::CacheModel;
use crate::database::BunkerDatabase;
use crate::error::{ErrorKind, ServerError, ServerResult};
use crate::storage::{artifact_key, Download, StorageBackend};
use crate::{RequestState, State};

/// The version segment that resolves through the `latest`
/// pointer instead of naming a literal version.
const LATEST_VERSION: &str = "latest";

/// Response header naming the version a `latest` request
/// resolved to, so logs and clients can see what was served.
const X_BUNKER_ARTIFACT_VERSION: HeaderName = HeaderName::from_static("x-bunker-artifact-version");

/// Cache-Control for versioned artifact URLs: the bytes behind
/// a versioned URL never change, so clients may cache forever.
const CACHE_CONTROL_VERSIONED: &str = "public, max-age=31536000, immutable";

/// Cache-Control for `latest` URLs: the pointer moves, so
/// clients must revalidate.
const CACHE_CONTROL_LATEST: &str = "no-cache";

/// One artifact download request, with the conditional headers
/// the serving logic consults already lifted out of the header
/// map (deliberately not the whole map: these three are the
/// entire conditional surface of this endpoint).
pub(crate) struct ArtifactRequest<'a> {
    /// The cache the artifact belongs to.
    pub(crate) cache_name: &'a CacheName,

    /// Artifact name from the URL.
    pub(crate) name: &'a str,

    /// Version from the URL; the literal `latest` resolves
    /// through the pointer.
    pub(crate) version: &'a str,

    /// Bare filename from the URL.
    pub(crate) filename: &'a str,

    /// The `Range` header, if any.
    pub(crate) range: Option<&'a str>,

    /// The `If-None-Match` header, if any.
    pub(crate) if_none_match: Option<&'a str>,

    /// The `If-Range` header, if any.
    pub(crate) if_range: Option<&'a str>,
}

/// Downloads one artifact.
///
/// Thin HTTP plumbing over [`serve_artifact_inner`]: resolves
/// the server state, lifts the conditional headers, and records
/// the cache's visibility for the `X-Bunker-Cache-Visibility`
/// middleware header.
#[instrument(skip_all, fields(cache_name, name, version, filename))]
pub(crate) async fn get_artifact(
    Extension(state): Extension<State>,
    Extension(req_state): Extension<RequestState>,
    Path((cache_name, name, version, filename)): Path<(CacheName, String, String, String)>,
    headers: HeaderMap,
) -> ServerResult<Response> {
    let database = state.database().await?;
    let storage = state.storage().await?;

    let request = ArtifactRequest {
        cache_name: &cache_name,
        name: &name,
        version: &version,
        filename: &filename,
        range: header_text(&headers, header::RANGE),
        if_none_match: header_text(&headers, header::IF_NONE_MATCH),
        if_range: header_text(&headers, header::IF_RANGE),
    };

    let (response, is_public) = serve_artifact_inner(
        database,
        storage.as_ref().as_ref(),
        &req_state.auth,
        &request,
    )
    .await?;

    req_state.set_public_cache(is_public);

    Ok(response)
}

/// Returns the text of one header, or `None` when it is absent
/// or not valid text (a non-text conditional header cannot match
/// anything, so it is treated as absent).
fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Serves one artifact download.
///
/// Order of operations is contractual:
///
/// 1. The addressing tokens are validated with the upload
///    endpoint's discipline, before anything is read.
/// 2. Authorization runs through the cache's existing `pull`
///    permission (`auth_cache` also resolves the cache, so an
///    unknown cache fails here with the codebase's
///    discovery-aware error).
/// 3. The artifact row is resolved (`latest` through the
///    pointer); an unknown name, version or filename is a 404.
/// 4. The object is served from its digest key: a `Range`
///    request reads exactly its window through the backend's
///    ranged read, a full request streams through the server
///    or — for public caches only — redirects to storage.
///
/// Returns the response and whether the cache is public (for
/// the visibility middleware header).
pub(crate) async fn serve_artifact_inner(
    database: &DatabaseConnection,
    storage: &dyn StorageBackend,
    auth: &AuthState,
    request: &ArtifactRequest<'_>,
) -> ServerResult<(Response, bool)> {
    validate_artifact_tokens(request.name, request.version, request.filename)?;

    let cache = auth
        .auth_cache(database, request.cache_name, |cache, permission| {
            permission.require_pull()?;
            Ok(cache)
        })
        .await?;

    let artifact = resolve_artifact(database, &cache, request).await?;

    let response = respond_for_artifact(storage, &cache, &artifact, request).await?;

    Ok((response, cache.is_public))
}

/// Resolves the addressed artifact row.
///
/// For `latest`, the pointer names the artifact for
/// `(cache, name)`; the requested filename must be that
/// artifact's filename — the pointer is per name, so a
/// `latest` URL for a different file of the same name is a
/// 404, not a guess at another file.
async fn resolve_artifact(
    database: &DatabaseConnection,
    cache: &CacheModel,
    request: &ArtifactRequest<'_>,
) -> ServerResult<ArtifactModel> {
    if request.version == LATEST_VERSION {
        return database
            .find_artifact_latest(cache.id, request.name)
            .await?
            .filter(|artifact| artifact.filename == request.filename)
            .ok_or_else(|| ErrorKind::NotFound.into());
    }

    Artifact::find()
        .filter(artifact::Column::CacheId.eq(cache.id))
        .filter(artifact::Column::Name.eq(request.name))
        .filter(artifact::Column::Version.eq(request.version))
        .filter(artifact::Column::Filename.eq(request.filename))
        .one(database)
        .await
        .map_err(ServerError::database_error)?
        .ok_or_else(|| ErrorKind::NotFound.into())
}

/// The facts every artifact response is built from, resolved
/// once from the artifact row.
struct ServeFacts {
    /// The stored content type, recorded at upload time.
    content_type: String,

    /// `Content-Disposition` value (the filename is a validated
    /// ASCII token, so plain quoting is safe).
    content_disposition: String,

    /// The strong ETag: the artifact's SHA-256, hex-encoded
    /// and quoted.
    etag: String,

    /// `Last-Modified` value, from the row's creation time.
    last_modified: String,

    /// Cache-Control for this response.
    cache_control: &'static str,

    /// The version a `latest` request resolved to, if it did.
    resolved_version: Option<String>,

    /// Size of the artifact in bytes.
    size: u64,

    /// The artifact's SHA-256 digest: the ETag's source and
    /// the storage key's input.
    digest: [u8; 32],
}

impl ServeFacts {
    /// Builds the facts from the artifact row.
    ///
    /// A row whose digest is not 32 bytes or whose size is
    /// negative is corrupt server-side state, not a client
    /// error: it fails as an internal error.
    fn from_artifact(artifact: &ArtifactModel, via_latest: bool) -> ServerResult<Self> {
        let digest: [u8; 32] = artifact
            .sha256
            .as_slice()
            .try_into()
            .map_err(|_| ServerError::from(ErrorKind::InternalServerError))?;

        let size = u64::try_from(artifact.size)
            .map_err(|_| ServerError::from(ErrorKind::InternalServerError))?;

        Ok(Self {
            content_type: artifact.content_type.clone(),
            content_disposition: format!("attachment; filename=\"{}\"", artifact.filename),
            etag: format!("\"{}\"", hex::encode(digest)),
            last_modified: artifact
                .created_at
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
            cache_control: if via_latest {
                CACHE_CONTROL_LATEST
            } else {
                CACHE_CONTROL_VERSIONED
            },
            resolved_version: via_latest.then(|| artifact.version.clone()),
            size,
            digest,
        })
    }

    /// The headers common to full and ranged body responses.
    fn body_headers(&self) -> ServerResult<HeaderMap> {
        let mut headers = self.validator_headers()?;
        headers.insert(header::CONTENT_TYPE, header_value(&self.content_type)?);
        headers.insert(
            header::CONTENT_DISPOSITION,
            header_value(&self.content_disposition)?,
        );
        Ok(headers)
    }

    /// The validator headers: everything a 304 or 416 response
    /// needs to describe the artifact without serving it.
    fn validator_headers(&self) -> ServerResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(header::ETAG, header_value(&self.etag)?);
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        headers.insert(header::LAST_MODIFIED, header_value(&self.last_modified)?);
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(self.cache_control),
        );
        if let Some(version) = &self.resolved_version {
            headers.insert(X_BUNKER_ARTIFACT_VERSION, header_value(version)?);
        }
        Ok(headers)
    }
}

/// Converts text into a header value.
///
/// Every value converted here is server-generated or a
/// validated token; failure means corrupt server state, so it
/// is an internal error, never a client error.
fn header_value(text: &str) -> ServerResult<HeaderValue> {
    HeaderValue::from_str(text).map_err(|_| ErrorKind::InternalServerError.into())
}

/// Builds the response for a resolved artifact: conditional
/// evaluation first, then a ranged or full body.
async fn respond_for_artifact(
    storage: &dyn StorageBackend,
    cache: &CacheModel,
    artifact: &ArtifactModel,
    request: &ArtifactRequest<'_>,
) -> ServerResult<Response> {
    let via_latest = request.version == LATEST_VERSION;
    let facts = ServeFacts::from_artifact(artifact, via_latest)?;

    // If-None-Match is evaluated before Range (RFC 9110
    // §13.2.2): a matching validator means the client's copy
    // is current regardless of the range it asked for.
    if let Some(if_none_match) = request.if_none_match {
        if if_none_match_matches(if_none_match, &facts.etag) {
            return Ok((
                StatusCode::NOT_MODIFIED,
                facts.validator_headers()?,
                Body::empty(),
            )
                .into_response());
        }
    }

    let key = artifact_key(cache.id, &facts.digest);

    // A Range is honoured only when If-Range names the current
    // ETag; a stale If-Range means the client's copy is of a
    // different version of the file and it gets the full body.
    let range = match request.range {
        Some(raw) if request.if_range.is_none_or(|value| value == facts.etag) => {
            parse_range(raw, facts.size)
        }
        _ => RangeDecision::Full,
    };

    match range {
        RangeDecision::Unsatisfiable => {
            let mut headers = facts.validator_headers()?;
            headers.insert(
                header::CONTENT_RANGE,
                header_value(&format!("bytes */{}", facts.size))?,
            );
            Ok((StatusCode::RANGE_NOT_SATISFIABLE, headers, Body::empty()).into_response())
        }
        RangeDecision::Single { start, end } => {
            respond_range(storage, &key, &facts, start, end).await
        }
        RangeDecision::Full => respond_full(storage, &key, cache, &facts).await,
    }
}

/// Serves one satisfiable byte range (206).
///
/// The window is read through the backend's ranged read, whose
/// contract clamps at the end of the object: a short read
/// therefore means the stored object disagrees with the
/// artifact row, which is a server inconsistency (500), never
/// a truncated 206.
async fn respond_range(
    storage: &dyn StorageBackend,
    key: &str,
    facts: &ServeFacts,
    start: u64,
    end: u64,
) -> ServerResult<Response> {
    // `end >= start` and `end < size` hold by parse_range's
    // construction, so this cannot overflow.
    let len = end - start + 1;

    let bytes = storage.get_range(key.to_owned(), start, len).await?;

    if bytes.len() as u64 != len {
        tracing::error!(
            "Artifact object at {key} is shorter than its row claims: \
             wanted {len} bytes at offset {start}, got {}",
            bytes.len()
        );
        return Err(ErrorKind::InternalServerError.into());
    }

    let mut headers = facts.body_headers()?;
    headers.insert(
        header::CONTENT_RANGE,
        header_value(&format!("bytes {}-{}/{}", start, end, facts.size))?,
    );
    headers.insert(header::CONTENT_LENGTH, header_value(&len.to_string())?);

    Ok((StatusCode::PARTIAL_CONTENT, headers, Body::from(bytes)).into_response())
}

/// Serves the full body (200), or a redirect to storage (307)
/// for a public cache on a backend that offers one.
///
/// The object is probed before anything is served: an
/// artifact row whose object is missing is a server
/// inconsistency, and the probe's storage error surfaces it
/// as a 500 — never as a 404 and never as a redirect to an
/// object that is not there.
async fn respond_full(
    storage: &dyn StorageBackend,
    key: &str,
    cache: &CacheModel,
    facts: &ServeFacts,
) -> ServerResult<Response> {
    storage.get_range(key.to_owned(), 0, 1).await?;

    // The posture, in one line: private caches always stream
    // through the server (a presigned URL would be a bearer
    // capability); public caches may be redirected to storage,
    // as single-chunk NAR downloads are.
    let prefer_stream = !cache.is_public;

    match storage.download_file(key.to_owned(), prefer_stream).await? {
        Download::Url(url) => {
            // Reachable only when prefer_stream is false,
            // which is to say only for a public cache.
            let mut response = Redirect::temporary(&url).into_response();
            response.headers_mut().extend(facts.validator_headers()?);
            Ok(response)
        }
        Download::AsyncRead(reader) => {
            let stream = ReaderStream::new(reader).map_err(|e| {
                tracing::error!(%e, "Artifact stream error");
                e
            });
            let mut headers = facts.body_headers()?;
            headers.insert(
                header::CONTENT_LENGTH,
                header_value(&facts.size.to_string())?,
            );
            Ok((StatusCode::OK, headers, Body::from_stream(stream)).into_response())
        }
    }
}

/// Whether an `If-None-Match` value matches the artifact's
/// ETag, under the weak comparison the header uses: any
/// comma-separated candidate equal to the ETag, to its weak
/// form, or to `*` matches.
fn if_none_match_matches(header: &str, etag: &str) -> bool {
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate == etag || candidate == format!("W/{etag}")
    })
}

/// A parsed `Range` header, resolved against the artifact's
/// size.
enum RangeDecision {
    /// Serve the full body (no header, an unparseable header,
    /// or a multi-range header — ignoring Range is always
    /// legal, and multipart responses are out of scope).
    Full,

    /// Serve bytes `start..=end` (206).
    Single { start: u64, end: u64 },

    /// A well-formed range that cannot be satisfied (416).
    Unsatisfiable,
}

/// Parses a single-range `Range` header against `size`.
///
/// Accepted forms: `bytes=a-b`, `bytes=a-`, `bytes=-n`. An
/// end past the last byte clamps to it; a suffix longer than
/// the body selects the whole body.
fn parse_range(header: &str, size: u64) -> RangeDecision {
    let header = header.trim();
    let Some(spec) = header
        .get(..6)
        .filter(|unit| unit.eq_ignore_ascii_case("bytes="))
        .map(|_| &header[6..])
    else {
        return RangeDecision::Full;
    };

    let spec = spec.trim();
    if spec.contains(',') {
        // Multiple ranges: out of scope by contract; the
        // header is ignored and the full body is served.
        return RangeDecision::Full;
    }

    let Some((first, last)) = spec.split_once('-') else {
        return RangeDecision::Full;
    };
    let (first, last) = (first.trim(), last.trim());

    if first.is_empty() {
        // Suffix range: the last `n` bytes.
        let Ok(count) = last.parse::<u64>() else {
            return RangeDecision::Full;
        };
        if count == 0 || size == 0 {
            return RangeDecision::Unsatisfiable;
        }
        return RangeDecision::Single {
            start: size.saturating_sub(count),
            end: size - 1,
        };
    }

    let Ok(start) = first.parse::<u64>() else {
        return RangeDecision::Full;
    };
    if start >= size {
        return RangeDecision::Unsatisfiable;
    }
    if last.is_empty() {
        return RangeDecision::Single {
            start,
            end: size - 1,
        };
    }
    let Ok(end) = last.parse::<u64>() else {
        return RangeDecision::Full;
    };
    if end < start {
        return RangeDecision::Unsatisfiable;
    }

    RangeDecision::Single {
        start,
        end: end.min(size - 1),
    }
}

pub fn get_router() -> Router {
    Router::new().route("/:cache/artifacts/:name/:version/:file", get(get_artifact))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicI8, AtomicU32, Ordering};
    use std::sync::Arc;

    use bytes::Bytes;
    use chrono::{Duration, Utc};
    use futures::StreamExt as _;
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncRead;

    use bunker::api::v1::artifacts::ArtifactUploadResponse;

    use crate::access::Token;
    use crate::api::v1::artifacts::{upload_artifact_inner, UploadParams};
    use crate::database::entity::cache;
    use crate::database::entity::Json as DbJson;
    use crate::database::migration::{Migrator, MigratorTrait};
    use crate::storage::{LocalBackend, LocalStorageConfig, RemoteFile};

    const CACHE_NAME: &str = "test-cache";
    const BODY: &[u8] = b"widget release bytes, version one";
    const BODY_V2: &[u8] = b"widget release bytes, version two (different contents)";
    const RANGE_BODY: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
    const FILENAME: &str = "widget_1.0.0_linux-x86_64.tar.gz";
    const FILENAME_V2: &str = "widget_2.0.0_linux-x86_64.tar.gz";

    /// A storage backend that emulates the S3 backend's
    /// download split on top of the local backend: asked not to
    /// stream, it answers with a (fake) presigned URL; asked to
    /// stream, it streams. It records the `prefer_stream` flag
    /// of the most recent `download_file` call (-1 = never
    /// called, 0 = false, 1 = true), so tests can assert the
    /// redirect posture directly.
    #[derive(Debug)]
    struct RecordingBackend {
        inner: LocalBackend,
        prefer_stream: Arc<AtomicI8>,
    }

    #[async_trait::async_trait]
    impl StorageBackend for RecordingBackend {
        async fn upload_file(
            &self,
            name: String,
            stream: &mut (dyn AsyncRead + Unpin + Send),
        ) -> ServerResult<RemoteFile> {
            self.inner.upload_file(name, stream).await
        }

        async fn delete_file(&self, name: String) -> ServerResult<()> {
            self.inner.delete_file(name).await
        }

        async fn delete_file_db(&self, file: &RemoteFile) -> ServerResult<()> {
            self.inner.delete_file_db(file).await
        }

        async fn download_file(&self, name: String, prefer_stream: bool) -> ServerResult<Download> {
            self.prefer_stream
                .store(i8::from(prefer_stream), Ordering::SeqCst);
            if prefer_stream {
                self.inner.download_file(name, true).await
            } else {
                Ok(Download::Url(format!("http://storage.invalid/{name}")))
            }
        }

        async fn download_file_db(
            &self,
            file: &RemoteFile,
            prefer_stream: bool,
        ) -> ServerResult<Download> {
            self.inner.download_file_db(file, prefer_stream).await
        }

        async fn make_db_reference(&self, name: String) -> ServerResult<RemoteFile> {
            self.inner.make_db_reference(name).await
        }

        async fn get_range(&self, name: String, offset: u64, len: u64) -> ServerResult<Bytes> {
            self.inner.get_range(name, offset, len).await
        }
    }

    /// Everything one test needs: a migrated database, a
    /// recording storage backend in a temp dir, and one cache
    /// row.
    struct Rig {
        db: DatabaseConnection,
        storage: RecordingBackend,
        root: PathBuf,
        cache_id: i64,
    }

    impl Rig {
        fn last_prefer_stream(&self) -> i8 {
            self.storage.prefer_stream.load(Ordering::SeqCst)
        }

        /// Forgets recorded `download_file` calls. Uploads make
        /// such a call themselves (placing the object), so tests
        /// asserting on the serving posture reset after seeding.
        fn reset_prefer_stream(&self) {
            self.storage.prefer_stream.store(-1, Ordering::SeqCst);
        }
    }

    async fn rig(test: &str, public: bool) -> Rig {
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let root = std::env::temp_dir().join(format!(
            "bunker-artifact-serving-test-{}-{}-{}",
            test,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        tokio::fs::create_dir_all(&root).await.unwrap();

        let url = format!("sqlite://{}/test.db?mode=rwc", root.display());
        let db = Database::connect(&url).await.unwrap();
        Migrator::up(&db, None).await.unwrap();

        // LocalStorageConfig's fields are private to its
        // module; build it through its Deserialize impl, as
        // config loading does.
        let storage_config: LocalStorageConfig =
            serde_json::from_value(serde_json::json!({ "path": root.join("storage") })).unwrap();
        let inner = LocalBackend::new(storage_config).await.unwrap();
        let storage = RecordingBackend {
            inner,
            prefer_stream: Arc::new(AtomicI8::new(-1)),
        };

        let now = Utc::now();
        let cache = cache::ActiveModel {
            name: Set(CACHE_NAME.to_owned()),
            keypair: Set("test-keypair".to_owned()),
            is_public: Set(public),
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

    fn cache_name() -> CacheName {
        CacheName::new(CACHE_NAME.to_owned()).unwrap()
    }

    /// An auth state holding a token with the given permissions
    /// on the named cache — the state the auth middleware
    /// produces from a valid JWT.
    fn auth_for(cache: &str, push: bool, pull: bool) -> AuthState {
        let mut token = Token::new(
            "artifact-tester".to_owned(),
            &(Utc::now() + Duration::days(1)),
        );
        let name = CacheName::new(cache.to_owned()).unwrap();
        let permission = token.get_or_insert_permission_mut(name.to_pattern());
        permission.push = push;
        permission.pull = pull;

        let auth = AuthState::new();
        auth.token.set(token).unwrap();
        auth
    }

    fn push_auth() -> AuthState {
        auth_for(CACHE_NAME, true, false)
    }

    fn pull_auth() -> AuthState {
        auth_for(CACHE_NAME, false, true)
    }

    async fn upload(
        rig: &Rig,
        name: &str,
        version: &str,
        filename: &str,
        body: &'static [u8],
    ) -> ArtifactUploadResponse {
        let request = bunker::api::v1::artifacts::ArtifactUploadRequest {
            cache: cache_name(),
            name: name.to_owned(),
            version: version.to_owned(),
            filename: filename.to_owned(),
        };
        upload_artifact_inner(
            &rig.db,
            &rig.storage,
            &push_auth(),
            &UploadParams {
                request: &request,
                expected_sha256: None,
                expected_size: None,
                max_size: 1 << 30,
            },
            Body::from(body),
        )
        .await
        .unwrap()
    }

    fn request<'a>(
        cache_name: &'a CacheName,
        name: &'a str,
        version: &'a str,
        filename: &'a str,
    ) -> ArtifactRequest<'a> {
        ArtifactRequest {
            cache_name,
            name,
            version,
            filename,
            range: None,
            if_none_match: None,
            if_range: None,
        }
    }

    async fn serve(
        rig: &Rig,
        auth: &AuthState,
        request: &ArtifactRequest<'_>,
    ) -> ServerResult<(Response, bool)> {
        serve_artifact_inner(&rig.db, &rig.storage, auth, request).await
    }

    async fn body_bytes(response: Response) -> Vec<u8> {
        let mut stream = response.into_body().into_data_stream();
        let mut out = Vec::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn etag_of(data: &[u8]) -> String {
        format!("\"{}\"", sha256_hex(data))
    }

    async fn error_status(result: ServerResult<(Response, bool)>) -> StatusCode {
        match result {
            Ok(_) => panic!("expected an error, got a response"),
            Err(e) => e.into_response().status(),
        }
    }

    // -- Validation (happy paths) --------------------------------

    #[tokio::test]
    async fn serves_uploaded_artifact_byte_exact() {
        let rig = rig("byte-exact", false).await;
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;

        let cache = cache_name();
        let (response, is_public) = serve(
            &rig,
            &pull_auth(),
            &request(&cache, "widget", "1.0.0", FILENAME),
        )
        .await
        .unwrap();

        assert!(!is_public);
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(headers[header::CONTENT_TYPE], "application/gzip");
        assert_eq!(
            headers[header::CONTENT_LENGTH],
            BODY.len().to_string().as_str()
        );
        assert_eq!(headers[header::ETAG], etag_of(BODY).as_str());
        assert_eq!(headers[header::ACCEPT_RANGES], "bytes");
        assert_eq!(headers[header::CACHE_CONTROL], CACHE_CONTROL_VERSIONED);
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            format!("attachment; filename=\"{FILENAME}\"").as_str()
        );
        assert_eq!(body_bytes(response).await, BODY);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn latest_tracks_newest_and_pinned_version_still_served() {
        let rig = rig("latest", false).await;
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;
        upload(&rig, "widget", "2.0.0", FILENAME_V2, BODY_V2).await;
        let cache = cache_name();

        // latest resolves to the newest finalized upload and
        // says which version it served.
        let (response, _) = serve(
            &rig,
            &pull_auth(),
            &request(&cache, "widget", "latest", FILENAME_V2),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[X_BUNKER_ARTIFACT_VERSION], "2.0.0");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            CACHE_CONTROL_LATEST
        );
        assert_eq!(body_bytes(response).await, BODY_V2);

        // The pinned old version is still served, byte-exact.
        let (response, _) = serve(
            &rig,
            &pull_auth(),
            &request(&cache, "widget", "1.0.0", FILENAME),
        )
        .await
        .unwrap();
        assert_eq!(body_bytes(response).await, BODY);

        // latest is per (cache, name): it names v2's row, so
        // v1's filename under latest is a 404, not a guess.
        let status = error_status(
            serve(
                &rig,
                &pull_auth(),
                &request(&cache, "widget", "latest", FILENAME),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn range_requests_return_exact_windows() {
        let rig = rig("ranges", false).await;
        upload(&rig, "range", "1.0.0", "range.bin", RANGE_BODY).await;
        let cache = cache_name();

        let cases: [(&str, &str, usize, usize); 5] = [
            ("bytes=0-3", "bytes 0-3/46", 0, 4),
            ("bytes=10-14", "bytes 10-14/46", 10, 15),
            ("bytes=40-", "bytes 40-45/46", 40, 46),
            ("bytes=-5", "bytes 41-45/46", 41, 46),
            ("bytes=0-9999", "bytes 0-45/46", 0, 46),
        ];

        for (header_value, content_range, from, to) in cases {
            let mut req = request(&cache, "range", "1.0.0", "range.bin");
            req.range = Some(header_value);
            let (response, _) = serve(&rig, &pull_auth(), &req).await.unwrap();

            assert_eq!(
                response.status(),
                StatusCode::PARTIAL_CONTENT,
                "{header_value}"
            );
            assert_eq!(
                response.headers()[header::CONTENT_RANGE],
                content_range,
                "{header_value}"
            );
            assert_eq!(
                response.headers()[header::CONTENT_LENGTH],
                (to - from).to_string().as_str(),
                "{header_value}"
            );
            assert_eq!(
                body_bytes(response).await,
                &RANGE_BODY[from..to],
                "{header_value}"
            );
        }

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn unsatisfiable_ranges_are_416() {
        let rig = rig("range-416", false).await;
        upload(&rig, "range", "1.0.0", "range.bin", RANGE_BODY).await;
        let cache = cache_name();

        for header_value in ["bytes=46-", "bytes=46-50", "bytes=9-5", "bytes=-0"] {
            let mut req = request(&cache, "range", "1.0.0", "range.bin");
            req.range = Some(header_value);
            let (response, _) = serve(&rig, &pull_auth(), &req).await.unwrap();

            assert_eq!(
                response.status(),
                StatusCode::RANGE_NOT_SATISFIABLE,
                "{header_value}"
            );
            assert_eq!(
                response.headers()[header::CONTENT_RANGE],
                "bytes */46",
                "{header_value}"
            );
            assert!(body_bytes(response).await.is_empty());
        }

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn multi_range_header_is_ignored() {
        let rig = rig("multi-range", false).await;
        upload(&rig, "range", "1.0.0", "range.bin", RANGE_BODY).await;
        let cache = cache_name();

        let mut req = request(&cache, "range", "1.0.0", "range.bin");
        req.range = Some("bytes=0-1,5-9");
        let (response, _) = serve(&rig, &pull_auth(), &req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await, RANGE_BODY);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn if_none_match_short_circuits_and_if_range_is_honoured() {
        let rig = rig("conditionals", false).await;
        upload(&rig, "range", "1.0.0", "range.bin", RANGE_BODY).await;
        let cache = cache_name();
        let etag = etag_of(RANGE_BODY);

        // Matching validator: 304, no body — even with a Range.
        let mut req = request(&cache, "range", "1.0.0", "range.bin");
        req.if_none_match = Some(&etag);
        req.range = Some("bytes=0-3");
        let (response, _) = serve(&rig, &pull_auth(), &req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(response.headers()[header::ETAG], etag.as_str());
        assert!(body_bytes(response).await.is_empty());

        // Non-matching validator: full serve proceeds.
        let mut req = request(&cache, "range", "1.0.0", "range.bin");
        req.if_none_match = Some("\"some-other-etag\"");
        let (response, _) = serve(&rig, &pull_auth(), &req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await, RANGE_BODY);

        // If-Range with the current ETag: the range applies.
        let mut req = request(&cache, "range", "1.0.0", "range.bin");
        req.range = Some("bytes=0-3");
        req.if_range = Some(&etag);
        let (response, _) = serve(&rig, &pull_auth(), &req).await.unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(body_bytes(response).await, &RANGE_BODY[0..4]);

        // If-Range with a stale ETag: full body instead.
        let mut req = request(&cache, "range", "1.0.0", "range.bin");
        req.range = Some("bytes=0-3");
        req.if_range = Some("\"stale-etag\"");
        let (response, _) = serve(&rig, &pull_auth(), &req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await, RANGE_BODY);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    // -- Adversarial ---------------------------------------------

    #[tokio::test]
    async fn unknown_artifact_is_404() {
        let rig = rig("unknown-artifact", false).await;
        let cache = cache_name();

        // Nothing uploaded at all.
        let status = error_status(
            serve(
                &rig,
                &pull_auth(),
                &request(&cache, "widget", "1.0.0", FILENAME),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Uploaded name, unknown version.
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;
        let status = error_status(
            serve(
                &rig,
                &pull_auth(),
                &request(&cache, "widget", "9.9.9", FILENAME),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn unknown_cache_is_404_with_discovery_and_401_without() {
        let rig = rig("unknown-cache", false).await;
        let missing = CacheName::new("no-such-cache".to_owned()).unwrap();
        let req = request(&missing, "widget", "1.0.0", FILENAME);

        // A token with a grant on that name can discover, so it
        // learns the truth: no such cache.
        let status =
            error_status(serve(&rig, &auth_for("no-such-cache", false, true), &req).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Anonymous callers get the anti-enumeration answer.
        let status = error_status(serve(&rig, &AuthState::new(), &req).await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn private_cache_denies_without_pull() {
        let rig = rig("private-denied", false).await;
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;
        let cache = cache_name();
        let req = request(&cache, "widget", "1.0.0", FILENAME);
        rig.reset_prefer_stream();

        // Push is not pull: a push-only token is denied.
        let status = error_status(serve(&rig, &push_auth(), &req).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Anonymous is denied too (anti-enumeration form).
        let status = error_status(serve(&rig, &AuthState::new(), &req).await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Denial happens before storage is ever consulted.
        assert_eq!(rig.last_prefer_stream(), -1);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn public_cache_grants_anonymous_pull() {
        let rig = rig("public-anon", true).await;
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;
        let cache = cache_name();
        rig.reset_prefer_stream();

        // No token at all: a public cache grants pull, so the
        // request reaches storage. (This rig's backend emulates
        // the S3 split, so a granted full download of a public
        // cache is the storage redirect; the streamed anonymous
        // serve on a real local backend is smoke-verified.)
        let (response, is_public) = serve(
            &rig,
            &AuthState::new(),
            &request(&cache, "widget", "1.0.0", FILENAME),
        )
        .await
        .unwrap();

        assert!(is_public);
        assert_eq!(rig.last_prefer_stream(), 0);
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn public_cache_may_redirect_to_storage() {
        // Public cache: the backend is offered the redirect
        // (prefer_stream = false) and its URL is the response.
        let rig = rig("posture-public", true).await;
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;
        let cache = cache_name();

        let (response, _) = serve(
            &rig,
            &AuthState::new(),
            &request(&cache, "widget", "1.0.0", FILENAME),
        )
        .await
        .unwrap();

        assert_eq!(rig.last_prefer_stream(), 0);
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let digest: [u8; 32] = Sha256::digest(BODY).into();
        let key = artifact_key(rig.cache_id, &digest);
        assert_eq!(
            response.headers()[header::LOCATION],
            format!("http://storage.invalid/{key}").as_str()
        );
        // The redirect itself carries the artifact's validator,
        // so a client can verify the bytes it is sent for.
        assert_eq!(response.headers()[header::ETAG], etag_of(BODY).as_str());

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn private_cache_never_redirects() {
        // Private cache: the backend is always asked to stream
        // (prefer_stream = true); the response is the bytes,
        // never a redirect.
        let rig = rig("posture-private", false).await;
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;
        let cache = cache_name();
        rig.reset_prefer_stream();

        let (response, _) = serve(
            &rig,
            &pull_auth(),
            &request(&cache, "widget", "1.0.0", FILENAME),
        )
        .await
        .unwrap();

        assert_eq!(rig.last_prefer_stream(), 1);
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(body_bytes(response).await, BODY);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn missing_object_behind_row_is_500() {
        let rig = rig("missing-object", false).await;
        upload(&rig, "widget", "1.0.0", FILENAME, BODY).await;
        let cache = cache_name();

        // Delete the object out from under its row.
        let digest: [u8; 32] = Sha256::digest(BODY).into();
        let key = artifact_key(rig.cache_id, &digest);
        rig.storage.delete_file(key).await.unwrap();

        let status = error_status(
            serve(
                &rig,
                &pull_auth(),
                &request(&cache, "widget", "1.0.0", FILENAME),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        // Ranged reads hit the same inconsistency, not a 404
        // and not a truncated 206.
        let mut req = request(&cache, "widget", "1.0.0", FILENAME);
        req.range = Some("bytes=0-3");
        let status = error_status(serve(&rig, &pull_auth(), &req).await).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }

    #[tokio::test]
    async fn traversal_tokens_are_400() {
        let rig = rig("traversal", false).await;
        let cache = cache_name();

        // Rejected by the shared validation discipline, before
        // any database or storage touch: separators, control
        // shapes, whitespace, emptiness, `..` in the filename.
        let cases: [(&str, &str, &str); 5] = [
            ("wid get", "1.0.0", FILENAME),
            ("", "1.0.0", FILENAME),
            ("widget", "../1.0.0", FILENAME),
            ("widget", "1.0.0", "../../etc/passwd"),
            ("widget", "1.0.0", "a/b.tar.gz"),
        ];

        for (name, version, filename) in cases {
            let status = error_status(
                serve(
                    &rig,
                    &pull_auth(),
                    &request(&cache, name, version, filename),
                )
                .await,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{name} {version} {filename}"
            );
        }

        // A `..` name passes the charset (dots are legal in the
        // upload discipline) but is a pure database key: nothing
        // is stored under it, so it is a 404 — and it can never
        // address storage, because objects are fetched by digest
        // key only.
        let status = error_status(
            serve(
                &rig,
                &pull_auth(),
                &request(&cache, "..", "1.0.0", FILENAME),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        tokio::fs::remove_dir_all(&rig.root).await.ok();
    }
}
