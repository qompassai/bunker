use std::error::Error as StdError;
use std::fmt;
use std::path::Path;
use std::time::Duration;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use const_format::concatcp;
use displaydoc::Display;
use futures::{
    future,
    stream::{self, StreamExt, TryStream, TryStreamExt},
};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT},
    redirect::Policy,
    Body, Client as HttpClient, Response, StatusCode, Url,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::config::ServerConfig;
use crate::version::BUNKER_DISTRIBUTOR;
use bunker::api::v1::artifacts::{
    ArtifactUploadRequest, ArtifactUploadResponse, BUNKER_ARTIFACT_INFO, BUNKER_ARTIFACT_SHA256,
    BUNKER_ARTIFACT_SIZE,
};
use bunker::api::v1::cache_config::{CacheConfig, CreateCacheRequest};
use bunker::api::v1::get_missing_paths::{GetMissingPathsRequest, GetMissingPathsResponse};
use bunker::api::v1::upload_path::{
    UploadPathNarInfo, UploadPathResult, BUNKER_NAR_INFO, BUNKER_NAR_INFO_PREAMBLE_SIZE,
};
use bunker::cache::CacheName;
use bunker::nix_store::StorePathHash;

const BUNKER_USER_AGENT: &str =
    concatcp!("Bunker/{} ({})", env!("CARGO_PKG_NAME"), BUNKER_DISTRIBUTOR);

const NAR_INFO_PREAMBLE_THRESHOLD: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct ApiClient {
    endpoint: Url,
    client: HttpClient,

    /// Client used for artifact downloads. Identical to
    /// `client`, except that it never follows redirects
    /// automatically: the download path must see the bunker
    /// server's own response (its ETag is the digest the bytes
    /// are verified against), even when that response is a
    /// redirect to storage.
    download_client: HttpClient,
}

/// What a successful artifact download proved about the bytes
/// it wrote.
#[derive(Debug)]
pub struct DownloadedArtifact {
    /// Total bytes written to the destination.
    pub bytes_written: u64,

    /// Lowercase hex SHA-256 of the downloaded bytes, computed
    /// while streaming. `download_artifact` verified it against
    /// the digest the server served before returning.
    pub sha256: String,

    /// The artifact version actually served. For a `latest`
    /// request this is the version the pointer resolved to,
    /// read off the server's `X-Bunker-Artifact-Version`
    /// header; otherwise it equals the requested version.
    pub version: String,
}

/// The grace period, in seconds, allowed for one artifact
/// download request before reqwest gives up.
const DOWNLOAD_TIMEOUT_SECS: u64 = 600;

/// Header carrying the artifact's SHA-256 as a quoted ETag.
const ETAG_HEADER: &str = "etag";

/// Header the server sets on `latest` responses naming the
/// resolved version.
const VERSION_HEADER: &str = "x-bunker-artifact-version";

// Artifact addressing limits, mirroring the server's
// validation (server/src/api/v1/artifacts.rs is the source of
// truth). Downloads validate against these before a URL is
// built, because URL parsing normalizes traversal segments
// away instead of reporting them.
const MAX_ARTIFACT_FILENAME_LEN: usize = 128;
const MAX_ARTIFACT_NAME_LEN: usize = 50;
const MAX_ARTIFACT_VERSION_LEN: usize = 64;
/// Error returned by a Bunker API call.
#[derive(Debug, Display)]
pub enum ApiError {
    /// {0}
    Structured(StructuredApiError),
    /// HTTP {0}: {1}
    Unstructured(StatusCode, String),
}
#[derive(Debug, Clone, Deserialize)]
pub struct StructuredApiError {
    #[allow(dead_code)]
    code: u16,
    error: String,
    message: String,
}
impl ApiClient {
    pub fn from_server_config(config: ServerConfig) -> Result<Self> {
        let token = config.token()?;
        let client = build_http_client(token.as_deref());
        let download_client = build_download_client(token.as_deref());

        Ok(Self {
            endpoint: Url::parse(&config.endpoint)?,
            client,
            download_client,
        })
    }
    pub fn set_endpoint(&mut self, endpoint: &str) -> Result<()> {
        self.endpoint = Url::parse(endpoint)?;
        Ok(())
    }
    pub async fn get_cache_config(&self, cache: &CacheName) -> Result<CacheConfig> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.get(endpoint).send().await?;

        if res.status().is_success() {
            let cache_config = res.json().await?;
            Ok(cache_config)
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }
    pub async fn create_cache(&self, cache: &CacheName, request: CreateCacheRequest) -> Result<()> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.post(endpoint).json(&request).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }
    pub async fn configure_cache(&self, cache: &CacheName, config: &CacheConfig) -> Result<()> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.patch(endpoint).json(&config).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }
    pub async fn destroy_cache(&self, cache: &CacheName) -> Result<()> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.delete(endpoint).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }
    pub async fn get_missing_paths(
        &self,
        cache: &CacheName,
        store_path_hashes: Vec<StorePathHash>,
    ) -> Result<GetMissingPathsResponse> {
        let endpoint = self.endpoint.join("_api/v1/get-missing-paths")?;
        let payload = GetMissingPathsRequest {
            cache: cache.to_owned(),
            store_path_hashes,
        };

        let res = self.client.post(endpoint).json(&payload).send().await?;

        if res.status().is_success() {
            let cache_config = res.json().await?;
            Ok(cache_config)
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }
    pub async fn upload_path<S>(
        &self,
        nar_info: UploadPathNarInfo,
        stream: S,
        force_preamble: bool,
    ) -> Result<Option<UploadPathResult>>
    where
        S: TryStream<Ok = Bytes> + Send + Sync + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
    {
        let endpoint = self.endpoint.join("_api/v1/upload-path")?;
        let upload_info_json = serde_json::to_string(&nar_info)?;

        let mut req = self
            .client
            .put(endpoint)
            .header(USER_AGENT, HeaderValue::from_str(BUNKER_USER_AGENT)?);
        if force_preamble || upload_info_json.len() >= NAR_INFO_PREAMBLE_THRESHOLD {
            let preamble = Bytes::from(upload_info_json);
            let preamble_len = preamble.len();
            let preamble_stream = stream::once(future::ok(preamble));
            let chained = preamble_stream.chain(stream.into_stream());
            req = req
                .header(BUNKER_NAR_INFO_PREAMBLE_SIZE, preamble_len)
                .body(Body::wrap_stream(chained));
        } else {
            req = req
                .header(BUNKER_NAR_INFO, HeaderValue::from_str(&upload_info_json)?)
                .body(Body::wrap_stream(stream));
        }
        let res = req.send().await?;
        if res.status().is_success() {
            match res.json().await {
                Ok(r) => Ok(Some(r)),
                Err(_) => Ok(None),
            }
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Uploads one artifact to a cache.
    ///
    /// The file is streamed to the server in bounded chunks; it
    /// is never loaded into memory. `sha256` and `size` are the
    /// digest and byte count the client computed for the file;
    /// the server verifies what it receives against them and
    /// rejects the upload on mismatch.
    pub async fn upload_artifact(
        &self,
        request: &ArtifactUploadRequest,
        sha256: &str,
        size: u64,
        file: tokio::fs::File,
    ) -> Result<ArtifactUploadResponse> {
        let endpoint = self.endpoint.join("_api/v1/artifacts")?;
        let info_json = serde_json::to_string(request)?;

        let stream = stream::try_unfold(file, |mut file| async move {
            let mut buf = vec![0u8; 64 * 1024];
            let n = file.read(&mut buf).await?;
            if n == 0 {
                Ok::<Option<(Bytes, tokio::fs::File)>, std::io::Error>(None)
            } else {
                buf.truncate(n);
                Ok(Some((Bytes::from(buf), file)))
            }
        });

        let res = self
            .client
            .put(endpoint)
            .header(USER_AGENT, HeaderValue::from_str(BUNKER_USER_AGENT)?)
            .header(BUNKER_ARTIFACT_INFO, HeaderValue::from_str(&info_json)?)
            .header(BUNKER_ARTIFACT_SHA256, HeaderValue::from_str(sha256)?)
            .header(
                BUNKER_ARTIFACT_SIZE,
                HeaderValue::from_str(&size.to_string())?,
            )
            .body(Body::wrap_stream(stream))
            .send()
            .await?;

        if res.status().is_success() {
            let response = res.json().await?;
            Ok(response)
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Downloads an artifact from a cache to a local path.
    ///
    /// `version` may be `latest`, in which case the server
    /// resolves its latest-version pointer and reports the
    /// resolved version in the returned value.
    ///
    /// The bytes are streamed to `<dest>.part` while their
    /// SHA-256 is computed, then verified against the digest
    /// the server served (its ETag) and the served byte count.
    /// Only a verified download is moved into place at `dest`;
    /// on any mismatch the partial file is deleted and an error
    /// is returned — a corrupt or substituted artifact is never
    /// left behind as if it were the real one.
    ///
    /// A public cache on remote storage answers with a
    /// redirect to a presigned URL. That single hop is followed
    /// manually, with a header-less client: the cache token is
    /// never sent to the storage host, and verification still
    /// uses the digest from the bunker server's own response.
    pub async fn download_artifact(
        &self,
        cache: &CacheName,
        name: &str,
        version: &str,
        filename: &str,
        dest: &Path,
    ) -> Result<DownloadedArtifact> {
        validate_artifact_address(name, version, filename)?;

        let url = self.endpoint.join(&format!(
            "{}/artifacts/{}/{}/{}",
            cache, name, version, filename
        ))?;

        let first = self
            .download_client
            .get(url)
            .header(USER_AGENT, HeaderValue::from_str(BUNKER_USER_AGENT)?)
            .send()
            .await?;

        let status = first.status();

        // The digest and resolved version always come from the
        // bunker server's response — on a redirect, never from
        // the storage host's response.
        let expected_sha256 = if status.is_success() || status.is_redirection() {
            Some(parse_etag_digest(&first)?)
        } else {
            None
        };
        let served_version = first
            .headers()
            .get(VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| version.to_owned());

        let response = if status.is_redirection() {
            let location = first
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| anyhow!("Artifact download redirect has no Location"))?
                .to_owned();

            // Header-less on purpose: no cache token rides
            // along to the storage host.
            let bare = HttpClient::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
                .build()?;

            let second = bare.get(&location).send().await?;
            if second.status().is_redirection() {
                return Err(anyhow!(
                    "Artifact download redirected more than once; refusing to follow"
                ));
            }
            second
        } else {
            first
        };

        if !response.status().is_success() {
            let api_error = ApiError::try_from_response(response).await?;
            return Err(api_error.into());
        }

        let expected_sha256 = match expected_sha256 {
            Some(digest) => digest,
            None => return Err(anyhow!("Artifact response carries no verifiable digest")),
        };
        let content_length = response.content_length();

        let mut part_path = dest.as_os_str().to_owned();
        part_path.push(".part");
        let part_path = std::path::PathBuf::from(part_path);

        let outcome = stream_to_file(response, &part_path).await;

        let (sha256, bytes_written) = match outcome {
            Ok(pair) => pair,
            Err(e) => {
                let _ = tokio::fs::remove_file(&part_path).await;
                return Err(e);
            }
        };

        if sha256 != expected_sha256 {
            let _ = tokio::fs::remove_file(&part_path).await;
            return Err(anyhow!(
                "Artifact digest mismatch: the server declared sha256 {} but the downloaded bytes hash to {}. The download was discarded; nothing was written to {}.",
                expected_sha256,
                sha256,
                dest.display()
            ));
        }

        if let Some(expected_len) = content_length {
            if bytes_written != expected_len {
                let _ = tokio::fs::remove_file(&part_path).await;
                return Err(anyhow!(
                    "Artifact size mismatch: the server declared {} bytes but {} were downloaded. The download was discarded; nothing was written to {}.",
                    expected_len,
                    bytes_written,
                    dest.display()
                ));
            }
        }

        tokio::fs::rename(&part_path, dest).await?;

        Ok(DownloadedArtifact {
            bytes_written,
            sha256,
            version: served_version,
        })
    }
}

/// Streams a response body to `path`, computing the SHA-256
/// of the bytes as they pass. Returns the hex digest and the
/// byte count.
async fn stream_to_file(response: Response, path: &Path) -> Result<(String, u64)> {
    let mut file = tokio::fs::File::create(path).await?;
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        hasher.update(&chunk);
        written += chunk.len() as u64;
    }
    file.flush().await?;

    Ok((hex::encode(hasher.finalize()), written))
}

/// Extracts the hex SHA-256 from a response's ETag. The
/// artifact route serves the artifact's digest as a quoted
/// strong ETag; anything else means the bytes cannot be
/// verified, which is an error, not a download.
fn parse_etag_digest(response: &Response) -> Result<String> {
    let etag = response
        .headers()
        .get(ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow!("Artifact response carries no ETag; cannot verify the download"))?;

    let digest = etag
        .trim()
        .strip_prefix("W/")
        .unwrap_or(etag.trim())
        .trim_matches('"');

    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "Artifact response ETag {:?} is not a SHA-256 digest; cannot verify the download",
            etag
        ));
    }

    Ok(digest.to_lowercase())
}

/// Rejects an artifact address the server would reject,
/// before a URL is built from it. URL parsing normalizes
/// traversal segments away, so checking after construction
/// would be checking nothing.
fn validate_artifact_address(name: &str, version: &str, filename: &str) -> Result<()> {
    fn check(field: &str, value: &str, max_len: usize) -> Result<()> {
        if value.is_empty()
            || value.len() > max_len
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        {
            return Err(anyhow!(
                "Invalid artifact {} {:?}: use 1-{} characters from [A-Za-z0-9._+-]",
                field,
                value,
                max_len
            ));
        }
        Ok(())
    }

    check("name", name, MAX_ARTIFACT_NAME_LEN)?;
    check("version", version, MAX_ARTIFACT_VERSION_LEN)?;
    check("filename", filename, MAX_ARTIFACT_FILENAME_LEN)?;

    if filename == ".." || filename == "." {
        return Err(anyhow!("Invalid artifact filename {:?}", filename));
    }

    Ok(())
}
impl StdError for ApiError {}
impl ApiError {
    async fn try_from_response(response: Response) -> Result<Self> {
        let status = response.status();
        let text = response.text().await?;
        match serde_json::from_str(&text) {
            Ok(s) => Ok(Self::Structured(s)),
            Err(_) => Ok(Self::Unstructured(status, text)),
        }
    }
}
impl fmt::Display for StructuredApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}
fn build_http_client(token: Option<&str>) -> HttpClient {
    reqwest::Client::builder()
        .default_headers(auth_headers(token))
        .build()
        .unwrap()
}

fn build_download_client(token: Option<&str>) -> HttpClient {
    reqwest::Client::builder()
        .default_headers(auth_headers(token))
        .redirect(Policy::none())
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .build()
        .unwrap()
}

fn auth_headers(token: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        let auth_header = HeaderValue::from_str(&format!("bearer {}", token)).unwrap();
        headers.insert(AUTHORIZATION, auth_header);
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    const BODY: &[u8] = b"client pull test bytes, served fresh";
    const TOKEN: &str = "test-token-123";

    fn etag_of(bytes: &[u8]) -> String {
        format!("\"{}\"", hex::encode(Sha256::digest(bytes)))
    }

    fn test_client(endpoint: &str) -> ApiClient {
        ApiClient {
            endpoint: Url::parse(endpoint).unwrap(),
            client: build_http_client(Some(TOKEN)),
            download_client: build_download_client(Some(TOKEN)),
        }
    }

    fn cache() -> CacheName {
        CacheName::new("test-cache".to_owned()).unwrap()
    }

    fn dest_dir(test: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "bunker-client-test-{}-{}-{}",
            std::process::id(),
            test,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A one-shot HTTP server: answers each queued response in
    /// order, recording the head of every request it receives.
    struct FakeServer {
        base: String,
        requests: Arc<Mutex<Vec<String>>>,
    }

    async fn fake_server(build: impl FnOnce(&str) -> Vec<Vec<u8>>) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}/", addr);
        let responses = build(&base);
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();

        tokio::spawn(async move {
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                recorded
                    .lock()
                    .await
                    .push(String::from_utf8_lossy(&buf).into_owned());
                socket.write_all(&response).await.unwrap();
                socket.shutdown().await.ok();
            }
        });

        FakeServer { base, requests }
    }

    fn ok_response(body: &[u8], etag: &str, resolved_version: Option<&str>) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\netag: {}\r\n",
            body.len(),
            etag
        );
        if let Some(version) = resolved_version {
            head += &format!("x-bunker-artifact-version: {}\r\n", version);
        }
        head += "\r\n";
        let mut response = head.into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn redirect_response(location: &str, etag: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 307 Temporary Redirect\r\ncontent-length: 0\r\netag: {}\r\nlocation: {}\r\n\r\n",
            etag, location
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn downloads_and_verifies_direct_200() {
        let server = fake_server(|_| vec![ok_response(BODY, &etag_of(BODY), Some("2.0.0"))]).await;
        let client = test_client(&server.base);
        let dir = dest_dir("direct");
        let dest = dir.join("widget.tar.gz");

        let downloaded = client
            .download_artifact(&cache(), "widget", "latest", "widget.tar.gz", &dest)
            .await
            .unwrap();

        assert_eq!(downloaded.version, "2.0.0");
        assert_eq!(downloaded.bytes_written, BODY.len() as u64);
        assert_eq!(downloaded.sha256, hex::encode(Sha256::digest(BODY)));
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), BODY);
        assert!(!dir.join("widget.tar.gz.part").exists());

        let requests = server.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains(&format!("authorization: bearer {}", TOKEN)));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rejects_corrupt_body_and_leaves_nothing() {
        // The served digest names different bytes than the body
        // carries: a substituted or corrupted artifact.
        let server = fake_server(|_| {
            vec![ok_response(
                BODY,
                &etag_of(b"some other bytes entirely"),
                None,
            )]
        })
        .await;
        let client = test_client(&server.base);
        let dir = dest_dir("corrupt");
        let dest = dir.join("widget.tar.gz");

        let err = client
            .download_artifact(&cache(), "widget", "1.0.0", "widget.tar.gz", &dest)
            .await
            .unwrap_err();

        assert!(
            format!("{:?}", err).contains("digest mismatch"),
            "{:?}",
            err
        );
        assert!(!dest.exists());
        assert!(!dir.join("widget.tar.gz.part").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn follows_one_redirect_and_verifies_against_first_etag() {
        // The storage response carries a WRONG etag of its own;
        // verification must use the bunker server's (the first
        // response's) etag, so the download still succeeds.
        let server = fake_server(|base| {
            vec![
                redirect_response(&format!("{}storage/object", base), &etag_of(BODY)),
                ok_response(BODY, &etag_of(b"unrelated"), None),
            ]
        })
        .await;
        let client = test_client(&server.base);
        let dir = dest_dir("redirect");
        let dest = dir.join("widget.tar.gz");

        let downloaded = client
            .download_artifact(&cache(), "widget", "1.0.0", "widget.tar.gz", &dest)
            .await
            .unwrap();

        assert_eq!(downloaded.bytes_written, BODY.len() as u64);
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), BODY);

        let requests = server.requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains(&format!("authorization: bearer {}", TOKEN)));
        // The storage hop must not carry the cache token.
        assert!(!requests[1].to_lowercase().contains("authorization"));
        assert!(requests[1].contains("/storage/object"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn second_redirect_is_refused() {
        let server = fake_server(|base| {
            let location = format!("{}loop", base);
            vec![
                redirect_response(&location, &etag_of(BODY)),
                redirect_response(&location, &etag_of(BODY)),
            ]
        })
        .await;
        let client = test_client(&server.base);
        let dir = dest_dir("loop");
        let dest = dir.join("widget.tar.gz");

        let err = client
            .download_artifact(&cache(), "widget", "1.0.0", "widget.tar.gz", &dest)
            .await
            .unwrap_err();

        assert!(format!("{:?}", err).contains("more than once"), "{:?}", err);
        assert!(!dest.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn unknown_artifact_is_an_error_and_writes_nothing() {
        let body = br#"{"code":404,"error":"Not Found","message":"no such artifact"}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let mut response = response.into_bytes();
        response.extend_from_slice(body);

        let server = fake_server(|_| vec![response]).await;
        let client = test_client(&server.base);
        let dir = dest_dir("missing");
        let dest = dir.join("widget.tar.gz");

        let result = client
            .download_artifact(&cache(), "widget", "1.0.0", "widget.tar.gz", &dest)
            .await;

        assert!(result.is_err());
        assert!(!dest.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn artifact_address_validation_rejects_traversal() {
        assert!(validate_artifact_address("widget", "1.0.0", "f.tar.gz").is_ok());
        assert!(validate_artifact_address("widget", "latest", "f.tar.gz").is_ok());
        assert!(validate_artifact_address("../widget", "1.0.0", "f.tar.gz").is_err());
        assert!(validate_artifact_address("widget", "../1.0.0", "f.tar.gz").is_err());
        assert!(validate_artifact_address("widget", "1.0.0", "../../etc/passwd").is_err());
        assert!(validate_artifact_address("widget", "1.0.0", "..").is_err());
        assert!(validate_artifact_address("", "1.0.0", "f.tar.gz").is_err());
    }
}
