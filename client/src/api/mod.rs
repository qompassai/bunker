use std::error::Error as StdError;
use std::fmt;
use anyhow::Result;
use bytes::Bytes;
use const_format::concatcp;
use displaydoc::Display;
use futures::{
    future,
    stream::{self, StreamExt, TryStream, TryStreamExt},
};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT},
    Body, Client as HttpClient, Response, StatusCode, Url,
};
use serde::Deserialize;
use crate::config::ServerConfig;
use crate::version::BUNKER_DISTRIBUTOR;
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
}
#[derive(Debug, Display)]
pub enum ApiError {
    Structured(StructuredApiError),
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
        let client = build_http_client(config.token()?.as_deref());

        Ok(Self {
            endpoint: Url::parse(&config.endpoint)?,
            client,
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
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        let auth_header = HeaderValue::from_str(&format!("bearer {}", token)).unwrap();
        headers.insert(AUTHORIZATION, auth_header);
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}
