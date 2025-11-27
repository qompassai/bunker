use crate::signing::NixKeypair;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCacheRequest {
    pub keypair: KeypairConfig,
    pub is_public: bool,
    pub store_dir: String,
    pub priority: i32,

    pub upstream_cache_key_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keypair: Option<KeypairConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub substituter_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_dir: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_cache_key_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_period: Option<RetentionPeriodConfig>,
}
#[derive(Debug, Serialize, Deserialize)]
pub enum KeypairConfig {
    Generate,
    Keypair(NixKeypair),
}
#[derive(Debug, Serialize, Deserialize)]
pub enum RetentionPeriodConfig {
    Global,
    Period(u32),
}
impl CacheConfig {
    pub fn blank() -> Self {
        Self {
            keypair: None,
            substituter_endpoint: None,
            api_endpoint: None,
            public_key: None,
            is_public: None,
            store_dir: None,
            priority: None,
            upstream_cache_key_names: None,
            retention_period: None,
        }
    }
}
