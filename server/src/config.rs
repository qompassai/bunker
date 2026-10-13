// /qompassai/bunker/server/src/config.rs
// Qompass AI Bunker Server Config
// Copyright (C) 2025 Qompass AI, All rights reserved
/////////////////////////////////////////////////////
//! Server configuration.
use crate::access::{
    decode_token_ed25519_pubkey_base64, decode_token_ed25519_secret_base64, Ed25519KeyPair,
    Ed25519PublicKey,
};
use crate::narinfo::Compression as NixCompression;
use crate::storage::{LocalStorageConfig, S3StorageConfig};
use anyhow::{anyhow, Context, Result};
use async_compression::Level as CompressionLevel;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use bunker::signing::HybridKeypair;
use bunker_token::SignatureType;
use derivative::Derivative;
use serde::{de, Deserialize};
use std::collections::HashSet;
use std::env;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use xdg::BaseDirectories;

/// Application prefix in XDG base directories.
///
/// This will be concatenated into `$XDG_CONFIG_HOME/bunker`. # TO DO
const XDG_PREFIX: &str = "bunker";

/// Environment variable storing the Base64-encoded TOML configuration.
///
/// This is useful for deploying to certain application platforms like Fly.io
const ENV_CONFIG_BASE64: &str = "BUNKER_SERVER_CONFIG_BASE64";

/// Environment variable storing the base64-encoded Ed25519 PEM private key (used for signing and
/// verifying received JWTs).
const ENV_TOKEN_ED25519_SECRET_BASE64: &str = "BUNKER_SERVER_TOKEN_ED25519_SECRET_BASE64";

/// Environment variable storing the base64-encoded Ed25519 PEM public key (used for verifying
/// received JWTs only).
const ENV_TOKEN_ED25519_PUBKEY_BASE64: &str = "BUNKER_SERVER_TOKEN_ED25519_PUBKEY_BASE64";

/// Environment variable storing the database connection string.
const ENV_DATABASE_URL: &str = "BUNKER_SERVER_DATABASE_URL";

/// Configuration for the Bunker Server.
#[derive(Clone, Derivative, Deserialize)]
#[derivative(Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Socket address to listen on.
    #[serde(default = "default_listen_address")]
    pub listen: SocketAddr,

    /// Allowed `Host` headers.
    ///
    /// This _must_ be configured for production use. If unconfigured or the
    /// list is empty, all `Host` headers are allowed.
    #[serde(rename = "allowed-hosts")]
    #[serde(default = "Vec::new")]
    pub allowed_hosts: Vec<String>,

    /// The canonical API endpoint of this server.
    ///
    /// This is the endpoint exposed to clients in `cache-config` responses.
    ///
    /// This _must_ be configured for production use. If not configured, the
    /// API endpoint is synthesized from the client's `Host` header which may
    /// be insecure.
    ///
    /// The API endpoint _must_ end with a slash (e.g., `https://domain.tld/bunker/`
    /// not `https://domain.tld/bunker`). # TO DO
    #[serde(rename = "api-endpoint")]
    pub api_endpoint: Option<String>,

    /// The canonical Nix Binary Cache endpoint of this server.
    ///
    /// This is usually the same as `api_endpoint` but can be configured
    /// to a different value.
    ///
    /// If unconfigured, it's assumed to be the same as `api_endpoint`.
    #[serde(rename = "substituter-endpoint")]
    pub substituter_endpoint: Option<String>,

    /// Whether to soft-delete caches.
    ///
    /// If this is enabled, caches are soft-deleted instead of actually
    /// removed from the database. Note that soft-deleted caches cannot
    /// have their names reused as long as the original database records
    /// are there.
    #[serde(rename = "soft-delete-caches")]
    #[serde(default = "default_soft_delete_caches")]
    pub soft_delete_caches: bool,

    /// Whether to require fully uploading a NAR if it exists in the global cache.
    ///
    /// If set to false, simply knowing the NAR hash is enough for
    /// an uploader to gain access to an existing NAR in the global
    /// cache.
    #[serde(rename = "require-proof-of-possession")]
    #[serde(default = "default_require_proof_of_possession")]
    pub require_proof_of_possession: bool,

    /// Database connection.
    pub database: DatabaseConfig,

    /// Storage.
    pub storage: StorageConfig,

    /// Data chunking.
    pub chunking: ChunkingConfig,

    /// Compression.
    #[serde(default = "Default::default")]
    pub compression: CompressionConfig,

    /// Garbage collection.
    #[serde(rename = "garbage-collection")]
    #[serde(default = "Default::default")]
    pub garbage_collection: GarbageCollectionConfig,

    /// Artifact serving.
    #[serde(default = "Default::default")]
    pub artifacts: ArtifactsConfig,

    /// JSON Web Token.
    #[serde(default = "Default::default")]
    pub jwt: JWTConfig,

    /// Cache signing.
    #[serde(default = "Default::default")]
    pub signing: SigningConfig,

    /// The hybrid signing keypair loaded from `signing.hybrid-secret-key-file`.
    ///
    /// Populated by [`load_config`] after deserialization; it is never read
    /// from the TOML configuration itself. When present, narinfos are signed
    /// with this key (hybrid Ed25519 + ML-DSA-65) instead of the per-cache
    /// classical keypair stored in the database.
    #[serde(skip)]
    #[derivative(Debug = "ignore")]
    pub hybrid_keypair: Option<Arc<HybridKeypair>>,

    /// (Deprecated Stub)
    ///
    /// This simply results in an error telling the user to update
    /// their configuration.
    #[serde(rename = "token-hs256-secret-base64")]
    #[serde(default = "Default::default")]
    #[serde(deserialize_with = "deserialize_deprecated_token_hs256_secret")]
    #[derivative(Debug = "ignore")]
    pub _depreated_token_hs256_secret: Option<String>,
}

/// Default maximum size of a single artifact upload: 1 GiB.
pub const DEFAULT_MAX_ARTIFACT_SIZE: u64 = 1 << 30;

/// Artifact serving configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ArtifactsConfig {
    /// Maximum size of a single artifact upload, in bytes.
    ///
    /// Uploads whose body exceeds this are rejected while they
    /// stream; nothing is stored for them.
    #[serde(rename = "max-size", default = "default_max_artifact_size")]
    pub max_size: u64,
}

impl Default for ArtifactsConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_ARTIFACT_SIZE,
        }
    }
}

fn default_max_artifact_size() -> u64 {
    DEFAULT_MAX_ARTIFACT_SIZE
}

/// JSON Web Token configuration.
#[derive(Clone, Derivative, Deserialize)]
#[derivative(Debug)]
pub struct JWTConfig {
    /// The `iss` claim of the JWT.
    ///
    /// If specified, received JWTs must have this claim, and its value must match this
    /// configuration.
    #[serde(rename = "token-bound-issuer")]
    #[serde(default = "Default::default")]
    pub token_bound_issuer: Option<String>,

    /// The `aud` claim of the JWT.
    ///
    /// If specified, received JWTs must have this claim, and must contain one of the configured
    /// values.
    #[serde(rename = "token-bound-audiences")]
    #[serde(default = "Default::default")]
    pub token_bound_audiences: Option<HashSet<String>>,

    /// JSON Web Token signing.
    #[serde(rename = "signing")]
    #[serde(default = "load_jwt_signing_config_from_env")]
    #[derivative(Debug = "ignore")]
    pub signing_config: JWTSigningConfig,
}

/// JSON Web Token signing configuration.
///
/// Only EdDSA (Ed25519) is supported. HS256 and RS256 were removed to
/// prevent algorithm-confusion attacks.
#[derive(Clone, Deserialize)]
pub enum JWTSigningConfig {
    /// JSON Web Token Ed25519 pubkey.
    ///
    /// Set this to the base64-encoded Ed25519 PEM public key to use for verifying JWTs only.
    #[serde(rename = "token-ed25519-pubkey-base64")]
    #[serde(deserialize_with = "deserialize_token_ed25519_pubkey_base64")]
    EdDSAVerifyOnly(Ed25519PublicKey),

    /// JSON Web Token Ed25519 secret.
    ///
    /// Set this to the base64-encoded Ed25519 PEM private key to use for signing and verifying
    /// JWTs.
    #[serde(rename = "token-ed25519-secret-base64")]
    #[serde(deserialize_with = "deserialize_token_ed25519_secret_base64")]
    EdDSASignAndVerify(Box<Ed25519KeyPair>),
}

impl From<JWTSigningConfig> for SignatureType {
    fn from(value: JWTSigningConfig) -> Self {
        match value {
            JWTSigningConfig::EdDSAVerifyOnly(key) => Self::EdDSAPubkeyOnly(key),
            JWTSigningConfig::EdDSASignAndVerify(key) => Self::EdDSA(key),
        }
    }
}

/// Cache signing configuration.
///
/// The hybrid signing key itself is never stored in the configuration file:
/// only its expected name and the path of the file holding it. The file is
/// read and strictly validated when the configuration is loaded (see
/// [`load_config`]), so a bad key fails `bunkerd --mode check-config` and
/// server startup alike.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SigningConfig {
    /// Expected name of the hybrid signing key.
    ///
    /// Must match the name embedded in the hybrid secret key file; a
    /// mismatch is a hard error at load time.
    #[serde(rename = "hybrid-key-name")]
    #[serde(default = "Default::default")]
    pub hybrid_key_name: Option<String>,

    /// Path to the file containing the hybrid secret key in canonical
    /// format (`{name}:{base64}` over a 96-byte payload).
    #[serde(rename = "hybrid-secret-key-file")]
    #[serde(default = "Default::default")]
    pub hybrid_secret_key_file: Option<PathBuf>,
}

/// Database connection configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Connection URL.
    #[serde(default = "load_database_url_from_env")]
    pub url: String,

    /// Whether to enable sending of periodic heartbeat queries.
    ///
    /// If enabled, a heartbeat query will be sent every minute.
    #[serde(default = "default_db_heartbeat")]
    pub heartbeat: bool,
}

/// File storage configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum StorageConfig {
    /// Local file storage.
    #[serde(rename = "local")]
    Local(LocalStorageConfig),

    /// S3 storage.
    #[serde(rename = "s3")]
    S3(S3StorageConfig),
}

/// Data chunking.
///
/// This must be set, but a default set of values is provided
/// through the OOBE sequence. The reason is that this allows
/// us to provide a new set of recommended "defaults" for newer
/// deployments without affecting existing ones.
///
/// Warning: If you change any of the values here, it will be
/// difficult to reuse existing chunks for newly-uploaded NARs
/// since the cutpoints will be different. As a result, the
/// deduplication ratio will suffer for a while after the change.
///
/// `bunkeradm test-chunking` provides a way to test chunking
/// on a set of files so you can fine-tune the values.
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkingConfig {
    /// The minimum NAR size to trigger chunking.
    ///
    /// If 0, chunking is disabled entirely for newly-uploaded
    /// NARs.
    ///
    /// If 1, all newly-uploaded NARs are chunked.
    ///
    /// By default, the threshold is 128KB.
    #[serde(rename = "nar-size-threshold")]
    pub nar_size_threshold: usize,

    /// The preferred minimum size of a chunk, in bytes.
    #[serde(rename = "min-size")]
    pub min_size: usize,

    /// The preferred average size of a chunk, in bytes.
    #[serde(rename = "avg-size")]
    pub avg_size: usize,

    /// The preferred maximum size of a chunk, in bytes.
    #[serde(rename = "max-size")]
    pub max_size: usize,
}

/// Compression configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CompressionConfig {
    /// Compression type.
    pub r#type: CompressionType,

    /// Compression level.
    ///
    /// If unspecified, Bunker will choose a default one.
    pub level: Option<i32>,
}

/// Compression type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum CompressionType {
    /// No compression.
    #[serde(rename = "none")]
    None,

    /// Brotli.
    #[serde(rename = "brotli")]
    Brotli,

    /// ZSTD.
    #[serde(rename = "zstd")]
    Zstd,

    /// XZ.
    #[serde(rename = "xz")]
    Xz,
}

/// Garbage collection config.
#[derive(Debug, Clone, Deserialize)]
pub struct GarbageCollectionConfig {
    /// The frequency to run garbage collection at.
    ///
    /// If zero, automatic garbage collection is disabled, but
    /// it can still be run manually with `bunkerd --mode garbage-collector-once`.
    #[serde(with = "humantime_serde", default = "default_gc_interval")]
    pub interval: Duration,

    /// The default retention period of unaccessed objects.
    ///
    /// Objects are subject to garbage collection if both the
    /// `created_at` and `last_accessed_at` timestamps are older
    /// than the retention period.
    ///
    /// Zero (default) means time-based garbage-collection is
    /// disabled by default. You can enable it on a per-cache basis.
    #[serde(rename = "default-retention-period")]
    #[serde(with = "humantime_serde", default = "default_default_retention_period")]
    pub default_retention_period: Duration,
}

fn load_jwt_signing_config_from_env() -> JWTSigningConfig {
    let config = if let Some(config) = load_token_ed25519_pubkey_from_env() {
        config
    } else if let Some(config) = load_token_ed25519_secret_from_env() {
        config
    } else {
        panic!(
            "\n\
            You must configure JWT signing and verification inside your TOML \
            configuration by setting one of the following options in the \
            [jwt.signing] block:\n\
            \n\
            * token-ed25519-pubkey-base64\n\
            * token-ed25519-secret-base64\n\
            \n\
            or by setting one of the following environment variables:\n\
            \n\
            * {ENV_TOKEN_ED25519_PUBKEY_BASE64}\n\
            * {ENV_TOKEN_ED25519_SECRET_BASE64}\n\
            \n\
            Options will be tried in that same order (configuration options \
            first, then environment options if none of the configuration options \
            were set, starting with the Ed25519 pubkey option, then the Ed25519 \
            secret option). \
            The first option that is found will be used.\n\
            \n\
            If an Ed25519 pubkey is \
            provided, it will only be possible to verify received JWTs, and not \
            sign new JWTs.\n\
            \n\
            If an Ed25519 secret is \
            provided, it will be used for both signing new JWTs and verifying \
            received JWTs.\n\
\n\
            "
        )
    };

    config
}

fn read_non_empty_var(key: &str) -> Result<Option<String>> {
    let value = match env::var(key) {
        Err(env::VarError::NotPresent) => {
            return Ok(None);
        }
        r => r?,
    };

    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn load_token_ed25519_secret_from_env() -> Option<JWTSigningConfig> {
    let s = read_non_empty_var(ENV_TOKEN_ED25519_SECRET_BASE64)
        .expect("Ed25519 environment cannot be read")?;

    let secret = decode_token_ed25519_secret_base64(&s).expect("Ed25519 secret cannot be decoded");

    Some(JWTSigningConfig::EdDSASignAndVerify(Box::new(secret)))
}

fn load_token_ed25519_pubkey_from_env() -> Option<JWTSigningConfig> {
    let s = read_non_empty_var(ENV_TOKEN_ED25519_PUBKEY_BASE64)
        .expect("Ed25519 pubkey environment cannot be read")?;

    let pubkey = decode_token_ed25519_pubkey_base64(&s).expect("Ed25519 pubkey cannot be decoded");

    Some(JWTSigningConfig::EdDSAVerifyOnly(pubkey))
}

fn load_database_url_from_env() -> String {
    env::var(ENV_DATABASE_URL).unwrap_or_else(|_| {
        panic!(
            "Database URL must be specified in either database.url \
        or the {ENV_DATABASE_URL} environment."
        )
    })
}

impl Default for JWTConfig {
    fn default() -> Self {
        Self {
            token_bound_issuer: None,
            token_bound_audiences: None,
            signing_config: load_jwt_signing_config_from_env(),
        }
    }
}

impl CompressionConfig {
    pub fn level(&self) -> CompressionLevel {
        if let Some(level) = self.level {
            return CompressionLevel::Precise(level);
        }

        match self.r#type {
            CompressionType::Brotli => CompressionLevel::Precise(5),
            CompressionType::Zstd => CompressionLevel::Precise(8),
            CompressionType::Xz => CompressionLevel::Precise(2),
            _ => CompressionLevel::Default,
        }
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            r#type: CompressionType::Zstd,
            level: None,
        }
    }
}

impl From<CompressionType> for NixCompression {
    fn from(t: CompressionType) -> Self {
        match t {
            CompressionType::None => NixCompression::None,
            CompressionType::Brotli => NixCompression::Brotli,
            CompressionType::Zstd => NixCompression::Zstd,
            CompressionType::Xz => NixCompression::Xz,
        }
    }
}

impl Default for GarbageCollectionConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(43200),
            default_retention_period: Duration::ZERO,
        }
    }
}

fn deserialize_deprecated_token_hs256_secret<'de, D>(
    _deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    use de::Error;

    Err(Error::custom(
        "\n\
            The token-hs256-secret-base64 field has been moved to [jwt.signing].\n\
            \n\
            To continue using HS256 signing, move your current config:\n\
            \n\
            token-hs256-secret-base64 = \"your token\"\n\
            \n\
            To the bottom of the file like so:\n\
            \n\
            [jwt.signing]\n\
            token-hs256-secret-base64 = \"your token\"\n\
            ",
    ))
}

fn deserialize_token_ed25519_secret_base64<'de, D>(
    deserializer: D,
) -> Result<Box<Ed25519KeyPair>, D::Error>
where
    D: de::Deserializer<'de>,
{
    use de::Error;

    let s = String::deserialize(deserializer)?;
    let key = decode_token_ed25519_secret_base64(&s).map_err(Error::custom)?;

    Ok(Box::new(key))
}

fn deserialize_token_ed25519_pubkey_base64<'de, D>(
    deserializer: D,
) -> Result<Ed25519PublicKey, D::Error>
where
    D: de::Deserializer<'de>,
{
    use de::Error;

    let s = String::deserialize(deserializer)?;
    let key = decode_token_ed25519_pubkey_base64(&s).map_err(Error::custom)?;

    Ok(key)
}

fn default_listen_address() -> SocketAddr {
    "[::]:8080".parse().unwrap()
}

fn default_db_heartbeat() -> bool {
    false
}

fn default_soft_delete_caches() -> bool {
    false
}

fn default_require_proof_of_possession() -> bool {
    true
}

fn default_gc_interval() -> Duration {
    Duration::from_secs(43200)
}

fn default_default_retention_period() -> Duration {
    Duration::ZERO
}

/// Maximum size of a hybrid secret key file, in bytes.
///
/// The canonical representation of a 96-byte payload is 128 base64
/// characters plus the key name and a colon; this bound is generous while
/// keeping the read bounded.
pub const HYBRID_SECRET_KEY_FILE_BYTES_MAX: u64 = 4096;

/// Message signed as a self-check probe when a hybrid key is loaded.
///
/// Signing this message and verifying the signature against the derived
/// public key proves that the secret and public halves of the loaded key
/// correspond to each other.
const HYBRID_KEY_PROBE_MESSAGE: &[u8] = b"bunker hybrid signing key self-check";

/// Reads a hybrid secret key file and parses it in canonical format.
///
/// Fail-closed: the read is bounded to [`HYBRID_SECRET_KEY_FILE_BYTES_MAX`]
/// bytes and the contents must parse strictly (valid key name, valid
/// base64, payload of exactly 96 bytes: a 64-byte Ed25519 keypair followed
/// by a 32-byte ML-DSA-65 seed). A trailing newline, as written by shell
/// redirection, is accepted.
pub fn read_hybrid_keypair_file(path: &Path) -> Result<HybridKeypair> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open hybrid secret key file: {}", path.display()))?;

    let mut contents = Vec::new();
    file.take(HYBRID_SECRET_KEY_FILE_BYTES_MAX + 1)
        .read_to_end(&mut contents)
        .with_context(|| format!("Failed to read hybrid secret key file: {}", path.display()))?;

    if contents.len() as u64 > HYBRID_SECRET_KEY_FILE_BYTES_MAX {
        return Err(anyhow!(
            "Hybrid secret key file {} is too large: {} bytes (maximum {})",
            path.display(),
            contents.len(),
            HYBRID_SECRET_KEY_FILE_BYTES_MAX
        ));
    }

    let text = String::from_utf8(contents).map_err(|_| {
        anyhow!(
            "Hybrid secret key file {} is not valid UTF-8",
            path.display()
        )
    })?;

    HybridKeypair::from_str(text.trim())
        .map_err(|e| anyhow!("Invalid hybrid secret key in {}: {e}", path.display()))
}

/// Loads a hybrid secret key file and validates it against the configured
/// key name.
///
/// Fail-closed checks (see the Phase-5 key-management runbook):
/// - the file parses strictly (canonical format, 96-byte payload);
/// - the key name embedded in the file equals `expected_name`;
/// - a probe signature verifies against the public key derived from the
///   secret, proving the secret and public halves correspond.
pub fn load_hybrid_keypair(expected_name: &str, path: &Path) -> Result<HybridKeypair> {
    let keypair = read_hybrid_keypair_file(path)?;

    if keypair.name() != expected_name {
        return Err(anyhow!(
            "Hybrid key name mismatch: the configuration expects {expected_name:?} \
            but the key file {} contains {:?}. Refusing to start: signatures \
            would be published under an unexpected identity.",
            path.display(),
            keypair.name()
        ));
    }

    let probe_signature = keypair.sign(HYBRID_KEY_PROBE_MESSAGE);
    keypair
        .to_public_key()
        .verify(HYBRID_KEY_PROBE_MESSAGE, &probe_signature)
        .map_err(|e| {
            anyhow!(
                "Hybrid key in {} failed its load-time self-check:                 a probe signature does not verify against the derived                 public key ({e}). The key file is corrupt or its halves                 do not correspond.",
                path.display()
            )
        })?;

    Ok(keypair)
}

impl Config {
    /// Loads the configured hybrid signing keypair, if any.
    ///
    /// `signing.hybrid-key-name` and `signing.hybrid-secret-key-file` must
    /// be configured together or not at all; a half-configured hybrid key
    /// is a hard error, never a silent fall-back to classical signing.
    fn load_configured_hybrid_keypair(&mut self) -> Result<()> {
        match (
            &self.signing.hybrid_key_name,
            &self.signing.hybrid_secret_key_file,
        ) {
            (None, None) => Ok(()),
            (Some(name), Some(path)) => {
                let keypair = load_hybrid_keypair(name, path)?;
                tracing::info!("Loaded hybrid signing key {name:?} from {}", path.display());
                self.hybrid_keypair = Some(Arc::new(keypair));
                Ok(())
            }
            (Some(_), None) => Err(anyhow!(
                "signing.hybrid-key-name is set but signing.hybrid-secret-key-file \
                is missing; configure both or neither"
            )),
            (None, Some(_)) => Err(anyhow!(
                "signing.hybrid-secret-key-file is set but signing.hybrid-key-name \
                is missing; configure both or neither"
            )),
        }
    }

    /// Returns the configured hybrid signing keypair, if one was loaded.
    pub fn hybrid_keypair(&self) -> Option<&HybridKeypair> {
        self.hybrid_keypair.as_deref()
    }
}

fn load_config_from_path(path: &Path) -> Result<Config> {
    tracing::info!("Using configurations: {:?}", path);

    let config = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&config)?)
}

fn load_config_from_str(s: &str) -> Result<Config> {
    tracing::info!("Using configurations from environment variable");
    Ok(toml::from_str(s)?)
}

/// Loads the configuration in the standard order.
///
/// After the TOML configuration is parsed, the configured hybrid signing
/// key (if any) is loaded and validated, so every mode of the server —
/// including `--mode check-config` — fails closed on a bad key.
pub async fn load_config(config_path: Option<&Path>, allow_oobe: bool) -> Result<Config> {
    let mut config = if let Some(config_path) = config_path {
        load_config_from_path(config_path)?
    } else if let Ok(config_env) = env::var(ENV_CONFIG_BASE64) {
        let decoded = String::from_utf8(BASE64_STANDARD.decode(config_env.as_bytes())?)?;
        load_config_from_str(&decoded)?
    } else {
        // Config from XDG
        let config_path = get_xdg_config_path()?;

        if allow_oobe {
            // Special OOBE sequence
            crate::oobe::run_oobe().await?;
        }

        load_config_from_path(&config_path)?
    };

    config.load_configured_hybrid_keypair()?;

    Ok(config)
}

pub fn get_xdg_config_path() -> anyhow::Result<PathBuf> {
    let xdg_dirs = BaseDirectories::with_prefix(XDG_PREFIX)?;
    let config_path = xdg_dirs.place_config_file("server.toml")?;

    Ok(config_path)
}

pub fn get_xdg_data_path() -> anyhow::Result<PathBuf> {
    let xdg_dirs = BaseDirectories::with_prefix(XDG_PREFIX)?;
    let data_path = xdg_dirs.create_data_directory("")?;

    Ok(data_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bunker::signing::hybrid::HYBRID_PUBKEY_LEN;
    use bunker::signing::NixKeypair;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Throwaway Ed25519 key (base64 of the PKCS#8 PEM), generated solely
    /// as a test fixture. Never used outside tests.
    const TEST_TOKEN_ED25519_SECRET_BASE64: &str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUxpdlM2bDZvYzZTeWZYcnk1YUpsZmtYZEVnblZCQnVjOFg1K3VTWEFiMmUKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=";

    fn temp_key_file(contents: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "bunker-config-test-{}-{}.key",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn config_toml(signing: &str) -> String {
        format!(
            r#"
[database]
url = "sqlite::memory:"

[storage]
type = "local"
path = "/tmp"

[chunking]
nar-size-threshold = 1
min-size = 1024
avg-size = 2048
max-size = 4096

[jwt.signing]
token-ed25519-secret-base64 = "{TEST_TOKEN_ED25519_SECRET_BASE64}"

{signing}
"#
        )
    }

    // --- Validation ---

    #[test]
    fn hybrid_keypair_file_roundtrip() {
        let keypair = HybridKeypair::generate("cache.example.org-1").unwrap();
        // A trailing newline, as written by shell redirection, is accepted.
        let path = temp_key_file(&format!("{}\n", keypair.export_keypair()));

        let loaded = read_hybrid_keypair_file(&path).unwrap();
        assert_eq!(loaded.name(), "cache.example.org-1");
        assert_eq!(loaded.export_public_key(), keypair.export_public_key());

        let payload = loaded
            .export_public_key()
            .split_once(':')
            .map(|(_, payload)| payload.to_string())
            .unwrap();
        assert_eq!(
            BASE64_STANDARD.decode(payload).unwrap().len(),
            HYBRID_PUBKEY_LEN
        );

        let signature = loaded.sign(b"message");
        loaded.verify(b"message", &signature).unwrap();

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_hybrid_keypair_accepts_matching_name() {
        let keypair = HybridKeypair::generate("cache.example.org-1").unwrap();
        let path = temp_key_file(&keypair.export_keypair());

        let loaded = load_hybrid_keypair("cache.example.org-1", &path).unwrap();
        assert_eq!(loaded.name(), "cache.example.org-1");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn config_loads_configured_hybrid_keypair() {
        let keypair = HybridKeypair::generate("cache.example.org-1").unwrap();
        let path = temp_key_file(&keypair.export_keypair());
        let toml = config_toml(&format!(
            "[signing]\nhybrid-key-name = \"cache.example.org-1\"\nhybrid-secret-key-file = {:?}",
            path
        ));

        let mut config = load_config_from_str(&toml).unwrap();
        config.load_configured_hybrid_keypair().unwrap();
        let loaded = config.hybrid_keypair().expect("keypair must be loaded");
        assert_eq!(loaded.name(), "cache.example.org-1");
        assert_eq!(loaded.export_public_key(), keypair.export_public_key());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn config_without_signing_loads_no_keypair() {
        let mut config = load_config_from_str(&config_toml("")).unwrap();
        config.load_configured_hybrid_keypair().unwrap();
        assert!(config.hybrid_keypair().is_none());
    }

    // --- Adversarial ---

    #[test]
    fn load_hybrid_keypair_rejects_name_mismatch() {
        let keypair = HybridKeypair::generate("cache.example.org-1").unwrap();
        let path = temp_key_file(&keypair.export_keypair());

        let err = load_hybrid_keypair("cache.example.org-2", &path).unwrap_err();
        assert!(err.to_string().contains("name mismatch"), "got: {err}");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_hybrid_keypair_rejects_mismatched_ed25519_halves() {
        // Splice the public half of one key's Ed25519 keypair onto the
        // secret half of another's. The strict parse succeeds (the payload
        // is still 96 bytes), so only the load-time self-check (probe
        // signature against the derived public key) can catch this.
        let keypair = HybridKeypair::generate("cache.example.org-1").unwrap();
        let other = HybridKeypair::generate("cache.example.org-1").unwrap();
        let decode_payload = |export: &str| {
            BASE64_STANDARD
                .decode(export.split_once(':').unwrap().1)
                .unwrap()
        };
        let mut bytes = decode_payload(&keypair.export_keypair());
        let other_bytes = decode_payload(&other.export_keypair());
        bytes[32..64].copy_from_slice(&other_bytes[32..64]);
        let tampered = format!("cache.example.org-1:{}", BASE64_STANDARD.encode(bytes));
        let path = temp_key_file(&tampered);

        let err = load_hybrid_keypair("cache.example.org-1", &path).unwrap_err();
        assert!(err.to_string().contains("self-check"), "got: {err}");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn read_hybrid_keypair_file_rejects_classical_keypair() {
        // A classical 64-byte Nix keypair is not a hybrid key: the payload
        // length check must reject it (no silent classical fall-back).
        let classical = NixKeypair::generate("cache.example.org-1").unwrap();
        let path = temp_key_file(&classical.export_keypair());

        assert!(read_hybrid_keypair_file(&path).is_err());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn read_hybrid_keypair_file_rejects_corrupt_contents() {
        let not_base64 = temp_key_file("cache.example.org-1:not*base64*here");
        assert!(read_hybrid_keypair_file(&not_base64).is_err());
        std::fs::remove_file(not_base64).ok();

        let no_colon = temp_key_file("cache.example.org-1");
        assert!(read_hybrid_keypair_file(&no_colon).is_err());
        std::fs::remove_file(no_colon).ok();

        let empty = temp_key_file("");
        assert!(read_hybrid_keypair_file(&empty).is_err());
        std::fs::remove_file(empty).ok();
    }

    #[test]
    fn read_hybrid_keypair_file_rejects_missing_file() {
        let path = std::env::temp_dir().join("bunker-config-test-does-not-exist.key");
        assert!(read_hybrid_keypair_file(&path).is_err());
    }

    #[test]
    fn read_hybrid_keypair_file_rejects_oversized_file() {
        let oversized = "A".repeat(HYBRID_SECRET_KEY_FILE_BYTES_MAX as usize + 1);
        let path = temp_key_file(&oversized);

        let err = read_hybrid_keypair_file(&path).unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn config_rejects_half_configured_hybrid_key() {
        let name_only = config_toml("[signing]\nhybrid-key-name = \"cache.example.org-1\"");
        let mut config = load_config_from_str(&name_only).unwrap();
        assert!(config.load_configured_hybrid_keypair().is_err());

        let file_only = config_toml("[signing]\nhybrid-secret-key-file = \"/does/not/matter.key\"");
        let mut config = load_config_from_str(&file_only).unwrap();
        assert!(config.load_configured_hybrid_keypair().is_err());
    }
}
