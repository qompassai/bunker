//! Bunker TLS-terminating reverse proxy.
//!
//! A minimal Pingora-based reverse proxy that terminates TLS and forwards
//! to the bunker server. Designed for NixOS deployment, local dev, and
//! remote ops.
//!
//! ## Contract
//!
//! - Listens on a configurable address (default `[::]:4430`).
//! - Forwards to a configurable upstream (default `127.0.0.1:8080`).
//! - TLS 1.3 only, restricted to `TLS_AES_256_GCM_SHA384` and
//!   `TLS_CHACHA20_POLY1305_SHA256`. No weaker protocols or ciphers.
//! - Fail-closed: panics with helpful instructions if TLS cert/key are
//!   absent. Never falls back to plaintext.
//! - Rate limits clients by IP (token bucket, configurable).
//! - Serves `GET /healthz` directly (200 OK) for load balancers and
//!   systemd health checks. Never proxied upstream.
//! - Logs at `debug` level only; request paths never hit stdout
//!   unconditionally.
//!
//! ## Configuration
//!
//! Environment variables (all optional, defaults shown):
//! - `BUNKER_PROXY_LISTEN`: `[::]:4430`
//! - `BUNKER_PROXY_RATE_LIMIT_BURST`: `200` (max burst per IP)
//! - `BUNKER_PROXY_RATE_LIMIT_RPS`: `100` (requests per second per IP)
//! - `BUNKER_PROXY_TLS_CERT`: path to the TLS certificate file
//! - `BUNKER_PROXY_TLS_KEY`: path to the TLS private key file
//! - `BUNKER_PROXY_UPSTREAM`: `127.0.0.1:8080`
//!
//! CLI flags override environment variables. See `--help`.
//!
//! TLS material is resolved fail-closed, in this order:
//! 1. `--tls-cert` and `--tls-key` together (or the matching env vars).
//!    Giving exactly one of the two is a configuration error.
//! 2. The XDG default paths `$XDG_CONFIG_HOME/bunker/bunker_cert.pem`
//!    and `$XDG_CONFIG_HOME/bunker/bunker_key.pem`.
//!
//! If neither source yields both files, the proxy refuses to start.
//! There is no plaintext fallback.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use clap::Parser;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Bounds (all named with units)
// ---------------------------------------------------------------------------

/// Default listen address.
const DEFAULT_LISTEN: &str = "[::]:4430";
/// Default upstream address (bunker server).
const DEFAULT_UPSTREAM: &str = "127.0.0.1:8080";
/// Default rate limit: requests per second per client IP.
const DEFAULT_RATE_LIMIT_RPS: u64 = 100;
/// Default rate limit burst capacity per client IP.
const DEFAULT_RATE_LIMIT_BURST: u64 = 200;
/// Maximum tracked client IPs before oldest entries are evicted.
const RATE_LIMIT_TABLE_MAX: usize = 10_000;
/// Health check path. Served directly, never proxied.
const HEALTHZ_PATH: &str = "/healthz";
/// Maximum bytes of a config value (address, etc.).
const CONFIG_VALUE_BYTES_MAX: usize = 512;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Bunker reverse proxy configuration.
///
/// CLI flags override environment variables, which override defaults.
#[derive(Debug, Parser)]
#[command(
    name = "bunker-proxy",
    about = "TLS-terminating reverse proxy for bunker"
)]
struct Config {
    /// Address to listen on (e.g., "[::]:4430").
    #[arg(long, env = "BUNKER_PROXY_LISTEN", default_value = DEFAULT_LISTEN)]
    listen: String,

    /// Rate limit: max burst requests per client IP.
    #[arg(long, env = "BUNKER_PROXY_RATE_LIMIT_BURST", default_value_t = DEFAULT_RATE_LIMIT_BURST)]
    rate_limit_burst: u64,

    /// Rate limit: max requests per second per client IP.
    #[arg(long, env = "BUNKER_PROXY_RATE_LIMIT_RPS", default_value_t = DEFAULT_RATE_LIMIT_RPS)]
    rate_limit_rps: u64,

    /// Path to the TLS certificate file.
    ///
    /// Must be given together with `--tls-key`. When both are given they
    /// win over the XDG default paths.
    #[arg(long, env = "BUNKER_PROXY_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Path to the TLS private key file.
    ///
    /// Must be given together with `--tls-cert`. When both are given they
    /// win over the XDG default paths.
    #[arg(long, env = "BUNKER_PROXY_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Upstream bunker server address (e.g., "127.0.0.1:8080").
    #[arg(long, env = "BUNKER_PROXY_UPSTREAM", default_value = DEFAULT_UPSTREAM)]
    upstream: String,
}

impl Config {
    /// Validate the configuration. Returns typed errors, never panics.
    fn validate(&self) -> Result<ValidatedConfig, String> {
        if self.listen.len() > CONFIG_VALUE_BYTES_MAX || self.listen.is_empty() {
            return Err("listen address is empty or too long".to_string());
        }
        if self.upstream.len() > CONFIG_VALUE_BYTES_MAX || self.upstream.is_empty() {
            return Err("upstream address is empty or too long".to_string());
        }
        let listen: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| format!("invalid listen address: {}", self.listen))?;
        // Upstream may be a hostname; validate as socket addr or leave for
        // Pingora to resolve. We require it to parse as SocketAddr for
        // now (explicit, no DNS surprises at runtime).
        let upstream: SocketAddr = self
            .upstream
            .parse()
            .map_err(|_| format!("invalid upstream address: {}", self.upstream))?;
        if self.rate_limit_rps == 0 {
            return Err("rate_limit_rps must be > 0".to_string());
        }
        if self.rate_limit_burst == 0 {
            return Err("rate_limit_burst must be > 0".to_string());
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err(
                "--tls-cert and --tls-key must be specified together (or neither)".to_string(),
            );
        }
        Ok(ValidatedConfig {
            listen,
            rate_limit_burst: self.rate_limit_burst,
            rate_limit_rps: self.rate_limit_rps,
            tls_cert: self.tls_cert.clone(),
            tls_key: self.tls_key.clone(),
            upstream,
        })
    }
}

/// A validated configuration. Cannot be constructed with invalid values.
#[derive(Debug, Clone)]
struct ValidatedConfig {
    listen: SocketAddr,
    rate_limit_burst: u64,
    rate_limit_rps: u64,
    /// TLS certificate path from `--tls-cert`, if given.
    ///
    /// Invariant (enforced by [`Config::validate`]): `tls_cert` and
    /// `tls_key` are either both `Some` or both `None`.
    tls_cert: Option<PathBuf>,
    /// TLS private key path from `--tls-key`, if given.
    tls_key: Option<PathBuf>,
    upstream: SocketAddr,
}

// ---------------------------------------------------------------------------
// Rate limiter (token bucket per client IP)
// ---------------------------------------------------------------------------

/// One token bucket.
struct Bucket {
    /// Current token count (fractional for smooth refill).
    tokens: f64,
    /// Last refill timestamp.
    last_refill: Instant,
}

/// Per-IP token-bucket rate limiter.
///
/// Bounded: at most [`RATE_LIMIT_TABLE_MAX`] IPs tracked; oldest entries
/// evicted when full. Thread-safe via interior mutability; never held
/// across `.await` (lock scope is synchronous).
struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Tokens added per second.
    refill_rate: f64,
    /// Maximum tokens (burst capacity).
    capacity: f64,
}

impl RateLimiter {
    /// Create a limiter allowing `rps` requests/sec with `burst` burst.
    fn new(rps: u64, burst: u64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            refill_rate: rps as f64,
            capacity: burst as f64,
        }
    }

    /// Check whether `ip` may proceed. Returns `true` if a token was
    /// consumed, `false` if rate limited.
    ///
    /// Lock is held only for the synchronous bucket update, never across
    /// `.await`. Poisoned mutex fails closed (denies the request).
    fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(g) => g,
            Err(_) => return false, // Fail closed on poisoned mutex.
        };
        let now = Instant::now();
        // Evict oldest entries if over capacity. We approximate "oldest"
        // by least-recently-refilled; full LRU would need more bookkeeping.
        if buckets.len() >= RATE_LIMIT_TABLE_MAX && !buckets.contains_key(&ip) {
            let oldest: Option<IpAddr> = buckets
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(k, _)| *k);
            if let Some(addr) = oldest {
                buckets.remove(&addr);
            }
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        // Refill based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// The reverse proxy.
///
/// Holds validated config and shared rate limiter. `Clone` shares the
/// limiter across Pingora worker threads via `Arc`.
#[derive(Clone)]
struct ReverseProxy {
    config: ValidatedConfig,
    rate_limiter: Arc<RateLimiter>,
}

impl ReverseProxy {
    fn new(config: ValidatedConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_rps,
            config.rate_limit_burst,
        ));
        Self {
            config,
            rate_limiter,
        }
    }
}

#[async_trait]
impl ProxyHttp for ReverseProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    /// Select the upstream peer.
    ///
    /// Uses TLS to upstream (matching the original behavior). The SNI is
    /// "localhost" since the upstream is expected on loopback.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            self.config.upstream.to_string(),
            true, // TLS to upstream (original behavior; upstream must serve TLS).
            "localhost".to_string(),
        )))
    }

    /// Pre-proxy filter: health check, rate limiting, debug logging.
    ///
    /// Returns `Ok(true)` if the response was written directly (health check
    /// or rate limited). Returns `Ok(false)` to continue proxying.
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path().to_string();
        debug!(path = %path, "incoming request");

        // Health check: serve directly, never proxy.
        if path == HEALTHZ_PATH {
            debug!("serving health check");
            let _ = session
                .respond_error_with_body(200, bytes::Bytes::from_static(b"ok"))
                .await;
            return Ok(true);
        }

        // Rate limit by client IP.
        let client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet().map(|inet| inet.ip()));
        if let Some(ip) = client_ip {
            if !self.rate_limiter.check(ip) {
                warn!(%ip, "rate limited");
                let _ = session
                    .respond_error_with_body(429, bytes::Bytes::from_static(b"rate limited"))
                    .await;
                return Ok(true);
            }
        } else {
            // No client IP available (e.g., Unix socket). Allow but log.
            debug!("no client IP available, skipping rate limit");
        }

        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// TLS and main
// ---------------------------------------------------------------------------

/// The XDG default TLS paths under a config directory.
fn tls_paths_from(config_dir: &str) -> (PathBuf, PathBuf) {
    let base = PathBuf::from(config_dir).join("bunker");
    (base.join("bunker_cert.pem"), base.join("bunker_key.pem"))
}

/// Load TLS certificate paths from XDG config.
///
/// Returns `(cert_path, key_path)` or a human-readable error. Never
/// panics; the caller decides fail-closed behavior.
fn tls_paths() -> Result<(PathBuf, PathBuf), String> {
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .or_else(|_| std::env::var("HOME").map(|h| format!("{}/.config", h)))
        .map_err(|_| {
            "cannot determine config directory: set XDG_CONFIG_HOME or HOME".to_string()
        })?;
    if config_dir.len() > CONFIG_VALUE_BYTES_MAX {
        return Err("config directory path too long".to_string());
    }
    Ok(tls_paths_from(&config_dir))
}

/// Resolve the TLS paths given by `--tls-cert`/`--tls-key`.
///
/// Returns `Some` only when both flags are given; `Config::validate`
/// rejects the half-specified case before this is consulted, so a single
/// flag also yields `None` here and the caller falls back to the XDG
/// default paths (unreachable for validated configs).
fn flag_tls_paths(tls_cert: Option<&Path>, tls_key: Option<&Path>) -> Option<(PathBuf, PathBuf)> {
    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => Some((cert.to_path_buf(), key.to_path_buf())),
        _ => None,
    }
}

/// Build the TLS settings with 1.3-only and restricted ciphersuites.
///
/// # Contract
/// - Minimum protocol: TLS 1.3. Never lowered.
/// - Ciphersuites: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` only.
/// - Key exchange: X25519+ML-KEM-768 hybrid preferred, X25519 fallback.
/// - Fails if cert/key are missing or unreadable (fail-closed, no plaintext fallback).
fn build_tls(config: &ValidatedConfig) -> Result<TlsSettings, String> {
    let (cert_path, key_path) =
        match flag_tls_paths(config.tls_cert.as_deref(), config.tls_key.as_deref()) {
            Some(paths) => paths,
            None => tls_paths()?,
        };
    if !cert_path.exists() || !key_path.exists() {
        return Err(format!(
            "TLS certificate files not found in: {:?}\n\
             Generate them with:\n\
             mkdir -p ~/.config/bunker && \\\n\
             openssl genpkey -algorithm ED25519 -out ~/.config/bunker/bunker_key.pem && \\\n\
             openssl req -x509 -key ~/.config/bunker/bunker_key.pem \\\n\
               -out ~/.config/bunker/bunker_cert.pem \\\n\
               -days 90 -subj '/CN=localhost'",
            cert_path.parent().unwrap_or(&cert_path)
        ));
    }
    let cert_str = cert_path
        .to_str()
        .ok_or_else(|| "cert path is not valid UTF-8".to_string())?;
    let key_str = key_path
        .to_str()
        .ok_or_else(|| "key path is not valid UTF-8".to_string())?;
    let mut tls_settings = TlsSettings::intermediate(cert_str, key_str)
        .map_err(|e| format!("TLS init failed: {}", e))?;
    // Override Mozilla intermediate defaults: TLS 1.3 minimum, restricted ciphers.
    // TlsSettings derefs to SslAcceptorBuilder, so these are openssl crate methods.
    tls_settings
        .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
        .map_err(|e| format!("failed to set TLS 1.3 minimum: {}", e))?;
    tls_settings
        .set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        .map_err(|e| format!("failed to set ciphersuites: {}", e))?;
    // PQ hybrid KEX: X25519+ML-KEM-768 preferred, X25519 fallback.
    // OpenSSL 3.5+ supports X25519MLKEM768. If the group is unavailable,
    // this fails closed (no silent downgrade to non-PQ).
    tls_settings
        .set_groups_list("X25519MLKEM768:X25519")
        .map_err(|e| format!("failed to set PQ hybrid groups: {}", e))?;
    Ok(tls_settings)
}

fn main() -> Result<(), String> {
    // Structured logging. Respects RUST_LOG; defaults to info.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();
    let validated = config.validate()?;
    info!(
        listen = %validated.listen,
        upstream = %validated.upstream,
        rps = validated.rate_limit_rps,
        burst = validated.rate_limit_burst,
        "starting bunker-proxy"
    );

    let tls_settings = build_tls(&validated)?;

    let mut server = Server::new(None).map_err(|e| format!("server init failed: {}", e))?;
    server.bootstrap();
    let mut proxy = pingora::proxy::http_proxy_service(
        &server.configuration,
        ReverseProxy::new(validated.clone()),
    );
    proxy.add_tls_with_settings(&validated.listen.to_string(), None, tls_settings);
    server.add_service(proxy);
    info!("listening on {}", validated.listen);
    server.run_forever()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(tls_cert: Option<&str>, tls_key: Option<&str>) -> Config {
        Config {
            listen: DEFAULT_LISTEN.to_string(),
            rate_limit_burst: DEFAULT_RATE_LIMIT_BURST,
            rate_limit_rps: DEFAULT_RATE_LIMIT_RPS,
            tls_cert: tls_cert.map(PathBuf::from),
            tls_key: tls_key.map(PathBuf::from),
            upstream: DEFAULT_UPSTREAM.to_string(),
        }
    }

    // --- Validation ---

    #[test]
    fn defaults_validate_unchanged() {
        let validated = config(None, None).validate().unwrap();
        assert_eq!(validated.listen.to_string(), "[::]:4430");
        assert_eq!(validated.upstream.to_string(), "127.0.0.1:8080");
        assert_eq!(validated.rate_limit_rps, 100);
        assert_eq!(validated.rate_limit_burst, 200);
        assert_eq!(validated.tls_cert, None);
        assert_eq!(validated.tls_key, None);
    }

    #[test]
    fn tls_flags_are_carried_through_validation() {
        let validated = config(Some("/run/secrets/cert.pem"), Some("/run/secrets/key.pem"))
            .validate()
            .unwrap();
        assert_eq!(
            validated.tls_cert,
            Some(PathBuf::from("/run/secrets/cert.pem"))
        );
        assert_eq!(
            validated.tls_key,
            Some(PathBuf::from("/run/secrets/key.pem"))
        );
    }

    #[test]
    fn flag_tls_paths_win_when_both_given() {
        let cert = Path::new("/acme/fullchain.pem");
        let key = Path::new("/acme/key.pem");
        assert_eq!(
            flag_tls_paths(Some(cert), Some(key)),
            Some((cert.to_path_buf(), key.to_path_buf()))
        );
    }

    #[test]
    fn xdg_fallback_paths_are_the_documented_filenames() {
        let (cert, key) = tls_paths_from("/home/test/.config");
        assert_eq!(
            cert,
            PathBuf::from("/home/test/.config/bunker/bunker_cert.pem")
        );
        assert_eq!(
            key,
            PathBuf::from("/home/test/.config/bunker/bunker_key.pem")
        );
    }

    // --- Adversarial ---

    #[test]
    fn cert_without_key_is_rejected() {
        let err = config(Some("/run/secrets/cert.pem"), None)
            .validate()
            .unwrap_err();
        assert!(err.contains("together"), "got: {err}");
    }

    #[test]
    fn key_without_cert_is_rejected() {
        let err = config(None, Some("/run/secrets/key.pem"))
            .validate()
            .unwrap_err();
        assert!(err.contains("together"), "got: {err}");
    }

    #[test]
    fn flag_tls_paths_fall_back_when_incomplete() {
        let cert = Path::new("/acme/fullchain.pem");
        let key = Path::new("/acme/key.pem");
        assert_eq!(flag_tls_paths(Some(cert), None), None);
        assert_eq!(flag_tls_paths(None, Some(key)), None);
        assert_eq!(flag_tls_paths(None, None), None);
    }
}
