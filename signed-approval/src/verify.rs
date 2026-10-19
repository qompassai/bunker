//! Executor-side verification, in DESIGN section 4 order, all
//! steps fail-closed. The pilot performs steps 1-4, 6, 7 and the
//! policy-fingerprint half of step 5; the flowguard `decide()`
//! halves of steps 5 and 8 are the phlow integration step
//! (DESIGN section 7.4) and are NOT in pilot scope.

use std::collections::HashSet;
use std::fmt;

use crate::manifest::Manifest;
use crate::record::{AuthorityKeySource, RecordError};
use crate::token::{ApprovalToken, TokenError};

/// Approval tier (DESIGN section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Standard effects: revocation data up to 15 min old.
    T1,
    /// High effect (delete/publish/send/pay): revocation data up
    /// to 60 s old, validity window at most 2 min.
    T2,
}

impl Tier {
    /// Maximum acceptable authority-record age, in seconds.
    pub fn max_key_age_secs(self) -> i64 {
        match self {
            Tier::T1 => 900,
            Tier::T2 => 60,
        }
    }

    /// Maximum manifest validity window, in seconds.
    pub fn max_validity_secs(self) -> i64 {
        match self {
            Tier::T1 => 300,
            Tier::T2 => 120,
        }
    }
}

/// What the executor expects, against which a token is checked.
#[derive(Debug, Clone)]
pub struct VerifyContext {
    /// This executor's identity.
    pub audience: String,
    /// Effect classes the invoked tool declares.
    pub declared_effects: Vec<String>,
    /// Current policy fingerprint.
    pub policy_fp: String,
    pub tier: Tier,
    /// The invoked tool's id.
    pub tool: String,
    /// Digest of the tool's current definition.
    pub tool_digest: String,
    /// The executor's clock, unix seconds.
    pub now: i64,
}

/// A token that passed every check. The executor dispatches on
/// this, and audits its digest (payloads are never logged, F-13).
#[derive(Debug, Clone)]
pub struct VerifiedApproval {
    pub digest: String,
    pub key_fingerprint: String,
    pub manifest: Manifest,
}

/// Every way verification can refuse, one variant per DESIGN
/// finding so tests can pin behavior precisely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    AudienceMismatch,
    BadSignature,
    EffectsNotSubset,
    Expired,
    IssuedInFuture,
    KeyFingerprintMismatch,
    KeyRecord(RecordError),
    KeyRevoked,
    KeyStale,
    KeyUnknown,
    ManifestInvalid(String),
    NonceReplay,
    PolicyMismatch,
    TierWindowExceeded,
    TokenInvalid(String),
    ToolDigestMismatch,
    ToolMismatch,
    TrajectoryMismatch(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::AudienceMismatch => write!(f, "approval audience is not this executor"),
            VerifyError::BadSignature => write!(f, "signature does not verify"),
            VerifyError::EffectsNotSubset => {
                write!(f, "manifest effects exceed the tool's declared effects")
            }
            VerifyError::Expired => write!(f, "approval has expired"),
            VerifyError::IssuedInFuture => {
                write!(f, "approval issued_at is beyond the allowed clock skew")
            }
            VerifyError::KeyFingerprintMismatch => {
                write!(
                    f,
                    "authority record fingerprint does not match its key material"
                )
            }
            VerifyError::KeyRecord(e) => write!(f, "authority record unusable: {e}"),
            VerifyError::KeyRevoked => write!(f, "authority key is revoked"),
            VerifyError::KeyStale => {
                write!(f, "authority record is older than the tier freshness bound")
            }
            VerifyError::KeyUnknown => write!(f, "no authority record for the signing key"),
            VerifyError::ManifestInvalid(msg) => write!(f, "manifest invalid: {msg}"),
            VerifyError::NonceReplay => write!(f, "nonce already consumed"),
            VerifyError::PolicyMismatch => write!(f, "policy fingerprint mismatch"),
            VerifyError::TierWindowExceeded => {
                write!(f, "validity window exceeds the tier bound")
            }
            VerifyError::TokenInvalid(msg) => write!(f, "token invalid: {msg}"),
            VerifyError::ToolDigestMismatch => {
                write!(
                    f,
                    "tool definition changed since approval (digest mismatch)"
                )
            }
            VerifyError::ToolMismatch => write!(f, "approval names a different tool"),
            VerifyError::TrajectoryMismatch(msg) => write!(f, "trajectory mismatch: {msg}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Where nonces are consumed. Consumption must be atomic
/// check-and-set, durable across restarts in production
/// (DESIGN section 4 step 7, F-04).
pub trait NonceStore {
    /// Consumes `nonce` (valid until `expires_at`). Returns
    /// [`VerifyError::NonceReplay`] when the nonce was already
    /// consumed and has not been pruned.
    fn consume(&mut self, nonce: &str, expires_at: i64) -> Result<(), VerifyError>;
}

/// In-memory nonce store (tests, and executors whose state dir is
/// managed elsewhere).
#[derive(Debug, Default)]
pub struct MemoryNonceStore {
    consumed: HashSet<String>,
}

impl NonceStore for MemoryNonceStore {
    fn consume(&mut self, nonce: &str, _expires_at: i64) -> Result<(), VerifyError> {
        if self.consumed.insert(nonce.to_string()) {
            Ok(())
        } else {
            Err(VerifyError::NonceReplay)
        }
    }
}

/// Verifies a token end-to-end, in DESIGN section 4 order. On
/// success the nonce has been consumed: the caller must dispatch
/// exactly once, and a failed dispatch does NOT restore the
/// nonce (F-04).
pub fn verify_token(
    token_bytes: &[u8],
    ctx: &VerifyContext,
    keys: &dyn AuthorityKeySource,
    nonces: &mut dyn NonceStore,
    expected_trajectory: &str,
) -> Result<VerifiedApproval, VerifyError> {
    // Step 1: strict parse; manifest validity incl. canonical
    // shape, concreteness, closed effect enumeration.
    let token = ApprovalToken::from_json(token_bytes).map_err(|e| match e {
        TokenError::Manifest(m) => VerifyError::ManifestInvalid(m.to_string()),
        TokenError::Shape(msg) => VerifyError::TokenInvalid(msg),
    })?;
    let manifest = &token.manifest;
    // Step 2/3: resolve the authority key; fingerprint honesty,
    // revocation, freshness (fail closed when stale, T2).
    let record = keys
        .record(&token.key_fingerprint)
        .map_err(VerifyError::KeyRecord)?
        .ok_or(VerifyError::KeyUnknown)?;
    if record
        .computed_fingerprint()
        .map_err(VerifyError::KeyRecord)?
        != record.fingerprint
        || record.fingerprint != token.key_fingerprint
    {
        return Err(VerifyError::KeyFingerprintMismatch);
    }
    if record.revoked {
        return Err(VerifyError::KeyRevoked);
    }
    if ctx.now - record.fetched_at > ctx.tier.max_key_age_secs() || record.fetched_at > ctx.now + 30
    {
        return Err(VerifyError::KeyStale);
    }
    // Step 2 (signature): allowlist is structural — Ed25519 is the
    // only scheme the token format admits (F-17).
    let public_key = record.public_key_bytes().map_err(VerifyError::KeyRecord)?;
    if !token.verify_signature(&public_key) {
        return Err(VerifyError::BadSignature);
    }
    // Step 4: binding to this executor, tool, tool definition,
    // declared effects, and the live session trajectory (F-03,
    // F-10, F-19).
    if manifest.audience != ctx.audience {
        return Err(VerifyError::AudienceMismatch);
    }
    if manifest.tool != ctx.tool {
        return Err(VerifyError::ToolMismatch);
    }
    if manifest.tool_digest != ctx.tool_digest {
        return Err(VerifyError::ToolDigestMismatch);
    }
    if !manifest
        .effects
        .iter()
        .all(|e| ctx.declared_effects.contains(e))
    {
        return Err(VerifyError::EffectsNotSubset);
    }
    if manifest.trajectory != expected_trajectory {
        return Err(VerifyError::TrajectoryMismatch(format!(
            "manifest is for session {}, this session is {}",
            manifest.trajectory, expected_trajectory
        )));
    }
    // Step 5 (pilot half): policy fingerprint equality (F-06).
    if manifest.policy_fp != ctx.policy_fp {
        return Err(VerifyError::PolicyMismatch);
    }
    // Step 6: expiry. Skew is tolerated on issued_at only (F-12).
    if manifest.issued_at > ctx.now + 30 {
        return Err(VerifyError::IssuedInFuture);
    }
    if ctx.now >= manifest.expires_at {
        return Err(VerifyError::Expired);
    }
    if manifest.expires_at - manifest.issued_at > ctx.tier.max_validity_secs() {
        return Err(VerifyError::TierWindowExceeded);
    }
    // Step 7: consume the nonce BEFORE dispatch (F-04).
    nonces.consume(&manifest.nonce, manifest.expires_at)?;
    Ok(VerifiedApproval {
        digest: manifest.digest(),
        key_fingerprint: token.key_fingerprint.clone(),
        manifest: manifest.clone(),
    })
}
