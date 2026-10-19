//! Authority key records and their sources (DESIGN section 4
//! step 3). The pilot pins records directly; production resolves
//! the same record shape from Volta behind this trait. OpenPGP
//! handling is explicitly NOT implemented here (pilot scope).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};

use crate::canonical::JsonValue;
use crate::manifest::hex_encode;

/// One authority key, as a resolver would serve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRecord {
    /// Unix seconds when this record was fetched. Freshness is
    /// judged by executors against their own clock (DESIGN
    /// section 5).
    pub fetched_at: i64,
    /// SHA-256 of the public key bytes, lowercase hex.
    pub fingerprint: String,
    /// The Ed25519 public key, base64 (32 bytes).
    pub public_key: String,
    pub revoked: bool,
}

impl AuthorityRecord {
    /// Parses a record from its JSON form.
    pub fn from_value(value: &JsonValue) -> Result<AuthorityRecord, RecordError> {
        let get = |name: &'static str| value.get(name).ok_or(RecordError::MissingField(name));
        let fingerprint = get("fingerprint")?
            .as_str()
            .ok_or(RecordError::FieldType("fingerprint"))?
            .to_string();
        let public_key = get("public_key")?
            .as_str()
            .ok_or(RecordError::FieldType("public_key"))?
            .to_string();
        let revoked = get("revoked")?
            .as_bool()
            .ok_or(RecordError::FieldType("revoked"))?;
        let fetched_at = get("fetched_at")?
            .as_i64()
            .ok_or(RecordError::FieldType("fetched_at"))?;
        Ok(AuthorityRecord {
            fetched_at,
            fingerprint,
            public_key,
            revoked,
        })
    }

    /// The record as a JSON value (for `--generate-test-key` and
    /// fixtures).
    pub fn to_value(&self) -> JsonValue {
        crate::canonical::object(vec![
            ("fetched_at", JsonValue::Number(self.fetched_at.to_string())),
            ("fingerprint", JsonValue::String(self.fingerprint.clone())),
            ("public_key", JsonValue::String(self.public_key.clone())),
            ("revoked", JsonValue::Bool(self.revoked)),
        ])
    }

    /// The decoded public key bytes.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, RecordError> {
        BASE64
            .decode(self.public_key.as_bytes())
            .map_err(|_| RecordError::FieldType("public_key (base64)"))
    }

    /// The fingerprint this record's key material actually has.
    pub fn computed_fingerprint(&self) -> Result<String, RecordError> {
        let key = self.public_key_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&key);
        Ok(hex_encode(&hasher.finalize()))
    }
}

/// Why an authority record is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    FieldType(&'static str),
    MissingField(&'static str),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::FieldType(name) => {
                write!(f, "authority record field {name} has a bad type")
            }
            RecordError::MissingField(name) => write!(f, "authority record missing field: {name}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// Where an executor gets authority records. Production: Volta.
/// Pilot: [`PinnedKeySource`].
pub trait AuthorityKeySource {
    /// The record for `fingerprint`, or `None` when this source
    /// does not serve that key.
    fn record(&self, fingerprint: &str) -> Result<Option<AuthorityRecord>, RecordError>;
}

/// A fixed set of records, loaded from one JSON file holding
/// either a single record object or an array of them.
#[derive(Debug, Clone)]
pub struct PinnedKeySource {
    records: Vec<AuthorityRecord>,
}

impl PinnedKeySource {
    /// Builds the source from record JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<PinnedKeySource, RecordError> {
        let value = crate::canonical::parse_strict(bytes)
            .map_err(|_| RecordError::FieldType("record file (strict JSON)"))?;
        let mut records = Vec::new();
        match &value {
            JsonValue::Array(items) => {
                for item in items {
                    records.push(AuthorityRecord::from_value(item)?);
                }
            }
            JsonValue::Object(_) => records.push(AuthorityRecord::from_value(&value)?),
            _ => return Err(RecordError::FieldType("record file (shape)")),
        }
        Ok(PinnedKeySource { records })
    }
}

impl AuthorityKeySource for PinnedKeySource {
    fn record(&self, fingerprint: &str) -> Result<Option<AuthorityRecord>, RecordError> {
        Ok(self
            .records
            .iter()
            .find(|r| r.fingerprint == fingerprint)
            .cloned())
    }
}
