//! The approval manifest: the signed object (DESIGN section 2).
//!
//! A manifest is accepted only as canonical bytes: the strict
//! parser must accept it AND re-serialization must reproduce the
//! input byte-for-byte (DESIGN verification step 1, F-01).

use std::fmt;

use sha2::{Digest, Sha256};

use crate::canonical::{JsonValue, ParseError, object, parse_strict, serialize};

/// The closed effect-class enumeration for the pilot (DESIGN
/// section 2). Anything outside this set is invalid everywhere.
pub const KNOWN_EFFECTS: [&str; 5] = ["delete", "pay", "publish", "send", "submit"];

/// Maximum manifest size in bytes (DESIGN section 2, F-15).
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Longest validity window any manifest may carry (tier T1 cap,
/// DESIGN section 5). Tier T2 executors enforce a tighter bound
/// through the verify context.
pub const MAX_VALIDITY_SECS: i64 = 300;

/// The data + destination label pair carried at issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labels {
    pub data: String,
    pub destination: String,
}

/// A validated approval manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub audience: String,
    pub effects: Vec<String>,
    pub expires_at: i64,
    pub issued_at: i64,
    pub labels: Labels,
    pub nonce: String,
    pub payload: JsonValue,
    pub policy_fp: String,
    pub tool: String,
    pub tool_digest: String,
    pub trajectory: String,
    pub v: u32,
}

/// Why a byte string is not a valid manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// A required field is absent.
    MissingField(&'static str),
    /// The byte-equality (canonical form) check failed.
    NonCanonical,
    /// The strict parser rejected the input.
    Parse(ParseError),
    /// A field failed validation; the message names the rule.
    Rule(String),
    /// Input exceeds [`MAX_MANIFEST_BYTES`].
    TooLarge,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::MissingField(name) => write!(f, "manifest missing field: {name}"),
            ManifestError::NonCanonical => {
                write!(f, "manifest is not in canonical (RFC 8785) form")
            }
            ManifestError::Parse(e) => write!(f, "manifest parse failed: {e}"),
            ManifestError::Rule(msg) => write!(f, "manifest rule violated: {msg}"),
            ManifestError::TooLarge => write!(f, "manifest exceeds {MAX_MANIFEST_BYTES} bytes"),
        }
    }
}

impl std::error::Error for ManifestError {}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn rule<T>(ok: bool, message: &str) -> Result<T, ManifestError>
where
    T: Default,
{
    if ok {
        Ok(T::default())
    } else {
        Err(ManifestError::Rule(message.to_string()))
    }
}

/// Whether a payload is concrete: no wildcard or template markers
/// in any string value, at any depth (DESIGN F-11). Pilot policy:
/// `*`, `?`, `{`, `}` are forbidden inside payload strings.
pub fn payload_is_concrete(value: &JsonValue) -> bool {
    match value {
        JsonValue::String(s) => !s.chars().any(|c| matches!(c, '*' | '?' | '{' | '}')),
        JsonValue::Array(items) => items.iter().all(payload_is_concrete),
        JsonValue::Object(entries) => entries.iter().all(|(_, v)| payload_is_concrete(v)),
        _ => true,
    }
}

impl Manifest {
    /// Parses and validates a manifest from its canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge);
        }
        let value = parse_strict(bytes).map_err(ManifestError::Parse)?;
        if serialize(&value).as_bytes() != bytes {
            return Err(ManifestError::NonCanonical);
        }
        Self::from_value(&value)
    }

    /// Validates a parsed value as a manifest (used when the
    /// manifest arrives embedded in a token envelope).
    pub fn from_value(value: &JsonValue) -> Result<Manifest, ManifestError> {
        let fields = value
            .as_object()
            .ok_or_else(|| ManifestError::Rule("manifest is not an object".to_string()))?;
        const FIELD_NAMES: [&str; 12] = [
            "audience",
            "effects",
            "expires_at",
            "issued_at",
            "labels",
            "nonce",
            "payload",
            "policy_fp",
            "tool",
            "tool_digest",
            "trajectory",
            "v",
        ];
        for (key, _) in fields {
            if !FIELD_NAMES.contains(&key.as_str()) {
                return Err(ManifestError::Rule(format!(
                    "unknown manifest field: {key}"
                )));
            }
        }
        let get = |name: &'static str| -> Result<&JsonValue, ManifestError> {
            value.get(name).ok_or(ManifestError::MissingField(name))
        };
        let get_str = |name: &'static str| -> Result<String, ManifestError> {
            get(name)?
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| ManifestError::Rule(format!("field {name} is not a string")))
        };
        let get_i64 = |name: &'static str| -> Result<i64, ManifestError> {
            get(name)?
                .as_i64()
                .ok_or_else(|| ManifestError::Rule(format!("field {name} is not an integer")))
        };

        let v_raw = get("v")?
            .as_i64()
            .ok_or_else(|| ManifestError::Rule("field v is not an integer".to_string()))?;
        rule::<()>(v_raw == 1, "manifest version must be 1")?;
        let tool_digest = get_str("tool_digest")?;
        rule::<()>(
            is_lower_hex(&tool_digest, 64),
            "tool_digest must be 64 lowercase hex characters",
        )?;
        let policy_fp = get_str("policy_fp")?;
        rule::<()>(
            is_lower_hex(&policy_fp, 64),
            "policy_fp must be 64 lowercase hex characters",
        )?;
        let nonce = get_str("nonce")?;
        rule::<()>(
            is_lower_hex(&nonce, 32),
            "nonce must be 32 lowercase hex characters (128-bit)",
        )?;
        let effects_raw = get("effects")?
            .as_array()
            .ok_or_else(|| ManifestError::Rule("field effects is not an array".to_string()))?;
        let mut effects: Vec<String> = Vec::new();
        for item in effects_raw {
            let effect = item
                .as_str()
                .ok_or_else(|| ManifestError::Rule("effect is not a string".to_string()))?;
            rule::<()>(
                KNOWN_EFFECTS.contains(&effect),
                "effect is outside the closed enumeration",
            )?;
            rule::<()>(
                !effects.iter().any(|e| e == effect),
                "duplicate effect in manifest",
            )?;
            effects.push(effect.to_string());
        }
        rule::<()>(!effects.is_empty(), "effects must not be empty")?;
        let labels_value = get("labels")?;
        let labels = Labels {
            data: labels_value
                .get("data")
                .and_then(JsonValue::as_str)
                .ok_or(ManifestError::MissingField("labels.data"))?
                .to_string(),
            destination: labels_value
                .get("destination")
                .and_then(JsonValue::as_str)
                .ok_or(ManifestError::MissingField("labels.destination"))?
                .to_string(),
        };
        let payload = get("payload")?.clone();
        rule::<()>(
            payload.as_object().is_some(),
            "payload must be a single object (batches are out of scope, F-09)",
        )?;
        rule::<()>(
            payload_is_concrete(&payload),
            "payload is not concrete (wildcard or template marker present, F-11)",
        )?;
        let issued_at = get_i64("issued_at")?;
        let expires_at = get_i64("expires_at")?;
        rule::<()>(expires_at > issued_at, "expires_at must follow issued_at")?;
        rule::<()>(
            expires_at - issued_at <= MAX_VALIDITY_SECS,
            "validity window exceeds the tier T1 cap",
        )?;
        Ok(Manifest {
            audience: get_str("audience")?,
            effects,
            expires_at,
            issued_at,
            labels,
            nonce,
            payload,
            policy_fp,
            tool: get_str("tool")?,
            tool_digest,
            trajectory: get_str("trajectory")?,
            v: 1,
        })
    }

    /// The manifest as a JSON value (field insertion order is
    /// irrelevant; serialization sorts canonically).
    pub fn to_value(&self) -> JsonValue {
        object(vec![
            ("audience", JsonValue::String(self.audience.clone())),
            (
                "effects",
                JsonValue::Array(
                    self.effects
                        .iter()
                        .map(|e| JsonValue::String(e.clone()))
                        .collect(),
                ),
            ),
            ("expires_at", JsonValue::Number(self.expires_at.to_string())),
            ("issued_at", JsonValue::Number(self.issued_at.to_string())),
            (
                "labels",
                object(vec![
                    ("data", JsonValue::String(self.labels.data.clone())),
                    (
                        "destination",
                        JsonValue::String(self.labels.destination.clone()),
                    ),
                ]),
            ),
            ("nonce", JsonValue::String(self.nonce.clone())),
            ("payload", self.payload.clone()),
            ("policy_fp", JsonValue::String(self.policy_fp.clone())),
            ("tool", JsonValue::String(self.tool.clone())),
            ("tool_digest", JsonValue::String(self.tool_digest.clone())),
            ("trajectory", JsonValue::String(self.trajectory.clone())),
            ("v", JsonValue::Number(self.v.to_string())),
        ])
    }

    /// The canonical bytes: what gets signed and digested.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serialize(&self.to_value()).into_bytes()
    }

    /// SHA-256 over the canonical bytes, lowercase hex.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hex_encode(&hasher.finalize())
    }

    /// The first 8 digest characters: the human comparison check
    /// (DESIGN section 3).
    pub fn digest_check(&self) -> String {
        self.digest()[..8].to_string()
    }
}

/// Lowercase hex encoding (estate-local; no extra dependency).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decodes lowercase/uppercase hex; `None` on any invalid byte or
/// odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::object;

    fn sample_manifest() -> Manifest {
        Manifest {
            audience: "bunker-mcp@primo".to_string(),
            effects: vec!["delete".to_string()],
            expires_at: 1_800_000_120,
            issued_at: 1_800_000_000,
            labels: Labels {
                data: "internal".to_string(),
                destination: "local-cache".to_string(),
            },
            nonce: "0123456789abcdef0123456789abcdef".to_string(),
            payload: object(vec![
                ("cache", JsonValue::String("main".to_string())),
                ("file", JsonValue::String("a.bin".to_string())),
                ("name", JsonValue::String("pkg".to_string())),
                ("version", JsonValue::String("1.0.0".to_string())),
            ]),
            policy_fp: "a".repeat(64),
            tool: "mcp:bunker/artifact_delete".to_string(),
            tool_digest: "b".repeat(64),
            trajectory: "sess-1".to_string(),
            v: 1,
        }
    }

    #[test]
    fn round_trips_through_canonical_bytes() {
        let manifest = sample_manifest();
        let bytes = manifest.canonical_bytes();
        let parsed = Manifest::from_canonical_bytes(&bytes).expect("valid manifest");
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn rejects_noncanonical_spelling() {
        // Same value, keys out of canonical order.
        let bytes = br#"{"v":1,"tool":"t"}"#;
        assert!(matches!(
            Manifest::from_canonical_bytes(bytes),
            Err(ManifestError::NonCanonical)
        ));
    }

    #[test]
    fn rejects_wildcard_payload() {
        let mut manifest = sample_manifest();
        manifest.payload = object(vec![("file", JsonValue::String("*.bin".to_string()))]);
        let bytes = manifest.canonical_bytes();
        assert!(Manifest::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn digest_check_is_digest_prefix() {
        let manifest = sample_manifest();
        assert_eq!(manifest.digest_check(), manifest.digest()[..8]);
        assert_eq!(manifest.digest().len(), 64);
    }
}
