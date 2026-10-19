//! The approval token: the manifest plus its signature, as
//! carried from signer to executor (DESIGN section 2: the token
//! carries the manifest itself, never a bare digest, F-02).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::canonical::{JsonValue, object, parse_strict, serialize};
use crate::manifest::{Manifest, ManifestError};

/// A signed approval, ready to present to an executor.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalToken {
    pub key_fingerprint: String,
    pub manifest: Manifest,
    /// Ed25519 signature over the manifest's canonical bytes.
    pub signature: [u8; 64],
}

/// Why a byte string is not an approval token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The envelope parsed but the manifest inside is invalid.
    Manifest(ManifestError),
    /// The envelope is structurally wrong.
    Shape(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Manifest(e) => write!(f, "token manifest invalid: {e}"),
            TokenError::Shape(msg) => write!(f, "token shape invalid: {msg}"),
        }
    }
}

impl std::error::Error for TokenError {}

impl ApprovalToken {
    /// Signs a manifest with `key` under `key_fingerprint`.
    pub fn sign(manifest: Manifest, key: &SigningKey, key_fingerprint: &str) -> ApprovalToken {
        let signature = key.sign(&manifest.canonical_bytes());
        ApprovalToken {
            key_fingerprint: key_fingerprint.to_string(),
            manifest,
            signature: signature.to_bytes(),
        }
    }

    /// Serializes the token envelope as JSON.
    pub fn to_json(&self) -> Vec<u8> {
        let value = object(vec![
            (
                "key_fingerprint",
                JsonValue::String(self.key_fingerprint.clone()),
            ),
            ("manifest", self.manifest.to_value()),
            (
                "signature",
                JsonValue::String(BASE64.encode(self.signature)),
            ),
        ]);
        serialize(&value).into_bytes()
    }

    /// Parses a token envelope. The envelope is parsed strictly
    /// (duplicate keys anywhere reject, F-01); the embedded
    /// manifest must re-serialize to exactly the bytes that were
    /// signed, which the verifier checks by digest (F-01/F-02).
    pub fn from_json(bytes: &[u8]) -> Result<ApprovalToken, TokenError> {
        let value = parse_strict(bytes)
            .map_err(|e| TokenError::Shape(format!("strict parse failed: {e}")))?;
        let fields = value
            .as_object()
            .ok_or_else(|| TokenError::Shape("token is not an object".to_string()))?;
        for (key, _) in fields {
            if !["key_fingerprint", "manifest", "signature"].contains(&key.as_str()) {
                return Err(TokenError::Shape(format!("unknown token field: {key}")));
            }
        }
        let key_fingerprint = value
            .get("key_fingerprint")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| TokenError::Shape("key_fingerprint missing".to_string()))?
            .to_string();
        let signature_b64 = value
            .get("signature")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| TokenError::Shape("signature missing".to_string()))?;
        let signature_bytes = BASE64
            .decode(signature_b64.as_bytes())
            .map_err(|_| TokenError::Shape("signature is not base64".to_string()))?;
        let signature: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| TokenError::Shape("signature is not 64 bytes".to_string()))?;
        let manifest_value = value
            .get("manifest")
            .ok_or_else(|| TokenError::Shape("manifest missing".to_string()))?;
        let manifest = Manifest::from_value(manifest_value).map_err(TokenError::Manifest)?;
        Ok(ApprovalToken {
            key_fingerprint,
            manifest,
            signature,
        })
    }

    /// Verifies the signature against an Ed25519 public key.
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        let key_bytes: &[u8; 32] = match public_key.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let verifying = match VerifyingKey::from_bytes(key_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&self.signature);
        verifying
            .verify(&self.manifest.canonical_bytes(), &signature)
            .is_ok()
    }
}
