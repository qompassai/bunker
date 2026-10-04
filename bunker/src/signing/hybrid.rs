//! Hybrid post-quantum signatures: Ed25519 + ML-DSA-65.
//!
//! ## Design
//!
//! A hybrid signature concatenates two independent signatures over the same
//! message:
//!
//! ```text
//! hybrid_sig = ed25519_sig (64 bytes) || mldsa65_sig (3309 bytes)
//! ```
//!
//! Verification requires BOTH signatures to verify (AND-verification).
//! An attacker who breaks Ed25519 still faces ML-DSA-65, and vice versa.
//!
//! ## Wire format
//!
//! Follows the canonical `{keyName}:{base64Payload}` format:
//!
//! - Keypair: `{name}:base64(ed25519_keypair || mldsa65_seed)` (64 + 32 = 96 bytes)
//! - Public key: `{name}:base64(ed25519_pubkey || mldsa65_vk)` (32 + 1952 = 1984 bytes)
//! - Signature: `{name}:base64(ed25519_sig || mldsa65_sig)` (64 + 3309 = 3373 bytes)
//!
//! The ML-DSA-65 signing key is stored as its 32-byte seed; the full key
//! is rederived via `SigningKey::from_seed` on import.
//!
//! ## Backwards compatibility
//!
//! Pure-Ed25519 signatures (64 bytes) continue to verify via
//! [`crate::signing::NixPublicKey`]. [`HybridPublicKey`] rejects them:
//! a hybrid verifier requires the full 3373-byte hybrid format.

use ed25519_compact::{KeyPair as EdKeyPair, PublicKey as EdPublicKey, Signature as EdSignature};
use ml_dsa::{
    Generate as _, Keypair as _, MlDsa65, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use signature::{Signer as _, Verifier as _};

use crate::error::BunkerResult;
use crate::signing::{Error as SigningError, decode_string, validate_name};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

/// Length of an Ed25519 signature in bytes.
const ED25519_SIG_LEN: usize = 64;
/// Length of an ML-DSA-65 signature in bytes (FIPS 204).
const MLDSA65_SIG_LEN: usize = 3309;
/// Length of a hybrid signature: Ed25519 || ML-DSA-65.
const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN;

/// Length of an Ed25519 keypair (secret || public) in bytes.
const ED25519_KEYPAIR_LEN: usize = 64;
/// Length of an ML-DSA-65 seed in bytes.
const MLDSA65_SEED_LEN: usize = 32;
/// Length of a hybrid keypair export: Ed25519 keypair || ML-DSA-65 seed.
const HYBRID_KEYPAIR_LEN: usize = ED25519_KEYPAIR_LEN + MLDSA65_SEED_LEN;

/// Length of an Ed25519 public key in bytes.
const ED25519_PUBKEY_LEN: usize = 32;
/// Length of an encoded ML-DSA-65 verifying key in bytes.
const MLDSA65_VK_LEN: usize = 1952;
/// Length of a hybrid public key export: Ed25519 pubkey || ML-DSA-65 vk.
const HYBRID_PUBKEY_LEN: usize = ED25519_PUBKEY_LEN + MLDSA65_VK_LEN;

/// A hybrid Ed25519 + ML-DSA-65 keypair for signing.
#[derive(Debug)]
pub struct HybridKeypair {
    /// Name of this key.
    name: String,
    /// Classical Ed25519 keypair.
    ed25519: EdKeyPair,
    /// Post-quantum ML-DSA-65 signing key.
    mldsa: MlDsaSigningKey<MlDsa65>,
}

/// A hybrid Ed25519 + ML-DSA-65 public key for verification.
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    /// Name of this key.
    name: String,
    /// Classical Ed25519 public key.
    ed25519: EdPublicKey,
    /// Post-quantum ML-DSA-65 verifying key.
    mldsa: MlDsaVerifyingKey<MlDsa65>,
}

impl HybridKeypair {
    /// Generates a new hybrid keypair.
    ///
    /// Uses the OS CSPRNG for both the Ed25519 keypair and the ML-DSA-65
    /// seed. Rejects blank names and names containing colons.
    pub fn generate(name: &str) -> BunkerResult<Self> {
        validate_name(name)?;
        let ed25519 = EdKeyPair::generate();
        let mldsa = MlDsaSigningKey::<MlDsa65>::generate();
        Ok(Self {
            name: name.to_string(),
            ed25519,
            mldsa,
        })
    }

    /// Imports a hybrid keypair from its canonical representation.
    ///
    /// Expected format: `{name}:base64(ed25519_keypair || mldsa65_seed)`.
    /// Rejects malformed base64, wrong lengths, and invalid key material.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(keypair: &str) -> BunkerResult<Self> {
        let (name, bytes) = decode_string(keypair, "hybrid keypair", HYBRID_KEYPAIR_LEN, None)?;

        let ed25519 = EdKeyPair::from_slice(&bytes[..ED25519_KEYPAIR_LEN])
            .map_err(SigningError::SignatureError)?;
        let seed_bytes: [u8; MLDSA65_SEED_LEN] = bytes[ED25519_KEYPAIR_LEN..]
            .try_into()
            .expect("decode_string guaranteed HYBRID_KEYPAIR_LEN bytes");
        let mldsa = MlDsaSigningKey::<MlDsa65>::from_seed(&seed_bytes.into());

        Ok(Self {
            name: name.to_string(),
            ed25519,
            mldsa,
        })
    }

    /// Returns the canonical representation of the hybrid keypair.
    ///
    /// Format: `{name}:base64(ed25519_keypair || mldsa65_seed)}`.
    pub fn export_keypair(&self) -> String {
        let mut bytes = Vec::with_capacity(HYBRID_KEYPAIR_LEN);
        bytes.extend_from_slice(&self.ed25519[..]);
        bytes.extend_from_slice(self.mldsa.to_seed().as_slice());
        format!("{}:{}", self.name, BASE64_STANDARD.encode(bytes))
    }

    /// Returns the canonical representation of the hybrid public key.
    ///
    /// Format: `{name}:base64(ed25519_pubkey || mldsa65_vk)}`.
    pub fn export_public_key(&self) -> String {
        self.to_public_key().export()
    }

    /// Returns the public key portion of the keypair.
    pub fn to_public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            name: self.name.clone(),
            ed25519: self.ed25519.pk,
            mldsa: self.mldsa.verifying_key(),
        }
    }

    /// Signs a message with both Ed25519 and ML-DSA-65.
    ///
    /// Returns the canonical `{name}:base64(ed25519_sig || mldsa65_sig)}`.
    /// ML-DSA-65 signing is randomized (fresh randomness per signature).
    pub fn sign(&self, message: &[u8]) -> String {
        let ed_sig = self.ed25519.sk.sign(message, None);
        let mldsa_sig: MlDsaSignature<MlDsa65> = self.mldsa.sign(message);

        let mut bytes = Vec::with_capacity(HYBRID_SIG_LEN);
        bytes.extend_from_slice(&ed_sig[..]);
        bytes.extend_from_slice(mldsa_sig.encode().as_slice());

        format!("{}:{}", self.name, BASE64_STANDARD.encode(bytes))
    }

    /// Verifies a hybrid signature against this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &str) -> BunkerResult<()> {
        self.to_public_key().verify(message, signature)
    }
}

impl HybridPublicKey {
    /// Imports a hybrid public key from its canonical representation.
    ///
    /// Expected format: `{name}:base64(ed25519_pubkey || mldsa65_vk)}`.
    /// Rejects malformed base64, wrong lengths, and invalid key material.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(public_key: &str) -> BunkerResult<Self> {
        let (name, bytes) =
            decode_string(public_key, "hybrid public key", HYBRID_PUBKEY_LEN, None)?;

        let ed25519 = EdPublicKey::from_slice(&bytes[..ED25519_PUBKEY_LEN])
            .map_err(SigningError::SignatureError)?;
        // VerifyingKey::decode is infallible (raw byte decode); an invalid
        // key simply fails verification later.
        let mldsa = MlDsaVerifyingKey::<MlDsa65>::decode(
            &bytes[ED25519_PUBKEY_LEN..]
                .try_into()
                .expect("decode_string guaranteed HYBRID_PUBKEY_LEN bytes"),
        );

        Ok(Self {
            name: name.to_string(),
            ed25519,
            mldsa,
        })
    }

    /// Returns the canonical representation of the hybrid public key.
    pub fn export(&self) -> String {
        let mut bytes = Vec::with_capacity(HYBRID_PUBKEY_LEN);
        bytes.extend_from_slice(&self.ed25519[..]);
        bytes.extend_from_slice(self.mldsa.encode().as_slice());
        format!("{}:{}", self.name, BASE64_STANDARD.encode(bytes))
    }

    /// Verifies a hybrid signature.
    ///
    /// Both the Ed25519 and ML-DSA-65 signatures must verify
    /// (AND-verification). Rejects pure-Ed25519 signatures: they are
    /// 64 bytes, not the required 3373 bytes.
    pub fn verify(&self, message: &[u8], signature: &str) -> BunkerResult<()> {
        let (_, bytes) = decode_string(
            signature,
            "hybrid signature",
            HYBRID_SIG_LEN,
            Some(&self.name),
        )?;

        // Split into Ed25519 and ML-DSA-65 halves.
        let ed_sig = EdSignature::from_slice(&bytes[..ED25519_SIG_LEN])
            .map_err(SigningError::SignatureError)?;
        let mldsa_encoded: [u8; MLDSA65_SIG_LEN] = bytes[ED25519_SIG_LEN..]
            .try_into()
            .expect("decode_string guaranteed HYBRID_SIG_LEN bytes");
        let mldsa_sig = MlDsaSignature::<MlDsa65>::decode(&mldsa_encoded.into()).ok_or(
            SigningError::InvalidPayloadLength {
                expected: MLDSA65_SIG_LEN,
                actual: MLDSA65_SIG_LEN,
                usage: "ML-DSA-65 signature decode",
            },
        )?;

        // AND-verification: both must pass. Check Ed25519 first (cheap),
        // then ML-DSA-65.
        let ed_ok = self.ed25519.verify(message, &ed_sig).is_ok();
        let mldsa_ok = self.mldsa.verify(message, &mldsa_sig).is_ok();

        match (ed_ok, mldsa_ok) {
            (true, true) => Ok(()),
            (false, _) => Err(SigningError::HybridVerifyFailed("ed25519").into()),
            (_, false) => Err(SigningError::HybridVerifyFailed("mldsa65").into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::NixKeypair;

    // ---------------------------------------------------------------------------
    // Validation: correct behavior
    // ---------------------------------------------------------------------------

    #[test]
    fn sign_verify_roundtrip() {
        let keypair = HybridKeypair::generate("test").unwrap();
        let message = b"hello, hybrid world";

        let sig = keypair.sign(message);

        // Verify via the keypair.
        keypair.verify(message, &sig).unwrap();
        // Verify via the public key.
        keypair.to_public_key().verify(message, &sig).unwrap();
    }

    #[test]
    fn keypair_export_import_roundtrip() {
        let keypair = HybridKeypair::generate("roundtrip").unwrap();
        let exported = keypair.export_keypair();

        let imported = HybridKeypair::from_str(&exported).unwrap();

        // Imported keypair signs verifiably.
        let message = b"roundtrip test";
        let sig = imported.sign(message);
        imported.verify(message, &sig).unwrap();
        keypair.to_public_key().verify(message, &sig).unwrap();
    }

    #[test]
    fn public_key_export_import_roundtrip() {
        let keypair = HybridKeypair::generate("pubkey").unwrap();
        let exported = keypair.export_public_key();

        let public = HybridPublicKey::from_str(&exported).unwrap();

        let message = b"public key test";
        let sig = keypair.sign(message);
        public.verify(message, &sig).unwrap();
    }

    #[test]
    fn cross_verify_separate_public_key() {
        // Sign with keypair A, verify with A's exported public key
        // imported as a separate object.
        let keypair_a = HybridKeypair::generate("key-a").unwrap();
        let public_a = HybridPublicKey::from_str(&keypair_a.export_public_key()).unwrap();

        let message = b"cross verification";
        let sig = keypair_a.sign(message);

        public_a.verify(message, &sig).unwrap();
    }

    #[test]
    fn signature_format_has_correct_lengths() {
        let keypair = HybridKeypair::generate("lengths").unwrap();
        let sig = keypair.sign(b"length check");

        // Format: {name}:{base64(3373 bytes)}
        let (_, payload) = sig.split_once(':').unwrap();
        let bytes = BASE64_STANDARD.decode(payload).unwrap();
        assert_eq!(bytes.len(), HYBRID_SIG_LEN);
        assert_eq!(HYBRID_SIG_LEN, 3373);
    }

    // ---------------------------------------------------------------------------
    // Adversarial: malformed and hostile inputs must fail closed
    // ---------------------------------------------------------------------------

    /// Helper: tamper one byte in a base64-encoded hybrid signature.
    fn tamper_signature_byte(sig: &str, byte_index: usize) -> String {
        let (name, payload) = sig.split_once(':').unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        bytes[byte_index] ^= 0xFF;
        format!("{}:{}", name, BASE64_STANDARD.encode(bytes))
    }

    #[test]
    fn rejects_tampered_ed25519_half() {
        let keypair = HybridKeypair::generate("tamper-ed").unwrap();
        let message = b"tamper test";
        let sig = keypair.sign(message);

        // Flip a byte in the Ed25519 half (first 64 bytes).
        let tampered = tamper_signature_byte(&sig, 10);

        let result = keypair.to_public_key().verify(message, &tampered);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("ed25519"),
            "expected ed25519 failure, got: {}",
            err
        );
    }

    #[test]
    fn rejects_tampered_mldsa_half() {
        let keypair = HybridKeypair::generate("tamper-ml").unwrap();
        let message = b"tamper test";
        let sig = keypair.sign(message);

        // Flip a byte in the ML-DSA-65 half (after byte 64).
        let tampered = tamper_signature_byte(&sig, 100);

        let result = keypair.to_public_key().verify(message, &tampered);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("mldsa65"),
            "expected mldsa65 failure, got: {}",
            err
        );
    }

    #[test]
    fn rejects_truncated_signature() {
        let keypair = HybridKeypair::generate("truncate").unwrap();
        let message = b"truncate test";
        let sig = keypair.sign(message);

        // Truncate to Ed25519-only length.
        let (name, payload) = sig.split_once(':').unwrap();
        let bytes = BASE64_STANDARD.decode(payload).unwrap();
        let truncated = format!(
            "{}:{}",
            name,
            BASE64_STANDARD.encode(&bytes[..ED25519_SIG_LEN])
        );

        let result = keypair.to_public_key().verify(message, &truncated);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_key_name() {
        let keypair_a = HybridKeypair::generate("key-a").unwrap();
        let keypair_b = HybridKeypair::generate("key-b").unwrap();

        let message = b"wrong name test";
        let sig_a = keypair_a.sign(message);

        // Verify A's signature against B's public key (different name).
        let result = keypair_b.to_public_key().verify(message, &sig_a);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_pure_ed25519_as_hybrid() {
        // A valid Ed25519 signature must NOT verify as a hybrid signature.
        // This is the downgrade attack: strip the PQ half and present
        // the classical signature alone.
        let hybrid = HybridKeypair::generate("hybrid").unwrap();
        let classic = NixKeypair::generate("hybrid").unwrap();

        let message = b"downgrade test";
        let classic_sig = classic.sign(message);

        // The classic sig is 64 bytes; hybrid expects 3373.
        let result = hybrid.to_public_key().verify(message, &classic_sig);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_replay_across_keys() {
        let keypair_a = HybridKeypair::generate("key-a").unwrap();
        let keypair_b = HybridKeypair::generate("key-b").unwrap();

        let message = b"replay test";
        // Sign with A, but re-label with B's name to bypass the name check.
        let sig_a = keypair_a.sign(message);
        let (_, payload) = sig_a.split_once(':').unwrap();
        let relabeled = format!("key-b:{}", payload);

        let result = keypair_b.to_public_key().verify(message, &relabeled);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_message() {
        let keypair = HybridKeypair::generate("wrong-msg").unwrap();
        let sig = keypair.sign(b"original message");

        let result = keypair.to_public_key().verify(b"different message", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_malformed_base64() {
        let keypair = HybridKeypair::generate("bad-b64").unwrap();
        let bad_sig = "bad-b64:!!!not-valid-base64!!!";

        let result = keypair.to_public_key().verify(b"test", bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_blank_name_on_generate() {
        assert!(HybridKeypair::generate("").is_err());
        assert!(HybridKeypair::generate("has:colon").is_err());
    }
}
