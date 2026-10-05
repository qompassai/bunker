use super::Token as BunkerToken;
use super::*;

use bunker::cache::CacheName;
use jwt_simple::prelude::EdDSAKeyPairLike;

macro_rules! cache {
    ($n:expr) => {
        CacheName::new($n.to_string()).unwrap()
    };
}

/// Creates a test token with the given claims, signed with EdDSA.
fn make_test_token(key: &Ed25519KeyPair, sub: &str, exp_offset_secs: i64) -> String {
    let claims = TokenClaims {
        bunker_ns: BunkerAccess::default(),
    };
    let now = Utc::now().timestamp();
    let claims = JWTClaims {
        issued_at: Some(UnixTimeStamp::from_secs(now as u64)),
        expires_at: Some(UnixTimeStamp::from_secs((now + exp_offset_secs) as u64)),
        invalid_before: None,
        issuer: Some("test-issuer".to_string()),
        subject: Some(sub.to_string()),
        audiences: None,
        jwt_id: None,
        nonce: None,
        custom: claims,
    };
    key.sign(claims).unwrap()
}

fn test_signature_type(key: &Ed25519KeyPair) -> SignatureType {
    SignatureType::EdDSA(Box::new(
        Ed25519KeyPair::from_bytes(&key.to_bytes()).unwrap(),
    ))
}

fn test_issuer() -> Option<String> {
    Some("test-issuer".to_string())
}

// --- Validation tests ---

#[test]
fn valid_eddsa_token_verifies() {
    let key = Ed25519KeyPair::generate();
    let sig_type = test_signature_type(&key);
    let token_str = make_test_token(&key, "alice", 3600);

    let token = BunkerToken::from_jwt(&token_str, &sig_type, &test_issuer(), &None).unwrap();
    assert_eq!(token.sub(), Some("alice"));
}

#[test]
fn expired_token_rejected() {
    let key = Ed25519KeyPair::generate();
    let sig_type = test_signature_type(&key);
    // Expired 1 hour ago
    let token_str = make_test_token(&key, "alice", -3600);

    let result = BunkerToken::from_jwt(&token_str, &sig_type, &test_issuer(), &None);
    assert!(result.is_err(), "expired token must be rejected");
}

#[test]
fn wrong_issuer_rejected() {
    let key = Ed25519KeyPair::generate();
    let sig_type = test_signature_type(&key);
    let token_str = make_test_token(&key, "alice", 3600);

    let wrong_issuer = Some("evil-issuer".to_string());
    let result = BunkerToken::from_jwt(&token_str, &sig_type, &wrong_issuer, &None);
    assert!(result.is_err(), "wrong issuer must be rejected");
}

#[test]
fn token_without_expiry_rejected() {
    let key = Ed25519KeyPair::generate();
    let claims = JWTClaims {
        issued_at: None,
        expires_at: None, // No expiry!
        invalid_before: None,
        issuer: Some("test-issuer".to_string()),
        subject: Some("alice".to_string()),
        audiences: None,
        jwt_id: None,
        nonce: None,
        custom: TokenClaims {
            bunker_ns: BunkerAccess::default(),
        },
    };
    let token_str = key.sign(claims).unwrap();
    let sig_type = test_signature_type(&key);

    let result = BunkerToken::from_jwt(&token_str, &sig_type, &test_issuer(), &None);
    assert!(
        matches!(result, Err(Error::MissingExpiry)),
        "token without exp must be rejected"
    );
}

// --- Adversarial tests ---

#[test]
fn alg_none_rejected() {
    // Craft a JWT with alg: none (no signature)
    let header = BASE64_STANDARD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = BASE64_STANDARD.encode(r#"{"sub":"alice","exp":4102324986}"#);
    let token_str = format!("{}.{}.", header, payload);

    let key = Ed25519KeyPair::generate();
    let sig_type = test_signature_type(&key);

    let result = BunkerToken::from_jwt(&token_str, &sig_type, &None, &None);
    assert!(
        matches!(result, Err(Error::AlgorithmMismatch)),
        "alg:none must be rejected"
    );
}

#[test]
fn alg_hs256_rejected() {
    // Craft a JWT with alg: HS256 (algorithm confusion attempt)
    let header = BASE64_STANDARD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = BASE64_STANDARD.encode(r#"{"sub":"alice","exp":4102324986}"#);
    let fake_sig = BASE64_STANDARD.encode("fakesignature");
    let token_str = format!("{}.{}.{}", header, payload, fake_sig);

    let key = Ed25519KeyPair::generate();
    let sig_type = test_signature_type(&key);

    let result = BunkerToken::from_jwt(&token_str, &sig_type, &None, &None);
    assert!(
        matches!(result, Err(Error::AlgorithmMismatch)),
        "alg:HS256 must be rejected"
    );
}

#[test]
fn tampered_signature_rejected() {
    let key = Ed25519KeyPair::generate();
    let sig_type = test_signature_type(&key);
    let token_str = make_test_token(&key, "alice", 3600);

    // Tamper with the last character of the signature
    let mut tampered = token_str.clone();
    let last_char = tampered.pop().unwrap();
    let new_char = if last_char == 'A' { 'B' } else { 'A' };
    tampered.push(new_char);

    let result = BunkerToken::from_jwt(&tampered, &sig_type, &test_issuer(), &None);
    assert!(result.is_err(), "tampered signature must be rejected");
}

#[test]
fn future_nbf_rejected() {
    let key = Ed25519KeyPair::generate();
    let now = Utc::now().timestamp();
    let claims = JWTClaims {
        issued_at: None,
        expires_at: Some(UnixTimeStamp::from_secs((now + 3600) as u64)),
        // Not valid for another hour
        invalid_before: Some(UnixTimeStamp::from_secs((now + 3600) as u64)),
        issuer: Some("test-issuer".to_string()),
        subject: Some("alice".to_string()),
        audiences: None,
        jwt_id: None,
        nonce: None,
        custom: TokenClaims {
            bunker_ns: BunkerAccess::default(),
        },
    };
    let token_str = key.sign(claims).unwrap();
    let sig_type = test_signature_type(&key);

    let result = BunkerToken::from_jwt(&token_str, &sig_type, &test_issuer(), &None);
    assert!(result.is_err(), "future nbf must be rejected");
}

#[test]
fn malformed_jwt_rejected() {
    let key = Ed25519KeyPair::generate();
    let sig_type = test_signature_type(&key);

    // Not 3 parts
    let result = BunkerToken::from_jwt("not.a.jwt.at.all.extra", &sig_type, &None, &None);
    assert!(result.is_err());

    // Invalid base64 in header
    let result = BunkerToken::from_jwt("!!!.payload.sig", &sig_type, &None, &None);
    assert!(result.is_err());

    // Empty string
    let result = BunkerToken::from_jwt("", &sig_type, &None, &None);
    assert!(result.is_err());
}

#[test]
fn wrong_key_rejected() {
    let key1 = Ed25519KeyPair::generate();
    let key2 = Ed25519KeyPair::generate();
    let sig_type2 = test_signature_type(&key2);

    // Sign with key1, verify with key2
    let token_str = make_test_token(&key1, "alice", 3600);
    let result = BunkerToken::from_jwt(&token_str, &sig_type2, &test_issuer(), &None);
    assert!(result.is_err(), "wrong key must be rejected");
}

// --- Permission tests (from original test_basic, adapted for EdDSA) ---

#[test]
fn test_permissions() {
    // Create a token and verify basic permission defaults.
    // Note: BunkerToken::new creates a token with default (empty) permissions.
    let token = BunkerToken::new("meow".to_string(), &Utc::now());

    let perm = token.get_permission_for_cache(&cache!("any-cache"));
    assert!(!perm.can_discover());
}
