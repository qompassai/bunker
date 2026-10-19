//! Signed Authority Approvals — pilot implementation.
//!
//! Design: `~/workspace/signed-consent-20261018/DESIGN.md` (v2).
//! One human signs one canonical manifest per concrete action;
//! executors verify in a fixed, fail-closed order and consume the
//! nonce before dispatch. The pilot pins the authority key by
//! fingerprint plus record; binding that key into an OpenPGP
//! certificate served by Volta is the production follow-on
//! behind the [`record::AuthorityKeySource`] trait.

pub mod canonical;
pub mod manifest;
pub mod record;
pub mod token;
pub mod verify;

pub use manifest::{Labels, Manifest, ManifestError};
pub use record::{AuthorityKeySource, AuthorityRecord, PinnedKeySource};
pub use token::ApprovalToken;
pub use verify::{
    MemoryNonceStore, NonceStore, Tier, VerifiedApproval, VerifyContext, VerifyError, verify_token,
};
