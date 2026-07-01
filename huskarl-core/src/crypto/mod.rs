//! Cryptographic interfaces and definitions.
//!
//! Many `OAuth2` grants and auxiliary interfaces require cryptographic
//! operations to ensure properties such as integrity, authentication,
//! confidentiality, and non-repudiation.
//!
//! This module holds the signing ([`signer`]), verification ([`verifier`]), and
//! encryption ([`cipher`]) traits, plus the shared key-matching types
//! ([`KeyMatchStrength`]). Concrete implementations live in platform crates.
//!
//! Each base trait comes with a family of composable wrappers (multi-key,
//! refreshable, scheduled-refresh, retrying) that decorate it without changing
//! its interface. See [composing crypto
//! strategies](crate::_docs::explanation::crypto_strategies) for how they stack.

pub mod cipher;
pub(crate) mod refreshable;
pub mod signer;
pub mod verifier;

/// States how well a particular key matched the selection criteria from a JOSE header.
///
/// Used by both JWS verifiers and JWE ciphers to express the strength of a key match,
/// allowing multi-key types to prefer exact matches over algorithm-only matches.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyMatchStrength {
    /// Both the algorithm and the key ID match exactly.
    ByKeyId,
    /// The algorithm matches but the key ID was not used for matching — either
    /// the header has no `kid`, or this key has no `kid` registered.
    ByAlgorithm,
}

/// The shared `kid` half of the key-matching rules, applied after the
/// algorithm has already been found compatible: both sides present and equal
/// is a `ByKeyId` match, both present and different is a mismatch, and a
/// `kid` missing on either side falls back to `ByAlgorithm`.
pub(crate) fn kid_match_strength(
    requested: Option<&str>,
    registered: Option<&str>,
) -> Option<KeyMatchStrength> {
    match (requested, registered) {
        (Some(requested), Some(registered)) => {
            (requested == registered).then_some(KeyMatchStrength::ByKeyId)
        }
        _ => Some(KeyMatchStrength::ByAlgorithm),
    }
}
