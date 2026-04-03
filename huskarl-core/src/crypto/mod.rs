//! Cryptographic interfaces and definitions.
//!
//! Many `OAuth2` grants and auxiliary interfaces require use
//! of cryptographic operations to ensure properties such as
//! integrity, authentication, confidentiality, non-repudiation.
//!
//! This module provides interfaces to support that. Implementations
//! are provided externally.

pub mod cipher;
pub mod signer;
pub mod verifier;

/// States how well a particular key matched the selection criteria from a JOSE header.
///
/// Used by both JWS verifiers and JWE ciphers to express the strength of a key match,
/// allowing multi-key types to prefer exact matches over algorithm-only matches.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyMatchStrength {
    /// Both the algorithm and the key ID match exactly.
    ByKeyId,
    /// The algorithm matches but the key ID was not used for matching — either
    /// the header has no `kid`, or this key has no `kid` registered.
    ByAlgorithm,
}
