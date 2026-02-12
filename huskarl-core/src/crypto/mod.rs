//! Cryptographic interfaces and definitions.
//!
//! Many `OAuth2` grants and auxiliary interfaces require use
//! of cryptographic operations to ensure properties such as
//! integrity, authentication, confidentiality, non-repudiation.
//!
//! This module provides interfaces to support that. Implementations
//! are provided externally.

pub mod signer;
pub mod verifier;
