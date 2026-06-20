//! Native (RustCrypto-backed) implementations of huskarl's crypto traits: JWS
//! signing and verification, plus AEAD encryption.
//!
//! - [`asymmetric`] and [`symmetric`] provide the JWS signer/verifier key types
//!   ([`PrivateKey`](asymmetric::signer::PrivateKey),
//!   [`AsymmetricPublicKey`](asymmetric::verifier::AsymmetricPublicKey), and
//!   [`SymmetricKey`](symmetric::SymmetricKey)).
//! - [`NativeVerifierPlatform`] builds a verifier from a public JWK; it is the
//!   feature-gated default verifier platform for the ecosystem.
//! - [`aead`] provides an AES-GCM AEAD cipher ([`AesGcmKey`](aead::AesGcmKey)).
//!
//! The following JWS algorithms are available:
//!
//! - Asymmetric (Edwards-curve)
//!   - `Ed25519` (aka `EdDSA`)
//! - Asymmetric (NIST elliptic curves)
//!   - ES256
//!   - ES384
//! - Symmetric (HMAC)
//!   - HS256
//!   - HS384
//!   - HS512
//! - Asymmetric (RSA)
//!   - RS256
//!   - RS384
//!   - RS512
//!   - PS256
//!   - PS384
//!   - PS512

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aead;
mod factory;

pub mod asymmetric;
pub mod symmetric;

pub use factory::NativeVerifierPlatform;
