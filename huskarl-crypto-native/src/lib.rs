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
//!
//! # Getting started
//!
//! Generate a signing key, then build and sign a JWT with it:
//!
//! ```
//! use huskarl_core::jwt::Jwt;
//! use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! // A signer backed by a freshly generated Ed25519 key.
//! let signer = PrivateKey::generate(GenerateAlgorithm::Ed25519, Some("key-1".to_string()))?;
//!
//! let jwt = Jwt::builder()
//!     .issuer("https://issuer.example")
//!     .subject("user-123")
//!     .issued_now_expires_after(std::time::Duration::from_secs(300))
//!     .claims(serde_json::json!({ "scope": "read write" }))
//!     .build();
//!
//! // A compact JWS string, ready for the wire.
//! let compact = jwt.to_jws_compact(&signer).await?;
//! # let _ = compact;
//! # Ok::<(), huskarl_core::error::Error>(())
//! # }).unwrap();
//! ```
//!
//! To verify, build an [`AsymmetricPublicKey`](asymmetric::verifier::AsymmetricPublicKey)
//! from a public JWK (or use [`NativeVerifierPlatform`] over a JWKS) and hand it
//! to `huskarl-core`'s JWT validator.
//!
//! # Further reading
//!
//! These pages live in `huskarl-core`, which defines the traits this crate
//! implements:
//!
//! - [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
//! - [Validating a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/validating_a_jwt/index.html)
//! - [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
//!   — how the multi-key, refreshable, and retrying wrappers stack on these keys.

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
