//! Native (RustCrypto-backed) implementations of huskarl's crypto traits: JWS
//! signing and verification, plus AEAD encryption.
//!
//! - [`asymmetric`] and [`symmetric`] provide the JWS signer/verifier key types
//!   ([`PrivateKey`](asymmetric::signer::PrivateKey),
//!   [`AsymmetricPublicKey`](asymmetric::verifier::AsymmetricPublicKey), and
//!   [`SymmetricKey`](symmetric::SymmetricKey)).
//! - [`NativeVerifierPlatform`] builds a verifier from a public JWK; it is the
//!   feature-gated default verifier platform for the ecosystem.
//! - [`aead`] provides two AEAD ciphers — [`AesGcmKey`](aead::AesGcmKey)
//!   (`A128GCM`/`A192GCM`/`A256GCM`) and [`XChaChaKey`](aead::XChaChaKey)
//!   (`XC20P`) — plus [`aead::from_jwk`], which selects between them by the
//!   JWK's `alg`.
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
//! To sign, generate or load a
//! [`PrivateKey`](asymmetric::signer::PrivateKey) and hand it to `huskarl-core`'s
//! [`Jwt`](huskarl_core::jwt::Jwt) builder; to verify, build an
//! [`AsymmetricPublicKey`](asymmetric::verifier::AsymmetricPublicKey) from a
//! public JWK (or use [`NativeVerifierPlatform`] over a JWKS) and hand it to the
//! JWT validator. The guides below walk through both.
//!
//! # Further reading
//!
//! - [Loading a signing key](crate::_docs::guide::loading_a_signing_key) — the
//!   recommended JWK path, and the PKCS#8 options.
//! - [Why JWK is the native key format](crate::_docs::explanation::jwk_as_key_format)
//!   — the design behind the loading API.
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

#[cfg(any(doc, docsrs))]
pub mod _docs;

pub use factory::NativeVerifierPlatform;
