//! `WebCrypto` (`SubtleCrypto`) implementations of huskarl's crypto traits: JWS
//! signing and verification, plus AES-GCM AEAD. wasm32-only.
//!
//! - [`asymmetric`] provides the JWS signer/verifier key types
//!   ([`PrivateKey`](asymmetric::signer::PrivateKey),
//!   [`AsymmetricPublicKey`](asymmetric::verifier::AsymmetricPublicKey)).
//! - [`WebCryptoVerifierPlatform`] builds a verifier from a public JWK; it is the
//!   default verifier platform on wasm targets.
//! - [`aead`] provides an AES-GCM AEAD cipher ([`AesGcmKey`](aead::AesGcmKey)).
//!
//! Because `WebCrypto` is async, signing, verification, and key import are `async`.
//!
//! To sign, generate a non-extractable
//! [`PrivateKey`](asymmetric::signer::PrivateKey) and hand it to `huskarl-core`'s
//! [`Jwt`](huskarl_core::jwt::Jwt) builder. To verify, build an
//! [`AsymmetricPublicKey`](asymmetric::verifier::AsymmetricPublicKey) from a
//! public JWK (or use [`WebCryptoVerifierPlatform`] over a JWKS).
//!
//! # Documentation
//!
//! - **Solve a task:** [sign a JWT in the browser](crate::_docs::guide::signing_a_jwt)
//!   with an async, non-extractable key.
//! - **Understand the design:** read the
//!   [platform constraints](crate::_docs::explanation::platform_constraints)
//!   that distinguish this backend from `huskarl-crypto-native`.
//! - **Look up the API:** use the crate modules and item pages in this reference.
//!
//! Related how-to guides and explanation live in `huskarl-core`, which defines
//! the traits this crate implements:
//!
//! - [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
//! - [Validating a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/validating_a_jwt/index.html)
//! - [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
//!   — how the multi-key, refreshable, and retrying wrappers stack on these keys.

// WebCrypto is a browser API and every trait impl here wraps `JsFuture`
// (`!Send`), so the crate only compiles for wasm32 — off-wasm32 it's empty,
// letting `cargo publish`/docs.rs verification build on the host target.
#![cfg(target_arch = "wasm32")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod factory;

pub mod aead;
pub mod asymmetric;
pub(crate) mod helpers;

#[cfg(any(doc, docsrs))]
pub mod _docs;

pub use error::JsError;
pub use factory::WebCryptoVerifierPlatform;
use serde::Serialize;

/// Indicates the possible uses of a key.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyUsage {
    /// The key may be used to encrypt messages.
    Encrypt,
    /// The key may be used to decrypt messages.
    Decrypt,
    /// The key may be used to sign messages.
    Sign,
    /// The key may be used to verify signatures.
    Verify,
    /// The key may be used in deriving a new key.
    DeriveKey,
    /// The key may be used in deriving bits.
    DeriveBits,
    /// The key may be used to wrap a key.
    WrapKey,
    /// The key may be used to unwrap a key.
    UnwrapKey,
}
