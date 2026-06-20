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

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod factory;

pub mod aead;
pub mod asymmetric;
pub(crate) mod helpers;

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
