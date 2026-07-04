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
//! # Getting started
//!
//! Generate a non-extractable signing key, then build and sign a JWT with it.
//! Every crypto call is `async`, and the key never leaves `SubtleCrypto`:
//!
//! ```no_run
//! use huskarl_core::jwt::Jwt;
//! use huskarl_crypto_webcrypto::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = PrivateKey::generate(GenerateAlgorithm::Es256, Some("key-1".to_string())).await?;
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
//! # Ok(())
//! # }
//! ```
//!
//! To verify, build an [`AsymmetricPublicKey`](asymmetric::verifier::AsymmetricPublicKey)
//! from a public JWK (or use [`WebCryptoVerifierPlatform`] over a JWKS) and hand
//! it to `huskarl-core`'s JWT validator.
//!
//! # Parity with `huskarl-crypto-native`
//!
//! Code written against `huskarl-crypto-native` does not always port directly;
//! the differences are `WebCrypto` platform constraints, not omissions:
//!
//! | Capability | native | webcrypto |
//! |---|---|---|
//! | Generate a signing key | ✔ (sync) | ✔ (`async`) |
//! | **Import** a signing key (PKCS#8 / private JWK) | ✔ | ✘ — keys are generated non-extractable; there is no `load_pkcs8_*`/`from_jwk` on the signer |
//! | Import a *public* verify key (JWK / JWKS) | ✔ | ✔ (`async`) |
//! | Symmetric JWS (HMAC, e.g. `HS256` / `client_secret_jwt`) | ✔ (`SymmetricKey`) | ✘ — no symmetric signing module |
//! | AES-GCM AEAD from key material | ✔ | ✔ (plus [`from_crypto_key`](aead::AesGcmKey::from_crypto_key) for an existing `CryptoKey`) |
//! | Sign / verify / import calls | sync | `async` (`SubtleCrypto`) |
//!
//! Practical consequences: a wasm client authenticates with `private_key_jwt`
//! only via a key **generated in-browser** and registered by its public JWK
//! (which also suits `DPoP`, where an ephemeral per-session key is the normal
//! deployment) — it cannot load a pre-provisioned private key, and
//! `client_secret_jwt` is unavailable.
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
