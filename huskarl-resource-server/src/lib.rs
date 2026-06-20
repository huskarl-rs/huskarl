#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! # `OAuth2` library for resource servers.
//!
//! A resource server has two jobs: validate the access token presented with a
//! request, and decide whether that token authorizes the request.
//!
//! This crate does the first. A [`validator`] verifies the token
//! (signature/introspection, expiry, audience, and any sender-constraint
//! binding) and returns a [`ValidatedRequest`]
//! carrying its claims — from which your application makes the second decision.
//!
//! ## Example with RFC 9068 token validation:
//!
//! ```
//! use std::sync::Arc;
//!
//! use huskarl_resource_server::{
//!     core::{http::HttpClient, jwk::JwksSource},
//!     validator::rfc9068::Rfc9068Validator,
//! };
//!
//! # fn setup_resource_server(http_client: impl HttpClient + Clone + 'static) {
//! let validator = Rfc9068Validator::builder()
//!     .issuer("https://issuer")
//!     .audience("audience")
//!     .jws_verifier_factory(Arc::new(
//!         JwksSource::builder().http_client(http_client).build(),
//!     ))
//!     .build();
//! # }
//! ```

pub mod error;
pub mod introspection;
pub mod validator;

use std::sync::Arc;

#[doc(inline)]
pub use huskarl_core as core;
use validator::{AccessTokenValidator, ValidatedRequest, extract::TokenType};

/// The platform default [`core::crypto::verifier::JwsVerifierPlatform`] implementation.
///
/// On native platforms this wraps `huskarl-crypto-native`; on WebAssembly it wraps
/// `huskarl-crypto-webcrypto`. Enabled by the `default-jws-verifier-platform` feature.
#[derive(Debug, Clone)]
pub struct DefaultJwsVerifierPlatform(Arc<dyn core::crypto::verifier::JwsVerifierPlatform>);

impl From<DefaultJwsVerifierPlatform> for Arc<dyn core::crypto::verifier::JwsVerifierPlatform> {
    fn from(value: DefaultJwsVerifierPlatform) -> Self {
        value.0
    }
}

/// The platform default JWS verifier factory for native platforms.
#[cfg(all(
    feature = "default-jws-verifier-platform",
    not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))
))]
impl Default for DefaultJwsVerifierPlatform {
    fn default() -> Self {
        Self(Arc::new(huskarl_crypto_native::NativeVerifierPlatform))
    }
}

/// The platform default JWS verifier factory for WebAssembly/WebCrypto platforms.
#[cfg(all(
    feature = "default-jws-verifier-platform",
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
impl Default for DefaultJwsVerifierPlatform {
    fn default() -> Self {
        Self(Arc::new(
            huskarl_crypto_webcrypto::WebCryptoVerifierPlatform::default(),
        ))
    }
}
