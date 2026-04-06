#![warn(missing_docs)]
//! # `OAuth2` library for resource servers.
//!
//! This library handles concerns of interest to `OAuth2` resource servers. The primary need
//! in this case is validating provided access tokens, and checking whether the authorization
//! matches the necessary level.
//!
//! Currently this crate helps to handle the first of these; validating access tokens. It
//! then provides the context from those access tokens which let the server implement the
//! rest of the authorization checking.
//!
//! ## Example with RFC 9068 token validation:
//!
//! ```
//! use std::sync::Arc;
//! use huskarl_resource_server::core::jwk::JwksSource;
//! use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;
//! use huskarl_resource_server::validator::dpop_nonce::NoNonceCheck;
//!
//! # fn setup_resource_server(http_client: impl huskarl_resource_server::core::http::HttpClient + Clone + 'static) {
//! let validator = Rfc9068Validator::builder()
//!   .issuer("https://issuer")
//!   .audience("audience")
//!   .dpop_nonce_checker(NoNonceCheck)
//!   .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(http_client).build()))
//!   .build();
//! # }
//! ```

pub mod error;
pub mod introspection;
pub mod validator;

use std::sync::Arc;

use validator::extract::TokenType;
use validator::{AccessTokenValidator, ValidatedRequest};

#[doc(inline)]
pub use huskarl_core as core;

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
