//! # `OAuth2` library for resource servers.
//!
//! This library handles concerns of interest to `OAuth2` resource servers. The primary need
//! in this case is validating provided access tokens, and checking whether the authorization
//! matches the necessary level.
//!
//! Currently this crate helps to handle the first of these; validating access tokens. It
//! then provides the context from those access tokens which let the server implement the
//! rest of the authorization checking.

pub mod error;
pub mod introspection;
pub mod validator;

use std::sync::Arc;

#[doc(inline)]
pub use huskarl_core as core;

pub use crate::core::jwt::ConfirmationClaim;
pub use validator::introspection::{IntrospectionValidateError, IntrospectionValidator};
pub use validator::{AccessTokenValidator, OnValidate, ValidatedRequest, ValidationOutcome};

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
