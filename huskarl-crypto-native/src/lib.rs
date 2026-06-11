//! Native rust implementation of JWS signers.
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
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aead;
mod factory;

pub mod asymmetric;
pub mod symmetric;

pub use factory::NativeVerifierPlatform;
