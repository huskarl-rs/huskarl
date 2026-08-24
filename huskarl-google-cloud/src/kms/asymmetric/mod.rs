//! KMS-backed asymmetric JWS signing and public-key (JWKS) serving.
//!
//! - [`signer`] — a [`SigningKey`] that signs JWS via Cloud KMS, pinning a
//!   version per [`VersionStrategy`](super::VersionStrategy).
//! - [`jwks`] — a [`Jwks`] provider that publishes the key's public versions.
//!
//! See [key versions and
//! rotation](crate::_docs::explanation::versions_and_rotation) for the version
//! and rotation model, and the [signing guide](crate::_docs::guide::asymmetric_signing).

pub mod jwks;
pub mod signer;

pub use jwks::{Jwks, JwksError};
pub use signer::{KeyVersion, SetupError, SigningError, SigningKey};
