//! Google Cloud KMS crypto integrations.
//!
//! - [`asymmetric`] — JWS signing with EC, RSA, and Ed25519 keys, plus JWKS
//!   publication.
//! - [`symmetric`] — AEAD encryption and decryption (`RAW_ENCRYPT_DECRYPT`) and
//!   HMAC signing and verification (`MAC`).
//! - [`version`] — the [`VersionStrategy`] that selects which key version to
//!   pin.
//!
//! Keys resolve their version(s) once, at build time, and pin the result;
//! signing and encryption pin a single version while verification and
//! decryption span all enabled versions. For the model and how to rotate
//! safely, see [key versions and
//! rotation](crate::_docs::explanation::versions_and_rotation); to rebuild keys
//! on a schedule, see the [self-refreshing keys
//! guide](crate::_docs::guide::refreshing_keys).

pub mod asymmetric;
pub mod symmetric;
pub mod version;

pub use version::VersionStrategy;
