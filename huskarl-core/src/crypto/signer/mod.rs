//! Cryptographic signing key traits.

mod asymmetric;
mod error;
mod symmetric;

pub use asymmetric::boxed::BoxedAsymmetricJwsSigner;
pub use asymmetric::{
    AsymmetricJwsSigner, AsymmetricJwsSigningKey, AsymmetricSigningKeyMetadata,
    SignByThumbprintError,
};
pub use error::JwsSignerError;
pub use symmetric::boxed::BoxedJwsSigner;
pub use symmetric::{JwsSigner, JwsSigningKey, SigningKeyMetadata};
