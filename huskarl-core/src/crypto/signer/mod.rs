//! Cryptographic signing key traits.

mod error;
mod r#trait;

pub use error::JwsSignerError;
pub use r#trait::{
    BoxedAsymmetricJwsSigningKey, BoxedJwsSigningKey, HasPublicKey, JwsSigningKey,
    SigningKeyMetadata,
};
