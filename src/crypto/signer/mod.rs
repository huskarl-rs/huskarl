//! Cryptographic signing key traits.

mod error;
#[cfg(any(
    doc,
    all(feature = "default-crypto-native", not(target_arch = "wasm32"))
))]
pub mod native;
mod r#trait;
#[cfg(any(doc, all(feature = "default-crypto-webcrypto", target_arch = "wasm32")))]
pub mod webcrypto;

pub use error::JwsSignerError;
pub use r#trait::{
    BoxedAsymmetricJwsSigningKey, BoxedJwsSigningKey, HasPublicKey, JwsSigningKey,
    SigningKeyMetadata,
};
