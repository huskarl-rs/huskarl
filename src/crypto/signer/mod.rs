//! Cryptographic signing key traits.

mod error;
#[cfg(any(
    feature = "crypto-native",
    all(feature = "default-crypto-native", not(target_arch = "wasm32"))
))]
pub mod native;
mod r#trait;
#[cfg(all(target_arch = "wasm32", feature = "crypto-webcrypto"))]
pub mod webcrypto;

pub use error::JwsSignerError;
pub use r#trait::{
    BoxedAsymmetricJwsSigningKey, BoxedJwsSigningKey, HasPublicKey, JwsSigningKey,
    SigningKeyMetadata,
};
