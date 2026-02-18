//! Implements JWS signing keys using pure rust code.
//!
//! Currently, the following JWS algorithms are available:
//!
//! - Asymmetric (NIST elliptic curves)
//!   - ES256
//!   - ES384
//!   - ES512
//! - Symmetric (HMAC)
//!   - HS256
//!   - HS384
//!   - HS512
//! - Asymmetric (RSA)
//!   - RS256
//!   - PS256
//!   - PS384
//!   - PS512

mod es256;
mod es384;
mod es512;
mod hmac;
mod rsa;

pub use es256::{Es256PrivateKey, Es256PrivateKeyLoadError};
pub use es384::{Es384PrivateKey, Es384PrivateKeyLoadError};
pub use es512::{Es512PrivateKey, Es512PrivateKeyLoadError};
pub use hmac::{HmacAlgorithm, HmacKey};
pub use rsa::{RsaAlgorithm, RsaPrivateKey, RsaPrivateKeyLoadError};
