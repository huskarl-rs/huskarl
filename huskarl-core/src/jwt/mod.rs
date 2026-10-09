//! JWT support
//!
//! Supports the following operations:
//!  - Typesafe JWT builder
//!  - Creation of a JWT using JWS compact seralization
//!  - Checking if the supplied JTI was previous seen

mod builder;
#[cfg(feature = "experimental-oidc-key-binding")]
mod confirmation;
mod jti;
mod parse;
mod structure;
pub mod validator;

pub use builder::{JwsSigningInputError, Jwt, JwtBuilder};
#[cfg(feature = "experimental-oidc-key-binding")]
pub use confirmation::JwkConfirmationClaim;
pub use jti::JtiUniquenessChecker;
#[cfg(feature = "experimental-oidc-key-binding")]
pub use parse::parse_compact_jws_with_confirmation;
pub use parse::{JwsParseError, ParsedJws, parse_compact_jws};
pub use structure::{ConfirmationClaim, JwtClaims, JwtHeader};
