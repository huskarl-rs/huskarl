//! JWT support
//!
//! Supports the following operations:
//!  - Typesafe JWT builder
//!  - Creation of a JWT using JWS compact seralization
//!  - Checking if the supplied JTI was previous seen

mod builder;
mod jti;
mod parse;
mod structure;
pub mod validator;

pub use builder::{JwsSerializationError, Jwt, JwtBuilder};
pub use jti::{BoxedJtiUniquenessChecker, JtiUniquenessChecker};
pub use parse::{JwsParseError, ParsedJws, parse_compact_jws};
pub use structure::ConfirmationClaim;
