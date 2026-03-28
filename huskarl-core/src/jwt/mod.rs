//! JWT support
//!
//! Supports the following operations:
//!  - Typesafe JWT builder
//!  - Creation of a JWT using JWS compact seralization

mod builder;
mod parse;
mod structure;
pub mod validator;

pub use builder::{JwsSerializationError, Jwt, JwtBuilder};
pub use parse::{JwsParseError, ParsedJws, parse_compact_jws};
pub use structure::ConfirmationClaim;
