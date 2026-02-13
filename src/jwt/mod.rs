//! JWT support
//!
//! Supports the following operations:
//!  - Typesafe JWT builder
//!  - Creation of a JWT using JWS compact seralization

mod builder;
mod structure;

pub use builder::{JwsSerializationError, Jwt, JwtBuilder, SimpleJwt};
