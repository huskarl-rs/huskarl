//! `OAuth2` grant type implementations.
//!
//! Each grant type (e.g. authorization code, client credentials) is built on
//! top of the [`core`] module, which provides the shared exchange logic,
//! form serialization, and token response handling.

pub mod authorization_code;
pub mod client_credentials;
pub mod core;
pub mod refresh;
