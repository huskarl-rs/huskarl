//! `OAuth2` grant type implementations.
//!
//! Each grant type (e.g. authorization code, client credentials) is built on
//! top of the [`core`] module, which provides the shared exchange logic,
//! form serialization, and token response handling.

pub mod core;
