//! Implements an `OAuth2` client library.

#![forbid(unsafe_code)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod client_auth;
pub mod crypto;
pub mod dpop;
mod endpoint_url;
mod error;
pub mod grant;
pub mod http;
pub mod jwk;
pub mod jwt;
pub mod platform;
pub mod prelude;
pub mod revocation;
pub mod secrets;
pub mod server_metadata;
pub mod token;
mod uuid;

pub use endpoint_url::{EndpointUrl, IntoEndpointUrl};
pub use error::{BoxedError, Error};

/// Documentation
pub mod _documentation {
    #[doc = include_str!("../README.md")]
    mod readme {}
    #[doc = include_str!("../CHANGELOG.md")]
    pub mod changelog {}
}

/// Re-export of parts of the `secrecy` crate.
pub mod secrecy {
    pub use ::secrecy::{ExposeSecret, SecretBox, SecretString};
}

pub use bytes::Bytes;
