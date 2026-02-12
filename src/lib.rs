#![forbid(unsafe_code)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]

pub mod client_auth;
pub mod dpop;
mod error;
pub mod grant;
pub mod http;
pub mod platform;
pub mod token;

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
