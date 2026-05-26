/*!
Huskarl provides tools for implementing secure `OAuth2` in rust.

huskarl-core provides the base traits and implementations for the huskarl ecosystem.
*/

#![forbid(unsafe_code)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod endpoint_url;
mod error;
mod uuid;

pub mod client_auth;
pub mod crypto;
pub mod dpop;
pub mod http;
pub mod jwk;
pub mod jwt;
pub mod platform;
pub mod prelude;
pub mod secrets;
pub mod serde_utils;
pub mod server_metadata;

pub use endpoint_url::{EndpointUrl, IntoEndpointUrl};
pub use error::{BoxedError, Error};
