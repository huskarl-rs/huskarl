//! OAuth 2.0 Dynamic Client Registration (RFC 7591).
//!
//! A client registers itself with an authorization server by sending an HTTP
//! `POST` of the desired [`ClientMetadata`] to the registration endpoint via
//! [`ClientRegistration`]. On success the server returns a
//! [`ClientInformationResponse`] carrying the issued `client_id` and, for
//! confidential clients, a `client_secret` — the credentials the OAuth grants in
//! [`crate::grant`] then use to obtain tokens.
//!
//! Registration-management (RFC 7592 read/update/delete) is not yet implemented,
//! but the management fields the server issues
//! ([`registration_access_token`](ClientInformationResponse::registration_access_token)
//! and [`registration_client_uri`](ClientInformationResponse::registration_client_uri))
//! are captured on the response.
//!
//! See the [dynamic client registration how-to
//! guide](crate::_docs::guide::registration) for an example and for how to handle
//! the issued client secret.

mod client;
mod error;
mod metadata;
mod response;

pub use client::*;
pub use metadata::ClientMetadata;
pub use response::{ClientInformationResponse, ClientSecretExpiry};
