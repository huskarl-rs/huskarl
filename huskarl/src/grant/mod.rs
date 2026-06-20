//! `OAuth2` grant type implementations.
//!
//! Choose the grant type that fits your use case:
//!
//! | Grant | Use case |
//! |-------|----------|
//! | [`authorization_code`] | User-facing apps — the user logs in via a browser |
//! | [`client_credentials`] | Machine-to-machine — the client acts on its own behalf |
//! | [`device_authorization`] | Devices with limited input (TVs, CLIs) |
//! | [`jwt_bearer`] | Present a signed JWT assertion vouching for a principal |
//! | [`token_exchange`] | Exchange an existing token for a new one (impersonation, delegation) |
//! | [`refresh`] | Renew an access token using a refresh token |
//!
//! ## Setting up an HTTP client
//!
//! Every grant drives its token requests through an
//! [`HttpClient`](crate::core::http::HttpClient). The examples in these modules
//! use the `huskarl_reqwest` crate:
//!
//! ```rust
//! use huskarl_reqwest::ReqwestClient;
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Setting up client authentication
//!
//! Grants take a [`ClientAuthentication`](crate::core::client_auth) implementation.
//! A confidential client authenticates with its credentials — for example a
//! client secret (any `ClientAuthentication` implementation works):
//!
//! ```rust
//! use huskarl::core::{
//!     client_auth::ClientSecret,
//!     secrets::{EnvVarSecret, encodings::StringEncoding},
//! };
//!
//! # async fn setup_client_auth() -> Result<(), Box<dyn std::error::Error>> {
//! let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! let client_auth: ClientSecret = ClientSecret::new(env_secret);
//! # Ok(())
//! # }
//! ```
//!
//! A public client — one that holds no credentials, such as a single-page app,
//! CLI, or device — uses [`NoAuth`](crate::core::client_auth::NoAuth):
//!
//! ```rust
//! use huskarl::core::client_auth::NoAuth;
//!
//! let client_auth = NoAuth;
//! ```
//!
//! The [`jwt_bearer`], [`token_exchange`], and [`refresh`] grants carry their own
//! authorization (an assertion or an existing token), so client authentication is
//! optional and *independent* of the grant: such a grant may authenticate the
//! client separately, or present no client identity at all (RFC 7523 §3.1,
//! RFC 8693 §2).

pub mod authorization_code;
pub mod client_credentials;
pub mod core;
pub mod device_authorization;
pub mod jwt_bearer;
pub mod refresh;
pub mod token_exchange;
