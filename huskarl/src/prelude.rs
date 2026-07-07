//! Anonymous trait imports that make the crate's method syntax work.
//!
//! `use huskarl::prelude::*` brings the crate's extension traits into scope so
//! method calls like `grant.exchange(…)` resolve. Everything is imported
//! anonymously (`as _`), so it adds **zero names** to your namespace and never
//! collides. It is trait-only *by design* — types are named and imported
//! explicitly at their use site; see [why the prelude is
//! trait-only](crate::_docs::explanation::prelude) for the reasoning.
//!
//! The typical import block for an application looks like:
//!
//! ```rust
//! use huskarl::{
//!     authorizer::HttpAuthorizer,
//!     cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
//!     core::{
//!         client_auth::ClientSecret, secrets::EnvVarSecret,
//!         server_metadata::AuthorizationServerMetadata,
//!     },
//!     grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
//!     prelude::*,
//! };
//! ```
//!
//! What the prelude currently enables:
//!
//! - [`OAuth2ExchangeGrant`](crate::grant::core::OAuth2ExchangeGrant) —
//!   `.exchange(…)`, `.to_refresh_grant()`, `.dpop()` on any grant.
//! - [`TokenSource`](crate::cache::TokenSource) — `.token()`,
//!   `.invalidate()`, `.clear()` on caches and sources.
//! - The [`huskarl-core` prelude](crate::core::prelude) — `.get_secret_value()`
//!   on secrets, and `DPoP` proof methods.

pub use crate::{cache::TokenSource as _, core::prelude::*, grant::core::OAuth2ExchangeGrant as _};
