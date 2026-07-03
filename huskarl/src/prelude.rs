//! Anonymous trait imports that make the crate's method syntax work.
//!
//! This prelude is **trait-only, by design**. A trait earns a place here iff
//! users call its methods on values they already hold — because a method call
//! like `grant.exchange(…)` gives no hint which trait must be in scope, that
//! is the one discovery problem only a prelude can solve. Everything is
//! imported anonymously (`as _`), so `use huskarl::prelude::*` adds **zero
//! names** to your namespace: it can never collide with your code or another
//! crate, and it is always safe to grow.
//!
//! Types are deliberately *not* re-exported here: a type is named at its use
//! site, so an explicit import documents where it came from (and your IDE
//! adds it for you). The rule of thumb: **if you'd write its name in your
//! code, import it yourself; if you'd only call its methods, the prelude does
//! it for you.** Traits you *implement* (rather than call) are also excluded —
//! an `impl` block names its trait explicitly anyway.
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
