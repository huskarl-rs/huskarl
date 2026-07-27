//! Extended documentation: a tutorial, how-to guides, and explanation.
//!
//! The API items in this crate are the **reference** documentation — they say
//! what each type and method is. These pages cover the other
//! [Diátaxis](https://diataxis.fr) quadrants:
//!
//! - **[Tutorial](tutorial)** — a start-to-finish lesson: run a local server
//!   and obtain your first access token.
//! - **[How-to guides](guide)** — task-oriented recipes for setting up each
//!   grant, caching tokens, making authenticated requests, and implementing
//!   token infrastructure.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//!
//! This module is documentation only; it contains no runnable API. It is gated
//! on `cfg(docsrs)`, so its code blocks are real doctests that run only under
//! `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly test --doc` (mirroring the
//! docs.rs build environment); a plain `cargo test --doc` skips them.

/// A start-to-finish lesson: obtain your first access token against a local
/// authorization server.
pub mod tutorial {
    #[doc = include_str!("../docs/tutorial/first_token.md")]
    pub mod first_token {}
}

/// Task-oriented recipes for setting up grants, making authenticated requests,
/// and implementing token infrastructure.
pub mod guide {
    #[doc = include_str!("../docs/guide/setup.md")]
    pub mod setup {}

    #[doc = include_str!("../docs/guide/client_authentication.md")]
    pub mod client_authentication {}

    #[doc = include_str!("../docs/guide/authorization_code.md")]
    pub mod authorization_code {}

    #[doc = include_str!("../docs/guide/device_authorization.md")]
    pub mod device_authorization {}

    #[doc = include_str!("../docs/guide/client_credentials.md")]
    pub mod client_credentials {}

    #[doc = include_str!("../docs/guide/refresh.md")]
    pub mod refresh {}

    #[doc = include_str!("../docs/guide/token_exchange.md")]
    pub mod token_exchange {}

    #[doc = include_str!("../docs/guide/jwt_bearer.md")]
    pub mod jwt_bearer {}

    #[doc = include_str!("../docs/guide/registration.md")]
    pub mod registration {}

    #[doc = include_str!("../docs/guide/caching.md")]
    pub mod caching {}

    #[doc = include_str!("../docs/guide/handling_errors.md")]
    pub mod handling_errors {}

    #[doc = include_str!("../docs/guide/implementing_token_infrastructure.md")]
    pub mod implementing_token_infrastructure {}

    #[doc = include_str!("../docs/guide/authorizer.md")]
    pub mod authorizer {}

    #[doc = include_str!("../docs/guide/dpop.md")]
    pub mod dpop {}
}

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/error_handling.md")]
    pub mod error_handling {}

    #[doc = include_str!("../docs/explanation/sharing_a_token_store.md")]
    pub mod sharing_a_token_store {}

    #[doc = include_str!("../docs/explanation/token_source_resolution.md")]
    pub mod token_source_resolution {}

    #[doc = include_str!("../docs/explanation/refresh_timing.md")]
    pub mod refresh_timing {}

    #[doc = include_str!("../docs/explanation/prelude.md")]
    pub mod prelude {}
}
