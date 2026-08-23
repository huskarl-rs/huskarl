//! Task-oriented and conceptual documentation for the shared foundation.
//!
//! Choose a section by what you need:
//!
//! - **[How-to guides](guide)** — task-oriented recipes for the things people
//!   reach for this crate to do: building and validating JWTs, providing
//!   secrets, plugging in a transport or crypto backend, and returning errors
//!   from an extension.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//! - **Reference** — the crate's API modules describe its types, traits,
//!   parameters, and return values.
//!
//! This module is documentation only; it contains no runnable API. It is gated
//! on `cfg(docsrs)`, so its code blocks are real doctests that run only under
//! `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly test --doc` (mirroring the
//! docs.rs build environment); a plain `cargo test --doc` skips them.

/// Task-oriented recipes for building JWTs, handling secrets, plugging in
/// backends, and returning errors from extensions.
pub mod guide {
    #[doc = include_str!("../docs/guide/signing_a_jwt.md")]
    pub mod signing_a_jwt {}

    #[doc = include_str!("../docs/guide/validating_a_jwt.md")]
    pub mod validating_a_jwt {}

    #[doc = include_str!("../docs/guide/configuring_jwt_verification.md")]
    pub mod configuring_jwt_verification {}

    #[doc = include_str!("../docs/guide/providing_secrets.md")]
    pub mod providing_secrets {}

    #[doc = include_str!("../docs/guide/implementing_a_backend.md")]
    pub mod implementing_a_backend {}

    #[doc = include_str!("../docs/guide/returning_errors.md")]
    pub mod returning_errors {}
}

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/error_handling.md")]
    pub mod error_handling {}

    #[doc = include_str!("../docs/explanation/untrusted_keys.md")]
    pub mod untrusted_keys {}

    #[doc = include_str!("../docs/explanation/crypto_strategies.md")]
    // The metrics wrappers only exist behind the `metrics` feature, so their
    // intra-doc links would break a no-feature `cargo doc` (the crate denies
    // broken links). Append that section only when the feature is on; docs.rs
    // builds `all-features`, so the published docs still carry it.
    #[cfg_attr(
        feature = "metrics",
        doc = include_str!("../docs/explanation/crypto_strategies_metrics.md")
    )]
    pub mod crypto_strategies {}
}
