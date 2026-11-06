//! Task-oriented and conceptual documentation for resource servers.
//!
//! Choose a section by what you need:
//!
//! - **[How-to guides](guide)** — task-oriented recipes for wiring a validator
//!   into a resource server.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//! - **Reference** — the crate's API modules describe its types, methods,
//!   parameters, and return values.
//!
//! This module is documentation only; it contains no runnable API. It is gated
//! on `cfg(doc)`, which rustdoc sets for both rendering and doctest collection.
//! Its code blocks are tested by `cargo test --doc` on stable Rust.

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/error_handling.md")]
    pub mod error_handling {}

    #[doc = include_str!("../docs/explanation/choosing_a_validator.md")]
    pub mod choosing_a_validator {}

    #[doc = include_str!("../docs/explanation/multi_issuer_routing.md")]
    pub mod multi_issuer_routing {}
}

/// Task-oriented recipes for wiring a validator into a resource server.
pub mod guide {
    #[doc = include_str!("../docs/guide/cors.md")]
    pub mod cors {}

    #[doc = include_str!("../docs/guide/resource_metadata.md")]
    pub mod resource_metadata {}

    #[doc = include_str!("../docs/guide/rfc9068.md")]
    pub mod rfc9068 {}

    #[doc = include_str!("../docs/guide/custom.md")]
    pub mod custom {}

    #[doc = include_str!("../docs/guide/introspection.md")]
    pub mod introspection {}

    #[doc = include_str!("../docs/guide/multi_issuer.md")]
    pub mod multi_issuer {}

    #[doc = include_str!("../docs/guide/prefix_routing.md")]
    pub mod prefix_routing {}

    #[doc = include_str!("../docs/guide/dpop.md")]
    pub mod dpop {}
}
