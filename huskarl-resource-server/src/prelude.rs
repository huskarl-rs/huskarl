//! Anonymous trait imports that make the crate's method syntax work.
//!
//! This prelude is **trait-only, by design**: it holds exactly the traits
//! whose methods users call on values they already hold, imported anonymously
//! (`as _`) so a glob import adds **zero names** to your namespace — it can
//! never collide with your code, and it is always safe to grow. Types are
//! named at their use sites, so they are imported explicitly instead; traits
//! you *implement* (rather than call) are excluded too.
//!
//! What the prelude currently enables:
//!
//! - [`AccessTokenValidator`](crate::validator::AccessTokenValidator) —
//!   `.validate_request(…)` on boxed/generic validators. (The concrete
//!   validators also provide it inherently, so this matters when working
//!   through `Box<dyn AccessTokenValidator<…>>`.)
//! - [`ProvideValidatorMetadata`](crate::validator::metadata::ProvideValidatorMetadata)
//!   — `.validator_metadata(…)` in generic contexts.
//! - [`ToRfc6750Error`](crate::error::ToRfc6750Error) — `.token_error()`,
//!   `.error_description()` on validation errors when building responses by
//!   hand.
//! - The [`huskarl-core` prelude](crate::core::prelude) — `.get_secret_value()`
//!   on secrets, and `DPoP` proof methods.

pub use crate::{
    core::prelude::*,
    error::ToRfc6750Error as _,
    validator::{AccessTokenValidator as _, metadata::ProvideValidatorMetadata as _},
};
