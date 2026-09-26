//! Anonymous trait imports that make the crate's method syntax work.
//!
//! This prelude imports traits anonymously (`as _`) to enable method calls
//! without introducing trait names. Imported traits can still make calls
//! ambiguous if their methods overlap. Import types and traits used in `impl`
//! blocks explicitly.
//!
//! What the prelude currently enables:
//!
//! - [`AccessTokenValidator`](crate::validator::AccessTokenValidator) —
//!   `.validate_request(…)` on boxed/generic validators. (The concrete
//!   validators also provide it inherently, so this matters when working
//!   through `Box<dyn AccessTokenValidator<…>>`.)
//! - [`ProvideValidatorMetadata`](crate::validator::metadata::ProvideValidatorMetadata)
//!   — `.validator_metadata(…)` in generic contexts.
//! - [`ToRfc6750Error`](crate::error::ToRfc6750Error) — `.challenge()` on
//!   validation errors when building responses by hand.
//! - The [`huskarl-core` prelude](crate::core::prelude) — `.get_secret_value()`
//!   on secrets, and `DPoP` proof methods.

pub use crate::{
    core::prelude::*,
    error::ToRfc6750Error as _,
    validator::{AccessTokenValidator as _, metadata::ProvideValidatorMetadata as _},
};
