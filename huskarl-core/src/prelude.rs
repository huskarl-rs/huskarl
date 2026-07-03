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
//! - [`Secret`](crate::secrets::Secret) — `.get_secret_value()`, `.map(…)` on
//!   secret sources.
//! - [`AuthorizationServerDPoP`](crate::dpop::AuthorizationServerDPoP) /
//!   [`ResourceServerDPoP`](crate::dpop::ResourceServerDPoP) —
//!   `.to_resource_server_dpop()` and `.proof(…)` on `DPoP` values.
//!
//! Downstream crates re-export this from their own preludes (e.g.
//! `huskarl::prelude`), so importing the outermost prelude is enough.

pub use crate::{
    dpop::{AuthorizationServerDPoP as _, ResourceServerDPoP as _},
    secrets::Secret as _,
};
