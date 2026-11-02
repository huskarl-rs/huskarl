//! OpenID Connect Client-Initiated Backchannel Authentication (CIBA).
//!
//! [`CibaPollGrant`] starts authentication for a known user on a separate
//! device and polls for the result. It needs no client notification endpoint.
//! Register the client for `poll` delivery before using this grant.
//!
//! See the [CIBA how-to guide](crate::_docs::guide::ciba) for setup and
//! [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
//! for the protocol. Ping and push modes are not implemented.
//!
//! The `experimental-oidc-key-binding` feature does not support CIBA. With that feature enabled,
//! `start` rejects `bound_key` before contacting the provider.

mod error;
mod poll;
mod types;

pub use error::PollError;
pub use poll::{
    CibaPollGrant, CibaPollGrantBuilder, DEFAULT_MAX_TRANSIENT_POLL_FAILURES,
    DEFAULT_MIN_POLL_INTERVAL_SECS,
};
pub use types::{
    CibaHint, CibaPollGrantForm, CibaPollGrantParameters, CompleteOutput, PendingState, PollResult,
    StartInput, StartInputBuilder, StartOutput,
};

#[cfg(test)]
mod tests;
