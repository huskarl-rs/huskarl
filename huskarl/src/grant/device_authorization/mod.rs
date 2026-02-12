//! Implements the OAuth 2.0 Device Authorization Grant (RFC 8628 §4.1).

mod grant;

pub use grant::{
    DeviceAuthorizationGrant, DeviceAuthorizationGrantBuilder, DeviceAuthorizationGrantParameters,
    PendingState, PollError, PollResult, StartInput, StartOutput,
};
