//! Device authorization grant (RFC 8628).
//!
//! Used for devices with limited input capabilities, such as smart TVs or CLI
//! tools. The device displays a short code and URL for the user to visit on a
//! separate device, then polls the token endpoint until authorization completes
//! or the code expires.
//!
//! See the [device authorization how-to
//! guide](crate::_docs::guide::device_authorization) for step-by-step setup.

mod grant;

pub use grant::{
    DeviceAuthorizationGrant, DeviceAuthorizationGrantBuilder, DeviceAuthorizationGrantParameters,
    PendingState, PollError, PollResult, StartInput, StartOutput,
};
