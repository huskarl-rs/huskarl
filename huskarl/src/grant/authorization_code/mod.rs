//! Authorization code grant (RFC 6749 §4.1).
//!
//! Used when a user needs to authorize the application: the user is redirected to
//! the authorization server to authenticate and grant consent, then redirected
//! back with a short-lived code that is exchanged for tokens. PKCE (RFC 7636) is
//! applied automatically.
//!
//! See the [authorization code how-to guide](crate::_docs::guide::authorization_code)
//! for step-by-step setup, including completing the flow on a loopback server for
//! CLI tools.

mod error;
mod flow;
mod grant;
mod jar;
#[cfg(all(
    feature = "authorization-flow-loopback",
    any(
        not(target_family = "wasm"),
        all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
    )
))]
mod loopback;
mod par;
mod types;

pub mod pkce;

pub use error::{BuildError, CompleteError, ParseCallbackError, StartError};
pub use grant::{
    AuthorizationCodeGrant, AuthorizationCodeGrantBuilder, AuthorizationCodeGrantParameters,
};
pub use jar::{Jar, NoJar};
#[cfg(all(
    feature = "authorization-flow-loopback",
    any(
        not(target_family = "wasm"),
        all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
    )
))]
pub use loopback::{
    CallbackRenderer, CallbackResponse, ErrorContext, LoopbackError, SuccessContext, bind_loopback,
};
pub use types::{
    CompleteInput, CompleteInputBuilder, CompleteInputCallbackBuilder, CompleteOutput,
    PendingState, ResponseMode, StartInput, StartOutput,
};
