//! Implements the OAuth 2.0 Authorization Code Grant (RFC 6749 §4.1).

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

pub use error::{CompleteError, StartError};
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
pub use types::{CompleteInput, PendingState, StartInput, StartOutput};
