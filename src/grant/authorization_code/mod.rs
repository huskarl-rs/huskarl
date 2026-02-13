//! Implements the OAuth 2.0 Authorization Code Grant (RFC 6749 §4.1).

mod error;
mod exchange;
mod flow;
mod grant;
mod jar;
#[cfg(feature = "authorization-flow-loopback")]
mod loopback;
mod par;
pub mod pkce;
mod types;

pub use error::{CompleteError, StartError};
pub use exchange::AuthorizationCodeGrantParameters;
pub use grant::AuthorizationCodeGrant;
#[cfg(feature = "authorization-flow-loopback")]
pub use loopback::{LoopbackError, bind_loopback};
pub use types::{CompleteInput, PendingState, StartInput, StartOutput};
