/*!
Huskarl provides tools for implementing secure `OAuth2` in rust.

huskarl-core provides the base traits and implementations for the huskarl ecosystem.
*/

#![forbid(unsafe_code)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// The dyn-capable strategy traits are shared between native and wasm32 behind
// `Arc<dyn Trait>`. On wasm32 (single-threaded) the implementations are
// intentionally not `Send`/`Sync` (see `platform::MaybeSend`), which trips this
// lint even though the `Arc` never crosses a thread boundary there.
#![cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]

mod endpoint_url;
mod uuid;

pub mod client_auth;
pub mod crypto;
pub mod dpop;
pub mod error;
pub mod http;
pub mod jwk;
pub mod jwt;
pub mod platform;
pub mod prelude;
pub mod secrets;
pub mod serde_utils;
pub mod server_metadata;

pub use endpoint_url::EndpointUrl;
pub use error::{Error, ErrorKind};
