/*!
The foundational traits and types for the huskarl `OAuth2` ecosystem.

Most applications depend on the higher-level `huskarl` crate (grants, token
cache, authorizer) rather than this crate directly. `huskarl-core` is the shared
base they build on: the one concrete [`Error`]/[`ErrorKind`], the
[`HttpClient`](http::HttpClient) abstraction, client authentication
([`client_auth`]), `DPoP` ([`dpop`]), the JOSE primitives ([`jwt`], [`jwk`],
[`crypto`]), secret handling ([`secrets`]), and authorization-server metadata
([`server_metadata`]). Implement its traits to plug in a transport, crypto
backend, or secret source.
*/

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
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
