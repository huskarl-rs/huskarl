//! Authorization code grant (RFC 6749 §4.1).
//!
//! Used when a user needs to authorize the application. The user is redirected to the
//! authorization server to authenticate and grant consent, then redirected back with
//! a short-lived code that is exchanged for tokens. PKCE (RFC 7636) is applied
//! automatically.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! The examples below use the `huskarl_reqwest` crate; see [Setting up an HTTP
//! client](crate::grant#setting-up-an-http-client) for the shared setup the rest
//! of this page assumes.
//!
//! ## 2. Set up client authentication (if necessary)
//!
//! Public clients (single-page apps, CLI tools) typically use `NoAuth`;
//! confidential clients pass their credentials instead. See [Setting up client
//! authentication](crate::grant#setting-up-client-authentication).
//!
//! ## 3a. Set up the grant with authorization server metadata
//!
//! Note: `builder_from_metadata` returns `None` if the server does not advertise
//! an authorization endpoint.
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::NoAuth, server_metadata::AuthorizationServerMetadata},
//!     grant::authorization_code::AuthorizationCodeGrant,
//! };
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//!
//! let metadata = AuthorizationServerMetadata::fetch()
//!     .http_client(&client)
//!     .issuer("https://my-issuer")
//!     .call()
//!     .await?;
//!
//! let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
//!     .expect("server does not support authorization code grant")
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(NoAuth)
//!     .redirect_uri("https://my-app/callback")
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 3b. Alternative: Set up the grant without metadata
//!
//! ```rust
//! use huskarl::{core::client_auth::NoAuth, grant::authorization_code::AuthorizationCodeGrant};
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//!
//! let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder()
//!     .authorization_endpoint("https://my-server/authorize".parse()?)
//!     .token_endpoint("https://my-server/token".parse()?)
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(NoAuth)
//!     .redirect_uri("https://my-app/callback")
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Start the authorization flow
//!
//! Call `start()` to get the URL to redirect the user to and the pending state
//! that must be persisted until the callback arrives. `PendingState` implements
//! `Serialize`/`Deserialize` and can be stored in a session or database.
//!
//! ```rust
//! use huskarl::grant::authorization_code::{AuthorizationCodeGrant, StartInput};
//! # async fn start_flow(
//! #     grant: &AuthorizationCodeGrant,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//!
//! let start_output = grant.start(StartInput::scopes(["read", "write"])).await?;
//!
//! // Redirect the user to this URL to authorize.
//! let authorization_url = start_output.authorization_url;
//!
//! // Persist this — it is needed to complete the flow when the callback arrives.
//! let pending_state = start_output.pending_state;
//! # Ok(())
//! # }
//! ```
//!
//! ## 5a. Complete the authorization flow
//!
//! When the authorization server redirects back to your application, extract the
//! `code` and `state` query parameters and pass them to `complete()`.
//!
//! ```rust
//! use huskarl::{
//!     grant::authorization_code::{AuthorizationCodeGrant, CompleteInput, PendingState},
//!     token::AccessToken,
//! };
//! # async fn complete_flow(
//! #     grant: &AuthorizationCodeGrant,
//! #     pending_state: &PendingState,
//! #     code_from_callback: String,
//! #     state_from_callback: String,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//!
//! // Build from the query parameters in the redirect callback.
//! let complete_input = CompleteInput::builder()
//!     .code(code_from_callback)
//!     .state(state_from_callback)
//!     .build();
//!
//! let response = grant.complete(pending_state, complete_input).await?;
//! let token: &AccessToken = response.access_token();
//! # Ok(())
//! # }
//! ```
//!
//! ## 5b. Alternative for CLI tools: complete using the loopback server
//!
//! For command-line tools, `complete_on_loopback` handles the callback automatically
//! by binding a local HTTP server to receive it — no need to extract parameters manually.
//! Use `bind_loopback` to create the listener, include its port in the `redirect_uri`,
//! and pass it to `complete_on_loopback` after calling `start`.
//!
//! Requires the `authorization-flow-loopback` feature.

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

pub use error::{BuildError, CompleteError};
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
