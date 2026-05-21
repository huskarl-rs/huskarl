//! Device authorization grant (RFC 8628).
//!
//! Used for devices with limited input capabilities, such as smart TVs or CLI tools.
//! The device displays a short code and URL for the user to visit on a separate device,
//! then polls the token endpoint until authorization completes or the code expires.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! A HTTP client needs to be configured. Using the `huskarl_reqwest` crate:
//!
//! ```rust
//! use huskarl_reqwest::{ReqwestClient, mtls::NoMtls};
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().mtls(NoMtls).build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 2. Set up client authentication (if necessary).
//!
//! Device authorization is commonly used by public clients (CLI tools, smart TVs)
//! which do not need to authenticate. Use `NoAuth` in that case:
//!
//! ```rust
//! use huskarl::core::client_auth::NoAuth;
//!
//! let client_auth = NoAuth;
//! ```
//!
//! For confidential clients, any `ClientAuthentication` implementation can be used.
//! See the client credentials grant for an example using `ClientSecret`.
//!
//! ## 3a. Set up the grant with authorization server metadata
//!
//! Note: `builder_from_metadata` returns `None` if the server does not advertise
//! a device authorization endpoint.
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::NoAuth, dpop::NoDPoP, server_metadata::AuthorizationServerMetadata},
//!     grant::device_authorization::DeviceAuthorizationGrant,
//! };
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .mtls(NoMtls)
//! #     .build()
//! #     .await?;
//!
//! let metadata = AuthorizationServerMetadata::builder()
//!     .issuer("https://my-issuer")
//!     .http_client(&client)
//!     .build()
//!     .await?;
//!
//! let grant: DeviceAuthorizationGrant<NoAuth, NoDPoP> =
//!     DeviceAuthorizationGrant::builder_from_metadata(&metadata)
//!         .expect("server does not support device authorization")
//!         .client_id("client_id")
//!         .client_auth(NoAuth)
//!         .dpop(NoDPoP)
//!         .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 3b. Alternative: Set up the grant without metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::NoAuth, dpop::NoDPoP},
//!     grant::device_authorization::DeviceAuthorizationGrant,
//! };
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let grant: DeviceAuthorizationGrant<NoAuth, NoDPoP> = DeviceAuthorizationGrant::builder()
//!     .device_authorization_endpoint("https://my-server/device_authorization")?
//!     .token_endpoint("https://my-server/token")?
//!     .client_id("client_id")
//!     .client_auth(NoAuth)
//!     .dpop(NoDPoP)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Start the device authorization flow
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::NoAuth, dpop::NoDPoP},
//!     grant::device_authorization::{DeviceAuthorizationGrant, StartInput},
//! };
//! # async fn start_flow(
//! #     client: &huskarl_reqwest::ReqwestClient,
//! #     grant: &DeviceAuthorizationGrant<NoAuth, NoDPoP>,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//!
//! let start_output = grant
//!     .start(client, StartInput::scopes(["read", "write"]))
//!     .await?;
//!
//! // Display to the user — they visit the URL and enter the code on another device.
//! println!("Visit: {}", start_output.verification_uri);
//! println!("Code: {}", start_output.user_code);
//! # Ok(())
//! # }
//! ```
//!
//! ## 5. Poll for completion
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::NoAuth, dpop::NoDPoP},
//!     grant::device_authorization::{DeviceAuthorizationGrant, StartOutput},
//!     token::AccessToken,
//! };
//! # async fn poll_flow(
//! #     client: &huskarl_reqwest::ReqwestClient,
//! #     grant: &DeviceAuthorizationGrant<NoAuth, NoDPoP>,
//! #     start_output: StartOutput,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//!
//! let mut pending_state = start_output.pending_state;
//! let response = grant
//!     .poll_to_completion(client, &mut pending_state, None)
//!     .await?;
//! let token: &AccessToken = response.access_token();
//! # Ok(())
//! # }
//! ```

mod grant;

pub use grant::{
    DeviceAuthorizationGrant, DeviceAuthorizationGrantBuilder, DeviceAuthorizationGrantParameters,
    PendingState, PollError, PollResult, StartInput, StartOutput,
};
