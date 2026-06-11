use std::sync::Arc;

use bon::Builder;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use crate::{
    core::{
        EndpointUrl, Error,
        client_auth::ClientAuthentication,
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
        platform::{Duration, sleep},
    },
    grant::{
        core::{
            OAuth2ExchangeGrant, TokenResponse,
            form::{OAuth2FormRequest, with_dpop_nonce_retry},
        },
        refresh::RefreshGrant,
    },
};

/// An `OAuth2` device authorization grant.
///
/// This grant is used for devices that either lack a browser or have limited
/// input capabilities. The device displays a code and a URL to the user, who
/// then authorizes the device on a separate device with a browser. The client
/// polls the token endpoint until the user completes authorization or the code expires.
///
/// See the [module documentation][crate::grant::device_authorization] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Clone, Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct DeviceAuthorizationGrant {
    /// The client ID.
    client_id: String,

    /// The HTTP client used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// The client authentication method.
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Arc<dyn ClientAuthentication>,

    /// The `DPoP` signer. Defaults to [`NoDPoP`] (no token sender-constraining).
    #[builder(
        with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>,
        default = Arc::new(NoDPoP),
    )]
    dpop: Arc<dyn AuthorizationServerDPoP>,

    /// The issuer for tokens created by the authorization server.
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The URL of the token endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be converted via
    /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
    #[from_metadata(path = "token_endpoint")]
    #[builder(with = |url: impl crate::core::IntoEndpointUrl| -> Result<_, crate::core::Error> {
        crate::core::IntoEndpointUrl::into_endpoint_url(url)
    })]
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be converted via
    /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
    #[builder(with = |url: impl crate::core::IntoEndpointUrl| -> Result<_, crate::core::Error> {
        crate::core::IntoEndpointUrl::into_endpoint_url(url)
    })]
    mtls_token_endpoint: Option<EndpointUrl>,

    /// The endpoint used for token requests: the mTLS alias when the HTTP
    /// client uses mTLS, the primary token endpoint otherwise.
    #[builder(skip = crate::grant::core::resolve_mtls_alias(http_client.as_ref(), &token_endpoint, mtls_token_endpoint.as_ref()))]
    effective_token_endpoint: EndpointUrl,

    /// Supported endpoint auth methods; used to auto-select basic or
    /// form auth for client secrets.
    #[from_metadata(path = "token_endpoint_auth_methods_supported")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// The device authorization endpoint (RFC 8628 §3.1).
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be converted via
    /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
    #[from_metadata(path = "device_authorization_endpoint?")]
    #[builder(with = |url: impl crate::core::IntoEndpointUrl| -> Result<_, crate::core::Error> {
        crate::core::IntoEndpointUrl::into_endpoint_url(url)
    })]
    device_authorization_endpoint: EndpointUrl,

    /// The mTLS alias for the device authorization endpoint (RFC 8705 §5).
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be converted via
    /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
    #[from_metadata(path = "mtls_endpoint_aliases?.device_authorization_endpoint?")]
    #[builder(with = |url: impl crate::core::IntoEndpointUrl| -> Result<_, crate::core::Error> {
        crate::core::IntoEndpointUrl::into_endpoint_url(url)
    })]
    mtls_device_authorization_endpoint: Option<EndpointUrl>,

    /// The endpoint used for device authorization requests: the mTLS alias
    /// when the HTTP client uses mTLS, the primary endpoint otherwise.
    #[builder(skip = crate::grant::core::resolve_mtls_alias(http_client.as_ref(), &device_authorization_endpoint, mtls_device_authorization_endpoint.as_ref()))]
    effective_device_authorization_endpoint: EndpointUrl,
}

impl core::fmt::Debug for DeviceAuthorizationGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceAuthorizationGrant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("mtls_token_endpoint", &self.mtls_token_endpoint)
            .field(
                "device_authorization_endpoint",
                &self.device_authorization_endpoint,
            )
            .field(
                "mtls_device_authorization_endpoint",
                &self.mtls_device_authorization_endpoint,
            )
            .finish_non_exhaustive()
    }
}

impl DeviceAuthorizationGrant {
    /// Begin a device authorization request.
    ///
    /// This sends a request to the device authorization endpoint. The endpoint
    /// should return state which can be used to wait for the result, as well
    /// as information to the user on how to authorize the device.
    ///
    /// # Errors
    ///
    /// Returns an error if one is returned when attempting to make the device
    /// authorization request.
    pub async fn start(&self, start_input: StartInput) -> Result<StartOutput, Error> {
        let payload = DeviceAuthorizationRequest {
            scope: start_input.scopes.as_deref(),
            resource: start_input.resource.as_deref(),
        };

        let device_auth_endpoint = &self.effective_device_authorization_endpoint;

        let dpop_jkt = self.dpop().get_current_thumbprint();

        let response: DeviceAuthorizationResponse = with_dpop_nonce_retry!({
            let auth_params = self.authentication_params().await?;

            OAuth2FormRequest::builder()
                .form(&payload)
                .auth_params(auth_params)
                .uri(device_auth_endpoint.as_uri())
                .dpop(self.dpop())
                .maybe_dpop_jkt(dpop_jkt.as_deref())
                .build()
                .execute(self.http_client.as_ref())
                .await
        })?;

        Ok(StartOutput::builder()
            .expires_at(
                crate::core::platform::SystemTime::now()
                    .checked_add(Duration::from_secs(response.expires_in.into()))
                    .unwrap_or_else(crate::core::platform::SystemTime::now),
            )
            .verification_uri(response.verification_uri)
            .maybe_verification_uri_complete(response.verification_uri_complete)
            .user_code(response.user_code)
            .pending_state(PendingState {
                device_code: response.device_code,
                interval_secs: response.interval,
            })
            .build())
    }

    /// Poll pending state until there is a result or error, waiting an
    /// appropriate amount of time between requests.
    ///
    /// # Errors
    ///
    /// Returns an error if one is returned when attempting to poll. This
    /// can be an error like access denied, token expiry, or an error
    /// when making the token request.
    pub async fn poll_to_completion(
        &self,
        pending_state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<TokenResponse, PollError> {
        loop {
            sleep(Duration::from_secs(pending_state.interval_secs.into())).await;

            if let PollResult::Complete(token_response) =
                self.poll(pending_state, resource.clone()).await?
            {
                return Ok(*token_response);
            }
        }
    }

    /// Poll pending state once.
    ///
    /// # Errors
    ///
    /// Returns an error if one is returned when attempting to poll. This
    /// can be an error like access denied, token expiry, or an error
    /// when making the token request.
    pub async fn poll(
        &self,
        pending_state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<PollResult, PollError> {
        let token_or_err = self
            .exchange(super::grant::DeviceAuthorizationGrantParameters {
                device_code: pending_state.device_code.clone(),
                resource,
            })
            .await;

        match token_or_err {
            Ok(token) => Ok(PollResult::Complete(Box::new(token))),
            Err(err) => match err.oauth_error_code() {
                Some("slow_down") => {
                    pending_state.interval_secs = pending_state.interval_secs.saturating_add(5);
                    Ok(PollResult::Pending)
                }
                Some("authorization_pending") => Ok(PollResult::Pending),
                Some("access_denied") => AccessDeniedSnafu.fail(),
                Some("expired_token") => TokenExpiredSnafu.fail(),
                _ => Err(err).context(ExchangeSnafu),
            },
        }
    }
}

/// Parameters passed to each token request.
#[derive(Debug, Clone, Builder)]
pub struct DeviceAuthorizationGrantParameters {
    /// The device verification code, `device_code`, from the device authorization response.
    pub device_code: String,
    /// The target resource(s) for the access token.
    pub resource: Option<Vec<String>>,
}

/// Device authorization grant body.
#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationGrantForm {
    /// Must be set to `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628 §3.4).
    grant_type: &'static str,
    /// The device verification code, `device_code`, from the authorization response (RFC 8628 §3.4).
    device_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<Vec<String>>,
}

impl OAuth2ExchangeGrant for DeviceAuthorizationGrant {
    type Parameters = DeviceAuthorizationGrantParameters;
    type Form<'a> = DeviceAuthorizationGrantForm;

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> &dyn ClientAuthentication {
        self.client_auth.as_ref()
    }

    // Deliberately returns the build-time-resolved endpoint, not the raw
    // `token_endpoint` builder input.
    #[allow(clippy::misnamed_getters)]
    fn token_endpoint(&self) -> &EndpointUrl {
        &self.effective_token_endpoint
    }

    fn dpop(&self) -> &dyn AuthorizationServerDPoP {
        self.dpop.as_ref()
    }

    fn http_client(&self) -> &dyn HttpClient {
        self.http_client.as_ref()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn to_refresh_grant(&self) -> RefreshGrant {
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .http_client(self.http_client.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.effective_token_endpoint.clone())
            .expect("an EndpointUrl converts to itself infallibly")
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        DeviceAuthorizationGrantForm {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: params.device_code,
            resource: params.resource,
        }
    }
}

/// Response from the device authorization endpoint.
#[derive(Debug, Clone, Deserialize)]
struct DeviceAuthorizationResponse {
    /// The device verification code.
    device_code: String,

    /// The end-user verification code.
    user_code: String,

    /// The end-user verification URI on the authorization server.
    verification_uri: String,

    /// Optional: A verification URI that includes the user code.
    verification_uri_complete: Option<String>,

    /// The lifetime in seconds of the `device_code` and `user_code`.
    expires_in: u32,

    /// The minimum amount of time in seconds the client should wait between polling requests.
    /// Defaults to 5 seconds if not provided by the server.
    #[serde(default = "default_interval")]
    interval: u32,
}

/// Default polling interval in seconds.
#[inline]
const fn default_interval() -> u32 {
    5
}

#[derive(Debug, Serialize)]
struct DeviceAuthorizationRequest<'a> {
    scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<&'a [String]>,
}

/// The output information from starting the device authorization flow.
#[derive(Debug, Builder)]
#[builder(on(String, into))]
pub struct StartOutput {
    /// The end-user verification code.
    pub user_code: String,
    /// The end-user verification URI on the authorization server.
    pub verification_uri: String,
    /// A verification URI that includes the user code.
    pub verification_uri_complete: Option<String>,
    /// The time at which the user code expires.
    pub expires_at: crate::core::platform::SystemTime,
    /// The pending state information (to be passed to the `poll` function).
    pub pending_state: PendingState,
}

/// The pending state information (to be passed to the `poll` function).
#[derive(Debug, Builder, Serialize, Deserialize)]
#[builder(on(String, into))]
pub struct PendingState {
    /// The device verification code.
    pub device_code: String,
    /// The minimum amount of time in seconds the client should wait between polling requests.
    pub interval_secs: u32,
}

/// Errors that may occur during polling for a token.
///
/// The `AccessDenied` and `TokenExpired` variants are control flow for
/// device-flow UIs; everything else carries the underlying [`Error`].
#[derive(Debug, Snafu)]
pub enum PollError {
    /// Access was denied.
    AccessDenied,
    /// The token expired.
    TokenExpired,
    /// There was an error while attempting to exchange the code for a token.
    Exchange {
        /// The underlying error.
        source: Error,
    },
}

/// The result of polling.
pub enum PollResult {
    /// The token is still pending.
    Pending,
    /// Polling completed with a token response.
    Complete(Box<TokenResponse>),
}

/// The input to start the device authorization flow.
#[derive(Debug, Clone, Builder)]
pub struct StartInput {
    #[builder(required, with = |scopes: impl IntoIterator<Item = impl Into<String>>| crate::grant::core::mk_scopes(scopes))]
    scopes: Option<String>,
    resource: Option<Vec<String>>,
}

impl StartInput {
    /// Implements a simple complete input to the flow including just scopes.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    #[must_use]
    pub fn scopes(scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::builder().scopes(scopes).build()
    }
}
