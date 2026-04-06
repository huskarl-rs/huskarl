use bon::Builder;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use crate::{
    core::{
        EndpointUrl,
        client_auth::ClientAuthentication,
        dpop::AuthorizationServerDPoP,
        http::HttpClient,
        platform::{Duration, sleep},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{
        core::{
            ExchangeError, OAuth2ExchangeGrant, OAuth2ExchangeGrantError, TokenResponse,
            form::{HandleResponseError, OAuth2ErrorBody, OAuth2FormError, OAuth2FormRequest},
        },
        device_authorization::grant::builder::{
            SetDeviceAuthorizationEndpoint, SetMtlsDeviceAuthorizationEndpoint,
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
#[huskarl_macros::grant]
#[derive(Debug, Clone, Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct DeviceAuthorizationGrant {
    /// The device authorization endpoint (RFC 8628 §3.1).
    #[endpoint_url]
    device_authorization_endpoint: EndpointUrl,

    /// The mTLS alias for the device authorization endpoint (RFC 8705 §5).
    #[endpoint_url]
    mtls_device_authorization_endpoint: Option<EndpointUrl>,
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static>
    DeviceAuthorizationGrant<Auth, D>
{
    /// Configure the grant from authorization server metadata.
    #[allow(clippy::type_complexity)]
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        DeviceAuthorizationGrantBuilder<
            Auth,
            D,
            SetMtlsDeviceAuthorizationEndpoint<SetDeviceAuthorizationEndpoint<SetCommonMetadata>>,
        >,
    > {
        metadata
            .device_authorization_endpoint
            .as_ref()
            .map(|device_authorization_endpoint| {
                DeviceAuthorizationGrant::builder()
                    .with_common_metadata(metadata)
                    .device_authorization_endpoint_internal(device_authorization_endpoint.clone())
                    .maybe_mtls_device_authorization_endpoint_internal(
                        metadata
                            .mtls_endpoint_aliases
                            .as_ref()
                            .and_then(|a| a.device_authorization_endpoint.clone()),
                    )
            })
    }

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
    pub async fn start<C: HttpClient>(
        &self,
        http_client: &C,
        start_input: StartInput,
    ) -> Result<StartOutput, StartError<Auth::Error, C::Error, C::ResponseError, D::Error>> {
        let payload = DeviceAuthorizationRequest {
            scope: start_input.scopes.as_deref(),
            resource: start_input.resource.as_deref(),
        };

        let effective_device_auth_endpoint = if http_client.uses_mtls() {
            self.mtls_device_authorization_endpoint
                .as_ref()
                .unwrap_or(&self.device_authorization_endpoint)
        } else {
            &self.device_authorization_endpoint
        };

        let response: DeviceAuthorizationResponse = OAuth2FormRequest::builder()
            .form(&payload)
            .auth_params(
                self.authentication_params()
                    .await
                    .context(ClientAuthSnafu)?,
            )
            .uri(effective_device_auth_endpoint.as_uri())
            .dpop(self.dpop())
            .build()
            .execute(http_client)
            .await
            .context(FormSnafu)?;

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
    pub async fn poll_to_completion<C: HttpClient>(
        &self,
        http_client: &C,
        pending_state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<TokenResponse, PollError<ExchangeError<C, Self>>> {
        loop {
            sleep(Duration::from_secs(pending_state.interval_secs.into())).await;

            if let PollResult::Complete(token_response) = self
                .poll(http_client, pending_state, resource.clone())
                .await?
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
    pub async fn poll<C: HttpClient>(
        &self,
        http_client: &C,
        pending_state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<PollResult, PollError<ExchangeError<C, Self>>> {
        let token_or_err = self
            .exchange(
                http_client,
                super::grant::DeviceAuthorizationGrantParameters {
                    device_code: pending_state.device_code.clone(),
                    resource,
                },
            )
            .await;

        match token_or_err {
            Ok(token) => Ok(PollResult::Complete(Box::new(token))),
            Err(err) => match &err {
                OAuth2ExchangeGrantError::OAuth2Form {
                    source:
                        OAuth2FormError::Response {
                            source:
                                HandleResponseError::OAuth2 {
                                    body: OAuth2ErrorBody { error, .. },
                                    ..
                                },
                        },
                } => match error.as_ref() {
                    "slow_down" => {
                        pending_state.interval_secs = pending_state.interval_secs.saturating_add(5);
                        Ok(PollResult::Pending)
                    }
                    "authorization_pending" => Ok(PollResult::Pending),
                    "access_denied" => AccessDeniedSnafu.fail(),
                    "expired_token" => TokenExpiredSnafu.fail(),
                    _ => Err(err).context(ExchangeSnafu),
                },
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

#[huskarl_macros::grant_impl]
impl<Auth: ClientAuthentication + Clone + 'static, D: AuthorizationServerDPoP + 'static>
    OAuth2ExchangeGrant for DeviceAuthorizationGrant<Auth, D>
{
    type Parameters = DeviceAuthorizationGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = DeviceAuthorizationGrantForm;

    fn to_refresh_grant(&self) -> RefreshGrant<Auth, D> {
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.token_endpoint.clone())
            .unwrap_or_else(|e: std::convert::Infallible| match e {})
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
#[derive(Debug, Snafu)]
pub enum PollError<ExchangeErr: crate::core::Error + 'static> {
    /// Access was denied.
    AccessDenied,
    /// The token expired.
    TokenExpired,
    /// There was an error while attempting to exchange the code for a token.
    Exchange {
        /// The underlying error.
        source: ExchangeErr,
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

#[derive(Debug, Snafu)]
pub enum StartError<
    AuthErr: crate::core::Error + 'static,
    HttpErr: crate::core::Error + 'static,
    HttpRespErr: crate::core::Error + 'static,
    DPoPErr: crate::core::Error + 'static,
> {
    Form {
        source: OAuth2FormError<HttpErr, HttpRespErr, DPoPErr>,
    },
    ClientAuth {
        source: AuthErr,
    },
}
