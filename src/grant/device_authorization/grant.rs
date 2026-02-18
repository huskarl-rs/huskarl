use std::{borrow::Cow, time::Duration};

use bon::Builder;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use crate::{
    EndpointUrl,
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::{
        core::{
            OAuth2ExchangeGrant, OAuth2ExchangeGrantError, RefreshableGrant, TokenResponse,
            form::{HandleResponseError, OAuth2ErrorBody, OAuth2FormError, OAuth2FormRequest},
        },
        device_authorization::grant::builder::{
            SetDeviceAuthorizationEndpoint, SetTokenEndpoint, SetTokenEndpointAuthMethodsSupported,
        },
        refresh::RefreshGrant,
    },
    http::{HttpClient, HttpResponse},
    platform::sleep,
    server_metadata::AuthorizationServerMetadata,
};

/// The device authorization grant.
#[derive(Debug, Clone, Builder)]
#[builder(state_mod(name = "builder"))]
pub struct DeviceAuthorizationGrant<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static = NoDPoP,
> {
    /// The `DPoP` configuration.
    pub(super) dpop: D,

    // -- User-supplied fields --
    /// The client ID.
    #[builder(into)]
    pub(super) client_id: Cow<'static, str>,

    /// The client authentication method.
    pub(super) client_auth: Auth,

    // -- Metadata fields --
    /// The issuer for tokens created by the authorization server.
    #[builder(into)]
    issuer: Option<String>,

    /// The URL of the token endpoint.
    pub(super) token_endpoint: EndpointUrl,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    pub(super) token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// The device authorization endpoint (RFC 8628 §3.1).
    pub(super) device_authorization_endpoint: EndpointUrl,
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static>
    DeviceAuthorizationGrant<Auth, D>
{
    /// Configure the grant from authorization server metadata.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        DeviceAuthorizationGrantBuilder<
            Auth,
            D,
            SetDeviceAuthorizationEndpoint<SetTokenEndpointAuthMethodsSupported<SetTokenEndpoint>>,
        >,
    > {
        metadata
            .device_authorization_endpoint
            .as_ref()
            .map(|device_authorization_endpoint| {
                DeviceAuthorizationGrant::builder()
                    .token_endpoint(metadata.token_endpoint.clone())
                    .token_endpoint_auth_methods_supported(
                        metadata.token_endpoint_auth_methods_supported.clone(),
                    )
                    .device_authorization_endpoint(device_authorization_endpoint.clone())
            })
    }
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static>
    DeviceAuthorizationGrant<Auth, D>
{
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
    ) -> Result<
        StartOutput,
        StartError<Auth::Error, C::Error, <C::Response as HttpResponse>::Error, D::Error>,
    > {
        let payload = DeviceAuthorizationRequest {
            scope: start_input.scopes.as_deref(),
        };

        let response: DeviceAuthorizationResponse = OAuth2FormRequest::builder()
            .form(&payload)
            .auth_params(
                self.authentication_params()
                    .await
                    .context(ClientAuthSnafu)?,
            )
            .uri(self.device_authorization_endpoint.as_uri())
            .dpop(self.dpop())
            .build()
            .execute(http_client)
            .await
            .context(FormSnafu)?;

        Ok(StartOutput::builder()
            .expires_at(
                crate::platform::SystemTime::now()
                    .checked_add(Duration::from_secs(response.expires_in.into()))
                    .unwrap_or_else(crate::platform::SystemTime::now),
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
    ) -> Result<
        TokenResponse,
        PollError<
            OAuth2ExchangeGrantError<
                C::Error,
                <C::Response as HttpResponse>::Error,
                Auth::Error,
                D::Error,
            >,
        >,
    > {
        loop {
            sleep(Duration::from_secs(pending_state.interval_secs.into())).await;

            if let PollResult::Complete(token_response) =
                self.poll(http_client, pending_state).await?
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
    ) -> Result<
        PollResult,
        PollError<
            OAuth2ExchangeGrantError<
                C::Error,
                <C::Response as HttpResponse>::Error,
                Auth::Error,
                D::Error,
            >,
        >,
    > {
        let token_or_err = self
            .exchange(
                http_client,
                super::grant::Parameters {
                    device_code: pending_state.device_code.clone(),
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
#[derive(Debug, Clone)]
pub struct Parameters {
    /// The device verification code, `device_code`, from the device authorization response.
    pub device_code: String,
}

/// Authorization code grant body.
#[derive(Debug, Serialize)]
pub struct Form {
    /// Must be set to `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628 §3.4).
    grant_type: &'static str,
    /// The device verification code, `device_code`, from the authorization response (RFC 8628 §3.4).
    device_code: String,
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static> OAuth2ExchangeGrant
    for DeviceAuthorizationGrant<Auth, D>
{
    type Parameters = Parameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = Form;

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.client_auth
    }

    fn client_id(&self) -> &Cow<'static, str> {
        &self.client_id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.dpop
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        Self::Form {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: params.device_code,
        }
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }
}

impl<Auth: ClientAuthentication + Clone + 'static, D: AuthorizationServerDPoP + Clone + 'static>
    RefreshableGrant for DeviceAuthorizationGrant<Auth, D>
{
    type ClientAuth = Auth;
    type DPoP = D;

    fn to_refresh_grant(&self) -> RefreshGrant<Auth, D> {
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint_url(self.token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
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
}

#[derive(Debug, Builder)]
#[builder(on(String, into))]
pub struct StartOutput {
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_at: crate::platform::SystemTime,
    pub pending_state: PendingState,
}

#[derive(Debug, Builder, Serialize, Deserialize)]
#[builder(on(String, into))]
pub struct PendingState {
    pub device_code: String,
    pub interval_secs: u32,
}

/// Errors that may occur during polling for a token.
#[derive(Debug, Snafu)]
pub enum PollError<ExchangeErr: crate::Error + 'static> {
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
}

impl StartInput {
    /// Implements a simple complete input to the flow including just scopes.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    pub fn scopes(scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::builder().scopes(scopes).build()
    }
}

#[derive(Debug, Snafu)]
pub enum StartError<
    AuthErr: crate::Error + 'static,
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> {
    Form {
        source: OAuth2FormError<HttpErr, HttpRespErr, DPoPErr>,
    },
    ClientAuth {
        source: AuthErr,
    },
}
