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
#[builder(on(String, into))]
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

    /// Minimum delay between token-endpoint polls, in seconds.
    ///
    /// Enforced even when the server supplies a smaller (or zero) `interval`,
    /// so a misbehaving or malicious authorization server cannot drive a tight
    /// polling loop (RFC 8628 §3.5 expects clients to throttle their polling).
    /// Defaults to [`DEFAULT_MIN_POLL_INTERVAL_SECS`] (RFC 8628 §3.2 baseline).
    #[builder(default = DEFAULT_MIN_POLL_INTERVAL_SECS)]
    min_poll_interval_secs: u32,

    /// The issuer for tokens created by the authorization server.
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The URL of the token endpoint.
    #[from_metadata(path = "token_endpoint")]
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
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
    #[from_metadata(path = "device_authorization_endpoint?")]
    device_authorization_endpoint: EndpointUrl,

    /// The mTLS alias for the device authorization endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.device_authorization_endpoint?")]
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
            authorization_details: start_input.authorization_details.as_deref(),
        };

        let device_auth_endpoint = &self.effective_device_authorization_endpoint;

        let dpop_jkt = self.dpop().get_current_thumbprint();

        let response: DeviceAuthorizationResponse = with_dpop_nonce_retry!({
            // The assertion is sent to the device authorization endpoint, not
            // the token endpoint: pass that as the target endpoint (RFC 8628 is
            // one of the non-token endpoints named in the audience-injection
            // analysis, draft-ietf-oauth-security-topics-update §2.1.1.2).
            let auth_params = self
                .client_auth
                .authentication_params(
                    &self.client_id,
                    self.issuer.as_deref(),
                    Some(&self.token_endpoint),
                    device_auth_endpoint,
                    self.token_endpoint_auth_methods_supported.as_deref(),
                )
                .await?;

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
            // Clamp to the configured floor: a server (or a deserialized
            // pending state) can carry `interval: 0`, which would otherwise
            // spin a zero-delay hot loop hammering the token endpoint.
            let interval_secs = pending_state.interval_secs.max(self.min_poll_interval_secs);
            sleep(Duration::from_secs(interval_secs.into())).await;

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
    resource: Option<Vec<String>>,
}

impl OAuth2ExchangeGrant for DeviceAuthorizationGrant {
    type Parameters = DeviceAuthorizationGrantParameters;
    type Form<'a> = DeviceAuthorizationGrantForm;

    fn client_id(&self) -> Option<&str> {
        Some(&self.client_id)
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> Option<&dyn ClientAuthentication> {
        Some(self.client_auth.as_ref())
    }

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn effective_token_endpoint(&self) -> &EndpointUrl {
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

/// Default polling interval in seconds (RFC 8628 §3.2), used when the device
/// authorization response omits `interval`.
#[inline]
const fn default_interval() -> u32 {
    5
}

/// Default minimum delay between token-endpoint polls, in seconds (RFC 8628
/// §3.2 baseline cadence). Configurable per grant via
/// [`DeviceAuthorizationGrant`]'s `min_poll_interval_secs` builder setter.
pub const DEFAULT_MIN_POLL_INTERVAL_SECS: u32 = 5;

#[derive(Debug, Serialize)]
struct DeviceAuthorizationRequest<'a> {
    scope: Option<&'a str>,
    resource: Option<&'a [String]>,
    authorization_details: Option<&'a [crate::core::AuthorizationDetail]>,
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
#[derive(Debug)]
pub enum PollResult {
    /// The token is still pending.
    Pending,
    /// Polling completed with a token response.
    Complete(Box<TokenResponse>),
}

/// The input to start the device authorization flow.
#[derive(Debug, Clone, Builder)]
pub struct StartInput {
    #[builder(required, default, with = |scopes: impl IntoIterator<Item = impl Into<String>>| crate::grant::core::mk_scopes(scopes))]
    scopes: Option<String>,
    resource: Option<Vec<String>>,
    /// RFC 9396 Rich Authorization Requests, sent on the device authorization
    /// request alongside (or instead of) `scopes`.
    authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
}

impl StartInput {
    /// Convenience constructor for a start input carrying only scopes.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    #[must_use]
    pub fn scopes(scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::builder().scopes(scopes).build()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{HeaderMap, Request, StatusCode};

    use super::*;
    use crate::core::{
        Error,
        client_auth::NoAuth,
        http::{HttpClient, HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
    };

    /// An [`HttpClient`] that ignores the request and returns a fixed response.
    struct FakeClient {
        status: StatusCode,
        body: &'static str,
    }

    impl HttpClient for FakeClient {
        fn execute(
            &self,
            _request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            let status = self.status;
            let body = Bytes::from_static(self.body.as_bytes());
            Box::pin(async move {
                Ok(HttpResponse {
                    status,
                    headers: HeaderMap::new(),
                    body,
                })
            })
        }
    }

    /// A grant whose token endpoint always answers with the given status/body.
    fn grant(status: StatusCode, body: &'static str) -> DeviceAuthorizationGrant {
        DeviceAuthorizationGrant::builder()
            .client_id("device-client")
            .http_client(FakeClient { status, body })
            .client_auth(NoAuth)
            .token_endpoint("https://as.example/token".parse::<EndpointUrl>().unwrap())
            .device_authorization_endpoint(
                "https://as.example/device".parse::<EndpointUrl>().unwrap(),
            )
            .build()
    }

    fn pending() -> PendingState {
        PendingState {
            device_code: "dev-code".to_string(),
            interval_secs: 5,
        }
    }

    #[test]
    fn device_authorization_request_carries_authorization_details() {
        let details = vec![
            crate::core::AuthorizationDetail::builder("payment_initiation")
                .with("actions", serde_json::json!(["initiate"]))
                .build(),
        ];
        let payload = DeviceAuthorizationRequest {
            scope: Some("openid"),
            resource: None,
            authorization_details: Some(&details),
        };

        let encoded = crate::core::oauth_form::to_string(&payload).unwrap();
        assert!(encoded.contains("scope=openid"), "encoded: {encoded}");
        // RFC 9396 §3: one parameter carrying URL-encoded JSON (`%5B%7B` = `[{`).
        assert!(
            encoded.contains("authorization_details=%5B%7B"),
            "encoded: {encoded}"
        );
    }

    #[test]
    fn start_input_scope_is_optional() {
        // RFC 6749 §3.1.1 / RFC 9396 §3: scope is optional; a request may carry
        // only authorization_details.
        let input = StartInput::builder()
            .authorization_details(vec![
                crate::core::AuthorizationDetail::builder("payment_initiation").build(),
            ])
            .build();
        assert!(input.scopes.is_none());
        assert!(input.authorization_details.is_some());
    }

    #[tokio::test]
    async fn slow_down_bumps_interval_and_stays_pending() {
        let g = grant(StatusCode::BAD_REQUEST, r#"{"error":"slow_down"}"#);
        let mut state = pending();
        let result = g.poll(&mut state, None).await.unwrap();
        assert!(matches!(result, PollResult::Pending));
        assert_eq!(state.interval_secs, 10, "slow_down adds 5s to the interval");
    }

    #[tokio::test]
    async fn authorization_pending_stays_pending_without_bump() {
        let g = grant(
            StatusCode::BAD_REQUEST,
            r#"{"error":"authorization_pending"}"#,
        );
        let mut state = pending();
        let result = g.poll(&mut state, None).await.unwrap();
        assert!(matches!(result, PollResult::Pending));
        assert_eq!(
            state.interval_secs, 5,
            "authorization_pending leaves the interval unchanged"
        );
    }

    #[tokio::test]
    async fn access_denied_maps_to_error() {
        let g = grant(StatusCode::BAD_REQUEST, r#"{"error":"access_denied"}"#);
        assert!(matches!(
            g.poll(&mut pending(), None).await,
            Err(PollError::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn expired_token_maps_to_error() {
        let g = grant(StatusCode::BAD_REQUEST, r#"{"error":"expired_token"}"#);
        assert!(matches!(
            g.poll(&mut pending(), None).await,
            Err(PollError::TokenExpired)
        ));
    }

    #[tokio::test]
    async fn other_oauth_error_propagates_as_exchange() {
        let g = grant(StatusCode::BAD_REQUEST, r#"{"error":"invalid_client"}"#);
        assert!(matches!(
            g.poll(&mut pending(), None).await,
            Err(PollError::Exchange { .. })
        ));
    }

    #[tokio::test]
    async fn successful_token_completes_poll() {
        let g = grant(
            StatusCode::OK,
            r#"{"access_token":"at-123","token_type":"bearer"}"#,
        );
        let result = g.poll(&mut pending(), None).await.unwrap();
        assert!(matches!(result, PollResult::Complete(_)));
    }

    #[test]
    fn min_poll_interval_defaults_to_baseline_and_is_configurable() {
        let g = grant(StatusCode::OK, "{}");
        assert_eq!(g.min_poll_interval_secs, DEFAULT_MIN_POLL_INTERVAL_SECS);

        let configured = DeviceAuthorizationGrant::builder()
            .client_id("device-client")
            .http_client(FakeClient {
                status: StatusCode::OK,
                body: "{}",
            })
            .client_auth(NoAuth)
            .token_endpoint("https://as.example/token".parse::<EndpointUrl>().unwrap())
            .device_authorization_endpoint(
                "https://as.example/device".parse::<EndpointUrl>().unwrap(),
            )
            .min_poll_interval_secs(30)
            .build();
        assert_eq!(configured.min_poll_interval_secs, 30);
    }

    /// A server-supplied `interval: 0` must not spin a zero-delay hot loop:
    /// `poll_to_completion` waits at least the configured floor before polling.
    #[tokio::test(start_paused = true)]
    async fn poll_to_completion_enforces_interval_floor_on_zero() {
        let g = grant(
            StatusCode::OK,
            r#"{"access_token":"at-123","token_type":"bearer"}"#,
        );
        let mut state = PendingState {
            device_code: "dev-code".to_string(),
            interval_secs: 0,
        };

        let start = tokio::time::Instant::now();
        g.poll_to_completion(&mut state, None).await.unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= std::time::Duration::from_secs(DEFAULT_MIN_POLL_INTERVAL_SECS.into()),
            "expected at least the {DEFAULT_MIN_POLL_INTERVAL_SECS}s floor, slept {elapsed:?}"
        );
    }
}
