use std::sync::Arc;

use bon::Builder;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use crate::{
    core::{
        EndpointUrl, Error, OAuthError, OAuthErrorCode, RetryAdvice,
        client_auth::{AuthenticationContext, ClientAuthentication},
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

    /// Maximum consecutive retryable failures absorbed by
    /// [`poll_to_completion`](Self::poll_to_completion).
    ///
    /// Any response from the server, including `authorization_pending`, resets
    /// the count.
    ///
    /// Defaults to [`DEFAULT_MAX_TRANSIENT_POLL_FAILURES`]. Set it to `0` to
    /// surface the first retryable failure to the caller and drive the retry
    /// policy yourself.
    #[builder(default = DEFAULT_MAX_TRANSIENT_POLL_FAILURES)]
    max_transient_poll_failures: u32,

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
    /// Sends a request to the device authorization endpoint and returns the
    /// state needed for polling plus the verification instructions to display.
    ///
    /// # Errors
    ///
    /// Returns an error if client authentication, `DPoP` proof generation, the
    /// HTTP request, or response parsing fails, or if the endpoint rejects the
    /// request.
    pub async fn start(&self, start_input: StartInput) -> Result<StartOutput, Error> {
        let payload = DeviceAuthorizationRequest {
            scope: crate::grant::core::join_space(start_input.scope.as_deref()),
            resource: start_input.resource.as_deref(),
            authorization_details: start_input.authorization_details.as_deref(),
        };

        let device_auth_endpoint = &self.effective_device_authorization_endpoint;

        let dpop_jkt = self.dpop().get_current_thumbprint().await;

        let response: DeviceAuthorizationResponse = with_dpop_nonce_retry!({
            // The assertion is sent to the device authorization endpoint, not
            // the token endpoint: pass that as the target endpoint (RFC 8628 is
            // one of the non-token endpoints named in the audience-injection
            // analysis, draft-ietf-oauth-security-topics-update §2.1.1.2).
            let auth_params = self
                .client_auth
                .authentication_context(
                    AuthenticationContext::builder()
                        .client_id(&self.client_id)
                        .target_endpoint(device_auth_endpoint)
                        .maybe_issuer(self.issuer.as_deref())
                        .token_endpoint(&self.token_endpoint)
                        .maybe_allowed_methods(
                            self.token_endpoint_auth_methods_supported.as_deref(),
                        )
                        .build(),
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
    /// Retryable failures are absorbed up to the configured limit. A
    /// `Retry-After` delay is honored, and any server response resets the
    /// consecutive-failure count.
    ///
    /// # Errors
    ///
    /// Returns [`AccessDenied`](PollError::AccessDenied) or
    /// [`TokenExpired`](PollError::TokenExpired) when the flow ended for good,
    /// and [`Exchange`](PollError::Exchange) for a token request that failed
    /// unretryably, or that stayed retryable for too long.
    pub async fn poll_to_completion(
        &self,
        pending_state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<TokenResponse, PollError> {
        let mut consecutive_failures: u32 = 0;
        loop {
            // Clamp to the configured floor: a server (or a deserialized
            // pending state) can carry `interval: 0`, which would otherwise
            // spin a zero-delay hot loop hammering the token endpoint.
            let interval_secs = pending_state.interval_secs.max(self.min_poll_interval_secs);
            let interval = Duration::from_secs(interval_secs.into());
            sleep(interval).await;

            let err = match self.poll(pending_state, resource.clone()).await {
                Ok(PollResult::Complete(token_response)) => return Ok(*token_response),
                // The server answered, so whatever was wrong is over.
                Ok(PollResult::Pending) => {
                    consecutive_failures = 0;
                    continue;
                }
                Err(err) => err,
            };

            // Preserve the retry classification established by the request.
            let RetryAdvice::Retry { after } = err.retry_advice() else {
                return Err(err);
            };
            consecutive_failures += 1;
            if consecutive_failures > self.max_transient_poll_failures {
                return Err(err);
            }
            // The next loop already sleeps for `interval`, so wait only the excess.
            if let Some(after) = after {
                sleep(after.saturating_sub(interval)).await;
            }
        }
    }

    /// Polls the token endpoint once for the pending device authorization.
    ///
    /// # Errors
    ///
    /// Returns [`PollError::AccessDenied`] when the user denies access,
    /// [`PollError::TokenExpired`] when the device code expires, and
    /// [`PollError::Exchange`] when the token request fails. The
    /// `authorization_pending` and `slow_down` responses are returned as
    /// non-error [`PollResult`] values.
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
            Err(err) => {
                // Only genuine verdicts control the device flow. Error-shaped
                // 429 and 5xx bodies remain exchange failures.
                match err.verdict().map(OAuthError::code) {
                    Some(OAuthErrorCode::SlowDown) => {
                        pending_state.interval_secs = pending_state.interval_secs.saturating_add(5);
                        Ok(PollResult::Pending)
                    }
                    Some(OAuthErrorCode::AuthorizationPending) => Ok(PollResult::Pending),
                    Some(OAuthErrorCode::AccessDenied) => AccessDeniedSnafu.fail(),
                    Some(OAuthErrorCode::ExpiredToken) => TokenExpiredSnafu.fail(),
                    _ => Err(err).context(ExchangeSnafu),
                }
            }
        }
    }
}

/// Parameters passed to each token request.
#[derive(Debug, Clone, Builder)]
#[builder(on(String, into))]
pub struct DeviceAuthorizationGrantParameters {
    /// The device verification code, `device_code`, from the device authorization response.
    device_code: String,
    /// The target resource(s) for the access token.
    resource: Option<Vec<String>>,
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
            .token_endpoint(self.token_endpoint.clone())
            .maybe_mtls_token_endpoint(self.mtls_token_endpoint.clone())
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
    #[serde(deserialize_with = "crate::serde_utils::deserialize_u32_or_string")]
    expires_in: u32,

    /// The minimum amount of time in seconds the client should wait between polling requests.
    /// Defaults to 5 seconds if not provided by the server.
    #[serde(
        default = "default_interval",
        deserialize_with = "crate::serde_utils::deserialize_u32_or_string"
    )]
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

/// Default number of consecutive retryable failures
/// [`poll_to_completion`](DeviceAuthorizationGrant::poll_to_completion)
/// absorbs before giving up.
///
/// At the default poll interval, this tolerates roughly half a minute of
/// transient failures. RFC 8628 does not prescribe a limit.
pub const DEFAULT_MAX_TRANSIENT_POLL_FAILURES: u32 = 5;

#[derive(Debug, Serialize)]
struct DeviceAuthorizationRequest<'a> {
    scope: Option<String>,
    resource: Option<&'a [String]>,
    authorization_details: Option<&'a [crate::core::AuthorizationDetail]>,
}

/// The output information from starting the device authorization flow.
#[derive(Debug, Builder)]
#[builder(on(String, into))]
#[non_exhaustive]
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
#[derive(Builder, Serialize, Deserialize)]
#[builder(on(String, into))]
#[non_exhaustive]
pub struct PendingState {
    /// The device verification code.
    pub device_code: String,
    /// The minimum amount of time in seconds the client should wait between polling requests.
    pub interval_secs: u32,
}

// `PendingState` is designed to be persisted between polls and is therefore
// likely to end up in logs. The `device_code` is the bearer credential for
// the token exchange (RFC 8628 §5.2), so it may not appear in `Debug` output.
impl core::fmt::Debug for PendingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingState")
            .field("device_code", &"[REDACTED]")
            .field("interval_secs", &self.interval_secs)
            .finish()
    }
}

/// Errors that may occur during polling for a token.
///
/// The `AccessDenied` and `TokenExpired` variants are control flow for
/// device-flow UIs; everything else carries the underlying [`Error`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PollError {
    /// The authorization request was denied (RFC 8628 §3.5 `access_denied`).
    #[snafu(display(
        "the user denied the request, or the authorization server refused it on \
         their behalf (RFC 8628 §3.5 access_denied)"
    ))]
    AccessDenied,
    /// The `device_code` expired before the user finished (RFC 8628 §3.5
    /// `expired_token`).
    #[snafu(display(
        "the device code expired before the user finished (RFC 8628 §3.5 expired_token)"
    ))]
    TokenExpired,
    /// The token request failed without a terminal verdict on the device flow.
    /// Use [`retry_advice`](PollError::retry_advice) to decide whether to retry.
    #[snafu(display("polling the token endpoint"))]
    Exchange {
        /// The underlying error.
        source: Error,
    },
}

impl PollError {
    /// Returns whether another poll may help and any minimum delay.
    ///
    /// Exchange failures preserve the underlying error's retry advice. Denial
    /// and expiration are terminal.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            Self::AccessDenied | Self::TokenExpired => RetryAdvice::No,
            Self::Exchange { source } => source.retry_advice(),
        }
    }
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
    /// The requested scope(s) for the device authorization request.
    scope: Option<Vec<String>>,
    resource: Option<Vec<String>>,
    /// RFC 9396 Rich Authorization Requests, sent on the device authorization
    /// request alongside (or instead of) `scope`.
    authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
}

impl StartInput {
    /// Convenience constructor for a start input carrying only scopes.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    #[must_use]
    pub fn scope(scope: Vec<String>) -> Self {
        Self::builder().scope(scope).build()
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

    /// Same wire leniency as the token response's `expires_in`: seconds
    /// counts may arrive as floats, number strings, or float strings.
    #[rstest::rstest]
    #[case::floats("1800.0", "5.5")]
    #[case::strings(r#""1800""#, r#""5""#)]
    #[case::float_strings(r#""1800.0""#, r#""5.5""#)]
    fn device_authorization_response_accepts_float_and_string_seconds(
        #[case] expires_in: &str,
        #[case] interval: &str,
    ) {
        let json = format!(
            r#"{{"device_code":"dc","user_code":"uc","verification_uri":"https://as.example/verify","expires_in":{expires_in},"interval":{interval}}}"#
        );
        let response: DeviceAuthorizationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.expires_in, 1800);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn pending_state_debug_redacts_the_device_code() {
        let rendered = format!("{:?}", pending());
        assert!(rendered.contains("[REDACTED]"), "got {rendered}");
        assert!(!rendered.contains("dev-code"), "got {rendered}");
        assert!(rendered.contains("interval_secs: 5"), "got {rendered}");
    }

    #[test]
    fn device_authorization_request_carries_authorization_details() {
        let details = vec![
            crate::core::AuthorizationDetail::builder("payment_initiation")
                .with("actions", serde_json::json!(["initiate"]))
                .build(),
        ];
        let payload = DeviceAuthorizationRequest {
            scope: Some("openid".into()),
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
        assert!(input.scope.is_none());
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

    // A 5xx is a server fault, not a verdict on the flow: `form.rs` reclassifies
    // it as retryable while leaving the body's error code attached but not a
    // verdict. Honoring that code would end a flow the user never denied —
    // and, since the device code is still live, end it for no reason.
    #[rstest::rstest]
    #[case::access_denied(r#"{"error":"access_denied"}"#)]
    #[case::expired_token(r#"{"error":"expired_token"}"#)]
    #[tokio::test]
    async fn terminal_code_on_a_5xx_does_not_end_the_flow(#[case] body: &'static str) {
        let g = grant(StatusCode::SERVICE_UNAVAILABLE, body);
        let err = g.poll(&mut pending(), None).await.unwrap_err();

        let PollError::Exchange { source } = err else {
            panic!("a 5xx must stay an exchange error, got {err:?}");
        };
        assert!(
            matches!(
                source.retry_advice(),
                crate::core::RetryAdvice::Retry { .. }
            ),
            "the reclassified server error must reach the caller as retryable"
        );
    }

    // A terminal-looking code in a 429 body is not a flow verdict.
    #[rstest::rstest]
    #[case::access_denied(r#"{"error":"access_denied"}"#)]
    #[case::expired_token(r#"{"error":"expired_token"}"#)]
    #[tokio::test]
    async fn terminal_code_on_a_429_does_not_end_the_flow(#[case] body: &'static str) {
        let g = grant(StatusCode::TOO_MANY_REQUESTS, body);
        let err = g.poll(&mut pending(), None).await.unwrap_err();

        let PollError::Exchange { source } = err else {
            panic!("a 429 must stay an exchange error, got {err:?}");
        };
        assert!(
            matches!(
                source.retry_advice(),
                crate::core::RetryAdvice::Retry { .. }
            ),
            "a rate-limited poll must reach the caller as retryable"
        );
    }

    // A pending code echoed in a 5xx body must still consume the failure budget.
    #[tokio::test(start_paused = true)]
    async fn an_echoed_pending_code_is_an_outage_not_a_wait() {
        let (g, calls) = scripted_grant(
            vec![(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"authorization_pending"}"#,
            )],
            2,
        );

        assert!(matches!(
            g.poll_to_completion(&mut pending(), None).await,
            Err(PollError::Exchange { .. })
        ));
        // Bounded: a budget of 2 absorbs two, and the third ends it.
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    // Only a genuine `slow_down` verdict changes the poll interval.
    #[tokio::test]
    async fn slow_down_echoed_on_a_5xx_does_not_re_pace_the_poll() {
        let g = grant(StatusCode::SERVICE_UNAVAILABLE, r#"{"error":"slow_down"}"#);
        let mut state = pending();
        let err = g.poll(&mut state, None).await.unwrap_err();

        assert!(
            matches!(err, PollError::Exchange { .. }),
            "an echoed code leaves it an exchange failure, got {err:?}"
        );
        assert_eq!(state.interval_secs, 5, "the interval is untouched");
    }

    // A 4xx verdict remains terminal even if another layer marked it retryable.
    #[tokio::test]
    async fn a_retryable_4xx_verdict_still_ends_the_flow() {
        let g = grant(StatusCode::BAD_REQUEST, r#"{"error":"access_denied"}"#);
        let mut state = pending();
        let err = g.poll(&mut state, None).await.unwrap_err();
        assert!(
            matches!(err, PollError::AccessDenied),
            "a 4xx denial is terminal regardless of advice, got {err:?}"
        );
    }

    // The same codes on a genuine 4xx remain terminal — the guard must not
    // disarm the verdicts, only decline to read one into a server fault.
    #[rstest::rstest]
    #[case::access_denied(r#"{"error":"access_denied"}"#, PollError::AccessDenied)]
    #[case::expired_token(r#"{"error":"expired_token"}"#, PollError::TokenExpired)]
    #[tokio::test]
    async fn terminal_code_on_a_4xx_still_ends_the_flow(
        #[case] body: &'static str,
        #[case] expected: PollError,
    ) {
        let g = grant(StatusCode::BAD_REQUEST, body);
        let err = g.poll(&mut pending(), None).await.unwrap_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&expected),
            "got {err:?}"
        );
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

    // A zero server interval must still honor the configured floor.
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

    // Repeats the last scripted response and counts requests.
    struct ScriptedClient {
        responses: Vec<(StatusCode, &'static str)>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl HttpClient for ScriptedClient {
        fn execute(
            &self,
            _request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            let call = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (status, body) = self.responses[call.min(self.responses.len() - 1)];
            Box::pin(async move {
                Ok(HttpResponse {
                    status,
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(body.as_bytes()),
                })
            })
        }
    }

    // Builds a grant and returns its shared request counter.
    fn scripted_grant(
        responses: Vec<(StatusCode, &'static str)>,
        max_transient_poll_failures: u32,
    ) -> (
        DeviceAuthorizationGrant,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let grant = DeviceAuthorizationGrant::builder()
            .client_id("device-client")
            .http_client(ScriptedClient {
                responses,
                calls: Arc::clone(&calls),
            })
            .client_auth(NoAuth)
            .token_endpoint("https://as.example/token".parse::<EndpointUrl>().unwrap())
            .device_authorization_endpoint(
                "https://as.example/device".parse::<EndpointUrl>().unwrap(),
            )
            .max_transient_poll_failures(max_transient_poll_failures)
            .build();
        (grant, calls)
    }

    const TOKEN: &str = r#"{"access_token":"at-123","token_type":"bearer"}"#;

    // One transient failure should not end an otherwise live flow.
    #[rstest::rstest]
    #[case::server_error(StatusCode::SERVICE_UNAVAILABLE)]
    #[case::bad_gateway(StatusCode::BAD_GATEWAY)]
    #[case::rate_limited(StatusCode::TOO_MANY_REQUESTS)]
    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_does_not_end_the_flow(#[case] status: StatusCode) {
        let (g, _) = scripted_grant(
            vec![(status, "{}"), (StatusCode::OK, TOKEN)],
            DEFAULT_MAX_TRANSIENT_POLL_FAILURES,
        );

        let token = g
            .poll_to_completion(&mut pending(), None)
            .await
            .expect("the flow survives a blip");
        assert_eq!(token.access_token().token().expose_secret(), "at-123");
    }

    // A sustained outage returns the underlying failure after the budget.
    #[tokio::test(start_paused = true)]
    async fn a_sustained_outage_still_ends_the_flow() {
        let (g, calls) = scripted_grant(vec![(StatusCode::SERVICE_UNAVAILABLE, "{}")], 2);

        let err = g
            .poll_to_completion(&mut pending(), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PollError::Exchange { .. }),
            "expected the underlying failure, got {err:?}"
        );
        // A budget of 2 absorbs two failures; the third ends it.
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    // A zero budget lets callers drive their own retry policy.
    #[tokio::test(start_paused = true)]
    async fn a_zero_budget_surfaces_the_first_transient_failure() {
        let (g, _) = scripted_grant(
            vec![
                (StatusCode::SERVICE_UNAVAILABLE, "{}"),
                (StatusCode::OK, TOKEN),
            ],
            0,
        );
        assert!(matches!(
            g.poll_to_completion(&mut pending(), None).await,
            Err(PollError::Exchange { .. })
        ));
    }

    // Any server answer resets the consecutive-failure count.
    #[tokio::test(start_paused = true)]
    async fn an_answer_resets_the_transient_budget() {
        const PENDING: &str = r#"{"error":"authorization_pending"}"#;
        let (g, _) = scripted_grant(
            vec![
                (StatusCode::SERVICE_UNAVAILABLE, "{}"),
                (StatusCode::BAD_REQUEST, PENDING),
                (StatusCode::SERVICE_UNAVAILABLE, "{}"),
                (StatusCode::BAD_REQUEST, PENDING),
                (StatusCode::SERVICE_UNAVAILABLE, "{}"),
                (StatusCode::OK, TOKEN),
            ],
            1,
        );

        let token = g
            .poll_to_completion(&mut pending(), None)
            .await
            .expect("each blip is a fresh streak of one");
        assert_eq!(token.access_token().token().expose_secret(), "at-123");
    }

    // A terminal verdict bypasses the transient-failure budget.
    #[rstest::rstest]
    #[case::denied(r#"{"error":"access_denied"}"#)]
    #[case::expired(r#"{"error":"expired_token"}"#)]
    #[tokio::test(start_paused = true)]
    async fn a_verdict_ends_the_flow_immediately(#[case] body: &'static str) {
        let (g, _) = scripted_grant(
            vec![(StatusCode::BAD_REQUEST, body), (StatusCode::OK, TOKEN)],
            DEFAULT_MAX_TRANSIENT_POLL_FAILURES,
        );

        let err = g
            .poll_to_completion(&mut pending(), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PollError::AccessDenied | PollError::TokenExpired),
            "got {err:?}"
        );
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    // Honor `Retry-After` when it exceeds the normal poll interval.
    #[tokio::test(start_paused = true)]
    async fn a_named_interval_is_honoured_before_re_attempting() {
        // Answers once with `Retry-After: 60`, then issues the token.
        struct ThrottlingClient(std::sync::atomic::AtomicUsize);

        impl HttpClient for ThrottlingClient {
            fn execute(
                &self,
                _request: Request<Bytes>,
                _idempotency: Idempotency,
            ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
                let first = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0;
                Box::pin(async move {
                    let mut headers = HeaderMap::new();
                    if first {
                        headers.insert("retry-after", http::HeaderValue::from_static("60"));
                    }
                    Ok(HttpResponse {
                        status: if first {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::OK
                        },
                        headers,
                        body: Bytes::from_static(TOKEN.as_bytes()),
                    })
                })
            }
        }

        let g = DeviceAuthorizationGrant::builder()
            .client_id("device-client")
            .http_client(ThrottlingClient(std::sync::atomic::AtomicUsize::new(0)))
            .client_auth(NoAuth)
            .token_endpoint("https://as.example/token".parse::<EndpointUrl>().unwrap())
            .device_authorization_endpoint(
                "https://as.example/device".parse::<EndpointUrl>().unwrap(),
            )
            .build();

        let start = tokio::time::Instant::now();
        g.poll_to_completion(&mut pending(), None)
            .await
            .expect("the flow survives a throttle");

        // The 60s the server asked for, not the 5s poll cadence.
        assert!(
            start.elapsed() >= std::time::Duration::from_mins(1),
            "slept only {:?}; the server's Retry-After was dropped",
            start.elapsed()
        );
    }

    // Poll errors expose terminal and wrapped retry advice consistently.
    #[test]
    fn poll_error_reports_the_advice_of_what_failed() {
        assert_eq!(PollError::AccessDenied.retry_advice(), RetryAdvice::No);
        assert_eq!(PollError::TokenExpired.retry_advice(), RetryAdvice::No);

        let retryable = PollError::Exchange {
            source: Error::new(RetryAdvice::RETRY, "the server is unavailable"),
        };
        assert_eq!(retryable.retry_advice(), RetryAdvice::RETRY);

        let terminal = PollError::Exchange {
            source: Error::new(RetryAdvice::No, "config failure"),
        };
        assert_eq!(terminal.retry_advice(), RetryAdvice::No);
    }
}
