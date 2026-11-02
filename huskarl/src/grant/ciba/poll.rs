use std::{collections::HashSet, sync::Arc};

use bon::Builder;
use snafu::{ResultExt as _, ensure};

#[cfg(feature = "experimental-oidc-key-binding")]
use super::error::BoundKeyUnsupportedSnafu;
use super::{
    error::{
        AccessDeniedSnafu, ClientAuthenticationRequiredSnafu, ExchangeSnafu,
        InvalidAcknowledgementSnafu, PollError, PollModeUnsupportedSnafu,
        RequestSigningUnsupportedSnafu, TokenExpiredSnafu, UserCodeUnsupportedSnafu,
    },
    types::{
        AuthenticationForm, AuthenticationRequest, AuthenticationResponse, CibaPollGrantForm,
        CibaPollGrantParameters, CompleteOutput, PendingState, PollResult, StartInput, StartOutput,
    },
};
/// Default number of consecutive retryable failures absorbed by automatic polling.
pub use crate::grant::core::polling::DEFAULT_MAX_TRANSIENT_POLL_FAILURES;
/// Default minimum delay between polls, in seconds (CIBA Core §7.3).
pub use crate::grant::core::polling::DEFAULT_MIN_POLL_INTERVAL_SECS;
use crate::{
    core::{
        EndpointUrl, Error, OAuthError, OAuthErrorCode,
        client_auth::{AuthenticationContext, ClientAuthentication},
        crypto::{signer::AsymmetricJwsSignerSelector, verifier::JwsVerifier},
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
        jwt::Jwt,
        platform::Duration,
        time::{Clock, PlatformClock, PlatformTimer, Timer},
    },
    grant::{
        core::{
            OAuth2ExchangeGrant, TokenResponse,
            form::{OAuth2FormRequest, with_dpop_nonce_retry},
        },
        refresh::RefreshGrant,
    },
    token::id_token::IdTokenValidator,
};

/// An OpenID Connect CIBA grant registered for poll mode.
///
/// Start authentication for a known user, then poll for tokens. Completion
/// requires a validated ID token. See the [how-to guide](crate::_docs::guide::ciba).
///
/// The builder requires an issuer and a JWS verifier. Signed authentication
/// requests accept only an asymmetric signer. These inputs are independent of
/// the credentials used to authenticate the client at the provider.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Clone, Builder)]
#[builder(on(String, into), finish_fn(name = build_internal, vis = ""), builder_type(doc {
    /// Configures a [`CibaPollGrant`].
    ///
    /// Use [`CibaPollGrant::builder_from_metadata`] to populate endpoint and
    /// capability settings. Supply the client's registered authentication and
    /// the provider's JWS verifier, then call [`build`](Self::build).
}))]
pub struct CibaPollGrant {
    /// Clock used for requests and received tokens; inherited by refresh grants.
    #[builder(default = Arc::<PlatformClock>::default(), with = |clock: impl Clock + 'static| Arc::new(clock) as Arc<dyn Clock>)]
    clock: Arc<dyn Clock>,
    /// The registered OAuth client ID.
    client_id: String,
    /// Transport used for backchannel authentication and token requests.
    /// Configure it to allow at least 30 seconds for long-poll responses.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,
    /// Client authentication registered with the provider. Public clients are unsupported.
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Arc<dyn ClientAuthentication>,
    /// DPoP implementation; defaults to no sender-constraining.
    #[builder(default = Arc::new(NoDPoP), with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>)]
    dpop: Arc<dyn AuthorizationServerDPoP>,
    /// Minimum interval enforced by automatic polling, even for restored state.
    #[builder(default = DEFAULT_MIN_POLL_INTERVAL_SECS)]
    min_poll_interval_secs: u32,
    /// Consecutive retryable failures automatic polling tolerates. Zero surfaces the first failure.
    #[builder(default = DEFAULT_MAX_TRANSIENT_POLL_FAILURES)]
    max_transient_poll_failures: u32,
    /// Timer used for automatic polling; inherited by refresh grants.
    #[builder(default = Arc::<PlatformTimer>::default(), with = |timer: impl Timer + 'static| Arc::new(timer) as Arc<dyn Timer>)]
    timer: Arc<dyn Timer>,
    /// Exact provider issuer, used for ID-token validation and signed requests.
    #[from_metadata(path = "issuer")]
    issuer: String,
    /// Canonical token endpoint, before mTLS alias resolution.
    #[from_metadata(path = "token_endpoint")]
    token_endpoint: EndpointUrl,
    /// mTLS alias for the token endpoint.
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
    mtls_token_endpoint: Option<EndpointUrl>,
    #[builder(skip = crate::grant::core::resolve_mtls_alias(http_client.as_ref(), &token_endpoint, mtls_token_endpoint.as_ref()))]
    effective_token_endpoint: EndpointUrl,
    /// Authentication methods supported at both endpoints (CIBA Core §4).
    #[from_metadata(path = "token_endpoint_auth_methods_supported")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Backchannel authentication endpoint.
    #[from_metadata(path = "backchannel_authentication_endpoint?")]
    backchannel_authentication_endpoint: EndpointUrl,
    /// mTLS alias for the backchannel authentication endpoint.
    #[from_metadata(path = "mtls_endpoint_aliases?.backchannel_authentication_endpoint?")]
    mtls_backchannel_authentication_endpoint: Option<EndpointUrl>,
    #[builder(skip = crate::grant::core::resolve_mtls_alias(http_client.as_ref(), &backchannel_authentication_endpoint, mtls_backchannel_authentication_endpoint.as_ref()))]
    effective_backchannel_authentication_endpoint: EndpointUrl,
    /// Provider token delivery modes. When supplied, must include `poll`.
    #[from_metadata(with = |m: &crate::core::server_metadata::AuthorizationServerMetadata| Some(m.backchannel_token_delivery_modes_supported.clone().unwrap_or_default()), maybe)]
    backchannel_token_delivery_modes_supported: Option<Vec<String>>,
    /// Provider algorithms for signed authentication requests.
    /// An empty list prohibits signed requests. Without discovery, omission
    /// leaves selection to the configured asymmetric signer.
    #[from_metadata(with = |m: &crate::core::server_metadata::AuthorizationServerMetadata| Some(m.backchannel_authentication_request_signing_alg_values_supported.clone().unwrap_or_default()), maybe)]
    backchannel_authentication_request_signing_alg_values_supported: Option<Vec<String>>,
    /// Whether the provider supports user codes. Without discovery, omission
    /// leaves this capability unconstrained. The client must also be registered for it.
    #[from_metadata(path = "backchannel_user_code_parameter_supported")]
    backchannel_user_code_parameter_supported: Option<bool>,
    /// Optional signer for authentication requests. Register its algorithm with
    /// the provider before use. Request signing does not replace client authentication.
    #[builder(with = |signer: impl AsymmetricJwsSignerSelector + 'static| Arc::new(signer) as Arc<dyn AsymmetricJwsSignerSelector>)]
    request_signer: Option<Arc<dyn AsymmetricJwsSignerSelector>>,
    /// Verifier for provider-issued ID tokens. Reuse an existing in-memory or
    /// refreshable verifier; building this grant does not fetch verification keys.
    #[builder(with = |verifier: impl JwsVerifier + 'static| Arc::new(verifier) as Arc<dyn JwsVerifier>)]
    jws_verifier: Arc<dyn JwsVerifier>,
    /// Maximum time since a returned ID token was issued (`iat`).
    /// Unset by default. Validation includes the ID-token validator's clock leeway.
    /// This local acceptance policy is not sent to the provider and does not limit
    /// how long the user may take to approve the request.
    max_id_token_age: Option<Duration>,
    /// Accepted ID-token signing algorithms. Omission accepts algorithms
    /// supported by the verifier; unsigned ID tokens are always rejected.
    #[from_metadata(with = |m: &crate::core::server_metadata::AuthorizationServerMetadata| m.id_token_signing_alg_values_supported.as_ref().map(|algs| algs.iter().cloned().collect::<HashSet<_>>()), maybe)]
    allowed_id_token_signed_response_algs: Option<HashSet<String>>,
}

impl core::fmt::Debug for CibaPollGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CibaPollGrant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("mtls_token_endpoint", &self.mtls_token_endpoint)
            .field(
                "backchannel_authentication_endpoint",
                &self.backchannel_authentication_endpoint,
            )
            .field(
                "mtls_backchannel_authentication_endpoint",
                &self.mtls_backchannel_authentication_endpoint,
            )
            .finish_non_exhaustive()
    }
}

impl<S: ciba_poll_grant_builder::IsComplete> CibaPollGrantBuilder<S> {
    /// Builds the grant without performing network requests.
    ///
    /// # Errors
    ///
    /// Returns an error for public-client authentication, unsupported poll
    /// mode, or signing configured when discovery prohibits signed requests.
    pub fn build(self) -> Result<CibaPollGrant, Error> {
        let grant = self.build_internal();
        ensure!(!grant.is_public_client(), ClientAuthenticationRequiredSnafu);
        ensure!(
            grant
                .backchannel_token_delivery_modes_supported
                .as_ref()
                .is_none_or(|modes| modes.iter().any(|mode| mode == "poll")),
            PollModeUnsupportedSnafu
        );
        ensure!(
            grant.request_signer.is_none()
                || grant
                    .backchannel_authentication_request_signing_alg_values_supported
                    .as_ref()
                    .is_none_or(|algs| !algs.is_empty()),
            RequestSigningUnsupportedSnafu
        );
        Ok(grant)
    }
}

impl CibaPollGrant {
    /// Starts authentication for the user identified by `start_input`.
    ///
    /// The `openid` scope is included automatically. Display any binding
    /// message to the user before polling. The provider handles authentication
    /// on the user's separate device.
    ///
    /// # Errors
    ///
    /// Returns an error if request signing, client authentication, transport,
    /// response validation, or expiry arithmetic fails, or the provider rejects
    /// the request. User codes are rejected when discovery prohibits them.
    /// With `experimental-oidc-key-binding` enabled, the unsupported `bound_key`
    /// scope is rejected before contacting the provider.
    pub async fn start(&self, start_input: StartInput) -> Result<StartOutput, Error> {
        ensure!(
            start_input.user_code.is_none()
                || self.backchannel_user_code_parameter_supported != Some(false),
            UserCodeUnsupportedSnafu
        );
        let scopes = authentication_scopes(start_input.scope);
        #[cfg(feature = "experimental-oidc-key-binding")]
        validate_key_binding_scopes(&scopes)?;
        let payload = AuthenticationRequest {
            scope: crate::grant::core::join_space(Some(&scopes)),
            hint: &start_input.hint,
            acr_values: crate::grant::core::join_space(start_input.acr_values.as_deref()),
            binding_message: start_input.binding_message.as_deref(),
            user_code: start_input.user_code.as_ref(),
            requested_expiry: start_input.requested_expiry,
            resource: start_input.resource.as_deref(),
            authorization_details: start_input.authorization_details.as_deref(),
        };
        let endpoint = &self.effective_backchannel_authentication_endpoint;
        let dpop_jkt = self.dpop.get_current_thumbprint().await;
        let (response, received_at): (AuthenticationResponse, _) = with_dpop_nonce_retry!({
            let now = self.clock.now();
            let request = if let Some(selector) = &self.request_signer {
                let signer = selector.select_asymmetric_signer().await;
                ensure!(
                    self.backchannel_authentication_request_signing_alg_values_supported
                        .as_ref()
                        .is_none_or(|algs| algs
                            .iter()
                            .any(|alg| alg == signer.jws_algorithm().as_ref())),
                    RequestSigningUnsupportedSnafu
                );
                Some(
                    Jwt::builder()
                        .typ("oauth-authz-req+jwt")
                        .iss(self.client_id.as_str())
                        .audience(&self.issuer)
                        .issued_at_not_before_expires_after(
                            crate::core::time::system_time_from_timestamp_saturating(now),
                            Duration::from_secs(60),
                        )
                        .claims(&payload)
                        .build()
                        .to_jws_compact(signer.as_ref())
                        .await?,
                )
            } else {
                None
            };
            let form = match &request {
                Some(request) => AuthenticationForm::Signed { request },
                None => AuthenticationForm::Unsigned(&payload),
            };
            let auth_params = self
                .client_auth
                .authentication_context(
                    AuthenticationContext::builder()
                        .now(now)
                        .client_id(&self.client_id)
                        .target_endpoint(endpoint)
                        .issuer(&self.issuer)
                        .token_endpoint(&self.token_endpoint)
                        .maybe_allowed_methods(
                            self.token_endpoint_auth_methods_supported.as_deref(),
                        )
                        .build(),
                )
                .await?;
            OAuth2FormRequest::builder()
                .now(now)
                .form(&form)
                .auth_params(auth_params)
                .uri(endpoint.as_uri())
                .dpop(self.dpop())
                .maybe_dpop_jkt(dpop_jkt.as_deref())
                .build()
                .execute(self.http_client.as_ref(), self.clock.as_ref())
                .await
        })?;
        ensure!(
            !response.auth_req_id.is_empty(),
            InvalidAcknowledgementSnafu
        );
        let expires_at =
            crate::grant::core::response_expiry(received_at, u64::from(response.expires_in.get()))?;
        Ok(StartOutput::builder()
            .expires_at(expires_at)
            .pending_state(PendingState {
                auth_req_id: response.auth_req_id,
                expires_at,
                expected_sub: start_input.expected_sub,
                interval_secs: response.interval.get(),
            })
            .build())
    }

    /// Polls until authentication completes, waiting between requests.
    ///
    /// Waits before the first request and after each response. Honors `Retry-After`
    /// and limits consecutive retryable failures. Waits are capped at the persisted
    /// expiry and no new request is sent once it passes. Configure transport
    /// timeouts to bound requests already in flight.
    ///
    /// # Errors
    ///
    /// Returns denial, expiry, an unretryable exchange failure, exhausted
    /// retries, or an ID-token validation failure. Completion failures never
    /// trigger another exchange because the request has already been redeemed.
    pub async fn poll_to_completion(
        &self,
        pending_state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<CompleteOutput, PollError> {
        crate::grant::core::polling::PollingDriver {
            timer: self.timer.as_ref(),
            clock: self.clock.as_ref(),
            min_interval_secs: self.min_poll_interval_secs,
            max_transient_failures: self.max_transient_poll_failures,
        }
        .run(self, pending_state, resource)
        .await
    }

    /// Polls once without waiting or enforcing the advertised interval.
    ///
    /// Wait for the state's interval between calls and avoid concurrent requests
    /// for the same state. A `slow_down` response updates `interval_secs`.
    /// Use [`Self::poll_to_completion`] for automatic pacing and retries.
    ///
    /// # Errors
    ///
    /// Returns an error on denial, expiry, exchange failure, or missing or
    /// invalid ID token. Only a successful validation returns completion.
    pub async fn poll(
        &self,
        pending_state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<PollResult, PollError> {
        let token_or_err = self
            .exchange(CibaPollGrantParameters {
                auth_req_id: pending_state.auth_req_id.clone(),
                resource,
            })
            .await;
        match token_or_err {
            Ok(token_response) => self
                .complete(token_response, pending_state)
                .await
                .map(|output| PollResult::Complete(Box::new(output))),
            Err(err) => match err.verdict().map(OAuthError::code) {
                Some(OAuthErrorCode::SlowDown) => {
                    crate::grant::core::polling::slow_down(
                        &mut pending_state.interval_secs,
                        self.min_poll_interval_secs,
                    );
                    Ok(PollResult::Pending)
                }
                Some(OAuthErrorCode::AuthorizationPending) => Ok(PollResult::Pending),
                Some(OAuthErrorCode::AccessDenied) => AccessDeniedSnafu.fail(),
                Some(OAuthErrorCode::ExpiredToken) => TokenExpiredSnafu.fail(),
                _ => Err(err).context(ExchangeSnafu),
            },
        }
    }

    /// Validates an already-issued response without redeeming the request again.
    /// Pass the original pending state so the expected subject is checked on every attempt.
    ///
    /// # Errors
    /// Returns the unvalidated response with any missing-token, validation, or
    /// subject-mismatch error, allowing validation to be retried independently.
    pub async fn complete(
        &self,
        token_response: TokenResponse,
        pending_state: &PendingState,
    ) -> Result<CompleteOutput, PollError> {
        let Some(id_token) = token_response.id_token() else {
            return Err(PollError::MissingIdToken {
                token_response: Box::new(token_response),
            });
        };
        let validated = IdTokenValidator::builder()
            .verifier(self.jws_verifier.clone())
            .issuer(self.issuer.clone())
            .audience(self.client_id.clone())
            .maybe_max_token_age(self.max_id_token_age)
            .maybe_allowed_algorithms(self.allowed_id_token_signed_response_algs.clone())
            .build()
            .validate_at(id_token, None, token_response.received_at())
            .await;
        let id_token = match validated {
            Ok(id_token) => id_token,
            Err(source) => {
                return Err(PollError::ValidatingIdToken {
                    source,
                    token_response: Box::new(token_response),
                });
            }
        };
        if pending_state
            .expected_sub
            .as_deref()
            .is_some_and(|expected| id_token.sub.as_deref() != Some(expected))
        {
            return Err(PollError::SubjectMismatch {
                token_response: Box::new(token_response),
            });
        }
        Ok(CompleteOutput {
            token_response,
            id_token,
        })
    }
}

impl OAuth2ExchangeGrant for CibaPollGrant {
    async fn authentication_params_at(
        &self,
        now: jiff::Timestamp,
    ) -> Result<crate::core::client_auth::AuthenticationParams<'_>, crate::core::Error> {
        crate::grant::core::authentication_params_at(self, now).await
    }

    type Parameters = CibaPollGrantParameters;
    type Form<'a> = CibaPollGrantForm;

    fn jws_verifier(&self) -> Option<Arc<dyn JwsVerifier>> {
        Some(self.jws_verifier.clone())
    }

    fn client_id(&self) -> Option<&str> {
        Some(&self.client_id)
    }

    fn issuer(&self) -> Option<&str> {
        Some(self.issuer.as_str())
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

    fn timer(&self) -> Arc<dyn crate::core::time::Timer> {
        self.timer.clone()
    }

    fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    fn http_client(&self) -> &dyn HttpClient {
        self.http_client.as_ref()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn to_refresh_grant(&self) -> RefreshGrant {
        RefreshGrant::builder()
            .clock(self.clock.clone())
            .timer(OAuth2ExchangeGrant::timer(self))
            .client_id(self.client_id.clone())
            .issuer(self.issuer.clone())
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
        CibaPollGrantForm {
            grant_type: "urn:openid:params:grant-type:ciba",
            auth_req_id: params.auth_req_id,
            resource: params.resource,
        }
    }
}

impl<S: ciba_poll_grant_builder::State> CibaPollGrantBuilder<S> {
    /// Sets client identity, authentication, and DPoP from shared configuration.
    ///
    /// Call this before `client_id`, `client_auth`, or `dpop`. These setters
    /// are unavailable afterward, even when the configuration uses
    /// [`NoDPoP`].
    pub fn client(
        self,
        client: &crate::grant::ClientConfiguration,
    ) -> CibaPollGrantBuilder<
        ciba_poll_grant_builder::SetDpop<
            ciba_poll_grant_builder::SetClientAuth<ciba_poll_grant_builder::SetClientId<S>>,
        >,
    >
    where
        S::ClientId: ciba_poll_grant_builder::IsUnset,
        S::ClientAuth: ciba_poll_grant_builder::IsUnset,
        S::Dpop: ciba_poll_grant_builder::IsUnset,
    {
        self.client_id(client.client_id.clone())
            .client_auth(client.client_auth.clone())
            .dpop(client.dpop.clone())
    }
}

impl crate::grant::core::polling::PollingState for PendingState {
    fn interval_secs(&self) -> u32 {
        self.interval_secs
    }
    fn expires_at(&self) -> crate::core::platform::SystemTime {
        self.expires_at
    }
}

#[cfg(feature = "experimental-oidc-key-binding")]
fn validate_key_binding_scopes(scopes: &[String]) -> Result<(), Error> {
    ensure!(
        !scopes
            .iter()
            .flat_map(|scope| scope.split(' '))
            .any(|scope| scope == "bound_key"),
        BoundKeyUnsupportedSnafu
    );
    Ok(())
}

fn authentication_scopes(scope: Option<Vec<String>>) -> Vec<String> {
    let mut scopes = scope.unwrap_or_default();
    if !scopes
        .iter()
        .flat_map(|scope| scope.split(' '))
        .any(|scope| scope == "openid")
    {
        scopes.insert(0, "openid".to_owned());
    }
    scopes
}

impl crate::grant::core::polling::PollingGrant for CibaPollGrant {
    type State = PendingState;
    type Output = CompleteOutput;
    type Error = PollError;

    async fn poll_once(
        &self,
        state: &mut PendingState,
        resource: Option<Vec<String>>,
    ) -> Result<Option<Self::Output>, PollError> {
        match self.poll(state, resource).await? {
            PollResult::Pending => Ok(None),
            PollResult::Complete(output) => Ok(Some(*output)),
        }
    }

    fn retry_advice(error: &PollError) -> crate::core::RetryAdvice {
        error.retry_advice()
    }

    fn expired() -> PollError {
        PollError::TokenExpired
    }
}
