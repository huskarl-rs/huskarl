use serde::Serialize;
use snafu::prelude::*;

use crate::{
    core::{
        EndpointUrl,
        client_auth::{AuthenticationParams, ClientAuthentication},
        dpop::AuthorizationServerDPoP,
        http::HttpClient,
        platform::{MaybeSend, MaybeSendSync},
    },
    grant::{
        core::{
            ExchangeError,
            form::{DPoPNonceError, OAuth2FormError, OAuth2FormRequest, with_dpop_nonce_retry},
            token_response::{InvalidTokenResponse, RawTokenResponse, TokenResponse},
        },
        refresh::RefreshGrant,
    },
};

/// An `OAuth2` exchange grant.
///
/// This represents an `OAuth2` grant implementation. It provides
/// the ability of the grant to provide features like parameters,
/// authentication, its `DPoP` configuration, and so forth.
pub trait OAuth2ExchangeGrant: MaybeSendSync {
    /// Parameters exchanged when making the token request.
    type Parameters: Clone + MaybeSendSync;

    /// Whether [`Self::Parameters`] may safely be submitted more than once.
    ///
    /// `false` for grants whose parameters contain single-use credentials —
    /// an authorization code (RFC 6749 §4.1.2), a device code, or a possibly
    /// rotating refresh token. Replaying those not only fails but may cause
    /// the authorization server to revoke tokens already issued for them.
    /// [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache) consumes such
    /// parameters on first use instead of replaying them after a failed refresh.
    const REUSABLE_PARAMETERS: bool = false;

    /// The client credentials used when making the token request.
    type ClientAuth: ClientAuthentication + 'static;

    /// The proof implementation used when adding a `DPoP` token binding.
    type DPoP: AuthorizationServerDPoP + 'static;

    /// The request body.
    type Form<'a>: MaybeSendSync + Serialize
    where
        Self: 'a;

    /// Returns the configured client ID.
    fn client_id(&self) -> &str;

    /// Returns the configured issuer.
    fn issuer(&self) -> Option<&str>;

    /// Returns the configured client auth.
    fn client_auth(&self) -> &Self::ClientAuth;

    /// Returns the bound `DPoP` thumbprint for the session.
    ///
    /// Often bound for authorization code grants or refresh grants.
    fn bound_dpop_jkt(_params: &Self::Parameters) -> Option<&str> {
        None
    }

    /// Returns the token endpoint URL.
    fn token_endpoint(&self) -> &EndpointUrl;

    /// Returns the mTLS alias for the token endpoint, if any (RFC 8705 §5).
    fn mtls_token_endpoint(&self) -> Option<&EndpointUrl> {
        None
    }

    /// Returns the effective token endpoint, preferring the mTLS alias when `uses_mtls` is true.
    fn effective_token_endpoint(&self, uses_mtls: bool) -> &EndpointUrl {
        if uses_mtls {
            self.mtls_token_endpoint()
                .unwrap_or_else(|| self.token_endpoint())
        } else {
            self.token_endpoint()
        }
    }

    /// Returns the configured `DPoP` implementation (if any).
    fn dpop(&self) -> &Self::DPoP;

    /// Builds the body for the request.
    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_>;

    /// Returns allowed authentication methods (formatted as in authorization server metadata).
    fn allowed_auth_methods(&self) -> Option<&[String]>;

    /// Returns the authentication parameters for this grant.
    fn authentication_params(
        &self,
    ) -> impl Future<
        Output = Result<
            AuthenticationParams<'_>,
            <Self::ClientAuth as ClientAuthentication>::Error,
        >,
    > + MaybeSend {
        async {
            self.client_auth()
                .authentication_params(
                    self.client_id(),
                    self.issuer(),
                    self.token_endpoint().as_uri(),
                    self.allowed_auth_methods(),
                )
                .await
        }
    }

    /// Exchange the parameters for an access token.
    fn exchange<C: HttpClient>(
        &self,
        http_client: &C,
        params: Self::Parameters,
    ) -> impl Future<Output = Result<TokenResponse, ExchangeError<C, Self>>> + MaybeSend {
        async move {
            let dpop_jkt = Self::bound_dpop_jkt(&params)
                .map(ToString::to_string)
                .or_else(|| self.dpop().get_current_thumbprint());

            let effective_endpoint = self.effective_token_endpoint(http_client.uses_mtls());
            let form = self.build_form(params);

            let raw_token_response: RawTokenResponse = with_dpop_nonce_retry!({
                let auth_params = self
                    .client_auth()
                    .authentication_params(
                        self.client_id(),
                        self.issuer(),
                        effective_endpoint.as_uri(),
                        self.allowed_auth_methods(),
                    )
                    .await
                    .context(AuthSnafu)?;

                OAuth2FormRequest::builder()
                    .auth_params(auth_params)
                    .dpop(self.dpop())
                    .maybe_dpop_jkt(dpop_jkt.as_deref())
                    .form(&form)
                    .uri(effective_endpoint.as_uri())
                    .build()
                    .execute(http_client)
                    .await
                    .context(OAuth2FormSnafu)
            })?;

            raw_token_response
                .into_token_response(dpop_jkt, crate::core::platform::SystemTime::now())
                .context(InvalidTokenResponseSnafu)
        }
    }

    /// Creates a refresh grant from this grant's configuration.
    fn to_refresh_grant(&self) -> RefreshGrant<Self::ClientAuth, Self::DPoP>;
}

/// Errors that can occur when making a token request.
#[derive(Debug, Snafu)]
pub enum OAuth2ExchangeGrantError<
    HttpReqErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
    AuthErr: crate::core::Error,
    DPoPErr: crate::core::Error,
> {
    /// There was a failure to get client authentication details.
    Auth {
        /// The underlying error.
        source: AuthErr,
    },
    /// There was a failure to submit the form.
    OAuth2Form {
        /// The underlying error.
        source: OAuth2FormError<HttpReqErr, HttpRespErr, DPoPErr>,
    },
    /// The token response was not valid.
    InvalidTokenResponse {
        /// The underlying error.
        source: InvalidTokenResponse,
    },
}

impl<
    HttpErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
    AuthErr: crate::core::Error,
    DPoPErr: crate::core::Error,
> DPoPNonceError for OAuth2ExchangeGrantError<HttpErr, HttpRespErr, AuthErr, DPoPErr>
{
    fn is_dpop_nonce_required(&self) -> bool {
        matches!(self, Self::OAuth2Form { source } if source.is_dpop_nonce_required())
    }
}

impl<
    HttpErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
    AuthErr: crate::core::Error,
    DPoPErr: crate::core::Error,
> OAuth2ExchangeGrantError<HttpErr, HttpRespErr, AuthErr, DPoPErr>
{
    /// Returns `true` if the server definitively rejected the grant itself with
    /// `invalid_grant` (RFC 6749 §5.2), e.g. a revoked, expired, or otherwise
    /// invalid refresh token or authorization code.
    pub fn is_invalid_grant(&self) -> bool {
        matches!(self, Self::OAuth2Form { source } if source.is_invalid_grant())
    }
}

impl<
    HttpErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
    AuthErr: crate::core::Error,
    DPoPErr: crate::core::Error,
> crate::core::Error for OAuth2ExchangeGrantError<HttpErr, HttpRespErr, AuthErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::Auth { source } => source.is_retryable(),
            Self::OAuth2Form { source } => source.is_retryable(),
            Self::InvalidTokenResponse { source } => source.is_retryable(),
        }
    }
}
