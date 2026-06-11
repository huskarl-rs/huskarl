use serde::Serialize;

use crate::{
    core::{
        EndpointUrl, Error, ErrorKind,
        client_auth::{AuthenticationParams, ClientAuthentication},
        dpop::AuthorizationServerDPoP,
        http::HttpClient,
        platform::{MaybeSend, MaybeSendSync},
    },
    grant::{
        core::{
            form::{OAuth2FormRequest, with_dpop_nonce_retry},
            token_response::{RawTokenResponse, TokenResponse},
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

    /// The request body.
    type Form<'a>: MaybeSendSync + Serialize
    where
        Self: 'a;

    /// Whether [`Self::Parameters`] may safely be submitted more than once.
    ///
    /// `false` for grants whose parameters contain single-use credentials —
    /// an authorization code (RFC 6749 §4.1.2), a device code, or a possibly
    /// rotating refresh token. Replaying those not only fails but may cause
    /// the authorization server to revoke tokens already issued for them.
    /// [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache) consumes such
    /// parameters on first use instead of replaying them after a failed refresh.
    fn reusable_parameters(&self) -> bool {
        false
    }

    /// Returns the configured client ID.
    fn client_id(&self) -> &str;

    /// Returns the configured issuer.
    fn issuer(&self) -> Option<&str>;

    /// Returns the configured client auth.
    fn client_auth(&self) -> &dyn ClientAuthentication;

    /// Returns the bound `DPoP` thumbprint for the session.
    ///
    /// Often bound for authorization code grants or refresh grants.
    fn bound_dpop_jkt(_params: &Self::Parameters) -> Option<&str> {
        None
    }

    /// Returns the token endpoint URL used for token requests.
    ///
    /// Already resolved at grant build time to the RFC 8705 §5 mTLS alias
    /// when the grant's HTTP client uses mTLS.
    fn token_endpoint(&self) -> &EndpointUrl;

    /// Returns the configured `DPoP` implementation (if any).
    fn dpop(&self) -> &dyn AuthorizationServerDPoP;

    /// Returns the HTTP client used for token requests.
    fn http_client(&self) -> &dyn HttpClient;

    /// Builds the body for the request.
    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_>;

    /// Returns allowed authentication methods (formatted as in authorization server metadata).
    fn allowed_auth_methods(&self) -> Option<&[String]>;

    /// Returns the authentication parameters for this grant.
    fn authentication_params(
        &self,
    ) -> impl Future<Output = Result<AuthenticationParams<'_>, Error>> + MaybeSend {
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
    fn exchange(
        &self,
        params: Self::Parameters,
    ) -> impl Future<Output = Result<TokenResponse, Error>> + MaybeSend {
        async move {
            let dpop_jkt = Self::bound_dpop_jkt(&params)
                .map(ToString::to_string)
                .or_else(|| self.dpop().get_current_thumbprint());

            let http_client = self.http_client();
            let endpoint = self.token_endpoint();
            let form = self.build_form(params);

            let raw_token_response: RawTokenResponse = with_dpop_nonce_retry!({
                let auth_params = self
                    .client_auth()
                    .authentication_params(
                        self.client_id(),
                        self.issuer(),
                        endpoint.as_uri(),
                        self.allowed_auth_methods(),
                    )
                    .await?;

                OAuth2FormRequest::builder()
                    .auth_params(auth_params)
                    .dpop(self.dpop())
                    .maybe_dpop_jkt(dpop_jkt.as_deref())
                    .form(&form)
                    .uri(endpoint.as_uri())
                    .build()
                    .execute(http_client)
                    .await
            })?;

            raw_token_response
                .into_token_response(dpop_jkt, crate::core::platform::SystemTime::now())
                .map_err(|source| Error::new(ErrorKind::Protocol, source))
        }
    }

    /// Creates a refresh grant from this grant's configuration.
    fn to_refresh_grant(&self) -> RefreshGrant;
}
