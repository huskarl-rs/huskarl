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

/// The core trait every grant implements: exchanges grant-specific parameters
/// for a token at the token endpoint.
///
/// Most methods are accessors the built-in [`exchange`](Self::exchange)
/// machinery reads — client identity and authentication, the token endpoint,
/// the `DPoP` binding, and how to build the request body. Implement it to add a
/// grant this crate does not ship; application code calls
/// [`exchange`](Self::exchange) (or hands the grant to a
/// [`GrantTokenSource`](crate::cache::GrantTokenSource)) rather than the
/// accessors directly.
pub trait OAuth2ExchangeGrant: MaybeSendSync {
    /// Parameters exchanged when making the token request.
    type Parameters: Clone + MaybeSendSync;

    /// The request body.
    type Form<'a>: MaybeSendSync + Serialize
    where
        Self: 'a;

    /// Returns the configured client ID, if the client is identified.
    ///
    /// `None` for a grant that presents no client identification (e.g. an
    /// anonymous JWT bearer or token exchange request).
    fn client_id(&self) -> Option<&str>;

    /// Returns the configured issuer.
    fn issuer(&self) -> Option<&str>;

    /// Returns the configured client auth, if the client authenticates.
    ///
    /// `None` for a grant that does not authenticate the client to the token
    /// endpoint. The grant carries its own authorization (an assertion or an
    /// existing token), so client authentication is an independent, optional
    /// concern (RFC 7523 §3.1, RFC 8693 §2).
    fn client_auth(&self) -> Option<&dyn ClientAuthentication>;

    /// Returns the bound `DPoP` thumbprint for the session.
    ///
    /// Often bound for authorization code grants or refresh grants.
    fn bound_dpop_jkt(_params: &Self::Parameters) -> Option<&str> {
        None
    }

    /// Returns the token endpoint URL as published in authorization server
    /// metadata.
    ///
    /// This is the authorization server's canonical token endpoint, before any
    /// RFC 8705 §5 mTLS-alias resolution, and the audience for
    /// [`Audience::TokenEndpoint`] client assertions — which identify the
    /// authorization server by its token endpoint rather than the
    /// (possibly mTLS-aliased) endpoint actually contacted.
    ///
    /// [`Audience::TokenEndpoint`]: crate::core::client_auth::Audience::TokenEndpoint
    fn token_endpoint(&self) -> &EndpointUrl;

    /// Returns the endpoint that token requests are actually sent to.
    ///
    /// This is [`Self::token_endpoint`] resolved to the RFC 8705 §5 mTLS alias
    /// when the grant's HTTP client uses mTLS, and so the `target_endpoint` for
    /// client authentication (see [`Audience::TargetEndpoint`]). Defaults to
    /// [`Self::token_endpoint`]; grants that resolve an mTLS alias override it.
    ///
    /// [`Audience::TargetEndpoint`]: crate::core::client_auth::Audience::TargetEndpoint
    fn effective_token_endpoint(&self) -> &EndpointUrl {
        self.token_endpoint()
    }

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
            // No client authentication: present nothing (no credentials, and no
            // `client_id`). The grant's own authorization stands on its own.
            let Some(client_auth) = self.client_auth() else {
                return Ok(AuthenticationParams::builder().build());
            };
            // Every authentication method identifies the client, so it needs a
            // client ID (e.g. the basic-auth username, or the assertion subject).
            let client_id = self.client_id().ok_or_else(|| {
                Error::new(
                    ErrorKind::Auth,
                    "client authentication requires a client ID",
                )
            })?;
            client_auth
                .authentication_params(
                    client_id,
                    self.issuer(),
                    Some(self.token_endpoint()),
                    self.effective_token_endpoint(),
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
            let endpoint = self.effective_token_endpoint();
            let form = self.build_form(params);

            let raw_token_response: RawTokenResponse = with_dpop_nonce_retry!({
                let auth_params = self.authentication_params().await?;

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
