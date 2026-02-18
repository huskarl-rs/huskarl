use std::borrow::Cow;

use serde::Serialize;
use snafu::prelude::*;

use crate::client_auth::AuthenticationParams;
use crate::grant::refresh::RefreshGrant;
use crate::{
    EndpointUrl,
    client_auth::ClientAuthentication,
    dpop::AuthorizationServerDPoP,
    grant::core::{
        form::{OAuth2FormError, OAuth2FormRequest},
        token_response::TokenResponse,
    },
    http::{HttpClient, HttpResponse},
    platform::{MaybeSend, MaybeSendSync},
};

/// An `OAuth2` exchange grant.
///
/// This represents an `OAuth2` grant implementation. It provides
/// the ability of the grant to provide features like parameters,
/// authentication, its `DPoP` configuration, and so forth.
pub trait OAuth2ExchangeGrant: MaybeSendSync {
    /// Parameters exchanged when making the token request.
    type Parameters: MaybeSendSync;

    /// The client credentials used when making the token request.
    type ClientAuth: ClientAuthentication + 'static;

    /// The proof implementation used when adding a `DPoP` token binding.
    type DPoP: AuthorizationServerDPoP + 'static;

    /// The request body.
    type Form<'a>: MaybeSendSync + Serialize
    where
        Self: 'a;

    /// Returns the configured client ID.
    fn client_id(&self) -> &Cow<'static, str>;

    /// Returns the configured issuer.
    fn issuer(&self) -> Option<&str>;

    /// Returns the configured client auth.
    fn client_auth(&self) -> &Self::ClientAuth;

    /// Returns the token endpoint URL.
    fn token_endpoint(&self) -> &EndpointUrl;

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
    #[allow(clippy::type_complexity)]
    fn exchange<C: HttpClient>(
        &self,
        http_client: &C,
        params: Self::Parameters,
    ) -> impl Future<
        Output = Result<
            TokenResponse,
            OAuth2ExchangeGrantError<
                C::Error,
                <C::Response as HttpResponse>::Error,
                <Self::ClientAuth as ClientAuthentication>::Error,
                <Self::DPoP as AuthorizationServerDPoP>::Error,
            >,
        >,
    > + MaybeSend {
        async {
            let auth_params = self.authentication_params().await.context(AuthSnafu)?;
            let form = self.build_form(params);

            let token_response = OAuth2FormRequest::builder()
                .auth_params(auth_params)
                .dpop(self.dpop())
                .form(&form)
                .uri(self.token_endpoint().as_uri())
                .build()
                .execute(http_client)
                .await
                .context(OAuth2FormSnafu)?;

            Ok(token_response)
        }
    }
}

/// A refreshable grant.
///
/// This represents the ability to obtain a refresh grant that can
/// refresh the refresh tokens acquired by this grant.
pub trait RefreshableGrant: MaybeSendSync {
    /// The client credentials used when making the token request.
    type ClientAuth: ClientAuthentication + 'static;

    /// The proof implementation used when adding a `DPoP` token binding.
    type DPoP: AuthorizationServerDPoP + 'static;

    /// Returns the refresh grant corresponding to this grant.
    fn to_refresh_grant(&self) -> RefreshGrant<Self::ClientAuth, Self::DPoP>;
}

/// Errors that can occur when making a token request.
#[derive(Debug, Snafu)]
pub enum OAuth2ExchangeGrantError<
    HttpReqErr: crate::Error,
    HttpRespErr: crate::Error,
    AuthErr: crate::Error,
    DPoPErr: crate::Error,
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
}

impl<HttpErr: crate::Error, HttpRespErr: crate::Error, AuthErr: crate::Error, DPoPErr: crate::Error>
    crate::Error for OAuth2ExchangeGrantError<HttpErr, HttpRespErr, AuthErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::Auth { source } => source.is_retryable(),
            Self::OAuth2Form { source } => source.is_retryable(),
        }
    }
}
