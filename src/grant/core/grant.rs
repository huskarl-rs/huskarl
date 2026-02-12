use http::Uri;
use serde::Serialize;
use snafu::prelude::*;
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::AuthorizationServerDPoP,
    grant::core::{
        form::{OAuth2FormError, OAuth2FormRequest},
        token_response::TokenResponse,
    },
    http::{HttpClient, HttpResponse},
    platform::{MaybeSend, MaybeSendSync},
};

/// An OAuth2 exchange grant.
///
/// This represents an OAuth2 grant implementation. It provides
/// the ability of the grant to provide features like parameters,
/// authentication, its DPoP configuration, and so forth.
pub trait OAuth2ExchangeGrant: MaybeSendSync {
    /// Parameters exchanged when making the token request.
    type Parameters: MaybeSendSync;

    /// The client credentials used when making token request.
    type ClientAuth: ClientAuthentication + 'static;

    /// The proof implementation used when adding a `DPoP` token binding.
    type DPoP: AuthorizationServerDPoP + 'static;

    /// The request body.
    type Form<'a>: MaybeSendSync + Serialize
    where
        Self: 'a;

    /// Returns the configured client ID.
    fn client_id(&self) -> &str;

    /// Returns the configured client auth.
    fn client_auth(&self) -> &Self::ClientAuth;

    /// Returns the token endpoint URL.
    fn token_endpoint(&self) -> &Url;

    /// Returns the configured `DPoP` implementation (if any).
    fn dpop(&self) -> Option<&Self::DPoP>;

    /// Builds the body for the request.
    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_>;

    /// Returns the refresh grant corresponding to this grant.
    // fn refresh_grant(&self) -> refresh::Grant<Self::ClientAuth, Self::DPoP>;

    /// Returns allowed authentication methods (formatted as in authorization server metadata).
    fn allowed_auth_methods(&self) -> Option<&[String]>;

    /// Exchange the parameters for an access token.
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
            let auth_params = self
                .client_auth()
                .authentication_params(
                    self.client_id(),
                    self.token_endpoint(),
                    self.allowed_auth_methods(),
                )
                .await
                .context(AuthSnafu)?;

            let form = self.build_form(params);

            let token_response = OAuth2FormRequest::builder()
                .auth_params(auth_params)
                .maybe_dpop(self.dpop())
                .form(&form)
                .uri(
                    self.token_endpoint()
                        .to_string()
                        .parse::<Uri>()
                        .context(InvalidUriSnafu)?,
                )
                .build()
                .execute(http_client)
                .await
                .context(OAuth2FormSnafu)?;

            Ok(token_response)
        }
    }
}

#[derive(Debug, Snafu)]
pub enum OAuth2ExchangeGrantError<
    HttpReqErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    AuthErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> {
    Auth {
        source: AuthErr,
    },
    InvalidUri {
        source: http::uri::InvalidUri,
    },
    OAuth2Form {
        source: OAuth2FormError<HttpReqErr, HttpRespErr, DPoPErr>,
    },
}

impl<
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    AuthErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> crate::Error for OAuth2ExchangeGrantError<HttpErr, HttpRespErr, AuthErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::Auth { source } => source.is_retryable(),
            Self::InvalidUri { .. } => false,
            Self::OAuth2Form { source } => source.is_retryable(),
        }
    }
}
