//! Token revocation (RFC 7009).
//!
//! Provides the ability to revoke access tokens and refresh tokens at an
//! authorization server's revocation endpoint.

use std::borrow::Cow;
use std::convert::Infallible;

use bon::Builder;
use serde::Serialize;
use snafu::prelude::*;

use crate::{
    EndpointUrl, IntoEndpointUrl,
    client_auth::ClientAuthentication,
    dpop::NoDPoP,
    grant::core::form::{OAuth2FormError, OAuth2FormRequest},
    http::{HttpClient, HttpResponse},
    server_metadata::AuthorizationServerMetadata,
    token::{AccessToken, RefreshToken},
};

/// A token that can be revoked.
pub trait RevocableToken {
    /// Returns the token value.
    fn token_value(&self) -> &str;

    /// Returns the token type hint as defined in RFC 7009 §2.1.
    fn token_type_hint(&self) -> &'static str;
}

impl RevocableToken for AccessToken {
    fn token_value(&self) -> &str {
        self.expose_token()
    }

    fn token_type_hint(&self) -> &'static str {
        "access_token"
    }
}

impl RevocableToken for RefreshToken {
    fn token_value(&self) -> &str {
        self.expose_token()
    }

    fn token_type_hint(&self) -> &'static str {
        "refresh_token"
    }
}

/// Implementation of token revocation.
#[derive(Debug, Clone, Builder)]
#[builder(state_mod(name = "builder"))]
pub struct TokenRevocation<Auth: ClientAuthentication + 'static> {
    // -- User-supplied fields --
    /// The client ID.
    #[builder(into)]
    client_id: Cow<'static, str>,

    /// The client authentication method.
    client_auth: Auth,

    // -- Metadata fields --
    /// The issuer for tokens created by the authorization server.
    #[builder(into)]
    issuer: Option<String>,

    /// The URL of the revocation endpoint.
    #[builder(setters(name = "revocation_endpoint_url"))]
    revocation_endpoint: EndpointUrl,

    /// Supported endpoint auth methods (RFC 8414).
    revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication + 'static> TokenRevocation<Auth> {
    /// Fills builder parameters relevant to revocation from authorization server metadata.
    ///
    /// Returns an `Option` if the revocation endoint is not included in metadata.
    #[allow(clippy::type_complexity)]
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        TokenRevocationBuilder<
            Auth,
            builder::SetRevocationEndpointAuthMethodsSupported<
                builder::SetRevocationEndpoint<builder::SetIssuer<builder::Empty>>,
            >,
        >,
    > {
        let revocation_endpoint = metadata.revocation_endpoint.clone()?;

        Some(
            Self::builder()
                .issuer(metadata.issuer.clone())
                .revocation_endpoint_url(revocation_endpoint)
                .revocation_endpoint_auth_methods_supported(
                    metadata.revocation_endpoint_auth_methods_supported.clone(),
                ),
        )
    }

    /// Revoke a token at the authorization server's revocation endpoint.
    ///
    /// Sends a POST request to the revocation endpoint with the token and
    /// a token type hint. Per RFC 7009, the server returns 200 OK
    /// with an empty body on success.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationError::Auth`] if client authentication fails, or
    /// [`RevocationError::Revocation`] if the HTTP request or server response fails.
    pub async fn revoke<C: HttpClient>(
        &self,
        http_client: &C,
        token: &impl RevocableToken,
    ) -> Result<
        (),
        RevocationError<
            C::Error,
            <C::Response as HttpResponse>::Error,
            <Auth as ClientAuthentication>::Error,
        >,
    > {
        let auth_params = self
            .client_auth
            .authentication_params(
                &self.client_id,
                self.issuer.as_deref(),
                self.revocation_endpoint.as_uri(),
                self.revocation_endpoint_auth_methods_supported.as_deref(),
            )
            .await
            .context(AuthSnafu)?;

        let form = RevocationForm {
            token: token.token_value(),
            token_type_hint: token.token_type_hint(),
        };

        OAuth2FormRequest::builder()
            .auth_params(auth_params)
            .form(&form)
            .uri(self.revocation_endpoint.as_uri())
            .dpop(&NoDPoP)
            .build()
            .execute_empty_response(http_client)
            .await
            .context(RevocationSnafu)?;

        Ok(())
    }
}

impl<Auth: ClientAuthentication, S: builder::State> TokenRevocationBuilder<Auth, S> {
    /// Sets the revocation endpoint URL.
    ///
    /// Accepts any type that implements [`IntoEndpointUrl`], including
    /// `&str`, [`String`], [`Url`](url::Url), [`Uri`](http::Uri), and
    /// [`EndpointUrl`].
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed as a valid URI.
    pub fn revocation_endpoint<U: IntoEndpointUrl>(
        self,
        url: U,
    ) -> Result<TokenRevocationBuilder<Auth, builder::SetRevocationEndpoint<S>>, U::Error>
    where
        S::RevocationEndpoint: builder::IsUnset,
    {
        Ok(self.revocation_endpoint_url(url.into_endpoint_url()?))
    }
}

#[derive(Debug, Serialize)]
struct RevocationForm<'a> {
    token: &'a str,
    token_type_hint: &'static str,
}

/// Errors that can occur when revoking a token.
#[derive(Debug, Snafu)]
pub enum RevocationError<HttpReqErr: crate::Error, HttpRespErr: crate::Error, AuthErr: crate::Error>
{
    /// An error occurred during client authentication.
    Auth {
        /// The underlying error.
        source: AuthErr,
    },
    /// An error occurred during the revocation request.
    Revocation {
        /// The underlying error.
        source: OAuth2FormError<HttpReqErr, HttpRespErr, Infallible>,
    },
}

impl<HttpReqErr: crate::Error, HttpRespErr: crate::Error, AuthErr: crate::Error> crate::Error
    for RevocationError<HttpReqErr, HttpRespErr, AuthErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::Auth { source } => source.is_retryable(),
            Self::Revocation { source } => source.is_retryable(),
        }
    }
}
