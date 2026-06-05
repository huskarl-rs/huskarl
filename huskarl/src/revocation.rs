//! Token revocation (RFC 7009).
//!
//! Provides the ability to revoke access tokens and refresh tokens at an
//! authorization server's revocation endpoint.

use std::borrow::Cow;

use bon::Builder;
use serde::Serialize;
use snafu::prelude::*;

use crate::{
    core::{
        EndpointUrl,
        client_auth::ClientAuthentication,
        dpop::{DPoPNotConfigured, NoDPoP},
        http::HttpClient,
    },
    grant::core::form::{OAuth2FormError, OAuth2FormRequest},
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
        self.token().expose_secret()
    }

    fn token_type_hint(&self) -> &'static str {
        "access_token"
    }
}

impl RevocableToken for RefreshToken {
    fn token_value(&self) -> &str {
        self.token().expose_secret()
    }

    fn token_type_hint(&self) -> &'static str {
        "refresh_token"
    }
}

/// Implementation of token revocation.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[huskarl_macros::try_builder]
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
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The URL of the revocation endpoint.
    #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
    #[from_metadata(path = "revocation_endpoint?")]
    revocation_endpoint: EndpointUrl,

    /// The mTLS alias for the revocation endpoint (RFC 8705 §5).
    #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
    #[from_metadata(path = "mtls_endpoint_aliases?.revocation_endpoint?")]
    mtls_revocation_endpoint: Option<EndpointUrl>,

    /// Supported endpoint auth methods (RFC 8414).
    #[from_metadata(path = "revocation_endpoint_auth_methods_supported")]
    revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication + 'static> TokenRevocation<Auth> {
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
        RevocationError<C::Error, C::ResponseError, <Auth as ClientAuthentication>::Error>,
    > {
        let effective_endpoint = if http_client.uses_mtls() {
            self.mtls_revocation_endpoint
                .as_ref()
                .unwrap_or(&self.revocation_endpoint)
        } else {
            &self.revocation_endpoint
        };

        let auth_params = self
            .client_auth
            .authentication_params(
                &self.client_id,
                self.issuer.as_deref(),
                effective_endpoint.as_uri(),
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
            .uri(effective_endpoint.as_uri())
            .dpop(&NoDPoP)
            .build()
            .execute_empty_response(http_client)
            .await
            .context(RevocationSnafu)?;

        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct RevocationForm<'a> {
    token: &'a str,
    token_type_hint: &'static str,
}

/// Errors that can occur when revoking a token.
#[derive(Debug, Snafu)]
pub enum RevocationError<
    HttpReqErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
    AuthErr: crate::core::Error,
> {
    /// An error occurred during client authentication.
    Auth {
        /// The underlying error.
        source: AuthErr,
    },
    /// An error occurred during the revocation request.
    Revocation {
        /// The underlying error.
        source: OAuth2FormError<HttpReqErr, HttpRespErr, DPoPNotConfigured>,
    },
}

impl<HttpReqErr: crate::core::Error, HttpRespErr: crate::core::Error, AuthErr: crate::core::Error>
    crate::core::Error for RevocationError<HttpReqErr, HttpRespErr, AuthErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::Auth { source } => source.is_retryable(),
            Self::Revocation { source } => source.is_retryable(),
        }
    }
}
