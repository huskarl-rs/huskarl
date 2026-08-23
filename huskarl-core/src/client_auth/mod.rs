//! OAuth 2.0 client authentication support.
//!
//! This module includes base types and implementations for different ways
//! clients can authenticate to an authorization server inside the request.
//!
//! Note: mTLS authentication is a transport-level concern, and should be
//! implemented at the HTTP client level. In such cases, the server may not
//! need any credentials inside the request, and [`NoAuth`] authentication
//! may suffice here.

mod client_secret;
mod form_value;
mod jwt_bearer;
mod no_auth;

use std::sync::Arc;

use bon::Builder;
pub use client_secret::{ClientSecret, ClientSecretBuilder};
pub use form_value::FormValue;
use http::HeaderMap;
pub use jwt_bearer::{Audience, JwtBearer, JwtBearerBuilder, MissingIssuer, MissingTokenEndpoint};
pub use no_auth::NoAuth;

use crate::{
    EndpointUrl,
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// Abstracts over client authentication types.
///
/// The client authentication provided here is mixed in with parameters
/// specific to the grant in use when authenticating to the authorization
/// server.
///
/// This trait is dyn-capable: grants store it as
/// `Arc<dyn ClientAuthentication>`.
///
/// # Implementing
///
/// Write the method body as `Box::pin(async move { ... })`. Failures to
/// construct the credentials carry
/// [`RetryAdvice::No`](crate::error::RetryAdvice::No) — the same inputs assemble
/// the same way next time — while a transient failure of an underlying fetch
/// (such as a secret store) retains that fetch's classification.
pub trait ClientAuthentication: MaybeSendSync {
    /// Returns the authentication parameters for the request described by
    /// `ctx` (see [`AuthenticationContext`]).
    fn authentication_context<'a>(
        &'a self,
        ctx: AuthenticationContext<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>>;
}

impl<T: ClientAuthentication + ?Sized> ClientAuthentication for &T {
    fn authentication_context<'a>(
        &'a self,
        ctx: AuthenticationContext<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        (**self).authentication_context(ctx)
    }
}

impl<T: ClientAuthentication + ?Sized> ClientAuthentication for Box<T> {
    fn authentication_context<'a>(
        &'a self,
        ctx: AuthenticationContext<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        (**self).authentication_context(ctx)
    }
}

impl<T: ClientAuthentication + ?Sized> ClientAuthentication for Arc<T> {
    fn authentication_context<'a>(
        &'a self,
        ctx: AuthenticationContext<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        (**self).authentication_context(ctx)
    }
}

/// Everything an authentication method may need to build credentials for one
/// request.
///
/// The endpoints feed the audience of signature-based client assertions: per
/// draft-ietf-oauth-security-topics-update §2.1.2 the safe choices are the
/// issuer (§2.1.2.1) or the exact [`target_endpoint`](Self::target_endpoint)
/// (§2.1.2.2); a [`token_endpoint`](Self::token_endpoint) audience is offered
/// only for legacy servers that demand it, and enables audience-injection
/// attacks (see [`Audience`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Builder)]
pub struct AuthenticationContext<'a> {
    /// The client being authenticated.
    pub client_id: &'a str,
    /// The exact endpoint the request is sent to — the token endpoint for
    /// grant exchanges, but equally the PAR, revocation, or introspection
    /// endpoint.
    pub target_endpoint: &'a EndpointUrl,
    /// The authorization server's issuer identifier, when the caller knows it.
    pub issuer: Option<&'a str>,
    /// The authorization server's token endpoint, when the caller knows it.
    ///
    /// It differs from [`target_endpoint`](Self::target_endpoint) whenever the
    /// request targets some other endpoint, and is `None` where the caller
    /// cannot supply it.
    pub token_endpoint: Option<&'a EndpointUrl>,
    /// The `*_endpoint_auth_methods_supported` metadata for the target
    /// endpoint, when the caller knows it.
    pub allowed_methods: Option<&'a [String]>,
}

/// The authentication credentials that need to be added to the request.
#[non_exhaustive]
#[derive(Debug, Clone, Builder)]
pub struct AuthenticationParams<'a> {
    /// Additional headers to include in the request.
    pub headers: Option<HeaderMap>,
    /// Additional form parameters to include in the request body.
    pub form_params: Option<Vec<(&'a str, FormValue<'a>)>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn erased_authentication_dispatches() {
        let auth: Arc<dyn ClientAuthentication> = Arc::new(NoAuth);
        let uri: EndpointUrl = "https://as.example/token".parse().unwrap();
        let params = auth
            .authentication_context(
                AuthenticationContext::builder()
                    .client_id("my-client")
                    .target_endpoint(&uri)
                    .token_endpoint(&uri)
                    .build(),
            )
            .await
            .expect("no_auth never fails");
        let form = params.form_params.expect("client_id form param");
        assert!(form.iter().any(|(k, _)| *k == "client_id"));
    }
}
