//! `OAuth2` client authentication support.
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
pub use client_secret::ClientSecret;
pub use form_value::FormValue;
use http::{HeaderMap, Uri};
pub use jwt_bearer::{Audience, JwtBearer, JwtBearerBuilder};
pub use no_auth::NoAuth;

use crate::{
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
/// construct the credentials classify as
/// [`ErrorKind::Auth`](crate::error::ErrorKind::Auth); transient failures of
/// an underlying fetch (e.g. a secret store) as
/// [`ErrorKind::Transport`](crate::error::ErrorKind::Transport).
pub trait ClientAuthentication: MaybeSendSync {
    /// Returns the authentication parameters for the token request.
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        issuer: Option<&'a str>,
        token_endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>>;
}

impl<T: ClientAuthentication + ?Sized> ClientAuthentication for &T {
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        issuer: Option<&'a str>,
        token_endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        (**self).authentication_params(client_id, issuer, token_endpoint, allowed_methods)
    }
}

impl<T: ClientAuthentication + ?Sized> ClientAuthentication for Box<T> {
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        issuer: Option<&'a str>,
        token_endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        (**self).authentication_params(client_id, issuer, token_endpoint, allowed_methods)
    }
}

impl<T: ClientAuthentication + ?Sized> ClientAuthentication for Arc<T> {
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        issuer: Option<&'a str>,
        token_endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        (**self).authentication_params(client_id, issuer, token_endpoint, allowed_methods)
    }
}

/// The authentication credentials that need to be added to the request.
#[non_exhaustive]
#[derive(Debug, Clone, Builder)]
pub struct AuthenticationParams<'a> {
    /// Additional headers to include in the request.
    pub headers: Option<HeaderMap>,
    /// Additional form parameters to include in the request body.
    pub form_params: Option<Vec<(&'static str, FormValue<'a>)>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn erased_authentication_dispatches() {
        let auth: Arc<dyn ClientAuthentication> = Arc::new(NoAuth);
        let uri = Uri::from_static("https://as.example/token");
        let params = auth
            .authentication_params("my-client", None, &uri, None)
            .await
            .expect("no_auth never fails");
        let form = params.form_params.expect("client_id form param");
        assert!(form.iter().any(|(k, _)| *k == "client_id"));
    }
}
