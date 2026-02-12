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
mod no_auth;

use std::{borrow::Cow, sync::Arc};

use bon::Builder;
use http::{HeaderMap, Uri};

use crate::platform::{MaybeSend, MaybeSendSync};

pub use client_secret::{ClientSecret, ClientSecretError};
pub use form_value::FormValue;
pub use no_auth::NoAuth;

/// Abstracts over client authentication types.
///
/// The client authentication provided here is mixed in with parameters
/// specific to the grant in use when authenticating to the authorization
/// server.
pub trait ClientAuthentication: MaybeSendSync {
    /// The error type that may be returned during authentication.
    type Error: crate::Error;

    /// Returns the authentication parameters for the token request.
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        token_endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> impl Future<Output = Result<AuthenticationParams<'a>, Self::Error>> + MaybeSend;
}

impl<Auth: ClientAuthentication> ClientAuthentication for Arc<Auth> {
    type Error = Auth::Error;

    async fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        token_endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> Result<AuthenticationParams<'a>, Self::Error> {
        self.as_ref()
            .authentication_params(client_id, token_endpoint, allowed_methods)
            .await
    }
}

/// The authentication credentials that need to be added to the request.
#[derive(Debug, Clone, Builder)]
pub struct AuthenticationParams<'a> {
    /// Additional headers to include in the request.
    pub headers: Option<Cow<'a, HeaderMap>>,
    /// Additional form parameters to include in the request body.
    pub form_params: Option<Vec<(&'static str, FormValue<'a>)>>,
}
