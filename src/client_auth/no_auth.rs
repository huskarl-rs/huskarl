use std::convert::Infallible;

use http::Uri;

use crate::client_auth::{AuthenticationParams, ClientAuthentication};

/// Authentication that only provides the client ID.
///
/// The client may be public, or provide authentication through another mechanism.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuth;

impl ClientAuthentication for NoAuth {
    type Error = Infallible;

    async fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        _audience: Option<&'a str>,
        _token_endpoint: &'a Uri,
        _allowed_methods: Option<&'a [String]>,
    ) -> Result<AuthenticationParams<'a>, Self::Error> {
        Ok(AuthenticationParams::builder()
            .form_params(bon::map! {
                "client_id": client_id
            })
            .build())
    }
}
