use crate::{
    EndpointUrl,
    client_auth::{AuthenticationParams, ClientAuthentication},
    error::Error,
    platform::MaybeSendBoxFuture,
};

/// Authentication that only provides the client ID.
///
/// The client may be public, or provide authentication through another mechanism.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuth;

impl ClientAuthentication for NoAuth {
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        _issuer: Option<&'a str>,
        _token_endpoint: Option<&'a EndpointUrl>,
        _target_endpoint: &'a EndpointUrl,
        _allowed_methods: Option<&'a [String]>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        Box::pin(async move {
            Ok(AuthenticationParams::builder()
                .form_params(bon::map! {
                    "client_id": client_id
                })
                .build())
        })
    }
}
