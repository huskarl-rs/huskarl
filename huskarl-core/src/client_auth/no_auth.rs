use crate::{
    client_auth::{AuthenticationContext, AuthenticationParams, ClientAuthentication},
    error::Error,
    platform::MaybeSendBoxFuture,
};

/// Authentication that only provides the client ID.
///
/// The client may be public, or provide authentication through another mechanism.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuth;

impl ClientAuthentication for NoAuth {
    fn authentication_context<'a>(
        &'a self,
        ctx: AuthenticationContext<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        Box::pin(async move {
            Ok(AuthenticationParams::builder()
                .form_params(bon::map! {
                    "client_id": ctx.client_id
                })
                .build())
        })
    }
}
