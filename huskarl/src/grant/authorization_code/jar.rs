use std::time::Duration;

use crate::{
    core::{
        Error,
        crypto::signer::JwsSignerSelector,
        jwt::Jwt,
        platform::{MaybeSendBoxFuture, MaybeSendSync},
        secrets::SecretString,
    },
    grant::authorization_code::types::AuthorizationPayloadWithClientId,
};

/// Implementation for how to create a JAR (JWT-secured authorization request).
///
/// This trait is dyn-capable: grants store it as `Arc<dyn Jar>`. Implement it
/// with a `Box::pin(async move { ... })` method body.
pub trait Jar: MaybeSendSync {
    /// Generates the JAR request object.
    fn generate_request_object<'a>(
        &'a self,
        audience: &'a str,
        authorization_payload: AuthorizationPayloadWithClientId<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>>;
}

/// An implementation of the Jar trait that indicates an inability to create a JAR request.
#[derive(Debug, Clone, Copy)]
pub struct NoJar;

impl Jar for NoJar {
    fn generate_request_object<'a>(
        &'a self,
        _audience: &'a str,
        _authorization_payload: AuthorizationPayloadWithClientId<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        Box::pin(async { Ok(None) })
    }
}

impl<S: JwsSignerSelector> Jar for S {
    fn generate_request_object<'a>(
        &'a self,
        audience: &'a str,
        authorization_payload: AuthorizationPayloadWithClientId<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        Box::pin(async move {
            Jwt::builder()
                .typ("oauth-authz-req+jwt")
                .issuer(authorization_payload.client_id)
                .audience(audience)
                .issued_now_not_before_now_expires_after(Duration::from_mins(1))
                .claims(authorization_payload)
                .build()
                .to_jws_compact(self.select_signer().as_ref())
                .await
                .map(Some)
        })
    }
}
