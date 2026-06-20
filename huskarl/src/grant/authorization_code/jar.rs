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

/// Produces a JWT-secured authorization request (JAR, RFC 9101) object.
///
/// With JAR, the initial authorization-request parameters are signed into a JWT
/// — the *request object* — instead of being sent as plain URL query parameters,
/// adding authenticity (the request demonstrably comes from the client) and
/// integrity (it cannot be tampered with in transit). Implement this trait to
/// produce that object; the only built-in is [`NoJar`], the default, which
/// produces none.
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

/// A [`Jar`] that produces no request object — the default, with JAR disabled.
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
