use std::{convert::Infallible, time::Duration};

use secrecy::SecretString;

use crate::{
    grant::authorization_code::types::AuthorizationPayloadWithClientId,
    jwt::{JwsSerializationError, Jwt},
    platform::{MaybeSend, MaybeSendSync},
    prelude::JwsSigningKey,
};

/// Implementation for how to create a JAR (JWT-secured authorization request).
pub trait Jar: MaybeSendSync {
    /// The type of errors that can occur when attempting to create a JAR.
    type Error: crate::Error;

    /// Generates the JAR request object.
    fn generate_request_object(
        &self,
        audience: &str,
        authorization_payload: AuthorizationPayloadWithClientId<'_>,
    ) -> impl Future<Output = Result<Option<SecretString>, Self::Error>> + MaybeSend;
}

/// An implementation of the Jar trait that indicates an inability to create a JAR request.
#[derive(Debug, Clone, Copy)]
pub struct NoJar;

impl Jar for NoJar {
    type Error = Infallible;

    async fn generate_request_object(
        &self,
        _audience: &str,
        _authorization_payload: AuthorizationPayloadWithClientId<'_>,
    ) -> Result<Option<SecretString>, Self::Error> {
        Ok(None)
    }
}

impl<S: JwsSigningKey> Jar for S {
    type Error = JwsSerializationError<<S as JwsSigningKey>::Error>;

    async fn generate_request_object(
        &self,
        audience: &str,
        authorization_payload: AuthorizationPayloadWithClientId<'_>,
    ) -> Result<Option<SecretString>, Self::Error> {
        Jwt::<(), AuthorizationPayloadWithClientId>::builder()
            .issuer(authorization_payload.client_id)
            .audience(audience)
            .issued_now_expires_after(Duration::from_mins(1))
            .extra_claims(authorization_payload)
            .build()
            .to_jws_compact(self)
            .await
            .map(Some)
    }
}
