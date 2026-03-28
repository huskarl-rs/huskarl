use std::{convert::Infallible, time::Duration};

use huskarl_core::crypto::signer::{JwsSigner, JwsSignerSelector};

use crate::{
    core::{
        jwt::{JwsSerializationError, Jwt},
        platform::{MaybeSend, MaybeSendSync},
        secrets::SecretString,
    },
    grant::authorization_code::types::AuthorizationPayloadWithClientId,
};

/// Implementation for how to create a JAR (JWT-secured authorization request).
pub trait Jar: MaybeSendSync {
    /// The type of errors that can occur when attempting to create a JAR.
    type Error: crate::core::Error;

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

impl<S: JwsSignerSelector> Jar for S {
    type Error = JwsSerializationError<<S::Signer as JwsSigner>::Error>;

    async fn generate_request_object(
        &self,
        audience: &str,
        authorization_payload: AuthorizationPayloadWithClientId<'_>,
    ) -> Result<Option<SecretString>, Self::Error> {
        Jwt::builder()
            .issuer(authorization_payload.client_id)
            .audience(audience)
            .issued_now_expires_after(Duration::from_mins(1))
            .extra_claims(authorization_payload)
            .build()
            .to_jws_compact(&self.select_signer())
            .await
            .map(Some)
    }
}
