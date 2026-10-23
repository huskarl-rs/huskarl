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
/// produce that object. [`NoJar`] disables JAR; a signer can be used directly
/// with the timestamp supplied by the grant.
///
/// This trait is dyn-capable: grants store it as `Arc<dyn Jar>`. Implement it
/// with a `Box::pin(async move { ... })` method body.
pub trait Jar: MaybeSendSync {
    /// Generates the JAR request object using the implementation's clock.
    fn generate_request_object<'a>(
        &'a self,
        audience: &'a str,
        authorization_payload: AuthorizationPayloadWithClientId<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>>;

    /// Uses the supplied timestamp when supported; legacy implementations use their own clock.
    fn generate_request_object_at<'a>(
        &'a self,
        audience: &'a str,
        authorization_payload: AuthorizationPayloadWithClientId<'a>,
        _now: jiff::Timestamp,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        // TODO(next breaking release): require timestamp-aware implementations.
        self.generate_request_object(audience, authorization_payload)
    }
}

/// A [`Jar`] that produces no request object — the default, with JAR disabled.
#[derive(Debug, Clone, Copy)]
pub struct NoJar;

impl Jar for NoJar {
    fn generate_request_object<'a>(
        &'a self,
        audience: &'a str,
        authorization_payload: AuthorizationPayloadWithClientId<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        self.generate_request_object_at(
            audience,
            authorization_payload,
            crate::core::time::Clock::now(&crate::core::time::PlatformClock),
        )
    }

    fn generate_request_object_at<'a>(
        &'a self,
        _audience: &'a str,
        _authorization_payload: AuthorizationPayloadWithClientId<'a>,
        _now: jiff::Timestamp,
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
        self.generate_request_object_at(
            audience,
            authorization_payload,
            crate::core::time::Clock::now(&crate::core::time::PlatformClock),
        )
    }

    fn generate_request_object_at<'a>(
        &'a self,
        audience: &'a str,
        authorization_payload: AuthorizationPayloadWithClientId<'a>,
        now: jiff::Timestamp,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        Box::pin(sign_request_object(
            self,
            now,
            audience,
            authorization_payload,
        ))
    }
}

async fn sign_request_object(
    signer: &impl JwsSignerSelector,
    now: jiff::Timestamp,
    audience: &str,
    authorization_payload: AuthorizationPayloadWithClientId<'_>,
) -> Result<Option<SecretString>, Error> {
    Jwt::builder()
        .typ("oauth-authz-req+jwt")
        .iss(authorization_payload.client_id)
        .audience(audience)
        .issued_at_not_before_expires_after(
            huskarl_core::time::system_time_from_timestamp_saturating(now),
            Duration::from_mins(1),
        )
        .claims(authorization_payload)
        .build()
        .to_jws_compact(signer.select_signer().await.as_ref())
        .await
        .map(Some)
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use crate::grant::authorization_code::types::AuthorizationPayload;

    struct LegacyJar;
    impl Jar for LegacyJar {
        fn generate_request_object<'a>(
            &'a self,
            audience: &'a str,
            _payload: AuthorizationPayloadWithClientId<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
            Box::pin(async move { Ok(Some(SecretString::new(audience))) })
        }
    }

    #[tokio::test]
    async fn timestamp_hook_calls_legacy_implementation() {
        let payload = AuthorizationPayloadWithClientId {
            client_id: "client",
            rest: AuthorizationPayload {
                response_type: "code",
                redirect_uri: "https://client.example/callback",
                state: "state",
                scope: None,
                code_challenge: None,
                code_challenge_method: None,
                dpop_jkt: None,
                nonce: None,
                response_mode: None,
                display: None,
                prompt: None,
                max_age: None,
                ui_locales: None,
                id_token_hint: None,
                login_hint: None,
                acr_values: None,
                resource: None,
                authorization_details: None,
            },
        };
        let jar: &dyn Jar = &LegacyJar;
        let result = jar
            .generate_request_object_at("audience", payload, jiff::Timestamp::UNIX_EPOCH)
            .await
            .unwrap();
        assert_eq!(result.unwrap().expose_secret(), "audience");
    }
}
