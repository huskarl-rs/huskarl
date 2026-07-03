use std::{sync::Arc, time::Duration};

use bon::Builder;
use snafu::Snafu;

use crate::{
    EndpointUrl,
    client_auth::{AuthenticationParams, ClientAuthentication},
    crypto::signer::JwsSignerSelector,
    error::{Error, ErrorKind},
    jwt::Jwt,
    platform::MaybeSendBoxFuture,
};

/// JWT Authentication (RFC 7521 / 7523 / `OpenID` Connect Core 1.0 §9)
///
/// With this method, the client authenticates using a JWT which has been
/// cryptographically signed.
///
/// The caller provides the client ID and signing implementation.
///
/// The implementation creates a JWT with these claims:
///  - iss (client ID)
///  - sub (client ID)
///  - aud (per the configured [`Audience`] policy)
///  - exp (expiry time)
///  - iat (current time)
///  - jti (unique ID for replay protection)
///
/// The JWT carries the explicit type `client-authentication+jwt`
/// (draft-ietf-oauth-rfc7523bis); set `explicit_typ(false)` for
/// authorization servers that reject it.
///
/// ## Asymmetric private key
///
/// When the underlying key is an asymmetric private key, the code implements
/// RFC 7523 (private key JWT).
///
/// Benefits:
///  - no shared secrets
///  - stateless verification
///  - non-repudiation (proof that the client sent it)
///
/// ## HMAC shared key
///
/// When the underlying key is a symmetric HMAC key, the code implements
/// `OpenID` Connect Core 1.0 §9 (`client_secret_jwt`).
///
/// Benefits:
///  - simpler setup when a shared secret is acceptable
#[derive(Debug, Clone, Builder)]
pub struct JwtBearer {
    /// The signer of the JWT.
    #[builder(with = |signer: impl JwsSignerSelector + 'static| Arc::new(signer) as Arc<dyn JwsSignerSelector>)]
    signer: Arc<dyn JwsSignerSelector>,
    /// Sets the subject, if different to the issuer.
    #[builder(into)]
    subject: Option<String>,
    /// Sets the audience value for the bearer token.
    audience: Audience,
    /// The lifetime of the JWT (as set in the `exp` claim).
    #[builder(default = Duration::from_mins(1))]
    expires_after: Duration,
    /// Whether to set the explicit JWT type `client-authentication+jwt`
    /// on the client assertion (draft-ietf-oauth-rfc7523bis).
    ///
    /// Defaults to `true`. Authorization servers are directed not to reject
    /// assertions over their `typ`, but set this to `false` for a legacy
    /// server that only accepts `typ: JWT`.
    #[builder(default = true)]
    explicit_typ: bool,
}

/// Sets the value used for the audience of the JWT.
///
/// Signature-based client authentication is subject to audience-injection
/// attacks (draft-ietf-oauth-security-topics-update §2.1): a malicious
/// authorization server that advertises an honest server's token endpoint can
/// replay a client's assertion against the honest server. The draft gives two
/// safe countermeasures, both of which use a *single* audience value:
///
///  - §2.1.2.1 — the authorization server's issuer identifier
///    ([`Audience::Issuer`], recommended; also required for FAPI 2.0); and
///  - §2.1.2.2 — the exact endpoint URI the assertion is sent to
///    ([`Audience::TargetEndpoint`]).
///
/// [`Audience::TokenEndpoint`] (the authorization server's token endpoint, even
/// for assertions sent elsewhere) is the historically common pattern
/// "encouraged, or at least allowed" by RFC 7521/7522/7523, RFC 9126 and
/// `OpenID` Connect Core 1.0 §9 — and is exactly the value an audience-injection
/// attack exploits. Use it only for a legacy server that demands it.
/// [`Audience::Custom`] pins some other value.
///
/// See <https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/>,
/// <https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/>,
/// <https://www.rfc-editor.org/rfc/rfc7523> and
/// <https://openid.net/specs/fapi-security-profile-2_0-final.html>
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// Use the authorization server's issuer identifier as the sole audience
    /// (draft-ietf-oauth-security-topics-update §2.1.2.1). Recommended.
    ///
    /// The issuer usually comes from authorization server metadata. Fails
    /// with [`ErrorKind::Config`] if no issuer is configured — there is no
    /// fallback, since an endpoint-URL audience weakens audience-injection
    /// protection.
    Issuer,
    /// Use the authorization server's token endpoint URL, even when the
    /// assertion is sent to another endpoint (PAR, revocation, introspection,
    /// device authorization).
    ///
    /// This is the historically common pattern, but it is the value an
    /// audience-injection attack
    /// (draft-ietf-oauth-security-topics-update §2.1) exploits — only use it
    /// for a legacy server that requires it. Fails with [`ErrorKind::Config`]
    /// if the caller cannot supply the token endpoint (e.g. a revocation or
    /// introspection client configured without one).
    TokenEndpoint,
    /// Use the exact endpoint URI the assertion is sent to
    /// (draft-ietf-oauth-security-topics-update §2.1.2.2).
    ///
    /// Always available, and a safe countermeasure for servers that do not
    /// publish a verifiable issuer identifier. Note that for grant exchanges
    /// the target endpoint *is* the token endpoint.
    TargetEndpoint,
    /// Use a custom audience value.
    Custom(Arc<str>),
}

/// [`Audience::Issuer`] requires an issuer, but none was configured.
///
/// Carried as the source of [`ErrorKind::Config`] errors from
/// [`JwtBearer::authentication_params`](ClientAuthentication::authentication_params).
#[derive(Debug, Clone, Copy, Default, Snafu)]
#[snafu(display(
    "Audience::Issuer requires an issuer; fetch authorization server metadata \
     or set an issuer explicitly"
))]
pub struct MissingIssuer;

/// [`Audience::TokenEndpoint`] requires the authorization server's token
/// endpoint, but the caller could not supply one.
///
/// Carried as the source of [`ErrorKind::Config`] errors from
/// [`JwtBearer::authentication_params`](ClientAuthentication::authentication_params).
/// Arises when authenticating to an endpoint whose client is configured
/// without the token endpoint (e.g. revocation or introspection).
#[derive(Debug, Clone, Copy, Default, Snafu)]
#[snafu(display(
    "Audience::TokenEndpoint requires the authorization server's token endpoint, \
     but none was available; use Audience::TargetEndpoint or Audience::Issuer, \
     or configure the token endpoint"
))]
pub struct MissingTokenEndpoint;

impl ClientAuthentication for JwtBearer {
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        issuer: Option<&'a str>,
        token_endpoint: Option<&'a EndpointUrl>,
        target_endpoint: &'a EndpointUrl,
        _allowed_methods: Option<&'a [String]>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        Box::pin(async move {
            let audience = match &self.audience {
                Audience::Issuer => issuer
                    .ok_or_else(|| Error::new(ErrorKind::Config, MissingIssuer))?
                    .to_string(),
                Audience::TokenEndpoint => token_endpoint
                    .ok_or_else(|| Error::new(ErrorKind::Config, MissingTokenEndpoint))?
                    .to_string(),
                Audience::TargetEndpoint => target_endpoint.to_string(),
                Audience::Custom(custom) => custom.to_string(),
            };

            let jwt = Jwt::builder()
                .typ(if self.explicit_typ {
                    "client-authentication+jwt"
                } else {
                    "JWT"
                })
                .audience(audience)
                .issuer(client_id)
                .subject(self.subject.as_deref().unwrap_or(client_id))
                .issued_now_expires_after(self.expires_after)
                .claims(())
                .build();

            let assertion = jwt
                .to_jws_compact(&*self.signer.select_signer().await)
                .await
                .map_err(|err| err.with_context("signing client assertion JWT"))?;

            Ok(AuthenticationParams::builder()
                .form_params(bon::map! {
                    "client_id": client_id,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion
                })
                .build())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use base64::Engine as _;

    use super::*;
    use crate::{
        client_auth::{ClientAuthentication, FormValue},
        crypto::signer::JwsSigner,
    };

    #[derive(Debug, Clone)]
    struct MockJwsSigner {
        alg: &'static str,
    }

    impl JwsSigner for MockJwsSigner {
        fn jws_algorithm(&self) -> std::borrow::Cow<'_, str> {
            self.alg.into()
        }
        fn key_id(&self) -> Option<std::borrow::Cow<'_, str>> {
            None
        }
        fn sign<'a>(&'a self, _input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
            Box::pin(async { Ok(vec![0xAB]) })
        }
    }

    impl JwsSignerSelector for MockJwsSigner {
        fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
            let signer: Arc<dyn JwsSigner> = Arc::new(self.clone());
            Box::pin(async move { signer })
        }
    }

    fn extract_form_str(form: &[(&'static str, FormValue<'_>)], key: &str) -> String {
        form.iter().find(|(k, _)| *k == key).map_or_else(
            || unreachable!("key {key} not found in form params"),
            |(_, v)| match v {
                FormValue::NonSensitive(c) => c.to_string(),
                FormValue::Sensitive(c) => c.expose_secret().to_string(),
            },
        )
    }

    fn decode_claims(assertion: &str) -> serde_json::Value {
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        serde_json::from_slice(
            &base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(parts[1])
                .unwrap(),
        )
        .unwrap()
    }

    fn decode_header(assertion: &str) -> serde_json::Value {
        let parts: Vec<&str> = assertion.split('.').collect();
        serde_json::from_slice(
            &base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(parts[0])
                .unwrap(),
        )
        .unwrap()
    }

    // A token endpoint distinct from the target endpoint, so tests can tell
    // `TokenEndpoint` and `TargetEndpoint` audiences apart.
    fn token_endpoint() -> &'static EndpointUrl {
        static E: LazyLock<EndpointUrl> =
            LazyLock::new(|| "https://token.example.com/token".parse().unwrap());
        LazyLock::force(&E)
    }
    fn target_endpoint() -> &'static EndpointUrl {
        static E: LazyLock<EndpointUrl> =
            LazyLock::new(|| "https://as.example.com/revoke".parse().unwrap());
        LazyLock::force(&E)
    }

    #[tokio::test]
    async fn audience_issuer_with_issuer() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::Issuer)
            .build();
        let params = bearer
            .authentication_params(
                "cid",
                Some("https://issuer.example.com"),
                Some(token_endpoint()),
                target_endpoint(),
                None,
            )
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        let claims = decode_claims(&extract_form_str(&form, "client_assertion"));
        assert_eq!(claims["aud"], "https://issuer.example.com");
    }

    #[tokio::test]
    async fn audience_issuer_without_issuer_fails_closed() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::Issuer)
            .build();
        let err = bearer
            .authentication_params("cid", None, Some(token_endpoint()), target_endpoint(), None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(
            std::error::Error::source(&err)
                .expect("carries a source")
                .downcast_ref::<MissingIssuer>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn assertion_is_explicitly_typed_by_default() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::TargetEndpoint)
            .build();
        let params = bearer
            .authentication_params("cid", None, None, target_endpoint(), None)
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        let header = decode_header(&extract_form_str(&form, "client_assertion"));
        assert_eq!(header["typ"], "client-authentication+jwt");
    }

    #[tokio::test]
    async fn explicit_typ_opt_out_restores_plain_jwt() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::TargetEndpoint)
            .explicit_typ(false)
            .build();
        let params = bearer
            .authentication_params("cid", None, None, target_endpoint(), None)
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        let header = decode_header(&extract_form_str(&form, "client_assertion"));
        assert_eq!(header["typ"], "JWT");
    }

    #[tokio::test]
    async fn audience_target_endpoint_uses_target_not_token() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::TargetEndpoint)
            .build();
        let params = bearer
            .authentication_params(
                "cid",
                Some("https://issuer.example.com"),
                Some(token_endpoint()),
                target_endpoint(),
                None,
            )
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        let claims = decode_claims(&extract_form_str(&form, "client_assertion"));
        assert_eq!(claims["aud"], "https://as.example.com/revoke");
    }

    #[tokio::test]
    async fn audience_token_endpoint_uses_token_not_target() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::TokenEndpoint)
            .build();
        let params = bearer
            .authentication_params(
                "cid",
                Some("https://issuer.example.com"),
                Some(token_endpoint()),
                target_endpoint(),
                None,
            )
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        let claims = decode_claims(&extract_form_str(&form, "client_assertion"));
        assert_eq!(claims["aud"], "https://token.example.com/token");
    }

    #[tokio::test]
    async fn audience_token_endpoint_without_token_endpoint_fails_closed() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::TokenEndpoint)
            .build();
        let err = bearer
            .authentication_params(
                "cid",
                Some("https://issuer.example.com"),
                None,
                target_endpoint(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(
            std::error::Error::source(&err)
                .expect("carries a source")
                .downcast_ref::<MissingTokenEndpoint>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn audience_custom() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::Custom("https://custom.example.com".into()))
            .build();
        let params = bearer
            .authentication_params(
                "cid",
                Some("https://issuer.example.com"),
                Some(token_endpoint()),
                target_endpoint(),
                None,
            )
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        let claims = decode_claims(&extract_form_str(&form, "client_assertion"));
        assert_eq!(claims["aud"], "https://custom.example.com");
    }

    #[tokio::test]
    async fn form_params_structure() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::TargetEndpoint)
            .build();
        let params = bearer
            .authentication_params("my-client", None, None, target_endpoint(), None)
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        assert_eq!(extract_form_str(&form, "client_id"), "my-client");
        assert_eq!(
            extract_form_str(&form, "client_assertion_type"),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
        let assertion = extract_form_str(&form, "client_assertion");
        assert_eq!(assertion.split('.').count(), 3);
    }

    #[tokio::test]
    async fn subject_override() {
        let bearer = JwtBearer::builder()
            .signer(MockJwsSigner { alg: "ES256" })
            .audience(Audience::TargetEndpoint)
            .subject("custom-subject")
            .build();
        let params = bearer
            .authentication_params("my-client", None, None, target_endpoint(), None)
            .await
            .unwrap();
        let form = params.form_params.unwrap();
        let claims = decode_claims(&extract_form_str(&form, "client_assertion"));
        assert_eq!(claims["iss"], "my-client");
        assert_eq!(claims["sub"], "custom-subject");
    }
}
