use std::borrow::Cow;

use base64::prelude::*;
use bon::Builder;
use serde::Serialize;
use snafu::prelude::*;

use crate::{
    crypto::signer::JwsSigner,
    error::{Error, ErrorKind},
    jwk::PublicJwk,
    jwt::{
        builder::jwt_builder::{SetClaims, SetExtraHeaders},
        structure::{JwtClaims, JwtHeader},
    },
    platform::{Duration, SystemTime, SystemTimeError},
    secrets::SecretString,
};

/// A built JWT with all information except signing metadata.
///
/// This represents a full JWT that can be signed with information
/// from the signing layer. The signing layer can add the algorithm
/// and key ID information, creates a JWS signature, and builds the
/// final string.
#[non_exhaustive]
#[derive(Debug, Clone, Builder)]
#[builder(
    start_fn(vis = "", name = "builder_internal"),
    generics(setters(name = "with_{}"))
)]
pub struct Jwt<'a, ExtraHeaders = (), Claims = ()>
where
    ExtraHeaders: Serialize + Clone,
    Claims: Serialize + Clone,
{
    /// The type (`typ`) of the JWT.
    #[builder(default = "JWT", into)]
    pub typ: Cow<'a, str>,
    /// The issuer (`iss`) of the JWT.
    #[builder(into)]
    pub issuer: Option<Cow<'a, str>>,
    /// The subject (`sub`) of the JWT.
    #[builder(into)]
    pub subject: Option<Cow<'a, str>>,
    /// The audiences (`aud`) of the JWT.
    #[builder(default, into)]
    pub audiences: Vec<String>,
    /// The number of seconds since the epoch (`iat`) when the JWT was issued.
    pub issued_at: Option<SystemTime>,
    /// The number of seconds since the epoch (`exp`) when the JWT will expire (or has expired).
    pub expiration: Option<SystemTime>,
    /// The number of seconds since the epoch (`nbf`) when the JWT will (or did) become valid.
    pub not_before: Option<SystemTime>,
    /// The unique identifier (`jti`) for this JWT, can be used to avoid replay attacks.
    #[builder(required, into, default = crate::uuid::uuid_v7())]
    pub jti: Option<String>,
    /// Embedded public key (`jwk` header parameter). Present only in `DPoP` proofs (RFC 9449 §4.2).
    pub jwk: Option<PublicJwk>,
    /// Extra key/value pairs in the JWT protected header not included above.
    #[builder(setters(vis = "", name = "extra_headers_internal"))]
    pub extra_headers: Option<ExtraHeaders>,
    /// Additional claims beyond the registered JWT claim set.
    #[builder(setters(vis = "", name = "claims_internal"))]
    pub claims: Claims,
}

impl<'a> Jwt<'a, (), ()> {
    /// Creates a new [`JwtBuilder`] with no extra headers or claims.
    pub fn builder() -> JwtBuilder<'a, (), ()> {
        Jwt::<(), ()>::builder_internal()
    }
}

impl<'a, ExtraHeaders, Claims, S: jwt_builder::State> JwtBuilder<'a, ExtraHeaders, Claims, S>
where
    ExtraHeaders: Serialize + Clone,
    Claims: Serialize + Clone,
{
    /// Sets a single audience value for the JWT.
    pub fn audience(
        self,
        audience: impl Into<String>,
    ) -> JwtBuilder<'a, ExtraHeaders, Claims, jwt_builder::SetAudiences<S>>
    where
        S::Audiences: jwt_builder::IsUnset,
    {
        self.audiences(vec![audience.into()])
    }

    /// Sets the issued value for the JWT to the current time.
    ///
    /// # Panics
    ///
    /// This call panics if the reported time is before the epoch.
    pub fn issued_now(self) -> JwtBuilder<'a, ExtraHeaders, Claims, jwt_builder::SetIssuedAt<S>>
    where
        S::IssuedAt: jwt_builder::IsUnset,
    {
        self.issued_at(crate::platform::SystemTime::now())
    }

    /// Sets the issued value for the JWT to the current time, and the expiry time to the current time plus a specified duration.
    ///
    /// # Panics
    ///
    /// This call panics if the reported time is before the epoch.
    pub fn issued_now_expires_after(
        self,
        after: Duration,
    ) -> JwtBuilder<'a, ExtraHeaders, Claims, jwt_builder::SetExpiration<jwt_builder::SetIssuedAt<S>>>
    where
        S::IssuedAt: jwt_builder::IsUnset,
        S::Expiration: jwt_builder::IsUnset,
    {
        let now = crate::platform::SystemTime::now();
        self.issued_at(now).expiration(now + after)
    }

    /// Sets `iat`, `nbf`, and `exp` from a single captured timestamp.
    ///
    /// Equivalent to [`issued_now_expires_after`](Self::issued_now_expires_after) but also sets
    /// `nbf` to the same `now` value, ensuring `iat == nbf` without a race between calls.
    ///
    /// # Panics
    ///
    /// This call panics if the reported time is before the epoch.
    pub fn issued_now_not_before_now_expires_after(
        self,
        after: Duration,
    ) -> JwtBuilder<
        'a,
        ExtraHeaders,
        Claims,
        jwt_builder::SetNotBefore<jwt_builder::SetExpiration<jwt_builder::SetIssuedAt<S>>>,
    >
    where
        S::IssuedAt: jwt_builder::IsUnset,
        S::Expiration: jwt_builder::IsUnset,
        S::NotBefore: jwt_builder::IsUnset,
    {
        let now = crate::platform::SystemTime::now();
        self.issued_at(now).expiration(now + after).not_before(now)
    }

    /// Sets additional claims for the JWT, replacing the current claims type parameter.
    pub fn claims<E2>(self, claims: E2) -> JwtBuilder<'a, ExtraHeaders, E2, SetClaims<S>>
    where
        E2: Serialize + Clone,
        S::Claims: jwt_builder::IsUnset,
    {
        self.with_claims::<E2>().claims_internal(claims)
    }

    /// Sets extra headers for the JWT, replacing the current extra-headers type parameter.
    pub fn extra_headers<E2>(self, headers: E2) -> JwtBuilder<'a, E2, Claims, SetExtraHeaders<S>>
    where
        E2: Serialize + Clone,
        S::ExtraHeaders: jwt_builder::IsUnset,
    {
        self.with_extra_headers::<E2>()
            .extra_headers_internal(headers)
    }
}

/// Errors that occur when generating the JWS signing input.
#[derive(Debug, Snafu)]
pub enum JwsSigningInputError {
    /// Failed to encode claims as they could not be converted to JSON.
    EncodeClaims {
        /// The underlying error from `serde_json`.
        source: serde_json::Error,
    },
    /// Failed to encode headers as they could not be converted to JSON.
    EncodeHeader {
        /// The underlying error from `serde_json`.
        source: serde_json::Error,
    },
    /// Failed to convert the current time to a JWT-compatible format.
    Time {
        /// The underlying error.
        source: SystemTimeError,
    },
}

impl<ExtraHeaders, Claims> Jwt<'_, ExtraHeaders, Claims>
where
    ExtraHeaders: Serialize + Clone,
    Claims: Serialize + Clone,
{
    /// Creates a string using the JWS compact serialization.
    ///
    /// The key must already have been selected by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`](crate::error::ErrorKind::Config) if the
    /// JWT could not be serialized to JSON, or the signer's error if signing
    /// failed.
    pub async fn to_jws_compact(
        &self,
        signer: &(impl JwsSigner + ?Sized),
    ) -> Result<SecretString, Error> {
        let signing_input = self
            .generate_jwt_signing_input(&signer.jws_algorithm(), signer.key_id().as_deref())
            .map_err(|source| {
                Error::new(ErrorKind::Config, source).with_context("generating JWS signing input")
            })?;

        let signature = signer.sign(signing_input.as_bytes()).await?;

        let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(&signature);
        let result = [signing_input, signature_b64].join(".");

        Ok(SecretString::new(result))
    }

    fn generate_jwt_signing_input(
        &self,
        alg: &str,
        kid: Option<&str>,
    ) -> Result<String, JwsSigningInputError> {
        let jwt_header = JwtHeader {
            alg: Cow::Borrowed(alg),
            typ: Some(Cow::Borrowed(&self.typ)),
            kid: kid.map(Cow::Borrowed),
            crit: Vec::new(),
            jwk: self.jwk.clone(),
            extra_headers: self.extra_headers.as_ref().map(Cow::Borrowed),
        };

        // Validate eagerly so a pre-epoch timestamp surfaces as a Time error
        // rather than a generic claims-encoding failure during serialization.
        for t in [self.issued_at, self.expiration, self.not_before]
            .into_iter()
            .flatten()
        {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .context(TimeSnafu)?;
        }

        let jwt_claims = JwtClaims {
            iss: self.issuer.as_deref().map(Cow::Borrowed),
            sub: self.subject.as_deref().map(Cow::Borrowed),
            aud: self.audiences.clone(),
            iat: self.issued_at,
            exp: self.expiration,
            nbf: self.not_before,
            jti: self.jti.as_deref().map(Cow::Borrowed),
            cnf: None,
            claims: Cow::Borrowed(&self.claims),
        };
        let jwt_header_json = serde_json::to_vec(&jwt_header).context(EncodeHeaderSnafu)?;
        let jwt_header_b64 = BASE64_URL_SAFE_NO_PAD.encode(&jwt_header_json);
        let jwt_claims_json = serde_json::to_vec(&jwt_claims).context(EncodeClaimsSnafu)?;
        let jwt_claims_b64 = BASE64_URL_SAFE_NO_PAD.encode(&jwt_claims_json);

        Ok([jwt_header_b64, jwt_claims_b64].join("."))
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;
    use serde::Serialize;

    use crate::{
        crypto::signer::JwsSigner,
        error::Error,
        jwt::Jwt,
        platform::{MaybeSendBoxFuture, SystemTime},
    };

    #[derive(Debug, Clone)]
    struct MockJwsSigner {
        alg: &'static str,
        kid: Option<&'static str>,
    }

    impl JwsSigner for MockJwsSigner {
        fn jws_algorithm(&self) -> Cow<'_, str> {
            self.alg.into()
        }
        fn key_id(&self) -> Option<Cow<'_, str>> {
            self.kid.map(Into::into)
        }
        fn sign<'a>(&'a self, _input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
            Box::pin(async { Ok(vec![0xDE, 0xAD]) })
        }
    }

    use std::borrow::Cow;

    #[tokio::test]
    async fn to_jws_compact_basic() {
        let signer = MockJwsSigner {
            alg: "ES256",
            kid: None,
        };
        let jwt = Jwt::builder()
            .jti(Some("test-jti".to_string()))
            .claims(())
            .build();
        let compact = jwt.to_jws_compact(&signer).await.unwrap();
        let parts: Vec<&str> = compact.expose_secret().split('.').collect();
        assert_eq!(parts.len(), 3);

        // Verify header
        let header_json: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header_json["alg"], "ES256");
        assert_eq!(header_json["typ"], "JWT");

        // Verify signature is base64url of [0xDE, 0xAD]
        let sig_bytes = BASE64_URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes, vec![0xDE, 0xAD]);
    }

    #[tokio::test]
    async fn to_jws_compact_with_all_fields() {
        let signer = MockJwsSigner {
            alg: "RS256",
            kid: Some("key-1"),
        };
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let exp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000);
        let nbf = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(999_999);

        let jwt = Jwt::builder()
            .issuer("my-issuer")
            .subject("my-subject")
            .audiences(vec!["aud1".into(), "aud2".into()])
            .issued_at(now)
            .expiration(exp)
            .not_before(nbf)
            .jti(Some("unique-id".to_string()))
            .claims(())
            .build();

        let compact = jwt.to_jws_compact(&signer).await.unwrap();
        let parts: Vec<&str> = compact.expose_secret().split('.').collect();

        let header: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "key-1");
        assert_eq!(header["typ"], "JWT");

        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "my-issuer");
        assert_eq!(claims["sub"], "my-subject");
        assert_eq!(claims["aud"], serde_json::json!(["aud1", "aud2"]));
        assert_eq!(claims["iat"], 1_000_000);
        assert_eq!(claims["exp"], 2_000_000);
        assert_eq!(claims["nbf"], 999_999);
        assert_eq!(claims["jti"], "unique-id");
    }

    #[tokio::test]
    async fn to_jws_compact_with_extra_headers_and_claims() {
        #[derive(Debug, Clone, Serialize)]
        struct ExtraHeaders {
            nonce: String,
        }

        #[derive(Debug, Clone, Serialize)]
        struct ExtraClaims {
            scope: String,
        }

        let signer = MockJwsSigner {
            alg: "ES256",
            kid: None,
        };
        let jwt = Jwt::builder()
            .jti(Some("jti-val".to_string()))
            .extra_headers(ExtraHeaders {
                nonce: "abc123".into(),
            })
            .claims(ExtraClaims {
                scope: "openid".into(),
            })
            .build();

        let compact = jwt.to_jws_compact(&signer).await.unwrap();
        let parts: Vec<&str> = compact.expose_secret().split('.').collect();

        let header: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["nonce"], "abc123");

        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["scope"], "openid");
    }

    #[tokio::test]
    async fn to_jws_compact_no_kid() {
        let signer = MockJwsSigner {
            alg: "EdDSA",
            kid: None,
        };
        let jwt = Jwt::builder().jti(Some("j".to_string())).claims(()).build();
        let compact = jwt.to_jws_compact(&signer).await.unwrap();
        let parts: Vec<&str> = compact.expose_secret().split('.').collect();

        let header: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert!(header.get("kid").is_none());
    }
}
