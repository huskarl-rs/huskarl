use std::{borrow::Cow, convert::Infallible, time::Duration};

use base64::prelude::*;
use bon::Builder;
use secrecy::SecretString;
use serde::Serialize;
use snafu::prelude::*;

use crate::{
    crypto::signer::{JwsSignerError, JwsSigningKey},
    jwt::structure::{JwtClaims, JwtHeader},
};

/// A built JWT with all information except signing metadata.
///
/// This represents a full JWT that can be signed with information
/// from the signing layer. The signing layer can add the algorithm
/// and key ID information, creates a JWS signature, and builds the
/// final string.
#[derive(Debug, Clone, Builder)]
pub struct Jwt<'a, ExtraHeaders, ExtraClaims>
where
    ExtraHeaders: Serialize + Clone,
    ExtraClaims: Serialize + Clone,
{
    #[builder(default = "JWT", into)]
    pub typ: Cow<'a, str>,
    #[builder(into)]
    pub issuer: Option<Cow<'a, str>>,
    #[builder(into)]
    pub subject: Option<Cow<'a, str>>,
    #[builder(default, into)]
    pub audiences: Vec<Cow<'a, str>>,
    pub issued_at: Option<u64>,
    pub expiration: Option<u64>,
    pub not_before: Option<u64>,
    #[builder(required, into, default = crate::uuid::uuid_v7())]
    pub jti: Option<String>,
    pub extra_headers: Option<ExtraHeaders>,
    pub extra_claims: Option<ExtraClaims>,
}

impl<'a, ExtraHeaders, ExtraClaims, S: jwt_builder::State>
    JwtBuilder<'a, ExtraHeaders, ExtraClaims, S>
where
    ExtraHeaders: Serialize + Clone,
    ExtraClaims: Serialize + Clone,
{
    /// Sets a single audience value for the JWT.
    pub fn audience(
        self,
        audience: impl Into<Cow<'a, str>>,
    ) -> JwtBuilder<'a, ExtraHeaders, ExtraClaims, jwt_builder::SetAudiences<S>>
    where
        S::Audiences: jwt_builder::IsUnset,
    {
        self.audiences(vec![audience.into()])
    }

    #[allow(clippy::expect_used)]
    /// Sets the issued value for the JWT to the current time.
    ///
    /// # Panics
    ///
    /// This call panics if the reported time is before the epoch.
    pub fn issued_now(
        self,
    ) -> JwtBuilder<'a, ExtraHeaders, ExtraClaims, jwt_builder::SetIssuedAt<S>>
    where
        S::IssuedAt: jwt_builder::IsUnset,
    {
        self.issued_at(
            crate::platform::SystemTime::now()
                .duration_since(crate::platform::SystemTime::UNIX_EPOCH)
                .expect("All times are after epoch")
                .as_secs(),
        )
    }

    #[allow(clippy::expect_used)]
    /// Sets the issued value for the JWT to the current time, and the expiry time to the current time plus a specified duration.
    ///
    /// # Panics
    ///
    /// This call panics if the reported time is before the epoch.
    pub fn issued_now_expires_after(
        self,
        after: Duration,
    ) -> JwtBuilder<
        'a,
        ExtraHeaders,
        ExtraClaims,
        jwt_builder::SetExpiration<jwt_builder::SetIssuedAt<S>>,
    >
    where
        S::IssuedAt: jwt_builder::IsUnset,
        S::Expiration: jwt_builder::IsUnset,
    {
        let now = crate::platform::SystemTime::now()
            .duration_since(crate::platform::SystemTime::UNIX_EPOCH)
            .expect("All times are after epoch")
            .as_secs();
        let expiration = now.saturating_add(after.as_secs());
        self.issued_at(now).expiration(expiration)
    }
}

/// Errors that occur when attempting to serialize the JWT.
#[derive(Debug, Snafu)]
pub enum JwsSerializationError<SgnErr: crate::Error + 'static = Infallible> {
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
    /// Failed to sign the JWT.
    Sign {
        /// The underlying signing error.
        source: JwsSignerError<SgnErr>,
    },
}

impl<SgnErr: crate::Error> crate::Error for JwsSerializationError<SgnErr> {
    fn is_retryable(&self) -> bool {
        match self {
            JwsSerializationError::EncodeClaims { .. }
            | JwsSerializationError::EncodeHeader { .. } => false,
            JwsSerializationError::Sign { source } => source.is_retryable(),
        }
    }
}

impl<ExtraHeaders, ExtraClaims> Jwt<'_, ExtraHeaders, ExtraClaims>
where
    ExtraHeaders: Serialize + Clone,
    ExtraClaims: Serialize + Clone,
{
    async fn attempt_to_jws_compact<Sgn: JwsSigningKey>(
        &self,
        signer: &Sgn,
    ) -> Result<SecretString, JwsSerializationError<Sgn::Error>> {
        let key_metadata = signer.key_metadata();

        let jwt_header = JwtHeader {
            alg: Cow::Borrowed(&key_metadata.jws_algorithm),
            typ: Some(Cow::Borrowed(&self.typ)),
            kid: key_metadata.key_id.as_deref().map(Cow::Borrowed),
            extra_headers: self.extra_headers.as_ref().map(Cow::Borrowed),
        };
        let jwt_claims = JwtClaims {
            iss: self.issuer.as_deref().map(Cow::Borrowed),
            sub: self.subject.as_deref().map(Cow::Borrowed),
            aud: self.audiences.clone(),
            iat: self.issued_at,
            exp: self.expiration,
            nbf: self.not_before,
            jti: self.jti.as_deref().map(Cow::Borrowed),
            extra_claims: self.extra_claims.as_ref().map(Cow::Borrowed),
        };
        let jwt_header_json = serde_json::to_vec(&jwt_header).context(EncodeHeaderSnafu)?;
        let jwt_header_b64 = BASE64_URL_SAFE_NO_PAD.encode(&jwt_header_json);
        let jwt_claims_json = serde_json::to_vec(&jwt_claims).context(EncodeClaimsSnafu)?;
        let jwt_claims_b64 = BASE64_URL_SAFE_NO_PAD.encode(&jwt_claims_json);

        let signing_input = [jwt_header_b64, jwt_claims_b64].join(".");

        let signature = signer
            .sign(signing_input.as_bytes(), &key_metadata)
            .await
            .context(SignSnafu)?;

        let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(&signature);
        let result = [signing_input, signature_b64].join(".");

        Ok(result.into())
    }

    /// Creates a string using the JWS compact serialization.
    ///
    /// # Errors
    ///
    /// Returns an error if the JWT could not be serialized to JSON, or signing failed.
    pub async fn to_jws_compact<Sgn: JwsSigningKey>(
        &self,
        signer: &Sgn,
    ) -> Result<SecretString, JwsSerializationError<Sgn::Error>> {
        match self.attempt_to_jws_compact(signer).await {
            Ok(jws) => Ok(jws),
            Err(JwsSerializationError::Sign {
                source: JwsSignerError::MismatchedKeyMetadata,
            }) => self.attempt_to_jws_compact(signer).await,
            other => other,
        }
    }
}

/// JWT with no extra headers or fields.
pub type SimpleJwt<'a> = Jwt<'a, (), ()>;
