//! `OpenID` Connect ID token support.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bon::Builder;
use serde::{Deserialize, Serialize};
use snafu::{ensure, prelude::*};

use crate::core::{
    crypto::verifier::JwsVerifier,
    jwt::validator::{
        ClaimCheck, JwtValidationError, JwtValidator, ValidatedJwt, within_max_age_secs,
    },
    platform::{Duration, SystemTime},
};

/// An `OpenID` Connect ID token: the compact-JWS string exactly as received.
///
/// Obtained from
/// [`TokenResponse::id_token`](crate::grant::core::TokenResponse::id_token). It
/// is unverified — validate it with [`IdTokenValidator`] before trusting any
/// claim. [`token`](Self::token) exposes the raw string, e.g. to pass back as an
/// `id_token_hint`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdToken(String);

impl std::fmt::Debug for IdToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IdToken").field(&"[REDACTED]").finish()
    }
}

impl IdToken {
    /// Exposes the raw compact-JWS string. Validate with [`IdTokenValidator`]
    /// rather than parsing this directly.
    #[must_use]
    pub fn token(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&str> for IdToken {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<String> for IdToken {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Claims for a standard `OpenID` Connect ID token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IdTokenClaims {
    /// The nonce value from the token claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// The authentication time from the token claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    /// The authentication context class reference from the token claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// The authentication methods reference from the token claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    /// The authorized party from the token claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// Session ID — identifies a specific login session at the issuer. Defined
    /// in OIDC Front-Channel Logout 1.0 §3; front-channel and back-channel
    /// logout requests carry it so the RP can scope logout to the session this
    /// token established rather than all of the End-User's sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Standard OIDC profile claims (OIDC Core §5.1), flattened into the
    /// token's claim set.
    #[serde(flatten)]
    pub profile: StandardOidcProfileClaims,

    /// Extra claims beyond the standard `OpenID` Connect set.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Standard `OpenID` Connect profile claims as defined in OIDC Core §5.1.
///
/// Shared between [`IdTokenClaims`] and
/// [`UserInfo`](crate::userinfo::UserInfo) — the same claim set may be
/// asserted in either place (OIDC Core §5.4). `sub` is excluded: on the ID
/// token it is the registered JWT claim (see [`ValidatedJwt`]); `UserInfo`
/// carries its own required field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StandardOidcProfileClaims {
    /// End-User's full name in displayable form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// End-User's given name(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// End-User's surname(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// End-User's middle name(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// End-User's casual name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// End-User's preferred username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// End-User's profile URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// URL of the End-User's profile picture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// URL of the End-User's Web page or blog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// End-User's preferred e-mail address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// `true` if the End-User's e-mail address has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// End-User's gender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    /// End-User's birthday, represented as an ISO 8601:2004 `YYYY-MM-DD` date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// String from the IANA Time Zone Database representing the End-User's time zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// End-User's locale, represented as a BCP47 language tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// End-User's preferred telephone number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// `true` if the End-User's phone number has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// End-User's preferred postal address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<StandardOidcAddressClaims>,
    /// Time the End-User's information was last updated.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::core::serde_utils::time::option_unix_secs"
    )]
    pub updated_at: Option<SystemTime>,
}

/// Standard `OpenID` Connect address claim as defined in OIDC Core §5.1.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StandardOidcAddressClaims {
    /// Full mailing address, formatted for display or use on a mailing label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Full street address component, which MAY include house number, street name, P.O. Box.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// City or locality component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// State, province, prefecture, or region component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Zip code or postal code component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Country name component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Validates an `OpenID` Connect ID token: signature (via the configured
/// [`JwsVerifier`]), `iss`, and `aud`, plus — when configured — `nonce`,
/// `max_age`, `acr`, and the set of permitted signature algorithms.
///
/// Build one with [`builder`](Self::builder); call [`validate`](Self::validate)
/// to check a token and recover its claims.
#[derive(Debug, Builder)]
#[builder(on(String, into))]
pub struct IdTokenValidator {
    /// The JWS verifier to use for validating the ID token.
    #[builder(with = |verifier: impl JwsVerifier + 'static| Arc::new(verifier) as Arc<dyn JwsVerifier>)]
    verifier: Arc<dyn JwsVerifier>,
    /// The issuer to validate against.
    issuer: String,
    /// The audience to validate against — the client ID this token must be
    /// issued to. Required: OIDC Core §3.1.3.7 step 3 makes the `aud` check
    /// mandatory for ID tokens.
    audience: String,
    /// Audiences the client trusts beyond its own `client_id` (OIDC Core
    /// §3.1.3.7 step 3). Empty by default.
    #[builder(default)]
    trusted_audiences: Vec<String>,
    /// The maximum age of the token.
    max_age: Option<Duration>,
    /// The clock leeway to use when validating the token.
    #[builder(default = Duration::from_secs(10))]
    clock_leeway: Duration,
    /// If set, verifies the `acr` (authentication context class reference) claim matches this value.
    required_acr: Option<String>,
    /// If set, restricts accepted signature algorithms to this set.
    allowed_algorithms: Option<HashSet<String>>,
}

impl IdTokenValidator {
    /// Validates `id_token` against this validator's configuration and returns
    /// its verified claims.
    ///
    /// Pass `expected_nonce` when the authorization request carried a `nonce` —
    /// it is then required to match; otherwise pass `None`.
    ///
    /// # Errors
    ///
    /// Returns an [`IdTokenValidationError`] if any configured check fails —
    /// signature, `iss`, `aud`, `nonce`, `max_age`, `acr`, or signature
    /// algorithm.
    pub async fn validate(
        &self,
        id_token: &IdToken,
        expected_nonce: Option<&str>,
    ) -> Result<ValidatedJwt<IdTokenClaims>, IdTokenValidationError> {
        let jwt_validator = JwtValidator::builder()
            .verifier(self.verifier.clone())
            .iss(ClaimCheck::required_value(self.issuer.clone()))
            .aud(ClaimCheck::required_value(self.audience.clone()))
            .typ(ClaimCheck::if_present("JWT"))
            .require_exp(true)
            .require_iat(true)
            .clock_leeway(self.clock_leeway)
            .maybe_allowed_algorithms(self.allowed_algorithms.clone())
            .build();

        let validated_jwt = jwt_validator
            .validate::<IdTokenClaims>(id_token.token())
            .await
            .context(JwtSnafu)?;

        ensure!(validated_jwt.sub.is_some(), SubjectMissingSnafu);

        // OIDC Core §3.1.3.7 step 11: if nonce was sent, it MUST be present and match.
        ensure!(
            expected_nonce
                .is_none_or(|expected| validated_jwt.claims.nonce.as_deref() == Some(expected)),
            NonceMismatchSnafu
        );

        // OIDC Core §3.1.3.7 step 13: if max_age was sent, auth_time MUST be present and the
        // time since last authentication MUST NOT exceed max_age.
        if let Some(max_age) = self.max_age {
            ensure!(
                validated_jwt.claims.auth_time.is_some(),
                AuthTimeMissingSnafu
            );

            if let Some(auth_time) = validated_jwt.claims.auth_time {
                ensure!(
                    within_max_age_secs(SystemTime::now(), auth_time, max_age, self.clock_leeway),
                    AuthTimeTooOldSnafu {
                        auth_time,
                        max_age_secs: max_age.as_secs(),
                    }
                );
            }
        }

        // OIDC Core §3.1.3.7 step 3: reject any audience beyond our own
        // client_id, the only one we trust. (`azp` is deliberately not
        // validated — OIDC erratum #973 / PR #340 — only surfaced on the claims.)
        let untrusted_audiences: Vec<String> = validated_jwt
            .aud
            .iter()
            .filter(|aud| *aud != &self.audience && !self.trusted_audiences.contains(*aud))
            .cloned()
            .collect();
        ensure!(
            untrusted_audiences.is_empty(),
            UntrustedAudienceSnafu {
                untrusted: untrusted_audiences,
            }
        );

        // OIDC Core §3.1.3.7 step 12: if acr was requested, check the asserted value.
        if let Some(required_acr) = &self.required_acr {
            match validated_jwt.claims.acr.as_ref() {
                Some(acr) => ensure!(
                    acr == required_acr,
                    AcrMismatchSnafu {
                        expected: required_acr.clone(),
                        actual: acr.clone(),
                    }
                ),
                None => return AcrMissingSnafu.fail(),
            }
        }

        Ok(validated_jwt)
    }
}

/// Errors that can occur when validating an ID token.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum IdTokenValidationError {
    /// Base JWT errors.
    #[snafu(display("validating the ID token as a JWT"))]
    Jwt {
        /// The underlying error.
        source: JwtValidationError,
    },
    /// Nonce mismatch between expected and actual nonce.
    #[snafu(display("the 'nonce' claim does not match the one sent with the request"))]
    NonceMismatch,
    /// `max_age` set but `auth_time` absent.
    #[snafu(display(
        "'max_age' was requested but the ID token has no 'auth_time' claim, \
         which OIDC Core 1.0 §2 requires when it was"
    ))]
    AuthTimeMissing,
    /// Subject missing from JWT claims.
    #[snafu(display("the ID token has no 'sub' claim"))]
    SubjectMissing,
    /// Authentication time exceeds `max_age`. OIDC Core §3.1.3.7 step 13.
    #[snafu(display(
        "the end-user authenticated at {auth_time}, longer ago than the requested \
         'max_age' of {max_age_secs}s (OIDC Core 1.0 §3.1.3.7 step 13)"
    ))]
    AuthTimeTooOld {
        /// The authentication time (seconds since Unix epoch).
        auth_time: u64,
        /// The maximum age in seconds.
        max_age_secs: u64,
    },
    /// The token lists one or more audiences the client does not trust.
    /// OIDC Core §3.1.3.7 step 3.
    #[snafu(display("token contains untrusted audience(s): {}", untrusted.join(", ")))]
    UntrustedAudience {
        /// The audiences on the token that are not the client's own.
        untrusted: Vec<String>,
    },
    /// `acr` claim missing but was required.
    #[snafu(display("the ID token has no 'acr' claim, which was required"))]
    AcrMissing,
    /// `acr` claim does not match the required value. OIDC Core §3.1.3.7 step 12.
    #[snafu(display(
        "the 'acr' claim is '{actual}', expected '{expected}' \
         (OIDC Core 1.0 §3.1.3.7 step 12)"
    ))]
    AcrMismatch {
        /// The expected authentication context class reference.
        expected: String,
        /// The actual authentication context class reference.
        actual: String,
    },
}

impl crate::core::error::propagation::Cause for IdTokenValidationError {
    fn origin(&self) -> crate::core::error::propagation::Origin<'_> {
        match self {
            Self::Jwt { source } => crate::core::error::propagation::Cause::origin(source),
            _ => crate::core::error::propagation::Origin::Establishes(
                crate::core::RetryAdvice::No.into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use huskarl_crypto_native::{
        NativeVerifierPlatform,
        asymmetric::signer::{GenerateAlgorithm, PrivateKey},
    };
    use rstest::rstest;

    use super::*;
    use crate::core::{
        crypto::{signer::JwsSignerSelector, verifier::JwsVerifierPlatform},
        jwt::Jwt,
        platform::Duration,
    };

    const ISS: &str = "https://issuer.example.com";
    const AUD: &str = "client-123";
    const SUB: &str = "user-abc";

    /// Mints an ES256 signer paired with a verifier built from its public JWK,
    /// so signed tokens verify end-to-end against the validator.
    async fn signer_and_verifier() -> (PrivateKey, Arc<dyn JwsVerifier>) {
        let signer = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
        let verifier = NativeVerifierPlatform
            .create_verifier_from_jwk(signer.as_private_jwk().public_jwk())
            .await
            .unwrap();
        (signer, verifier)
    }

    /// Signs an ID token with the given issuer/audiences/subject and claim body.
    async fn mint(
        signer: &PrivateKey,
        iss: &str,
        audiences: Vec<String>,
        sub: Option<&str>,
        claims: IdTokenClaims,
    ) -> IdToken {
        let token = Jwt::builder()
            .typ("JWT")
            .iss(iss.to_string())
            .aud(audiences)
            .maybe_sub(sub.map(str::to_string))
            .issued_now_expires_after(Duration::from_hours(1))
            .claims(claims)
            .build()
            .to_jws_compact(&*signer.select_signer().await)
            .await
            .unwrap();
        IdToken::from(token.expose_secret())
    }

    /// A well-formed ID token with a single audience and the given claim body.
    async fn mint_standard(signer: &PrivateKey, claims: IdTokenClaims) -> IdToken {
        mint(signer, ISS, vec![AUD.to_string()], Some(SUB), claims).await
    }

    /// Builds a validator with the same shape every time; optional OIDC knobs
    /// are passed as `Some`/`None` through `maybe_` setters.
    fn validator(
        verifier: Arc<dyn JwsVerifier>,
        max_age: Option<Duration>,
        required_acr: Option<&str>,
    ) -> IdTokenValidator {
        IdTokenValidator::builder()
            .verifier(verifier)
            .issuer(ISS)
            .audience(AUD)
            .maybe_max_age(max_age)
            .maybe_required_acr(required_acr.map(str::to_string))
            .build()
    }

    #[tokio::test]
    async fn valid_id_token_is_accepted() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint_standard(&signer, IdTokenClaims::default()).await;
        let validated = validator(verifier, None, None)
            .validate(&token, None)
            .await
            .expect("token should validate");
        assert_eq!(validated.sub.as_deref(), Some(SUB));
        assert_eq!(validated.iss.as_deref(), Some(ISS));
    }

    #[tokio::test]
    async fn missing_subject_is_rejected() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint(
            &signer,
            ISS,
            vec![AUD.to_string()],
            None,
            IdTokenClaims::default(),
        )
        .await;
        let err = validator(verifier, None, None)
            .validate(&token, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdTokenValidationError::SubjectMissing),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn nonce_mismatch_is_rejected() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                nonce: Some("actual".to_string()),
                ..IdTokenClaims::default()
            },
        )
        .await;
        let err = validator(verifier, None, None)
            .validate(&token, Some("expected"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdTokenValidationError::NonceMismatch),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn matching_nonce_is_accepted() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                nonce: Some("the-nonce".to_string()),
                ..IdTokenClaims::default()
            },
        )
        .await;
        validator(verifier, None, None)
            .validate(&token, Some("the-nonce"))
            .await
            .expect("matching nonce should validate");
    }

    /// The aud check is mandatory (OIDC Core §3.1.3.7 step 3): a valid token
    /// the OP issued to a *different* client must be rejected.
    #[tokio::test]
    async fn token_for_other_client_is_rejected() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint(
            &signer,
            ISS,
            vec!["other-client".to_string()],
            Some(SUB),
            IdTokenClaims::default(),
        )
        .await;
        let err = validator(verifier, None, None)
            .validate(&token, None)
            .await
            .unwrap_err();
        assert!(matches!(err, IdTokenValidationError::Jwt { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn max_age_without_auth_time_is_rejected() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint_standard(&signer, IdTokenClaims::default()).await;
        let err = validator(verifier, Some(Duration::from_mins(1)), None)
            .validate(&token, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdTokenValidationError::AuthTimeMissing),
            "got {err:?}"
        );
    }

    /// An `auth_time` slightly ahead of the client clock (routine AS skew on a
    /// fresh interactive login) must validate rather than failing
    /// `duration_since` and being rejected as `AuthTimeTooOld`.
    #[tokio::test]
    async fn auth_time_slightly_in_future_is_accepted() {
        let (signer, verifier) = signer_and_verifier().await;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                auth_time: Some(now + 2),
                ..IdTokenClaims::default()
            },
        )
        .await;
        validator(verifier, Some(Duration::from_mins(1)), None)
            .validate(&token, None)
            .await
            .expect("fresh login with 2s AS clock skew should validate");
    }

    #[tokio::test]
    async fn auth_time_older_than_max_age_is_rejected() {
        let (signer, verifier) = signer_and_verifier().await;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                auth_time: Some(now - 1000),
                ..IdTokenClaims::default()
            },
        )
        .await;
        let err = validator(verifier, Some(Duration::from_mins(1)), None)
            .validate(&token, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdTokenValidationError::AuthTimeTooOld { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn recent_auth_time_within_max_age_is_accepted() {
        let (signer, verifier) = signer_and_verifier().await;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                auth_time: Some(now - 10),
                ..IdTokenClaims::default()
            },
        )
        .await;
        validator(verifier, Some(Duration::from_mins(5)), None)
            .validate(&token, None)
            .await
            .expect("recent auth_time should validate");
    }

    #[tokio::test]
    async fn auth_time_at_u64_max_does_not_panic() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                auth_time: Some(u64::MAX),
                ..IdTokenClaims::default()
            },
        )
        .await;
        validator(verifier, Some(Duration::from_mins(1)), None)
            .validate(&token, None)
            .await
            .expect("overflowing auth_time must not panic");
    }

    /// A non-matching `azp` is surfaced on the claims but never validated, so
    /// it is ignored rather than rejected (OIDC erratum #973 / PR #340).
    #[tokio::test]
    async fn non_matching_azp_is_ignored() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                azp: Some("someone-else".to_string()),
                ..IdTokenClaims::default()
            },
        )
        .await;
        let validated = validator(verifier, None, None)
            .validate(&token, None)
            .await
            .expect("a non-matching azp must be ignored, not rejected");
        assert_eq!(validated.claims.azp.as_deref(), Some("someone-else"));
    }

    #[tokio::test]
    async fn audience_not_trusted_is_rejected() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint(
            &signer,
            ISS,
            vec![AUD.to_string(), "other-aud".to_string()],
            Some(SUB),
            IdTokenClaims::default(),
        )
        .await;
        let err = validator(verifier, None, None)
            .validate(&token, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                IdTokenValidationError::UntrustedAudience { untrusted }
                    if untrusted == &["other-aud".to_string()]
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn extra_audience_in_trusted_set_is_accepted() {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint(
            &signer,
            ISS,
            vec![AUD.to_string(), "other-aud".to_string()],
            Some(SUB),
            IdTokenClaims::default(),
        )
        .await;
        IdTokenValidator::builder()
            .verifier(verifier)
            .issuer(ISS)
            .audience(AUD)
            .trusted_audiences(vec!["other-aud".to_string()])
            .build()
            .validate(&token, None)
            .await
            .expect("a listed extra audience should validate");
    }

    /// `required_acr` against the token's asserted `acr` (OIDC Core §3.1.3.7 step 12).
    #[rstest]
    #[case::missing(None, true)]
    #[case::mismatch(Some("urn:loa:low"), true)]
    #[case::matches(Some("urn:loa:high"), false)]
    #[tokio::test]
    async fn required_acr_is_enforced(#[case] token_acr: Option<&str>, #[case] expect_err: bool) {
        let (signer, verifier) = signer_and_verifier().await;
        let token = mint_standard(
            &signer,
            IdTokenClaims {
                acr: token_acr.map(str::to_string),
                ..IdTokenClaims::default()
            },
        )
        .await;
        let result = validator(verifier, None, Some("urn:loa:high"))
            .validate(&token, None)
            .await;
        assert_eq!(result.is_err(), expect_err, "got {result:?}");
    }

    #[test]
    fn id_token_debug_redacts_the_raw_jws() {
        let token = IdToken::from("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig");
        let rendered = format!("{token:?}");
        assert!(rendered.contains("[REDACTED]"), "got {rendered}");
        assert!(!rendered.contains("alice"), "got {rendered}");
        assert!(!rendered.contains("eyJ"), "got {rendered}");
    }

    #[test]
    fn updated_at_deserializes_from_unix_seconds() {
        let json = r#"{"sub":"alice","updated_at":1700000000}"#;
        let claims: IdTokenClaims = serde_json::from_str(json).unwrap();
        let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(claims.profile.updated_at, Some(expected));
    }

    #[test]
    fn updated_at_serializes_as_unix_seconds() {
        let claims = IdTokenClaims {
            profile: StandardOidcProfileClaims {
                updated_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                ..StandardOidcProfileClaims::default()
            },
            ..IdTokenClaims::default()
        };
        let value: serde_json::Value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["updated_at"], serde_json::json!(1_700_000_000));
    }

    #[test]
    fn updated_at_round_trips() {
        let json = r#"{"sub":"alice","updated_at":1700000000}"#;
        let claims: IdTokenClaims = serde_json::from_str(json).unwrap();
        let reserialized = serde_json::to_value(&claims).unwrap();
        assert_eq!(reserialized["updated_at"], serde_json::json!(1_700_000_000));
    }

    #[test]
    fn updated_at_absent_deserializes_to_none_and_is_omitted_on_serialize() {
        let claims: IdTokenClaims = serde_json::from_str(r#"{"sub":"alice"}"#).unwrap();
        assert!(claims.profile.updated_at.is_none());
        let value: serde_json::Value = serde_json::to_value(&claims).unwrap();
        assert!(value.get("updated_at").is_none());
    }

    #[test]
    fn updated_at_null_deserializes_to_none() {
        let claims: IdTokenClaims =
            serde_json::from_str(r#"{"sub":"alice","updated_at":null}"#).unwrap();
        assert!(claims.profile.updated_at.is_none());
    }

    #[test]
    fn sid_deserializes_to_typed_field_not_extra() {
        let json = r#"{"sub":"alice","sid":"sess-123"}"#;
        let claims: IdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sid.as_deref(), Some("sess-123"));
        assert!(!claims.extra.contains_key("sid"));
    }

    #[test]
    fn unknown_claims_land_in_extra_not_profile() {
        let json = r#"{"sub":"alice","email":"a@example.com","groups":["admin"]}"#;
        let claims: IdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.profile.email.as_deref(), Some("a@example.com"));
        assert_eq!(claims.extra["groups"], serde_json::json!(["admin"]));
        assert!(!claims.extra.contains_key("email"));
    }
}
