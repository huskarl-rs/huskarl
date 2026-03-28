//! `OpenID` Connect ID token support.

use std::collections::{HashMap, HashSet};

use bon::Builder;
use serde::{Deserialize, Serialize};
use snafu::{ensure, prelude::*};

use crate::core::{
    crypto::verifier::BoxedJwsVerifier,
    jwt::validator::{ClaimCheck, JwtValidationError, JwtValidator, ValidatedJwt},
    platform::{Duration, SystemTime},
};

/// An `OpenID` Connect ID token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdToken(String);

impl IdToken {
    /// Exposes the token as a string.
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
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims<Extra = HashMap<String, serde_json::Value>> {
    /// The nonce value from the token claims.
    pub nonce: Option<String>,
    /// The authentication time from the token claims.
    pub auth_time: Option<u64>,
    /// The authentication context class reference from the token claims.
    pub acr: Option<String>,
    /// The authentication methods reference from the token claims.
    #[serde(default)]
    pub amr: Vec<String>,
    /// The authorized party from the token claims.
    pub azp: Option<String>,
    /// Subject - Identifier for the End-User at the Issuer.
    pub sub: Option<String>,
    /// End-User's full name in displayable form.
    pub name: Option<String>,
    /// End-User's given name(s).
    pub given_name: Option<String>,
    /// End-User's surname(s).
    pub family_name: Option<String>,
    /// End-User's middle name(s).
    pub middle_name: Option<String>,
    /// End-User's preferred username.
    pub nickname: Option<String>,
    /// End-User's preferred username.
    pub preferred_username: Option<String>,
    /// End-User's profile URL.
    pub profile: Option<String>,
    /// URL of the End-User's profile picture.
    pub picture: Option<String>,
    /// URL of the End-User's Web page or blog.
    pub website: Option<String>,
    /// End-User's preferred e-mail address.
    pub email: Option<String>,
    /// `true` if the End-User's e-mail address has been verified.
    pub email_verified: Option<bool>,
    /// End-User's gender.
    pub gender: Option<String>,
    /// End-User's birthday, represented as an ISO 8601:2004 `YYYY-MM-DD` date.
    pub birthdate: Option<String>,
    /// String from the IANA Time Zone Database representing the End-User's time zone.
    pub zoneinfo: Option<String>,
    /// End-User's locale, represented as a BCP47 language tag.
    pub locale: Option<String>,
    /// End-User's preferred telephone number.
    pub phone_number: Option<String>,
    /// `true` if the End-User's phone number has been verified.
    pub phone_number_verified: Option<bool>,
    /// End-User's preferred postal address.
    pub address: Option<StandardOidcAddressClaims>,
    /// Time the End-User's information was last updated.
    pub updated_at: Option<SystemTime>,

    /// Extra claims beyond the standard `OpenID` Connect set.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Standard `OpenID` Connect address claim as defined in OIDC Core §5.1.1.
#[derive(Debug, Clone, Deserialize)]
pub struct StandardOidcAddressClaims {
    /// Full mailing address, formatted for display or use on a mailing label.
    pub formatted: Option<String>,
    /// Full street address component, which MAY include house number, street name, P.O. Box.
    pub street_address: Option<String>,
    /// City or locality component.
    pub locality: Option<String>,
    /// State, province, prefecture, or region component.
    pub region: Option<String>,
    /// Zip code or postal code component.
    pub postal_code: Option<String>,
    /// Country name component.
    pub country: Option<String>,
}

/// Validates an ID token against configuration.
#[derive(Debug, Builder)]
pub struct IdTokenValidator {
    /// The JWS verifier to use for validating the ID token.
    verifier: BoxedJwsVerifier,
    /// The issuer to validate against.
    #[builder(into)]
    issuer: String,
    /// The audience to validate against.
    #[builder(into)]
    audience: Option<String>,
    /// The maximum age of the token.
    max_age: Option<Duration>,
    /// The clock leeway to use when validating the token.
    #[builder(default)]
    clock_leeway: Duration,
    /// If set, verifies the `azp` (authorized party) claim matches this value when present.
    #[builder(into)]
    expected_azp: Option<String>,
    /// If set, verifies the `acr` (authentication context class reference) claim matches this value.
    #[builder(into)]
    required_acr: Option<String>,
    /// If set, restricts accepted signature algorithms to this set.
    allowed_algorithms: Option<HashSet<String>>,
}

impl IdTokenValidator {
    /// Validates an ID token against configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is not valid according to the configuration.
    pub async fn validate<E: Clone + for<'de> Deserialize<'de> + 'static>(
        &self,
        id_token: &IdToken,
        expected_nonce: Option<&str>,
    ) -> Result<ValidatedJwt<IdTokenClaims<E>>, IdTokenValidationError> {
        let jwt_validator = JwtValidator::builder()
            .verifier(self.verifier.clone())
            .iss(ClaimCheck::required_value(self.issuer.clone()))
            .maybe_aud(self.audience.as_deref().map(ClaimCheck::required_value))
            .typ(ClaimCheck::if_present("JWT"))
            .require_exp(true)
            .require_iat(true)
            .clock_leeway(self.clock_leeway)
            .maybe_allowed_algorithms(self.allowed_algorithms.clone())
            .build();

        let validated_jwt = jwt_validator
            .validate::<IdTokenClaims<E>>(id_token.token())
            .await
            .context(JwtSnafu)?;

        ensure!(validated_jwt.subject.is_some(), SubjectMissingSnafu);

        // OIDC Core §3.1.3.7 step 11: if nonce was sent, it MUST be present and match.
        ensure!(
            expected_nonce.is_none_or(|expected| validated_jwt
                .claims
                .as_ref()
                .is_some_and(|claims| claims.nonce.as_deref() == Some(expected))),
            NonceMismatchSnafu
        );

        // OIDC Core §3.1.3.7 step 13: if max_age was sent, auth_time MUST be present and the
        // time since last authentication MUST NOT exceed max_age.
        if let Some(max_age) = self.max_age {
            ensure!(
                validated_jwt
                    .claims
                    .as_ref()
                    .is_none_or(|claims| claims.auth_time.is_some()),
                AuthTimeMissingSnafu
            );

            if let Some(auth_time) = validated_jwt.claims.as_ref().and_then(|c| c.auth_time) {
                let auth_at = SystemTime::UNIX_EPOCH + Duration::from_secs(auth_time);
                let now = SystemTime::now();
                ensure!(
                    now.duration_since(auth_at)
                        .is_ok_and(|d| d <= max_age + self.clock_leeway),
                    AuthTimeTooOldSnafu {
                        auth_time,
                        max_age_secs: max_age.as_secs(),
                    }
                );
            }
        }

        // OIDC Core §3.1.3.7 step 5: if azp is present, it MUST contain our client_id.
        if let Some(expected_azp) = &self.expected_azp
            && let Some(azp) = validated_jwt.claims.as_ref().and_then(|c| c.azp.as_ref())
        {
            ensure!(
                azp == expected_azp,
                AzpMismatchSnafu {
                    expected: expected_azp.clone(),
                    actual: azp.clone(),
                }
            );
        }

        // OIDC Core §3.1.3.7 step 12: if acr was requested, check the asserted value.
        if let Some(required_acr) = &self.required_acr {
            match validated_jwt.claims.as_ref().and_then(|c| c.acr.as_ref()) {
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
pub enum IdTokenValidationError {
    /// Base JWT errors.
    Jwt {
        /// The underlying error.
        source: JwtValidationError,
    },
    /// Nonce mismatch between expected and actual nonce.
    NonceMismatch,
    /// `max_age` set but `auth_time` absent.
    AuthTimeMissing,
    /// Subject missing from JWT claims.
    SubjectMissing,
    /// Authentication time exceeds `max_age`. OIDC Core §3.1.3.7 step 13.
    AuthTimeTooOld {
        /// The authentication time (seconds since Unix epoch).
        auth_time: u64,
        /// The maximum age in seconds.
        max_age_secs: u64,
    },
    /// `azp` claim present but does not match the expected client ID. OIDC Core §3.1.3.7 step 5.
    AzpMismatch {
        /// The expected authorized party.
        expected: String,
        /// The actual authorized party.
        actual: String,
    },
    /// `acr` claim missing but was required.
    AcrMissing,
    /// `acr` claim does not match the required value. OIDC Core §3.1.3.7 step 12.
    AcrMismatch {
        /// The expected authentication context class reference.
        expected: String,
        /// The actual authentication context class reference.
        actual: String,
    },
}
