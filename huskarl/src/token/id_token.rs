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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Subject - Identifier for the End-User at the Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
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
/// asserted in either place (OIDC Core §5.4). `sub` is excluded: it is
/// optional on ID-token claims but required on `UserInfo` responses, so each
/// outer type carries its own.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// Validates an ID token against configuration.
#[derive(Debug, Builder)]
pub struct IdTokenValidator {
    /// The JWS verifier to use for validating the ID token.
    #[builder(with = |verifier: impl JwsVerifier + 'static| Arc::new(verifier) as Arc<dyn JwsVerifier>)]
    verifier: Arc<dyn JwsVerifier>,
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
    pub async fn validate(
        &self,
        id_token: &IdToken,
        expected_nonce: Option<&str>,
    ) -> Result<ValidatedJwt<IdTokenClaims>, IdTokenValidationError> {
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
            .validate::<IdTokenClaims>(id_token.token())
            .await
            .context(JwtSnafu)?;

        ensure!(validated_jwt.subject.is_some(), SubjectMissingSnafu);

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

        // OIDC Core §3.1.3.7 clauses 3 & 4: when aud contains multiple values, azp MUST be
        // present and match our client_id.
        if validated_jwt.audience.len() > 1 {
            let azp = validated_jwt
                .claims
                .azp
                .as_deref()
                .ok_or_else(|| AzpMissingSnafu.build())?;
            if let Some(expected) = self.audience.as_deref() {
                ensure!(
                    azp == expected,
                    AzpMismatchSnafu {
                        expected: expected.to_string(),
                        actual: azp.to_string(),
                    }
                );
            }
        }

        // OIDC Core §3.1.3.7 step 5: if azp is present, it MUST contain our client_id.
        if let Some(expected_azp) = &self.expected_azp
            && let Some(azp) = validated_jwt.claims.azp.as_ref()
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
    /// `azp` claim missing when `aud` contains multiple values. OIDC Core §3.1.3.7 clause 4.
    #[snafu(display("azp claim is required when aud contains multiple values"))]
    AzpMissing,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::platform::Duration;

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
