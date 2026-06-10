//! Validation infrastructure for JWT tokens.

use std::{collections::HashSet, sync::Arc};

use bon::Builder;
use serde::Deserialize;
use snafu::{ResultExt as _, Snafu, ensure};

use crate::{
    BoxedError,
    crypto::verifier::{BoxedJwsVerifier, JwsVerifier, KeyMatch, VerifyError},
    jwt::{ConfirmationClaim, JtiUniquenessChecker, JwsParseError, ParsedJws, parse_compact_jws},
    platform::{Duration, SystemTime},
};

/// A check to perform on a JWT claim.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub enum ClaimCheck {
    /// If claim is present, it must equal this value. Lack of value is acceptable.
    IfPresent(String),
    /// Claim must be present, value must match one of these.
    RequireAny(Vec<String>),
    /// Claim must be present and equal this value.
    RequiredValue(String),
    /// Claim must be present.
    Present,
    /// No check is performed.
    #[default]
    NoCheck,
}

impl ClaimCheck {
    /// If claim is present, it must equal this value. Lack of value is acceptable.
    pub fn if_present(value: impl Into<String>) -> Self {
        Self::IfPresent(value.into())
    }

    /// Claim must be present, and value must match one of these.
    pub fn require_any(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::RequireAny(values.into_iter().map(Into::into).collect())
    }

    /// Claim must be present and equal this value.
    pub fn required_value(value: impl Into<String>) -> Self {
        Self::RequiredValue(value.into())
    }

    /// Claim must be present.
    #[must_use]
    pub fn present() -> Self {
        Self::Present
    }
}

/// JWT token validator.
#[allow(clippy::struct_excessive_bools)]
#[allow(clippy::should_implement_trait)] // `sub` is the JWT claim name, not arithmetic subtraction
#[derive(Debug, Builder)]
pub struct JwtValidator {
    /// JWS verifier to use for token validation.
    verifier: BoxedJwsVerifier,
    /// Check on the `iss` claim.
    #[builder(default)]
    iss: ClaimCheck,
    /// Check on the `sub` claim.
    #[builder(default)]
    sub: ClaimCheck,
    /// Check on the `aud` claim.
    #[builder(default)]
    aud: ClaimCheck,
    /// Type to validate against.
    #[builder(default)]
    typ: ClaimCheck,
    /// The `exp` claim is required.
    #[builder(default)]
    require_exp: bool,
    /// The `iat` claim is required.
    #[builder(default)]
    require_iat: bool,
    /// The `jti` claim is required.
    #[builder(default)]
    require_jti: bool,
    /// Maximum allowed byte length for the `jti` claim. Defaults to 255.
    #[builder(default = 255)]
    max_jti_len: usize,
    /// Implementation of a JTI checker to check for uniqueness.
    #[builder(with = |checker: impl JtiUniquenessChecker + 'static| Arc::new(checker) as Arc<dyn JtiUniquenessChecker>)]
    jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
    /// Maximum token age to validate against.
    max_token_age: Option<Duration>,
    #[builder(default)]
    clock_leeway: Duration,
    /// Specifies which `crit` values as allowed.
    ///
    /// By default, no values are understood, and a token
    /// containing any values will be rejected. Values may
    /// be added, where the user of the token is able to
    /// understand and handle the corresponding extension.
    #[builder(default, with = FromIterator::from_iter)]
    allowed_crit: HashSet<String>,
    /// If set, restricts accepted signature algorithms to this set.
    ///
    /// Per OIDC Core §3.1.3.7 step 7, the `alg` value SHOULD be `RS256` or the algorithm
    /// registered during client registration. Use this to enforce an allowlist.
    ///
    /// Regardless of this setting, the algorithm `"none"` is always rejected.
    #[builder(with = FromIterator::from_iter)]
    allowed_algorithms: Option<HashSet<String>>,
}

/// Per RFC 7515 §4.1.9 and RFC 2045, `typ` media type subtypes are case-insensitive,
/// and the `application/` prefix may be omitted when there is no other `/` in the value.
/// Normalize to the short form before comparison.
fn normalize_typ(typ: &str) -> &str {
    match typ.split_at_checked(12) {
        Some((prefix, rest)) if !rest.is_empty() && prefix.eq_ignore_ascii_case("application/") => {
            rest
        }
        _ => typ,
    }
}

fn check_str_claim(
    claim: &'static str,
    check: &ClaimCheck,
    value: Option<&str>,
) -> Result<(), JwtValidationError> {
    match check {
        ClaimCheck::Present => {
            if value.is_none() {
                return Err(RequiredClaimMissingSnafu { claim }.build());
            }
        }
        ClaimCheck::RequiredValue(v) => match value {
            Some(val) if val == v.as_str() => {}
            Some(val) => {
                return Err(ClaimMismatchSnafu {
                    claim,
                    expected: v.clone(),
                    actual: val,
                }
                .build());
            }
            None => return Err(RequiredClaimMissingSnafu { claim }.build()),
        },
        ClaimCheck::RequireAny(vs) => match value {
            Some(val) if vs.iter().any(|x| val == x.as_str()) => {}
            Some(val) => {
                return Err(ClaimMismatchSnafu {
                    claim,
                    expected: vs.join(", "),
                    actual: val,
                }
                .build());
            }
            None => return Err(RequiredClaimMissingSnafu { claim }.build()),
        },
        ClaimCheck::IfPresent(v) => {
            if let Some(val) = value
                && val != v.as_str()
            {
                return Err(ClaimMismatchSnafu {
                    claim,
                    expected: v.clone(),
                    actual: val,
                }
                .build());
            }
        }
        ClaimCheck::NoCheck => {}
    }
    Ok(())
}

fn check_aud(check: &ClaimCheck, aud: &[String]) -> Result<(), JwtValidationError> {
    match check {
        ClaimCheck::Present => ensure!(!aud.is_empty(), RequiredClaimMissingSnafu { claim: "aud" }),
        ClaimCheck::RequiredValue(v) => ensure!(
            aud.contains(v),
            ClaimMismatchSnafu {
                claim: "aud",
                expected: v.clone(),
                actual: aud.join(", "),
            }
        ),
        ClaimCheck::RequireAny(vs) => ensure!(
            vs.iter().any(|v| aud.contains(v)),
            ClaimMismatchSnafu {
                claim: "aud",
                expected: vs.join(", "),
                actual: aud.join(", "),
            }
        ),
        ClaimCheck::IfPresent(v) => {
            if !aud.is_empty() {
                ensure!(
                    aud.contains(v),
                    ClaimMismatchSnafu {
                        claim: "aud",
                        expected: v.clone(),
                        actual: aud.join(", "),
                    }
                );
            }
        }
        ClaimCheck::NoCheck => {}
    }
    Ok(())
}

fn check_typ(check: &ClaimCheck, typ: Option<&str>) -> Result<(), JwtValidationError> {
    match check {
        ClaimCheck::IfPresent(t) => ensure!(
            typ.is_none_or(|v| normalize_typ(v).eq_ignore_ascii_case(normalize_typ(t))),
            InvalidTokenTypeSnafu {
                typ: typ.map(Into::into)
            }
        ),
        ClaimCheck::RequireAny(allowed) => match typ {
            None => return RequiredClaimMissingSnafu { claim: "typ" }.fail(),
            Some(v)
                if allowed
                    .iter()
                    .any(|t| normalize_typ(v).eq_ignore_ascii_case(normalize_typ(t))) => {}
            Some(v) => {
                return InvalidTokenTypeSnafu {
                    typ: Some(v.into()),
                }
                .fail();
            }
        },
        ClaimCheck::RequiredValue(t) => match typ {
            None => return RequiredClaimMissingSnafu { claim: "typ" }.fail(),
            Some(v) if normalize_typ(v).eq_ignore_ascii_case(normalize_typ(t)) => {}
            Some(v) => {
                return InvalidTokenTypeSnafu {
                    typ: Some(v.into()),
                }
                .fail();
            }
        },
        ClaimCheck::Present => {
            ensure!(typ.is_some(), RequiredClaimMissingSnafu { claim: "typ" });
        }
        ClaimCheck::NoCheck => {}
    }
    Ok(())
}

/// Temporal comparisons are expressed via `duration_since` rather than
/// `SystemTime`/`Duration` addition: the claim timestamps are attacker-controlled
/// and may sit at the edge of the representable range, where addition panics.
fn check_temporal(
    now: SystemTime,
    clock_leeway: Duration,
    exp: Option<SystemTime>,
    nbf: Option<SystemTime>,
    iat: Option<SystemTime>,
) -> Result<(), JwtValidationError> {
    if let Some(expiration) = exp {
        // Expired iff `now > expiration + leeway`.
        ensure!(
            !now.duration_since(expiration)
                .is_ok_and(|past| past > clock_leeway),
            ExpiredSnafu { expiration, now }
        );
    }
    if let Some(not_before) = nbf {
        // Not yet valid iff `not_before > now + leeway`.
        ensure!(
            !not_before
                .duration_since(now)
                .is_ok_and(|ahead| ahead > clock_leeway),
            NotYetValidSnafu { not_before, now }
        );
    }
    if let Some(issued_at) = iat {
        // Issued in the future iff `issued_at > now + leeway`.
        ensure!(
            !issued_at
                .duration_since(now)
                .is_ok_and(|ahead| ahead > clock_leeway),
            IssuedInFutureSnafu { issued_at, now }
        );
    }
    Ok(())
}

impl JwtValidator {
    fn validate_header(&self, alg: &str, crit: &[String]) -> Result<(), JwtValidationError> {
        ensure!(alg != "none", UnsignedTokenSnafu);

        if let Some(allowed) = &self.allowed_algorithms {
            ensure!(
                allowed.contains(alg),
                DisallowedAlgorithmSnafu {
                    alg: alg.to_string()
                }
            );
        }

        ensure!(
            crit.iter().all(|v| self.allowed_crit.contains(v)),
            UnrecognizedCriticalHeaderSnafu {
                params: crit.to_vec()
            }
        );

        Ok(())
    }

    async fn validate_jti(&self, jti: Option<&str>) -> Result<(), JwtValidationError> {
        if let Some(jti) = jti {
            ensure!(
                jti.len() <= self.max_jti_len,
                JtiTooLongSnafu {
                    len: jti.len(),
                    max_len: self.max_jti_len,
                }
            );
            if let Some(jti_checker) = self.jti_checker.as_ref() {
                ensure!(
                    !jti_checker
                        .check_and_mark_seen(jti)
                        .await
                        .context(JtiCheckSnafu)?,
                    JtiNotUniqueSnafu
                );
            }
        }
        Ok(())
    }

    fn check_required_claims(
        &self,
        exp: Option<SystemTime>,
        iat: Option<SystemTime>,
        jti: Option<&str>,
    ) -> Result<(), JwtValidationError> {
        if self.require_exp {
            ensure!(exp.is_some(), RequiredClaimMissingSnafu { claim: "exp" });
        }
        if self.require_iat {
            ensure!(iat.is_some(), RequiredClaimMissingSnafu { claim: "iat" });
        }
        if self.require_jti {
            ensure!(jti.is_some(), RequiredClaimMissingSnafu { claim: "jti" });
        }
        Ok(())
    }

    /// Validate a pre-parsed JWS, returning a [`ValidatedJwt`] on success.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtValidationError`] if the token is invalid.
    pub async fn validate_parsed_jws<C: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        parsed_jwt: ParsedJws<(), C>,
    ) -> Result<ValidatedJwt<C>, JwtValidationError> {
        let now = SystemTime::now();

        self.validate_header(&parsed_jwt.header.alg, &parsed_jwt.header.crit)?;

        let key_match = KeyMatch {
            alg: &parsed_jwt.header.alg,
            kid: parsed_jwt.header.kid.as_deref(),
        };
        self.verifier
            .verify(&parsed_jwt.signing_input, &parsed_jwt.signature, &key_match)
            .await
            .context(SignatureSnafu)?;

        check_aud(&self.aud, &parsed_jwt.claims.aud)?;
        self.check_required_claims(
            parsed_jwt.claims.exp,
            parsed_jwt.claims.iat,
            parsed_jwt.claims.jti.as_deref(),
        )?;

        if let Some(max_token_age) = self.max_token_age {
            let issued_at = parsed_jwt
                .claims
                .iat
                .ok_or_else(|| RequiredClaimMissingSnafu { claim: "iat" }.build())?;

            ensure!(
                now.duration_since(issued_at)
                    .is_ok_and(|d| d <= max_token_age.saturating_add(self.clock_leeway)),
                TokenTooOldSnafu {
                    issued_at,
                    max_token_age
                }
            );
        }

        check_typ(&self.typ, parsed_jwt.header.typ.as_deref())?;
        check_str_claim("iss", &self.iss, parsed_jwt.claims.iss.as_deref())?;
        check_str_claim("sub", &self.sub, parsed_jwt.claims.sub.as_deref())?;

        check_temporal(
            now,
            self.clock_leeway,
            parsed_jwt.claims.exp,
            parsed_jwt.claims.nbf,
            parsed_jwt.claims.iat,
        )?;

        // Burn JTI after all other checks have passed.
        self.validate_jti(parsed_jwt.claims.jti.as_deref()).await?;

        Ok(ValidatedJwt {
            issuer: parsed_jwt.claims.iss.map(Into::into),
            subject: parsed_jwt.claims.sub.map(Into::into),
            audience: parsed_jwt.claims.aud.iter().map(Into::into).collect(),
            issued_at: parsed_jwt.claims.iat,
            expiration: parsed_jwt.claims.exp,
            jti: parsed_jwt.claims.jti.map(Into::into),
            cnf: parsed_jwt.claims.cnf,
            claims: match parsed_jwt.claims.claims {
                std::borrow::Cow::Borrowed(c) => c.clone(),
                std::borrow::Cow::Owned(c) => c,
            },
        })
    }

    /// Validate a JWT token, returning a [`ValidatedJwt`] on success.
    ///
    /// Uses two-phase parsing: the JWT is first parsed and validated structurally
    /// (signature, standard claims), then the extra claims are deserialized into
    /// the target type `C`. If the token is valid but does not contain the required
    /// extra claims, returns [`JwtValidationError::ExtraClaims`] instead of
    /// [`JwtValidationError::Parse`].
    ///
    /// # Errors
    ///
    /// Returns a [`JwtValidationError`] if the token is invalid.
    pub async fn validate<C: Clone + for<'de> Deserialize<'de> + 'static>(
        &self,
        token: &str,
    ) -> Result<ValidatedJwt<C>, JwtValidationError> {
        let parsed_jwt = parse_compact_jws::<(), serde_json::Value>(token).context(ParseSnafu)?;
        let validated = self.validate_parsed_jws(parsed_jwt).await?;
        validated.try_map_claims(|value| {
            if std::any::TypeId::of::<C>() == std::any::TypeId::of::<()>() {
                serde_json::from_value(serde_json::Value::Null).context(ExtraClaimsSnafu)
            } else {
                serde_json::from_value(value).context(ExtraClaimsSnafu)
            }
        })
    }
}

/// A validated JWT, containing the parsed claims and other metadata.
#[non_exhaustive]
#[derive(Debug, Builder)]
pub struct ValidatedJwt<Claims> {
    /// The issuer of the JWT, if present.
    pub issuer: Option<String>,
    /// The subject of the JWT, if present.
    pub subject: Option<String>,
    /// The audience of the JWT, if present.
    pub audience: Vec<String>,
    /// The JWT ID, if present.
    pub jti: Option<String>,
    /// The issued-at timestamp of the JWT, if present.
    pub issued_at: Option<SystemTime>,
    /// The expiration timestamp of the JWT, if present.
    pub expiration: Option<SystemTime>,
    /// The key confirmation claim (`cnf`, RFC 7800), if present.
    ///
    /// Binds the token to a `DPoP` key (`jkt`, RFC 9449) or mTLS certificate
    /// (`x5t#S256`, RFC 8705). Independent of the token profile and claims type.
    pub cnf: Option<ConfirmationClaim>,
    /// Additional claims beyond the registered JWT claim set.
    pub claims: Claims,
}

impl<Claims> ValidatedJwt<Claims> {
    /// Maps the claims of the JWT using the provided function.
    pub fn map_claims<C1, F>(self, f: F) -> ValidatedJwt<C1>
    where
        F: FnOnce(Claims) -> C1,
    {
        ValidatedJwt {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            jti: self.jti,
            issued_at: self.issued_at,
            expiration: self.expiration,
            cnf: self.cnf,
            claims: f(self.claims),
        }
    }

    /// Maps the claims of the JWT using a fallible function.
    ///
    /// # Errors
    ///
    /// Returns the error of the mapper, if it fails.
    pub fn try_map_claims<C1, E, F>(self, f: F) -> Result<ValidatedJwt<C1>, E>
    where
        F: FnOnce(Claims) -> Result<C1, E>,
    {
        Ok(ValidatedJwt {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            jti: self.jti,
            issued_at: self.issued_at,
            expiration: self.expiration,
            cnf: self.cnf,
            claims: f(self.claims)?,
        })
    }
}

/// Validation errors that can occur while processing a JWT.
#[derive(Debug, Snafu)]
pub enum JwtValidationError {
    /// The token is invalid.
    Parse {
        /// The underlying error.
        source: JwsParseError,
    },
    /// The token signature is invalid.
    Signature {
        /// The underlying error.
        source: VerifyError<BoxedError>,
    },
    /// The token is unsigned.
    UnsignedToken,
    /// The token uses a disallowed signature algorithm.
    DisallowedAlgorithm {
        /// The algorithm used by the token.
        alg: String,
    },
    /// The token contains unrecognized critical header parameters.
    UnrecognizedCriticalHeader {
        /// The unrecognized critical header parameters.
        params: Vec<String>,
    },
    /// The token is expired.
    Expired {
        /// The expiration timestamp of the JWT.
        expiration: SystemTime,
        /// The current time.
        now: SystemTime,
    },
    /// The token is not yet valid.
    NotYetValid {
        /// The not-before timestamp of the JWT.
        not_before: SystemTime,
        /// The current time.
        now: SystemTime,
    },
    /// The token is issued in the future.
    IssuedInFuture {
        /// The issued-at timestamp of the JWT.
        issued_at: SystemTime,
        /// The current time.
        now: SystemTime,
    },
    /// The token is too old.
    TokenTooOld {
        /// The issued-at timestamp of the JWT.
        issued_at: SystemTime,
        /// The maximum age of the token.
        max_token_age: Duration,
    },
    /// The token type claim is invalid.
    InvalidTokenType {
        /// The type of the JWT.
        typ: Option<String>,
    },
    /// A claim did not match the expected value.
    ClaimMismatch {
        /// The claim name.
        claim: &'static str,
        /// The expected value.
        expected: String,
        /// The actual value.
        actual: String,
    },
    /// A required claim is missing from the JWT.
    RequiredClaimMissing {
        /// The missing claim.
        claim: &'static str,
    },
    /// The `jti` claim exceeds the maximum allowed length.
    JtiTooLong {
        /// The length of the `jti` value in bytes.
        len: usize,
        /// The maximum allowed length in bytes.
        max_len: usize,
    },
    /// The JTI was required to be unique, but was previously marked as seen.
    JtiNotUnique,
    /// There was an internal failure when attempting to check for JTI uniqueness.
    JtiCheck {
        /// The underlying error.
        source: crate::error::Error,
    },
    /// The token is structurally valid but does not contain the required extra claims.
    ExtraClaims {
        /// The underlying deserialization error.
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    };

    #[derive(Debug)]
    struct MockVerifier;

    impl JwsVerifier for MockVerifier {
        type Error = crate::BoxedError;

        fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            Some(KeyMatchStrength::ByAlgorithm)
        }

        async fn verify(
            &self,
            _input: &[u8],
            _signature: &[u8],
            _key: &KeyMatch<'_>,
        ) -> Result<(), VerifyError<Self::Error>> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_validate_unit_claims_with_extra_fields() {
        // A JWT with standard claims + an extra field "foo"
        // Header: {"alg": "RS256", "typ": "JWT"}
        // Claims: {"iss": "joe", "foo": "bar"}
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJmb28iOiJiYXIifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::required_value("joe"))
            .build();

        // This should succeed even though "foo": "bar" is present and C is ()
        let result = validator.validate::<()>(token).await;
        assert!(result.is_ok(), "Expected Ok, got {:?}", result.err());
    }

    #[tokio::test]
    async fn test_validate_custom_claims_success() {
        #[derive(Debug, Clone, Deserialize, PartialEq)]
        struct MyClaims {
            foo: String,
        }

        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJmb28iOiJiYXIifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::required_value("joe"))
            .build();

        let result = validator.validate::<MyClaims>(token).await.unwrap();
        assert_eq!(
            result.claims,
            MyClaims {
                foo: "bar".to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_validate_custom_claims_failure() {
        #[derive(Debug, Clone, Deserialize, PartialEq)]
        struct MyClaims {
            missing: String,
        }

        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJmb28iOiJiYXIifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::required_value("joe"))
            .build();

        let result = validator.validate::<MyClaims>(token).await;
        assert!(matches!(
            result,
            Err(JwtValidationError::ExtraClaims { .. })
        ));
    }

    // Helper to create a ParsedJws with given header/claims
    fn make_parsed_jws(
        header: serde_json::Value,
        claims: serde_json::Value,
    ) -> ParsedJws<(), serde_json::Value> {
        use crate::jwt::structure::{JwtClaims, JwtHeader};

        let header: JwtHeader<'static, ()> = serde_json::from_value(header).unwrap();
        let claims: JwtClaims<'static, serde_json::Value> = serde_json::from_value(claims).unwrap();

        ParsedJws {
            header,
            claims,
            signing_input: b"dummy.input".to_vec(),
            signature: vec![0x00],
        }
    }

    fn default_validator() -> JwtValidator {
        JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .build()
    }

    // --- Algorithm checks ---

    #[tokio::test]
    async fn reject_alg_none() {
        let parsed = make_parsed_jws(serde_json::json!({"alg": "none"}), serde_json::json!({}));
        let result = default_validator()
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(result, Err(JwtValidationError::UnsignedToken)));
    }

    #[tokio::test]
    async fn reject_disallowed_algorithm() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .allowed_algorithms(["ES256".to_string()])
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::DisallowedAlgorithm { .. })
        ));
    }

    // --- Critical header ---

    #[tokio::test]
    async fn reject_unrecognized_crit() {
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256", "crit": ["unknown-ext"]}),
            serde_json::json!({}),
        );
        let result = default_validator()
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::UnrecognizedCriticalHeader { .. })
        ));
    }

    // --- Temporal checks ---

    #[tokio::test]
    async fn reject_expired_token() {
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"exp": 1}), // expired long ago
        );
        let result = default_validator()
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(result, Err(JwtValidationError::Expired { .. })));
    }

    #[tokio::test]
    async fn reject_not_yet_valid() {
        let far_future = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 999_999;
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"nbf": far_future}),
        );
        let result = default_validator()
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::NotYetValid { .. })
        ));
    }

    #[tokio::test]
    async fn reject_issued_in_future() {
        let far_future = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 999_999;
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"iat": far_future}),
        );
        let result = default_validator()
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::IssuedInFuture { .. })
        ));
    }

    #[tokio::test]
    async fn clock_leeway_allows_slightly_expired() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .clock_leeway(Duration::from_secs(10))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"exp": now - 5}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(result.is_ok());
    }

    // --- Required claims ---

    #[tokio::test]
    async fn require_exp_missing() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .require_exp(true)
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::RequiredClaimMissing { claim: "exp" })
        ));
    }

    #[tokio::test]
    async fn require_iat_missing() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .require_iat(true)
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::RequiredClaimMissing { claim: "iat" })
        ));
    }

    #[tokio::test]
    async fn require_jti_missing() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .require_jti(true)
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::RequiredClaimMissing { claim: "jti" })
        ));
    }

    // --- iss claim checks ---

    #[tokio::test]
    async fn iss_required_value_mismatch() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::required_value("expected-issuer"))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"iss": "wrong-issuer"}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::ClaimMismatch { claim: "iss", .. })
        ));
    }

    #[tokio::test]
    async fn iss_require_any_mismatch() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::require_any(["a", "b"]))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"iss": "c"}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::ClaimMismatch { claim: "iss", .. })
        ));
    }

    #[tokio::test]
    async fn iss_present_missing() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::present())
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::RequiredClaimMissing { claim: "iss" })
        ));
    }

    #[tokio::test]
    async fn iss_if_present_mismatch() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::if_present("expected"))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"iss": "wrong"}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::ClaimMismatch { claim: "iss", .. })
        ));
    }

    #[tokio::test]
    async fn iss_if_present_absent_ok() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .iss(ClaimCheck::if_present("expected"))
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(result.is_ok());
    }

    // --- aud claim checks ---

    #[tokio::test]
    async fn aud_required_value_not_in_list() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .aud(ClaimCheck::required_value("expected-aud"))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"aud": "wrong-aud"}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::ClaimMismatch { claim: "aud", .. })
        ));
    }

    #[tokio::test]
    async fn aud_empty_when_required() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .aud(ClaimCheck::present())
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::RequiredClaimMissing { claim: "aud" })
        ));
    }

    // --- typ claim checks ---

    #[tokio::test]
    async fn typ_required_value_mismatch() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .typ(ClaimCheck::required_value("at+jwt"))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256", "typ": "JWT"}),
            serde_json::json!({}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::InvalidTokenType { .. })
        ));
    }

    #[tokio::test]
    async fn typ_application_prefix_normalization() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .typ(ClaimCheck::required_value("at+jwt"))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256", "typ": "application/at+jwt"}),
            serde_json::json!({}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn typ_case_insensitive() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .typ(ClaimCheck::required_value("AT+JWT"))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256", "typ": "at+jwt"}),
            serde_json::json!({}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(result.is_ok());
    }

    // --- max_token_age ---

    #[tokio::test]
    async fn max_token_age_old_token() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .max_token_age(Duration::from_mins(1))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"iat": 1}), // issued at epoch
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::TokenTooOld { .. })
        ));
    }

    #[tokio::test]
    async fn max_token_age_missing_iat() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .max_token_age(Duration::from_mins(1))
            .build();
        let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::RequiredClaimMissing { claim: "iat" })
        ));
    }

    // --- Panic resistance on attacker-controlled input ---

    #[test]
    fn normalize_typ_non_char_boundary() {
        // 11 ASCII bytes followed by a two-byte UTF-8 char: byte 12 is not a
        // char boundary. Direct `&typ[..12]` indexing would panic here.
        let typ = "abcdefghijké-jwt";
        assert!(!typ.is_char_boundary(12));
        assert_eq!(normalize_typ(typ), typ);

        // Normal prefix stripping still works.
        assert_eq!(normalize_typ("application/at+jwt"), "at+jwt");
        assert_eq!(normalize_typ("APPLICATION/at+jwt"), "at+jwt");
        assert_eq!(normalize_typ("application/"), "application/");
        assert_eq!(normalize_typ("JWT"), "JWT");
    }

    #[tokio::test]
    async fn overflowing_exp_is_a_parse_error_not_a_panic() {
        use base64::prelude::*;

        // exp = u64::MAX overflows SystemTime on every platform; the token must
        // fail structural parsing instead of panicking during validation.
        let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let claims = BASE64_URL_SAFE_NO_PAD.encode(r#"{"exp":18446744073709551615}"#);
        let signature = BASE64_URL_SAFE_NO_PAD.encode([0x00]);
        let token = [header, claims, signature].join(".");

        let result = default_validator().validate::<()>(&token).await;
        assert!(matches!(result, Err(JwtValidationError::Parse { .. })));
    }

    #[tokio::test]
    async fn max_representable_exp_with_leeway_does_not_panic() {
        // An `exp` at the edge of the representable SystemTime range used to
        // panic in `expiration + clock_leeway`. Skip on platforms where the
        // value is not representable (it then fails at deserialization instead).
        let secs = 9_223_372_036_854_775_807_u64;
        if SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))
            .is_none()
        {
            return;
        }

        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .clock_leeway(Duration::from_secs(10))
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"exp": secs, "nbf": 0, "iat": 0}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(result.is_ok(), "far-future exp is valid: {result:?}");
    }

    // --- JTI uniqueness ordering ---

    /// In-memory JTI store recording every `check_and_mark_seen` call.
    #[derive(Debug, Default)]
    struct InMemoryJtiChecker {
        seen: std::sync::Mutex<std::collections::HashSet<String>>,
    }

    impl JtiUniquenessChecker for InMemoryJtiChecker {
        fn check_and_mark_seen(
            &self,
            jti: &str,
        ) -> crate::platform::MaybeSendBoxFuture<'_, Result<bool, crate::error::Error>> {
            let previously_seen = !self.seen.lock().unwrap().insert(jti.to_owned());
            Box::pin(async move { Ok(previously_seen) })
        }
    }

    #[tokio::test]
    async fn temporally_invalid_token_does_not_burn_jti() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .jti_checker(InMemoryJtiChecker::default())
            .build();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // A token presented before its `nbf` is rejected, but its `jti` must
        // not be marked seen — the later legitimate presentation must succeed.
        let early = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"jti": "jti-1", "nbf": now + 999_999}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(early)
            .await;
        assert!(matches!(
            result,
            Err(JwtValidationError::NotYetValid { .. })
        ));

        // Likewise for an expired token.
        let expired = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"jti": "jti-2", "exp": 1}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(expired)
            .await;
        assert!(matches!(result, Err(JwtValidationError::Expired { .. })));

        // The legitimate presentations succeed.
        for jti in ["jti-1", "jti-2"] {
            let valid = make_parsed_jws(
                serde_json::json!({"alg": "RS256"}),
                serde_json::json!({"jti": jti, "nbf": now - 10, "exp": now + 3600}),
            );
            let result = validator
                .validate_parsed_jws::<serde_json::Value>(valid)
                .await;
            assert!(result.is_ok(), "{jti} should not be burned: {result:?}");
        }

        // Replay of a successfully validated token is still rejected.
        let replay = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"jti": "jti-1", "nbf": now - 10, "exp": now + 3600}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(replay)
            .await;
        assert!(matches!(result, Err(JwtValidationError::JtiNotUnique)));
    }

    // --- JTI too long ---

    #[tokio::test]
    async fn jti_too_long() {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(MockVerifier))
            .max_jti_len(5)
            .build();
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"jti": "toolong"}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(parsed)
            .await;
        assert!(matches!(result, Err(JwtValidationError::JtiTooLong { .. })));
    }
}
