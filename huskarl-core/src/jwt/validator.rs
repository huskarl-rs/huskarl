//! Validation infrastructure for JWT tokens.

use std::collections::HashSet;

use bon::Builder;
use serde::Deserialize;
use snafu::{ResultExt as _, Snafu, ensure};

use crate::{
    BoxedError,
    crypto::verifier::{BoxedJwsVerifier, JwsVerifier, KeyMatch, VerifyError},
    jwt::{
        BoxedJtiUniquenessChecker, ConfirmationClaim, JtiUniquenessChecker, JwsParseError,
        ParsedJws, parse_compact_jws,
    },
    platform::{Duration, SystemTime},
};

/// A check to perform on a JWT claim.
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
    jti_checker: Option<BoxedJtiUniquenessChecker>,
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
    if typ.len() > 12 && typ[..12].eq_ignore_ascii_case("application/") {
        &typ[12..]
    } else {
        typ
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

fn check_temporal(
    now: SystemTime,
    clock_leeway: Duration,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
) -> Result<(), JwtValidationError> {
    if let Some(exp) = exp {
        let expiration = SystemTime::UNIX_EPOCH + Duration::from_secs(exp);
        ensure!(
            expiration + clock_leeway >= now,
            ExpiredSnafu { expiration, now }
        );
    }
    if let Some(nbf) = nbf {
        let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(nbf);
        ensure!(
            not_before <= now + clock_leeway,
            NotYetValidSnafu { not_before, now }
        );
    }
    if let Some(iat) = iat {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(iat);
        ensure!(
            issued_at <= now + clock_leeway,
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
        exp: Option<u64>,
        iat: Option<u64>,
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
        self.validate_jti(parsed_jwt.claims.jti.as_deref()).await?;

        if let Some(max_token_age) = self.max_token_age {
            let iat = parsed_jwt
                .claims
                .iat
                .ok_or_else(|| RequiredClaimMissingSnafu { claim: "iat" }.build())?;

            let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(iat);

            ensure!(
                now.duration_since(issued_at)
                    .is_ok_and(|d| d <= max_token_age + self.clock_leeway),
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

        Ok(ValidatedJwt {
            issuer: parsed_jwt.claims.iss.map(Into::into),
            subject: parsed_jwt.claims.sub.map(Into::into),
            audience: parsed_jwt.claims.aud.iter().map(Into::into).collect(),
            issued_at: parsed_jwt
                .claims
                .iat
                .map(|iat| SystemTime::UNIX_EPOCH + Duration::from_secs(iat)),
            expiration: parsed_jwt
                .claims
                .exp
                .map(|exp| SystemTime::UNIX_EPOCH + Duration::from_secs(exp)),
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
#[derive(Debug)]
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
        source: BoxedError,
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
}
