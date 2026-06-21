//! Validation infrastructure for JWT tokens.

use std::{collections::HashSet, sync::Arc};

use bon::Builder;
use serde::Deserialize;
use snafu::{ResultExt as _, Snafu, ensure};

use crate::{
    crypto::verifier::{JwsVerifier, KeyMatch, VerifyError},
    jwt::{JtiUniquenessChecker, JwsParseError, ParsedJws, parse_compact_jws},
    platform::{Duration, SystemTime},
};

mod checks;
mod claim_check;
mod validated_jwt;

use checks::{check_aud, check_str_claim, check_temporal, check_typ};
pub use claim_check::ClaimCheck;
pub use validated_jwt::{ValidatedJwt, ValidatedJwtBuilder};

/// Validates a JWT: verifies the JWS signature and checks the registered claims
/// (`iss`/`sub`/`aud`/`typ`/`exp`/`iat`/`nbf`, and optionally `jti` uniqueness).
///
/// Build one with [`builder`](Self::builder); call [`validate`](Self::validate)
/// to verify a token and recover its claims.
///
/// # Warning
///
/// By default `exp` is **not** required: a validly-signed token with no expiry
/// is accepted. Set `require_exp(true)` on the [builder](Self::builder) unless
/// non-expiring tokens are intentional. The bundled profiles (RFC 9068 access
/// tokens, OIDC ID tokens) already enable it.
#[allow(clippy::struct_excessive_bools)]
#[allow(clippy::should_implement_trait)] // `sub` is the JWT claim name, not arithmetic subtraction
#[derive(Debug, Builder)]
pub struct JwtValidator {
    /// JWS verifier to use for token validation.
    #[builder(with = |verifier: impl JwsVerifier + 'static| Arc::new(verifier) as Arc<dyn JwsVerifier>)]
    verifier: Arc<dyn JwsVerifier>,
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
    /// Optional checker used to reject replayed `jti` values; see
    /// [`JtiUniquenessChecker`].
    #[builder(with = |checker: impl JtiUniquenessChecker + 'static| Arc::new(checker) as Arc<dyn JtiUniquenessChecker>)]
    jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
    /// Maximum token age to validate against.
    max_token_age: Option<Duration>,
    /// Leeway applied to the time-based checks (`exp`, `nbf`, `iat`, and
    /// `max_token_age`) to tolerate clock skew. Defaults to none.
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

/// Validation errors that can occur while processing a JWT.
#[derive(Debug, Snafu)]
pub enum JwtValidationError {
    /// The token could not be parsed as a compact JWS.
    Parse {
        /// The underlying error.
        source: JwsParseError,
    },
    /// The token signature is invalid.
    Signature {
        /// The underlying error.
        source: VerifyError,
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
mod tests;
