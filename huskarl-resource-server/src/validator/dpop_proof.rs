//! `DPoP` proof structural validation.
//!
//! Validates `DPoP` proof structure (JWS format, embedded JWK, signature, typ/alg/iat/exp)
//! and returns the validated claims for downstream binding checks. Does **not** check
//! htm/htu/ath against request context or thumbprint against `cnf.jkt` — those are
//! binding-level checks that depend on consumer context.

use std::sync::Arc;

use bon::Builder;
use serde::Deserialize;
use snafu::prelude::*;

use crate::core::{
    crypto::verifier::{CreateVerifierError, JwsVerifierPlatform},
    jwt::{
        JtiUniquenessChecker, JwsParseError, parse_compact_jws,
        validator::{ClaimCheck, JwtValidationError, JwtValidator},
    },
    platform::{Duration, SystemTime},
};

/// Claims extracted from a validated `DPoP` proof.
///
/// All claim fields are `Option` because this validator only enforces structural
/// validity (signature, typ, alg, iat/exp). Whether specific claims like `htm`,
/// `htu`, or `ath` are required is a consumer-level decision.
#[non_exhaustive]
pub struct ValidatedDPoPProof {
    /// HTTP method the proof was created for (`htm` claim).
    pub htm: Option<String>,
    /// HTTP URI the proof was created for (`htu` claim).
    pub htu: Option<String>,
    /// Access token hash, base64url SHA-256 (`ath` claim).
    pub ath: Option<String>,
    /// Server-provided nonce echoed in the proof (`nonce` claim).
    pub nonce: Option<String>,
    /// Unique identifier for replay protection (`jti` claim).
    pub jti: Option<String>,
    /// JWK thumbprint of the proof's embedded key.
    pub thumbprint: Option<String>,
    /// Algorithm used by the proof (`alg` header).
    pub alg: String,
    /// Issued-at timestamp (seconds since epoch), if present.
    pub iat: Option<u64>,
    /// Expiration timestamp (seconds since epoch), if present.
    pub exp: Option<u64>,
}

/// Configuration for `DPoP` proof structural validation.
///
/// Validates that a `DPoP` proof is a well-formed, self-signed JWS with
/// `typ=dpop+jwt`, an asymmetric algorithm, and an embedded JWK. Returns
/// the proof's claims for downstream binding checks.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use huskarl_resource_server::validator::dpop_proof::DPoPProofValidator;
/// # use huskarl_resource_server::core::crypto::verifier::JwsVerifierPlatform;
///
/// # fn example(platform: Arc<dyn JwsVerifierPlatform>) {
/// let validator = DPoPProofValidator::builder()
///     .jws_verifier_platform(platform)
///     .build();
/// # }
/// ```
#[derive(Debug, Builder)]
pub struct DPoPProofValidator {
    /// Crypto platform for creating signature verifiers from embedded JWKs.
    jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
    /// Maximum allowed proof age based on `iat`. Default: 1 minute.
    #[builder(default = Duration::from_mins(1))]
    max_proof_age: Duration,
    /// Clock-skew leeway for the proof's temporal checks (RFC 9449 §11.1).
    /// Default: [`DEFAULT_CLOCK_LEEWAY`](super::DEFAULT_CLOCK_LEEWAY).
    #[builder(default = super::DEFAULT_CLOCK_LEEWAY)]
    clock_leeway: Duration,
    /// Allowed signing algorithms. `None` permits any asymmetric algorithm.
    allowed_signing_algorithms: Option<Vec<String>>,
    /// Optional JTI uniqueness checker for replay protection.
    jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
}

impl DPoPProofValidator {
    /// Returns the allowed signing algorithms, if configured.
    #[must_use]
    pub fn allowed_signing_algorithms(&self) -> Option<&[String]> {
        self.allowed_signing_algorithms.as_deref()
    }

    /// Validate a `DPoP` proof's structure and signature.
    ///
    /// On success, returns a [`ValidatedDPoPProof`] containing the proof's claims
    /// and the JWK thumbprint. The caller is responsible for binding checks (e.g.
    /// verifying `htm`/`htu`/`ath` match the request, or `thumbprint` matches
    /// the token's `cnf.jkt`).
    ///
    /// # Errors
    ///
    /// Returns a [`DPoPProofError`] if the proof is malformed, uses a disallowed
    /// algorithm, has an invalid signature, or fails temporal checks.
    pub async fn validate(&self, proof: &str) -> Result<ValidatedDPoPProof, DPoPProofError> {
        let parsed = parse_compact_jws::<(), DPoPProofClaims>(proof).context(BadFormatSnafu)?;

        let jwk = parsed
            .header
            .jwk
            .clone()
            .ok_or_else(|| MissingJwkHeaderSnafu.build())?;

        ensure!(jwk.x5u.is_none(), JwkX5uSnafu);
        ensure!(!jwk.has_private_parameters, JwkPrivateKeySnafu);

        let thumbprint = jwk.thumbprint();
        let alg = parsed.header.alg.clone().into_owned();

        let verifier = self
            .jws_verifier_platform
            .create_verifier_from_jwk(jwk)
            .await
            .context(CreateVerifierSnafu)?;

        let validator = JwtValidator::builder()
            .verifier(verifier)
            .typ(ClaimCheck::required_value("dpop+jwt"))
            .maybe_allowed_algorithms(self.allowed_signing_algorithms.clone())
            .max_token_age(self.max_proof_age)
            .clock_leeway(self.clock_leeway)
            .require_jti(self.jti_checker.is_some())
            .maybe_jti_checker(self.jti_checker.clone())
            .build();

        let validated = validator
            .validate_parsed_jws(parsed)
            .await
            .context(InvalidProofSnafu)?;

        Ok(ValidatedDPoPProof {
            htm: validated.claims.htm,
            htu: validated.claims.htu,
            ath: validated.claims.ath,
            nonce: validated.claims.nonce,
            jti: validated.jti,
            thumbprint: Some(thumbprint),
            alg,
            iat: validated.iat.and_then(|t| {
                t.duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            }),
            exp: validated.exp.and_then(|t| {
                t.duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            }),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DPoPProofClaims {
    htm: Option<String>,
    htu: Option<String>,
    ath: Option<String>,
    nonce: Option<String>,
}

impl DPoPProofError {
    /// Human-readable error description suitable for RFC 6750 `error_description`.
    #[must_use]
    pub fn error_description(&self) -> Option<String> {
        match self {
            Self::BadFormat { .. } => Some("The DPoP proof is malformed".to_string()),
            Self::MissingJwkHeader => Some("The DPoP proof is missing the JWK header".to_string()),
            Self::JwkX5u => {
                Some("The DPoP proof JWK contains an unsupported x5u parameter".to_string())
            }
            Self::JwkPrivateKey => {
                Some("The DPoP proof JWK contains private-key material".to_string())
            }
            Self::CreateVerifier { .. } => Some("The DPoP proof signature is invalid".to_string()),
            Self::InvalidProof { source } => {
                use JwtValidationError as E;
                match source {
                    E::Parse { .. } => Some("The DPoP proof is malformed".to_string()),
                    E::Signature { .. } => Some("The DPoP proof signature is invalid".to_string()),
                    E::UnsignedToken => Some("The DPoP proof is unsigned".to_string()),
                    E::DisallowedAlgorithm { .. } => {
                        Some("The DPoP proof uses an unsupported signature algorithm".to_string())
                    }
                    E::UnrecognizedCriticalHeader { .. } => Some(
                        "The DPoP proof contains unrecognized critical header parameters"
                            .to_string(),
                    ),
                    E::Expired { .. } => Some("The DPoP proof has expired".to_string()),
                    E::NotYetValid { .. } => Some("The DPoP proof is not yet valid".to_string()),
                    E::IssuedInFuture { .. } => {
                        Some("The DPoP proof was issued in the future".to_string())
                    }
                    E::TokenTooOld { .. } => Some("The DPoP proof is too old".to_string()),
                    E::InvalidTokenType { .. } => {
                        Some("The DPoP proof has an invalid typ header".to_string())
                    }
                    E::ClaimMismatch { claim, .. } => {
                        Some(format!("The DPoP proof '{claim}' claim is invalid"))
                    }
                    E::RequiredClaimMissing { claim } => Some(format!(
                        "The DPoP proof is missing the required '{claim}' claim"
                    )),
                    E::JtiNotUnique => Some("The DPoP proof jti has already been used".to_string()),
                    E::JtiTooLong { .. } => Some("The DPoP proof jti is too long".to_string()),
                    E::JtiCheck { .. } | E::ExtraClaims { .. } => None,
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(all(not(target_family = "wasm"), feature = "default-jws-verifier-platform"))]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;
    use crate::DefaultJwsVerifierPlatform;

    const EC_PUBLIC: &str = r#""kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM""#;

    /// A structurally valid proof with the given JWK JSON embedded in the
    /// header. The signature is garbage, which is fine for these tests: the
    /// JWK header checks fire before signature verification.
    fn proof_with_jwk(jwk_json: &str) -> String {
        let header = format!(r#"{{"alg":"ES256","typ":"dpop+jwt","jwk":{jwk_json}}}"#);
        let claims = r#"{"jti":"test-jti","htm":"GET","htu":"https://rs.example/r"}"#;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode("sig")
        )
    }

    fn validator() -> DPoPProofValidator {
        DPoPProofValidator::builder()
            .jws_verifier_platform(DefaultJwsVerifierPlatform::default().into())
            .build()
    }

    /// RFC 9449 §4.2: the proof's `jwk` header MUST NOT contain a private key.
    #[tokio::test]
    async fn proof_jwk_with_private_key_material_is_rejected() {
        let jwk = format!(r#"{{{EC_PUBLIC},"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}}"#);
        let err = validator()
            .validate(&proof_with_jwk(&jwk))
            .await
            .err()
            .expect("validation should fail");
        assert!(matches!(err, DPoPProofError::JwkPrivateKey), "got {err:?}");
    }

    /// Control: the same proof without `d` gets past the JWK header checks
    /// (it fails later, on its garbage signature).
    #[tokio::test]
    async fn proof_jwk_without_private_key_material_passes_the_header_check() {
        let jwk = format!("{{{EC_PUBLIC}}}");
        let err = validator()
            .validate(&proof_with_jwk(&jwk))
            .await
            .err()
            .expect("validation should fail");
        assert!(!matches!(err, DPoPProofError::JwkPrivateKey), "got {err:?}");
    }
}

/// Errors from `DPoP` proof structural validation.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DPoPProofError {
    /// Not a valid compact JWS.
    #[snafu(display("Bad DPoP proof format"))]
    BadFormat {
        /// The underlying parse error.
        source: JwsParseError,
    },
    /// No embedded JWK in proof header.
    #[snafu(display("DPoP proof is missing the JWK header"))]
    MissingJwkHeader,
    /// JWK contains `x5u`, rejected for SSRF prevention.
    #[snafu(display("DPoP proof JWK contains unsupported x5u parameter"))]
    JwkX5u,
    /// JWK contains private-key material, forbidden by RFC 9449 §4.2.
    #[snafu(display("DPoP proof JWK contains private-key material"))]
    JwkPrivateKey,
    /// Cannot create verifier from embedded JWK.
    #[snafu(display("Failed to create DPoP verification key"))]
    CreateVerifier {
        /// The underlying error.
        source: CreateVerifierError,
    },
    /// JWT validation failed (signature, expiry, typ, alg, etc.).
    #[snafu(display("Invalid DPoP proof"))]
    InvalidProof {
        /// The underlying validation error.
        source: JwtValidationError,
    },
}
