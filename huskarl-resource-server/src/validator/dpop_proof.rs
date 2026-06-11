//! DPoP proof structural validation.
//!
//! Validates DPoP proof structure (JWS format, embedded JWK, signature, typ/alg/iat/exp)
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

/// Claims extracted from a validated DPoP proof.
///
/// All claim fields are `Option` because this validator only enforces structural
/// validity (signature, typ, alg, iat/exp). Whether specific claims like `htm`,
/// `htu`, or `ath` are required is a consumer-level decision.
pub struct ValidatedDpopProof {
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

/// Configuration for DPoP proof structural validation.
///
/// Validates that a DPoP proof is a well-formed, self-signed JWS with
/// `typ=dpop+jwt`, an asymmetric algorithm, and an embedded JWK. Returns
/// the proof's claims for downstream binding checks.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use huskarl_resource_server::validator::dpop_proof::DpopProofValidator;
/// # use huskarl_resource_server::core::crypto::verifier::JwsVerifierPlatform;
///
/// # fn example(platform: Arc<dyn JwsVerifierPlatform>) {
/// let validator = DpopProofValidator::builder()
///     .jws_verifier_platform(platform)
///     .build();
/// # }
/// ```
#[derive(Debug, Builder)]
pub struct DpopProofValidator {
    /// Crypto platform for creating signature verifiers from embedded JWKs.
    jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
    /// Maximum allowed proof age based on `iat`. Default: 60 seconds.
    #[builder(default = Duration::from_secs(60))]
    max_proof_age: Duration,
    /// Allowed signing algorithms. `None` permits any asymmetric algorithm.
    allowed_signing_algorithms: Option<Vec<String>>,
    /// Optional JTI uniqueness checker for replay protection.
    jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
}

impl DpopProofValidator {
    /// Returns the allowed signing algorithms, if configured.
    #[must_use]
    pub fn allowed_signing_algorithms(&self) -> Option<&[String]> {
        self.allowed_signing_algorithms.as_deref()
    }

    /// Validate a DPoP proof's structure and signature.
    ///
    /// On success, returns a [`ValidatedDpopProof`] containing the proof's claims
    /// and the JWK thumbprint. The caller is responsible for binding checks (e.g.
    /// verifying `htm`/`htu`/`ath` match the request, or `thumbprint` matches
    /// the token's `cnf.jkt`).
    ///
    /// # Errors
    ///
    /// Returns a [`DpopProofError`] if the proof is malformed, uses a disallowed
    /// algorithm, has an invalid signature, or fails temporal checks.
    pub async fn validate(&self, proof: &str) -> Result<ValidatedDpopProof, DpopProofError> {
        let parsed = parse_compact_jws::<(), DpopProofClaims>(proof).context(BadFormatSnafu)?;

        let jwk = parsed
            .header
            .jwk
            .clone()
            .ok_or_else(|| MissingJwkHeaderSnafu.build())?;

        ensure!(jwk.x5u.is_none(), JwkX5uSnafu);

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
            .require_jti(self.jti_checker.is_some())
            .maybe_jti_checker(self.jti_checker.clone())
            .build();

        let validated = validator
            .validate_parsed_jws(parsed)
            .await
            .context(InvalidProofSnafu)?;

        Ok(ValidatedDpopProof {
            htm: validated.claims.htm,
            htu: validated.claims.htu,
            ath: validated.claims.ath,
            nonce: validated.claims.nonce,
            jti: validated.jti,
            thumbprint: Some(thumbprint),
            alg,
            iat: validated.issued_at.and_then(|t| {
                t.duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            }),
            exp: validated.expiration.and_then(|t| {
                t.duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            }),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DpopProofClaims {
    htm: Option<String>,
    htu: Option<String>,
    ath: Option<String>,
    nonce: Option<String>,
}

impl DpopProofError {
    /// Human-readable error description suitable for RFC 6750 `error_description`.
    #[must_use]
    pub fn error_description(&self) -> Option<String> {
        match self {
            Self::BadFormat { .. } => Some("The DPoP proof is malformed".to_string()),
            Self::MissingJwkHeader => Some("The DPoP proof is missing the JWK header".to_string()),
            Self::JwkX5u => {
                Some("The DPoP proof JWK contains an unsupported x5u parameter".to_string())
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

/// Errors from DPoP proof structural validation.
#[derive(Debug, Snafu)]
pub enum DpopProofError {
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
