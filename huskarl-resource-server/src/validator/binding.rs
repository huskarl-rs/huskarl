//! Token sender-constraint binding checks for DPoP and mTLS.
//!
//! These functions operate on an already-validated token's [`ConfirmationClaim`]
//! and can be shared across JWT validation and token introspection flows.

use std::sync::Arc;

use base64::prelude::*;
use http::StatusCode;
use huskarl_core::{BoxedError, jwt::BoxedJtiUniquenessChecker, secrets::SecretString};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use snafu::{ensure, prelude::*};

use crate::{
    TokenType,
    core::{
        crypto::verifier::{CreateVerifierError, JwsVerifierPlatform},
        dpop::{hash_access_token_for_dpop, normalize_uri_for_dpop},
        jwt::{
            ConfirmationClaim, JwsParseError, parse_compact_jws,
            validator::{ClaimCheck, JwtValidationError, JwtValidator},
        },
        platform::Duration,
    },
    validator::{
        dpop_nonce::{DpopNonceChecker, NonceCheck},
        error::{
            DPoPBindingSnafu, DPoPHeaderNotStringSnafu, DpopRequiredForBoundTokenSnafu,
            DpopRequiredSnafu, MissingDPoPHeaderSnafu, MtlsBindingSnafu, TokenBindingError,
            UnsupportedCnfMethodSnafu,
        },
    },
};

/// Checks mTLS sender-constraint binding for a validated token.
///
/// If the token contains a certificate thumbprint binding (`cnf.x5t#S256`),
/// the provided client certificate must match. If `require_mtls` is `true`,
/// the token must carry a binding; tokens without one are rejected.
pub(crate) fn check_mtls_binding(
    cnf: Option<&ConfirmationClaim>,
    client_cert_der: Option<&[u8]>,
    require_mtls: bool,
) -> Result<(), MtlsBindingError> {
    if let Some(expected_thumbprint) = cnf.and_then(|c| c.x5t_s256.as_ref()) {
        let cert_der = client_cert_der.ok_or_else(|| CertBoundTokenWithoutCertSnafu.build())?;
        ensure!(
            cert_thumbprint(cert_der) == *expected_thumbprint,
            CertThumbprintMismatchSnafu
        );
    } else if require_mtls {
        MtlsRequiredSnafu.fail()?;
    }
    Ok(())
}

/// Validates all sender-constraint bindings for an access token.
///
/// Checks unsupported `cnf` methods (`jwe`, `jku`), then performs
/// token-type-specific binding (Bearer: rejects DPoP-bound tokens; DPoP: validates
/// the proof), then validates any mTLS certificate binding.
/// Returns the DPoP nonce to include in the response (if any) alongside the binding result.
///
/// The nonce is `Some` when the nonce checker issued a fresh nonce (either proactively on
/// [`NonceCheck::ValidWithNewNonce`] or as a required retry on [`NonceCheck::Invalid`]).
/// It is present even when the binding result is `Err`, so callers can always set the
/// `DPoP-Nonce` response header regardless of outcome.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn check_token_binding<N: DpopNonceChecker>(
    token_type: TokenType,
    cnf: Option<&ConfirmationClaim>,
    access_token: &SecretString,
    dpop_binding_checker: &DPoPBindingChecker<N>,
    require_mtls: bool,
    headers: &http::HeaderMap,
    http_method: &http::Method,
    http_uri: &http::Uri,
    client_cert_der: Option<&[u8]>,
) -> (Option<String>, Result<(), TokenBindingError>) {
    if let Some(cnf) = cnf {
        if cnf.jwe.is_some() {
            return (None, UnsupportedCnfMethodSnafu { method: "jwe" }.fail());
        }
        if cnf.jku.is_some() {
            return (None, UnsupportedCnfMethodSnafu { method: "jku" }.fail());
        }
    }

    let dpop_nonce = match token_type {
        TokenType::Bearer => {
            // RFC 9449 §7.1: a token with a DPoP key binding (cnf.jkt) MUST NOT be
            // accepted as a Bearer token — doing so would defeat the binding entirely.
            if cnf.and_then(|c| c.jkt.as_ref()).is_some() {
                return (None, DpopRequiredForBoundTokenSnafu.fail());
            }
            if dpop_binding_checker.required {
                return (None, DpopRequiredSnafu.fail());
            }
            None
        }
        TokenType::DPoP => {
            let dpop_proof = match headers
                .get("DPoP")
                .map(|hv| hv.to_str().context(DPoPHeaderNotStringSnafu))
                .transpose()
                .and_then(|opt| opt.context(MissingDPoPHeaderSnafu))
            {
                Ok(proof) => proof,
                Err(e) => return (None, Err(e)),
            };

            match dpop_binding_checker
                .check(cnf, access_token, dpop_proof, http_method, http_uri)
                .await
            {
                Ok(nonce) => nonce,
                Err(e) => {
                    let nonce = if let DPoPBindingError::NonceRequired { ref nonce } = e {
                        Some(nonce.clone())
                    } else {
                        None
                    };
                    return (nonce, Err(e).context(DPoPBindingSnafu));
                }
            }
        }
    };

    if let Err(e) = check_mtls_binding(cnf, client_cert_der, require_mtls).context(MtlsBindingSnafu)
    {
        return (dpop_nonce, Err(e));
    }

    (dpop_nonce, Ok(()))
}

fn cert_thumbprint(der: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

/// Error returned by [`check_mtls_binding`].
#[derive(Debug, Snafu)]
pub enum MtlsBindingError {
    /// Token has a certificate thumbprint binding (`cnf.x5t#S256`) but no client
    /// certificate was provided to verify against.
    #[snafu(display("Token is certificate-bound but no client certificate was presented"))]
    CertBoundTokenWithoutCert,
    /// The client certificate thumbprint does not match the binding in the token.
    #[snafu(display("Client certificate thumbprint does not match token binding"))]
    CertThumbprintMismatch,
    /// mTLS certificate-bound tokens are required but the token has no `cnf.x5t#S256` binding.
    #[snafu(display("Certificate-bound tokens are required but token has no certificate binding"))]
    MtlsRequired,
}

/// Validates DPoP sender-constraint binding for a validated token.
///
/// Verifies the DPoP proof signature, checks the `htm`/`htu`/`ath` claims
/// against the request, and confirms the proof key matches the `cnf.jkt`
/// thumbprint in the token. Also validates the provided DPoP nonce.
pub(crate) struct DPoPBindingChecker<N: DpopNonceChecker> {
    pub(crate) dpop_nonce_checker: N,
    pub(crate) dpop_jti_checker: Option<BoxedJtiUniquenessChecker>,
    pub(crate) max_proof_age: Duration,
    pub(crate) jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
    pub(crate) allowed_signing_algorithms: Option<Vec<String>>,
    /// If `true`, Bearer tokens are rejected — all tokens must be DPoP-bound.
    pub(crate) required: bool,
}

impl<N: DpopNonceChecker> DPoPBindingChecker<N> {
    pub(crate) async fn check(
        &self,
        cnf: Option<&ConfirmationClaim>,
        access_token: &SecretString,
        dpop_proof: &str,
        method: &http::Method,
        uri: &http::Uri,
    ) -> Result<Option<String>, DPoPBindingError> {
        let parsed_proof =
            parse_compact_jws::<(), DPoPClaims>(dpop_proof).context(BadFormatSnafu)?;

        let jwk_header = parsed_proof
            .header
            .jwk
            .clone()
            .ok_or_else(|| MissingJwkHeaderSnafu.build())?;

        ensure!(jwk_header.x5u.is_none(), JwkX5uSnafu);

        let thumbprint = jwk_header.thumbprint();

        let dpop_verifier = self
            .jws_verifier_platform
            .create_verifier_from_jwk(jwk_header)
            .await
            .context(CreateVerifierSnafu)?;

        let dpop_validator = JwtValidator::builder()
            .verifier(dpop_verifier)
            .typ(ClaimCheck::required_value("dpop+jwt"))
            .maybe_allowed_algorithms(self.allowed_signing_algorithms.clone())
            .max_token_age(self.max_proof_age)
            .require_jti(self.dpop_jti_checker.is_some())
            .maybe_jti_checker(self.dpop_jti_checker.clone())
            .build();

        let validated_proof = dpop_validator
            .validate_parsed_jws(parsed_proof)
            .await
            .context(InvalidProofSnafu)?;

        let proof_nonce = validated_proof
            .claims
            .as_ref()
            .and_then(|p| p.nonce.as_deref());

        let nonce_check = self
            .dpop_nonce_checker
            .check_nonce(proof_nonce)
            .await
            .map_err(|e| DPoPBindingError::NonceCheckFailed {
                source: BoxedError::from_err(e),
            })?;

        let new_nonce = match nonce_check {
            NonceCheck::Valid => None,
            NonceCheck::ValidWithNewNonce(n) => Some(n),
            NonceCheck::Invalid(n) => return NonceRequiredSnafu { nonce: n }.fail(),
        };

        let access_token_hash = hash_access_token_for_dpop(access_token.expose_secret());

        match (
            validated_proof.claims.as_ref().and_then(|c| c.htm.as_ref()),
            validated_proof.claims.as_ref().and_then(|c| c.htu.as_ref()),
            validated_proof.claims.as_ref().and_then(|c| c.ath.as_ref()),
        ) {
            (None, _, _) => return MissingProofClaimSnafu { claim: "htm" }.fail(),
            (_, None, _) => return MissingProofClaimSnafu { claim: "htu" }.fail(),
            (_, _, None) => return MissingProofClaimSnafu { claim: "ath" }.fail(),
            (Some(htm), Some(htu), Some(ath)) => {
                ensure!(
                    htm == method.as_str(),
                    ProofClaimMismatchSnafu {
                        claim: "htm",
                        expected: method.as_str(),
                        actual: htm,
                    }
                );
                ensure!(
                    *htu == normalize_uri_for_dpop(uri)
                        .context(MalformedUrlSnafu)?
                        .to_string(),
                    ProofClaimMismatchSnafu {
                        claim: "htu",
                        expected: uri.to_string(),
                        actual: htu,
                    }
                );
                ensure!(
                    *ath == access_token_hash,
                    ProofClaimMismatchSnafu {
                        claim: "ath",
                        expected: &access_token_hash,
                        actual: ath,
                    }
                );
            }
        }

        match (cnf.and_then(|c| c.jkt.as_ref()), thumbprint) {
            (None, _) => return MissingThumbprintBindingSnafu.fail(),
            (_, None) => return NoThumbprintForKeySnafu.fail(),
            (Some(jkt), Some(tp)) => ensure!(*jkt == tp, ThumbprintMismatchSnafu),
        }

        Ok(new_nonce)
    }
}

#[derive(Debug, Deserialize, Clone)]
struct DPoPClaims {
    htm: Option<String>,
    htu: Option<String>,
    ath: Option<String>,
    nonce: Option<String>,
}

/// Error returned by [`DPoPBindingChecker::check`].
#[derive(Debug, Snafu)]
pub enum DPoPBindingError {
    /// The token has no `cnf.jkt` thumbprint binding.
    #[snafu(display("Token has no DPoP key thumbprint binding"))]
    MissingThumbprintBinding,
    /// The DPoP proof key algorithm does not support thumbprint computation.
    #[snafu(display("No thumbprint for DPoP proof key"))]
    NoThumbprintForKey,
    /// The DPoP key thumbprint does not match the token's `cnf.jkt`.
    #[snafu(display("DPoP key thumbprint does not match token binding"))]
    ThumbprintMismatch,
    /// Failed to create a verifier from the embedded JWK.
    #[snafu(display("Failed to create DPoP verification key"))]
    CreateVerifier { source: CreateVerifierError },
    /// The DPoP proof is not a valid compact JWS.
    #[snafu(display("Bad DPoP proof format"))]
    BadFormat { source: JwsParseError },
    /// The HTTP URI in the proof could not be normalized.
    #[snafu(display("Malformed HTTP URL in DPoP proof"))]
    MalformedUrl { source: http::Error },
    /// The DPoP proof JWT failed validation (signature, expiry, typ, etc.).
    #[snafu(display("Invalid DPoP proof"))]
    InvalidProof { source: JwtValidationError },
    /// The DPoP proof has no `jwk` header.
    #[snafu(display("DPoP proof is missing the JWK header"))]
    MissingJwkHeader,
    /// The DPoP proof JWK header contains `x5u`, which triggers a remote fetch
    /// and is rejected to prevent SSRF and key substitution attacks.
    #[snafu(display("DPoP proof JWK contains unsupported x5u parameter"))]
    JwkX5u,
    /// The nonce checker returned an error (server-side failure).
    #[snafu(display("DPoP nonce check failed"))]
    NonceCheckFailed { source: BoxedError },
    /// The DPoP proof nonce is missing or invalid. The client must retry with the provided nonce.
    #[snafu(display("A DPoP nonce is required"))]
    NonceRequired { nonce: String },
    /// The DPoP proof is missing a required claim.
    #[snafu(display("DPoP proof is missing the required claim '{claim}'"))]
    MissingProofClaim {
        /// The missing claim name.
        claim: &'static str,
    },
    /// A claim in the DPoP proof does not match the expected value.
    #[snafu(display("DPoP proof claim '{claim}' mismatch: expected {expected}, got {actual}"))]
    ProofClaimMismatch {
        /// The claim name.
        claim: &'static str,
        /// The expected value.
        expected: String,
        /// The actual value.
        actual: String,
    },
}

impl crate::error::ToRfc6750Error for DPoPBindingError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        Some(TokenType::DPoP)
    }

    fn token_error(&self) -> crate::error::TokenValidationError {
        use crate::error::{TokenErrorCode, TokenValidationError};
        match self {
            Self::NonceCheckFailed { .. } => {
                TokenValidationError::Server(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Self::InvalidProof {
                source: crate::core::jwt::validator::JwtValidationError::JtiCheck { .. },
            } => TokenValidationError::Server(StatusCode::INTERNAL_SERVER_ERROR),
            Self::NonceRequired { .. } => {
                TokenValidationError::Client(TokenErrorCode::UseDPoPNonce)
            }
            // The token itself lacks a DPoP key binding — token-level failure.
            Self::MissingThumbprintBinding => {
                TokenValidationError::Client(TokenErrorCode::InvalidToken)
            }
            // All other variants correspond to §4.3 proof validation criteria.
            _ => TokenValidationError::Client(TokenErrorCode::InvalidDPoPProof),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::MissingThumbprintBinding => {
                Some("The access token has no DPoP key thumbprint binding".to_string())
            }
            Self::NoThumbprintForKey => Some("The DPoP proof key is invalid".to_string()),
            Self::ThumbprintMismatch => {
                Some("The DPoP key thumbprint does not match the token binding".to_string())
            }
            Self::CreateVerifier { .. } => Some("The DPoP proof signature is invalid".to_string()),
            Self::BadFormat { .. } => Some("The DPoP proof is malformed".to_string()),
            Self::MalformedUrl { .. } => {
                Some("The DPoP proof has a malformed HTTP URL".to_string())
            }
            Self::InvalidProof { source } => {
                use crate::core::jwt::validator::JwtValidationError as E;
                match source {
                    E::Parse { .. } => Some("The DPoP proof is malformed".to_string()),
                    E::Signature { .. } => {
                        Some("The DPoP proof signature is invalid".to_string())
                    }
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
                    E::JtiNotUnique => {
                        Some("The DPoP proof jti has already been used".to_string())
                    }
                    E::JtiCheck { .. } => None,
                }
            }
            Self::MissingJwkHeader => Some("The DPoP proof is missing the JWK header".to_string()),
            Self::JwkX5u => {
                Some("The DPoP proof JWK contains an unsupported x5u parameter".to_string())
            }
            Self::NonceCheckFailed { .. } => None,
            Self::NonceRequired { .. } => Some("A DPoP nonce is required".to_string()),
            Self::MissingProofClaim { claim } => Some(format!(
                "The DPoP proof is missing the required '{claim}' claim"
            )),
            Self::ProofClaimMismatch { claim, .. } => {
                Some(format!("The DPoP proof '{claim}' claim is invalid"))
            }
        }
    }
}

impl crate::error::ToRfc6750Error for MtlsBindingError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn token_error(&self) -> crate::error::TokenValidationError {
        crate::error::TokenValidationError::Client(crate::error::TokenErrorCode::InvalidToken)
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::CertBoundTokenWithoutCert => Some(
                "The access token is certificate-bound but no client certificate was presented"
                    .to_string(),
            ),
            Self::CertThumbprintMismatch => Some(
                "The client certificate thumbprint does not match the token binding".to_string(),
            ),
            Self::MtlsRequired => {
                Some("The protected resource requires a client certificate".to_string())
            }
        }
    }
}
