//! Token sender-constraint binding checks for DPoP and mTLS.
//!
//! These functions operate on an already-validated token's [`ConfirmationClaim`]
//! and can be shared across JWT validation and token introspection flows.

use std::sync::Arc;

use base64::prelude::*;
use huskarl_core::secrets::SecretString;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use snafu::{ensure, prelude::*};

use crate::{
    core::{
        crypto::verifier::{CreateVerifierError, JwsVerifierPlatform},
        dpop::{hash_access_token_for_dpop, normalize_uri_for_dpop},
        jwt::validator::{ClaimCheck, JwtValidationError, JwtValidator},
        jwt::{ConfirmationClaim, JwsParseError, parse_compact_jws},
        platform::Duration,
    },
    validator::{
        error::{
            DPoPBindingSnafu, DPoPHeaderNotStringSnafu, DpopRequiredForBoundTokenSnafu,
            DpopRequiredSnafu, MissingDPoPHeaderSnafu, MtlsBindingSnafu, TokenBindingError,
            UnsupportedCnfMethodSnafu,
        },
        extract::TokenType,
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn check_token_binding(
    token_type: TokenType,
    cnf: Option<&ConfirmationClaim>,
    access_token: &SecretString,
    dpop_binding_checker: &DPoPBindingChecker,
    require_mtls: bool,
    headers: &http::HeaderMap,
    http_method: &http::Method,
    http_uri: &http::Uri,
    client_cert_der: Option<&[u8]>,
) -> Result<(), TokenBindingError> {
    if let Some(cnf) = cnf {
        if cnf.jwe.is_some() {
            UnsupportedCnfMethodSnafu { method: "jwe" }.fail()?;
        }
        if cnf.jku.is_some() {
            UnsupportedCnfMethodSnafu { method: "jku" }.fail()?;
        }
    }

    match token_type {
        TokenType::Bearer => {
            // RFC 9449 §7.1: a token with a DPoP key binding (cnf.jkt) MUST NOT be
            // accepted as a Bearer token — doing so would defeat the binding entirely.
            if cnf.and_then(|c| c.jkt.as_ref()).is_some() {
                DpopRequiredForBoundTokenSnafu.fail()?;
            }
            if dpop_binding_checker.required {
                DpopRequiredSnafu.fail()?;
            }
        }
        TokenType::DPoP => {
            let dpop_proof = headers
                .get("DPoP")
                .map(|hv| hv.to_str().context(DPoPHeaderNotStringSnafu))
                .transpose()?
                .context(MissingDPoPHeaderSnafu)?;

            dpop_binding_checker
                .check(cnf, access_token, dpop_proof, http_method, http_uri)
                .await
                .context(DPoPBindingSnafu)?;
        }
    }

    check_mtls_binding(cnf, client_cert_der, require_mtls).context(MtlsBindingSnafu)?;

    Ok(())
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
/// thumbprint in the token.
pub(crate) struct DPoPBindingChecker {
    pub(crate) max_proof_age: Duration,
    pub(crate) jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
    pub(crate) allowed_signing_algorithms: Option<Vec<String>>,
    /// If `true`, Bearer tokens are rejected — all tokens must be DPoP-bound.
    pub(crate) required: bool,
}

impl DPoPBindingChecker {
    pub(crate) async fn check(
        &self,
        cnf: Option<&ConfirmationClaim>,
        access_token: &SecretString,
        dpop_proof: &str,
        method: &http::Method,
        uri: &http::Uri,
    ) -> Result<(), DPoPBindingError> {
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
            .require_jti(true)
            .build();

        let validated_proof = dpop_validator
            .validate_parsed_jws(parsed_proof)
            .await
            .context(InvalidProofSnafu)?;

        let access_token_hash = hash_access_token_for_dpop(access_token.expose_secret());

        match (
            validated_proof.claims.as_ref().and_then(|c| c.htm.as_ref()),
            validated_proof.claims.as_ref().and_then(|c| c.htu.as_ref()),
            validated_proof.claims.as_ref().and_then(|c| c.ath.as_ref()),
        ) {
            (None, _, _) => return HttpMethodMissingSnafu.fail(),
            (_, None, _) => return HttpUrlMissingSnafu.fail(),
            (_, _, None) => return AccessTokenHashMissingSnafu.fail(),
            (Some(htm), Some(htu), Some(ath)) => {
                ensure!(
                    htm == method.as_str(),
                    HttpMethodMismatchSnafu {
                        expected: method.as_str(),
                        actual: htm,
                    }
                );
                ensure!(
                    *htu == normalize_uri_for_dpop(uri)
                        .context(MalformedUrlSnafu)?
                        .to_string(),
                    HttpUrlMismatchSnafu {
                        expected: uri.to_string(),
                        actual: htu,
                    }
                );
                ensure!(
                    *ath == access_token_hash,
                    AccessTokenHashMismatchSnafu {
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

        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
struct DPoPClaims {
    htm: Option<String>,
    htu: Option<String>,
    ath: Option<String>,
    #[allow(dead_code)]
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
    /// The DPoP proof key thumbprint does not match the token's `cnf.jkt`.
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
    /// The DPoP proof is missing the `htm` claim.
    #[snafu(display("DPoP proof is missing the HTTP method claim (htm)"))]
    HttpMethodMissing,
    /// The DPoP proof is missing the `htu` claim.
    #[snafu(display("DPoP proof is missing the HTTP URL claim (htu)"))]
    HttpUrlMissing,
    /// The DPoP proof is missing the `ath` claim.
    #[snafu(display("DPoP proof is missing the access token hash claim (ath)"))]
    AccessTokenHashMissing,
    /// The `htm` claim does not match the request method.
    #[snafu(display("HTTP method mismatch: expected {expected}, got {actual}"))]
    HttpMethodMismatch { expected: String, actual: String },
    /// The `htu` claim does not match the request URL.
    #[snafu(display("HTTP URL mismatch: expected {expected}, got {actual}"))]
    HttpUrlMismatch { expected: String, actual: String },
    /// The `ath` claim does not match the hash of the access token.
    #[snafu(display("Access token hash mismatch"))]
    AccessTokenHashMismatch { expected: String, actual: String },
}
