//! Token sender-constraint binding checks for `DPoP` and mTLS.
//!
//! These functions operate on an already-validated token's [`ConfirmationClaim`]
//! and can be shared across JWT validation and token introspection flows.

use base64::prelude::*;
use http::StatusCode;
use sha2::{Digest as _, Sha256};
use snafu::{ensure, prelude::*};

use crate::{
    TokenType,
    core::{
        Error,
        dpop::{hash_access_token_for_dpop, normalize_uri_for_dpop},
        jwt::ConfirmationClaim,
        secrets::SecretString,
    },
    validator::{
        dpop_nonce::{DPoPNonceChecker, NonceCheck},
        dpop_proof::{DPoPProofError, DPoPProofValidator, ValidatedDPoPProof},
        error::{
            DPoPBindingSnafu, DPoPHeaderNotStringSnafu, DPoPRequiredForBoundTokenSnafu,
            DPoPRequiredSnafu, MissingDPoPHeaderSnafu, MtlsBindingSnafu, MultipleDPoPHeadersSnafu,
            TokenBindingError, UnsupportedCnfMethodSnafu,
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
/// token-type-specific binding (Bearer: rejects DPoP-bound tokens; `DPoP`: validates
/// the proof), then validates any mTLS certificate binding.
/// Returns the `DPoP` nonce to include in the response (if any) alongside the binding result.
///
/// The nonce is `Some` when the nonce checker issued a fresh nonce (either proactively on
/// [`NonceCheck::ValidWithNewNonce`] or as a required retry on [`NonceCheck::Invalid`]).
/// It is present even when the binding result is `Err`, so callers can always set the
/// `DPoP-Nonce` response header regardless of outcome.
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
                return (None, DPoPRequiredForBoundTokenSnafu.fail());
            }
            if dpop_binding_checker.required {
                return (None, DPoPRequiredSnafu.fail());
            }
            None
        }
        TokenType::DPoP => {
            // RFC 9449 §4.3: exactly one DPoP header.
            if headers.get_all("DPoP").iter().count() > 1 {
                return (None, MultipleDPoPHeadersSnafu.fail());
            }
            let dpop_proof = match headers
                .get("DPoP")
                .map(|hv| hv.to_str().context(DPoPHeaderNotStringSnafu))
                .transpose()
                .and_then(|opt| opt.context(MissingDPoPHeaderSnafu))
            {
                Ok(proof) => proof,
                Err(e) => return (None, Err(e)),
            };

            let (nonce, result) = dpop_binding_checker
                .check(cnf, access_token, dpop_proof, http_method, http_uri)
                .await;
            match result {
                Ok(()) => nonce,
                // `nonce` is carried on every error path, so rotation survives.
                Err(e) => return (nonce, Err(e).context(DPoPBindingSnafu)),
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
#[non_exhaustive]
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

/// Validates `DPoP` sender-constraint binding for a validated token.
///
/// Verifies the `DPoP` proof signature, checks the `htm`/`htu`/`ath` claims
/// against the request, and confirms the proof key matches the `cnf.jkt`
/// thumbprint in the token. Also validates the provided `DPoP` nonce.
pub(crate) struct DPoPBindingChecker {
    pub(crate) dpop_nonce_checker: Option<std::sync::Arc<dyn DPoPNonceChecker>>,
    pub(crate) proof_validator: DPoPProofValidator,
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
    ) -> (Option<String>, Result<(), DPoPBindingError>) {
        // The `htu` comparison below needs the absolute external target URI
        // (RFC 9449 §4.3), which only the deployment knows once proxies are
        // involved. A framework request object usually carries only the
        // origin-form path, which can never match a compliant proof — fail
        // with an integration error instead of a per-request `htu` mismatch.
        if uri.scheme().is_none() || uri.authority().is_none() {
            return (
                None,
                RequestUriNotAbsoluteSnafu {
                    uri: uri.to_string(),
                }
                .fail(),
            );
        }

        let validated_proof = match self
            .proof_validator
            .validate(dpop_proof)
            .await
            .context(ProofValidationSnafu)
        {
            Ok(proof) => proof,
            Err(e) => return (None, Err(e)),
        };

        let nonce_check = match self.dpop_nonce_checker.as_ref() {
            Some(c) => c.check_nonce(validated_proof.nonce.as_deref()).await,
            None => Ok(NonceCheck::Valid),
        };
        let nonce_check = match nonce_check {
            Ok(check) => check,
            Err(source) => return (None, Err(DPoPBindingError::NonceCheckFailed { source })),
        };

        let new_nonce = match nonce_check {
            NonceCheck::Valid => None,
            NonceCheck::ValidWithNewNonce(n) => Some(n),
            // Required retry: return the nonce *and* fail.
            NonceCheck::Invalid(n) => {
                return (Some(n.clone()), NonceRequiredSnafu { nonce: n }.fail());
            }
        };

        // Failures below must still surface `new_nonce` (see check_token_binding).
        let result = verify_claims_and_binding(cnf, access_token, &validated_proof, method, uri);
        (new_nonce, result)
    }
}

/// Checks the `htm`/`htu`/`ath` proof claims against the request and the proof
/// key thumbprint against the token's `cnf.jkt`. Does not touch the nonce —
/// that is resolved by [`DPoPBindingChecker::check`] before this runs.
fn verify_claims_and_binding(
    cnf: Option<&ConfirmationClaim>,
    access_token: &SecretString,
    validated_proof: &ValidatedDPoPProof,
    method: &http::Method,
    uri: &http::Uri,
) -> Result<(), DPoPBindingError> {
    let access_token_hash = hash_access_token_for_dpop(access_token.expose_secret());

    match (
        validated_proof.htm.as_ref(),
        validated_proof.htu.as_ref(),
        validated_proof.ath.as_ref(),
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

    match (
        cnf.and_then(|c| c.jkt.as_ref()),
        validated_proof.thumbprint.as_ref(),
    ) {
        (None, _) => return MissingThumbprintBindingSnafu.fail(),
        (_, None) => return NoThumbprintForKeySnafu.fail(),
        (Some(jkt), Some(tp)) => ensure!(jkt == tp, ThumbprintMismatchSnafu),
    }

    Ok(())
}

/// Error returned by [`DPoPBindingChecker::check`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DPoPBindingError {
    /// The token has no `cnf.jkt` thumbprint binding.
    #[snafu(display("Token has no DPoP key thumbprint binding"))]
    MissingThumbprintBinding,
    /// The `DPoP` proof key algorithm does not support thumbprint computation.
    #[snafu(display("No thumbprint for DPoP proof key"))]
    NoThumbprintForKey,
    /// The `DPoP` key thumbprint does not match the token's `cnf.jkt`.
    #[snafu(display("DPoP key thumbprint does not match token binding"))]
    ThumbprintMismatch,
    /// The `DPoP` proof failed structural validation (format, signature, JWK, typ, alg, etc.).
    #[snafu(display("DPoP proof validation failed: {source}"))]
    ProofValidation { source: DPoPProofError },
    /// The HTTP URI in the proof could not be normalized.
    #[snafu(display("Malformed HTTP URL in DPoP proof"))]
    MalformedUrl { source: http::Error },
    /// The request URI supplied to the validator is not absolute (e.g. an
    /// origin-form `/path` taken straight from a framework request object).
    ///
    /// An integration error on the resource server, not a client fault: the
    /// `htu` check needs the absolute external target URI (RFC 9449 §4.3). See
    /// the [`validate_request`](super::AccessTokenValidator::validate_request)
    /// `uri` contract and [validating DPoP-bound
    /// tokens](crate::_docs::guide::dpop) for reconstructing it behind a proxy.
    #[snafu(display(
        "Request URI '{uri}' is not absolute; reconstruct the external target URI \
         (scheme + authority + path) before calling the validator"
    ))]
    RequestUriNotAbsolute {
        /// The URI as supplied to the validator.
        uri: String,
    },
    /// The nonce checker returned an error (server-side failure).
    #[snafu(display("DPoP nonce check failed"))]
    NonceCheckFailed { source: Error },
    /// The `DPoP` proof nonce is missing or invalid. The client must retry with the provided nonce.
    #[snafu(display("A DPoP nonce is required"))]
    NonceRequired { nonce: String },
    /// The `DPoP` proof is missing a required claim.
    #[snafu(display("DPoP proof is missing the required claim '{claim}'"))]
    MissingProofClaim {
        /// The missing claim name.
        claim: &'static str,
    },
    /// A claim in the `DPoP` proof does not match the expected value.
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
            // NonceCheckFailed is a checker malfunction; RequestUriNotAbsolute
            // is an integration bug (the deployment passed a non-absolute
            // request URI). Neither is a client error.
            Self::NonceCheckFailed { .. } | Self::RequestUriNotAbsolute { .. } => {
                TokenValidationError::Server(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Self::ProofValidation {
                source:
                    DPoPProofError::InvalidProof {
                        source: crate::core::jwt::validator::JwtValidationError::JtiCheck { .. },
                    },
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
            Self::ProofValidation { source } => source.error_description(),
            Self::MalformedUrl { .. } => {
                Some("The DPoP proof has a malformed HTTP URL".to_string())
            }
            // Server-side details; nothing actionable for the client.
            Self::RequestUriNotAbsolute { .. } | Self::NonceCheckFailed { .. } => None,
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

#[cfg(test)]
#[cfg(all(not(target_family = "wasm"), feature = "default-jws-verifier-platform"))]
mod tests {
    use std::sync::Arc;

    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
    use rstest::rstest;
    use serde::Serialize;

    use super::*;
    use crate::{
        DefaultJwsVerifierPlatform,
        core::{
            crypto::signer::{AsymmetricJwsSignerSelector as _, JwsSignerSelector as _},
            jwt::Jwt,
            platform::Duration,
        },
    };

    // The request the proof is bound to. Tests keep these fixed and vary the proof.
    const ACCESS_TOKEN: &str = "the-access-token";

    fn req_uri() -> http::Uri {
        "https://rs.example.com/resource".parse().unwrap()
    }

    fn es256() -> PrivateKey {
        PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap()
    }

    /// The `cnf.jkt` value that correctly binds the token to `signer`'s key.
    fn matching_jkt(signer: &PrivateKey) -> String {
        signer.as_private_jwk().public_jwk().thumbprint()
    }

    /// `DPoP` proof claims, with `None` fields omitted entirely from the JWT so
    /// the binding checker sees a genuinely missing claim rather than `null`.
    #[derive(Debug, Clone, Default, Serialize)]
    struct ProofClaims {
        #[serde(skip_serializing_if = "Option::is_none")]
        htm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        htu: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ath: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    }

    /// Claims that match the fixed request (`POST` `req_uri()` + `ACCESS_TOKEN`).
    fn valid_claims() -> ProofClaims {
        ProofClaims {
            htm: Some("POST".to_string()),
            htu: Some(normalize_uri_for_dpop(&req_uri()).unwrap().to_string()),
            ath: Some(hash_access_token_for_dpop(ACCESS_TOKEN)),
            nonce: None,
        }
    }

    async fn sign_proof(signer: &PrivateKey, claims: ProofClaims) -> SecretString {
        let signer = signer.select_asymmetric_signer().await;
        Jwt::builder()
            .typ("dpop+jwt")
            .issued_now_expires_after(Duration::from_mins(1))
            .jwk(signer.public_key_jwk().into_owned())
            .claims(claims)
            .build()
            .to_jws_compact(&*signer)
            .await
            .unwrap()
    }

    fn checker(
        nonce_checker: Option<Arc<dyn DPoPNonceChecker>>,
        required: bool,
    ) -> DPoPBindingChecker {
        DPoPBindingChecker {
            dpop_nonce_checker: nonce_checker,
            proof_validator: DPoPProofValidator::builder()
                .jws_verifier_platform(DefaultJwsVerifierPlatform::default().into())
                .build(),
            required,
        }
    }

    fn cnf(jkt: Option<String>) -> ConfirmationClaim {
        ConfirmationClaim {
            jkt,
            x5t_s256: None,
            jwe: None,
            jku: None,
        }
    }

    /// A nonce checker that always returns a preconfigured verdict, so binding
    /// tests can exercise the nonce branches without a real sealed-nonce setup.
    #[derive(Debug)]
    struct FixedNonce(NonceCheck);

    impl DPoPNonceChecker for FixedNonce {
        fn check_nonce<'a>(
            &'a self,
            _nonce: Option<&'a str>,
        ) -> crate::core::platform::MaybeSendBoxFuture<'a, Result<NonceCheck, Error>> {
            let verdict = self.0.clone();
            Box::pin(async move { Ok(verdict) })
        }
    }

    /// Runs `check` for the fixed request against a freshly signed proof,
    /// returning the raw `(nonce, result)` pair.
    async fn run_raw(
        signer: &PrivateKey,
        claims: ProofClaims,
        cnf_jkt: Option<String>,
        nonce_checker: Option<Arc<dyn DPoPNonceChecker>>,
        required: bool,
    ) -> (Option<String>, Result<(), DPoPBindingError>) {
        let proof = sign_proof(signer, claims).await;
        let confirmation = cnf(cnf_jkt);
        checker(nonce_checker, required)
            .check(
                Some(&confirmation),
                &SecretString::new(ACCESS_TOKEN),
                proof.expose_secret(),
                &http::Method::POST,
                &req_uri(),
            )
            .await
    }

    /// Like [`run_raw`] but collapses the pair to the nonce-on-success shape the
    /// outcome-focused tests assert against.
    async fn run(
        signer: &PrivateKey,
        claims: ProofClaims,
        cnf_jkt: Option<String>,
        nonce_checker: Option<Arc<dyn DPoPNonceChecker>>,
        required: bool,
    ) -> Result<Option<String>, DPoPBindingError> {
        let (nonce, result) = run_raw(signer, claims, cnf_jkt, nonce_checker, required).await;
        result.map(|()| nonce)
    }

    /// Regression: a proof whose `iat` is a couple of seconds ahead of the RS
    /// clock (routine NTP drift on the client) must validate — the default
    /// clock leeway absorbs it, per RFC 9449 §11.1.
    #[tokio::test]
    async fn proof_with_slightly_future_iat_is_accepted() {
        let signer = es256();
        let now = crate::core::platform::SystemTime::now();
        let selected = signer.select_asymmetric_signer().await;
        let proof = Jwt::builder()
            .typ("dpop+jwt")
            .issued_at(now + Duration::from_secs(2))
            .expiration(now + Duration::from_mins(1))
            .jwk(selected.public_key_jwk().into_owned())
            .claims(valid_claims())
            .build()
            .to_jws_compact(&*selected)
            .await
            .unwrap();

        let confirmation = cnf(Some(matching_jkt(&signer)));
        let (nonce, result) = checker(None, false)
            .check(
                Some(&confirmation),
                &SecretString::new(ACCESS_TOKEN),
                proof.expose_secret(),
                &http::Method::POST,
                &req_uri(),
            )
            .await;
        assert!(
            nonce.is_none() && result.is_ok(),
            "2s future iat within default leeway must validate, got ({nonce:?}, {result:?})"
        );
    }

    /// An origin-form request URI (what a framework request object carries)
    /// can never match a compliant proof's absolute `htu` — it must be
    /// reported as an integration error, not as an `htu` mismatch.
    #[tokio::test]
    async fn origin_form_request_uri_is_an_integration_error() {
        let signer = es256();
        let proof = sign_proof(&signer, valid_claims()).await;
        let confirmation = cnf(Some(matching_jkt(&signer)));
        let (nonce, result) = checker(None, false)
            .check(
                Some(&confirmation),
                &SecretString::new(ACCESS_TOKEN),
                proof.expose_secret(),
                &http::Method::POST,
                &"/resource".parse::<http::Uri>().unwrap(),
            )
            .await;
        assert!(
            nonce.is_none()
                && matches!(result, Err(DPoPBindingError::RequestUriNotAbsolute { .. })),
            "expected RequestUriNotAbsolute, got ({nonce:?}, {result:?})"
        );
    }

    #[tokio::test]
    async fn valid_proof_and_binding_is_accepted() {
        let signer = es256();
        let result = run(
            &signer,
            valid_claims(),
            Some(matching_jkt(&signer)),
            None,
            false,
        )
        .await;
        assert!(
            matches!(result, Ok(None)),
            "expected Ok(None), got {result:?}"
        );
    }

    #[rstest]
    #[case::htm(ProofClaims { htm: None, ..valid_claims() }, "htm")]
    #[case::htu(ProofClaims { htu: None, ..valid_claims() }, "htu")]
    #[case::ath(ProofClaims { ath: None, ..valid_claims() }, "ath")]
    #[tokio::test]
    async fn missing_required_proof_claim_is_rejected(
        #[case] claims: ProofClaims,
        #[case] expected_claim: &str,
    ) {
        let signer = es256();
        let err = run(&signer, claims, Some(matching_jkt(&signer)), None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DPoPBindingError::MissingProofClaim { claim } if claim == expected_claim),
            "expected MissingProofClaim({expected_claim}), got {err:?}"
        );
    }

    #[rstest]
    #[case::htm(ProofClaims { htm: Some("GET".to_string()), ..valid_claims() }, "htm")]
    #[case::htu(ProofClaims { htu: Some("https://evil.example/other".to_string()), ..valid_claims() }, "htu")]
    #[case::ath(ProofClaims { ath: Some("not-the-token-hash".to_string()), ..valid_claims() }, "ath")]
    #[tokio::test]
    async fn proof_claim_mismatch_is_rejected(
        #[case] claims: ProofClaims,
        #[case] expected_claim: &str,
    ) {
        let signer = es256();
        let err = run(&signer, claims, Some(matching_jkt(&signer)), None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DPoPBindingError::ProofClaimMismatch { claim, .. } if claim == expected_claim),
            "expected ProofClaimMismatch({expected_claim}), got {err:?}"
        );
    }

    #[tokio::test]
    async fn token_without_jkt_binding_is_rejected() {
        let signer = es256();
        let err = run(&signer, valid_claims(), None, None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DPoPBindingError::MissingThumbprintBinding),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn thumbprint_mismatch_is_rejected() {
        let signer = es256();
        // A jkt that belongs to a different key than the one that signed the proof.
        let other_jkt = matching_jkt(&es256());
        let err = run(&signer, valid_claims(), Some(other_jkt), None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DPoPBindingError::ThumbprintMismatch),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn invalid_nonce_requires_retry_with_new_nonce() {
        let signer = es256();
        let nonce_checker = Arc::new(FixedNonce(NonceCheck::Invalid("fresh-nonce".to_string())));
        let err = run(
            &signer,
            valid_claims(),
            Some(matching_jkt(&signer)),
            Some(nonce_checker),
            false,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, DPoPBindingError::NonceRequired { ref nonce } if nonce == "fresh-nonce"),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rotating_nonce_is_returned_on_success() {
        let signer = es256();
        let nonce_checker = Arc::new(FixedNonce(NonceCheck::ValidWithNewNonce(
            "rotated-nonce".to_string(),
        )));
        let result = run(
            &signer,
            valid_claims(),
            Some(matching_jkt(&signer)),
            Some(nonce_checker),
            false,
        )
        .await;
        assert!(
            matches!(result, Ok(Some(ref n)) if n == "rotated-nonce"),
            "expected Ok(Some(\"rotated-nonce\")), got {result:?}"
        );
    }

    /// Regression: a rotated nonce must still reach the caller when a later
    /// binding check fails (here `htu`), so the client can retry with it.
    #[tokio::test]
    async fn rotating_nonce_is_returned_even_when_binding_fails() {
        let signer = es256();
        let nonce_checker = Arc::new(FixedNonce(NonceCheck::ValidWithNewNonce(
            "rotated-nonce".to_string(),
        )));
        let (nonce, result) = run_raw(
            &signer,
            ProofClaims {
                htu: Some("https://evil.example/other".to_string()),
                ..valid_claims()
            },
            Some(matching_jkt(&signer)),
            Some(nonce_checker),
            false,
        )
        .await;
        assert_eq!(
            nonce.as_deref(),
            Some("rotated-nonce"),
            "rotated nonce must survive a binding failure"
        );
        assert!(
            matches!(result, Err(DPoPBindingError::ProofClaimMismatch { claim, .. }) if claim == "htu"),
            "expected htu mismatch, got {result:?}"
        );
    }

    /// RFC 9449 §4.3: more than one `DPoP` header must be rejected outright.
    #[tokio::test]
    async fn multiple_dpop_headers_are_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.append("DPoP", http::HeaderValue::from_static("proof-one"));
        headers.append("DPoP", http::HeaderValue::from_static("proof-two"));
        let confirmation = cnf(Some("some-jkt".to_string()));
        let (nonce, result) = check_token_binding(
            TokenType::DPoP,
            Some(&confirmation),
            &SecretString::new(ACCESS_TOKEN),
            &checker(None, false),
            false,
            &headers,
            &http::Method::POST,
            &req_uri(),
            None,
        )
        .await;
        assert!(nonce.is_none());
        assert!(
            matches!(result, Err(TokenBindingError::MultipleDPoPHeaders)),
            "got {result:?}"
        );
    }

    /// Signs a proof whose embedded `jwk` header is `embedded`'s public key but
    /// whose signature is produced by `signer` — a proof not signed by the key
    /// it claims to be signed by.
    async fn sign_proof_with_embedded_jwk(
        signer: &PrivateKey,
        embedded: &PrivateKey,
        claims: ProofClaims,
    ) -> SecretString {
        Jwt::builder()
            .typ("dpop+jwt")
            .issued_now_expires_after(Duration::from_mins(1))
            .jwk(embedded.as_private_jwk().public_jwk())
            .claims(claims)
            .build()
            .to_jws_compact(&*signer.select_signer().await)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn proof_signed_by_key_other_than_embedded_jwk_is_rejected() {
        // RFC 9449 §4.3: the proof MUST be signed by the key in its `jwk` header.
        // Here the proof embeds the victim's public key — and the token is bound
        // to that key, so the `jkt` check would pass — but it is signed by the
        // attacker's key, so the signature cannot verify against the embedded JWK.
        let attacker = es256();
        let victim = es256();
        let proof = sign_proof_with_embedded_jwk(&attacker, &victim, valid_claims()).await;
        let confirmation = cnf(Some(matching_jkt(&victim)));
        let (_nonce, result) = checker(None, false)
            .check(
                Some(&confirmation),
                &SecretString::new(ACCESS_TOKEN),
                proof.expose_secret(),
                &http::Method::POST,
                &req_uri(),
            )
            .await;
        let err = result.unwrap_err();
        assert!(
            matches!(err, DPoPBindingError::ProofValidation { .. }),
            "expected ProofValidation (signature vs embedded key), got {err:?}"
        );
    }

    /// A `cnf` carrying only an `x5t#S256` certificate-thumbprint binding.
    fn cnf_x5t(thumbprint: Option<String>) -> ConfirmationClaim {
        ConfirmationClaim {
            jkt: None,
            x5t_s256: thumbprint,
            jwe: None,
            jku: None,
        }
    }

    const CLIENT_CERT_DER: &[u8] = b"a-client-certificate-in-der-form";

    #[test]
    fn mtls_matching_certificate_is_accepted() {
        let confirmation = cnf_x5t(Some(cert_thumbprint(CLIENT_CERT_DER)));
        assert!(check_mtls_binding(Some(&confirmation), Some(CLIENT_CERT_DER), false).is_ok());
    }

    #[test]
    fn mtls_wrong_certificate_is_rejected() {
        let confirmation = cnf_x5t(Some(cert_thumbprint(CLIENT_CERT_DER)));
        let err = check_mtls_binding(Some(&confirmation), Some(b"a-different-certificate"), false)
            .unwrap_err();
        assert!(
            matches!(err, MtlsBindingError::CertThumbprintMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn mtls_bound_token_without_client_certificate_is_rejected() {
        let confirmation = cnf_x5t(Some(cert_thumbprint(CLIENT_CERT_DER)));
        let err = check_mtls_binding(Some(&confirmation), None, false).unwrap_err();
        assert!(
            matches!(err, MtlsBindingError::CertBoundTokenWithoutCert),
            "got {err:?}"
        );
    }

    #[test]
    fn mtls_required_but_token_unbound_is_rejected() {
        // The RS requires certificate-bound tokens, but this token has no binding.
        let err =
            check_mtls_binding(Some(&cnf_x5t(None)), Some(CLIENT_CERT_DER), true).unwrap_err();
        assert!(matches!(err, MtlsBindingError::MtlsRequired), "got {err:?}");
    }

    #[test]
    fn mtls_unbound_token_is_accepted_when_not_required() {
        // No binding present and mTLS not required: the certificate is ignored.
        assert!(check_mtls_binding(None, None, false).is_ok());
        assert!(check_mtls_binding(Some(&cnf_x5t(None)), Some(CLIENT_CERT_DER), false).is_ok());
    }
}
