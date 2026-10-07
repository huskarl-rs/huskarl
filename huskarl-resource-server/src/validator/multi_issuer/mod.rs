//! Accept access tokens from several issuers with one validator.
//!
//! [`MultiIssuerValidator`] routes each request to a per-issuer validator by
//! reading the token's `iss` claim, then delegates the full validation to it. It
//! implements [`AccessTokenValidator`], so it drops into a `ValidatorLayer`,
//! Pingora guard, or any other consumer exactly like a single-issuer validator.
//!
//! Routing supports compact JWS tokens only; encrypted and opaque tokens are
//! not supported.
//!
//! Per-issuer validators usually have different claims types; wrap each in
//! [`MapClaims`] or [`TryMapClaims`] to give them a common type. To read or
//! rewrite universal token fields such as `sub`, map the whole request with
//! [`MapRequest`] or [`TryMapRequest`] instead. For why
//! issuer-based routing is safe and how to unify claim types, see the
//! [multi-issuer routing
//! explanation](crate::_docs::explanation::multi_issuer_routing); for a worked
//! two-issuer example, see the [multi-issuer
//! guide](crate::_docs::guide::multi_issuer).
//!
//! One [`ObservedValidator`](crate::validator::observe::ObservedValidator)
//! around the composite observes the whole deployment per issuer — sources do
//! not need their own wrappers.

pub mod error;
mod map;
mod source;
mod try_map;

use std::collections::HashMap;

use base64::prelude::*;
pub use error::MultiIssuerError;
use http::{HeaderName, header::AUTHORIZATION};
pub use map::{MapClaims, MapRequest};
use serde::Deserialize;
use snafu::prelude::*;
#[allow(deprecated)]
pub use try_map::TryMapClaimsError;
pub use try_map::{TryMapClaims, TryMapError, TryMapRequest};

use self::error::{
    ExtractSnafu, ParseSnafu, UnrecognizedIssuerSnafu, UnsupportedEncryptedTokenSnafu,
};
use crate::{
    AccessTokenValidator,
    core::{
        jwt::JwsParseError,
        platform::{MaybeSendBoxFuture, MaybeSendSync},
    },
    error::ToRfc6750Error,
    validator::{
        ValidationResult,
        extract::extract_token,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        multi_issuer::source::{RegisteredSource, SourceValidator},
    },
};

/// A validator that accepts tokens from several issuers, routing each request to
/// a per-issuer validator that produces a common claims type `C`.
///
/// Build one with [`MultiIssuerValidator::builder`]. See the [module
/// documentation](self) for routing semantics and an example.
pub struct MultiIssuerValidator<C> {
    by_issuer: HashMap<String, Box<dyn SourceValidator<C>>>,
    metadata: ValidatorMetadata,
    token_header: HeaderName,
}

#[bon::bon]
impl<C: MaybeSendSync + 'static> MultiIssuerValidator<C> {
    /// Creates a [`MultiIssuerValidator`], precomputing the union of the
    /// registered validators' metadata.
    ///
    /// Register validators with [`source`](MultiIssuerValidatorBuilder::source);
    /// the build is invoked via [`MultiIssuerValidator::builder`].
    #[builder]
    pub fn new(
        /// Per-issuer validators, accumulated by
        /// [`source`](MultiIssuerValidatorBuilder::source).
        #[builder(field)]
        sources: Vec<(String, Box<dyn SourceValidator<C>>)>,
        /// The HTTP header to extract the access token from. Defaults to
        /// `Authorization`.
        #[builder(default = AUTHORIZATION)]
        token_header: HeaderName,
    ) -> Self {
        let metadata = union_metadata(&sources, None);
        Self {
            by_issuer: sources.into_iter().collect(),
            metadata,
            token_header,
        }
    }
}

impl<C: MaybeSendSync + 'static, S: multi_issuer_validator_builder::State>
    MultiIssuerValidatorBuilder<C, S>
{
    /// Registers `validator` for tokens whose `iss` claim equals `issuer`.
    ///
    /// The validator must produce `Claims = C`; wrap source-specific validators
    /// in [`MapClaims`] or [`TryMapClaims`] to normalize their claims into `C`.
    /// If the same issuer is registered twice, the last registration wins. Call
    /// repeatedly, once per authorization server.
    pub fn source<V>(mut self, issuer: impl Into<String>, validator: V) -> Self
    where
        V: AccessTokenValidator<Claims = C> + ProvideValidatorMetadata + 'static,
        V::Error: ToRfc6750Error + 'static,
    {
        let issuer = issuer.into();
        self.sources.push((
            issuer.clone(),
            Box::new(RegisteredSource {
                issuer,
                inner: validator,
            }),
        ));
        self
    }
}

impl<C: MaybeSendSync + 'static> AccessTokenValidator for MultiIssuerValidator<C> {
    type Claims = C;
    type Error = MultiIssuerError;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<C, MultiIssuerError>> {
        Box::pin(async move {
            // Extract the token. No token is an unauthenticated request, matching
            // the single-issuer validators (`Ok(None)`), not an error.
            let token = match extract_token(headers, &self.token_header).context(ExtractSnafu) {
                Ok(Some((_token_type, token))) => token,
                Ok(None) => {
                    return ValidationResult {
                        outcome: Ok(None),
                        dpop_nonce: None,
                    };
                }
                Err(e) => {
                    return ValidationResult {
                        outcome: Err(e),
                        dpop_nonce: None,
                    };
                }
            };

            // Route on the unverified issuer; the selected validator does all
            // real verification. Preserve parsing failures separately from
            // missing or unregistered issuers.
            let iss = match peek_issuer(token.expose_secret()) {
                Ok(iss) => iss,
                Err(error) => {
                    return ValidationResult {
                        outcome: Err(error),
                        dpop_nonce: None,
                    };
                }
            };
            let Some(validator) = iss.as_ref().and_then(|iss| self.by_issuer.get(iss)) else {
                return ValidationResult {
                    outcome: UnrecognizedIssuerSnafu { iss }.fail(),
                    dpop_nonce: None,
                };
            };

            validator
                .validate_request(headers, method, uri, client_cert_der)
                .await
        })
    }
}

impl<C> ProvideValidatorMetadata for MultiIssuerValidator<C> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        // `resource` is per-deployment, so stamp it onto the precomputed union.
        ValidatorMetadata {
            resource: resource.map(str::to_owned),
            ..self.metadata.clone()
        }
    }
}

/// Reads the `iss` claim from a JWS compact payload **without verifying the
/// signature**.
///
/// Returns an untrusted routing hint, or `None` for an absent or null issuer.
/// Rejects five-segment tokens as unsupported JWE. The header and signature
/// are not decoded here.
fn peek_issuer(token: &str) -> Result<Option<String>, MultiIssuerError> {
    #[derive(Deserialize)]
    struct IssOnly {
        iss: Option<String>,
    }

    // Bound the scan even for hostile input containing many separators.
    let mut parts = token.splitn(6, '.');
    let payload = match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some(_), Some(payload), Some(_), None, None, None) => payload,
        (Some(_), Some(_), Some(_), Some(_), Some(_), None) => {
            return UnsupportedEncryptedTokenSnafu.fail();
        }
        _ => return Err(JwsParseError::InvalidFormat).context(ParseSnafu),
    };

    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|source| JwsParseError::Base64 { source })
        .context(ParseSnafu)?;
    serde_json::from_slice::<IssOnly>(&bytes)
        .map_err(|source| JwsParseError::Claims { source })
        .context(ParseSnafu)
        .map(|i| i.iss)
}

/// Builds the union of the registered validators' [`ValidatorMetadata`]:
/// concatenated `authorization_servers`, unioned `DPoP` signing algorithms,
/// `dpop_bound_access_tokens_required` only if *every* source requires it (so a
/// token may still be presented as Bearer if any source accepts Bearer),
/// mTLS-bound token support if *any* source reports it (the deployment handles
/// the binding regardless of which issuer minted the token), and the `realm`
/// and `resource_metadata` only when every source reports the same one (each
/// names something deployment-wide — the protection space and this resource's
/// metadata document — so disagreement means none).
fn union_metadata<C>(
    sources: &[(String, Box<dyn SourceValidator<C>>)],
    resource: Option<&str>,
) -> ValidatorMetadata {
    let mut authorization_servers = Vec::new();
    let mut dpop_algs: Vec<String> = Vec::new();
    let mut all_require_dpop = !sources.is_empty();
    let mut any_dpop_supported = false;
    let mut any_mtls_bound_supported = false;
    let mut realm: Option<Option<String>> = None;
    let mut resource_metadata: Option<Option<String>> = None;

    for (_issuer, validator) in sources {
        let m = validator.validator_metadata(resource);
        realm = match realm {
            None => Some(m.realm.clone()),
            Some(r) if r == m.realm => Some(r),
            Some(_) => Some(None),
        };
        resource_metadata = match resource_metadata {
            None => Some(m.resource_metadata.clone()),
            Some(r) if r == m.resource_metadata => Some(r),
            Some(_) => Some(None),
        };
        any_dpop_supported |= m.supports_dpop();
        any_mtls_bound_supported |= m.tls_client_certificate_bound_access_tokens == Some(true);
        if let Some(servers) = m.authorization_servers {
            authorization_servers.extend(servers);
        }
        if let Some(algs) = m.dpop_signing_alg_values_supported {
            for alg in algs {
                if !dpop_algs.contains(&alg) {
                    dpop_algs.push(alg);
                }
            }
        }
        all_require_dpop &= m.dpop_bound_access_tokens_required.unwrap_or(false);
    }

    ValidatorMetadata {
        realm: realm.flatten(),
        authorization_servers: (!authorization_servers.is_empty()).then_some(authorization_servers),
        dpop_supported: Some(any_dpop_supported),
        dpop_signing_alg_values_supported: (!dpop_algs.is_empty()).then_some(dpop_algs),
        dpop_bound_access_tokens_required: Some(all_require_dpop),
        tls_client_certificate_bound_access_tokens: any_mtls_bound_supported.then_some(true),
        resource: resource.map(str::to_owned),
        bearer_methods_supported: Some(vec!["header"]),
        resource_metadata: resource_metadata.flatten(),
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    /// base64url-no-pad encodes `s` as one JWS segment.
    fn seg(s: &str) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(s)
    }

    /// Assembles a three-part compact JWS with the given base64url payload.
    /// The header and signature are opaque to `peek_issuer`, so they are fixed.
    fn token_with_payload(payload_b64: &str) -> String {
        format!("{}.{payload_b64}.{}", seg(r#"{"alg":"RS256"}"#), seg("sig"))
    }

    #[rstest]
    // The signature is never checked, so any non-empty signature segment works.
    #[case::standard(
        token_with_payload(&seg(r#"{"iss":"https://issuer.example","sub":"abc"}"#)),
        "https://issuer.example"
    )]
    // RFC 7519 permits an empty signature (`alg: none`); it is still three
    // segments, and routing carries no trust regardless.
    #[case::empty_signature(
        format!("{}.{}.", seg(r#"{"alg":"none"}"#), seg(r#"{"iss":"iss-a"}"#)),
        "iss-a"
    )]
    fn reads_iss_from_unverified_payload(#[case] token: String, #[case] expected: &str) {
        assert_eq!(peek_issuer(&token).unwrap().as_deref(), Some(expected));
    }

    #[rstest]
    #[case::single_segment("not-a-jwt".to_owned())]
    // No signature segment: not a JWS.
    #[case::two_segments(format!("{}.{}", seg(r#"{"alg":"none"}"#), seg(r#"{"iss":"iss-a"}"#)))]
    // Four segments is neither compact JWS nor compact JWE.
    #[case::four_segments(format!(
        "{}.{}.{}.{}",
        seg(r#"{"alg":"none"}"#),
        seg(r#"{"iss":"iss-a"}"#),
        seg("sig"),
        seg("extra"),
    ))]
    #[case::six_segments("a.b.c.d.e.f".to_owned())]
    fn wrong_segment_count_is_rejected(#[case] token: String) {
        assert!(matches!(
            peek_issuer(&token),
            Err(MultiIssuerError::Parse {
                source: JwsParseError::InvalidFormat
            })
        ));
    }

    #[rstest]
    // `!` is outside the base64url alphabet.
    #[case::non_base64url("not!base64".to_owned(), true)]
    #[case::not_json(seg("this is not json"), false)]
    // `iss` deserializes as an `Option<String>`; a numeric value fails to parse.
    #[case::non_string_iss(seg(r#"{"iss":42}"#), false)]
    fn malformed_payload_is_rejected(#[case] payload_b64: String, #[case] base64_error: bool) {
        let error = peek_issuer(&token_with_payload(&payload_b64)).unwrap_err();
        if base64_error {
            assert!(matches!(
                error,
                MultiIssuerError::Parse {
                    source: JwsParseError::Base64 { .. }
                }
            ));
        } else {
            assert!(matches!(
                error,
                MultiIssuerError::Parse {
                    source: JwsParseError::Claims { .. }
                }
            ));
        }
    }

    #[rstest]
    #[case::single_character("b".to_owned(), true)]
    #[case::invalid_base64(token_with_payload("b"), true)]
    #[case::invalid_json(token_with_payload(&seg("not json")), true)]
    #[case::array_payload(token_with_payload(&seg("[]")), true)]
    #[case::string_payload(token_with_payload(&seg(r#""x""#)), true)]
    #[case::invalid_issuer(token_with_payload(&seg(r#"{"iss":42}"#)), true)]
    #[case::missing_issuer(token_with_payload(&seg(r#"{"sub":"abc"}"#)), false)]
    #[case::null_issuer(token_with_payload(&seg(r#"{"iss":null}"#)), false)]
    #[case::unknown_issuer(token_with_payload(&seg(r#"{"iss":"unknown"}"#)), false)]
    #[tokio::test]
    async fn routing_distinguishes_malformed_tokens_from_unrecognized_issuers(
        #[case] token: String,
        #[case] malformed: bool,
    ) {
        use crate::{
            error::{TokenErrorCode, TokenValidationError},
            validator::observe::ValidationOutcome,
        };

        let validator = MultiIssuerValidator::<()>::builder().build();
        let mut headers = http::HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        let result = validator
            .validate_request(
                &headers,
                &http::Method::GET,
                &http::Uri::from_static("/"),
                None,
            )
            .await;
        let error = result.outcome.unwrap_err();
        let challenge = error.challenge();
        assert_eq!(
            challenge.error,
            TokenValidationError::Client(TokenErrorCode::InvalidToken)
        );
        assert_eq!(error.issuer(), None);
        assert!(result.dpop_nonce.is_none());
        if malformed {
            assert!(matches!(error, MultiIssuerError::Parse { .. }));
            assert_eq!(
                challenge.description.as_deref(),
                Some("The access token is malformed")
            );
            assert_eq!(
                error.validation_outcome(&challenge),
                ValidationOutcome::InvalidToken
            );
            assert!(
                std::error::Error::source(&error)
                    .unwrap()
                    .is::<JwsParseError>()
            );
        } else {
            assert!(matches!(error, MultiIssuerError::UnrecognizedIssuer { .. }));
            assert_eq!(
                error.validation_outcome(&challenge),
                ValidationOutcome::UnrecognizedIssuer
            );
        }
    }

    #[rstest]
    // The empty encrypted-key segment is possible with direct encryption.
    #[case::jwe_shape(format!("{}..{}.{}.{}", seg(r#"{"alg":"dir","enc":"A256GCM"}"#), seg("iv"), seg("ciphertext"), seg("tag")))]
    // Classification is a shape hint, not a claim that this is a valid JWE.
    #[case::unvalidated_segments("a.b.c.d.e".to_owned())]
    #[tokio::test]
    async fn five_segment_tokens_report_unsupported_encryption(#[case] token: String) {
        use crate::{
            error::{TokenErrorCode, TokenValidationError},
            validator::observe::ValidationOutcome,
        };

        let validator = MultiIssuerValidator::<()>::builder().build();
        let mut headers = http::HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        let result = validator
            .validate_request(
                &headers,
                &http::Method::GET,
                &http::Uri::from_static("/"),
                None,
            )
            .await;
        let error = result.outcome.unwrap_err();
        assert!(matches!(error, MultiIssuerError::UnsupportedEncryptedToken));
        let challenge = error.challenge();
        assert_eq!(
            challenge.error,
            TokenValidationError::Client(TokenErrorCode::InvalidToken)
        );
        assert_eq!(
            challenge.description.as_deref(),
            Some("The access token format is not supported")
        );
        assert_eq!(
            error.to_string(),
            "unsupported five-segment (possibly JWE) token"
        );
        assert_eq!(
            error.validation_outcome(&challenge),
            ValidationOutcome::InvalidToken
        );
        assert_eq!(error.issuer(), None);
        assert_eq!(error.attempted_scheme(), None);
        assert!(std::error::Error::source(&error).is_none());
        assert!(result.dpop_nonce.is_none());
    }

    /// A [`SourceValidator`] double that only carries metadata.
    #[derive(Default)]
    struct StubSource {
        realm: Option<&'static str>,
        resource_metadata: Option<&'static str>,
        mtls_bound_supported: Option<bool>,
    }

    impl AccessTokenValidator for StubSource {
        type Claims = ();
        type Error = MultiIssuerError;

        fn validate_request<'a>(
            &'a self,
            _headers: &'a http::HeaderMap,
            _method: &'a http::Method,
            _uri: &'a http::Uri,
            _client_cert_der: Option<&'a [u8]>,
        ) -> MaybeSendBoxFuture<'a, ValidationResult<(), MultiIssuerError>> {
            Box::pin(async {
                ValidationResult {
                    outcome: Ok(None),
                    dpop_nonce: None,
                }
            })
        }
    }

    impl ProvideValidatorMetadata for StubSource {
        fn validator_metadata(&self, _resource: Option<&str>) -> ValidatorMetadata {
            ValidatorMetadata::builder()
                .maybe_realm(self.realm.map(str::to_owned))
                .maybe_resource_metadata(self.resource_metadata.map(str::to_owned))
                .maybe_tls_client_certificate_bound_access_tokens(self.mtls_bound_supported)
                .build()
        }
    }

    fn boxed_sources(
        stubs: impl IntoIterator<Item = StubSource>,
    ) -> Vec<(String, Box<dyn SourceValidator<()>>)> {
        stubs
            .into_iter()
            .enumerate()
            .map(|(i, stub)| {
                (
                    format!("https://issuer-{i}.example"),
                    Box::new(stub) as Box<dyn SourceValidator<()>>,
                )
            })
            .collect()
    }

    fn stub_sources(
        realms: &[Option<&'static str>],
    ) -> Vec<(String, Box<dyn SourceValidator<()>>)> {
        boxed_sources(realms.iter().map(|realm| StubSource {
            realm: *realm,
            ..StubSource::default()
        }))
    }

    #[rstest]
    // The realm names the whole deployment's protection space, so it unions
    // only when every source reports the same one.
    #[case::all_agree(&[Some("api"), Some("api")], Some("api"))]
    #[case::disagreement(&[Some("api"), Some("other")], None)]
    #[case::partial(&[Some("api"), None], None)]
    #[case::none_set(&[None, None], None)]
    fn union_realm_requires_agreement(
        #[case] realms: &[Option<&'static str>],
        #[case] expected: Option<&str>,
    ) {
        let meta = union_metadata(&stub_sources(realms), None);
        assert_eq!(meta.realm.as_deref(), expected);
    }

    #[rstest]
    // The metadata URL locates this resource's one document, so like the
    // realm it unions only when every source reports the same one.
    #[case::all_agree(&[Some("https://api.example/prm"), Some("https://api.example/prm")], Some("https://api.example/prm"))]
    #[case::disagreement(&[Some("https://api.example/prm"), Some("https://other.example/prm")], None)]
    #[case::partial(&[Some("https://api.example/prm"), None], None)]
    fn union_resource_metadata_requires_agreement(
        #[case] urls: &[Option<&'static str>],
        #[case] expected: Option<&str>,
    ) {
        let sources = boxed_sources(urls.iter().map(|url| StubSource {
            resource_metadata: *url,
            ..StubSource::default()
        }));
        assert_eq!(
            union_metadata(&sources, None).resource_metadata.as_deref(),
            expected
        );
    }

    #[rstest]
    // mTLS-bound token support is a deployment capability, so any source
    // asserting it makes the union assert it.
    #[case::any_true(&[None, Some(true)], Some(true))]
    #[case::none_assert(&[None, Some(false)], None)]
    fn union_mtls_bound_support_is_any(
        #[case] flags: &[Option<bool>],
        #[case] expected: Option<bool>,
    ) {
        let sources = boxed_sources(flags.iter().map(|flag| StubSource {
            mtls_bound_supported: *flag,
            ..StubSource::default()
        }));
        assert_eq!(
            union_metadata(&sources, None).tls_client_certificate_bound_access_tokens,
            expected
        );
    }
}
