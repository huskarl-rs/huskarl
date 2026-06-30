//! Accept access tokens from several issuers with one validator.
//!
//! [`MultiIssuerValidator`] routes each request to a per-issuer validator by
//! reading the token's `iss` claim, then delegates the full validation to it. It
//! implements [`AccessTokenValidator`], so it drops into a `ValidatorLayer`,
//! Pingora guard, or any other consumer exactly like a single-issuer validator.
//!
//! # How routing stays safe
//!
//! The issuer is read from the token's payload **without verifying the
//! signature**, and is used *only* to select a validator. The selected validator
//! independently re-checks `iss`, the signature (against its own JWKS), the
//! audience, and any sender-constraint binding — so a token that lies about its
//! issuer is merely routed to a validator that rejects it. Routing grants no
//! trust; verification is still done in full by the chosen validator.
//!
//! Each per-issuer validator carries its own audience: pin it exactly, because
//! the audience check is the access boundary. This matters most when a validator
//! accepts tokens (such as OIDC ID tokens) that a different relying party could
//! also obtain.
//!
//! # Unifying claim types
//!
//! Per-issuer validators usually have different claims types. Give them a common
//! type `C` by wrapping each in [`MapClaims`], whose mapping is a plain
//! `Fn(SourceClaims) -> C`. The library attaches no semantics to that mapping —
//! any authorization model your application layers on top of `C` is its own
//! concern.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use huskarl_resource_server::{
//!     core::{jwk::JwksSource, jwt::validator::ClaimCheck},
//!     validator::{
//!         custom::CustomValidator,
//!         multi_issuer::{MapClaims, MultiIssuerValidator},
//!     },
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http = huskarl_reqwest::ReqwestClient::builder().build().await?;
//! #[derive(Clone, serde::Deserialize)]
//! struct GoogleIdClaims {
//!     email: Option<String>,
//!     email_verified: Option<bool>,
//! }
//! #[derive(Clone, serde::Deserialize)]
//! struct OktaClaims {
//!     #[serde(default)]
//!     scp: Vec<String>,
//! }
//!
//! #[derive(Clone)]
//! struct Principal {
//!     email: Option<String>,
//!     scopes: Vec<String>,
//! }
//!
//! let google = CustomValidator::builder()
//!     .with_claims::<GoogleIdClaims>()
//!     .authorization_server("https://accounts.google.com")
//!     .issuer(ClaimCheck::required_value("https://accounts.google.com"))
//!     .audience(ClaimCheck::required_value("<your-google-oauth-client-id>"))
//!     .token_type(ClaimCheck::NoCheck)
//!     .require_jti(false)
//!     .jwks_uri("https://www.googleapis.com/oauth2/v3/certs".parse()?)
//!     .jws_verifier_factory(Arc::new(
//!         JwksSource::builder().http_client(http.clone()).build(),
//!     ))
//!     .build()
//!     .await?;
//!
//! let okta = CustomValidator::builder()
//!     .with_claims::<OktaClaims>()
//!     .authorization_server("https://example.okta.com/oauth2/default")
//!     .issuer(ClaimCheck::required_value(
//!         "https://example.okta.com/oauth2/default",
//!     ))
//!     .audience(ClaimCheck::required_value("api://my-resource"))
//!     .jwks_uri("https://example.okta.com/oauth2/default/v1/keys".parse()?)
//!     .jws_verifier_factory(Arc::new(
//!         JwksSource::builder().http_client(http.clone()).build(),
//!     ))
//!     .build()
//!     .await?;
//!
//! let validator = MultiIssuerValidator::<Principal>::builder()
//!     .source(
//!         "https://accounts.google.com",
//!         MapClaims::new(google, |c: GoogleIdClaims| Principal {
//!             email: c.email.filter(|_| c.email_verified == Some(true)),
//!             scopes: Vec::new(),
//!         }),
//!     )
//!     .source(
//!         "https://example.okta.com/oauth2/default",
//!         MapClaims::new(okta, |c: OktaClaims| Principal {
//!             email: None,
//!             scopes: c.scp,
//!         }),
//!     )
//!     .build();
//! # let _ = validator;
//! # Ok(())
//! # }
//! ```

pub mod error;
mod map;
mod source;

use std::collections::HashMap;

use base64::prelude::*;
pub use error::MultiIssuerError;
use http::{HeaderName, header::AUTHORIZATION};
pub use map::MapClaims;
use serde::Deserialize;

use crate::{
    AccessTokenValidator,
    core::platform::{MaybeSendBoxFuture, MaybeSendSync},
    error::ToRfc6750Error,
    validator::{
        ValidationResult,
        extract::extract_token,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        multi_issuer::source::{FoldError, SourceValidator},
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
    /// in [`MapClaims`] to normalize their claims into `C`. If the same issuer is
    /// registered twice, the last registration wins. Call repeatedly, once per
    /// authorization server.
    pub fn source<V>(mut self, issuer: impl Into<String>, validator: V) -> Self
    where
        V: AccessTokenValidator<Claims = C> + ProvideValidatorMetadata + 'static,
        V::Error: ToRfc6750Error + 'static,
    {
        self.sources
            .push((issuer.into(), Box::new(FoldError(validator))));
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
            let token = match extract_token(headers, &self.token_header) {
                Ok(Some((_token_type, token))) => token,
                Ok(None) => {
                    return ValidationResult {
                        outcome: Ok(None),
                        dpop_nonce: None,
                    };
                }
                Err(e) => {
                    return ValidationResult {
                        outcome: Err(MultiIssuerError::Extract { source: e }),
                        dpop_nonce: None,
                    };
                }
            };

            // Route on the unverified issuer; the selected validator does all
            // real verification. A missing/unparseable/unregistered issuer is
            // rejected.
            let Some(validator) =
                peek_issuer(token.expose_secret()).and_then(|iss| self.by_issuer.get(&iss))
            else {
                return ValidationResult {
                    outcome: Err(MultiIssuerError::UnrecognizedIssuer),
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
/// The result is used only to select a validator (see the [module
/// documentation](self)); it carries no trust. Returns `None` if the token is
/// not a three-part JWS, the payload is not valid base64url JSON, or it has no
/// string `iss`.
fn peek_issuer(token: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct IssOnly {
        iss: String,
    }

    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    parts.next()?; // require a signature segment
    if parts.next().is_some() {
        return None; // more than three segments is not a JWS
    }

    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<IssOnly>(&bytes)
        .ok()
        .map(|i| i.iss)
}

/// Builds the union of the registered validators' [`ValidatorMetadata`]:
/// concatenated `authorization_servers`, unioned `DPoP` signing algorithms, and
/// `dpop_bound_access_tokens_required` only if *every* source requires it (so a
/// token may still be presented as Bearer if any source accepts Bearer).
fn union_metadata<C>(
    sources: &[(String, Box<dyn SourceValidator<C>>)],
    resource: Option<&str>,
) -> ValidatorMetadata {
    let mut authorization_servers = Vec::new();
    let mut dpop_algs: Vec<String> = Vec::new();
    let mut all_require_dpop = !sources.is_empty();

    for (_issuer, validator) in sources {
        let m = validator.validator_metadata(resource);
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
        realm: None,
        authorization_servers: (!authorization_servers.is_empty()).then_some(authorization_servers),
        dpop_signing_alg_values_supported: (!dpop_algs.is_empty()).then_some(dpop_algs),
        dpop_bound_access_tokens_required: Some(all_require_dpop),
        resource: resource.map(str::to_owned),
        bearer_methods_supported: Some(vec!["header"]),
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
        assert_eq!(peek_issuer(&token).as_deref(), Some(expected));
    }

    #[rstest]
    #[case::single_segment("not-a-jwt".to_owned())]
    // No signature segment: not a JWS.
    #[case::two_segments(format!("{}.{}", seg(r#"{"alg":"none"}"#), seg(r#"{"iss":"iss-a"}"#)))]
    // More than three segments (e.g. a JWE) is not a compact JWS.
    #[case::four_segments(format!(
        "{}.{}.{}.{}",
        seg(r#"{"alg":"none"}"#),
        seg(r#"{"iss":"iss-a"}"#),
        seg("sig"),
        seg("extra"),
    ))]
    fn wrong_segment_count_is_rejected(#[case] token: String) {
        assert_eq!(peek_issuer(&token), None);
    }

    #[rstest]
    // `!` is outside the base64url alphabet.
    #[case::non_base64url("not!base64".to_owned())]
    #[case::not_json(seg("this is not json"))]
    #[case::no_iss(seg(r#"{"sub":"abc","aud":"api"}"#))]
    // `iss` deserializes as a `String`; a numeric value fails to parse.
    #[case::non_string_iss(seg(r#"{"iss":42}"#))]
    fn malformed_payload_is_rejected(#[case] payload_b64: String) {
        assert_eq!(peek_issuer(&token_with_payload(&payload_b64)), None);
    }
}
