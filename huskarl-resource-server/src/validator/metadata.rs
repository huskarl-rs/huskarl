//! Validator configuration metadata.

/// Metadata about how an access token validator is configured.
///
/// Returned by [`ProvideValidatorMetadata::validator_metadata`]. Serves two
/// purposes: as input to a Protected Resource Metadata document (RFC 9728) —
/// via [`to_resource_metadata`](Self::to_resource_metadata) — and as the
/// configuration that shapes `WWW-Authenticate` challenges, via
/// [`challenges`](Self::challenges) and the assembled
/// [`rejection`](Self::rejection) (see the [`rejection`](crate::rejection)
/// module).
///
/// Construct one with [`builder`](Self::builder).
#[derive(Debug, Clone, bon::Builder)]
#[builder(on(String, into))]
#[non_exhaustive]
pub struct ValidatorMetadata {
    /// The realm identifying the protection space (RFC 6750 §3).
    ///
    /// Included as `realm="..."` in `WWW-Authenticate` challenges when set.
    /// The built-in validators fill this from their `realm` builder option.
    pub realm: Option<String>,
    /// The authorization server(s) this validator trusts, by issuer URI.
    ///
    /// `None` if not known or if the authorization server does not have an issuer URI.
    pub authorization_servers: Option<Vec<String>>,
    /// Whether this validator accepts `DPoP`-bound tokens.
    ///
    /// Drives whether a `DPoP` challenge is included in `WWW-Authenticate`
    /// responses (RFC 9449 §7); it is not part of the RFC 9728 document. The
    /// built-in validators always accept `DPoP` presentation and set
    /// `Some(true)`. When `None`, support is inferred from the other fields:
    /// an advertised alg allowlist, or `DPoP`-bound tokens being required.
    pub dpop_supported: Option<bool>,
    /// `DPoP` proof signing algorithms accepted by this validator.
    ///
    /// `None` if unrestricted (the validator accepts any algorithm its verifier supports).
    /// When `None`, the field is omitted from RFC 9728 metadata.
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// Whether DPoP-bound tokens are required.
    ///
    /// `Some(true)` means Bearer tokens are rejected. `None` means the requirement
    /// status is not known (e.g. a validator that cannot determine this). Maps to
    /// `dpop_bound_access_tokens_required` in RFC 9728 metadata.
    pub dpop_bound_access_tokens_required: Option<bool>,
    /// Whether mutual-TLS certificate-bound access tokens (RFC 8705) are
    /// supported.
    ///
    /// Maps to `tls_client_certificate_bound_access_tokens` in RFC 9728
    /// metadata. The built-in validators check a token's `cnf.x5t#S256`
    /// binding whenever the deployment supplies the client certificate, but
    /// cannot know whether TLS termination actually presents one — they set
    /// `Some(true)` only when the binding is required (`require_mtls`) and
    /// leave `None` otherwise. Deployments that accept optionally-bound
    /// tokens should set this themselves.
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// The resource server's identifier URI.
    ///
    /// Provided by the caller to identify this specific resource instance. Maps to `resource` in
    /// RFC 9728 metadata.
    pub resource: Option<String>,
    /// Supported methods for presenting Bearer tokens (RFC 6750).
    ///
    /// Values correspond to RFC 6750 sections: `"header"` (§2.1 Authorization header),
    /// `"body"` (§2.2 form-encoded body parameter), `"query"` (§2.3 URI query parameter).
    /// `None` means unspecified. Maps to `bearer_methods_supported` in RFC 9728 metadata.
    pub bearer_methods_supported: Option<Vec<&'static str>>,
    /// URL of this resource's Protected Resource Metadata document (RFC 9728).
    ///
    /// Included as `resource_metadata="..."` in `WWW-Authenticate` challenges
    /// (RFC 9728 §5.1) so clients can discover the document. It locates the
    /// document rather than appearing inside it, so
    /// [`to_resource_metadata`](Self::to_resource_metadata) does not copy it.
    /// Derive it from the resource identifier with
    /// [`resource_metadata::well_known_url`](crate::core::resource_metadata::well_known_url).
    pub resource_metadata: Option<String>,
}

use crate::{
    TokenType,
    core::resource_metadata::ProtectedResourceMetadata,
    error::{Challenge, ToRfc6750Error, TokenValidationError, escape_quoted},
};

impl ValidatorMetadata {
    /// Builds the RFC 9728 Protected Resource Metadata document described by
    /// this validator configuration.
    ///
    /// Returns `None` when [`resource`](Self::resource) is unset: the
    /// document's `resource` member is required (RFC 9728 §2). The
    /// challenge-only fields ([`realm`](Self::realm),
    /// [`dpop_supported`](Self::dpop_supported),
    /// [`resource_metadata`](Self::resource_metadata)) are not part of the
    /// document, and fields only the deployment can know (`scopes_supported`,
    /// `resource_name`, the documentation/policy URLs, `jwks_uri`, …) are
    /// left unset — assign them on the returned document:
    ///
    /// ```
    /// # use huskarl_resource_server::validator::metadata::ValidatorMetadata;
    /// let metadata = ValidatorMetadata::builder()
    ///     .resource("https://api.example.com")
    ///     .dpop_bound_access_tokens_required(true)
    ///     .build();
    /// let mut document = metadata.to_resource_metadata().expect("resource is set");
    /// document.scopes_supported = Some(vec!["profile.read".into()]);
    /// let body = serde_json::to_string(&document).unwrap();
    /// # assert!(body.contains("profile.read"));
    /// ```
    #[must_use]
    pub fn to_resource_metadata(&self) -> Option<ProtectedResourceMetadata> {
        Some(
            ProtectedResourceMetadata::builder()
                .resource(self.resource.clone()?)
                .maybe_authorization_servers(self.authorization_servers.clone())
                .maybe_dpop_signing_alg_values_supported(
                    self.dpop_signing_alg_values_supported.clone(),
                )
                // `None` means "not known"; the document's RFC defaults
                // (false) say no more than that, so unknowns map to absent.
                .dpop_bound_access_tokens_required(
                    self.dpop_bound_access_tokens_required.unwrap_or(false),
                )
                .tls_client_certificate_bound_access_tokens(
                    self.tls_client_certificate_bound_access_tokens
                        .unwrap_or(false),
                )
                .maybe_bearer_methods_supported(
                    self.bearer_methods_supported
                        .as_ref()
                        .map(|methods| methods.iter().map(|m| (*m).to_owned()).collect()),
                )
                .build(),
        )
    }

    /// Returns `WWW-Authenticate` field values for a request.
    ///
    /// # Behavior
    ///
    /// With no error, this returns an unauthenticated challenge for every
    /// supported scheme. For a client error, error details are added to the
    /// attempted scheme; if the scheme is unknown, they are added to every
    /// supported challenge as permitted by RFC 9449 §7.1. Other supported
    /// schemes remain available without error details.
    ///
    /// A server error returns an empty vector because re-authentication cannot
    /// resolve the failure. Use [`rejection`](Self::rejection) to obtain its 5xx
    /// status and optional retry interval.
    ///
    /// When both `Bearer` and `DPoP` are supported, both challenges are returned
    /// as recommended by RFC 9449 §7.1. They may be sent as separate fields or
    /// combined according to RFC 9110 §§5.2 and 11.6.1.
    ///
    /// # Parameters
    ///
    /// The error's [`Challenge::scope`](crate::error::Challenge::scope) takes
    /// precedence over `scope`. `error_uri` is emitted only with client error
    /// details.
    ///
    /// For assembled response metadata, including status, `DPoP-Nonce`, and
    /// `Retry-After`, use [`rejection`](Self::rejection) or
    /// [`ValidationResult::rejection`](crate::validator::ValidationResult::rejection)
    /// instead.
    ///
    /// # Examples
    ///
    /// ```
    /// # use huskarl_resource_server::validator::metadata::ValidatorMetadata;
    /// let metadata = ValidatorMetadata::builder()
    ///     .realm("example")
    ///     .dpop_supported(true)
    ///     .dpop_signing_alg_values_supported(vec!["ES256".to_string()])
    ///     .dpop_bound_access_tokens_required(false)
    ///     .build();
    /// let challenges = metadata.challenges(None, Some("read write"), None);
    /// assert_eq!(challenges.len(), 2);
    /// assert_eq!(
    ///     challenges[0],
    ///     r#"Bearer realm="example", scope="read write""#
    /// );
    /// assert_eq!(
    ///     challenges[1],
    ///     r#"DPoP realm="example", scope="read write", algs="ES256""#
    /// );
    /// ```
    #[must_use]
    pub fn challenges(
        &self,
        error: Option<&dyn ToRfc6750Error>,
        scope: Option<&str>,
        error_uri: Option<&str>,
    ) -> Vec<String> {
        let attempted_scheme =
            error.and_then(super::super::error::ToRfc6750Error::attempted_scheme);
        let challenge = error.map(super::super::error::ToRfc6750Error::challenge);
        self.challenges_from(attempted_scheme, challenge.as_ref(), scope, error_uri)
    }

    /// Returns `WWW-Authenticate` field values using an already-built challenge.
    ///
    /// This is the borrowed counterpart to [`Self::challenges`]. It is useful
    /// when a caller also needs to inspect the challenge for response status or
    /// observation metadata and wants to avoid constructing its owned values
    /// more than once.
    #[must_use]
    pub fn challenges_from(
        &self,
        attempted_scheme: Option<TokenType>,
        challenge: Option<&Challenge>,
        scope: Option<&str>,
        error_uri: Option<&str>,
    ) -> Vec<String> {
        let mut challenges = Vec::new();

        // The error's own scope requirement (e.g. `InsufficientScope::new`)
        // names the specific unmet requirement, so it wins over the generic
        // `scope` argument.
        let scope = challenge.and_then(|c| c.scope.as_deref()).or(scope);

        let dpop_supported = self.supports_dpop();
        let bearer_allowed = !self.dpop_bound_access_tokens_required.unwrap_or(false);

        // For server errors (5xx), omit WWW-Authenticate entirely — including it would
        // mislead clients into thinking re-authenticating would resolve the failure.
        if matches!(
            challenge.map(|c| &c.error),
            Some(TokenValidationError::Server { .. })
        ) {
            return Vec::new();
        }

        let is_client_error = matches!(
            challenge.map(|c| &c.error),
            Some(TokenValidationError::Client(_))
        );

        let include_in_dpop = dpop_supported
            && is_client_error
            && (attempted_scheme.is_none() || attempted_scheme == Some(TokenType::DPoP));
        let include_in_bearer = bearer_allowed
            && is_client_error
            && (attempted_scheme.is_none() || attempted_scheme == Some(TokenType::Bearer));

        if bearer_allowed {
            challenges.push(self.build_challenge(
                "Bearer",
                scope,
                include_in_bearer.then_some(challenge).flatten(),
                error_uri,
            ));
        }

        if dpop_supported {
            challenges.push(self.build_challenge(
                "DPoP",
                scope,
                include_in_dpop.then_some(challenge).flatten(),
                error_uri,
            ));
        }

        challenges
    }

    /// Resolves whether `DPoP`-bound tokens are accepted: the explicit
    /// [`dpop_supported`](Self::dpop_supported) flag when set, otherwise
    /// inferred from an advertised alg allowlist or `DPoP` being required.
    pub(crate) fn supports_dpop(&self) -> bool {
        self.dpop_supported.unwrap_or_else(|| {
            self.dpop_signing_alg_values_supported.is_some()
                || self.dpop_bound_access_tokens_required == Some(true)
        })
    }

    /// Builds a single `WWW-Authenticate` challenge string for the given scheme.
    ///
    /// If `error` is `Some`, includes error details (code, description, uri, extra params).
    fn build_challenge(
        &self,
        scheme: &str,
        scope: Option<&str>,
        challenge: Option<&Challenge>,
        error_uri: Option<&str>,
    ) -> String {
        let mut parts = Vec::new();

        if let Some(realm) = self.realm.as_deref() {
            parts.push(format!(r#"realm="{}""#, escape_quoted(realm)));
        }

        if let Some(scope) = scope {
            parts.push(format!(r#"scope="{}""#, escape_quoted(scope)));
        }

        if let Some(c) = challenge
            && let TokenValidationError::Client(code) = &c.error
        {
            parts.push(format!(r#"error="{}""#, code.as_str()));
            if let Some(desc) = &c.description {
                parts.push(format!(r#"error_description="{}""#, escape_quoted(desc)));
            }
            if let Some(uri) = error_uri {
                parts.push(format!(r#"error_uri="{}""#, escape_quoted(uri)));
            }
            parts.extend(
                c.params
                    .iter()
                    .map(super::super::error::ChallengeParam::format),
            );
        }

        if let Some(url) = self.resource_metadata.as_deref() {
            parts.push(format!(r#"resource_metadata="{}""#, escape_quoted(url)));
        }

        if scheme == "DPoP"
            && let Some(algs) = &self.dpop_signing_alg_values_supported
        {
            parts.push(format!(r#"algs="{}""#, escape_quoted(&algs.join(" "))));
        }

        if parts.is_empty() {
            scheme.to_string()
        } else {
            format!("{} {}", scheme, parts.join(", "))
        }
    }

    /// Returns the `WWW-Authenticate` header values for an unauthenticated request.
    ///
    /// This is equivalent to `self.challenges(None, scope, None)`.
    #[must_use]
    pub fn unauthenticated_challenges(&self, scope: Option<&str>) -> Vec<String> {
        self.challenges(None, scope, None)
    }
}

/// Describes how a validator is configured, for populating a Protected Resource
/// Metadata document (RFC 9728) — see the returned [`ValidatorMetadata`].
pub trait ProvideValidatorMetadata {
    /// Returns metadata describing how this validator is configured, for the
    /// protected resource at `resource`.
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TokenType,
        error::{Challenge, ChallengeParam, ServerStatus, TokenErrorCode, TokenValidationError},
        introspection::IntrospectionCallError,
        validator::{
            binding::{DPoPBindingError, MtlsBindingError},
            dpop_proof::DPoPProofError,
            extract::TokenExtractError,
        },
    };

    /// A configurable [`ToRfc6750Error`] test double.
    #[derive(Debug)]
    struct TestError {
        scheme: Option<TokenType>,
        token_error: TokenValidationError,
        description: Option<String>,
        extra: Vec<ChallengeParam>,
    }

    impl TestError {
        fn client(code: TokenErrorCode) -> Self {
            Self {
                scheme: None,
                token_error: TokenValidationError::Client(code),
                description: None,
                extra: Vec::new(),
            }
        }

        fn server() -> Self {
            Self {
                scheme: None,
                token_error: TokenValidationError::server(ServerStatus::BAD_GATEWAY),
                description: None,
                extra: Vec::new(),
            }
        }

        fn scheme(mut self, s: TokenType) -> Self {
            self.scheme = Some(s);
            self
        }

        fn description(mut self, d: &str) -> Self {
            self.description = Some(d.to_string());
            self
        }

        fn extra(mut self, p: ChallengeParam) -> Self {
            self.extra.push(p);
            self
        }
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("test error")
        }
    }

    impl std::error::Error for TestError {}

    impl ToRfc6750Error for TestError {
        fn attempted_scheme(&self) -> Option<TokenType> {
            self.scheme
        }

        fn challenge(&self) -> Challenge {
            let c = Challenge::new(self.token_error.clone());
            let c = match &self.description {
                Some(d) => c.with_description(d.clone()),
                None => c,
            };
            c.with_params(self.extra.clone())
        }
    }

    fn meta() -> ValidatorMetadata {
        ValidatorMetadata {
            realm: None,
            authorization_servers: None,
            dpop_supported: None,
            dpop_signing_alg_values_supported: None,
            dpop_bound_access_tokens_required: None,
            tls_client_certificate_bound_access_tokens: None,
            resource: None,
            bearer_methods_supported: None,
            resource_metadata: None,
        }
    }

    #[test]
    fn unauthenticated_bearer_only_by_default() {
        // No DPoP config → Bearer is the only supported scheme.
        assert_eq!(meta().challenges(None, None, None), vec!["Bearer"]);
    }

    #[test]
    fn unauthenticated_both_schemes_with_realm_and_scope() {
        let mut m = meta();
        m.realm = Some("api".to_string());
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string(), "RS256".to_string()]);

        assert_eq!(
            m.challenges(None, Some("read write"), None),
            vec![
                r#"Bearer realm="api", scope="read write""#,
                r#"DPoP realm="api", scope="read write", algs="ES256 RS256""#,
            ]
        );
    }

    #[test]
    fn dpop_required_omits_bearer() {
        let mut m = meta();
        m.dpop_bound_access_tokens_required = Some(true);
        // DPoP is supported (required) even with no advertised algs; Bearer is rejected.
        assert_eq!(m.unauthenticated_challenges(None), vec!["DPoP"]);
    }

    #[test]
    fn dpop_required_false_keeps_bearer_only() {
        let mut m = meta();
        m.dpop_bound_access_tokens_required = Some(false);
        // Hand-built metadata without the explicit flag: not-required and no
        // algs infers no DPoP support, so DPoP is not advertised.
        assert_eq!(m.unauthenticated_challenges(None), vec!["Bearer"]);
    }

    #[test]
    fn dpop_supported_advertises_dpop_without_algs() {
        let mut m = meta();
        m.dpop_supported = Some(true);
        m.dpop_bound_access_tokens_required = Some(false);
        // The validators' default shape: DPoP accepted, optional, unrestricted
        // algs. Both challenges must be advertised (RFC 9449 §7.1).
        assert_eq!(m.unauthenticated_challenges(None), vec!["Bearer", "DPoP"]);
    }

    #[test]
    fn dpop_supported_carries_nonce_error_without_algs() {
        let mut m = meta();
        m.dpop_supported = Some(true);
        m.dpop_bound_access_tokens_required = Some(false);
        let err = TestError::client(TokenErrorCode::UseDPoPNonce).scheme(TokenType::DPoP);

        // Regression: a stale-nonce 401 from an unrestricted validator must
        // carry the DPoP challenge with error="use_dpop_nonce" (RFC 9449 §8.2)
        // — clients key their nonce retry on it.
        assert_eq!(
            m.challenges(Some(&err), None, None),
            vec![
                "Bearer".to_string(),
                r#"DPoP error="use_dpop_nonce""#.to_string(),
            ]
        );
    }

    #[test]
    fn dpop_supported_false_overrides_inference() {
        let mut m = meta();
        m.dpop_supported = Some(false);
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string()]);
        // The explicit flag wins over the alg-allowlist inference.
        assert_eq!(m.unauthenticated_challenges(None), vec!["Bearer"]);
    }

    #[test]
    fn server_error_returns_no_challenges() {
        let mut m = meta();
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string()]);
        // 5xx failures omit WWW-Authenticate entirely.
        assert!(
            m.challenges(Some(&TestError::server()), None, None)
                .is_empty()
        );
    }

    #[test]
    fn client_error_without_scheme_appears_in_both() {
        let mut m = meta();
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string()]);
        let err = TestError::client(TokenErrorCode::InvalidToken).description("bad token");

        assert_eq!(
            m.challenges(Some(&err), None, None),
            vec![
                r#"Bearer error="invalid_token", error_description="bad token""#,
                r#"DPoP error="invalid_token", error_description="bad token", algs="ES256""#,
            ]
        );
    }

    #[test]
    fn client_error_attempted_bearer_details_only_in_bearer() {
        let mut m = meta();
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string()]);
        let err = TestError::client(TokenErrorCode::InvalidToken)
            .scheme(TokenType::Bearer)
            .description("bad token");

        // Error details only in the attempted (Bearer) scheme; DPoP stays unauthenticated.
        assert_eq!(
            m.challenges(Some(&err), None, None),
            vec![
                r#"Bearer error="invalid_token", error_description="bad token""#,
                r#"DPoP algs="ES256""#,
            ]
        );
    }

    #[test]
    fn client_error_attempted_dpop_details_only_in_dpop() {
        let mut m = meta();
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string()]);
        let err = TestError::client(TokenErrorCode::InvalidDPoPProof).scheme(TokenType::DPoP);

        assert_eq!(
            m.challenges(Some(&err), None, None),
            vec![
                "Bearer".to_string(),
                r#"DPoP error="invalid_dpop_proof", algs="ES256""#.to_string(),
            ]
        );
    }

    #[test]
    fn leaf_error_descriptions_reach_authenticate_headers() {
        let mut m = meta();
        m.dpop_supported = Some(true);

        assert_eq!(
            m.challenges(
                Some(&TokenExtractError::InvalidTokenHeaderFormat),
                None,
                None,
            ),
            vec![
                r#"Bearer error="invalid_request", error_description="The access token header format is invalid""#,
                r#"DPoP error="invalid_request", error_description="The access token header format is invalid""#,
            ],
        );
        assert_eq!(
            m.challenges(Some(&DPoPBindingError::ThumbprintMismatch), None, None),
            vec![
                "Bearer".to_string(),
                r#"DPoP error="invalid_dpop_proof", error_description="The DPoP key thumbprint does not match the token binding""#.to_string(),
            ],
        );
        assert_eq!(
            m.challenges(
                Some(&DPoPBindingError::ProofValidation {
                    source: DPoPProofError::MissingJwkHeader,
                }),
                None,
                None,
            ),
            vec![
                "Bearer".to_string(),
                r#"DPoP error="invalid_dpop_proof", error_description="The DPoP proof is missing the JWK header""#.to_string(),
            ],
        );
        assert_eq!(
            m.challenges(
                Some(&MtlsBindingError::CertBoundTokenWithoutCert),
                None,
                None,
            ),
            vec![
                r#"Bearer error="invalid_token", error_description="The access token is certificate-bound but no client certificate was presented""#,
                r#"DPoP error="invalid_token", error_description="The access token is certificate-bound but no client certificate was presented""#,
            ],
        );
        assert_eq!(
            m.challenges(Some(&IntrospectionCallError::TokenInactive), None, None),
            vec![
                r#"Bearer error="invalid_token", error_description="The access token is revoked""#,
                r#"DPoP error="invalid_token", error_description="The access token is revoked""#,
            ],
        );
    }

    #[test]
    fn error_uri_included_only_for_client_errors() {
        let err = TestError::client(TokenErrorCode::InvalidToken);
        assert_eq!(
            meta().challenges(Some(&err), None, Some("https://err.example/info")),
            vec![r#"Bearer error="invalid_token", error_uri="https://err.example/info""#]
        );
    }

    #[test]
    fn realm_and_extra_params_are_escaped_and_ordered() {
        let mut m = meta();
        m.realm = Some(r#"my"realm"#.to_string());
        let err = TestError::client(TokenErrorCode::InsufficientUserAuthentication)
            .description("step up")
            .extra(ChallengeParam::Token("max_age", "60".to_string()));

        // Part order: realm, scope, error, error_description, extra_params.
        assert_eq!(
            m.challenges(Some(&err), Some("read"), None),
            vec![
                r#"Bearer realm="my\"realm", scope="read", error="insufficient_user_authentication", error_description="step up", max_age=60"#
            ]
        );
    }

    #[test]
    fn error_required_scope_fills_scope_attribute() {
        let err = crate::error::InsufficientScope::new("admin");
        assert_eq!(
            meta().challenges(Some(&err), None, None),
            vec![
                r#"Bearer scope="admin", error="insufficient_scope", error_description="The access token has insufficient scope for the requested resource""#
            ]
        );
    }

    #[test]
    fn error_required_scope_wins_over_scope_argument() {
        // The error names the specific unmet requirement; the generic
        // argument is the fallback.
        let err = crate::error::InsufficientScope::new("admin");
        let challenges = meta().challenges(Some(&err), Some("read"), None);
        assert!(challenges[0].contains(r#"scope="admin""#), "{challenges:?}");
        assert!(!challenges[0].contains(r#"scope="read""#), "{challenges:?}");
    }

    #[test]
    fn resource_metadata_in_all_challenges() {
        let mut m = meta();
        m.dpop_supported = Some(true);
        m.resource_metadata =
            Some("https://api.example/.well-known/oauth-protected-resource".to_string());

        // RFC 9728 §5.1: the challenge points clients at the metadata document,
        // on every supported scheme.
        assert_eq!(
            m.unauthenticated_challenges(None),
            vec![
                r#"Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource""#,
                r#"DPoP resource_metadata="https://api.example/.well-known/oauth-protected-resource""#,
            ]
        );
    }

    #[test]
    fn resource_metadata_follows_error_params() {
        let mut m = meta();
        m.realm = Some("api".to_string());
        m.resource_metadata =
            Some("https://api.example/.well-known/oauth-protected-resource".to_string());
        let err = TestError::client(TokenErrorCode::InvalidToken).description("bad token");

        // Part order: realm, scope, error params, resource_metadata.
        assert_eq!(
            m.challenges(Some(&err), Some("read"), None),
            vec![
                r#"Bearer realm="api", scope="read", error="invalid_token", error_description="bad token", resource_metadata="https://api.example/.well-known/oauth-protected-resource""#
            ]
        );
    }

    #[test]
    fn to_resource_metadata_requires_a_resource() {
        // The document's `resource` member is required (RFC 9728 §2).
        assert!(meta().to_resource_metadata().is_none());
    }

    #[test]
    fn to_resource_metadata_copies_document_fields_only() {
        let mut m = meta();
        m.realm = Some("api".to_string());
        m.dpop_supported = Some(true);
        m.resource_metadata =
            Some("https://api.example/.well-known/oauth-protected-resource".to_string());
        m.resource = Some("https://api.example".to_string());
        m.authorization_servers = Some(vec!["https://as.example".to_string()]);
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string()]);
        m.dpop_bound_access_tokens_required = Some(true);
        m.tls_client_certificate_bound_access_tokens = Some(true);
        m.bearer_methods_supported = Some(vec!["header"]);

        // Serializing pins both the copied values and that the
        // challenge-only fields (realm, dpop_supported, resource_metadata)
        // stay out of the document.
        let document = m.to_resource_metadata().unwrap();
        assert_eq!(
            serde_json::to_value(&document).unwrap(),
            serde_json::json!({
                "resource": "https://api.example",
                "authorization_servers": ["https://as.example"],
                "bearer_methods_supported": ["header"],
                "dpop_signing_alg_values_supported": ["ES256"],
                "dpop_bound_access_tokens_required": true,
                "tls_client_certificate_bound_access_tokens": true,
            })
        );
    }

    #[test]
    fn to_resource_metadata_maps_unknowns_to_rfc_defaults() {
        let mut m = meta();
        m.resource = Some("https://api.example".to_string());

        // `None` (not known) becomes the RFC default `false`, which the
        // document omits when serialized.
        let document = m.to_resource_metadata().unwrap();
        assert!(!document.dpop_bound_access_tokens_required);
        assert!(!document.tls_client_certificate_bound_access_tokens);
        assert_eq!(
            serde_json::to_value(&document).unwrap(),
            serde_json::json!({"resource": "https://api.example"})
        );
    }

    #[test]
    fn unauthenticated_challenges_matches_challenges_with_none() {
        let mut m = meta();
        m.realm = Some("api".to_string());
        m.dpop_signing_alg_values_supported = Some(vec!["ES256".to_string()]);
        assert_eq!(
            m.unauthenticated_challenges(Some("read")),
            m.challenges(None, Some("read"), None)
        );
    }
}
