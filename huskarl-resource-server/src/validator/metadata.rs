//! Validator configuration metadata.

use serde::Serialize;

/// Metadata about how an access token validator is configured.
///
/// Returned by [`ProvideValidatorMetadata::validator_metadata`]. Intended as
/// input to a Protected Resource Metadata document (RFC 9728).
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorMetadata {
    /// The realm identifying the protection space (RFC 6750 §3).
    ///
    /// Included as `realm="..."` in `WWW-Authenticate` challenges when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// The authorization server(s) this validator trusts, by issuer URI.
    ///
    /// `None` if not known or if the authorization server does not have an issuer URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,
    /// `DPoP` proof signing algorithms accepted by this validator.
    ///
    /// `None` if unrestricted (the validator accepts any algorithm its verifier supports).
    /// When `None`, this field should be omitted from RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// Whether DPoP-bound tokens are required.
    ///
    /// `Some(true)` means Bearer tokens are rejected. `None` means the requirement
    /// status is not known (e.g. a validator that cannot determine this). Maps to
    /// `dpop_bound_access_tokens_required` in RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens_required: Option<bool>,
    /// The resource server's identifier URI.
    ///
    /// Provided by the caller to identify this specific resource instance. Maps to `resource` in
    /// RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Supported methods for presenting Bearer tokens (RFC 6750).
    ///
    /// Values correspond to RFC 6750 sections: `"header"` (§2.1 Authorization header),
    /// `"body"` (§2.2 form-encoded body parameter), `"query"` (§2.3 URI query parameter).
    /// `None` means unspecified. Maps to `bearer_methods_supported` in RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<&'static str>>,
}

use crate::{
    TokenType,
    error::{ToRfc6750Error, TokenValidationError, escape_quoted},
};

impl ValidatorMetadata {
    /// Returns the `WWW-Authenticate` challenges for a request.
    ///
    /// If `error` is `None`, returns unauthenticated challenges for all supported
    /// schemes. If `error` is `Some` and the error is a [`TokenValidationError::Client`],
    /// the attempted scheme's challenge includes error details; other schemes are
    /// returned as unauthenticated challenges. If the attempted scheme is ambiguous,
    /// both challenges include error details, as permitted by RFC 9449 §7.1.
    ///
    /// If `error` is `Some` and the error is a [`TokenValidationError::Server`], returns
    /// an empty `Vec` — server-side failures (e.g. unreachable introspection endpoint) use
    /// a 5xx status code and no `WWW-Authenticate` header, since re-authenticating would
    /// not resolve the failure.
    ///
    /// If both Bearer and `DPoP` are supported, challenges for both are returned, as
    /// recommended by RFC 9449 §7.1. Per RFC 7235, the challenges may be sent as
    /// separate `WWW-Authenticate` headers or joined with `, ` on a single header —
    /// both forms are equivalent.
    ///
    /// # Example
    ///
    /// ```
    /// # use huskarl_resource_server::validator::metadata::ValidatorMetadata;
    /// let metadata = ValidatorMetadata {
    ///     realm: Some("example".to_string()),
    ///     authorization_servers: None,
    ///     dpop_signing_alg_values_supported: Some(vec!["ES256".to_string()]),
    ///     dpop_bound_access_tokens_required: Some(false),
    ///     resource: None,
    ///     bearer_methods_supported: None,
    /// };
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
        let mut challenges = Vec::new();
        let attempted_scheme =
            error.and_then(super::super::error::ToRfc6750Error::attempted_scheme);

        let dpop_supported = self.dpop_signing_alg_values_supported.is_some()
            || self.dpop_bound_access_tokens_required == Some(true);
        let bearer_allowed = !self.dpop_bound_access_tokens_required.unwrap_or(false);

        // For server errors (5xx), omit WWW-Authenticate entirely — including it would
        // mislead clients into thinking re-authenticating would resolve the failure.
        if error.is_some_and(|e| matches!(e.token_error(), TokenValidationError::Server(_))) {
            return Vec::new();
        }

        let is_client_error =
            error.is_some_and(|e| matches!(e.token_error(), TokenValidationError::Client(_)));

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
                include_in_bearer.then_some(error).flatten(),
                error_uri,
            ));
        }

        if dpop_supported {
            challenges.push(self.build_challenge(
                "DPoP",
                scope,
                include_in_dpop.then_some(error).flatten(),
                error_uri,
            ));
        }

        challenges
    }

    /// Builds a single `WWW-Authenticate` challenge string for the given scheme.
    ///
    /// If `error` is `Some`, includes error details (code, description, uri, extra params).
    fn build_challenge(
        &self,
        scheme: &str,
        scope: Option<&str>,
        error: Option<&dyn ToRfc6750Error>,
        error_uri: Option<&str>,
    ) -> String {
        let mut parts = Vec::new();

        if let Some(realm) = self.realm.as_deref() {
            parts.push(format!(r#"realm="{}""#, escape_quoted(realm)));
        }

        if let Some(scope) = scope {
            parts.push(format!(r#"scope="{}""#, escape_quoted(scope)));
        }

        if let Some(e) = error
            && let TokenValidationError::Client(code) = e.token_error()
        {
            parts.push(format!(r#"error="{}""#, code.as_str()));
            if let Some(desc) = e.error_description() {
                parts.push(format!(r#"error_description="{}""#, escape_quoted(&desc)));
            }
            if let Some(uri) = error_uri {
                parts.push(format!(r#"error_uri="{}""#, escape_quoted(uri)));
            }
            parts.extend(e.extra_params().into_iter().map(|p| p.format()));
        }

        if scheme == "DPoP"
            && let Some(algs) = &self.dpop_signing_alg_values_supported
        {
            parts.push(format!(r#"algs="{}""#, algs.join(" ")));
        }

        if parts.is_empty() {
            scheme.to_string()
        } else {
            format!("{} {}", scheme, parts.join(", "))
        }
    }

    /// Returns the `WWW-Authenticate` header values for an unauthenticated request.
    ///
    /// Equivalent to calling [`Self::challenges(None, scope, None)`].
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
        error::{ChallengeParam, TokenErrorCode, TokenValidationError},
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
                token_error: TokenValidationError::Server(http::StatusCode::BAD_GATEWAY),
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

    impl ToRfc6750Error for TestError {
        fn attempted_scheme(&self) -> Option<TokenType> {
            self.scheme
        }

        fn token_error(&self) -> TokenValidationError {
            self.token_error.clone()
        }

        fn error_description(&self) -> Option<String> {
            self.description.clone()
        }

        fn extra_params(&self) -> Vec<ChallengeParam> {
            self.extra.clone()
        }
    }

    fn meta() -> ValidatorMetadata {
        ValidatorMetadata {
            realm: None,
            authorization_servers: None,
            dpop_signing_alg_values_supported: None,
            dpop_bound_access_tokens_required: None,
            resource: None,
            bearer_methods_supported: None,
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
        // Explicitly-not-required and no algs → DPoP is not advertised at all.
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
