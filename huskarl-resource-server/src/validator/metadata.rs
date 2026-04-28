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
    /// DPoP proof signing algorithms accepted by this validator.
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

use crate::TokenType;
use crate::error::{ToRfc6750Error, TokenValidationError, escape_quoted};

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
    /// If both Bearer and DPoP are supported, challenges for both are returned, as
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
    /// assert_eq!(challenges[0], r#"Bearer realm="example", scope="read write""#);
    /// assert_eq!(challenges[1], r#"DPoP realm="example", scope="read write", algs="ES256""#);
    /// ```
    #[must_use]
    pub fn challenges(
        &self,
        error: Option<&dyn ToRfc6750Error>,
        scope: Option<&str>,
        error_uri: Option<&str>,
    ) -> Vec<String> {
        let mut challenges = Vec::new();
        let attempted_scheme = error.and_then(|e| e.attempted_scheme());

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
            let mut bearer_parts = Vec::new();
            if let Some(realm) = self.realm.as_deref() {
                bearer_parts.push(format!(r#"realm="{}""#, escape_quoted(realm)));
            }

            if let Some(scope) = scope {
                bearer_parts.push(format!(r#"scope="{}""#, escape_quoted(scope)));
            }

            if include_in_bearer
                && let Some(e) = error
                && let TokenValidationError::Client(code) = e.token_error()
            {
                bearer_parts.push(format!(r#"error="{}""#, code.as_str()));
                if let Some(desc) = e.error_description() {
                    bearer_parts.push(format!(r#"error_description="{}""#, escape_quoted(&desc)));
                }
                if let Some(uri) = error_uri {
                    bearer_parts.push(format!(r#"error_uri="{}""#, escape_quoted(uri)));
                }
                bearer_parts.extend(e.extra_params().into_iter().map(|p| p.format()));
            }

            let mut bearer = "Bearer".to_string();
            if !bearer_parts.is_empty() {
                bearer.push(' ');
                bearer.push_str(&bearer_parts.join(", "));
            }
            challenges.push(bearer);
        }

        if dpop_supported {
            let mut dpop_parts = Vec::new();
            if let Some(realm) = self.realm.as_deref() {
                dpop_parts.push(format!(r#"realm="{}""#, escape_quoted(realm)));
            }

            if let Some(scope) = scope {
                dpop_parts.push(format!(r#"scope="{}""#, escape_quoted(scope)));
            }

            if include_in_dpop
                && let Some(e) = error
                && let TokenValidationError::Client(code) = e.token_error()
            {
                dpop_parts.push(format!(r#"error="{}""#, code.as_str()));
                if let Some(desc) = e.error_description() {
                    dpop_parts.push(format!(r#"error_description="{}""#, escape_quoted(&desc)));
                }
                if let Some(uri) = error_uri {
                    dpop_parts.push(format!(r#"error_uri="{}""#, escape_quoted(uri)));
                }
                dpop_parts.extend(e.extra_params().into_iter().map(|p| p.format()));
            }

            if let Some(algs) = &self.dpop_signing_alg_values_supported {
                dpop_parts.push(format!(r#"algs="{}""#, algs.join(" ")));
            }

            let mut dpop = "DPoP".to_string();
            if !dpop_parts.is_empty() {
                dpop.push(' ');
                dpop.push_str(&dpop_parts.join(", "));
            }
            challenges.push(dpop);
        }

        challenges
    }

    /// Returns the `WWW-Authenticate` header values for an unauthenticated request.
    ///
    /// Equivalent to calling [`Self::challenges(None, scope, None)`].
    #[must_use]
    pub fn unauthenticated_challenges(&self, scope: Option<&str>) -> Vec<String> {
        self.challenges(None, scope, None)
    }
}

/// A trait for validators that can describe their configuration.
///
/// The returned [`ValidatorMetadata`] can be used to populate a Protected Resource
/// Metadata document (RFC 9728).
pub trait ProvideValidatorMetadata {
    /// Returns metadata describing how this validator is configured.
    ///
    /// The resource is the URL of the protected resource.
    ///
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata;
}
