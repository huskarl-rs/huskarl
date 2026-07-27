//! Typed OAuth error responses.
//!
//! [`OAuthErrorCode`] represents the `error` member returned by OAuth endpoints.
//! [`OAuthError`] also preserves `error_description` and `error_uri`. See
//! [the error model](crate::_docs::explanation::error_handling) for how these
//! protocol errors are classified by [`crate::Error`].

use std::fmt;

use crate::error::RetryAdvice;

/// The `error` member of an `OAuth2` error response (RFC 6749 §5.2).
///
/// Which codes are valid depends on the endpoint. For example,
/// [`AuthorizationPending`](Self::AuthorizationPending) is defined for a
/// device-flow token request, while [`InvalidRedirectUri`](Self::InvalidRedirectUri)
/// is defined for dynamic client registration.
///
/// Unrecognised codes are preserved verbatim as [`Other`](Self::Other).
///
/// This enum is non-exhaustive; use a wildcard arm when matching it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
// Derive the count only for the test that ensures every variant has a wire
// spelling. This keeps the implementation detail out of the public API.
#[cfg_attr(test, derive(strum::EnumCount))]
pub enum OAuthErrorCode {
    // ---- RFC 6749 §5.2 — token endpoint ----
    /// The request was malformed or repeated a parameter.
    InvalidRequest,
    /// Client authentication failed (RFC 6749 §5.2). Usually accompanies a 401.
    InvalidClient,
    /// The grant or refresh token is invalid, expired, or revoked.
    InvalidGrant,
    /// This client is not authorized to use this grant type.
    UnauthorizedClient,
    /// The authorization server does not implement this grant type.
    UnsupportedGrantType,
    /// The requested scope is invalid, unknown, or exceeds what was granted.
    InvalidScope,

    // ---- RFC 6749 §4.1.2.1 — authorization endpoint ----
    /// The resource owner or authorization server denied the request.
    AccessDenied,
    /// The authorization server does not support this response type.
    UnsupportedResponseType,
    /// The authorization server hit an unexpected condition (RFC 6749 §4.1.2.1
    /// defines this as a code because a redirect cannot carry a 500).
    ServerError,
    /// The authorization server is temporarily overloaded or down.
    TemporarilyUnavailable,

    // ---- OpenID Connect Core 1.0 §3.1.2.6 — authorization endpoint ----
    /// The authorization server requires end-user interaction.
    ///
    /// This can be returned for `prompt=none` when the request and credential
    /// are valid but the flow cannot continue silently. Retry without
    /// `prompt=none`.
    InteractionRequired,
    /// The authorization server requires end-user authentication.
    ///
    /// The `prompt=none` answer when there is no usable session at the
    /// authorization server.
    LoginRequired,
    /// The end-user is required to select a session at the authorization
    /// server.
    AccountSelectionRequired,
    /// The authorization server requires end-user consent.
    ConsentRequired,
    /// The provider does not support the `registration` request parameter.
    RegistrationNotSupported,

    // ---- RFC 9101 §7 and OIDC Core 1.0 §3.1.2.6 — request objects (JAR) ----
    // OIDC Core and RFC 9101 define the same wire spellings.
    /// The `request` parameter contains an invalid request object.
    InvalidRequestObject,
    /// The `request_uri` returns an error or contains invalid data.
    InvalidRequestUri,
    /// The authorization server does not support the `request` parameter.
    RequestNotSupported,
    /// The authorization server does not support the `request_uri` parameter.
    RequestUriNotSupported,

    // ---- RFC 8628 §3.5 — device authorization grant ----
    /// The user has not yet completed the device flow; keep polling.
    AuthorizationPending,
    /// Polling is too frequent; increase the interval by 5 seconds.
    SlowDown,
    /// The `device_code` expired before the user completed the flow.
    ExpiredToken,

    // ---- RFC 8707 §2 — resource indicators ----
    /// The requested `resource` is invalid, unknown, or malformed.
    InvalidTarget,
    /// A non-standard spelling of [`InvalidTarget`](Self::InvalidTarget) used
    /// by some deployments.
    InvalidResource,

    // ---- RFC 9449 — DPoP ----
    /// The server requires a `DPoP` nonce; retry with the one it just issued
    /// (RFC 9449 §8).
    UseDPoPNonce,
    /// The `DPoP` proof was rejected (RFC 9449 §5).
    InvalidDPoPProof,

    // ---- RFC 9396 §5 — rich authorization requests ----
    /// The `authorization_details` are invalid, unknown, or malformed.
    InvalidAuthorizationDetails,

    // ---- RFC 7591 §3.2.2 — dynamic client registration ----
    /// The server rejected one or more redirection URIs.
    InvalidRedirectUri,
    /// The server rejected a client metadata value.
    InvalidClientMetadata,
    /// The presented software statement is invalid.
    InvalidSoftwareStatement,
    /// The presented software statement is not approved by this server.
    UnapprovedSoftwareStatement,

    // ---- RFC 7009 §2.2.1 — token revocation ----
    /// The authorization server cannot revoke the presented token type, such
    /// as an access token on a server that only revokes refresh tokens.
    ///
    /// This describes a server capability, not the validity of the token.
    UnsupportedTokenType,

    // ---- RFC 6750 §3.1 — resource server ----
    /// The access token is expired, revoked, or otherwise unusable.
    InvalidToken,
    /// The access token lacks the scope this resource requires.
    InsufficientScope,

    // ---- RFC 9470 §3 — step-up authentication ----
    /// The authentication event behind the access token does not meet the
    /// protected resource's requirements.
    ///
    /// The challenge describes the required authentication with `acr_values`
    /// and/or `max_age`. Like [`InsufficientScope`](Self::InsufficientScope),
    /// this applies to an issued token; the client needs a new authorization
    /// with stronger authentication.
    InsufficientUserAuthentication,

    /// An unrecognized code, preserved verbatim.
    ///
    /// [`UnknownCode`] has no public constructor. Convert from `&str` or
    /// [`String`] so recognized spellings always produce their named variant.
    Other(UnknownCode),
}

/// The wire spelling of an error with no named [`OAuthErrorCode`] variant.
///
/// This type is opaque so [`OAuthErrorCode::Other`] cannot be constructed with
/// the spelling of a recognized code. Read it with [`as_str`](Self::as_str).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownCode(String);

impl UnknownCode {
    /// Returns the code as it appeared on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnknownCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// A single table keeps formatting, parsing, and round-trip tests consistent.
pub(crate) const CODES: &[(OAuthErrorCode, &str)] = &[
    (OAuthErrorCode::InvalidRequest, "invalid_request"),
    (OAuthErrorCode::InvalidClient, "invalid_client"),
    (OAuthErrorCode::InvalidGrant, "invalid_grant"),
    (OAuthErrorCode::UnauthorizedClient, "unauthorized_client"),
    (
        OAuthErrorCode::UnsupportedGrantType,
        "unsupported_grant_type",
    ),
    (OAuthErrorCode::InvalidScope, "invalid_scope"),
    (OAuthErrorCode::AccessDenied, "access_denied"),
    (
        OAuthErrorCode::UnsupportedResponseType,
        "unsupported_response_type",
    ),
    (OAuthErrorCode::ServerError, "server_error"),
    (
        OAuthErrorCode::TemporarilyUnavailable,
        "temporarily_unavailable",
    ),
    (OAuthErrorCode::InteractionRequired, "interaction_required"),
    (OAuthErrorCode::LoginRequired, "login_required"),
    (
        OAuthErrorCode::AccountSelectionRequired,
        "account_selection_required",
    ),
    (OAuthErrorCode::ConsentRequired, "consent_required"),
    (
        OAuthErrorCode::RegistrationNotSupported,
        "registration_not_supported",
    ),
    (
        OAuthErrorCode::InvalidRequestObject,
        "invalid_request_object",
    ),
    (OAuthErrorCode::InvalidRequestUri, "invalid_request_uri"),
    (OAuthErrorCode::RequestNotSupported, "request_not_supported"),
    (
        OAuthErrorCode::RequestUriNotSupported,
        "request_uri_not_supported",
    ),
    (
        OAuthErrorCode::AuthorizationPending,
        "authorization_pending",
    ),
    (OAuthErrorCode::SlowDown, "slow_down"),
    (OAuthErrorCode::ExpiredToken, "expired_token"),
    (OAuthErrorCode::InvalidTarget, "invalid_target"),
    (OAuthErrorCode::InvalidResource, "invalid_resource"),
    (OAuthErrorCode::UseDPoPNonce, "use_dpop_nonce"),
    (OAuthErrorCode::InvalidDPoPProof, "invalid_dpop_proof"),
    (
        OAuthErrorCode::InvalidAuthorizationDetails,
        "invalid_authorization_details",
    ),
    (OAuthErrorCode::InvalidRedirectUri, "invalid_redirect_uri"),
    (
        OAuthErrorCode::InvalidClientMetadata,
        "invalid_client_metadata",
    ),
    (
        OAuthErrorCode::InvalidSoftwareStatement,
        "invalid_software_statement",
    ),
    (
        OAuthErrorCode::UnapprovedSoftwareStatement,
        "unapproved_software_statement",
    ),
    (
        OAuthErrorCode::UnsupportedTokenType,
        "unsupported_token_type",
    ),
    (OAuthErrorCode::InvalidToken, "invalid_token"),
    (OAuthErrorCode::InsufficientScope, "insufficient_scope"),
    (
        OAuthErrorCode::InsufficientUserAuthentication,
        "insufficient_user_authentication",
    ),
];

impl OAuthErrorCode {
    /// Returns the code's wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        if let Self::Other(raw) = self {
            return raw.as_str();
        }
        CODES
            .iter()
            .find_map(|(code, text)| (code == self).then_some(*text))
            // The coverage test makes this unreachable for current variants.
            // Keep the fallback so a future omission does not panic.
            .unwrap_or("unknown")
    }

    /// Returns whether changing caller-supplied request parameters may resolve
    /// this error without re-authentication.
    ///
    /// This includes invalid scope, resource, authorization details,
    /// registration metadata, and request-object values. It excludes
    /// [`InvalidRequest`](Self::InvalidRequest), which indicates a malformed
    /// protocol request, and resource-server verdicts such as
    /// [`InsufficientScope`](Self::InsufficientScope) and
    /// [`InsufficientUserAuthentication`](Self::InsufficientUserAuthentication),
    /// which concern an already-issued token.
    #[must_use]
    pub fn parameters_at_fault(&self) -> bool {
        matches!(
            self,
            // Invalid caller-selected values in token or authorization requests.
            Self::InvalidScope
                | Self::InvalidTarget
                | Self::InvalidResource
                | Self::InvalidAuthorizationDetails
                // Invalid registration metadata (RFC 7591 §3.2.2).
                | Self::InvalidRedirectUri
                | Self::InvalidClientMetadata
                | Self::InvalidSoftwareStatement
                | Self::UnapprovedSoftwareStatement
                // Invalid request-object values (RFC 9101 §7). The corresponding
                // `*_not_supported` codes describe server capabilities instead.
                | Self::InvalidRequestObject
                | Self::InvalidRequestUri
        )
    }

    /// Returns whether an `OpenID` Connect `prompt=none` request requires user
    /// interaction to continue.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use huskarl_core::OAuthErrorCode;
    /// assert!(OAuthErrorCode::LoginRequired.requires_interaction());
    /// assert!(!OAuthErrorCode::AccessDenied.requires_interaction());
    /// ```
    #[must_use]
    pub fn requires_interaction(&self) -> bool {
        matches!(
            self,
            Self::InteractionRequired
                | Self::LoginRequired
                | Self::AccountSelectionRequired
                | Self::ConsentRequired
        )
    }

    /// Returns the retry advice implied by this code alone.
    ///
    /// [`TemporarilyUnavailable`](Self::TemporarilyUnavailable) and
    /// [`ServerError`](Self::ServerError) return [`RetryAdvice::RETRY`]. All
    /// other codes return [`RetryAdvice::No`]. No delay is inferred from the
    /// code. Code handling that also has response headers should use
    /// the failed-response conversion path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use huskarl_core::{OAuthErrorCode, RetryAdvice};
    /// assert_eq!(
    ///     OAuthErrorCode::TemporarilyUnavailable.implied_retry_advice(),
    ///     RetryAdvice::RETRY
    /// );
    /// assert_eq!(
    ///     OAuthErrorCode::AccessDenied.implied_retry_advice(),
    ///     RetryAdvice::No
    /// );
    /// ```
    #[must_use]
    pub fn implied_retry_advice(&self) -> RetryAdvice {
        match self {
            Self::TemporarilyUnavailable | Self::ServerError => RetryAdvice::RETRY,
            _ => RetryAdvice::No,
        }
    }
}

/// Converts a wire spelling to a recognized code or
/// [`OAuthErrorCode::Other`].
impl From<&str> for OAuthErrorCode {
    fn from(code: &str) -> Self {
        CODES
            .iter()
            .find_map(|(known, text)| (*text == code).then(|| known.clone()))
            .unwrap_or_else(|| Self::Other(UnknownCode(code.to_owned())))
    }
}

impl From<String> for OAuthErrorCode {
    fn from(code: String) -> Self {
        match Self::from(code.as_str()) {
            // Reuse the allocation we were handed rather than cloning it back.
            Self::Other(_) => Self::Other(UnknownCode(code)),
            known => known,
        }
    }
}

impl fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An OAuth error response.
///
/// This preserves the required `error` code and optional `error_description`
/// and `error_uri` members defined by RFC 6749.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    code: OAuthErrorCode,
    description: Option<String>,
    uri: Option<String>,
}

impl OAuthError {
    /// Creates an error response containing only `code`.
    #[must_use]
    pub fn new(code: impl Into<OAuthErrorCode>) -> Self {
        Self {
            code: code.into(),
            description: None,
            uri: None,
        }
    }

    /// Sets the server's optional `error_description`.
    #[must_use]
    pub fn with_description(mut self, description: Option<String>) -> Self {
        self.description = description;
        self
    }

    /// Sets the server's optional `error_uri`.
    #[must_use]
    pub fn with_uri(mut self, uri: Option<String>) -> Self {
        self.uri = uri;
        self
    }

    /// Returns the error code sent by the server.
    #[must_use]
    pub fn code(&self) -> &OAuthErrorCode {
        &self.code
    }

    /// Returns the server's human-readable `error_description`, if present.
    ///
    /// This value is untrusted, server-controlled text intended for developers.
    /// Do not use it for protocol decisions, and escape it before rendering it.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the server's `error_uri`, if present.
    ///
    /// This URI is untrusted and server-controlled. Do not fetch it
    /// automatically or expose it as a link without validating its scheme and
    /// origin.
    #[must_use]
    pub fn uri(&self) -> Option<&str> {
        self.uri.as_deref()
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(f)?;
        if let Some(description) = &self.description {
            write!(f, ": {description}")?;
        }
        if let Some(uri) = &self.uri {
            write!(f, " (see {uri})")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keep the variant count and wire-spelling table in sync. The round-trip
    // test below also catches duplicates or missing variants.
    #[test]
    fn every_named_variant_has_a_spelling() {
        use strum::EnumCount as _;

        assert_eq!(
            CODES.len(),
            OAuthErrorCode::COUNT - 1,
            "every variant except `Other` needs a row in `CODES` — one was added \
             without a spelling, and `as_str` will render it as \"unknown\""
        );
    }

    // Preserve all three members of an RFC 6749 §5.2 response.
    #[test]
    fn oauth_error_carries_code_description_and_uri() {
        let err = crate::Error::propagate(
            crate::error::propagation::Classification::judged(
                RetryAdvice::No,
                OAuthError::new("invalid_scope")
                    .with_description(Some("scope 'admin' is not permitted".to_owned()))
                    .with_uri(Some(
                        "https://as.example.com/errors/invalid_scope".to_owned(),
                    )),
            ),
            "underlying",
        );
        let oauth = err.verdict().expect("verdict attached");
        assert_eq!(oauth.code(), &OAuthErrorCode::InvalidScope);
        assert_eq!(oauth.description(), Some("scope 'admin' is not permitted"));
        assert_eq!(
            oauth.uri(),
            Some("https://as.example.com/errors/invalid_scope")
        );
    }

    #[test]
    fn every_code_round_trips() {
        for (code, text) in CODES {
            assert_eq!(code.as_str(), *text);
            assert_eq!(&OAuthErrorCode::from(*text), code);
            assert_eq!(&OAuthErrorCode::from((*text).to_owned()), code);
        }
    }

    // Preserve the RFC's DPoP capitalization when deriving wire spellings.
    #[test]
    fn dpop_codes_use_their_rfc_spelling() {
        assert_eq!(OAuthErrorCode::UseDPoPNonce.as_str(), "use_dpop_nonce");
        assert_eq!(
            OAuthErrorCode::InvalidDPoPProof.as_str(),
            "invalid_dpop_proof"
        );
    }

    // Preserve extension codes verbatim for callers that understand them.
    #[test]
    fn unknown_codes_are_preserved_verbatim() {
        let code = OAuthErrorCode::from("something_bespoke");
        assert_eq!(
            code,
            OAuthErrorCode::Other(UnknownCode("something_bespoke".to_owned()))
        );
        assert_eq!(code.as_str(), "something_bespoke");
        assert_eq!(code.to_string(), "something_bespoke");
        // Unknown codes do not imply a remedy.
        assert!(!code.parameters_at_fault());
    }

    // Parsing a known spelling must always produce its named variant.
    #[test]
    fn a_known_spelling_never_arrives_as_other() {
        use std::hash::{BuildHasher as _, RandomState};

        // Use one `RandomState` so both values use the same hash keys.
        let hasher = RandomState::new();
        for (code, text) in CODES {
            for parsed in [
                OAuthErrorCode::from(*text),
                OAuthErrorCode::from((*text).to_owned()),
            ] {
                assert!(
                    !matches!(parsed, OAuthErrorCode::Other(_)),
                    "{text} parsed as `Other` rather than {code:?}"
                );
                assert_eq!(&parsed, code);
                // Equal codes must also hash identically.
                assert_eq!(hasher.hash_one(&parsed), hasher.hash_one(code), "{text}");
            }
        }
    }

    // A code must not recommend more than one remedy: adjust the request, retry
    // later, or involve the user.
    #[test]
    fn the_registry_facts_are_mutually_exclusive() {
        for (code, text) in CODES {
            let facts = [
                ("blames the parameters", code.parameters_at_fault()),
                (
                    "asks for a retry",
                    code.implied_retry_advice() == RetryAdvice::RETRY,
                ),
                ("requires interaction", code.requires_interaction()),
            ];
            let claimed: Vec<_> = facts
                .iter()
                .filter_map(|(label, holds)| holds.then_some(*label))
                .collect();
            assert!(
                claimed.len() <= 1,
                "{text} claims {claimed:?}, but these remedies are exclusive"
            );
        }
    }

    // Only the four `prompt=none` responses require interaction.
    #[test]
    fn only_the_prompt_none_answers_require_interaction() {
        for (code, text) in CODES {
            let expected = matches!(
                code,
                OAuthErrorCode::InteractionRequired
                    | OAuthErrorCode::LoginRequired
                    | OAuthErrorCode::AccountSelectionRequired
                    | OAuthErrorCode::ConsentRequired
            );
            assert_eq!(code.requires_interaction(), expected, "{text}");
        }
        // Extension codes provide no interaction advice.
        assert!(!OAuthErrorCode::from("something_bespoke").requires_interaction());
    }

    // Distinguish invalid caller-selected values from nearby codes that require
    // a different remedy. In particular, `invalid_grant` must not be treated as
    // a request-shape error because a cache may discard the credential.
    #[test]
    fn only_request_shape_codes_blame_the_parameters() {
        for code in [
            OAuthErrorCode::InvalidScope,
            OAuthErrorCode::InvalidTarget,
            OAuthErrorCode::InvalidResource,
            OAuthErrorCode::InvalidAuthorizationDetails,
            OAuthErrorCode::InvalidRedirectUri,
            OAuthErrorCode::InvalidClientMetadata,
            OAuthErrorCode::InvalidSoftwareStatement,
            OAuthErrorCode::UnapprovedSoftwareStatement,
            // Rebuild request objects rejected for invalid values.
            OAuthErrorCode::InvalidRequestObject,
            OAuthErrorCode::InvalidRequestUri,
        ] {
            assert!(code.parameters_at_fault(), "{code:?}");
        }
        for code in [
            OAuthErrorCode::InvalidGrant,
            OAuthErrorCode::InvalidClient,
            OAuthErrorCode::AccessDenied,
            OAuthErrorCode::UseDPoPNonce,
            // `invalid_request` means the library built a malformed protocol
            // request; there is no caller-selected value to adjust.
            OAuthErrorCode::InvalidRequest,
            OAuthErrorCode::ExpiredToken,
            // These verdicts concern an issued token, not request parameters.
            OAuthErrorCode::InsufficientScope,
            OAuthErrorCode::InsufficientUserAuthentication,
            // Unsupported token types describe a server capability.
            OAuthErrorCode::UnsupportedTokenType,
            // These `prompt=none` responses require user interaction.
            OAuthErrorCode::InteractionRequired,
            OAuthErrorCode::LoginRequired,
            OAuthErrorCode::AccountSelectionRequired,
            OAuthErrorCode::ConsentRequired,
            // Capability gaps cannot be fixed by adjusting the request.
            OAuthErrorCode::RequestNotSupported,
            OAuthErrorCode::RequestUriNotSupported,
            OAuthErrorCode::RegistrationNotSupported,
            OAuthErrorCode::UnsupportedGrantType,
            OAuthErrorCode::UnsupportedResponseType,
        ] {
            assert!(!code.parameters_at_fault(), "{code:?}");
        }
    }

    // Redirects cannot carry HTTP 500 or 503 statuses, so RFC 6749 represents
    // those retryable conditions as error codes.
    #[test]
    fn the_redirect_borne_5xx_codes_imply_a_retry() {
        for code in [
            OAuthErrorCode::TemporarilyUnavailable,
            OAuthErrorCode::ServerError,
        ] {
            assert_eq!(code.implied_retry_advice(), RetryAdvice::RETRY, "{code:?}");
        }
    }

    // New codes must not become retryable implicitly.
    #[test]
    fn no_other_code_implies_a_retry() {
        for (code, _) in CODES {
            let expected = matches!(
                code,
                OAuthErrorCode::TemporarilyUnavailable | OAuthErrorCode::ServerError
            );
            assert_eq!(
                code.implied_retry_advice() == RetryAdvice::RETRY,
                expected,
                "{code:?}"
            );
        }
        // Extension codes provide no retry advice.
        assert_eq!(
            OAuthErrorCode::from("something_bespoke").implied_retry_advice(),
            RetryAdvice::No
        );
    }

    // Keep the four `prompt=none` responses distinct for typed handling.
    #[test]
    fn the_prompt_none_answers_are_typed_and_distinct() {
        let answers = [
            ("interaction_required", OAuthErrorCode::InteractionRequired),
            ("login_required", OAuthErrorCode::LoginRequired),
            (
                "account_selection_required",
                OAuthErrorCode::AccountSelectionRequired,
            ),
            ("consent_required", OAuthErrorCode::ConsentRequired),
        ];
        for (wire, expected) in &answers {
            assert_eq!(&OAuthErrorCode::from(*wire), expected);
            assert_eq!(expected.as_str(), *wire);
        }
        // A UI can handle each response separately.
        for (i, (_, a)) in answers.iter().enumerate() {
            for (_, b) in &answers[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // RFC 9101 and OIDC Core use identical request-object error codes.
    #[test]
    fn the_jar_codes_are_one_set_under_two_specs() {
        for (wire, expected) in [
            (
                "invalid_request_object",
                OAuthErrorCode::InvalidRequestObject,
            ),
            ("invalid_request_uri", OAuthErrorCode::InvalidRequestUri),
            ("request_not_supported", OAuthErrorCode::RequestNotSupported),
            (
                "request_uri_not_supported",
                OAuthErrorCode::RequestUriNotSupported,
            ),
        ] {
            assert_eq!(OAuthErrorCode::from(wire), expected);
            assert_eq!(expected.as_str(), wire);
        }
    }

    #[test]
    fn display_renders_the_whole_response_object() {
        let err = OAuthError::new("invalid_scope")
            .with_description(Some("scope 'admin' is not permitted".to_owned()))
            .with_uri(Some("https://as.example.com/errors".to_owned()));
        assert_eq!(
            err.to_string(),
            "invalid_scope: scope 'admin' is not permitted (see https://as.example.com/errors)"
        );
        assert_eq!(err.code(), &OAuthErrorCode::InvalidScope);

        // A response without optional fields renders as only its code.
        assert_eq!(
            OAuthError::new("invalid_grant").to_string(),
            "invalid_grant"
        );
    }
}
