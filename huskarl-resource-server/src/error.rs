//! RFC 6750 attribute-based error types and traits for resource server responses.
//!
//! These attributes (error, `error_description`) are used by both the
//! `Bearer` (RFC 6750) and `DPoP` (RFC 9449) authentication schemes.
//! The `error_uri` attribute is supported as a parameter to
//! [`crate::validator::metadata::ValidatorMetadata::challenges`].
//!
//! [`TokenValidationError`] classifies a validation failure as either a client-side
//! error (include RFC 6750 error details in the response) or a server-side error
//! (respond with a status code, no error details).

use std::borrow::Cow;

use crate::{TokenType, core::platform::MaybeSendSync};

/// Escapes a value for safe inclusion in an HTTP quoted-string (RFC 9110 §5.6.4).
///
/// Double-quotes and backslashes are backslash-escaped. Control characters other
/// than HTAB cannot appear in a quoted-string and would break header framing, so
/// they are stripped. All other characters — including non-ASCII `obs-text` —
/// pass through unchanged. The common (clean) case borrows without allocating.
pub(crate) fn escape_quoted(s: &str) -> Cow<'_, str> {
    let needs_work = s
        .chars()
        .any(|c| c == '"' || c == '\\' || (c.is_control() && c != '\t'));
    if !needs_work {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Control characters (except HTAB) are invalid in a quoted-string and
            // would break header framing; drop them rather than emit them.
            c if c.is_control() && c != '\t' => {}
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Returns `true` if `c` is a valid HTTP `token` character (RFC 9110 §5.6.2).
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// A parameter for a `WWW-Authenticate` challenge.
///
/// Used as the return type of [`ToRfc6750Error::extra_params`] to ensure values
/// are correctly formatted and escaped in the challenge header.
#[derive(Debug, Clone)]
pub enum ChallengeParam {
    /// A quoted-string parameter: `key="value"`.
    ///
    /// The value is sanitized per RFC 9110 §5.6.4 when formatted: backslashes and
    /// double-quotes are backslash-escaped, and control characters (other than
    /// HTAB) are stripped, so the value cannot break header framing.
    Quoted(&'static str, String),
    /// An unquoted token parameter: `key=value`.
    ///
    /// The value should be a valid HTTP token (RFC 9110 §5.6.2). Because an
    /// unquoted value cannot be escaped, any non-token characters are stripped
    /// when formatted.
    Token(&'static str, String),
}

impl ChallengeParam {
    /// Formats this parameter as a `key=value` or `key="escaped-value"` string.
    ///
    /// Values are sanitized so the result is always a valid challenge parameter
    /// regardless of input (see the variant docs).
    #[must_use]
    pub fn format(&self) -> String {
        match self {
            Self::Quoted(key, value) => format!(r#"{}="{}""#, key, escape_quoted(value)),
            Self::Token(key, value) => {
                let value: String = value.chars().filter(|c| is_tchar(*c)).collect();
                format!("{key}={value}")
            }
        }
    }
}

/// Classifies a token validation failure for HTTP response generation.
///
/// Returned by [`ToRfc6750Error::token_error`].
#[derive(Debug, Clone)]
pub enum TokenValidationError {
    /// A client-side error. Include RFC 6750 error details in the `WWW-Authenticate` response.
    Client(TokenErrorCode),
    /// A server-side error. Respond with this status code and no `WWW-Authenticate` header,
    /// since the failure is not caused by the client's token or request.
    Server(http::StatusCode),
}

impl TokenValidationError {
    /// The HTTP status code to use for this error.
    #[must_use]
    pub fn suggested_status(&self) -> http::StatusCode {
        match self {
            Self::Client(code) => code.suggested_status(),
            Self::Server(status) => *status,
        }
    }
}

/// RFC 6750 §3.1 error codes for resource server responses.
///
/// Most variants are returned directly by this library's validators. [`Self::InsufficientScope`]
/// and [`Self::InsufficientUserAuthentication`] are application-level decisions — use
/// [`InsufficientScope`] and [`InsufficientUserAuthentication`] respectively to build
/// `WWW-Authenticate` responses for those cases.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::IntoStaticStr,
    strum::AsRefStr,
    strum::Display,
    strum::EnumString,
)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum TokenErrorCode {
    /// The request is malformed. Respond with HTTP 400.
    InvalidRequest,
    /// The access token is invalid, expired, or revoked. Respond with HTTP 401.
    InvalidToken,
    /// The token has insufficient scope for the requested resource. Respond with HTTP 403.
    InsufficientScope,
    /// The `DPoP` proof is invalid. Respond with HTTP 401 (RFC 9449).
    // `snake_case` would mangle the `DPoP` acronym, so spell it out.
    #[strum(serialize = "invalid_dpop_proof")]
    InvalidDPoPProof,
    /// A `DPoP` nonce is required. Respond with HTTP 401 (RFC 9449).
    #[strum(serialize = "use_dpop_nonce")]
    UseDPoPNonce,
    /// The token was obtained with insufficient user authentication strength.
    /// Respond with HTTP 401 (RFC 9470).
    InsufficientUserAuthentication,
}

impl TokenErrorCode {
    /// The error code string as defined in RFC 6750 §3.1 or RFC 9449 §7.1.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }

    /// The suggested HTTP status code.
    #[must_use]
    pub fn suggested_status(&self) -> http::StatusCode {
        match self {
            Self::InvalidRequest => http::StatusCode::BAD_REQUEST,
            Self::InvalidToken
            | Self::InvalidDPoPProof
            | Self::UseDPoPNonce
            | Self::InsufficientUserAuthentication => http::StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => http::StatusCode::FORBIDDEN,
        }
    }
}

/// An application-level error for tokens that lack the required scope.
///
/// Implements [`ToRfc6750Error`] so it can be passed to
/// [`crate::validator::metadata::ValidatorMetadata::challenges`] (or the
/// assembled [`rejection`](crate::validator::metadata::ValidatorMetadata::rejection))
/// when building a `WWW-Authenticate` response for an insufficient-scope
/// rejection.
///
/// Construct with [`new`](Self::new) so the challenge tells the client which
/// scope it was missing (RFC 6750 §3 `scope` attribute); use
/// [`InsufficientScope::default()`] only when the required scope should not
/// be disclosed.
#[derive(Debug, Clone, Default)]
pub struct InsufficientScope {
    /// The scope required to access the resource, as a space-separated list
    /// (RFC 6750 §3). Emitted as the challenge `scope` attribute.
    pub scope: Option<String>,
}

impl InsufficientScope {
    /// An insufficient-scope rejection naming the `scope` the resource requires.
    #[must_use]
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: Some(scope.into()),
        }
    }
}

impl ToRfc6750Error for InsufficientScope {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InsufficientScope)
    }

    fn error_description(&self) -> Option<String> {
        Some("The access token has insufficient scope for the requested resource".to_string())
    }

    fn required_scope(&self) -> Option<String> {
        self.scope.clone()
    }
}

/// An application-level error for tokens obtained with insufficient authentication strength.
///
/// Implements [`ToRfc6750Error`] so it can be passed to
/// [`crate::validator::metadata::ValidatorMetadata::challenges`] when building
/// a `WWW-Authenticate` response per RFC 9470 (Step Up Authentication Challenge Protocol).
///
/// Set `acr_values` and/or `max_age` to include the corresponding RFC 9470 challenge parameters.
#[derive(Debug, Clone, Default)]
pub struct InsufficientUserAuthentication {
    /// The required Authentication Context Class Reference values (RFC 9470 §2).
    pub acr_values: Option<String>,
    /// The maximum acceptable authentication age in seconds (RFC 9470 §2).
    pub max_age: Option<u64>,
}

impl ToRfc6750Error for InsufficientUserAuthentication {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InsufficientUserAuthentication)
    }

    fn error_description(&self) -> Option<String> {
        Some("A higher authentication level is required to access this resource".to_string())
    }

    fn extra_params(&self) -> Vec<ChallengeParam> {
        let mut params = Vec::new();
        if let Some(acr) = &self.acr_values {
            params.push(ChallengeParam::Quoted("acr_values", acr.clone()));
        }
        if let Some(max_age) = self.max_age {
            params.push(ChallengeParam::Token("max_age", max_age.to_string()));
        }
        params
    }
}

/// A trait for errors that can be classified into an RFC 6750-style error response.
pub trait ToRfc6750Error: std::fmt::Debug + MaybeSendSync {
    /// Returns the attempted authentication scheme, if known.
    fn attempted_scheme(&self) -> Option<TokenType>;

    /// Classifies this error as a client-side or server-side failure; see
    /// [`TokenValidationError`] for how each is rendered into a response.
    fn token_error(&self) -> TokenValidationError;

    /// Returns a human-readable description of the error for the `error_description` parameter.
    ///
    /// Only included in the response for [`TokenValidationError::Client`] errors.
    fn error_description(&self) -> Option<String>;

    /// Returns additional challenge parameters to include in the `WWW-Authenticate` response.
    ///
    /// Only included for [`TokenValidationError::Client`] errors. Use [`ChallengeParam::Quoted`]
    /// for string values (escaping is handled automatically) and [`ChallengeParam::Token`] for
    /// unquoted values such as integers.
    fn extra_params(&self) -> Vec<ChallengeParam> {
        Vec::new()
    }

    /// Returns the scope the resource requires, as a space-separated list, for
    /// the challenge `scope` attribute (RFC 6750 §3).
    ///
    /// When `Some`, it takes precedence over the `scope` argument to
    /// [`crate::validator::metadata::ValidatorMetadata::challenges`] — the
    /// error names the specific unmet requirement. Defaults to `None`; see
    /// [`InsufficientScope`] for the standard carrier.
    fn required_scope(&self) -> Option<String> {
        None
    }
}

impl ToRfc6750Error for crate::core::jwt::validator::JwtValidationError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InvalidToken)
    }

    fn error_description(&self) -> Option<String> {
        use crate::core::jwt::validator::JwtValidationError as E;
        match self {
            E::Parse { .. } => Some("The access token is malformed".to_string()),
            E::Signature { .. } => Some("The access token signature is invalid".to_string()),
            E::UnsignedToken => Some("The access token is unsigned".to_string()),
            E::DisallowedAlgorithm { .. } => {
                Some("The access token uses an unsupported signature algorithm".to_string())
            }
            E::UnrecognizedCriticalHeader { .. } => Some(
                "The access token contains unrecognized critical header parameters".to_string(),
            ),
            E::Expired { .. } => Some("The access token expired".to_string()),
            E::NotYetValid { .. } => Some("The access token is not yet valid".to_string()),
            E::IssuedInFuture { .. } => {
                Some("The access token was issued in the future".to_string())
            }
            E::TokenTooOld { .. } => Some("The access token is too old".to_string()),
            E::InvalidTokenType { .. } => Some("The access token type is invalid".to_string()),
            E::ClaimMismatch { claim, .. } => {
                Some(format!("The access token '{claim}' claim is invalid"))
            }
            E::RequiredClaimMissing { claim } => Some(format!(
                "The access token is missing the required '{claim}' claim"
            )),
            E::JtiNotUnique => {
                Some("The access token 'jti' claim value was previously seen".to_string())
            }
            E::JtiCheck { .. } => None,
            E::ExtraClaims { .. } => {
                Some("The access token does not contain the required claims".to_string())
            }
            E::JtiTooLong { .. } => Some("The access token 'jti' claim is too long".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_error_code_str_roundtrip() {
        for (code, s) in [
            (TokenErrorCode::InvalidRequest, "invalid_request"),
            (TokenErrorCode::InvalidToken, "invalid_token"),
            (TokenErrorCode::InsufficientScope, "insufficient_scope"),
            (TokenErrorCode::InvalidDPoPProof, "invalid_dpop_proof"),
            (TokenErrorCode::UseDPoPNonce, "use_dpop_nonce"),
            (
                TokenErrorCode::InsufficientUserAuthentication,
                "insufficient_user_authentication",
            ),
        ] {
            assert_eq!(code.as_str(), s);
            assert_eq!(code.to_string(), s, "Display matches the RFC code");
            assert_eq!(s.parse::<TokenErrorCode>().unwrap(), code);
        }
        // Unknown codes are rejected.
        assert!("not_a_code".parse::<TokenErrorCode>().is_err());
    }

    #[test]
    fn escape_quoted_escapes_quote_and_backslash() {
        assert_eq!(escape_quoted(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn escape_quoted_clean_input_is_borrowed() {
        assert!(matches!(escape_quoted("clean value"), Cow::Borrowed(_)));
    }

    #[test]
    fn escape_quoted_strips_control_chars_but_keeps_tab_and_unicode() {
        // CR/LF and other controls are removed (no header-framing injection);
        // HTAB and non-ASCII obs-text survive.
        let out = escape_quoted("a\r\nb\u{0007}c\td\u{00e9}");
        assert_eq!(out, "abc\td\u{00e9}");
        assert!(!out.contains(['\r', '\n']));
    }

    #[test]
    fn token_param_strips_non_token_chars() {
        // A valid token is unchanged.
        assert_eq!(
            ChallengeParam::Token("max_age", "60".to_string()).format(),
            "max_age=60"
        );
        // An injection attempt via a Token value cannot split the header.
        let injected = ChallengeParam::Token("max_age", "1\r\n2".to_string()).format();
        assert_eq!(injected, "max_age=12");
        assert!(!injected.contains(['\r', '\n']));
    }
}
