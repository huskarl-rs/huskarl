//! RFC 6750 attribute-based error types and traits for resource server responses.
//!
//! These attributes (error, error_description) are used by both the
//! `Bearer` (RFC 6750) and `DPoP` (RFC 9449) authentication schemes.
//! The `error_uri` attribute is supported as a parameter to
//! [`crate::validator::metadata::ValidatorMetadata::challenges`].
//!
//! [`TokenValidationError`] classifies a validation failure as either a client-side
//! error (include RFC 6750 error details in the response) or a server-side error
//! (respond with a status code, no error details).

use crate::TokenType;
use crate::core::platform::MaybeSendSync;

/// Escapes a value for use in an HTTP quoted-string (RFC 9110 §5.6.4).
///
/// Backslashes and double-quotes must be escaped with a leading backslash.
pub(crate) fn escape_quoted(s: &str) -> std::borrow::Cow<'_, str> {
    if s.contains('"') || s.contains('\\') {
        std::borrow::Cow::Owned(s.replace('\\', r"\\").replace('"', r#"\""#))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// A parameter for a `WWW-Authenticate` challenge.
///
/// Used as the return type of [`ToRfc6750Error::extra_params`] to ensure values
/// are correctly formatted and escaped in the challenge header.
#[derive(Debug, Clone)]
pub enum ChallengeParam {
    /// A quoted-string parameter: `key="value"`.
    ///
    /// The value is automatically escaped per RFC 9110 §5.6.4 — backslashes
    /// and double-quotes are prefixed with a backslash.
    Quoted(&'static str, String),
    /// An unquoted token parameter: `key=value`.
    ///
    /// The value must be a valid HTTP token (ASCII, no whitespace or delimiters).
    Token(&'static str, String),
}

impl ChallengeParam {
    /// Formats this parameter as a `key=value` or `key="escaped-value"` string.
    #[must_use]
    pub fn format(&self) -> String {
        match self {
            Self::Quoted(key, value) => format!(r#"{}="{}""#, key, escape_quoted(value)),
            Self::Token(key, value) => format!("{}={}", key, value),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenErrorCode {
    /// The request is malformed. Respond with HTTP 400.
    InvalidRequest,
    /// The access token is invalid, expired, or revoked. Respond with HTTP 401.
    InvalidToken,
    /// The token has insufficient scope for the requested resource. Respond with HTTP 403.
    InsufficientScope,
    /// The `DPoP` proof is invalid. Respond with HTTP 401 (RFC 9449).
    InvalidDPoPProof,
    /// A `DPoP` nonce is required. Respond with HTTP 401 (RFC 9449).
    UseDPoPNonce,
    /// The token was obtained with insufficient user authentication strength.
    /// Respond with HTTP 401 (RFC 9470).
    InsufficientUserAuthentication,
}

impl TokenErrorCode {
    /// The error code string as defined in RFC 6750 §3.1 or RFC 9449 §7.1.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::InvalidDPoPProof => "invalid_dpop_proof",
            Self::UseDPoPNonce => "use_dpop_nonce",
            Self::InsufficientUserAuthentication => "insufficient_user_authentication",
        }
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
/// [`crate::validator::metadata::ValidatorMetadata::challenges`] when building
/// a `WWW-Authenticate` response for an insufficient-scope rejection.
#[derive(Debug, Clone, Default)]
pub struct InsufficientScope;

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
pub trait ToRfc6750Error: MaybeSendSync {
    /// Returns the attempted authentication scheme, if known.
    fn attempted_scheme(&self) -> Option<TokenType>;

    /// Classifies this error as a client-side or server-side failure.
    ///
    /// - [`TokenValidationError::Client`]: a problem with the client's token or request.
    ///   Include RFC 6750 error details in the `WWW-Authenticate` response.
    /// - [`TokenValidationError::Server`]: a server-side failure (e.g. unreachable introspection
    ///   endpoint). Respond with the given status code and no `WWW-Authenticate` header.
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
            E::ExtraClaims { .. } => Some(
                "The access token does not contain the required claims".to_string(),
            ),
        }
    }
}
