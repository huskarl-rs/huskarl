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
/// `InsufficientScope` is not returned by this library — it is an application-level
/// decision based on the scopes in the validated token. It is included here so
/// callers can use a single type when building `WWW-Authenticate` error responses.
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
        }
    }

    /// The suggested HTTP status code.
    #[must_use]
    pub fn suggested_status(&self) -> http::StatusCode {
        match self {
            Self::InvalidRequest => http::StatusCode::BAD_REQUEST,
            Self::InvalidToken | Self::InvalidDPoPProof | Self::UseDPoPNonce => {
                http::StatusCode::UNAUTHORIZED
            }
            Self::InsufficientScope => http::StatusCode::FORBIDDEN,
        }
    }
}

/// A trait for errors that can be classified into an RFC 6750-style error response.
pub trait ToRfc6750Error {
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
        }
    }
}
