//! RFC 6750 attribute-based error types and traits for resource server responses.
//!
//! These attributes (error, error_description) are used by both the
//! `Bearer` (RFC 6750) and `DPoP` (RFC 9449) authentication schemes.
//! The `error_uri` attribute is supported as a parameter to
//! [`crate::validator::metadata::ValidatorMetadata::challenges`].

use crate::TokenType;

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

/// A trait for errors that can be converted into an RFC 6750-style error response.
pub trait ToRfc6750Error {
    /// Returns the attempted authentication scheme, if known.
    fn attempted_scheme(&self) -> Option<TokenType>;

    /// Returns the RFC 6750 §3.1 error code for this error, or `None` for
    /// server-side failures where the resource server should respond with HTTP
    /// 5xx and omit the error code from the `WWW-Authenticate` header.
    fn error_code(&self) -> Option<TokenErrorCode>;

    /// Returns a human-readable description of the error for the `error_description` parameter.
    fn error_description(&self) -> Option<String>;


}

impl ToRfc6750Error for crate::core::jwt::validator::JwtValidationError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn error_code(&self) -> Option<TokenErrorCode> {
        Some(TokenErrorCode::InvalidToken)
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
