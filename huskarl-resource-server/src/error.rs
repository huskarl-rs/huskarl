use http::StatusCode;

/// RFC 6750 §3.1 error codes for resource server responses.
///
/// `InsufficientScope` is not returned by this library — it is an application-level
/// decision based on the scopes in the validated token. It is included here so
/// callers can use a single type when building `WWW-Authenticate` error responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rfc6750ErrorCode {
    /// The request is malformed. Respond with HTTP 400.
    InvalidRequest,
    /// The access token is invalid, expired, or revoked. Respond with HTTP 401.
    InvalidToken,
    /// The token has insufficient scope for the requested resource. Respond with HTTP 403.
    InsufficientScope,
}

impl Rfc6750ErrorCode {
    /// The error code string as defined in RFC 6750 §3.1.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
        }
    }

    /// The suggested HTTP status code per RFC 6750 §3.1.
    pub fn suggested_status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => StatusCode::FORBIDDEN,
        }
    }
}
