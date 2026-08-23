//! Internal token validation error types.

use http::header::ToStrError;
use snafu::prelude::*;
use strum::EnumMessage as _;

use crate::{
    TokenType,
    core::jwt::validator::JwtValidationError,
    error::{Challenge, ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{
        binding::{DPoPBindingError, MtlsBindingError},
        extract::TokenExtractError,
        observe::ValidationOutcome,
    },
};

/// Errors produced while dispatching token sender-constraint checks.
///
/// Header syntax failures produce `invalid_request`; token binding failures
/// produce `invalid_token` or the classification supplied by the underlying
/// `DPoP` or mTLS error.
// `#[strum(message)]` on each variant carries the client-facing RFC 6750
// `error_description`; the `#[snafu(display)]` is the operator-facing `Display`.
// The client description is a sentence; `Display` is a source-chain fragment.
// Variants that delegate to a source have no `strum` message.
#[derive(Debug, Snafu, strum::EnumMessage)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum TokenBindingError {
    /// The `DPoP` header is required but missing from the request.
    #[snafu(display("the request has no DPoP header"))]
    #[strum(message = "The DPoP header is missing")]
    MissingDPoPHeader,
    /// The `DPoP` header is present but is not valid UTF-8.
    #[snafu(display("the DPoP header value is not valid UTF-8"))]
    #[strum(message = "The DPoP header value is invalid")]
    DPoPHeaderNotString {
        /// The underlying string conversion error.
        source: ToStrError,
    },
    /// More than one `DPoP` header was present (RFC 9449 §4.3 requires exactly one).
    #[snafu(display("request has more than one DPoP header"))]
    #[strum(message = "The request has more than one DPoP header")]
    MultipleDPoPHeaders,
    /// The token has a `DPoP` key binding (`cnf.jkt`) but was presented as a Bearer token.
    ///
    /// Per RFC 9449 §7.1, DPoP-bound tokens MUST be presented using the `DPoP`
    /// token type, not `Bearer`. Accepting a bound token as Bearer would allow an
    /// attacker who stole the token to use it without possessing the private key.
    #[snafu(display("token is DPoP-bound but was presented as Bearer"))]
    #[strum(message = "The access token is DPoP-bound")]
    DPoPRequiredForBoundToken,
    /// `DPoP` is required by this resource server but the token was presented as Bearer.
    #[snafu(display("DPoP-bound tokens are required"))]
    #[strum(message = "DPoP is required to access this resource")]
    DPoPRequired,
    /// The token `cnf` claim contains a confirmation method that is not supported.
    /// Only `jkt` (`DPoP`) and `x5t#S256` (mTLS) are checked; `jwe` and `jku` are rejected
    /// rather than silently ignored, per RFC 7800's requirement that applications ensure
    /// confirmation members they require are understood and processed.
    #[snafu(display("unsupported cnf confirmation method: {method}"))]
    #[strum(message = "The access token confirmation method is not supported")]
    UnsupportedCnfMethod {
        /// The name of the unsupported confirmation method.
        method: &'static str,
    },
    /// The `DPoP` binding is invalid.
    #[snafu(display("checking the DPoP binding"))]
    DPoPBinding {
        /// The underlying `DPoP` binding error.
        source: DPoPBindingError,
    },
    /// The mTLS binding is invalid.
    #[snafu(display("checking the mTLS binding"))]
    MtlsBinding {
        /// The underlying mTLS binding error.
        source: MtlsBindingError,
    },
}

impl ToRfc6750Error for TokenBindingError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::MissingDPoPHeader
            | Self::DPoPHeaderNotString { .. }
            | Self::MultipleDPoPHeaders
            | Self::DPoPBinding { .. } => Some(TokenType::DPoP),
            Self::DPoPRequiredForBoundToken
            | Self::DPoPRequired
            | Self::UnsupportedCnfMethod { .. }
            | Self::MtlsBinding { .. } => None,
        }
    }

    fn challenge(&self) -> Challenge {
        match self {
            Self::DPoPBinding { source } => source.challenge(),
            Self::MtlsBinding { source } => source.challenge(),
            other => {
                let code = match other {
                    Self::MissingDPoPHeader
                    | Self::DPoPHeaderNotString { .. }
                    | Self::MultipleDPoPHeaders => TokenErrorCode::InvalidRequest,
                    _ => TokenErrorCode::InvalidToken,
                };
                let challenge = Challenge::new(TokenValidationError::Client(code));
                match other.get_message() {
                    Some(message) => challenge.with_description(message),
                    None => challenge,
                }
            }
        }
    }
}

/// Errors produced while validating a JWT access token from request headers.
///
/// Each variant preserves the underlying challenge. The recorded token type
/// selects which supported authentication scheme receives client error details.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum ValidateHeadersError {
    /// The access token could not be extracted from the request headers.
    #[snafu(display("token presentation error"))]
    Extract {
        /// The underlying extraction error.
        source: TokenExtractError,
    },
    /// The token sender-constraint binding check failed.
    #[snafu(display("token binding error"))]
    Binding {
        /// The token type that was presented, used to select the challenge that
        /// receives error details.
        token_type: TokenType,
        /// The underlying binding error.
        source: TokenBindingError,
    },
    /// The token is not a valid JWT.
    #[snafu(display("validating the access token as a JWT"))]
    InvalidJwt {
        /// The token type that was presented, used to select the challenge that
        /// receives error details.
        token_type: TokenType,
        /// The underlying JWT validation error.
        source: JwtValidationError,
    },
}

impl ToRfc6750Error for ValidateHeadersError {
    fn challenge(&self) -> Challenge {
        match self {
            Self::Extract { source } => source.challenge(),
            Self::Binding { source, .. } => source.challenge(),
            Self::InvalidJwt { source, .. } => source.challenge(),
        }
    }

    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Binding { token_type, .. } | Self::InvalidJwt { token_type, .. } => {
                Some(*token_type)
            }
        }
    }

    fn validation_outcome(&self, challenge: &Challenge) -> ValidationOutcome {
        match challenge.error {
            // Metrics must agree with the wire: a 5xx (e.g. replay store or
            // nonce checker down) is our failure, whichever check tripped it,
            // and a nonce challenge is routine churn, not a binding failure.
            TokenValidationError::Server { .. } => return ValidationOutcome::CallError,
            TokenValidationError::Client(TokenErrorCode::UseDPoPNonce) => {
                return ValidationOutcome::NonceRequired;
            }
            TokenValidationError::Client(_) => {}
        }
        match self {
            Self::Extract { .. } => ValidationOutcome::ExtractError,
            Self::Binding { .. } => ValidationOutcome::BindingError,
            Self::InvalidJwt {
                source: JwtValidationError::Expired { .. },
                ..
            } => ValidationOutcome::Expired,
            Self::InvalidJwt { .. } => ValidationOutcome::InvalidToken,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::binding::{DPoPBindingError, MtlsBindingError};

    crate::forwarding_table! {
        /// Binding wrappers preserve every challenge attribute.
        token_binding_error_forwards {
            || MtlsBindingError::CertBoundTokenWithoutCert
                => |source| TokenBindingError::MtlsBinding { source },
            || DPoPBindingError::ThumbprintMismatch
                => |source| TokenBindingError::DPoPBinding { source },
        }
    }

    crate::forwarding_table! {
        /// The outer wrapper preserves each kind of inner challenge.
        validate_headers_error_forwards {
            || TokenExtractError::InvalidTokenHeaderFormat
                => |source| ValidateHeadersError::Extract { source },
            || TokenBindingError::MtlsBinding {
                source: MtlsBindingError::CertBoundTokenWithoutCert,
            } => |source| ValidateHeadersError::Binding {
                token_type: TokenType::Bearer,
                source,
            },
            || JwtValidationError::UnsignedToken
                => |source| ValidateHeadersError::InvalidJwt {
                    token_type: TokenType::Bearer,
                    source,
                },
        }
    }

    // Wrappers retain their own presentation and validation-stage context.
    #[test]
    fn a_wrapper_keeps_the_members_that_are_its_own() {
        let inner = JwtValidationError::UnsignedToken;
        let wrapped = ValidateHeadersError::InvalidJwt {
            token_type: TokenType::DPoP,
            source: JwtValidationError::UnsignedToken,
        };

        // The leaf has no idea how the token was presented; the wrapper does.
        assert_eq!(inner.attempted_scheme(), None);
        assert_eq!(wrapped.attempted_scheme(), Some(TokenType::DPoP));

        // And which stage failed is the wrapper's to report.
        let challenge = wrapped.challenge();
        assert_eq!(
            wrapped.validation_outcome(&challenge),
            ValidationOutcome::InvalidToken
        );
        let extract = ValidateHeadersError::Extract {
            source: TokenExtractError::InvalidTokenHeaderFormat,
        };
        let challenge = extract.challenge();
        assert_eq!(
            extract.validation_outcome(&challenge),
            ValidationOutcome::ExtractError,
        );
    }
}
