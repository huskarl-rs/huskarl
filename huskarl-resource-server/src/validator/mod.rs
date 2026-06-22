//! Access token validation: the [`AccessTokenValidator`] trait and ready-made
//! implementations of it.
//!
//! A validator turns an incoming request's headers into a [`ValidatedRequest`]
//! (or a typed rejection). Pick the one matching how your tokens are verified:
//! [`rfc9068::Rfc9068Validator`] for self-contained RFC 9068 JWT access tokens,
//! [`introspection::IntrospectionValidator`] for RFC 7662 introspection, or
//! [`custom::CustomValidator`] for an authorization server that follows neither.

mod binding;
mod common;
pub mod custom;
pub mod dpop_nonce;
pub mod dpop_proof;
pub mod error;
pub mod extract;
pub mod introspection;
pub mod metadata;
pub mod observe;
pub mod rfc9068;

use crate::{
    core::{
        jwt::{ConfirmationClaim, validator::ValidatedJwt},
        platform::{MaybeSend, MaybeSendSync, SystemTime},
    },
    error::ToRfc6750Error,
};

/// A trait for validators that authenticate and validate access tokens from HTTP requests.
///
/// Implementations handle token extraction from request headers, JWT validation,
/// and sender-constraint binding checks (`DPoP`, mTLS).
///
/// The `outcome` field of [`ValidationResult`] is `Ok(None)` when no authentication header is
/// present (unauthenticated request), `Ok(Some(_))` when a valid token is found, and `Err(_)`
/// when a token is present but invalid.
pub trait AccessTokenValidator: MaybeSendSync {
    /// The application-specific claims type extracted from the token.
    type Claims: MaybeSendSync;
    /// The error type returned when validation fails.
    type Error: ToRfc6750Error;

    /// Validates an access token from the given HTTP request headers.
    fn validate_request(
        &self,
        headers: &http::HeaderMap,
        method: &http::Method,
        uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> impl Future<Output = ValidationResult<Self::Claims, Self::Error>> + MaybeSend;
}

/// The result of an [`AccessTokenValidator::validate_request`] call.
#[derive(Debug)]
pub struct ValidationResult<C, E> {
    /// The outcome of the validation.
    pub outcome: Result<Option<ValidatedRequest<C>>, E>,
    /// A `DPoP` nonce to include in the response `DPoP-Nonce` header, if any.
    pub dpop_nonce: Option<String>,
}

/// A validated access token request, containing the parsed claims and other metadata.
///
/// Returned by [`super::AccessTokenValidator::validate_request`].
#[derive(Debug)]
pub struct ValidatedRequest<Claims> {
    /// The issuer of the token, if present.
    pub issuer: Option<String>,
    /// The subject of the token, if present.
    pub subject: Option<String>,
    /// The audience of the token.
    pub audience: Vec<String>,
    /// The token ID, if present.
    pub jti: Option<String>,
    /// The issued-at timestamp, if present.
    pub issued_at: Option<SystemTime>,
    /// The expiration timestamp, if present.
    pub expiration: Option<SystemTime>,
    /// The key confirmation claim (`cnf`, RFC 7800), if present.
    ///
    /// Binds the token to a `DPoP` key (`jkt`, RFC 9449) or mTLS certificate
    /// (`x5t#S256`, RFC 8705).
    pub cnf: Option<ConfirmationClaim>,
    /// Additional claims beyond the registered token claim set.
    ///
    /// Format-specific and extension claims (e.g. RFC 9068 `client_id` and the
    /// RFC 9396 `authorization_details`) live here, in the typed claims type —
    /// not as fields on this struct, which carries only the universal token set.
    pub claims: Claims,
    /// Raw introspection JWT (RFC 9701), if the authorization server returned one.
    ///
    /// Populated only when using [`crate::validator::introspection::IntrospectionValidator`] and the
    /// AS responded with `application/token-introspection+jwt`. Useful for forwarding to
    /// downstream services.
    pub introspection_jwt: Option<String>,
}

impl<C> From<ValidatedJwt<C>> for ValidatedRequest<C> {
    fn from(jwt: ValidatedJwt<C>) -> Self {
        Self {
            issuer: jwt.issuer,
            subject: jwt.subject,
            audience: jwt.audience,
            jti: jwt.jti,
            issued_at: jwt.issued_at,
            expiration: jwt.expiration,
            cnf: jwt.cnf,
            claims: jwt.claims,
            introspection_jwt: None,
        }
    }
}
