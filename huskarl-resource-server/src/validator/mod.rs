mod binding;
mod common;
pub mod custom;
pub mod error;
pub mod extract;
pub mod introspection;
pub mod metadata;
pub mod observe;
pub mod rfc9068;

pub use observe::{OnValidate, ValidationOutcome};

use huskarl_core::{
    jwt::ConfirmationClaim, jwt::validator::ValidatedJwt, platform::MaybeSend,
    platform::MaybeSendSync, platform::SystemTime,
};

use crate::error::ToRfc6750Error;

/// A trait for validators that authenticate and validate access tokens from HTTP requests.
///
/// Implementations handle token extraction from request headers, JWT validation,
/// and sender-constraint binding checks (DPoP, mTLS).
///
/// Returns `Ok(None)` when no authentication header is present (unauthenticated request),
/// `Ok(Some(_))` when a valid token is found, and `Err(_)` when a token is present but invalid.
pub trait AccessTokenValidator: MaybeSendSync {
    type Claims: MaybeSendSync;
    type Error: ToRfc6750Error;

    fn validate_request(
        &self,
        headers: &http::HeaderMap,
        method: &http::Method,
        uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> impl Future<Output = Result<Option<ValidatedRequest<Self::Claims>>, Self::Error>> + MaybeSend;
}

/// A validated access token request, containing the parsed claims and other metadata.
///
/// Returned by [`super::AccessTokenValidator::validate_request`].
#[derive(Debug)]
pub struct ValidatedRequest<C> {
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
    /// Binds the token to a DPoP key (`jkt`, RFC 9449) or mTLS certificate
    /// (`x5t#S256`, RFC 8705).
    pub cnf: Option<ConfirmationClaim>,
    /// The claims of the token, if present.
    pub claims: Option<C>,
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
