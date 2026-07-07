//! The [`ValidatedJwt`] output of a successful validation.

use bon::Builder;

use crate::{jwt::ConfirmationClaim, platform::SystemTime};

/// A JWT that passed [`JwtValidator::validate`](super::JwtValidator::validate): its registered claims plus the
/// deserialized custom `Claims`.
///
/// Produced only by the validator. Transform the custom claims payload with
/// [`map_claims`](Self::map_claims) or [`try_map_claims`](Self::try_map_claims).
#[non_exhaustive]
#[allow(clippy::should_implement_trait)] // `sub` is the JWT claim name, not arithmetic subtraction
#[derive(Debug, Builder)]
pub struct ValidatedJwt<Claims> {
    /// The `iss` (issuer) claim of the JWT, if present.
    pub iss: Option<String>,
    /// The `sub` (subject) claim of the JWT, if present.
    pub sub: Option<String>,
    /// The `aud` (audience) claim of the JWT; empty if absent.
    pub aud: Vec<String>,
    /// The JWT ID, if present.
    pub jti: Option<String>,
    /// The `iat` (issued-at) timestamp of the JWT, if present.
    pub iat: Option<SystemTime>,
    /// The `exp` (expiration) timestamp of the JWT, if present.
    pub exp: Option<SystemTime>,
    /// The key confirmation claim (`cnf`), if present; see [`ConfirmationClaim`]
    /// for what it binds the token to.
    pub cnf: Option<ConfirmationClaim>,
    /// Additional claims beyond the registered JWT claim set.
    pub claims: Claims,
}

impl<Claims> ValidatedJwt<Claims> {
    /// Maps the claims of the JWT using the provided function.
    pub fn map_claims<C1, F>(self, f: F) -> ValidatedJwt<C1>
    where
        F: FnOnce(Claims) -> C1,
    {
        ValidatedJwt {
            iss: self.iss,
            sub: self.sub,
            aud: self.aud,
            jti: self.jti,
            iat: self.iat,
            exp: self.exp,
            cnf: self.cnf,
            claims: f(self.claims),
        }
    }

    /// Maps the claims of the JWT using a fallible function.
    ///
    /// # Errors
    ///
    /// Returns the error of the mapper, if it fails.
    pub fn try_map_claims<C1, E, F>(self, f: F) -> Result<ValidatedJwt<C1>, E>
    where
        F: FnOnce(Claims) -> Result<C1, E>,
    {
        Ok(ValidatedJwt {
            iss: self.iss,
            sub: self.sub,
            aud: self.aud,
            jti: self.jti,
            iat: self.iat,
            exp: self.exp,
            cnf: self.cnf,
            claims: f(self.claims)?,
        })
    }
}
