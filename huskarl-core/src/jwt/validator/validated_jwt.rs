//! The [`ValidatedJwt`] output of a successful validation.

use bon::Builder;

use crate::{jwt::ConfirmationClaim, platform::SystemTime};

/// A JWT that passed [`JwtValidator::validate`](super::JwtValidator::validate): its registered claims plus the
/// deserialized custom `Claims`.
///
/// Produced only by the validator. Transform the custom claims payload with
/// [`map_claims`](Self::map_claims) or [`try_map_claims`](Self::try_map_claims).
#[non_exhaustive]
#[derive(Debug, Builder)]
pub struct ValidatedJwt<Claims> {
    /// The issuer of the JWT, if present.
    pub issuer: Option<String>,
    /// The subject of the JWT, if present.
    pub subject: Option<String>,
    /// The audience of the JWT, if present.
    pub audience: Vec<String>,
    /// The JWT ID, if present.
    pub jti: Option<String>,
    /// The issued-at timestamp of the JWT, if present.
    pub issued_at: Option<SystemTime>,
    /// The expiration timestamp of the JWT, if present.
    pub expiration: Option<SystemTime>,
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
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            jti: self.jti,
            issued_at: self.issued_at,
            expiration: self.expiration,
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
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            jti: self.jti,
            issued_at: self.issued_at,
            expiration: self.expiration,
            cnf: self.cnf,
            claims: f(self.claims)?,
        })
    }
}
