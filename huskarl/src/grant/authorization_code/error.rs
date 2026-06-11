use snafu::Snafu;

/// Source vocabulary for authorization-code completion failures.
///
/// Carried as the source of [`ErrorKind::Protocol`](crate::core::ErrorKind::Protocol)
/// errors returned by
/// [`complete`](super::AuthorizationCodeGrant::complete) /
/// [`complete_oidc`](super::AuthorizationCodeGrant::complete_oidc) — match on
/// the error kind rather than downcasting to this type.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum CompleteError {
    /// There was a mismatch between the required and returned issuer values.
    #[snafu(display("Issuer mismatch: original = {}, callback = {}", original, callback))]
    IssuerMismatch {
        /// The required issuer value.
        original: String,
        /// The issuer value returned to the callback.
        callback: String,
    },
    /// There was a mismatch between the required and returned state values.
    #[snafu(display("State mismatch: original = {}, callback = {}", original, callback))]
    StateMismatch {
        /// The required state value.
        original: String,
        /// The state value returned to the callback.
        callback: String,
    },
    /// The authorization server claimed to support issuer identification but no issuer was returned.
    #[snafu(display(
        "Authorization server claims to support issuer identification but no issuer returned."
    ))]
    MissingIssuer,
    /// The token response included an ID token but no JWS verifier was configured on the grant.
    #[snafu(display(
        "ID token received but grant has no JWS verifier configured; \
         call `.jws_verifier_factory(...)` on the builder to enable ID token validation"
    ))]
    IdTokenVerifierNotConfigured,
    /// The token response included an ID token but no issuer was configured on the grant.
    #[snafu(display(
        "ID token received but grant has no issuer configured; provide an issuer via server metadata or builder"
    ))]
    IdTokenIssuerNotConfigured,
}

/// An error that occurs when building an [`AuthorizationCodeGrant`](super::AuthorizationCodeGrant).
///
/// Carried as the source of [`ErrorKind::Config`](crate::core::ErrorKind::Config)
/// errors returned by the grant builder.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum BuildError {
    /// A JWS verifier factory was provided but no verifier platform is available.
    #[snafu(display(
        "jws_verifier_factory was set but no JWS verifier platform is configured; \
         enable the `default-jws-verifier-platform` feature or call \
         `.jws_verifier_platform(...)` on the builder"
    ))]
    MissingJwsVerifierPlatform,
}
