use snafu::Snafu;

/// Source vocabulary for authorization-code completion failures.
///
/// Carried as the source of [`ErrorKind::Protocol`](crate::core::ErrorKind::Protocol)
/// errors returned by
/// [`complete`](super::AuthorizationCodeGrant::complete) /
/// [`complete`](super::AuthorizationCodeGrant::complete) — match on
/// the error kind, and read an `OAuthError`'s members off the wrapping
/// [`Error`](crate::core::Error), rather than downcasting to this type.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum CompleteError {
    /// The callback was an OAuth error response (RFC 6749 §4.1.2.1) — e.g.
    /// the user denied access.
    ///
    /// Only a response bound to the flow reaches this variant; an unsolicited
    /// one is [`StateMismatch`](Self::StateMismatch).
    #[snafu(display(
        "Authorization server returned error: {error}{}",
        error_uri.as_ref().map(|uri| format!(" (see {uri})")).unwrap_or_default()
    ))]
    #[non_exhaustive]
    OAuthError {
        /// The `error` field in the `OAuth2` error response.
        error: String,
        /// The `error_description` field in the `OAuth2` error response.
        error_description: Option<String>,
        /// The `error_uri` field in the `OAuth2` error response.
        error_uri: Option<String>,
    },
    /// There was a mismatch between the required and returned issuer values.
    #[snafu(display("Issuer mismatch: original = {}, callback = {}", original, callback))]
    IssuerMismatch {
        /// The required issuer value.
        original: String,
        /// The issuer value returned to the callback.
        callback: String,
    },
    /// There was a mismatch between the required and returned state values.
    #[snafu(display("State mismatch between original request and callback"))]
    StateMismatch,
    /// The authorization server claimed to support issuer identification but no issuer was returned.
    #[snafu(display(
        "Authorization server claims to support issuer identification but no issuer returned."
    ))]
    MissingIssuer,
    /// The token response included an ID token but the grant cannot validate it.
    #[snafu(display(
        "ID token received but the grant cannot validate it; \
         supply `jws_verifier_factory` on the builder"
    ))]
    IdTokenVerifierNotConfigured,
    /// The token response included an ID token but no issuer was configured on the grant.
    #[snafu(display(
        "ID token received but grant has no issuer configured; provide an issuer via server metadata or builder"
    ))]
    IdTokenIssuerNotConfigured,
    /// `openid` was granted but the token response carried no ID token.
    #[snafu(display(
        "openid scope granted but token response contained no ID token (OIDC Core 1.0 §3.1.3.3)"
    ))]
    MissingIdToken,
    /// A JARM response mode was requested but the callback carried plain
    /// parameters — a possible downgrade to an unsigned response.
    #[snafu(display(
        "a JWT-secured authorization response (JARM) was requested but the callback \
         carried plain parameters; refusing the unsigned response"
    ))]
    MissingJarmResponse,
    /// The callback carried a JARM `response` JWT but none was requested.
    #[snafu(display(
        "callback carried a JARM `response` JWT but no JWT-secured response mode was requested"
    ))]
    UnexpectedJarmResponse,
    /// The JARM response JWT failed validation.
    #[snafu(display("JARM response JWT validation failed: {source}"))]
    JarmValidation {
        /// The underlying validation error.
        source: crate::core::jwt::validator::JwtValidationError,
    },
    /// A validated JARM response carried neither an error nor this parameter.
    #[snafu(display("JARM response is missing the `{param}` claim"))]
    JarmMissingParameter {
        /// The missing parameter name.
        param: &'static str,
    },
    /// A JARM response was received but the grant cannot validate it.
    #[snafu(display(
        "JARM response received but the grant cannot validate it; \
         supply `jws_verifier_factory` on the builder"
    ))]
    JarmVerifierNotConfigured,
    /// A JARM response was received but no issuer is configured on the grant.
    #[snafu(display(
        "JARM response received but grant has no issuer configured; \
         provide an issuer via server metadata or builder"
    ))]
    JarmIssuerNotConfigured,
}

/// Source vocabulary for authorization-code start failures.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum StartError {
    /// An OIDC flow was started but the grant cannot validate ID tokens.
    #[snafu(display(
        "OIDC flow started (scope contains `openid`) but no `jws_verifier_factory` was \
         supplied, so the required ID token (OIDC Core 1.0 §3.1.3.3) could never be \
         validated; supply one on the builder, or set `oidc(false)` if `openid` is an \
         ordinary scope on this server"
    ))]
    OidcVerifierNotConfigured,
    /// An OIDC flow was started but the grant has no issuer configured.
    #[snafu(display(
        "OIDC flow started (scope contains `openid`) but the grant has no issuer \
         configured, so the required ID token (OIDC Core 1.0 §3.1.3.3) could never be \
         validated; provide an issuer via server metadata or builder, or `.oidc(false)` \
         if `openid` is an ordinary scope on this server"
    ))]
    OidcIssuerNotConfigured,
}

/// An error parsing authorization-callback parameters into a
/// [`CompleteInput`](super::CompleteInput).
///
/// An OAuth error response is not a parse failure: it parses, and completion
/// surfaces it as [`CompleteError::OAuthError`].
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum ParseCallbackError {
    /// The callback parameters could not be parsed (malformed query, or a
    /// single-valued parameter that appeared more than once — RFC 6749 §3.1).
    #[snafu(display("Failed to parse callback parameters: {source}"))]
    InvalidParameters {
        /// The underlying parse error.
        source: crate::core::oauth_form::Error,
    },
    /// A required parameter was missing from the callback.
    #[snafu(display("Missing required parameter: {param}"))]
    MissingParameter {
        /// The missing parameter name.
        param: &'static str,
    },
}

/// An error that occurs when building an [`AuthorizationCodeGrant`](super::AuthorizationCodeGrant).
///
/// Carried as the source of [`ErrorKind::Config`](crate::core::ErrorKind::Config)
/// errors returned by the grant builder.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum BuildError {
    /// A JWS verifier factory was provided but no verifier platform is available.
    #[snafu(display(
        "jws_verifier_factory was set but no JWS verifier platform is configured; \
         enable the `default-jws-verifier-platform` feature or call \
         `.jws_verifier_platform(...)` on the builder"
    ))]
    MissingJwsVerifierPlatform,
    /// PAR is required but no PAR endpoint is configured.
    #[snafu(display(
        "require_pushed_authorization_requests is set but no \
         pushed_authorization_request_endpoint is configured; supply the endpoint \
         or unset the requirement — proceeding would silently downgrade required \
         PAR (RFC 9126 §5) to a plain authorization request"
    ))]
    RequiredParEndpointMissing,
    /// `oidc(true)` was set but the grant cannot validate ID tokens.
    #[snafu(display(
        "oidc(true) was set but no `jws_verifier_factory` was supplied, \
         so ID tokens could never be validated"
    ))]
    OidcRequiresVerifier,
    /// `oidc(true)` was set but no issuer is configured.
    #[snafu(display(
        "oidc(true) was set but no issuer is configured; \
         provide one via server metadata or builder"
    ))]
    OidcRequiresIssuer,
    /// A JWT-secured response mode was set but the grant cannot validate JARM responses.
    #[snafu(display(
        "a JWT-secured response_mode was set but no `jws_verifier_factory` was \
         supplied, so the JARM responses could never be validated"
    ))]
    JarmRequiresVerifier,
    /// A JWT-secured response mode was set but no issuer is configured.
    #[snafu(display(
        "a JWT-secured response_mode was set but no issuer is configured; \
         provide one via server metadata or builder"
    ))]
    JarmRequiresIssuer,
}
