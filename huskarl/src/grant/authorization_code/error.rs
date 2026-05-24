use snafu::Snafu;

use crate::{
    grant::core::form::{DPoPNonceError, OAuth2FormError},
    token::id_token::IdTokenValidationError,
};

/// An error that occurs when attempting to start an authorization code flow.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum StartError<
    AuthErr: crate::core::Error + 'static,
    HttpErr: crate::core::Error + 'static,
    HttpRespErr: crate::core::Error + 'static,
    DPoPErr: crate::core::Error + 'static,
    JarErr: crate::core::Error + 'static,
> {
    /// An error occurred when attempting to encode the parameters in `x-www-form-urlencoded` format.
    #[snafu(display("Encoding of the request parameters failed"))]
    EncodeUrlEncoded {
        /// The underlying error.
        source: serde_html_form::ser::Error,
    },
    /// An error occurred when attempting to make a PAR request.
    #[snafu(display("Failed to make PAR request"))]
    ParRequest {
        /// The underlying error.
        source: OAuth2FormError<HttpErr, HttpRespErr, DPoPErr>,
    },
    /// An error occurred when creating the JAR request.
    #[snafu(display("Failed to create JAR (JWT-secured authorization request)"))]
    Jar {
        /// The underlying error.
        source: JarErr,
    },
    /// An error occurred when calculating the client authentication parameters.
    #[snafu(display("Failed to get client authentication parameters"))]
    ClientAuth {
        /// The underlying error.
        source: AuthErr,
    },
}

/// Errors that occur while attempting to complete the flow.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum CompleteError<GrantErr: crate::core::Error + 'static> {
    /// An error occurred when making the token call.
    #[snafu(display("Failed to make token call"))]
    Grant {
        /// The underlying error.
        source: GrantErr,
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
    /// ID token validation failed.
    #[snafu(display("ID token validation failed"))]
    IdTokenValidation {
        /// The underlying validation error.
        source: IdTokenValidationError,
    },
}

impl<
    AuthErr: crate::core::Error + 'static,
    HttpErr: crate::core::Error + 'static,
    HttpRespErr: crate::core::Error + 'static,
    DPoPErr: crate::core::Error + 'static,
    JarErr: crate::core::Error + 'static,
> DPoPNonceError for StartError<AuthErr, HttpErr, HttpRespErr, DPoPErr, JarErr>
{
    fn is_dpop_nonce_required(&self) -> bool {
        matches!(self, Self::ParRequest { source } if source.is_dpop_nonce_required())
    }
}

impl<
    AuthErr: crate::core::Error + 'static,
    HttpErr: crate::core::Error + 'static,
    HttpRespErr: crate::core::Error + 'static,
    DPoPErr: crate::core::Error + 'static,
    JarErr: crate::core::Error + 'static,
> crate::core::Error for StartError<AuthErr, HttpErr, HttpRespErr, DPoPErr, JarErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            StartError::EncodeUrlEncoded { .. } => false,
            StartError::ParRequest { source } => source.is_retryable(),
            StartError::Jar { source } => source.is_retryable(),
            StartError::ClientAuth { source } => source.is_retryable(),
        }
    }
}

/// An error that occurs when building an [`AuthorizationCodeGrant`](super::AuthorizationCodeGrant).
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

impl crate::core::Error for BuildError {
    fn is_retryable(&self) -> bool {
        false
    }
}

impl<GrantErr: crate::core::Error + 'static> crate::core::Error for CompleteError<GrantErr> {
    fn is_retryable(&self) -> bool {
        match self {
            CompleteError::Grant { source } => source.is_retryable(),
            CompleteError::IssuerMismatch { .. }
            | CompleteError::StateMismatch { .. }
            | CompleteError::MissingIssuer
            | CompleteError::IdTokenVerifierNotConfigured
            | CompleteError::IdTokenIssuerNotConfigured
            | CompleteError::IdTokenValidation { .. } => false,
        }
    }
}
