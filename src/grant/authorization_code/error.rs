use snafu::Snafu;

use crate::grant::core::form::OAuth2FormError;

/// An error that occurs when attempting to start an authorization code flow.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum StartError<
    AuthErr: crate::Error + 'static,
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
    JarErr: crate::Error + 'static,
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
#[derive(Debug, Clone, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum CompleteError<GrantErr: crate::Error + 'static> {
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
}

impl<GrantErr: crate::Error + 'static> crate::Error for CompleteError<GrantErr> {
    fn is_retryable(&self) -> bool {
        match self {
            CompleteError::Grant { source } => source.is_retryable(),
            CompleteError::IssuerMismatch { .. }
            | CompleteError::StateMismatch { .. }
            | CompleteError::MissingIssuer => false,
        }
    }
}
