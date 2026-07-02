//! Errors for OAuth 2.0 Dynamic Client Registration (RFC 7591 §3.2.2).

use http::{StatusCode, header::InvalidHeaderValue};
use snafu::Snafu;

use crate::core::{Error, ErrorKind};

/// Wraps a [`RegistrationError`] with its error kind.
///
/// Local misuse (a malformed initial access token, an invalid request body, a
/// `jwks`/`jwks_uri` conflict) is [`ErrorKind::Config`]; a server rejection of
/// the request is [`ErrorKind::RequestRejected`] (adjust the metadata and retry
/// without re-authenticating); a malformed server response is
/// [`ErrorKind::Protocol`].
pub(crate) fn registration_error(source: RegistrationError) -> Error {
    let kind = match &source {
        RegistrationError::JwksConflict
        | RegistrationError::Serialize { .. }
        | RegistrationError::AuthHeader { .. } => ErrorKind::Config,
        RegistrationError::InvalidRedirectUri { .. }
        | RegistrationError::InvalidClientMetadata { .. }
        | RegistrationError::InvalidSoftwareStatement { .. }
        | RegistrationError::UnapprovedSoftwareStatement { .. }
        | RegistrationError::ServerError { .. } => ErrorKind::RequestRejected,
        RegistrationError::MissingContentType
        | RegistrationError::UnexpectedContentType { .. }
        | RegistrationError::Deserialize { .. }
        | RegistrationError::BadStatus { .. } => ErrorKind::Protocol,
    };
    Error::new(kind, source)
}

/// Source vocabulary for client registration failures.
///
/// Carried as the source of errors returned by
/// [`ClientRegistration::register`](super::ClientRegistration::register) —
/// match on the [`ErrorKind`] rather than downcasting
/// to this type. Server-supplied error codes are also preserved verbatim on the
/// [`Error`] via [`oauth_error_code`](crate::core::Error::oauth_error_code).
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RegistrationError {
    /// The client metadata set both `jwks` and `jwks_uri` (RFC 7591 §2 forbids
    /// sending both in the same request).
    #[snafu(display("client metadata may not set both jwks and jwks_uri (RFC 7591 §2)"))]
    JwksConflict,

    /// The client metadata could not be serialized to JSON.
    #[snafu(display("failed to serialize client metadata"))]
    Serialize {
        /// The underlying error.
        source: serde_json::Error,
    },

    /// The initial access token could not be set as an `Authorization` header.
    #[snafu(display("initial access token is not a valid HTTP header value"))]
    AuthHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },

    /// The server rejected one or more redirection URIs (`invalid_redirect_uri`).
    #[snafu(display("the authorization server rejected one or more redirect URIs"))]
    InvalidRedirectUri {
        /// The human-readable description from the server, if any.
        description: Option<String>,
    },

    /// The server rejected a client metadata value (`invalid_client_metadata`).
    #[snafu(display("the authorization server rejected the client metadata"))]
    InvalidClientMetadata {
        /// The human-readable description from the server, if any.
        description: Option<String>,
    },

    /// The presented software statement is invalid (`invalid_software_statement`).
    #[snafu(display("the software statement is invalid"))]
    InvalidSoftwareStatement {
        /// The human-readable description from the server, if any.
        description: Option<String>,
    },

    /// The presented software statement is not approved for use by this server
    /// (`unapproved_software_statement`).
    #[snafu(display("the software statement is not approved by the authorization server"))]
    UnapprovedSoftwareStatement {
        /// The human-readable description from the server, if any.
        description: Option<String>,
    },

    /// The server returned a registration error with a code outside the set
    /// defined by RFC 7591 §3.2.2.
    #[snafu(display("the registration request was rejected: {error}"))]
    ServerError {
        /// The raw error code returned by the server.
        error: String,
        /// The human-readable description from the server, if any.
        description: Option<String>,
    },

    /// The registration response is missing the `Content-Type` header.
    ///
    /// Per RFC 7591 §3.2.1, a successful response uses `application/json`.
    #[snafu(display("registration response is missing the Content-Type header"))]
    MissingContentType,

    /// The registration endpoint returned an unexpected `Content-Type`.
    ///
    /// Per RFC 7591 §3.2.1, a successful response uses `application/json`.
    #[snafu(display("registration endpoint returned unexpected Content-Type: {content_type}"))]
    UnexpectedContentType {
        /// The Content-Type value received.
        content_type: String,
    },

    /// The client information response could not be deserialized.
    #[snafu(display("failed to deserialize the client information response"))]
    Deserialize {
        /// The underlying error.
        source: serde_json::Error,
    },

    /// The server returned a non-success status without a recognizable
    /// RFC 7591 error body.
    #[snafu(display("registration endpoint returned HTTP {status}"))]
    BadStatus {
        /// The HTTP status code.
        status: StatusCode,
        /// The raw response body.
        body: Vec<u8>,
    },
}
