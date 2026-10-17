use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header::ACCEPT};
use serde::de::DeserializeOwned;
use snafu::prelude::*;

use crate::{
    error::Error,
    http::{FailedResponse, HttpClient, Idempotency, TruncatedBody},
};

/// A non-success response from a document endpoint.
#[derive(Debug, Snafu)]
#[snafu(display("bad status {status}: {body}"))]
pub(crate) struct BadStatusError {
    status: StatusCode,
    /// A bounded prefix of the response body for diagnostics.
    body: TruncatedBody,
}

/// A response body that could not be parsed as the expected document.
#[derive(Debug, Snafu)]
#[snafu(display("parsing the JSON document from {uri}"))]
pub(crate) struct MalformedDocumentError {
    uri: String,
    source: serde_json::Error,
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(name = "huskarl.http.document", level = "debug", skip_all, fields(document = document.as_str()))
)]
pub(crate) async fn get<T: DeserializeOwned>(
    http_client: &dyn HttpClient,
    uri: http::Uri,
    mut headers: HeaderMap,
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))] document: DocumentKind,
) -> Result<T, Error> {
    headers
        .entry(ACCEPT)
        .or_insert(HeaderValue::from_static("application/json"));
    let (mut parts, ()) = http::Request::new(()).into_parts();
    parts.headers = headers;
    // Retain the URI for parse errors. Cloning it only increments a refcount.
    parts.uri = uri.clone();
    let request = http::Request::from_parts(parts, Bytes::new());

    #[cfg(feature = "tracing")]
    tracing::trace!(method = "GET", "Fetching JSON document");
    let response = http_client
        .execute(request, Idempotency::Idempotent)
        .await
        .inspect_err(|_| {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                outcome = "transport_error",
                "Document request failed before a response was received"
            );
        })?;

    #[cfg(feature = "tracing")]
    if response.status.is_success() {
        tracing::trace!(
            status = response.status.as_u16(),
            "Received document response"
        );
    } else {
        tracing::debug!(
            status = response.status.as_u16(),
            "Received document response"
        );
    }

    // Document fetches are idempotent, so transient failures may be retried.
    let Some(failed) = FailedResponse::new(response.status, &response.headers) else {
        // Format the URI only if parsing fails.
        return Ok(serde_json::from_slice(&response.body).with_context(|_| {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                outcome = "malformed_document",
                "Document response was not valid for the expected schema"
            );
            MalformedDocumentSnafu {
                uri: uri.to_string(),
            }
        })?);
    };

    // Document endpoints do not return OAuth verdicts.
    Err(failed.into_error(
        None,
        BadStatusSnafu {
            status: response.status,
            body: TruncatedBody::from_bytes(&response.body),
        }
        .build(),
    ))
}

// This single-shape cause always establishes the same classification.
impl crate::error::propagation::Cause for MalformedDocumentError {
    fn origin(&self) -> crate::error::propagation::Origin<'_> {
        crate::error::propagation::Origin::Establishes(crate::error::RetryAdvice::No.into())
    }
}

impl From<MalformedDocumentError> for Error {
    #[track_caller]
    fn from(source: MalformedDocumentError) -> Self {
        Self::from_cause(source)
    }
}

/// The role of a fetched document, independent of its potentially sensitive URI.
pub(crate) enum DocumentKind {
    AuthorizationServerMetadata,
    ResourceMetadata,
    Jwks,
}

impl DocumentKind {
    #[cfg(feature = "tracing")]
    fn as_str(&self) -> &'static str {
        match self {
            Self::AuthorizationServerMetadata => "authorization_server_metadata",
            Self::ResourceMetadata => "resource_metadata",
            Self::Jwks => "jwks",
        }
    }
}
