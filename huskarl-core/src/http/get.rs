use bytes::Bytes;
use http::{HeaderMap, StatusCode};
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

pub(crate) async fn get<T: DeserializeOwned>(
    http_client: &dyn HttpClient,
    uri: http::Uri,
    headers: HeaderMap,
) -> Result<T, Error> {
    let (mut parts, ()) = http::Request::new(()).into_parts();
    parts.headers = headers;
    // Retain the URI for parse errors. Cloning it only increments a refcount.
    parts.uri = uri.clone();
    let request = http::Request::from_parts(parts, Bytes::new());

    let response = http_client
        .execute(request, Idempotency::Idempotent)
        .await?;

    // Document fetches are idempotent, so transient failures may be retried.
    let Some(failed) = FailedResponse::new(response.status, &response.headers) else {
        // Format the URI only if parsing fails.
        return Ok(serde_json::from_slice(&response.body).with_context(|_| {
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
