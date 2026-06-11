use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use snafu::prelude::*;

use crate::{
    error::{Error, ErrorKind},
    http::{HttpClient, Idempotency},
};

/// Source error for non-2xx responses; the kind-level classification is
/// [`ErrorKind::Protocol`].
#[derive(Debug, Snafu)]
#[snafu(display("bad status: {status}"))]
pub(crate) struct BadStatusError {
    status: StatusCode,
    body: Bytes,
}

pub(crate) async fn get<T: DeserializeOwned>(
    http_client: &dyn HttpClient,
    uri: http::Uri,
    headers: HeaderMap,
) -> Result<T, Error> {
    let (mut parts, ()) = http::Request::new(()).into_parts();
    parts.headers = headers;
    parts.uri = uri;
    let request = http::Request::from_parts(parts, Bytes::new());

    let response = http_client
        .execute(request, Idempotency::Idempotent)
        .await?;

    if response.status.is_success() {
        serde_json::from_slice(&response.body)
            .map_err(|source| Error::new(ErrorKind::Protocol, source))
    } else {
        Err(Error::new(
            ErrorKind::Protocol,
            BadStatusSnafu {
                status: response.status,
                body: response.body,
            }
            .build(),
        ))
    }
}
