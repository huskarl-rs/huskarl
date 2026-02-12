use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use snafu::prelude::*;

use crate::http::{HttpClient, HttpResponse};

#[derive(Debug, Snafu)]
pub enum GetError<HttpReqErr: crate::Error + 'static, HttpRespErr: crate::Error + 'static> {
    Request { source: HttpReqErr },
    Response { source: HttpRespErr },
    Deserialize { source: serde_json::Error },
    BadStatus { status: StatusCode, body: Bytes },
}

pub(crate) async fn get<C: HttpClient, T: DeserializeOwned>(
    http_client: &C,
    uri: http::Uri,
    headers: HeaderMap,
) -> Result<T, GetError<C::Error, <C::Response as HttpResponse>::Error>> {
    let (mut parts, ()) = http::Request::new(()).into_parts();
    parts.headers = headers;
    parts.uri = uri;
    let request = http::Request::from_parts(parts, Bytes::new());

    let response = http_client.execute(request).await.context(RequestSnafu)?;
    let status = response.status();
    let body = response.body().await.context(ResponseSnafu)?;

    if status.is_success() {
        Ok(serde_json::from_slice(&body).context(DeserializeSnafu)?)
    } else {
        BadStatusSnafu { status, body }.fail()
    }
}
