use bon::Builder;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Uri, header::CONTENT_TYPE};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use crate::{
    client_auth::AuthenticationParams,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    http::{HttpClient, HttpResponse},
};

#[derive(Debug, Builder)]
#[builder(state_mod(name = builder))]
pub struct OAuth2FormRequest<'a, F: Serialize, D: AuthorizationServerDPoP = NoDPoP> {
    uri: Uri,
    form: &'a F,
    auth_params: AuthenticationParams<'a>,
    dpop: Option<&'a D>,
}

impl<F: Serialize, D: AuthorizationServerDPoP> OAuth2FormRequest<'_, F, D> {
    pub async fn build_request(
        &self,
    ) -> Result<Request<Bytes>, SerializeOAuth2FormError<D::Error>> {
        let headers = self
            .auth_params
            .headers
            .as_ref()
            .map(|h| h.clone())
            .unwrap_or_default();

        let mut body = serde_html_form::to_string(self.form).context(SerializeFormSnafu)?;

        if let Some(kv) = &self.auth_params.form_params
            && !body.is_empty()
        {
            body.push('&');

            serde_html_form::push_to_string(&mut body, kv).context(SerializeFormSnafu)?;
        }

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.method = Method::POST;
        parts.uri = self.uri.clone();

        if let Some(dpop) = self.dpop
            && let Some(proof) = dpop
                .proof(&parts.method, &parts.uri)
                .await
                .context(DPoPSignSnafu)?
        {
            parts.headers.insert(
                "DPoP",
                HeaderValue::from_str(proof.expose_secret()).context(BadHeaderSnafu)?,
            );
        }

        parts.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        parts.headers.extend(headers);

        Ok(Request::from_parts(parts, body.into()))
    }

    pub async fn execute_once<C: HttpClient, R: for<'de> Deserialize<'de>>(
        &self,
        http_client: &C,
        updated_nonce: &mut bool,
    ) -> Result<R, OAuth2FormError<C::Error, <C::Response as HttpResponse>::Error, D::Error>> {
        let request = self.build_request().await.context(SerializeSnafu)?;
        let response = http_client.execute(request).await.context(RequestSnafu)?;
        let status = response.status();
        let content_type = if status.is_success() {
            None
        } else {
            response.headers().get(CONTENT_TYPE).cloned()
        };

        if let Some(nonce) = response.headers().get("DPoP-Nonce")
            && let Ok(nonce_str) = nonce.to_str()
        {
            if let Some(d) = self.dpop {
                d.update_nonce(nonce_str.to_string())
            }
            *updated_nonce = true;
        }

        let body = response.body().await.context(ResponseBodyReadSnafu)?;

        let parsed_response =
            parse_oauth2_response(status, content_type, &body).context(ResponseSnafu)?;

        Ok(parsed_response)
    }

    pub async fn execute<C: HttpClient, R: for<'de> Deserialize<'de>>(
        &self,
        http_client: &C,
    ) -> Result<R, OAuth2FormError<C::Error, <C::Response as HttpResponse>::Error, D::Error>> {
        let mut updated_nonce = false;

        let response_or_error = self.execute_once(http_client, &mut updated_nonce).await;

        if updated_nonce
            && let Err(OAuth2FormError::Response {
                source:
                    HandleResponseError::OAuth2 {
                        body: OAuth2ErrorBody { error, .. },
                        ..
                    },
            }) = &response_or_error
            && error == "use_dpop_nonce"
        {
            return self.execute_once(http_client, &mut updated_nonce).await;
        }

        response_or_error
    }
}

fn parse_oauth2_response<T: for<'de> Deserialize<'de>>(
    status: http::StatusCode,
    content_type: Option<HeaderValue>,
    body: &Bytes,
) -> Result<T, HandleResponseError> {
    if !status.is_success() {
        // Attempt to parse the body as a standard OAuth 2.0 error response.
        let error_body = serde_json::from_slice::<OAuth2ErrorBody>(body).context(
            UnparseableErrorResponseSnafu {
                status,
                content_type: content_type.clone(),
                body: String::from_utf8_lossy(body),
            },
        )?;

        return OAuth2Snafu {
            body: error_body,
            status,
            content_type,
        }
        .fail();
    }

    serde_json::from_slice(body).context(UnparseableSuccessResponseSnafu {
        body: String::from_utf8_lossy(body),
    })
}

/// Errors that can occur when attempting to get a token using `OAuth2`.
#[derive(Debug, Snafu)]
pub enum OAuth2FormError<HttpReqErr: crate::Error, HttpRespErr: crate::Error, DPoPErr: crate::Error>
{
    /// There was an error when attempting to serialize the form.
    Serialize {
        /// The underlying serialization error.
        source: SerializeOAuth2FormError<DPoPErr>,
    },
    /// There was an error when reading the response body.
    #[snafu(display("Failed to read response body"))]
    ResponseBodyRead {
        /// The underlying error when reading the respone body.
        source: HttpRespErr,
    },
    /// An error occurred when making the HTTP request.
    #[snafu(display("Failed to make HTTP request"))]
    Request {
        /// An error when handling the response.
        source: HttpReqErr,
    },
    /// An error occurred when parsing the HTTP response.
    Response {
        /// An error when handling the response.
        source: HandleResponseError,
    },
}

impl<HttpReqErr: crate::Error, HttpRespErr: crate::Error, DPoPErr: crate::Error> crate::Error
    for OAuth2FormError<HttpReqErr, HttpRespErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::Serialize { source } => source.is_retryable(),
            Self::Request { source } => source.is_retryable(),
            Self::Response { source } => source.is_retryable(),
            Self::ResponseBodyRead { source } => source.is_retryable(),
        }
    }
}

#[derive(Debug, Snafu)]
pub enum SerializeOAuth2FormError<DPoPErr: crate::Error> {
    /// There was an error when attempting to serialize the form parameters.
    #[snafu(display("Failed to serialize exchange parameters"))]
    SerializeForm {
        /// The underlying error.
        source: serde_html_form::ser::Error,
    },
    /// The provided header value was invalid.
    #[snafu(display("Provided header value was invalid"))]
    BadHeader {
        /// The underlying error.
        source: http::header::InvalidHeaderValue,
    },
    /// The `DPoP` proof could not be signed.
    #[snafu(display("Failed to sign DPoP proof"))]
    DPoPSign {
        /// The underlying error.
        source: DPoPErr,
    },
}

impl<DPoPErr: crate::Error + 'static> crate::Error for SerializeOAuth2FormError<DPoPErr> {
    fn is_retryable(&self) -> bool {
        match self {
            Self::SerializeForm { .. } | Self::BadHeader { .. } => false,
            Self::DPoPSign { source } => source.is_retryable(),
        }
    }
}

#[derive(Debug, Snafu)]
pub enum HandleResponseError {
    /// The response was an error response code, but could not be parsed as an `OAuth2` error.
    #[snafu(display(
        "Failed to parse error response as OAuth2 error: status={status}, content-type={}", content_type.as_ref().map(|s| s.to_str().ok().unwrap_or_default()).unwrap_or_default()
    ))]
    UnparseableErrorResponse {
        /// The body of the response.
        body: String,
        /// The status code of the response.
        status: http::StatusCode,
        /// The content type of the response.
        content_type: Option<http::HeaderValue>,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// The response had a success response code but could not be parsed.
    #[snafu(display("Failed to parse successful response as an OAuth2 payload"))]
    UnparseableSuccessResponse {
        /// The unparseable body.
        body: String,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// An `OAuth2` error was returned.
    #[snafu(display("OAuth2 request failed with an OAuth2 error payload: {:?}", body))]
    OAuth2 {
        /// The `OAuth2` error body.
        body: OAuth2ErrorBody,
        /// The status code of the `OAuth2` error response.
        status: http::StatusCode,
        /// The content type of the `OAuth2` error response.
        content_type: Option<http::HeaderValue>,
    },
}

impl crate::Error for HandleResponseError {
    fn is_retryable(&self) -> bool {
        match self {
            HandleResponseError::UnparseableErrorResponse { status, .. } => {
                status.is_server_error()
            }
            HandleResponseError::UnparseableSuccessResponse { .. } => false,
            HandleResponseError::OAuth2 { status, .. } => status.is_server_error(),
        }
    }
}

/// The `OAuth2` error response.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuth2ErrorBody {
    /// The error field from the `OAuth2` error.
    pub error: String,
    /// The `error_description` field from the `OAuth2` error.
    #[allow(dead_code)]
    pub error_description: Option<String>,
    /// The (optional) `error_uri` from the `OAuth2` error.
    #[allow(dead_code)]
    pub error_uri: Option<String>,
}
