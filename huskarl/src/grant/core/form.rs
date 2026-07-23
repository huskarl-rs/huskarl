use bon::Builder;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Uri, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::core::{
    Error, ErrorKind,
    client_auth::AuthenticationParams,
    dpop::AuthorizationServerDPoP,
    http::{HttpClient, Idempotency},
    oauth_form,
};

#[derive(Builder)]
pub struct OAuth2FormRequest<'a, F: Serialize> {
    uri: &'a Uri,
    form: &'a F,
    auth_params: AuthenticationParams<'a>,
    dpop: &'a dyn AuthorizationServerDPoP,
    dpop_jkt: Option<&'a str>,
}

impl<F: Serialize> OAuth2FormRequest<'_, F> {
    pub async fn build_request(&self) -> Result<Request<Bytes>, Error> {
        let headers = self.auth_params.headers.clone().unwrap_or_default();

        let mut body = oauth_form::to_string(self.form)
            .map_err(|e| serialize_form_error(e).with_context("serializing exchange parameters"))?;

        if let Some(kv) = &self.auth_params.form_params {
            if !body.is_empty() {
                body.push('&');
            }

            oauth_form::push_to_string(&mut body, kv).map_err(|e| {
                serialize_form_error(e).with_context("serializing authentication parameters")
            })?;
        }

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.method = Method::POST;
        parts.uri = self.uri.clone();

        if let Some(proof) = self
            .dpop
            .proof(&parts.method, &parts.uri, self.dpop_jkt)
            .await?
        {
            parts.headers.insert(
                "DPoP",
                HeaderValue::from_str(proof.expose_secret()).map_err(|e| {
                    Error::new(ErrorKind::DPoP, e)
                        .with_context("DPoP proof is not a valid header value")
                })?,
            );
        }

        parts.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        parts.headers.extend(headers);

        Ok(Request::from_parts(parts, body.into()))
    }

    /// Executes the form request once, without `DPoP` nonce auto-retry.
    ///
    /// If the server returns a `DPoP-Nonce` header, the `DPoP` nonce state is updated.
    /// If the error is `use_dpop_nonce`, no retry is performed — wrap the call site
    /// with [`with_dpop_nonce_retry!`], which retries with freshly generated
    /// `auth_params`.
    pub async fn execute<R: for<'de> Deserialize<'de>>(
        &self,
        http_client: &dyn HttpClient,
    ) -> Result<R, Error> {
        let request = self.build_request().await?;
        // Token requests may consume one-shot state (an authorization code,
        // a rotating refresh token) — never known-idempotent.
        let response = http_client.execute(request, Idempotency::Unknown).await?;

        let content_type = if response.status.is_success() {
            None
        } else {
            response.headers.get(CONTENT_TYPE).cloned()
        };

        if let Some(nonce) = crate::authorizer::extract_dpop_nonce(&response.headers) {
            self.dpop.update_nonce(nonce);
        }

        parse_oauth2_response(response.status, content_type, &response.body)
    }

    /// Executes the form request, expecting an empty response body on success.
    ///
    /// On success status codes, returns `Ok(())` after consuming the body.
    /// On error status codes, attempts to parse the body as an `OAuth2` error.
    ///
    /// The main current use of this endpoint is the revocation endpoint, which is
    /// not expected to require a `DPoP` nonce.
    pub async fn execute_empty_response(&self, http_client: &dyn HttpClient) -> Result<(), Error> {
        let request = self.build_request().await?;
        let response = http_client.execute(request, Idempotency::Unknown).await?;

        if response.status.is_success() {
            return Ok(());
        }

        let content_type = response.headers.get(CONTENT_TYPE).cloned();

        Err(parse_oauth2_error_response(
            response.status,
            content_type,
            &response.body,
        ))
    }
}

fn serialize_form_error(source: oauth_form::Error) -> Error {
    Error::new(ErrorKind::Config, source)
}

/// Parses an error response body as an `OAuth2` error. Always returns an error.
///
/// Any 5xx → retryable [`ErrorKind::Transport`] whatever the body says; else by
/// code: `invalid_grant` → [`ErrorKind::InvalidGrant`], `invalid_scope`/
/// `invalid_target`/`invalid_resource` → [`ErrorKind::RequestRejected`],
/// `use_dpop_nonce` → [`ErrorKind::DPoP`], other → [`ErrorKind::Protocol`].
fn parse_oauth2_error_response(
    status: http::StatusCode,
    content_type: Option<HeaderValue>,
    body: &Bytes,
) -> Error {
    match serde_json::from_slice::<OAuth2ErrorBody>(body) {
        Ok(error_body) => {
            let code = error_body.error.clone();
            let description = error_body.error_description.clone();
            // 5xx is a server fault, not a verdict on the credential (RFC 6749
            // §5.2 requires 4xx): don't discard a valid RT on a stray code.
            let kind = if status.is_server_error() {
                ErrorKind::Transport { retryable: true }
            } else {
                match code.as_str() {
                    "invalid_grant" => ErrorKind::InvalidGrant,
                    "invalid_scope" | "invalid_target" | "invalid_resource" => {
                        ErrorKind::RequestRejected
                    }
                    "use_dpop_nonce" => ErrorKind::DPoP,
                    _ => ErrorKind::Protocol,
                }
            };
            Error::new(
                kind,
                HandleResponseError::OAuth2 {
                    body: error_body,
                    status,
                    content_type,
                },
            )
            .with_oauth_error(code, description)
        }
        Err(source) => {
            let kind = if status.is_server_error() {
                ErrorKind::Transport { retryable: true }
            } else {
                ErrorKind::Protocol
            };
            Error::new(
                kind,
                HandleResponseError::UnparseableErrorResponse {
                    body: String::from_utf8_lossy(body).into_owned(),
                    status,
                    content_type,
                    source,
                },
            )
        }
    }
}

fn parse_oauth2_response<T: for<'de> Deserialize<'de>>(
    status: http::StatusCode,
    content_type: Option<HeaderValue>,
    body: &Bytes,
) -> Result<T, Error> {
    if !status.is_success() {
        return Err(parse_oauth2_error_response(status, content_type, body));
    }

    serde_json::from_slice(body).map_err(|source| {
        Error::new(
            ErrorKind::Protocol,
            HandleResponseError::UnparseableSuccessResponse {
                body: RedactedBody(String::from_utf8_lossy(body).into_owned()),
                source,
            },
        )
    })
}

/// A captured response body whose contents are withheld from `Debug`.
///
/// A successful token-endpoint response carries cleartext access and refresh
/// tokens. Letting the raw body surface through `{:?}` — directly or via the
/// wrapping [`Error`]'s source chain — would leak those tokens to logs, so the
/// body is retained only to construct the error and its contents are never
/// rendered.
pub struct RedactedBody(String);

impl std::fmt::Debug for RedactedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED {} bytes]", self.0.len())
    }
}

/// Source vocabulary for `OAuth2` token-endpoint response failures.
///
/// Carried as the source of the [`Error`]s produced by the form machinery —
/// match on [`ErrorKind`] and [`Error::oauth_error_code`] instead of
/// downcasting to this type.
#[derive(Debug, Snafu)]
pub enum HandleResponseError {
    /// The response was an error response code, but could not be parsed as an `OAuth2` error.
    #[snafu(display(
        "Failed to parse error response as OAuth2 error: status={status}, content-type={ct}, body={body}",
        ct = content_type.as_ref().map(|s| s.to_str().ok().unwrap_or_default()).unwrap_or_default()
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
        body: RedactedBody,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// An `OAuth2` error was returned.
    #[snafu(display("OAuth2 request failed with an OAuth2 error payload: {body}"))]
    OAuth2 {
        /// The `OAuth2` error body.
        body: OAuth2ErrorBody,
        /// The status code of the `OAuth2` error response.
        status: http::StatusCode,
        /// The content type of the `OAuth2` error response.
        content_type: Option<http::HeaderValue>,
    },
}

/// The `OAuth2` error response.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuth2ErrorBody {
    /// The error field from the `OAuth2` error.
    pub error: String,
    /// The `error_description` field from the `OAuth2` error.
    pub error_description: Option<String>,
    /// The (optional) `error_uri` from the `OAuth2` error.
    pub error_uri: Option<String>,
}

impl std::fmt::Display for OAuth2ErrorBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.error)?;
        if let Some(description) = &self.error_description {
            write!(f, ": {description}")?;
        }
        if let Some(uri) = &self.error_uri {
            write!(f, " (see {uri})")?;
        }
        Ok(())
    }
}

/// Executes a block, retrying once if the error indicates a `DPoP` nonce is required.
///
/// The block is expected to regenerate fresh authentication parameters on each
/// invocation to avoid `jti` reuse in `private_key_jwt` client assertions (RFC 7523 §3).
macro_rules! with_dpop_nonce_retry {
    ($body:block) => {{
        let result = $body;
        if let Err(ref e) = result
            && e.is_dpop_nonce_required()
        {
            $body
        } else {
            result
        }
    }};
}

pub(crate) use with_dpop_nonce_retry;

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(status: u16, body: &str) -> ErrorKind {
        parse_oauth2_error_response(
            http::StatusCode::from_u16(status).unwrap(),
            None,
            &Bytes::copy_from_slice(body.as_bytes()),
        )
        .kind()
    }

    #[test]
    fn invalid_grant_on_400_rejects_credential() {
        assert_eq!(
            classify(400, r#"{"error":"invalid_grant"}"#),
            ErrorKind::InvalidGrant
        );
    }

    #[test]
    fn invalid_grant_in_5xx_body_is_retryable_transport() {
        // A stray invalid_grant in a server-error body must not drop the token.
        assert_eq!(
            classify(503, r#"{"error":"invalid_grant"}"#),
            ErrorKind::Transport { retryable: true }
        );
    }
}
