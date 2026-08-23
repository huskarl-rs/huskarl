use bon::Builder;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Uri, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;

use crate::core::{
    Error, OAuthError, RetryAdvice,
    client_auth::AuthenticationParams,
    dpop::AuthorizationServerDPoP,
    http::{FailedResponse, HttpClient, Idempotency, TruncatedBody},
    oauth_form,
};

#[derive(Builder)]
pub(crate) struct OAuth2FormRequest<'a, F: Serialize> {
    /// Endpoint receiving the form request.
    uri: &'a Uri,
    /// Grant- or operation-specific form fields.
    form: &'a F,
    /// Client-authentication headers and form fields to merge into the request.
    auth_params: AuthenticationParams<'a>,
    /// `DPoP` implementation used to create a proof for this request.
    dpop: &'a dyn AuthorizationServerDPoP,
    /// Public-key thumbprint to request a DPoP-bound token with, when needed by
    /// the grant.
    dpop_jkt: Option<&'a str>,
}

impl<F: Serialize> OAuth2FormRequest<'_, F> {
    pub(crate) async fn build_request(&self) -> Result<Request<Bytes>, Error> {
        let headers = self.auth_params.headers.clone().unwrap_or_default();

        let mut body =
            oauth_form::to_string(self.form).context(SerializingExchangeParametersSnafu)?;

        if let Some(kv) = &self.auth_params.form_params {
            if !body.is_empty() {
                body.push('&');
            }

            oauth_form::push_to_string(&mut body, kv)
                .context(SerializingAuthenticationParametersSnafu)?;
        }

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.method = Method::POST;
        parts.uri = self.uri.clone();

        if let Some(proof) = self
            .dpop
            .proof(&parts.method, &parts.uri, self.dpop_jkt)
            .await?
        {
            let mut proof_value =
                HeaderValue::from_str(proof.expose_secret()).context(ProofNotAHeaderValueSnafu)?;
            proof_value.set_sensitive(true);
            parts.headers.insert("DPoP", proof_value);
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
    pub(crate) async fn execute<R: for<'de> Deserialize<'de>>(
        &self,
        http_client: &dyn HttpClient,
    ) -> Result<R, Error> {
        let request = self.build_request().await?;
        // The body may consume one-shot state, and replaying it would reuse the
        // `jti` and DPoP proof. Higher layers must rebuild any retry.
        let response = http_client.execute(request, Idempotency::Unknown).await?;

        if let Some(nonce) = crate::authorizer::extract_dpop_nonce(&response.headers) {
            self.dpop.update_nonce(nonce);
        }

        parse_oauth2_response(response.status, &response.headers, &response.body)
    }

    /// Executes the form request, expecting an empty response body on success.
    ///
    /// On success status codes, returns `Ok(())` after consuming the body.
    /// On error status codes, attempts to parse the body as an OAuth 2.0 error.
    ///
    /// The main current use of this endpoint is the revocation endpoint, which is
    /// not expected to require a `DPoP` nonce.
    pub(crate) async fn execute_empty_response(
        &self,
        http_client: &dyn HttpClient,
    ) -> Result<(), Error> {
        let request = self.build_request().await?;
        let response = http_client.execute(request, Idempotency::Unknown).await?;

        if response.status.is_success() {
            return Ok(());
        }

        Err(parse_oauth2_error_response(
            response.status,
            &response.headers,
            &response.body,
        ))
    }
}
/// The cause of a failure assembling an OAuth 2.0 form request.
#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum FormError {
    /// The exchange parameters could not be form-encoded.
    #[snafu(display("serializing exchange parameters"))]
    #[classify(no)]
    SerializingExchangeParameters {
        /// The underlying error.
        source: oauth_form::FormError,
    },
    /// The client-authentication parameters could not be form-encoded.
    #[snafu(display("serializing authentication parameters"))]
    #[classify(no)]
    SerializingAuthenticationParameters {
        /// The underlying error.
        source: oauth_form::FormError,
    },
    /// The generated `DPoP` proof is not a valid HTTP header value.
    #[snafu(display("DPoP proof is not a valid header value"))]
    #[classify(no)]
    ProofNotAHeaderValue {
        /// The underlying error.
        source: http::header::InvalidHeaderValue,
    },
}

/// Parses an error response body as an OAuth 2.0 error. Always returns an error.
///
/// A well-formed body becomes a verbatim [`OAuthError`] verdict; endpoint code
/// interprets its meaning. [`FailedResponse::into_error`] combines the code
/// with the HTTP status and `Retry-After` header.
///
/// A `429` or `5xx` body is never a verdict, and an unparseable body produces an
/// unusable-response error.
fn parse_oauth2_error_response(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body: &Bytes,
) -> Error {
    let content_type = headers.get(CONTENT_TYPE).cloned();
    // Handle an unexpected success status without panicking.
    let Some(failed) = FailedResponse::new(status, headers) else {
        return Error::new(
            RetryAdvice::No,
            HandleResponseError::UnparseableSuccessResponse {
                body: RedactedBody(String::from_utf8_lossy(body).into_owned()),
                source: serde::de::Error::custom("success status on the error path"),
            },
        );
    };

    match serde_json::from_slice::<OAuth2ErrorBody>(body) {
        Ok(error_body) => {
            let verdict = OAuthError::new(error_body.error.as_str())
                .with_description(error_body.error_description.clone())
                .with_uri(error_body.error_uri.clone());
            failed.into_error(
                Some(verdict),
                HandleResponseError::OAuth2 {
                    body: error_body,
                    status,
                    content_type,
                },
            )
        }
        // An unparseable body supplies no verdict.
        Err(source) => failed.into_error(
            None,
            HandleResponseError::UnparseableErrorResponse {
                body: TruncatedBody::from_bytes(body),
                status,
                content_type,
                source,
            },
        ),
    }
}

fn parse_oauth2_response<T: for<'de> Deserialize<'de>>(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body: &Bytes,
) -> Result<T, Error> {
    if !status.is_success() {
        return Err(parse_oauth2_error_response(status, headers, body));
    }

    serde_json::from_slice(body).map_err(|source| {
        Error::new(
            RetryAdvice::No,
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
pub(crate) struct RedactedBody(String);

impl std::fmt::Debug for RedactedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED {} bytes]", self.0.len())
    }
}

/// The cause of an OAuth 2.0 token-endpoint response failure.
#[derive(Debug, Snafu)]
pub(crate) enum HandleResponseError {
    /// The response was an error response code, but could not be parsed as an OAuth 2.0 error.
    #[snafu(display(
        "failed to parse error response as OAuth2 error: status={status}, content-type={ct}, body={body}",
        ct = content_type.as_ref().map(|s| s.to_str().ok().unwrap_or_default()).unwrap_or_default()
    ))]
    UnparseableErrorResponse {
        /// The body of the response.
        body: TruncatedBody,
        /// The status code of the response.
        status: http::StatusCode,
        /// The content type of the response.
        content_type: Option<http::HeaderValue>,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// The response had a success response code but could not be parsed.
    #[snafu(display("failed to parse successful response as an OAuth2 payload"))]
    UnparseableSuccessResponse {
        /// The unparseable body.
        body: RedactedBody,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// An OAuth 2.0 error body was returned.
    ///
    /// The message includes the status because codes in `5xx` bodies are
    /// diagnostic rather than [`Error::verdict`] values.
    #[snafu(display(
        "the token endpoint returned HTTP {status}: {}{}{}{}",
        body.error,
        body.error_description.as_ref().map(|d| format!(": {d}")).unwrap_or_default(),
        body.error_uri.as_ref().map(|uri| format!(" (see {uri})")).unwrap_or_default(),
        content_type.as_ref().map(|ct| format!(" (content-type: {})", ct.to_str().unwrap_or_default())).unwrap_or_default()
    ))]
    OAuth2 {
        /// The OAuth 2.0 error body.
        body: OAuth2ErrorBody,
        /// The status code of the OAuth 2.0 error response.
        status: http::StatusCode,
        /// The content type of the OAuth 2.0 error response.
        content_type: Option<http::HeaderValue>,
    },
}

impl HandleResponseError {
    /// Returns whether the response is unusable because its body could not be parsed.
    ///
    /// A parsed OAuth body is classified separately using the HTTP status.
    #[cfg(any(feature = "metrics", test))]
    pub(crate) fn is_unusable_response(&self) -> bool {
        match self {
            Self::UnparseableErrorResponse { .. } | Self::UnparseableSuccessResponse { .. } => true,
            Self::OAuth2 { .. } => false,
        }
    }
}

/// The OAuth 2.0 error response, as it arrived on the wire.
///
/// Read a classified response through [`Error::verdict`], which exposes these
/// members as a typed [`OAuthError`].
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OAuth2ErrorBody {
    /// The error field from the OAuth 2.0 error.
    pub(crate) error: String,
    /// The `error_description` field from the OAuth 2.0 error.
    pub(crate) error_description: Option<String>,
    /// The (optional) `error_uri` from the OAuth 2.0 error.
    pub(crate) error_uri: Option<String>,
}

/// Executes a block, retrying once if the error indicates a `DPoP` nonce is required.
///
/// The block is expected to regenerate fresh authentication parameters on each
/// invocation to avoid `jti` reuse in `private_key_jwt` client assertions (RFC 7523 §3).
macro_rules! with_dpop_nonce_retry {
    ($body:block) => {{
        let result = $body;
        // Fully qualified: this expands at each call site, which need not have
        // the extension trait in scope.
        if let Err(ref e) = result
            && $crate::core::Error::verdict(e).is_some_and(|verdict| {
                *verdict.code() == $crate::core::OAuthErrorCode::UseDPoPNonce
            })
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
    use rstest::rstest;

    use super::*;
    use crate::core::OAuthErrorCode;

    fn classify(status: u16, body: &str) -> RetryAdvice {
        let err = parse_oauth2_error_response(
            http::StatusCode::from_u16(status).unwrap(),
            &http::HeaderMap::new(),
            &Bytes::copy_from_slice(body.as_bytes()),
        );
        err.retry_advice()
    }

    #[test]
    fn short_bodies_render_whole() {
        let body = TruncatedBody::new("upstream is down");
        assert_eq!(body.to_string(), "upstream is down");
    }

    // Bound the size of gateway responses in log output.
    #[test]
    fn long_bodies_are_truncated_with_their_true_length() {
        let body = TruncatedBody::new("x".repeat(5000));
        let rendered = body.to_string();
        assert!(rendered.len() < 300, "got {rendered}");
        assert!(rendered.ends_with("… [5000 bytes total]"), "got {rendered}");
    }

    // Truncation must preserve UTF-8 character boundaries.
    #[test]
    fn truncation_does_not_split_a_multibyte_character() {
        // Each 'é' occupies two bytes.
        let body = TruncatedBody::new("é".repeat(1000));
        let rendered = body.to_string();
        assert!(rendered.ends_with("… [2000 bytes total]"), "got {rendered}");
    }

    // Preserve every 4xx OAuth code as a typed verdict.
    #[rstest]
    #[case::dead_credential("invalid_grant", OAuthErrorCode::InvalidGrant)]
    #[case::bad_scope("invalid_scope", OAuthErrorCode::InvalidScope)]
    #[case::bad_client_auth("invalid_client", OAuthErrorCode::InvalidClient)]
    #[case::dpop_proof("invalid_dpop_proof", OAuthErrorCode::InvalidDPoPProof)]
    #[case::dpop_nonce("use_dpop_nonce", OAuthErrorCode::UseDPoPNonce)]
    #[case::device_polling("authorization_pending", OAuthErrorCode::AuthorizationPending)]
    #[case::grant_not_permitted("unauthorized_client", OAuthErrorCode::UnauthorizedClient)]
    #[case::extension("something_bespoke", OAuthErrorCode::from("something_bespoke"))]
    fn every_4xx_verdict_is_a_rejection_carrying_its_code(
        #[case] wire: &str,
        #[case] expected: OAuthErrorCode,
    ) {
        let err = parse_oauth2_error_response(
            http::StatusCode::BAD_REQUEST,
            &http::HeaderMap::new(),
            &Bytes::from(format!(r#"{{"error":"{wire}"}}"#)),
        );
        assert_eq!(err.retry_advice(), RetryAdvice::No, "{wire}");
        assert_eq!(err.verdict().map(OAuthError::code), Some(&expected));
        assert_eq!(
            err.verdict().map(|v| v.code().as_str()),
            Some(wire),
            "verbatim on the wire"
        );
    }

    // The source chain must render each part of the response exactly once.
    #[test]
    fn the_chain_says_the_code_once_and_the_gloss_once() {
        let err = parse_oauth2_error_response(
            http::StatusCode::BAD_REQUEST,
            &http::HeaderMap::new(),
            &Bytes::from_static(
                br#"{"error":"invalid_scope",
                     "error_description":"scope 'admin' is not permitted",
                     "error_uri":"https://as.example.com/errors"}"#,
            ),
        );

        assert_eq!(
            format!("{err:#}"),
            "the token endpoint returned HTTP 400 Bad Request: invalid_scope: \
             scope 'admin' is not permitted (see https://as.example.com/errors)"
        );
        assert_eq!(
            format!("{err:#}").matches("invalid_scope").count(),
            1,
            "the code must appear once across the whole chain"
        );

        // A bare, well-formed OAuth error still renders its code.
        let bare = parse_oauth2_error_response(
            http::StatusCode::BAD_REQUEST,
            &http::HeaderMap::new(),
            &Bytes::from_static(br#"{"error":"invalid_grant"}"#),
        );
        assert_eq!(
            format!("{bare:#}"),
            "the token endpoint returned HTTP 400 Bad Request: invalid_grant"
        );
    }

    // Only the token source knows whether another credential is available, so
    // a rejection alone cannot require reauthentication.
    #[test]
    fn a_rejection_never_demands_reauth_by_itself() {
        let err = parse_oauth2_error_response(
            http::StatusCode::BAD_REQUEST,
            &http::HeaderMap::new(),
            &Bytes::from_static(br#"{"error":"invalid_grant"}"#),
        );
        assert_ne!(
            crate::cache::Recovery::implied_by(&err),
            crate::cache::Recovery::Reauthenticate
        );
    }

    // A gateway's `invalid_grant` body must not become a credential verdict.
    #[test]
    fn invalid_grant_in_5xx_body_is_a_retryable_server_condition() {
        assert_eq!(
            classify(503, r#"{"error":"invalid_grant"}"#),
            RetryAdvice::RETRY
        );

        // Include the status that prevented the body from becoming a verdict.
        let err = parse_oauth2_error_response(
            http::StatusCode::BAD_GATEWAY,
            &http::HeaderMap::new(),
            &Bytes::from_static(br#"{"error":"invalid_grant"}"#),
        );
        assert!(err.verdict().is_none());
        assert_eq!(
            format!("{err:#}"),
            "the token endpoint returned HTTP 502 Bad Gateway: invalid_grant"
        );
    }

    // Preserve a throttled endpoint's retry delay.
    #[test]
    fn a_429_is_retryable_and_keeps_retry_after() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::RETRY_AFTER, "20".parse().unwrap());
        let err = parse_oauth2_error_response(
            http::StatusCode::TOO_MANY_REQUESTS,
            &headers,
            &Bytes::from_static(br#"{"error":"slow_down"}"#),
        );
        assert_eq!(
            err.retry_advice(),
            RetryAdvice::retry_after(crate::core::platform::Duration::from_secs(20))
        );
    }

    // The status distinguishes a 4xx verdict from a 5xx server failure.
    #[test]
    fn only_a_judged_response_yields_a_verdict() {
        let err = parse_oauth2_error_response(
            http::StatusCode::UNAUTHORIZED,
            &http::HeaderMap::new(),
            &Bytes::from_static(br#"{"error":"invalid_client"}"#),
        );
        assert_eq!(
            err.verdict().map(|v| v.code().as_str()),
            Some("invalid_client")
        );

        // An unparseable gateway response has no verdict.
        let unparseable = parse_oauth2_error_response(
            http::StatusCode::BAD_GATEWAY,
            &http::HeaderMap::new(),
            &Bytes::from_static(b"<html>nope</html>"),
        );
        assert!(unparseable.verdict().is_none());
    }

    // DPoP nonce retries use the typed verdict, not generic retry advice.
    #[test]
    fn dpop_nonce_is_not_generically_retryable() {
        let err = parse_oauth2_error_response(
            http::StatusCode::BAD_REQUEST,
            &http::HeaderMap::new(),
            &Bytes::from_static(br#"{"error":"use_dpop_nonce"}"#),
        );
        assert_eq!(err.retry_advice(), RetryAdvice::No);
        assert!(
            err.verdict()
                .is_some_and(|v| *v.code() == crate::core::OAuthErrorCode::UseDPoPNonce)
        );
    }
}
