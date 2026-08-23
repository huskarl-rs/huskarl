//! HTTP client and response abstractions.
//!
//! This module defines the [`HttpClient`] trait, which decouples the library
//! from any specific HTTP implementation. Users provide their own client
//! (e.g. backed by `reqwest`, `hyper`, or a WASM-compatible client) and the
//! library operates against the trait, usually as `&dyn HttpClient` or
//! `Arc<dyn HttpClient>`.

mod get;
#[cfg(feature = "metrics")]
mod metrics_client;

use std::sync::Arc;

use bytes::Bytes;
pub(crate) use get::get;
use http::{HeaderMap, Request, StatusCode};
#[cfg(feature = "metrics")]
pub use metrics_client::MetricsHttpClient;

use crate::{
    error::{Error, RetryAdvice},
    platform::{Duration, MaybeSendBoxFuture, MaybeSendSync},
};

// Cap unreasonable server values at one day.
const MAX_RETRY_AFTER: Duration = Duration::from_hours(24);

/// Parses the `Retry-After` header as a delay.
///
/// Supports both forms defined by RFC 9110 §10.2.3: delta-seconds and HTTP
/// dates. Dates are resolved against the current clock. Past dates produce a
/// zero delay, and delays longer than 24 hours are capped at 24 hours.
///
/// Returns `None` when the header is absent, is not valid text, or contains
/// neither supported form.
#[must_use]
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    // Servers occasionally pad the value; RFC 9110 §5.5 lets us ignore that.
    let value = value.trim();
    let delay = match value.parse::<u64>() {
        Ok(seconds) => Duration::from_secs(seconds),
        Err(_) => http_date_delay(value)?,
    };
    Some(delay.min(MAX_RETRY_AFTER))
}

// Convert any RFC 9110 HTTP-date spelling to a delay. Past dates mean retry now.
fn http_date_delay(value: &str) -> Option<Duration> {
    // Compare durations because browser wasm uses `web_time::SystemTime`, while
    // `httpdate` returns `std::time::SystemTime`.
    let deadline = httpdate::parse_http_date(value)
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let now = crate::platform::SystemTime::now()
        .duration_since(crate::platform::SystemTime::UNIX_EPOCH)
        .ok()?;
    // A date already past is "retry now", not a failure to parse.
    Some(deadline.saturating_sub(now))
}

/// What a non-success status establishes before the body is inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusVerdict {
    /// A `429` or retryable `5xx`, including any server-supplied delay.
    Transient(RetryAdvice),
    /// A `501` or `505` capability failure that retrying cannot resolve.
    Unsupported,
    /// The status alone concludes nothing; only the body says what it means.
    Undecided,
}

// Classify a status before inspecting the response body. A 5xx never becomes
// an OAuth verdict; `501` and `505` are separated because waiting cannot fix
// those capability failures.
#[must_use]
fn status_verdict(status: StatusCode, headers: &HeaderMap) -> StatusVerdict {
    if matches!(
        status,
        StatusCode::NOT_IMPLEMENTED | StatusCode::HTTP_VERSION_NOT_SUPPORTED
    ) {
        return StatusVerdict::Unsupported;
    }
    if !(status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS) {
        return StatusVerdict::Undecided;
    }
    StatusVerdict::Transient(
        retry_after(headers).map_or(RetryAdvice::RETRY, RetryAdvice::retry_after),
    )
}

/// A non-successful HTTP response being converted into an [`Error`].
///
/// This type cannot be constructed for a successful response. It applies HTTP
/// status, `Retry-After`, and OAuth verdict semantics together when producing
/// an error. See [the error model](crate::_docs::explanation::error_handling)
/// for the rationale.
///
/// # Examples
///
/// ```rust
/// # use huskarl_core::{OAuthError, OAuthErrorCode, http::FailedResponse};
/// # use http::{HeaderMap, StatusCode};
/// # #[derive(Debug)] struct Cause;
/// # impl std::fmt::Display for Cause {
/// #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("cause") }
/// # }
/// # impl std::error::Error for Cause {}
/// # let headers = HeaderMap::new();
/// assert!(FailedResponse::new(StatusCode::OK, &headers).is_none());
///
/// let failed = FailedResponse::new(StatusCode::BAD_REQUEST, &headers).unwrap();
/// let err = failed.into_error(Some(OAuthError::new("invalid_scope")), Cause);
/// assert_eq!(err.verdict().map(OAuthError::code), Some(&OAuthErrorCode::InvalidScope));
///
/// // OAuth codes in 5xx bodies are not treated as verdicts on the request.
/// let gateway = FailedResponse::new(StatusCode::BAD_GATEWAY, &headers).unwrap();
/// let err = gateway.into_error(Some(OAuthError::new("invalid_scope")), Cause);
/// assert!(err.verdict().is_none());
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FailedResponse<'a> {
    status: StatusCode,
    headers: &'a HeaderMap,
}

impl<'a> FailedResponse<'a> {
    /// Creates a failed response, or returns `None` for a successful status.
    #[must_use]
    pub fn new(status: StatusCode, headers: &'a HeaderMap) -> Option<Self> {
        (!status.is_success()).then_some(Self { status, headers })
    }

    /// The response's status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns whether the status represents a transient server condition.
    ///
    /// This returns `true` for `429` and for `5xx` except `501` and `505`.
    /// [`into_error`](Self::into_error) applies the same classification.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            status_verdict(self.status, self.headers),
            StatusVerdict::Transient(_)
        )
    }

    /// Converts this response into an [`Error`].
    ///
    /// The caller supplies an OAuth verdict parsed from the body or headers, if
    /// present. Classification follows these rules:
    ///
    /// - `429` and transient `5xx` statuses are retryable and honor
    ///   `Retry-After`.
    /// - `501` and `505` are not retryable.
    /// - No `429` or `5xx` response produces an [`Error::verdict`], even if its
    ///   body contains an OAuth error code.
    /// - For other statuses, a supplied verdict is preserved. Its code
    ///   determines retryability, and `Retry-After` supplies any delay.
    /// - A response without a usable verdict is not retryable.
    ///
    /// The caller's location is recorded and returned by [`Error::location`].
    #[track_caller]
    #[must_use]
    pub fn into_error(
        self,
        verdict: Option<crate::oauth_error::OAuthError>,
        cause: impl Into<crate::error::BoxedSource>,
    ) -> Error {
        Error::establish(self.classification(verdict), cause)
    }

    /// Classifies this response without constructing an [`Error`].
    ///
    /// This applies the same rules as [`into_error`](Self::into_error) and is
    /// intended for a cause enum that reports an
    /// [`Origin`](crate::error::propagation::Origin).
    #[must_use]
    pub fn classification(
        self,
        verdict: Option<crate::oauth_error::OAuthError>,
    ) -> crate::error::propagation::Classification {
        let (advice, judged) = match status_verdict(self.status, self.headers) {
            StatusVerdict::Transient(advice) => (advice, false),
            // `temporarily_unavailable` and `server_error` represent retryable
            // server failures when delivered as OAuth verdicts (RFC 6749
            // §4.1.2.1). Preserve a corresponding `Retry-After` delay.
            StatusVerdict::Undecided => match &verdict {
                Some(verdict) => {
                    let advice = match verdict.code().implied_retry_advice() {
                        RetryAdvice::Retry { .. } => retry_after(self.headers)
                            .map_or(RetryAdvice::RETRY, RetryAdvice::retry_after),
                        advice => advice,
                    };
                    (advice, true)
                }
                // A response without a verdict is terminal.
                None => (RetryAdvice::No, false),
            },
            // Capability failures are terminal.
            StatusVerdict::Unsupported => (RetryAdvice::No, false),
        };
        match verdict {
            // A code becomes a verdict only when the status allows the body to
            // judge the request. Codes echoed by a gateway remain diagnostic.
            Some(verdict) if judged => {
                crate::error::propagation::Classification::judged(advice, verdict)
            }
            _ => advice.into(),
        }
    }
}

// Enough context to recognize a typical error page without flooding logs.
const MAX_RENDERED_BODY: usize = 256;

/// A response body whose diagnostic output is limited to a bounded prefix.
///
/// [`Display`](std::fmt::Display) and [`Debug`](std::fmt::Debug) show at most
/// 256 bytes and report the full byte length when truncated. This limits log
/// volume and reduces exposure if a server reflects credentials into an error
/// response. It does not redact secrets that occur within the displayed prefix.
///
/// # Examples
///
/// ```rust
/// # use huskarl_core::http::TruncatedBody;
/// assert_eq!(
///     TruncatedBody::new("upstream is down").to_string(),
///     "upstream is down"
/// );
/// assert!(
///     TruncatedBody::new("x".repeat(5000))
///         .to_string()
///         .ends_with("… [5000 bytes total]")
/// );
/// ```
pub struct TruncatedBody(String);

impl TruncatedBody {
    /// Captures a string response body.
    #[must_use]
    pub fn new(body: impl Into<String>) -> Self {
        Self(body.into())
    }

    /// Captures a byte response body using lossy UTF-8 conversion.
    ///
    /// Invalid UTF-8 sequences are replaced with the replacement character.
    #[must_use]
    pub fn from_bytes(body: &[u8]) -> Self {
        Self(String::from_utf8_lossy(body).into_owned())
    }
}

impl std::fmt::Display for TruncatedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.len() <= MAX_RENDERED_BODY {
            return f.write_str(&self.0);
        }
        // Cut on a character boundary; slicing through a multi-byte character
        // would panic.
        let end = self
            .0
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|i| *i <= MAX_RENDERED_BODY)
            .last()
            .unwrap_or(0);
        write!(f, "{}… [{} bytes total]", &self.0[..end], self.0.len())
    }
}

// Keep debug output subject to the same bound as display output.
impl std::fmt::Debug for TruncatedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.to_string(), f)
    }
}

/// A fully-read HTTP response.
///
/// All responses this library consumes are small JSON, JWKS, or metadata
/// documents, so [`HttpClient::execute`] reads the entire body before
/// returning — there is no streaming interface.
#[derive(Clone)]
pub struct HttpResponse {
    /// The HTTP status code of the response.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The full response body.
    pub body: Bytes,
}

// The body may contain credentials, so debug output includes only its length.
impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Whether an HTTP request is known to be safe to re-send.
///
/// [`HttpClient`] implementations use this when classifying transport failures
/// that occur after delivery becomes uncertain, such as timeouts or interrupted
/// responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idempotency {
    /// Re-sending is safe even if the server processed an earlier attempt.
    Idempotent,
    /// Re-sending may repeat an operation that the server already processed.
    ///
    /// Transport failures are retryable only when the request is known not to
    /// have reached the server.
    Unknown,
}

/// Executes HTTP requests on behalf of the library.
///
/// Implementations return a fully buffered [`HttpResponse`] and must use
/// [`Idempotency`] when determining whether a transport failure is safe to
/// retry. The trait is dyn-compatible and is used through values such as
/// `&dyn HttpClient` and `Arc<dyn HttpClient>`.
///
/// Implementations must enforce a response-body size limit while reading.
/// Endpoints may be attacker-controlled, so buffering an unbounded or
/// never-ending response can exhaust memory. Classify an oversized response
/// with [`RetryAdvice::No`]. See
/// [Implementing a backend](crate::_docs::guide::implementing_a_backend) for a
/// step-by-step implementation guide.
pub trait HttpClient: MaybeSendSync {
    /// Executes an HTTP request and returns the fully-read response.
    ///
    /// # Arguments
    ///
    /// * `request`: request to execute, with a [`Bytes`] body.
    /// * `idempotency`: whether re-sending is safe after a transport failure.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when sending the request or reading its bounded
    /// response body fails.
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>>;

    /// Indicates whether this client uses mTLS for authentication.
    ///
    /// If true, grants should prefer to use mTLS endpoint aliases
    /// (RFC 8705 §5) when making requests to the authorization server.
    fn uses_mtls(&self) -> bool {
        false
    }
}

impl<T: HttpClient + ?Sized> HttpClient for &T {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request, idempotency)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

impl<T: HttpClient + ?Sized> HttpClient for Box<T> {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request, idempotency)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

impl<T: HttpClient + ?Sized> HttpClient for Arc<T> {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request, idempotency)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::{error::RetryAdvice, oauth_error::OAuthError};

    #[test]
    fn truncated_body_debug_is_bounded_and_escaped() {
        let rendered = format!("{:?}", TruncatedBody::new("first line\nsecond\tline"));
        assert_eq!(rendered, r#""first line\nsecond\tline""#);
        assert!(!rendered.contains('\n'));

        let rendered = format!("{:?}", TruncatedBody::new("x".repeat(5_000)));
        assert!(rendered.len() < 512, "{rendered}");
        assert!(rendered.contains("5000 bytes total"), "{rendered}");
    }

    struct FakeClient {
        status: StatusCode,
        body: &'static str,
        retry_after: Option<&'static str>,
    }

    impl FakeClient {
        fn new(status: StatusCode, body: &'static str) -> Self {
            Self {
                status,
                body,
                retry_after: None,
            }
        }
    }

    impl HttpClient for FakeClient {
        fn execute(
            &self,
            _request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            Box::pin(async move {
                let mut headers = HeaderMap::new();
                if let Some(value) = self.retry_after {
                    headers.insert(http::header::RETRY_AFTER, value.parse().unwrap());
                }
                Ok(HttpResponse {
                    status: self.status,
                    headers,
                    body: Bytes::from_static(self.body.as_bytes()),
                })
            })
        }
    }

    fn headers_with_retry_after(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::RETRY_AFTER, value.parse().unwrap());
        headers
    }

    // A 4xx status alone does not determine whether the body is a verdict.
    #[rstest]
    #[case::bad_request(StatusCode::BAD_REQUEST, StatusVerdict::Undecided)]
    #[case::unauthorized(StatusCode::UNAUTHORIZED, StatusVerdict::Undecided)]
    #[case::forbidden(StatusCode::FORBIDDEN, StatusVerdict::Undecided)]
    #[case::not_found(StatusCode::NOT_FOUND, StatusVerdict::Undecided)]
    #[case::ok(StatusCode::OK, StatusVerdict::Undecided)]
    #[case::too_many_requests(
        StatusCode::TOO_MANY_REQUESTS,
        StatusVerdict::Transient(RetryAdvice::RETRY)
    )]
    #[case::internal(
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusVerdict::Transient(RetryAdvice::RETRY)
    )]
    #[case::bad_gateway(StatusCode::BAD_GATEWAY, StatusVerdict::Transient(RetryAdvice::RETRY))]
    #[case::unavailable(
        StatusCode::SERVICE_UNAVAILABLE,
        StatusVerdict::Transient(RetryAdvice::RETRY)
    )]
    #[case::gateway_timeout(
        StatusCode::GATEWAY_TIMEOUT,
        StatusVerdict::Transient(RetryAdvice::RETRY)
    )]
    fn only_5xx_and_429_are_transient(#[case] status: StatusCode, #[case] expected: StatusVerdict) {
        assert_eq!(status_verdict(status, &HeaderMap::new()), expected);
    }

    // RFC 9110 defines 501 and 505 as capability failures, not outages.
    #[rstest]
    #[case::not_implemented(StatusCode::NOT_IMPLEMENTED)]
    #[case::version_not_supported(StatusCode::HTTP_VERSION_NOT_SUPPORTED)]
    fn an_unimplemented_endpoint_is_not_a_transient_outage(#[case] status: StatusCode) {
        let none = HeaderMap::new();
        assert_eq!(status_verdict(status, &none), StatusVerdict::Unsupported);

        let err = FailedResponse::new(status, &none)
            .expect("not a success")
            .into_error(None, "cause");
        assert_eq!(err.retry_advice(), RetryAdvice::No);
        assert!(err.verdict().is_none());

        // `Retry-After` cannot make an unsupported capability retryable.
        let err = FailedResponse::new(StatusCode::NOT_IMPLEMENTED, &headers_with_retry_after("30"))
            .expect("not a success")
            .into_error(None, "cause");
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    // An OAuth code in any 5xx body remains diagnostic, not a verdict.
    #[test]
    fn a_code_on_an_unimplemented_status_is_still_not_a_verdict() {
        let none = HeaderMap::new();
        let err = FailedResponse::new(StatusCode::NOT_IMPLEMENTED, &none)
            .expect("not a success")
            .into_error(
                Some(crate::oauth_error::OAuthError::new("invalid_grant")),
                "cause",
            );

        assert!(
            err.verdict().is_none(),
            "a 5xx body must never become a verdict: {err:?}"
        );
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    // Unrecognized values leave the delay unspecified.
    #[rstest]
    #[case::word("soon")]
    #[case::negative("-5")]
    #[case::exponent("1e3")]
    #[case::malformed_date("Wed, 99 Xxx 2015 07:28:00 GMT")]
    fn unparseable_retry_after_leaves_the_delay_unknown(#[case] value: &str) {
        let headers = headers_with_retry_after(value);
        assert_eq!(retry_after(&headers), None);
        assert_eq!(
            status_verdict(StatusCode::SERVICE_UNAVAILABLE, &headers),
            StatusVerdict::Transient(RetryAdvice::RETRY)
        );
    }

    #[test]
    fn an_absent_retry_after_is_no_delay() {
        assert_eq!(retry_after(&HeaderMap::new()), None);
    }

    // Clamp excessive delays instead of discarding the server's constraint.
    #[rstest]
    #[case::a_week("604800")]
    #[case::just_over("86401")]
    #[case::max("18446744073709551615")]
    // The ceiling itself is unchanged.
    #[case::the_ceiling("86400")]
    fn an_oversized_delay_is_clamped_rather_than_discarded(#[case] value: &str) {
        assert_eq!(
            retry_after(&headers_with_retry_after(value)),
            Some(MAX_RETRY_AFTER)
        );
    }

    // RFC 9110 allows an HTTP-date as well as delta-seconds.
    #[test]
    fn the_http_date_form_is_read_as_a_delay() {
        let in_a_minute = crate::platform::SystemTime::now() + Duration::from_mins(1);
        // `httpdate` renders the preferred IMF-fixdate form.
        let rendered = httpdate::fmt_http_date(
            std::time::UNIX_EPOCH
                + in_a_minute
                    .duration_since(crate::platform::SystemTime::UNIX_EPOCH)
                    .expect("after the epoch"),
        );

        let delay = retry_after(&headers_with_retry_after(&rendered)).expect("a date is a delay");
        // Allow for whole-second precision and time elapsed during the test.
        assert!(
            delay <= Duration::from_mins(1) && delay >= Duration::from_secs(55),
            "got {delay:?}"
        );
    }

    // RFC 9110 requires recipients to accept all three HTTP-date spellings.
    // Each case is in the past and therefore means retry now.
    #[rstest]
    #[case::imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT")]
    #[case::rfc850("Sunday, 06-Nov-94 08:49:37 GMT")]
    #[case::asctime("Sun Nov  6 08:49:37 1994")]
    fn every_http_date_spelling_is_accepted(#[case] value: &str) {
        assert_eq!(
            retry_after(&headers_with_retry_after(value)),
            Some(Duration::ZERO)
        );
    }

    // Parse numeric values directly, without consulting the clock.
    #[test]
    fn delta_seconds_wins_over_the_clock() {
        let headers = headers_with_retry_after("30");
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(30)));
        assert_eq!(
            status_verdict(StatusCode::TOO_MANY_REQUESTS, &headers),
            StatusVerdict::Transient(RetryAdvice::retry_after(Duration::from_secs(30)))
        );
    }

    #[derive(Debug)]
    struct Cause;

    impl std::fmt::Display for Cause {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("cause")
        }
    }

    impl std::error::Error for Cause {}

    #[derive(Debug)]
    struct ClassifiedCause(Error);

    impl std::fmt::Display for ClassifiedCause {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("wrapping an already-classified failure")
        }
    }

    impl std::error::Error for ClassifiedCause {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    // `into_error` must not replace a classification already in the cause.
    #[test]
    #[should_panic(expected = "`Error::new` was handed a cause wrapping an already-classified")]
    fn into_error_rejects_an_already_classified_cause() {
        let cause = ClassifiedCause(Error::new(RetryAdvice::RETRY, "backend failure"));
        let _ = FailedResponse::new(StatusCode::BAD_REQUEST, &HeaderMap::new())
            .expect("non-success")
            .into_error(None, cause);
    }

    // Only non-success statuses can construct `FailedResponse`.
    #[rstest]
    #[case::ok(StatusCode::OK, false)]
    #[case::created(StatusCode::CREATED, false)]
    #[case::no_content(StatusCode::NO_CONTENT, false)]
    #[case::last_success(StatusCode::from_u16(299).unwrap(), false)]
    #[case::redirect(StatusCode::MOVED_PERMANENTLY, true)]
    #[case::bad_request(StatusCode::BAD_REQUEST, true)]
    #[case::unavailable(StatusCode::SERVICE_UNAVAILABLE, true)]
    fn a_success_is_not_a_failed_response(#[case] status: StatusCode, #[case] is_failure: bool) {
        assert_eq!(
            FailedResponse::new(status, &HeaderMap::new()).is_some(),
            is_failure
        );
    }

    // The body supplies a verdict only when the status is undecided.
    #[test]
    fn only_an_undecided_status_lets_the_body_be_a_verdict() {
        let none = HeaderMap::new();
        let cases = [
            (StatusCode::BAD_REQUEST, None, false),
            (
                StatusCode::BAD_REQUEST,
                Some(OAuthError::new("invalid_grant")),
                true,
            ),
            (StatusCode::SERVICE_UNAVAILABLE, None, false),
            (
                StatusCode::TOO_MANY_REQUESTS,
                Some(OAuthError::new("slow_down")),
                false,
            ),
        ];
        for (status, verdict, is_oauth) in cases {
            let err = FailedResponse::new(status, &none)
                .expect("non-success")
                .into_error(verdict, Cause);
            assert_eq!(
                err.verdict().is_some(),
                is_oauth,
                "{status}: verdict only where the status was undecided"
            );
        }
    }

    // A gateway's OAuth-shaped body must not override a transient status.
    #[test]
    fn a_transient_status_outranks_the_body() {
        let err = FailedResponse::new(StatusCode::SERVICE_UNAVAILABLE, &HeaderMap::new())
            .expect("non-success")
            .into_error(Some(OAuthError::new("invalid_grant")), Cause);

        assert_eq!(err.retry_advice(), RetryAdvice::RETRY);
    }

    // RFC 6749 uses these codes to carry retryable server failures in redirects.
    #[rstest]
    #[case::temporarily_unavailable("temporarily_unavailable")]
    #[case::server_error("server_error")]
    fn a_rejection_naming_a_server_condition_is_retryable(#[case] code: &str) {
        let err = FailedResponse::new(StatusCode::BAD_REQUEST, &HeaderMap::new())
            .expect("non-success")
            .into_error(Some(OAuthError::new(code)), Cause);

        assert_eq!(err.retry_advice(), RetryAdvice::RETRY);
        // Preserve the verdict as well as its retry advice.
        assert_eq!(err.verdict().map(|v| v.code().as_str()), Some(code));
    }

    // Preserve `Retry-After` for retryable OAuth verdicts.
    #[test]
    fn a_retryable_rejection_honours_retry_after() {
        let headers = headers_with_retry_after("30");
        let err = FailedResponse::new(StatusCode::BAD_REQUEST, &headers)
            .expect("non-success")
            .into_error(Some(OAuthError::new("temporarily_unavailable")), Cause);

        assert_eq!(
            err.retry_advice(),
            RetryAdvice::retry_after(Duration::from_secs(30))
        );
    }

    // Ordinary OAuth rejections remain terminal.
    #[rstest]
    #[case::access_denied("access_denied")]
    #[case::invalid_grant("invalid_grant")]
    #[case::invalid_scope("invalid_scope")]
    fn an_ordinary_rejection_stays_terminal(#[case] code: &str) {
        let err = FailedResponse::new(StatusCode::BAD_REQUEST, &HeaderMap::new())
            .expect("non-success")
            .into_error(Some(OAuthError::new(code)), Cause);

        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    // `Retry-After` supplies timing but cannot make a terminal code retryable.
    #[test]
    fn a_retry_after_does_not_make_a_terminal_rejection_retryable() {
        let headers = headers_with_retry_after("30");
        let err = FailedResponse::new(StatusCode::BAD_REQUEST, &headers)
            .expect("non-success")
            .into_error(Some(OAuthError::new("invalid_grant")), Cause);

        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    // Preserve `Retry-After` through conversion to `Error`.
    #[test]
    fn into_error_honours_retry_after() {
        let headers = headers_with_retry_after("42");
        let err = FailedResponse::new(StatusCode::TOO_MANY_REQUESTS, &headers)
            .expect("non-success")
            .into_error(None, Cause);

        assert_eq!(
            err.retry_advice(),
            RetryAdvice::retry_after(Duration::from_secs(42))
        );
    }

    // A verdict distinguishes a request rejection from an unusable 4xx response.
    #[test]
    fn a_verdict_is_what_makes_a_4xx_a_rejection() {
        let none = HeaderMap::new();
        let failed = || FailedResponse::new(StatusCode::FORBIDDEN, &none).expect("non-success");

        let judged = failed().into_error(Some(OAuthError::new("invalid_scope")), Cause);
        assert_eq!(
            judged.verdict().map(|v| v.code().as_str()),
            Some("invalid_scope")
        );
        assert_eq!(judged.retry_advice(), RetryAdvice::No);

        let unusable = failed().into_error(None, Cause);
        assert!(unusable.verdict().is_none());
        assert_eq!(unusable.retry_advice(), RetryAdvice::No);
    }

    // Tolerate common whitespace padding.
    #[test]
    fn retry_after_tolerates_surrounding_whitespace() {
        assert_eq!(
            retry_after(&headers_with_retry_after(" 12 ")),
            Some(Duration::from_secs(12))
        );
    }

    #[derive(Debug, serde::Deserialize)]
    struct Doc {
        value: u32,
    }

    fn uri() -> http::Uri {
        http::Uri::from_static("https://example.com/doc")
    }

    #[tokio::test]
    async fn get_deserializes_through_dyn_client() {
        let client = FakeClient::new(StatusCode::OK, r#"{"value": 7}"#);
        let dyn_client: &dyn HttpClient = &client;
        let doc: Doc = get(dyn_client, uri(), HeaderMap::new())
            .await
            .expect("get succeeds");
        assert_eq!(doc.value, 7);
    }

    // Document GETs classify 5xx responses as transient.
    #[tokio::test]
    async fn get_classifies_a_5xx_as_a_retryable_server_condition() {
        let client = FakeClient::new(StatusCode::INTERNAL_SERVER_ERROR, "");
        let err = get::<Doc>(&client, uri(), HeaderMap::new())
            .await
            .expect_err("non-2xx fails");
        assert_eq!(err.retry_advice(), RetryAdvice::RETRY);
        assert!(err.verdict().is_none());
    }

    // A throttled document fetch preserves the server's delay.
    #[tokio::test]
    async fn get_carries_retry_after_through() {
        let client = FakeClient {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: "",
            retry_after: Some("15"),
        };
        let err = get::<Doc>(&client, uri(), HeaderMap::new())
            .await
            .expect_err("429 fails");
        assert_eq!(
            err.retry_advice(),
            RetryAdvice::retry_after(Duration::from_secs(15))
        );
    }

    // A document endpoint's 4xx response is terminal.
    #[tokio::test]
    async fn get_classifies_a_4xx_as_protocol() {
        let client = FakeClient::new(StatusCode::NOT_FOUND, "");
        let err = get::<Doc>(&client, uri(), HeaderMap::new())
            .await
            .expect_err("non-2xx fails");
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    #[tokio::test]
    async fn erased_clients_still_implement_the_trait() {
        fn takes_impl(_: &impl HttpClient) {}

        let arc: Arc<dyn HttpClient> = Arc::new(FakeClient::new(StatusCode::OK, r#"{"value": 1}"#));
        // Blanket implementations preserve dynamic dispatch.
        takes_impl(&arc);
        let boxed: Box<dyn HttpClient> =
            Box::new(FakeClient::new(StatusCode::OK, r#"{"value": 2}"#));
        takes_impl(&boxed);
        let doc: Doc = get(&arc, uri(), HeaderMap::new()).await.expect("get");
        assert_eq!(doc.value, 1);
    }
}
