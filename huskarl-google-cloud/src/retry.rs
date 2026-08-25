//! Maps Google Cloud API failures to `huskarl` retry advice.
//!
//! A failed RPC may include a `RetryInfo` detail that specifies a minimum delay
//! before another attempt ([AIP-193]). This module preserves that information
//! when it converts the failure to [`RetryAdvice`].
//!
//! [AIP-193]: https://google.aip.dev/193

use google_cloud_gax::error::{
    Error,
    rpc::{Code, StatusDetails},
};
use huskarl_core::RetryAdvice;

/// Returns retry advice for a failed Google Cloud API call.
///
/// A failure is retryable when repeating the same request could succeed without
/// external intervention. Recovery that requires an operator to change a quota,
/// re-enable a key, or rebuild a signer does not make the failed request itself
/// retryable.
///
/// A service-provided `RetryInfo` delay takes precedence, even when the status
/// code would otherwise be classified as permanent. Without such a delay,
/// `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, HTTP 503, I/O
/// failures, and failures raised before the RPC starts are retryable. Exhaustion
/// of gax's internal retry limit or timeout is also retryable because gax had
/// already classified the underlying failures as transient.
///
/// This is broader than gax's [`Aip194Strict`] policy, which retries only
/// `UNAVAILABLE`. That policy excludes `RESOURCE_EXHAUSTED` to avoid excessive
/// load and excludes `DEADLINE_EXCEEDED` because repeating a non-idempotent
/// request may be unsafe. Callers remain responsible for their retry budget,
/// deadline, and backoff policy.
///
/// Every request made by this crate is safe to repeat, including secret reads,
/// version listings, metadata lookups, and KMS cryptographic operations.
///
/// [`Aip194Strict`]: google_cloud_gax::retry_policy::Aip194Strict
pub(crate) fn advice(error: &Error) -> RetryAdvice {
    if let Some(after) = retry_delay(error) {
        return RetryAdvice::retry_after(after);
    }
    RetryAdvice::retry_if(is_retryable(error))
}

/// Returns whether the call may succeed if repeated without a service-provided
/// delay.
fn is_retryable(error: &Error) -> bool {
    error.is_transient_and_before_rpc()
        || error.is_io()
        || error
            .status()
            .is_some_and(|s| {
                matches!(
                    s.code,
                    Code::Unavailable | Code::ResourceExhausted | Code::DeadlineExceeded
                )
            })
        // Some services report a 503 with a status of `Unknown`. That misuses
        // the gRPC codes, but the intent is unambiguous.
        || error.http_status_code() == Some(503)
        // gax's own retry loop ran out of attempts or time. Reaching either
        // means it had already judged the underlying failures retryable.
        || error.is_timeout()
        || error.is_exhausted()
}

/// The `RetryInfo` delay attached to the failed RPC, if the service sent one.
///
/// A negative delay has no [`std::time::Duration`] representation, so it is
/// ignored rather than clamped. The caller's backoff policy then determines the
/// delay.
fn retry_delay(error: &Error) -> Option<std::time::Duration> {
    error
        .status()?
        .details
        .iter()
        .find_map(|detail| match detail {
            StatusDetails::RetryInfo(info) => info.retry_delay,
            _ => None,
        })
        .and_then(|delay| std::time::Duration::try_from(delay).ok())
}

/// Creates a `RESOURCE_EXHAUSTED` failure with a `RetryInfo` delay of `seconds`.
///
/// Error-type tests use this to verify that conversion to
/// [`huskarl_core::Error`] preserves the delay.
#[cfg(test)]
pub(crate) fn quota_error_retrying_after(seconds: i64) -> Error {
    Error::service(
        google_cloud_gax::error::rpc::Status::default()
            .set_code(Code::ResourceExhausted)
            .set_details([StatusDetails::RetryInfo(
                google_cloud_rpc::model::RetryInfo::new()
                    .set_retry_delay(google_cloud_wkt::Duration::clamp(seconds, 0)),
            )]),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use google_cloud_gax::error::rpc::Status;
    use google_cloud_rpc::model::RetryInfo;
    use rstest::rstest;

    use super::*;

    fn status(code: Code) -> Status {
        Status::default().set_code(code)
    }

    fn with_retry_delay(code: Code, delay: google_cloud_wkt::Duration) -> Error {
        Error::service(status(code).set_details([StatusDetails::RetryInfo(
            RetryInfo::new().set_retry_delay(delay),
        )]))
    }

    #[test]
    fn a_server_supplied_delay_becomes_retry_after() {
        let error = with_retry_delay(
            Code::ResourceExhausted,
            google_cloud_wkt::Duration::clamp(30, 0),
        );

        assert_eq!(
            advice(&error),
            RetryAdvice::retry_after(Duration::from_secs(30))
        );
    }

    #[test]
    fn a_delay_wins_over_a_code_that_would_otherwise_be_permanent() {
        // The service knows more about its own recovery than the code does.
        let error = with_retry_delay(
            Code::Aborted,
            google_cloud_wkt::Duration::clamp(2, 500_000_000),
        );

        assert_eq!(
            advice(&error),
            RetryAdvice::retry_after(Duration::from_millis(2_500))
        );
    }

    #[test]
    fn a_negative_delay_falls_back_to_the_code() {
        // The delay cannot be represented as a `std::time::Duration`, so ignore
        // it and classify the `PermissionDenied` status instead.
        let error = with_retry_delay(
            Code::PermissionDenied,
            google_cloud_wkt::Duration::clamp(-5, 0),
        );

        assert_eq!(advice(&error), RetryAdvice::No);
    }

    #[rstest]
    // Each clears with time alone, so each is the same call succeeding later.
    #[case(Code::Unavailable, RetryAdvice::RETRY)]
    #[case(Code::ResourceExhausted, RetryAdvice::RETRY)]
    #[case(Code::DeadlineExceeded, RetryAdvice::RETRY)]
    // None of these change without someone intervening.
    #[case(Code::PermissionDenied, RetryAdvice::No)]
    #[case(Code::InvalidArgument, RetryAdvice::No)]
    #[case(Code::NotFound, RetryAdvice::No)]
    fn a_bare_status_code_is_judged_by_what_time_alone_can_fix(
        #[case] code: Code,
        #[case] expected: RetryAdvice,
    ) {
        assert_eq!(advice(&Error::service(status(code))), expected);
    }

    #[test]
    fn an_exhausted_client_retry_loop_stays_retryable() {
        // gax only reaches this after retrying, so the failure was transient.
        assert_eq!(
            advice(&Error::exhausted("too many attempts")),
            RetryAdvice::RETRY
        );
        assert_eq!(advice(&Error::timeout("deadline")), RetryAdvice::RETRY);
    }
}
