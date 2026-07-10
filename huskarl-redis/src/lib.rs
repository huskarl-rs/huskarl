//! Redis-backed replay prevention for the huskarl (`OAuth2`) ecosystem.
//!
//! Provides [`jti::RedisJtiUniquenessChecker`], a
//! [`JtiUniquenessChecker`](huskarl_core::jwt::JtiUniquenessChecker) that
//! shares its seen-set across server replicas — replay prevention for JWT
//! `jti` claims and server-side `DPoP` proofs.
//!
//! ```no_run
//! # async fn wire() -> Result<(), Box<dyn std::error::Error>> {
//! use std::{sync::Arc, time::Duration};
//!
//! use huskarl_core::jwt::JtiUniquenessChecker;
//! use huskarl_redis::jti::RedisJtiUniquenessChecker;
//!
//! let client = redis::Client::open("redis://127.0.0.1/")?;
//! let connection = client.get_multiplexed_async_connection().await?;
//!
//! let checker: Arc<dyn JtiUniquenessChecker> = Arc::new(
//!     RedisJtiUniquenessChecker::builder()
//!         .connection(connection)
//!         // Must cover the validator's acceptance window plus clock leeway.
//!         .ttl(Duration::from_mins(5))
//!         .build(),
//! );
//! # drop(checker);
//! # Ok(())
//! # }
//! ```
//!
//! Hand the `Arc` to whichever validator should enforce uniqueness:
//! huskarl-core's `JwtValidator` (`jti_checker`), or huskarl-resource-server's
//! RFC 9068 validator (`jti_checker` for access-token `jti`s,
//! `dpop_jti_checker` for `DPoP` proof `jti`s).
//!
//! For automatic reconnection, build the checker on redis's
//! `ConnectionManager` (behind the redis crate's `connection-manager`
//! feature) instead of the multiplexed connection shown above.
//!
//! # Runtime
//!
//! The default `tokio-comp` feature enables redis's feature of the same
//! name. If your application's redis dependency already enables a runtime,
//! opt out with `default-features = false`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]

pub mod jti;

use redis::RedisError;

/// Everything except `NoRetry` (reconnects, wait-and-retry, redirects) may
/// succeed on a re-send. This only classifies; whether a re-send is *safe*
/// is per-command — argue it at the call site.
fn transport_error(source: RedisError, context: &'static str) -> huskarl_core::Error {
    let retryable = !matches!(source.retry_method(), redis::RetryMethod::NoRetry);
    huskarl_core::Error::new(huskarl_core::ErrorKind::Transport { retryable }, source)
        .with_context(context)
}

#[cfg(test)]
mod tests {
    use huskarl_core::ErrorKind;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::reconnectable_io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into(), true)]
    #[case::forbidden_io(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into(), false)]
    #[case::wrong_type((redis::ErrorKind::UnexpectedReturnType, "not a bool").into(), false)]
    fn classifies_retryability_from_retry_method(
        #[case] source: RedisError,
        #[case] retryable: bool,
    ) {
        assert_eq!(
            transport_error(source, "testing").kind(),
            ErrorKind::Transport { retryable }
        );
    }
}
