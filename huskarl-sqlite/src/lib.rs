//! Local SQLite storage for replay prevention in the huskarl (OAuth 2.0) ecosystem.
pub mod jti;

mod sqlite;
use sqlite::SqliteClientError;

/// The cause of a SQLite error.
#[derive(Debug, snafu::Snafu)]
#[snafu(display("{operation}"))]
struct SqliteOperationError {
    /// What was being attempted.
    operation: &'static str,
    /// The underlying error.
    source: SqliteClientError,
}

fn core_err(operation: &'static str) -> impl FnOnce(SqliteClientError) -> huskarl_core::Error {
    move |source| transport_error(SqliteOperationError { operation, source })
}

#[track_caller]
fn transport_error(err: SqliteOperationError) -> huskarl_core::Error {
    huskarl_core::Error::new(
        huskarl_core::RetryAdvice::retry_if(err.source.is_retriable()),
        err,
    )
}
