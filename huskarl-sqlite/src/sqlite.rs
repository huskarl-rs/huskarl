use std::{
    ops::Deref,
    time::{Duration, SystemTime, SystemTimeError},
};

use sqlx::{Error as SqlxError, sqlite::SqliteExecutor};

use crate::jti::SqliteJtiCheckerConfig;

/// Enumueration of errors that can be returned by internal database operations.
#[derive(Debug, thiserror::Error)]
pub(super) enum SqliteClientError {
    #[error("database client returned error: {0}")]
    Database(#[from] SqlxError),
    #[error("conversion to sqlite integer type failed: {0}")]
    Convert(#[from] std::num::TryFromIntError),
    #[error("system time not synced: {0}")]
    Sync(#[from] SystemTimeError),
}

impl SqliteClientError {
    pub(super) fn is_retriable(&self) -> bool {
        // What else to retry?
        matches!(self, Self::Database(SqlxError::PoolTimedOut))
    }
}

/// Underlying SQLite connection pool.
#[derive(Debug, Clone)]
pub(super) struct SqliteClient {
    pool: sqlx::SqlitePool,
}

impl SqliteClient {
    /// Intialize the SQLite backend and client.
    pub(super) async fn new(config: SqliteJtiCheckerConfig) -> Result<Self, SqliteClientError> {
        let pool = config
            .pool_options
            .connect_with(config.connect_options)
            .await?;
        let this = Self { pool };
        this.init().await?;
        Ok(this)
    }

    /// Create the SQLite schema to support the JTI replay checker.
    ///
    /// Skips if the supporting objects already exist.
    pub(super) async fn init(&self) -> Result<(), SqliteClientError> {
        let mut tx = self.pool.begin().await?;
        create_table(&mut *tx).await?;
        create_index(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Check to see if this JTI was attached to a previously issued token.
    pub(super) async fn check_issued(
        &self,
        key: Vec<u8>,
        ttl: Duration,
    ) -> Result<bool, SqliteClientError> {
        let (now, expiry) = self.expiry_millis(ttl)?;
        check_issued_or_insert(&**self, &key, now, expiry).await
    }

    /// Get the expiration of a JTI in unix epoch milliseconds.
    ///
    /// Returns a tuple (now, expiry) of the unix epoch timestamp of the time
    /// the expiry was calculated, and the expiry itself.
    // TODO(dmd): Is below the correct method of handling some clock/time
    // weirdness? huskarl-redis sets the expiry to be 1 ms if the u128 -> u64
    // conversion fails, so I'm maintaining that behavior, but when do we just want to exist w/ error?
    fn expiry_millis(&self, ttl: Duration) -> Result<(i64, i64), SqliteClientError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(SqliteClientError::Sync)?;
        let now = i64::try_from(now.as_millis())?;
        let ttl = i64::try_from(ttl.as_millis()).unwrap_or_default();
        let expiry = now.saturating_add(ttl);
        Ok((now, expiry))
    }
}

impl Deref for SqliteClient {
    type Target = sqlx::SqlitePool;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

/// Initialize the SQLite schema.
async fn create_table<'c, C: SqliteExecutor<'c>>(conn: C) -> Result<(), SqliteClientError> {
    sqlx::query(
        "
CREATE TABLE IF NOT EXISTS issued (
  key blob PRIMARY KEY NOT NULL,
  expires_at integer NOT NULL
);
",
    )
    .execute(conn)
    .await?;
    Ok(())
}

async fn create_index<'c, C: SqliteExecutor<'c>>(conn: C) -> Result<(), SqliteClientError> {
    sqlx::query(
        "
CREATE INDEX IF NOT EXISTS issued_expires_at_idx
  ON issued (expires_at DESC);
",
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Insert a hashed JTI into the table with the given expiry.
///
/// Returns `true` if the key has been previously issued and is not expired.
async fn check_issued_or_insert<'c, C: SqliteExecutor<'c>>(
    conn: C,
    key: &[u8],
    now: i64,
    expiry: i64,
) -> Result<bool, SqliteClientError> {
    sqlx::query(
        "
INSERT INTO issued (key, expires_at) VALUES (?, ?)
ON CONFLICT (key) DO
  UPDATE SET expires_at = ?
  WHERE issued.expires_at <= ?
RETURNING 1;
",
    )
    .bind(key)
    .bind(expiry)
    .bind(expiry)
    .bind(now)
    .execute(conn)
    .await
    .map(|r| r.rows_affected() == 0) // 0 if the key exists and is not expired
    .map_err(SqliteClientError::from)
}
