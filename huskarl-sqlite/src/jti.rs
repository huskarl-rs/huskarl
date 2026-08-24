//! Support for a [`JtiUniquenessChecker`] relying on SQLite as the backend
//! cache for storing JTIs of issued tokens.
use std::{
    fmt::{self, Debug, Formatter},
    time::Duration,
};

use huskarl_core::{jwt::JtiUniquenessChecker, platform::MaybeSendBoxFuture};
use sha2::{Digest as _, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::sqlite::SqliteClient;

/// Configuration to build a [`SqliteJtiUniquenessChecker`].
#[derive(Clone, bon::Builder)]
pub struct SqliteJtiCheckerConfig {
    /// Options to configure the SQLite client connection.
    pub(crate) connect_options: SqliteConnectOptions,
    /// Options to configure a pool of SQLite connections.
    pub(crate) pool_options: SqlitePoolOptions,
    /// How long a seen JTI is remembered. See the type docs for sizing.
    pub(crate) ttl: Duration,
}

/// A [`JtiUniquenessChecker`] with SQLite backend, for a local solution to
/// replay prevention.
#[derive(Clone)]
pub struct SqliteJtiUniquenessChecker {
    /// The SQLite connection pool backing the JTI cache.
    client: SqliteClient,
    ttl: Duration,
}

impl SqliteJtiUniquenessChecker {
    /// Initialize the JTI cache and checker from configuration.
    pub async fn new(config: SqliteJtiCheckerConfig) -> Result<Self, huskarl_core::Error> {
        let ttl = config.ttl;
        let client = SqliteClient::new(config)
            .await
            .map_err(super::core_err("initialization"))?;

        Ok(Self { client, ttl })
    }
}

impl Debug for SqliteJtiUniquenessChecker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteJtiUniquenessChecker")
            .field("client", &self.client)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl JtiUniquenessChecker for SqliteJtiUniquenessChecker {
    fn check_and_mark_seen(
        &self,
        jti: &str,
    ) -> MaybeSendBoxFuture<'_, Result<bool, huskarl_core::Error>> {
        let key = hex::encode(Sha256::digest(jti));

        Box::pin(async move {
            self.client
                .check_issued(key.into(), self.ttl)
                .await
                .map_err(super::core_err("checking JTI uniqueness in SQLite"))
        })
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    const JTI: &str = "test-jti";
    const JTI_HEX: &str = "63288f218c3de4ee5c260eaf76e4078c05fae857846a2beed41badfc35d2dd13";
    const OTHER_JTI: &str = "other-jti";

    /// Build an in-memory checker config with the given TTL.
    fn config(ttl: Duration) -> SqliteJtiCheckerConfig {
        SqliteJtiCheckerConfig::builder()
            .connect_options(SqliteConnectOptions::new().in_memory(true))
            .pool_options(SqlitePoolOptions::new().max_connections(1))
            .ttl(ttl)
            .build()
    }

    #[fixture]
    fn expired() -> SqliteJtiCheckerConfig {
        config(Duration::from_millis(0))
    }

    #[fixture]
    fn not_expired() -> SqliteJtiCheckerConfig {
        config(Duration::from_secs(300))
    }

    #[fixture]
    fn max_ttl() -> SqliteJtiCheckerConfig {
        config(Duration::MAX)
    }

    #[rstest]
    #[tokio::test]
    async fn expired_jti_returns_false(expired: SqliteJtiCheckerConfig) {
        let checker = SqliteJtiUniquenessChecker::new(expired)
            .await
            .expect("could not create test db");
        assert!(
            !checker
                .check_and_mark_seen(JTI)
                .await
                .is_ok_and(std::convert::identity)
        );
        assert!(
            !checker
                .check_and_mark_seen(JTI)
                .await
                .is_ok_and(std::convert::identity)
        );
    }

    #[rstest]
    #[tokio::test]
    async fn not_expired_jti_returns_true(not_expired: SqliteJtiCheckerConfig) {
        let checker = SqliteJtiUniquenessChecker::new(not_expired)
            .await
            .expect("could not create test db");
        assert!(
            !checker
                .check_and_mark_seen(JTI)
                .await
                .is_ok_and(std::convert::identity)
        );
        assert!(
            checker
                .check_and_mark_seen(JTI)
                .await
                .is_ok_and(std::convert::identity)
        );
    }

    #[rstest]
    #[tokio::test]
    async fn distinct_jtis_return_false(not_expired: SqliteJtiCheckerConfig) {
        let checker = SqliteJtiUniquenessChecker::new(not_expired)
            .await
            .expect("could not create test db");
        assert!(
            !checker
                .check_and_mark_seen(JTI)
                .await
                .is_ok_and(std::convert::identity)
        );
        assert!(
            !checker
                .check_and_mark_seen(OTHER_JTI)
                .await
                .is_ok_and(std::convert::identity)
        );
    }

    #[rstest]
    #[tokio::test]
    async fn check_key_sha256(not_expired: SqliteJtiCheckerConfig) {
        let checker = SqliteJtiUniquenessChecker::new(not_expired)
            .await
            .expect("could not create test db");
        assert!(
            !checker
                .check_and_mark_seen(JTI)
                .await
                .is_ok_and(std::convert::identity)
        );

        // Check that the hashed JTI roundtrip is sound.
        let stored: Vec<u8> = sqlx::query_scalar("SELECT key FROM issued")
            .fetch_one(&*checker.client)
            .await
            .expect("could not read back stored key");
        assert_eq!(String::from_utf8(stored).unwrap(), JTI_HEX);
        assert_eq!(JTI_HEX, hex::encode(Sha256::digest(JTI)));
    }
}
