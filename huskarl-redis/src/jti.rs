//! Replay prevention: a Redis-backed [`JtiUniquenessChecker`].

use std::time::Duration;

use huskarl_core::{jwt::JtiUniquenessChecker, platform::MaybeSendSync};
use redis::{AsyncCommands as _, SetOptions, aio::ConnectionLike};
use sha2::{Digest as _, Sha256};

use crate::transport_error;

/// A [`JtiUniquenessChecker`] backed by Redis, for replay prevention shared
/// across server instances.
///
/// Each check is a single atomic `SET NX PX` on the key
/// `{key_prefix}{lowercase hex of SHA-256(jti)}`; hashing keeps
/// token-supplied bytes out of the key space and makes keys fixed-size. To
/// find the entry for a known JTI, hash it the same way.
///
/// This checker fails closed: if Redis is unreachable, it returns a retryable
/// error and validation rejects the token.
///
/// # TTL sizing
///
/// `ttl` must cover the full window in which a replayed token would otherwise
/// still validate: the validator's acceptance window (the `DPoP` `iat` window,
/// or the maximum accepted token lifetime) plus clock leeway. A too-short TTL
/// silently reopens the replay window.
#[derive(Clone, bon::Builder)]
pub struct RedisJtiUniquenessChecker<C> {
    /// The Redis connection, cloned per check. Use a cheaply clonable
    /// connection such as `MultiplexedConnection` or `ConnectionManager`
    /// (the latter needs the redis crate's `connection-manager` feature).
    connection: C,
    /// How long a seen JTI is remembered. See the type docs for sizing.
    ttl: Duration,
    /// Key prefix; give each checker sharing a Redis database its own prefix (e.g. `jti:`).
    #[builder(into)]
    key_prefix: String,
}

impl<C> std::fmt::Debug for RedisJtiUniquenessChecker<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisJtiUniquenessChecker")
            .field("ttl", &self.ttl)
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
}

impl<C: ConnectionLike + Clone + MaybeSendSync> JtiUniquenessChecker
    for RedisJtiUniquenessChecker<C>
{
    fn check_and_mark_seen(
        &self,
        jti: &str,
    ) -> huskarl_core::platform::MaybeSendBoxFuture<'_, Result<bool, huskarl_core::Error>> {
        let mut connection = self.connection.clone();
        // Hash the token-supplied JTI so keys are fixed-size and uniform no
        // matter what the caller lets through.
        let key = format!("{}{}", self.key_prefix, hex::encode(Sha256::digest(jti)));
        // Redis rejects PX 0, so clamp to the minimum expiry it accepts.
        let px = u64::try_from(self.ttl.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let opts = SetOptions::default()
            .with_expiration(redis::SetExpiry::PX(px))
            .conditional_set(redis::ExistenceCheck::NX);

        Box::pin(async move {
            let set: bool = connection
                .set_options(key, 1, opts)
                .await
                // Re-sending a retryable failure is safe for this command:
                // a duplicate `SET NX` can only err toward "seen".
                .map_err(|source| transport_error(source, "checking JTI uniqueness in Redis"))?;

            Ok(!set)
        })
    }
}

#[cfg(test)]
mod tests {
    use redis::{ExistenceCheck, RedisError, SetExpiry, Value};
    use redis_test::{MockCmd, MockRedisConnection};
    use rstest::rstest;

    use super::*;

    const JTI: &str = "test-jti";
    /// Lowercase hex of `SHA-256("test-jti")`; pins the key-derivation scheme.
    const JTI_HEX: &str = "63288f218c3de4ee5c260eaf76e4078c05fae857846a2beed41badfc35d2dd13";

    /// The exact command the checker must send: `SET {key} 1 PX {px} NX`.
    fn expected_set(key: &str, px: u64) -> redis::Cmd {
        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(1).arg(
            SetOptions::default()
                .with_expiration(SetExpiry::PX(px))
                .conditional_set(ExistenceCheck::NX),
        );
        cmd
    }

    #[rstest]
    #[case::newly_marked(Value::Okay, false)]
    #[case::already_seen(Value::Nil, true)]
    #[tokio::test]
    async fn maps_set_nx_reply_to_seen(#[case] reply: Value, #[case] seen: bool) {
        let mock = MockRedisConnection::new(vec![MockCmd::new(
            expected_set(&format!("jti:{JTI_HEX}"), 300_000),
            Ok(reply),
        )])
        .assert_all_commands_consumed();
        let checker = RedisJtiUniquenessChecker::builder()
            .connection(mock)
            .ttl(Duration::from_mins(5))
            .key_prefix("jti:")
            .build();

        assert_eq!(checker.check_and_mark_seen(JTI).await.unwrap(), seen);
    }

    #[tokio::test]
    async fn custom_prefix_and_minimum_px() {
        let mock = MockRedisConnection::new(vec![MockCmd::new(
            expected_set(&format!("dpop:{JTI_HEX}"), 1),
            Ok(Value::Okay),
        )])
        .assert_all_commands_consumed();
        let checker = RedisJtiUniquenessChecker::builder()
            .connection(mock)
            .ttl(Duration::ZERO)
            .key_prefix("dpop:")
            .build();

        assert!(!checker.check_and_mark_seen(JTI).await.unwrap());
    }

    #[tokio::test]
    async fn redis_failure_maps_to_transport() {
        let refused = RedisError::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        let mock = MockRedisConnection::new(vec![MockCmd::new(
            expected_set(&format!("jti:{JTI_HEX}"), 300_000),
            Err::<Value, _>(refused),
        )]);
        let checker = RedisJtiUniquenessChecker::builder()
            .connection(mock)
            .ttl(Duration::from_mins(5))
            .key_prefix("jti:")
            .build();

        let err = checker.check_and_mark_seen(JTI).await.unwrap_err();
        assert_eq!(err.retry_advice(), huskarl_core::RetryAdvice::RETRY);
    }
}
