//! Exercises [`RedisJtiUniquenessChecker`] against a real Redis, verifying
//! that the `SET NX PX` commands behave as the unit-test mocks assume.
//!
//! Ignored by default; `mise run redis:test` (from `integration/`) brings up
//! a local Redis and runs them. To run against an existing server instead,
//! point `REDIS_URL` at it and run:
//!
//! ```sh
//! cargo test -p huskarl-redis --test redis -- --ignored
//! ```

use std::{
    fmt::Write as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use huskarl_core::jwt::JtiUniquenessChecker as _;
use huskarl_redis::jti::RedisJtiUniquenessChecker;
use redis::AsyncCommands as _;
use sha2::{Digest as _, Sha256};

async fn connection() -> redis::aio::MultiplexedConnection {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_owned());
    redis::Client::open(url)
        .expect("REDIS_URL parses")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis reachable")
}

/// A JTI unique per test run, so reruns don't collide with keys still inside
/// their TTL from a previous run.
fn fresh_jti(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    format!("{name}-{nanos}")
}

fn checker(
    connection: redis::aio::MultiplexedConnection,
    ttl: Duration,
) -> RedisJtiUniquenessChecker<redis::aio::MultiplexedConnection> {
    RedisJtiUniquenessChecker::builder()
        .connection(connection)
        .ttl(ttl)
        .key_prefix("huskarl-test:")
        .build()
}

#[tokio::test]
#[ignore = "needs a running Redis (REDIS_URL or redis://127.0.0.1/)"]
async fn first_check_marks_and_second_detects_replay() {
    let checker = checker(connection().await, Duration::from_mins(1));
    let jti = fresh_jti("replay");

    assert!(!checker.check_and_mark_seen(&jti).await.unwrap());
    assert!(checker.check_and_mark_seen(&jti).await.unwrap());
}

#[tokio::test]
#[ignore = "needs a running Redis (REDIS_URL or redis://127.0.0.1/)"]
async fn distinct_jtis_are_independent() {
    let checker = checker(connection().await, Duration::from_mins(1));

    assert!(!checker.check_and_mark_seen(&fresh_jti("a")).await.unwrap());
    assert!(!checker.check_and_mark_seen(&fresh_jti("b")).await.unwrap());
}

#[tokio::test]
#[ignore = "needs a running Redis (REDIS_URL or redis://127.0.0.1/)"]
async fn seen_set_expires_with_ttl() {
    let checker = checker(connection().await, Duration::from_millis(100));
    let jti = fresh_jti("expiry");

    assert!(!checker.check_and_mark_seen(&jti).await.unwrap());
    assert!(checker.check_and_mark_seen(&jti).await.unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The replay window has closed: the key expired and the JTI reads unseen.
    assert!(!checker.check_and_mark_seen(&jti).await.unwrap());
}

#[tokio::test]
#[ignore = "needs a running Redis (REDIS_URL or redis://127.0.0.1/)"]
async fn key_prefix_isolates_checkers() {
    let conn = connection().await;
    let jti = fresh_jti("prefix");
    for prefix in ["huskarl-test-a:", "huskarl-test-b:"] {
        let checker = RedisJtiUniquenessChecker::builder()
            .connection(conn.clone())
            .ttl(Duration::from_mins(1))
            .key_prefix(prefix)
            .build();
        assert!(
            !checker.check_and_mark_seen(&jti).await.unwrap(),
            "the same JTI under prefix {prefix} must be unseen"
        );
    }
}

#[tokio::test]
#[ignore = "needs a running Redis (REDIS_URL or redis://127.0.0.1/)"]
async fn stores_documented_hashed_key_with_ttl() {
    let ttl = Duration::from_mins(1);
    let mut conn = connection().await;
    let checker = checker(conn.clone(), ttl);
    let jti = fresh_jti("key-shape");

    assert!(!checker.check_and_mark_seen(&jti).await.unwrap());

    // The docs promise the entry lives at `{key_prefix}{hex of SHA-256(jti)}`.
    let mut key = String::from("huskarl-test:");
    for b in Sha256::digest(&jti) {
        write!(key, "{b:02x}").unwrap();
    }
    assert!(conn.exists::<_, bool>(&key).await.unwrap());
    let pttl: i64 = conn.pttl(&key).await.unwrap();
    assert!(
        pttl > 0 && pttl <= i64::try_from(ttl.as_millis()).unwrap(),
        "PTTL {pttl} outside (0, {}]",
        ttl.as_millis()
    );
}
