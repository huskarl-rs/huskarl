<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Redis-backed replay prevention for the huskarl (`OAuth2`) ecosystem.

Provides [`jti::RedisJtiUniquenessChecker`](https://docs.rs/huskarl-redis/latest/huskarl_redis/jti/struct.RedisJtiUniquenessChecker.html), a
[`JtiUniquenessChecker`](https://docs.rs/huskarl_core/latest/huskarl_core/jwt/jti/trait.JtiUniquenessChecker.html) that
shares its seen-set across server replicas — replay prevention for JWT
`jti` claims and server-side `DPoP` proofs.

```rust
use std::{sync::Arc, time::Duration};

use huskarl_core::jwt::JtiUniquenessChecker;
use huskarl_redis::jti::RedisJtiUniquenessChecker;

let client = redis::Client::open("redis://127.0.0.1/")?;
let connection = client.get_multiplexed_async_connection().await?;

let checker: Arc<dyn JtiUniquenessChecker> = Arc::new(
    RedisJtiUniquenessChecker::builder()
        .connection(connection)
        // Must cover the validator's acceptance window plus clock leeway.
        .ttl(Duration::from_mins(5))
        .key_prefix("jti:")
        .build(),
);
```

Hand the `Arc` to whichever validator should enforce uniqueness:
huskarl-core’s `JwtValidator` (`jti_checker`), or huskarl-resource-server’s
RFC 9068 validator (`jti_checker` for access-token `jti`s,
`dpop_jti_checker` for `DPoP` proof `jti`s).

For automatic reconnection, build the checker on redis’s
`ConnectionManager` (behind the redis crate’s `connection-manager`
feature) instead of the multiplexed connection shown above.

# Runtime

The default `tokio-comp` feature enables redis’s feature of the same
name. If your application’s redis dependency already enables a runtime,
opt out with `default-features = false`.

<!-- cargo-reedme: end -->
