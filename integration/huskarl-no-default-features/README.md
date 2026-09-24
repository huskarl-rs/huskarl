# Tests without default features

Run with:

```sh
cargo test --manifest-path integration/huskarl-no-default-features/Cargo.toml
```

This standalone workspace prevents the main workspace's dev-dependencies from
implicitly enabling the default JWS verifier platform. It checks configuration
errors, explicit platform support, and UserInfo's resolved-verifier precedence.
