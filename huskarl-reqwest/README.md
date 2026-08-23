<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

An [`HttpClient`](https://docs.rs/huskarl_core/latest/huskarl_core/http/trait.HttpClient.html) for the huskarl crates, backed by [`reqwest`](https://docs.rs/reqwest/latest/reqwest/).

[`ReqwestClient`](https://docs.rs/huskarl-reqwest/latest/huskarl_reqwest/struct.ReqwestClient.html) is the entry point — build one with its `builder()` and
hand it to a grant, authorizer, or validator. The [`mtls`](https://docs.rs/huskarl-reqwest/latest/huskarl_reqwest/mtls/) module supplies
the mTLS providers (RFC 8705) for the builder.

# Example

```rust
use huskarl_reqwest::ReqwestClient;

let http_client = ReqwestClient::builder().build().await?;
```

<!-- cargo-reedme: end -->
