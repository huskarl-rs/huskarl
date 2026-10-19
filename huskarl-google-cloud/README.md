<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Google Cloud cryptographic integrations for `huskarl`.

- [`kms`](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/kms/) — Cloud KMS signers, verifiers, and AEAD ciphers (asymmetric JWS,
  symmetric HMAC and AES), with version pinning and rotation support.
- [`secretmanager`](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/secretmanager/) — a `huskarl` secret provider backed by Secret Manager.

Each integration is gated by a Cargo feature with the same name.

# Documentation

- **Solve a task:** [sign JWS and serve
  JWKS](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/asymmetric_signing/) from an asymmetric key,
  [encrypt and sign](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/symmetric_crypto/) with symmetric
  keys, [keep keys fresh](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/refreshing_keys/) under
  rotation, or [read secrets](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/secret_manager/) from
  Secret Manager.
- **Understand the design:** read how
  [versions and rotation](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/explanation/versions_and_rotation/)
  work, how keys derive a [`kid`](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/explanation/key_ids/), and
  the [error model](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/explanation/error_handling/).
- **Look up the API:** use the crate modules and item pages in this reference.

Related how-to guides and explanation live in `huskarl-core`, which defines
the traits this crate implements:

- [Providing secrets](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/providing_secrets/index.html)
- [Configuring JWT verification](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/configuring_jwt_verification/index.html)
- [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
  — how the multi-key, refreshable, and retrying wrappers stack on these keys.

# Diagnostic tracing

Enable the optional `tracing` feature to emit structured diagnostics. It also
enables `huskarl-core/tracing`; no subscriber or exporter is installed.

For decisions and page summaries, configure an application subscriber with
`RUST_LOG=huskarl_google_cloud=trace,huskarl_google_cloud::api=off`.
DEBUG spans describe boundary operations; DEBUG events report RPC status and
retry advice, version-resolution failures, missing payloads and mismatched keys.
RPC events use `rpc` for the API method, `outcome = "success"` or `"error"`,
and numeric retry delays. Failures use `reason` for specific classifications.

The child target `huskarl_google_cloud::api` retains the API view before Huskarl
converts it: version IDs, protocol state and algorithm names, and KMS creation
timestamps in Unix seconds. Unknown enum values are recorded as `unknown`.
Set that target to `trace` to enable the detail. Parent filters apply to child
targets, so `huskarl_google_cloud=trace` alone enables both views.
These events describe the configured API requests, not a complete inventory:
enabled-version filters, listing limits and caller permissions still apply.

Full resource names appear in selection and selection-failure events. Other
version identifiers use the last resource-name segment. Secret values, PEM/key
bytes, plaintext, ciphertext, signatures, page tokens, arbitrary labels and raw service error
messages are excluded. Configure Google Cloud SDK logging separately; this
policy covers Huskarl events.

<!-- cargo-reedme: end -->
