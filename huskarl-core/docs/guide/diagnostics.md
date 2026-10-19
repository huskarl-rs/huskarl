# Enable diagnostic tracing

Enable the optional `tracing` feature on the crates your application uses:

```toml
[dependencies]
huskarl = { version = "0.11.6", features = ["tracing"] }
huskarl-resource-server = { version = "0.11.9", features = ["tracing"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

Both Huskarl features also enable `huskarl-core/tracing`. Applications using core
directly can enable its feature themselves. All three features are off by default.
Huskarl installs no subscriber, exporter, global filter, or background collector.
Your application owns those choices.

Initialize a subscriber once, in the application:

```ignore
tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .init();
```

Start with `RUST_LOG=info,huskarl=debug,huskarl_core=debug,huskarl_resource_server=debug`.
If necessary, narrow a TRACE filter to one module, for example
`RUST_LOG=info,huskarl::cache=trace`. `RUST_LOG` only works when the application's
subscriber reads it, as in this example. A subscriber can also filter its console
and OpenTelemetry layers independently.

Use INFO for token acquisition and authorization-code completion summaries. DEBUG reports
completed token exchanges (type, lifetime, and presence of refresh/ID tokens),
ID-token validation results, interactive login progress, failures, and recovery
decisions. TRACE adds policy selections, routine request and cache activity,
successful HTTP statuses, and low-level validation and cryptographic detail.
Resource-server validation reports successful validation and absent tokens at TRACE,
and rejected requests at DEBUG. Events inherit the caller's current application span.

Huskarl does not directly record token values, private key material,
secret-manager values, or request URL paths and query strings. Key IDs, metric
wrapper names, hostnames, and grant-type identifiers may appear verbatim. Choose
identifiers without sensitive data: a metric wrapper name containing a URL will
include its path and query string in traces. Arbitrary extra metric labels are
not copied into traces. Configure application and dependency logging separately.

The `huskarl-reqwest`, `huskarl-redis`, and `huskarl-google-cloud` adapters also
have optional `tracing` features that forward to core. Enable each adapter's
feature separately. Use targets `huskarl_reqwest`, `huskarl_redis`, and
`huskarl_google_cloud` to filter their events.

Google Cloud emits page summaries and selection decisions on its normal target.
Its child target `huskarl_google_cloud::api` adds per-version API metadata before
conversion. For decisions only, use
`RUST_LOG=huskarl_google_cloud=trace,huskarl_google_cloud::api=off`; set the child
target to `trace` for the API view. A parent TRACE filter alone enables both.
Full resource names appear in selection and selection-failure events; other
events use version IDs. State and algorithm names use the API's protocol names, with unknown values
normalized to `unknown`. API filters and configured listing limits still apply;
traces are not a complete resource inventory. Secret values, key bytes,
cryptographic payloads, page tokens and raw service error messages are excluded.

The `huskarl-crypto-native` and `huskarl-crypto-webcrypto` backends provide the
same optional feature, enabled separately and forwarding to core. Filter with
`huskarl_crypto_native` or `huskarl_crypto_webcrypto`, for example
`RUST_LOG=info,huskarl_crypto_native=trace,huskarl_crypto_webcrypto=trace`.
TRACE covers key setup and
cryptographic operation spans; DEBUG reports fixed failure categories. These
backends exclude key IDs, key material, signatures, cryptographic inputs and
outputs, and raw backend errors (including JavaScript errors).
