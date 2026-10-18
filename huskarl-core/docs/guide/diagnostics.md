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
