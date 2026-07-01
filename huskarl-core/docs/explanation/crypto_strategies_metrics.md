## Observability

A fifth wrapper family, available behind the `metrics` feature, cross-cuts the
rest: [`MetricsJwsVerifier`](crate::crypto::verifier::MetricsJwsVerifier) and
[`MetricsAeadDecryptor`](crate::crypto::cipher::MetricsAeadDecryptor) wrap any
layer to emit counters and timings without changing its behaviour.
