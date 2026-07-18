## Observability

A fifth wrapper family, available behind the `metrics` feature, cross-cuts the
rest: [`MetricsJwsVerifier`](crate::crypto::verifier::MetricsJwsVerifier),
[`MetricsAeadDecryptor`](crate::crypto::cipher::MetricsAeadDecryptor), and
[`MetricsAeadEncryptorSelector`](crate::crypto::cipher::MetricsAeadEncryptorSelector)
wrap any layer to emit counters and timings without changing its behaviour.

Key selection and encryption are distinct events on distinct traits — a
selection resolves rotation to a concrete key, an encryption uses it — so the
encrypt-side wrapper sits at the selector, the one seam that sees both, and
counts each separately. Every `kid` label is read off the frozen snapshot that
encrypts, making rotation progress observable per key even when a rotation
lands mid-operation. Registered key IDs are safe labels — cardinality is
bounded by your keyset — where wire-supplied identifiers are not, which is why
[`CipherMatch`](crate::crypto::cipher::CipherMatch) values stay off the
decrypt-side labels.
