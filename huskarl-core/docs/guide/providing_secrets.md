# Providing secrets

Anything that needs a credential — a client secret, a signing key's raw bytes —
takes it through the [`Secret`](crate::secrets::Secret) trait, which yields the
value wrapped in a redacted [`SecretString`](crate::secrets::SecretString) or
[`SecretBytes`](crate::secrets::SecretBytes) so it does not leak into logs or
`Debug` output. The crate ships providers for the common sources and lets you
implement your own.

## Built-in providers

[`EnvVarSecret`](crate::secrets::EnvVarSecret) reads an environment variable. A
[`SecretMap`](crate::secrets::SecretMap) controls how the stored form is
interpreted — [`StringEncoding`](crate::secrets::encodings::StringEncoding)
for UTF-8 text, [`Base64Encoding`](crate::secrets::encodings::Base64Encoding) or
[`HexEncoding`](crate::secrets::encodings::HexEncoding) for binary key material:

```rust
use huskarl_core::secrets::{EnvVarSecret, encodings::Base64Encoding};

# fn example() -> Result<(), huskarl_core::error::Error> {
// UTF-8 text, the common case.
let client_secret = EnvVarSecret::string("APP_CLIENT_SECRET")?;

// Base64-encoded bytes decoded into `SecretBytes`.
let signing_key = EnvVarSecret::new("APP_SIGNING_KEY", &Base64Encoding)?;
# let _ = (client_secret, signing_key);
# Ok(())
# }
```

With the `fs` feature, `FileSecret` reads from a file on each access —
convenient for mounted-secret rotation. It is `FileBytes` (the raw file
contents) composed with a `SecretMap`; the same composition is available on any
provider through [`Secret::mapped`](crate::secrets::Secret::mapped):

```rust,no_run
use huskarl_core::prelude::*; // brings `Secret::mapped` into scope
use huskarl_core::secrets::{FileBytes, FileSecret, encodings::Base64Encoding};

let client_secret = FileSecret::string("/run/secrets/client_secret");

// Equivalent to FileSecret::new(path, Base64Encoding):
let signing_key = FileBytes::new("/run/secrets/signing_key").mapped(Base64Encoding);
# let _ = (client_secret, signing_key);
```

A managed store needs a provider crate: `huskarl-google-cloud` implements
`Secret` for Google Cloud Secret Manager, including a multi-version source for
rotated keys ([guide](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/secret_manager/index.html)).

## A secret you already hold

[`ProvidedSecret`](crate::secrets::ProvidedSecret) wraps a value the process
already obtained at runtime — from a store the crate has no provider for, or
from deserialized configuration
([`SecretString`](crate::secrets::SecretString) implements `Deserialize`):

```rust
use huskarl_core::secrets::{ProvidedSecret, SecretString};
use serde::Deserialize;

#[derive(Deserialize)]
struct AppConfig {
    client_secret: SecretString,
}

# fn example(config: AppConfig) {
let client_secret = ProvidedSecret::new(config.client_secret);
# let _ = client_secret;
# }
```

Do not reach for it to embed a credential in source code — a hardcoded secret
lands in version control, binaries, and backups, and cannot be rotated without
a release. If the value is known before the process starts, it belongs in the
environment or a file. `ProvidedSecret` is also a snapshot: if the upstream
source rotates the value, [implement `Secret` for the
source](#a-custom-provider) instead, so each fetch sees the current value.

## Transforming a secret

A fetched value is often not yet the value you need — a store hands back a
string whose *contents* are base64-encoded key material, or a value that needs
trimming or parsing. Any [`Secret`](crate::secrets::Secret) can be transformed
in place, leaving the source (and its `identity`) untouched:

- [`Secret::mapped`](crate::secrets::Secret::mapped) applies a named
  [`SecretMap`](crate::secrets::SecretMap). Named maps chain, and the result's
  type can be written out, so it can be stored in a struct field.
- [`Secret::map`](crate::secrets::Secret::map) and
  [`Secret::try_map`](crate::secrets::Secret::try_map) take a closure — the
  convenient form for a one-off transform at the call site.

```rust
use huskarl_core::prelude::*; // brings `Secret::mapped` / `Secret::map` into scope
use huskarl_core::secrets::{
    EnvVarSecret, SecretString,
    encodings::{Base64Encoding, StringToBytes},
};

# fn example() -> Result<(), huskarl_core::error::Error> {
// A string secret whose contents are base64: view it as bytes, then decode.
let signing_key = EnvVarSecret::string("WRAPPED_SIGNING_KEY")?
    .mapped(StringToBytes)
    .mapped(Base64Encoding);

// A one-off transform with a closure, e.g. stripping a legacy prefix.
let api_key = EnvVarSecret::string("PREFIXED_API_KEY")?
    .map(|s: SecretString| SecretString::new(s.expose_secret().trim_start_matches("v1:")));
# let _ = (signing_key, api_key);
# Ok(())
# }
```

A failed transform surfaces as a non-retryable error; use
[`with_context`](crate::secrets::MappedSecret::with_context) to name the source
in the error (`"decoding secret file /run/secrets/key"`). Transforms run on
every fetch, so wrap the *transformed* secret in
[`CachedSecret`](crate::secrets::CachedSecret) (below) to memoize the final
value.

## A custom provider

Implement [`Secret`](crate::secrets::Secret) to pull from anywhere — a vault, a
KMS, a config service. Write the body as `Box::pin(async move { ... })`:

```rust
use huskarl_core::{
    error::Error,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretOutput, SecretString},
};

#[derive(Debug)]
struct VaultSecret {
    path: String,
}

impl Secret for VaultSecret {
    type Output = SecretString;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        Box::pin(async move {
            // ... fetch `self.path` from your store ...
            Ok(SecretOutput {
                value: SecretString::new("fetched-value"),
                identity: None,
            })
        })
    }
}
```

Convert provider failures with [`Error::new`](crate::error::Error::new). Use
[`RetryAdvice::Retry`](crate::error::RetryAdvice::Retry) for a transient fetch
failure such as a vault timeout. Use [`RetryAdvice::No`](crate::error::RetryAdvice::No)
for a missing key, bad permissions, or undecodable data. If the provider reports
a cooldown, preserve it with
[`RetryAdvice::retry_after`](crate::error::RetryAdvice::retry_after).

If your provider wraps another component that already returns `Error`, preserve
that classification instead of constructing a new one. See
[returning errors from an extension](crate::_docs::guide::returning_errors) for
the propagation and typed-error-enum patterns.

That one `impl` is the whole integration: the provider composes like the
built-ins, so [transforms](#transforming-a-secret) chain over it
(`vault_secret.mapped(StringToBytes).mapped(Base64Encoding)`) and
[`CachedSecret`](crate::secrets::CachedSecret) wraps it — keep fetching and
decoding out of the provider and let the decorators do it.

## Caching

Fetching on every use is wasteful when the value rarely changes. Wrap any
provider in [`CachedSecret`](crate::secrets::CachedSecret) to memoize it, with an
optional TTL after which the next access reloads inline:

```rust
use std::time::Duration;

use huskarl_core::secrets::{CachedSecret, EnvVarSecret};

# fn example() -> Result<(), huskarl_core::error::Error> {
let cached = CachedSecret::builder()
    .secret(EnvVarSecret::string("APP_CLIENT_SECRET")?)
    .ttl(Duration::from_secs(300))
    .build();
# let _ = cached;
# Ok(())
# }
```

Without a TTL the value is held until [`invalidate`](crate::secrets::CachedSecret::invalidate)
is called. `CachedSecret` is itself a [`Secret`](crate::secrets::Secret), so it
drops in wherever a provider is expected.
