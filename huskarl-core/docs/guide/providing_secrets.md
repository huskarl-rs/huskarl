# Providing secrets

Anything that needs a credential — a client secret, a signing key's raw bytes —
takes it through the [`Secret`](crate::secrets::Secret) trait, which yields the
value wrapped in a redacted [`SecretString`](crate::secrets::SecretString) or
[`SecretBytes`](crate::secrets::SecretBytes) so it does not leak into logs or
`Debug` output. The crate ships providers for the common sources and lets you
implement your own.

## Built-in providers

[`EnvVarSecret`](crate::secrets::EnvVarSecret) reads an environment variable. A
[`SecretDecoder`](crate::secrets::encodings::SecretDecoder) controls how the
stored form is interpreted — [`StringEncoding`](crate::secrets::encodings::StringEncoding)
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
convenient for mounted-secret rotation:

```ignore
use huskarl_core::secrets::FileSecret;

let client_secret = FileSecret::string("/run/secrets/client_secret");
```

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

Classify failures by intent: a transient fetch failure (a vault timeout) as
[`ErrorKind::Transport`](crate::error::ErrorKind::Transport) with `retryable: true`,
and a persistent one (missing key, bad permissions, undecodable data) as
[`ErrorKind::Config`](crate::error::ErrorKind::Config). See [the error
model](crate::_docs::explanation::error_handling).

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
