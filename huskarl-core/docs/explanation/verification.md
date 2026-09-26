# How verification fits together

Choose how keys are obtained and refreshed independently of how tokens are
validated. The same validation policy can use a fixed public key, a JWKS loaded
from a file, or a remotely refreshed JWKS. Discovery is optional in all three
cases.

The boundary is [`JwsVerifier`](crate::crypto::verifier::JwsVerifier). A verifier
can represent one key, a set of keys, or a composition that refreshes keys and
retries verification. The JWT validator consumes that interface, so changing
key management does not require changing its claim checks.

## One policy, three key configurations

Here is a policy for JWTs from one issuer, intended for one audience, with an
expiry and an explicit algorithm allowlist:

```rust
use huskarl_core::{
    crypto::verifier::JwsVerifier,
    jwt::validator::{ClaimCheck, JwtValidator},
};

fn validator(verifier: impl JwsVerifier + 'static) -> JwtValidator {
    JwtValidator::builder()
        .verifier(verifier)
        .iss(ClaimCheck::required_value("https://issuer.example"))
        .aud(ClaimCheck::require_any(["https://api.example"]))
        .require_exp(true)
        .allowed_algorithms(["ES256".to_owned(), "RS256".to_owned()])
        .build()
}
```

Each configuration below produces a verifier you can pass to `validator`.
`platform` is the cryptographic backend, such as the native or WebCrypto
implementation of
[`JwsVerifierPlatform`](crate::crypto::verifier::JwsVerifierPlatform).

**A fixed public key.** The application supplies a trusted JWK directly. No
JWKS document or HTTP client is involved.

```rust,no_run
use huskarl_core::{crypto::verifier::JwsVerifierPlatform, jwk::PublicJwk};

# async fn example(platform: &dyn JwsVerifierPlatform, public_key: PublicJwk)
#     -> Result<(), Box<dyn std::error::Error>> {
let verifier = platform.create_verifier_from_jwk(public_key).await?;
# Ok(())
# }
```

**A JWKS from a file.** Deployment configuration supplies the keys. Parse the
file and construct a verifier for the whole set; this loads one snapshot and
does not watch the file for changes.

```rust,no_run
use huskarl_core::{
    crypto::verifier::{JwsVerifierPlatform, MultiKeyVerifier},
    jwk::Jwks,
};

# async fn example(platform: &dyn JwsVerifierPlatform)
#     -> Result<(), Box<dyn std::error::Error>> {
let jwks_json = std::fs::read_to_string("trusted-jwks.json")?;
let jwks: Jwks = serde_json::from_str(&jwks_json)?;
let verifier = MultiKeyVerifier::from_jwks(&jwks.into(), platform).await?;
# Ok(())
# }
```

**A remotely refreshed JWKS.** An HTTP source fetches the initial keys and
builds a verifier with scheduled refresh and retry on a key miss. The URI can
come from explicit configuration, as here, or from discovery metadata.

```rust,no_run
use huskarl_core::{
    crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
    jwk::JwksSource,
};
# use std::sync::Arc;
# use huskarl_core::http::HttpClient;

# async fn example(platform: Arc<dyn JwsVerifierPlatform>, http_client: impl HttpClient + 'static)
#     -> Result<(), Box<dyn std::error::Error>> {
let jwks_uri = "https://issuer.example/jwks.json".parse()?;
let source = JwksSource::builder().http_client(http_client).build();
let verifier = source.build(Some(&jwks_uri), platform).await?;
# Ok(())
# }
```

The remote configuration can perform HTTP work during validation. Its default
refresh policy attempts a reload on use after one hour, and on key misses
subject to rate limits and backoff. Failed refreshes retain existing keys; the
TTL is a refresh trigger, not a maximum key age. The fixed-key and file examples
have no refresh behavior.

In every case, the caller constructs the policy with `validator(verifier)` and
uses the same `validate` method. For a complete validation call and claim-policy
options, see [validating a JWT](crate::_docs::guide::validating_a_jwt).

## Combining sources

The configurations can also be composed. For example, an OpenID Connect client
can hold an HMAC verifier built from its client secret alongside a verifier
for the provider's public JWKS:

```rust
use std::sync::Arc;
use huskarl_core::crypto::verifier::{JwsVerifier, MultiKeyVerifier, RetryingVerifier};

# fn example(hmac_verifier: Arc<dyn JwsVerifier>, jwks_verifier: Arc<dyn JwsVerifier>) {
let combined = MultiKeyVerifier::new(vec![hmac_verifier, jwks_verifier]);
let verifier = RetryingVerifier::new(combined);
# }
```

Here the JWKS child supplies scheduled refresh, while retry wraps the combined
verifier so a key miss can request a refresh through the whole composition.
The HMAC child need not refresh. When assembling this stack, apply retry once
at the outside, as shown in the
[mixed-source recipe](crate::_docs::guide::configuring_jwt_verification).
The consumer still sees one `JwsVerifier`.

[OIDC Core §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
specifies the client secret's UTF-8 bytes as the verification key for
HMAC-signed ID tokens. A native
[`SymmetricKey`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/symmetric/struct.SymmetricKey.html)
can provide that verifier. The client's ID-token algorithm policy still
follows its registration/configuration: composing verifiers does not itself
authorize accepting both symmetric and asymmetric algorithms. Full ID-token
validation also includes the OIDC claim and flow checks; the generic policy
above is only a JWT example.

## Verification can also be remote

Google Cloud KMS HMAC verification is another implementation of `JwsVerifier`.
It calls KMS to verify the MAC, keeping the symmetric key in KMS. The validator
uses the same interface, with an algorithm allowlist appropriate to the key
(for example, `HS256`). Asynchronous verification accommodates that remote
operation as well as WebCrypto and local cryptography.

For asymmetric KMS signing keys, public keys can instead be fetched and used
for local verification. See the Google Cloud guides for
[HMAC verification](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/symmetric_crypto/index.html)
and [publishing asymmetric public keys](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/asymmetric_signing/index.html).

## The boundaries

```text
Configured key / file / remote source
                 |
                 v
        JwsVerifier implementation
        (optionally wrapped with refresh, retry, metrics)
                 |
                 v
        JWT signature verification
                 |
                 v
           Claims validation
```

`JwsVerifier` exposes key matching, asynchronous signature verification, and a
best-effort refresh hook. Wrappers implement the same trait, so they can add
behavior without changing the consumer. A fixed verifier can use the default
refresh hook, which does nothing.

`JwsVerifierPlatform` turns public JWK data into verifiers for a cryptographic
backend. `JwsVerifierFactory` constructs a verifier when a consumer supplies a
platform and an optional JWKS URI. The factory is useful for discovery-based
configuration; a caller that already has a verifier can pass it directly to
`JwtValidator`.

Discovery supplies metadata independently of key acquisition. An application
can fetch metadata, amend it, or construct it from its own configuration before
building a consumer. Obtaining metadata does not itself require fetching a
JWKS, and using a JWKS does not require discovery.

For configuration recipes, see
[configuring JWT verification](crate::_docs::guide::configuring_jwt_verification).
For how the wrappers cooperate during refresh and key selection, see
[composing crypto strategies](crate::_docs::explanation::crypto_strategies).
