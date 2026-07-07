# Signing a JWT in the browser

Generate a non-extractable signing key with
[`PrivateKey`](crate::asymmetric::signer::PrivateKey), then build and sign a JWT
with `huskarl-core`'s [`Jwt`](huskarl_core::jwt::Jwt) builder. Every crypto call
is `async`, and the key never leaves `SubtleCrypto`:

```rust,no_run
use huskarl_core::{crypto::signer::JwsSignerSelector as _, jwt::Jwt};
use huskarl_crypto_webcrypto::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("key-1".to_string())).await?;

let jwt = Jwt::builder()
    .iss("https://issuer.example")
    .sub("user-123")
    .issued_now_expires_after(std::time::Duration::from_secs(300))
    .claims(serde_json::json!({ "scope": "read write" }))
    .build();

// Select the signer snapshot, then produce a compact JWS string.
let compact = jwt.to_jws_compact(&*key.select_signer().await).await?;
# let _ = compact;
# Ok(())
# }
```

To verify, build an
[`AsymmetricPublicKey`](crate::asymmetric::verifier::AsymmetricPublicKey) from a
public JWK (or use [`WebCryptoVerifierPlatform`](crate::WebCryptoVerifierPlatform)
over a JWKS) and hand it to `huskarl-core`'s JWT validator.

Because the signing key is generated non-extractable and never exported, a wasm
client authenticates with `private_key_jwt` by registering the key's *public*
JWK with the authorization server — see [platform
constraints](crate::_docs::explanation::platform_constraints) for why importing a
pre-provisioned private key is not available here.
