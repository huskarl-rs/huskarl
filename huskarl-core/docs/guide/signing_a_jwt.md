# Building and signing a JWT

Use [`Jwt::builder`](crate::jwt::Jwt::builder) to assemble the registered claims
and any custom ones, then [`to_jws_compact`](crate::jwt::Jwt::to_jws_compact) to
sign them into a compact JWS string. Signing is delegated to a
[`JwsSigner`](crate::crypto::signer::JwsSigner): `huskarl-core` defines the trait
but not the keys — a concrete signer comes from a crypto backend crate (the
native or WebCrypto backends), or you can [implement one
yourself](crate::_docs::guide::implementing_a_backend).

```rust
# use std::borrow::Cow;
# use huskarl_core::{crypto::signer::JwsSigner, error::Error, platform::MaybeSendBoxFuture};
# // Stand-in for the signer your crypto backend provides.
# #[derive(Debug)]
# struct BackendSigner;
# impl JwsSigner for BackendSigner {
#     fn jws_algorithm(&self) -> Cow<'_, str> { "ES256".into() }
#     fn key_id(&self) -> Option<Cow<'_, str>> { Some("key-1".into()) }
#     fn sign<'a>(&'a self, _input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
#         Box::pin(async move { Ok(vec![0xDE, 0xAD, 0xBE, 0xEF]) })
#     }
# }
use huskarl_core::jwt::Jwt;

# async fn example(signer: BackendSigner) -> Result<(), huskarl_core::error::Error> {
let jwt = Jwt::builder()
    .issuer("https://issuer.example")
    .subject("user-123")
    .audience("https://api.example")
    // Sets `iat` and `exp` from one captured timestamp.
    .issued_now_expires_after(std::time::Duration::from_secs(300))
    // Any `Serialize` value becomes the extra claims.
    .claims(serde_json::json!({ "scope": "read write" }))
    .build();

let compact = jwt.to_jws_compact(&signer).await?;
println!("{}", compact.expose_secret());
# Ok(())
# }
```

The algorithm (`alg`) and key ID (`kid`) headers come from the signer, so they
always match the key that produced the signature. A `jti` is generated
automatically (UUIDv7) unless you set one; the [builder](crate::jwt::Jwt::builder)
also offers [`issued_now_not_before_now_expires_after`](crate::jwt::JwtBuilder::issued_now_not_before_now_expires_after)
when you need `nbf` pinned to the same instant as `iat`, and
[`extra_headers`](crate::jwt::JwtBuilder::extra_headers) for protected
header parameters beyond the registered set (as `DPoP` proofs use).

The returned [`SecretString`](crate::secrets::SecretString) keeps the signed
token out of accidental logs; call `expose_secret()` only at the point you hand
it to the wire.
