# Choosing client authentication

Every grant takes a
[`ClientAuthentication`](crate::core::client_auth::ClientAuthentication)
implementation via its `client_auth` builder option. This page is the map of
the methods huskarl ships and when to pick each; [the setup
guide](crate::_docs::guide::setup) shows where the value plugs in.

| Registered method | huskarl type | Pick it when |
|---|---|---|
| *(public client)* | [`NoAuth`](crate::core::client_auth::NoAuth) | The client holds no credentials (SPA, CLI, device) |
| `client_secret_post` / `client_secret_basic` | [`ClientSecret`](crate::core::client_auth::ClientSecret) | A shared secret is acceptable |
| `private_key_jwt` | [`JwtBearer`](crate::core::client_auth::JwtBearer) + an asymmetric key | No shared secrets; required by FAPI 2.0 |
| `client_secret_jwt` | [`JwtBearer`](crate::core::client_auth::JwtBearer) + an HMAC key | A shared secret, without putting it on the wire |
| `tls_client_auth` / mTLS | [`NoAuth`](crate::core::client_auth::NoAuth) + an mTLS HTTP client | Authentication belongs to the transport (RFC 8705) |

Whatever the type, the grant negotiates against the server: the methods
advertised in `token_endpoint_auth_methods_supported` (via
`builder_from_metadata`) are passed to the implementation, which picks a
mutually supported variant.

## Public clients: `NoAuth`

[`NoAuth`](crate::core::client_auth::NoAuth) sends only the `client_id`.
Public clients should still sender-constrain their tokens — see
[PKCE](crate::_docs::guide::authorization_code) (automatic) and
[DPoP](crate::_docs::guide::dpop).

```rust
use huskarl::core::client_auth::NoAuth;

let client_auth = NoAuth;
```

## Shared secret: `ClientSecret`

[`ClientSecret`](crate::core::client_auth::ClientSecret) implements both
RFC 6749 §2.3.1 forms. It defaults to `client_secret_post` (the OAuth 2.1
mandatory-to-support method) and switches to `client_secret_basic` when the
server only advertises that; opt into preferring Basic with the builder. The
secret comes from any [`Secret`](crate::core::secrets::Secret) source, so
the credential itself stays out of your code:

```rust
use huskarl::core::{client_auth::ClientSecret, secrets::EnvVarSecret};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let client_auth = ClientSecret::new(EnvVarSecret::string("CLIENT_SECRET")?);

// Prefer client_secret_basic when the server supports both:
let basic_preferring = ClientSecret::builder()
    .client_secret(EnvVarSecret::string("CLIENT_SECRET")?)
    .prefer_basic_auth(true)
    .build();
# let _ = (client_auth, basic_preferring);
# Ok(())
# }
```

## Signed assertion: `private_key_jwt`

[`JwtBearer`](crate::core::client_auth::JwtBearer) authenticates with a
signed JWT (RFC 7523 / OIDC Core §9): no secret crosses the wire, the server
verifies against your registered public key, and FAPI 2.0 requires it. Give
it an asymmetric signer and an [`Audience`](crate::core::client_auth::Audience)
policy:

```rust
use huskarl::core::client_auth::{Audience, JwtBearer};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
# let signing_key = PrivateKey::generate(GenerateAlgorithm::Es256, None)?;
let client_auth = JwtBearer::builder()
    .signer(signing_key)
    .audience(Audience::Issuer)
    .build();
# let _ = client_auth;
# Ok(())
# }
```

In production the key is registered with the authorization server, so load
it rather than generating: `PrivateKey::load_pkcs8_pem` / `load_pkcs8_der`
(from a [`Secret`](crate::core::secrets::Secret) source) or
`PrivateKey::from_jwk` in `huskarl_crypto_native`.

**Choose the audience deliberately.** Signature-based authentication is
subject to audience-injection attacks
(draft-ietf-oauth-security-topics-update §2.1):

- [`Audience::Issuer`](crate::core::client_auth::Audience::Issuer) —
  recommended, and required by FAPI 2.0.
- [`Audience::TargetEndpoint`](crate::core::client_auth::Audience::TargetEndpoint)
  — the other safe choice: the exact endpoint the assertion is sent to.
- [`Audience::TokenEndpoint`](crate::core::client_auth::Audience::TokenEndpoint)
  — the historically common value; it is what audience injection exploits.
  Use only for a legacy server that demands it.

Two more knobs for legacy servers: `explicit_typ(false)` if the server
rejects the `client-authentication+jwt` typ, and `expires_after` for
assertion lifetime (default one minute).

### `client_secret_jwt`

The same [`JwtBearer`](crate::core::client_auth::JwtBearer) with a symmetric
HMAC key (`SymmetricKey` in `huskarl_crypto_native`) implements
`client_secret_jwt` — the shared secret signs the assertion instead of
appearing in the request.

## mTLS: authenticate the connection

RFC 8705 `tls_client_auth` authenticates at the TLS layer, so it is
configured on the **HTTP client**, not the grant: give `huskarl-reqwest` an
mTLS provider, and pair it with
[`NoAuth`](crate::core::client_auth::NoAuth) — the token request itself then
carries only the `client_id`, as the RFC requires:

```rust,no_run
use huskarl_reqwest::{ReqwestClient, mtls::MtlsPem};
use huskarl::core::secrets::EnvVarSecret;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
// PEM bundle holding the client certificate chain and private key.
let identity = EnvVarSecret::string("MTLS_IDENTITY_PEM")?;

let http_client = ReqwestClient::builder()
    .mtls(MtlsPem::new(identity))
    .build()
    .await?;
# let _ = http_client;
# Ok(())
# }
```

(`MtlsPkcs12` and `MtlsPkcs8Pem` cover the other packaging formats; a
pre-built `reqwest::Client` with an identity needs
`ReqwestClient::with_uses_mtls`.)

Because the client reports that it uses mTLS, grants built from server
metadata automatically send token requests to the server's RFC 8705 §5
`mtls_endpoint_aliases` instead of the plain endpoints — no extra
configuration.

## Grants that carry their own authorization

The [`jwt_bearer`](crate::_docs::guide::jwt_bearer),
[`token_exchange`](crate::_docs::guide::token_exchange), and
[`refresh`](crate::_docs::guide::refresh) grants present an assertion or an
existing token, so `client_auth` (and `client_id`) are optional there and
independent of the grant — anonymous presentation is spec-valid (RFC 7523
§3.1, RFC 8693 §2). Set them when the authorization server also wants the
client authenticated.
