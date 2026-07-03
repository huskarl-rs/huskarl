# Setting up an HTTP client and client authentication

Every grant needs two things before it can run: an
[`HttpClient`](crate::core::http::HttpClient) to drive its token requests, and
(usually) a [`ClientAuthentication`](crate::core::client_auth) implementation.
The per-grant guides all assume the setup on this page.

A note on imports: `use huskarl::prelude::*` brings in the crate's extension
traits (so methods like `.exchange(…)` resolve) and deliberately nothing
else — types are imported explicitly. The [`prelude`](crate::prelude) docs
explain the principle and carry a copy-pasteable import block for a typical
application.

## Setting up an HTTP client

The examples throughout these guides use the `huskarl_reqwest` crate:

```rust
use huskarl_reqwest::ReqwestClient;

# async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
let client: ReqwestClient = ReqwestClient::builder().build().await?;
# Ok(())
# }
```

## Setting up client authentication

Grants take a [`ClientAuthentication`](crate::core::client_auth) implementation.
This page shows the two simplest; for the full map — `private_key_jwt`,
`client_secret_jwt`, mTLS, and how to choose — see [choosing client
authentication](crate::_docs::guide::client_authentication).

A confidential client authenticates with its credentials — for example a
client secret (any `ClientAuthentication` implementation works):

```rust
use huskarl::core::{
    client_auth::ClientSecret,
    secrets::{EnvVarSecret, encodings::StringEncoding},
};

# async fn setup_client_auth() -> Result<(), Box<dyn std::error::Error>> {
let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
let client_auth: ClientSecret = ClientSecret::new(env_secret);
# Ok(())
# }
```

A public client — one that holds no credentials, such as a single-page app,
CLI, or device — uses [`NoAuth`](crate::core::client_auth::NoAuth):

```rust
use huskarl::core::client_auth::NoAuth;

let client_auth = NoAuth;
```

The [`jwt_bearer`](crate::grant::jwt_bearer),
[`token_exchange`](crate::grant::token_exchange), and
[`refresh`](crate::grant::refresh) grants carry their own authorization (an
assertion or an existing token), so client authentication is optional and
*independent* of the grant: such a grant may authenticate the client
separately, or present no client identity at all (RFC 7523 §3.1, RFC 8693 §2).
