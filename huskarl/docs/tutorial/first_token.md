# Get your first access token

This tutorial takes you from nothing to a working program that requests a real
`OAuth2` access token and prints it. You will start a local authorization
server, write a small Rust program against huskarl, and watch it obtain a token.

By the end you will have run a complete client-credentials flow end to end
against a live server — the foundation every other grant builds on.

You do not need to know `OAuth2` beforehand, and you do not need an account with
any provider: everything runs on your machine. Follow the steps in order; each
one builds on the last.

**What you need:**

- Rust 1.92 or newer (`rustc --version`).
- [Docker](https://docs.docker.com/get-docker/), to run the local server.

It should take about ten minutes.

## 1. Start a local authorization server

An `OAuth2` client needs an authorization server to talk to. You will run
[Keycloak](https://www.keycloak.org/) — a widely used open-source server —
locally in Docker, pre-configured with one client for this tutorial.

Create a file called `realm.json` with this content. It defines a realm named
`huskarl-tutorial` containing a single confidential client
(`tutorial-client`) whose secret is `tutorial-secret`:

```json
{
  "realm": "huskarl-tutorial",
  "enabled": true,
  "clients": [
    {
      "clientId": "tutorial-client",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "tutorial-secret"
    }
  ]
}
```

In the same directory, start Keycloak and import that realm:

```console
$ docker run --rm --name huskarl-keycloak \
    -p 8080:8080 \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -v "$PWD/realm.json:/opt/keycloak/data/import/realm.json:ro" \
    quay.io/keycloak/keycloak:26.4 \
    start-dev --import-realm
```

Leave this running in its own terminal. Wait until it logs a line like
`Imported realm huskarl-tutorial` followed by
`Keycloak … started`. The server is now listening on `http://localhost:8080`.

To confirm it is up, open
<http://localhost:8080/realms/huskarl-tutorial/.well-known/oauth-authorization-server>
in a browser — you should see a JSON discovery document. huskarl will read this
same document to find the server's token endpoint.

## 2. Create the project

In a second terminal, create a new binary project and add the dependencies:

```console
$ cargo new huskarl-tutorial
$ cd huskarl-tutorial
$ cargo add huskarl huskarl-reqwest
$ cargo add tokio --features full
```

`huskarl` is the client library, `huskarl-reqwest` provides the HTTP client it
uses, and `tokio` is the async runtime that drives it.

## 3. Write the program

Replace the contents of `src/main.rs` with this:

```rust,no_run
use huskarl::core::client_auth::ClientSecret;
use huskarl::core::secrets::EnvVarSecret;
use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl::grant::client_credentials::{
    ClientCredentialsGrant, ClientCredentialsGrantParameters,
};
use huskarl::prelude::*;
use huskarl_reqwest::ReqwestClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The HTTP client huskarl uses to make its requests.
    let http_client = ReqwestClient::builder().build().await?;

    // Discover the server's endpoints from its issuer URL
    // (the `/.well-known/oauth-authorization-server` document you opened
    // in step 1).
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer("http://localhost:8080/realms/huskarl-tutorial")
        .call()
        .await?;

    // Describe the client and how it authenticates. The secret is read from
    // the CLIENT_SECRET environment variable, never hardcoded.
    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id("tutorial-client")
        .http_client(http_client)
        .client_auth(ClientSecret::new(EnvVarSecret::string("CLIENT_SECRET")?))
        .build();

    // Exchange the client's credentials for an access token.
    let response = grant.exchange(ClientCredentialsGrantParameters::new()).await?;

    println!(
        "Access token: {}",
        response.access_token().token().expose_secret()
    );

    Ok(())
}
```

Each block does one thing: build an HTTP client, discover the server, describe
your client, then exchange its credentials for a token. You will meet all four
pieces again in the how-to guides.

## 4. Run it

The client's secret comes from the environment, so set it, then run the program:

```console
$ export CLIENT_SECRET=tutorial-secret
$ cargo run
```

You should see a line like this (the token itself will be a long string):

```text
Access token: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA...
```

That long string is a real access token, minted by the server just now. You have
completed a full `OAuth2` client-credentials exchange.

If instead you see an error, check that the Keycloak terminal from step 1 is
still running and has finished starting, and that `CLIENT_SECRET` is set in the
same terminal you ran `cargo run` from.

## What you did

In one short program you:

- pointed huskarl at an authorization server by its **issuer URL** and let it
  **discover** the endpoints itself, rather than hardcoding them;
- described a client and its **credentials**, keeping the secret out of the
  source;
- ran a **client-credentials grant** — the flow a service uses to act on its own
  behalf — and received an access token.

The token you printed is what a client attaches to requests against a protected
API. Notice that huskarl handed it back wrapped so it does not leak into logs:
you had to call `expose_secret()` deliberately to print it.

When you are done, stop the server with `Ctrl-C` in its terminal, or
`docker stop huskarl-keycloak`.

## Where to go next

Now that a token flows end to end, the how-to guides show how to adapt this to
real applications, and the explanation pages cover the "why":

- [Client credentials grant](crate::_docs::guide::client_credentials) — the
  same grant with scopes, resources, and a client secret loaded from your own
  secret manager.
- [Authorization code grant](crate::_docs::guide::authorization_code) — the flow
  for logging a **user** in, with PKCE applied automatically.
- [Caching tokens](crate::_docs::guide::caching) and
  [the request authorizer](crate::_docs::guide::authorizer) — stop fetching a
  token per request: cache one, refresh it ahead of expiry, and attach it to
  outgoing requests automatically.
- [The error model](crate::_docs::explanation::error_handling) — how huskarl's
  one [`Error`](crate::core::Error) tells you whether to retry, re-authenticate,
  or give up.

For the full list of grants and the API reference, see the
[`grant`](crate::grant) module and the crate root.
