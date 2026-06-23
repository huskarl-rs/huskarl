# Integration Tests

This directory contains integration tests that run against external services,
each with its own Docker infrastructure:

- **Provider matrix** (`huskarl-integration`) — real OAuth2/OIDC flows against
  self-hosted servers (Keycloak on 8080 + 8444, Dex on 5556, node-oidc-provider
  on 3000).
- **OpenID conformance suite** — the official certification test plans (8443).

Every backend binds a distinct port, so they can all run at once — no juggling.
The fast provider matrix and the slower conformance suite are separate commands
(`mise run providers:test` and `mise run conformance:test`), mirroring CI: PRs
run the matrix, conformance runs on a weekly schedule.

All commands run from the `integration/` directory.

## Quick Reference

| Task | Command |
|---|---|
| All provider matrix tests | `mise run providers:test` |
| Keycloak: test | `mise run keycloak:test` |
| Keycloak: stop | `mise run keycloak:down` |
| Dex: test | `mise run dex:test` |
| Dex: stop | `mise run dex:down` |
| node-oidc-provider: test | `mise run node-oidc:test` |
| node-oidc-provider: stop | `mise run node-oidc:down` |
| Okta: test (hosted; needs `OKTA_*`) | `mise run okta:test` |
| Coverage report (all providers) | `mise run matrix` |
| Conformance: all tests | `mise run conformance:test` |
| Conformance: OIDC only | `mise run conformance:test:oidc` |
| Conformance: FAPI2 only | `mise run conformance:test:fapi2` |
| Conformance: stop | `mise run conformance:down` |

The test tasks automatically start the required infrastructure. The backends use
distinct ports, so they can all run at the same time.

## Provider Matrix Tests

Tests in the `huskarl-integration` crate exercise real OAuth2/OIDC flows against
self-hosted authorization servers. Flow bodies live in `huskarl-integration/src/suite.rs`
and are written generically against the `TestProvider` trait (in `huskarl-testkit`);
each `tests/<provider>.rs` file is a thin wrapper that runs the suite against one
provider. A flow checks the provider's advertised `Capabilities` and skips cleanly
when a server can't do it.

Wired providers and the flows each runs (others skip on the feature check). Each
provider is provisioned differently — Keycloak via its admin API, Dex via static
config, node-oidc-provider via RFC 7591 dynamic registration — which is exactly
what the `TestProvider` seam abstracts.

| flow / variant | Keycloak | Dex | node-oidc |
|---|---|---|---|
| client_credentials (plain, dpop, private_key_jwt) | ✓ | — | — |
| refresh | ✓ | — | — |
| introspection | ✓ | — | — |
| mtls | ✓ | — | — |
| rejection (wrong_audience) | ✓ | — | — |
| auth_code/direct | ✓ | ✓ | ✓ |
| auth_code/par | ✓ | — | ✓ |
| auth_code/jar | ✓ | — | ✓ |

node-oidc-provider issues opaque access tokens, so the client-credentials/JWKS
flows are out of its feature set; it covers the authorization-code family
(including PAR and JAR) as a conformant reference.

Each `tests/<provider>.rs` is a `harness = false` `main` that turns the
canonical flow list (`huskarl_integration::FLOWS`) into one `libtest-mimic` test
per variant via `provider_trials`, named `flow::variant`. For the coverage
report — each provider and the variants it exercises — run `mise run matrix`
(or `cargo run -p huskarl-integration --example coverage`); it reads each
provider's `FEATURES` const, so no server is needed.

### Running them

`mise run <provider>:test` starts the server and runs that provider's tests in
one step — that's the path the per-provider sections below describe. These tasks
use [nextest](https://nexte.st) (each test in its own process), matching CI, so
you'll need it installed. To iterate, start the server once with
`mise run <provider>:up` and drive nextest directly; that's what lets you filter
to a single variant:

```sh
mise run keycloak:up    # start the server once
cargo nextest run -p huskarl-integration --test keycloak --features keycloak
cargo nextest run -p huskarl-integration --test keycloak --features keycloak auth_code::par   # one variant
```

The `--test` target and `--features` flag differ per provider (note the
`node_oidc` underscore in the target name):

| provider | mise task | `--test` | `--features` |
|---|---|---|---|
| Keycloak | `keycloak` | `keycloak` | `keycloak` |
| Dex | `dex` | `dex` | `dex` |
| node-oidc-provider | `node-oidc` | `node_oidc` | `node-oidc` |
| Okta (hosted, no `up`) | `okta` | `okta` | `okta` |

### Keycloak

```sh
mise run keycloak:test    # starts Keycloak, runs tests
mise run keycloak:down    # stop when done
```

Keycloak is available at `http://localhost:8080` (HTTP) and
`https://localhost:8444` (HTTPS/mTLS; host 8444 → container 8443). Admin
credentials: `admin`/`admin`. Each
test provisions an ephemeral realm (deleted on drop). `auth_code` creates a user
and drives Keycloak's login form headlessly.

### Dex

Dex serves OIDC on `http://127.0.0.1:5556/dex` with a static auth-code client
(`integration/dex/config.yaml`) and the mock connector (fixed identity, no login
form), so `auth_code` is driven as a pure redirect chain. The client's redirect
URI is pinned to port 5557. Dex doesn't support client credentials / introspection
/ mTLS here, so those flows skip.

```sh
mise run dex:test
mise run dex:down
```

### node-oidc-provider

A small Node app (`integration/node-oidc-provider/`) mounts
[`node-oidc-provider`](https://github.com/panva/node-oidc-provider) — the
reference OIDC implementation — as a conformant oracle on
`http://127.0.0.1:3000`. Clients are created at runtime via **RFC 7591 dynamic
client registration** (no static or admin-provisioned clients), and login is
driven headlessly through the built-in `devInteractions` UI (a fixed identity:
any username, any password). It serves the authorization-code family —
`auth_code/{direct,par,jar}` — and skips the rest (opaque access tokens).

```sh
mise run node-oidc:test    # builds + starts the container, runs tests
mise run node-oidc:down
```

## OpenID Conformance Suite Tests

Tests in `huskarl-conformance/` that validate huskarl against the
[OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite).
Runs the official test plans for OIDC Basic RP certification and FAPI 2.0 Security
Profile.

```sh
mise run conformance:test         # starts suite, runs all tests
mise run conformance:test:oidc    # OIDC Basic RP certification only
mise run conformance:test:fapi2   # FAPI 2.0 Security Profile only
mise run conformance:down         # stop when done
```

The suite runs MongoDB, the conformance server, and an nginx reverse proxy on
port 8443, accessible at `https://localhost.emobix.co.uk:8443`
(this domain resolves to 127.0.0.1).

Or manually:

```sh
mise run conformance:up
cargo test -p huskarl-conformance --features conformance-suite-tests -- --nocapture
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `CONFORMANCE_SUITE_BASE` | `https://localhost.emobix.co.uk:8443` | Base URL of the conformance suite |
| `CONFORMANCE_CLIENT_ID` | `client` | Client ID for OIDC basic tests |
| `CONFORMANCE_CLIENT_SECRET` | `client-secret` | Client secret for OIDC basic tests |
