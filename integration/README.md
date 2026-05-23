# Integration Tests

This directory contains integration tests that run against external services.
There are two independent test suites, each with its own Docker infrastructure.
Both use port 8443, so each `up` task automatically stops the other suite first.

All commands run from the `integration/` directory.

## Quick Reference

| Task | Command |
|---|---|
| Keycloak: test | `mise run keycloak:test` |
| Keycloak: stop | `mise run keycloak:down` |
| Conformance: all tests | `mise run conformance:test` |
| Conformance: OIDC only | `mise run conformance:test:oidc` |
| Conformance: FAPI2 only | `mise run conformance:test:fapi2` |
| Conformance: stop | `mise run conformance:down` |

The test tasks automatically start the required infrastructure (and stop the
other suite if it is running).

## Keycloak Tests

Tests in the main `huskarl` crate (`huskarl/tests/`) that exercise real OAuth2/OIDC
flows against a local Keycloak instance. Covers client credentials, token
introspection, and mTLS certificate-bound tokens.

```sh
mise run keycloak:test    # stops conformance suite, starts Keycloak, runs tests
mise run keycloak:down    # stop when done
```

Keycloak will be available at `http://localhost:8080` (HTTP) and
`https://localhost:8443` (HTTPS/mTLS). Admin credentials: `admin`/`admin`.

Or manually:

```sh
mise run keycloak:up
cargo test --manifest-path ../huskarl/Cargo.toml --features keycloak-tests
```

## OpenID Conformance Suite Tests

Tests in `huskarl-conformance/` that validate huskarl against the
[OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite).
Runs the official test plans for OIDC Basic RP certification and FAPI 2.0 Security
Profile.

```sh
mise run conformance:test         # stops Keycloak, starts suite, runs all tests
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
