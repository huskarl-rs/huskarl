# huskarl-conformance

Integration tests that run huskarl against the
[OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite).

## Prerequisites

### DNS

The conformance suite expects to be reached at `localhost.emobix.co.uk`.
This hostname must resolve to `127.0.0.1` on the machine running the tests.

Check with:

```sh
dig +short localhost.emobix.co.uk
```

If it doesn't resolve (e.g. due to DNS filtering or a corporate proxy), add
an entry to `/etc/hosts`:

```
127.0.0.1  localhost.emobix.co.uk
```

### Docker

Start the conformance suite:

```sh
docker compose -f docker/docker-compose-prebuilt.yml up --wait
```

The tests will automatically wait up to 60 seconds for the suite to become
ready before creating test plans.

## Running

```sh
cargo test -p huskarl-conformance --features conformance-suite-tests -- --nocapture
```

Run a single test file:

```sh
cargo test -p huskarl-conformance --test oidc --features conformance-suite-tests -- --nocapture
cargo test -p huskarl-conformance --test fapi2 --features conformance-suite-tests -- --nocapture
```

## Environment variables

| Variable                    | Default                                  | Description                  |
|-----------------------------|------------------------------------------|------------------------------|
| `CONFORMANCE_SUITE_BASE`    | `https://localhost.emobix.co.uk:8443`    | Base URL of the suite        |
| `CONFORMANCE_CLIENT_ID`     | `client`                                 | OAuth client ID              |
| `CONFORMANCE_CLIENT_SECRET` | `client-secret`                          | OAuth client secret (OIDC tests) |
