# huskarl-conformance

Runs Huskarl's RP/client tests against the [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite).

**Run all commands below from the repository root.** Rust/Cargo is required to
run tests; the preset tool needs Python 3.10+ and no Python dependencies.

## 1. Select presets

```sh
python3 integration/huskarl-conformance/tools/certification.py list
```

| Preset | Coverage |
|---|---|
| `oidc-basic` | OIDC Basic, authorization code |
| `oidc-configuration` | Discovery and signing-key rotation |
| `oidc-form-post` | OIDC Basic with form-post responses |
| `fapi2-security` | FAPI 2 Security Profile |
| `fapi2-message-signing` | Signed requests, plain responses |
| `fapi2-message-signing-jarm` | Signed requests and JARM responses |
| `fapi2-client-credentials` | FAPI 2 client credentials |

OIDC presets use static registration and `client_secret_basic`. FAPI presets use
`private_key_jwt` and DPoP. Select the profiles/configurations you intend to
certify; these presets are a starting point. See [full coverage](docs/coverage.md)
for additional authentication, registration, mTLS, OAuth, and RAR variants.

## 2. Run

For hosted testing, set `CONFORMANCE_API_TOKEN` to your suite API token, then run
the selected presets, for example:

```sh
python3 integration/huskarl-conformance/tools/certification.py run \
  --preset oidc-basic --preset oidc-configuration --preset oidc-form-post \
  --suite-base https://www.certification.openid.net
```

The tool runs exact tests sequentially and stops on failure. TLS verification is
enabled. Add `--dry-run` to inspect commands first. The authorization callback uses
a local loopback listener, with the HTTP browser running on the same machine.

### Local suite

Docker is required. Ensure `localhost.emobix.co.uk` resolves to `127.0.0.1`:

```sh
dig +short localhost.emobix.co.uk
docker compose -f integration/huskarl-conformance/docker/docker-compose-prebuilt.yml up --pull always --wait
```

If DNS is blocked, add `127.0.0.1 localhost.emobix.co.uk` to `/etc/hosts`.
Use the local URL and allow its self-signed certificate explicitly:

```sh
python3 integration/huskarl-conformance/tools/certification.py run \
  --preset oidc-basic \
  --suite-base https://localhost.emobix.co.uk:8443 --insecure-tls
```

To run the complete regression matrix:

```sh
CONFORMANCE_INSECURE_TLS=true cargo test -p huskarl-conformance --features conformance-suite-tests -- --nocapture
```

Narrow a Cargo run with `--test oidc`, `--test fapi2`, or `--test client_credentials`
and an optional test-name filter. The suite exposes TLS on 8443 and mTLS on
8444/8445. Tests wait up to 60 seconds for startup.

## 3. Check readiness

Run from a clean revision and retain its full ID (`git rev-parse HEAD`). Inspect
the saved evidence for that revision and the same selected presets/suite:

```sh
python3 integration/huskarl-conformance/tools/certification.py ready \
  --preset oidc-basic --preset oidc-configuration --preset oidc-form-post \
  --suite-base https://www.certification.openid.net \
  --revision FULL_GIT_REVISION \
  --output /tmp/huskarl-certification-readiness.md
```

Replace `FULL_GIT_REVISION` with the tested revision. Exit status 0 means evidence
checks passed; 1 means blockers or operational errors; 2 means invalid arguments.
WARNING, REVIEW, and SKIPPED outcomes still need inspection. Readiness does not
publish results or establish certification approval.

Both commands accept `--evidence-dir` (default: `target/conformance`, or
`CONFORMANCE_EVIDENCE_DIR`). Omit `--output` to print the checklist. Details of
validation, artifacts, and environment settings are in the [evidence reference](docs/evidence.md).

## 4. Publish

Inspect the checklist and each plan's `client-logs/`, resolve review items, then
use **Publish for certification** in the suite UI and upload the per-test client
files. Retain the resulting certification ZIP for submission. The automatically
saved `suite-export.zip` is an ordinary export and does not replace that ZIP.

Evidence can contain sensitive test data; keep it private and inspect files
before sharing. Publishing is manual.

## Extending the harness

See [scenario development](docs/developing.md). To select another existing Rust
test, add a preset or pass `--presets-file PATH` before `run`, `ready`, or `list`.
Each preset specifies its description, test binary, exact test name, suite plan,
and plan-level variant. Module overrides come from the suite. A new preset does
not implement a new protocol scenario.
