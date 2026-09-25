# Evidence reference

[Run instructions](../README.md). Each plan has a unique directory under
`target/conformance`, configurable with `CONFORMANCE_EVIDENCE_DIR`.

## Artifacts

| Artifact | Contents |
|---|---|
| `report.json` | Plan and module identities, variants, provenance, client observations, verdicts, and artifact paths |
| `client-logs/*.log` | One RP evidence file per module, containing its observations and provenance |
| `suite-logs/module-N.json` | Full suite metadata (`testInfo`) and condition logs (`results`), including unknown fields |
| `suite-export.zip` | The suite's signed JSON export |

All artifacts use atomic replacement. Each module's client and suite logs are
written once; the report is updated after each module and at completion.
Completed modules retain their evidence if execution stops before the final
export. Interruption during a module or its download can lose that module's data.
Configuration failures before plan creation have no report.

Client filenames begin with the test name, followed by the response type when
present and a sequence number, for example
`oidcc-client-test-invalid-iss_code-id_token-3.log`. The sequence distinguishes
repeated tests. Upload these client files using the workflow in the README.

## Report fields (schema version 2)

| Field | Meaning |
|---|---|
| `run` | Plan, variants, suite URL, revision, dirty state, TLS setting, start time, and export status |
| `run.local_cached_images` | Local cached image digests; not proof of the running server version |
| `run.elapsed_seconds` | Time from evidence initialization through export, including collection |
| `run.incremental_suite_evidence` | Indicates that per-module raw suite files are required |
| `modules[].effective_variant` | Plan variant merged with module overrides |
| `preparation`, `registration`, `token_exchange` | Discovery/grant setup, dynamic registration, and client-credentials exchange outcomes, when performed |
| `authorization_attempts` | Ordered authorizations and resource results, including both key-rotation flows |
| `authorization`, `resources` | Final attempt's outcomes; absent resources were not requested |
| `client_check` | Independent check of the observed client behavior |
| `suite`, `harness_error` | Suite status/result and any harness failure |
| `suite_log`, `client_log` | Relative artifact paths |
| `suite_evidence_error` | Failure to collect or save raw suite evidence |
| `elapsed_seconds` | Module creation, protocol execution, and verdict waiting; excludes evidence download |
| `conditions.counts` | Counts for every suite condition-result category |
| `conditions.diagnostics` | FAILURE, WARNING, and REVIEW source, message, block ID, and timestamp |
| `counts`, `client_check_failures` | Module verdict counts and unsuccessful/missing client checks |

Client errors contain `{ "message": "...", "rejection": ... }`, preserving the
cause chain and classified rejection. Successful UserInfo validation has no HTTP
status; FAPI accounts results include the final HTTP status.

## Outcome rules

Positive scenarios must complete all expected operations. Negative scenarios
must reject at the expected operation for the expected reason; transport/setup
errors do not qualify. Unknown modules require a registered expectation.

FAILED, INTERRUPTED, incomplete/unknown results, harness errors, failed client
checks, and evidence collection/write/export errors fail the run. WARNING,
REVIEW, and SKIPPED require manual review and cannot override a failed client
check. A module skipped before client activity does not require that activity.
Condition summaries provide diagnostics without changing these rules.

## Export and readiness checks

Export downloads retry transient HTTP/network errors and invalid archives up to
five times, with delays of 1, 2, 4, and 8 seconds. Permanent client errors such as
401/403 fail immediately. Every ZIP entry is read to EOF to validate decompression
and CRC before saving; this does not verify cryptographic signatures.

Readiness matches plan, variant, revision, and suite URL. It selects the latest
completed matching run, including a failed one, and flags newer incomplete runs.
It checks clean revision provenance, complete module coverage, identities and
variants, verdicts, client-log consistency, and export integrity. For reports
with incremental evidence it also checks raw-log identity, verdict, condition
counts, and module durations. Older reports remain readable. Malformed evidence
is reported as a blocker.

## Storage and provenance

Evidence can contain credentials or tokens in raw suite data, diagnostic messages,
and container logs. Keep it private and inspect files before uploading.

CI uploads the evidence directory, running-container image metadata, and container
logs on success or failure, retaining them for 14 days. Use the suite export and
CI metadata to identify the running build. Pin `IMAGE_TAG` for reproducible local
runs; `latest` tracks upstream development.

## Configuration


| Variable                    | Default                                  | Description                  |
|-----------------------------|------------------------------------------|------------------------------|
| `CONFORMANCE_SUITE_BASE`    | `https://localhost.emobix.co.uk:8443`    | Base URL of the suite        |
| `CONFORMANCE_CLIENT_ID`     | `client`                                 | OAuth client ID              |
| `CONFORMANCE_CLIENT_SECRET` | `client-secret`                          | OAuth client secret (OIDC tests) |
| `CONFORMANCE_API_TOKEN` | unset | Bearer token for the suite management API only |
| `CONFORMANCE_INSECURE_TLS` | `false` | Accept self-signed certificates for local testing; `true`/`false` or `1`/`0` |
| `CONFORMANCE_REQUEST_TIMEOUT_SECONDS` | `30` | Positive HTTP request timeout, shared by all clients |
| `CONFORMANCE_EVIDENCE_DIR` | workspace `target/conformance` | Evidence root; each plan gets a unique subdirectory |
| `IMAGE_TAG` | `latest` | Local server/nginx image tag; also used for cached-image provenance |

