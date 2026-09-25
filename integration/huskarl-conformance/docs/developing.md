# Developing conformance scenarios


`runner::Runner` owns suite readiness, plan creation, sequential module execution,
verdict polling, and evidence capture/export. After a module reaches `WAITING`,
it reads `/api/runner/{id}` and records the exposed `issuer` and `accounts_endpoint`
in module evidence. Scenarios access these through `module.exposed`; discovery
continues to use the configured plan alias. Accounts requests use the exposed URL
without reconstructing its path, and missing or invalid resource URLs fail explicitly. Its `Deadlines` defaults are 60 seconds
for suite startup, 30 seconds for each status wait, and 180 seconds for an entire
module. A module timeout records a harness error and preserves observations already
collected before continuing to the next module.

Each test supplies plan configuration, variants, and an async scenario callback.
The callback receives the created module, its effective variant, and mutable client evidence.
Suite-provided module overrides are sent when creating each module and shallowly
merged over the plan variant for scenario execution and client checks. Each module's
`effective_variant` is recorded in `report.json`; the plan retains the raw overrides.
Scenarios with preconfigured clients reject settings they cannot honor as harness
errors rather than silently executing the plan-wide configuration. Return errors
for harness failures; record expected protocol rejections in `authorization` or
`resources` so the runner can still collect the suite verdict. Modules already
finished or interrupted during readiness do not invoke the callback.
Register each module's expected client outcome in `src/expectations.rs`. These
assertions run after the scenario and do not affect protocol actions. Capture
client errors with `ClientError::capture` before converting them to strings.
Public error types supply rejection reasons; a few private library causes use
specific diagnostic messages, which deliberately fail closed if wording changes.

`flow::FlowContext` holds the HTTP/browser clients and registered loopback listener.
`AuthorizationOptions` selects client ID, scopes, response mode, authorization
details, and optional PAR preference; authentication,
DPoP, and request signing are generic arguments to `authorize`. Registration and
resource actions remain scenario-specific, allowing a scenario to supply newly
registered credentials without changing the lifecycle runner.

For multi-flow scenarios, call `prepare_authorization` once per module and reuse
its result with `authorize_prepared`. This preserves JWKS state across flows while
generating fresh authorization state/nonce values. `discover` supports modules
that require metadata retrieval without authorization.

Run harness tests from the repository root:

```sh
cargo test -p huskarl-conformance
python3 -B -m unittest discover -s integration/huskarl-conformance/tools -v
```
