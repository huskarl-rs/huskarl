# huskarl-core fuzz targets

Coverage-guided fuzzing of the attacker-facing parsers (see
`crypto-layer-issues.md` §7 at the repo root for the rationale).

| Target | Surface |
|---|---|
| `parse_compact_jws` | Compact JWS parsing, incl. full `JwtHeader`/embedded-`jwk` deserialization; asserts the signing-input invariant |
| `unseal_v1` | v1 sealed-bundle header parsing and slicing, via a passthrough decryptor |
| `jwks` | `Jwks` JSON ingestion, RFC 7638 thumbprints, private→public conversion |
| `challenges` | RFC 7235 `WWW-Authenticate` challenge parsing (lives in the `huskarl` client crate); asserts scheme/token68 invariants |

## Running locally

```sh
mise run fuzz jwks            # until interrupted
mise run fuzz jwks --time 60  # bounded
```

The task seeds from `seeds/<target>/` (checked in), writes coverage-novel
inputs to `corpus/<target>/` (gitignored scratch; CI accumulates it in a
cache across weekly runs), and pins the host triple — a Rosetta-installed
cargo-fuzz binary otherwise defaults to x86_64 on Apple Silicon. Requires
nightly (the default toolchain here).

The equivalent raw invocation, from `huskarl-core/`:

```sh
cargo fuzz run jwks fuzz/corpus/jwks fuzz/seeds/jwks -- -max_len=16384
```

(libFuzzer writes new inputs to the first directory and only reads the
rest.) Crashes land in `artifacts/<target>/` (gitignored) — reproduce with
`cargo fuzz run <target> artifacts/<target>/<file>`.

## Coverage

```sh
mise run fuzz-coverage jwks
```

Replays the accumulated corpus through an instrumented build and prints an
llvm-cov table plus an HTML report (`fuzz/coverage/<target>/index.html`).
Read the per-file rows for the target's parsing surface (e.g. `jwk/mod.rs`
for `jwks`), not TOTAL — all of huskarl-core is linked in, so the total is
diluted by code the target never calls. A plateauing per-file number across
runs means the fuzzer has exhausted what it can reach.
