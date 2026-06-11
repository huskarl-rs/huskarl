#![cfg(not(target_family = "wasm"))]

// The .stderr snapshots are recorded against nightly diagnostics; stable and
// MSRV toolchains render errors differently, so only compare them on nightly.
#[rustversion::attr(
    not(nightly),
    ignore = "stderr snapshots are pinned to nightly diagnostics"
)]
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/pass_*.rs");
    t.compile_fail("tests/ui/fail_*.rs");
}
