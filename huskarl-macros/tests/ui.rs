#![cfg(not(target_family = "wasm"))]

// The pass cases only need to compile, which works on any toolchain.
#[test]
fn ui_pass() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/pass_*.rs");
}

// The .stderr snapshots are recorded against nightly diagnostics; stable and
// MSRV toolchains render errors differently, so only compare them on nightly.
#[rustversion::attr(
    not(nightly),
    ignore = "stderr snapshots are pinned to nightly diagnostics"
)]
#[test]
fn ui_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/fail_*.rs");
}
