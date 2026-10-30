#!/usr/bin/env bash
# Checks crates one at a time at their minimum dependency versions. Each is
# resolved alone, with other huskarl crates from crates.io.
#
# Usage: scripts/check-minimal-versions.sh <crate,crate,...> [cargo args]
# Set BOUNDS_RESULTS to append Markdown result rows, and BOUNDS_CHECK to label them.
set -euo pipefail

crates=$1
shift

backup=$(mktemp -d)
cp Cargo.toml Cargo.lock "$backup"
trap 'cp "$backup/Cargo.toml" "$backup/Cargo.lock" .; rm -rf "$backup"' EXIT

status=0
for crate in ${crates//,/ }; do
  cp "$backup/Cargo.toml" Cargo.toml
  perl -0pi -e "s/^members = \[.*?^\]\n/members = [\"$crate\"]\n/ms; s/^default-members = \[.*?^\]\n//ms" Cargo.toml
  rm -f Cargo.lock
  # Keep a separate log for each crate: a resolution failure in one must not
  # conceal a compilation failure in another. Disable color for classification.
  if CARGO_TERM_COLOR=never cargo minimal-versions check --direct --no-dev-deps --detach-path-deps "$@" 2>&1 | tee "$backup/crate.log"; then
    result=passed
  else
    status=1
    if grep -Eq 'failed to select a version|no matching package named' "$backup/crate.log"; then
      result=resolve
    elif grep -q '^error: could not compile' "$backup/crate.log"; then
      result=compile
    else
      result=other
    fi
  fi
  printf '%s: %s\n' "$crate" "$result"
  if [ -n "${BOUNDS_RESULTS:-}" ]; then
    printf '| %s | %s | %s |\n' "${BOUNDS_CHECK:-check}" "$crate" "$result" >> "$BOUNDS_RESULTS"
  fi
done
exit "$status"
