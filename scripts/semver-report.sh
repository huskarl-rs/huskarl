#!/usr/bin/env bash
# Report whether this branch is semver-affecting, per publishable crate, and
# cross-check each breaking crate against its commits' conventional-commit type.
#
# cargo-semver-checks only detects *breaking* API changes, so the only class of
# mislabelled commit it can catch is a change tagged patch/minor (no `!`, no
# `BREAKING CHANGE:`) whose public API actually broke — the direction worth
# catching. It cannot tell `feat` from `fix` when neither breaks the API.
#
# Usage: scripts/semver-report.sh [baseline-ref]   (default: origin/main)
# Set SEMVER_REPORT=<path> to also write a Markdown report (used by CI).
# Always exits 0: this reports, it does not gate.
#
# Works under both git (CI: HEAD is the PR head) and a colocated jj repo (dev:
# the tip we evaluate is `@`, the working copy, not git's HEAD which tracks @-).
# In jj mode revisions resolve to their underlying git commit ids, which is what
# cargo-semver-checks' --baseline-rev consumes.
set -euo pipefail

base_ref="${1:-${SEMVER_BASELINE:-origin/main}}"

if command -v jj >/dev/null 2>&1 && jj root >/dev/null 2>&1; then
  vcs=jj
  tip_rev="$(jj log --no-graph -r @ -T commit_id)"
else
  vcs=git
  tip_rev="$(git rev-parse HEAD)"
fi

# Compare against the fork point, not the tip of the base branch, so breaks that
# the base introduced independently aren't attributed to this branch. The git
# store underlies jj too, so merge-base is computed with git in both modes.
base_rev="$(git merge-base "$base_ref" "$tip_rev" 2>/dev/null || echo "$base_ref")"

# Publishable library crates only: skip publish=false integration crates, the
# proc-macro crate (no introspectable API), and the wasm32-only crate (its
# rustdoc won't build on the host target).
crates=()
while IFS= read -r entry; do
  crates+=("$entry")
done < <(
  cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p.get("publish") == []:
        continue
    if "lib" not in {k for t in p["targets"] for k in t["kind"]}:
        continue
    if p["name"] == "huskarl-crypto-webcrypto":
        continue
    print(p["name"], p["manifest_path"].rsplit("/", 1)[0], sep="\t")
'
)

# Publishable dependency edges, as "dependent<TAB>dependency". Dev-dependencies
# are excluded: they never reach a downstream user. Unlike `crates` above this
# keeps huskarl-crypto-webcrypto — unverifiable on the host, but still draggable.
edges="$(
  cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
pkgs = json.load(sys.stdin)["packages"]
pub = {p["name"] for p in pkgs if p.get("publish") != []}
edges = {
    (p["name"], d["name"])
    for p in pkgs if p["name"] in pub
    for d in p["dependencies"] if d["kind"] in (None, "build") and d["name"] in pub
}
for dependent, dependency in sorted(edges):
    print(dependent, dependency, sep="\t")
'
)"

# Manifest directory per publishable crate, keyed by name.
dirs="$(
  cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p.get("publish") != []:
        print(p["name"], p["manifest_path"].rsplit("/", 1)[0], sep="\t")
'
)"

# Full messages of the commits in base_rev..tip that touch a crate's directory.
crate_messages() {
  local dir="$1"
  if [[ $vcs == jj ]]; then
    # `description` is the whole message; separate commits so subjects stay on
    # their own line for the `^type!:` match below.
    jj log --no-graph -r "${base_rev}..${tip_rev} & files(\"$dir\")" \
      -T 'description ++ "\n\n"' 2>/dev/null
  else
    git log --format='%B' "$base_rev..$tip_rev" -- "$dir"
  fi
}

# A commit declares a break if a subject is `type(scope)!:` or the body carries
# a `BREAKING CHANGE:` / `BREAKING-CHANGE:` footer (Conventional Commits).
crate_declares_break() {
  local msgs
  msgs="$(crate_messages "$1")"
  grep -qE '^[a-z]+(\([^)]*\))?!:' <<<"$msgs" && return 0
  grep -qE '^BREAKING[ -]CHANGE:' <<<"$msgs" && return 0
  return 1
}

rows=""
any_break=0
mismatch=0
breaking_crates=""
printf '%-26s %s\n' "CRATE" "VERDICT"
printf '%-26s %s\n' "-----" "-------"

for entry in "${crates[@]}"; do
  crate="${entry%%$'\t'*}"
  dir="${entry#*$'\t'}"
  out="$(cargo semver-checks --package "$crate" --baseline-rev "$base_rev" --color never 2>&1)" || true

  if grep -q "requires new" <<<"$out"; then
    any_break=1
    breaking_crates+="$crate"$'\n'
    if crate_declares_break "$dir"; then
      verdict="breaking — declared (has \`!\`/BREAKING CHANGE)"
      row="| \`$crate\` | ⚠️ breaking | ✅ declared |"
    else
      mismatch=1
      verdict="BREAKING — commit type UNDERSTATES it"
      row="| \`$crate\` | ⚠️ breaking | ❌ **commit type understates — re-tag \`type!:\` or add \`BREAKING CHANGE:\`** |"
    fi
  elif grep -q "no semver update required" <<<"$out"; then
    verdict="compatible"
    row="| \`$crate\` | compatible | — |"
  else
    verdict="could not check (build error / no baseline)"
    row="| \`$crate\` | ⚠️ unchecked | build error or missing baseline |"
  fi
  printf '%-26s %s\n' "$crate" "$verdict"
  rows+="$row"$'\n'
done

# A crate that exposes a broken dependency's types breaks too, even though its
# own API is textually unchanged: its requirement moves out of range, so a
# downstream pinned to the old version compiles against two incompatible copies.
# cargo-semver-checks sees one crate at a time and reads that as "patch"
# (cargo-semver-checks#447, blocked on cross-crate items #638; release-plz#1599
# punted to it). Distinguishing exposure from internal use needs the same
# introspection, so flag every dependent and let the author confirm.
propagation="$(
  EDGES="$edges" BREAKING="$breaking_crates" python3 -c '
import collections, os
breaking = {line for line in os.environ["BREAKING"].splitlines() if line}
if not breaking:
    raise SystemExit
dependents = collections.defaultdict(set)
for line in filter(None, os.environ["EDGES"].splitlines()):
    dependent, dependency = line.split("\t")
    dependents[dependency].add(dependent)
# Breadth-first over the reverse graph, seeded with the crates that broke on
# their own account — those already bump incompatibly, so they are not results.
cause, queue = {}, sorted(breaking)
while queue:
    crate = queue.pop(0)
    for dependent in sorted(dependents[crate]):
        if dependent not in breaking and dependent not in cause:
            cause[dependent] = crate
            queue.append(dependent)
for crate in sorted(cause):
    print(crate, cause[crate], sep="\t")
'
)"

propagation_lines=""
propagation_rows=""
while IFS=$'\t' read -r crate cause; do
  [[ -n "$crate" ]] || continue
  dir="$(grep -m1 "^$crate"$'\t' <<<"$dirs" | cut -f2)"
  # A crate whose own commits declare a break already bumps incompatibly; only
  # the ones release-plz would silently patch-bump are worth listing.
  if [[ -n "$dir" ]] && crate_declares_break "$dir"; then
    continue
  fi
  propagation_lines+="$(printf '  %-24s incompatible bump needed — depends on %s' "$crate" "$cause")"$'\n'
  propagation_rows+="| \`$crate\` | \`$cause\` |"$'\n'
done <<<"$propagation"

if [[ -n "$propagation_rows" ]]; then
  echo
  echo "Dependents of a breaking crate (cargo-semver-checks cannot see these):"
  printf '%s' "$propagation_lines"
fi

echo
if [[ $mismatch -eq 1 ]]; then
  echo "RESULT: semver-affecting; at least one commit type understates a breaking change."
elif [[ $any_break -eq 1 ]]; then
  echo "RESULT: semver-affecting; breaking changes are correctly declared."
else
  echo "RESULT: not semver-affecting (no breaking API changes vs $base_rev)."
fi
if [[ -n "$propagation_rows" ]]; then
  echo "        Dependents listed above need an incompatible bump too."
fi

if [[ -n "${SEMVER_REPORT:-}" ]]; then
  {
    echo "### 📦 Semver report"
    echo
    echo "Baseline: \`$base_ref\` (merge-base \`$(git rev-parse --short "$base_rev")\`)"
    echo
    echo "| Crate | API vs baseline | Conventional commit |"
    echo "| --- | --- | --- |"
    printf '%s' "$rows"
    echo
    if [[ $mismatch -eq 1 ]]; then
      echo "⚠️ **A breaking change is tagged as non-breaking.** On a 0.x crate a breaking"
      echo "change is a minor bump and needs \`type!:\` or a \`BREAKING CHANGE:\` footer so"
      echo "release-plz bumps correctly."
    elif [[ $any_break -eq 1 ]]; then
      echo "This PR is **semver-affecting**; the breaking changes are correctly declared."
    else
      echo "No breaking API changes detected. Not semver-affecting."
    fi
    echo
    if [[ -n "$propagation_rows" ]]; then
      echo "#### ⛓️ Breaks that must propagate"
      echo
      echo "These crates' own APIs are unchanged, so release-plz will patch-bump them —"
      echo "but their in-workspace requirement moves to an incompatible range. Any that"
      echo "expose the broken crate's types in their own API need a minor bump too, or a"
      echo "downstream \`cargo update\` silently pulls in two incompatible copies."
      echo
      echo "| Crate | Depends on |"
      echo "| --- | --- |"
      printf '%s' "$propagation_rows"
      echo
    fi
    echo "<sub>cargo-semver-checks detects breaking changes only; it can't tell \`feat\` from \`fix\` when neither breaks the API, and it can't see a break arriving through a dependency ([#447](https://github.com/obi1kenobi/cargo-semver-checks/issues/447)) — that last part is what the propagation table covers.</sub>"
  } >"$SEMVER_REPORT"
fi

exit 0
