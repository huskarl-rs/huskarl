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
console_rows=""
any_break=0
mismatch=0
unchecked=0

for entry in "${crates[@]}"; do
  crate="${entry%%$'\t'*}"
  dir="${entry#*$'\t'}"
  # Stream diagnostics immediately, keeping group markers and checker output
  # on stdout so GitHub Actions preserves their order.
  if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    printf '::group::cargo-semver-checks %s\n' "$crate"
  else
    printf '\n--- cargo-semver-checks %s ---\n' "$crate"
  fi
  status=0
  cargo semver-checks --package "$crate" --baseline-rev "$base_rev" --color never 2>&1 || status=$?
  printf 'Checker exited %s\n' "$status"
  if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    echo '::endgroup::'
  fi

  # Since cargo-semver-checks 0.49, exit codes distinguish violations (100)
  # from errors (101). Human-readable summary wording is not a stable API.
  if [[ $status -eq 100 ]]; then
    any_break=1
    if crate_declares_break "$dir"; then
      verdict="breaking — declared (has \`!\`/BREAKING CHANGE)"
      row="| \`$crate\` | ⚠️ breaking | ✅ declared |"
    else
      mismatch=1
      verdict="BREAKING — commit type UNDERSTATES it"
      row="| \`$crate\` | ⚠️ breaking | ❌ **commit type understates — re-tag \`type!:\` or add \`BREAKING CHANGE:\`** |"
    fi
  elif [[ $status -eq 0 ]]; then
    verdict="compatible"
    row="| \`$crate\` | compatible | — |"
  else
    unchecked=$((unchecked + 1))
    verdict="could not check (exit $status; see diagnostics)"
    row="| \`$crate\` | ⚠️ unchecked | checker exited $status; see CI log |"
  fi
  console_rows+="$(printf '%-26s %s' "$crate" "$verdict")"$'\n'
  rows+="$row"$'\n'
done

echo
printf '%-26s %s\n' "CRATE" "VERDICT"
printf '%-26s %s\n' "-----" "-------"
printf '%s' "$console_rows"
echo
if [[ $mismatch -eq 1 ]]; then
  echo "RESULT: semver-affecting; at least one commit type understates a breaking change."
elif [[ $any_break -eq 1 ]]; then
  echo "RESULT: semver-affecting; breaking changes are correctly declared."
elif [[ $unchecked -gt 0 ]]; then
  echo "RESULT: inconclusive ($unchecked crate(s) could not be checked vs $base_rev)."
else
  echo "RESULT: not semver-affecting (no breaking API changes vs $base_rev)."
fi
if [[ $unchecked -gt 0 && $any_break -eq 1 ]]; then
  echo "Report incomplete: $unchecked crate(s) could not be checked; additional breaking changes may exist."
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
    elif [[ $unchecked -gt 0 ]]; then
      echo "**Inconclusive:** $unchecked crate(s) could not be checked. See the CI log for checker diagnostics."
    else
      echo "No breaking API changes detected. Not semver-affecting."
    fi
    if [[ $unchecked -gt 0 && $any_break -eq 1 ]]; then
      echo
      echo "**Report incomplete:** $unchecked crate(s) could not be checked; additional breaking changes may exist."
    fi
    echo
    echo "<sub>cargo-semver-checks detects breaking changes only; it can't tell \`feat\` from \`fix\` when neither breaks the API.</sub>"
  } >"$SEMVER_REPORT"
fi

exit 0
