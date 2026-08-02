#!/usr/bin/env bash
# The whole story: generate privately, export exactly, solve publicly, grade as unreportable,
# then run every gate at its declared population.
set -euo pipefail
cd "$(dirname "$0")/.."
AF=${AF:-.venv/bin/artifactforge}
WORK=$(mktemp -d)
cleanup() {
  # Public exports are intentionally 0555/0444. Restore only this exact mktemp workspace so
  # the shell can remove its own demonstration output on POSIX hosts.
  chmod -R u+w -- "$WORK" 2>/dev/null || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT

set -x
"$AF" bench new "$WORK/suite" --n 4 --kind holdout
ls "$WORK/suite/scenarios/$(ls "$WORK/suite/scenarios" | head -1)"
"$AF" bench export "$WORK/suite" "$WORK/public"
"$AF" bench solve "$WORK/public" --out "$WORK/answers.jsonl"
"$AF" bench grade "$WORK/suite" --submission "$WORK/answers.jsonl"
set +x

for g in identity validity inertness; do
  "$AF" gate "$g" --n 8 || { echo "FAILED: gate $g is expected to pass" >&2; exit 1; }
done

echo
echo "Gates 1-3 passed; the local benchmark grade remains explicitly unreportable."
echo "Gate 4 is not asserted here: a fresh-holdout non-detection is stochastic by design."
echo "Release validation uses the deterministic, source-bound scorecard measurement instead."
