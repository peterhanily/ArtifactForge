#!/usr/bin/env bash
# The whole story in one short run: generate, solve, grade, and check the keystone.
# Not -e on the gates: Gate 4 is deliberately red and exits non-zero, which is the system
# working rather than the demo breaking. Each gate's status is reported explicitly instead.
set -uo pipefail
cd "$(dirname "$0")/.."
AF=${AF:-.venv/bin/artifactforge}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

set -x
"$AF" bench new "$WORK/suite" --n 4 --kind holdout
ls "$WORK/suite/scenarios/$(ls "$WORK/suite/scenarios" | head -1)"
"$AF" bench solve "$WORK/suite" --out "$WORK/answers.jsonl"
"$AF" bench grade "$WORK/suite" --submission "$WORK/answers.jsonl"
set +x

for g in identity validity inertness; do
  "$AF" gate "$g" --n 8 || { echo "FAILED: gate $g is expected to pass" >&2; exit 1; }
done

# Gate 4 must FAIL. If it ever passes, the benchmark was fixed and this script, the README
# and the scorecard baseline all need updating together.
if "$AF" gate solvability --n 8; then
  echo "Gate 4 unexpectedly PASSES — re-measure and update the README" >&2
  exit 1
fi
echo
echo "Gate 4 failed, as documented. See README \"Benchmark validity\"."
