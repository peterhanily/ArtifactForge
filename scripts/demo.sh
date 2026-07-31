#!/usr/bin/env bash
# The whole story in one short run: generate, solve, grade, and check the keystone.
set -euo pipefail
cd "$(dirname "$0")/.."
AF=${AF:-.venv/bin/artifactforge}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

set -x
"$AF" bench new "$WORK/suite" --n 4 --kind holdout
ls "$WORK/suite/scenarios/$(ls "$WORK/suite/scenarios" | head -1)"
"$AF" bench solve "$WORK/suite" --out "$WORK/answers.jsonl"
"$AF" bench grade "$WORK/suite" --submission "$WORK/answers.jsonl"
"$AF" gate identity
"$AF" gate solvability
