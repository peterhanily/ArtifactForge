#!/usr/bin/env bash
# Produce or check a machine-readable scanner attestation.
#
# A clean line on a terminal is not evidence. Run mode binds every result to an exact corpus
# manifest, records engine/rule identity, command, UTC time, control, coverage, exclusions,
# errors and non-proof boundary, then immediately applies the same fail-closed checker used by
# check mode. Missing scanners, missing controls, partial rule loads and scan errors are red —
# never SKIPPED. Default Linux tests use fixtures/fakes and do not require platform scanners.
set -euo pipefail
cd "$(dirname "$0")/.."

AF=${AF:-.venv/bin/artifactforge}
PY=${PY:-.venv/bin/python}

usage() {
  echo "usage: scripts/scan-exposure.sh --output ATTESTATION.json" >&2
  echo "       scripts/scan-exposure.sh --check ATTESTATION.json [--corpus DIR]" >&2
  echo "run mode also reads YARA_RULES=/path/to/community/rules" >&2
}

if [ "${1:-}" = "--check" ]; then
  [ "$#" -ge 2 ] || { usage; exit 2; }
  RECORD=$2
  shift 2
  exec "$PY" scripts/scanner_attestation.py check "$RECORD" "$@"
fi

if [ "${1:-}" != "--output" ] || [ "$#" -ne 2 ]; then
  usage
  exit 2
fi
OUTPUT=$2

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "== building exact corpus: fresh 20-scenario batch plus committed gallery =="
"$AF" bench new "$WORK/batch" --n 20 >/dev/null
mkdir -p "$WORK/corpus"
mkdir -p "$WORK/corpus/generated" "$WORK/corpus/gallery"
cp -R "$WORK/batch/scenarios/." "$WORK/corpus/generated/"
cp -R samples/. "$WORK/corpus/gallery/"
find "$WORK/corpus" -type f \( \
  -name README.md -o -name ARTIFACT_ANSWERS.json -o -name .DS_Store \
\) -delete

EXPECTED=$(find "$WORK/batch/scenarios" samples -type f \
  ! -name README.md ! -name ARTIFACT_ANSWERS.json ! -name .DS_Store | wc -l | tr -d ' ')
ACTUAL=$(find "$WORK/corpus" -type f | wc -l | tr -d ' ')
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "corpus copy lost files: expected $EXPECTED, found $ACTUAL" >&2
  exit 1
fi
echo "   $ACTUAL collision-free files"

# A missing rule checkout is passed as a nonexistent path. The producer records that as an
# error result and the checker fails; it is never silently omitted from the required set.
YARA_RULE_ROOT=${YARA_RULES:-"$WORK/missing-community-yara-rules"}

echo "== running required scanners and writing attestation =="
"$PY" scripts/scanner_attestation.py run \
  --corpus "$WORK/corpus" \
  --yara-rules "$YARA_RULE_ROOT" \
  --output "$OUTPUT"
