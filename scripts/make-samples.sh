#!/usr/bin/env bash
# Regenerate samples/ from scratch, deterministically.
#
# The gallery is built from a DEV suite — the key is published in the source, so anyone can
# reproduce these bytes exactly and check that the committed files are what this script
# produces. That is the point of committing them at all.
#
# The SQLite version is recorded because it is embedded in the macOS database headers: a
# different sqlite3 produces different bytes, and that is a disclosed tell rather than a bug.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PY:-.venv/bin/python}
AF=${AF:-.venv/bin/artifactforge}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

"$AF" bench new "$WORK/suite" --n 2 --kind dev >/dev/null

WIN=$("$PY" -c "import json;print(next(s['scenario_id'] for s in json.load(open('$WORK/suite/public.json'))['scenarios'] if s['family']=='windows'))")
MAC=$("$PY" -c "import json;print(next(s['scenario_id'] for s in json.load(open('$WORK/suite/public.json'))['scenarios'] if s['family']=='macos'))")

rm -rf samples/01-windows-dropper samples/02-macos-quarantined-app
mkdir -p samples/01-windows-dropper samples/02-macos-quarantined-app
cp "$WORK/suite/scenarios/$WIN"/* samples/01-windows-dropper/
cp "$WORK/suite/scenarios/$MAC"/* samples/02-macos-quarantined-app/

"$PY" scripts/write_sample_docs.py \
  --suite "$WORK/suite" --windows "$WIN" --macos "$MAC"

echo "regenerated samples/ (sqlite3 $("$PY" -c 'import sqlite3;print(sqlite3.sqlite_version)'))"
