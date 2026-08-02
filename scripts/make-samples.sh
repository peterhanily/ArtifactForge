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
"$AF" fixture build examples/fixtures/linux-glibc-x86_64-loose-v1.json \
  "$WORK/linux-fixture" >/dev/null

WIN=$("$PY" -c "import json;print(next(s['scenario_id'] for s in json.load(open('$WORK/suite/public.json'))['scenarios'] if s['family']=='windows'))")
MAC=$("$PY" -c "import json;print(next(s['scenario_id'] for s in json.load(open('$WORK/suite/public.json'))['scenarios'] if s['family']=='macos'))")

rm -rf samples/01-windows-dropper samples/02-macos-quarantined-app \
       samples/03-linux-autostart-history
mkdir -p samples/01-windows-dropper samples/02-macos-quarantined-app \
         samples/03-linux-autostart-history
# `source/*` silently drops dot-prefixed evidence and cannot preserve a recursive scene.
# Copy each complete generated tree, then compare every canonical relative path and byte
# through the same no-follow inventory the gates use.
cp -R "$WORK/suite/scenarios/$WIN"/. samples/01-windows-dropper/
cp -R "$WORK/suite/scenarios/$MAC"/. samples/02-macos-quarantined-app/
cp -R "$WORK/linux-fixture/artifacts"/. samples/03-linux-autostart-history/

"$PY" - "$WORK/suite/scenarios/$WIN" samples/01-windows-dropper \
          "$WORK/suite/scenarios/$MAC" samples/02-macos-quarantined-app \
          "$WORK/linux-fixture/artifacts" samples/03-linux-autostart-history <<'PY'
import sys

from artifactforge.inventory import inventory_regular_files


def snapshot(path):
    files = inventory_regular_files(path, capture_bytes=True)
    return tuple((file.relative_path, file.data) for file in files)


for source, destination in zip(sys.argv[1::2], sys.argv[2::2], strict=True):
    if snapshot(source) != snapshot(destination):
        raise SystemExit(f"recursive sample copy differs: {source} -> {destination}")
PY

"$PY" scripts/write_sample_docs.py \
  --suite "$WORK/suite" --windows "$WIN" --macos "$MAC" \
  --linux-fixture "$WORK/linux-fixture"

echo "regenerated samples/ (sqlite3 $("$PY" -c 'import sqlite3;print(sqlite3.sqlite_version)'))"
