#!/usr/bin/env bash
# What do real scanners make of what we generate?
#
# Committing malware-shaped binaries to a public repository means they will be crawled,
# downloaded and scanned. This runs whatever scanners are on the machine against a fresh
# corpus, and each one is preceded by a POSITIVE CONTROL — a scanner that detects nothing
# because it is misconfigured is indistinguishable from a clean result, which is the same
# trap the gates are built to avoid.
#
# A missing scanner is reported as SKIPPED and the script still exits 0: this is a
# pre-publication check run by a person, not a CI gate. Detections exit 1.
# NOT pipefail. Every scanner here exits non-zero precisely when it DOES detect something —
# clamscan 1, spctl 3 — so under pipefail a `scanner | grep -q` condition takes its status
# from the scanner rather than from grep, and inverts. Output is captured into a variable and
# tested afterwards, so the exit code of the scanner is never mistaken for the answer.
set -u
cd "$(dirname "$0")/.."
AF=${AF:-.venv/bin/artifactforge}
PY=${PY:-.venv/bin/python}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

echo "== building a corpus: a fresh 20-scenario batch plus the committed gallery =="
"$AF" bench new "$WORK/batch" --n 20 >/dev/null
mkdir -p "$WORK/corpus"
find "$WORK/batch/scenarios" -type f -exec cp {} "$WORK/corpus/" \; 2>/dev/null
cp samples/*/* "$WORK/corpus/" 2>/dev/null
rm -f "$WORK/corpus/README.md" "$WORK/corpus/ARTIFACT_ANSWERS.json"
echo "   $(ls "$WORK/corpus" | wc -l | tr -d ' ') files"

# ---------------------------------------------------------------- ClamAV
echo
echo "== ClamAV =="
if command -v clamscan >/dev/null; then
  # EICAR is the industry-standard test string: universally detected, harmless by design.
  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > "$WORK/eicar.com"
  CONTROL=$(clamscan --no-summary "$WORK/eicar.com" 2>&1)
  if [[ "$CONTROL" == *FOUND* ]]; then
    echo "   control: EICAR detected — the scanner works"
    HITS=$(clamscan -r --no-summary "$WORK/corpus" 2>&1 | grep FOUND || true)
    if [ -n "$HITS" ]; then
      echo "$HITS" | sed 's/^/   DETECTION /'; FAILED=1
    else
      echo "   result:  0 detections across $(ls "$WORK/corpus" | wc -l | tr -d ' ') files"
    fi
  else
    echo "   SKIPPED: clamscan did not detect EICAR, so a clean result would mean nothing."
    echo "            Run freshclam to download signatures."
  fi
else
  echo "   SKIPPED: clamscan not installed (brew install clamav && freshclam)"
fi

# ---------------------------------------------------------------- Apple XProtect
echo
echo "== Apple XProtect (the signature set macOS actually scans downloads with) =="
"$PY" scripts/scan_yara.py --xprotect --corpus "$WORK/corpus" || FAILED=1

# ---------------------------------------------------------------- community YARA
echo
echo "== community YARA rules =="
if [ -d "${YARA_RULES:-}" ]; then
  "$PY" scripts/scan_yara.py --rules "$YARA_RULES" --corpus "$WORK/corpus" || FAILED=1
else
  echo "   SKIPPED: set YARA_RULES to a checkout of github.com/Yara-Rules/rules"
fi

# ---------------------------------------------------------------- Gatekeeper
echo
echo "== Gatekeeper and codesign (macOS only) =="
if command -v spctl >/dev/null && command -v codesign >/dev/null; then
  BIN=$(for f in "$WORK"/corpus/*; do
          [ "$(head -c4 "$f" | xxd -p)" = "cffaedfe" ] && echo "$f" && break
        done)
  if [ -n "$BIN" ]; then
    cp "$BIN" "$WORK/gk" && chmod +x "$WORK/gk"
    if codesign -v "$WORK/gk" 2>/dev/null; then
      echo "   codesign: signature valid on disk"
    else
      echo "   codesign: INVALID — the in-process signature is wrong"; FAILED=1
    fi
    ASSESS=$(spctl -a -t execute "$WORK/gk" 2>&1)
    if [[ "$ASSESS" == *rejected* ]]; then
      echo "   spctl:    REJECTED — Gatekeeper refuses it, as it refuses any ad-hoc signature"
    else
      echo "   spctl:    $ASSESS"
      echo "             ACCEPTED is unexpected for an ad-hoc signature; investigate"; FAILED=1
    fi
  fi
else
  echo "   SKIPPED: not macOS"
fi

echo
[ "$FAILED" -eq 0 ] && echo "== no scanner flagged anything ==" || echo "== SOMETHING WAS FLAGGED =="
exit "$FAILED"
