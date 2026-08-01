# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Rewrite the figures quoted in prose so they equal the committed scorecard.

`tests/test_published_numbers.py` catches the divergence; this closes it. Between them the
README's numbers are as maintained as the code, which they were not: the scorecard was
regenerated twice after the prose had been pinned to it, and prose does not regenerate.

Run after anything that changes what the gates measure:

    artifactforge scorecard --n 40 --out fidelity-scorecard.json
    python scripts/pin-published-numbers.py
    pytest -q tests/test_published_numbers.py

It edits only the percentage inside sentences it recognises, and reports anything it could not
find rather than silently doing nothing — a pinning tool that quietly matches nothing is worse
than no pinning tool.
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: (file, regex with one capture group around the number, which scorecard figure it must be).
#: Anchored on surrounding words rather than on the digits, so a stale value still matches.
TARGETS = [
    ("README.md", r"(?<=at )(\d+(?:\.\d+)?%)(?= against a \d+(?:\.\d+)?% floor)", "footprint"),
    ("README.md", r"(?<=against a )(\d+(?:\.\d+)?%)(?= floor)", "chance"),
    ("README.md", r"(?<=parser-assisted completion\) \| \*\*)(\d+(?:\.\d+)?%)(?=\*\* \|)", "footprint"),
    ("README.md", r"(?<=visible candidates\) \| \*\*)(\d+(?:\.\d+)?%)(?=\*\* \|)", "chance"),
    ("docs/ROADMAP.md", r"(?<=take the maximum — scores \*\*)(\d+(?:\.\d+)?%)(?=\*\*)", "footprint"),
    ("docs/ROADMAP.md", r"(?<=against a \*\*)(\d+(?:\.\d+)?%)(?=\*\* chance floor)", "chance"),
    ("docs/DESIGN.md", r"(?<=take the maximum — scores )(\d+(?:\.\d+)?%)", "footprint"),
    ("docs/DESIGN.md", r"(?<=against a )(\d+(?:\.\d+)?%)(?= chance floor)", "chance"),
]


def main() -> int:
    with open(os.path.join(ROOT, "fidelity-scorecard.json")) as f:
        card = json.load(f)
    s = card["gates"]["solvability"]
    figures = {
        "footprint": f"{s['footprint_solver_score']:.1%}",
        "chance": f"{s['chance_floor']:.1%}",
    }

    changed, missing = [], []
    for rel, pattern, key in TARGETS:
        path = os.path.join(ROOT, rel)
        with open(path) as f:
            text = f.read()
        new, n = re.subn(pattern, figures[key], text)
        if n == 0:
            missing.append(f"{rel}: no match for the {key} figure ({pattern})")
            continue
        if new != text:
            with open(path, "w") as f:
                f.write(new)
            changed.append(f"{rel}: {key} -> {figures[key]}")

    for line in changed:
        print("  updated", line)
    for line in missing:
        print("  MISSING", line, file=sys.stderr)
    if not changed and not missing:
        print("  every published figure already matches the scorecard")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
