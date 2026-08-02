# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Synchronize the scoped status block with the committed scorecard.

The historical version of this helper copied benchmark attack percentages into prose.  That
made public, non-reportable diagnostics look like product results and encouraged withdrawn v1
figures to survive protocol changes.  Protocol constants are now checked directly from the
current measurement contract by ``tests/test_published_numbers.py``; this helper updates only
the three machine-scoped verdicts and the version of the scorecard that owns them.

Run after publishing a clean-source scorecard:

    artifactforge scorecard --n 40 --out fidelity-scorecard.json
    python scripts/pin-published-numbers.py
    pytest -q tests/test_published_numbers.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
STATUS_START = "<!-- scorecard-status:start -->"
STATUS_END = "<!-- scorecard-status:end -->"
STATUS_PATTERN = re.compile(
    re.escape(STATUS_START) + r".*?" + re.escape(STATUS_END),
    re.DOTALL,
)


def _status_block(card: dict) -> str:
    try:
        version = card["generator"]["artifactforge_version"]
        generator = card["status"]["generator_assurance"]["verdict"]
        benchmark = card["status"]["benchmark_validity"]["verdict"]
        aggregate = card["verdict"]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"scorecard lacks required scoped status: {exc}") from exc
    allowed = {"pass", "gap", "fail"}
    if not all(value in allowed for value in (generator, benchmark, aggregate)):
        raise ValueError("scorecard status values must be pass, gap or fail")
    return (
        f"{STATUS_START}\n"
        f"**Committed scorecard scopes (`{version}`).** Generator assurance is "
        f"`{generator}`;\n"
        f"experimental benchmark validity is `{benchmark}`; the all-gates compatibility "
        f"verdict is\n`{aggregate}`. Its reproducible measurement corpus is explicitly "
        f"non-reportable.\n"
        f"{STATUS_END}"
    )


def _replace_exactly_once(path: Path, replacement: str) -> bool:
    original = path.read_text(encoding="utf-8")
    updated, count = STATUS_PATTERN.subn(replacement, original)
    if count != 1:
        raise ValueError(f"{path.relative_to(ROOT)} must contain exactly one scorecard block")
    if updated == original:
        return False

    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(updated)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    return True


def main() -> int:
    try:
        card = json.loads((ROOT / "fidelity-scorecard.json").read_text(encoding="utf-8"))
        changed = _replace_exactly_once(ROOT / "README.md", _status_block(card))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"cannot synchronize scorecard status: {exc}", file=sys.stderr)
        return 1
    print("  updated README scorecard status" if changed else "  scorecard status already matches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
