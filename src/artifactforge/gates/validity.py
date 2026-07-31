# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 — validity: does an independent real parser read every artifact we ship?

"Realistic" is not a matter of taste here. Either a parser a responder actually runs opens
the file, or it does not. Two independent implementations are required per format, because
one permissive parser hides what a strict one rejects: every prefetch file this project
emitted was accepted by `windowsprefetch` and rejected by `pyscca`, the libyal parser plaso
is built on, for eighteen days — because `windowsprefetch` was the only oracle installed.

A missing oracle is a FAILURE, never a skip. A skipped check exits 0 and reads exactly like
a passing one.

Where a genuinely independent second implementation does not exist — SQLite databases and
binary plists are read back by the same library that wrote them — that is recorded as a
declared gap rather than quietly counted as validation.
"""
from __future__ import annotations

import os

from artifactforge.gates import GateReport

# format -> the oracles that must all read it, plus any declared gap in that oracle set.
ORACLES = {
    "pe":       {"required": ["pefile", "lief"], "gap": None},
    "macho":    {"required": ["lief", "macholib"], "gap": None},
    "hive":     {"required": ["regipy", "libregf"], "gap": None},
    "prefetch": {"required": ["windowsprefetch", "pyscca"], "gap": None},
    "sqlite":   {"required": ["sqlite3"],
                 "gap": "sqlite3 both writes and reads these databases, so it is not an "
                        "independent oracle; a second reader is an open gap"},
    "plist":    {"required": ["plistlib"],
                 "gap": "plistlib both writes and reads the LaunchAgent plist, so it is not "
                        "an independent oracle; a second reader is an open gap"},
}


#: Files that travel with a scene but are not artifacts: documentation, answer keys, and the
#: quarantine xattr, which is a value emitted as data rather than a format with a parser. They
#: have no oracle because there is nothing to be wrong about. Anything else the gate cannot
#: classify IS a failure — an unidentifiable file in a scene is exactly what should be noticed.
_SIDECAR_SUFFIXES = (".md", ".json", ".txt", ".quarantine.xattr")


def classify(path: str) -> str | None:
    """Which format is this file? Magic first, extension only as a tiebreak."""
    with open(path, "rb") as f:
        head = f.read(16)
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\xcf\xfa\xed\xfe":
        return "macho"
    if head[:4] == b"regf":
        return "hive"
    if head[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if head[:8] == b"bplist00":
        return "plist"
    if path.lower().endswith(".pf"):
        return "prefetch"
    return None


# --- one reader per oracle. Each returns a short detail string, or raises. ---

def _read_pefile(path):
    import pefile
    pe = pefile.PE(path)
    return f"imphash={pe.get_imphash()}"


def _read_lief(path):
    import lief
    b = lief.parse(path)
    if b is None:
        raise ValueError("lief returned None")
    return f"format={b.format}"


def _read_macholib(path):
    from macholib.MachO import MachO
    m = MachO(path)
    return f"headers={len(m.headers)},cmds={len(m.headers[0].commands)}"


def _read_regipy(path):
    from regipy.registry import RegistryHive
    return f"root={RegistryHive(path).root.name}"


def _read_libregf(path):
    import pyregf
    f = pyregf.file()
    f.open(path)
    try:
        return f"root={f.get_root_key().name}"
    finally:
        f.close()


def _read_windowsprefetch(path):
    from windowsprefetch import Prefetch
    return f"exe={Prefetch(path).executableName}"


def _read_pyscca(path):
    import pyscca
    f = pyscca.file()
    f.open(path)
    try:
        return f"exe={f.get_executable_filename()}"
    finally:
        f.close()


def _read_sqlite3(path):
    import sqlite3
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA integrity_check").fetchone()
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        return f"tables={','.join(tables)}"
    finally:
        con.close()


def _read_plistlib(path):
    import plistlib
    with open(path, "rb") as f:
        return f"keys={','.join(sorted(plistlib.load(f)))}"


READERS = {
    "pefile": _read_pefile,
    "lief": _read_lief,
    "macholib": _read_macholib,
    "regipy": _read_regipy,
    "libregf": _read_libregf,
    "windowsprefetch": _read_windowsprefetch,
    "pyscca": _read_pyscca,
    "sqlite3": _read_sqlite3,
    "plistlib": _read_plistlib,
}


def run(scene_dir: str) -> GateReport:
    r = GateReport(1, "validity",
                   "does an independent real parser read every artifact we ship?")
    checked = passed = 0
    seen_formats = set()

    for name in sorted(os.listdir(scene_dir)):
        path = os.path.join(scene_dir, name)
        if not os.path.isfile(path) or name.startswith("."):
            continue
        if name.endswith(_SIDECAR_SUFFIXES):
            continue
        fmt = classify(path)
        if fmt is None:
            r.fail(f"{name}: no format recognised, so nothing can validate it")
            continue
        if fmt not in ORACLES:
            r.fail(f"{name}: format '{fmt}' has no declared oracle set")
            continue
        seen_formats.add(fmt)
        for oracle in ORACLES[fmt]["required"]:
            checked += 1
            try:
                detail = READERS[oracle](path)
            except ImportError:
                r.fail(f"{fmt}: oracle '{oracle}' is not installed — a missing "
                               f"oracle is a failure, not a skip")
                continue
            except Exception as exc:                     # noqa: BLE001 — any parser refusal
                r.fail(f"{fmt}: {oracle} rejected it — "
                               f"{type(exc).__name__}: {str(exc)[:110]}")
                continue
            passed += 1
            r.metrics.setdefault("reads", {})[f"{name}:{oracle}"] = detail

    for fmt in sorted(seen_formats):
        if ORACLES[fmt]["gap"]:
            r.gap(f"{fmt}: {ORACLES[fmt]['gap']}")

    if checked == 0:
        # A gate that classified no artifact has not passed; it has not run. Reporting PASS
        # with 0/0 and exiting 0 is the exact vacuous success this project is built to catch,
        # and it did it to itself.
        r.fail(f"no artifact in {scene_dir!r} was classified, so nothing was validated")
    r.metrics["oracle_reads_passed"] = passed
    r.metrics["oracle_reads_total"] = checked
    r.metrics.pop("reads", None)                          # detail is for humans, not the card
    r.denominator = f"{passed}/{checked} oracle reads succeeded"
    return r
