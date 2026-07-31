# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The reference solver — a worked investigation, and the benchmark's positive control.

It reads a scene with the parsers a responder actually runs and answers the questions without
ever seeing the answer key: it is handed a `PublicTask`, which has no `expected` field to
consult. If it scores 100%, the artifacts genuinely encode the ground truth.

Every routine below follows a pivot rather than reading a value. The persisted binary is
found by taking the Run key's program paths and asking which of them is *present*; the
Amcache answer is found by hashing every resident file and asking which recorded FileId
matches. That is the work the benchmark is meant to measure, so the reference solver has to
actually do it.

Parser imports are lazy, so `import artifactforge` never requires the dev oracles.
"""
from __future__ import annotations

import glob
import hashlib
import os
import plistlib
import sqlite3


def _resident(directory: str) -> dict:
    """lowercased filename -> (path, bytes) for every PE actually present in the scene."""
    out = {}
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        if data[:2] == b"MZ":
            out[name.lower()] = (path, data)
    return out


def _basename(win_path: str) -> str:
    return win_path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _solve_windows(d: str) -> dict:
    import pefile
    from regipy.registry import RegistryHive
    from windowsprefetch import Prefetch

    files = _resident(d)
    a = {}

    # Pivot 1: of the Run key's autostarts, exactly one names a program that is here.
    run = RegistryHive(os.path.join(d, "Software.run.hive")).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run")
    persisted = [v.value for v in run.get_values() if _basename(v.value) in files]
    if len(persisted) != 1:
        raise ValueError(f"expected exactly one resident autostart, found {len(persisted)}")
    pname = _basename(persisted[0])
    _, pdata = files[pname]
    a["persisted_sha256"] = hashlib.sha256(pdata).hexdigest()
    a["persisted_imphash"] = pefile.PE(data=pdata).get_imphash()

    # Pivot 2: the prefetch record for that same program carries its run count.
    prefetches = {}
    for pf_path in sorted(glob.glob(os.path.join(d, "*.pf"))):
        pf = Prefetch(pf_path)
        prefetches[pf.executableName.lower()] = pf
    a["persisted_run_count"] = prefetches[pname].runCount

    # Pivot 3: hash every resident file, then find the one Amcache row that matches.
    by_sha1 = {hashlib.sha1(data).hexdigest(): data                 # noqa: S324 - identity
               for _, data in files.values()}
    iaf = RegistryHive(os.path.join(d, "Amcache.hve")).get_key(
        "\\Root\\InventoryApplicationFile")
    matched = [by_sha1[v.value[4:]]
               for sub in iaf.iter_subkeys()
               for v in sub.get_values()
               if v.name == "FileId" and v.value[4:] in by_sha1]
    if len(matched) != 1:
        raise ValueError(f"expected exactly one Amcache hash to match a resident file, "
                         f"found {len(matched)}")
    a["amcache_match_sha256"] = hashlib.sha256(matched[0]).hexdigest()

    # Pivot 4: an execution record with no corresponding file.
    orphans = [name for name in prefetches if name not in files]
    if len(orphans) != 1:
        raise ValueError(f"expected exactly one orphan execution, found {len(orphans)}")
    a["orphan_execution"] = orphans[0]
    return a


def _query(path: str, sql: str):
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _solve_macos(d: str) -> dict:
    a = {}

    # Pivot 1: allowed by TCC *and* actually used, per knowledgeC.
    granted = {r[0] for r in _query(os.path.join(d, "TCC.db"),
                                    "SELECT client FROM access WHERE auth_value = 2")}
    used = {r[0] for r in _query(os.path.join(d, "knowledgeC.db"),
                                 "SELECT ZVALUESTRING FROM ZOBJECT "
                                 "WHERE ZSTREAMNAME = '/app/inFocus'")}
    subjects = sorted(granted & used)
    if len(subjects) != 1:
        raise ValueError(f"expected exactly one granted-and-used bundle, got {subjects}")
    subject = subjects[0]
    a["granted_and_used_bundle"] = subject

    # Pivot 2: that app's quarantine xattr names the download event.
    with open(os.path.join(d, f"{subject}.quarantine.xattr")) as f:
        uuid = f.read().strip().split(";")[-1]
    rows = _query(os.path.join(d, "QuarantineEventsV2"),
                  "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
                  "LSQuarantineAgentName FROM LSQuarantineEvent")
    row = next(r for r in rows if r[0] == uuid)
    a["subject_download_url"], a["subject_quarantine_agent"] = row[1], row[2]

    # Pivot 3: the LaunchAgent whose Label is that bundle id.
    with open(os.path.join(d, f"{subject}.plist"), "rb") as f:
        a["subject_persistence_path"] = plistlib.load(f)["ProgramArguments"][0]

    # Pivot 4: that app's binary, read with a real Mach-O parser.
    import lief
    with open(os.path.join(d, subject), "rb") as f:
        data = f.read()
    a["subject_binary_sha256"] = hashlib.sha256(data).hexdigest()
    binary = lief.parse(os.path.join(d, subject))
    undefined = sorted(sym.name for sym in binary.symbols
                       if sym.is_external and not sym.has_export_info
                       and sym.name.startswith("_"))
    a["subject_binary_symhash"] = hashlib.md5(                        # noqa: S324 - identity
        ",".join(undefined).encode()).hexdigest()
    return a


def reference_solve(public) -> dict:
    """Answer a PublicTask by reading its artifacts. Never sees an expected value."""
    return (_solve_windows if public.family == "windows" else _solve_macos)(public.directory)
