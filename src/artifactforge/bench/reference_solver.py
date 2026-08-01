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

import hashlib
import os
from pathlib import Path
import plistlib
import sqlite3

from artifactforge.inventory import InventoryFile, captured_regular_tree


SUPPORTED_FAMILIES = frozenset(("windows", "macos"))


def _named(files: tuple[InventoryFile, ...], name: str) -> InventoryFile:
    """Resolve one artifact by basename while refusing recursive ambiguity."""
    matches = [file for file in files if file.name == name]
    if len(matches) != 1:
        locations = [file.relative_path for file in matches]
        raise ValueError(
            f"expected exactly one artifact named {name!r}, found {len(matches)}: {locations}"
        )
    return matches[0]


def _resident(files: tuple[InventoryFile, ...]) -> dict:
    """lowercased filename -> (path, bytes) for every PE actually present in the scene."""
    out = {}
    for file in files:
        data = file.data
        if data is None:
            raise AssertionError("reference-solver snapshot contains no bytes")
        if data[:2] == b"MZ":
            name = file.name.lower()
            if name in out:
                raise ValueError(f"resident PE basename is ambiguous: {file.name!r}")
            out[name] = (file.path, data)
    return out


def _basename(win_path: str) -> str:
    return win_path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _solve_windows(files_snapshot: tuple[InventoryFile, ...]) -> dict:
    import pefile
    from regipy.registry import RegistryHive
    from windowsprefetch import Prefetch

    files = _resident(files_snapshot)
    a = {}

    # Pivot 1: of the Run key's autostarts, exactly one names a program that is here.
    run = RegistryHive(os.fspath(_named(files_snapshot, "Software.run.hive").path)).get_key(
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
    for file in files_snapshot:
        if not file.name.endswith(".pf"):
            continue
        pf = Prefetch(os.fspath(file.path))
        prefetches[pf.executableName.lower()] = pf
    a["persisted_run_count"] = prefetches[pname].runCount

    # Pivot 3: hash every resident file, then find the one Amcache row that matches.
    by_sha1 = {hashlib.sha1(data).hexdigest(): data                 # noqa: S324 - identity
               for _, data in files.values()}
    iaf = RegistryHive(os.fspath(_named(files_snapshot, "Amcache.hve").path)).get_key(
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
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _solve_macos(files: tuple[InventoryFile, ...]) -> dict:
    a = {}

    # Pivot 1: allowed by TCC *and* actually used, per knowledgeC.
    granted = {r[0] for r in _query(os.fspath(_named(files, "TCC.db").path),
                                    "SELECT client FROM access WHERE auth_value = 2")}
    used = {r[0] for r in _query(os.fspath(_named(files, "knowledgeC.db").path),
                                 "SELECT ZVALUESTRING FROM ZOBJECT "
                                 "WHERE ZSTREAMNAME = '/app/inFocus'")}
    subjects = sorted(granted & used)
    if len(subjects) != 1:
        raise ValueError(f"expected exactly one granted-and-used bundle, got {subjects}")
    subject = subjects[0]
    a["granted_and_used_bundle"] = subject

    # Pivot 2: that app's quarantine xattr names the download event.
    xattr = _named(files, f"{subject}.quarantine.xattr").data
    if xattr is None:
        raise AssertionError("reference-solver snapshot contains no bytes")
    uuid = xattr.decode().strip().split(";")[-1]
    rows = _query(os.fspath(_named(files, "QuarantineEventsV2").path),
                  "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
                  "LSQuarantineAgentName FROM LSQuarantineEvent")
    row = next(r for r in rows if r[0] == uuid)
    a["subject_download_url"], a["subject_quarantine_agent"] = row[1], row[2]

    # Pivot 3: the LaunchAgent whose Label is that bundle id.
    launch_agent = _named(files, f"{subject}.plist").data
    if launch_agent is None:
        raise AssertionError("reference-solver snapshot contains no bytes")
    a["subject_persistence_path"] = plistlib.loads(launch_agent)["ProgramArguments"][0]

    # Pivot 4: that app's binary, read with a real Mach-O parser.
    import lief
    binary_file = _named(files, subject)
    data = binary_file.data
    if data is None:
        raise AssertionError("reference-solver snapshot contains no bytes")
    a["subject_binary_sha256"] = hashlib.sha256(data).hexdigest()
    binary = lief.parse(os.fspath(binary_file.path))
    undefined = sorted(sym.name for sym in binary.symbols
                       if sym.is_external and not sym.has_export_info
                       and sym.name.startswith("_"))
    a["subject_binary_symhash"] = hashlib.md5(                        # noqa: S324 - identity
        ",".join(undefined).encode()).hexdigest()
    return a


def reference_solve(public) -> dict:
    """Answer a PublicTask by reading its artifacts. Never sees an expected value."""
    solvers = {"windows": _solve_windows, "macos": _solve_macos}
    try:
        solver = solvers[public.family]
    except KeyError as exc:
        raise ValueError(f"unsupported benchmark family: {public.family!r}") from exc
    with captured_regular_tree(public.directory) as files:
        return solver(files)
