# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 2 — identity: do the declared answer-bearing pivots agree with emitted bytes?

This is the keystone. EvidenceForge's Sysmon and Zeek paths use emitter-local synthetic seed
domains rather than shared file bytes. Their same-algorithm sets are disjoint in the measured
stock run, but that run contains no basename-matched transfer/execution pair and therefore is
not proof that one logical binary received two inconsistent hashes. ArtifactForge's scoped
answer is to synthesize each answer-bearing binary once and reuse its ``Content`` identity in
the declared joins.

The gate is written to be falsifiable in the one way that matters: each value in its declared
scope is re-derived from the FILES ON DISK, through a real parser where appropriate, and only
then compared. Deliberate stale and absent Amcache decoy hashes are not claims about resident
bytes and are outside this gate. The predecessor of this gate asserted
`amcache == "0000" + c.sha1` one line after assigning `amcache = "0000" + c.sha1`, and stayed
green when the underlying hash was replaced with a placeholder string.

The join is passed in rather than read from the scene, because the answer key does not live
in a directory a solver can see. Every check names the two artifacts it spans: a check
confined to one artifact cannot detect a broken pivot.
"""
from __future__ import annotations

import hashlib
import os
import plistlib
import sqlite3

from artifactforge.gates import GateReport
from artifactforge.inventory import InventoryError, InventoryFile, captured_regular_tree


def _check(r: GateReport, spans: str, what: str, got, want):
    """One cross-artifact equality, counted whether it holds or not."""
    r.metrics["checks_total"] = r.metrics.get("checks_total", 0) + 1
    if got == want:
        r.metrics["checks_joined"] = r.metrics.get("checks_joined", 0) + 1
        return True
    r.fail(f"{spans}: {what} — evidence says {str(got)[:64]!r}, "
           f"the scene claims {str(want)[:64]!r}")
    return False


def _named(
    r: GateReport, files: tuple[InventoryFile, ...], name: str, where: str
) -> InventoryFile | None:
    matches = [file for file in files if file.name == name]
    if not matches:
        r.fail(f"{where}: required artifact {name!r} is absent from the scene")
        return None
    if len(matches) != 1:
        r.fail(
            f"{where}: required artifact basename {name!r} is ambiguous across "
            + ", ".join(file.relative_path for file in matches)
        )
        return None
    return matches[0]


def _resident(r: GateReport, scene_files: tuple[InventoryFile, ...]) -> dict:
    out = {}
    ambiguous = set()
    for file in scene_files:
        data = file.data
        if data is None:
            raise AssertionError("identity inventory did not capture file bytes")
        if data[:2] == b"MZ":
            key = file.name.lower()
            if key in out or key in ambiguous:
                out.pop(key, None)
                ambiguous.add(key)
                locations = [candidate.relative_path for candidate in scene_files
                             if candidate.name.lower() == key]
                r.fail(
                    f"disk: resident binary basename {file.name!r} is ambiguous across "
                    + ", ".join(locations)
                )
                continue
            out[key] = data
    return out


def _q(file: InventoryFile, sql: str):
    con = sqlite3.connect(file.path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _windows(
    r: GateReport, scene_files: tuple[InventoryFile, ...], join: dict
):
    import pefile
    from regipy.registry import RegistryHive
    from windowsprefetch import Prefetch

    files = _resident(r, scene_files)
    p, a = join["persisted"], join["amcache_match"]

    for label, claim in (("persisted", p), ("amcache_match", a)):
        data = files.get(claim["name"].lower())
        if data is None:
            r.fail(f"disk: the {label} binary {claim['name']!r} is not in the scene, so its "
                   f"hashes are claims about a file nobody can check")
            continue
        _check(r, f"disk->{label}", "sha256", hashlib.sha256(data).hexdigest(), claim["sha256"])
        _check(r, f"disk->{label}", "sha1",
               hashlib.sha1(data).hexdigest(), claim["sha1"])         # noqa: S324 - identity
        _check(r, f"pefile->{label}", "imphash",
               pefile.PE(data=data).get_imphash(), claim["imphash"])

    # The registry->disk pivot: exactly one recorded FileId must belong to a resident file,
    # and it must be the one the scene says it is.
    by_sha1 = {hashlib.sha1(d).hexdigest(): n                         # noqa: S324 - identity
               for n, d in files.items()}
    amcache_file = _named(r, scene_files, "Amcache.hve", "Amcache")
    if amcache_file is not None:
        iaf = RegistryHive(os.fspath(amcache_file.path)).get_key(
            "\\Root\\InventoryApplicationFile")
        matches = sorted(by_sha1[v.value[4:]] for sub in iaf.iter_subkeys()
                         for v in sub.get_values()
                         if v.name == "FileId" and v.value[4:] in by_sha1)
        _check(r, "Amcache->disk", "exactly one recorded hash belongs to a resident file",
               matches, [a["name"].lower()])

    # The persistence->disk pivot: exactly one autostart names a program that is here.
    run_file = _named(r, scene_files, "Software.run.hive", "Run key")
    if run_file is not None:
        run = RegistryHive(os.fspath(run_file.path)).get_key(
            "\\Microsoft\\Windows\\CurrentVersion\\Run")
        named = sorted(v.value for v in run.get_values()
                       if v.value.replace("/", "\\").rsplit("\\", 1)[-1].lower() in files)
        _check(r, "Run key->disk", "exactly one autostart names a resident program",
               named, [p["path"]])

    # The execution pivot: the persisted program's run count, and exactly one orphan.
    prefetches = {}
    for file in scene_files:
        if not file.name.endswith(".pf"):
            continue
        pf = Prefetch(os.fspath(file.path))
        prefetches[pf.executableName.lower()] = pf.runCount
    if p["name"].lower() in prefetches:
        _check(r, "prefetch->persisted", "run count",
               prefetches[p["name"].lower()], p["run_count"])
    else:
        r.fail("prefetch: the persisted program has no execution record to join to")
    _check(r, "prefetch->disk", "exactly one execution record names an absent program",
           sorted(n for n in prefetches if n not in files),
           [join["orphan_execution"].lower()])


def _macos(
    r: GateReport, scene_files: tuple[InventoryFile, ...], join: dict
):
    from artifactforge.content.macho import cdhash_of_file

    s = join["subject"]

    # The macOS half of the keystone: the subject's binary is a real Mach-O and every
    # hash-shaped field about it is re-derived from those bytes.
    binary = _named(r, scene_files, s["bundle_id"], "subject binary")
    if binary is not None:
        data = binary.data
        if data is None:
            raise AssertionError("identity inventory did not capture file bytes")
        _check(r, "disk->subject", "sha256", hashlib.sha256(data).hexdigest(), s["sha256"])
        _check(r, "disk->subject", "sha1",
               hashlib.sha1(data).hexdigest(), s["sha1"])             # noqa: S324 - identity
        _check(r, "codesign blob->subject", "cdhash", cdhash_of_file(data), s["cdhash"])
        _check(r, "disk->subject", "the binary is a 64-bit Mach-O",
               data[:4], b"\xcf\xfa\xed\xfe")
    tcc = _named(r, scene_files, "TCC.db", "TCC")
    knowledge = _named(r, scene_files, "knowledgeC.db", "knowledgeC")
    if tcc is not None and knowledge is not None:
        granted = {row[0] for row in _q(
            tcc, "SELECT client FROM access WHERE auth_value = 2"
        )}
        used = {row[0] for row in _q(
            knowledge,
            "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME = '/app/inFocus'",
        )}
        _check(r, "TCC->knowledgeC", "exactly one granted client was also used",
               sorted(granted & used), [s["bundle_id"]])

    xattr = _named(
        r, scene_files, f"{s['bundle_id']}.quarantine.xattr", "quarantine xattr"
    )
    if xattr is not None:
        data = xattr.data
        if data is None:
            raise AssertionError("identity inventory did not capture file bytes")
        uuid = data.decode().strip().split(";")[-1]
        _check(r, "xattr->subject", "quarantine UUID", uuid, s["quarantine_uuid"])
        quarantine = _named(
            r, scene_files, "QuarantineEventsV2", "QuarantineEventsV2"
        )
        if quarantine is not None:
            rows = {row[0]: row for row in _q(
                quarantine,
                "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
                "LSQuarantineAgentName FROM LSQuarantineEvent",
            )}
            if uuid in rows:
                _check(r, "xattr->QuarantineEventsV2", "download URL",
                       rows[uuid][1], s["download_url"])
                _check(r, "xattr->QuarantineEventsV2", "downloading agent",
                       rows[uuid][2], s["agent"])
            else:
                r.fail("QuarantineEventsV2: the subject's xattr UUID matches no row, so the "
                       "download pivot dead-ends")

    plist = _named(r, scene_files, f"{s['bundle_id']}.plist", "LaunchAgent")
    if plist is not None:
        data = plist.data
        if data is None:
            raise AssertionError("identity inventory did not capture file bytes")
        pl = plistlib.loads(data)
        _check(r, "LaunchAgent->subject", "Label", pl["Label"], s["bundle_id"])
        _check(r, "LaunchAgent->subject", "program", pl["ProgramArguments"][0], s["app_path"])


def run(scene_dir: str, join: dict) -> GateReport:
    r = GateReport(2, "identity",
                   "do the declared answer-bearing pivots agree with emitted bytes?")
    try:
        with captured_regular_tree(scene_dir) as scene_files:
            if not scene_files:
                r.fail(
                    f"no artifact in {scene_dir!r} was inventoried, so no identity pivot was checked"
                )
            elif join.get("family") == "windows":
                _windows(r, scene_files, join)
            elif join.get("family") == "macos":
                _macos(r, scene_files, join)
            else:
                r.fail(f"scene family {join.get('family')!r} has no identity gate implementation")
    except InventoryError as exc:
        r.fail(f"scene inventory is unsafe: {exc}")
    joined = r.metrics.get("checks_joined", 0)
    total = r.metrics.get("checks_total", 0)
    r.denominator = f"{joined}/{total} cross-artifact identity checks hold"
    return r
