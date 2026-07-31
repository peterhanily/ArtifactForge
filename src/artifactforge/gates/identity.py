# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 2 — identity: is every hash-shaped field a genuine digest of one ContentStore blob?

This is the keystone. The whole project exists because EvidenceForge computes a file's
"hashes" as digests of a per-emitter seed string, so the same binary carries disagreeing
hashes across sources and the file-hash pivot — the core move of DFIR — silently never works.
ArtifactForge's answer is to synthesize the bytes once and let every artifact quote a real
digest of them.

The gate is written to be falsifiable in the one way that matters: every value is re-derived
from the FILES ON DISK, through a real parser, and only then compared. Nothing is compared
against the value that produced it. The predecessor of this gate asserted
`amcache == "0000" + c.sha1` one line after assigning `amcache = "0000" + c.sha1`, and stayed
green when the underlying hash was replaced with a placeholder string.

The join is passed in rather than read from the scene, because the answer key does not live
in a directory a solver can see. Every check names the two artifacts it spans: a check
confined to one artifact cannot detect a broken pivot.
"""
from __future__ import annotations

import glob
import hashlib
import os
import plistlib
import sqlite3

from artifactforge.gates import GateReport


def _check(r: GateReport, spans: str, what: str, got, want):
    """One cross-artifact equality, counted whether it holds or not."""
    r.metrics["checks_total"] = r.metrics.get("checks_total", 0) + 1
    if got == want:
        r.metrics["checks_joined"] = r.metrics.get("checks_joined", 0) + 1
        return True
    r.fail(f"{spans}: {what} — evidence says {str(got)[:64]!r}, "
           f"the scene claims {str(want)[:64]!r}")
    return False


def _resident(scene_dir: str) -> dict:
    out = {}
    for name in sorted(os.listdir(scene_dir)):
        path = os.path.join(scene_dir, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        if data[:2] == b"MZ":
            out[name.lower()] = data
    return out


def _q(scene_dir: str, name: str, sql: str):
    con = sqlite3.connect(os.path.join(scene_dir, name))
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _windows(r: GateReport, scene_dir: str, join: dict):
    import pefile
    from regipy.registry import RegistryHive
    from windowsprefetch import Prefetch

    files = _resident(scene_dir)
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
    iaf = RegistryHive(os.path.join(scene_dir, "Amcache.hve")).get_key(
        "\\Root\\InventoryApplicationFile")
    matches = sorted(by_sha1[v.value[4:]] for sub in iaf.iter_subkeys()
                     for v in sub.get_values()
                     if v.name == "FileId" and v.value[4:] in by_sha1)
    _check(r, "Amcache->disk", "exactly one recorded hash belongs to a resident file",
           matches, [a["name"].lower()])

    # The persistence->disk pivot: exactly one autostart names a program that is here.
    run = RegistryHive(os.path.join(scene_dir, "Software.run.hive")).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run")
    named = sorted(v.value for v in run.get_values()
                   if v.value.replace("/", "\\").rsplit("\\", 1)[-1].lower() in files)
    _check(r, "Run key->disk", "exactly one autostart names a resident program",
           named, [p["path"]])

    # The execution pivot: the persisted program's run count, and exactly one orphan.
    prefetches = {}
    for pf_path in sorted(glob.glob(os.path.join(scene_dir, "*.pf"))):
        pf = Prefetch(pf_path)
        prefetches[pf.executableName.lower()] = pf.runCount
    if p["name"].lower() in prefetches:
        _check(r, "prefetch->persisted", "run count",
               prefetches[p["name"].lower()], p["run_count"])
    else:
        r.fail("prefetch: the persisted program has no execution record to join to")
    _check(r, "prefetch->disk", "exactly one execution record names an absent program",
           sorted(n for n in prefetches if n not in files),
           [join["orphan_execution"].lower()])


def _macos(r: GateReport, scene_dir: str, join: dict):
    s = join["subject"]

    granted = {row[0] for row in _q(scene_dir, "TCC.db",
                                    "SELECT client FROM access WHERE auth_value = 2")}
    used = {row[0] for row in _q(scene_dir, "knowledgeC.db",
                                 "SELECT ZVALUESTRING FROM ZOBJECT "
                                 "WHERE ZSTREAMNAME = '/app/inFocus'")}
    _check(r, "TCC->knowledgeC", "exactly one granted client was also used",
           sorted(granted & used), [s["bundle_id"]])

    xattr_path = os.path.join(scene_dir, f"{s['bundle_id']}.quarantine.xattr")
    if os.path.exists(xattr_path):
        with open(xattr_path) as f:
            uuid = f.read().strip().split(";")[-1]
        _check(r, "xattr->subject", "quarantine UUID", uuid, s["quarantine_uuid"])
        rows = {row[0]: row for row in _q(
            scene_dir, "QuarantineEventsV2",
            "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
            "LSQuarantineAgentName FROM LSQuarantineEvent")}
        if uuid in rows:
            _check(r, "xattr->QuarantineEventsV2", "download URL",
                   rows[uuid][1], s["download_url"])
            _check(r, "xattr->QuarantineEventsV2", "downloading agent",
                   rows[uuid][2], s["agent"])
        else:
            r.fail("QuarantineEventsV2: the subject's xattr UUID matches no row, so the "
                   "download pivot dead-ends")
    else:
        r.fail("scene: the subject has no quarantine xattr, so nothing links it to a download")

    plist_path = os.path.join(scene_dir, f"{s['bundle_id']}.plist")
    if os.path.exists(plist_path):
        with open(plist_path, "rb") as f:
            pl = plistlib.load(f)
        _check(r, "LaunchAgent->subject", "Label", pl["Label"], s["bundle_id"])
        _check(r, "LaunchAgent->subject", "program", pl["ProgramArguments"][0], s["app_path"])
    else:
        r.fail("scene: the subject has no LaunchAgent, so the persistence pivot is absent")


def run(scene_dir: str, join: dict) -> GateReport:
    r = GateReport(2, "identity",
                   "is every hash-shaped field a genuine digest of one ContentStore blob?")
    if join.get("family") == "windows":
        _windows(r, scene_dir, join)
    else:
        _macos(r, scene_dir, join)
        r.gap("macOS scenes carry no binary and therefore no hash-shaped field; the keystone "
              "currently covers the Windows family only")
    joined = r.metrics.get("checks_joined", 0)
    total = r.metrics.get("checks_total", 0)
    r.denominator = f"{joined}/{total} cross-artifact identity checks hold"
    return r
