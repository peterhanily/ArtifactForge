# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 2 — identity: is every hash-shaped field a genuine digest of one ContentStore blob?

This is the keystone. The whole project exists because EvidenceForge computes a file's
"hashes" as digests of a per-emitter seed string, so the same binary carries disagreeing
hashes across sources and the file-hash pivot — the core move of DFIR — silently never
works. ArtifactForge's answer is to synthesize the bytes once and let every artifact quote a
real digest of them.

The gate is therefore written to be falsifiable in the one way that matters: every value is
re-derived from the FILES ON DISK, through a real parser, and only then compared. Nothing is
compared against the value that produced it. The predecessor of this gate asserted
`amcache == "0000" + c.sha1` one line after assigning `amcache = "0000" + c.sha1`, and stayed
green when the underlying hash was replaced with a placeholder string.

Every check names the two artifacts it spans, because a check confined to one artifact
cannot detect a broken pivot.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import plistlib
import sqlite3

from artifactforge.gates import GateReport


def load_join(scene_dir: str) -> dict:
    """The scene's answer key. Kept as a parameter so it can live outside the served tree."""
    with open(os.path.join(scene_dir, "JOIN_MANIFEST.json")) as f:
        return json.load(f)


def _find_by_magic(scene_dir: str, magic: bytes) -> str | None:
    for name in sorted(os.listdir(scene_dir)):
        path = os.path.join(scene_dir, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            if f.read(len(magic)) == magic:
                return path
    return None


def _check(r: GateReport, spans: str, what: str, got, want):
    """One cross-artifact equality, counted whether it holds or not."""
    r.metrics["checks_total"] = r.metrics.get("checks_total", 0) + 1
    if got == want:
        r.metrics["checks_joined"] = r.metrics.get("checks_joined", 0) + 1
        return True
    r.fail(f"{spans}: {what} — disk says {got!r}, manifest says {want!r}")
    return False


def _windows(r: GateReport, scene_dir: str, join: dict):
    import pefile
    from regipy.registry import RegistryHive
    from windowsprefetch import Prefetch

    pe_path = _find_by_magic(scene_dir, b"MZ")
    if pe_path is None:
        r.fail("scene: no PE on disk, so no hash-shaped field can be a digest of anything — "
               "every identity claim in the manifest is unanswerable")
        return
    with open(pe_path, "rb") as f:
        data = f.read()

    _check(r, "disk->manifest", "sha256",
           hashlib.sha256(data).hexdigest(), join["sha256"])
    _check(r, "disk->manifest", "sha1",
           hashlib.sha1(data).hexdigest(), join["sha1"])       # noqa: S324 - identity, not auth
    _check(r, "disk->manifest", "md5",
           hashlib.md5(data).hexdigest(), join["md5"])         # noqa: S324 - identity, not auth
    _check(r, "pefile->manifest", "imphash",
           pefile.PE(data=data).get_imphash(), join["imphash"])

    amcache = os.path.join(scene_dir, "Amcache.hve")
    if os.path.exists(amcache):
        iaf = RegistryHive(amcache).get_key("\\Root\\InventoryApplicationFile")
        vals = {v.name: v.value for v in next(iaf.iter_subkeys()).get_values()}
        _check(r, "Amcache->PE bytes", "FileId trailing SHA1",
               vals["FileId"][4:], hashlib.sha1(data).hexdigest())  # noqa: S324
        _check(r, "Amcache->manifest", "LowerCaseLongPath",
               vals["LowerCaseLongPath"], join["exec_path"].lower())
    else:
        r.fail("scene: no Amcache.hve, so the registry->disk hash pivot is absent")

    run_hive = os.path.join(scene_dir, "Software.run.hive")
    if os.path.exists(run_hive):
        run = RegistryHive(run_hive).get_key("\\Microsoft\\Windows\\CurrentVersion\\Run")
        paths = [v.value for v in run.get_values()]
        _check(r, "Run key->manifest", "persisted path",
               join["exec_path"] in paths, True)
    else:
        r.fail("scene: no Run hive, so the persistence->binary pivot is absent")

    pfs = glob.glob(os.path.join(scene_dir, "*.pf"))
    if pfs:
        pf = Prefetch(pfs[0])
        _check(r, "prefetch->manifest", "executed name",
               pf.executableName.lower(), join["exec_name"].lower())
        _check(r, "prefetch->Run key", "referenced path names the persisted binary",
               any(join["exec_name"].upper() in ref.upper() for ref in pf.resources), True)
    else:
        r.fail("scene: no prefetch file, so there is no execution evidence to join")


def _macos(r: GateReport, scene_dir: str, join: dict):
    qdb = os.path.join(scene_dir, "QuarantineEventsV2")
    xattrs = glob.glob(os.path.join(scene_dir, "*.quarantine.xattr"))
    if os.path.exists(qdb) and xattrs:
        con = sqlite3.connect(qdb)
        try:
            db_uuid = con.execute(
                "SELECT LSQuarantineEventIdentifier FROM LSQuarantineEvent").fetchone()[0]
        finally:
            con.close()
        with open(xattrs[0]) as f:
            xattr_uuid = f.read().split(";")[-1]
        _check(r, "xattr->QuarantineEventsV2", "quarantine UUID", xattr_uuid, db_uuid)
        _check(r, "QuarantineEventsV2->manifest", "quarantine UUID",
               db_uuid, join["quarantine_uuid"])
    else:
        r.fail("scene: quarantine xattr or QuarantineEventsV2 missing, so the macOS "
               "download pivot is absent")

    tcc = os.path.join(scene_dir, "TCC.db")
    if os.path.exists(tcc):
        con = sqlite3.connect(tcc)
        try:
            client = con.execute(
                "SELECT client FROM access WHERE auth_value = 2").fetchone()[0]
        finally:
            con.close()
        _check(r, "TCC->manifest", "granted client", client, join["bundle_id"])

    kc = os.path.join(scene_dir, "knowledgeC.db")
    if os.path.exists(kc):
        con = sqlite3.connect(kc)
        try:
            used = con.execute(
                "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME = '/app/inFocus'"
            ).fetchone()[0]
        finally:
            con.close()
        _check(r, "knowledgeC->TCC", "the app that was used is the app that was granted",
               used, join["bundle_id"])

    plists = glob.glob(os.path.join(scene_dir, "*.plist"))
    if plists:
        with open(plists[0], "rb") as f:
            pl = plistlib.load(f)
        _check(r, "LaunchAgent->manifest", "persisted program",
               pl["ProgramArguments"][0], join["app_path"])
    else:
        r.fail("scene: no LaunchAgent plist, so the macOS persistence pivot is absent")


def run(scene_dir: str, join: dict | None = None) -> GateReport:
    r = GateReport(2, "identity",
                   "is every hash-shaped field a genuine digest of one ContentStore blob?")
    join = load_join(scene_dir) if join is None else join
    if "sha256" in join:
        _windows(r, scene_dir, join)
    else:
        _macos(r, scene_dir, join)
        r.gap("macOS scenes carry no binary and therefore no hash-shaped field; the "
              "keystone currently covers the Windows family only")
    joined = r.metrics.get("checks_joined", 0)
    total = r.metrics.get("checks_total", 0)
    r.denominator = f"{joined}/{total} cross-artifact identity checks hold"
    return r
