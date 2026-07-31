"""A reference solver — the benchmark's validity gate and a worked example.

It reads a Task's artifacts with real DFIR parsers and answers the questions independently of
the answer key. If it scores 100%, the artifacts genuinely encode the ground truth (the
answer key is not asserted, it is *recovered*). Trivial solvers (null / constant) exist to
prove the scorer is not vacuously passing.

Parser imports are lazy so `import artifactforge` never requires the dev oracles.
"""
from __future__ import annotations

import glob
import hashlib
import os
import plistlib
import sqlite3

from artifactforge.bench.benchmark import Task


def _find_pe(directory: str) -> str:
    for f in os.listdir(directory):
        p = os.path.join(directory, f)
        if os.path.isfile(p):
            with open(p, "rb") as fh:
                if fh.read(2) == b"MZ":
                    return p
    raise FileNotFoundError("no PE in " + directory)


def _query1(path: str, sql: str):
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchone()
    finally:
        con.close()


def reference_solve(task: Task) -> dict:
    """Recover answers from the artifacts using real parsers."""
    import pefile
    from regipy.registry import RegistryHive
    from windowsprefetch import Prefetch

    d = task.directory
    a = {}
    if task.family == "windows":
        pe_path = _find_pe(d)
        data = open(pe_path, "rb").read()
        a["dropped_sha256"] = hashlib.sha256(data).hexdigest()
        a["amcache_sha1"] = hashlib.sha1(data).hexdigest()
        a["imphash"] = pefile.PE(data=data).get_imphash()
        run = RegistryHive(os.path.join(d, "Software.run.hive")).get_key(
            "\\Microsoft\\Windows\\CurrentVersion\\Run")
        a["persistence_path"] = next(iter({v.name: v.value for v in run.get_values()}.values()))
        pf = Prefetch(glob.glob(os.path.join(d, "*.pf"))[0])
        a["exec_name"] = pf.executableName.lower()
        a["run_count"] = pf.runCount
        # cross-check Amcache FileId really equals the PE SHA1
        iaf = RegistryHive(os.path.join(d, "Amcache.hve")).get_key("\\Root\\InventoryApplicationFile")
        fid = {v.name: v.value for v in next(iaf.iter_subkeys()).get_values()}["FileId"]
        assert fid[4:] == a["amcache_sha1"], "Amcache/PE hash join broken in artifacts"
    else:
        row = _query1(os.path.join(d, "QuarantineEventsV2"),
                      "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString FROM LSQuarantineEvent")
        a["quarantine_uuid"], a["download_url"] = row
        a["tcc_bundle_id"] = _query1(os.path.join(d, "TCC.db"),
                                     "SELECT client FROM access WHERE auth_value = 2")[0]
        with open(glob.glob(os.path.join(d, "*.plist"))[0], "rb") as f:
            a["persistence_path"] = plistlib.load(f)["ProgramArguments"][0]
    return a


# The trivial solvers that used to live here now sit in artifactforge.bench.adversary,
# alongside the two that actually threaten the benchmark. Keeping the weak baselines apart
# from the strong ones was how "trivial solvers score 0%" came to read as a validity proof
# when a solver opening zero files was scoring 100%.
