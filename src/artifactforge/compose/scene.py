# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Compose a scene: several artifacts, one incident, and exactly one thread through them.

A scene is deliberately noisy. A host with a single binary, a single registry value and a
single execution record is not an investigation — every question about it is a lookup, and a
benchmark built on it cannot tell whether the cross-artifact hash pivot works, because there
is nothing to pivot between. That is not hypothetical: the previous scenes scored 100% after
their Amcache-to-disk hash join had been deliberately destroyed.

So each scene carries decoys, and the signals deliberately do not all point at the same file:

  * five binaries on disk, of which one is what persistence launches and a *different* one is
    the one Amcache's recorded hashes actually match,
  * three Run-key values, only one naming a program that is present,
  * eight Amcache rows, only one whose recorded SHA1 belongs to a resident file — including a
    row for the persisted binary carrying a deliberately stale value; the historical bytes
    behind that modeled value are not retained,
  * four prefetch records, one of which names an executable that is no longer there.

Nothing is written into the served directory directly. Artifacts are built into a staging
area and copied in by allowlist, so what a solver can see equals what we intended it to see —
by construction, rather than by filtering a listing after the fact.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from artifactforge import pools
from artifactforge.artifacts.hive import build_amcache_hive, build_run_hive
from artifactforge.artifacts.macos import (
    build_knowledgec,
    build_launch_agent,
    build_quarantine_events,
    build_tcc,
    quarantine_xattr,
)
from artifactforge.artifacts.prefetch import build_prefetch, prefetch_name_hash
from artifactforge import suite
from artifactforge.content import ContentStore
from artifactforge.inventory import open_real_directory, write_regular_file_at
from artifactforge.model import PINNED_UNIX, HostProfile, deterministic_uuid


@dataclass
class Scene:
    family: str
    directory: str                                  # the served directory
    artifacts: list = field(default_factory=list)   # exactly what a solver can see
    join: dict = field(default_factory=dict)        # server-side: answers and how they join


def _device_path(exec_path: str) -> str:
    """A Windows path as prefetch records it: one device token, not two.

    Real prefetch writes `\\DEVICE\\HARDDISKVOLUME<n>\\...` in both the filename-strings array
    and the volume-information block. Emitting a different token in each — which this did —
    is the sort of thing a responder notices in the first minute.
    """
    tail = exec_path.split(":", 1)[-1] if ":" in exec_path else exec_path
    return "\\DEVICE\\HARDDISKVOLUME1" + tail.upper()


#: Where a given executable actually lives on Windows. Shipping `C:\\Program Files\\
#: explorer.exe` is the kind of detail that tells a responder the scene was not made by
#: someone who has looked at one; anything not listed here is third-party and does live under
#: Program Files.
_SYSTEM32 = frozenset({
    "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe", "explorer.exe", "javaw.exe",
    "powershell.exe", "conhost_x.exe", "ctfmon_x64.exe", "dllhost_up.exe", "taskeng_x.exe",
    "rundll_svc.exe", "spoolsvr.exe", "srvhost32.exe", "smartscrn.exe", "winlogon_h.exe",
    "lsass_mon.exe", "shellexp.exe", "dnscache.exe", "wmi_perf.exe", "printsvc.exe",
})


def _install_dir(name: str) -> str:
    """Where this executable would sit on a real host."""
    if name.lower() == "explorer.exe":
        return "C:\\Windows"
    return "C:\\Windows\\System32" if name.lower() in _SYSTEM32 else "C:\\Program Files"


def _full_path(name: str) -> str:
    return f"{_install_dir(name)}\\{name}"


def _absent_sha1(skey: bytes, tag: str) -> str:
    """A hash-shaped value belonging to no file here — the decoy Amcache rows' whole job."""
    return hashlib.sha1(skey + tag.encode()).hexdigest()          # noqa: S324 - identity


def _write(staging: str, name: str, data: bytes) -> None:
    root_fd = open_real_directory(staging, create=True)
    try:
        write_regular_file_at(root_fd, name, data)
    finally:
        os.close(root_fd)


def build_windows_scene(store: ContentStore, *, skey: bytes, profile: HostProfile,
                        scene_dir: str, staging_dir: str) -> Scene:
    temp = f"{profile.home_dir}\\AppData\\Local\\Temp"

    persisted_name = suite.pick(skey, "persisted-name", pools.MALWARE_NAMES)
    amcache_name, *noise_names = suite.pick_many(skey, "resident", pools.BENIGN_NAMES, 4)
    absent_name = suite.pick(skey, "absent",
                             [n for n in pools.MALWARE_NAMES if n != persisted_name])

    persisted_path = f"{temp}\\{persisted_name}"
    amcache_path = f"{_install_dir(amcache_name)}\\{amcache_name}"

    # --- the binaries. Two carry answers; the rest are the haystack. ------------------
    resident = {}
    for role, name in [("persisted", persisted_name), ("amcache-match", amcache_name),
                       *[(f"noise{i}", n) for i, n in enumerate(noise_names)]]:
        c = store.materialize("pe:" + suite.content_seed(skey, role))
        resident[name] = c
        _write(staging_dir, name, c.bytes)

    persisted, matched = resident[persisted_name], resident[amcache_name]

    # --- persistence: three autostarts, only one naming a program that is here --------
    names = suite.pick_many(skey, "run-values", pools.RUN_VALUE_NAMES, 3)
    absent_targets = [n for n in pools.BENIGN_NAMES if n not in resident]
    run_values = [
        (names[0], persisted_path),
        (names[1], _full_path(suite.pick(skey, "run-decoy-1", absent_targets))),
        (names[2], _full_path(suite.pick(skey, "run-decoy-2", absent_targets))),
    ]
    _write(staging_dir, "Software.run.hive", build_run_hive(run_values))

    # --- Amcache: eight rows, exactly one hash belonging to a file that is still here --
    rows = [(matched.sha1, amcache_path.lower(), amcache_name, len(matched.bytes))]
    # The persisted binary IS recorded, but under a deliberately stale value. This models the
    # pivot shape without retaining historical bytes, so do not describe it as a verified
    # digest of an earlier version. Following hashes still leads somewhere different from
    # following paths, which is the point.
    rows.append((_absent_sha1(skey, "stale-persisted"), persisted_path.lower(),
                 persisted_name, len(persisted.bytes) + 4096))
    for i, n in enumerate(suite.pick_many(skey, "amcache-decoys", absent_targets, 6)):
        rows.append((_absent_sha1(skey, f"amcache{i}"), _full_path(n).lower(), n, 4096 * (i + 3)))
    _write(staging_dir, "Amcache.hve", build_amcache_hive(rows))

    # --- prefetch: four executions, one of a program that has since gone --------------
    run_count = 1 + skey[0] % 9
    executions = [
        (persisted_name, persisted_path, run_count),
        (amcache_name, amcache_path, 1 + skey[1] % 5),
        (noise_names[0], _full_path(noise_names[0]), 1 + skey[2] % 5),
        (absent_name, f"{temp}\\{absent_name}", 1 + skey[3] % 5),
    ]
    pf_names = []
    for name, path, count in executions:
        dev = _device_path(path)
        pf = f"{name.upper()}-{prefetch_name_hash(dev):08X}.pf"
        _write(staging_dir, pf, build_prefetch(name, dev, count))
        pf_names.append(pf)

    allowlist = sorted([*resident, "Software.run.hive", "Amcache.hve", *pf_names])
    artifacts = suite.stage(scene_dir, staging_dir, allowlist)

    join = {
        "family": "windows",
        "os": f"{profile.os_family} {profile.version}",
        "host": profile.hostname,
        "user": profile.username,
        "persisted": {"name": persisted_name, "path": persisted_path,
                      "sha256": persisted.sha256, "sha1": persisted.sha1,
                      "md5": persisted.md5, "imphash": persisted.imphash,
                      "marker": persisted.marker, "run_count": run_count},
        "amcache_match": {"name": amcache_name, "path": amcache_path,
                          "sha256": matched.sha256, "sha1": matched.sha1,
                          "file_id": "0000" + matched.sha1, "imphash": matched.imphash},
        "orphan_execution": absent_name,
        "decoys": {"binaries": len(resident), "run_values": len(run_values),
                   "amcache_rows": len(rows), "prefetch": len(pf_names)},
        "pivots": {
            "persisted": "the one Run value naming a resident program -> that file on disk",
            "amcache_match": "the one FileId whose SHA1 belongs to a resident file -> that file",
            "run_count": "Run value -> resident program -> its prefetch record",
            "orphan_execution": "the prefetch record naming a program absent from disk",
        },
    }
    return Scene("windows", scene_dir, artifacts, join)


def build_macos_scene(store: ContentStore, *, skey: bytes, profile: HostProfile,
                      scene_dir: str, staging_dir: str) -> Scene:
    support = f"{profile.home_dir}/Library/Application Support"
    t = profile.mac_abs_time()

    # Five candidate apps. Two hold an allowed TCC grant; only one of those was ever used.
    bundles = suite.pick_many(skey, "bundles", pools.BUNDLES, 3)
    benign = suite.pick_many(skey, "benign-bundles", pools.BENIGN_BUNDLES, 2)
    subject, also_granted, persisted_only = bundles

    def app_path(b):
        return f"{support}/{b}/{b.rsplit('.', 1)[-1]}"

    # --- the binaries. Real Mach-O, routed through the same ContentStore as the PEs, so a
    # macOS scene carries genuine hash-shaped identity rather than only database rows. The
    # signing identifier is part of the content id because it lives inside the CodeDirectory
    # and therefore changes the file's SHA256.
    binaries = {}
    for b in [subject, also_granted, persisted_only, *benign]:
        c = store.materialize(f"macho:{b}:" + suite.content_seed(skey, f"macho:{b}"))
        binaries[b] = c
        _write(staging_dir, b, c.bytes)

    # --- quarantine: five downloads, each with its own UUID and origin ----------------
    all_bundles = [subject, also_granted, persisted_only, *benign]
    uuids, events = {}, []
    for b in all_bundles:
        u = deterministic_uuid(suite.content_seed(skey, f"quarantine:{b}"))
        agent = suite.pick(skey, f"agent:{b}", pools.DOWNLOAD_AGENTS)
        host = suite.pick(skey, f"dlhost:{b}", pools.DOWNLOAD_HOSTS)
        url = f"https://{host}/{b}.dmg"
        uuids[b] = (u, agent, url)
        events.append((u, agent, url, f"https://{host}/downloads", t))
        _write(staging_dir, f"{b}.quarantine.xattr",
               quarantine_xattr(u, agent, PINNED_UNIX).encode())
    _write(staging_dir, "QuarantineEventsV2", build_quarantine_events(events))

    # --- TCC: four clients, two allowed. Only one of those appears in knowledgeC -------
    tcc_rows = [
        (subject, suite.pick(skey, "tcc-subject", pools.TCC_SERVICES), 2),
        (also_granted, suite.pick(skey, "tcc-other", pools.TCC_SERVICES), 2),
        (benign[0], "kTCCServiceAppleEvents", 0),
        (persisted_only, "kTCCServiceCamera", 0),
    ]
    # TCC stores Unix time, not Mac absolute time — see build_tcc.
    _write(staging_dir, "TCC.db",
           build_tcc([(c, s, a, PINNED_UNIX) for c, s, a in tcc_rows]))

    # --- knowledgeC: three apps actually used -----------------------------------------
    used = [subject, *benign]
    _write(staging_dir, "knowledgeC.db",
           build_knowledgec([(b, t + 60 * i, t + 60 * i + 120) for i, b in enumerate(used)]))

    # --- persistence: three LaunchAgents, only one for an app with an allowed grant ----
    agents = [subject, persisted_only, benign[1]]
    for b in agents:
        _write(staging_dir, f"{b}.plist", build_launch_agent(b, app_path(b)))

    allowlist = sorted(["QuarantineEventsV2", "TCC.db", "knowledgeC.db",
                        *all_bundles,
                        *[f"{b}.plist" for b in agents],
                        *[f"{b}.quarantine.xattr" for b in all_bundles]])
    artifacts = suite.stage(scene_dir, staging_dir, allowlist)

    u, agent, url = uuids[subject]
    c = binaries[subject]
    join = {
        "family": "macos",
        "os": f"{profile.os_family} {profile.version}",
        "host": profile.hostname,
        "user": profile.username,
        "subject": {"bundle_id": subject, "app_path": app_path(subject),
                    "quarantine_uuid": u, "download_url": url, "agent": agent,
                    "tcc_service": tcc_rows[0][1],
                    "sha256": c.sha256, "sha1": c.sha1, "md5": c.md5,
                    "symhash": c.symhash, "cdhash": c.cdhash, "marker": c.marker},
        "decoys": {"bundles": len(all_bundles), "tcc_rows": len(tcc_rows),
                   "quarantine_rows": len(events), "launch_agents": len(agents),
                   "binaries": len(binaries),
                   "also_granted": also_granted, "persisted_only": persisted_only},
        "pivots": {
            "subject": "the one TCC-allowed client that also appears in knowledgeC",
            "download_url": "subject -> its quarantine xattr UUID -> QuarantineEventsV2 row",
            "agent": "the same row's LSQuarantineAgentName",
            "persistence": "subject -> the LaunchAgent whose Label matches it",
            "sha256": "subject -> the binary on disk carrying its bundle identifier",
        },
    }
    return Scene("macos", scene_dir, artifacts, join)
