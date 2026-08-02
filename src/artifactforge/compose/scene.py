# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Compose a scene: several artifacts, one incident, and exactly one thread through them.

A scene is deliberately noisy. A host with a single binary, a single registry value and a
single execution record is not an investigation — every question about it is a lookup, and a
benchmark built on it cannot tell whether the cross-artifact hash pivot works, because there
is nothing to pivot between. That is not hypothetical: the previous scenes scored 100% after
their Amcache-to-disk hash join had been deliberately destroyed.

So each Windows scene carries five equal-size resident binaries and two deliberately separate
layers. Run/prefetch still model one resident autostart and one orphan execution for Gates 1–3.
Gate 4 instead receives five historical Amcache rows: every FileId is the real SHA1 of a
different resident's bytes, while historical Name/path fields identify none of the current
filenames. Five questions therefore cover all five candidate slots once; three additional
Amcache rows carry absent hashes as ordinary noise. Resident generation, FileId mapping,
registry-row order and question order use independent keyed permutations.

Nothing is written into the served directory directly. Artifacts are built into a staging
area and copied in by allowlist, so what a solver can see equals what we intended it to see —
by construction, rather than by filtering a listing after the fact.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import PurePosixPath

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
from artifactforge.artifacts.linux import build_bash_history, build_desktop_entry
from artifactforge import suite
from artifactforge.content import ContentStore
from artifactforge.inventory import open_real_directory, write_regular_file_at
from artifactforge.model import PINNED_UNIX, HostProfile, deterministic_uuid


WINDOWS_AMCACHE_RULE = "amcache-fileid-byte-agreement-v1"
MACOS_QUARANTINE_RULE = "quarantine-uuid-event-agreement-v1"


def _keyed_order(skey: bytes, label: str, values, *, identity) -> list:
    """A deterministic order with a domain independent from every other scene order.

    Record position is observable evidence.  Reusing construction order for residents,
    database rows and public questions made the first role the answer in every scene, so each
    sequence gets its own keyed ranking even when it contains the same logical objects.
    """
    return sorted(
        values,
        key=lambda value: suite.scene_value(
            skey, f"scene-order:{label}:{identity(value)}"
        ),
    )


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


def _linux_served_path(profile: HostProfile, guest_path: str) -> str:
    """Map one exact guest path into the recursive loose export namespace.

    The mapping is deliberately boring and reversible: an absolute guest path loses exactly
    its leading slash.  No basename search or host-path projection is allowed, so two files
    with the same basename in different guest directories remain different evidence.
    """
    home = profile.home_dir
    path = PurePosixPath(guest_path)
    if (
        profile.os_family != "linux"
        or not guest_path.startswith(home + "/")
        or not guest_path.startswith("/")
        or guest_path.startswith("//")
        or guest_path.endswith("/")
        or "\\" in guest_path
        or path.as_posix() != guest_path
        or any(part in {"", ".", ".."} for part in guest_path.split("/")[1:])
    ):
        raise ValueError(f"Linux guest path is outside the exact home export profile: {guest_path!r}")
    return guest_path[1:]


def build_windows_scene(store: ContentStore, *, skey: bytes, profile: HostProfile,
                        scene_dir: str, staging_dir: str) -> Scene:
    temp = f"{profile.home_dir}\\AppData\\Local\\Temp"

    persisted_name = suite.pick(skey, "persisted-name", pools.MALWARE_NAMES)
    amcache_name, *noise_names = suite.pick_many(skey, "resident", pools.BENIGN_NAMES, 4)
    absent_name = suite.pick(skey, "absent",
                             [n for n in pools.MALWARE_NAMES if n != persisted_name])

    persisted_path = f"{temp}\\{persisted_name}"

    # --- five equal-size resident binaries --------------------------------------------
    # Generation order, the Amcache relation permutation and every stored row order are
    # independent.  A role-first solver used to recover every answer because all three were
    # the same list with different encodings.
    resident_specs = [
        ("persisted", persisted_name),
        ("amcache-match", amcache_name),
        *[(f"noise{i}", name) for i, name in enumerate(noise_names)],
    ]
    resident_specs = _keyed_order(
        skey, "windows-resident-generation", resident_specs, identity=lambda item: item[0]
    )
    resident = {}
    resident_claims = {}
    for role, name in resident_specs:
        c = store.materialize("pe:" + suite.content_seed(skey, role))
        resident[name] = c
        path = persisted_path if role == "persisted" else _full_path(name)
        resident_claims[name] = {
            "role": role,
            "name": name,
            "path": path,
            "size": len(c.bytes),
            "sha256": c.sha256,
            "sha1": c.sha1,
            "md5": c.md5,
            "imphash": c.imphash,
            "marker": c.marker,
        }
        _write(staging_dir, name, c.bytes)

    sizes = {len(content.bytes) for content in resident.values()}
    if len(sizes) != 1:
        raise ValueError(f"Windows benchmark residents left the fixed-size PE profile: {sizes}")
    persisted = resident[persisted_name]

    # --- persistence: three autostarts, only one naming a program that is here --------
    names = suite.pick_many(skey, "run-values", pools.RUN_VALUE_NAMES, 3)
    absent_targets = [n for n in pools.BENIGN_NAMES if n not in resident]
    run_values = [
        (names[0], persisted_path),
        (names[1], _full_path(suite.pick(skey, "run-decoy-1", absent_targets))),
        (names[2], _full_path(suite.pick(skey, "run-decoy-2", absent_targets))),
    ]
    _write(staging_dir, "Software.run.hive", build_run_hive(run_values))

    # --- Amcache: five independent byte-identity relations plus stale noise ------------
    # Each prompted historical row describes bytes later found under a different resident
    # filename.  Name, path, size, order and role therefore cannot map a prompt to the current
    # file: the row's FileId SHA1 agreeing with bytes on disk is the relation.
    resident_names = set(resident)
    historical_pool = [
        name for name in pools.BENIGN_NAMES if name.lower() not in {
            resident_name.lower() for resident_name in resident_names
        }
    ]
    historical_names = suite.pick_many(
        skey, "amcache-historical-names", historical_pool, len(resident)
    )
    mapped_residents = _keyed_order(
        skey,
        "windows-amcache-mapping",
        list(resident_claims.values()),
        identity=lambda claim: claim["name"],
    )
    benchmark_relations = []
    current_rows = []

    def opaque_amcache_record_key(label: str) -> str:
        """Derive a row identifier that cannot act as an alternate resident-hash link."""
        resident_sha1s = tuple(claim["sha1"] for claim in resident_claims.values())
        for nonce in range(256):
            token = suite.content_seed(skey, f"amcache-record:{label}:{nonce}")[:16]
            if not any(sha1.startswith(token) for sha1 in resident_sha1s):
                return "0000" + token
        raise ValueError("could not derive an Amcache record key independent of resident SHA1")

    for index, (historical_name, claim) in enumerate(
        zip(historical_names, mapped_residents, strict=True)
    ):
        token = suite.content_seed(skey, f"amcache-history:{index}")[:12]
        lower_path = (
            f"c:\\programdata\\package cache\\{token}\\{historical_name.lower()}"
        )
        selector = {"lower_case_long_path": lower_path}
        current_rows.append({
            "sha1": claim["sha1"],
            "lower_path": lower_path,
            "name": historical_name,
            "size": claim["size"],
            "record_key": opaque_amcache_record_key(lower_path),
        })
        benchmark_relations.append({
            "rule": WINDOWS_AMCACHE_RULE,
            "selector": selector,
            "expected": claim["sha256"],
            "candidate": claim["name"],
            "link_value": claim["sha1"],
        })

    used_names = resident_names | set(historical_names)
    decoy_pool = [name for name in pools.BENIGN_NAMES if name not in used_names]
    stale_rows = []
    for index, name in enumerate(suite.pick_many(skey, "amcache-decoys", decoy_pool, 3)):
        stale_rows.append({
            "sha1": _absent_sha1(skey, f"amcache-decoy:{index}"),
            "lower_path": _full_path(name).lower(),
            "name": name,
            "size": len(persisted.bytes),
            "record_key": opaque_amcache_record_key(f"stale:{index}:{name}"),
        })
    amcache_rows = _keyed_order(
        skey,
        "windows-amcache-row",
        [*current_rows, *stale_rows],
        identity=lambda row: row["lower_path"],
    )
    _write(
        staging_dir,
        "Amcache.hve",
        build_amcache_hive([
            (
                row["sha1"],
                row["lower_path"],
                row["name"],
                row["size"],
                row["record_key"],
            )
            for row in amcache_rows
        ]),
    )

    # --- prefetch: four executions, one of a program that has since gone --------------
    run_count = 1 + skey[0] % 9
    executions = [
        (persisted_name, persisted_path, run_count),
        (amcache_name, _full_path(amcache_name), 1 + skey[1] % 5),
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

    benchmark_relations = _keyed_order(
        skey,
        "windows-question",
        benchmark_relations,
        identity=lambda relation: relation["selector"]["lower_case_long_path"],
    )
    benchmark_candidates = _keyed_order(
        skey,
        "windows-candidate",
        [
            {
                "identity": claim["name"],
                "value": claim["sha256"],
                "link_value": claim["sha1"],
            }
            for claim in resident_claims.values()
        ],
        identity=lambda candidate: candidate["identity"],
    )
    join = {
        "family": "windows",
        "os": f"{profile.os_family} {profile.version}",
        "host": profile.hostname,
        "user": profile.username,
        "persisted": {"name": persisted_name, "path": persisted_path,
                      "sha256": persisted.sha256, "sha1": persisted.sha1,
                      "md5": persisted.md5, "imphash": persisted.imphash,
                      "marker": persisted.marker, "run_count": run_count},
        "residents": _keyed_order(
            skey,
            "windows-private-resident-truth",
            list(resident_claims.values()),
            identity=lambda claim: claim["name"],
        ),
        "benchmark_candidates": benchmark_candidates,
        "benchmark_relations": benchmark_relations,
        "orphan_execution": absent_name,
        "decoys": {"binaries": len(resident), "run_values": len(run_values),
                   "amcache_rows": len(amcache_rows), "prefetch": len(pf_names)},
        "pivots": {
            "persisted": "the one Run value naming a resident program -> that file on disk",
            "amcache": "five historical rows' FileId SHA1 values -> five resident files",
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
    all_bundles = [subject, also_granted, persisted_only, *benign]
    binary_order = _keyed_order(
        skey, "macos-binary-generation", all_bundles, identity=lambda bundle: bundle
    )
    for b in binary_order:
        c = store.materialize(f"macho:{b}:" + suite.content_seed(skey, f"macho:{b}"))
        binaries[b] = c
        _write(staging_dir, b, c.bytes)

    # --- quarantine: five UUID relations with no name/order/agent shortcut ------------
    # Every sidecar carries a distinct UUID and every public-grade relation follows that
    # value into QuarantineEventsV2.  Bundle names do not occur in URLs, while agent and time
    # are deliberately equal across rows, leaving UUID equality as the only row selector.
    uuids, events = {}, []
    shared_agent = suite.pick(skey, "quarantine-agent", pools.DOWNLOAD_AGENTS)
    shared_host = suite.pick(skey, "quarantine-host", pools.DOWNLOAD_HOSTS)
    benchmark_relations = []
    for b in all_bundles:
        u = deterministic_uuid(suite.content_seed(skey, f"quarantine:{b}"))
        opaque_download = suite.content_seed(skey, f"quarantine-url:{b}")[:24]
        url = f"https://{shared_host}/downloads/{opaque_download}.dmg"
        uuids[b] = (u, shared_agent, url)
        events.append((u, shared_agent, url, f"https://{shared_host}/downloads", t))
        xattr_relative_path = f"{b}.quarantine.xattr"
        _write(staging_dir, f"{b}.quarantine.xattr",
               quarantine_xattr(u, shared_agent, PINNED_UNIX).encode())
        benchmark_relations.append({
            "rule": MACOS_QUARANTINE_RULE,
            "selector": {"xattr_relative_path": xattr_relative_path},
            "expected": url,
            "candidate": b,
            "link_value": u,
        })
    events = _keyed_order(
        skey, "macos-quarantine-row", events, identity=lambda event: event[0]
    )
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

    benchmark_relations = _keyed_order(
        skey,
        "macos-question",
        benchmark_relations,
        identity=lambda relation: relation["selector"]["xattr_relative_path"],
    )
    benchmark_candidates = _keyed_order(
        skey,
        "macos-candidate",
        [
            {"identity": bundle, "value": values[2], "link_value": values[0]}
            for bundle, values in uuids.items()
        ],
        identity=lambda candidate: candidate["identity"],
    )
    u, agent, url = uuids[subject]
    c = binaries[subject]
    binary_truth = _keyed_order(
        skey,
        "macos-private-binary-truth",
        [
            {
                "bundle_id": bundle,
                "size": len(content.bytes),
                "sha256": content.sha256,
                "sha1": content.sha1,
                "md5": content.md5,
                "symhash": content.symhash,
                "cdhash": content.cdhash,
                "marker": content.marker,
            }
            for bundle, content in binaries.items()
        ],
        identity=lambda claim: claim["bundle_id"],
    )
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
        "binaries": binary_truth,
        "benchmark_candidates": benchmark_candidates,
        "benchmark_relations": benchmark_relations,
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


def build_linux_scene(store: ContentStore, *, skey: bytes, profile: HostProfile,
                      scene_dir: str, staging_dir: str) -> Scene:
    """Build the bounded glibc/x86-64 loose-artifact assurance scene.

    This is not a benchmark task and does not claim a working desktop session.  It emits five
    real inert ELF files, three structurally valid XDG autostart records, and one timestamped
    Bash history.  The unique evidence thread is the resident named by both an autostart
    ``Exec`` value and a direct history command.  Every guest path has one exact recursive
    served-path counterpart.
    """
    if profile.os_family != "linux" or profile.version != "glibc-x86_64":
        raise ValueError(
            "Linux loose scenes require the exact linux/glibc-x86_64 host profile"
        )

    names = suite.pick_many(skey, "linux-residents", pools.LINUX_EXECUTABLE_NAMES, 5)
    roles = (
        "subject",
        "autostart-decoy-1",
        "autostart-decoy-2",
        "history-decoy-1",
        "history-decoy-2",
    )
    resident_by_role = {}
    for role, name in zip(roles, names):
        guest_path = f"{profile.home_dir}/.local/bin/{name}"
        served_relpath = _linux_served_path(profile, guest_path)
        content = store.materialize("elf:" + suite.content_seed(skey, f"linux:{role}"))
        _write(staging_dir, served_relpath, content.bytes)
        resident_by_role[role] = {
            "role": role,
            "name": name,
            "guest_path": guest_path,
            "served_relpath": served_relpath,
            "sha256": content.sha256,
            "sha1": content.sha1,
            "md5": content.md5,
            "marker": content.marker,
        }

    autostart_roles = roles[:3]
    desktop_records = []
    for index, role in enumerate(autostart_roles, start=1):
        resident = resident_by_role[role]
        desktop_guest = (
            f"{profile.home_dir}/.config/autostart/"
            f"artifactforge-{index}-{resident['name']}.desktop"
        )
        desktop_served = _linux_served_path(profile, desktop_guest)
        _write(
            staging_dir,
            desktop_served,
            build_desktop_entry(
                f"User helper {index}",
                "Synthetic ArtifactForge XDG autostart evidence",
                resident["guest_path"],
            ),
        )
        desktop_records.append({
            "role": role,
            "guest_path": desktop_guest,
            "served_relpath": desktop_served,
            "exec_guest_path": resident["guest_path"],
        })

    history_roles = (roles[0], roles[3], roles[4])
    history_guest = f"{profile.home_dir}/.bash_history"
    history_served = _linux_served_path(profile, history_guest)
    all_guest_paths = tuple(
        resident_by_role[role]["guest_path"] for role in roles
    )
    history_entries = [
        (PINNED_UNIX, ": 'ARTIFACTFORGE-SYNTHETIC-LINUX'"),
        *[
            (PINNED_UNIX + index, resident_by_role[role]["guest_path"])
            for index, role in enumerate(history_roles, start=1)
        ],
    ]
    _write(
        staging_dir,
        history_served,
        build_bash_history(history_entries, resident_paths=all_guest_paths),
    )

    residents = sorted(resident_by_role.values(), key=lambda item: item["served_relpath"])
    allowlist = sorted([
        *(resident["served_relpath"] for resident in residents),
        *(record["served_relpath"] for record in desktop_records),
        history_served,
    ])
    artifacts = suite.stage(scene_dir, staging_dir, allowlist)
    subject = dict(resident_by_role["subject"])
    join = {
        "family": "linux",
        "profile": "linux-glibc-x86_64-loose-v1",
        "os": f"{profile.os_family} {profile.version}",
        "host": profile.hostname,
        "user": profile.username,
        "home_dir": profile.home_dir,
        "residents": residents,
        "subject": subject,
        "autostart": sorted(desktop_records, key=lambda item: item["served_relpath"]),
        "bash_history": {
            "guest_path": history_guest,
            "served_relpath": history_served,
            "direct_exec_guest_paths": sorted(
                resident_by_role[role]["guest_path"] for role in history_roles
            ),
        },
        "decoys": {
            "resident_elfs": len(residents),
            "autostart_entries": len(desktop_records),
            "history_direct_execs": len(history_roles),
        },
        "pivots": {
            "subject": "the one resident named by both XDG autostart Exec and Bash history",
            "digest": "guest path -> exact served relative path -> resident ELF bytes",
        },
    }
    return Scene("linux", scene_dir, artifacts, join)
