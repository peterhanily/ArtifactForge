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

import os
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from artifactforge import pools
from artifactforge.artifacts.hive import (
    HiveTimestampSpec,
    build_amcache_hive,
    build_run_hive,
)
from artifactforge.artifacts.macos import (
    build_knowledgec,
    build_launch_agent,
    build_quarantine_events,
    build_tcc,
    quarantine_xattr,
)
from artifactforge.artifacts.prefetch import (
    PrefetchTimestamps,
    build_prefetch_v30,
    prefetch_vista_name_hash,
)
from artifactforge.artifacts.shell_link import (
    ShellLinkTimestamps,
    build_shell_link,
)
from artifactforge.artifacts.windows import ChromiumDownload, build_chromium_history
from artifactforge.artifacts.windows_task import build_scheduled_task_xml
from artifactforge.artifacts.linux import build_bash_history, build_desktop_entry
from artifactforge import suite
from artifactforge.compose.derivation import (
    BENCHMARK_SCENE_DERIVATION,
    SceneDerivation,
)
from artifactforge.content import ContentStore
from artifactforge.disclosure import RESERVED_NAME
from artifactforge.inventory import open_real_directory, write_regular_file_at
from artifactforge.model import HostProfile, deterministic_uuid

if TYPE_CHECKING:
    from artifactforge.fixture.causal import CausalClockSpec


WINDOWS_AMCACHE_RULE = "amcache-fileid-byte-agreement-v1"
MACOS_QUARANTINE_RULE = "quarantine-uuid-event-agreement-v1"
WINDOWS_TASK_XML_SOURCE = "ArtifactForgeMaintenance.task.xml"
WINDOWS_SHELL_LINK_SOURCE = "ArtifactForgeMaintenance.lnk"


def _keyed_order(
    derivation: SceneDerivation,
    skey: bytes,
    label: str,
    values,
    *,
    identity,
) -> list:
    """A deterministic order with a domain independent from every other scene order.

    Record position is observable evidence.  Reusing construction order for residents,
    database rows and public questions made the first role the answer in every scene, so each
    sequence gets its own keyed ranking even when it contains the same logical objects.
    """
    return derivation.order(skey, label, values, identity=identity)


@dataclass
class Scene:
    family: str
    directory: str                                  # the served directory
    artifacts: list = field(default_factory=list)   # exactly what a solver can see
    join: dict = field(default_factory=dict)        # server-side: answers and how they join
    # Public, answer-free facts available to Fixture v2 guest-metadata materialisation.
    # Each value is (generic artifact role, exact Unix nanoseconds); it never names private
    # subject/persisted/decoy roles or any cross-artifact answer relation.
    timestamp_roles: dict[str, tuple[tuple[str, int], ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.timestamp_roles:
            return
        if set(self.timestamp_roles) != set(self.artifacts):
            raise ValueError("scene timestamp roles must cover the exact served inventory")
        forbidden = {"answer", "decoy", "join", "persisted", "subject"}
        for path, records in self.timestamp_roles.items():
            if type(path) is not str or type(records) is not tuple or not records:
                raise ValueError("scene timestamp roles require non-empty tuples by public path")
            names = set()
            for record in records:
                if type(record) is not tuple or len(record) != 2:
                    raise ValueError("scene timestamp role records must be (role, unix_ns) tuples")
                role, unix_ns = record
                if (
                    type(role) is not str
                    or not role
                    or any(token in forbidden for token in role.split("."))
                ):
                    raise ValueError("scene timestamp role is empty or answer-bearing")
                if role in names or type(unix_ns) is not int:
                    raise ValueError("scene timestamp roles must be unique exact integer facts")
                names.add(role)


def _causal_clock(skey: bytes, causal_clock: CausalClockSpec | None) -> CausalClockSpec:
    # Import lazily: fixture lifecycle imports compose, so importing the fixture package while
    # compose itself is initialising would make the package dependency cycle executable.
    from artifactforge.fixture.causal import CausalClockSpec

    if causal_clock is None:
        if type(skey) is not bytes:
            raise ValueError("scene key must be bytes when deriving its causal clock")
        return CausalClockSpec.from_seed_hex(skey.hex())
    if type(causal_clock) is not CausalClockSpec:
        raise ValueError("causal_clock must be a CausalClockSpec or None")
    return causal_clock


def _scene_derivation(value: object) -> SceneDerivation:
    if type(value) is not SceneDerivation:
        raise ValueError("derivation must be an exact SceneDerivation")
    return value


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


def build_windows_download_only_scene(
    store: ContentStore, *, skey: bytes, profile: HostProfile,
    scene_dir: str, staging_dir: str,
    causal_clock: CausalClockSpec | None = None,
    derivation: SceneDerivation = BENCHMARK_SCENE_DERIVATION,
) -> Scene:
    """One completed download that was never run.

    The dropper scene answers "what did this program do".  This one answers the narrower
    question a responder asks first: which of these files came from the web, and is there any
    evidence it executed?  Provenance is present — a completed Chromium download row and the
    logical mark of the web on exactly one resident PE — while every execution and persistence
    surface is absent by construction.  That absence is the claim, so the fixture's logical
    assurance asserts it rather than merely not looking for it.
    """
    derivation = _scene_derivation(derivation)
    derivation.validate_key(skey)
    timeline = _causal_clock(skey, causal_clock).windows()
    downloads_dir = f"{profile.home_dir}\\Downloads"

    downloaded_name = derivation.pick(skey, "downloaded-name", pools.MALWARE_NAMES)
    settled_names = derivation.pick_many(skey, "settled", pools.BENIGN_NAMES, 2)
    downloaded_path = f"{downloads_dir}\\{downloaded_name}"

    # --- three equal-size resident binaries, one of which arrived over HTTP ------------
    # Generation order and the stored row order are independent for the same reason the
    # dropper keeps them apart: position must not become a shortcut to the answer.
    resident_specs = _keyed_order(
        derivation,
        skey,
        "windows-download-only-generation",
        [("downloaded", downloaded_name), *(("settled", name) for name in settled_names)],
        identity=lambda item: item[1],
    )
    resident = {}
    resident_claims = {}
    for role, name in resident_specs:
        content = store.materialize("pe:" + derivation.content_seed(skey, f"{role}:{name}"))
        resident[name] = content
        path = downloaded_path if name == downloaded_name else _full_path(name)
        resident_claims[name] = {
            "role": role,
            "name": name,
            "path": path,
            "size": len(content.bytes),
            "sha256": content.sha256,
            "sha1": content.sha1,
            "md5": content.md5,
            "imphash": content.imphash,
            "marker": content.marker,
        }
        _write(staging_dir, name, content.bytes)

    # The downloaded name comes from a different pool than the settled ones; if those pools ever
    # overlap the scene silently loses a file rather than failing, so state the shape here.
    if len(resident) != 3:
        raise ValueError(
            f"Windows download-only scene needs three distinct residents: {sorted(resident)}"
        )
    sizes = {len(content.bytes) for content in resident.values()}
    if len(sizes) != 1:
        raise ValueError(f"Windows download-only residents left the fixed-size PE profile: {sizes}")
    downloaded = resident[downloaded_name]

    # --- browser download history: one resident arrival, two completed-and-gone -------
    # Chromium persists an empty BLOB in downloads.hash, so the candidate digest travels in a
    # marked reserved URL exactly as it does in the dropper scene.  The two absent rows stop
    # the history surface from being a one-row lookup.
    absent_names = derivation.pick_many(
        skey,
        "windows-download-only-absent",
        [name for name in pools.BENIGN_NAMES if name not in resident],
        2,
    )
    download_specs = [
        {
            "kind": "resident",
            "name": downloaded_name,
            "path": downloaded_path,
            "sha256": downloaded.sha256,
            "size": len(downloaded.bytes),
            "start": timeline.host_initialized.filetime // 10 + 30_000_000,
            "end": timeline.file_created.filetime // 10,
        }
    ]
    for index, name in enumerate(absent_names, start=1):
        start = timeline.host_initialized.filetime // 10 + index * 10_000_000
        download_specs.append(
            {
                "kind": f"absent-{index}",
                "name": name,
                "path": f"{downloads_dir}\\{name}",
                "sha256": derivation.value(
                    skey, "windows-download-only-decoy", str(index)
                ).hex(),
                "size": len(downloaded.bytes),
                "start": start,
                "end": start + 5_000_000,
            }
        )
    download_specs = _keyed_order(
        derivation,
        skey,
        "windows-download-only-row",
        download_specs,
        identity=lambda row: row["kind"],
    )
    download_rows = []
    download_truth = None
    for index, row in enumerate(download_specs):
        digest = row["sha256"]
        token = derivation.content_seed(skey, f"windows-download-only-referrer:{index}")[:12]
        source_url = (
            "https://downloads.artifactforge.invalid/ARTIFACTFORGE/sha256/"
            f"{digest}/{row['name']}"
        )
        referrer_url = (
            "https://portal.artifactforge.invalid/ARTIFACTFORGE/catalog/" + token
        )
        download_rows.append(
            ChromiumDownload(
                target_path=row["path"],
                source_url=source_url,
                referrer_url=referrer_url,
                sha256=bytes.fromhex(digest),
                size=row["size"],
                start_time_windows_us=row["start"],
                end_time_windows_us=row["end"],
                # Never opened: this scene's whole claim is that nothing ran.
                opened=False,
                last_access_time_windows_us=0,
            )
        )
        if row["kind"] == "resident":
            download_truth = {
                "target_path": row["path"],
                "sha256": digest,
                "size": row["size"],
                "source_url": source_url,
                "referrer_url": referrer_url,
            }
    if download_truth is None:
        raise AssertionError("download-only history lost its resident download relation")
    _write(
        staging_dir,
        "History",
        build_chromium_history(tuple(download_rows), identity_seed=skey),
    )

    allowlist = sorted([*resident, "History"])
    artifacts = suite.stage(scene_dir, staging_dir, allowlist)

    join = {
        "family": "windows",
        "os": f"{profile.os_family} {profile.version}",
        "host": profile.hostname,
        "user": profile.username,
        "residents": _keyed_order(
            derivation,
            skey,
            "windows-download-only-resident-truth",
            list(resident_claims.values()),
            identity=lambda claim: claim["name"],
        ),
        "browser_download": download_truth,
        "decoys": {
            "binaries": len(resident),
            "browser_downloads": len(download_rows),
        },
        # Named so the fixture's logical assurance can assert each absence rather than infer
        # it from an inventory that happens to be short.
        "absent_surfaces": [
            "amcache",
            "prefetch",
            "run-key",
            "scheduled-task",
            "shell-link",
        ],
        "pivots": {
            "browser_download": (
                "completed-download content-addressed URL -> resident PE SHA256; "
                "URL/referrer -> logical Zone.Identifier on that one PE"
            ),
            "never_executed": (
                "no prefetch record, Amcache row, Run value, Task definition or Shell Link "
                "names any resident PE; arrival is evidenced, execution is not"
            ),
        },
    }
    timestamp_roles = {
        **{
            name: (("artifact.file-created", timeline.file_created.unix_ns),)
            for name in resident
        },
        "History": (("artifact.logical-updated", timeline.file_created.unix_ns),),
    }
    return Scene("windows", scene_dir, artifacts, join, timestamp_roles)


def build_windows_scene(store: ContentStore, *, skey: bytes, profile: HostProfile,
                        scene_dir: str, staging_dir: str,
                        causal_clock: CausalClockSpec | None = None,
                        derivation: SceneDerivation = BENCHMARK_SCENE_DERIVATION) -> Scene:
    derivation = _scene_derivation(derivation)
    derivation.validate_key(skey)
    timeline = _causal_clock(skey, causal_clock).windows()
    temp = f"{profile.home_dir}\\AppData\\Local\\Temp"

    persisted_name = derivation.pick(skey, "persisted-name", pools.MALWARE_NAMES)
    amcache_name, *noise_names = derivation.pick_many(
        skey, "resident", pools.BENIGN_NAMES, 4
    )
    absent_name = derivation.pick(
        skey,
        "absent",
        [name for name in pools.MALWARE_NAMES if name != persisted_name],
    )

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
        derivation,
        skey,
        "windows-resident-generation",
        resident_specs,
        identity=lambda item: item[0],
    )
    resident = {}
    resident_claims = {}
    for role, name in resident_specs:
        c = store.materialize("pe:" + derivation.content_seed(skey, role))
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
    names = derivation.pick_many(skey, "run-values", pools.RUN_VALUE_NAMES, 3)
    absent_targets = [n for n in pools.BENIGN_NAMES if n not in resident]
    run_values = [
        (names[0], persisted_path),
        (names[1], _full_path(derivation.pick(skey, "run-decoy-1", absent_targets))),
        (names[2], _full_path(derivation.pick(skey, "run-decoy-2", absent_targets))),
    ]
    run_filetime = timeline.run_configured.filetime
    _write(
        staging_dir,
        "Software.run.hive",
        build_run_hive(
            run_values,
            timestamps=HiveTimestampSpec(
                hive_filetime=run_filetime,
                default_key_filetime=timeline.host_initialized.filetime,
                key_filetimes=(
                    (f"ROOT\\{RESERVED_NAME}", run_filetime),
                    (r"ROOT\Microsoft\Windows\CurrentVersion\Run", run_filetime),
                ),
            ),
        ),
    )

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
    historical_names = derivation.pick_many(
        skey, "amcache-historical-names", historical_pool, len(resident)
    )
    mapped_residents = _keyed_order(
        derivation,
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
            token = derivation.content_seed(skey, f"amcache-record:{label}:{nonce}")[:16]
            if not any(sha1.startswith(token) for sha1 in resident_sha1s):
                return "0000" + token
        raise ValueError("could not derive an Amcache record key independent of resident SHA1")

    for index, (historical_name, claim) in enumerate(
        zip(historical_names, mapped_residents, strict=True)
    ):
        token = derivation.content_seed(skey, f"amcache-history:{index}")[:12]
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
    for index, name in enumerate(
        derivation.pick_many(skey, "amcache-decoys", decoy_pool, 3)
    ):
        stale_rows.append({
            "sha1": derivation.opaque_sha1(skey, f"amcache-decoy:{index}"),
            "lower_path": _full_path(name).lower(),
            "name": name,
            "size": len(persisted.bytes),
            "record_key": opaque_amcache_record_key(f"stale:{index}:{name}"),
        })
    amcache_rows = _keyed_order(
        derivation,
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
        ], timestamps=HiveTimestampSpec(
            hive_filetime=timeline.amcache_observed.filetime,
            default_key_filetime=timeline.host_initialized.filetime,
            key_filetimes=(
                (f"amcache\\{RESERVED_NAME}", timeline.amcache_observed.filetime),
                *(
                    (
                        "amcache\\Root\\InventoryApplicationFile\\" + row["record_key"],
                        timeline.amcache_observed.filetime,
                    )
                    for row in amcache_rows
                ),
            ),
        )),
    )

    # --- browser download history: native-empty hash field, byte-derived URL identity ---
    # Current Chromium persists an empty BLOB in downloads.hash for completed downloads.
    # ArtifactForge therefore binds each candidate digest into a marked reserved URL rather
    # than filling a schema-valid field with bytes Chrome itself does not retain.  Only the
    # downloaded temporary executable is resident; two absent completed downloads prevent
    # the history surface from becoming a one-row lookup.
    browser_decoy_names = derivation.pick_many(
        skey,
        "windows-browser-download-decoys",
        [name for name in pools.BENIGN_NAMES if name not in resident],
        2,
    )
    browser_specs = [
        {
            "kind": "resident",
            "name": persisted_name,
            "path": persisted_path,
            "sha256": persisted.sha256,
            "size": len(persisted.bytes),
            "start": timeline.host_initialized.filetime // 10 + 30_000_000,
            "end": timeline.file_created.filetime // 10,
            "opened": True,
            "last_access": timeline.executed.filetime // 10,
        }
    ]
    for index, name in enumerate(browser_decoy_names, start=1):
        start = timeline.host_initialized.filetime // 10 + index * 10_000_000
        browser_specs.append(
            {
                "kind": f"absent-{index}",
                "name": name,
                "path": f"{profile.home_dir}\\Downloads\\{name}",
                "sha256": derivation.value(
                    skey, "windows-browser-download-decoy", str(index)
                ).hex(),
                "size": len(persisted.bytes),
                "start": start,
                "end": start + 5_000_000,
                "opened": False,
                "last_access": 0,
            }
        )
    browser_specs = _keyed_order(
        derivation,
        skey,
        "windows-browser-download-row",
        browser_specs,
        identity=lambda row: row["kind"],
    )
    browser_rows = []
    browser_truth = None
    for index, row in enumerate(browser_specs):
        digest = row["sha256"]
        name = row["name"]
        token = derivation.content_seed(skey, f"windows-browser-referrer:{index}")[:12]
        source_url = (
            "https://downloads.artifactforge.invalid/ARTIFACTFORGE/sha256/"
            f"{digest}/{name}"
        )
        referrer_url = (
            "https://portal.artifactforge.invalid/ARTIFACTFORGE/catalog/" + token
        )
        browser_rows.append(
            ChromiumDownload(
                target_path=row["path"],
                source_url=source_url,
                referrer_url=referrer_url,
                sha256=bytes.fromhex(digest),
                size=row["size"],
                start_time_windows_us=row["start"],
                end_time_windows_us=row["end"],
                opened=row["opened"],
                last_access_time_windows_us=row["last_access"],
            )
        )
        if row["kind"] == "resident":
            browser_truth = {
                "target_path": row["path"],
                "sha256": digest,
                "size": row["size"],
                "source_url": source_url,
                "referrer_url": referrer_url,
            }
    if browser_truth is None:
        raise AssertionError("browser history lost its resident download relation")
    _write(
        staging_dir,
        "History",
        build_chromium_history(tuple(browser_rows), identity_seed=skey),
    )

    # --- inert reference/configuration surfaces ---------------------------------------
    # A disabled, trigger-free Task definition and a local Shell Link each name a real
    # resident PE, but neither is execution evidence.  Their targets come from separately
    # ordered non-persistence sets and must be distinct: adding these reference surfaces must
    # not amplify the Run-key/browser answer into a mention-count shortcut.
    non_persistence_targets = [
        claim for claim in resident_claims.values() if claim["role"] != "persisted"
    ]
    task_targets = _keyed_order(
        derivation,
        skey,
        "windows-task-targets",
        non_persistence_targets,
        identity=lambda claim: claim["name"],
    )
    shell_link_targets = _keyed_order(
        derivation,
        skey,
        "windows-shell-link-targets",
        non_persistence_targets,
        identity=lambda claim: claim["name"],
    )
    if len(task_targets) < 2:
        raise AssertionError("Windows reference artifacts require two non-persistence residents")
    task_name = "Maintenance-" + derivation.content_seed(
        skey, "windows-task-name"
    )[:12]
    task_guest_path = rf"C:\Windows\System32\Tasks\ArtifactForge\{task_name}"
    task_target = None
    task_data = None
    for candidate in task_targets:
        try:
            candidate_data = build_scheduled_task_xml(
                task_name,
                candidate["path"],
                resident_pe_paths=(candidate["path"],),
            )
        except ValueError:
            # The task profile deliberately excludes interpreters and command utilities.
            # Candidate ordering remains independent; compatibility is proved by the writer
            # itself rather than by duplicating its denylist in scene composition.
            continue
        task_target = candidate
        task_data = candidate_data
        break
    if task_target is None or task_data is None:
        raise ValueError(
            "Windows scene has no non-persistence resident inside the scheduled-task profile"
        )
    shell_link_target = next(
        (claim for claim in shell_link_targets if claim["name"] != task_target["name"]),
        None,
    )
    if shell_link_target is None:
        raise AssertionError("Windows Shell Link requires a target distinct from the Task")
    _write(
        staging_dir,
        WINDOWS_TASK_XML_SOURCE,
        task_data,
    )
    scheduled_task_truth = {
        "source": WINDOWS_TASK_XML_SOURCE,
        "guest_path": task_guest_path,
        "task_name": task_name,
        "target_name": task_target["name"],
        "target_path": task_target["path"],
        "target_role": task_target["role"],
        "target_size": task_target["size"],
        "target_sha256": task_target["sha256"],
    }

    shell_link_guest_path = (
        f"{profile.home_dir}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\"
        f"Programs\\{WINDOWS_SHELL_LINK_SOURCE}"
    )
    shell_link_timestamps = ShellLinkTimestamps(
        creation_filetime=timeline.file_created.filetime,
        access_filetime=timeline.executed.filetime,
        write_filetime=timeline.file_created.filetime,
    )
    volume_serial = int(
        derivation.content_seed(skey, "windows-shell-link-volume")[:8], 16
    ) | 1
    _write(
        staging_dir,
        WINDOWS_SHELL_LINK_SOURCE,
        build_shell_link(
            shell_link_target["path"],
            "System Maintenance",
            shell_link_target["size"],
            timestamps=shell_link_timestamps,
            volume_serial=volume_serial,
            volume_label="SYSTEM",
        ),
    )
    shell_link_truth = {
        "source": WINDOWS_SHELL_LINK_SOURCE,
        "guest_path": shell_link_guest_path,
        "target_name": shell_link_target["name"],
        "target_path": shell_link_target["path"],
        "target_role": shell_link_target["role"],
        "target_size": shell_link_target["size"],
        "target_sha256": shell_link_target["sha256"],
        "creation_filetime": shell_link_timestamps.creation_filetime,
        "access_filetime": shell_link_timestamps.access_filetime,
        "write_filetime": shell_link_timestamps.write_filetime,
        "volume_serial": volume_serial,
    }

    # --- prefetch: four executions, one of a program that has since gone --------------
    run_count = derivation.bounded_key_value(
        skey,
        "windows-prefetch-persisted-run-count",
        key_index=0,
        modulus=9,
        offset=1,
    )
    executions = [
        (persisted_name, persisted_path, run_count),
        (
            amcache_name,
            _full_path(amcache_name),
            derivation.bounded_key_value(
                skey,
                "windows-prefetch-amcache-run-count",
                key_index=1,
                modulus=5,
                offset=1,
            ),
        ),
        (
            noise_names[0],
            _full_path(noise_names[0]),
            derivation.bounded_key_value(
                skey,
                "windows-prefetch-noise-run-count",
                key_index=2,
                modulus=5,
                offset=1,
            ),
        ),
        (
            absent_name,
            f"{temp}\\{absent_name}",
            derivation.bounded_key_value(
                skey,
                "windows-prefetch-absent-run-count",
                key_index=3,
                modulus=5,
                offset=1,
            ),
        ),
    ]
    pf_names = []
    for name, path, count in executions:
        dev = _device_path(path)
        pf = f"{name.upper()}-{prefetch_vista_name_hash(dev):08X}.pf"
        _write(
            staging_dir,
            pf,
            build_prefetch_v30(
                name,
                dev,
                count,
                timestamps=PrefetchTimestamps(
                    last_run_filetime=timeline.executed.filetime,
                    volume_creation_filetime=timeline.host_initialized.filetime,
                ),
                volume_serial=volume_serial,
            ),
        )
        pf_names.append(pf)

    allowlist = sorted(
        [
            *resident,
            "Software.run.hive",
            "Amcache.hve",
            "History",
            WINDOWS_TASK_XML_SOURCE,
            WINDOWS_SHELL_LINK_SOURCE,
            *pf_names,
        ]
    )
    artifacts = suite.stage(scene_dir, staging_dir, allowlist)

    benchmark_relations = _keyed_order(
        derivation,
        skey,
        "windows-question",
        benchmark_relations,
        identity=lambda relation: relation["selector"]["lower_case_long_path"],
    )
    benchmark_candidates = _keyed_order(
        derivation,
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
            derivation,
            skey,
            "windows-private-resident-truth",
            list(resident_claims.values()),
            identity=lambda claim: claim["name"],
        ),
        "benchmark_candidates": benchmark_candidates,
        "benchmark_relations": benchmark_relations,
        "orphan_execution": absent_name,
        "prefetch": {
            "artifact_count": len(executions),
            "execution_names": sorted(name for name, _path, _count in executions),
        },
        "browser_download": browser_truth,
        "scheduled_task": scheduled_task_truth,
        "shell_link": shell_link_truth,
        "decoys": {"binaries": len(resident), "run_values": len(run_values),
                   "amcache_rows": len(amcache_rows), "prefetch": len(pf_names),
                   "browser_downloads": len(browser_rows)},
        "pivots": {
            "persisted": "the one Run value naming a resident program -> that file on disk",
            "amcache": "five historical rows' FileId SHA1 values -> five resident files",
            "run_count": "Run value -> resident program -> its prefetch record",
            "orphan_execution": "the prefetch record naming a program absent from disk",
            "browser_download": (
                "completed-download content-addressed URL -> resident PE SHA256; "
                "URL/referrer -> logical Zone.Identifier"
            ),
            "scheduled_task": (
                "disabled trigger-free Task command -> a distinct resident PE reference; "
                "configuration only, never execution"
            ),
            "shell_link": (
                "local Shell Link target path/size/timestamps -> a distinct resident PE; "
                "reference only, never execution"
            ),
        },
    }
    timestamp_roles = {
        **{
            name: (("artifact.file-created", timeline.file_created.unix_ns),)
            for name in resident
        },
        "Software.run.hive": (
            ("artifact.logical-updated", timeline.run_configured.unix_ns),
            ("registry.run-key-last-written", timeline.run_configured.unix_ns),
        ),
        "Amcache.hve": (
            ("artifact.logical-updated", timeline.amcache_observed.unix_ns),
            ("registry.inventory-key-last-written", timeline.amcache_observed.unix_ns),
        ),
        "History": (
            ("artifact.logical-updated", timeline.executed.unix_ns),
        ),
        WINDOWS_TASK_XML_SOURCE: (
            ("artifact.logical-updated", timeline.run_configured.unix_ns),
            ("task.definition-written", timeline.run_configured.unix_ns),
        ),
        WINDOWS_SHELL_LINK_SOURCE: (
            ("artifact.logical-updated", timeline.run_configured.unix_ns),
            ("shell-link.reference-written", timeline.run_configured.unix_ns),
        ),
        **{
            name: (
                ("artifact.logical-updated", timeline.prefetch_updated.unix_ns),
                ("prefetch.last-run", timeline.executed.unix_ns),
                ("prefetch.volume-created", timeline.host_initialized.unix_ns),
            )
            for name in pf_names
        },
    }
    return Scene("windows", scene_dir, artifacts, join, timestamp_roles)


def build_macos_scene(store: ContentStore, *, skey: bytes, profile: HostProfile,
                      scene_dir: str, staging_dir: str,
                      causal_clock: CausalClockSpec | None = None,
                      derivation: SceneDerivation = BENCHMARK_SCENE_DERIVATION) -> Scene:
    derivation = _scene_derivation(derivation)
    derivation.validate_key(skey)
    timeline = _causal_clock(skey, causal_clock).macos()
    support = f"{profile.home_dir}/Library/Application Support"

    # Five candidate apps. Two hold an allowed TCC grant; only one of those was ever used.
    bundles = derivation.pick_many(skey, "bundles", pools.BUNDLES, 3)
    benign = derivation.pick_many(skey, "benign-bundles", pools.BENIGN_BUNDLES, 2)
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
        derivation,
        skey,
        "macos-binary-generation",
        all_bundles,
        identity=lambda bundle: bundle,
    )
    for b in binary_order:
        c = store.materialize(
            f"macho:{b}:" + derivation.content_seed(skey, f"macho:{b}")
        )
        binaries[b] = c
        _write(staging_dir, b, c.bytes)

    # --- quarantine: five UUID relations with no name/order/agent shortcut ------------
    # Every sidecar carries a distinct UUID and every public-grade relation follows that
    # value into QuarantineEventsV2.  Bundle names do not occur in URLs, while agent and time
    # are deliberately equal across rows, leaving UUID equality as the only row selector.
    uuids, events = {}, []
    shared_agent = derivation.pick(skey, "quarantine-agent", pools.DOWNLOAD_AGENTS)
    shared_host = derivation.pick(skey, "quarantine-host", pools.DOWNLOAD_HOSTS)
    benchmark_relations = []
    for b in all_bundles:
        u = deterministic_uuid(derivation.content_seed(skey, f"quarantine:{b}"))
        opaque_download = derivation.content_seed(skey, f"quarantine-url:{b}")[:24]
        url = f"https://{shared_host}/downloads/{opaque_download}.dmg"
        uuids[b] = (u, shared_agent, url)
        events.append(
            (
                u,
                shared_agent,
                url,
                f"https://{shared_host}/downloads",
                timeline.downloaded.mac_seconds_real,
            )
        )
        xattr_relative_path = f"{b}.quarantine.xattr"
        _write(staging_dir, f"{b}.quarantine.xattr",
               quarantine_xattr(u, shared_agent, timeline.downloaded.unix_seconds).encode())
        benchmark_relations.append({
            "rule": MACOS_QUARANTINE_RULE,
            "selector": {"xattr_relative_path": xattr_relative_path},
            "expected": url,
            "candidate": b,
            "link_value": u,
        })
    events = _keyed_order(
        derivation,
        skey,
        "macos-quarantine-row",
        events,
        identity=lambda event: event[0],
    )
    _write(staging_dir, "QuarantineEventsV2", build_quarantine_events(events))

    # --- TCC: four clients, two allowed. Only one of those appears in knowledgeC -------
    tcc_rows = [
        (subject, derivation.pick(skey, "tcc-subject", pools.TCC_SERVICES), 2),
        (also_granted, derivation.pick(skey, "tcc-other", pools.TCC_SERVICES), 2),
        (benign[0], "kTCCServiceAppleEvents", 0),
        (persisted_only, "kTCCServiceCamera", 0),
    ]
    # TCC stores Unix time, not Mac absolute time — see build_tcc.
    _write(staging_dir, "TCC.db",
           build_tcc([
               (c, s, a, timeline.tcc_decided.unix_seconds)
               for c, s, a in tcc_rows
           ]))

    # --- knowledgeC: three apps actually used -----------------------------------------
    used = [subject, *benign]
    knowledge_intervals = tuple(
        timeline.knowledge_interval(index, count=len(used))
        for index in range(len(used))
    )
    knowledge_identity_seed = None
    if derivation != BENCHMARK_SCENE_DERIVATION:
        knowledge_identity_seed = bytes.fromhex(
            derivation.content_seed(skey, "knowledgec-row-identities")
        )
    _write(
        staging_dir,
        "knowledgeC.db",
        build_knowledgec(
            [
                (bundle, interval.start.mac_seconds_real, interval.end.mac_seconds_real)
                for bundle, interval in zip(used, knowledge_intervals, strict=True)
            ],
            identity_seed=knowledge_identity_seed,
        ),
    )

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
        derivation,
        skey,
        "macos-question",
        benchmark_relations,
        identity=lambda relation: relation["selector"]["xattr_relative_path"],
    )
    benchmark_candidates = _keyed_order(
        derivation,
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
        derivation,
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
    timestamp_roles = {
        **{
            bundle: (("artifact.logical-installed", timeline.installed.unix_ns),)
            for bundle in all_bundles
        },
        **{
            f"{bundle}.quarantine.xattr": (
                ("artifact.logical-updated", timeline.downloaded.unix_ns),
                ("quarantine.timestamp", timeline.downloaded.unix_ns),
            )
            for bundle in all_bundles
        },
        "QuarantineEventsV2": (
            ("artifact.logical-updated", timeline.downloaded.unix_ns),
            ("quarantine.event-timestamp", timeline.downloaded.unix_ns),
        ),
        "TCC.db": (
            ("artifact.logical-updated", timeline.tcc_decided.unix_ns),
            ("tcc.last-modified", timeline.tcc_decided.unix_ns),
        ),
        "knowledgeC.db": (
            ("artifact.logical-updated", timeline.knowledge_ended.unix_ns),
            *tuple(
                item
                for index, interval in enumerate(knowledge_intervals)
                for item in (
                    (f"knowledge.record-{index}.start", interval.start.unix_ns),
                    (f"knowledge.record-{index}.end", interval.end.unix_ns),
                )
            ),
        ),
        **{
            f"{bundle}.plist": (
                ("artifact.logical-updated", timeline.launch_agent_written.unix_ns),
            )
            for bundle in agents
        },
    }
    return Scene("macos", scene_dir, artifacts, join, timestamp_roles)


def build_linux_scene(store: ContentStore, *, skey: bytes, profile: HostProfile,
                      scene_dir: str, staging_dir: str,
                      causal_clock: CausalClockSpec | None = None,
                      derivation: SceneDerivation = BENCHMARK_SCENE_DERIVATION) -> Scene:
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
    derivation = _scene_derivation(derivation)
    derivation.validate_key(skey)
    timeline = _causal_clock(skey, causal_clock).linux()

    names = derivation.pick_many(skey, "linux-residents", pools.LINUX_EXECUTABLE_NAMES, 5)
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
        content = store.materialize(
            "elf:" + derivation.content_seed(skey, f"linux:{role}")
        )
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
        (timeline.history_marker.unix_seconds, ": 'ARTIFACTFORGE-SYNTHETIC-LINUX'"),
        (timeline.history_subject.unix_seconds, resident_by_role[history_roles[0]]["guest_path"]),
        (timeline.history_decoy_one.unix_seconds, resident_by_role[history_roles[1]]["guest_path"]),
        (timeline.history_decoy_two.unix_seconds, resident_by_role[history_roles[2]]["guest_path"]),
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
    timestamp_roles = {
        **{
            resident["served_relpath"]: (
                ("artifact.logical-installed", timeline.installed.unix_ns),
            )
            for resident in residents
        },
        **{
            record["served_relpath"]: (
                ("artifact.logical-updated", timeline.autostart_written.unix_ns),
            )
            for record in desktop_records
        },
        history_served: (
            ("artifact.logical-updated", timeline.history_decoy_two.unix_ns),
            ("bash-history.record-0", timeline.history_marker.unix_ns),
            ("bash-history.record-1", timeline.history_subject.unix_ns),
            ("bash-history.record-2", timeline.history_decoy_one.unix_ns),
            ("bash-history.record-3", timeline.history_decoy_two.unix_ns),
        ),
    }
    return Scene("linux", scene_dir, artifacts, join, timestamp_roles)
