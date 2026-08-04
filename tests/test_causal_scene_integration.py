# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Artifact bytes and scene metadata consume one exact causal clock."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import struct

import pytest

from artifactforge.artifacts.hive import (
    HiveTimestampSpec,
    build_amcache_hive,
    build_run_hive,
)
from artifactforge.artifacts.prefetch import PrefetchTimestamps, build_prefetch
from artifactforge.artifacts.shell_link import parse_shell_link
from artifactforge.compose.scene import (
    WINDOWS_SHELL_LINK_SOURCE,
    WINDOWS_TASK_XML_SOURCE,
    build_linux_scene,
    build_macos_scene,
    build_windows_scene,
)
from artifactforge.content import ContentStore
from artifactforge.disclosure import RESERVED_NAME
from artifactforge.fixture.causal import CausalClockSpec
from artifactforge.gates import validity
from artifactforge.gates.oracles import load_bash_history
from artifactforge.gates.oracles.prefetch_profile import parse_mam_prefetch_v30_variant1
from artifactforge.model import linux_profile, macos_profile, windows_profile


KEY = b"causal-scene-integration-key!!!!"
assert len(KEY) == 32
PREFETCH_PATH = r"\DEVICE\HARDDISKVOLUME1\WINDOWS\NOTEPAD.EXE"


def _query(path: Path, sql: str) -> tuple[tuple, ...]:
    connection = sqlite3.connect(path)
    try:
        return tuple(connection.execute(sql))
    finally:
        connection.close()


def _hive_views(path: Path):
    pytest.importorskip("regipy")
    pytest.importorskip("pyregf")
    regipy = validity._read_regipy(str(path))
    libregf = validity._read_libregf(str(path))
    assert regipy == libregf
    return libregf


def _child(key, name: str):
    matches = tuple(item for item in key.subkeys if item.name == name)
    assert len(matches) == 1
    return matches[0]


def _scene(root: Path, family: str, *, clock: CausalClockSpec | None):
    store = ContentStore("causal-scene-integration", str(root / "content"))
    builders = {
        "windows": (build_windows_scene, windows_profile()),
        "macos": (build_macos_scene, macos_profile()),
        "linux": (build_linux_scene, linux_profile()),
    }
    builder, profile = builders[family]
    return builder(
        store,
        skey=KEY,
        profile=profile,
        scene_dir=str(root / family / "scene"),
        staging_dir=str(root / family / "staging"),
        causal_clock=clock,
    )


def test_timestamp_optional_writer_defaults_preserve_frozen_bytes():
    vectors = (
        (
            build_run_hive([("Updater", r"C:\Updater.exe")]),
            "a0499d5a28c1b2d1c7a2ad8eeaf3d73428df116b8823af2c6bb38b66e63874a9",
        ),
        (
            build_amcache_hive([("a" * 40, r"c:\a.exe", "a.exe", 1)]),
            "382f74c319bca57a8093cb4e4a188e78188100593ba78f50b8548c87023e2ec6",
        ),
        (
            build_prefetch("notepad.exe", PREFETCH_PATH, 3),
            "21ad45c60485907f946877b4e275c971edff7c0892dea3292ebfa72efa76e51d",
        ),
    )
    assert [hashlib.sha256(data).hexdigest() for data, _digest in vectors] == [
        digest for _data, digest in vectors
    ]


def test_prefetch_typed_timestamps_are_exact_wire_filetimes():
    timeline = CausalClockSpec().windows()
    data = build_prefetch(
        "notepad.exe",
        PREFETCH_PATH,
        3,
        timestamps=PrefetchTimestamps(
            last_run_filetime=timeline.executed.filetime,
            volume_creation_filetime=timeline.host_initialized.filetime,
        ),
    )
    volumes_offset = struct.unpack_from("<I", data, 108)[0]
    assert struct.unpack_from("<Q", data, 120)[0] == timeline.executed.filetime
    assert struct.unpack_from("<Q", data, volumes_offset + 8)[0] == (
        timeline.host_initialized.filetime
    )
    assert timeline.host_initialized.filetime < timeline.executed.filetime


def test_hive_typed_per_key_timestamps_round_trip_both_consumers(tmp_path):
    timeline = CausalClockSpec().windows()
    run_time = timeline.run_configured.filetime
    data = build_run_hive(
        [("Updater", r"C:\Updater.exe")],
        timestamps=HiveTimestampSpec(
            hive_filetime=run_time,
            default_key_filetime=timeline.host_initialized.filetime,
            key_filetimes=(
                (f"ROOT\\{RESERVED_NAME}", run_time),
                (r"ROOT\Microsoft\Windows\CurrentVersion\Run", run_time),
            ),
        ),
    )
    path = tmp_path / "Software.run.hive"
    path.write_bytes(data)
    view = _hive_views(path)
    microsoft = _child(view.root, "Microsoft")
    windows = _child(microsoft, "Windows")
    current = _child(windows, "CurrentVersion")
    run = _child(current, "Run")
    marker = _child(view.root, RESERVED_NAME)
    assert {
        view.root.last_written_filetime,
        microsoft.last_written_filetime,
        windows.last_written_filetime,
        current.last_written_filetime,
    } == {timeline.host_initialized.filetime}
    assert run.last_written_filetime == marker.last_written_filetime == run_time


@pytest.mark.parametrize(
    "value",
    (True, -1, 1 << 64),
)
def test_typed_writer_timestamp_boundaries_reject_ambiguous_values(value):
    with pytest.raises(ValueError, match="FILETIME"):
        PrefetchTimestamps(last_run_filetime=value)
    with pytest.raises(ValueError, match="FILETIME"):
        HiveTimestampSpec(hive_filetime=value)


def test_hive_timestamp_override_must_name_an_emitted_key():
    with pytest.raises(ValueError, match="do not exist"):
        build_run_hive(
            [("Updater", r"C:\Updater.exe")],
            timestamps=HiveTimestampSpec(
                key_filetimes=((r"ROOT\Missing", 133_497_684_000_000_000),)
            ),
        )


def test_explicit_windows_clock_reaches_hives_prefetch_and_public_roles(tmp_path):
    clock = CausalClockSpec()
    timeline = clock.windows()
    scene = _scene(tmp_path, "windows", clock=clock)
    root = Path(scene.directory)

    software = _hive_views(root / "Software.run.hive")
    run = _child(
        _child(_child(_child(software.root, "Microsoft"), "Windows"), "CurrentVersion"),
        "Run",
    )
    amcache = _hive_views(root / "Amcache.hve")
    inventory = _child(_child(amcache.root, "Root"), "InventoryApplicationFile")
    assert run.last_written_filetime == timeline.run_configured.filetime
    assert {record.last_written_filetime for record in inventory.subkeys} == {
        timeline.amcache_observed.filetime
    }

    for path in root.glob("*.pf"):
        view = parse_mam_prefetch_v30_variant1(path.read_bytes())
        assert view.last_run_filetimes == (timeline.executed.filetime,) + (0,) * 7
        assert view.volume_creation_filetime == timeline.host_initialized.filetime
        roles = dict(scene.timestamp_roles[path.name])
        assert roles["prefetch.last-run"] == timeline.executed.unix_ns
        assert roles["artifact.logical-updated"] == timeline.prefetch_updated.unix_ns

    shell = parse_shell_link((root / WINDOWS_SHELL_LINK_SOURCE).read_bytes())
    assert (
        shell.creation_filetime,
        shell.access_filetime,
        shell.write_filetime,
    ) == (
        timeline.file_created.filetime,
        timeline.executed.filetime,
        timeline.file_created.filetime,
    )
    assert dict(scene.timestamp_roles[WINDOWS_TASK_XML_SOURCE]) == {
        "artifact.logical-updated": timeline.run_configured.unix_ns,
        "task.definition-written": timeline.run_configured.unix_ns,
    }
    assert dict(scene.timestamp_roles[WINDOWS_SHELL_LINK_SOURCE]) == {
        "artifact.logical-updated": timeline.run_configured.unix_ns,
        "shell-link.reference-written": timeline.run_configured.unix_ns,
    }

    assert set(scene.timestamp_roles) == set(scene.artifacts)
    assert timeline.file_created < timeline.run_configured < timeline.executed
    assert timeline.executed < timeline.prefetch_updated < timeline.amcache_observed


def test_explicit_macos_clock_reaches_every_embedded_time_domain(tmp_path):
    clock = CausalClockSpec()
    timeline = clock.macos()
    scene = _scene(tmp_path, "macos", clock=clock)
    root = Path(scene.directory)

    quarantine_times = _query(
        root / "QuarantineEventsV2",
        "SELECT LSQuarantineTimeStamp FROM LSQuarantineEvent ORDER BY rowid",
    )
    assert {row[0] for row in quarantine_times} == {timeline.downloaded.mac_seconds_real}
    for path in root.glob("*.quarantine.xattr"):
        fields = path.read_text(encoding="ascii").split(";")
        assert fields[1] == timeline.downloaded.quarantine_hex_seconds

    assert _query(root / "TCC.db", "SELECT DISTINCT last_modified FROM access") == (
        (timeline.tcc_decided.unix_seconds,),
    )
    intervals = tuple(timeline.knowledge_interval(index, count=3) for index in range(3))
    assert _query(
        root / "knowledgeC.db",
        "SELECT ZSTARTDATE, ZENDDATE FROM ZOBJECT ORDER BY Z_PK",
    ) == tuple(
        (interval.start.mac_seconds_real, interval.end.mac_seconds_real)
        for interval in intervals
    )
    assert set(scene.timestamp_roles) == set(scene.artifacts)
    assert timeline.downloaded < timeline.installed < timeline.tcc_decided
    assert timeline.tcc_decided < timeline.launch_agent_written < timeline.knowledge_started


def test_explicit_linux_clock_reaches_all_history_records(tmp_path):
    clock = CausalClockSpec()
    timeline = clock.linux()
    scene = _scene(tmp_path, "linux", clock=clock)
    history_path = Path(scene.directory) / scene.join["bash_history"]["served_relpath"]
    records = load_bash_history(
        history_path,
        resident_paths=tuple(item["guest_path"] for item in scene.join["residents"]),
    )
    assert tuple(record.epoch for record in records) == (
        timeline.history_marker.unix_seconds,
        timeline.history_subject.unix_seconds,
        timeline.history_decoy_one.unix_seconds,
        timeline.history_decoy_two.unix_seconds,
    )
    assert set(scene.timestamp_roles) == set(scene.artifacts)
    assert timeline.installed < timeline.autostart_written < timeline.history_marker


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_default_scene_clock_is_the_seed_derived_clock(tmp_path, family):
    implicit = _scene(tmp_path / "implicit", family, clock=None)
    explicit = _scene(
        tmp_path / "explicit",
        family,
        clock=CausalClockSpec.from_seed_hex(KEY.hex()),
    )
    assert implicit.timestamp_roles == explicit.timestamp_roles
    assert implicit.artifacts == explicit.artifacts
    for name in implicit.artifacts:
        assert (Path(implicit.directory) / name).read_bytes() == (
            Path(explicit.directory) / name
        ).read_bytes()


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_public_timestamp_roles_are_complete_and_answer_free(tmp_path, family):
    scene = _scene(tmp_path, family, clock=CausalClockSpec())
    assert set(scene.timestamp_roles) == set(scene.artifacts)
    forbidden = {"answer", "decoy", "join", "persisted", "subject"}
    assert not {
        token
        for records in scene.timestamp_roles.values()
        for role, _unix_ns in records
        for token in role.split(".")
        if token in forbidden
    }


def test_parser_valid_prefetch_temporal_inversion_turns_gate_red(tmp_path):
    pytest.importorskip("windowsprefetch")
    pytest.importorskip("pyscca")
    timeline = CausalClockSpec().windows()
    name = "NOTEPAD.EXE-189578DA.pf"
    path = tmp_path / name
    path.write_bytes(
        build_prefetch(
            "notepad.exe",
            PREFETCH_PATH,
            3,
            timestamps=PrefetchTimestamps(
                last_run_filetime=timeline.executed.filetime,
                volume_creation_filetime=timeline.host_initialized.filetime,
            ),
        )
    )
    assert validity.run(str(tmp_path)).ok

    path.write_bytes(
        build_prefetch(
            "notepad.exe",
            PREFETCH_PATH,
            3,
            timestamps=PrefetchTimestamps(
                last_run_filetime=timeline.host_initialized.filetime,
                volume_creation_filetime=timeline.executed.filetime,
            ),
        )
    )
    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any("volume creation must precede" in failure for failure in report.fails)


@pytest.mark.parametrize("profile", ("software", "amcache"))
def test_parser_valid_hive_temporal_inversion_turns_gate_red(tmp_path, profile):
    pytest.importorskip("regipy")
    pytest.importorskip("pyregf")
    timeline = CausalClockSpec().windows()
    early = timeline.host_initialized.filetime
    late = timeline.amcache_observed.filetime
    if profile == "software":
        path = tmp_path / "Software.run.hive"
        valid = HiveTimestampSpec(
            hive_filetime=late,
            default_key_filetime=early,
            key_filetimes=(
                (f"ROOT\\{RESERVED_NAME}", late),
                (r"ROOT\Microsoft\Windows\CurrentVersion\Run", late),
            ),
        )
        inverted = HiveTimestampSpec(
            hive_filetime=late,
            default_key_filetime=late,
            key_filetimes=(
                (f"ROOT\\{RESERVED_NAME}", early),
                (r"ROOT\Microsoft\Windows\CurrentVersion\Run", early),
            ),
        )
        builder = lambda timestamps: build_run_hive(  # noqa: E731
            [("Updater", r"C:\Updater.exe")], timestamps=timestamps
        )
        expected = "Run configuration after its ancestors"
    else:
        path = tmp_path / "Amcache.hve"
        record = "0000000000000001"
        valid = HiveTimestampSpec(
            hive_filetime=late,
            default_key_filetime=early,
            key_filetimes=(
                (f"amcache\\{RESERVED_NAME}", late),
                (f"amcache\\Root\\InventoryApplicationFile\\{record}", late),
            ),
        )
        inverted = HiveTimestampSpec(
            hive_filetime=late,
            default_key_filetime=late,
            key_filetimes=(
                (f"amcache\\{RESERVED_NAME}", early),
                (f"amcache\\Root\\InventoryApplicationFile\\{record}", early),
            ),
        )
        builder = lambda timestamps: build_amcache_hive(  # noqa: E731
            [("a" * 40, r"c:\a.exe", "a.exe", 1, record)],
            timestamps=timestamps,
        )
        expected = "inventory observations after ancestors"

    path.write_bytes(builder(valid))
    assert validity.run(str(tmp_path)).ok
    path.write_bytes(builder(inverted))
    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any(expected in failure for failure in report.fails)
