# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Runtime and boundary tests for the loose-Scene to Fixture ABI v2 projection."""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from artifactforge.artifacts.macos import parse_quarantine_xattr
from artifactforge.artifacts.shell_link import parse_shell_link
from artifactforge.artifacts.windows_task import validate_scheduled_task_xml
from artifactforge.artifacts.zone_identifier import parse_zone_identifier
from artifactforge.compose.fixture_scene_v2 import (
    LINUX_LOGICAL_GID_V2,
    LINUX_LOGICAL_UID_V2,
    MACOS_LOGICAL_GID_V2,
    MACOS_LOGICAL_UID_V2,
    MACOS_QUARANTINE_XATTR_V2,
    WINDOWS_LOGICAL_OWNER_SID_V2,
    WINDOWS_ZONE_STREAM_V2,
    FixtureSceneProjectionError,
    project_fixture_scene_v2,
)
from artifactforge.compose.scene import (
    WINDOWS_SHELL_LINK_SOURCE,
    WINDOWS_TASK_XML_SOURCE,
    Scene,
    build_linux_scene,
    build_macos_scene,
    build_windows_scene,
)
from artifactforge.content import ContentStore
from artifactforge.fixture.canonical import canonical_json_bytes
from artifactforge.fixture.model_v2 import (
    FixturePayloadV2,
    FixtureSpecV2,
    LinuxMetadataV2,
    MacOSMetadataV2,
    ProfileSpecV2,
    WindowsMetadataV2,
)
from artifactforge.inventory import inventory_regular_files
from artifactforge.model import linux_profile, macos_profile, windows_profile


SEED_HEX = "41" * 32
PROFILE_IDS = {
    "windows": "windows-loose-v2",
    "macos": "macos-14-loose-v2",
    "linux": "linux-glibc-x86_64-loose-v2",
}
BUILDERS = {
    "windows": (build_windows_scene, windows_profile),
    "macos": (build_macos_scene, macos_profile),
    "linux": (build_linux_scene, linux_profile),
}


_STORY_IDS = {
    "windows": "windows-dropper-v1",
    "macos": "macos-quarantined-app-v1",
    "linux": "linux-autostart-v1",
}


def _case(root: Path, family: str):
    builder, profile_factory = BUILDERS[family]
    host = profile_factory()
    spec = FixtureSpecV2.create(
        fixture_id=f"projection-{family}",
        family=family,
        story=_STORY_IDS[family],
        profile=ProfileSpecV2(
            id=PROFILE_IDS[family],
            hostname=host.hostname,
            username=host.username,
        ),
        seed_hex=SEED_HEX,
    )
    scene = builder(
        ContentStore("fixture-scene-v2-tests", str(root / "content")),
        skey=bytes.fromhex(SEED_HEX),
        profile=host,
        scene_dir=str(root / "scene"),
        staging_dir=str(root / "staging"),
        causal_clock=spec.causal_clock,
    )
    loose = {
        item.relative_path: item.data
        for item in inventory_regular_files(scene.directory, capture_bytes=True)
    }
    plan = project_fixture_scene_v2(spec=spec, scene=scene, loose_files=loose)
    return spec, scene, loose, plan


def _required_parents(served_paths: set[str]) -> set[str]:
    return {
        "/".join(parts[:index])
        for path in served_paths
        for parts in (path.split("/"),)
        for index in range(1, len(parts))
    }


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_runtime_projection_is_canonical_complete_and_preserves_carrier_bytes(tmp_path, family):
    _spec, _scene, loose, plan = _case(tmp_path, family)
    payload = FixturePayloadV2.create(
        family=family,
        directories=plan.directories,
        files=plan.file_nodes,
    )

    assert plan.file_nodes == payload.files
    assert plan.directories == payload.directories
    assert [item.node.served_path for item in plan.files] == sorted(
        item.node.served_path for item in plan.files
    )
    assert [item.served_path for item in plan.directories] == sorted(
        item.served_path for item in plan.directories
    )
    assert {item.served_path for item in plan.directories} == _required_parents(
        {item.node.served_path for item in plan.files}
    )

    consumed = {
        name for name in loose if family == "macos" and name.endswith(".quarantine.xattr")
    }
    assert Counter(item.default_bytes for item in plan.files) == Counter(
        data for name, data in loose.items() if name not in consumed
    )
    assert dict(plan.default_files) == {
        item.node.served_path: item.default_bytes for item in plan.files
    }
    expected_metadata_blobs = {"windows": 1, "macos": 5, "linux": 0}
    assert payload.metadata_blob_count == expected_metadata_blobs[family]


def test_windows_projection_maps_paths_and_correlates_browser_history_to_motw(tmp_path):
    spec, scene, loose, plan = _case(tmp_path, "windows")
    timeline = spec.causal_clock.windows()
    files = {item.node.guest_path: item for item in plan.files}
    resident_paths = {claim["path"] for claim in scene.join["residents"]}
    expected = {
        *resident_paths,
        r"C:\Windows\System32\config\SOFTWARE",
        r"C:\Windows\AppCompat\Programs\Amcache.hve",
        rf"C:\Users\{spec.profile.username}\AppData\Local\Chromium\User Data\Default\History",
        scene.join["scheduled_task"]["guest_path"],
        scene.join["shell_link"]["guest_path"],
        *(rf"C:\Windows\Prefetch\{name}" for name in loose if name.endswith(".pf")),
    }
    assert set(files) == expected
    assert all(":" not in item.node.served_path for item in plan.files)

    residents = [item for item in plan.files if item.default_bytes.startswith(b"MZ")]
    assert len(residents) == 5
    structural_metadata = {
        (
            item.node.metadata.owner_sid,
            item.node.metadata.attributes,
            item.node.metadata.creation_unix_ns,
            item.node.metadata.access_unix_ns,
            item.node.metadata.write_unix_ns,
            item.node.metadata.change_unix_ns,
        )
        for item in residents
        if isinstance(item.node.metadata, WindowsMetadataV2)
    }
    assert len(structural_metadata) == 1
    for item in residents:
        metadata = item.node.metadata
        assert isinstance(metadata, WindowsMetadataV2)
        assert metadata.owner_sid == WINDOWS_LOGICAL_OWNER_SID_V2
        assert metadata.attributes == ("ARCHIVE",)
        assert (
            metadata.creation_unix_ns,
            metadata.access_unix_ns,
            metadata.write_unix_ns,
            metadata.change_unix_ns,
        ) == (
            timeline.file_created.unix_ns,
            timeline.executed.unix_ns,
            timeline.file_created.unix_ns,
            timeline.file_created.unix_ns,
        )
    streamed = [item for item in residents if item.node.metadata.streams]
    assert len(streamed) == 1
    downloaded = scene.join["browser_download"]
    assert streamed[0].node.guest_path == downloaded["target_path"]
    [stream] = streamed[0].node.metadata.streams
    assert stream.name == WINDOWS_ZONE_STREAM_V2
    parsed = parse_zone_identifier(stream.data)
    assert parsed.host_url == downloaded["source_url"]
    assert parsed.referrer_url == downloaded["referrer_url"]
    assert b"ARTIFACTFORGE" in stream.data

    task_truth = scene.join["scheduled_task"]
    shell_truth = scene.join["shell_link"]
    task_item = files[task_truth["guest_path"]]
    shell_item = files[shell_truth["guest_path"]]
    task = validate_scheduled_task_xml(
        task_item.default_bytes,
        resident_pe_paths=(task_truth["target_path"],),
    )
    shell = parse_shell_link(shell_item.default_bytes)
    assert task_item.node.served_path.endswith("/" + task_truth["task_name"])
    assert not task_item.node.guest_path.endswith(".xml")
    assert task.command == task_truth["target_path"]
    assert shell_item.node.guest_path.endswith("\\" + WINDOWS_SHELL_LINK_SOURCE)
    assert shell.target_path == shell_truth["target_path"]
    assert task.command != shell.target_path
    assert task.command != downloaded["target_path"]
    assert shell.target_path != downloaded["target_path"]
    assert files[task.command].default_bytes.startswith(b"MZ")
    shell_target = files[shell.target_path]
    assert shell_target.default_bytes.startswith(b"MZ")
    assert shell.target_size == len(shell_target.default_bytes)
    assert (
        shell.creation_filetime,
        shell.access_filetime,
        shell.write_filetime,
    ) == (
        timeline.file_created.filetime,
        timeline.executed.filetime,
        timeline.file_created.filetime,
    )
    for item, source_role in (
        (task_item, "task.definition-written"),
        (shell_item, "shell-link.reference-written"),
    ):
        assert isinstance(item.node.metadata, WindowsMetadataV2)
        assert (
            item.node.metadata.creation_unix_ns,
            item.node.metadata.access_unix_ns,
            item.node.metadata.write_unix_ns,
            item.node.metadata.change_unix_ns,
        ) == (timeline.run_configured.unix_ns,) * 4
        assert dict(scene.timestamp_roles[
            WINDOWS_TASK_XML_SOURCE
            if item is task_item
            else WINDOWS_SHELL_LINK_SOURCE
        ]) == {
            "artifact.logical-updated": timeline.run_configured.unix_ns,
            source_role: timeline.run_configured.unix_ns,
        }

    directory_metadata = {item.metadata for item in plan.directories}
    assert len(directory_metadata) == 1
    [metadata] = directory_metadata
    assert isinstance(metadata, WindowsMetadataV2)
    assert metadata.attributes == ("DIRECTORY",)
    assert metadata.creation_unix_ns == timeline.host_initialized.unix_ns


def test_macos_projection_maps_paths_and_consumes_sidecars_as_exact_xattrs(tmp_path):
    spec, _scene, loose, plan = _case(tmp_path, "macos")
    timeline = spec.causal_clock.macos()
    username = spec.profile.username
    binaries = {
        name for name, data in loose.items() if data.startswith(b"\xcf\xfa\xed\xfe")
    }
    expected_binary_paths = {
        f"/Users/{username}/Library/Application Support/{bundle}/"
        f"{bundle.rsplit('.', 1)[-1]}"
        for bundle in binaries
    }
    files = {item.node.guest_path: item for item in plan.files}
    assert expected_binary_paths <= set(files)
    assert not any(
        item.node.guest_path.endswith(".quarantine.xattr") for item in plan.files
    )
    assert not any(":" in item.node.served_path for item in plan.files)

    for bundle, guest_path in zip(sorted(binaries), sorted(expected_binary_paths), strict=True):
        item = files[guest_path]
        metadata = item.node.metadata
        assert isinstance(metadata, MacOSMetadataV2)
        assert (metadata.uid, metadata.gid, metadata.mode) == (
            MACOS_LOGICAL_UID_V2,
            MACOS_LOGICAL_GID_V2,
            0o755,
        )
        assert metadata.birthtime_unix_ns == timeline.downloaded.unix_ns
        assert metadata.mtime_unix_ns == timeline.installed.unix_ns
        assert len(metadata.xattrs) == 1
        assert metadata.xattrs[0].name == MACOS_QUARANTINE_XATTR_V2
        assert metadata.xattrs[0].data == loose[f"{bundle}.quarantine.xattr"]
        parse_quarantine_xattr(metadata.xattrs[0].data)

    assert files["/private/var/db/CoreDuet/Knowledge/knowledgeC.db"].node.metadata.mode == 0o644
    launch_agents = [
        item for item in plan.files if "/Library/LaunchAgents/" in item.node.guest_path
    ]
    assert len(launch_agents) == 3
    assert {item.node.metadata.mtime_unix_ns for item in launch_agents} == {
        timeline.launch_agent_written.unix_ns
    }
    assert {
        (item.metadata.uid, item.metadata.gid, item.metadata.mode)
        for item in plan.directories
        if isinstance(item.metadata, MacOSMetadataV2)
    } == {(MACOS_LOGICAL_UID_V2, MACOS_LOGICAL_GID_V2, 0o755)}


def test_linux_projection_preserves_existing_guest_paths_and_closed_modes(tmp_path):
    spec, _scene, loose, plan = _case(tmp_path, "linux")
    timeline = spec.causal_clock.linux()
    assert {item.node.guest_path for item in plan.files} == {"/" + path for path in loose}
    for item in plan.files:
        metadata = item.node.metadata
        assert isinstance(metadata, LinuxMetadataV2)
        assert (metadata.uid, metadata.gid) == (LINUX_LOGICAL_UID_V2, LINUX_LOGICAL_GID_V2)
        if item.default_bytes.startswith(b"\x7fELF"):
            expected = (0o755, timeline.installed.unix_ns)
        elif item.node.guest_path.endswith(".desktop"):
            expected = (0o644, timeline.autostart_written.unix_ns)
        else:
            assert item.node.guest_path.endswith("/.bash_history")
            expected = (0o600, timeline.history_decoy_two.unix_ns)
        assert (metadata.mode, metadata.mtime_unix_ns) == expected
    assert {
        (item.metadata.uid, item.metadata.gid, item.metadata.mode)
        for item in plan.directories
        if isinstance(item.metadata, LinuxMetadataV2)
    } == {(LINUX_LOGICAL_UID_V2, LINUX_LOGICAL_GID_V2, 0o755)}


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_serialized_nodes_are_deterministic_immutable_and_answer_free(tmp_path, family):
    spec, scene, loose, plan = _case(tmp_path, family)
    serialized = canonical_json_bytes(plan.nodes_mapping())
    forbidden = (b'"answer"', b'"candidate"', b'"decoy"', b'"join"', b'"persisted"', b'"subject"')
    assert not any(token in serialized.lower() for token in forbidden)
    assert project_fixture_scene_v2(spec=spec, scene=scene, loose_files=dict(reversed(loose.items()))) == plan
    with pytest.raises(AttributeError):
        plan.family = "changed"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        plan.files[0].default_bytes = b"changed"  # type: ignore[misc]


def test_projection_rejects_inexact_inventory_profile_clock_and_resident_truth(tmp_path):
    spec, scene, loose, _plan = _case(tmp_path, "windows")
    first = next(iter(loose))
    with pytest.raises(FixtureSceneProjectionError, match="missing"):
        project_fixture_scene_v2(
            spec=spec,
            scene=scene,
            loose_files={name: data for name, data in loose.items() if name != first},
        )
    with pytest.raises(FixtureSceneProjectionError, match="extra"):
        project_fixture_scene_v2(
            spec=spec, scene=scene, loose_files={**loose, "unexpected.bin": b"not evidence"}
        )
    bad_bytes = dict(loose)
    bad_bytes[first] = bytearray(bad_bytes[first])  # type: ignore[assignment]
    with pytest.raises(FixtureSceneProjectionError, match="exact bytes"):
        project_fixture_scene_v2(spec=spec, scene=scene, loose_files=bad_bytes)  # type: ignore[arg-type]

    other_spec = FixtureSpecV2.create(
        fixture_id=spec.fixture_id,
        family=spec.family,
        story=_STORY_IDS[spec.family],
        profile=spec.profile,
        seed_hex="42" * 32,
    )
    with pytest.raises(FixtureSceneProjectionError, match="causal clock"):
        project_fixture_scene_v2(spec=other_spec, scene=scene, loose_files=loose)

    wrong_profile = replace(
        scene,
        join={**scene.join, "user": "different-user"},
    )
    with pytest.raises(FixtureSceneProjectionError, match="username"):
        project_fixture_scene_v2(spec=spec, scene=wrong_profile, loose_files=loose)

    missing_truth = replace(scene, join={**scene.join, "residents": []})
    with pytest.raises(FixtureSceneProjectionError, match="resident path truth"):
        project_fixture_scene_v2(spec=spec, scene=missing_truth, loose_files=loose)

    stale_task = replace(
        scene,
        join={
            **scene.join,
            "scheduled_task": {
                **scene.join["scheduled_task"],
                "target_size": scene.join["scheduled_task"]["target_size"] + 1,
            },
        },
    )
    with pytest.raises(FixtureSceneProjectionError, match="scheduled task byte identity"):
        project_fixture_scene_v2(spec=spec, scene=stale_task, loose_files=loose)

    stale_shell_time = replace(
        scene,
        join={
            **scene.join,
            "shell_link": {
                **scene.join["shell_link"],
                "access_filetime": scene.join["shell_link"]["access_filetime"] + 1,
            },
        },
    )
    with pytest.raises(FixtureSceneProjectionError, match="causal clock"):
        project_fixture_scene_v2(spec=spec, scene=stale_shell_time, loose_files=loose)


def test_macos_projection_requires_one_valid_sidecar_per_binary(tmp_path):
    spec, scene, loose, _plan = _case(tmp_path, "macos")
    sidecar = next(name for name in loose if name.endswith(".quarantine.xattr"))
    reduced_loose = {name: data for name, data in loose.items() if name != sidecar}
    reduced_scene = Scene(
        family=scene.family,
        directory=scene.directory,
        artifacts=sorted(reduced_loose),
        join=scene.join,
        timestamp_roles={
            name: records for name, records in scene.timestamp_roles.items() if name != sidecar
        },
    )
    with pytest.raises(FixtureSceneProjectionError, match="do not match binaries"):
        project_fixture_scene_v2(spec=spec, scene=reduced_scene, loose_files=reduced_loose)

    malformed = dict(loose)
    malformed[sidecar] = b"not-a-quarantine-value"
    with pytest.raises(FixtureSceneProjectionError, match="malformed"):
        project_fixture_scene_v2(spec=spec, scene=scene, loose_files=malformed)
