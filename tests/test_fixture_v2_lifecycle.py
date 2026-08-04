# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""End-to-end contracts for Fixture ABI v2 publication and reproduction."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import stat

import pytest

from artifactforge.artifacts.sqlite_owned import ColumnSpec, TableSpec, build_sqlite
from artifactforge.artifacts.shell_link import (
    ShellLinkTimestamps,
    build_shell_link,
    parse_shell_link,
)
from artifactforge.artifacts.windows_task import (
    build_scheduled_task_xml,
    parse_scheduled_task_xml,
)
from artifactforge.artifacts.zone_identifier import (
    build_zone_identifier,
    parse_zone_identifier,
)
from artifactforge.fixture.model import FixtureSpec, ProfileSpec
from artifactforge.fixture.model_v2 import (
    FileNodeV2,
    FixtureManifestV2,
    FixturePayloadV2,
    FixtureSpecV2,
    LinuxMetadataV2,
    NamedBlobV2,
    ProfileSpecV2,
    WindowsMetadataV2,
)
from artifactforge.fixture.operations import (
    FixtureUsageError,
    build_fixture,
    inspect_fixture,
    verify_fixture,
)
from artifactforge.gates import validity
from artifactforge.gates.oracles import SQLiteWireProfile, loads_sqlite


PROFILE_IDS = {
    "windows": "windows-loose-v2",
    "macos": "macos-14-loose-v2",
    "linux": "linux-glibc-x86_64-loose-v2",
}
HOSTNAMES = {
    "windows": "WKSTN-01",
    "macos": "mac-01",
    "linux": "linux-01",
}
SEEDS = {
    "windows": "11" * 32,
    "macos": "22" * 32,
    "linux": "33" * 32,
}


def _spec(family: str) -> FixtureSpecV2:
    return FixtureSpecV2.create(
        fixture_id=f"lifecycle-{family}",
        family=family,
        profile=ProfileSpecV2(
            id=PROFILE_IDS[family],
            hostname=HOSTNAMES[family],
            username="v",
        ),
        seed_hex=SEEDS[family],
    )


def _tree_bytes(root: Path) -> tuple[tuple[str, bytes], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _replace_v2_files(root: Path, manifest: FixtureManifestV2, files) -> FixtureManifestV2:
    payload = FixturePayloadV2.create(
        family=manifest.recipe.family,
        directories=manifest.payload.directories,
        files=files,
    )
    altered = FixtureManifestV2.create(
        generator_version=manifest.generator.version,
        recipe=manifest.recipe,
        payload=payload,
    )
    (root / "fixture.json").write_bytes(altered.canonical_bytes())
    return altered


def _windows_zone_node(manifest: FixtureManifestV2):
    matches = [
        (node, blob)
        for node in manifest.payload.files
        if type(node.metadata) is WindowsMetadataV2
        for blob in node.metadata.streams
        if blob.name == "Zone.Identifier"
    ]
    assert len(matches) == 1
    return matches[0]


def _windows_reference_nodes(manifest: FixtureManifestV2):
    tasks = [
        node
        for node in manifest.payload.files
        if node.guest_path.startswith(
            "C:\\Windows\\System32\\Tasks\\ArtifactForge\\"
        )
    ]
    links = [
        node
        for node in manifest.payload.files
        if node.guest_path.endswith(
            "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\"
            "ArtifactForgeMaintenance.lnk"
        )
    ]
    assert len(tasks) == len(links) == 1
    return tasks[0], links[0]


def _mutate_owned_history(data: bytes, *, target_path: str, mutation: str) -> bytes:
    database = loads_sqlite(
        data,
        wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
    )
    tables = []
    target_id = None
    for table in database.tables:
        columns = tuple(
            ColumnSpec(column.name, column.declared_type, column.primary_key)
            for column in table.columns
        )
        positions = {column.name: index for index, column in enumerate(table.columns)}
        rows = [list(row.values) for row in table.rows]
        if table.name == "downloads":
            for row in rows:
                if row[positions["target_path"]] != target_path:
                    continue
                target_id = row[positions["id"]]
                if mutation == "target":
                    replacement = r"C:\Users\v\AppData\Local\Temp\renamed.exe"
                    row[positions["current_path"]] = replacement
                    row[positions["target_path"]] = replacement
                elif mutation == "size":
                    row[positions["received_bytes"]] += 1
                    row[positions["total_bytes"]] += 1
                break
        elif table.name == "downloads_url_chains":
            for row in rows:
                if row[positions["id"]] != target_id:
                    continue
                source = row[positions["url"]]
                if mutation == "target":
                    row[positions["url"]] = source.rsplit("/", 1)[0] + "/renamed.exe"
                elif mutation == "digest":
                    components = source.split("/")
                    components[components.index("sha256") + 1] = "0" * 64
                    row[positions["url"]] = "/".join(components)
                break
        tables.append(TableSpec(table.name, columns, tuple(tuple(row) for row in rows)))
    assert target_id is not None
    return build_sqlite(tuple(tables))


def _assert_fixed_carrier(root: Path) -> None:
    assert not root.is_symlink()
    assert sorted(path.name for path in root.iterdir()) == ["artifacts", "fixture.json"]
    artifacts = root / "artifacts"

    if os.name != "nt":
        assert stat.S_IMODE(root.lstat().st_mode) == 0o700
        assert stat.S_IMODE(artifacts.lstat().st_mode) == 0o700
        assert stat.S_IMODE((root / "fixture.json").lstat().st_mode) == 0o600

    # Incidental host xattrs/ADS are not logical guest metadata and are outside the raw
    # carrier-integrity claim. Canonical release copies only these default streams.
    for path in (root, *sorted(root.rglob("*"))):
        assert not path.is_symlink()

    for path in sorted(artifacts.rglob("*")):
        relative = path.relative_to(artifacts).as_posix()
        assert ":" not in relative
        assert not relative.endswith(".quarantine.xattr")
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_dir():
            if os.name != "nt":
                assert mode == 0o700
        else:
            assert path.is_file()
            if os.name != "nt":
                assert mode == 0o600
                assert mode & 0o111 == 0


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_v2_build_verify_assurance_and_integrity_only_inspection(tmp_path, family):
    root = tmp_path / family
    manifest = build_fixture(_spec(family), root)

    assert type(manifest) is FixtureManifestV2
    assert (root / "fixture.json").read_bytes() == manifest.canonical_bytes()
    assert sorted(path.name for path in tmp_path.iterdir()) == [family]
    assert b'"join"' not in manifest.canonical_bytes().lower()
    assert b'"answers"' not in manifest.canonical_bytes().lower()
    _assert_fixed_carrier(root)

    verified = verify_fixture(root, assurance=True)
    assert verified.ok
    assert verified.manifest == manifest
    assert verified.integrity_ok
    assert verified.reproduction_requested
    assert verified.reproduction_ok is True
    assert verified.assurance_ok is True
    assert [report.gate for report in verified.assurance_reports] == [1, 3]

    inspected = inspect_fixture(root)
    assert inspected.ok
    assert inspected.manifest == manifest
    assert inspected.integrity_ok
    assert inspected.reproduction_requested is False
    assert inspected.reproduction_ok is None
    assert inspected.assurance_ok is None
    assert inspected.assurance_summary == {
        "requested": False,
        "verdict": "not-run",
        "gates": [],
    }


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_v2_same_recipe_repeats_every_public_byte_exactly(tmp_path, family):
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_manifest = build_fixture(_spec(family), first)
    second_manifest = build_fixture(_spec(family), second)

    assert first_manifest == second_manifest
    assert first_manifest.canonical_bytes() == second_manifest.canonical_bytes()
    assert _tree_bytes(first) == _tree_bytes(second)


def test_v2_generator_version_is_provenance_not_a_compatibility_gate(tmp_path):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec("linux"), root)
    foreign_version = replace(
        manifest,
        generator=replace(manifest.generator, version="999.0.provenance-only"),
    )
    (root / "fixture.json").write_bytes(foreign_version.canonical_bytes())

    result = verify_fixture(root)

    assert result.ok
    assert result.manifest == foreign_version
    assert result.integrity_ok
    assert result.reproduction_ok is True


def test_v2_reproduction_catches_rehashed_logical_metadata_mutation(tmp_path):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec("linux"), root)
    original = manifest.payload.files[0]
    assert type(original.metadata) is LinuxMetadataV2
    changed = replace(
        original,
        metadata=replace(original.metadata, uid=original.metadata.uid + 1),
    )
    files = (changed, *manifest.payload.files[1:])
    payload = FixturePayloadV2.create(
        family=manifest.recipe.family,
        directories=manifest.payload.directories,
        files=files,
    )
    mutated = FixtureManifestV2.create(
        generator_version=manifest.generator.version,
        recipe=manifest.recipe,
        payload=payload,
    )
    (root / "fixture.json").write_bytes(mutated.canonical_bytes())

    result = verify_fixture(root)

    assert not result.ok
    assert result.integrity_ok
    assert result.integrity_failures == ()
    assert result.reproduction_ok is False
    assert result.reproduction_failures == (
        "recipe reproduction does not reproduce the complete logical fixture manifest",
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX umask and carrier-mode contract")
def test_v2_publication_and_reproduction_are_exact_under_hostile_umask(tmp_path):
    root = tmp_path / "fixture"
    previous_umask = os.umask(0o777)
    try:
        manifest = build_fixture(_spec("linux"), root)
        verified = verify_fixture(root)
    finally:
        os.umask(previous_umask)

    assert verified.ok
    assert verified.manifest == manifest
    _assert_fixed_carrier(root)


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_v2_build_never_projects_logical_metadata_through_host_syscalls(
    tmp_path, monkeypatch, family
):
    calls: list[str] = []

    def forbidden(*_args, **_kwargs):
        calls.append("called")
        raise AssertionError("logical metadata must remain in the v2 manifest")

    for name in ("setxattr", "chown", "lchown", "fchown", "utime"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden)

    root = tmp_path / "fixture"
    build_fixture(_spec(family), root)

    assert calls == []
    _assert_fixed_carrier(root)


def test_v2_macos_logical_xattrs_run_both_gate1_readers_and_semantics(
    tmp_path, monkeypatch
):
    observed: list[tuple[str, bytes]] = []
    originals = {
        name: validity.READERS[name]
        for name in ("macos-xattr", "quarantine-xattr-raw")
    }

    def recording(name):
        def read(source):
            assert type(source) is bytes
            observed.append((name, source))
            return originals[name](source)

        return read

    for name in originals:
        monkeypatch.setitem(validity.READERS, name, recording(name))

    root = tmp_path / "macos"
    build_fixture(_spec("macos"), root)
    result = verify_fixture(root, assurance=True)

    assert result.ok, result.failures
    assert len(observed) == 10
    for standard, raw in zip(observed[::2], observed[1::2], strict=True):
        assert (standard[0], raw[0]) == ("macos-xattr", "quarantine-xattr-raw")
        assert standard[1] is raw[1]
    gate1 = result.assurance_reports[0]
    assert gate1.metrics["oracle_reads_passed"] == 32
    assert gate1.metrics["oracle_reads_total"] == 32
    assert gate1.metrics["semantic_checks_passed"] == 35
    assert gate1.metrics["semantic_checks_total"] == 35


def test_v2_macos_logical_xattr_independent_reader_failure_blocks_assurance(
    tmp_path, monkeypatch
):
    root = tmp_path / "macos"
    build_fixture(_spec("macos"), root)

    def reject(_source):
        raise ValueError("logical raw-reader witness")

    monkeypatch.setitem(validity.READERS, "quarantine-xattr-raw", reject)
    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert result.integrity_ok
    assert result.reproduction_ok is True
    assert result.assurance_ok is False
    gate1, gate3 = result.assurance_reports
    assert not gate1.ok
    assert gate3.ok
    assert any(
        "logical metadata" in failure
        and "quarantine-xattr-raw rejected" in failure
        and "logical raw-reader witness" in failure
        for failure in gate1.fails
    )


def test_v2_windows_logical_zone_streams_run_both_readers_on_the_same_bytes(
    tmp_path, monkeypatch
):
    observed: list[tuple[str, bytes]] = []
    originals = {
        name: validity.READERS[name]
        for name in ("configparser", "zone-identifier-raw")
    }

    def recording(name):
        def read(source):
            assert type(source) is bytes
            observed.append((name, source))
            return originals[name](source)

        return read

    for name in originals:
        monkeypatch.setitem(validity.READERS, name, recording(name))

    root = tmp_path / "windows"
    manifest = build_fixture(_spec("windows"), root)
    stream_count = sum(
        blob.name == "Zone.Identifier"
        for node in manifest.payload.files
        if type(node.metadata) is WindowsMetadataV2
        for blob in node.metadata.streams
    )
    result = verify_fixture(root, assurance=True)

    assert result.ok, result.failures
    assert stream_count == 1
    assert len(observed) == 2 * stream_count
    for production, raw in zip(observed[::2], observed[1::2], strict=True):
        assert (production[0], raw[0]) == ("configparser", "zone-identifier-raw")
        assert production[1] is raw[1]


@pytest.mark.parametrize("reader", ("configparser", "zone-identifier-raw"))
def test_v2_windows_logical_zone_reader_failure_blocks_assurance(
    tmp_path, monkeypatch, reader
):
    root = tmp_path / reader
    build_fixture(_spec("windows"), root)

    def reject(_source):
        raise ValueError(f"logical {reader} witness")

    monkeypatch.setitem(validity.READERS, reader, reject)
    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert result.integrity_ok
    assert result.reproduction_ok is True
    assert result.assurance_ok is False
    gate1, gate3 = result.assurance_reports
    assert not gate1.ok
    assert gate3.ok
    assert any(
        "logical metadata" in failure
        and f"{reader} rejected" in failure
        and f"logical {reader} witness" in failure
        for failure in gate1.fails
    )


def test_v2_windows_malformed_logical_zone_stream_blocks_assurance(tmp_path):
    root = tmp_path / "malformed-zone"
    manifest = build_fixture(_spec("windows"), root)
    files = list(manifest.payload.files)
    replaced = False
    for file_index, node in enumerate(files):
        if type(node.metadata) is not WindowsMetadataV2:
            continue
        streams = list(node.metadata.streams)
        for stream_index, stream in enumerate(streams):
            if stream.name != "Zone.Identifier":
                continue
            malformed = stream.data.replace(
                b"ZoneId=3\r\n",
                b"ZoneId=3\r\nZoneId=3\r\n",
            )
            streams[stream_index] = NamedBlobV2.from_bytes(stream.name, malformed)
            files[file_index] = replace(
                node,
                metadata=replace(node.metadata, streams=tuple(streams)),
            )
            replaced = True
            break
        if replaced:
            break
    assert replaced
    altered = replace(
        manifest,
        payload=FixturePayloadV2.create(
            family="windows",
            directories=manifest.payload.directories,
            files=files,
        ),
    )
    (root / "fixture.json").write_bytes(altered.canonical_bytes())

    result = verify_fixture(root, assurance=True)

    assert result.integrity_ok
    assert result.reproduction_ok is False
    assert result.assurance_ok is False
    gate1, _gate3 = result.assurance_reports
    assert any(
        "logical metadata" in failure and "configparser rejected" in failure
        for failure in gate1.fails
    )
    assert any(
        "logical metadata" in failure and "zone-identifier-raw rejected" in failure
        for failure in gate1.fails
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("host", "HostUrl does not match History"),
        ("referrer", "ReferrerUrl does not match History"),
    ),
)
def test_v2_windows_parser_valid_zone_history_mismatch_blocks_assurance(
    tmp_path, mutation, message
):
    root = tmp_path / mutation
    manifest = build_fixture(_spec("windows"), root)
    zone_node, zone_blob = _windows_zone_node(manifest)
    observed = parse_zone_identifier(zone_blob.data)
    changed_zone = build_zone_identifier(
        (
            "https://portal.example/ARTIFACTFORGE/mismatched-referrer"
            if mutation == "referrer"
            else observed.referrer_url
        ),
        (
            "https://downloads.example/ARTIFACTFORGE/mismatched-host"
            if mutation == "host"
            else observed.host_url
        ),
    )
    streams = tuple(
        NamedBlobV2.from_bytes(stream.name, changed_zone)
        if stream.name == "Zone.Identifier"
        else stream
        for stream in zone_node.metadata.streams
    )
    changed_node = replace(
        zone_node,
        metadata=replace(zone_node.metadata, streams=streams),
    )
    _replace_v2_files(
        root,
        manifest,
        tuple(changed_node if node == zone_node else node for node in manifest.payload.files),
    )

    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert result.integrity_ok
    assert result.reproduction_ok is False
    gate1, gate3 = result.assurance_reports
    assert not gate1.ok
    assert gate3.ok
    assert any(message in failure for failure in gate1.fails)
    assert not any("configparser rejected" in failure for failure in gate1.fails)
    assert not any("zone-identifier-raw rejected" in failure for failure in gate1.fails)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("target", "exactly one row for the Zone.Identifier-bearing target"),
        ("digest", "URL digest does not identify the emitted target bytes"),
        ("size", "byte counts do not match the emitted target"),
    ),
)
def test_v2_windows_parser_valid_history_byte_join_mismatch_blocks_assurance(
    tmp_path, mutation, message
):
    root = tmp_path / mutation
    manifest = build_fixture(_spec("windows"), root)
    zone_node, _zone_blob = _windows_zone_node(manifest)
    history_nodes = [
        node
        for node in manifest.payload.files
        if node.guest_path.endswith(
            r"\AppData\Local\Chromium\User Data\Default\History"
        )
    ]
    assert len(history_nodes) == 1
    history_node = history_nodes[0]
    history_path = root / "artifacts" / history_node.served_path
    changed_history = _mutate_owned_history(
        history_path.read_bytes(),
        target_path=zone_node.guest_path,
        mutation=mutation,
    )
    history_path.write_bytes(changed_history)
    changed_node = FileNodeV2.from_bytes(
        guest_path=history_node.guest_path,
        served_path=history_node.served_path,
        data=changed_history,
        metadata=history_node.metadata,
    )
    _replace_v2_files(
        root,
        manifest,
        tuple(
            changed_node if node == history_node else node
            for node in manifest.payload.files
        ),
    )

    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert result.integrity_ok
    assert result.reproduction_ok is False
    gate1, gate3 = result.assurance_reports
    assert not gate1.ok
    assert gate3.ok
    assert any(message in failure for failure in gate1.fails)
    assert not any("sqlite-profile" in failure for failure in gate1.fails)


def test_v2_windows_parser_valid_task_nonresident_join_blocks_assurance(tmp_path):
    root = tmp_path / "task-nonresident"
    manifest = build_fixture(_spec("windows"), root)
    task_node, _shell_node = _windows_reference_nodes(manifest)
    task_path = root / "artifacts" / task_node.served_path
    parsed = parse_scheduled_task_xml(task_path.read_bytes())
    missing = r"C:\Program Files\ArtifactForge\missing-helper.exe"
    changed = build_scheduled_task_xml(
        parsed.task_name,
        missing,
        resident_pe_paths=(missing,),
        version=parsed.version,
    )
    task_path.write_bytes(changed)
    changed_node = FileNodeV2.from_bytes(
        guest_path=task_node.guest_path,
        served_path=task_node.served_path,
        data=changed,
        metadata=task_node.metadata,
    )
    _replace_v2_files(
        root,
        manifest,
        tuple(
            changed_node if node == task_node else node
            for node in manifest.payload.files
        ),
    )

    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert result.integrity_ok
    assert result.reproduction_ok is False
    gate1, gate3 = result.assurance_reports
    assert not gate1.ok
    assert gate3.ok
    assert any(
        "scheduled task must resolve to exactly one emitted PE" in failure
        for failure in gate1.fails
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("path", "Shell Link must resolve to exactly one emitted PE"),
        ("size", "Shell Link target size does not match emitted PE bytes"),
        ("timestamp", "Shell Link target FILETIMEs do not match logical PE metadata"),
    ),
)
def test_v2_windows_parser_valid_shell_link_join_mutation_blocks_assurance(
    tmp_path, mutation, message
):
    root = tmp_path / f"shell-{mutation}"
    manifest = build_fixture(_spec("windows"), root)
    _task_node, shell_node = _windows_reference_nodes(manifest)
    shell_path = root / "artifacts" / shell_node.served_path
    parsed = parse_shell_link(shell_path.read_bytes())
    changed = build_shell_link(
        (
            r"C:\Program Files\ArtifactForge\missing-helper.exe"
            if mutation == "path"
            else parsed.target_path
        ),
        parsed.display_name,
        parsed.target_size + (1 if mutation == "size" else 0),
        timestamps=ShellLinkTimestamps(
            creation_filetime=(
                parsed.creation_filetime + 10_000_000
                if mutation == "timestamp"
                else parsed.creation_filetime
            ),
            access_filetime=parsed.access_filetime,
            write_filetime=parsed.write_filetime,
        ),
        volume_serial=parsed.volume_serial,
        volume_label=parsed.volume_label,
    )
    shell_path.write_bytes(changed)
    changed_node = FileNodeV2.from_bytes(
        guest_path=shell_node.guest_path,
        served_path=shell_node.served_path,
        data=changed,
        metadata=shell_node.metadata,
    )
    _replace_v2_files(
        root,
        manifest,
        tuple(
            changed_node if node == shell_node else node
            for node in manifest.payload.files
        ),
    )

    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert result.integrity_ok
    assert result.reproduction_ok is False
    gate1, gate3 = result.assurance_reports
    assert not gate1.ok
    assert gate3.ok
    assert any(message in failure for failure in gate1.fails)


def test_v1_build_refuses_before_any_output_or_scene_side_effect(tmp_path, monkeypatch):
    spec = FixtureSpec(
        fixture_id="historical-v1",
        family="windows",
        profile=ProfileSpec("windows-loose-v1", "WKSTN-01", "v"),
        seed_hex="44" * 32,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a parse-only v1 writer ran")

    monkeypatch.setattr("artifactforge.fixture.operations.build_windows_scene", forbidden)
    output = tmp_path / "absent-parent" / "fixture"

    with pytest.raises(FixtureUsageError, match="parse-only.*must not relabel"):
        build_fixture(spec, output)

    assert not output.parent.exists()


def test_v2_publication_refuses_existing_output_without_touching_it(tmp_path, monkeypatch):
    output = tmp_path / "fixture"
    output.mkdir()
    sentinel = output / "belongs-to-caller"
    sentinel.write_bytes(b"do not replace")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("generation ran before the no-replace check")

    monkeypatch.setattr("artifactforge.fixture.operations._materialise_publication", forbidden)

    with pytest.raises(FixtureUsageError, match="existing fixture output"):
        build_fixture(_spec("linux"), output)

    assert sentinel.read_bytes() == b"do not replace"
    assert sorted(path.name for path in output.iterdir()) == ["belongs-to-caller"]
