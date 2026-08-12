# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The fixture CLI reports v2 logical state without overstating inspection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from artifactforge.cli import fixture as fixture_cli
from artifactforge.fixture.archive import ArchiveResult
from artifactforge.fixture.canonical import canonical_json_bytes
from artifactforge.fixture.model import parse_fixture_manifest
from artifactforge.fixture.model_v2 import (
    DirectoryNodeV2,
    FileNodeV2,
    FixtureManifestV2,
    FixturePayloadV2,
    FixtureSpecV2,
    LinuxMetadataV2,
    MacOSMetadataV2,
    NamedBlobV2,
    ProfileSpecV2,
    WindowsMetadataV2,
)
from artifactforge.fixture.operations import VerificationResult, build_fixture


ROOT = Path(__file__).parents[1]
V1_GOLDEN = ROOT / "tests/fixtures/fixture-v1-goldens/linux-v0.5.0.json"


def _args(**values):
    return argparse.Namespace(**values)


def _linux_metadata(*, mode: int, offset: int = 0) -> LinuxMetadataV2:
    timestamp = 1_800_000_000_000_000_000 + offset
    return LinuxMetadataV2(
        mode=mode,
        uid=1000,
        gid=1000,
        atime_unix_ns=timestamp,
        mtime_unix_ns=timestamp,
        ctime_unix_ns=timestamp,
    )


def _linux_manifest(
    *,
    directory_offset: int = 0,
    file_data: bytes = b"fixture bytes",
    extra_file: bool = False,
) -> FixtureManifestV2:
    profile = ProfileSpecV2(
        id="linux-glibc-x86_64-loose-v2",
        hostname="workstation",
        username="analyst",
    )
    spec = FixtureSpecV2.create(
        fixture_id="cli-v2",
        family="linux",
        story="linux-autostart-v1",
        profile=profile,
        seed_hex="4" * 64,
    )
    directories = [
        DirectoryNodeV2("/home", "home", _linux_metadata(mode=0o755)),
        DirectoryNodeV2(
            "/home/analyst",
            "home/analyst",
            _linux_metadata(mode=0o750, offset=directory_offset),
        ),
    ]
    files = [
        FileNodeV2.from_bytes(
            guest_path="/home/analyst/artifact.bin",
            served_path="home/analyst/artifact.bin",
            data=file_data,
            metadata=_linux_metadata(mode=0o640),
        )
    ]
    if extra_file:
        directories.append(
            DirectoryNodeV2(
                "/home/analyst/cases",
                "home/analyst/cases",
                _linux_metadata(mode=0o750),
            )
        )
        files.append(
            FileNodeV2.from_bytes(
                guest_path="/home/analyst/cases/second.bin",
                served_path="home/analyst/cases/second.bin",
                data=b"second",
                metadata=_linux_metadata(mode=0o640),
            )
        )
    payload = FixturePayloadV2.create(
        family="linux", directories=directories, files=files
    )
    return FixtureManifestV2.create(
        generator_version="cli-test", recipe=spec, payload=payload
    )


def _windows_file(*, stream_data: bytes) -> FileNodeV2:
    timestamp = 1_800_000_000_000_000_000
    return FileNodeV2.from_bytes(
        guest_path=r"C:\Users\Analyst\artifact.exe",
        served_path="C/Users/Analyst/artifact.exe",
        data=b"MZ",
        metadata=WindowsMetadataV2(
            owner_sid="S-1-5-21-1000-1000-1000-1001",
            attributes=("ARCHIVE",),
            creation_unix_ns=timestamp,
            access_unix_ns=timestamp,
            write_unix_ns=timestamp,
            change_unix_ns=timestamp,
            streams=(NamedBlobV2.from_bytes("Zone.Identifier", stream_data),),
        ),
    )


def _macos_file(*, xattr_data: bytes) -> FileNodeV2:
    timestamp = 1_800_000_000_000_000_000
    return FileNodeV2.from_bytes(
        guest_path="/Users/analyst/artifact",
        served_path="Users/analyst/artifact",
        data=b"Mach-O",
        metadata=MacOSMetadataV2(
            mode=0o640,
            uid=501,
            gid=20,
            atime_unix_ns=timestamp,
            mtime_unix_ns=timestamp,
            ctime_unix_ns=timestamp,
            birthtime_unix_ns=timestamp,
            xattrs=(
                NamedBlobV2.from_bytes("com.apple.quarantine", xattr_data),
            ),
        ),
    )


def test_load_and_build_dispatch_v2_and_report_all_logical_counters(
    tmp_path, monkeypatch, capsys
):
    manifest = _linux_manifest()
    spec_path = tmp_path / "spec.json"
    spec_path.write_bytes(manifest.recipe.canonical_bytes())
    assert fixture_cli._load_spec(spec_path) == manifest.recipe

    received = []

    def build(spec, output):
        received.append((spec, output))
        return manifest

    monkeypatch.setattr(fixture_cli, "build_fixture", build)
    output = tmp_path / "fixture"
    assert fixture_cli.cmd_build(
        _args(spec=spec_path, output=output, json=True)
    ) == 0
    assert received == [(manifest.recipe, output)]
    record = json.loads(capsys.readouterr().out)
    expected_counters = {
        "directory_count": 2,
        "file_count": 1,
        "regular_file_bytes": len(b"fixture bytes"),
        "metadata_blob_count": 0,
        "metadata_blob_bytes": 0,
        "total_bound_bytes": len(b"fixture bytes"),
    }
    assert {key: record[key] for key in expected_counters} == expected_counters
    assert {
        key: record["payload"][key] for key in expected_counters
    } == expected_counters
    assert record["generator"]["producer_profile"] == (
        "artifactforge-fixture-producer-v2"
    )
    assert record["producer"] == {
        "abi_contract": "v2",
        "available": True,
        "frozen_release": "unreleased",
        "implementation": "artifactforge-fixture-producer-v2",
        "mode": "produce-and-parse",
        "profile": "artifactforge-fixture-producer-v2",
    }
    assert record["checks"] == {
        "assurance": "not-run",
        "integrity": "pass",
        "reproduction": "pass",
    }


def test_inspect_is_integrity_only_for_v2_and_v1_parse_only(
    monkeypatch, capsys
):
    v2 = _linux_manifest()
    monkeypatch.setattr(
        fixture_cli,
        "inspect_fixture",
        lambda _path: VerificationResult(v2, reproduction_requested=False),
    )
    assert fixture_cli.cmd_inspect(_args(fixture="v2", json=True)) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["checks"] == {
        "assurance": "not-run",
        "integrity": "pass",
        "reproduction": "not-run",
    }
    assert record["payload"]["directory_count"] == 2
    assert record["payload"]["metadata_blob_count"] == 0

    v1 = parse_fixture_manifest(V1_GOLDEN.read_bytes(), require_canonical=True)
    monkeypatch.setattr(
        fixture_cli,
        "inspect_fixture",
        lambda _path: VerificationResult(v1, reproduction_requested=False),
    )
    assert fixture_cli.cmd_inspect(_args(fixture="v1", json=True)) == 0
    historical = json.loads(capsys.readouterr().out)
    assert historical["checks"]["reproduction"] == "not-run"
    assert historical["producer"]["mode"] == "parse-only"
    assert historical["producer"]["available"] is False
    assert historical["producer"]["profile"] is None
    assert set(historical["payload"]) == {
        "file_count",
        "total_bytes",
        "tree_sha256",
    }


def test_inspect_reports_oversized_sid_as_canonical_usage_json(tmp_path, capsys):
    spec = FixtureSpecV2.from_json(
        (ROOT / "examples/fixtures/windows-loose-v2.json").read_bytes()
    )
    fixture = tmp_path / "fixture"
    manifest = build_fixture(spec, fixture)
    mapping = manifest.to_mapping()
    mapping["payload"]["files"][0]["metadata"]["owner_sid"] = (
        "S-1-" + "9" * 5000 + "-1"
    )
    (fixture / "fixture.json").write_bytes(canonical_json_bytes(mapping))

    assert fixture_cli.cmd_inspect(_args(fixture=fixture, json=True)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    error = json.loads(captured.err)
    assert error["command"] == "inspect"
    assert error["exit_code"] == 2
    assert error["ok"] is False
    assert "184-byte SID limit" in error["error"]


def test_verify_and_release_report_v2_phase_status_and_producer(
    tmp_path, monkeypatch, capsys
):
    manifest = _linux_manifest()
    verification = VerificationResult(manifest, reproduction_requested=True)
    monkeypatch.setattr(
        fixture_cli,
        "verify_fixture",
        lambda _path, assurance=False: verification,
    )
    assert fixture_cli.cmd_verify(
        _args(fixture="fixture", assurance=False, json=True)
    ) == 0
    verified = json.loads(capsys.readouterr().out)["verification"]
    assert verified["checks"] == {
        "assurance": "not-run",
        "integrity": "pass",
        "reproduction": "pass",
    }
    assert verified["producer"]["profile"] == "artifactforge-fixture-producer-v2"
    assert verified["regular_file_bytes"] == len(b"fixture bytes")

    archive_result = ArchiveResult(
        path=tmp_path / "fixture.tar",
        sha256="sha256:" + "1" * 64,
        size=10240,
        members=("cli-v2/",),
        manifest=manifest,
        fixture_verification=verification,
    )
    monkeypatch.setattr(
        fixture_cli,
        "create_release_archive",
        lambda *_args, **_kwargs: archive_result,
    )
    assert fixture_cli.cmd_release(
        _args(
            fixture="fixture",
            output=tmp_path / "fixture.tar",
            assurance=False,
            json=True,
        )
    ) == 0
    released = json.loads(capsys.readouterr().out)
    assert released["checks"] == {
        "archive_integrity": "pass",
        "assurance": "not-run",
        "integrity": "pass",
        "reproduction": "pass",
    }
    assert released["payload"]["directory_count"] == 2
    assert released["producer"]["implementation"] == (
        "artifactforge-fixture-producer-v2"
    )


def test_v2_diff_exposes_directories_guest_paths_and_logical_metadata(
    monkeypatch, capsys
):
    left = _linux_manifest()
    right = _linux_manifest(
        directory_offset=1_000_000_000,
        file_data=b"changed fixture bytes",
        extra_file=True,
    )
    results = {
        "left": VerificationResult(left),
        "right": VerificationResult(right),
    }
    monkeypatch.setattr(
        fixture_cli,
        "verify_fixture",
        lambda path, assurance=False: results[str(path)],
    )

    assert fixture_cli.cmd_diff(
        _args(left="left", right="right", json=True)
    ) == 1
    record = json.loads(capsys.readouterr().out)
    directories = record["payload"]["directories"]
    assert [node["served_path"] for node in directories["added"]] == [
        "home/analyst/cases"
    ]
    assert directories["added"][0]["guest_path"] == "/home/analyst/cases"
    assert directories["added"][0]["metadata"]["mode"] == 0o750
    assert directories["changed"][0]["served_path"] == "home/analyst"
    assert directories["changed"][0]["left_guest_path"] == "/home/analyst"
    assert {
        change["path"] for change in directories["changed"][0]["changes"]
    } == {
        "/metadata/atime_unix_ns",
        "/metadata/ctime_unix_ns",
        "/metadata/mtime_unix_ns",
    }
    files = record["payload"]["files"]
    assert files["added"][0]["guest_path"] == "/home/analyst/cases/second.bin"
    assert files["changed"][0]["served_path"] == "home/analyst/artifact.bin"
    assert {change["path"] for change in files["changed"][0]["changes"]} == {
        "/sha256",
        "/size",
    }


def test_v2_node_diff_names_ads_and_xattrs_in_logical_metadata():
    windows = fixture_cli._v2_node_diff(
        (_windows_file(stream_data=b"ZoneId=3"),),
        (_windows_file(stream_data=b"ZoneId=4"),),
    )
    assert {
        change["path"] for change in windows["changed"][0]["changes"]
    } == {
        "/metadata/streams/Zone.Identifier/data_base64",
        "/metadata/streams/Zone.Identifier/sha256",
    }
    assert "Zone.Identifier" in json.dumps(windows)

    macos = fixture_cli._v2_node_diff(
        (_macos_file(xattr_data=b"0083;old"),),
        (_macos_file(xattr_data=b"0083;new"),),
    )
    assert {
        change["path"] for change in macos["changed"][0]["changes"]
    } == {
        "/metadata/xattrs/com.apple.quarantine/data_base64",
        "/metadata/xattrs/com.apple.quarantine/sha256",
    }
    assert "com.apple.quarantine" in json.dumps(macos)


def test_v2_identical_diff_has_empty_node_collections(monkeypatch, capsys):
    manifest = _linux_manifest()
    monkeypatch.setattr(
        fixture_cli,
        "verify_fixture",
        lambda _path, assurance=False: VerificationResult(manifest),
    )
    assert fixture_cli.cmd_diff(
        _args(left="left", right="right", json=True)
    ) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["identical"] is True
    assert record["contract_changes"] == []
    assert record["payload"] == {
        "directories": {"added": [], "changed": [], "removed": []},
        "files": {"added": [], "changed": [], "removed": []},
    }


def test_phase_specific_failure_status_is_not_conflated(monkeypatch, capsys):
    manifest = _linux_manifest()
    result = VerificationResult(
        manifest,
        failures=("exact reproduction changed metadata",),
        reproduction_failures=("exact reproduction changed metadata",),
    )
    monkeypatch.setattr(
        fixture_cli,
        "verify_fixture",
        lambda _path, assurance=False: result,
    )
    assert fixture_cli.cmd_verify(
        _args(fixture="fixture", assurance=False, json=True)
    ) == 1
    record = json.loads(capsys.readouterr().out)
    assert record["verification"]["checks"] == {
        "assurance": "not-run",
        "integrity": "pass",
        "reproduction": "fail",
    }


def test_public_fixture_package_exports_v2_models():
    import artifactforge.fixture as fixture

    assert fixture.FixtureSpecV2 is FixtureSpecV2
    assert fixture.FixtureManifestV2 is FixtureManifestV2
    assert fixture.DirectoryNodeV2 is DirectoryNodeV2
    assert fixture.FileNodeV2 is FileNodeV2
    assert fixture.NodeMetadataV2 is not None
    assert fixture.validate_ustar_member_name_v2("fixture/artifacts/value") == (
        "fixture/artifacts/value"
    )
