# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Platform-independent tests for native attestation provenance and claim boundaries."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parents[1] / "scripts" / "attest_macos_native.py"
_SCRIPT_GLOBALS = runpy.run_path(str(_SCRIPT))
_canonical_json_bytes = _SCRIPT_GLOBALS["_canonical_json_bytes"]
_file_identity = _SCRIPT_GLOBALS["_file_identity"]
_gatekeeper_conclusion = _SCRIPT_GLOBALS["_gatekeeper_conclusion"]
_github_run_identity = _SCRIPT_GLOBALS["_github_run_identity"]
_inside = _SCRIPT_GLOBALS["_inside"]
_project_markers = _SCRIPT_GLOBALS["_project_markers"]
_scene_manifest = _SCRIPT_GLOBALS["_scene_manifest"]
_scene_postcondition = _SCRIPT_GLOBALS["_scene_postcondition"]
_source_postcondition = _SCRIPT_GLOBALS["_source_postcondition"]
_source_provenance = _SCRIPT_GLOBALS["_source_provenance"]
_timestamp = _SCRIPT_GLOBALS["_timestamp"]
main = _SCRIPT_GLOBALS["main"]


def _result(returncode: int, *, stdout: str = "", stderr: str = "") -> dict:
    return {"returncode": returncode, "stdout": stdout, "stderr": stderr}


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()


def test_gatekeeper_success_is_an_unexpected_acceptance():
    assert _gatekeeper_conclusion(_result(0), control_working=True) == "accepted_unexpectedly"


def test_gatekeeper_rejection_requires_a_working_positive_control():
    rejected = _result(3, stderr="synthetic: rejected")
    assert _gatekeeper_conclusion(rejected, control_working=True) == "rejected"
    assert (
        _gatekeeper_conclusion(rejected, control_working=False)
        == "inconclusive_non_acceptance"
    )


def test_gatekeeper_nonzero_service_error_is_inconclusive():
    error = _result(1, stderr="Code Signing subsystem unavailable")
    assert (
        _gatekeeper_conclusion(error, control_working=True)
        == "inconclusive_non_acceptance"
    )


def test_timestamp_is_second_precision_canonical_utc():
    value = dt.datetime(2026, 8, 1, 13, 14, 15, 999999, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    assert _timestamp(value) == "2026-08-01T12:14:15Z"
    with pytest.raises(ValueError, match="timezone-aware"):
        _timestamp(dt.datetime(2026, 8, 1))


def test_canonical_json_is_sorted_compact_utf8_with_one_lf():
    value = {"z": [3, 2], "accent": "é", "nested": {"b": False, "a": None}}
    assert _canonical_json_bytes(value) == (
        b'{"accent":"\xc3\xa9","nested":{"a":null,"b":false},"z":[3,2]}\n'
    )
    assert json.loads(_canonical_json_bytes(value)) == value


def test_recursive_scene_manifest_binds_paths_sizes_bytes_and_tree(tmp_path):
    scene = tmp_path / "scene"
    (scene / "nested").mkdir(parents=True)
    (scene / "a.bin").write_bytes(b"one")
    (scene / "nested" / "b.bin").write_bytes(b"two")

    manifest = _scene_manifest(scene)
    files = [
        {
            "path": "a.bin",
            "sha256": hashlib.sha256(b"one").hexdigest(),
            "size": 3,
        },
        {
            "path": "nested/b.bin",
            "sha256": hashlib.sha256(b"two").hexdigest(),
            "size": 3,
        },
    ]
    digest_input = (
        json.dumps({"files": files}, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode()
    assert manifest["files"] == files
    assert manifest["file_count"] == 2
    assert manifest["total_bytes"] == 6
    assert manifest["tree_sha256"] == hashlib.sha256(digest_input).hexdigest()


def test_scene_byte_mutation_fails_postcondition_even_at_same_size(tmp_path):
    scene = tmp_path / "scene"
    scene.mkdir()
    artifact = scene / "artifact.bin"
    artifact.write_bytes(b"before")
    initial = _scene_manifest(scene)

    artifact.write_bytes(b"AFTER!")
    postcondition = _scene_postcondition(initial, scene)
    assert postcondition["unchanged"] is False
    assert postcondition["file_count"] == initial["file_count"]
    assert postcondition["total_bytes"] == initial["total_bytes"]
    assert postcondition["tree_sha256"] != initial["tree_sha256"]


def test_scene_manifest_rejects_symlinks_instead_of_hiding_them(tmp_path):
    scene = tmp_path / "scene"
    scene.mkdir()
    target = tmp_path / "outside.bin"
    target.write_bytes(b"outside")
    try:
        (scene / "link.bin").symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create test symlink: {exc}")
    with pytest.raises(RuntimeError, match="symbolic link"):
        _scene_manifest(scene)


def test_file_identity_binds_resolved_executable_bytes(tmp_path):
    executable = tmp_path / "native-tool"
    executable.write_bytes(b"tool-v1")
    identity = _file_identity(executable)
    assert identity == {
        "path": str(executable),
        "resolved_path": str(executable.resolve()),
        "sha256": hashlib.sha256(b"tool-v1").hexdigest(),
        "size": 7,
    }
    executable.write_bytes(b"tool-v2")
    assert _file_identity(executable)["sha256"] != identity["sha256"]


def test_apple_build_markers_are_deduplicated_and_sorted():
    output = """
        PROGRAM:xattr  PROJECT:file_cmds-479
        PROGRAM:codesign  PROJECT:codesign-83.100.6
        PROGRAM:xattr  PROJECT:file_cmds-479
    """
    assert _project_markers(output) == [
        {"program": "codesign", "project": "codesign-83.100.6"},
        {"program": "xattr", "project": "file_cmds-479"},
    ]


def test_source_provenance_binds_commit_tree_and_clean_state(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "ArtifactForge Test")
    _git(repository, "config", "user.email", "artifactforge@example.invalid")
    tracked = repository / "tracked.txt"
    tracked.write_text("committed\n")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "--quiet", "-m", "fixture")

    clean = _source_provenance(repository)
    assert clean["git_commit"] == _git(repository, "rev-parse", "HEAD")
    assert clean["git_tree"] == _git(repository, "rev-parse", "HEAD^{tree}")
    assert clean["worktree_clean"] is True
    assert clean["status_porcelain_sha256"] == hashlib.sha256(b"").hexdigest()

    tracked.write_text("modified!\n")
    dirty = _source_provenance(repository)
    assert dirty["git_commit"] == clean["git_commit"]
    assert dirty["git_tree"] == clean["git_tree"]
    assert dirty["worktree_clean"] is False
    assert dirty["status_porcelain_sha256"] != clean["status_porcelain_sha256"]
    assert _source_postcondition(clean, repository)["unchanged"] is False


def test_github_run_identity_is_optional_and_contains_no_environment_dump():
    assert _github_run_identity({}) is None
    environ = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_JOB": "macos-native",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "example/ArtifactForge",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_RUN_ID": "1234",
        "GITHUB_SERVER_URL": "https://github.example",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW": "CI",
        "GITHUB_WORKFLOW_REF": "example/ArtifactForge/.github/workflows/ci.yml@refs/heads/main",
        "A_SECRET": "must-not-appear",
    }
    identity = _github_run_identity(environ)
    assert identity == {
        "event_name": "push",
        "git_sha": "a" * 40,
        "job": "macos-native",
        "ref": "refs/heads/main",
        "repository": "example/ArtifactForge",
        "run_attempt": "2",
        "run_id": "1234",
        "run_url": "https://github.example/example/ArtifactForge/actions/runs/1234",
        "server_url": "https://github.example",
        "workflow": "CI",
        "workflow_ref": "example/ArtifactForge/.github/workflows/ci.yml@refs/heads/main",
    }
    assert "must-not-appear" not in json.dumps(identity)


def test_output_path_inside_scene_is_detected(tmp_path):
    scene = tmp_path / "scene"
    scene.mkdir()
    assert _inside(scene / "attestation.json", scene)
    assert not _inside(tmp_path / "attestation.json", scene)


def test_main_writes_canonical_json(monkeypatch, tmp_path):
    scene = tmp_path / "scene"
    scene.mkdir()
    output = tmp_path / "attestation.json"
    fake_report = {"failures": [], "schema": "fixture", "verdict": "pass", "z": 1}
    monkeypatch.setitem(main.__globals__, "attest", lambda _scene: fake_report)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(_SCRIPT), "--scene", str(scene), "--out", str(output)],
    )
    assert main() == 0
    assert output.read_bytes() == _canonical_json_bytes(fake_report)
