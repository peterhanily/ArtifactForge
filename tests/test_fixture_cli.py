# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fixture command handlers keep output and exit meanings stable."""
from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path

from artifactforge.cli import fixture as fixture_cli
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixtureSpec,
    GeneratorIdentity,
)
from artifactforge.fixture import archive, operations
from artifactforge.fixture.operations import VerificationResult

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "examples" / "fixtures" / "windows-loose-v1.json"


def _args(**values):
    return argparse.Namespace(**values)


def _build(tmp_path, capsys, *, json_output=False):
    output = tmp_path / "fixture"
    result = fixture_cli.cmd_build(_args(spec=SPEC, output=output, json=json_output))
    captured = capsys.readouterr()
    assert result == 0, captured.err
    return output, captured


def test_build_inspect_and_verify_have_stable_json_summaries(tmp_path, capsys):
    fixture, built = _build(tmp_path, capsys, json_output=True)
    build_record = json.loads(built.out)
    assert build_record["command"] == "build" and build_record["ok"] is True
    assert build_record["recipe_sha256"].startswith("sha256:")

    args = _args(fixture=fixture, json=True)
    assert fixture_cli.cmd_inspect(args) == 0
    first = capsys.readouterr().out
    assert fixture_cli.cmd_inspect(args) == 0
    second = capsys.readouterr().out
    assert first == second
    inspected = json.loads(first)
    assert inspected["fixture_id"] == "windows-dropper-001"
    assert inspected["profile"] == "windows-loose-v1"
    assert set(inspected["payload"]) == {"file_count", "total_bytes", "tree_sha256"}
    assert "manifest" not in inspected and "seed_hex" not in first

    assert fixture_cli.cmd_verify(_args(fixture=fixture, assurance=False, json=True)) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["verification"]["assurance_summary"]["verdict"] == "not-run"


def test_human_output_leads_with_the_outcome(tmp_path, capsys):
    fixture, built = _build(tmp_path, capsys)
    assert built.out.startswith("fixture build: PASS")
    assert fixture_cli.cmd_verify(_args(fixture=fixture, assurance=False, json=False)) == 0
    assert capsys.readouterr().out.startswith("fixture verify: PASS")


def test_existing_output_and_malformed_spec_are_usage_exit_two(tmp_path, capsys):
    fixture, _captured = _build(tmp_path, capsys)
    assert fixture_cli.cmd_build(_args(spec=SPEC, output=fixture, json=False)) == 2
    assert "refusing existing fixture output" in capsys.readouterr().err

    malformed = tmp_path / "bad.json"
    malformed.write_text('{"schema": "wrong"}\n')
    assert fixture_cli.cmd_build(
        _args(spec=malformed, output=tmp_path / "bad", json=True)) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["exit_code"] == 2 and error["ok"] is False

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b'{"value":' + b"9" * 5000 + b"}")
    assert fixture_cli.cmd_build(
        _args(spec=oversized, output=tmp_path / "oversized", json=True)
    ) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["exit_code"] == 2 and "invalid JSON" in error["error"]


def test_post_publish_sync_uncertainty_is_explicit_in_canonical_stderr(
    monkeypatch, tmp_path, capsys
):
    output = tmp_path / "fixture"
    real_fsync_directory = operations._fsync_directory
    calls = 0

    def fail_post_publish(directory):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise operations.FixtureUsageError("injected post-rename fsync failure")
        return real_fsync_directory(directory)

    monkeypatch.setattr(operations, "_fsync_directory", fail_post_publish)
    assert fixture_cli.cmd_build(_args(spec=SPEC, output=output, json=True)) == 2
    captured = capsys.readouterr()
    assert not captured.out
    record = json.loads(captured.err)
    assert record["published"] is True
    assert record["fixture"] == str(output)
    assert record["ok"] is False and record["exit_code"] == 2
    assert record["recipe_sha256"].startswith("sha256:")
    assert record["tree_sha256"].startswith("sha256:")
    assert output.is_dir()


def test_verification_mismatch_is_exit_one_not_usage_error(tmp_path, capsys):
    fixture, _captured = _build(tmp_path, capsys)
    victim = next((fixture / "artifacts").iterdir())
    while victim.is_dir():
        victim = next(victim.iterdir())
    victim.write_bytes(victim.read_bytes() + b"mutation")
    assert fixture_cli.cmd_verify(
        _args(fixture=fixture, assurance=False, json=True)) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["verification"]["failures"]


def test_semantic_diff_is_path_keyed_and_does_not_shift_array_indices(monkeypatch, capsys):
    base = FixtureSpec.from_json(SPEC.read_bytes())
    other = FixtureSpec.from_mapping({
        **base.to_mapping(),
        "fixture_id": "windows-dropper-002",
        "seed_hex": "1" * 64,
    })
    left = FixtureManifest.create(
        base,
        generator_version="1",
        entries=(ArtifactEntry.from_bytes("a.bin", b"a"),
                 ArtifactEntry.from_bytes("b.bin", b"b")),
    )
    right = FixtureManifest.create(
        other,
        generator_version="2",
        entries=(ArtifactEntry.from_bytes("b.bin", b"changed"),
                 ArtifactEntry.from_bytes("c.bin", b"c")),
    )
    right = dataclasses.replace(right, generator=GeneratorIdentity(version="2"))
    results = {"left": VerificationResult(left), "right": VerificationResult(right)}
    monkeypatch.setattr(fixture_cli, "verify_fixture",
                        lambda path, assurance=False: results[str(path)])

    assert fixture_cli.cmd_diff(_args(left="left", right="right", json=True)) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["payload"]["added"] == ["c.bin"]
    assert result["payload"]["removed"] == ["a.bin"]
    assert [item["path"] for item in result["payload"]["changed"]] == ["b.bin"]
    assert {item["path"] for item in result["recipe_changes"]} == {
        "/fixture_id", "/seed_hex",
    }
    assert result["generator_changes"] == [{"left": "1", "path": "/version", "right": "2"}]
    rendered = json.dumps(result)
    assert "payload.files[" not in rendered and "tree_sha256" not in rendered


def test_identical_diff_is_exit_zero(tmp_path, capsys):
    fixture, _captured = _build(tmp_path, capsys)
    assert fixture_cli.cmd_diff(
        _args(left=fixture, right=fixture, json=True)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["identical"] is True
    assert result["payload"] == {"added": [], "changed": [], "removed": []}


def test_release_handler_publishes_once_and_existing_output_is_exit_two(tmp_path, capsys):
    fixture, _captured = _build(tmp_path, capsys)
    output = tmp_path / "fixture.tar"
    args = _args(fixture=fixture, output=output, assurance=False, json=True)
    assert fixture_cli.cmd_release(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["release"]["sha256"].startswith("sha256:")
    assert output.is_file()
    assert fixture_cli.cmd_release(args) == 2
    assert json.loads(capsys.readouterr().err)["exit_code"] == 2


def test_release_sync_uncertainty_reports_published_archive_in_stderr(
    tmp_path, monkeypatch, capsys
):
    fixture, _captured = _build(tmp_path, capsys)
    output = tmp_path / "fixture.tar"

    def fail_sync(_path):
        raise archive.FixtureArchiveError("injected post-link sync failure")

    monkeypatch.setattr(archive, "_fsync_directory", fail_sync)
    args = _args(fixture=fixture, output=output, assurance=False, json=True)
    assert fixture_cli.cmd_release(args) == 2
    captured = capsys.readouterr()
    assert not captured.out
    record = json.loads(captured.err)
    assert record["published"] is True
    assert record["archive"] == str(output)
    assert record["sha256"].startswith("sha256:")
    assert record["size"] == output.stat().st_size
    assert record["ok"] is False and record["exit_code"] == 2
