# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fixture Core builds only public payloads and verifies them by exact reproduction."""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from dataclasses import replace

import pytest

from artifactforge import suite
from artifactforge.fixture.canonical import canonical_json_bytes
from artifactforge.fixture.model import (
    FixtureManifest,
    FixtureSpec,
    GeneratorIdentity,
    ProfileSpec,
    artifact_entries_from_tree,
)
from artifactforge.fixture import operations
from artifactforge.fixture.operations import (
    FixturePublicationUncertain,
    FixtureUsageError,
    build_fixture,
    verify_fixture,
)


def _spec(family: str = "windows") -> FixtureSpec:
    if family == "windows":
        profile = ProfileSpec("windows-loose-v1", "WKSTN-01", "v")
    else:
        profile = ProfileSpec("macos-14-loose-v1", "mac-01", "v")
    return FixtureSpec(
        fixture_id=f"{family}-fixture-001",
        family=family,
        profile=profile,
        seed_hex=("01" if family == "windows" else "02") * 32,
    )


def _first_artifact(root: Path) -> Path:
    return next(path for path in sorted((root / "artifacts").rglob("*")) if path.is_file())


def _rewrite_manifest_for_current_payload(root: Path) -> None:
    old = FixtureManifest.from_json((root / "fixture.json").read_bytes())
    updated = FixtureManifest.create(
        old.recipe,
        generator_version=old.generator.version,
        entries=artifact_entries_from_tree(root / "artifacts"),
    )
    (root / "fixture.json").write_bytes(updated.canonical_bytes())


@pytest.mark.parametrize("family,expected_files", [("windows", 11), ("macos", 16)])
def test_builds_canonical_answer_free_fixture_and_verifies(tmp_path, family, expected_files):
    root = tmp_path / family
    manifest = build_fixture(_spec(family), root)

    assert sorted(path.name for path in root.iterdir()) == ["artifacts", "fixture.json"]
    assert manifest.payload.file_count == expected_files
    assert (root / "fixture.json").read_bytes() == manifest.canonical_bytes()
    assert b'"benchmark_eligible":false' in manifest.canonical_bytes()
    assert b'"join"' not in manifest.canonical_bytes()
    assert b'"answers"' not in manifest.canonical_bytes()

    result = verify_fixture(root)
    assert result.ok
    assert result.manifest == manifest
    assert result.assurance_summary == {
        "requested": False,
        "verdict": "not-run",
        "gates": [],
    }


def test_same_recipe_is_byte_identical(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    build_fixture(_spec(), first)
    build_fixture(_spec(), second)

    first_paths = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    second_paths = sorted(path.relative_to(second) for path in second.rglob("*") if path.is_file())
    assert first_paths == second_paths
    for relative in first_paths:
        assert (first / relative).read_bytes() == (second / relative).read_bytes(), relative


def test_scene_key_uses_fixture_domain_and_exact_profile(monkeypatch, tmp_path):
    seen = []
    real_builder = operations.build_windows_scene

    def capture(**arguments):
        seen.append((arguments["skey"], arguments["profile"]))
        return real_builder(**arguments)

    monkeypatch.setattr(operations, "build_windows_scene", capture)
    spec = _spec()
    build_fixture(spec, tmp_path / "fixture")

    without_seed = spec.to_mapping()
    seed = bytes.fromhex(without_seed.pop("seed_hex"))
    expected = hmac.new(
        seed,
        b"artifactforge/fixture/scene-key/v1\0" + canonical_json_bytes(without_seed),
        hashlib.sha256,
    ).digest()
    assert seen and {key for key, _profile in seen} == {expected}
    assert expected != suite.scenario_key(seed, spec.fixture_id)
    assert {(profile.os_family, profile.version) for _key, profile in seen} == {
        ("windows", "loose-v1")
    }


@pytest.mark.parametrize("kind", ["file", "directory", "broken-symlink"])
def test_build_refuses_every_lexisting_output(tmp_path, kind):
    output = tmp_path / "fixture"
    if kind == "file":
        output.write_text("keep me")
    elif kind == "directory":
        output.mkdir()
        (output / "keep").write_text("keep me")
    else:
        output.symlink_to(tmp_path / "missing-target")

    with pytest.raises(FixtureUsageError, match="existing fixture output"):
        build_fixture(_spec(), output)
    assert os.path.lexists(output)
    if kind == "file":
        assert output.read_text() == "keep me"
    elif kind == "directory":
        assert (output / "keep").read_text() == "keep me"


def test_destination_race_is_no_replace_and_leaves_racer_untouched(monkeypatch, tmp_path):
    output = tmp_path / "fixture"
    rename_no_replace = operations._rename_no_replace

    def race(source, destination):
        destination.mkdir()
        (destination / "belongs-to-racer").write_text("keep me")
        rename_no_replace(source, destination)

    monkeypatch.setattr(operations, "_rename_no_replace", race)
    with pytest.raises(FixtureUsageError, match="appeared during build"):
        build_fixture(_spec(), output)
    assert sorted(path.name for path in output.iterdir()) == ["belongs-to-racer"]
    assert (output / "belongs-to-racer").read_text() == "keep me"


def test_build_stages_beside_destination(monkeypatch, tmp_path):
    calls = []
    real_mkdtemp = operations.tempfile.mkdtemp

    def capture(*args, **kwargs):
        calls.append(Path(kwargs["dir"]) if kwargs.get("dir") is not None else None)
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(operations.tempfile, "mkdtemp", capture)
    build_fixture(_spec(), tmp_path / "fixture")
    assert calls[0].samefile(tmp_path)
    assert None in calls[1:]


def test_build_does_not_publish_if_internal_reproduction_fails(monkeypatch, tmp_path):
    output = tmp_path / "fixture"
    monkeypatch.setattr(
        operations,
        "_exact_reproduction_differences",
        lambda _left, _right: ["injected byte mismatch"],
    )
    with pytest.raises(FixtureUsageError, match="injected byte mismatch"):
        build_fixture(_spec(), output)
    assert not os.path.lexists(output)


def test_manifest_digest_detects_payload_mutation(tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)
    target = _first_artifact(root)
    target.write_bytes(target.read_bytes() + b"changed")

    result = verify_fixture(root)
    assert not result.ok
    assert any("size mismatch" in failure for failure in result.failures)
    assert any("SHA-256 mismatch" in failure for failure in result.failures)
    assert any("do not reproduce" in failure for failure in result.failures)


def test_reproduction_detects_mutation_even_after_manifest_is_rehashed(tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)
    target = _first_artifact(root)
    data = bytearray(target.read_bytes())
    data[-1] ^= 0x01
    target.write_bytes(data)
    _rewrite_manifest_for_current_payload(root)

    result = verify_fixture(root)
    assert not result.ok
    assert not [failure for failure in result.failures if "manifest" in failure.lower()]
    assert any("do not reproduce" in failure for failure in result.failures)


@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_recursive_inventory_must_be_exact(tmp_path, mutation):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec(), root)
    if mutation == "extra":
        (root / "artifacts" / "extra.bin").write_bytes(b"extra")
        expected = "absent from manifest"
    else:
        (root / "artifacts" / manifest.payload.files[0].path).unlink()
        expected = "missing from disk"

    result = verify_fixture(root)
    assert not result.ok
    assert any(expected in failure for failure in result.failures)


def test_noncanonical_manifest_is_a_verification_failure(tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)
    path = root / "fixture.json"
    path.write_bytes(path.read_bytes().replace(b"{", b"{ ", 1))

    result = verify_fixture(root)
    assert not result.ok
    assert "fixture.json is not canonical ArtifactForge JSON" in result.failures


def test_duplicate_manifest_member_is_malformed_input(tmp_path):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec(), root)
    path = root / "fixture.json"
    duplicate = b'{"schema":"' + manifest.schema.encode() + b'",' + path.read_bytes()[1:]
    path.write_bytes(duplicate)

    with pytest.raises(FixtureUsageError, match="duplicate object member"):
        verify_fixture(root)


def test_manifest_symlink_swap_during_open_is_rejected(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)
    manifest = root / "fixture.json"
    external = tmp_path / "external.json"
    external.write_bytes(manifest.read_bytes())
    real_open = operations.os.open
    swapped = False

    def swap(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and path == "fixture.json" and kwargs.get("dir_fd") is not None:
            swapped = True
            manifest.unlink()
            manifest.symlink_to(external)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(operations.os, "open", swap)
    with pytest.raises(FixtureUsageError, match="safely|changed"):
        verify_fixture(root)
    assert swapped


def test_fixture_root_symlink_swap_never_redirects_verification(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    moved = tmp_path / "original-fixture"
    attacker = tmp_path / "attacker"
    build_fixture(_spec(), root)
    attacker.mkdir()
    exact_compare = operations._exact_reproduction_differences

    def swap_root_after_compare(left, right):
        result = exact_compare(left, right)
        root.rename(moved)
        root.symlink_to(attacker, target_is_directory=True)
        return result

    monkeypatch.setattr(
        operations, "_exact_reproduction_differences", swap_root_after_compare
    )
    with pytest.raises(FixtureUsageError, match="fixture root changed"):
        verify_fixture(root)
    assert root.is_symlink()
    assert moved.joinpath("fixture.json").is_file()


def test_foreign_generator_version_is_unsupported_not_reproduced(tmp_path):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec(), root)
    forged = replace(manifest, generator=GeneratorIdentity(version="999.0.0"))
    (root / "fixture.json").write_bytes(forged.canonical_bytes())

    with pytest.raises(FixtureUsageError, match="unsupported fixture generator version"):
        verify_fixture(root)


def test_post_publish_sync_failure_reports_verified_output_exists(monkeypatch, tmp_path):
    output = tmp_path / "fixture"
    real_fsync_directory = operations._fsync_directory
    calls = 0

    def fail_post_publish(directory):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FixtureUsageError("injected post-rename fsync failure")
        return real_fsync_directory(directory)

    monkeypatch.setattr(operations, "_fsync_directory", fail_post_publish)
    with pytest.raises(FixturePublicationUncertain, match="output exists and verified") as error:
        build_fixture(_spec(), output)
    assert error.value.published is True
    assert error.value.output == output
    assert output.is_dir()
    assert verify_fixture(output).ok


def test_pre_publish_tree_sync_failure_leaves_no_output(monkeypatch, tmp_path):
    output = tmp_path / "fixture"

    def fail_before_publish(_publication):
        raise FixtureUsageError("injected payload sync failure")

    monkeypatch.setattr(operations, "_fsync_tree", fail_before_publish)
    with pytest.raises(FixtureUsageError, match="injected payload sync failure"):
        build_fixture(_spec(), output)
    assert not os.path.lexists(output)


def test_payload_change_after_reproduction_is_rejected_as_a_race(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)
    target = _first_artifact(root)
    exact_compare = operations._exact_reproduction_differences

    def change_after_compare(left, right):
        result = exact_compare(left, right)
        target.write_bytes(target.read_bytes() + b"raced")
        return result

    monkeypatch.setattr(operations, "_exact_reproduction_differences", change_after_compare)
    with pytest.raises(FixtureUsageError, match="payload changed during verification"):
        verify_fixture(root)


def test_symlink_in_payload_is_unsafe_not_a_digest_mismatch(tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)
    target = _first_artifact(root)
    external = tmp_path / "external"
    external.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(external)

    with pytest.raises(FixtureUsageError, match="symlink"):
        verify_fixture(root)


def test_verification_reproduction_uses_caller_neutral_temporary_space(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)
    real_mkdtemp = operations.tempfile.mkdtemp

    def require_no_fixture_parent(*args, **kwargs):
        assert kwargs.get("dir") is None
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(operations.tempfile, "mkdtemp", require_no_fixture_parent)
    assert verify_fixture(root).ok


def test_assurance_runs_only_gates_one_and_three_and_missing_oracle_is_red(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)

    def missing(_path):
        raise ImportError("deliberately absent")

    monkeypatch.setitem(operations.validity.READERS, "pefile", missing)
    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert [report.gate for report in result.assurance_reports] == [1, 3]
    assert result.assurance_ok is False
    assert result.assurance_summary["verdict"] == "fail"
    assert any("not installed" in failure for failure in result.assurance_reports[0].fails)
    assert not result.assurance_reports[0].ok
    assert result.assurance_reports[1].ok
