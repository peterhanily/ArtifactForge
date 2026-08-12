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
from artifactforge.compose.derivation import FIXTURE_V2_SCENE_DERIVATION
from artifactforge.fixture import operations
from artifactforge.fixture.abi import GENERATOR_ABI_V1
from artifactforge.fixture.canonical import canonical_json_bytes
from artifactforge.fixture.model_v2 import (
    SCENE_KEY_DOMAIN_V2,
    FileNodeV2,
    FixtureManifestV2,
    FixturePayloadV2,
    FixtureSpecV2,
    GeneratorIdentityV2,
    LinuxMetadataV2,
    ProfileSpecV2,
)
from artifactforge.fixture.operations import (
    FixturePublicationUncertain,
    FixtureUsageError,
    build_fixture,
    verify_fixture,
)


_STORY_IDS = {
    "windows": "windows-dropper-v1",
    "macos": "macos-quarantined-app-v1",
    "linux": "linux-autostart-v1",
}


def _spec(family: str = "windows") -> FixtureSpecV2:
    if family == "windows":
        profile = ProfileSpecV2("windows-loose-v2", "WKSTN-01", "v")
        fixture_id = "windows-fixture-001"
        seed_hex = "01" * 32
    elif family == "macos":
        profile = ProfileSpecV2("macos-14-loose-v2", "mac-01", "v")
        fixture_id = "macos-fixture-001"
        seed_hex = "02" * 32
    elif family == "linux":
        profile = ProfileSpecV2("linux-glibc-x86_64-loose-v2", "linux-01", "v")
        fixture_id = "linux-autostart-001"
        seed_hex = "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
    else:
        raise AssertionError(f"unsupported test family: {family}")
    return FixtureSpecV2.create(
        fixture_id=fixture_id,
        family=family,
        story=_STORY_IDS[family],
        profile=profile,
        seed_hex=seed_hex,
    )


def _first_artifact(root: Path) -> Path:
    return next(path for path in sorted((root / "artifacts").rglob("*")) if path.is_file())


def _rewrite_manifest_for_current_payload(root: Path) -> None:
    old = FixtureManifestV2.from_json((root / "fixture.json").read_bytes())
    files = tuple(
        FileNodeV2.from_bytes(
            guest_path=node.guest_path,
            served_path=node.served_path,
            data=(root / "artifacts" / node.served_path).read_bytes(),
            metadata=node.metadata,
        )
        for node in old.payload.files
    )
    updated = FixtureManifestV2.create(
        generator_version=old.generator.version,
        recipe=old.recipe,
        payload=FixturePayloadV2.create(
            family=old.payload.family,
            directories=old.payload.directories,
            files=files,
        ),
    )
    (root / "fixture.json").write_bytes(updated.canonical_bytes())


@pytest.mark.parametrize(
    ("family", "expected_files"),
    [("windows", 14), ("macos", 11), ("linux", 9)],
)
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

    if family == "linux":
        assert b"answer" not in manifest.canonical_bytes().lower()
        assert b"join" not in manifest.canonical_bytes().lower()
        assert b'"mode"' in manifest.canonical_bytes()
        assert all(
            set(entry.to_mapping())
            == {"guest_path", "served_path", "size", "sha256", "metadata"}
            for entry in manifest.payload.files
        )
        served_paths = tuple(entry.served_path for entry in manifest.payload.files)
        assert served_paths == (
            "home/v/.bash_history",
            "home/v/.config/autostart/artifactforge-1-session-helper.desktop",
            "home/v/.config/autostart/artifactforge-2-thumbnail-helper.desktop",
            "home/v/.config/autostart/artifactforge-3-cloud-watch.desktop",
            "home/v/.local/bin/cloud-watch",
            "home/v/.local/bin/search-index",
            "home/v/.local/bin/session-check",
            "home/v/.local/bin/session-helper",
            "home/v/.local/bin/thumbnail-helper",
        )
        assert tuple(entry.guest_path for entry in manifest.payload.files) == tuple(
            "/" + path for path in served_paths
        )
        assert tuple(directory.guest_path for directory in manifest.payload.directories) == tuple(
            "/" + directory.served_path for directory in manifest.payload.directories
        )
        assert all(
            isinstance(directory.metadata, LinuxMetadataV2)
            and directory.metadata.mode == 0o755
            for directory in manifest.payload.directories
        )
        for entry in manifest.payload.files:
            assert isinstance(entry.metadata, LinuxMetadataV2)
            if entry.served_path.endswith("/.bash_history"):
                assert entry.metadata.mode == 0o600
            elif "/.config/autostart/" in entry.served_path:
                assert entry.metadata.mode == 0o644
            else:
                assert entry.metadata.mode == 0o755
            if os.name != "nt":
                carrier = root / "artifacts" / entry.served_path
                assert carrier.stat().st_mode & 0o777 == 0o600
        if os.name != "nt":
            assert all(
                (root / "artifacts" / directory.served_path).stat().st_mode & 0o777
                == 0o700
                for directory in manifest.payload.directories
            )


@pytest.mark.parametrize("family", ["windows", "macos", "linux"])
def test_same_recipe_is_byte_identical(tmp_path, family):
    first, second = tmp_path / "first", tmp_path / "second"
    build_fixture(_spec(family), first)
    build_fixture(_spec(family), second)

    first_paths = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    second_paths = sorted(path.relative_to(second) for path in second.rglob("*") if path.is_file())
    assert first_paths == second_paths
    for relative in first_paths:
        assert (first / relative).read_bytes() == (second / relative).read_bytes(), relative


def test_scene_key_uses_fixture_domain_and_exact_profile(monkeypatch, tmp_path):
    seen = []
    real_builder = operations.build_windows_scene

    def capture(**arguments):
        seen.append(
            (
                arguments["skey"],
                arguments["profile"],
                arguments["causal_clock"],
                arguments["derivation"],
            )
        )
        return real_builder(**arguments)

    monkeypatch.setattr(operations, "build_windows_scene", capture)
    spec = _spec()
    build_fixture(spec, tmp_path / "fixture")

    without_seed = spec.to_mapping()
    seed = bytes.fromhex(without_seed.pop("seed_hex"))
    expected = hmac.new(
        seed,
        SCENE_KEY_DOMAIN_V2 + canonical_json_bytes(without_seed),
        hashlib.sha256,
    ).digest()
    assert len(seen) == 2
    assert {key for key, _profile, _clock, _derivation in seen} == {expected}
    assert expected != suite.scenario_key(seed, spec.fixture_id)
    assert {
        (profile.os_family, profile.version)
        for _key, profile, _clock, _derivation in seen
    } == {
        ("windows", "loose-v2")
    }
    assert {clock for _key, _profile, clock, _derivation in seen} == {
        spec.causal_clock
    }
    assert {derivation for _key, _profile, _clock, derivation in seen} == {
        FIXTURE_V2_SCENE_DERIVATION
    }


def test_linux_fixture_dispatches_the_exact_glibc_x86_64_profile(monkeypatch, tmp_path):
    seen = []
    real_builder = operations.build_linux_scene

    def capture(**arguments):
        seen.append(arguments["profile"])
        return real_builder(**arguments)

    monkeypatch.setattr(operations, "build_linux_scene", capture)
    build_fixture(_spec("linux"), tmp_path / "fixture")

    assert [(profile.os_family, profile.version) for profile in seen] == [
        ("linux", "glibc-x86_64"),
        ("linux", "glibc-x86_64"),
    ]


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
        lambda _left, _right, **_kwargs: ["injected byte mismatch"],
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
    assert result.integrity_ok
    assert result.integrity_failures == ()
    assert result.reproduction_ok is False
    assert any("do not reproduce" in failure for failure in result.failures)
    assert any(
        "complete logical fixture manifest" in failure
        for failure in result.reproduction_failures
    )


@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_recursive_inventory_must_be_exact(tmp_path, mutation):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec(), root)
    if mutation == "extra":
        extra = root / "artifacts" / "extra.bin"
        extra.write_bytes(b"extra")
        extra.chmod(0o600)
        expected = "absent from manifest"
    else:
        (root / "artifacts" / manifest.payload.files[0].served_path).unlink()
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

    def swap_root_after_compare(left, right, **kwargs):
        result = exact_compare(left, right, **kwargs)
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


def test_foreign_v2_generator_version_is_provenance_and_reproduces(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec(), root)
    foreign = replace(manifest, generator=GeneratorIdentityV2(version="999.0.0"))
    (root / "fixture.json").write_bytes(foreign.canonical_bytes())
    real_materialise = operations._materialise_publication
    reproduced: list[str] = []

    def recording_materialise(spec, publication, work):
        reproduced.append(spec.fixture_id)
        return real_materialise(spec, publication, work)

    monkeypatch.setattr(operations, "_materialise_publication", recording_materialise)
    result = verify_fixture(root)

    assert result.ok
    assert result.reproduction_ok is True
    assert result.manifest.generator.version == "999.0.0"
    assert reproduced == [manifest.recipe.fixture_id]


def test_incompatible_generator_abi_is_rejected_before_reproduction(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    manifest = build_fixture(_spec(), root)
    mapping = manifest.to_mapping()
    generator = mapping["generator"]
    assert isinstance(generator, dict)
    generator["abi"] = GENERATOR_ABI_V1
    (root / "fixture.json").write_bytes(canonical_json_bytes(mapping))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("incompatible ABI reached fixture reproduction")

    monkeypatch.setattr(operations, "_materialise_publication", forbidden)
    with pytest.raises(FixtureUsageError, match="manifest.generator.abi"):
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

    def change_after_compare(left, right, **kwargs):
        result = exact_compare(left, right, **kwargs)
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
        raise ModuleNotFoundError("No module named 'pefile'", name="pefile")

    monkeypatch.setitem(operations.validity.READERS, "pefile", missing)
    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert [report.gate for report in result.assurance_reports] == [1, 3]
    assert result.assurance_ok is False
    assert result.assurance_summary["verdict"] == "fail"
    assert any("not installed" in failure for failure in result.assurance_reports[0].fails)
    assert not result.assurance_reports[0].ok
    assert result.assurance_reports[1].ok


@pytest.mark.parametrize("failure_kind", ("transitive-module", "generic-import"))
def test_assurance_does_not_mislabel_broken_parser_as_absent(
    monkeypatch, tmp_path, failure_kind
):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)

    def broken(_path):
        if failure_kind == "transitive-module":
            raise ModuleNotFoundError(
                "No module named 'pefile_support'", name="pefile_support"
            )
        raise ImportError("pefile ABI is incompatible")

    monkeypatch.setitem(operations.validity.READERS, "pefile", broken)
    result = verify_fixture(root, assurance=True)

    gate1 = result.assurance_reports[0]
    matching = [failure for failure in gate1.fails if "pefile" in failure]
    assert matching
    assert all("oracle 'pefile' is not installed" not in failure for failure in matching)
    assert any("pefile rejected it" in failure for failure in matching)


def test_assurance_missing_pe_safety_oracle_is_red_not_an_exception(monkeypatch, tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)

    def missing(_data):
        raise ModuleNotFoundError("No module named 'pefile'", name="pefile")

    monkeypatch.setattr(operations.inertness, "_pe_code_is_inert", missing)
    result = verify_fixture(root, assurance=True)

    assert not result.ok
    assert [report.gate for report in result.assurance_reports] == [1, 3]
    gate3 = result.assurance_reports[1]
    assert not gate3.ok
    assert gate3.metrics["binary_safety_checks_passed"] == 0
    assert gate3.metrics["binary_safety_checks_total"] == 5
    assert any(
        "PE binary-safety oracle 'pefile' is not installed" in failure
        and "failure, not a skip" in failure
        for failure in gate3.fails
    )


@pytest.mark.parametrize("failure_kind", ("transitive-module", "generic-import"))
def test_assurance_does_not_mislabel_broken_pe_safety_oracle_as_absent(
    monkeypatch, tmp_path, failure_kind
):
    root = tmp_path / "fixture"
    build_fixture(_spec(), root)

    def broken(_data):
        if failure_kind == "transitive-module":
            raise ModuleNotFoundError(
                "No module named 'pefile_support'", name="pefile_support"
            )
        raise ImportError("pefile ABI is incompatible")

    monkeypatch.setattr(operations.inertness, "_pe_code_is_inert", broken)
    result = verify_fixture(root, assurance=True)

    gate3 = result.assurance_reports[1]
    matching = [failure for failure in gate3.fails if "PE binary-safety oracle" in failure]
    assert matching
    assert all("is not installed" not in failure for failure in matching)
    assert all("failed" in failure for failure in matching)


def test_linux_fixture_assurance_runs_only_gates_one_and_three_and_passes(tmp_path):
    root = tmp_path / "fixture"
    build_fixture(_spec("linux"), root)

    result = verify_fixture(root, assurance=True)

    assert result.ok
    assert [report.gate for report in result.assurance_reports] == [1, 3]
    assert result.assurance_ok is True
    assert result.assurance_summary["verdict"] == "pass"
