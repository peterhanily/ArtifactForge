# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Recursive scene paths are canonical, bounded, visible to every gate, and fail closed."""

from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from artifactforge import suite
from artifactforge.bench.benchmark import generate_suite
from artifactforge.compose import scene as scene_module
from artifactforge.fixture.archive import create_release_archive, verify_release_archive
from artifactforge.fixture.model_v2 import FixtureSpecV2, ProfileSpecV2
from artifactforge.fixture.operations import build_fixture, verify_fixture
from artifactforge.gates import identity, inertness, validity
from artifactforge.inventory import (
    InventoryError,
    captured_regular_tree,
    canonical_relative_paths,
    inventory_regular_files,
    validate_relative_path,
)


def _fixture_spec() -> FixtureSpecV2:
    return FixtureSpecV2.create(
        fixture_id="nested-linux-fixture",
        family="linux",
        story="linux-autostart-v1",
        profile=ProfileSpecV2("linux-glibc-x86_64-loose-v2", "linux-01", "v"),
        seed_hex="71" * 32,
    )


def _write_tree(root: Path, files: dict[str, bytes]) -> None:
    for relative, data in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def test_relative_paths_include_dot_components_and_have_one_canonical_order():
    supplied = ("z.bin", ".config/autostart/a.desktop", "A/file", "name:stream")
    assert canonical_relative_paths(supplied) == (
        ".config/autostart/a.desktop",
        "A/file",
        "name:stream",
        "z.bin",
    )
    assert validate_relative_path(".local/share/.state/value") == ".local/share/.state/value"


@pytest.mark.parametrize(
    "path",
    ("", "/absolute", "../escape", "a/../escape", "./a", "a/./b", "a//b", "a/"),
)
def test_relative_path_traversal_and_alias_spellings_are_rejected(path):
    with pytest.raises(InventoryError):
        validate_relative_path(path)


@pytest.mark.parametrize(
    "paths,match",
    (
        (("a", "a"), "duplicate"),
        (("Dir/a", "dir/b"), "case-folding"),
        (("a", "a/b"), "both a file and a directory"),
        (("z", "a"), "sorted"),
    ),
)
def test_canonical_paths_reject_collisions_ancestors_and_noncanonical_input(paths, match):
    with pytest.raises(InventoryError, match=match):
        canonical_relative_paths(paths, require_sorted=True)


def test_recursive_inventory_includes_hidden_files_and_captures_bytes_in_path_order(tmp_path):
    root = tmp_path / "tree"
    _write_tree(
        root,
        {
            "z.bin": b"z",
            ".config/autostart/agent.desktop": b"desktop",
            ".local/share/state.db": b"sqlite-shaped-name-only",
            "nested/a.bin": b"a",
        },
    )

    files = inventory_regular_files(root, capture_bytes=True)
    assert [file.relative_path for file in files] == sorted(
        [
            "z.bin",
            ".config/autostart/agent.desktop",
            ".local/share/state.db",
            "nested/a.bin",
        ]
    )
    assert {file.relative_path: file.data for file in files}[
        ".config/autostart/agent.desktop"
    ] == b"desktop"


def test_recursive_inventory_rejects_linked_roots_entries_and_nonregular_files(tmp_path):
    real = tmp_path / "real"
    _write_tree(real, {"file": b"bytes"})
    linked_root = tmp_path / "linked-root"
    linked_entry = real / "linked-entry"
    try:
        linked_root.symlink_to(real, target_is_directory=True)
        linked_entry.symlink_to(real / "file")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(InventoryError, match="root must not be a symlink"):
        inventory_regular_files(linked_root)
    with pytest.raises(InventoryError, match="contains a symlink"):
        inventory_regular_files(real)

    linked_entry.unlink()
    fifo = real / "pipe"
    try:
        os.mkfifo(fifo)
    except (AttributeError, NotImplementedError, OSError):
        pytest.skip("FIFOs are unavailable on this platform")
    with pytest.raises(InventoryError, match="special file"):
        inventory_regular_files(real)


@pytest.mark.parametrize(
    "files,limits,match",
    (
        ({"a": b"a", "b": b"b"}, {"max_files": 1}, "1-file"),
        ({"large": b"abc"}, {"max_file_bytes": 2}, "2-byte limit"),
        ({"a": b"abc", "b": b"def"}, {"max_total_bytes": 5}, "5-byte total"),
        ({"a/b/c": b"x"}, {"max_depth": 2}, "2-component depth"),
    ),
)
def test_recursive_inventory_enforces_count_size_total_and_depth_caps(
    tmp_path, files, limits, match
):
    root = tmp_path / "tree"
    _write_tree(root, files)
    with pytest.raises(InventoryError, match=match):
        inventory_regular_files(root, **limits)


def test_stage_publishes_nested_hidden_paths_in_canonical_order(tmp_path):
    staging = tmp_path / "staging"
    _write_tree(
        staging,
        {
            "z/file.bin": b"z",
            ".config/autostart/agent.desktop": b"desktop",
            ".cache/.marker": b"marker",
        },
    )
    final = tmp_path / "scene"

    names = suite.stage(
        str(final),
        str(staging),
        ("z/file.bin", ".config/autostart/agent.desktop", ".cache/.marker"),
    )

    assert names == sorted(names)
    assert [file.relative_path for file in inventory_regular_files(final)] == names
    assert (final / ".config" / "autostart" / "agent.desktop").read_bytes() == b"desktop"
    assert not list(tmp_path.glob(".scene.stage-*"))


@pytest.mark.parametrize(
    "allowlist,match",
    (
        ((), "at least one"),
        (("../escape",), "unsafe scene allowlist"),
        (("a", "a/b"), "both a file and a directory"),
        (("Dir/a", "dir/b"), "case-folding"),
    ),
)
def test_stage_rejects_empty_unsafe_or_colliding_allowlists_without_a_final_tree(
    tmp_path, allowlist, match
):
    staging = tmp_path / "staging"
    _write_tree(staging, {"safe": b"safe"})
    final = tmp_path / "scene"
    with pytest.raises(ValueError, match=match):
        suite.stage(str(final), str(staging), allowlist)
    assert not os.path.lexists(final)


def test_stage_refuses_every_preexisting_final_even_when_empty(tmp_path):
    staging = tmp_path / "staging"
    _write_tree(staging, {"safe": b"safe"})
    final = tmp_path / "scene"
    final.mkdir()

    with pytest.raises(ValueError, match="pre-existing"):
        suite.stage(str(final), str(staging), ("safe",))
    assert final.is_dir()
    assert not list(final.iterdir())


def test_stage_failure_is_clean_and_never_exposes_a_partial_final(monkeypatch, tmp_path):
    staging = tmp_path / "staging"
    _write_tree(staging, {"a": b"a", "b": b"b"})
    final = tmp_path / "scene"
    real_write = suite.write_regular_file_at
    calls = 0

    def fail_second(root_fd, relative, data):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise InventoryError("injected mid-stage failure")
        return real_write(root_fd, relative, data)

    monkeypatch.setattr(suite, "write_regular_file_at", fail_second)
    with pytest.raises(InventoryError, match="injected mid-stage failure"):
        suite.stage(str(final), str(staging), ("a", "b"))
    assert calls == 2
    assert not os.path.lexists(final)
    assert not list(tmp_path.glob(".scene.stage-*"))


def test_stage_rejects_linked_or_special_sources_without_publishing(tmp_path):
    staging = tmp_path / "staging"
    _write_tree(staging, {"real": b"bytes"})
    link = staging / "link"
    try:
        link.symlink_to(staging / "real")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    final = tmp_path / "scene"
    with pytest.raises(ValueError, match="symlink"):
        suite.stage(str(final), str(staging), ("link",))
    assert not os.path.lexists(final)


def test_compose_writer_cannot_escape_through_a_linked_root_or_parent(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    linked_root = tmp_path / "linked-staging"
    real_root = tmp_path / "real-staging"
    real_root.mkdir()
    try:
        linked_root.symlink_to(external, target_is_directory=True)
        (real_root / ".config").symlink_to(external, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(InventoryError, match="real directory"):
        scene_module._write(str(linked_root), "escaped", b"no")
    with pytest.raises(InventoryError, match="parent is not a real directory"):
        scene_module._write(str(real_root), ".config/escaped", b"no")
    assert not (external / "escaped").exists()


def test_every_gate_reports_an_unsafe_recursive_entry_instead_of_crashing(tmp_path):
    scene = tmp_path / "scene"
    _write_tree(scene, {"safe": b"plain"})
    try:
        (scene / "linked").symlink_to(scene / "safe")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    reports = (
        validity.run(str(scene)),
        identity.run(str(scene), {"family": "windows"}),
        inertness.run(str(scene)),
    )
    for report in reports:
        assert not report.ok
        assert any("scene inventory is unsafe" in failure for failure in report.fails)


def test_gate_one_path_oracles_receive_only_the_private_snapshot(monkeypatch, tmp_path):
    scene = tmp_path / "scene"
    _write_tree(scene, {".hidden/program.exe": b"MZ" + b"synthetic"})
    seen = []
    observation = validity._PESemantics((), "d41d8cd98f00b204e9800998ecf8427e")

    def reader(source):
        path = Path(source)
        seen.append(path)
        assert scene not in path.parents
        assert path.read_bytes() == b"MZ" + b"synthetic"
        return observation

    monkeypatch.setitem(validity.READERS, "pefile", reader)
    monkeypatch.setitem(validity.READERS, "lief", reader)
    monkeypatch.setitem(validity.SEMANTIC_VALIDATORS, "pe", ())
    report = validity.run(str(scene))

    assert report.ok, report.render()
    assert len(seen) == 2
    assert all("artifactforge-scene-snapshot-" in os.fspath(path) for path in seen)


def test_private_snapshot_is_frozen_and_cleanup_never_follows_a_replacement_link(tmp_path):
    scene = tmp_path / "scene"
    _write_tree(scene, {"nested/value": b"captured"})
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    outside.chmod(0o644)

    try:
        with captured_regular_tree(scene) as files:
            captured = files[0].path
            snapshot_root = next(
                parent
                for parent in captured.parents
                if parent.name.startswith("artifactforge-scene-snapshot-")
            )
            assert stat.S_IMODE(snapshot_root.stat().st_mode) == 0o500
            assert stat.S_IMODE(captured.parent.stat().st_mode) == 0o500
            assert stat.S_IMODE(captured.stat().st_mode) == 0o400

            # Model a same-owner parser deliberately thawing and replacing its private copy.
            # Cleanup must unlink the replacement itself and never chmod its target.
            captured.parent.chmod(0o700)
            captured.unlink()
            captured.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks or descriptor-bound permissions are unavailable")

    assert stat.S_IMODE(outside.stat().st_mode) == 0o644
    assert outside.read_bytes() == b"outside"
    assert not snapshot_root.exists()


def test_stage_rejects_a_symlinked_destination_parent(tmp_path):
    staging = tmp_path / "staging"
    _write_tree(staging, {"safe": b"safe"})
    external = tmp_path / "external"
    external.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(external, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ValueError, match="existing real directory"):
        suite.stage(str(alias / "served"), str(staging), ("safe",))
    assert not (external / "served").exists()


def test_stage_binds_publication_to_the_directory_that_was_verified(monkeypatch, tmp_path):
    staging = tmp_path / "staging"
    _write_tree(staging, {"safe": b"verified"})
    final = tmp_path / "scene"
    real_rename = suite.rename_directory_no_replace

    def swap_before_rename(source, destination, **arguments):
        held = source.with_name(source.name + ".held")
        source.rename(held)
        source.mkdir(mode=0o700)
        (source / "safe").write_bytes(b"unverified")
        try:
            return real_rename(source, destination, **arguments)
        finally:
            if source.exists():
                for child in source.iterdir():
                    child.unlink()
                source.rmdir()
            held.rename(source)

    monkeypatch.setattr(suite, "rename_directory_no_replace", swap_before_rename)
    with pytest.raises(InventoryError, match="source changed after verification"):
        suite.stage(str(final), str(staging), ("safe",))
    assert not os.path.lexists(final)
    assert not list(tmp_path.glob(".scene.stage-*"))


def test_stage_rechecks_published_bytes_and_removes_its_failed_publication(
    monkeypatch, tmp_path
):
    staging = tmp_path / "staging"
    _write_tree(staging, {"safe": b"verified"})
    final = tmp_path / "scene"
    real_rename = suite.rename_directory_no_replace

    def mutate_after_rename(source, destination, **arguments):
        real_rename(source, destination, **arguments)
        (destination / "safe").write_bytes(b"changed-after-verification")

    monkeypatch.setattr(suite, "rename_directory_no_replace", mutate_after_rename)
    with pytest.raises(ValueError, match="changed after verification"):
        suite.stage(str(final), str(staging), ("safe",))
    assert not os.path.lexists(final)


def test_stage_final_verification_reads_the_held_root_not_a_parent_lookalike(
    monkeypatch, tmp_path
):
    staging = tmp_path / "staging"
    _write_tree(staging, {"safe": b"verified"})
    final = tmp_path / "scene"
    real_inventory = suite.inventory_regular_files
    aside = tmp_path.with_name(tmp_path.name + "-held")

    def parent_swap(root, **arguments):
        if Path(root) != final:
            return real_inventory(root, **arguments)

        tmp_path.rename(aside)
        tmp_path.mkdir()
        lookalike = tmp_path / "scene"
        _write_tree(lookalike, {"safe": b"verified"})
        (aside / "scene" / "safe").write_bytes(b"evil")
        try:
            return real_inventory(root, **arguments)
        finally:
            (lookalike / "safe").unlink()
            lookalike.rmdir()
            tmp_path.rmdir()
            aside.rename(tmp_path)

    monkeypatch.setattr(suite, "inventory_regular_files", parent_swap)
    with pytest.raises(ValueError, match="changed after verification"):
        suite.stage(str(final), str(staging), ("safe",))
    assert not os.path.lexists(final)


def test_all_three_gates_follow_nested_hidden_windows_and_macos_artifacts(tmp_path):
    tasks = generate_suite(2, str(tmp_path / "suite"), key=suite.PUBLIC_DEV_KEY)
    for task in tasks:
        root = Path(task.directory)
        original = inventory_regular_files(root)
        nested = root / ".evidence" / "nested"
        nested.mkdir(parents=True)
        for file in original:
            file.path.rename(nested / file.name)
        if task.family == "windows":
            for relation_name in ("scheduled_task", "shell_link"):
                relation = task.join[relation_name]
                relation["source"] = ".evidence/nested/" + relation["source"]
        elif task.family == "macos":
            for relation in task.join["benchmark_relations"]:
                selector = relation["selector"]
                selector["xattr_relative_path"] = (
                    ".evidence/nested/"
                    + selector["xattr_relative_path"].rsplit("/", 1)[-1]
                )

        reports = (
            validity.run(task.directory),
            identity.run(task.directory, task.join),
            inertness.run(task.directory),
        )
        for report in reports:
            assert report.ok, report.render()


def test_fixture_build_verify_and_release_preserve_nested_hidden_relative_paths(tmp_path):
    fixture = tmp_path / "fixture"
    manifest = build_fixture(_fixture_spec(), fixture)

    served_paths = {entry.served_path for entry in manifest.payload.files}
    assert "home/v/.bash_history" in served_paths
    assert any(path.startswith("home/v/.config/autostart/") for path in served_paths)
    assert any(path.startswith("home/v/.local/bin/") for path in served_paths)
    verification = verify_fixture(fixture, assurance=True)
    assert verification.ok
    assert verification.assurance_ok is True

    archive = create_release_archive(fixture, tmp_path / "fixture.tar", assurance=True)
    assert verify_release_archive(archive.path).ok
    assert any("/artifacts/home/v/.config/autostart/" in member for member in archive.members)
    assert any("/artifacts/home/v/.local/bin/" in member for member in archive.members)
