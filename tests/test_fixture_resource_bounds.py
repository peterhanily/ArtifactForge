# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fixture Core applies one finite policy before hostile input materialisation."""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path

import pytest

from artifactforge import __version__
from artifactforge.cli.fixture import _load_spec
from artifactforge.fixture import archive, model, operations, resources
from artifactforge.fixture.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    load_json_strict,
)
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixturePayload,
    FixtureSpec,
    FixtureValidationError,
    GeneratorIdentity,
    artifact_entries_from_tree,
    canonical_artifact_entries,
    compute_tree_sha256,
    validate_artifact_path,
)
from artifactforge.fixture.operations import FixtureUsageError


ROOT = Path(__file__).parents[1]


def _policy(**changes) -> resources.FixtureResourcePolicy:
    return replace(resources.RESOURCE_POLICY, **changes)


def _write_fixture_tree(
    root: Path,
    *,
    declared: dict[str, bytes],
    actual: dict[str, bytes] | None = None,
) -> FixtureManifest:
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True)
    for relative, payload in sorted((actual or declared).items()):
        target = artifacts / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    spec = FixtureSpec.from_json(
        (ROOT / "examples" / "fixtures" / "windows-loose-v1.json").read_bytes()
    )
    entries = tuple(
        ArtifactEntry.from_bytes(relative, payload)
        for relative, payload in sorted(declared.items())
    )
    manifest = FixtureManifest(
        generator=GeneratorIdentity(version=__version__),
        recipe=spec,
        recipe_sha256=spec.recipe_sha256,
        payload=FixturePayload(
            file_count=len(entries),
            total_bytes=sum(entry.size for entry in entries),
            tree_sha256=compute_tree_sha256(entries),
            files=entries,
        ),
    )
    (root / "fixture.json").write_bytes(manifest.canonical_bytes())
    return manifest


def _ustar_header(name: str, *, size: int = 0, typeflag: bytes = b"0") -> bytes:
    header = bytearray(512)
    encoded = name.encode("ascii")
    header[:len(encoded)] = encoded
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = f"{size:011o}\0".encode("ascii")
    header[136:148] = b"00000000000\0"
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    return bytes(header)


def _record_aligned(*headers: bytes) -> bytes:
    payload = b"".join(headers) + b"\0" * 1024
    return payload + b"\0" * ((-len(payload)) % 10240)


def _ustar_member(name: str, data: bytes) -> bytes:
    padding = b"\0" * ((-len(data)) % 512)
    return _ustar_header(name, size=len(data)) + data + padding


def test_shared_policy_is_finite_and_archive_limit_is_derived():
    policy = resources.RESOURCE_POLICY
    assert policy.max_input_bytes == 4 * 1024 * 1024
    assert policy.max_files == 4096
    assert policy.max_members == 8192
    assert policy.max_path_depth == policy.max_json_nesting == 32
    assert policy.max_file_bytes == 64 * 1024 * 1024
    assert policy.max_total_bytes == 256 * 1024 * 1024
    assert policy.max_archive_bytes > policy.max_total_bytes


def test_json_byte_limit_precedes_decoder(monkeypatch):
    monkeypatch.setattr(resources, "RESOURCE_POLICY", _policy(max_input_bytes=8))

    def must_not_decode(*_args, **_kwargs):
        raise AssertionError("oversized JSON reached json.loads")

    monkeypatch.setattr("artifactforge.fixture.canonical.json.loads", must_not_decode)
    with pytest.raises(CanonicalJSONError) as caught:
        load_json_strict(b'{"value":0}')
    assert str(caught.value) == "fixture JSON exceeds the 8-byte input limit"


def test_sparse_spec_path_is_rejected_before_read(monkeypatch, tmp_path):
    path = tmp_path / "spec.json"
    path.touch()
    os.truncate(path, 9)
    monkeypatch.setattr(resources, "RESOURCE_POLICY", _policy(max_input_bytes=8))

    def must_not_read(*_args, **_kwargs):
        raise AssertionError("oversized sparse spec was read")

    monkeypatch.setattr(resources.os, "read", must_not_read)
    with pytest.raises(FixtureUsageError) as caught:
        _load_spec(path)
    assert f"fixture spec {path} exceeds the 8-byte limit" in str(caught.value)


def test_json_nesting_accepts_the_boundary_and_rejects_one_more(monkeypatch):
    monkeypatch.setattr(resources, "RESOURCE_POLICY", _policy(max_json_nesting=4))
    assert load_json_strict(b"[[[[0]]]]") == [[[[0]]]]
    with pytest.raises(CanonicalJSONError) as caught:
        load_json_strict(b"[[[[[0]]]]]")
    assert str(caught.value) == "fixture JSON exceeds the 4-level nesting limit"
    with pytest.raises(CanonicalJSONError, match="4-level nesting"):
        canonical_json_bytes([[[[[0]]]]])


def test_payload_path_depth_accepts_the_boundary_and_rejects_one_more(monkeypatch):
    monkeypatch.setattr(resources, "RESOURCE_POLICY", _policy(max_path_depth=3))
    assert validate_artifact_path("a/b/c") == "a/b/c"
    with pytest.raises(FixtureValidationError) as caught:
        validate_artifact_path("a/b/c/d")
    assert str(caught.value) == (
        "artifact path exceeds the 3-component depth limit: 'a/b/c/d'"
    )


def test_declared_file_and_total_limits_fail_closed(monkeypatch):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=4, max_total_bytes=6),
    )
    with pytest.raises(FixtureValidationError) as caught:
        ArtifactEntry("large.bin", 5, "sha256:" + "0" * 64)
    assert str(caught.value) == (
        "artifact 'large.bin' exceeds the 4-byte per-file limit"
    )

    entries = (
        ArtifactEntry.from_bytes("a", b"aaaa"),
        ArtifactEntry.from_bytes("b", b"bbb"),
    )
    with pytest.raises(FixtureValidationError) as caught:
        canonical_artifact_entries(entries)
    assert str(caught.value) == "artifact files exceed the 6-byte total limit"

    entry = ArtifactEntry.from_bytes("small", b"x")
    valid = FixturePayload(
        file_count=1,
        total_bytes=1,
        tree_sha256=compute_tree_sha256((entry,)),
        files=(entry,),
    ).to_mapping()
    valid["total_bytes"] = 7
    with pytest.raises(FixtureValidationError) as caught:
        FixturePayload.from_mapping(valid)
    assert str(caught.value) == (
        "manifest.payload.total_bytes exceeds the 6-byte total limit"
    )


def test_entry_iteration_stops_at_limit_plus_one(monkeypatch):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_files=2, max_members=4),
    )
    consumed = 0

    def entries():
        nonlocal consumed
        for index in range(100):
            consumed += 1
            yield ArtifactEntry.from_bytes(f"{index:03}.bin", b"")

    with pytest.raises(FixtureValidationError) as caught:
        canonical_artifact_entries(entries())
    assert str(caught.value) == "artifact files exceed the 2-file limit"
    assert consumed == 3


def test_oversized_sparse_payload_is_rejected_without_reading(monkeypatch, tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    oversized = root / "sparse.bin"
    oversized.touch()
    os.truncate(oversized, 17)
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=16, max_total_bytes=32),
    )

    def must_not_read(*_args, **_kwargs):
        raise AssertionError("oversized sparse payload was read")

    monkeypatch.setattr("artifactforge.fixture.model.os.read", must_not_read)
    with pytest.raises(FixtureValidationError) as caught:
        artifact_entries_from_tree(root)
    assert str(caught.value) == (
        "artifact file exceeds the 16-byte limit: 'sparse.bin'"
    )


def test_tree_member_limit_precedes_any_payload_read(monkeypatch, tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    for name in ("a", "b", "c"):
        (root / name).write_bytes(b"x")
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_files=2, max_members=2),
    )

    def must_not_read(*_args, **_kwargs):
        raise AssertionError("over-member tree payload was read")

    monkeypatch.setattr("artifactforge.fixture.model.os.read", must_not_read)
    with pytest.raises(FixtureValidationError) as caught:
        artifact_entries_from_tree(root)
    assert str(caught.value) == "artifact tree exceeds the 2-member limit"


def test_oversized_sparse_archive_is_rejected_before_read(monkeypatch, tmp_path):
    path = tmp_path / "oversized.tar"
    path.touch()
    os.truncate(path, resources.RESOURCE_POLICY.max_archive_bytes + 1)

    def must_not_read(*_args, **_kwargs):
        raise AssertionError("oversized sparse archive was read")

    monkeypatch.setattr("artifactforge.fixture.resources.os.read", must_not_read)
    with pytest.raises(archive.FixtureArchiveError) as caught:
        archive.verify_release_archive(path)
    assert (
        f"release archive {path} exceeds the "
        f"{resources.RESOURCE_POLICY.max_archive_bytes}-byte limit"
    ) in str(caught.value)


def test_stable_path_read_detects_a_file_changed_during_bounded_loop(
    monkeypatch, tmp_path
):
    path = tmp_path / "raced"
    path.write_bytes(b"old")
    real_read = resources.os.read
    changed = False

    def read_then_change(descriptor, size):
        nonlocal changed
        chunk = real_read(descriptor, size)
        if chunk and not changed:
            changed = True
            with path.open("ab") as stream:
                stream.write(b"x")
                stream.flush()
        return chunk

    monkeypatch.setattr(resources.os, "read", read_then_change)
    with pytest.raises(resources.FixtureResourceError) as caught:
        resources.read_stable_regular_path(path, max_bytes=16, label="raced input")
    assert str(caught.value) == "raced input changed while it was being read"
    assert changed


def test_stable_reader_does_not_probe_past_the_opened_size(monkeypatch, tmp_path):
    path = tmp_path / "exact-boundary"
    path.write_bytes(b"1234")
    real_read = resources.os.read
    requests: list[int] = []

    def bounded_read(descriptor, size):
        requests.append(size)
        return real_read(descriptor, size)

    monkeypatch.setattr(resources.os, "read", bounded_read)
    assert resources.read_stable_regular_path(
        path, max_bytes=4, label="exact boundary"
    ) == b"1234"
    assert requests == [4]


def test_archive_snapshot_caps_actual_cumulative_bytes_before_retaining_file(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=8, max_total_bytes=5),
    )
    root = tmp_path / "fixture"
    _write_fixture_tree(
        root,
        declared={"a": b"aaa", "b": b"bb"},
        actual={"a": b"aaa", "b": b"bbbb"},
    )
    real_read = archive._read_regular_at
    payload_limits: list[tuple[str, int]] = []

    def recording_read(parent_fd, name, display, *, max_bytes):
        if name != archive.MANIFEST_NAME:
            payload_limits.append((name, max_bytes))
        return real_read(parent_fd, name, display, max_bytes=max_bytes)

    monkeypatch.setattr(archive, "_read_regular_at", recording_read)
    with pytest.raises(archive.FixtureArchiveError, match="exceeds the 2-byte limit"):
        archive._snapshot_fixture(root)
    assert payload_limits == [("a", 5), ("b", 2)]


@pytest.mark.parametrize(
    ("actual_first", "reason"),
    ((b"new", "sha256"), (b"long", "size 4")),
)
def test_archive_snapshot_aborts_on_first_member_mismatch(
    monkeypatch, tmp_path, actual_first, reason
):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=8, max_total_bytes=8),
    )
    root = tmp_path / "fixture"
    _write_fixture_tree(
        root,
        declared={"a": b"old", "b": b"bb"},
        actual={"a": actual_first, "b": b"bb"},
    )
    real_read = archive._read_regular_at
    payload_reads: list[str] = []

    def recording_read(parent_fd, name, display, *, max_bytes):
        if name != archive.MANIFEST_NAME:
            payload_reads.append(name)
        return real_read(parent_fd, name, display, max_bytes=max_bytes)

    monkeypatch.setattr(archive, "_read_regular_at", recording_read)
    with pytest.raises(archive.FixtureArchiveMismatch, match=f"a: {reason}"):
        archive._snapshot_fixture(root)
    assert payload_reads == ["a"]


def test_snapshot_budgets_stable_actual_bytes_and_rejects_stat_open_growth(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=8, max_total_bytes=5),
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "a").write_bytes(b"aaa")
    raced = source / "b"
    raced.write_bytes(b"bb")
    destination = tmp_path / "snapshot"
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    budget = operations._SnapshotBudget()
    real_read = operations._read_regular_at
    changed = False

    def grow_before_open(parent_descriptor, name, where, *, max_bytes=None):
        nonlocal changed
        if name == "b" and not changed:
            changed = True
            with raced.open("ab") as stream:
                stream.write(b"xx")
                stream.flush()
        return real_read(
            parent_descriptor, name, where, max_bytes=max_bytes
        )

    monkeypatch.setattr(operations, "_read_regular_at", grow_before_open)
    try:
        with pytest.raises(FixtureUsageError, match="exceeds the 2-byte limit"):
            operations._snapshot_directory_at(
                descriptor, destination, budget=budget
            )
    finally:
        os.close(descriptor)
    assert changed
    assert budget.total_bytes == 3
    assert sum(path.stat().st_size for path in destination.iterdir()) == 3


def test_snapshot_binds_outer_stat_to_the_stable_read(monkeypatch, tmp_path):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=8, max_total_bytes=8),
    )
    source = tmp_path / "source"
    source.mkdir()
    raced = source / "a"
    raced.write_bytes(b"old")
    destination = tmp_path / "snapshot"
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    real_read = operations._read_regular_at
    changed = False

    def replace_in_place_before_open(parent_descriptor, name, where, *, max_bytes=None):
        nonlocal changed
        if not changed:
            changed = True
            with raced.open("r+b") as stream:
                stream.write(b"new")
                stream.flush()
                os.fsync(stream.fileno())
        return real_read(
            parent_descriptor, name, where, max_bytes=max_bytes
        )

    monkeypatch.setattr(operations, "_read_regular_at", replace_in_place_before_open)
    try:
        with pytest.raises(
            FixtureUsageError, match="file changed while snapshotting: 'a'"
        ):
            operations._snapshot_directory_at(descriptor, destination)
    finally:
        os.close(descriptor)
    assert changed
    assert not (destination / "a").exists()


def test_tree_inventory_binds_full_state_across_stat_open_gap(monkeypatch, tmp_path):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=8, max_total_bytes=5),
    )
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "a").write_bytes(b"aaa")
    raced = root / "b"
    raced.write_bytes(b"bb")
    real_open = model.os.open
    changed = False

    def grow_between_stat_and_open(path, flags, *args, **kwargs):
        nonlocal changed
        if path == "b" and kwargs.get("dir_fd") is not None and not changed:
            changed = True
            writer = real_open(raced, os.O_WRONLY | os.O_APPEND)
            try:
                os.write(writer, b"xx")
            finally:
                os.close(writer)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(model.os, "open", grow_between_stat_and_open)
    with pytest.raises(FixtureValidationError, match="path changed while inventorying: 'b'"):
        artifact_entries_from_tree(root)
    assert changed


def test_tree_inventory_rejects_a_mixed_sibling_epoch(monkeypatch, tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "a").write_bytes(b"old-a")
    (root / "b").write_bytes(b"old-b")
    real_stat = model.os.stat
    changed = False

    def change_siblings_after_a_final_stat(path, *args, **kwargs):
        nonlocal changed
        result = real_stat(path, *args, **kwargs)
        if (
            path == "a"
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
            and not changed
        ):
            changed = True
            (root / "a").write_bytes(b"new-a")
            (root / "b").write_bytes(b"new-b")
        return result

    monkeypatch.setattr(model.os, "stat", change_siblings_after_a_final_stat)
    with pytest.raises(
        FixtureValidationError, match="file changed after inventorying: 'a'"
    ):
        artifact_entries_from_tree(root)
    assert changed


def test_tree_inventory_rejects_content_toggled_back_before_revalidation(
    monkeypatch, tmp_path
):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "a").write_bytes(b"old-a")
    (root / "b").write_bytes(b"old-b")
    real_stat = model.os.stat
    changed = False

    def toggle_a_and_change_b_after_a_final_stat(path, *args, **kwargs):
        nonlocal changed
        result = real_stat(path, *args, **kwargs)
        if (
            path == "a"
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
            and not changed
        ):
            changed = True
            (root / "a").write_bytes(b"new-a")
            (root / "a").write_bytes(b"old-a")
            (root / "b").write_bytes(b"new-b")
        return result

    monkeypatch.setattr(model.os, "stat", toggle_a_and_change_b_after_a_final_stat)
    with pytest.raises(
        FixtureValidationError, match="file changed after inventorying: 'a'"
    ):
        artifact_entries_from_tree(root)
    assert (root / "a").read_bytes() == b"old-a"
    assert changed


def test_snapshot_rejects_a_mixed_sibling_epoch(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a").write_bytes(b"old-a")
    (source / "b").write_bytes(b"old-b")
    destination = tmp_path / "snapshot"
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    real_stat = operations.os.stat
    a_stats = 0

    def change_siblings_after_a_final_stat(path, *args, **kwargs):
        nonlocal a_stats
        result = real_stat(path, *args, **kwargs)
        if (
            path == "a"
            and kwargs.get("dir_fd") == descriptor
            and kwargs.get("follow_symlinks") is False
        ):
            a_stats += 1
            # Outer stat, stable-reader pre/post stats, then the snapshot's final path stat.
            if a_stats == 4:
                (source / "a").write_bytes(b"new-a")
                (source / "b").write_bytes(b"new-b")
        return result

    monkeypatch.setattr(operations.os, "stat", change_siblings_after_a_final_stat)
    try:
        with pytest.raises(
            FixtureUsageError, match="file changed after snapshotting: 'a'"
        ):
            operations._snapshot_directory_at(descriptor, destination)
    finally:
        os.close(descriptor)
    assert (destination / "a").read_bytes() == b"old-a"
    assert (destination / "b").read_bytes() == b"new-b"
    assert a_stats >= 5


def test_snapshot_reduced_budget_normal_boundary(monkeypatch, tmp_path):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=4, max_total_bytes=5),
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "a").write_bytes(b"aaa")
    (source / "b").write_bytes(b"bb")
    destination = tmp_path / "snapshot"
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    budget = operations._SnapshotBudget()
    try:
        operations._snapshot_directory_at(descriptor, destination, budget=budget)
    finally:
        os.close(descriptor)
    assert budget.files == 2
    assert budget.total_bytes == 5
    assert (destination / "a").read_bytes() == b"aaa"
    assert (destination / "b").read_bytes() == b"bb"


def test_archive_header_size_is_bounded_before_tar_parser(monkeypatch, tmp_path):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_file_bytes=16, max_total_bytes=32),
    )
    path = tmp_path / "declared-large.tar"
    path.write_bytes(_record_aligned(
        _ustar_header("fixture/artifacts/large.bin", size=17)
    ))

    def must_not_parse(*_args, **_kwargs):
        raise AssertionError("oversized member reached tarfile")

    monkeypatch.setattr(archive.tarfile, "open", must_not_parse)
    with pytest.raises(archive.FixtureArchiveError) as caught:
        archive.verify_release_archive(path)
    assert str(caught.value) == (
        "archive member 'fixture/artifacts/large.bin' exceeds the 16-byte limit"
    )


def test_archive_header_count_is_bounded_before_tar_parser(monkeypatch, tmp_path):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_files=1, max_members=2),
    )
    path = tmp_path / "too-many.tar"
    path.write_bytes(_record_aligned(
        _ustar_header("fixture/", typeflag=b"5"),
        _ustar_header("fixture/artifacts/", typeflag=b"5"),
        _ustar_header("fixture/artifacts/extra/", typeflag=b"5"),
    ))

    def must_not_parse(*_args, **_kwargs):
        raise AssertionError("over-member archive reached tarfile")

    monkeypatch.setattr(archive.tarfile, "open", must_not_parse)
    with pytest.raises(archive.FixtureArchiveError) as caught:
        archive.verify_release_archive(path)
    assert str(caught.value) == "archive exceeds the 2-member limit"


def test_archive_extension_header_is_rejected_before_tar_parser(monkeypatch, tmp_path):
    path = tmp_path / "pax.tar"
    path.write_bytes(_record_aligned(
        _ustar_header("fixture/pax", typeflag=b"x"),
    ))

    def must_not_parse(*_args, **_kwargs):
        raise AssertionError("extension member reached tarfile")

    monkeypatch.setattr(archive.tarfile, "open", must_not_parse)
    with pytest.raises(archive.FixtureArchiveError) as caught:
        archive.verify_release_archive(path)
    assert str(caught.value) == (
        "archive contains an extension, link, or special member header"
    )


def test_archive_declared_total_is_bounded_before_tar_parser(monkeypatch, tmp_path):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(
            max_input_bytes=4,
            max_files=2,
            max_members=4,
            max_file_bytes=4,
            max_total_bytes=6,
        ),
    )
    raw = _ustar_member("fixture/artifacts/a", b"aaaa")
    raw += _ustar_member("fixture/artifacts/b", b"bbbb")
    raw += b"\0" * 1024
    path = tmp_path / "over-total.tar"
    path.write_bytes(raw + b"\0" * ((-len(raw)) % 10240))

    def must_not_parse(*_args, **_kwargs):
        raise AssertionError("over-total archive reached tarfile")

    monkeypatch.setattr(archive.tarfile, "open", must_not_parse)
    with pytest.raises(archive.FixtureArchiveError) as caught:
        archive.verify_release_archive(path)
    assert str(caught.value) == (
        "archive payload members exceed the 6-byte total limit"
    )


def test_archive_member_path_depth_is_bounded_before_tar_parser(monkeypatch, tmp_path):
    monkeypatch.setattr(
        resources,
        "RESOURCE_POLICY",
        _policy(max_path_depth=1),
    )
    path = tmp_path / "too-deep.tar"
    path.write_bytes(_record_aligned(
        _ustar_header("fixture/artifacts/nested/file", typeflag=b"5")
    ))

    def must_not_parse(*_args, **_kwargs):
        raise AssertionError("over-depth archive reached tarfile")

    monkeypatch.setattr(archive.tarfile, "open", must_not_parse)
    with pytest.raises(archive.FixtureArchiveError) as caught:
        archive.verify_release_archive(path)
    assert str(caught.value) == (
        "archive member path exceeds the 3-component depth limit: "
        "'fixture/artifacts/nested/file'"
    )
