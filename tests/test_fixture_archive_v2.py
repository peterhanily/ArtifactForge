# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Release archives preserve v2 logical trees without projecting guest metadata."""
from __future__ import annotations

from dataclasses import replace
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tarfile

import pytest

from artifactforge.fixture import archive
from artifactforge.fixture.causal import NANOSECONDS_PER_SECOND
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixturePayload,
    FixtureSpec,
    GeneratorIdentity,
    compute_tree_sha256,
)
from artifactforge.fixture.model_v2 import (
    DirectoryNodeV2,
    FileNodeV2,
    FixtureManifestV2,
    FixturePayloadV2,
    FixtureSpecV2,
    LinuxMetadataV2,
    ProfileSpecV2,
)
from artifactforge.fixture.operations import build_fixture, verify_fixture


ROOT = Path(__file__).parents[1]
V1_SPEC = ROOT / "examples" / "fixtures" / "linux-glibc-x86_64-loose-v1.json"
DEFAULT_BYTES = b"resident default stream\n"
SERVED_FILE = "home/v/.local/bin/tool"


def _linux_metadata(*, mode: int, uid: int = 1000) -> LinuxMetadataV2:
    timestamp = 1_705_294_800 * NANOSECONDS_PER_SECOND
    return LinuxMetadataV2(
        mode=mode,
        uid=uid,
        gid=1000,
        atime_unix_ns=timestamp,
        mtime_unix_ns=timestamp + NANOSECONDS_PER_SECOND,
        ctime_unix_ns=timestamp + 2 * NANOSECONDS_PER_SECOND,
    )


def _v2_manifest(
    *, file_mode: int = 0o755, directory_mode: int = 0o700
) -> FixtureManifestV2:
    spec = FixtureSpecV2.create(
        fixture_id="archive-v2",
        family="linux",
        profile=ProfileSpecV2(
            id="linux-glibc-x86_64-loose-v2",
            hostname="linux-01",
            username="v",
        ),
        seed_hex="5a" * 32,
    )
    directory_paths = ("home", "home/v", "home/v/.local", "home/v/.local/bin")
    directories = tuple(
        DirectoryNodeV2(
            guest_path="/" + path,
            served_path=path,
            metadata=_linux_metadata(mode=directory_mode),
        )
        for path in directory_paths
    )
    file_node = FileNodeV2.from_bytes(
        guest_path="/" + SERVED_FILE,
        served_path=SERVED_FILE,
        data=DEFAULT_BYTES,
        metadata=_linux_metadata(mode=file_mode),
    )
    return FixtureManifestV2.create(
        generator_version="0.6.0.dev0",
        recipe=spec,
        payload=FixturePayloadV2.create(
            family="linux", directories=directories, files=(file_node,)
        ),
    )


def _snapshot_for(manifest: FixtureManifestV2) -> archive._FixtureSnapshot:
    directories = (
        "artifacts/",
        *(f"artifacts/{node.served_path}/" for node in manifest.payload.directories),
    )
    files = (
        ("fixture.json", manifest.canonical_bytes()),
        (f"artifacts/{SERVED_FILE}", DEFAULT_BYTES),
    )
    return archive._FixtureSnapshot(
        root=Path("."),
        directories=tuple(sorted(directories)),
        files=tuple(sorted(files)),
        manifest=manifest,
    )


def _materialize(root: Path, manifest: FixtureManifestV2) -> None:
    resident = root / "artifacts" / SERVED_FILE
    resident.parent.mkdir(parents=True)
    resident.write_bytes(DEFAULT_BYTES)
    (root / "fixture.json").write_bytes(manifest.canonical_bytes())
    if os.name != "nt":
        root.chmod(0o700)
        (root / "artifacts").chmod(0o700)
        for node in manifest.payload.directories:
            (root / "artifacts" / node.served_path).chmod(0o700)
        resident.chmod(0o600)
        (root / "fixture.json").chmod(0o600)


def test_v2_snapshot_uses_served_paths_and_exact_explicit_directories(tmp_path):
    manifest = _v2_manifest()
    root = tmp_path / "fixture"
    _materialize(root, manifest)

    snapshot = archive._snapshot_fixture(root)

    assert snapshot.manifest == manifest
    assert snapshot.directories == _snapshot_for(manifest).directories
    assert dict(snapshot.files)[f"artifacts/{SERVED_FILE}"] == DEFAULT_BYTES

    (root / "artifacts" / "undeclared-empty").mkdir()
    with pytest.raises(archive.FixtureArchiveError, match="inventory|exceeds"):
        archive._snapshot_fixture(root)


def test_v2_logical_metadata_binds_archive_bytes_but_never_ustar_metadata():
    executable = _v2_manifest(file_mode=0o755, directory_mode=0o700)
    private = _v2_manifest(file_mode=0o600, directory_mode=0o711)
    executable_archive = archive._canonical_archive_bytes(_snapshot_for(executable))
    private_archive = archive._canonical_archive_bytes(_snapshot_for(private))

    assert executable.payload.tree_sha256 != private.payload.tree_sha256
    assert executable.canonical_bytes() != private.canonical_bytes()
    assert executable_archive != private_archive

    for payload in (executable_archive, private_archive):
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as bundle:
            members = bundle.getmembers()
        assert all(member.uid == member.gid == member.mtime == 0 for member in members)
        assert all(member.uname == member.gname == "" for member in members)
        assert all(member.mode == (0o755 if member.isdir() else 0o644) for member in members)
        assert all(not member.pax_headers for member in members)
        resident = next(member for member in members if member.name.endswith(SERVED_FILE))
        assert resident.mode == 0o644


@pytest.mark.skipif(os.name == "nt", reason="POSIX carrier-mode contract")
def test_v2_private_reconstruction_modes_are_exact_under_hostile_umask(tmp_path):
    snapshot = _snapshot_for(_v2_manifest(file_mode=0o755, directory_mode=0o711))
    destination = tmp_path / "reconstructed"
    previous_umask = os.umask(0o777)
    try:
        archive._materialize_snapshot(snapshot, destination)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE((destination / relative).stat().st_mode) == 0o700
        for relative in snapshot.directories
    )
    assert all(
        stat.S_IMODE((destination / relative).stat().st_mode) == 0o600
        for relative, _data in snapshot.files
    )


@pytest.mark.parametrize("directory_change", ("missing", "extra"))
def test_v2_archive_verifier_rejects_directory_set_not_declared_by_manifest(
    tmp_path, monkeypatch, directory_change
):
    manifest = _v2_manifest()
    snapshot = _snapshot_for(manifest)
    directories = set(snapshot.directories)
    if directory_change == "missing":
        directories.remove("artifacts/home/v/.local/bin/")
    else:
        directories.add("artifacts/undeclared-empty/")
    malformed = replace(snapshot, directories=tuple(sorted(directories)))
    output = tmp_path / f"{directory_change}.tar"
    output.write_bytes(archive._canonical_archive_bytes(malformed))

    monkeypatch.setattr(archive, "require_supported_manifest", lambda _manifest: None)
    monkeypatch.setattr(
        archive,
        "_verify_snapshot",
        lambda _snapshot, *, assurance=False: SimpleNamespace(ok=True, failures=()),
    )
    result = archive.verify_release_archive(output)

    assert not result.ok
    assert result.manifest == manifest
    assert "archive directory members differ" in "\n".join(result.failures)


def test_v2_archive_verifier_reconstructs_the_exact_declared_tree(tmp_path, monkeypatch):
    manifest = _v2_manifest()
    output = tmp_path / "fixture.tar"
    output.write_bytes(archive._canonical_archive_bytes(_snapshot_for(manifest)))
    reproduced: list[tuple[str, ...]] = []

    monkeypatch.setattr(archive, "require_supported_manifest", lambda _manifest: None)

    def accept(snapshot, *, assurance=False):
        assert assurance is False
        reproduced.append(snapshot.directories)
        return SimpleNamespace(ok=True, failures=())

    monkeypatch.setattr(archive, "_verify_snapshot", accept)
    result = archive.verify_release_archive(output)

    assert result.ok
    assert result.manifest == manifest
    assert reproduced == [_snapshot_for(manifest).directories]


def test_v2_release_runs_build_reproduction_publication_and_archive_verification(tmp_path):
    spec = _v2_manifest().recipe
    fixture = tmp_path / "fixture"
    manifest = build_fixture(spec, fixture)

    assert verify_fixture(fixture).ok
    release = archive.create_release_archive(fixture, tmp_path / "fixture.tar")
    verified = archive.verify_release_archive(release.path)

    assert verified.ok
    assert verified.manifest == manifest
    archive_root = f"{spec.fixture_id}/"
    expected_directories = {
        archive_root,
        f"{archive_root}artifacts/",
        *(
            f"{archive_root}artifacts/{node.served_path}/"
            for node in manifest.payload.directories
        ),
    }
    assert {name for name in verified.members if name.endswith("/")} == expected_directories


@pytest.mark.skipif(os.name == "nt", reason="POSIX umask and carrier-mode contract")
def test_v2_release_is_deterministic_under_hostile_umask(tmp_path):
    spec = _v2_manifest().recipe
    fixture = tmp_path / "fixture"
    build_fixture(spec, fixture)

    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    previous_umask = os.umask(0o777)
    try:
        first_result = archive.create_release_archive(fixture, first)
        first_verified = archive.verify_release_archive(first)
        second_result = archive.create_release_archive(fixture, second)
        second_verified = archive.verify_release_archive(second)
    finally:
        os.umask(previous_umask)

    assert first_verified.ok
    assert second_verified.ok
    assert first_result.sha256 == second_result.sha256
    assert first.read_bytes() == second.read_bytes()
    assert stat.S_IMODE(first.stat().st_mode) == 0o644
    assert stat.S_IMODE(second.stat().st_mode) == 0o644


@pytest.mark.skipif(os.name == "nt", reason="POSIX umask and carrier-mode contract")
def test_v2_release_creates_usable_nested_parent_under_hostile_umask(tmp_path):
    fixture = tmp_path / "fixture"
    build_fixture(_v2_manifest().recipe, fixture)
    output = tmp_path / "new-parent" / "nested" / "fixture.tar"

    previous_umask = os.umask(0o777)
    try:
        result = archive.create_release_archive(fixture, output)
        verified = archive.verify_release_archive(output)
    finally:
        os.umask(previous_umask)

    assert verified.ok
    assert result.path == output
    assert stat.S_IMODE((tmp_path / "new-parent").stat().st_mode) == 0o700
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(output.stat().st_mode) == 0o644


def test_v2_release_rejects_descendant_output_before_creating_parent(tmp_path):
    fixture = tmp_path / "fixture"
    build_fixture(_v2_manifest().recipe, fixture)
    output = fixture / "new-parent" / "nested" / "fixture.tar"

    with pytest.raises(archive.FixtureArchiveError, match="inside the fixture"):
        archive.create_release_archive(fixture, output)

    assert not (fixture / "new-parent").exists()
    assert verify_fixture(fixture).ok


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink preflight")
def test_v2_release_resolves_existing_symlink_before_descendant_preflight(tmp_path):
    fixture = tmp_path / "fixture"
    build_fixture(_v2_manifest().recipe, fixture)
    alias = tmp_path / "fixture-alias"
    alias.symlink_to(fixture, target_is_directory=True)
    output = alias / "new-parent" / "fixture.tar"

    with pytest.raises(archive.FixtureArchiveError, match="inside the fixture"):
        archive.create_release_archive(fixture, output)

    assert not (fixture / "new-parent").exists()
    assert verify_fixture(fixture).ok


@pytest.mark.skipif(os.name == "nt", reason="POSIX inode-identity containment")
def test_v2_release_rejects_case_alias_of_fixture_before_creating_parent(tmp_path):
    fixture = tmp_path / "casefixture"
    build_fixture(_v2_manifest().recipe, fixture)
    alias = tmp_path / "CASEFIXTURE"
    try:
        same_fixture = alias.samefile(fixture)
    except FileNotFoundError:
        same_fixture = False
    if not same_fixture:
        pytest.skip("test filesystem is case-sensitive")

    with pytest.raises(archive.FixtureArchiveError, match="inside the fixture"):
        archive.create_release_archive(
            fixture,
            alias / "new-parent" / "fixture.tar",
        )

    assert not (fixture / "new-parent").exists()
    assert verify_fixture(fixture).ok


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-anchored traversal")
def test_v2_release_rejects_output_ancestor_swapped_to_fixture_before_creation(
    tmp_path, monkeypatch
):
    fixture = tmp_path / "fixture"
    build_fixture(_v2_manifest().recipe, fixture)
    anchor = tmp_path / "race-anchor"
    anchor.mkdir()
    output = anchor / "new-parent" / "fixture.tar"
    real_open_parent = archive._open_or_create_output_parent
    swapped = False

    def swap_then_open(path, *, forbidden_identities):
        nonlocal swapped
        anchor.rename(tmp_path / "race-anchor-original")
        anchor.symlink_to(fixture, target_is_directory=True)
        swapped = True
        return real_open_parent(path, forbidden_identities=forbidden_identities)

    monkeypatch.setattr(archive, "_open_or_create_output_parent", swap_then_open)

    with pytest.raises(archive.FixtureArchiveError, match="no-follow|inside the fixture"):
        archive.create_release_archive(fixture, output)

    assert swapped
    assert not (fixture / "new-parent").exists()
    assert verify_fixture(fixture).ok


@pytest.mark.skipif(os.name == "nt", reason="POSIX carrier-mode contract")
@pytest.mark.parametrize(
    "target_kind,invalid_mode",
    (
        ("root", 0o755),
        ("manifest", 0o644),
        ("payload-root", 0o755),
        ("directory", 0o755),
        ("file", 0o644),
    ),
)
def test_v2_release_rejects_invalid_source_carrier_modes(
    tmp_path, target_kind, invalid_mode
):
    fixture = tmp_path / "fixture"
    manifest = build_fixture(_v2_manifest().recipe, fixture)
    if target_kind == "root":
        target = fixture
    elif target_kind == "manifest":
        target = fixture / "fixture.json"
    elif target_kind == "payload-root":
        target = fixture / "artifacts"
    elif target_kind == "directory":
        target = fixture / "artifacts" / manifest.payload.directories[-1].served_path
    else:
        target = fixture / "artifacts" / manifest.payload.files[0].served_path
    target.chmod(invalid_mode)
    output = tmp_path / f"{target_kind}.tar"

    with pytest.raises(archive.FixtureArchiveMismatch, match="carrier .* mode"):
        archive.create_release_archive(fixture, output)

    assert not output.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX carrier-mode contract")
def test_v2_payload_mode_rejection_closes_the_open_descriptor(tmp_path, monkeypatch):
    fixture = tmp_path / "fixture"
    build_fixture(_v2_manifest().recipe, fixture)
    (fixture / "artifacts").chmod(0o755)
    real_open = archive.os.open
    real_close = archive.os.close
    payload_descriptors: list[int] = []
    closed_descriptors: list[int] = []

    def recording_open(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        if path == archive.PAYLOAD_ROOT and kwargs.get("dir_fd") is not None:
            payload_descriptors.append(descriptor)
        return descriptor

    def recording_close(descriptor):
        closed_descriptors.append(descriptor)
        return real_close(descriptor)

    monkeypatch.setattr(archive.os, "open", recording_open)
    monkeypatch.setattr(archive.os, "close", recording_close)

    for _attempt in range(20):
        with pytest.raises(archive.FixtureArchiveMismatch, match="carrier .* mode"):
            archive._snapshot_fixture(fixture)

    assert len(payload_descriptors) == 20
    assert all(
        closed_descriptors.count(descriptor) >= payload_descriptors.count(descriptor)
        for descriptor in set(payload_descriptors)
    )


def test_v2_release_rejects_a_cross_file_rolling_capture(tmp_path, monkeypatch):
    fixture = tmp_path / "fixture"
    manifest = build_fixture(_v2_manifest().recipe, fixture)
    history_node = next(
        node for node in manifest.payload.files if node.served_path.endswith("/.bash_history")
    )
    later_node = next(
        node
        for node in manifest.payload.files
        if "/.config/autostart/" in f"/{node.served_path}"
    )
    history = fixture / "artifacts" / history_node.served_path
    later = fixture / "artifacts" / later_node.served_path
    good_history = history.read_bytes()
    good_later = later.read_bytes()

    def flipped(data: bytes) -> bytes:
        return bytes((data[0] ^ 1,)) + data[1:]

    # The earlier file is initially correct and the later file is not. Immediately before
    # the later directory is captured, swap those states. Each per-file read sees declared
    # bytes, but no whole-tree instant ever contains both declared values.
    later.write_bytes(flipped(good_later))
    real_list = archive.resources.bounded_directory_names
    swapped = False

    def rolling_list(descriptor, *, max_entries, label):
        nonlocal swapped
        if not swapped and str(label).endswith("home/v/.config/autostart"):
            swapped = True
            history.write_bytes(flipped(good_history))
            later.write_bytes(good_later)
        return real_list(descriptor, max_entries=max_entries, label=label)

    monkeypatch.setattr(archive.resources, "bounded_directory_names", rolling_list)
    output = tmp_path / "rolling.tar"

    with pytest.raises(archive.FixtureArchiveMismatch, match="changed after capture"):
        archive.create_release_archive(fixture, output)

    assert swapped
    assert not output.exists()


def test_v1_snapshot_stays_parseable_but_release_remains_parse_only(tmp_path):
    data = b"historical v1 bytes"
    spec = FixtureSpec.from_json(V1_SPEC.read_bytes())
    entry = ArtifactEntry.from_bytes("nested/historical.bin", data)
    manifest = FixtureManifest(
        generator=GeneratorIdentity(version="0.5.0"),
        recipe=spec,
        recipe_sha256=spec.recipe_sha256,
        payload=FixturePayload(
            file_count=1,
            total_bytes=len(data),
            tree_sha256=compute_tree_sha256((entry,)),
            files=(entry,),
        ),
    )
    root = tmp_path / "historical"
    resident = root / "artifacts" / entry.path
    resident.parent.mkdir(parents=True)
    resident.write_bytes(data)
    (root / "fixture.json").write_bytes(manifest.canonical_bytes())

    snapshot = archive._snapshot_fixture(root)
    assert snapshot.manifest == manifest
    assert snapshot.directories == ("artifacts/", "artifacts/nested/")

    output = tmp_path / "new-parent" / "historical.tar"
    with pytest.raises(archive.FixtureArchiveError, match="parse-only.*must not relabel"):
        archive.create_release_archive(root, output)
    assert not output.parent.exists()
