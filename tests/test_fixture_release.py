# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Release archives are deterministic, isolated and fail closed under mutation."""
from __future__ import annotations

import os
from pathlib import Path
import tarfile
import dataclasses

import pytest

from artifactforge.fixture.abi import GENERATOR_ABI_V1
from artifactforge.fixture import archive
from artifactforge.fixture.archive import (
    ArchivePublicationUncertain,
    FixtureArchiveError,
    FixtureArchiveMismatch,
    create_release_archive,
    verify_release_archive,
)
from artifactforge.fixture.canonical import canonical_json_bytes
from artifactforge.fixture.model_v2 import (
    FileNodeV2,
    FixtureManifestV2,
    FixturePayloadV2,
    FixtureSpecV2,
    GeneratorIdentityV2,
    LinuxMetadataV2,
    ProfileSpecV2,
)
from artifactforge.fixture.operations import build_fixture


_STORY_IDS = {
    "windows": "windows-dropper-v1",
    "macos": "macos-quarantined-app-v1",
    "linux": "linux-autostart-v1",
}


def _spec(family: str = "windows") -> FixtureSpecV2:
    profiles = {
        "windows": "windows-loose-v2",
        "macos": "macos-14-loose-v2",
        "linux": "linux-glibc-x86_64-loose-v2",
    }
    fixture_ids = {
        "windows": "windows-dropper-001",
        "macos": "macos-quarantined-app-001",
        "linux": "linux-autostart-001",
    }
    return FixtureSpecV2.create(
        fixture_id=fixture_ids[family],
        family=family,
        story=_STORY_IDS[family],
        profile=ProfileSpecV2(
            id=profiles[family],
            hostname=f"{family}-01",
            username="v",
        ),
        seed_hex="42" * 32,
    )


def _build(path: Path):
    return build_fixture(_spec(), path)


def _file_path(node: FileNodeV2) -> str:
    return node.served_path


def _manifest_for_carrier(
    manifest: FixtureManifestV2, files: dict[str, bytes]
) -> FixtureManifestV2:
    nodes = tuple(
        FileNodeV2.from_bytes(
            guest_path=node.guest_path,
            served_path=node.served_path,
            data=files[node.served_path],
            metadata=node.metadata,
        )
        for node in manifest.payload.files
    )
    return FixtureManifestV2.create(
        generator_version=manifest.generator.version,
        recipe=manifest.recipe,
        payload=FixturePayloadV2.create(
            family=manifest.payload.family,
            directories=manifest.payload.directories,
            files=nodes,
        ),
    )


def test_release_is_byte_deterministic_and_rooted_by_fixture_id(tmp_path):
    _build(tmp_path / "one")
    _build(tmp_path / "two")
    first = create_release_archive(tmp_path / "one", tmp_path / "one.tar")
    second = create_release_archive(tmp_path / "two", tmp_path / "two.tar")

    assert (tmp_path / "one.tar").read_bytes() == (tmp_path / "two.tar").read_bytes()
    assert first.sha256 == second.sha256
    assert second.sha256.startswith("sha256:")
    assert first.members == second.members
    assert first.members[0] == "windows-dropper-001/"
    assert "windows-dropper-001/fixture.json" in first.members
    assert all(name.startswith("windows-dropper-001/") for name in first.members)


def test_release_uses_only_fixed_ustar_metadata_and_regular_members(tmp_path):
    _build(tmp_path / "fixture")
    result = create_release_archive(tmp_path / "fixture", tmp_path / "fixture.tar")
    assert (tmp_path / "fixture.tar").stat().st_mode & 0o777 == 0o644

    with tarfile.open(tmp_path / "fixture.tar", mode="r:") as bundle:
        members = bundle.getmembers()
    assert tuple(member.name + ("/" if member.isdir() and not member.name.endswith("/") else "")
                 for member in members) == result.members
    assert all(member.uid == member.gid == member.mtime == 0 for member in members)
    assert all(member.uname == member.gname == "" for member in members)
    assert all(member.mode == (0o755 if member.isdir() else 0o644) for member in members)
    assert all(not member.pax_headers for member in members)
    assert all(member.isdir() or member.isreg() for member in members)
    assert b"ustar\x0000" in (tmp_path / "fixture.tar").read_bytes()[:512]
    verified = verify_release_archive(tmp_path / "fixture.tar")
    assert verified.ok and verified.failures == ()


def test_linux_logical_executables_remain_non_executable_ustar_carriers(tmp_path):
    manifest = build_fixture(_spec("linux"), tmp_path / "fixture")
    create_release_archive(tmp_path / "fixture", tmp_path / "linux.tar")

    elf_nodes = [
        node
        for node in manifest.payload.files
        if (tmp_path / "fixture" / "artifacts" / node.served_path)
        .read_bytes()
        .startswith(b"\x7fELF")
    ]
    assert len(elf_nodes) == 5
    assert all(
        isinstance(node.metadata, LinuxMetadataV2) and node.metadata.mode == 0o755
        for node in elf_nodes
    )

    with tarfile.open(tmp_path / "linux.tar", mode="r:") as bundle:
        elf_members = [
            member
            for member in bundle.getmembers()
            if member.isreg()
            and member.name.removeprefix("linux-autostart-001/artifacts/")
            in {node.served_path for node in elf_nodes}
        ]

    assert len(elf_members) == 5
    assert all(member.mode == 0o644 for member in elf_members)


def test_release_optional_assurance_runs_gates_one_and_three(tmp_path):
    _build(tmp_path / "fixture")
    result = create_release_archive(
        tmp_path / "fixture", tmp_path / "fixture.tar", assurance=True)
    assert result.fixture_verification.assurance_ok is True
    assert [report.gate for report in result.fixture_verification.assurance_reports] == [1, 3]


@pytest.mark.parametrize("existing", ("file", "broken-symlink"))
def test_release_refuses_every_lexisting_output(tmp_path, existing):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"
    if existing == "file":
        output.write_bytes(b"keep")
    else:
        output.symlink_to(tmp_path / "does-not-exist")
    with pytest.raises(FixtureArchiveError, match="refusing to replace"):
        create_release_archive(tmp_path / "fixture", output)
    if existing == "file":
        assert output.read_bytes() == b"keep"
    else:
        assert output.is_symlink()


def test_mutated_fixture_is_rejected_before_archive_publication(tmp_path):
    manifest = _build(tmp_path / "fixture")
    victim = tmp_path / "fixture" / "artifacts" / _file_path(manifest.payload.files[0])
    victim.write_bytes(victim.read_bytes() + b"changed")
    with pytest.raises(FixtureArchiveMismatch, match="match manifest|reproduce"):
        create_release_archive(tmp_path / "fixture", tmp_path / "release.tar")
    assert not os.path.lexists(tmp_path / "release.tar")


def test_fixture_change_after_capture_cannot_change_archived_snapshot(tmp_path, monkeypatch):
    manifest = _build(tmp_path / "fixture")
    victim = tmp_path / "fixture" / "artifacts" / _file_path(manifest.payload.files[0])
    original = archive._write_archive

    def write_then_mutate(path, snapshot):
        original(path, snapshot)
        victim.write_bytes(victim.read_bytes() + b"raced")

    monkeypatch.setattr(archive, "_write_archive", write_then_mutate)
    result = create_release_archive(tmp_path / "fixture", tmp_path / "release.tar")
    assert result.fixture_verification.ok
    assert verify_release_archive(tmp_path / "release.tar").ok
    assert victim.read_bytes().endswith(b"raced")


def test_postwrite_verification_detects_payload_mutation(tmp_path):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"
    create_release_archive(tmp_path / "fixture", output)
    with tarfile.open(output, mode="r:") as bundle:
        victim = next(member for member in bundle if member.isreg())
        offset = victim.offset_data
    data = bytearray(output.read_bytes())
    data[offset] ^= 1
    output.write_bytes(data)
    result = verify_release_archive(output)
    assert not result.ok
    assert any("sha256" in failure for failure in result.failures)


def test_appended_zero_record_is_not_another_valid_encoding(tmp_path):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"
    create_release_archive(tmp_path / "fixture", output)
    output.write_bytes(output.read_bytes() + b"\x00" * 10240)
    with pytest.raises(FixtureArchiveError, match="canonical USTAR requires"):
        verify_release_archive(output)


def test_noncanonical_header_encoding_is_rejected_even_with_valid_checksum(tmp_path):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"
    create_release_archive(tmp_path / "fixture", output)
    payload = bytearray(output.read_bytes())
    payload[147] = 0x20  # mtime zero with a space terminator instead of canonical NUL
    payload[148:156] = b"        "
    checksum = sum(payload[:512])
    payload[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    output.write_bytes(payload)
    with tarfile.open(output, mode="r:") as bundle:
        assert bundle.next().mtime == 0
    with pytest.raises(FixtureArchiveError, match="unique canonical"):
        verify_release_archive(output)


def test_nonzero_member_padding_is_rejected(tmp_path):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"
    create_release_archive(tmp_path / "fixture", output)
    with tarfile.open(output, mode="r:") as bundle:
        victim = next(member for member in bundle if member.isreg() and member.size % 512)
    payload = bytearray(output.read_bytes())
    payload[victim.offset_data + victim.size] = 1
    output.write_bytes(payload)
    with pytest.raises(FixtureArchiveError, match="non-zero USTAR data padding"):
        verify_release_archive(output)


def test_v2_generator_version_is_provenance_and_still_reproduces(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    snapshot = archive._snapshot_fixture(tmp_path / "fixture")
    assert isinstance(snapshot.manifest, FixtureManifestV2)
    foreign = dataclasses.replace(
        snapshot.manifest, generator=GeneratorIdentityV2(version="999.0.0")
    )
    files = dict(snapshot.files)
    files[archive.MANIFEST_NAME] = foreign.canonical_bytes()
    rewritten = dataclasses.replace(
        snapshot, files=tuple(sorted(files.items())), manifest=foreign
    )
    output = tmp_path / "foreign-version.tar"
    output.write_bytes(archive._canonical_archive_bytes(rewritten))
    real_verify_snapshot = archive._verify_snapshot
    reproduced: list[str] = []

    def recording_verify(snapshot, *, assurance=False):
        reproduced.append(snapshot.manifest.generator.version)
        return real_verify_snapshot(snapshot, assurance=assurance)

    monkeypatch.setattr(archive, "_verify_snapshot", recording_verify)
    verified = verify_release_archive(output)

    assert verified.ok
    assert verified.manifest.generator.version == "999.0.0"
    assert reproduced == ["999.0.0"]


def test_archive_rejects_mixed_generator_abi_before_reproduction(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    snapshot = archive._snapshot_fixture(tmp_path / "fixture")
    mapping = snapshot.manifest.to_mapping()
    generator = mapping["generator"]
    assert isinstance(generator, dict)
    generator["abi"] = GENERATOR_ABI_V1
    files = dict(snapshot.files)
    files[archive.MANIFEST_NAME] = canonical_json_bytes(mapping)
    rewritten = dataclasses.replace(snapshot, files=tuple(sorted(files.items())))
    output = tmp_path / "mixed-abi.tar"
    output.write_bytes(archive._canonical_archive_bytes(rewritten))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("mixed ABI reached fixture reproduction")

    monkeypatch.setattr(archive, "_verify_snapshot", forbidden)
    with pytest.raises(FixtureArchiveError, match="manifest.generator.abi"):
        verify_release_archive(output)


def test_fixture_reads_request_no_follow_and_publication_fsyncs_parent(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    seen_flags: list[tuple[Path, int]] = []
    real_open = archive.os.open
    real_fsync = archive._fsync_directory
    fsynced: list[Path | int] = []

    def recording_open(path, flags, *args, **kwargs):
        seen_flags.append((Path(path), flags))
        return real_open(path, flags, *args, **kwargs)

    def recording_fsync(path):
        fsynced.append(path)
        return real_fsync(path)

    monkeypatch.setattr(archive.os, "open", recording_open)
    archive._snapshot_fixture(tmp_path / "fixture")
    assert seen_flags
    assert all(flags & os.O_NOFOLLOW for _path, flags in seen_flags)
    monkeypatch.setattr(archive.os, "open", real_open)
    monkeypatch.setattr(archive, "_fsync_directory", recording_fsync)
    create_release_archive(tmp_path / "fixture", tmp_path / "release.tar")
    assert len(fsynced) == 1 and isinstance(fsynced[0], int)


def test_parent_directory_symlink_swap_is_rejected(tmp_path, monkeypatch):
    manifest = _build(tmp_path / "fixture")
    artifacts = tmp_path / "fixture" / "artifacts"
    top_level = manifest.payload.directories[0].served_path.split("/", 1)[0]
    nested = artifacts / top_level
    assert nested.is_dir()

    real_open = archive.os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == top_level and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            nested.rename(artifacts / f"{top_level}.real")
            nested.symlink_to(f"{top_level}.real", target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(archive.os, "open", swapping_open)
    with pytest.raises(FixtureArchiveError, match="safely traverse"):
        archive._snapshot_fixture(tmp_path / "fixture")
    assert swapped


def test_atomic_publication_race_preserves_competing_output(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"

    def racing_publish(_source_fd, _parent_fd, _output_name):
        output.write_bytes(b"winner")
        raise FileExistsError(output)

    monkeypatch.setattr(archive, "_publish_archive_inode", racing_publish)
    with pytest.raises(FixtureArchiveError, match="refusing to replace"):
        create_release_archive(tmp_path / "fixture", output)
    assert output.read_bytes() == b"winner"


def test_self_consistent_but_nonreproducible_fixture_is_not_released(tmp_path):
    manifest = _build(tmp_path / "fixture")
    artifacts = tmp_path / "fixture" / "artifacts"
    victim = artifacts / _file_path(manifest.payload.files[0])
    victim.write_bytes(victim.read_bytes() + b"self-consistent mutation")
    rewritten = _manifest_for_carrier(
        manifest,
        {
            node.served_path: (artifacts / node.served_path).read_bytes()
            for node in manifest.payload.files
        },
    )
    (tmp_path / "fixture" / "fixture.json").write_bytes(rewritten.canonical_bytes())

    with pytest.raises(FixtureArchiveMismatch, match="do not reproduce"):
        create_release_archive(tmp_path / "fixture", tmp_path / "release.tar")
    assert not os.path.lexists(tmp_path / "release.tar")


def test_archive_verifier_rejects_canonical_nonreproducible_payload(tmp_path):
    _build(tmp_path / "fixture")
    snapshot = archive._snapshot_fixture(tmp_path / "fixture")
    files = dict(snapshot.files)
    artifact_name = next(name for name in files if name.startswith("artifacts/"))
    files[artifact_name] += b"self-consistent mutation"
    assert isinstance(snapshot.manifest, FixtureManifestV2)
    manifest = _manifest_for_carrier(
        snapshot.manifest,
        {
            name.removeprefix("artifacts/"): payload
            for name, payload in files.items()
            if name.startswith("artifacts/")
        },
    )
    files[archive.MANIFEST_NAME] = manifest.canonical_bytes()
    rewritten = dataclasses.replace(
        snapshot,
        files=tuple(sorted(files.items())),
        manifest=manifest,
    )
    output = tmp_path / "nonreproducible.tar"
    output.write_bytes(archive._canonical_archive_bytes(rewritten))

    result = verify_release_archive(output)
    assert not result.ok
    assert any("does not reproduce" in failure for failure in result.failures)


def test_replaced_temporary_path_cannot_redirect_held_archive_fd(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"
    attacker = tmp_path / "attacker"
    attacker.write_bytes(b"keep me")
    real_create = archive._create_private_staging_file
    real_publish = archive._publish_archive_inode
    temporary_name = None
    staging_descriptor = None

    def record_file(parent_descriptor):
        nonlocal staging_descriptor, temporary_name
        temporary_name, descriptor = real_create(parent_descriptor)
        staging_descriptor = parent_descriptor
        return temporary_name, descriptor

    def replace_then_publish(source_fd, parent_fd, output_name):
        assert temporary_name is not None
        assert staging_descriptor is not None
        archive.os.rename(
            temporary_name,
            "held-original-inode",
            src_dir_fd=staging_descriptor,
            dst_dir_fd=staging_descriptor,
        )
        attacker_descriptor = archive.os.open(
            temporary_name,
            archive.os.O_WRONLY | archive.os.O_CREAT | archive.os.O_EXCL,
            0o600,
            dir_fd=staging_descriptor,
        )
        try:
            archive.os.write(attacker_descriptor, attacker.read_bytes())
        finally:
            archive.os.close(attacker_descriptor)
        real_publish(source_fd, parent_fd, output_name)

    monkeypatch.setattr(archive, "_create_private_staging_file", record_file)
    monkeypatch.setattr(archive, "_publish_archive_inode", replace_then_publish)
    create_release_archive(tmp_path / "fixture", output)
    assert attacker.read_bytes() == b"keep me"
    assert output.read_bytes() != b"keep me"
    assert verify_release_archive(output).ok
    staging_directories = list(tmp_path.glob(".artifactforge-release-*"))
    assert len(staging_directories) == 1
    for leftover in staging_directories[0].iterdir():
        leftover.unlink()
    staging_directories[0].rmdir()


def test_staging_directory_setup_failure_removes_its_exact_private_residue(
    tmp_path, monkeypatch
):
    parent_descriptor = archive.os.open(tmp_path, archive.os.O_RDONLY | archive.os.O_DIRECTORY)
    real_chmod = archive.os.chmod

    def fail_staging_chmod(path, mode, *args, **kwargs):
        if (
            isinstance(path, str)
            and path.startswith(".artifactforge-release-")
            and kwargs.get("dir_fd") == parent_descriptor
        ):
            raise OSError("injected staging directory chmod failure")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(archive.os, "chmod", fail_staging_chmod)
    try:
        with pytest.raises(archive.FixtureArchiveError, match="cannot hold private"):
            archive._create_private_staging_directory(
                parent_descriptor,
                forbidden_identities=frozenset(),
            )
    finally:
        archive.os.close(parent_descriptor)

    assert not list(tmp_path.glob(".artifactforge-release-*"))


def test_staging_file_setup_failure_removes_its_exact_private_residue(
    tmp_path, monkeypatch
):
    staging_descriptor = archive.os.open(
        tmp_path,
        archive.os.O_RDONLY | archive.os.O_DIRECTORY,
    )
    real_fchmod = archive.os.fchmod

    def fail_staging_fchmod(descriptor, mode):
        if mode == 0o600:
            raise OSError("injected staging file fchmod failure")
        return real_fchmod(descriptor, mode)

    monkeypatch.setattr(archive.os, "fchmod", fail_staging_fchmod)
    try:
        with pytest.raises(archive.FixtureArchiveError, match="cannot secure private"):
            archive._create_private_staging_file(staging_descriptor)
    finally:
        archive.os.close(staging_descriptor)

    assert not list(tmp_path.glob("archive-*.tmp"))


def test_archive_mode_is_set_before_final_file_sync(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    events = []
    real_fchmod = archive.os.fchmod
    real_fsync = archive.os.fsync

    def recording_fchmod(descriptor, mode):
        events.append(("fchmod", descriptor, mode))
        return real_fchmod(descriptor, mode)

    def recording_fsync(descriptor):
        events.append(("fsync", descriptor, None))
        return real_fsync(descriptor)

    monkeypatch.setattr(archive.os, "fchmod", recording_fchmod)
    monkeypatch.setattr(archive.os, "fsync", recording_fsync)
    create_release_archive(tmp_path / "fixture", tmp_path / "release.tar")
    # Other publication/snapshot primitives also use descriptor-bound fchmod. Identify the
    # archive file's contract by its required final mode rather than assuming it is globally
    # the first chmod during release verification.
    mode_index = next(
        index
        for index, event in enumerate(events)
        if event[0] == "fchmod" and event[2] == 0o644
    )
    mode_event = events[mode_index]
    sync_index = next(
        index for index, event in enumerate(events[mode_index + 1:], mode_index + 1)
        if event[0] == "fsync" and event[1] == mode_event[1]
    )
    assert mode_index < sync_index
    assert mode_event[2] == 0o644


def test_post_link_sync_failure_reports_published_verified_archive(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"

    def fail_sync(_path):
        raise FixtureArchiveError("injected parent sync failure")

    monkeypatch.setattr(archive, "_fsync_directory", fail_sync)
    with pytest.raises(ArchivePublicationUncertain, match="exists and verified") as error:
        create_release_archive(tmp_path / "fixture", output)
    assert error.value.published is True
    assert error.value.output == output
    assert output.is_file()
    assert verify_release_archive(output).ok


def test_published_inode_is_fsynced_before_parent_directory(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    destination_identity = None
    events = []
    real_publish = archive._publish_archive_inode
    real_file_sync = archive._fsync_published_archive
    real_directory_sync = archive._fsync_directory

    def recording_publish(source_fd, parent_fd, output_name):
        nonlocal destination_identity
        real_publish(source_fd, parent_fd, output_name)
        state = archive.os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        destination_identity = (state.st_dev, state.st_ino)

    def recording_file_sync(descriptor):
        state = archive.os.fstat(descriptor)
        assert (state.st_dev, state.st_ino) == destination_identity
        events.append("published-inode")
        return real_file_sync(descriptor)

    def recording_directory_sync(descriptor):
        events.append("parent-directory")
        return real_directory_sync(descriptor)

    monkeypatch.setattr(archive, "_publish_archive_inode", recording_publish)
    monkeypatch.setattr(archive, "_fsync_published_archive", recording_file_sync)
    monkeypatch.setattr(archive, "_fsync_directory", recording_directory_sync)
    create_release_archive(tmp_path / "fixture", tmp_path / "release.tar")
    assert events == ["published-inode", "parent-directory"]


def test_published_inode_sync_failure_is_explicit_and_retains_verified_output(
    tmp_path, monkeypatch
):
    _build(tmp_path / "fixture")
    output = tmp_path / "release.tar"

    def fail_inode_sync(_descriptor):
        raise FixtureArchiveError("injected destination inode sync failure")

    monkeypatch.setattr(archive, "_fsync_published_archive", fail_inode_sync)
    with pytest.raises(ArchivePublicationUncertain, match="exists and verified") as error:
        create_release_archive(tmp_path / "fixture", output)
    assert error.value.published is True
    assert error.value.output == output
    assert output.is_file()
    assert verify_release_archive(output).ok


def test_output_parent_symlink_swap_cannot_redirect_publication(tmp_path, monkeypatch):
    _build(tmp_path / "fixture")
    real_parent = tmp_path / "real-parent"
    attacker_parent = tmp_path / "attacker-parent"
    real_parent.mkdir()
    attacker_parent.mkdir()
    alias = tmp_path / "output-alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    requested = alias / "release.tar"
    real_publish = archive._publish_archive_inode

    def swap_parent_then_publish(source_fd, parent_fd, output_name):
        alias.unlink()
        alias.symlink_to(attacker_parent, target_is_directory=True)
        real_publish(source_fd, parent_fd, output_name)

    monkeypatch.setattr(archive, "_publish_archive_inode", swap_parent_then_publish)
    result = create_release_archive(tmp_path / "fixture", requested)
    assert result.path == real_parent / "release.tar"
    assert result.path.is_file()
    assert not (attacker_parent / "release.tar").exists()
    assert verify_release_archive(result.path).ok
