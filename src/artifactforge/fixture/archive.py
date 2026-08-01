# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic, fail-closed release archives for verified fixtures.

The archive is an uncompressed USTAR stream whose members do not inherit any host metadata.
Publication is bound to the verified temporary file descriptor: Darwin clones that inode into
the pinned destination directory and Linux links it through ``/proc/self/fd``. Both primitives
are exclusive; platforms without an inode-bound primitive fail closed.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile

from artifactforge.fixture.model import FixtureManifest, FixtureValidationError
from artifactforge.fixture.operations import (
    FixtureUsageError,
    VerificationResult,
    require_supported_manifest,
    verify_fixture,
)

MANIFEST_NAME = "fixture.json"
PAYLOAD_ROOT = "artifacts"
_BLOCK_SIZE = 512
_RECORD_SIZE = 10240
_FILE_MODE = 0o644
_DIRECTORY_MODE = 0o755


class FixtureArchiveError(ValueError):
    """The requested archive operation is malformed, unsafe, unsupported or impossible."""


class FixtureArchiveMismatch(RuntimeError):
    """A fixture or archive failed an integrity/reproduction check."""

    def __init__(self, failures: tuple[str, ...] | list[str]):
        self.failures = tuple(failures)
        super().__init__("; ".join(self.failures))


class ArchivePublicationUncertain(FixtureArchiveError):
    """The verified archive was linked into place, but directory durability is uncertain."""

    def __init__(
        self,
        output: Path,
        verification: ArchiveVerificationResult,
        cause: Exception,
    ):
        self.output = output
        self.verification = verification
        self.published = True
        super().__init__(
            f"release archive exists and verified at {output}, but publication durability is "
            f"uncertain because the post-link directory sync failed: {cause}"
        )


@dataclass(frozen=True)
class ArchiveResult:
    path: Path
    sha256: str
    size: int
    members: tuple[str, ...]
    manifest: FixtureManifest
    fixture_verification: VerificationResult

    def to_mapping(self) -> dict:
        return {
            "archive": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
            "member_count": len(self.members),
            "members": list(self.members),
        }


@dataclass(frozen=True)
class ArchiveVerificationResult:
    ok: bool
    failures: tuple[str, ...]
    manifest: FixtureManifest
    sha256: str
    size: int
    members: tuple[str, ...]

    def to_mapping(self) -> dict:
        return {
            "ok": self.ok,
            "failures": list(self.failures),
            "sha256": self.sha256,
            "size": self.size,
            "member_count": len(self.members),
            "members": list(self.members),
        }


@dataclass(frozen=True)
class _FixtureSnapshot:
    root: Path
    directories: tuple[str, ...]
    files: tuple[tuple[str, bytes], ...]
    manifest: FixtureManifest

    @property
    def archive_root(self) -> str:
        return self.manifest.recipe.fixture_id + "/"

    @property
    def member_names(self) -> tuple[str, ...]:
        prefix = self.archive_root
        return tuple(sorted((
            prefix,
            *(prefix + directory for directory in self.directories),
            *(prefix + name for name, _data in self.files),
        )))


def _normal_relative_path(value: str, *, directory: bool = False) -> str:
    candidate = value[:-1] if directory and value.endswith("/") else value
    raw_parts = candidate.split("/")
    path = PurePosixPath(candidate)
    if (not candidate or candidate.startswith("/") or "\\" in candidate
            or path.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts)):
        raise FixtureArchiveError(f"unsafe archive member path: {value!r}")
    normal = path.as_posix()
    return normal + "/" if directory else normal


def _required_open_flags() -> tuple[int, int]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise FixtureArchiveError(
            "this platform lacks O_NOFOLLOW/O_DIRECTORY; safe fixture release is unsupported")
    common = nofollow | getattr(os, "O_CLOEXEC", 0)
    return common | getattr(os, "O_BINARY", 0), common | directory


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_regular_at(parent_fd: int, name: str, display: Path) -> bytes:
    file_flags, _directory_flags = _required_open_flags()
    descriptor: int | None = None
    try:
        before_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before_path.st_mode):
            raise FixtureArchiveError(f"fixture member is not a regular file: {display}")
        descriptor = os.open(name, os.O_RDONLY | file_flags, dir_fd=parent_fd)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(before_path):
                raise FixtureArchiveMismatch((
                    f"fixture member changed before it could be read: {display}",))
            payload = stream.read()
            after = os.fstat(stream.fileno())
        after_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot read fixture member {display}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (_identity(before) != _identity(after) or _identity(after) != _identity(after_path)
            or len(payload) != before.st_size):
        raise FixtureArchiveMismatch((f"fixture member changed while being read: {display}",))
    return payload


def _manifest_entries(manifest: FixtureManifest):
    """The schema deliberately nests release bytes under payload.files."""
    return tuple(manifest.payload.files)


def _snapshot_fixture(root: Path | str) -> _FixtureSnapshot:
    root = Path(root)
    _file_flags, directory_flags = _required_open_flags()
    root_fd: int | None = None
    try:
        root_stat = root.lstat()
        root_fd = os.open(root, os.O_RDONLY | directory_flags)
        opened_root_stat = os.fstat(root_fd)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot inspect fixture root {root}: {exc}") from exc
    if (not stat.S_ISDIR(root_stat.st_mode) or not stat.S_ISDIR(opened_root_stat.st_mode)
            or _identity(root_stat) != _identity(opened_root_stat)):
        os.close(root_fd)
        raise FixtureArchiveError(f"fixture root is not a real directory: {root}")

    try:
        try:
            top_level = sorted(os.listdir(root_fd))
        except OSError as exc:
            raise FixtureArchiveError(f"cannot list fixture root {root}: {exc}") from exc
        expected_top_level = sorted((MANIFEST_NAME, PAYLOAD_ROOT))
        if top_level != expected_top_level:
            raise FixtureArchiveError(
                f"fixture root must contain exactly {expected_top_level}; found {top_level}")

        manifest_bytes = _read_regular_at(root_fd, MANIFEST_NAME, root / MANIFEST_NAME)
        try:
            manifest = FixtureManifest.from_canonical_json(manifest_bytes)
        except (FixtureValidationError, UnicodeDecodeError, ValueError) as exc:
            raise FixtureArchiveError(f"invalid {MANIFEST_NAME}: {exc}") from exc

        tree: dict[tuple[str, ...], tuple[set[str], set[str]]] = {(): (set(), set())}
        for entry in _manifest_entries(manifest):
            parts = tuple(entry.path.split("/"))
            for index, part in enumerate(parts):
                parent = parts[:index]
                directories_here, files_here = tree.setdefault(parent, (set(), set()))
                if index == len(parts) - 1:
                    files_here.add(part)
                else:
                    directories_here.add(part)
                    tree.setdefault(parts[:index + 1], (set(), set()))

        try:
            payload_fd = os.open(PAYLOAD_ROOT, os.O_RDONLY | directory_flags, dir_fd=root_fd)
        except OSError as exc:
            raise FixtureArchiveError(f"cannot safely open payload root {root / PAYLOAD_ROOT}: {exc}") from exc
        directories = [f"{PAYLOAD_ROOT}/"]
        files: list[tuple[str, bytes]] = [(MANIFEST_NAME, manifest_bytes)]

        def visit(directory_fd: int, parts: tuple[str, ...], display: Path) -> None:
            before = os.fstat(directory_fd)
            expected_directories, expected_files = tree[parts]
            try:
                observed = set(os.listdir(directory_fd))
            except OSError as exc:
                raise FixtureArchiveError(f"cannot list fixture directory {display}: {exc}") from exc
            expected = expected_directories | expected_files
            if observed != expected:
                missing = sorted(expected - observed)
                extra = sorted(observed - expected)
                reasons = []
                if missing:
                    reasons.append(f"missing {missing}")
                if extra:
                    reasons.append(f"undeclared {extra}")
                raise FixtureArchiveMismatch((
                    f"fixture directory inventory changed at {display}: " + "; ".join(reasons),))

            for filename in sorted(expected_files):
                relative_parts = (*parts, filename)
                relative = "/".join(relative_parts)
                files.append((f"{PAYLOAD_ROOT}/{relative}",
                              _read_regular_at(directory_fd, filename, display / filename)))
            for dirname in sorted(expected_directories):
                relative_parts = (*parts, dirname)
                relative = "/".join(relative_parts)
                child_fd: int | None = None
                try:
                    path_before = os.stat(dirname, dir_fd=directory_fd, follow_symlinks=False)
                    child_fd = os.open(
                        dirname, os.O_RDONLY | directory_flags, dir_fd=directory_fd)
                    child_before = os.fstat(child_fd)
                    if (not stat.S_ISDIR(path_before.st_mode)
                            or _identity(path_before) != _identity(child_before)):
                        raise FixtureArchiveMismatch((
                            f"fixture directory changed before traversal: {display / dirname}",))
                    directories.append(f"{PAYLOAD_ROOT}/{relative}/")
                    visit(child_fd, relative_parts, display / dirname)
                    child_after = os.fstat(child_fd)
                    path_after = os.stat(dirname, dir_fd=directory_fd, follow_symlinks=False)
                    if (_identity(child_before) != _identity(child_after)
                            or _identity(child_after) != _identity(path_after)):
                        raise FixtureArchiveMismatch((
                            f"fixture directory changed during traversal: {display / dirname}",))
                except OSError as exc:
                    raise FixtureArchiveError(
                        f"cannot safely traverse fixture directory {display / dirname}: {exc}") from exc
                finally:
                    if child_fd is not None:
                        os.close(child_fd)
            after = os.fstat(directory_fd)
            if _identity(before) != _identity(after):
                raise FixtureArchiveMismatch((
                    f"fixture directory changed during traversal: {display}",))

        try:
            visit(payload_fd, (), root / PAYLOAD_ROOT)
            payload_after = os.fstat(payload_fd)
            payload_path_after = os.stat(PAYLOAD_ROOT, dir_fd=root_fd, follow_symlinks=False)
            if _identity(payload_after) != _identity(payload_path_after):
                raise FixtureArchiveMismatch(("fixture payload root changed during traversal",))
        finally:
            os.close(payload_fd)

        root_after = os.fstat(root_fd)
        root_path_after = root.lstat()
        if (_identity(opened_root_stat) != _identity(root_after)
                or _identity(root_after) != _identity(root_path_after)):
            raise FixtureArchiveMismatch(("fixture root changed during traversal",))
    finally:
        if root_fd is not None:
            os.close(root_fd)

    actual_payload = {name.removeprefix(f"{PAYLOAD_ROOT}/"): data
                      for name, data in files if name != MANIFEST_NAME}
    declared_payload = {entry.path: entry for entry in _manifest_entries(manifest)}
    failures: list[str] = []
    if set(actual_payload) != set(declared_payload):
        missing = sorted(set(declared_payload) - set(actual_payload))
        extra = sorted(set(actual_payload) - set(declared_payload))
        if missing:
            failures.append(f"manifest payload members are missing: {missing}")
        if extra:
            failures.append(f"undeclared payload members are present: {extra}")
    for relative in sorted(set(actual_payload) & set(declared_payload)):
        payload = actual_payload[relative]
        entry = declared_payload[relative]
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        if len(payload) != entry.size:
            failures.append(
                f"{relative}: size {len(payload)} does not match manifest {entry.size}")
        if digest != entry.sha256:
            failures.append(f"{relative}: sha256 {digest} does not match manifest {entry.sha256}")
    if failures:
        raise FixtureArchiveMismatch(failures)

    return _FixtureSnapshot(
        root=root,
        directories=tuple(sorted(set(directories))),
        files=tuple(sorted(files)),
        manifest=manifest,
    )


def _materialize_snapshot(snapshot: _FixtureSnapshot, destination: Path) -> None:
    """Write exactly one in-memory capture into private verification storage."""
    try:
        destination.mkdir(mode=0o700)
        for relative in snapshot.directories:
            (destination / _normal_relative_path(relative, directory=True)).mkdir(
                mode=0o700, parents=True, exist_ok=True
            )
        for relative, payload in snapshot.files:
            path = destination / _normal_relative_path(relative)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(payload)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot materialize captured fixture snapshot: {exc}") from exc


def _verify_snapshot(
    snapshot: _FixtureSnapshot, *, assurance: bool = False
) -> VerificationResult:
    """Reproduce-verify the exact captured bytes, never the mutable caller pathname."""
    with tempfile.TemporaryDirectory(prefix="artifactforge-release-verify-") as temporary:
        fixture = Path(temporary) / "fixture"
        _materialize_snapshot(snapshot, fixture)
        try:
            return verify_fixture(fixture, assurance=assurance)
        except FixtureUsageError as exc:
            raise FixtureArchiveError(f"captured fixture is malformed: {exc}") from exc


def _tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    safe_name = _normal_relative_path(name, directory=directory)
    info = tarfile.TarInfo(safe_name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else size
    info.mode = _DIRECTORY_MODE if directory else _FILE_MODE
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.pax_headers = {}
    return info


def _canonical_archive_bytes(snapshot: _FixtureSnapshot) -> bytes:
    prefix = snapshot.archive_root
    directories = {prefix, *(prefix + name for name in snapshot.directories)}
    file_payloads = dict(snapshot.files)
    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT,
                          encoding="utf-8", errors="strict") as archive:
            for name in snapshot.member_names:
                if name in directories:
                    archive.addfile(_tar_info(name, directory=True))
                else:
                    payload = file_payloads[name.removeprefix(prefix)]
                    archive.addfile(_tar_info(name, directory=False, size=len(payload)),
                                    io.BytesIO(payload))
    except (tarfile.TarError, UnicodeError, ValueError) as exc:
        raise FixtureArchiveError(f"cannot encode deterministic USTAR archive: {exc}") from exc
    return output.getvalue()


def _write_archive(target: int | Path, snapshot: _FixtureSnapshot) -> None:
    """Write through an already-held inode when called by the release publisher."""
    payload = _canonical_archive_bytes(snapshot)
    descriptor: int | None = None
    close_descriptor = False
    try:
        if isinstance(target, int):
            descriptor = target
        else:
            flags = (
                os.O_RDWR
                | os.O_TRUNC
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(target, flags)
            close_descriptor = True
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise FixtureArchiveError("archive temporary target is not a regular file")
        with os.fdopen(os.dup(descriptor), "r+b") as raw:
            raw.seek(0)
            raw.truncate()
            raw.write(payload)
            raw.flush()
        os.fchmod(descriptor, _FILE_MODE)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or after.st_size != len(payload)
                or stat.S_IMODE(after.st_mode) != _FILE_MODE):
            raise FixtureArchiveError("archive temporary inode changed while it was written")
    except FixtureArchiveError:
        raise
    except OSError as exc:
        raise FixtureArchiveError(f"cannot write deterministic USTAR archive: {exc}") from exc
    finally:
        if close_descriptor and descriptor is not None:
            os.close(descriptor)


def _raw_archive_is_canonical(payload: bytes) -> None:
    if not payload or len(payload) % _RECORD_SIZE:
        raise FixtureArchiveError(
            f"archive size {len(payload)} is not a multiple of {_RECORD_SIZE} bytes")
    zero = b"\x00" * _BLOCK_SIZE
    blocks = [payload[index:index + _BLOCK_SIZE]
              for index in range(0, len(payload), _BLOCK_SIZE)]
    cursor = 0
    while cursor < len(blocks) and blocks[cursor] != zero:
        header = blocks[cursor]
        if header[257:263] != b"ustar\x00" or header[263:265] != b"00":
            raise FixtureArchiveError("archive contains a non-USTAR member header")
        try:
            size_text = header[124:136].rstrip(b"\x00 ") or b"0"
            member_size = int(size_text, 8)
        except ValueError as exc:
            raise FixtureArchiveError("archive member has an invalid USTAR size field") from exc
        member_blocks = (member_size + _BLOCK_SIZE - 1) // _BLOCK_SIZE
        data_start = (cursor + 1) * _BLOCK_SIZE
        data_end = data_start + member_size
        padded_end = (cursor + 1 + member_blocks) * _BLOCK_SIZE
        if any(payload[data_end:padded_end]):
            raise FixtureArchiveError("archive member has non-zero USTAR data padding")
        cursor += 1 + member_blocks
        if cursor > len(blocks):
            raise FixtureArchiveError("archive member data extends past the archive boundary")
    if (cursor + 1 >= len(blocks) or blocks[cursor] != zero
            or blocks[cursor + 1] != zero or any(block != zero for block in blocks[cursor:])):
        raise FixtureArchiveError("archive has no canonical all-zero USTAR trailer")
    expected_blocks = ((cursor + 2 + (_RECORD_SIZE // _BLOCK_SIZE) - 1)
                       // (_RECORD_SIZE // _BLOCK_SIZE)) * (_RECORD_SIZE // _BLOCK_SIZE)
    if len(blocks) != expected_blocks:
        raise FixtureArchiveError(
            f"archive has {len(blocks)} blocks; canonical USTAR requires {expected_blocks}")


def _read_descriptor(descriptor: int) -> bytes:
    try:
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode):
            raise FixtureArchiveError("release archive descriptor is not a regular file")
        chunks = []
        offset = 0
        while offset < state.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, state.st_size - offset), offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except FixtureArchiveError:
        raise
    except (AttributeError, OSError) as exc:
        raise FixtureArchiveError(f"cannot read held release archive inode: {exc}") from exc
    if _identity(state) != _identity(after) or offset != state.st_size:
        raise FixtureArchiveError("release archive inode changed while it was read")
    return b"".join(chunks)


def _read_archive(
    source: Path | str | int,
) -> tuple[bytes, tuple[tarfile.TarInfo, ...], dict[str, bytes]]:
    if isinstance(source, int):
        payload = _read_descriptor(source)
        display = f"descriptor {source}"
    else:
        path = Path(source)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise FixtureArchiveError(f"cannot read release archive {path}: {exc}") from exc
        display = str(path)
    _raw_archive_is_canonical(payload)
    members: list[tarfile.TarInfo] = []
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:", encoding="utf-8",
                          errors="strict") as archive:
            for member in archive:
                members.append(member)
                name = _normal_relative_path(member.name, directory=member.isdir())
                if name in files or any(existing.name == member.name for existing in members[:-1]):
                    raise FixtureArchiveError(f"duplicate archive member: {member.name!r}")
                if member.isdir():
                    continue
                if not member.isreg():
                    raise FixtureArchiveError(
                        f"archive member is a link or special file: {member.name!r}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise FixtureArchiveError(f"cannot read archive member: {member.name!r}")
                files[name] = stream.read()
    except (tarfile.TarError, UnicodeError, OSError) as exc:
        raise FixtureArchiveError(f"invalid uncompressed USTAR archive {display}: {exc}") from exc
    return payload, tuple(members), files


def _verify_metadata(members: tuple[tarfile.TarInfo, ...]) -> list[str]:
    failures: list[str] = []
    names = tuple(member.name + ("/" if member.isdir() and not member.name.endswith("/") else "")
                  for member in members)
    if names != tuple(sorted(names)):
        failures.append("archive members are not in canonical lexical order")
    for member in members:
        expected_mode = _DIRECTORY_MODE if member.isdir() else _FILE_MODE
        if member.uid != 0 or member.gid != 0:
            failures.append(f"{member.name}: uid/gid are not 0/0")
        if member.uname or member.gname:
            failures.append(f"{member.name}: uname/gname are not empty")
        if member.mtime != 0:
            failures.append(f"{member.name}: mtime is not zero")
        if member.mode != expected_mode:
            failures.append(f"{member.name}: mode {member.mode:#o} is not {expected_mode:#o}")
        if member.pax_headers:
            failures.append(f"{member.name}: PAX metadata is forbidden")
        if not (member.isdir() or member.isreg()):
            failures.append(f"{member.name}: links and special members are forbidden")
    return failures


def verify_release_archive(path: Path | str | int) -> ArchiveVerificationResult:
    """Validate archive structure, metadata and every manifest-bound payload byte."""
    payload, members, files = _read_archive(path)
    member_names = tuple(member.name + (
        "/" if member.isdir() and not member.name.endswith("/") else "") for member in members)
    failures = _verify_metadata(members)
    manifest_names = [name for name in files
                      if len(PurePosixPath(name).parts) == 2
                      and PurePosixPath(name).parts[1] == MANIFEST_NAME]
    if len(manifest_names) != 1:
        raise FixtureArchiveError(
            f"archive must contain exactly one <fixture_id>/{MANIFEST_NAME}")
    manifest_name = manifest_names[0]
    try:
        manifest = FixtureManifest.from_canonical_json(files[manifest_name])
    except (FixtureValidationError, UnicodeDecodeError, ValueError) as exc:
        raise FixtureArchiveError(f"invalid archived {MANIFEST_NAME}: {exc}") from exc
    archive_root = manifest.recipe.fixture_id + "/"
    if manifest_name != archive_root + MANIFEST_NAME:
        raise FixtureArchiveError(
            "archive root directory does not equal the manifest fixture_id")
    try:
        require_supported_manifest(manifest)
    except FixtureUsageError as exc:
        raise FixtureArchiveError(str(exc)) from exc

    expected_files = {archive_root + MANIFEST_NAME}
    declared = {entry.path: entry for entry in _manifest_entries(manifest)}
    for relative, entry in sorted(declared.items()):
        archive_name = f"{archive_root}{PAYLOAD_ROOT}/{relative}"
        expected_files.add(archive_name)
        if archive_name not in files:
            failures.append(f"archive is missing declared payload member {archive_name}")
            continue
        artifact = files[archive_name]
        digest = "sha256:" + hashlib.sha256(artifact).hexdigest()
        if len(artifact) != entry.size:
            failures.append(
                f"{archive_name}: size {len(artifact)} does not match manifest {entry.size}")
        if digest != entry.sha256:
            failures.append(
                f"{archive_name}: sha256 {digest} does not match manifest {entry.sha256}")
    extras = sorted(set(files) - expected_files)
    if extras:
        failures.append(f"archive has undeclared regular members: {extras}")

    required_directories = {archive_root, f"{archive_root}{PAYLOAD_ROOT}/"}
    for relative in declared:
        parts = PurePosixPath(relative).parts[:-1]
        for end in range(1, len(parts) + 1):
            required_directories.add(
                f"{archive_root}{PAYLOAD_ROOT}/" + "/".join(parts[:end]) + "/")
    actual_directories = {name for name in member_names if name.endswith("/")}
    if actual_directories != required_directories:
        failures.append(
            "archive directory members differ from the manifest-required directory set")
    expected_order = tuple(sorted((*required_directories, *expected_files)))
    if member_names != expected_order:
        failures.append("archive member set/order is not the canonical fixture layout")

    if (set(files) == expected_files and actual_directories == required_directories
            and member_names == expected_order):
        reconstructed = _FixtureSnapshot(
            root=Path("."),
            directories=tuple(sorted(
                name.removeprefix(archive_root)
                for name in required_directories if name != archive_root
            )),
            files=tuple(sorted(
                (name.removeprefix(archive_root), files[name]) for name in expected_files
            )),
            manifest=manifest,
        )
        if payload != _canonical_archive_bytes(reconstructed):
            raise FixtureArchiveError(
                "archive bytes are not the unique canonical ArtifactForge USTAR encoding")
        reproduction = _verify_snapshot(reconstructed, assurance=False)
        if not reproduction.ok:
            failures.extend(
                f"archive payload does not reproduce: {failure}"
                for failure in reproduction.failures
            )

    return ArchiveVerificationResult(
        ok=not failures,
        failures=tuple(failures),
        manifest=manifest,
        sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        members=member_names,
    )


def _open_pinned_directory(path: Path) -> int:
    _file_flags, directory_flags = _required_open_flags()
    descriptor: int | None = None
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | directory_flags)
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise FixtureArchiveError(f"cannot pin archive output directory {path}: {exc}") from exc
    if (not stat.S_ISDIR(opened.st_mode)
            or _identity(before) != _identity(opened)
            or _identity(opened) != _identity(after)):
        os.close(descriptor)
        raise FixtureArchiveError(f"archive output directory changed while opening: {path}")
    return descriptor


def _publish_archive_inode(source_fd: int, parent_fd: int, output_name: str) -> None:
    """Publish only the held source inode, never a replaceable temporary pathname."""
    libc = ctypes.CDLL(None, use_errno=True)
    encoded_name = os.fsencode(output_name)
    if sys.platform == "darwin" and hasattr(libc, "fclonefileat"):
        publish = libc.fclonefileat
        publish.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        publish.restype = ctypes.c_int
        result = publish(source_fd, parent_fd, encoded_name, 0)
    elif sys.platform.startswith("linux") and hasattr(libc, "linkat"):
        descriptor_path = f"/proc/self/fd/{source_fd}"
        try:
            state = os.stat(descriptor_path)
        except OSError as exc:
            raise FixtureArchiveError(
                "Linux fd-bound archive publication requires /proc/self/fd"
            ) from exc
        held = os.fstat(source_fd)
        if (state.st_dev, state.st_ino) != (held.st_dev, held.st_ino):
            raise FixtureArchiveError("/proc/self/fd does not resolve to the held archive inode")
        publish = libc.linkat
        publish.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        )
        publish.restype = ctypes.c_int
        result = publish(
            -100, os.fsencode(descriptor_path), parent_fd, encoded_name, 0x400
        )  # AT_FDCWD, AT_SYMLINK_FOLLOW
    else:
        raise FixtureArchiveError(
            "this platform has no supported inode-bound archive publication primitive"
        )
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(error, os.strerror(error), output_name)
        raise FixtureArchiveError(
            f"cannot publish held archive inode: {os.strerror(error)}"
        )


def _fsync_directory(path: Path | int) -> None:
    if isinstance(path, int):
        try:
            os.fsync(path)
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot fsync held archive directory: {exc}"
            ) from exc
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot fsync archive directory {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_published_archive(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot fsync published archive inode: {exc}") from exc


def create_release_archive(root: Path | str, output: Path | str, *,
                           assurance: bool = False) -> ArchiveResult:
    """Capture once, verify that capture, then exclusively publish only those exact bytes."""
    root = Path(root)
    output = Path(output)
    if os.path.lexists(output):
        raise FixtureArchiveError(f"refusing to replace existing output: {output}")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot create archive parent {output.parent}: {exc}") from exc
    try:
        output_parent = output.parent.resolve(strict=True)
        root_resolved = root.resolve(strict=True)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot resolve fixture/archive paths: {exc}") from exc
    if output_parent == root_resolved or root_resolved in output_parent.parents:
        raise FixtureArchiveError("release output must not be placed inside the fixture")
    output = output_parent / output.name
    if os.path.lexists(output):
        raise FixtureArchiveError(f"refusing to replace existing output: {output}")

    before = _snapshot_fixture(root)
    verification = _verify_snapshot(before, assurance=assurance)
    if not verification.ok:
        raise FixtureArchiveMismatch(verification.failures)

    temporary_directory: Path | None = None
    temporary: Path | None = None
    descriptor: int | None = None
    parent_descriptor: int | None = None
    published_descriptor: int | None = None
    try:
        parent_descriptor = _open_pinned_directory(output_parent)
        temporary_directory = Path(tempfile.mkdtemp(
            prefix=f".{output.name}.", dir=output_parent
        ))
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="archive-", suffix=".tmp", dir=temporary_directory
        )
        temporary = Path(temporary_name)
        _write_archive(descriptor, before)
        postwrite = verify_release_archive(descriptor)
        if not postwrite.ok:
            raise FixtureArchiveMismatch(postwrite.failures)
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot inspect archive output in its pinned parent: {exc}"
            ) from exc
        else:
            raise FixtureArchiveError(f"refusing to replace existing output: {output}")
        try:
            _publish_archive_inode(descriptor, parent_descriptor, output.name)
        except FileExistsError as exc:
            raise FixtureArchiveError(f"refusing to replace existing output: {output}") from exc
        try:
            published_state = os.stat(
                output.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            file_flags, _directory_flags = _required_open_flags()
            published_descriptor = os.open(
                output.name,
                os.O_RDONLY | file_flags,
                dir_fd=parent_descriptor,
            )
            opened_published_state = os.fstat(published_descriptor)
            if ((published_state.st_dev, published_state.st_ino)
                    != (opened_published_state.st_dev, opened_published_state.st_ino)
                    or not stat.S_ISREG(opened_published_state.st_mode)):
                raise FixtureArchiveError(
                    "published archive entry changed while its inode was being opened"
                )
            published_payload = _read_descriptor(published_descriptor)
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot confirm published release archive inode: {exc}"
            ) from exc
        published_sha256 = "sha256:" + hashlib.sha256(published_payload).hexdigest()
        if (not stat.S_ISREG(published_state.st_mode)
                or stat.S_IMODE(published_state.st_mode) != _FILE_MODE
                or len(published_payload) != postwrite.size
                or published_sha256 != postwrite.sha256):
            raise FixtureArchiveError(
                "published archive bytes, mode, or size differ from the held verified inode"
            )
        parent_path_state = output_parent.lstat()
        held_parent_state = os.fstat(parent_descriptor)
        if ((parent_path_state.st_dev, parent_path_state.st_ino)
                != (held_parent_state.st_dev, held_parent_state.st_ino)):
            raise FixtureArchiveError("archive output parent path changed during publication")
        try:
            _fsync_published_archive(published_descriptor)
        except FixtureArchiveError as exc:
            raise ArchivePublicationUncertain(output, postwrite, exc) from exc
        try:
            published_path_after_sync = os.stat(
                output.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            published_inode_after_sync = os.fstat(published_descriptor)
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot confirm published archive after inode sync: {exc}"
            ) from exc
        if ((published_path_after_sync.st_dev, published_path_after_sync.st_ino)
                != (published_inode_after_sync.st_dev, published_inode_after_sync.st_ino)):
            raise FixtureArchiveError("published archive entry changed during inode sync")
        try:
            _fsync_directory(parent_descriptor)
        except FixtureArchiveError as exc:
            raise ArchivePublicationUncertain(output, postwrite, exc) from exc
    finally:
        if temporary is not None and descriptor is not None:
            try:
                state = temporary.lstat()
                held = os.fstat(descriptor)
                if (state.st_dev, state.st_ino) == (held.st_dev, held.st_ino):
                    temporary.unlink()
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        if published_descriptor is not None:
            os.close(published_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if temporary_directory is not None:
            try:
                temporary_directory.rmdir()
            except OSError:
                pass

    return ArchiveResult(
        path=output,
        sha256=postwrite.sha256,
        size=postwrite.size,
        members=postwrite.members,
        manifest=before.manifest,
        fixture_verification=verification,
    )
