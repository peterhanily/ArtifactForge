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
import secrets
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile

from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixtureValidationError,
    parse_fixture_manifest,
)
from artifactforge.fixture.model_v2 import FileNodeV2, FixtureManifestV2
from artifactforge.fixture import resources
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

FixtureManifestRecord = FixtureManifest | FixtureManifestV2


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
    manifest: FixtureManifestRecord
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
    manifest: FixtureManifestRecord
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
    manifest: FixtureManifestRecord
    source_root_identity: tuple[int, int] | None = None
    source_directory_identities: frozenset[tuple[int, int]] = frozenset()

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


@dataclass
class _CaptureObservations:
    """First-pass states needed to reject a cross-file mixed archive capture."""

    directory_names: dict[tuple[str, ...], tuple[str, ...]]
    directory_states: dict[tuple[str, ...], tuple[int, int, int, int, int, int]]
    file_states: dict[tuple[str, ...], tuple[int, int, int, int, int, int]]


def _normal_relative_path(value: str, *, directory: bool = False) -> str:
    candidate = value[:-1] if directory and value.endswith("/") else value
    raw_parts = candidate.split("/")
    path = PurePosixPath(candidate)
    if (not candidate or candidate.startswith("/") or "\\" in candidate
            or path.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts)):
        raise FixtureArchiveError(f"unsafe archive member path: {value!r}")
    archive_depth_limit = resources.RESOURCE_POLICY.max_path_depth + 2
    if len(raw_parts) > archive_depth_limit:
        raise FixtureArchiveError(
            "archive member path exceeds the "
            f"{archive_depth_limit}-component depth limit: {value!r}"
        )
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


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return the inode state that must remain stable while it is captured."""
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_v2_carrier_mode(
    state: os.stat_result,
    expected: int,
    display: str,
) -> None:
    """Reject a source carrier that does not meet the v2 private-mode contract."""
    if os.name == "nt":
        return
    actual = stat.S_IMODE(state.st_mode)
    if actual != expected:
        raise FixtureArchiveMismatch(
            (f"fixture carrier {display} mode is {actual:#o}, expected {expected:#o}",)
        )


def _read_regular_at(
    parent_fd: int,
    name: str,
    display: Path,
    *,
    max_bytes: int,
) -> bytes:
    _required_open_flags()
    try:
        return resources.read_stable_regular_at(
            parent_fd,
            name,
            max_bytes=max_bytes,
            label=f"fixture member {display}",
        )
    except resources.FixtureResourceError as exc:
        raise FixtureArchiveError(str(exc)) from exc


def _manifest_entries(
    manifest: FixtureManifestRecord,
) -> tuple[ArtifactEntry | FileNodeV2, ...]:
    """Return the manifest-bound default-stream files for either frozen ABI."""
    if type(manifest) not in (FixtureManifest, FixtureManifestV2):
        raise FixtureArchiveError("archive snapshot has an unsupported manifest record")
    return tuple(manifest.payload.files)


def _entry_path(
    manifest: FixtureManifestRecord, entry: ArtifactEntry | FileNodeV2
) -> str:
    """Select the portable carrier path without confusing it with a v2 guest path."""
    if type(manifest) is FixtureManifestV2:
        if type(entry) is not FileNodeV2:  # pragma: no cover - typed model invariant
            raise FixtureArchiveError("v2 manifest contains a non-v2 file node")
        return entry.served_path
    if type(entry) is not ArtifactEntry:  # pragma: no cover - typed model invariant
        raise FixtureArchiveError("v1 manifest contains a non-v1 file entry")
    return entry.path


def _manifest_directory_paths(manifest: FixtureManifestRecord) -> tuple[str, ...]:
    """Return authoritative served directories, deriving only for the historical v1 ABI."""
    if type(manifest) is FixtureManifestV2:
        return tuple(node.served_path for node in manifest.payload.directories)
    directories: set[str] = set()
    for entry in manifest.payload.files:
        parts = PurePosixPath(entry.path).parts[:-1]
        directories.update("/".join(parts[:end]) for end in range(1, len(parts) + 1))
    return tuple(sorted(directories))


def _declared_tree(
    manifest: FixtureManifestRecord,
) -> tuple[
    dict[tuple[str, ...], tuple[set[str], set[str]]],
    dict[str, ArtifactEntry | FileNodeV2],
]:
    """Build the exact portable carrier inventory declared by one typed manifest."""
    tree: dict[tuple[str, ...], tuple[set[str], set[str]]] = {(): (set(), set())}
    directory_paths = _manifest_directory_paths(manifest)
    for relative in sorted(directory_paths, key=lambda value: (value.count("/"), value)):
        parts = tuple(relative.split("/"))
        parent = parts[:-1]
        if parent not in tree:
            raise FixtureArchiveError(
                f"manifest directory has no declared parent: {relative!r}"
            )
        tree[parent][0].add(parts[-1])
        tree[parts] = (set(), set())

    declared_payload = {
        _entry_path(manifest, entry): entry for entry in _manifest_entries(manifest)
    }
    for relative in declared_payload:
        parts = tuple(relative.split("/"))
        parent = parts[:-1]
        if parent not in tree:
            raise FixtureArchiveError(
                f"manifest file has no declared parent directory: {relative!r}"
            )
        tree[parent][1].add(parts[-1])
    return tree, declared_payload


def _revalidate_capture_directory_at(
    directory_fd: int,
    observations: _CaptureObservations,
    relative_parts: tuple[str, ...],
) -> None:
    """Recheck the complete descriptor-anchored tree after its final byte was read."""
    shown = f"{PAYLOAD_ROOT}/{'/'.join(relative_parts)}".rstrip("/")
    expected_state = observations.directory_states[relative_parts]
    if _identity(os.fstat(directory_fd)) != expected_state:
        raise FixtureArchiveMismatch(
            (f"fixture directory changed after capture: {shown}",)
        )
    expected_names = observations.directory_names[relative_parts]
    try:
        names = resources.bounded_directory_names(
            directory_fd,
            max_entries=len(expected_names),
            label=f"fixture directory {shown}",
        )
    except (OSError, resources.FixtureResourceError) as exc:
        raise FixtureArchiveMismatch(
            (f"fixture directory changed after capture: {shown}: {exc}",)
        ) from exc
    if names != expected_names:
        raise FixtureArchiveMismatch(
            (f"fixture directory changed after capture: {shown}",)
        )

    _unused_file_flags, directory_flags = _required_open_flags()
    for name in names:
        parts = (*relative_parts, name)
        relative = "/".join(parts)
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise FixtureArchiveMismatch(
                (f"cannot recheck fixture path {PAYLOAD_ROOT}/{relative}: {exc}",)
            ) from exc
        if parts in observations.file_states:
            if (
                not stat.S_ISREG(current.st_mode)
                or _identity(current) != observations.file_states[parts]
            ):
                raise FixtureArchiveMismatch(
                    (f"fixture file changed after capture: {PAYLOAD_ROOT}/{relative}",)
                )
            continue
        if parts not in observations.directory_states or not stat.S_ISDIR(current.st_mode):
            raise FixtureArchiveMismatch(
                (f"fixture path changed after capture: {PAYLOAD_ROOT}/{relative}",)
            )
        child_fd: int | None = None
        try:
            child_fd = os.open(
                name,
                os.O_RDONLY | directory_flags,
                dir_fd=directory_fd,
            )
            opened = os.fstat(child_fd)
            if _identity(opened) != observations.directory_states[parts]:
                raise FixtureArchiveMismatch(
                    (f"fixture directory changed after capture: {PAYLOAD_ROOT}/{relative}",)
                )
            _revalidate_capture_directory_at(child_fd, observations, parts)
            path_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _identity(path_after) != observations.directory_states[parts]:
                raise FixtureArchiveMismatch(
                    (f"fixture directory changed after capture: {PAYLOAD_ROOT}/{relative}",)
                )
        except FixtureArchiveMismatch:
            raise
        except OSError as exc:
            raise FixtureArchiveMismatch(
                (f"cannot recheck fixture directory {PAYLOAD_ROOT}/{relative}: {exc}",)
            ) from exc
        finally:
            if child_fd is not None:
                os.close(child_fd)

    if _identity(os.fstat(directory_fd)) != expected_state:
        raise FixtureArchiveMismatch(
            (f"fixture directory changed after capture: {shown}",)
        )


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
            top_level = list(resources.bounded_directory_names(
                root_fd,
                max_entries=2,
                label="fixture root",
            ))
        except (OSError, resources.FixtureResourceError) as exc:
            raise FixtureArchiveError(f"cannot list fixture root {root}: {exc}") from exc
        expected_top_level = sorted((MANIFEST_NAME, PAYLOAD_ROOT))
        if top_level != expected_top_level:
            raise FixtureArchiveError(
                f"fixture root must contain exactly {expected_top_level}; found {top_level}")

        try:
            manifest_before = os.stat(
                MANIFEST_NAME,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot inspect fixture manifest {root / MANIFEST_NAME}: {exc}"
            ) from exc
        manifest_bytes = _read_regular_at(
            root_fd,
            MANIFEST_NAME,
            root / MANIFEST_NAME,
            max_bytes=resources.RESOURCE_POLICY.max_input_bytes,
        )
        try:
            manifest_after = os.stat(
                MANIFEST_NAME,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot recheck fixture manifest {root / MANIFEST_NAME}: {exc}"
            ) from exc
        if (
            not stat.S_ISREG(manifest_before.st_mode)
            or _identity(manifest_before) != _identity(manifest_after)
        ):
            raise FixtureArchiveMismatch(("fixture manifest changed during capture",))
        try:
            manifest = parse_fixture_manifest(manifest_bytes, require_canonical=True)
        except (FixtureValidationError, UnicodeDecodeError, ValueError) as exc:
            raise FixtureArchiveError(f"invalid {MANIFEST_NAME}: {exc}") from exc

        is_v2 = type(manifest) is FixtureManifestV2
        if is_v2:
            _require_v2_carrier_mode(opened_root_stat, 0o700, "root")
            _require_v2_carrier_mode(manifest_after, 0o600, "manifest")

        tree, declared_payload = _declared_tree(manifest)

        try:
            payload_fd = os.open(PAYLOAD_ROOT, os.O_RDONLY | directory_flags, dir_fd=root_fd)
        except OSError as exc:
            raise FixtureArchiveError(f"cannot safely open payload root {root / PAYLOAD_ROOT}: {exc}") from exc
        try:
            payload_before = os.fstat(payload_fd)
            if is_v2:
                _require_v2_carrier_mode(
                    payload_before, 0o700, "directory 'artifacts'"
                )
        except (OSError, FixtureArchiveMismatch):
            os.close(payload_fd)
            raise
        directories = [f"{PAYLOAD_ROOT}/"]
        files: list[tuple[str, bytes]] = [(MANIFEST_NAME, manifest_bytes)]
        observations = _CaptureObservations({}, {}, {})
        payload_total = 0

        def visit(directory_fd: int, parts: tuple[str, ...], display: Path) -> None:
            nonlocal payload_total
            before = os.fstat(directory_fd)
            expected_directories, expected_files = tree[parts]
            try:
                observed = set(resources.bounded_directory_names(
                    directory_fd,
                    max_entries=len(expected_directories | expected_files),
                    label=f"fixture directory {display}",
                ))
            except (OSError, resources.FixtureResourceError) as exc:
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
                remaining = resources.RESOURCE_POLICY.max_total_bytes - payload_total
                try:
                    file_before = os.stat(
                        filename,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise FixtureArchiveError(
                        f"cannot inspect fixture file {display / filename}: {exc}"
                    ) from exc
                if is_v2:
                    _require_v2_carrier_mode(
                        file_before,
                        0o600,
                        f"file '{PAYLOAD_ROOT}/{relative}'",
                    )
                payload = _read_regular_at(
                    directory_fd,
                    filename,
                    display / filename,
                    max_bytes=min(resources.RESOURCE_POLICY.max_file_bytes, remaining),
                )
                try:
                    file_after = os.stat(
                        filename,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise FixtureArchiveError(
                        f"cannot recheck fixture file {display / filename}: {exc}"
                    ) from exc
                if _identity(file_before) != _identity(file_after):
                    raise FixtureArchiveMismatch(
                        (f"fixture file changed during capture: {display / filename}",)
                    )
                observations.file_states[relative_parts] = _identity(file_after)
                entry = declared_payload[relative]
                digest = "sha256:" + hashlib.sha256(payload).hexdigest()
                failures = []
                if len(payload) != entry.size:
                    failures.append(
                        f"{relative}: size {len(payload)} does not match manifest {entry.size}"
                    )
                if digest != entry.sha256:
                    failures.append(
                        f"{relative}: sha256 {digest} does not match manifest {entry.sha256}"
                    )
                if failures:
                    # Do not retain later payload bytes once the first declared member is false.
                    raise FixtureArchiveMismatch(failures)
                if len(payload) > remaining:  # defensive: the bounded reader already enforces it
                    raise FixtureArchiveError(
                        "fixture payload exceeds the "
                        f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
                    )
                payload_total += len(payload)
                files.append((f"{PAYLOAD_ROOT}/{relative}", payload))
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
                    if is_v2:
                        _require_v2_carrier_mode(
                            child_before,
                            0o700,
                            f"directory '{PAYLOAD_ROOT}/{relative}'",
                        )
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
            observations.directory_names[parts] = tuple(sorted(observed))
            observations.directory_states[parts] = _identity(after)

        try:
            visit(payload_fd, (), root / PAYLOAD_ROOT)
            _revalidate_capture_directory_at(payload_fd, observations, ())
            payload_after = os.fstat(payload_fd)
            payload_path_after = os.stat(PAYLOAD_ROOT, dir_fd=root_fd, follow_symlinks=False)
            if (
                _identity(payload_before) != _identity(payload_after)
                or _identity(payload_after) != _identity(payload_path_after)
            ):
                raise FixtureArchiveMismatch(("fixture payload root changed during traversal",))
        finally:
            os.close(payload_fd)

        try:
            manifest_final = os.stat(
                MANIFEST_NAME,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise FixtureArchiveMismatch(
                (f"cannot recheck fixture manifest after capture: {exc}",)
            ) from exc
        if _identity(manifest_final) != _identity(manifest_after):
            raise FixtureArchiveMismatch(("fixture manifest changed after capture",))

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
        source_root_identity=(root_after.st_dev, root_after.st_ino),
        source_directory_identities=frozenset(
            {
                (root_after.st_dev, root_after.st_ino),
                *((state[0], state[1]) for state in observations.directory_states.values()),
            }
        ),
    )


def _materialize_snapshot(snapshot: _FixtureSnapshot, destination: Path) -> None:
    """Write one capture with fixed private carrier modes, never logical guest metadata."""
    try:
        destination.mkdir(mode=0o700)
        destination.chmod(0o700, follow_symlinks=False)
        for relative in snapshot.directories:
            directory = destination / _normal_relative_path(relative, directory=True)
            directory.mkdir(
                mode=0o700, parents=True, exist_ok=True
            )
            directory.chmod(0o700, follow_symlinks=False)
        for relative, payload in snapshot.files:
            path = destination / _normal_relative_path(relative)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), 0o600)
    except OSError as exc:
        raise FixtureArchiveError(f"cannot materialize captured fixture snapshot: {exc}") from exc


def _verify_snapshot(
    snapshot: _FixtureSnapshot, *, assurance: bool = False
) -> VerificationResult:
    """Reproduce-verify the exact captured bytes, never the mutable caller pathname."""
    with tempfile.TemporaryDirectory(prefix="artifactforge-release-verify-") as temporary:
        temporary_root = Path(temporary)
        try:
            temporary_root.chmod(0o700, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise FixtureArchiveError(
                f"cannot set private release-verification mode: {exc}"
            ) from exc
        fixture = temporary_root / "fixture"
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
    payload = output.getvalue()
    if len(payload) > resources.RESOURCE_POLICY.max_archive_bytes:
        raise FixtureArchiveError(
            "release archive exceeds the "
            f"{resources.RESOURCE_POLICY.max_archive_bytes}-byte limit"
        )
    return payload


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
    if len(payload) > resources.RESOURCE_POLICY.max_archive_bytes:
        raise FixtureArchiveError(
            "release archive exceeds the "
            f"{resources.RESOURCE_POLICY.max_archive_bytes}-byte limit"
        )
    if not payload or len(payload) % _RECORD_SIZE:
        raise FixtureArchiveError(
            f"archive size {len(payload)} is not a multiple of {_RECORD_SIZE} bytes")
    zero = b"\x00" * _BLOCK_SIZE
    block_count = len(payload) // _BLOCK_SIZE
    cursor = 0
    member_count = 0
    manifest_total = 0
    payload_total = 0
    while cursor < block_count:
        header_start = cursor * _BLOCK_SIZE
        header = payload[header_start:header_start + _BLOCK_SIZE]
        if header == zero:
            break
        member_count += 1
        if member_count > resources.RESOURCE_POLICY.max_members:
            raise FixtureArchiveError(
                "archive exceeds the "
                f"{resources.RESOURCE_POLICY.max_members}-member limit"
            )
        if header[257:263] != b"ustar\x00" or header[263:265] != b"00":
            raise FixtureArchiveError("archive contains a non-USTAR member header")
        try:
            size_text = header[124:136].rstrip(b"\x00 ") or b"0"
            if any(character < ord("0") or character > ord("7") for character in size_text):
                raise ValueError
            member_size = int(size_text, 8)
        except ValueError as exc:
            raise FixtureArchiveError("archive member has an invalid USTAR size field") from exc
        try:
            name = header[0:100].split(b"\x00", 1)[0]
            prefix = header[345:500].split(b"\x00", 1)[0]
            raw_name = (prefix + (b"/" if prefix and name else b"") + name).decode("ascii")
        except UnicodeDecodeError as exc:
            raise FixtureArchiveError("archive member name is not printable ASCII") from exc
        typeflag = header[156:157]
        if typeflag not in {b"", b"\x00", b"0", b"5"}:
            raise FixtureArchiveError(
                "archive contains an extension, link, or special member header"
            )
        _normal_relative_path(raw_name, directory=typeflag == b"5")
        if typeflag in {b"", b"\x00", b"0"}:
            is_manifest = raw_name.endswith(f"/{MANIFEST_NAME}")
            byte_limit = (
                resources.RESOURCE_POLICY.max_input_bytes
                if is_manifest else resources.RESOURCE_POLICY.max_file_bytes
            )
            if member_size > byte_limit:
                raise FixtureArchiveError(
                    f"archive member {raw_name!r} exceeds the {byte_limit}-byte limit"
                )
            if is_manifest:
                manifest_total += member_size
                total_limit = resources.RESOURCE_POLICY.max_input_bytes
                total = manifest_total
                kind = "manifest members"
            else:
                payload_total += member_size
                total_limit = resources.RESOURCE_POLICY.max_total_bytes
                total = payload_total
                kind = "payload members"
            if total > total_limit:
                raise FixtureArchiveError(
                    f"archive {kind} exceed the {total_limit}-byte total limit"
                )
        elif typeflag == b"5" and member_size:
            raise FixtureArchiveError("archive directory member has non-zero size")
        member_blocks = (member_size + _BLOCK_SIZE - 1) // _BLOCK_SIZE
        data_start = (cursor + 1) * _BLOCK_SIZE
        data_end = data_start + member_size
        padded_end = (cursor + 1 + member_blocks) * _BLOCK_SIZE
        if padded_end > len(payload):
            raise FixtureArchiveError("archive member data extends past the archive boundary")
        if any(payload[data_end:padded_end]):
            raise FixtureArchiveError("archive member has non-zero USTAR data padding")
        cursor += 1 + member_blocks
    trailer_start = cursor * _BLOCK_SIZE
    if (
        cursor + 1 >= block_count
        or payload[trailer_start:trailer_start + _BLOCK_SIZE] != zero
        or payload[trailer_start + _BLOCK_SIZE:trailer_start + 2 * _BLOCK_SIZE] != zero
        or any(memoryview(payload)[trailer_start:])
    ):
        raise FixtureArchiveError("archive has no canonical all-zero USTAR trailer")
    expected_blocks = ((cursor + 2 + (_RECORD_SIZE // _BLOCK_SIZE) - 1)
                       // (_RECORD_SIZE // _BLOCK_SIZE)) * (_RECORD_SIZE // _BLOCK_SIZE)
    if block_count != expected_blocks:
        raise FixtureArchiveError(
            f"archive has {block_count} blocks; canonical USTAR requires {expected_blocks}")


def _read_descriptor(descriptor: int) -> bytes:
    try:
        return resources.read_stable_descriptor(
            descriptor,
            max_bytes=resources.RESOURCE_POLICY.max_archive_bytes,
            label="release archive descriptor",
        )
    except resources.FixtureResourceError as exc:
        raise FixtureArchiveError(str(exc)) from exc


def _read_archive(
    source: Path | str | int,
) -> tuple[bytes, tuple[tarfile.TarInfo, ...], dict[str, bytes]]:
    if isinstance(source, int):
        payload = _read_descriptor(source)
        display = f"descriptor {source}"
    else:
        path = Path(source)
        try:
            payload = resources.read_stable_regular_path(
                path,
                max_bytes=resources.RESOURCE_POLICY.max_archive_bytes,
                label=f"release archive {path}",
            )
        except (OSError, resources.FixtureResourceError) as exc:
            raise FixtureArchiveError(f"cannot read release archive {path}: {exc}") from exc
        display = str(path)
    _raw_archive_is_canonical(payload)
    members: list[tarfile.TarInfo] = []
    files: dict[str, bytes] = {}
    seen_names: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:", encoding="utf-8",
                          errors="strict") as archive:
            for member in archive:
                if len(members) + 1 > resources.RESOURCE_POLICY.max_members:
                    raise FixtureArchiveError(
                        "archive exceeds the "
                        f"{resources.RESOURCE_POLICY.max_members}-member limit"
                    )
                members.append(member)
                name = _normal_relative_path(member.name, directory=member.isdir())
                if name in seen_names:
                    raise FixtureArchiveError(f"duplicate archive member: {member.name!r}")
                seen_names.add(name)
                if member.isdir():
                    continue
                if not member.isreg():
                    raise FixtureArchiveError(
                        f"archive member is a link or special file: {member.name!r}")
                byte_limit = (
                    resources.RESOURCE_POLICY.max_input_bytes
                    if name.endswith(f"/{MANIFEST_NAME}")
                    else resources.RESOURCE_POLICY.max_file_bytes
                )
                if member.size > byte_limit:
                    raise FixtureArchiveError(
                        f"archive member {name!r} exceeds the {byte_limit}-byte limit"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise FixtureArchiveError(f"cannot read archive member: {member.name!r}")
                chunks: list[bytes] = []
                size = 0
                while size <= byte_limit:
                    chunk = stream.read(min(resources.READ_CHUNK, byte_limit + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                if size > byte_limit:
                    raise FixtureArchiveError(
                        f"archive member {name!r} exceeds the {byte_limit}-byte limit"
                    )
                if size != member.size:
                    raise FixtureArchiveError(
                        f"archive member {name!r} ended at {size} bytes; header declares "
                        f"{member.size}"
                    )
                files[name] = b"".join(chunks)
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
        manifest = parse_fixture_manifest(files[manifest_name], require_canonical=True)
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
    declared = {
        _entry_path(manifest, entry): entry for entry in _manifest_entries(manifest)
    }
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
    required_directories.update(
        f"{archive_root}{PAYLOAD_ROOT}/{relative}/"
        for relative in _manifest_directory_paths(manifest)
    )
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


def _open_or_create_output_parent(
    path: Path,
    *,
    forbidden_identities: frozenset[tuple[int, int]],
) -> tuple[Path, int]:
    """Traverse/create a resolved parent through held no-follow directory descriptors."""
    _unused_file_flags, directory_flags = _required_open_flags()
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute() or absolute.anchor != os.sep:
        raise FixtureArchiveError(f"archive output parent is not an absolute POSIX path: {path}")
    current_fd: int | None = None
    try:
        current_fd = os.open(os.sep, os.O_RDONLY | directory_flags)
        root_state = os.fstat(current_fd)
        if (root_state.st_dev, root_state.st_ino) in forbidden_identities:
            raise FixtureArchiveError("release output must not be placed inside the fixture")
        for component in absolute.parts[1:]:
            created_state: os.stat_result | None = None
            try:
                child_fd = os.open(
                    component,
                    os.O_RDONLY | directory_flags,
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise FixtureArchiveError(
                        f"cannot create archive parent component {component!r}: {exc}"
                    ) from exc
                else:
                    try:
                        created_state = os.stat(
                            component,
                            dir_fd=current_fd,
                            follow_symlinks=False,
                        )
                        os.chmod(
                            component,
                            0o700,
                            dir_fd=current_fd,
                            follow_symlinks=False,
                        )
                        chmod_state = os.stat(
                            component,
                            dir_fd=current_fd,
                            follow_symlinks=False,
                        )
                    except (NotImplementedError, OSError) as exc:
                        raise FixtureArchiveError(
                            f"cannot secure archive parent component {component!r}: {exc}"
                        ) from exc
                    if (
                        not stat.S_ISDIR(created_state.st_mode)
                        or (created_state.st_dev, created_state.st_ino)
                        != (chmod_state.st_dev, chmod_state.st_ino)
                        or stat.S_IMODE(chmod_state.st_mode) != 0o700
                    ):
                        raise FixtureArchiveError(
                            f"new archive parent component changed while securing: {component!r}"
                        )
                try:
                    child_fd = os.open(
                        component,
                        os.O_RDONLY | directory_flags,
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise FixtureArchiveError(
                        f"cannot open new archive parent component {component!r}: {exc}"
                    ) from exc
            except OSError as exc:
                raise FixtureArchiveError(
                    "archive output parents must remain real no-follow directories: "
                    f"{component!r}: {exc}"
                ) from exc

            try:
                opened = os.fstat(child_fd)
                named = os.stat(
                    component,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                    or (
                        created_state is not None
                        and (opened.st_dev, opened.st_ino)
                        != (created_state.st_dev, created_state.st_ino)
                    )
                ):
                    raise FixtureArchiveError(
                        f"archive output parent component changed while opening: {component!r}"
                    )
                if (opened.st_dev, opened.st_ino) in forbidden_identities:
                    raise FixtureArchiveError(
                        "release output must not be placed inside the fixture"
                    )
            except (OSError, FixtureArchiveError):
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return absolute, current_fd
    except FixtureArchiveError:
        if current_fd is not None:
            os.close(current_fd)
        raise
    except OSError as exc:
        if current_fd is not None:
            os.close(current_fd)
        raise FixtureArchiveError(f"cannot traverse archive output parent {absolute}: {exc}") from exc


def _create_private_staging_directory(
    parent_descriptor: int,
    *,
    forbidden_identities: frozenset[tuple[int, int]],
) -> tuple[str, int]:
    """Create and hold one private directory without resolving the parent by pathname."""
    _unused_file_flags, directory_flags = _required_open_flags()
    for _attempt in range(128):
        name = f".artifactforge-release-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        except OSError as exc:
            raise FixtureArchiveError(f"cannot create private archive staging directory: {exc}") from exc

        descriptor: int | None = None
        created: os.stat_result | None = None
        try:
            created = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            os.chmod(
                name,
                0o700,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            chmod_state = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            descriptor = os.open(
                name,
                os.O_RDONLY | directory_flags,
                dir_fd=parent_descriptor,
            )
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            os.fchmod(descriptor, 0o700)
            secured = os.fstat(descriptor)
        except (NotImplementedError, OSError) as exc:
            if descriptor is not None:
                os.close(descriptor)
            if created is not None:
                try:
                    named = os.stat(
                        name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        stat.S_ISDIR(named.st_mode)
                        and (named.st_dev, named.st_ino)
                        == (created.st_dev, created.st_ino)
                    ):
                        os.rmdir(name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            raise FixtureArchiveError(
                f"cannot hold private archive staging directory: {exc}"
            ) from exc
        identities = {
            (created.st_dev, created.st_ino),
            (chmod_state.st_dev, chmod_state.st_ino),
            (opened.st_dev, opened.st_ino),
            (named.st_dev, named.st_ino),
            (secured.st_dev, secured.st_ino),
        }
        if (
            len(identities) != 1
            or stat.S_IMODE(chmod_state.st_mode) != 0o700
            or not stat.S_ISDIR(secured.st_mode)
            or stat.S_IMODE(secured.st_mode) != 0o700
            or (secured.st_dev, secured.st_ino) in forbidden_identities
        ):
            os.close(descriptor)
            try:
                named = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    stat.S_ISDIR(named.st_mode)
                    and (named.st_dev, named.st_ino)
                    == (created.st_dev, created.st_ino)
                ):
                    os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise FixtureArchiveError(
                "private archive staging directory changed while it was secured"
            )
        return name, descriptor
    raise FixtureArchiveError("cannot allocate a unique private archive staging directory")


def _create_private_staging_file(staging_descriptor: int) -> tuple[str, int]:
    """Create and hold one private regular file relative to the held staging directory."""
    file_flags, _unused_directory_flags = _required_open_flags()
    for _attempt in range(128):
        name = f"archive-{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | file_flags,
                0o600,
                dir_fd=staging_descriptor,
            )
        except FileExistsError:
            continue
        except OSError as exc:
            raise FixtureArchiveError(f"cannot create private archive staging file: {exc}") from exc
        created: os.stat_result | None = None
        try:
            created = os.fstat(descriptor)
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=staging_descriptor, follow_symlinks=False)
        except OSError as exc:
            if created is not None:
                try:
                    named = os.stat(
                        name,
                        dir_fd=staging_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        stat.S_ISREG(named.st_mode)
                        and (named.st_dev, named.st_ino)
                        == (created.st_dev, created.st_ino)
                    ):
                        os.unlink(name, dir_fd=staging_descriptor)
                except OSError:
                    pass
            os.close(descriptor)
            raise FixtureArchiveError(f"cannot secure private archive staging file: {exc}") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            try:
                named = os.stat(
                    name,
                    dir_fd=staging_descriptor,
                    follow_symlinks=False,
                )
                if (
                    stat.S_ISREG(named.st_mode)
                    and (named.st_dev, named.st_ino)
                    == (created.st_dev, created.st_ino)
                ):
                    os.unlink(name, dir_fd=staging_descriptor)
            except OSError:
                pass
            os.close(descriptor)
            raise FixtureArchiveError("private archive staging file changed while it was secured")
        return name, descriptor
    raise FixtureArchiveError("cannot allocate a unique private archive staging file")


def create_release_archive(root: Path | str, output: Path | str, *,
                           assurance: bool = False) -> ArchiveResult:
    """Capture once, verify that capture, then exclusively publish only those exact bytes."""
    root = Path(root)
    output = Path(output)
    output_name = output.name
    if os.path.lexists(output):
        raise FixtureArchiveError(f"refusing to replace existing output: {output}")
    # Capture and check producer availability before creating even the output parent.  A
    # parse-only historical fixture can be inspected, but release necessarily promises exact
    # local reproduction and must therefore fail before publication preparation.
    before = _snapshot_fixture(root)
    try:
        require_supported_manifest(before.manifest)
    except FixtureUsageError as exc:
        raise FixtureArchiveError(str(exc)) from exc
    try:
        root_resolved = root.resolve(strict=True)
        prospective_output_parent = output.parent.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise FixtureArchiveError(f"cannot resolve fixture/archive paths: {exc}") from exc
    if (
        prospective_output_parent == root_resolved
        or root_resolved in prospective_output_parent.parents
    ):
        raise FixtureArchiveError("release output must not be placed inside the fixture")

    verification = _verify_snapshot(before, assurance=assurance)
    if not verification.ok:
        raise FixtureArchiveMismatch(verification.failures)
    if before.source_root_identity is None:  # pragma: no cover - disk snapshots always bind it.
        raise FixtureArchiveError("release snapshot lacks its source-root identity")
    if not before.source_directory_identities:  # pragma: no cover - same disk invariant.
        raise FixtureArchiveError("release snapshot lacks its source-directory identities")

    staging_name: str | None = None
    staging_descriptor: int | None = None
    temporary_name: str | None = None
    descriptor: int | None = None
    parent_descriptor: int | None = None
    published_descriptor: int | None = None
    try:
        output_parent, parent_descriptor = _open_or_create_output_parent(
            prospective_output_parent,
            forbidden_identities=before.source_directory_identities,
        )
        output = output_parent / output_name
        try:
            os.stat(output_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot inspect archive output in its pinned parent: {exc}"
            ) from exc
        else:
            raise FixtureArchiveError(f"refusing to replace existing output: {output}")
        staging_name, staging_descriptor = _create_private_staging_directory(
            parent_descriptor,
            forbidden_identities=before.source_directory_identities,
        )
        temporary_name, descriptor = _create_private_staging_file(staging_descriptor)
        _write_archive(descriptor, before)
        postwrite = verify_release_archive(descriptor)
        if not postwrite.ok:
            raise FixtureArchiveMismatch(postwrite.failures)
        try:
            parent_path_state = output_parent.lstat()
            held_parent_state = os.fstat(parent_descriptor)
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot recheck archive output parent before publication: {exc}"
            ) from exc
        if (parent_path_state.st_dev, parent_path_state.st_ino) != (
            held_parent_state.st_dev,
            held_parent_state.st_ino,
        ):
            raise FixtureArchiveError(
                "archive output parent path changed before publication"
            )
        try:
            os.stat(output_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise FixtureArchiveError(
                f"cannot inspect archive output in its pinned parent: {exc}"
            ) from exc
        else:
            raise FixtureArchiveError(f"refusing to replace existing output: {output}")
        try:
            _publish_archive_inode(descriptor, parent_descriptor, output_name)
        except FileExistsError as exc:
            raise FixtureArchiveError(f"refusing to replace existing output: {output}") from exc
        try:
            published_state = os.stat(
                output_name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            file_flags, _directory_flags = _required_open_flags()
            published_descriptor = os.open(
                output_name,
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
                output_name, dir_fd=parent_descriptor, follow_symlinks=False
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
        if temporary_name is not None and descriptor is not None and staging_descriptor is not None:
            try:
                state = os.stat(
                    temporary_name,
                    dir_fd=staging_descriptor,
                    follow_symlinks=False,
                )
                held = os.fstat(descriptor)
                if (state.st_dev, state.st_ino) == (held.st_dev, held.st_ino):
                    os.unlink(temporary_name, dir_fd=staging_descriptor)
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        if published_descriptor is not None:
            os.close(published_descriptor)
        remove_staging = False
        if (
            staging_name is not None
            and staging_descriptor is not None
            and parent_descriptor is not None
        ):
            try:
                named = os.stat(
                    staging_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                held = os.fstat(staging_descriptor)
                if (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino):
                    remove_staging = True
            except OSError:
                pass
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if remove_staging and staging_name is not None and parent_descriptor is not None:
            try:
                os.rmdir(staging_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        if parent_descriptor is not None:
            os.close(parent_descriptor)

    return ArchiveResult(
        path=output,
        sha256=postwrite.sha256,
        size=postwrite.size,
        members=postwrite.members,
        manifest=before.manifest,
        fixture_verification=verification,
    )
