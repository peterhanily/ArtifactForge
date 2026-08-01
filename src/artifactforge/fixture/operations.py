# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Build and verify public, reproducible fixture directories.

Fixtures are deliberately not benchmark suites.  Their recipe seed and every payload digest
are public, while the scene builders' answer-bearing ``join`` record is discarded in memory.
Verification consequently proves manifest integrity and exact recipe reproduction, with
optional format and inertness assurance, but never exposes or pretends to run Gate 2.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

from dataclasses import dataclass

from artifactforge import __version__
from artifactforge.compose.scene import build_macos_scene, build_windows_scene
from artifactforge.content import ContentStore
from artifactforge.fixture.canonical import CanonicalJSONError, canonical_json_bytes
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixtureSpec,
    FixtureValidationError,
    artifact_entries_from_tree,
    validate_artifact_path,
)
from artifactforge.gates import GateReport, inertness, validity
from artifactforge.model import HostProfile


_MANIFEST_NAME = "fixture.json"
_PAYLOAD_NAME = "artifacts"
_SCENE_KEY_DOMAIN = b"artifactforge/fixture/scene-key/v1\0"
_CONTENT_STORE_NAMESPACE = "artifactforge::fixture/v1"
_READ_CHUNK = 1024 * 1024


class FixtureUsageError(ValueError):
    """The fixture request, filesystem state, or on-disk structure is unsafe or malformed."""


class FixturePublicationUncertain(FixtureUsageError):
    """Atomic publication succeeded, but its parent directory could not be made durable."""

    def __init__(self, output: Path, manifest: FixtureManifest, cause: Exception):
        self.output = output
        self.manifest = manifest
        self.published = True
        super().__init__(
            f"fixture output exists and verified at {output}, but publication durability is "
            f"uncertain because the post-rename directory sync failed: {cause}"
        )


@dataclass(frozen=True)
class VerificationResult:
    """The meaningful (exit-code 1) outcome of verifying one well-formed fixture."""

    manifest: FixtureManifest
    failures: tuple[str, ...] = ()
    assurance_reports: tuple[GateReport, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.failures and all(report.ok for report in self.assurance_reports)

    @property
    def assurance_ok(self) -> bool | None:
        if not self.assurance_reports:
            return None
        return all(report.ok for report in self.assurance_reports)

    @property
    def assurance_summary(self) -> dict[str, object]:
        """A stable CLI-facing summary; full reports remain available for rendering."""
        if not self.assurance_reports:
            return {"requested": False, "verdict": "not-run", "gates": []}
        return {
            "requested": True,
            "verdict": "pass" if self.assurance_ok else "fail",
            "gates": [
                {
                    "gate": report.gate,
                    "name": report.name,
                    "verdict": "pass" if report.ok else "fail",
                }
                for report in self.assurance_reports
            ],
        }


def _scene_key(spec: FixtureSpec) -> bytes:
    """Derive a fixture-only scene key without reusing benchmark identifiers or domains."""
    recipe = spec.to_mapping()
    seed_hex = recipe.pop("seed_hex")
    if not isinstance(seed_hex, str):  # FixtureSpec already enforces this; keep the boundary exact.
        raise FixtureUsageError("fixture seed is not a hexadecimal string")
    return hmac.new(
        bytes.fromhex(seed_hex),
        _SCENE_KEY_DOMAIN + canonical_json_bytes(recipe),
        hashlib.sha256,
    ).digest()


def _host_profile(spec: FixtureSpec) -> HostProfile:
    profile = spec.profile
    if profile.id == "windows-loose-v1" and spec.family == "windows":
        return HostProfile("windows", "loose-v1", profile.hostname, profile.username)
    if profile.id == "macos-14-loose-v1" and spec.family == "macos":
        return HostProfile("macos", "14", profile.hostname, profile.username)
    raise FixtureUsageError(
        f"unsupported family/profile combination: {spec.family!r}/{profile.id!r}"
    )


def _materialise_publication(spec: FixtureSpec, publication: Path, work: Path) -> FixtureManifest:
    """Generate one unpublished fixture; answer-bearing scene state never crosses this call."""
    publication.mkdir(mode=0o755)
    artifacts = publication / _PAYLOAD_NAME
    staging = work / "staging"
    content = work / "content"
    work.mkdir(mode=0o700)

    store = ContentStore(_CONTENT_STORE_NAMESPACE, str(content))
    arguments = {
        "store": store,
        "skey": _scene_key(spec),
        "profile": _host_profile(spec),
        "scene_dir": str(artifacts),
        "staging_dir": str(staging),
    }
    if spec.family == "windows":
        scene = build_windows_scene(**arguments)
    elif spec.family == "macos":
        scene = build_macos_scene(**arguments)
    else:  # FixtureSpec rejects this, but do not let dispatch silently fall through.
        raise FixtureUsageError(f"unsupported fixture family: {spec.family!r}")

    # ``join`` is private construction state.  Only the allowlisted payload is retained and
    # the record is explicitly cleared before a manifest is made.
    expected_names = tuple(scene.artifacts)
    scene.join.clear()
    entries = artifact_entries_from_tree(artifacts)
    if tuple(entry.path for entry in entries) != expected_names:
        raise FixtureUsageError(
            "scene builder's allowlist does not equal the generated artifact inventory"
        )

    manifest = FixtureManifest.create(
        spec,
        generator_version=__version__,
        entries=entries,
    )
    manifest_path = publication / _MANIFEST_NAME
    with manifest_path.open("xb") as handle:
        handle.write(manifest.canonical_bytes())
        handle.flush()
        os.fsync(handle.fileno())
    return manifest


def _open_directory_path(path: Path, where: str) -> int:
    """Open and pin a directory without following a swapped final path component."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise FixtureUsageError(f"cannot inspect {where} {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise FixtureUsageError(f"{where} must be a real directory, not a link or special file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise FixtureUsageError(f"cannot safely open {where} {path}: {exc}") from exc
    identity = (opened.st_dev, opened.st_ino)
    if (not stat.S_ISDIR(opened.st_mode)
            or identity != (before.st_dev, before.st_ino)
            or identity != (after.st_dev, after.st_ino)):
        os.close(descriptor)
        raise FixtureUsageError(f"{where} changed while it was being opened")
    return descriptor


def _open_directory_at(parent_descriptor: int, name: str, where: str) -> int:
    """Open a directory entry relative to a pinned parent descriptor."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise FixtureUsageError(
                f"{where} must be a real directory, not a link or special file"
            )
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FixtureUsageError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except (NotImplementedError, OSError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise FixtureUsageError(f"cannot safely open {where}: {exc}") from exc
    identity = (opened.st_dev, opened.st_ino)
    if (not stat.S_ISDIR(opened.st_mode)
            or identity != (before.st_dev, before.st_ino)
            or identity != (after.st_dev, after.st_ino)):
        os.close(descriptor)
        raise FixtureUsageError(f"{where} changed while it was being opened")
    return descriptor


def _directory_path_matches_descriptor(path: Path, descriptor: int) -> bool:
    try:
        path_state = path.lstat()
        descriptor_state = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(path_state.st_mode)
        and (path_state.st_dev, path_state.st_ino)
        == (descriptor_state.st_dev, descriptor_state.st_ino)
    )


def _directory_entry_matches_descriptor(
    parent_descriptor: int, name: str, descriptor: int
) -> bool:
    try:
        path_state = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor_state = os.fstat(descriptor)
    except (NotImplementedError, OSError):
        return False
    return (
        stat.S_ISDIR(path_state.st_mode)
        and (path_state.st_dev, path_state.st_ino)
        == (descriptor_state.st_dev, descriptor_state.st_ino)
    )


def _read_regular_no_follow(path: Path, where: str) -> bytes:
    """Read one stable regular file without following a path swapped after ``lstat``."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise FixtureUsageError(f"cannot inspect {where} {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise FixtureUsageError(f"{where} must be a regular file, not a link or special file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise FixtureUsageError(f"{where} changed to a non-regular file while opening")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise FixtureUsageError(f"{where} changed while it was being opened")
        chunks = []
        while chunk := os.read(descriptor, _READ_CHUNK):
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        after_path = path.lstat()
    except FixtureUsageError:
        raise
    except OSError as exc:
        raise FixtureUsageError(f"cannot read {where} {path} safely: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = (opened.st_dev, opened.st_ino)
    if identity != (after_path.st_dev, after_path.st_ino):
        raise FixtureUsageError(f"{where} changed while it was being read")
    before_state = (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    after_state = (after_read.st_size, after_read.st_mtime_ns, after_read.st_ctime_ns)
    if before_state != after_state:
        raise FixtureUsageError(f"{where} contents changed while they were being read")
    return b"".join(chunks)


def _read_regular_at(parent_descriptor: int, name: str, where: str) -> bytes:
    """Read a stable regular entry relative to one pinned parent directory."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise FixtureUsageError(
                f"{where} must be a regular file, not a link or special file"
            )
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise FixtureUsageError(f"{where} changed while it was being opened")
        chunks = []
        while chunk := os.read(descriptor, _READ_CHUNK):
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FixtureUsageError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise FixtureUsageError(f"cannot read {where} safely: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = (opened.st_dev, opened.st_ino)
    if identity != (after_path.st_dev, after_path.st_ino):
        raise FixtureUsageError(f"{where} changed while it was being read")
    before_state = (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    after_state = (after_read.st_size, after_read.st_mtime_ns, after_read.st_ctime_ns)
    if before_state != after_state:
        raise FixtureUsageError(f"{where} contents changed while they were being read")
    return b"".join(chunks)


def _snapshot_directory_at(
    source_descriptor: int,
    destination: Path,
    *,
    relative_parts: tuple[str, ...] = (),
) -> None:
    """Copy one descriptor-anchored tree into private verification storage."""
    try:
        names = sorted(os.listdir(source_descriptor))
    except OSError as exc:
        raise FixtureUsageError(f"cannot list descriptor-anchored fixture payload: {exc}") from exc
    folded: dict[str, str] = {}
    for name in names:
        relative = "/".join((*relative_parts, name))
        try:
            validate_artifact_path(relative)
        except FixtureValidationError as exc:
            raise FixtureUsageError(f"unsafe fixture payload path: {exc}") from exc
        previous = folded.get(name.casefold())
        if previous is not None and previous != name:
            raise FixtureUsageError(
                f"case-folding artifact path collision: {previous!r} and {name!r}"
            )
        folded[name.casefold()] = name

    destination.mkdir(mode=0o700)
    for name in names:
        relative = "/".join((*relative_parts, name))
        try:
            state = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise FixtureUsageError(f"cannot inspect artifact path {relative!r}: {exc}") from exc
        target = destination / name
        if stat.S_ISLNK(state.st_mode):
            raise FixtureUsageError(f"artifact tree contains a symlink: {relative!r}")
        if stat.S_ISDIR(state.st_mode):
            child_descriptor = _open_directory_at(
                source_descriptor, name, f"artifact directory {relative!r}"
            )
            try:
                _snapshot_directory_at(
                    child_descriptor,
                    target,
                    relative_parts=(*relative_parts, name),
                )
            finally:
                os.close(child_descriptor)
            continue
        if not stat.S_ISREG(state.st_mode):
            raise FixtureUsageError(f"artifact tree contains a special file: {relative!r}")
        payload = _read_regular_at(source_descriptor, name, f"artifact file {relative!r}")
        try:
            with target.open("xb") as handle:
                handle.write(payload)
        except OSError as exc:
            raise FixtureUsageError(
                f"cannot snapshot artifact file {relative!r}: {exc}"
            ) from exc


def _payload_differences(
    expected: tuple[ArtifactEntry, ...], actual: tuple[ArtifactEntry, ...]
) -> list[str]:
    failures: list[str] = []
    expected_by_path = {entry.path: entry for entry in expected}
    actual_by_path = {entry.path: entry for entry in actual}
    missing = sorted(expected_by_path.keys() - actual_by_path.keys())
    extra = sorted(actual_by_path.keys() - expected_by_path.keys())
    if missing:
        failures.append("manifest payload files missing from disk: " + ", ".join(missing))
    if extra:
        failures.append("payload files absent from manifest: " + ", ".join(extra))
    for path in sorted(expected_by_path.keys() & actual_by_path.keys()):
        declared, observed = expected_by_path[path], actual_by_path[path]
        if declared.size != observed.size:
            failures.append(
                f"payload size mismatch for {path!r}: manifest {declared.size}, disk {observed.size}"
            )
        if declared.sha256 != observed.sha256:
            failures.append(
                f"payload SHA-256 mismatch for {path!r}: "
                f"manifest {declared.sha256}, disk {observed.sha256}"
            )
    return failures


def _root_inventory_at(root_descriptor: int) -> list[str]:
    """List a pinned public root while rejecting links and special top-level entries."""
    try:
        names = sorted(os.listdir(root_descriptor))
        for name in names:
            mode = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode) or not (
                stat.S_ISREG(mode) or stat.S_ISDIR(mode)
            ):
                raise FixtureUsageError(
                    f"fixture root contains a linked or special entry: {name!r}"
                )
    except FixtureUsageError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise FixtureUsageError(f"cannot inspect fixture root inventory safely: {exc}") from exc
    return names


def _regular_files_equal(left: Path, right: Path) -> bool:
    """Compare stable no-follow reads, not only the manifest's collision-resistant digests."""
    return _read_regular_no_follow(left, "fixture payload file") == _read_regular_no_follow(
        right, "reproduced payload file"
    )


def _exact_reproduction_differences(
    fixture_artifacts: Path, reproduced_artifacts: Path
) -> list[str]:
    observed = artifact_entries_from_tree(fixture_artifacts)
    reproduced = artifact_entries_from_tree(reproduced_artifacts)
    observed_paths = {entry.path for entry in observed}
    reproduced_paths = {entry.path for entry in reproduced}
    failures: list[str] = []
    missing = sorted(reproduced_paths - observed_paths)
    extra = sorted(observed_paths - reproduced_paths)
    if missing:
        failures.append("recipe reproduction produced files missing on disk: " + ", ".join(missing))
    if extra:
        failures.append("disk payload has files absent from recipe reproduction: " + ", ".join(extra))
    for relative in sorted(observed_paths & reproduced_paths):
        if not _regular_files_equal(
            fixture_artifacts / Path(relative), reproduced_artifacts / Path(relative)
        ):
            failures.append(f"payload bytes do not reproduce for {relative!r}")
    return failures


def require_supported_manifest(manifest: FixtureManifest) -> None:
    """Reject recipes whose exact generator implementation is not available locally."""
    if not isinstance(manifest, FixtureManifest):
        raise FixtureUsageError("fixture manifest is not a validated FixtureManifest")
    if manifest.generator.version != __version__:
        raise FixtureUsageError(
            "unsupported fixture generator version: "
            f"manifest requires {manifest.generator.version!r}, installed is {__version__!r}"
        )


def _verify_fixture(root: Path, *, assurance: bool) -> VerificationResult:
    root_descriptor = _open_directory_path(root, "fixture root")
    artifacts_descriptor = -1
    verification_root: Path | None = None
    try:
        artifacts_descriptor = _open_directory_at(
            root_descriptor, _PAYLOAD_NAME, "fixture payload"
        )
        raw_manifest = _read_regular_at(
            root_descriptor, _MANIFEST_NAME, "fixture manifest"
        )
        manifest = FixtureManifest.from_json(raw_manifest)
        require_supported_manifest(manifest)

        # APIs such as the parser gates require pathnames. Snapshot from held descriptors into
        # private system-temporary storage first, so no later pathname traversal can be steered
        # by replacing the caller's fixture root.
        verification_root = Path(tempfile.mkdtemp(prefix="artifactforge-verify-"))
        artifacts = verification_root / "observed-artifacts"
        _snapshot_directory_at(artifacts_descriptor, artifacts)
        actual_entries = artifact_entries_from_tree(artifacts)
        failures: list[str] = []
        root_names = _root_inventory_at(root_descriptor)
        if root_names != [_PAYLOAD_NAME, _MANIFEST_NAME]:
            failures.append(
                "fixture root inventory must be exactly artifacts/ and fixture.json; found "
                + ", ".join(root_names)
            )
        if raw_manifest != manifest.canonical_bytes():
            failures.append("fixture.json is not canonical ArtifactForge JSON")
        failures.extend(_payload_differences(manifest.payload.files, actual_entries))

        # Verification is read-only with respect to the fixture and must work from read-only
        # media. Its unpublished reproduction has no same-filesystem publication requirement.
        publication = verification_root / "reproduced-fixture"
        work = verification_root / "work"
        _materialise_publication(manifest.recipe, publication, work)
        failures.extend(
            _exact_reproduction_differences(artifacts, publication / _PAYLOAD_NAME)
        )

        reports: tuple[GateReport, ...] = ()
        if assurance:
            reports = (validity.run(str(artifacts)), inertness.run(str(artifacts)))
            for report in reports:
                if not report.ok:
                    failures.append(
                        f"assurance Gate {report.gate} ({report.name}) failed: "
                        + "; ".join(report.fails)
                    )

        # Bind the result to one stable snapshot. Every operation above reached the originally
        # opened root through its held descriptor, never through a replaceable parent path.
        if not _directory_path_matches_descriptor(root, root_descriptor):
            raise FixtureUsageError("fixture root changed during verification")
        if not _directory_entry_matches_descriptor(
            root_descriptor, _PAYLOAD_NAME, artifacts_descriptor
        ):
            raise FixtureUsageError("fixture payload directory changed during verification")
        if _root_inventory_at(root_descriptor) != root_names:
            raise FixtureUsageError("fixture root inventory changed during verification")
        if _read_regular_at(
            root_descriptor, _MANIFEST_NAME, "fixture manifest"
        ) != raw_manifest:
            raise FixtureUsageError("fixture manifest changed during verification")
        final_artifacts = verification_root / "final-artifacts"
        _snapshot_directory_at(artifacts_descriptor, final_artifacts)
        final_entries = artifact_entries_from_tree(final_artifacts)
        if final_entries != actual_entries:
            raise FixtureUsageError("fixture payload changed during verification")
        for entry in actual_entries:
            relative = Path(entry.path)
            if not _regular_files_equal(artifacts / relative, final_artifacts / relative):
                raise FixtureUsageError("fixture payload changed during verification")

        return VerificationResult(manifest, tuple(dict.fromkeys(failures)), reports)
    except FixtureUsageError:
        raise
    except (OSError, CanonicalJSONError, FixtureValidationError, UnicodeError) as exc:
        raise FixtureUsageError(f"malformed fixture: {exc}") from exc
    finally:
        if verification_root is not None:
            shutil.rmtree(verification_root, ignore_errors=True)
        if artifacts_descriptor >= 0:
            os.close(artifacts_descriptor)
        os.close(root_descriptor)


def verify_fixture(
    root: str | os.PathLike[str], *, assurance: bool = False
) -> VerificationResult:
    """Verify canonical integrity, exact recipe reproduction, and optional Gates 1 and 3."""
    try:
        root_path = Path(root)
    except TypeError as exc:
        raise FixtureUsageError("fixture root must be a filesystem path") from exc
    try:
        return _verify_fixture(root_path, assurance=assurance)
    except FixtureUsageError:
        raise
    except (OSError, FixtureValidationError, CanonicalJSONError, UnicodeError) as exc:
        raise FixtureUsageError(f"cannot verify fixture {root_path}: {exc}") from exc


def _rename_no_replace(source: Path, destination: Path) -> None:
    """Atomically rename a directory and fail if *anything* already names the destination."""
    source_bytes = os.fsencode(os.path.abspath(source))
    destination_bytes = os.fsencode(os.path.abspath(destination))

    if os.name == "nt":
        os.rename(source, destination)  # Windows rename is no-replace.
        return

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        rename = libc.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(source_bytes, destination_bytes, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        result = rename(-100, source_bytes, -100, destination_bytes, 0x00000001)
    else:
        raise OSError(errno.ENOTSUP, "platform has no atomic no-replace directory rename")

    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(error, os.strerror(error), destination)
        raise OSError(error, os.strerror(error), destination)


def _publish_directory(source: Path, destination: Path) -> None:
    try:
        _rename_no_replace(source, destination)
    except FileExistsError as exc:
        raise FixtureUsageError(
            f"refusing to replace fixture output that appeared during build: {destination}"
        ) from exc
    except OSError as exc:
        raise FixtureUsageError(f"cannot atomically publish fixture {destination}: {exc}") from exc


def _fsync_directory(directory: Path) -> None:
    """Synchronise one directory, failing rather than silently weakening durability."""
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = -1
    try:
        descriptor = os.open(directory, flags)
        os.fsync(descriptor)
    except OSError as exc:
        raise FixtureUsageError(f"cannot sync directory {directory}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    """Make every generated byte and directory entry durable before publication."""
    directories: list[Path] = []
    try:
        for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            directories.append(current_path)
            dirnames.sort()
            filenames.sort()
            for dirname in dirnames:
                state = (current_path / dirname).lstat()
                if stat.S_ISLNK(state.st_mode) or not stat.S_ISDIR(state.st_mode):
                    raise FixtureUsageError(
                        f"generated publication contains an unsafe directory: {dirname!r}"
                    )
            for filename in filenames:
                path = current_path / filename
                state = path.lstat()
                if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
                    raise FixtureUsageError(
                        f"generated publication contains an unsafe file: {filename!r}"
                    )
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(path, flags)
                try:
                    opened = os.fstat(descriptor)
                    if ((opened.st_dev, opened.st_ino) != (state.st_dev, state.st_ino)
                            or not stat.S_ISREG(opened.st_mode)):
                        raise FixtureUsageError(
                            f"generated publication file changed before sync: {path}"
                        )
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        for directory in reversed(directories):
            if os.name == "nt":
                continue
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(directory, flags)
            try:
                if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise FixtureUsageError(
                        f"generated publication directory changed before sync: {directory}"
                    )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except FixtureUsageError:
        raise
    except OSError as exc:
        raise FixtureUsageError(f"cannot sync generated fixture tree {root}: {exc}") from exc


def build_fixture(
    spec: FixtureSpec, output: str | os.PathLike[str]
) -> FixtureManifest:
    """Build, reproduce-verify, then atomically publish a new fixture directory."""
    if not isinstance(spec, FixtureSpec):
        raise FixtureUsageError("build_fixture requires a validated FixtureSpec")
    try:
        requested = Path(output)
    except TypeError as exc:
        raise FixtureUsageError("fixture output must be a filesystem path") from exc
    if not requested.name:
        raise FixtureUsageError("fixture output must name a directory below its parent")
    if os.path.lexists(requested):
        raise FixtureUsageError(f"refusing existing fixture output: {requested}")

    try:
        requested.parent.mkdir(parents=True, exist_ok=True)
        parent = requested.parent.resolve(strict=True)
    except OSError as exc:
        raise FixtureUsageError(f"cannot prepare fixture output parent {requested.parent}: {exc}") from exc
    output_path = parent / requested.name
    if os.path.lexists(output_path):
        raise FixtureUsageError(f"refusing existing fixture output: {output_path}")
    # Fail before generation if this filesystem cannot provide the durability primitive that
    # must commit the final rename. A later failure is necessarily an uncertain I/O event.
    _fsync_directory(parent)

    temporary_root = Path(tempfile.mkdtemp(prefix=f".{requested.name}.build-", dir=parent))
    publication = temporary_root / "publication"
    work = temporary_root / "work"
    try:
        manifest = _materialise_publication(spec, publication, work)
        result = _verify_fixture(publication, assurance=False)
        if not result.ok:
            raise FixtureUsageError(
                "newly generated fixture failed reproduction verification: "
                + "; ".join(result.failures)
            )
        shutil.rmtree(work)
        _fsync_tree(publication)
        _publish_directory(publication, output_path)
        try:
            _fsync_directory(parent)
        except FixtureUsageError as exc:
            raise FixturePublicationUncertain(output_path, manifest, exc) from exc
        return manifest
    except FixtureUsageError:
        raise
    except (OSError, FixtureValidationError, CanonicalJSONError, UnicodeError) as exc:
        raise FixtureUsageError(f"cannot build fixture {output_path}: {exc}") from exc
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
