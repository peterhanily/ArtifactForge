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
from urllib.parse import urlsplit

from dataclasses import dataclass

from artifactforge import __version__
from artifactforge.compose.derivation import FIXTURE_V2_SCENE_DERIVATION
from artifactforge.compose.scene import (
    build_linux_scene,
    build_macos_scene,
    build_windows_download_only_scene,
    build_windows_scene,
)
from artifactforge.content import ContentStore
from artifactforge.fixture.abi import (
    FixtureProducerUnavailable,
    require_manifest_producer,
    require_spec_producer,
)
from artifactforge.fixture.canonical import CanonicalJSONError, canonical_json_bytes
from artifactforge.fixture import resources
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixtureSpec,
    FixtureValidationError,
    artifact_entries_from_tree,
    parse_fixture_manifest,
    validate_artifact_path,
)
from artifactforge.fixture.model_v2 import (
    CONTENT_STORE_NAMESPACE_V2,
    SCENE_KEY_DOMAIN_V2,
    FileNodeV2,
    FixtureManifestV2,
    FixturePayloadV2,
    FixtureSpecV2,
    MacOSMetadataV2,
    WindowsMetadataV2,
)
from artifactforge.gates import GateReport, inertness, validity
from artifactforge.inventory import InventoryError, inventory_regular_files, open_real_directory
from artifactforge.inventory import write_regular_file_at
from artifactforge.model import HostProfile


_MANIFEST_NAME = "fixture.json"
_PAYLOAD_NAME = "artifacts"
_SCENE_KEY_DOMAIN = b"artifactforge/fixture/scene-key/v1\0"
_CONTENT_STORE_NAMESPACE = "artifactforge::fixture/v1"

FixtureSpecRecord = FixtureSpec | FixtureSpecV2
FixtureManifestRecord = FixtureManifest | FixtureManifestV2


def _stable_state(value: os.stat_result) -> tuple[int, int, int, int, int]:
    """State fields that bind one path observation to one stable inode version."""
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class FixtureUsageError(ValueError):
    """The fixture request, filesystem state, or on-disk structure is unsafe or malformed."""


class FixturePublicationUncertain(FixtureUsageError):
    """Atomic publication succeeded, but its parent directory could not be made durable."""

    def __init__(self, output: Path, manifest: FixtureManifestRecord, cause: Exception):
        self.output = output
        self.manifest = manifest
        self.published = True
        super().__init__(
            f"fixture output exists and verified at {output}, but publication durability is "
            f"uncertain because the post-rename directory sync failed: {cause}"
        )


def require_supported_spec(spec: FixtureSpecRecord) -> None:
    """Require an explicit local producer record before any fixture writer can run."""
    if type(spec) not in (FixtureSpec, FixtureSpecV2):
        raise FixtureUsageError("fixture spec is not a validated fixture specification")
    try:
        require_spec_producer(spec.schema)
    except FixtureProducerUnavailable as exc:
        raise FixtureUsageError(str(exc)) from exc


@dataclass(frozen=True)
class VerificationResult:
    """The meaningful (exit-code 1) outcome of verifying one well-formed fixture."""

    manifest: FixtureManifestRecord
    failures: tuple[str, ...] = ()
    assurance_reports: tuple[GateReport, ...] = ()
    integrity_failures: tuple[str, ...] = ()
    reproduction_failures: tuple[str, ...] = ()
    reproduction_requested: bool = True

    @property
    def ok(self) -> bool:
        return not self.failures and all(report.ok for report in self.assurance_reports)

    @property
    def assurance_ok(self) -> bool | None:
        if not self.assurance_reports:
            return None
        return all(report.ok for report in self.assurance_reports)

    @property
    def integrity_ok(self) -> bool:
        """Whether the record agrees with declared names, default streams, and modes."""
        if self.integrity_failures:
            return False
        # Preserve conservative behavior for externally constructed legacy results that did
        # not provide the phase-specific fields.
        if self.failures and not self.reproduction_failures and not self.assurance_reports:
            return False
        return True

    @property
    def reproduction_ok(self) -> bool | None:
        """Whether an available exact producer regenerated the complete logical fixture."""
        if not self.reproduction_requested:
            return None
        return not self.reproduction_failures

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


def _scene_key(spec: FixtureSpecRecord) -> bytes:
    """Derive a fixture-only scene key without reusing benchmark identifiers or domains."""
    recipe = spec.to_mapping()
    seed_hex = recipe.pop("seed_hex")
    if not isinstance(seed_hex, str):  # FixtureSpec already enforces this; keep the boundary exact.
        raise FixtureUsageError("fixture seed is not a hexadecimal string")
    domain = _SCENE_KEY_DOMAIN if type(spec) is FixtureSpec else SCENE_KEY_DOMAIN_V2
    return hmac.new(
        bytes.fromhex(seed_hex),
        domain + canonical_json_bytes(recipe),
        hashlib.sha256,
    ).digest()


def _host_profile(spec: FixtureSpecRecord) -> HostProfile:
    profile = spec.profile
    if profile.id == "windows-loose-v1" and spec.family == "windows":
        return HostProfile("windows", "loose-v1", profile.hostname, profile.username)
    if profile.id == "macos-14-loose-v1" and spec.family == "macos":
        return HostProfile("macos", "14", profile.hostname, profile.username)
    if profile.id == "linux-glibc-x86_64-loose-v1" and spec.family == "linux":
        return HostProfile("linux", "glibc-x86_64", profile.hostname, profile.username)
    if profile.id == "windows-loose-v2" and spec.family == "windows":
        return HostProfile("windows", "loose-v2", profile.hostname, profile.username)
    if profile.id == "macos-14-loose-v2" and spec.family == "macos":
        return HostProfile("macos", "14", profile.hostname, profile.username)
    if profile.id == "linux-glibc-x86_64-loose-v2" and spec.family == "linux":
        return HostProfile("linux", "glibc-x86_64", profile.hostname, profile.username)
    raise FixtureUsageError(
        f"unsupported family/profile combination: {spec.family!r}/{profile.id!r}"
    )


def _set_exact_mode(path: Path, mode: int) -> None:
    """Set one private carrier inode to a fixed non-logical publication mode."""
    try:
        path.chmod(mode, follow_symlinks=False)
    except (NotImplementedError, OSError) as exc:
        raise FixtureUsageError(f"cannot set fixed carrier mode on {path}: {exc}") from exc
    if os.name != "nt" and stat.S_IMODE(path.lstat().st_mode) != mode:
        raise FixtureUsageError(f"carrier path does not have required mode {mode:#o}: {path}")


def _materialise_v2_carrier(
    artifacts: Path, files: tuple[tuple[str, bytes], ...]
) -> None:
    """Write declared default streams with fixed modes; do not project logical metadata."""
    artifacts.mkdir(mode=0o700)
    _set_exact_mode(artifacts, 0o700)
    root_descriptor = -1
    try:
        root_descriptor = open_real_directory(artifacts)
        for relative, data in files:
            write_regular_file_at(root_descriptor, relative, data, mode=0o600)
    except InventoryError as exc:
        raise FixtureUsageError(f"cannot materialise v2 carrier: {exc}") from exc
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
    for current, dirnames, filenames in os.walk(artifacts, topdown=False, followlinks=False):
        current_path = Path(current)
        for filename in filenames:
            _set_exact_mode(current_path / filename, 0o600)
        for dirname in dirnames:
            _set_exact_mode(current_path / dirname, 0o700)
    _set_exact_mode(artifacts, 0o700)


def _build_scene(
    spec: FixtureSpecRecord, *, store: ContentStore, scene_dir: Path, staging: Path
):
    arguments = {
        "store": store,
        "skey": _scene_key(spec),
        "profile": _host_profile(spec),
        "scene_dir": str(scene_dir),
        "staging_dir": str(staging),
    }
    if type(spec) is FixtureSpecV2:
        # A v2 recipe selects its scene by story, not by family. The benchmark keeps calling
        # the builders directly: its scenario shape is frozen at five questions per scene, so a
        # story that changed that shape would have to re-enter Gate 4's registered attack
        # surface before it could mean anything.
        arguments["causal_clock"] = spec.causal_clock
        arguments["derivation"] = FIXTURE_V2_SCENE_DERIVATION
        if spec.story == "windows-dropper-v1":
            return build_windows_scene(**arguments)
        if spec.story == "windows-download-only-v1":
            return build_windows_download_only_scene(**arguments)
        if spec.story == "macos-quarantined-app-v1":
            return build_macos_scene(**arguments)
        if spec.story == "linux-autostart-v1":
            return build_linux_scene(**arguments)
        raise FixtureUsageError(f"fixture story has no registered builder: {spec.story!r}")
    if spec.family == "windows":
        return build_windows_scene(**arguments)
    if spec.family == "macos":
        return build_macos_scene(**arguments)
    if spec.family == "linux":
        return build_linux_scene(**arguments)
    raise FixtureUsageError(f"unsupported fixture family: {spec.family!r}")


def _materialise_publication(
    spec: FixtureSpecRecord, publication: Path, work: Path
) -> FixtureManifestRecord:
    """Generate one unpublished fixture; answer-bearing scene state never crosses this call."""
    require_supported_spec(spec)
    publication.mkdir(mode=0o700)
    _set_exact_mode(publication, 0o700)
    artifacts = publication / _PAYLOAD_NAME
    staging = work / "staging"
    scene_dir = artifacts if type(spec) is FixtureSpec else work / "loose-scene"
    content = work / "content"
    work.mkdir(mode=0o700)
    _set_exact_mode(work, 0o700)

    namespace = (
        _CONTENT_STORE_NAMESPACE if type(spec) is FixtureSpec else CONTENT_STORE_NAMESPACE_V2
    )
    store = ContentStore(namespace, str(content))
    scene = _build_scene(spec, store=store, scene_dir=scene_dir, staging=staging)

    if type(spec) is FixtureSpecV2:
        # Lazy import keeps the public ``artifactforge.fixture`` package initializer from
        # cycling through operations while the standalone projection module imports models.
        from artifactforge.compose.fixture_scene_v2 import project_fixture_scene_v2

        try:
            inventory = inventory_regular_files(scene_dir, capture_bytes=True)
        except InventoryError as exc:
            raise FixtureUsageError(f"cannot capture generated v2 loose scene: {exc}") from exc
        loose_files = {}
        for item in inventory:
            if item.data is None:  # capture_bytes=True is an invariant.
                raise FixtureUsageError("generated v2 loose scene was not captured")
            loose_files[item.relative_path] = item.data
        plan = project_fixture_scene_v2(spec=spec, scene=scene, loose_files=loose_files)
        # The projection has copied only the answer-free public facts it needs.  Destroy the
        # private construction state before writing any public path or manifest.
        scene.join.clear()
        _materialise_v2_carrier(artifacts, plan.default_files)
        payload = FixturePayloadV2.create(
            family=spec.family,
            directories=plan.directories,
            files=plan.file_nodes,
        )
        manifest: FixtureManifestRecord = FixtureManifestV2.create(
            generator_version=__version__, recipe=spec, payload=payload
        )
    else:
        # ``join`` is private construction state.  Only the allowlisted payload is retained
        # and the record is explicitly cleared before a v1 manifest is made.
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
    _set_exact_mode(manifest_path, 0o600)
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
    if (not stat.S_ISDIR(opened.st_mode)
            or _stable_state(opened) != _stable_state(before)
            or _stable_state(opened) != _stable_state(after)):
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
    if (not stat.S_ISDIR(opened.st_mode)
            or _stable_state(opened) != _stable_state(before)
            or _stable_state(opened) != _stable_state(after)):
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


def _read_regular_no_follow(
    path: Path,
    where: str,
    *,
    max_bytes: int | None = None,
) -> bytes:
    """Read one stable regular file without following a path swapped after ``lstat``."""
    try:
        return resources.read_stable_regular_path(
            path,
            max_bytes=(
                resources.RESOURCE_POLICY.max_file_bytes
                if max_bytes is None
                else max_bytes
            ),
            label=f"{where} {path}",
        )
    except resources.FixtureResourceError as exc:
        raise FixtureUsageError(str(exc)) from exc


def _read_regular_at(
    parent_descriptor: int,
    name: str,
    where: str,
    *,
    max_bytes: int | None = None,
) -> bytes:
    """Read a stable regular entry relative to one pinned parent directory."""
    try:
        return resources.read_stable_regular_at(
            parent_descriptor,
            name,
            max_bytes=(
                resources.RESOURCE_POLICY.max_file_bytes
                if max_bytes is None
                else max_bytes
            ),
            label=where,
        )
    except resources.FixtureResourceError as exc:
        raise FixtureUsageError(str(exc)) from exc


@dataclass
class _SnapshotBudget:
    members: int = 0
    files: int = 0
    total_bytes: int = 0


@dataclass
class _SnapshotObservations:
    """First-pass states needed to reject a cross-file mixed snapshot."""

    directory_names: dict[tuple[str, ...], tuple[str, ...]]
    directory_states: dict[tuple[str, ...], tuple[int, int, int, int, int]]
    file_states: dict[tuple[str, ...], tuple[int, int, int, int, int]]


def _revalidate_snapshot_directory_at(
    source_descriptor: int,
    observations: _SnapshotObservations,
    relative_parts: tuple[str, ...],
) -> None:
    """Recheck the complete first-pass tree after its last byte was captured."""
    shown = "/".join(relative_parts) or "."
    expected_directory_state = observations.directory_states[relative_parts]
    if _stable_state(os.fstat(source_descriptor)) != expected_directory_state:
        raise FixtureUsageError(
            f"artifact directory changed after snapshotting: {shown!r}"
        )

    expected_names = observations.directory_names[relative_parts]
    try:
        names = resources.bounded_directory_names(
            source_descriptor,
            max_entries=len(expected_names),
            label=f"fixture payload directory {shown!r}",
        )
    except resources.FixtureResourceError as exc:
        raise FixtureUsageError(
            f"artifact directory changed after snapshotting: {shown!r}: {exc}"
        ) from exc
    if names != expected_names:
        raise FixtureUsageError(
            f"artifact directory changed after snapshotting: {shown!r}"
        )

    for name in names:
        parts = (*relative_parts, name)
        relative = "/".join(parts)
        try:
            current = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise FixtureUsageError(
                f"cannot recheck artifact path {relative!r}: {exc}"
            ) from exc
        if parts in observations.file_states:
            if (
                not stat.S_ISREG(current.st_mode)
                or _stable_state(current) != observations.file_states[parts]
            ):
                raise FixtureUsageError(
                    f"artifact file changed after snapshotting: {relative!r}"
                )
            continue
        if parts not in observations.directory_states or not stat.S_ISDIR(current.st_mode):
            raise FixtureUsageError(
                f"artifact path changed after snapshotting: {relative!r}"
            )
        child_descriptor = _open_directory_at(
            source_descriptor, name, f"artifact directory {relative!r}"
        )
        try:
            _revalidate_snapshot_directory_at(child_descriptor, observations, parts)
            path_after = os.stat(
                name, dir_fd=source_descriptor, follow_symlinks=False
            )
            if _stable_state(path_after) != observations.directory_states[parts]:
                raise FixtureUsageError(
                    f"artifact directory changed after snapshotting: {relative!r}"
                )
        except (NotImplementedError, OSError) as exc:
            raise FixtureUsageError(
                f"cannot recheck artifact directory {relative!r}: {exc}"
            ) from exc
        finally:
            os.close(child_descriptor)

    if _stable_state(os.fstat(source_descriptor)) != expected_directory_state:
        raise FixtureUsageError(
            f"artifact directory changed after snapshotting: {shown!r}"
        )


def _snapshot_directory_at(
    source_descriptor: int,
    destination: Path,
    *,
    relative_parts: tuple[str, ...] = (),
    budget: _SnapshotBudget | None = None,
    _observations: _SnapshotObservations | None = None,
    expected_file_mode: int | None = None,
    expected_directory_mode: int | None = None,
) -> None:
    """Copy one descriptor-anchored tree into private verification storage."""
    if budget is None:
        budget = _SnapshotBudget()
    root_call = _observations is None
    if _observations is None:
        _observations = _SnapshotObservations({}, {}, {})
    before_directory = os.fstat(source_descriptor)
    if (
        expected_directory_mode is not None
        and os.name != "nt"
        and stat.S_IMODE(before_directory.st_mode) != expected_directory_mode
    ):
        shown = "/".join(relative_parts) or "."
        raise FixtureUsageError(
            f"fixture carrier directory mode for {shown!r} must be "
            f"{expected_directory_mode:#o}"
        )
    try:
        names = resources.bounded_directory_names(
            source_descriptor,
            max_entries=resources.RESOURCE_POLICY.max_members,
            label="fixture payload tree",
        )
    except resources.FixtureResourceError as exc:
        raise FixtureUsageError(str(exc)) from exc
    budget.members += len(names)
    if budget.members > resources.RESOURCE_POLICY.max_members:
        raise FixtureUsageError(
            "fixture payload tree exceeds the "
            f"{resources.RESOURCE_POLICY.max_members}-member limit"
        )
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
    _set_exact_mode(destination, 0o700)
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
                    budget=budget,
                    _observations=_observations,
                    expected_file_mode=expected_file_mode,
                    expected_directory_mode=expected_directory_mode,
                )
            finally:
                os.close(child_descriptor)
            continue
        if not stat.S_ISREG(state.st_mode):
            raise FixtureUsageError(f"artifact tree contains a special file: {relative!r}")
        if (
            expected_file_mode is not None
            and os.name != "nt"
            and stat.S_IMODE(state.st_mode) != expected_file_mode
        ):
            raise FixtureUsageError(
                f"fixture carrier file mode for {relative!r} must be {expected_file_mode:#o}"
            )
        if state.st_size > resources.RESOURCE_POLICY.max_file_bytes:
            raise FixtureUsageError(
                f"artifact file exceeds the {resources.RESOURCE_POLICY.max_file_bytes}-byte "
                f"limit: {relative!r}"
            )
        budget.files += 1
        if budget.files > resources.RESOURCE_POLICY.max_files:
            raise FixtureUsageError(
                f"fixture payload tree exceeds the {resources.RESOURCE_POLICY.max_files}-file limit"
            )
        remaining = resources.RESOURCE_POLICY.max_total_bytes - budget.total_bytes
        if state.st_size > remaining:
            raise FixtureUsageError(
                "fixture payload tree exceeds the "
                f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
            )
        payload = _read_regular_at(
            source_descriptor,
            name,
            f"artifact file {relative!r}",
            max_bytes=min(resources.RESOURCE_POLICY.max_file_bytes, remaining),
        )
        try:
            after_path = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise FixtureUsageError(
                f"cannot recheck artifact file {relative!r}: {exc}"
            ) from exc
        if _stable_state(state) != _stable_state(after_path):
            raise FixtureUsageError(
                f"artifact file changed while snapshotting: {relative!r}"
            )
        actual_size = len(payload)
        if actual_size > remaining:
            raise FixtureUsageError(
                "fixture payload tree exceeds the "
                f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
            )
        # Commit the actual stable byte count only after every race check has passed.
        budget.total_bytes += actual_size
        _observations.file_states[(*relative_parts, name)] = _stable_state(after_path)
        try:
            with target.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fchmod(handle.fileno(), 0o600)
        except OSError as exc:
            raise FixtureUsageError(
                f"cannot snapshot artifact file {relative!r}: {exc}"
            ) from exc
    after_directory = os.fstat(source_descriptor)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(
        getattr(before_directory, field) != getattr(after_directory, field)
        for field in stable_fields
    ):
        shown = "/".join(relative_parts) or "."
        raise FixtureUsageError(
            f"artifact directory changed while snapshotting: {shown!r}"
        )
    _observations.directory_names[relative_parts] = names
    _observations.directory_states[relative_parts] = _stable_state(after_directory)
    if root_call:
        _revalidate_snapshot_directory_at(
            source_descriptor, _observations, relative_parts
        )


def _manifest_file_path(entry: ArtifactEntry | FileNodeV2) -> str:
    if type(entry) is ArtifactEntry:
        return entry.path
    if type(entry) is FileNodeV2:
        return entry.served_path
    raise FixtureUsageError("fixture manifest contains an unsupported file record")


def _manifest_file_entries(
    manifest: FixtureManifestRecord,
) -> tuple[ArtifactEntry | FileNodeV2, ...]:
    return tuple(manifest.payload.files)


def _directory_prefixes(paths: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                "/".join(parts[:end])
                for path in paths
                for parts in (path.split("/"),)
                for end in range(1, len(parts))
            }
        )
    )


def _manifest_directory_paths(manifest: FixtureManifestRecord) -> tuple[str, ...]:
    if type(manifest) is FixtureManifestV2:
        return tuple(node.served_path for node in manifest.payload.directories)
    return _directory_prefixes(tuple(entry.path for entry in manifest.payload.files))


def _payload_differences(
    manifest: FixtureManifestRecord, actual: tuple[ArtifactEntry, ...]
) -> list[str]:
    failures: list[str] = []
    expected = _manifest_file_entries(manifest)
    expected_by_path = {_manifest_file_path(entry): entry for entry in expected}
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
    expected_directories = _manifest_directory_paths(manifest)
    actual_directories = _directory_prefixes(tuple(actual_by_path))
    missing_directories = sorted(set(expected_directories) - set(actual_directories))
    extra_directories = sorted(set(actual_directories) - set(expected_directories))
    if missing_directories:
        failures.append(
            "manifest payload directories missing from disk: "
            + ", ".join(missing_directories)
        )
    if extra_directories:
        failures.append(
            "payload directories absent from manifest: " + ", ".join(extra_directories)
        )
    return failures


def _root_inventory_at(root_descriptor: int) -> list[str]:
    """List a pinned public root while rejecting links and special top-level entries."""
    try:
        names = list(resources.bounded_directory_names(
            root_descriptor,
            max_entries=2,
            label="fixture root",
        ))
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
    except (NotImplementedError, OSError, resources.FixtureResourceError) as exc:
        raise FixtureUsageError(f"cannot inspect fixture root inventory safely: {exc}") from exc
    return names


def _regular_files_equal(left: Path, right: Path) -> bool:
    """Compare stable no-follow reads, not only the manifest's collision-resistant digests."""
    return _read_regular_no_follow(left, "fixture payload file") == _read_regular_no_follow(
        right, "reproduced payload file"
    )


def _manifest_reproduction_mapping(manifest: FixtureManifestRecord) -> dict[str, object]:
    """Return all reproducible semantics, excluding only informational package provenance."""
    mapping = manifest.to_mapping()
    if type(manifest) is FixtureManifestV2:
        generator = mapping.get("generator")
        if not isinstance(generator, dict):  # validated model invariant
            raise FixtureUsageError("v2 generator identity is malformed")
        generator = dict(generator)
        generator.pop("version", None)
        mapping = dict(mapping)
        mapping["generator"] = generator
    return mapping


def _exact_reproduction_differences(
    fixture_artifacts: Path,
    reproduced_artifacts: Path,
    *,
    declared_manifest: FixtureManifestRecord,
    reproduced_manifest: FixtureManifestRecord,
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
    if _manifest_reproduction_mapping(declared_manifest) != _manifest_reproduction_mapping(
        reproduced_manifest
    ):
        failures.append(
            "recipe reproduction does not reproduce the complete logical fixture manifest"
        )
    return failures


def require_supported_manifest(manifest: FixtureManifestRecord) -> None:
    """Reject recipes whose exact generator implementation is not available locally."""
    if type(manifest) not in (FixtureManifest, FixtureManifestV2):
        raise FixtureUsageError("fixture manifest is not a validated fixture manifest")
    try:
        require_manifest_producer(
            manifest_schema=manifest.schema,
            spec_schema=manifest.recipe.schema,
            generator_abi=manifest.generator.abi,
        )
    except FixtureProducerUnavailable as exc:
        raise FixtureUsageError(str(exc)) from exc
    if type(manifest) is FixtureManifest and manifest.generator.version != __version__:
        raise FixtureUsageError(
            "unsupported fixture generator version: "
            f"manifest requires {manifest.generator.version!r}, installed is {__version__!r}"
        )


def _merge_logical_validity_report(primary: GateReport, logical: GateReport) -> None:
    """Merge one private logical-metadata Gate 1 run into the public fixture report."""
    if primary.gate != 1 or logical.gate != 1:
        raise FixtureUsageError("logical metadata assurance did not produce Gate 1 reports")
    for failure in logical.fails:
        primary.fail(f"logical metadata: {failure}")
    for gap in logical.gaps:
        primary.gap(f"logical metadata: {gap}")
    for name in (
        "oracle_reads_passed",
        "oracle_reads_total",
        "semantic_checks_passed",
        "semantic_checks_total",
    ):
        primary.metrics[name] = int(primary.metrics.get(name, 0)) + int(
            logical.metrics.get(name, 0)
        )
    primary_scopes = primary.metrics.get("claim_scopes")
    logical_scopes = logical.metrics.get("claim_scopes")
    if not isinstance(primary_scopes, dict) or not isinstance(logical_scopes, dict):
        raise FixtureUsageError("logical metadata assurance lacks Gate 1 claim-scope metrics")
    for scope in validity.CLAIM_SCOPE_ORDER:
        primary_scope = primary_scopes.get(scope)
        logical_scope = logical_scopes.get(scope)
        if not isinstance(primary_scope, dict) or not isinstance(logical_scope, dict):
            raise FixtureUsageError(
                f"logical metadata assurance lacks Gate 1 scope {scope!r}"
            )
        for counter in ("passed", "total"):
            primary_scope[counter] = int(primary_scope.get(counter, 0)) + int(
                logical_scope.get(counter, 0)
            )
    primary.denominator = (
        f"{primary.metrics['oracle_reads_passed']}/{primary.metrics['oracle_reads_total']} "
        "oracle reads succeeded; "
        f"{primary.metrics['semantic_checks_passed']}/"
        f"{primary.metrics['semantic_checks_total']} semantic checks succeeded"
    )


def _windows_execution_surface_absences(manifest: FixtureManifestV2) -> list[str]:
    """Check the absences the download-only story asserts, one named surface at a time.

    Reporting "no execution artifacts were found" from a single sweep would pass just as
    happily if the sweep itself were broken.  Each surface is therefore looked for by its own
    exact guest path, and named in its own failure.
    """
    username = manifest.recipe.profile.username
    surfaces = (
        (
            "Task definition",
            lambda path: path.startswith("C:\\Windows\\System32\\Tasks\\ArtifactForge\\"),
        ),
        (
            "Shell Link",
            lambda path: path
            == (
                f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\"
                "Start Menu\\Programs\\ArtifactForgeMaintenance.lnk"
            ),
        ),
        ("Amcache hive", lambda path: path == "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"),
        ("SOFTWARE hive", lambda path: path == "C:\\Windows\\System32\\config\\SOFTWARE"),
        ("Prefetch record", lambda path: path.startswith("C:\\Windows\\Prefetch\\")),
    )
    failures = []
    for label, matches in surfaces:
        found = sorted(node.guest_path for node in manifest.payload.files if matches(node.guest_path))
        if found:
            failures.append(
                f"v2 logical Windows download-only assurance forbids a {label}: "
                + ", ".join(found)
            )
    return failures


def _windows_withheld_instant_absences(manifest: FixtureManifestV2) -> list[str]:
    """Check that no emitted stamp carries an instant the download-only story withholds.

    A short inventory is only half of the claim.  Nothing ran, so nothing may be stamped as
    though it had: a last access at ``executed`` asserts the withheld event exactly as loudly
    as a Prefetch record would, and the surface sweep above cannot see it because it reads
    guest paths.  Arrival is the only thing that happened here, so the two arrival instants
    are the only ones a stamp may carry, and every other instant is named on its own.
    """
    timeline = manifest.recipe.causal_clock.windows()
    arrival = (timeline.host_initialized.unix_ns, timeline.file_created.unix_ns)
    withheld = {
        timeline.run_configured.unix_ns: "run-key configuration",
        timeline.executed.unix_ns: "execution",
        timeline.prefetch_updated.unix_ns: "prefetch update",
        timeline.amcache_observed.unix_ns: "Amcache observation",
    }
    failures = []
    for node in manifest.payload.files:
        metadata = node.metadata
        if type(metadata) is not WindowsMetadataV2:
            failures.append(
                "v2 logical Windows download-only assurance requires Windows metadata on "
                f"{node.guest_path}"
            )
            continue
        for label, value in (
            ("creation", metadata.creation_unix_ns),
            ("access", metadata.access_unix_ns),
            ("write", metadata.write_unix_ns),
            ("change", metadata.change_unix_ns),
        ):
            if value in arrival:
                continue
            failures.append(
                "v2 logical Windows download-only assurance forbids the "
                f"{withheld.get(value, 'non-arrival')} instant as the {label} time of "
                f"{node.guest_path}"
            )
    return failures


def _v2_logical_assurance_failures(
    manifest: FixtureManifestRecord,
    artifacts: Path,
    logical_metadata_root: Path,
    validity_report: GateReport,
) -> list[str]:
    """Run Gate 1 over guest-only metadata, then validate its artifact joins."""
    if type(manifest) is not FixtureManifestV2:
        return []
    if manifest.recipe.family == "windows":
        from artifactforge.artifacts.shell_link import parse_shell_link
        from artifactforge.artifacts.windows_task import (
            parse_scheduled_task_xml,
            read_scheduled_task_xml_wire,
            validate_scheduled_task_xml,
        )
        from artifactforge.artifacts.zone_identifier import parse_zone_identifier
        from artifactforge.gates.oracles.sqlite_subset import (
            SQLiteDatabase,
            SQLiteWireProfile,
        )

        failures: list[str] = []
        logical_streams = [
            (node, blob)
            for node in manifest.payload.files
            if type(node.metadata) is WindowsMetadataV2
            for blob in node.metadata.streams
            if blob.name.casefold() == "zone.identifier"
        ]
        if not logical_streams:
            return ["v2 logical Windows assurance requires Zone.Identifier streams"]
        if len(logical_streams) != 1:
            failures.append(
                "v2 logical Windows assurance requires exactly one Zone.Identifier stream"
            )
        for node, blob in logical_streams:
            if blob.name != "Zone.Identifier":
                failures.append(
                    f"v2 logical stream on {node.guest_path!r} must be named "
                    "exactly 'Zone.Identifier'"
                )
        _materialise_v2_carrier(
            logical_metadata_root,
            tuple(
                (f"{index:04d}.Zone.Identifier", blob.data)
                for index, (_node, blob) in enumerate(logical_streams)
            ),
        )
        logical_report = validity.run(os.fspath(logical_metadata_root))
        _merge_logical_validity_report(validity_report, logical_report)

        if len(logical_streams) != 1:
            return failures
        downloaded_node, zone_blob = logical_streams[0]
        history_nodes = [
            node
            for node in manifest.payload.files
            if node.guest_path.endswith(
                r"\AppData\Local\Chromium\User Data\Default\History"
            )
        ]
        if len(history_nodes) != 1:
            failures.append(
                "v2 logical Windows download assurance requires exactly one History database"
            )
            return failures

        try:
            zone = parse_zone_identifier(zone_blob.data)
            history_data = _read_regular_no_follow(
                artifacts / history_nodes[0].served_path,
                "v2 Chromium History database",
            )
            database = SQLiteDatabase.from_bytes(
                history_data,
                wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
            )
            download_rows = database.table("downloads").dictionaries()
            chain_rows = database.table("downloads_url_chains").dictionaries()
            downloaded_bytes = _read_regular_no_follow(
                artifacts / downloaded_node.served_path,
                "v2 browser-downloaded Windows target",
            )
        except (KeyError, TypeError, ValueError, FixtureUsageError) as exc:
            failures.append(f"v2 logical Windows download assurance failed: {exc}")
            return failures

        matching_downloads = [
            row
            for row in download_rows
            if row.get("target_path") == downloaded_node.guest_path
            and row.get("current_path") == downloaded_node.guest_path
        ]
        if len(matching_downloads) != 1:
            failures.append(
                "v2 logical Windows History must contain exactly one row for the "
                "Zone.Identifier-bearing target"
            )
            return failures
        download = matching_downloads[0]
        download_id = download.get("id")
        matching_chains = [
            row
            for row in chain_rows
            if row.get("id") == download_id and row.get("chain_index") == 0
        ]
        if len(matching_chains) != 1:
            failures.append(
                "v2 logical Windows History target must resolve to exactly one final URL"
            )
            return failures

        source_url = matching_chains[0].get("url")
        if type(source_url) is not str:
            failures.append("v2 logical Windows History final URL is not text")
            return failures
        parsed_source = urlsplit(source_url)
        components = parsed_source.path.split("/")
        sha_positions = [
            index for index, component in enumerate(components) if component == "sha256"
        ]
        if (
            len(sha_positions) != 1
            or sha_positions[0] + 2 != len(components) - 1
            or len(components[sha_positions[0] + 1]) != 64
        ):
            failures.append(
                "v2 logical Windows History final URL lacks its exact content-addressed path"
            )
            return failures
        url_digest = components[sha_positions[0] + 1]
        observed_digest = hashlib.sha256(downloaded_bytes).hexdigest()
        expected_manifest_digest = "sha256:" + observed_digest
        if source_url != zone.host_url:
            failures.append(
                "v2 logical Windows Zone.Identifier HostUrl does not match History"
            )
        if (
            download.get("referrer") != zone.referrer_url
            or download.get("tab_url") != zone.referrer_url
        ):
            failures.append(
                "v2 logical Windows Zone.Identifier ReferrerUrl does not match History"
            )
        if (
            url_digest != observed_digest
            or downloaded_node.sha256 != expected_manifest_digest
        ):
            failures.append(
                "v2 logical Windows History URL digest does not identify the emitted target bytes"
            )
        if (
            download.get("received_bytes") != len(downloaded_bytes)
            or download.get("total_bytes") != len(downloaded_bytes)
            or downloaded_node.size != len(downloaded_bytes)
        ):
            failures.append(
                "v2 logical Windows History byte counts do not match the emitted target"
            )
        if download.get("hash") != b"":
            failures.append(
                "v2 logical Windows History hash BLOB must remain empty under Chromium semantics"
            )
        if not downloaded_bytes.startswith(b"MZ"):
            failures.append(
                "v2 logical Windows Zone.Identifier-bearing target is not an emitted PE"
            )

        if manifest.recipe.story == "windows-download-only-v1":
            # Arrival is evidenced above; from here the story's claim is what is missing.
            failures.extend(_windows_execution_surface_absences(manifest))
            failures.extend(_windows_withheld_instant_absences(manifest))
            # Chromium's own record of the same claim.  Row times are free-running microsecond
            # values rather than clock instants, so only the withheld instants can be named
            # here; the emitted stamps are checked exactly above.
            timeline = manifest.recipe.causal_clock.windows()
            withheld_us = {
                timeline.run_configured.filetime // 10,
                timeline.executed.filetime // 10,
                timeline.prefetch_updated.filetime // 10,
                timeline.amcache_observed.filetime // 10,
            }
            for row in download_rows:
                if (row.get("opened"), row.get("last_access_time")) != (0, 0):
                    failures.append(
                        "v2 logical Windows download-only History must record no opened "
                        f"download: {row.get('target_path')}"
                    )
                for column in ("start_time", "end_time"):
                    if row.get(column) in withheld_us:
                        failures.append(
                            "v2 logical Windows download-only History forbids a withheld "
                            f"instant as {column}: {row.get('target_path')}"
                        )
            return failures

        task_nodes = [
            node
            for node in manifest.payload.files
            if node.guest_path.startswith(
                "C:\\Windows\\System32\\Tasks\\ArtifactForge\\"
            )
        ]
        shell_nodes = [
            node
            for node in manifest.payload.files
            if node.guest_path
            == (
                f"C:\\Users\\{manifest.recipe.profile.username}\\AppData\\Roaming\\"
                "Microsoft\\Windows\\Start Menu\\Programs\\"
                "ArtifactForgeMaintenance.lnk"
            )
        ]
        if len(task_nodes) != 1:
            failures.append(
                "v2 logical Windows assurance requires exactly one ArtifactForge Task definition"
            )
        if len(shell_nodes) != 1:
            failures.append(
                "v2 logical Windows assurance requires exactly one ArtifactForge Shell Link"
            )
        if len(task_nodes) != 1 or len(shell_nodes) != 1:
            return failures

        resident_nodes: list[tuple[FileNodeV2, bytes]] = []
        try:
            task_data = _read_regular_no_follow(
                artifacts / task_nodes[0].served_path,
                "v2 Windows scheduled-task definition",
            )
            shell_data = _read_regular_no_follow(
                artifacts / shell_nodes[0].served_path,
                "v2 Windows Shell Link",
            )
            for node in manifest.payload.files:
                candidate = _read_regular_no_follow(
                    artifacts / node.served_path,
                    "v2 Windows resident candidate",
                )
                if candidate.startswith(b"MZ"):
                    resident_nodes.append((node, candidate))
            task = parse_scheduled_task_xml(task_data)
            task_wire = read_scheduled_task_xml_wire(task_data)
            shell = parse_shell_link(shell_data)
        except (TypeError, ValueError, FixtureUsageError) as exc:
            failures.append(f"v2 logical Windows reference assurance failed: {exc}")
            return failures

        task_targets = [
            (node, data)
            for node, data in resident_nodes
            if node.guest_path == task.command
        ]
        shell_targets = [
            (node, data)
            for node, data in resident_nodes
            if node.guest_path == shell.target_path
        ]
        if len(task_targets) != 1:
            failures.append(
                "v2 logical Windows scheduled task must resolve to exactly one emitted PE"
            )
        if len(shell_targets) != 1:
            failures.append(
                "v2 logical Windows Shell Link must resolve to exactly one emitted PE"
            )
        if len(task_targets) != 1 or len(shell_targets) != 1:
            return failures

        task_target, task_target_data = task_targets[0]
        shell_target, shell_target_data = shell_targets[0]
        try:
            validated_task = validate_scheduled_task_xml(
                task_data,
                resident_pe_paths=(task_target.guest_path,),
            )
        except ValueError as exc:
            failures.append(
                f"v2 logical Windows scheduled-task resident validation failed: {exc}"
            )
            return failures
        if (
            validated_task.command != task_wire.command
            or task_nodes[0].guest_path
            != "C:\\Windows\\System32\\Tasks\\ArtifactForge\\" + task.task_name
        ):
            failures.append(
                "v2 logical Windows scheduled-task readers or task-store path disagree"
            )
        for label, node, data in (
            ("scheduled task", task_target, task_target_data),
            ("Shell Link", shell_target, shell_target_data),
        ):
            if node.size != len(data) or node.sha256 != (
                "sha256:" + hashlib.sha256(data).hexdigest()
            ):
                failures.append(
                    f"v2 logical Windows {label} target manifest identity is stale"
                )
        if shell.target_size != len(shell_target_data):
            failures.append(
                "v2 logical Windows Shell Link target size does not match emitted PE bytes"
            )
        expected_target_filetimes = (
            manifest.recipe.causal_clock.windows().file_created.filetime,
            manifest.recipe.causal_clock.windows().executed.filetime,
            manifest.recipe.causal_clock.windows().file_created.filetime,
        )
        if (
            shell.creation_filetime,
            shell.access_filetime,
            shell.write_filetime,
        ) != expected_target_filetimes:
            failures.append(
                "v2 logical Windows Shell Link target FILETIMEs do not match logical PE metadata"
            )
        target_metadata = shell_target.metadata
        if not isinstance(target_metadata, WindowsMetadataV2) or (
            target_metadata.creation_unix_ns,
            target_metadata.access_unix_ns,
            target_metadata.write_unix_ns,
        ) != (
            manifest.recipe.causal_clock.windows().file_created.unix_ns,
            manifest.recipe.causal_clock.windows().executed.unix_ns,
            manifest.recipe.causal_clock.windows().file_created.unix_ns,
        ):
            failures.append(
                "v2 logical Windows Shell Link target metadata is outside the causal profile"
            )
        if (
            task_target.guest_path == shell_target.guest_path
            or task_target.guest_path == downloaded_node.guest_path
            or shell_target.guest_path == downloaded_node.guest_path
        ):
            failures.append(
                "v2 logical Windows Task and Shell Link must target distinct non-download PEs"
            )
        return failures
    if manifest.recipe.family != "macos":
        return []
    from artifactforge.artifacts.macos import parse_quarantine_xattr
    from artifactforge.gates.oracles.sqlite_subset import (
        SQLiteDatabase,
        SQLiteWireProfile,
    )

    failures: list[str] = []
    logical_xattrs = [
        (node, blob)
        for node in manifest.payload.files
        if type(node.metadata) is MacOSMetadataV2
        for blob in node.metadata.xattrs
        if blob.name == "com.apple.quarantine"
    ]
    _materialise_v2_carrier(
        logical_metadata_root,
        tuple(
            (f"{index:04d}.quarantine.xattr", blob.data)
            for index, (_node, blob) in enumerate(logical_xattrs)
        ),
    )
    logical_report = validity.run(os.fspath(logical_metadata_root))
    _merge_logical_validity_report(validity_report, logical_report)

    database_nodes = [
        node
        for node in manifest.payload.files
        if node.guest_path.endswith(
            "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        )
    ]
    if len(database_nodes) != 1:
        return ["v2 logical quarantine assurance requires exactly one event database"]
    try:
        data = _read_regular_no_follow(
            artifacts / database_nodes[0].served_path,
            "v2 quarantine event database",
        )
        database = SQLiteDatabase.from_bytes(
            data,
            wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
        )
        database_identifiers = {
            row["LSQuarantineEventIdentifier"]
            for row in database.table("LSQuarantineEvent").dictionaries()
        }
    except (KeyError, TypeError, ValueError, FixtureUsageError) as exc:
        return [f"v2 logical quarantine database assurance failed: {exc}"]

    xattr_identifiers: set[str] = set()
    for node, blob in logical_xattrs:
        try:
            parsed = parse_quarantine_xattr(blob.data)
        except ValueError as exc:
            failures.append(
                f"v2 logical quarantine xattr on {node.guest_path!r} is invalid: {exc}"
            )
            continue
        if parsed.event_uuid in xattr_identifiers:
            failures.append(
                f"v2 logical quarantine UUID is duplicated: {parsed.event_uuid}"
            )
        xattr_identifiers.add(parsed.event_uuid)
    if xattr_identifiers != database_identifiers:
        missing = sorted(database_identifiers - xattr_identifiers)
        extra = sorted(xattr_identifiers - database_identifiers)
        failures.append(
            "v2 logical quarantine xattr/database UUID join is not exact: "
            f"missing={missing!r}, extra={extra!r}"
        )
    return failures


def _verify_fixture(
    root: Path, *, assurance: bool, reproduce: bool = True
) -> VerificationResult:
    root_descriptor = _open_directory_path(root, "fixture root")
    artifacts_descriptor = -1
    verification_root: Path | None = None
    try:
        artifacts_descriptor = _open_directory_at(
            root_descriptor, _PAYLOAD_NAME, "fixture payload"
        )
        raw_manifest = _read_regular_at(
            root_descriptor,
            _MANIFEST_NAME,
            "fixture manifest",
            max_bytes=resources.RESOURCE_POLICY.max_input_bytes,
        )
        manifest = parse_fixture_manifest(raw_manifest)
        if reproduce:
            require_supported_manifest(manifest)

        # APIs such as the parser gates require pathnames. Snapshot from held descriptors into
        # private system-temporary storage first, so no later pathname traversal can be steered
        # by replacing the caller's fixture root.
        verification_root = Path(tempfile.mkdtemp(prefix="artifactforge-verify-"))
        _set_exact_mode(verification_root, 0o700)
        artifacts = verification_root / "observed-artifacts"
        is_v2 = type(manifest) is FixtureManifestV2
        _snapshot_directory_at(
            artifacts_descriptor,
            artifacts,
            expected_file_mode=0o600 if is_v2 else None,
            expected_directory_mode=0o700 if is_v2 else None,
        )
        actual_entries = artifact_entries_from_tree(artifacts)
        integrity_failures: list[str] = []
        reproduction_failures: list[str] = []
        root_names = _root_inventory_at(root_descriptor)
        if root_names != [_PAYLOAD_NAME, _MANIFEST_NAME]:
            integrity_failures.append(
                "fixture root inventory must be exactly artifacts/ and fixture.json; found "
                + ", ".join(root_names)
            )
        if raw_manifest != manifest.canonical_bytes():
            integrity_failures.append("fixture.json is not canonical ArtifactForge JSON")
        integrity_failures.extend(_payload_differences(manifest, actual_entries))
        if is_v2 and os.name != "nt":
            root_mode = stat.S_IMODE(os.fstat(root_descriptor).st_mode)
            manifest_mode = stat.S_IMODE(
                os.stat(
                    _MANIFEST_NAME,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                ).st_mode
            )
            if root_mode != 0o700:
                integrity_failures.append(
                    f"fixture carrier root mode is {root_mode:#o}, expected 0o700"
                )
            if manifest_mode != 0o600:
                integrity_failures.append(
                    f"fixture manifest carrier mode is {manifest_mode:#o}, expected 0o600"
                )

        # Verification is read-only with respect to the fixture and must work from read-only
        # media. Its unpublished reproduction has no same-filesystem publication requirement.
        if reproduce:
            publication = verification_root / "reproduced-fixture"
            work = verification_root / "work"
            reproduced_manifest = _materialise_publication(manifest.recipe, publication, work)
            reproduction_failures.extend(
                _exact_reproduction_differences(
                    artifacts,
                    publication / _PAYLOAD_NAME,
                    declared_manifest=manifest,
                    reproduced_manifest=reproduced_manifest,
                )
            )

        reports: tuple[GateReport, ...] = ()
        assurance_failures: list[str] = []
        if assurance:
            reports = (validity.run(str(artifacts)), inertness.run(str(artifacts)))
            for failure in _v2_logical_assurance_failures(
                manifest,
                artifacts,
                verification_root / "logical-metadata",
                reports[0],
            ):
                reports[0].fail(failure)
            for report in reports:
                if not report.ok:
                    assurance_failures.append(
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
            root_descriptor,
            _MANIFEST_NAME,
            "fixture manifest",
            max_bytes=resources.RESOURCE_POLICY.max_input_bytes,
        ) != raw_manifest:
            raise FixtureUsageError("fixture manifest changed during verification")
        final_artifacts = verification_root / "final-artifacts"
        _snapshot_directory_at(
            artifacts_descriptor,
            final_artifacts,
            expected_file_mode=0o600 if is_v2 else None,
            expected_directory_mode=0o700 if is_v2 else None,
        )
        final_entries = artifact_entries_from_tree(final_artifacts)
        if final_entries != actual_entries:
            raise FixtureUsageError("fixture payload changed during verification")
        for entry in actual_entries:
            relative = Path(entry.path)
            if not _regular_files_equal(artifacts / relative, final_artifacts / relative):
                raise FixtureUsageError("fixture payload changed during verification")

        deduplicated_integrity = tuple(dict.fromkeys(integrity_failures))
        deduplicated_reproduction = tuple(dict.fromkeys(reproduction_failures))
        failures = tuple(
            dict.fromkeys(
                (*deduplicated_integrity, *deduplicated_reproduction, *assurance_failures)
            )
        )
        return VerificationResult(
            manifest=manifest,
            failures=failures,
            assurance_reports=reports,
            integrity_failures=deduplicated_integrity,
            reproduction_failures=deduplicated_reproduction,
            reproduction_requested=reproduce,
        )
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
        return _verify_fixture(root_path, assurance=assurance, reproduce=True)
    except FixtureUsageError:
        raise
    except (OSError, FixtureValidationError, CanonicalJSONError, UnicodeError) as exc:
        raise FixtureUsageError(f"cannot verify fixture {root_path}: {exc}") from exc


def inspect_fixture(root: str | os.PathLike[str]) -> VerificationResult:
    """Validate stored manifest/payload bytes without claiming local reproduction."""
    try:
        root_path = Path(root)
    except TypeError as exc:
        raise FixtureUsageError("fixture root must be a filesystem path") from exc
    try:
        return _verify_fixture(root_path, assurance=False, reproduce=False)
    except FixtureUsageError:
        raise
    except (OSError, FixtureValidationError, CanonicalJSONError, UnicodeError) as exc:
        raise FixtureUsageError(f"cannot inspect fixture {root_path}: {exc}") from exc


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
    spec: FixtureSpecRecord, output: str | os.PathLike[str]
) -> FixtureManifestRecord:
    """Build, reproduce-verify, then atomically publish a new fixture directory."""
    if type(spec) not in (FixtureSpec, FixtureSpecV2):
        raise FixtureUsageError("build_fixture requires a validated fixture specification")
    require_supported_spec(spec)
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
    _set_exact_mode(temporary_root, 0o700)
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
