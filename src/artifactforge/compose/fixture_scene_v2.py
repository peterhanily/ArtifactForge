# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Project one validated loose scene into an answer-free Fixture ABI v2 tree.

The existing scene builders produce portable loose files.  A v2 fixture additionally needs
the guest path, logical filesystem metadata, xattrs/alternate streams, and every parent
directory.  This module is the deliberately narrow bridge between those representations.  It
does not write a carrier, retain private joins, or guess when the supplied loose inventory is
incomplete.

Ownership here is logical fixture metadata, not a claim to reproduce an ACL, security
descriptor, or a complete host image.  The bounded profiles use one documented owner identity
per family: Linux uid/gid 1000/1000, macOS uid/gid 501/20, and Windows LocalSystem.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib

from artifactforge.artifacts.macos import parse_quarantine_xattr
from artifactforge.artifacts.shell_link import parse_shell_link
from artifactforge.artifacts.windows_task import (
    read_scheduled_task_xml_wire,
    validate_scheduled_task_xml,
)
from artifactforge.artifacts.zone_identifier import build_zone_identifier
from artifactforge.compose.scene import (
    WINDOWS_SHELL_LINK_SOURCE,
    WINDOWS_TASK_XML_SOURCE,
    Scene,
)
from artifactforge.fixture.canonical import JSONValue
from artifactforge.fixture.model_v2 import (
    DirectoryNodeV2,
    FileNodeV2,
    FixtureSpecV2,
    FixtureV2ValidationError,
    LinuxMetadataV2,
    MacOSMetadataV2,
    NamedBlobV2,
    WindowsMetadataV2,
    canonical_nodes_v2,
    guest_path_to_served_path,
    served_path_to_guest_path,
)
from artifactforge.inventory import InventoryError, canonical_relative_paths


LINUX_LOGICAL_UID_V2 = 1000
LINUX_LOGICAL_GID_V2 = 1000
MACOS_LOGICAL_UID_V2 = 501
MACOS_LOGICAL_GID_V2 = 20
WINDOWS_LOGICAL_OWNER_SID_V2 = "S-1-5-18"

MACOS_QUARANTINE_XATTR_V2 = "com.apple.quarantine"
WINDOWS_ZONE_STREAM_V2 = "Zone.Identifier"

_WINDOWS_SOFTWARE_SOURCE = "Software.run.hive"
_WINDOWS_AMCACHE_SOURCE = "Amcache.hve"
_WINDOWS_HISTORY_SOURCE = "History"
_MACOS_DATABASE_PATHS = {
    "QuarantineEventsV2": (
        "/Users/{username}/Library/Preferences/"
        "com.apple.LaunchServices.QuarantineEventsV2"
    ),
    "TCC.db": "/Users/{username}/Library/Application Support/com.apple.TCC/TCC.db",
    "knowledgeC.db": "/private/var/db/CoreDuet/Knowledge/knowledgeC.db",
}
_FORBIDDEN_ROLE_TOKENS = frozenset({"answer", "candidate", "decoy", "join", "persisted", "subject"})
LogicalMetadataV2 = LinuxMetadataV2 | MacOSMetadataV2 | WindowsMetadataV2


class FixtureSceneProjectionError(FixtureV2ValidationError):
    """A loose Scene cannot be projected exactly into the closed v2 profile."""


@dataclass(frozen=True)
class ProjectedFileV2:
    """One immutable file node paired with its unchanged default-stream bytes."""

    node: FileNodeV2
    default_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.node) is not FileNodeV2:
            raise FixtureSceneProjectionError("projected file node must be a FileNodeV2")
        if type(self.default_bytes) is not bytes:
            raise FixtureSceneProjectionError("projected default stream must be exact bytes")
        if self.node.size != len(self.default_bytes):
            raise FixtureSceneProjectionError("projected default-stream size disagrees with node")
        digest = "sha256:" + hashlib.sha256(self.default_bytes).hexdigest()
        if self.node.sha256 != digest:
            raise FixtureSceneProjectionError("projected default-stream digest disagrees with node")


@dataclass(frozen=True)
class FixtureScenePlanV2:
    """Canonical, immutable projection output with no recipe or private scene truth."""

    family: str
    directories: tuple[DirectoryNodeV2, ...]
    files: tuple[ProjectedFileV2, ...]

    def __post_init__(self) -> None:
        if type(self.directories) is not tuple or type(self.files) is not tuple:
            raise FixtureSceneProjectionError("projected directories and files must be tuples")
        if any(type(item) is not DirectoryNodeV2 for item in self.directories):
            raise FixtureSceneProjectionError("projected directories contain a non-directory node")
        if any(type(item) is not ProjectedFileV2 for item in self.files):
            raise FixtureSceneProjectionError("projected files contain an unsupported value")
        ordered_directories, ordered_files = canonical_nodes_v2(
            family=self.family,
            directories=self.directories,
            files=self.file_nodes,
        )
        if ordered_directories != self.directories or ordered_files != self.file_nodes:
            raise FixtureSceneProjectionError("projected nodes must be in canonical served-path order")

    @property
    def file_nodes(self) -> tuple[FileNodeV2, ...]:
        return tuple(item.node for item in self.files)

    @property
    def default_files(self) -> tuple[tuple[str, bytes], ...]:
        """Return canonical ``(served_path, bytes)`` pairs for carrier materialisation."""
        return tuple((item.node.served_path, item.default_bytes) for item in self.files)

    def nodes_mapping(self) -> dict[str, JSONValue]:
        """Return only the public logical nodes; default-stream bytes travel separately."""
        return {
            "family": self.family,
            "directories": [item.to_mapping() for item in self.directories],
            "files": [item.to_mapping() for item in self.file_nodes],
        }


def _projection_error(message: str, exc: Exception | None = None) -> FixtureSceneProjectionError:
    error = FixtureSceneProjectionError(message)
    if exc is not None:
        error.__cause__ = exc
    return error


def _validate_scene_identity(spec: FixtureSpecV2, scene: Scene) -> None:
    if type(spec) is not FixtureSpecV2:
        raise FixtureSceneProjectionError("projection spec must be a validated FixtureSpecV2")
    if type(scene) is not Scene:
        raise FixtureSceneProjectionError("projection scene must be an exact Scene")
    if scene.family != spec.family:
        raise FixtureSceneProjectionError(
            f"scene family {scene.family!r} does not match recipe family {spec.family!r}"
        )
    # Scene currently carries public host identity inside its legacy private envelope.  Read it
    # only to prevent projecting bytes built for one profile under another; never retain it.
    if not isinstance(scene.join, Mapping):
        raise FixtureSceneProjectionError("scene identity envelope is unavailable")
    if scene.join.get("family") != spec.family:
        raise FixtureSceneProjectionError("scene identity family does not match the recipe")
    if scene.join.get("host") != spec.profile.hostname:
        raise FixtureSceneProjectionError("scene hostname does not match the recipe profile")
    if scene.join.get("user") != spec.profile.username:
        raise FixtureSceneProjectionError("scene username does not match the recipe profile")


def _validated_loose_files(scene: Scene, loose_files: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(loose_files, Mapping):
        raise FixtureSceneProjectionError("loose files must be an exact relative-path mapping")
    try:
        expected = canonical_relative_paths(scene.artifacts, require_sorted=True)
        observed = canonical_relative_paths(loose_files)
    except InventoryError as exc:
        raise _projection_error(f"invalid loose inventory: {exc}", exc)
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(repr(path) for path in missing))
        if extra:
            details.append("extra " + ", ".join(repr(path) for path in extra))
        raise FixtureSceneProjectionError("loose inventory is not exact: " + "; ".join(details))
    result: dict[str, bytes] = {}
    for path in expected:
        data = loose_files[path]
        if type(data) is not bytes:
            raise FixtureSceneProjectionError(f"loose file {path!r} must be exact bytes")
        result[path] = data
    return result


def _timestamp_roles(scene: Scene, path: str) -> dict[str, int]:
    if not isinstance(scene.timestamp_roles, Mapping):
        raise FixtureSceneProjectionError("scene public timestamp facts are unavailable")
    if set(scene.timestamp_roles) != set(scene.artifacts):
        raise FixtureSceneProjectionError("scene timestamp facts do not cover the exact inventory")
    records = scene.timestamp_roles.get(path)
    if type(records) is not tuple or not records:
        raise FixtureSceneProjectionError(f"scene timestamp facts are missing for {path!r}")
    result: dict[str, int] = {}
    for record in records:
        if type(record) is not tuple or len(record) != 2:
            raise FixtureSceneProjectionError(f"scene timestamp fact for {path!r} is malformed")
        role, unix_ns = record
        if type(role) is not str or not role or type(unix_ns) is not int:
            raise FixtureSceneProjectionError(f"scene timestamp fact for {path!r} is malformed")
        if role in result:
            raise FixtureSceneProjectionError(f"scene timestamp role {role!r} is duplicated")
        if any(token in _FORBIDDEN_ROLE_TOKENS for token in role.split(".")):
            raise FixtureSceneProjectionError(f"scene timestamp role {role!r} is answer-bearing")
        result[role] = unix_ns
    return result


def _require_timestamps(scene: Scene, path: str, expected: Mapping[str, int]) -> None:
    actual = _timestamp_roles(scene, path)
    if actual != dict(expected):
        raise FixtureSceneProjectionError(
            f"scene timestamp facts for {path!r} do not match the recipe causal clock"
        )


def _windows_metadata(
    *,
    created: int,
    accessed: int,
    written: int,
    changed: int,
    zone_identifier: bytes | None = None,
) -> WindowsMetadataV2:
    streams = ()
    if zone_identifier is not None:
        if type(zone_identifier) is not bytes:
            raise FixtureSceneProjectionError("Zone.Identifier projection must use exact bytes")
        streams = (
            NamedBlobV2.from_bytes(WINDOWS_ZONE_STREAM_V2, zone_identifier),
        )
    return WindowsMetadataV2(
        owner_sid=WINDOWS_LOGICAL_OWNER_SID_V2,
        attributes=("ARCHIVE",),
        creation_unix_ns=created,
        access_unix_ns=accessed,
        write_unix_ns=written,
        change_unix_ns=changed,
        streams=streams,
    )


def _macos_metadata(
    *, mode: int, born: int, changed: int, xattrs: tuple[NamedBlobV2, ...] = ()
) -> MacOSMetadataV2:
    return MacOSMetadataV2(
        mode=mode,
        uid=MACOS_LOGICAL_UID_V2,
        gid=MACOS_LOGICAL_GID_V2,
        atime_unix_ns=changed,
        mtime_unix_ns=changed,
        ctime_unix_ns=changed,
        birthtime_unix_ns=born,
        xattrs=xattrs,
    )


def _linux_metadata(*, mode: int, changed: int) -> LinuxMetadataV2:
    return LinuxMetadataV2(
        mode=mode,
        uid=LINUX_LOGICAL_UID_V2,
        gid=LINUX_LOGICAL_GID_V2,
        atime_unix_ns=changed,
        mtime_unix_ns=changed,
        ctime_unix_ns=changed,
    )


def _projected_file(
    *, family: str, guest_path: str, data: bytes, metadata: LogicalMetadataV2
) -> ProjectedFileV2:
    served_path = guest_path_to_served_path(family, guest_path)
    node = FileNodeV2.from_bytes(
        guest_path=guest_path,
        served_path=served_path,
        data=data,
        metadata=metadata,
    )
    return ProjectedFileV2(node=node, default_bytes=data)


def _windows_resident_paths(scene: Scene, loose: Mapping[str, bytes]) -> dict[str, str]:
    raw_claims = scene.join.get("residents")
    if not isinstance(raw_claims, list):
        raise FixtureSceneProjectionError(
            "Windows resident guest paths are absent from the legacy Scene truth"
        )
    result: dict[str, str] = {}
    for index, claim in enumerate(raw_claims):
        if not isinstance(claim, Mapping):
            raise FixtureSceneProjectionError(f"Windows resident claim {index} is malformed")
        name, path = claim.get("name"), claim.get("path")
        if type(name) is not str or type(path) is not str:
            raise FixtureSceneProjectionError(f"Windows resident claim {index} lacks name/path")
        if name in result:
            raise FixtureSceneProjectionError(f"Windows resident claim {name!r} is duplicated")
        data = loose.get(name)
        if data is None or not data.startswith(b"MZ"):
            raise FixtureSceneProjectionError(f"Windows resident claim {name!r} has no PE bytes")
        if claim.get("size") != len(data) or claim.get("sha256") != hashlib.sha256(data).hexdigest():
            raise FixtureSceneProjectionError(f"Windows resident claim {name!r} is stale")
        guest_path_to_served_path("windows", path)
        result[name] = path
    detected = {name for name, data in loose.items() if data.startswith(b"MZ")}
    if set(result) != detected:
        raise FixtureSceneProjectionError(
            "Windows resident path truth does not cover the exact PE inventory"
        )
    return result


def _windows_download_zone(
    scene: Scene, resident_paths: Mapping[str, str]
) -> tuple[str, bytes]:
    raw = scene.join.get("browser_download")
    if not isinstance(raw, Mapping) or set(raw) != {
        "target_path",
        "sha256",
        "size",
        "source_url",
        "referrer_url",
    }:
        raise FixtureSceneProjectionError("Windows browser-download truth is malformed")
    target_path = raw["target_path"]
    digest = raw["sha256"]
    size = raw["size"]
    source_url = raw["source_url"]
    referrer_url = raw["referrer_url"]
    if (
        type(target_path) is not str
        or type(digest) is not str
        or type(size) is not int
        or type(source_url) is not str
        or type(referrer_url) is not str
    ):
        raise FixtureSceneProjectionError("Windows browser-download truth has invalid types")
    matches = [source for source, path in resident_paths.items() if path == target_path]
    if len(matches) != 1:
        raise FixtureSceneProjectionError(
            "Windows browser-download target must name exactly one resident PE"
        )
    source = matches[0]
    claim = next(
        claim
        for claim in scene.join["residents"]
        if isinstance(claim, Mapping) and claim.get("name") == source
    )
    if claim.get("sha256") != digest or claim.get("size") != size:
        raise FixtureSceneProjectionError(
            "Windows browser-download byte identity disagrees with resident truth"
        )
    try:
        stream = build_zone_identifier(referrer_url, source_url)
    except ValueError as exc:
        raise _projection_error("Windows browser-download URLs cannot form MOTW", exc)
    return source, stream


def _windows_reference_artifacts(
    spec: FixtureSpecV2,
    scene: Scene,
    resident_paths: Mapping[str, str],
    loose: Mapping[str, bytes],
) -> dict[str, str]:
    """Validate private construction joins before retaining only public guest paths."""
    task_truth = scene.join.get("scheduled_task")
    shell_truth = scene.join.get("shell_link")
    if not isinstance(task_truth, Mapping) or set(task_truth) != {
        "source",
        "guest_path",
        "task_name",
        "target_name",
        "target_path",
        "target_role",
        "target_size",
        "target_sha256",
    }:
        raise FixtureSceneProjectionError("Windows scheduled-task truth is malformed")
    if not isinstance(shell_truth, Mapping) or set(shell_truth) != {
        "source",
        "guest_path",
        "target_name",
        "target_path",
        "target_role",
        "target_size",
        "target_sha256",
        "creation_filetime",
        "access_filetime",
        "write_filetime",
        "volume_serial",
    }:
        raise FixtureSceneProjectionError("Windows Shell Link truth is malformed")
    if (
        task_truth.get("source") != WINDOWS_TASK_XML_SOURCE
        or shell_truth.get("source") != WINDOWS_SHELL_LINK_SOURCE
    ):
        raise FixtureSceneProjectionError("Windows reference source names are not canonical")

    task_data = loose.get(WINDOWS_TASK_XML_SOURCE)
    shell_data = loose.get(WINDOWS_SHELL_LINK_SOURCE)
    if type(task_data) is not bytes or type(shell_data) is not bytes:
        raise FixtureSceneProjectionError(
            "Windows reference artifacts are absent from the exact loose inventory"
        )
    try:
        task = validate_scheduled_task_xml(
            task_data,
            resident_pe_paths=(task_truth.get("target_path"),),
        )
        task_wire = read_scheduled_task_xml_wire(task_data)
        shell = parse_shell_link(shell_data)
    except (TypeError, ValueError) as exc:
        raise _projection_error("Windows reference artifact validation failed", exc)

    claims = scene.join.get("residents")
    if not isinstance(claims, list):
        raise FixtureSceneProjectionError("Windows resident truth is unavailable")

    def target(source: str, truth: Mapping[str, object], path: str) -> tuple[str, bytes]:
        matches = [name for name, guest_path in resident_paths.items() if guest_path == path]
        if len(matches) != 1:
            raise FixtureSceneProjectionError(
                f"Windows {source} must resolve to exactly one resident PE"
            )
        resident_name = matches[0]
        data = loose[resident_name]
        claim_matches = [
            claim
            for claim in claims
            if isinstance(claim, Mapping) and claim.get("name") == resident_name
        ]
        if len(claim_matches) != 1:
            raise FixtureSceneProjectionError(
                f"Windows {source} target lacks one exact resident claim"
            )
        claim = claim_matches[0]
        if (
            truth.get("target_name") != resident_name
            or truth.get("target_path") != path
            or truth.get("target_role") != claim.get("role")
            or truth.get("target_role") == "persisted"
            or truth.get("target_size") != len(data)
            or truth.get("target_sha256") != hashlib.sha256(data).hexdigest()
        ):
            raise FixtureSceneProjectionError(
                f"Windows {source} byte identity disagrees with resident truth"
            )
        return resident_name, data

    task_name, _task_target_data = target("scheduled task", task_truth, task.command)
    shell_name, shell_target_data = target("Shell Link", shell_truth, shell.target_path)
    if task_name == shell_name:
        raise FixtureSceneProjectionError(
            "Windows scheduled task and Shell Link must target distinct residents"
        )
    if task.command != task_wire.command or task.task_name != task_truth.get("task_name"):
        raise FixtureSceneProjectionError("Windows scheduled-task readers/truth disagree")
    if shell.target_size != len(shell_target_data):
        raise FixtureSceneProjectionError(
            "Windows Shell Link target size disagrees with emitted PE bytes"
        )
    timeline = spec.causal_clock.windows()
    expected_filetimes = (
        timeline.file_created.filetime,
        timeline.executed.filetime,
        timeline.file_created.filetime,
    )
    if (
        (
            shell.creation_filetime,
            shell.access_filetime,
            shell.write_filetime,
        )
        != expected_filetimes
        or expected_filetimes
        != (
            shell_truth.get("creation_filetime"),
            shell_truth.get("access_filetime"),
            shell_truth.get("write_filetime"),
        )
        or shell.volume_serial != shell_truth.get("volume_serial")
    ):
        raise FixtureSceneProjectionError(
            "Windows Shell Link target metadata disagrees with the causal clock"
        )

    task_guest = task_truth.get("guest_path")
    shell_guest = shell_truth.get("guest_path")
    expected_task_guest = (
        rf"C:\Windows\System32\Tasks\ArtifactForge\{task.task_name}"
    )
    expected_shell_guest = (
        f"C:\\Users\\{spec.profile.username}\\AppData\\Roaming\\Microsoft\\Windows\\"
        f"Start Menu\\Programs\\{WINDOWS_SHELL_LINK_SOURCE}"
    )
    if task_guest != expected_task_guest or shell_guest != expected_shell_guest:
        raise FixtureSceneProjectionError("Windows reference guest paths are not canonical")
    guest_path_to_served_path("windows", task_guest)
    guest_path_to_served_path("windows", shell_guest)
    return {
        WINDOWS_TASK_XML_SOURCE: task_guest,
        WINDOWS_SHELL_LINK_SOURCE: shell_guest,
    }


def _project_windows(
    spec: FixtureSpecV2, scene: Scene, loose: Mapping[str, bytes]
) -> tuple[ProjectedFileV2, ...]:
    timeline = spec.causal_clock.windows()
    resident_paths = _windows_resident_paths(scene, loose)
    downloaded_source, zone_identifier = _windows_download_zone(scene, resident_paths)
    reference_guest_paths = _windows_reference_artifacts(
        spec, scene, resident_paths, loose
    )
    result: list[ProjectedFileV2] = []
    for source, data in loose.items():
        if source in resident_paths:
            _require_timestamps(
                scene, source, {"artifact.file-created": timeline.file_created.unix_ns}
            )
            metadata = _windows_metadata(
                created=timeline.file_created.unix_ns,
                accessed=timeline.executed.unix_ns,
                written=timeline.file_created.unix_ns,
                changed=timeline.file_created.unix_ns,
                zone_identifier=zone_identifier if source == downloaded_source else None,
            )
            guest_path = resident_paths[source]
        elif source == _WINDOWS_SOFTWARE_SOURCE:
            if not data.startswith(b"regf"):
                raise FixtureSceneProjectionError("Software.run.hive is not a registry hive")
            _require_timestamps(
                scene,
                source,
                {
                    "artifact.logical-updated": timeline.run_configured.unix_ns,
                    "registry.run-key-last-written": timeline.run_configured.unix_ns,
                },
            )
            metadata = _windows_metadata(
                created=timeline.host_initialized.unix_ns,
                accessed=timeline.run_configured.unix_ns,
                written=timeline.run_configured.unix_ns,
                changed=timeline.run_configured.unix_ns,
            )
            guest_path = r"C:\Windows\System32\config\SOFTWARE"
        elif source == _WINDOWS_AMCACHE_SOURCE:
            if not data.startswith(b"regf"):
                raise FixtureSceneProjectionError("Amcache.hve is not a registry hive")
            _require_timestamps(
                scene,
                source,
                {
                    "artifact.logical-updated": timeline.amcache_observed.unix_ns,
                    "registry.inventory-key-last-written": timeline.amcache_observed.unix_ns,
                },
            )
            metadata = _windows_metadata(
                created=timeline.host_initialized.unix_ns,
                accessed=timeline.amcache_observed.unix_ns,
                written=timeline.amcache_observed.unix_ns,
                changed=timeline.amcache_observed.unix_ns,
            )
            guest_path = r"C:\Windows\AppCompat\Programs\Amcache.hve"
        elif source == _WINDOWS_HISTORY_SOURCE:
            if not data.startswith(b"SQLite format 3\x00"):
                raise FixtureSceneProjectionError("History is not a SQLite database")
            _require_timestamps(
                scene,
                source,
                {"artifact.logical-updated": timeline.executed.unix_ns},
            )
            metadata = _windows_metadata(
                created=timeline.host_initialized.unix_ns,
                accessed=timeline.executed.unix_ns,
                written=timeline.executed.unix_ns,
                changed=timeline.executed.unix_ns,
            )
            guest_path = (
                f"C:\\Users\\{spec.profile.username}\\AppData\\Local\\Chromium\\"
                "User Data\\Default\\History"
            )
        elif source in reference_guest_paths:
            role = (
                "task.definition-written"
                if source == WINDOWS_TASK_XML_SOURCE
                else "shell-link.reference-written"
            )
            _require_timestamps(
                scene,
                source,
                {
                    "artifact.logical-updated": timeline.run_configured.unix_ns,
                    role: timeline.run_configured.unix_ns,
                },
            )
            metadata = _windows_metadata(
                created=timeline.run_configured.unix_ns,
                accessed=timeline.run_configured.unix_ns,
                written=timeline.run_configured.unix_ns,
                changed=timeline.run_configured.unix_ns,
            )
            guest_path = reference_guest_paths[source]
        elif source.endswith(".pf"):
            _require_timestamps(
                scene,
                source,
                {
                    "artifact.logical-updated": timeline.prefetch_updated.unix_ns,
                    "prefetch.last-run": timeline.executed.unix_ns,
                    "prefetch.volume-created": timeline.host_initialized.unix_ns,
                },
            )
            metadata = _windows_metadata(
                created=timeline.executed.unix_ns,
                accessed=timeline.prefetch_updated.unix_ns,
                written=timeline.prefetch_updated.unix_ns,
                changed=timeline.prefetch_updated.unix_ns,
            )
            guest_path = rf"C:\Windows\Prefetch\{source}"
        else:
            raise FixtureSceneProjectionError(
                f"Windows loose file {source!r} is outside the closed v2 projection profile"
            )
        result.append(
            _projected_file(
                family="windows", guest_path=guest_path, data=data, metadata=metadata
            )
        )
    return tuple(result)


def _knowledge_timestamp_roles(spec: FixtureSpecV2) -> dict[str, int]:
    timeline = spec.causal_clock.macos()
    result = {"artifact.logical-updated": timeline.knowledge_ended.unix_ns}
    for index in range(3):
        interval = timeline.knowledge_interval(index, count=3)
        result[f"knowledge.record-{index}.start"] = interval.start.unix_ns
        result[f"knowledge.record-{index}.end"] = interval.end.unix_ns
    return result


def _project_macos(
    spec: FixtureSpecV2, scene: Scene, loose: Mapping[str, bytes]
) -> tuple[ProjectedFileV2, ...]:
    timeline = spec.causal_clock.macos()
    username = spec.profile.username
    sidecars = {
        source.removesuffix(".quarantine.xattr"): source
        for source in loose
        if source.endswith(".quarantine.xattr")
    }
    binaries = {source for source, data in loose.items() if data.startswith(b"\xcf\xfa\xed\xfe")}
    if set(sidecars) != binaries:
        missing = sorted(binaries - set(sidecars))
        orphaned = sorted(set(sidecars) - binaries)
        raise FixtureSceneProjectionError(
            "macOS quarantine sidecars do not match binaries exactly: "
            f"missing={missing!r}; orphaned={orphaned!r}"
        )

    result: list[ProjectedFileV2] = []
    for source, data in loose.items():
        if source.endswith(".quarantine.xattr"):
            _require_timestamps(
                scene,
                source,
                {
                    "artifact.logical-updated": timeline.downloaded.unix_ns,
                    "quarantine.timestamp": timeline.downloaded.unix_ns,
                },
            )
            try:
                parse_quarantine_xattr(data)
            except ValueError as exc:
                raise _projection_error(
                    f"macOS quarantine sidecar {source!r} is malformed", exc
                )
            continue
        if source in binaries:
            _require_timestamps(
                scene, source, {"artifact.logical-installed": timeline.installed.unix_ns}
            )
            xattr_data = loose[sidecars[source]]
            metadata = _macos_metadata(
                mode=0o755,
                born=timeline.downloaded.unix_ns,
                changed=timeline.installed.unix_ns,
                xattrs=(NamedBlobV2.from_bytes(MACOS_QUARANTINE_XATTR_V2, xattr_data),),
            )
            guest_path = (
                f"/Users/{username}/Library/Application Support/{source}/"
                f"{source.rsplit('.', 1)[-1]}"
            )
        elif source in _MACOS_DATABASE_PATHS:
            if not data.startswith(b"SQLite format 3\x00"):
                raise FixtureSceneProjectionError(f"macOS database {source!r} is not SQLite")
            guest_path = _MACOS_DATABASE_PATHS[source].format(username=username)
            if source == "QuarantineEventsV2":
                changed = timeline.downloaded.unix_ns
                expected = {
                    "artifact.logical-updated": changed,
                    "quarantine.event-timestamp": changed,
                }
            elif source == "TCC.db":
                changed = timeline.tcc_decided.unix_ns
                expected = {
                    "artifact.logical-updated": changed,
                    "tcc.last-modified": changed,
                }
            else:
                changed = timeline.knowledge_ended.unix_ns
                expected = _knowledge_timestamp_roles(spec)
            _require_timestamps(scene, source, expected)
            metadata = _macos_metadata(
                mode=0o644,
                born=timeline.host_initialized.unix_ns,
                changed=changed,
            )
        elif source.endswith(".plist"):
            if not data.startswith(b"bplist00"):
                raise FixtureSceneProjectionError(f"macOS plist {source!r} is not binary plist")
            _require_timestamps(
                scene,
                source,
                {"artifact.logical-updated": timeline.launch_agent_written.unix_ns},
            )
            metadata = _macos_metadata(
                mode=0o644,
                born=timeline.launch_agent_written.unix_ns,
                changed=timeline.launch_agent_written.unix_ns,
            )
            guest_path = f"/Users/{username}/Library/LaunchAgents/{source}"
        else:
            raise FixtureSceneProjectionError(
                f"macOS loose file {source!r} is outside the closed v2 projection profile"
            )
        result.append(
            _projected_file(family="macos", guest_path=guest_path, data=data, metadata=metadata)
        )
    return tuple(result)


def _project_linux(
    spec: FixtureSpecV2, scene: Scene, loose: Mapping[str, bytes]
) -> tuple[ProjectedFileV2, ...]:
    timeline = spec.causal_clock.linux()
    home = f"home/{spec.profile.username}"
    result: list[ProjectedFileV2] = []
    for source, data in loose.items():
        guest_path = "/" + source
        if data.startswith(b"\x7fELF"):
            if not source.startswith(home + "/.local/bin/"):
                raise FixtureSceneProjectionError(
                    f"Linux ELF {source!r} is outside the current user's local bin"
                )
            _require_timestamps(
                scene, source, {"artifact.logical-installed": timeline.installed.unix_ns}
            )
            metadata = _linux_metadata(mode=0o755, changed=timeline.installed.unix_ns)
        elif source.endswith(".desktop"):
            if not source.startswith(home + "/.config/autostart/"):
                raise FixtureSceneProjectionError(
                    f"Linux desktop file {source!r} is outside the current user's autostart"
                )
            _require_timestamps(
                scene,
                source,
                {"artifact.logical-updated": timeline.autostart_written.unix_ns},
            )
            metadata = _linux_metadata(mode=0o644, changed=timeline.autostart_written.unix_ns)
        elif source == home + "/.bash_history":
            _require_timestamps(
                scene,
                source,
                {
                    "artifact.logical-updated": timeline.history_decoy_two.unix_ns,
                    "bash-history.record-0": timeline.history_marker.unix_ns,
                    "bash-history.record-1": timeline.history_subject.unix_ns,
                    "bash-history.record-2": timeline.history_decoy_one.unix_ns,
                    "bash-history.record-3": timeline.history_decoy_two.unix_ns,
                },
            )
            metadata = _linux_metadata(mode=0o600, changed=timeline.history_decoy_two.unix_ns)
        else:
            raise FixtureSceneProjectionError(
                f"Linux loose file {source!r} is outside the closed v2 projection profile"
            )
        result.append(
            _projected_file(family="linux", guest_path=guest_path, data=data, metadata=metadata)
        )
    return tuple(result)


def _directory_metadata(spec: FixtureSpecV2) -> LogicalMetadataV2:
    initialized = {
        "windows": spec.causal_clock.windows().host_initialized.unix_ns,
        "macos": spec.causal_clock.macos().host_initialized.unix_ns,
        "linux": spec.causal_clock.linux().host_initialized.unix_ns,
    }[spec.family]
    if spec.family == "windows":
        return WindowsMetadataV2(
            owner_sid=WINDOWS_LOGICAL_OWNER_SID_V2,
            attributes=("DIRECTORY",),
            creation_unix_ns=initialized,
            access_unix_ns=initialized,
            write_unix_ns=initialized,
            change_unix_ns=initialized,
        )
    if spec.family == "macos":
        return _macos_metadata(mode=0o755, born=initialized, changed=initialized)
    return _linux_metadata(mode=0o755, changed=initialized)


def _parent_directories(
    spec: FixtureSpecV2, files: tuple[ProjectedFileV2, ...]
) -> tuple[DirectoryNodeV2, ...]:
    served_paths = {
        "/".join(parts[:index])
        for item in files
        for parts in (item.node.served_path.split("/"),)
        for index in range(1, len(parts))
    }
    metadata = _directory_metadata(spec)
    return tuple(
        DirectoryNodeV2(
            guest_path=served_path_to_guest_path(spec.family, served_path),
            served_path=served_path,
            metadata=metadata,
        )
        for served_path in sorted(served_paths)
    )


def _assert_answer_free_nodes(plan: FixtureScenePlanV2) -> None:
    def walk(value: object) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key.casefold() in _FORBIDDEN_ROLE_TOKENS:
                    raise FixtureSceneProjectionError(
                        f"projected public node contains private field {key!r}"
                    )
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(plan.nodes_mapping())


def project_fixture_scene_v2(
    *, spec: FixtureSpecV2, scene: Scene, loose_files: Mapping[str, bytes]
) -> FixtureScenePlanV2:
    """Return the exact immutable v2 logical tree for one already-built loose scene.

    ``loose_files`` must equal ``scene.artifacts`` exactly.  macOS quarantine sidecars are
    consumed into xattrs and intentionally disappear as regular files; every other input byte
    string becomes exactly one unchanged default stream.  No output value retains ``Scene.join``.
    """
    _validate_scene_identity(spec, scene)
    loose = _validated_loose_files(scene, loose_files)
    projectors = {
        "windows": _project_windows,
        "macos": _project_macos,
        "linux": _project_linux,
    }
    files = tuple(
        sorted(projectors[spec.family](spec, scene, loose), key=lambda item: item.node.served_path)
    )
    directories = _parent_directories(spec, files)
    plan = FixtureScenePlanV2(family=spec.family, directories=directories, files=files)
    _assert_answer_free_nodes(plan)
    return plan
