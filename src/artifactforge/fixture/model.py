# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Strict, answer-free recipes and byte-bound fixture manifests.

The recipe contains only public inputs needed to reproduce a fixture.  The manifest repeats
that complete recipe and binds every payload file by safe POSIX path, byte length and SHA-256.
It intentionally has no answer key, join, timestamp, source checkout, or environment fields.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
from itertools import islice
import os
from pathlib import Path
import re
import stat
from typing import TYPE_CHECKING
import unicodedata

from artifactforge.fixture.canonical import (
    JSONValue,
    canonical_json_bytes,
    canonical_sha256,
    load_canonical_json,
    load_json_strict,
)
from artifactforge.fixture.abi import (
    CANONICALIZATION_V1 as CANONICALIZATION,
    GENERATOR_ABI_V1 as GENERATOR_ABI,
    MANIFEST_SCHEMA_V1 as MANIFEST_SCHEMA,
    SPEC_SCHEMA_V1 as SPEC_SCHEMA,
    MANIFEST_SCHEMA_V2,
    SPEC_SCHEMA_V2,
    TREE_CANONICALIZATION_V1 as TREE_CANONICALIZATION,
    require_spec_producer,
)
from artifactforge.fixture import resources
from artifactforge.inventory import InventoryError, validate_relative_path

if TYPE_CHECKING:
    from artifactforge.fixture.model_v2 import FixtureManifestV2, FixtureSpecV2

SPEC_PURPOSE = "public-reproducible-fixture"
GENERATOR_NAME = "artifactforge"
PAYLOAD_ROOT = "artifacts"

PROFILE_FAMILIES = {
    "windows-loose-v1": "windows",
    "macos-14-loose-v1": "macos",
    "linux-glibc-x86_64-loose-v1": "linux",
}

_FIXTURE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SEED_HEX = re.compile(r"^[0-9a-f]{64}$")
_LABELLED_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class FixtureValidationError(ValueError):
    """A recipe, manifest, artifact path, or payload tree violates the v1 contract."""


def _as_mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FixtureValidationError(f"{where} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise FixtureValidationError(f"{where} object member names must be strings")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], where: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(repr(item) for item in missing))
        if unknown:
            details.append("unknown " + ", ".join(repr(item) for item in unknown))
        raise FixtureValidationError(f"{where} has " + "; ".join(details))


def _text(value: object, where: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise FixtureValidationError(f"{where} must be a string")
    if nonempty and not value:
        raise FixtureValidationError(f"{where} must not be empty")
    if unicodedata.normalize("NFC", value) != value:
        raise FixtureValidationError(f"{where} must be Unicode NFC")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise FixtureValidationError(f"{where} contains an unpaired Unicode surrogate") from exc
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise FixtureValidationError(f"{where} must not contain control characters")
    return value


def _integer(value: object, where: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FixtureValidationError(f"{where} must be an integer")
    if value < minimum:
        raise FixtureValidationError(f"{where} must be at least {minimum}")
    return value


def _constant(value: object, expected: object, where: str) -> None:
    if value != expected or type(value) is not type(expected):
        raise FixtureValidationError(f"{where} must be {expected!r}")


def _labelled_sha256(value: object, where: str) -> str:
    text = _text(value, where)
    if not _LABELLED_SHA256.fullmatch(text):
        raise FixtureValidationError(f"{where} must be 'sha256:' plus 64 lowercase hex digits")
    return text


def validate_artifact_path(path: object) -> str:
    """Validate one printable-ASCII, relative POSIX payload path without normalising it."""
    try:
        validated = validate_relative_path(path)
    except InventoryError as exc:
        raise FixtureValidationError(str(exc)) from exc
    depth = len(validated.split("/"))
    if depth > resources.RESOURCE_POLICY.max_path_depth:
        raise FixtureValidationError(
            "artifact path exceeds the "
            f"{resources.RESOURCE_POLICY.max_path_depth}-component depth limit: {validated!r}"
        )
    return validated


@dataclass(frozen=True)
class ProfileSpec:
    id: str
    hostname: str
    username: str

    def __post_init__(self) -> None:
        profile_id = _text(self.id, "profile.id")
        if profile_id not in PROFILE_FAMILIES:
            choices = ", ".join(sorted(PROFILE_FAMILIES))
            raise FixtureValidationError(f"profile.id must be one of: {choices}")
        hostname = _text(self.hostname, "profile.hostname")
        if not _HOSTNAME.fullmatch(hostname):
            raise FixtureValidationError(
                "profile.hostname must be 1..63 ASCII letters, digits, dots or hyphens, "
                "starting with a letter or digit"
            )
        username = _text(self.username, "profile.username")
        if not _USERNAME.fullmatch(username):
            raise FixtureValidationError(
                "profile.username must be 1..64 ASCII letters, digits, dots, underscores "
                "or hyphens, starting with a letter or digit"
            )

    @classmethod
    def from_mapping(cls, value: object) -> ProfileSpec:
        mapping = _as_mapping(value, "profile")
        _exact_keys(mapping, {"id", "hostname", "username"}, "profile")
        return cls(
            id=_text(mapping["id"], "profile.id"),
            hostname=_text(mapping["hostname"], "profile.hostname"),
            username=_text(mapping["username"], "profile.username"),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {"id": self.id, "hostname": self.hostname, "username": self.username}


@dataclass(frozen=True)
class FixtureSpec:
    fixture_id: str
    family: str
    profile: ProfileSpec
    seed_hex: str
    schema: str = SPEC_SCHEMA
    purpose: str = SPEC_PURPOSE

    def __post_init__(self) -> None:
        _constant(self.schema, SPEC_SCHEMA, "spec.schema")
        _constant(self.purpose, SPEC_PURPOSE, "spec.purpose")
        fixture_id = _text(self.fixture_id, "spec.fixture_id")
        if not _FIXTURE_ID.fullmatch(fixture_id):
            raise FixtureValidationError(
                "spec.fixture_id must match [a-z0-9][a-z0-9._-]{0,63}"
            )
        family = _text(self.family, "spec.family")
        if family not in {"windows", "macos", "linux"}:
            raise FixtureValidationError("spec.family must be 'windows', 'macos' or 'linux'")
        if not isinstance(self.profile, ProfileSpec):
            raise FixtureValidationError("spec.profile must be a ProfileSpec")
        expected_family = PROFILE_FAMILIES[self.profile.id]
        if self.family != expected_family:
            raise FixtureValidationError(
                f"profile {self.profile.id!r} belongs to {expected_family!r}, not {self.family!r}"
            )
        seed_hex = _text(self.seed_hex, "spec.seed_hex")
        if not _SEED_HEX.fullmatch(seed_hex):
            raise FixtureValidationError("spec.seed_hex must be exactly 64 lowercase hex digits")

    @classmethod
    def from_mapping(cls, value: object) -> FixtureSpec:
        mapping = _as_mapping(value, "spec")
        _exact_keys(
            mapping,
            {"schema", "purpose", "fixture_id", "family", "profile", "seed_hex"},
            "spec",
        )
        return cls(
            schema=_text(mapping["schema"], "spec.schema"),
            purpose=_text(mapping["purpose"], "spec.purpose"),
            fixture_id=_text(mapping["fixture_id"], "spec.fixture_id"),
            family=_text(mapping["family"], "spec.family"),
            profile=ProfileSpec.from_mapping(mapping["profile"]),
            seed_hex=_text(mapping["seed_hex"], "spec.seed_hex"),
        )

    @classmethod
    def from_json(cls, data: bytes | str) -> FixtureSpec:
        return cls.from_mapping(load_json_strict(data))

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "schema": self.schema,
            "purpose": self.purpose,
            "fixture_id": self.fixture_id,
            "family": self.family,
            "profile": self.profile.to_mapping(),
            "seed_hex": self.seed_hex,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping())

    @property
    def recipe_sha256(self) -> str:
        return canonical_sha256(self.to_mapping())


def compute_recipe_sha256(spec: FixtureSpec) -> str:
    if not isinstance(spec, FixtureSpec):
        raise TypeError("recipe digest input must be a FixtureSpec")
    return spec.recipe_sha256


@dataclass(frozen=True)
class ArtifactEntry:
    path: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        validate_artifact_path(self.path)
        size = _integer(self.size, f"artifact {self.path!r} size")
        if size > resources.RESOURCE_POLICY.max_file_bytes:
            raise FixtureValidationError(
                f"artifact {self.path!r} exceeds the "
                f"{resources.RESOURCE_POLICY.max_file_bytes}-byte per-file limit"
            )
        _labelled_sha256(self.sha256, f"artifact {self.path!r} sha256")

    @classmethod
    def from_mapping(cls, value: object, *, where: str = "artifact") -> ArtifactEntry:
        mapping = _as_mapping(value, where)
        _exact_keys(mapping, {"path", "size", "sha256"}, where)
        return cls(
            path=validate_artifact_path(mapping["path"]),
            size=_integer(mapping["size"], f"{where}.size"),
            sha256=_labelled_sha256(mapping["sha256"], f"{where}.sha256"),
        )

    @classmethod
    def from_bytes(cls, path: str, data: bytes) -> ArtifactEntry:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        return cls(
            path=validate_artifact_path(path),
            size=len(data),
            sha256="sha256:" + hashlib.sha256(data).hexdigest(),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


def _validated_entries(
    entries: Iterable[ArtifactEntry], *, require_sorted: bool
) -> tuple[ArtifactEntry, ...]:
    if isinstance(entries, (str, bytes, Mapping)):
        raise FixtureValidationError("artifact files must be a sequence of ArtifactEntry values")
    try:
        iterator = iter(entries)
    except TypeError as exc:
        raise FixtureValidationError(
            "artifact files must be an iterable of ArtifactEntry values"
        ) from exc
    result = tuple(islice(iterator, resources.RESOURCE_POLICY.max_files + 1))
    if len(result) > resources.RESOURCE_POLICY.max_files:
        raise FixtureValidationError(
            f"artifact files exceed the {resources.RESOURCE_POLICY.max_files}-file limit"
        )
    if not result:
        raise FixtureValidationError("a fixture payload must contain at least one artifact file")
    for index, entry in enumerate(result):
        if not isinstance(entry, ArtifactEntry):
            raise FixtureValidationError(f"artifact files[{index}] must be an ArtifactEntry")

    ordered = tuple(sorted(result, key=lambda entry: entry.path))
    if require_sorted and result != ordered:
        raise FixtureValidationError("artifact files must be sorted by path")

    # Compare every path prefix, not just complete filenames.  Otherwise A/x and a/y would
    # extract into two directories on a case-sensitive host and collide on a common target.
    seen_casefold: dict[str, str] = {}
    directory_prefixes: set[str] = set()
    complete_paths: set[str] = set()
    for entry in ordered:
        parts = entry.path.split("/")
        prefixes = ["/".join(parts[:index]) for index in range(1, len(parts) + 1)]
        for prefix in prefixes:
            folded = prefix.casefold()
            previous = seen_casefold.get(folded)
            if previous is not None and previous != prefix:
                raise FixtureValidationError(
                    f"case-folding artifact path collision: {previous!r} and {prefix!r}"
                )
            seen_casefold[folded] = prefix

        for directory in prefixes[:-1]:
            if directory in complete_paths:
                raise FixtureValidationError(
                    f"artifact path is both a file and a directory: {directory!r}"
                )
            directory_prefixes.add(directory)
        if entry.path in directory_prefixes:
            raise FixtureValidationError(
                f"artifact path is both a file and a directory: {entry.path!r}"
            )
        if entry.path in complete_paths:
            raise FixtureValidationError(f"duplicate artifact path: {entry.path!r}")
        complete_paths.add(entry.path)
    total_bytes = sum(entry.size for entry in ordered)
    if total_bytes > resources.RESOURCE_POLICY.max_total_bytes:
        raise FixtureValidationError(
            "artifact files exceed the "
            f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
        )
    archive_members = len(complete_paths) + len(directory_prefixes) + 3
    if archive_members > resources.RESOURCE_POLICY.max_members:
        raise FixtureValidationError(
            "artifact paths require "
            f"{archive_members} archive members; limit is "
            f"{resources.RESOURCE_POLICY.max_members}"
        )
    return ordered


def validate_artifact_entries(
    entries: Iterable[ArtifactEntry], *, require_sorted: bool = True
) -> tuple[ArtifactEntry, ...]:
    """Validate ordering plus exact, case-folding, and file/directory path collisions."""
    return _validated_entries(entries, require_sorted=require_sorted)


def canonical_artifact_entries(entries: Iterable[ArtifactEntry]) -> tuple[ArtifactEntry, ...]:
    """Validate and return entries in the one order used by tree digests."""
    return _validated_entries(entries, require_sorted=False)


def compute_tree_sha256(entries: Iterable[ArtifactEntry]) -> str:
    ordered = canonical_artifact_entries(entries)
    digest_input = {
        "canonicalization": TREE_CANONICALIZATION,
        "files": [entry.to_mapping() for entry in ordered],
    }
    return canonical_sha256(digest_input)


def artifact_entries_from_tree(root: str | os.PathLike[str]) -> tuple[ArtifactEntry, ...]:
    """Inventory a payload directory without following attacker-swappable path components."""
    try:
        root_path = Path(root)
    except TypeError as exc:
        raise FixtureValidationError("artifact root must be a filesystem path") from exc
    try:
        root_stat = root_path.lstat()
    except OSError as exc:
        raise FixtureValidationError(f"cannot inspect artifact root {root_path}: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise FixtureValidationError(f"artifact root must not be a symlink: {root_path}")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise FixtureValidationError(f"artifact root must be a directory: {root_path}")

    entries: list[ArtifactEntry] = []
    member_count = 0
    total_bytes = 0
    observed_directory_names: dict[tuple[str, ...], tuple[str, ...]] = {}
    observed_directory_states: dict[tuple[str, ...], tuple[int, int, int, int, int]] = {}
    observed_file_states: dict[str, tuple[int, int, int, int, int]] = {}

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)

    def stable_state(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def open_checked(
        directory_fd: int, name: str, expected: os.stat_result, relative: str, *, is_dir: bool
    ) -> int:
        flags = os.O_RDONLY | cloexec | nofollow
        if is_dir:
            flags |= directory_flag
        try:
            opened = os.open(name, flags, dir_fd=directory_fd)
        except OSError as exc:
            raise FixtureValidationError(f"cannot safely open artifact path {relative!r}: {exc}") from exc
        opened_stat = os.fstat(opened)
        expected_kind = stat.S_ISDIR if is_dir else stat.S_ISREG
        if (
            not expected_kind(opened_stat.st_mode)
            or stable_state(expected) != stable_state(opened_stat)
        ):
            os.close(opened)
            raise FixtureValidationError(f"artifact path changed while inventorying: {relative!r}")
        # O_NOFOLLOW is absent on a few supported Python platforms.  A descriptor/path identity
        # check on those platforms closes the obvious lstat/open link-swap window.
        if not nofollow:
            try:
                path_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                os.close(opened)
                raise FixtureValidationError(
                    f"cannot recheck artifact path {relative!r}: {exc}"
                ) from exc
            if (
                not expected_kind(path_stat.st_mode)
                or stable_state(opened_stat) != stable_state(path_stat)
            ):
                os.close(opened)
                raise FixtureValidationError(
                    f"artifact path changed while inventorying: {relative!r}"
                )
        return opened

    def visit(directory_fd: int, relative_parts: tuple[str, ...]) -> int:
        nonlocal member_count, total_bytes
        before_directory = os.fstat(directory_fd)
        try:
            with os.scandir(directory_fd) as scan:
                children = []
                for child in scan:
                    member_count += 1
                    if member_count > resources.RESOURCE_POLICY.max_members:
                        raise FixtureValidationError(
                            "artifact tree exceeds the "
                            f"{resources.RESOURCE_POLICY.max_members}-member limit"
                        )
                    children.append(child)
                children.sort(key=lambda item: item.name)
        except FixtureValidationError:
            raise
        except OSError as exc:
            shown = "/".join(relative_parts) or "."
            raise FixtureValidationError(
                f"cannot list artifact directory {shown!r}: {exc}"
            ) from exc
        files_below = 0
        for child in children:
            relative = "/".join((*relative_parts, child.name))
            validate_artifact_path(relative)
            try:
                child_stat = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise FixtureValidationError(f"cannot inspect artifact path {relative!r}: {exc}") from exc
            mode = child_stat.st_mode
            if stat.S_ISLNK(mode):
                raise FixtureValidationError(f"artifact tree contains a symlink: {relative!r}")
            if stat.S_ISDIR(mode):
                child_fd = open_checked(
                    directory_fd, child.name, child_stat, relative, is_dir=True
                )
                try:
                    nested = visit(child_fd, (*relative_parts, child.name))
                finally:
                    os.close(child_fd)
                if nested == 0:
                    raise FixtureValidationError(
                        f"artifact tree contains an unbound empty directory: {relative!r}"
                    )
                files_below += nested
                continue
            if not stat.S_ISREG(mode):
                raise FixtureValidationError(f"artifact tree contains a special file: {relative!r}")
            if child_stat.st_size > resources.RESOURCE_POLICY.max_file_bytes:
                raise FixtureValidationError(
                    f"artifact file exceeds the "
                    f"{resources.RESOURCE_POLICY.max_file_bytes}-byte limit: {relative!r}"
                )
            if len(entries) + 1 > resources.RESOURCE_POLICY.max_files:
                raise FixtureValidationError(
                    f"artifact tree exceeds the {resources.RESOURCE_POLICY.max_files}-file limit"
                )
            if total_bytes + child_stat.st_size > resources.RESOURCE_POLICY.max_total_bytes:
                raise FixtureValidationError(
                    "artifact tree exceeds the "
                    f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
                )
            file_fd = open_checked(
                directory_fd, child.name, child_stat, relative, is_dir=False
            )
            digest = hashlib.sha256()
            size = 0
            try:
                before = os.fstat(file_fd)
                remaining = resources.RESOURCE_POLICY.max_total_bytes - total_bytes
                if before.st_size > remaining:
                    raise FixtureValidationError(
                        "artifact tree exceeds the "
                        f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
                    )
                # The opened file's full state is bound by open_checked. Read exactly that
                # many bytes; the post-read descriptor/path comparison detects any mutation.
                while size < before.st_size:
                    chunk = os.read(
                        file_fd,
                        min(
                            resources.READ_CHUNK,
                            before.st_size - size,
                        ),
                    )
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                after = os.fstat(file_fd)
                after_path = os.stat(
                    child.name, dir_fd=directory_fd, follow_symlinks=False
                )
            except FixtureValidationError:
                raise
            except OSError as exc:
                raise FixtureValidationError(f"cannot read artifact file {relative!r}: {exc}") from exc
            finally:
                os.close(file_fd)
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (
                any(getattr(before, field) != getattr(after, field) for field in stable_fields)
                or any(
                    getattr(after, field) != getattr(after_path, field)
                    for field in stable_fields
                )
            ):
                raise FixtureValidationError(
                    f"artifact file changed while inventorying: {relative!r}"
                )
            if size > resources.RESOURCE_POLICY.max_file_bytes:
                raise FixtureValidationError(
                    f"artifact file exceeds the "
                    f"{resources.RESOURCE_POLICY.max_file_bytes}-byte limit: {relative!r}"
                )
            if size != after.st_size:
                raise FixtureValidationError(
                    f"artifact file length changed while inventorying: {relative!r}"
                )
            if total_bytes + size > resources.RESOURCE_POLICY.max_total_bytes:
                raise FixtureValidationError(
                    "artifact tree exceeds the "
                    f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
                )
            entries.append(
                ArtifactEntry(
                    path=relative,
                    size=size,
                    sha256="sha256:" + digest.hexdigest(),
                )
            )
            observed_file_states[relative] = stable_state(after_path)
            total_bytes += size
            files_below += 1
        after_directory = os.fstat(directory_fd)
        directory_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before_directory, field) != getattr(after_directory, field)
            for field in directory_fields
        ):
            shown = "/".join(relative_parts) or "."
            raise FixtureValidationError(
                f"artifact directory changed while inventorying: {shown!r}"
            )
        observed_directory_names[relative_parts] = tuple(
            child.name for child in children
        )
        observed_directory_states[relative_parts] = stable_state(after_directory)
        return files_below

    def revalidate(directory_fd: int, relative_parts: tuple[str, ...]) -> None:
        """Reject changes to earlier siblings after the first-pass read completed."""
        shown = "/".join(relative_parts) or "."
        expected_directory_state = observed_directory_states[relative_parts]
        if stable_state(os.fstat(directory_fd)) != expected_directory_state:
            raise FixtureValidationError(
                f"artifact directory changed after inventorying: {shown!r}"
            )
        expected_names = observed_directory_names[relative_parts]
        try:
            names = resources.bounded_directory_names(
                directory_fd,
                max_entries=len(expected_names),
                label=f"artifact directory {shown!r}",
            )
        except resources.FixtureResourceError as exc:
            raise FixtureValidationError(
                f"artifact directory changed after inventorying: {shown!r}: {exc}"
            ) from exc
        if names != expected_names:
            raise FixtureValidationError(
                f"artifact directory changed after inventorying: {shown!r}"
            )
        for name in names:
            parts = (*relative_parts, name)
            relative = "/".join(parts)
            try:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except (NotImplementedError, OSError) as exc:
                raise FixtureValidationError(
                    f"cannot recheck artifact path {relative!r}: {exc}"
                ) from exc
            if relative in observed_file_states:
                if (
                    not stat.S_ISREG(current.st_mode)
                    or stable_state(current) != observed_file_states[relative]
                ):
                    raise FixtureValidationError(
                        f"artifact file changed after inventorying: {relative!r}"
                    )
                continue
            if parts not in observed_directory_states or not stat.S_ISDIR(current.st_mode):
                raise FixtureValidationError(
                    f"artifact path changed after inventorying: {relative!r}"
                )
            child_fd = open_checked(
                directory_fd, name, current, relative, is_dir=True
            )
            try:
                revalidate(child_fd, parts)
                path_after = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if stable_state(path_after) != observed_directory_states[parts]:
                    raise FixtureValidationError(
                        f"artifact directory changed after inventorying: {relative!r}"
                    )
            except OSError as exc:
                raise FixtureValidationError(
                    f"cannot recheck artifact directory {relative!r}: {exc}"
                ) from exc
            finally:
                os.close(child_fd)
        if stable_state(os.fstat(directory_fd)) != expected_directory_state:
            raise FixtureValidationError(
                f"artifact directory changed after inventorying: {shown!r}"
            )

    root_flags = os.O_RDONLY | cloexec | nofollow | directory_flag
    try:
        root_fd = os.open(root_path, root_flags)
    except OSError as exc:
        raise FixtureValidationError(f"cannot safely open artifact root {root_path}: {exc}") from exc
    try:
        opened_root_stat = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(opened_root_stat.st_mode)
            or stable_state(root_stat) != stable_state(opened_root_stat)
        ):
            raise FixtureValidationError(f"artifact root changed while inventorying: {root_path}")
        if not nofollow:
            after_open = root_path.lstat()
            if (
                not stat.S_ISDIR(after_open.st_mode)
                or stable_state(opened_root_stat) != stable_state(after_open)
            ):
                raise FixtureValidationError(
                    f"artifact root changed while inventorying: {root_path}"
                )
        visit(root_fd, ())
        revalidate(root_fd, ())
        final_root_stat = os.fstat(root_fd)
        try:
            final_root_path = root_path.lstat()
        except OSError as exc:
            raise FixtureValidationError(
                f"cannot recheck artifact root {root_path}: {exc}"
            ) from exc
        if (
            stable_state(opened_root_stat) != stable_state(final_root_stat)
            or stable_state(final_root_stat) != stable_state(final_root_path)
        ):
            raise FixtureValidationError(
                f"artifact root changed while inventorying: {root_path}"
            )
    finally:
        os.close(root_fd)
    return canonical_artifact_entries(entries)


@dataclass(frozen=True)
class FixturePurpose:
    kind: str = SPEC_PURPOSE
    benchmark_eligible: bool = False

    def __post_init__(self) -> None:
        _constant(self.kind, SPEC_PURPOSE, "manifest.purpose.kind")
        _constant(self.benchmark_eligible, False, "manifest.purpose.benchmark_eligible")

    @classmethod
    def from_mapping(cls, value: object) -> FixturePurpose:
        mapping = _as_mapping(value, "manifest.purpose")
        _exact_keys(mapping, {"kind", "benchmark_eligible"}, "manifest.purpose")
        return cls(
            kind=_text(mapping["kind"], "manifest.purpose.kind"),
            benchmark_eligible=mapping["benchmark_eligible"],
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {"kind": self.kind, "benchmark_eligible": self.benchmark_eligible}


@dataclass(frozen=True)
class GeneratorIdentity:
    version: str
    name: str = GENERATOR_NAME
    abi: str = GENERATOR_ABI

    def __post_init__(self) -> None:
        _constant(self.name, GENERATOR_NAME, "manifest.generator.name")
        _text(self.version, "manifest.generator.version")
        _constant(self.abi, GENERATOR_ABI, "manifest.generator.abi")

    @classmethod
    def from_mapping(cls, value: object) -> GeneratorIdentity:
        mapping = _as_mapping(value, "manifest.generator")
        _exact_keys(mapping, {"name", "version", "abi"}, "manifest.generator")
        return cls(
            name=_text(mapping["name"], "manifest.generator.name"),
            version=_text(mapping["version"], "manifest.generator.version"),
            abi=_text(mapping["abi"], "manifest.generator.abi"),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {"name": self.name, "version": self.version, "abi": self.abi}


@dataclass(frozen=True)
class FixturePayload:
    file_count: int
    total_bytes: int
    tree_sha256: str
    files: tuple[ArtifactEntry, ...]
    root: str = PAYLOAD_ROOT
    canonicalization: str = TREE_CANONICALIZATION

    def __post_init__(self) -> None:
        _constant(self.root, PAYLOAD_ROOT, "manifest.payload.root")
        _constant(
            self.canonicalization,
            TREE_CANONICALIZATION,
            "manifest.payload.canonicalization",
        )
        try:
            files = validate_artifact_entries(self.files, require_sorted=True)
        except TypeError as exc:
            raise FixtureValidationError(
                "manifest.payload.files must be an iterable of ArtifactEntry values"
            ) from exc
        object.__setattr__(self, "files", files)
        file_count = _integer(self.file_count, "manifest.payload.file_count", minimum=1)
        total_bytes = _integer(self.total_bytes, "manifest.payload.total_bytes")
        if file_count > resources.RESOURCE_POLICY.max_files:
            raise FixtureValidationError(
                "manifest.payload.file_count exceeds the "
                f"{resources.RESOURCE_POLICY.max_files}-file limit"
            )
        if total_bytes > resources.RESOURCE_POLICY.max_total_bytes:
            raise FixtureValidationError(
                "manifest.payload.total_bytes exceeds the "
                f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
            )
        if file_count != len(files):
            raise FixtureValidationError(
                "manifest.payload.file_count does not equal the number of files"
            )
        expected_bytes = sum(entry.size for entry in files)
        if total_bytes != expected_bytes:
            raise FixtureValidationError(
                "manifest.payload.total_bytes does not equal the sum of file sizes"
            )
        tree_sha256 = _labelled_sha256(
            self.tree_sha256, "manifest.payload.tree_sha256"
        )
        expected_tree = compute_tree_sha256(files)
        if tree_sha256 != expected_tree:
            raise FixtureValidationError(
                f"manifest.payload.tree_sha256 mismatch: expected {expected_tree}"
            )

    @classmethod
    def create(cls, entries: Iterable[ArtifactEntry]) -> FixturePayload:
        # This helper constructs a payload explicitly labelled with the v1 tree contract.
        # Keep validation/digest functions readable, but do not bless new trees as frozen v1.
        require_spec_producer(SPEC_SCHEMA)
        files = canonical_artifact_entries(entries)
        return cls(
            file_count=len(files),
            total_bytes=sum(entry.size for entry in files),
            tree_sha256=compute_tree_sha256(files),
            files=files,
        )

    @classmethod
    def from_mapping(cls, value: object) -> FixturePayload:
        mapping = _as_mapping(value, "manifest.payload")
        _exact_keys(
            mapping,
            {"root", "canonicalization", "file_count", "total_bytes", "tree_sha256", "files"},
            "manifest.payload",
        )
        raw_files = mapping["files"]
        if not isinstance(raw_files, list):
            raise FixtureValidationError("manifest.payload.files must be an array")
        file_count = _integer(
            mapping["file_count"], "manifest.payload.file_count", minimum=1
        )
        total_bytes = _integer(mapping["total_bytes"], "manifest.payload.total_bytes")
        if file_count > resources.RESOURCE_POLICY.max_files:
            raise FixtureValidationError(
                "manifest.payload.file_count exceeds the "
                f"{resources.RESOURCE_POLICY.max_files}-file limit"
            )
        if total_bytes > resources.RESOURCE_POLICY.max_total_bytes:
            raise FixtureValidationError(
                "manifest.payload.total_bytes exceeds the "
                f"{resources.RESOURCE_POLICY.max_total_bytes}-byte total limit"
            )
        if len(raw_files) > resources.RESOURCE_POLICY.max_files:
            raise FixtureValidationError(
                "manifest.payload.files exceeds the "
                f"{resources.RESOURCE_POLICY.max_files}-file limit"
            )
        files = tuple(
            ArtifactEntry.from_mapping(item, where=f"manifest.payload.files[{index}]")
            for index, item in enumerate(raw_files)
        )
        return cls(
            root=_text(mapping["root"], "manifest.payload.root"),
            canonicalization=_text(
                mapping["canonicalization"], "manifest.payload.canonicalization"
            ),
            file_count=file_count,
            total_bytes=total_bytes,
            tree_sha256=_labelled_sha256(
                mapping["tree_sha256"], "manifest.payload.tree_sha256"
            ),
            files=files,
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "root": self.root,
            "canonicalization": self.canonicalization,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "tree_sha256": self.tree_sha256,
            "files": [entry.to_mapping() for entry in self.files],
        }


@dataclass(frozen=True)
class FixtureManifest:
    generator: GeneratorIdentity
    recipe: FixtureSpec
    recipe_sha256: str
    payload: FixturePayload
    schema: str = MANIFEST_SCHEMA
    canonicalization: str = CANONICALIZATION
    purpose: FixturePurpose = FixturePurpose()

    def __post_init__(self) -> None:
        _constant(self.schema, MANIFEST_SCHEMA, "manifest.schema")
        _constant(
            self.canonicalization, CANONICALIZATION, "manifest.canonicalization"
        )
        if not isinstance(self.purpose, FixturePurpose):
            raise FixtureValidationError("manifest.purpose must be a FixturePurpose")
        if not isinstance(self.generator, GeneratorIdentity):
            raise FixtureValidationError("manifest.generator must be a GeneratorIdentity")
        if not isinstance(self.recipe, FixtureSpec):
            raise FixtureValidationError("manifest.recipe must be a FixtureSpec")
        if not isinstance(self.payload, FixturePayload):
            raise FixtureValidationError("manifest.payload must be a FixturePayload")
        recipe_sha256 = _labelled_sha256(self.recipe_sha256, "manifest.recipe_sha256")
        if recipe_sha256 != self.recipe.recipe_sha256:
            raise FixtureValidationError(
                f"manifest.recipe_sha256 mismatch: expected {self.recipe.recipe_sha256}"
            )

    @classmethod
    def create(
        cls,
        recipe: FixtureSpec,
        *,
        generator_version: str,
        entries: Iterable[ArtifactEntry],
    ) -> FixtureManifest:
        # Construction is a producer operation, not a parser convenience.  V1 remains
        # readable, but current writers are no longer the frozen 0.5.0 byte producer.
        require_spec_producer(recipe.schema)
        return cls(
            generator=GeneratorIdentity(version=generator_version),
            recipe=recipe,
            recipe_sha256=compute_recipe_sha256(recipe),
            payload=FixturePayload.create(entries),
        )

    @classmethod
    def from_mapping(cls, value: object) -> FixtureManifest:
        mapping = _as_mapping(value, "manifest")
        _exact_keys(
            mapping,
            {
                "schema",
                "canonicalization",
                "purpose",
                "generator",
                "recipe",
                "recipe_sha256",
                "payload",
            },
            "manifest",
        )
        return cls(
            schema=_text(mapping["schema"], "manifest.schema"),
            canonicalization=_text(
                mapping["canonicalization"], "manifest.canonicalization"
            ),
            purpose=FixturePurpose.from_mapping(mapping["purpose"]),
            generator=GeneratorIdentity.from_mapping(mapping["generator"]),
            recipe=FixtureSpec.from_mapping(mapping["recipe"]),
            recipe_sha256=_labelled_sha256(
                mapping["recipe_sha256"], "manifest.recipe_sha256"
            ),
            payload=FixturePayload.from_mapping(mapping["payload"]),
        )

    @classmethod
    def from_json(cls, data: bytes | str) -> FixtureManifest:
        return cls.from_mapping(load_json_strict(data))

    @classmethod
    def from_canonical_json(cls, data: bytes) -> FixtureManifest:
        """Read a stored manifest, rejecting harmless-looking alternate byte spellings."""
        return cls.from_mapping(load_canonical_json(data))

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "schema": self.schema,
            "canonicalization": self.canonicalization,
            "purpose": self.purpose.to_mapping(),
            "generator": self.generator.to_mapping(),
            "recipe": self.recipe.to_mapping(),
            "recipe_sha256": self.recipe_sha256,
            "payload": self.payload.to_mapping(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping())


def _dispatch_schema(
    value: object,
    *,
    where: str,
    parsers: Mapping[str, object],
) -> object:
    """Select a parser by the exact top-level schema before interpreting its fields."""
    mapping = _as_mapping(value, where)
    schema = mapping.get("schema")
    if not isinstance(schema, str):
        raise FixtureValidationError(f"{where}.schema must be a string")
    parser = parsers.get(schema)
    if parser is None:
        raise FixtureValidationError(f"unsupported fixture {where} schema: {schema!r}")
    return parser(mapping)  # type: ignore[operator]


def _parse_spec_v2(value: object) -> object:
    from artifactforge.fixture.model_v2 import FixtureSpecV2

    return FixtureSpecV2.from_mapping(value)


def _parse_manifest_v2(value: object) -> object:
    from artifactforge.fixture.model_v2 import FixtureManifestV2

    return FixtureManifestV2.from_mapping(value)


_SPEC_PARSERS = {
    SPEC_SCHEMA: FixtureSpec.from_mapping,
    SPEC_SCHEMA_V2: _parse_spec_v2,
}
_MANIFEST_PARSERS = {
    MANIFEST_SCHEMA: FixtureManifest.from_mapping,
    MANIFEST_SCHEMA_V2: _parse_manifest_v2,
}


def parse_fixture_spec(data: bytes | str) -> FixtureSpec | FixtureSpecV2:
    """Strictly decode and explicitly dispatch a public fixture recipe."""
    result = _dispatch_schema(load_json_strict(data), where="spec", parsers=_SPEC_PARSERS)
    from artifactforge.fixture.model_v2 import FixtureSpecV2

    if not isinstance(
        result, (FixtureSpec, FixtureSpecV2)
    ):  # pragma: no cover - registry invariant
        raise FixtureValidationError("fixture spec parser returned the wrong model type")
    return result


def parse_fixture_manifest(
    data: bytes | str, *, require_canonical: bool = False
) -> FixtureManifest | FixtureManifestV2:
    """Strictly decode and explicitly dispatch a fixture manifest.

    Stored/released machine records set ``require_canonical``; callers parsing an in-memory
    value can retain the historical whitespace-tolerant v1 parser behavior.
    """
    if require_canonical:
        if not isinstance(data, bytes):
            raise FixtureValidationError("canonical fixture manifests must be bytes")
        value = load_canonical_json(data)
    else:
        value = load_json_strict(data)
    result = _dispatch_schema(value, where="manifest", parsers=_MANIFEST_PARSERS)
    from artifactforge.fixture.model_v2 import FixtureManifestV2

    if not isinstance(
        result, (FixtureManifest, FixtureManifestV2)
    ):  # pragma: no cover - registry invariant
        raise FixtureValidationError("fixture manifest parser returned the wrong model type")
    return result
