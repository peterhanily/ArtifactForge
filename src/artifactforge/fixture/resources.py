# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""One fail-closed resource policy for every Fixture Core ingress.

The policy is deliberately part of the implementation rather than Fixture ABI v1: it changes
which hostile or impractically large inputs are accepted, never the bytes of a valid fixture.
Specs, manifests, loose payloads, captured snapshots and USTAR releases all use these same
ceilings before reading or materialising attacker-controlled bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat

from artifactforge.inventory import (
    MAX_SCENE_DEPTH,
    MAX_SCENE_FILE_BYTES,
    MAX_SCENE_FILES,
    MAX_SCENE_TOTAL_BYTES,
    path_handle_file_observations_match,
)

READ_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class FixtureResourcePolicy:
    """Finite ceilings shared by Fixture Core parsers, trees and archives."""

    max_input_bytes: int = 4 * 1024 * 1024
    max_files: int = MAX_SCENE_FILES
    max_members: int = 8192
    max_path_depth: int = MAX_SCENE_DEPTH
    max_file_bytes: int = MAX_SCENE_FILE_BYTES
    max_total_bytes: int = MAX_SCENE_TOTAL_BYTES
    max_json_nesting: int = 32

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_members < self.max_files:
            raise ValueError("max_members must be at least max_files")

    @property
    def max_archive_bytes(self) -> int:
        """Largest possible uncompressed USTAR under the other policy ceilings.

        This includes the payload and manifest, one 512-byte header per member, worst-case
        regular-file padding, and one final 10 KiB USTAR record for trailer/padding.
        """
        regular_files = self.max_files + 1  # fixture.json plus payload files
        return (
            self.max_total_bytes
            + self.max_input_bytes
            + self.max_members * 512
            + regular_files * 511
            + 10240
        )


# Tests may replace this immutable value with a smaller policy. Production code always reads
# it through the module, so every ingress observes the same replacement.
RESOURCE_POLICY = FixtureResourcePolicy()


class FixtureResourceError(ValueError):
    """A stable read or finite resource ceiling could not be satisfied."""


def _state(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _bounded_descriptor_bytes(
    descriptor: int,
    *,
    state: os.stat_result,
    max_bytes: int,
    label: str,
    use_pread: bool,
) -> bytes:
    if not stat.S_ISREG(state.st_mode):
        raise FixtureResourceError(f"{label} must be a regular file")
    if state.st_size > max_bytes:
        raise FixtureResourceError(f"{label} exceeds the {max_bytes}-byte limit")
    chunks: list[bytes] = []
    offset = 0
    try:
        # Read exactly the size bound to the opened descriptor.  A final state comparison
        # detects growth or truncation, so probing one byte past the stable size only creates
        # an avoidable max_bytes + 1 materialisation at a cumulative-budget boundary.
        while offset < state.st_size:
            request = min(READ_CHUNK, state.st_size - offset)
            if use_pread:
                chunk = os.pread(descriptor, request, offset)
            else:
                chunk = os.read(descriptor, request)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except (AttributeError, NotImplementedError, OSError) as exc:
        raise FixtureResourceError(f"cannot read {label} safely: {exc}") from exc
    if _state(state) != _state(after) or offset != state.st_size:
        raise FixtureResourceError(f"{label} changed while it was being read")
    return b"".join(chunks)


def read_stable_descriptor(descriptor: int, *, max_bytes: int, label: str) -> bytes:
    """Bounded positional read of one already-held regular-file descriptor."""
    try:
        state = os.fstat(descriptor)
    except OSError as exc:
        raise FixtureResourceError(f"cannot inspect {label}: {exc}") from exc
    return _bounded_descriptor_bytes(
        descriptor,
        state=state,
        max_bytes=max_bytes,
        label=label,
        use_pread=True,
    )


def read_stable_regular_path(path: Path, *, max_bytes: int, label: str) -> bytes:
    """No-follow, identity-bound and size-bounded read of one pathname."""
    descriptor = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise FixtureResourceError(
                f"{label} must be a regular file, not a link or special file"
            )
        if before.st_size > max_bytes:
            raise FixtureResourceError(f"{label} exceeds the {max_bytes}-byte limit")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not path_handle_file_observations_match(
            before,
            opened,
        ):
            raise FixtureResourceError(f"{label} changed while it was being opened")
        payload = _bounded_descriptor_bytes(
            descriptor,
            state=opened,
            max_bytes=max_bytes,
            label=label,
            use_pread=False,
        )
        after_path = path.lstat()
        if (
            not path_handle_file_observations_match(after_path, opened)
            or _state(before) != _state(after_path)
        ):
            raise FixtureResourceError(f"{label} changed while it was being read")
        return payload
    except FixtureResourceError:
        raise
    except OSError as exc:
        raise FixtureResourceError(f"cannot read {label} safely: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_stable_regular_at(
    parent_descriptor: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Descriptor-relative no-follow read with size and state bounds."""
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise FixtureResourceError(
                f"{label} must be a regular file, not a link or special file"
            )
        if before.st_size > max_bytes:
            raise FixtureResourceError(f"{label} exceeds the {max_bytes}-byte limit")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not path_handle_file_observations_match(
            before,
            opened,
        ):
            raise FixtureResourceError(f"{label} changed while it was being opened")
        payload = _bounded_descriptor_bytes(
            descriptor,
            state=opened,
            max_bytes=max_bytes,
            label=label,
            use_pread=False,
        )
        after_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not path_handle_file_observations_match(after_path, opened)
            or _state(before) != _state(after_path)
        ):
            raise FixtureResourceError(f"{label} changed while it was being read")
        return payload
    except FixtureResourceError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise FixtureResourceError(f"cannot read {label} safely: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def bounded_directory_names(
    descriptor: int,
    *,
    max_entries: int,
    label: str,
) -> tuple[str, ...]:
    """Read at most ``max_entries + 1`` names and bind them to stable directory state."""
    try:
        before = os.fstat(descriptor)
        names: list[str] = []
        with os.scandir(descriptor) as scan:
            for entry in scan:
                names.append(entry.name)
                if len(names) > max_entries:
                    raise FixtureResourceError(
                        f"{label} exceeds the {max_entries}-member limit"
                    )
        after = os.fstat(descriptor)
    except FixtureResourceError:
        raise
    except OSError as exc:
        raise FixtureResourceError(f"cannot list {label} safely: {exc}") from exc
    if _state(before) != _state(after):
        raise FixtureResourceError(f"{label} changed while it was being listed")
    return tuple(sorted(names))
