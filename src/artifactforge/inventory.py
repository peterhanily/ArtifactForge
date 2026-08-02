# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Canonical, recursive inventory for loose-file scenes.

Artifact paths are public identifiers.  They therefore use one spelling everywhere: printable
ASCII, relative POSIX paths, ordered byte-for-byte, with no normalisation, traversal aliases,
case-folding collisions, or file/directory ancestor conflicts.  Dot-prefixed components are
ordinary artifact names; only the literal ``.`` and ``..`` components are unsafe.

The fixture layer performs an additional descriptor-bound read while hashing publication
bytes.  This module supplies the shared path grammar and the read-only scene traversal used by
staging, gates, sample checks, and non-fixture callers.
"""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import stat
import sys
import tempfile


class InventoryError(ValueError):
    """A relative path or loose-file tree is ambiguous, unsafe, or malformed."""


MAX_SCENE_FILES = 4096
MAX_SCENE_FILE_BYTES = 64 * 1024 * 1024
MAX_SCENE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SCENE_DEPTH = 32


@dataclass(frozen=True)
class InventoryFile:
    """One regular file, named canonically relative to its inventory root."""

    relative_path: str
    path: Path
    data: bytes | None = None

    @property
    def name(self) -> str:
        return self.relative_path.rsplit("/", 1)[-1]


def validate_relative_path(path: object) -> str:
    """Validate a printable-ASCII relative POSIX path without normalising it."""
    if not isinstance(path, str) or not path:
        raise InventoryError("artifact path must be a non-empty string")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in path):
        raise InventoryError(f"artifact path must be printable ASCII: {path!r}")
    if path.startswith("/"):
        raise InventoryError(f"artifact path must be relative: {path!r}")
    if "\\" in path:
        raise InventoryError(f"artifact path must use POSIX separators: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise InventoryError(
            f"artifact path must not contain empty, '.' or '..' components: {path!r}"
        )
    return path


def canonical_relative_paths(
    paths: Iterable[str], *, require_sorted: bool = False
) -> tuple[str, ...]:
    """Validate path spelling, ordering, collisions, and ancestor conflicts."""
    if isinstance(paths, (str, bytes)):
        raise InventoryError("artifact paths must be an iterable of strings")
    try:
        supplied = tuple(validate_relative_path(path) for path in paths)
    except TypeError as exc:
        raise InventoryError("artifact paths must be an iterable of strings") from exc

    ordered = tuple(sorted(supplied))
    if require_sorted and supplied != ordered:
        raise InventoryError("artifact paths must be sorted")

    seen_casefold: dict[str, str] = {}
    directory_prefixes: set[str] = set()
    complete_paths: set[str] = set()
    for path in ordered:
        parts = path.split("/")
        prefixes = tuple("/".join(parts[:index]) for index in range(1, len(parts) + 1))
        for prefix in prefixes:
            folded = prefix.casefold()
            previous = seen_casefold.get(folded)
            if previous is not None and previous != prefix:
                raise InventoryError(
                    f"case-folding artifact path collision: {previous!r} and {prefix!r}"
                )
            seen_casefold[folded] = prefix

        for directory in prefixes[:-1]:
            if directory in complete_paths:
                raise InventoryError(f"artifact path is both a file and a directory: {directory!r}")
            directory_prefixes.add(directory)
        if path in directory_prefixes:
            raise InventoryError(f"artifact path is both a file and a directory: {path!r}")
        if path in complete_paths:
            raise InventoryError(f"duplicate artifact path: {path!r}")
        complete_paths.add(path)
    return ordered


def list_regular_file_paths(
    root: str | os.PathLike[str],
    *,
    max_files: int = MAX_SCENE_FILES,
    max_file_bytes: int = MAX_SCENE_FILE_BYTES,
    max_total_bytes: int = MAX_SCENE_TOTAL_BYTES,
    max_depth: int = MAX_SCENE_DEPTH,
) -> tuple[str, ...]:
    """List regular-file paths recursively without opening any regular file.

    This is the deliberately weaker view used by filename-only benchmark controls.  It may
    open directories and inspect entry metadata, but it never opens or reads a regular file;
    using :func:`inventory_regular_files` here would quietly give a listing adversary a more
    privileged observation than its name promises.
    """
    for label, value in (
        ("max_files", max_files),
        ("max_file_bytes", max_file_bytes),
        ("max_total_bytes", max_total_bytes),
        ("max_depth", max_depth),
    ):
        if type(value) is not int or value < 1:
            raise InventoryError(f"{label} must be a positive integer")
    try:
        root_path = Path(root)
    except TypeError as exc:
        raise InventoryError("artifact root must be a filesystem path") from exc
    try:
        root_state = root_path.lstat()
    except OSError as exc:
        raise InventoryError(f"cannot inspect artifact root {root_path}: {exc}") from exc
    if stat.S_ISLNK(root_state.st_mode):
        raise InventoryError(f"artifact root must not be a symlink: {root_path}")
    if not stat.S_ISDIR(root_state.st_mode):
        raise InventoryError(f"artifact root must be a directory: {root_path}")

    paths: list[str] = []
    total_bytes = 0
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")

    def same_state(first: os.stat_result, second: os.stat_result) -> bool:
        return all(getattr(first, field) == getattr(second, field) for field in stable_fields)

    def open_directory(
        parent_fd: int, name: str, expected: os.stat_result, relative: str
    ) -> int:
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | cloexec | nofollow | directory_flag,
                dir_fd=parent_fd,
            )
            opened = os.fstat(descriptor)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not same_state(expected, opened)
                or not same_state(opened, after)
            ):
                raise InventoryError(
                    f"artifact directory changed while listing: {relative!r}"
                )
            return descriptor
        except InventoryError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except (NotImplementedError, OSError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise InventoryError(
                f"cannot safely open artifact directory {relative!r}: {exc}"
            ) from exc

    def visit(directory_fd: int, relative_parts: tuple[str, ...]) -> int:
        nonlocal total_bytes
        before_directory = os.fstat(directory_fd)
        try:
            with os.scandir(directory_fd) as scan:
                children = sorted(scan, key=lambda child: child.name)
        except OSError as exc:
            shown = "/".join(relative_parts) or "."
            raise InventoryError(f"cannot list artifact directory {shown!r}: {exc}") from exc

        files_below = 0
        for child in children:
            parts = (*relative_parts, child.name)
            relative = validate_relative_path("/".join(parts))
            if len(parts) > max_depth:
                raise InventoryError(
                    f"artifact path exceeds the {max_depth}-component depth limit: {relative!r}"
                )
            try:
                child_state = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise InventoryError(f"cannot inspect artifact path {relative!r}: {exc}") from exc
            if stat.S_ISLNK(child_state.st_mode):
                raise InventoryError(f"artifact tree contains a symlink: {relative!r}")
            if stat.S_ISDIR(child_state.st_mode):
                child_fd = open_directory(directory_fd, child.name, child_state, relative)
                try:
                    nested = visit(child_fd, parts)
                    after_directory = os.fstat(child_fd)
                    after_path = os.stat(
                        child.name, dir_fd=directory_fd, follow_symlinks=False
                    )
                except OSError as exc:
                    raise InventoryError(
                        f"cannot recheck artifact directory {relative!r}: {exc}"
                    ) from exc
                finally:
                    os.close(child_fd)
                if (
                    not same_state(child_state, after_directory)
                    or not same_state(after_directory, after_path)
                ):
                    raise InventoryError(
                        f"artifact directory changed while listing: {relative!r}"
                    )
                if nested == 0:
                    raise InventoryError(
                        f"artifact tree contains an unbound empty directory: {relative!r}"
                    )
                files_below += nested
                continue
            if not stat.S_ISREG(child_state.st_mode):
                raise InventoryError(f"artifact tree contains a special file: {relative!r}")
            if child_state.st_size > max_file_bytes:
                raise InventoryError(
                    f"artifact file exceeds the {max_file_bytes}-byte limit: {relative!r}"
                )
            if len(paths) + 1 > max_files:
                raise InventoryError(f"artifact tree exceeds the {max_files}-file limit")
            if total_bytes + child_state.st_size > max_total_bytes:
                raise InventoryError(
                    f"artifact tree exceeds the {max_total_bytes}-byte total limit"
                )
            try:
                after_path = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise InventoryError(f"cannot recheck artifact path {relative!r}: {exc}") from exc
            if not stat.S_ISREG(after_path.st_mode) or not same_state(child_state, after_path):
                raise InventoryError(f"artifact file changed while listing: {relative!r}")
            paths.append(relative)
            total_bytes += child_state.st_size
            files_below += 1

        try:
            after_directory = os.fstat(directory_fd)
            final_names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            shown = "/".join(relative_parts) or "."
            raise InventoryError(f"cannot recheck artifact directory {shown!r}: {exc}") from exc
        if [child.name for child in children] != final_names or not same_state(
            before_directory, after_directory
        ):
            shown = "/".join(relative_parts) or "."
            raise InventoryError(f"artifact directory changed while listing: {shown!r}")
        return files_below

    root_fd = -1
    try:
        root_fd = os.open(
            root_path,
            os.O_RDONLY | cloexec | nofollow | directory_flag,
        )
        opened_root = os.fstat(root_fd)
        if not stat.S_ISDIR(opened_root.st_mode) or not same_state(root_state, opened_root):
            raise InventoryError(f"artifact root changed while listing: {root_path}")
        visit(root_fd, ())
        after_root = os.fstat(root_fd)
        after_path = root_path.lstat()
        if not same_state(opened_root, after_root) or not same_state(after_root, after_path):
            raise InventoryError(f"artifact root changed while listing: {root_path}")
    except InventoryError:
        raise
    except OSError as exc:
        raise InventoryError(f"cannot safely list artifact root {root_path}: {exc}") from exc
    finally:
        if root_fd >= 0:
            os.close(root_fd)

    return canonical_relative_paths(paths)


def inventory_regular_files(
    root: str | os.PathLike[str],
    *,
    capture_bytes: bool = False,
    pinned_root_fd: int | None = None,
    max_files: int = MAX_SCENE_FILES,
    max_file_bytes: int = MAX_SCENE_FILE_BYTES,
    max_total_bytes: int = MAX_SCENE_TOTAL_BYTES,
    max_depth: int = MAX_SCENE_DEPTH,
) -> tuple[InventoryFile, ...]:
    """Inventory regular files without links, optionally capturing stable bytes.

    ``pinned_root_fd`` is reserved for callers that already hold the exact directory being
    certified. In that mode traversal starts from a duplicate of the descriptor and ``root``
    is only the display/pathname associated with returned records; no security decision is
    made through that pathname.
    """
    for label, value in (
        ("max_files", max_files),
        ("max_file_bytes", max_file_bytes),
        ("max_total_bytes", max_total_bytes),
        ("max_depth", max_depth),
    ):
        if type(value) is not int or value < 1:
            raise InventoryError(f"{label} must be a positive integer")
    try:
        root_path = Path(root)
    except TypeError as exc:
        raise InventoryError("artifact root must be a filesystem path") from exc
    if pinned_root_fd is None:
        try:
            root_state = root_path.lstat()
        except OSError as exc:
            raise InventoryError(f"cannot inspect artifact root {root_path}: {exc}") from exc
        if stat.S_ISLNK(root_state.st_mode):
            raise InventoryError(f"artifact root must not be a symlink: {root_path}")
        if not stat.S_ISDIR(root_state.st_mode):
            raise InventoryError(f"artifact root must be a directory: {root_path}")
    else:
        if type(pinned_root_fd) is not int or pinned_root_fd < 0:
            raise InventoryError("pinned_root_fd must be an open directory descriptor")
        try:
            root_state = os.fstat(pinned_root_fd)
        except OSError as exc:
            raise InventoryError(f"cannot inspect pinned artifact root: {exc}") from exc
        if not stat.S_ISDIR(root_state.st_mode):
            raise InventoryError("pinned artifact root must be a directory")

    files: list[InventoryFile] = []
    total_bytes = 0
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)

    def identity(value: os.stat_result) -> tuple[int, int]:
        return value.st_dev, value.st_ino

    def open_checked(
        parent_fd: int,
        name: str,
        expected: os.stat_result,
        relative: str,
        *,
        directory: bool,
    ) -> int:
        flags = os.O_RDONLY | cloexec | nofollow
        if directory:
            flags |= directory_flag
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            opened = os.fstat(descriptor)
            expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if not expected_kind(opened.st_mode) or any(
                getattr(expected, field) != getattr(opened, field) for field in stable_fields
            ):
                raise InventoryError(f"artifact path changed while inventorying: {relative!r}")
            if not nofollow:
                after_open = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not expected_kind(after_open.st_mode) or any(
                    getattr(opened, field) != getattr(after_open, field) for field in stable_fields
                ):
                    raise InventoryError(f"artifact path changed while inventorying: {relative!r}")
            return descriptor
        except InventoryError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except (NotImplementedError, OSError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise InventoryError(f"cannot safely open artifact path {relative!r}: {exc}") from exc

    def visit(directory_fd: int, relative_parts: tuple[str, ...]) -> int:
        nonlocal total_bytes
        before_directory = os.fstat(directory_fd)
        try:
            with os.scandir(directory_fd) as scan:
                children = sorted(scan, key=lambda child: child.name)
        except OSError as exc:
            shown = "/".join(relative_parts) or "."
            raise InventoryError(f"cannot list artifact directory {shown!r}: {exc}") from exc

        files_below = 0
        for child in children:
            parts = (*relative_parts, child.name)
            relative = validate_relative_path("/".join(parts))
            if len(parts) > max_depth:
                raise InventoryError(
                    f"artifact path exceeds the {max_depth}-component depth limit: {relative!r}"
                )
            try:
                child_state = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise InventoryError(f"cannot inspect artifact path {relative!r}: {exc}") from exc
            if stat.S_ISLNK(child_state.st_mode):
                raise InventoryError(f"artifact tree contains a symlink: {relative!r}")
            if stat.S_ISDIR(child_state.st_mode):
                child_fd = open_checked(
                    directory_fd,
                    child.name,
                    child_state,
                    relative,
                    directory=True,
                )
                try:
                    nested = visit(child_fd, parts)
                    after = os.fstat(child_fd)
                    after_path = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    raise InventoryError(
                        f"cannot recheck artifact directory {relative!r}: {exc}"
                    ) from exc
                finally:
                    os.close(child_fd)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(
                    getattr(child_state, field) != getattr(after, field)
                    or getattr(after, field) != getattr(after_path, field)
                    for field in stable_fields
                ):
                    raise InventoryError(
                        f"artifact directory changed while inventorying: {relative!r}"
                    )
                if nested == 0:
                    raise InventoryError(
                        f"artifact tree contains an unbound empty directory: {relative!r}"
                    )
                files_below += nested
                continue
            if not stat.S_ISREG(child_state.st_mode):
                raise InventoryError(f"artifact tree contains a special file: {relative!r}")

            file_fd = open_checked(
                directory_fd,
                child.name,
                child_state,
                relative,
                directory=False,
            )
            try:
                opened = os.fstat(file_fd)
                if opened.st_size > max_file_bytes:
                    raise InventoryError(
                        f"artifact file exceeds the {max_file_bytes}-byte limit: {relative!r}"
                    )
                if len(files) + 1 > max_files:
                    raise InventoryError(f"artifact tree exceeds the {max_files}-file limit")
                if total_bytes + opened.st_size > max_total_bytes:
                    raise InventoryError(
                        f"artifact tree exceeds the {max_total_bytes}-byte total limit"
                    )
                payload = None
                if capture_bytes:
                    chunks = []
                    while chunk := os.read(file_fd, 1024 * 1024):
                        chunks.append(chunk)
                    payload = b"".join(chunks)
                after_read = os.fstat(file_fd)
                after_path = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise InventoryError(f"cannot recheck artifact file {relative!r}: {exc}") from exc
            finally:
                os.close(file_fd)
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (
                any(getattr(opened, field) != getattr(after_read, field) for field in stable_fields)
                or any(
                    getattr(after_read, field) != getattr(after_path, field)
                    for field in stable_fields
                )
                or identity(child_state) != identity(opened)
            ):
                raise InventoryError(f"artifact file changed while inventorying: {relative!r}")
            if payload is not None and len(payload) != after_read.st_size:
                raise InventoryError(
                    f"artifact file length changed while inventorying: {relative!r}"
                )
            files.append(InventoryFile(relative, root_path.joinpath(*parts), payload))
            total_bytes += after_read.st_size
            files_below += 1
        try:
            after_directory = os.fstat(directory_fd)
            final_names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            shown = "/".join(relative_parts) or "."
            raise InventoryError(f"cannot recheck artifact directory {shown!r}: {exc}") from exc
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if [child.name for child in children] != final_names or any(
            getattr(before_directory, field) != getattr(after_directory, field)
            for field in stable_fields
        ):
            shown = "/".join(relative_parts) or "."
            raise InventoryError(f"artifact directory changed while inventorying: {shown!r}")
        return files_below

    flags = os.O_RDONLY | cloexec | nofollow | directory_flag
    root_fd = -1
    try:
        root_fd = (
            os.open(root_path, flags)
            if pinned_root_fd is None
            else os.dup(pinned_root_fd)
        )
        opened_root = os.fstat(root_fd)
        if not stat.S_ISDIR(opened_root.st_mode) or identity(root_state) != identity(opened_root):
            raise InventoryError(f"artifact root changed while inventorying: {root_path}")
        visit(root_fd, ())
        after_root = os.fstat(root_fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        changed = any(
            getattr(opened_root, field) != getattr(after_root, field) for field in stable_fields
        )
        if pinned_root_fd is None:
            after_binding = root_path.lstat()
        else:
            after_binding = os.fstat(pinned_root_fd)
        if changed or any(
            getattr(after_root, field) != getattr(after_binding, field)
            for field in stable_fields
        ):
            raise InventoryError(f"artifact root changed while inventorying: {root_path}")
    except InventoryError:
        raise
    except OSError as exc:
        raise InventoryError(f"cannot safely inventory artifact root {root_path}: {exc}") from exc
    finally:
        if root_fd >= 0:
            os.close(root_fd)

    ordered = canonical_relative_paths(file.relative_path for file in files)
    by_relative = {file.relative_path: file for file in files}
    return tuple(by_relative[relative] for relative in ordered)


def _open_child_directory(parent_fd: int, name: str, expected: os.stat_result) -> int:
    """Open one no-follow directory entry and bind it to the inspected inode."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
        expected.st_dev,
        expected.st_ino,
    ):
        os.close(descriptor)
        raise InventoryError(f"directory entry changed while opening: {name!r}")
    return descriptor


def freeze_directory_tree(
    directory_fd: int,
    *,
    file_mode: int = 0o400,
    directory_mode: int = 0o500,
) -> None:
    """Make a held tree read-only without following any replaceable entry."""
    if file_mode & 0o222 or directory_mode & 0o222:
        raise InventoryError("frozen tree modes must not grant write permission")
    try:
        names = sorted(os.listdir(directory_fd))
        for name in names:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child_fd = _open_child_directory(directory_fd, name, before)
                try:
                    freeze_directory_tree(
                        child_fd,
                        file_mode=file_mode,
                        directory_mode=directory_mode,
                    )
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    opened = os.fstat(child_fd)
                    if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
                        raise InventoryError(
                            f"snapshot directory changed while freezing: {name!r}"
                        )
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise InventoryError(f"snapshot contains a non-regular entry: {name!r}")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
                os, "O_NOFOLLOW", 0
            )
            file_fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                opened = os.fstat(file_fd)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                    before.st_dev,
                    before.st_ino,
                ):
                    raise InventoryError(f"snapshot file changed while freezing: {name!r}")
                os.fchmod(file_fd, file_mode)
            finally:
                os.close(file_fd)
        os.fchmod(directory_fd, directory_mode)
    except InventoryError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise InventoryError(f"cannot freeze private scene snapshot: {exc}") from exc


def _clear_pinned_directory(directory_fd: int) -> None:
    """Best-effort descriptor-bound cleanup that never chmods through a symlink."""
    try:
        os.fchmod(directory_fd, 0o700)
        names = sorted(os.listdir(directory_fd))
    except OSError:
        return
    for name in names:
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child_fd = _open_child_directory(directory_fd, name, before)
                try:
                    _clear_pinned_directory(child_fd)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    opened = os.fstat(child_fd)
                    if (after.st_dev, after.st_ino) == (opened.st_dev, opened.st_ino):
                        os.rmdir(name, dir_fd=directory_fd)
                finally:
                    os.close(child_fd)
            else:
                # unlink removes links themselves.  No pathname chmod is ever performed.
                os.unlink(name, dir_fd=directory_fd)
        except (InventoryError, NotImplementedError, OSError):
            # Cleanup must not mask the gate result. A raced entry is left in the private
            # system-temporary directory rather than risking mutation outside it.
            continue


def directory_entry_matches_descriptor(
    parent_fd: int, name: str, directory_fd: int
) -> bool:
    """Return whether a no-follow directory entry still names a held directory inode."""
    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(directory_fd)
    except (NotImplementedError, OSError):
        return False
    return (
        stat.S_ISDIR(entry.st_mode)
        and stat.S_ISDIR(opened.st_mode)
        and (entry.st_dev, entry.st_ino) == (opened.st_dev, opened.st_ino)
    )


def remove_pinned_directory_at(parent_fd: int, name: str, directory_fd: int) -> bool:
    """Remove only the held directory if the pinned parent still names that exact inode."""
    if not directory_entry_matches_descriptor(parent_fd, name, directory_fd):
        return False
    _clear_pinned_directory(directory_fd)
    if not directory_entry_matches_descriptor(parent_fd, name, directory_fd):
        return False
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except (NotImplementedError, OSError):
        return False
    return True


@contextmanager
def captured_regular_tree(
    root: str | os.PathLike[str],
) -> Iterable[tuple[InventoryFile, ...]]:
    """Yield a private, frozen pathname tree backed by one stable byte capture."""
    source = inventory_regular_files(root, capture_bytes=True)
    temporary = Path(tempfile.mkdtemp(prefix="artifactforge-scene-snapshot-"))
    root_fd = -1
    root_identity: tuple[int, int] | None = None
    try:
        root_fd = open_real_directory(temporary)
        root_state = os.fstat(root_fd)
        root_identity = root_state.st_dev, root_state.st_ino
        captured = []
        try:
            for file in source:
                if file.data is None:
                    raise AssertionError("captured inventory contains no bytes")
                write_regular_file_at(root_fd, file.relative_path, file.data)
                target = temporary.joinpath(*file.relative_path.split("/"))
                captured.append(InventoryFile(file.relative_path, target, file.data))
            freeze_directory_tree(root_fd)
        except (InventoryError, OSError) as exc:
            raise InventoryError(f"cannot materialize private scene snapshot: {exc}") from exc
        yield tuple(captured)
    finally:
        if root_fd >= 0:
            _clear_pinned_directory(root_fd)
            os.close(root_fd)
        if root_identity is not None:
            try:
                state = temporary.lstat()
                if stat.S_ISDIR(state.st_mode) and (state.st_dev, state.st_ino) == root_identity:
                    temporary.rmdir()
            except OSError:
                pass


def open_real_directory(path: str | os.PathLike[str], *, create: bool = False) -> int:
    """Open and pin a real directory, optionally creating its absent final component."""
    directory = Path(path)
    if not os.path.lexists(directory):
        if not create:
            raise InventoryError(f"artifact directory does not exist: {directory}")
        try:
            directory.mkdir(parents=True)
        except OSError as exc:
            raise InventoryError(f"cannot create artifact directory {directory}: {exc}") from exc
    try:
        before = directory.lstat()
    except OSError as exc:
        raise InventoryError(f"cannot inspect artifact directory {directory}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise InventoryError(f"artifact directory must be a real directory: {directory}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(directory, flags)
        opened = os.fstat(descriptor)
        after = directory.lstat()
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise InventoryError(f"cannot safely open artifact directory {directory}: {exc}") from exc
    expected = before.st_dev, before.st_ino
    if (
        not stat.S_ISDIR(opened.st_mode)
        or expected != (opened.st_dev, opened.st_ino)
        or expected != (after.st_dev, after.st_ino)
    ):
        os.close(descriptor)
        raise InventoryError(f"artifact directory changed while opening: {directory}")
    return descriptor


def open_real_directory_at(parent_fd: int, name: str) -> int:
    """Open and pin one real directory entry below an already pinned parent."""
    if not isinstance(name, str) or not name or name in {".", ".."}:
        raise InventoryError("directory entry name must be one non-empty component")
    if "/" in name or "\\" in name or "\x00" in name:
        raise InventoryError("directory entry name must not contain a separator or NUL")
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise InventoryError(f"artifact directory entry must be a real directory: {name!r}")
        descriptor = _open_child_directory(parent_fd, name, before)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except InventoryError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except (NotImplementedError, OSError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise InventoryError(f"cannot safely open artifact directory entry {name!r}: {exc}") from exc
    opened = os.fstat(descriptor)
    if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
        os.close(descriptor)
        raise InventoryError(f"artifact directory entry changed while opening: {name!r}")
    return descriptor


def write_regular_file_at(
    root_fd: int, relative: str, data: bytes, *, mode: int = 0o666
) -> None:
    """Exclusively create a file through descriptor-anchored, non-link parents."""
    relative = validate_relative_path(relative)
    if not isinstance(data, bytes):
        raise TypeError("artifact payload must be bytes")
    if not isinstance(mode, int) or mode < 0 or mode > 0o777:
        raise ValueError("artifact file mode must be a POSIX permission mask")
    components = relative.split("/")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors = [os.dup(root_fd)]
    relationships: list[tuple[int, str, int]] = []
    try:
        for component in components[:-1]:
            parent_fd = descriptors[-1]
            try:
                os.mkdir(component, dir_fd=parent_fd)
            except FileExistsError:
                pass
            before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise InventoryError(f"artifact parent is not a real directory: {relative!r}")
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode) or (before.st_dev, before.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                os.close(child_fd)
                raise InventoryError(f"artifact parent changed while writing: {relative!r}")
            descriptors.append(child_fd)
            relationships.append((parent_fd, component, child_fd))

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        file_fd = os.open(components[-1], flags, mode, dir_fd=descriptors[-1])
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise InventoryError(f"artifact target is not a regular file: {relative!r}")
            view = memoryview(data)
            while view:
                written = os.write(file_fd, view)
                if written <= 0:
                    raise OSError("short write while creating artifact")
                view = view[written:]
            after_write = os.fstat(file_fd)
            if after_write.st_size != len(data):
                raise InventoryError(f"artifact target has the wrong size: {relative!r}")
        finally:
            os.close(file_fd)

        for parent_fd, component, child_fd in reversed(relationships):
            path_state = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(path_state.st_mode) or (path_state.st_dev, path_state.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise InventoryError(f"artifact parent changed while writing: {relative!r}")
    except InventoryError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise InventoryError(f"cannot safely write artifact {relative!r}: {exc}") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def rename_directory_no_replace(
    source: Path,
    destination: Path,
    *,
    parent_fd: int | None = None,
    expected_source: tuple[int, int] | None = None,
) -> None:
    """Atomically publish a directory while refusing every existing destination.

    When ``parent_fd`` is supplied, both sibling names are resolved by the held directory
    descriptor rather than through a replaceable parent pathname. ``expected_source`` binds
    the operation to the directory inode that the caller verified.
    """
    if parent_fd is not None:
        if os.path.abspath(source.parent) != os.path.abspath(destination.parent):
            raise InventoryError("descriptor-bound publication requires sibling directories")
        try:
            before = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise InventoryError(f"cannot inspect publication source {source}: {exc}") from exc
        if not stat.S_ISDIR(before.st_mode):
            raise InventoryError(f"publication source is not a directory: {source}")
        if expected_source is not None and (before.st_dev, before.st_ino) != expected_source:
            raise InventoryError("publication source changed after verification")

    if os.name == "nt":
        os.rename(source, destination)
        return

    source_bytes = os.fsencode(source.name if parent_fd is not None else os.path.abspath(source))
    destination_bytes = os.fsencode(
        destination.name if parent_fd is not None else os.path.abspath(destination)
    )
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and parent_fd is not None and hasattr(libc, "renameatx_np"):
        rename = libc.renameatx_np
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        result = rename(
            parent_fd, source_bytes, parent_fd, destination_bytes, 0x00000004
        )  # RENAME_EXCL
    elif sys.platform == "darwin" and parent_fd is None and hasattr(libc, "renamex_np"):
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
        directory = parent_fd if parent_fd is not None else -100
        result = rename(directory, source_bytes, directory, destination_bytes, 0x00000001)
    else:
        raise InventoryError("platform has no atomic no-replace directory rename")
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(error, os.strerror(error), destination)
        raise InventoryError(
            f"cannot atomically publish artifact directory {destination}: {os.strerror(error)}"
        )
    if parent_fd is not None and expected_source is not None:
        try:
            published = os.stat(
                destination.name, dir_fd=parent_fd, follow_symlinks=False
            )
        except (NotImplementedError, OSError) as exc:
            raise InventoryError(
                f"cannot bind published artifact directory {destination}: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(published.st_mode)
            or (published.st_dev, published.st_ino) != expected_source
        ):
            raise InventoryError("published directory is not the verified source")
