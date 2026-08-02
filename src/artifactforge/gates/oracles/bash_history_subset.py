# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Independent bounded reader for ArtifactForge's inert extended-Bash-history subset.

The reader accepts only alternating ``#epoch`` and one-line command records.  Commands are
data: this module never invokes a shell.  Each command is either an exact caller-supplied
resident path or a tightly quoted ArtifactForge ``:`` no-op disclosure marker.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
import os
from pathlib import PurePosixPath
import re


class BashHistorySubsetError(ValueError):
    """Input is outside the strict, non-executing Bash-history subset."""


@dataclass(frozen=True)
class BashHistoryLimits:
    max_bytes: int = 1024 * 1024
    max_records: int = 1024
    max_line_bytes: int = 4096
    max_resident_paths: int = 128

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_records", "max_line_bytes", "max_resident_paths"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class BashHistoryEntry:
    epoch: int
    command: str


DEFAULT_BASH_HISTORY_LIMITS = BashHistoryLimits()
_EPOCH = re.compile(r"#([1-9][0-9]{0,18})")
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._+@-]+")
_NOOP_MARKER = re.compile(
    r": 'ARTIFACTFORGE-SYNTHETIC-[A-Z0-9][A-Z0-9._-]{0,63}'"
)
_DANGEROUS_BASENAMES = frozenset(
    {
        ".",
        "bash",
        "cfdisk",
        "curl",
        "dash",
        "dd",
        "doas",
        "eval",
        "exec",
        "fdisk",
        "fish",
        "ftp",
        "halt",
        "kill",
        "killall",
        "ksh",
        "mkfs",
        "nc",
        "ncat",
        "netcat",
        "parted",
        "perl",
        "pkill",
        "poweroff",
        "python",
        "python2",
        "python3",
        "reboot",
        "rm",
        "rmdir",
        "rsync",
        "ruby",
        "scp",
        "sfdisk",
        "sftp",
        "sh",
        "shutdown",
        "shred",
        "socat",
        "source",
        "ssh",
        "su",
        "sudo",
        "telnet",
        "unlink",
        "wget",
        "wipefs",
        "xargs",
        "zsh",
    }
)


def _error(condition: bool, message: str) -> None:
    if not condition:
        raise BashHistorySubsetError(message)


def _resident_path(value: object, *, where: str, max_bytes: int) -> str:
    _error(type(value) is str, f"{where} must be text")
    assert isinstance(value, str)
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise BashHistorySubsetError(f"{where} must be an ASCII path") from exc
    path = PurePosixPath(value)
    parts = value.split("/")[1:] if value.startswith("/") else ()
    _error(
        value.startswith("/")
        and value != "/"
        and not value.startswith("//")
        and not value.endswith("/")
        and "\\" not in value
        and path.as_posix() == value
        and bool(parts)
        and all(
            part not in {"", ".", ".."} and _PATH_COMPONENT.fullmatch(part) is not None
            for part in parts
        ),
        f"{where} must be one normalized absolute path without shell syntax",
    )
    _error(len(encoded) <= min(1024, max_bytes), f"{where} exceeds the path limit")
    basename = value.rsplit("/", 1)[-1].casefold()
    _error(
        basename not in _DANGEROUS_BASENAMES and not basename.startswith("mkfs."),
        f"{where} names a forbidden command verb: {basename!r}",
    )
    return value


def _allowlist(values, limits: BashHistoryLimits) -> frozenset[str]:
    _error(
        not isinstance(values, (str, bytes, bytearray, dict)),
        "resident_paths must be an iterable of absolute paths",
    )
    try:
        materialised = tuple(islice(iter(values), limits.max_resident_paths + 1))
    except TypeError as exc:
        raise BashHistorySubsetError("resident_paths must be iterable") from exc
    _error(
        1 <= len(materialised) <= limits.max_resident_paths,
        f"resident_paths requires 1..{limits.max_resident_paths} paths",
    )
    paths = tuple(
        _resident_path(value, where=f"resident_paths item {index}", max_bytes=limits.max_line_bytes)
        for index, value in enumerate(materialised)
    )
    _error(len(set(paths)) == len(paths), "resident_paths cannot contain duplicates")
    return frozenset(paths)


def _command(value: str, residents: frozenset[str], limits: BashHistoryLimits) -> str:
    _error(bool(value), "Bash history command cannot be empty")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise BashHistorySubsetError("Bash history command must be ASCII") from exc
    _error(len(encoded) <= limits.max_line_bytes, "Bash history command exceeds the line limit")
    if _NOOP_MARKER.fullmatch(value):
        return value
    path = _resident_path(value, where="Bash history command", max_bytes=limits.max_line_bytes)
    _error(path in residents, "Bash history command is not an exact resident path")
    return path


def loads_bash_history(
    data: bytes | bytearray | memoryview,
    *,
    resident_paths,
    limits: BashHistoryLimits = DEFAULT_BASH_HISTORY_LIMITS,
) -> tuple[BashHistoryEntry, ...]:
    """Decode extended Bash history without evaluating any command text."""
    if not isinstance(limits, BashHistoryLimits):
        raise TypeError("limits must be a BashHistoryLimits instance")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("Bash history input must be bytes-like")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    _error(size <= limits.max_bytes, f"Bash history exceeds the {limits.max_bytes}-byte limit")
    raw = bytes(data)
    _error(bool(raw), "Bash history is empty")
    _error(raw.endswith(b"\n"), "Bash history must end with LF")
    _error(b"\r" not in raw, "Bash history must use LF rather than CR or CRLF")
    _error(b"\x00" not in raw, "Bash history contains NUL")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise BashHistorySubsetError("Bash history must be ASCII (and therefore UTF-8)") from exc
    lines = text[:-1].split("\n")
    _error(all(lines), "Bash history cannot contain blank or multiline records")
    _error(len(lines) % 2 == 0, "Bash history contains an orphan timestamp or command")
    _error(
        1 <= len(lines) // 2 <= limits.max_records,
        f"Bash history requires 1..{limits.max_records} records",
    )
    _error(
        all(len(line.encode("ascii")) <= limits.max_line_bytes for line in lines),
        "Bash history line exceeds the line limit",
    )
    residents = _allowlist(resident_paths, limits)

    result: list[BashHistoryEntry] = []
    previous = 0
    for record_index in range(0, len(lines), 2):
        timestamp_line = lines[record_index]
        match = _EPOCH.fullmatch(timestamp_line)
        _error(match is not None, f"Bash history record {record_index // 2} has no valid #epoch")
        assert match is not None
        epoch = int(match.group(1))
        _error(epoch < 1 << 63, "Bash history epoch exceeds signed int64")
        _error(epoch > previous, "Bash history epochs must be strictly increasing")
        command = _command(lines[record_index + 1], residents, limits)
        result.append(BashHistoryEntry(epoch, command))
        previous = epoch
    return tuple(result)


def load_bash_history(
    path: str | os.PathLike[str],
    *,
    resident_paths,
    limits: BashHistoryLimits = DEFAULT_BASH_HISTORY_LIMITS,
) -> tuple[BashHistoryEntry, ...]:
    """Read and parse one bounded Bash-history file without sourcing it."""
    if not isinstance(limits, BashHistoryLimits):
        raise TypeError("limits must be a BashHistoryLimits instance")
    try:
        with open(path, "rb") as handle:
            data = handle.read(limits.max_bytes + 1)
    except (OSError, TypeError) as exc:
        raise BashHistorySubsetError(f"cannot read Bash history {path!r}: {exc}") from exc
    return loads_bash_history(data, resident_paths=resident_paths, limits=limits)


__all__ = [
    "BashHistoryEntry",
    "BashHistoryLimits",
    "BashHistorySubsetError",
    "DEFAULT_BASH_HISTORY_LIMITS",
    "load_bash_history",
    "loads_bash_history",
]
