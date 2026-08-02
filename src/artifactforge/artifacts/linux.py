# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic Linux loose-artifact writers for the bounded v1 profiles.

These writers emit data only.  They never install, execute, source, or apply the desktop
entry and shell-history artifacts they create.  The corresponding Gate 1 readers live in
``artifactforge.gates.oracles`` and intentionally do not import this module.
"""
from __future__ import annotations

from itertools import islice
from pathlib import PurePosixPath
import re
import unicodedata

from artifactforge.disclosure import MARKER


_MAX_DESKTOP_BYTES = 64 * 1024
_MAX_HISTORY_BYTES = 1024 * 1024
_MAX_HISTORY_RECORDS = 1024
_MAX_RESIDENT_PATHS = 128
_MAX_LINE_BYTES = 4096
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._+@-]+")
_NOOP_MARKER = re.compile(
    r": 'ARTIFACTFORGE-SYNTHETIC-[A-Z0-9][A-Z0-9._-]{0,63}'"
)
_DANGEROUS_BASENAMES = frozenset(
    {
        # Shells, interpreters, and command dispatchers.
        ".",
        "bash",
        "dash",
        "doas",
        "eval",
        "exec",
        "fish",
        "ksh",
        "perl",
        "python",
        "python2",
        "python3",
        "ruby",
        "sh",
        "source",
        "su",
        "sudo",
        "xargs",
        "zsh",
        # Network clients and relays.
        "curl",
        "ftp",
        "nc",
        "ncat",
        "netcat",
        "rsync",
        "scp",
        "sftp",
        "socat",
        "ssh",
        "telnet",
        "wget",
        # Destructive or host-state control programs.
        "cfdisk",
        "dd",
        "fdisk",
        "halt",
        "kill",
        "killall",
        "mkfs",
        "parted",
        "pkill",
        "poweroff",
        "reboot",
        "rm",
        "rmdir",
        "sfdisk",
        "shutdown",
        "shred",
        "unlink",
        "wipefs",
    }
)


def _plain_text(value: object, *, where: str, max_bytes: int) -> str:
    if type(value) is not str:
        raise ValueError(f"{where} must be text")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{where} must be Unicode NFC")
    if not value or value != value.strip():
        raise ValueError(f"{where} must be non-empty without surrounding whitespace")
    if "\\" in value:
        raise ValueError(f"{where} cannot contain desktop-entry escape syntax")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{where} cannot contain control characters")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must be valid UTF-8 text") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{where} exceeds the {max_bytes}-byte profile limit")
    return value


def _absolute_program_path(value: object, *, where: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{where} must be text")
    try:
        value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must be an ASCII path") from exc
    path = PurePosixPath(value)
    parts = value.split("/")[1:] if value.startswith("/") else ()
    if (
        not value.startswith("/")
        or value == "/"
        or value.startswith("//")
        or value.endswith("/")
        or "\\" in value
        or path.as_posix() != value
        or not parts
        or any(
            part in {"", ".", ".."} or _PATH_COMPONENT.fullmatch(part) is None
            for part in parts
        )
    ):
        raise ValueError(
            f"{where} must be one normalized absolute ASCII path with no arguments"
        )
    if len(value.encode("ascii")) > 1024:
        raise ValueError(f"{where} exceeds the 1024-byte profile limit")
    return value


def _safe_resident_path(value: object, *, where: str) -> str:
    path = _absolute_program_path(value, where=where)
    basename = path.rsplit("/", 1)[-1].casefold()
    if basename in _DANGEROUS_BASENAMES or basename.startswith("mkfs."):
        raise ValueError(f"{where} names a forbidden command verb: {basename!r}")
    return path


def _resident_allowlist(values) -> frozenset[str]:
    if isinstance(values, (str, bytes, bytearray, dict)):
        raise ValueError("resident_paths must be an iterable of absolute paths")
    try:
        materialised = tuple(islice(iter(values), _MAX_RESIDENT_PATHS + 1))
    except TypeError as exc:
        raise ValueError("resident_paths must be iterable") from exc
    if not 1 <= len(materialised) <= _MAX_RESIDENT_PATHS:
        raise ValueError(f"resident_paths requires 1..{_MAX_RESIDENT_PATHS} paths")
    paths = tuple(
        _safe_resident_path(value, where=f"resident_paths item {index}")
        for index, value in enumerate(materialised)
    )
    if len(set(paths)) != len(paths):
        raise ValueError("resident_paths cannot contain duplicates")
    return frozenset(paths)


def _safe_history_command(command: object, residents: frozenset[str], *, where: str) -> str:
    if type(command) is not str:
        raise ValueError(f"{where} must be text")
    try:
        command.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must be ASCII") from exc
    if _NOOP_MARKER.fullmatch(command):
        return command
    path = _safe_resident_path(command, where=where)
    if path not in residents:
        raise ValueError(f"{where} is not an exact resident path")
    return path


def build_desktop_entry(name: str, comment: str, exec_path: str) -> bytes:
    """Emit one canonical XDG autostart ``Desktop Entry`` as inert loose bytes.

    ``Exec`` is exactly one normalized absolute ASCII path.  Arguments, field codes,
    quoting, shell metacharacters, actions, localized keys, and additional groups are outside
    this deliberately small profile.
    """
    name = _plain_text(name, where="desktop entry Name", max_bytes=256)
    comment = _plain_text(comment, where="desktop entry Comment", max_bytes=1024)
    exec_path = _absolute_program_path(exec_path, where="desktop entry Exec")
    text = "\n".join(
        (
            "[Desktop Entry]",
            "Version=1.5",
            "Type=Application",
            f"Name={name}",
            f"Comment={comment}",
            f"Exec={exec_path}",
            "Terminal=false",
            "Hidden=false",
            "DBusActivatable=false",
            f"X-ArtifactForge-Synthetic={MARKER}",
            "",
        )
    )
    data = text.encode("utf-8", errors="strict")
    if len(data) > _MAX_DESKTOP_BYTES:
        raise ValueError("desktop entry exceeds the bounded writer profile")
    return data


def build_bash_history(entries, *, resident_paths) -> bytes:
    """Emit bounded extended Bash history without executing or sourcing any command.

    Each input row is ``(positive_epoch, command)``.  A command must be either the exact
    absolute path of an inert resident supplied in ``resident_paths`` or the quoted ``:``
    no-op disclosure form ``: 'ARTIFACTFORGE-SYNTHETIC-<TOKEN>'``.
    """
    residents = _resident_allowlist(resident_paths)
    if isinstance(entries, (str, bytes, bytearray, dict)):
        raise ValueError("Bash history entries must be an iterable of two-item rows")
    try:
        materialised = tuple(islice(iter(entries), _MAX_HISTORY_RECORDS + 1))
    except TypeError as exc:
        raise ValueError("Bash history entries must be iterable") from exc
    if not 1 <= len(materialised) <= _MAX_HISTORY_RECORDS:
        raise ValueError(f"Bash history requires 1..{_MAX_HISTORY_RECORDS} records")

    lines: list[str] = []
    previous = 0
    for index, row in enumerate(materialised):
        if not isinstance(row, (tuple, list)) or len(row) != 2:
            raise ValueError(f"Bash history row {index} must contain exactly two values")
        epoch, command = row
        if type(epoch) is not int or not 0 < epoch < 1 << 63:
            raise ValueError(f"Bash history row {index} epoch must be a positive int64")
        if epoch <= previous:
            raise ValueError("Bash history epochs must be strictly increasing")
        command = _safe_history_command(
            command, residents, where=f"Bash history row {index} command"
        )
        if len(command.encode("ascii")) > _MAX_LINE_BYTES:
            raise ValueError(f"Bash history row {index} command is too long")
        lines.extend((f"#{epoch}", command))
        previous = epoch

    data = ("\n".join(lines) + "\n").encode("ascii")
    if len(data) > _MAX_HISTORY_BYTES:
        raise ValueError("Bash history exceeds the bounded writer profile")
    return data


__all__ = ["build_bash_history", "build_desktop_entry"]
