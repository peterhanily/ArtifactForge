# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Independent, bounded reader for ArtifactForge's exact XDG desktop-entry subset.

This is intentionally not a general freedesktop configuration parser.  It recognizes one
``[Desktop Entry]`` group and the nine exact keys/types the Linux loose-artifact writer emits.
It does not import the writer and never executes the value of ``Exec``.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import PurePosixPath
import re
import unicodedata


class DesktopEntrySubsetError(ValueError):
    """Input is outside the strict, non-executing desktop-entry subset."""


@dataclass(frozen=True)
class DesktopEntryLimits:
    max_bytes: int = 64 * 1024
    max_lines: int = 32
    max_value_bytes: int = 4096

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_lines", "max_value_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class DesktopEntry:
    version: str
    entry_type: str
    name: str
    comment: str
    exec_path: str
    terminal: bool
    hidden: bool
    dbus_activatable: bool
    synthetic_marker: str


DEFAULT_DESKTOP_ENTRY_LIMITS = DesktopEntryLimits()
_EXPECTED_KEYS = frozenset(
    {
        "Version",
        "Type",
        "Name",
        "Comment",
        "Exec",
        "Terminal",
        "Hidden",
        "DBusActivatable",
        "X-ArtifactForge-Synthetic",
    }
)
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._+@-]+")
_MARKER = "ARTIFACTFORGE"


def _error(condition: bool, message: str) -> None:
    if not condition:
        raise DesktopEntrySubsetError(message)


def _plain_value(value: str, *, key: str, limits: DesktopEntryLimits) -> str:
    _error(bool(value), f"desktop entry {key} cannot be empty")
    _error(value == value.strip(), f"desktop entry {key} has surrounding whitespace")
    _error("\\" not in value, f"desktop entry {key} uses unsupported escape syntax")
    _error(
        not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value),
        f"desktop entry {key} contains a control character",
    )
    _error(
        unicodedata.normalize("NFC", value) == value,
        f"desktop entry {key} is not Unicode NFC",
    )
    _error(
        len(value.encode("utf-8")) <= limits.max_value_bytes,
        f"desktop entry {key} exceeds the value limit",
    )
    return value


def _exec_path(value: str, limits: DesktopEntryLimits) -> str:
    try:
        value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise DesktopEntrySubsetError("desktop entry Exec must be an ASCII path") from exc
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
        "desktop entry Exec must be one normalized absolute path without arguments, "
        "field codes, or shell syntax",
    )
    _error(
        len(value.encode("ascii")) <= min(1024, limits.max_value_bytes),
        "desktop entry Exec exceeds the path limit",
    )
    return value


def loads_desktop_entry(
    data: bytes | bytearray | memoryview,
    *,
    limits: DesktopEntryLimits = DEFAULT_DESKTOP_ENTRY_LIMITS,
) -> DesktopEntry:
    """Parse exact profile bytes without invoking, expanding, or resolving ``Exec``."""
    if not isinstance(limits, DesktopEntryLimits):
        raise TypeError("limits must be a DesktopEntryLimits instance")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("desktop entry input must be bytes-like")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    _error(size <= limits.max_bytes, f"desktop entry exceeds the {limits.max_bytes}-byte limit")
    raw = bytes(data)
    _error(bool(raw), "desktop entry is empty")
    _error(raw.endswith(b"\n"), "desktop entry must end with LF")
    _error(b"\r" not in raw, "desktop entry must use LF rather than CR or CRLF")
    _error(b"\x00" not in raw, "desktop entry contains NUL")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DesktopEntrySubsetError("desktop entry is not valid UTF-8") from exc
    _error(not text.startswith("\ufeff"), "desktop entry cannot carry a UTF-8 BOM")
    lines = text[:-1].split("\n")
    _error(len(lines) <= limits.max_lines, "desktop entry exceeds the line limit")
    _error(bool(lines) and lines[0] == "[Desktop Entry]", "desktop entry group is missing")
    _error(all(lines), "desktop entry cannot contain blank lines")

    values: dict[str, str] = {}
    for line_number, line in enumerate(lines[1:], start=2):
        _error(
            not line.startswith("["),
            f"desktop entry contains an additional group at line {line_number}",
        )
        _error("=" in line, f"desktop entry line {line_number} has no key separator")
        key, value = line.split("=", 1)
        _error(
            _KEY.fullmatch(key) is not None,
            f"desktop entry key {key!r} is invalid or localized",
        )
        _error(key not in values, f"desktop entry key {key!r} is duplicated")
        values[key] = value

    missing = sorted(_EXPECTED_KEYS - values.keys())
    extra = sorted(values.keys() - _EXPECTED_KEYS)
    _error(not missing, f"desktop entry is missing keys: {', '.join(missing)}")
    _error(not extra, f"desktop entry has unsupported keys: {', '.join(extra)}")
    _error(values["Version"] == "1.5", "desktop entry Version must be 1.5")
    _error(values["Type"] == "Application", "desktop entry Type must be Application")
    for key in ("Terminal", "Hidden", "DBusActivatable"):
        _error(values[key] == "false", f"desktop entry {key} must be lowercase false")
    _error(
        values["X-ArtifactForge-Synthetic"] == _MARKER,
        "desktop entry synthetic marker is missing or altered",
    )

    return DesktopEntry(
        version="1.5",
        entry_type="Application",
        name=_plain_value(values["Name"], key="Name", limits=limits),
        comment=_plain_value(values["Comment"], key="Comment", limits=limits),
        exec_path=_exec_path(values["Exec"], limits),
        terminal=False,
        hidden=False,
        dbus_activatable=False,
        synthetic_marker=_MARKER,
    )


def load_desktop_entry(
    path: str | os.PathLike[str],
    *,
    limits: DesktopEntryLimits = DEFAULT_DESKTOP_ENTRY_LIMITS,
) -> DesktopEntry:
    """Read one bounded desktop-entry file without following format-specific helpers."""
    if not isinstance(limits, DesktopEntryLimits):
        raise TypeError("limits must be a DesktopEntryLimits instance")
    try:
        with open(path, "rb") as handle:
            data = handle.read(limits.max_bytes + 1)
    except (OSError, TypeError) as exc:
        raise DesktopEntrySubsetError(f"cannot read desktop entry {path!r}: {exc}") from exc
    return loads_desktop_entry(data, limits=limits)


__all__ = [
    "DEFAULT_DESKTOP_ENTRY_LIMITS",
    "DesktopEntry",
    "DesktopEntryLimits",
    "DesktopEntrySubsetError",
    "load_desktop_entry",
    "loads_desktop_entry",
]
