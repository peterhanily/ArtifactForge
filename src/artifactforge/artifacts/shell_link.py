# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic bounded Windows Shell Link writer and byte-level profile reader.

This module emits one deliberately small local-file profile from Microsoft's ``MS-SHLLINK``
format: a 76-byte ``ShellLinkHeader``, a ``LinkInfo`` with a 0x24-byte header and fixed-drive
``VolumeID``, one Unicode ``NAME_STRING``, and the four-byte terminal block.  The target path
is present in both the ANSI and UTF-16 LinkInfo fields and the reader requires those copies to
agree.  No target ID list, network target, arguments, working directory, icon, environment,
Darwin, shim, tracker, property-store, or other ExtraData block is emitted.

The layout follows the current Microsoft Open Specification rather than reverse-engineered
examples:

* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15
* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/6813269d-0cc8-4be2-933f-e96e8e3412dc
* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b7b3eea7-dbff-4275-bd58-83ba3f12d87a
* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/17b69472-0f34-4bcf-b290-eccdb8de224b

Generation has no host dependency and cannot resolve or inspect the target path.  The in-band
synthetic marker lives in the Unicode display name so it survives separation from its fixture.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct
import unicodedata

from artifactforge.disclosure import MARKER


SHELL_LINK_HEADER_SIZE = 0x4C
LINK_INFO_HEADER_SIZE = 0x24
MAX_SHELL_LINK_BYTES = 4096
MAX_WINDOWS_PATH_CHARACTERS = 259
MAX_STRING_DATA_CHARACTERS = 260

HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
IS_UNICODE = 0x00000080
SHELL_LINK_FLAGS = HAS_LINK_INFO | HAS_NAME | IS_UNICODE

FILE_ATTRIBUTE_ARCHIVE = 0x00000020
VOLUME_ID_AND_LOCAL_BASE_PATH = 0x00000001
DRIVE_FIXED = 0x00000003
SW_SHOWNORMAL = 0x00000001

# GUID 00021401-0000-0000-C000-000000000046 in Windows' mixed-endian GUID encoding.
SHELL_LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
DEFAULT_VOLUME_SERIAL = 0xA17F0A6E
DEFAULT_VOLUME_LABEL = "ARTIFACT"
DEFAULT_FILETIME = 133497684000000000  # 2024-01-15T05:00:00Z, pinned
# LnkParse3 1.6.0 converts a signed FILETIME through a binary64 Unix timestamp and
# ``datetime.fromtimestamp``. Zero is its explicit unset sentinel. Otherwise, 1970 through
# Unix + 2**33 seconds is the largest simple cross-platform interval in which every whole
# microsecond remains exact for that mandatory oracle. At MAX + 10 it collapses adjacent
# microseconds; pre-1970 conversion is outside the portable Windows CRT range.
MIN_PORTABLE_FILETIME = 116_444_736_000_000_000
MAX_PORTABLE_FILETIME = 202_344_081_920_000_000

_MARKED_NAME_SUFFIX = f" [{MARKER} SYNTHETIC]"
_INVALID_PATH_CHARACTERS = frozenset('<>:"/|?*')
_INVALID_LABEL_CHARACTERS = frozenset('\\/:*?"<>|')
_RESERVED_COMPONENT = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", re.I)


def _uint(value: object, bits: int, *, where: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{where} must be an unsigned {bits}-bit integer (not bool)")
    return value


def _filetime(value: object, *, where: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"{where} must be an unsigned 64-bit FILETIME integer (not bool)")
    # Both mandatory external oracles must be able to preserve the emitted value. liblnk
    # exposes all 100-nanosecond ticks, while LnkParse3 exposes Python datetimes and therefore
    # has microsecond precision. Refuse a value that generation could not pass back through
    # the declared parser-consensus gate exactly.
    if value % 10:
        raise ValueError(f"{where} must be an exact whole-microsecond FILETIME")
    if value != 0 and not MIN_PORTABLE_FILETIME <= value <= MAX_PORTABLE_FILETIME:
        raise ValueError(
            f"{where} must be zero/unset or inside the portable 1970..2242 "
            "LnkParse3 FILETIME interval"
        )
    return value


def _writer_ascii(value: object, *, where: str, minimum: int, maximum: int) -> str:
    if type(value) is not str:
        raise ValueError(f"{where} must be text")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{where} must be Unicode NFC")
    if not minimum <= len(value) <= maximum:
        raise ValueError(f"{where} must contain {minimum}..{maximum} characters")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must use the portable ASCII subset") from exc
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError(f"{where} contains a control character")
    return value


def _writer_target_path(value: object) -> str:
    path = _writer_ascii(
        value,
        where="Shell Link target path",
        minimum=4,
        maximum=MAX_WINDOWS_PATH_CHARACTERS,
    )
    if not ("A" <= path[0] <= "Z" and path[1:3] == ":\\"):
        raise ValueError("Shell Link target path must be a canonical uppercase-drive local path")
    if "\\\\" in path or path.endswith("\\"):
        raise ValueError("Shell Link target path must contain non-empty components and name a file")
    for component in path[3:].split("\\"):
        if (
            not component
            or component in {".", ".."}
            or len(component) > 255
            or component[-1] in {" ", "."}
            or any(character in _INVALID_PATH_CHARACTERS for character in component)
            or _RESERVED_COMPONENT.fullmatch(component)
        ):
            raise ValueError("Shell Link target path contains a non-canonical Windows component")
    return path


def _writer_display_name(value: object) -> str:
    maximum = MAX_STRING_DATA_CHARACTERS - len(_MARKED_NAME_SUFFIX)
    name = _writer_ascii(
        value,
        where="Shell Link display name",
        minimum=1,
        maximum=maximum,
    )
    if name != name.strip() or MARKER in name or "\\" in name:
        raise ValueError(
            "Shell Link display name must be trimmed, unmarked text without a path separator"
        )
    return name


def _writer_volume_label(value: object) -> str:
    label = _writer_ascii(
        value,
        where="Shell Link volume label",
        minimum=1,
        maximum=32,
    )
    if (
        label != label.strip()
        or label[-1] == "."
        or any(character in _INVALID_LABEL_CHARACTERS for character in label)
    ):
        raise ValueError("Shell Link volume label is not a canonical fixed-volume label")
    return label


@dataclass(frozen=True)
class ShellLinkTimestamps:
    """The target FILETIMEs represented by the bounded Shell Link profile."""

    creation_filetime: int = DEFAULT_FILETIME
    access_filetime: int = DEFAULT_FILETIME
    write_filetime: int = DEFAULT_FILETIME

    def __post_init__(self) -> None:
        _filetime(self.creation_filetime, where="Shell Link target creation timestamp")
        _filetime(self.access_filetime, where="Shell Link target access timestamp")
        _filetime(self.write_filetime, where="Shell Link target write timestamp")


@dataclass(frozen=True)
class ShellLinkValue:
    """One typed observation returned by :func:`parse_shell_link`."""

    target_path: str
    display_name: str
    name_string: str
    target_size: int
    creation_filetime: int
    access_filetime: int
    write_filetime: int
    volume_serial: int
    volume_label: str


def _ansi_z(value: str) -> bytes:
    return value.encode("ascii") + b"\x00"


def _utf16_z(value: str) -> bytes:
    return value.encode("utf-16-le") + b"\x00\x00"


def build_shell_link(
    target_path: str,
    display_name: str,
    target_size: int,
    *,
    timestamps: ShellLinkTimestamps | None = None,
    volume_serial: int = DEFAULT_VOLUME_SERIAL,
    volume_label: str = DEFAULT_VOLUME_LABEL,
) -> bytes:
    """Build the closed, local-file Shell Link profile.

    ``display_name`` is the human-facing portion only.  The writer appends an in-band
    ``ARTIFACTFORGE`` disclosure before encoding the complete ``NAME_STRING`` as UTF-16LE.
    """
    target_path = _writer_target_path(target_path)
    display_name = _writer_display_name(display_name)
    target_size = _uint(target_size, 32, where="Shell Link target size")
    volume_serial = _uint(volume_serial, 32, where="Shell Link volume serial")
    volume_label = _writer_volume_label(volume_label)
    if timestamps is None:
        timestamps = ShellLinkTimestamps()
    elif type(timestamps) is not ShellLinkTimestamps:
        raise ValueError("Shell Link timestamps must be a ShellLinkTimestamps or None")

    volume_label_bytes = _ansi_z(volume_label)
    volume = struct.pack(
        "<4I",
        16 + len(volume_label_bytes),
        DRIVE_FIXED,
        volume_serial,
        16,  # ANSI label offset; the mutually exclusive Unicode-label field is absent.
    ) + volume_label_bytes

    local_path_ansi = _ansi_z(target_path)
    common_suffix_ansi = b"\x00"
    local_path_unicode = _utf16_z(target_path)
    common_suffix_unicode = b"\x00\x00"

    volume_offset = LINK_INFO_HEADER_SIZE
    local_path_offset = volume_offset + len(volume)
    common_suffix_offset = local_path_offset + len(local_path_ansi)
    local_path_unicode_offset = common_suffix_offset + len(common_suffix_ansi)
    common_suffix_unicode_offset = local_path_unicode_offset + len(local_path_unicode)
    link_info_size = common_suffix_unicode_offset + len(common_suffix_unicode)
    link_info = struct.pack(
        "<9I",
        link_info_size,
        LINK_INFO_HEADER_SIZE,
        VOLUME_ID_AND_LOCAL_BASE_PATH,
        volume_offset,
        local_path_offset,
        0,  # no CommonNetworkRelativeLink
        common_suffix_offset,
        local_path_unicode_offset,
        common_suffix_unicode_offset,
    )
    link_info += (
        volume
        + local_path_ansi
        + common_suffix_ansi
        + local_path_unicode
        + common_suffix_unicode
    )

    header = struct.pack(
        "<I16sIIQQQIiIHHII",
        SHELL_LINK_HEADER_SIZE,
        SHELL_LINK_CLSID,
        SHELL_LINK_FLAGS,
        FILE_ATTRIBUTE_ARCHIVE,
        timestamps.creation_filetime,
        timestamps.access_filetime,
        timestamps.write_filetime,
        target_size,
        0,  # IconIndex
        SW_SHOWNORMAL,
        0,  # HotKey
        0,  # Reserved1
        0,  # Reserved2
        0,  # Reserved3
    )

    name_string = display_name + _MARKED_NAME_SUFFIX
    string_data = struct.pack("<H", len(name_string)) + name_string.encode("utf-16-le")
    data = header + link_info + string_data + b"\x00\x00\x00\x00"
    if len(data) > MAX_SHELL_LINK_BYTES:  # Defensive proof against contract drift.
        raise ValueError(f"Shell Link exceeds the {MAX_SHELL_LINK_BYTES}-byte profile limit")
    return data


class _Reader:
    """Bounds-checking byte reader used only by the independently stated read-back profile."""

    def __init__(self, data: bytes):
        self.data = data

    def unpack(self, fmt: str, offset: int, *, where: str) -> tuple[object, ...]:
        size = struct.calcsize(fmt)
        if not 0 <= offset <= len(self.data) - size:
            raise ValueError(f"Shell Link is truncated at {where}")
        return struct.unpack_from(fmt, self.data, offset)

    def span(self, start: int, end: int, *, where: str) -> bytes:
        if not 0 <= start <= end <= len(self.data):
            raise ValueError(f"Shell Link {where} extent is out of bounds")
        return self.data[start:end]


def _reader_ascii_z(data: bytes, *, where: str) -> str:
    if len(data) < 1 or data[-1:] != b"\x00" or b"\x00" in data[:-1]:
        raise ValueError(f"Shell Link {where} is not one exact ANSI NUL-terminated string")
    try:
        value = data[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Shell Link {where} is outside the portable ANSI subset") from exc
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"Shell Link {where} contains a control character")
    return value


def _reader_utf16_z(data: bytes, *, where: str) -> str:
    if len(data) < 2 or len(data) % 2 or data[-2:] != b"\x00\x00":
        raise ValueError(f"Shell Link {where} is not one exact UTF-16LE NUL-terminated string")
    try:
        value = data[:-2].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Shell Link {where} is not strict UTF-16LE") from exc
    if "\x00" in value:
        raise ValueError(f"Shell Link {where} contains an embedded NUL character")
    return value


def _reader_target_path(path: str) -> None:
    # Repeated independently from the writer so relaxing generation does not relax read-back.
    if (
        not 4 <= len(path) <= 259
        or unicodedata.normalize("NFC", path) != path
        or not ("A" <= path[0] <= "Z" and path[1:3] == ":\\")
        or "\\\\" in path
        or path.endswith("\\")
    ):
        raise ValueError("Shell Link observed target path is outside the closed local-path profile")
    for component in path[3:].split("\\"):
        if (
            not component
            or component in {".", ".."}
            or len(component) > 255
            or component[-1] in {" ", "."}
            or any(character in frozenset('<>:"/|?*') for character in component)
            or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", component, re.I)
        ):
            raise ValueError(
                "Shell Link observed target path contains a non-canonical Windows component"
            )


def _reader_volume_label(label: str) -> None:
    if (
        not 1 <= len(label) <= 32
        or unicodedata.normalize("NFC", label) != label
        or label != label.strip()
        or label[-1] == "."
        or any(character in frozenset('\\/:*?"<>|') for character in label)
    ):
        raise ValueError("Shell Link observed volume label is outside the closed profile")


def _reader_display_name(name: str) -> None:
    if (
        not 1 <= len(name) <= 260 - len(_MARKED_NAME_SUFFIX)
        or unicodedata.normalize("NFC", name) != name
        or name != name.strip()
        or MARKER in name
        or "\\" in name
    ):
        raise ValueError("Shell Link observed display name is outside the closed profile")
    try:
        encoded = name.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("Shell Link observed display name is outside portable ASCII") from exc
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError("Shell Link observed display name contains a control character")


def parse_shell_link(data: bytes) -> ShellLinkValue:
    """Read and enforce the exact bounded local-file Shell Link profile.

    Offsets and extents are read from the bytes and checked before use.  The reader rejects
    merely parseable variants: every omitted optional structure, reserved value, duplicate
    path, terminal position, and in-band marker is part of this closed profile.
    """
    if type(data) is not bytes:
        raise ValueError("Shell Link input must be immutable bytes")
    if not SHELL_LINK_HEADER_SIZE < len(data) <= MAX_SHELL_LINK_BYTES:
        raise ValueError(
            f"Shell Link input must contain {SHELL_LINK_HEADER_SIZE + 1}.."
            f"{MAX_SHELL_LINK_BYTES} bytes"
        )
    reader = _Reader(data)
    header = reader.unpack("<I16sIIQQQIiIHHII", 0, where="ShellLinkHeader")
    (
        header_size,
        clsid,
        link_flags,
        file_attributes,
        creation_filetime,
        access_filetime,
        write_filetime,
        target_size,
        icon_index,
        show_command,
        hotkey,
        reserved1,
        reserved2,
        reserved3,
    ) = header
    if header_size != 0x4C or clsid != bytes.fromhex("0114020000000000c000000000000046"):
        raise ValueError("Shell Link header size or CLSID is not canonical")
    if link_flags != 0x86:
        raise ValueError("Shell Link flags do not select exactly LinkInfo, Name, and Unicode")
    if file_attributes != 0x20:
        raise ValueError("Shell Link target attributes are not exact archive-file attributes")
    if (
        icon_index != 0
        or show_command != 1
        or hotkey != 0
        or reserved1 != 0
        or reserved2 != 0
        or reserved3 != 0
    ):
        raise ValueError("Shell Link header control and reserved fields are outside the profile")

    link_start = 0x4C
    link_header = reader.unpack("<9I", link_start, where="LinkInfo header")
    (
        link_size,
        link_header_size,
        link_info_flags,
        volume_offset,
        local_path_offset,
        network_offset,
        suffix_offset,
        local_unicode_offset,
        suffix_unicode_offset,
    ) = link_header
    link_end = link_start + link_size
    if not 0x24 < link_size or link_end > len(data):
        raise ValueError("Shell Link LinkInfo size is out of bounds")
    if link_header_size != 0x24 or link_info_flags != 1 or network_offset != 0:
        raise ValueError("Shell Link LinkInfo header is outside the local-volume profile")
    if volume_offset != 0x24:
        raise ValueError("Shell Link VolumeID is not canonical and contiguous")
    offsets = (
        volume_offset,
        local_path_offset,
        suffix_offset,
        local_unicode_offset,
        suffix_unicode_offset,
        link_size,
    )
    if any(left >= right for left, right in zip(offsets, offsets[1:])):
        raise ValueError("Shell Link LinkInfo fields are not strictly ordered and non-overlapping")

    volume_start = link_start + volume_offset
    volume_size, drive_type, volume_serial, label_offset = reader.unpack(
        "<4I", volume_start, where="VolumeID header"
    )
    if volume_size <= 16 or volume_offset + volume_size != local_path_offset:
        raise ValueError("Shell Link VolumeID extent is not canonical and contiguous")
    if drive_type != 3 or label_offset != 16:
        raise ValueError("Shell Link VolumeID is not the canonical fixed-drive ANSI-label form")
    volume_label = _reader_ascii_z(
        reader.span(volume_start + label_offset, volume_start + volume_size, where="volume label"),
        where="volume label",
    )
    _reader_volume_label(volume_label)

    target_path_ansi = _reader_ascii_z(
        reader.span(
            link_start + local_path_offset,
            link_start + suffix_offset,
            where="ANSI local path",
        ),
        where="ANSI local path",
    )
    suffix_ansi = reader.span(
        link_start + suffix_offset,
        link_start + local_unicode_offset,
        where="ANSI common suffix",
    )
    if suffix_ansi != b"\x00":
        raise ValueError("Shell Link ANSI common suffix must be exactly empty")
    target_path_unicode = _reader_utf16_z(
        reader.span(
            link_start + local_unicode_offset,
            link_start + suffix_unicode_offset,
            where="Unicode local path",
        ),
        where="Unicode local path",
    )
    suffix_unicode = reader.span(
        link_start + suffix_unicode_offset,
        link_end,
        where="Unicode common suffix",
    )
    if suffix_unicode != b"\x00\x00":
        raise ValueError("Shell Link Unicode common suffix must be exactly empty")
    if target_path_ansi != target_path_unicode:
        raise ValueError("Shell Link ANSI and Unicode target paths disagree")
    _reader_target_path(target_path_ansi)

    count_characters = reader.unpack("<H", link_end, where="NAME_STRING count")[0]
    if type(count_characters) is not int or not 1 <= count_characters <= 260:
        raise ValueError("Shell Link NAME_STRING character count is outside the profile")
    name_start = link_end + 2
    name_end = name_start + count_characters * 2
    name_bytes = reader.span(name_start, name_end, where="NAME_STRING")
    try:
        name_string = name_bytes.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Shell Link NAME_STRING is not strict UTF-16LE") from exc
    if "\x00" in name_string or not name_string.endswith(_MARKED_NAME_SUFFIX):
        raise ValueError("Shell Link NAME_STRING lacks the exact in-band synthetic marker")
    display_name = name_string[: -len(_MARKED_NAME_SUFFIX)]
    _reader_display_name(display_name)
    if reader.span(name_end, len(data), where="terminal block") != b"\x00\x00\x00\x00":
        raise ValueError("Shell Link must end with exactly one zero TerminalBlock")

    return ShellLinkValue(
        target_path=target_path_ansi,
        display_name=display_name,
        name_string=name_string,
        target_size=target_size,
        creation_filetime=creation_filetime,
        access_filetime=access_filetime,
        write_filetime=write_filetime,
        volume_serial=volume_serial,
        volume_label=volume_label,
    )


__all__ = [
    "DEFAULT_FILETIME",
    "DEFAULT_VOLUME_LABEL",
    "DEFAULT_VOLUME_SERIAL",
    "DRIVE_FIXED",
    "FILE_ATTRIBUTE_ARCHIVE",
    "HAS_LINK_INFO",
    "HAS_NAME",
    "IS_UNICODE",
    "LINK_INFO_HEADER_SIZE",
    "MAX_PORTABLE_FILETIME",
    "MAX_SHELL_LINK_BYTES",
    "MAX_STRING_DATA_CHARACTERS",
    "MAX_WINDOWS_PATH_CHARACTERS",
    "MIN_PORTABLE_FILETIME",
    "SHELL_LINK_CLSID",
    "SHELL_LINK_FLAGS",
    "SHELL_LINK_HEADER_SIZE",
    "SW_SHOWNORMAL",
    "ShellLinkTimestamps",
    "ShellLinkValue",
    "build_shell_link",
    "parse_shell_link",
]
