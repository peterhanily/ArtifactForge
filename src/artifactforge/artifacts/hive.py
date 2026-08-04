# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Minimal deterministic regf (Windows registry hive) writer.

Two passes: (1) assign every cell an offset (an nk's offset is reserved before its
children so they can point back at it); (2) serialize in the identical order. Offsets are
relative to the first hive bin (file offset 4096). Enough of the format to carry Run-key
persistence and Amcache InventoryApplicationFile entries; disk-image tiers are out of scope.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import ntpath
import re
import struct
import unicodedata

from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME

FILETIME = 133497684000000000  # 2024-01-15T05:00:00Z, pinned (deterministic)
REG_SZ, REG_BINARY, REG_DWORD = 1, 3, 4
_NONE = 0xFFFFFFFF
_AMCACHE_FILE_NAME = "Amcache.hve"
_SOFTWARE_FILE_NAME = r"\System32\config\SOFTWARE"
_MAX_PROFILE_ROWS = 64
_MAX_REGISTRY_NAME_CODE_UNITS = 255
_MAX_WINDOWS_PATH_CODE_UNITS = 260
_MAX_WINDOWS_COMPONENT_CODE_UNITS = 255
_SHA1 = re.compile(r"[0-9a-f]{40}")
_RECORD_KEY = re.compile(r"[0-9a-f]{1,64}")
_DRIVE = re.compile(r"[A-Za-z]:")
_INVALID_WINDOWS_COMPONENT_CHARACTERS = frozenset('<>:"|?*')
_RESERVED_WINDOWS_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def _filetime(value: object, *, where: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"{where} must be an unsigned 64-bit FILETIME integer (not bool)")
    return value


@dataclass(frozen=True)
class HiveTimestampSpec:
    """Exact REGF base/default/per-key FILETIMEs.

    Key override paths include the root name and use one backslash between components, for
    example ``ROOT\\Microsoft\\Windows\\CurrentVersion\\Run``.  A tuple rather than a mapping
    makes duplicate paths observable and keeps this writer's input deterministic.
    """

    hive_filetime: int = FILETIME
    default_key_filetime: int = FILETIME
    key_filetimes: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        _filetime(self.hive_filetime, where="REGF hive timestamp")
        _filetime(self.default_key_filetime, where="REGF default key timestamp")
        if type(self.key_filetimes) is not tuple:
            raise ValueError("REGF per-key timestamps must be a tuple")
        seen = set()
        for index, item in enumerate(self.key_filetimes):
            if type(item) is not tuple or len(item) != 2:
                raise ValueError(f"REGF per-key timestamp {index} must be a (path, FILETIME) tuple")
            path, value = item
            if (
                type(path) is not str
                or not path
                or path.startswith("\\")
                or path.endswith("\\")
                or any(not component for component in path.split("\\"))
            ):
                raise ValueError(
                    f"REGF per-key timestamp {index} path must be a canonical key path"
                )
            if path in seen:
                raise ValueError(f"duplicate REGF per-key timestamp path: {path!r}")
            seen.add(path)
            _filetime(value, where=f"REGF key {path!r} timestamp")


def _utf16_code_units(value: str, *, where: str) -> int:
    try:
        return len(value.encode("utf-16-le", errors="strict")) // 2
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} contains an unpaired surrogate") from exc


def _bounded_text(value, *, where: str, max_code_units: int) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{where} must be non-empty text")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{where} must be Unicode NFC")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError(f"{where} contains a control character")
    if _utf16_code_units(value, where=where) > max_code_units:
        raise ValueError(
            f"{where} exceeds the {max_code_units} UTF-16-code-unit profile limit"
        )
    return value


def _materialize_bounded(value, *, where: str, limit: int) -> tuple:
    """Consume one iterable once, taking no more than ``limit`` yielded items."""
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise ValueError(f"{where} must be an iterable of rows")
    try:
        iterator = iter(value)
    except TypeError as exc:
        raise ValueError(f"{where} must be iterable") from exc
    result = []
    for _ in range(limit):
        try:
            result.append(next(iterator))
        except StopIteration:
            break
    return tuple(result)


def _rows(value, *, where: str, widths: tuple[int, ...]) -> tuple[tuple, ...]:
    materialized = _materialize_bounded(
        value, where=f"{where} rows", limit=_MAX_PROFILE_ROWS + 1
    )
    if not 1 <= len(materialized) <= _MAX_PROFILE_ROWS:
        raise ValueError(f"{where} requires 1..{_MAX_PROFILE_ROWS} rows")

    rows = []
    maximum_width = max(widths)
    for index, row in enumerate(materialized):
        if isinstance(row, (str, bytes, bytearray, Mapping)):
            raise ValueError(
                f"{where} row {index} must contain "
                f"{' or '.join(str(width) for width in widths)} values"
            )
        fields = _materialize_bounded(
            row, where=f"{where} row {index}", limit=maximum_width + 1
        )
        if len(fields) not in widths:
            raise ValueError(
                f"{where} row {index} must contain "
                f"{' or '.join(str(width) for width in widths)} values"
            )
        rows.append(fields)
    return tuple(rows)


def _windows_path(value, *, where: str, lowercase: bool) -> str:
    value = _bounded_text(
        value, where=where, max_code_units=_MAX_WINDOWS_PATH_CODE_UNITS
    )
    if "/" in value:
        raise ValueError(f"{where} must use Windows backslash separators")
    drive, tail = ntpath.splitdrive(value)
    if (
        _DRIVE.fullmatch(drive) is None
        or not tail.startswith("\\")
        or tail.startswith("\\\\")
    ):
        raise ValueError(f"{where} must be an absolute drive-letter Windows path")
    components = tail[1:].split("\\")
    if not components or any(not component for component in components):
        raise ValueError(f"{where} must contain a file path without empty components")
    if ntpath.normpath(value) != value or any(
        component in {".", ".."} for component in components
    ):
        raise ValueError(f"{where} must be lexically normal without dot components")
    for component in components:
        if _utf16_code_units(component, where=where) > _MAX_WINDOWS_COMPONENT_CODE_UNITS:
            raise ValueError(
                f"{where} contains a component longer than "
                f"{_MAX_WINDOWS_COMPONENT_CODE_UNITS} UTF-16 code units"
            )
        if (
            component[-1] in {" ", "."}
            or any(
                character in _INVALID_WINDOWS_COMPONENT_CHARACTERS
                for character in component
            )
            or component.split(".", 1)[0].upper() in _RESERVED_WINDOWS_STEMS
        ):
            raise ValueError(f"{where} contains an invalid Windows path component")
    if lowercase and value.lower() != value:
        raise ValueError(f"{where} must be canonical lowercase text")
    return value


def _registry_name(value: str, *, where: str) -> tuple[bytes, bool]:
    """Encode one bounded REGF key/value name without lying about compression.

    The one-byte REGF form is safe only for ASCII in this deliberately small writer.  Real
    registry names are Unicode; using latin-1 while setting the compressed-name flag made
    U+0080..U+00ff parse as different text.  Non-ASCII names therefore use the native UTF-16LE
    representation and leave the compression flag clear.
    """
    value = _bounded_text(
        value, where=where, max_code_units=_MAX_REGISTRY_NAME_CODE_UNITS
    )
    encoded = value.encode("ascii") if value.isascii() else value.encode("utf-16-le")
    return encoded, value.isascii()


class Val:
    def __init__(self, name: str, type_: int, data: bytes):
        self.name, self.type, self.data = name, type_, data


class Key:
    def __init__(self, name: str, values=None, subkeys=None):
        self.name = name
        self.values = values or []
        self.subkeys = subkeys or []


def sz(name: str, value: str) -> Val:
    return Val(name, REG_SZ, (value + "\x00").encode("utf-16-le"))


def dword(name: str, value: int) -> Val:
    return Val(name, REG_DWORD, value.to_bytes(4, "little"))


def _padded_total(data_size: int) -> int:
    total = 4 + data_size
    return total + ((-total) % 8)


def build_hive(
    root: Key,
    *,
    file_name: str,
    timestamps: HiveTimestampSpec | None = None,
) -> bytes:
    if timestamps is None:
        timestamps = HiveTimestampSpec()
    elif type(timestamps) is not HiveTimestampSpec:
        raise ValueError("REGF timestamps must be a HiveTimestampSpec or None")
    encoded_file_name = file_name.encode("utf-16-le")
    if not encoded_file_name or len(encoded_file_name) > 64:
        raise ValueError("REGF base-block file_name must fit its 32 UTF-16-code-unit field")
    running = 0

    def alloc(data_size: int) -> int:
        nonlocal running
        off = 32 + running
        running += _padded_total(data_size)
        return off

    overrides = dict(timestamps.key_filetimes)
    used_overrides: set[str] = set()

    def assign(key: Key, parent_path: tuple[str, ...] = ()):
        key._name, key._compressed_name = _registry_name(key.name, where="registry key name")
        path = "\\".join((*parent_path, key.name))
        key._last_written_filetime = overrides.get(path, timestamps.default_key_filetime)
        if path in overrides:
            used_overrides.add(path)
        key._nk = alloc(76 + len(key._name))
        for v in key.values:
            v._name, v._compressed_name = _registry_name(
                v.name, where=f"registry value name under {key.name!r}"
            )
            v._inline = (v.type == REG_DWORD and len(v.data) <= 4)
            if not v._inline:
                v._data = alloc(len(v.data))
            v._vk = alloc(20 + len(v._name))
        key._vlist = alloc(4 * len(key.values)) if key.values else _NONE
        for c in key.subkeys:
            c._parent = key._nk
            assign(c, (*parent_path, key.name))
        key._sklist = alloc(4 + 8 * len(key.subkeys)) if key.subkeys else _NONE

    root._parent = 0
    assign(root)             # root nk is the FIRST cell (regipy treats cell #1 as the root)
    unknown_overrides = sorted(set(overrides) - used_overrides)
    if unknown_overrides:
        raise ValueError(
            "REGF per-key timestamp paths do not exist in the emitted tree: "
            + ", ".join(repr(path) for path in unknown_overrides)
        )
    sk_off = alloc(20)       # shared security cell, emitted last

    hbin_size = ((32 + running + 4095) // 4096) * 4096
    cells = bytearray()

    def emit(body: bytes):
        total = _padded_total(len(body))
        cells.extend(struct.pack("<i", -total) + body + b"\x00" * (total - 4 - len(body)))

    def write(key: Key, is_root=False):
        flags = (0x20 if key._compressed_name else 0) | (0x0C if is_root else 0)
        emit(b"nk" + struct.pack(
            "<HQIIIIIIIIIIIIIIIHH",
            flags, key._last_written_filetime, 0, key._parent,
            len(key.subkeys), 0, key._sklist, _NONE,
            len(key.values), key._vlist, sk_off, _NONE,
            0, 0, 0, 0, 0,
            len(key._name), 0) + key._name)
        for v in key.values:
            if v._inline:
                data_off = int.from_bytes(v.data.ljust(4, b"\x00")[:4], "little")
                data_size = 0x80000000 | len(v.data)
            else:
                emit(v.data)
                data_off, data_size = v._data, len(v.data)
            vflags = 0x0001 if v._compressed_name else 0
            emit(b"vk" + struct.pack("<HIIIHH", len(v._name), data_size, data_off, v.type, vflags, 0) + v._name)
        if key.values:
            emit(b"".join(struct.pack("<I", v._vk) for v in key.values))
        for c in key.subkeys:
            write(c)
        if key.subkeys:
            body = b"lf" + struct.pack("<H", len(key.subkeys))
            for c in key.subkeys:
                body += struct.pack("<I", c._nk) + c._name[:4].ljust(4, b"\x00")
            emit(body)

    write(root, is_root=True)
    emit(b"sk\x00\x00" + struct.pack("<IIII", 0, 0, 1, 0))  # shared security cell

    free = hbin_size - 32 - len(cells)
    if free >= 4:
        cells.extend(struct.pack("<i", free) + b"\x00" * (free - 4))

    hbin = (b"hbin" + struct.pack("<II", 0, hbin_size) + b"\x00" * 8
            + struct.pack("<Q", timestamps.hive_filetime) + b"\x00" * 4 + bytes(cells))
    hbin = hbin[:hbin_size].ljust(hbin_size, b"\x00")

    base = bytearray(4096)
    base[0:4] = b"regf"
    struct.pack_into("<II", base, 4, 1, 1)
    struct.pack_into("<Q", base, 12, timestamps.hive_filetime)
    struct.pack_into("<IIII", base, 20, 1, 3, 0, 1)
    struct.pack_into("<I", base, 36, root._nk)
    struct.pack_into("<I", base, 40, hbin_size)
    struct.pack_into("<I", base, 44, 1)
    base[48:48 + len(encoded_file_name)] = encoded_file_name
    checksum = 0
    for i in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", base, i)[0]
    if checksum in (0, 0xFFFFFFFF):
        checksum ^= 1
    struct.pack_into("<I", base, 508, checksum & 0xFFFFFFFF)
    return bytes(base) + hbin


def _marker_key() -> Key:
    """A normal, ignorable key carries disclosure without corrupting hive identity."""
    return Key(RESERVED_NAME, values=[sz("marker", MARKER), sz("notice", NOTICE)])


def build_run_hive(values, *, timestamps: HiveTimestampSpec | None = None) -> bytes:
    """A SOFTWARE-hive fragment: ...\\CurrentVersion\\Run with one value per autostart.

    ``values`` is a bounded iterable of 1..64 ``(value_name, program_path)`` rows.  Names
    must be unique under case-folding; paths must be normal absolute drive-letter paths.
    More than one is the normal case: a real Run key carries several entries and only one of
    them is interesting, which makes "which program does persistence launch" a question
    rather than a lookup.
    """
    rows = _rows(values, where="SOFTWARE Run", widths=(2,))
    validated = []
    names = set()
    for index, (name, program_path) in enumerate(rows):
        name = _bounded_text(
            name,
            where=f"SOFTWARE Run row {index} value name",
            max_code_units=_MAX_REGISTRY_NAME_CODE_UNITS,
        )
        # Keep the public boundary identical to the encoder's logical REGF-name domain.
        _registry_name(name, where=f"SOFTWARE Run row {index} value name")
        identity = name.casefold()
        if identity in names:
            raise ValueError("SOFTWARE Run value names must be unique case-insensitively")
        names.add(identity)
        validated.append(
            (
                name,
                _windows_path(
                    program_path,
                    where=f"SOFTWARE Run row {index} program path",
                    lowercase=False,
                ),
            )
        )

    return build_hive(Key("ROOT", subkeys=[Key("Microsoft", subkeys=[
        Key("Windows", subkeys=[Key("CurrentVersion", subkeys=[
            Key("Run", values=[sz(n, p) for n, p in validated])])])]), _marker_key()]),
        file_name=_SOFTWARE_FILE_NAME,
        timestamps=timestamps)


def build_amcache_hive(entries, *, timestamps: HiveTimestampSpec | None = None) -> bytes:
    """An Amcache.hve fragment: Root\\InventoryApplicationFile with one subkey per entry.

    ``entries`` is a bounded iterable of 1..64 ``(sha1, lower_path, name, size)`` rows or the
    same row followed by an opaque hexadecimal record key.  FileIds, paths and keys must be
    unique.  The registry subkey name is metadata, not a second copy of ``FileId``: encoding a
    SHA1 prefix there lets a solver bypass the value it is meant to interpret.  Four-field
    callers receive a deterministic index key; scene builders should pass independently
    derived keys.
    """
    rows = _rows(entries, where="Amcache inventory", widths=(4, 5))
    subkeys = []
    record_keys = set()
    file_ids = set()
    lower_paths = set()
    for index, entry in enumerate(rows):
        if len(entry) == 4:
            sha1, lower_path, name, size = entry
            record_key = "0000" + f"{index:016x}"
        else:
            sha1, lower_path, name, size, record_key = entry

        if type(sha1) is not str or _SHA1.fullmatch(sha1) is None:
            raise ValueError(
                f"Amcache inventory row {index} SHA1 must be exactly 40 lowercase hex digits"
            )
        if sha1 in file_ids:
            raise ValueError("Amcache FileIds must be unique")
        file_ids.add(sha1)

        lower_path = _windows_path(
            lower_path,
            where=f"Amcache inventory row {index} LowerCaseLongPath",
            lowercase=True,
        )
        if lower_path in lower_paths:
            raise ValueError("Amcache LowerCaseLongPath values must be unique")
        lower_paths.add(lower_path)

        name = _bounded_text(
            name,
            where=f"Amcache inventory row {index} Name",
            max_code_units=_MAX_WINDOWS_COMPONENT_CODE_UNITS,
        )
        if ntpath.basename(lower_path).casefold() != name.casefold():
            raise ValueError(
                f"Amcache inventory row {index} Name must match "
                "LowerCaseLongPath's basename case-insensitively"
            )

        if type(size) is not int or not 0 <= size <= 0xFFFFFFFF:
            raise ValueError(
                f"Amcache inventory row {index} Size must be a uint32 integer (not bool)"
            )
        if type(record_key) is not str or _RECORD_KEY.fullmatch(record_key) is None:
            raise ValueError(
                "Amcache record keys must contain 1..64 lowercase hexadecimal digits"
            )
        if record_key in record_keys:
            raise ValueError("Amcache record keys must be unique")
        record_keys.add(record_key)

        subkeys.append(Key(record_key, values=[
            sz("FileId", "0000" + sha1),
            sz("LowerCaseLongPath", lower_path),
            sz("Name", name),
            dword("Size", size),
        ]))
    return build_hive(Key("amcache", subkeys=[
        Key("Root", subkeys=[Key("InventoryApplicationFile", subkeys=subkeys)]),
        _marker_key(),
    ]), file_name=_AMCACHE_FILE_NAME, timestamps=timestamps)
