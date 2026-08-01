# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Independently decode the strict binary-plist subset used by LaunchAgents.

This is deliberately not a general binary-property-list implementation.  It accepts the
canonical ``bplist00`` encodings ArtifactForge emits for booleans, bounded integers, ASCII or
UTF-16BE strings, arrays, and string-keyed dictionaries.  It shares no parser or writer code
with the standard-library implementation that creates the files.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import struct
from typing import TypeAlias


BinaryPlistValue: TypeAlias = (
    bool
    | int
    | str
    | list["BinaryPlistValue"]
    | dict[str, "BinaryPlistValue"]
)


class BinaryPlistError(ValueError):
    """The input is outside the canonical, bounded LaunchAgent plist subset."""


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class BinaryPlistLimits:
    """Resource ceilings applied before references or strings are expanded."""

    max_bytes: int = 1024 * 1024
    max_objects: int = 4096
    max_depth: int = 64
    max_collection_items: int = 4096
    max_string_bytes: int = 256 * 1024
    max_references: int = 16384

    def __post_init__(self) -> None:
        for name in (
            "max_bytes",
            "max_objects",
            "max_depth",
            "max_collection_items",
            "max_string_bytes",
            "max_references",
        ):
            _positive_integer(getattr(self, name), name)


DEFAULT_LIMITS = BinaryPlistLimits()
_INTEGER_WIDTHS = frozenset((1, 2, 4, 8))
_MISSING = object()


def _canonical_width(value: int) -> int:
    """Return the 1/2/4/8-byte width used by the emitting implementation."""
    if value < 1 << 8:
        return 1
    if value < 1 << 16:
        return 2
    if value < 1 << 32:
        return 4
    return 8


class _Parser:
    def __init__(self, data: bytes, limits: BinaryPlistLimits):
        self.data = data
        self.limits = limits
        self.offsets: tuple[int, ...] = ()
        self.ends: tuple[int, ...] = ()
        self.reference_size = 0
        self.cache: dict[int, BinaryPlistValue] = {}
        self.active: set[int] = set()
        self.reference_count = 0

    def parse(self) -> BinaryPlistValue:
        if len(self.data) > self.limits.max_bytes:
            raise BinaryPlistError(
                f"binary plist exceeds the {self.limits.max_bytes}-byte limit"
            )
        if len(self.data) < 8 + 1 + 1 + 32:
            raise BinaryPlistError("binary plist is too short")
        if self.data[:8] != b"bplist00":
            raise BinaryPlistError("binary plist header must be bplist00")

        trailer = self.data[-32:]
        if trailer[:6] != b"\x00" * 6:
            raise BinaryPlistError("binary plist trailer reserved bytes must be zero")
        try:
            offset_size, reference_size, object_count, top_object, table_offset = (
                struct.unpack(">6xBBQQQ", trailer)
            )
        except struct.error as exc:  # pragma: no cover - length was checked above
            raise BinaryPlistError("binary plist trailer is truncated") from exc

        if not object_count:
            raise BinaryPlistError("binary plist must contain at least one object")
        if object_count > self.limits.max_objects:
            raise BinaryPlistError(
                f"binary plist exceeds the {self.limits.max_objects}-object limit"
            )
        if top_object != 0:
            raise BinaryPlistError("canonical binary plist top object must be object 0")
        if offset_size not in _INTEGER_WIDTHS:
            raise BinaryPlistError("binary plist offset width must be 1, 2, 4, or 8 bytes")
        if reference_size not in _INTEGER_WIDTHS:
            raise BinaryPlistError("binary plist reference width must be 1, 2, 4, or 8 bytes")
        if reference_size != _canonical_width(object_count):
            raise BinaryPlistError("binary plist reference width is not canonical")
        if table_offset < 9 or table_offset >= len(self.data) - 32:
            raise BinaryPlistError("binary plist offset table is outside the object region")
        if offset_size != _canonical_width(table_offset):
            raise BinaryPlistError("binary plist offset width is not canonical")

        table_bytes = object_count * offset_size
        if table_offset + table_bytes != len(self.data) - 32:
            raise BinaryPlistError(
                "binary plist offset table does not end exactly at the trailer"
            )
        offsets = tuple(
            int.from_bytes(
                self.data[table_offset + index * offset_size:
                          table_offset + (index + 1) * offset_size],
                "big",
            )
            for index in range(object_count)
        )
        if offsets[0] != 8:
            raise BinaryPlistError("canonical binary plist object table must begin at byte 8")
        if any(left >= right for left, right in zip(offsets, offsets[1:])):
            raise BinaryPlistError("binary plist object offsets must be unique and increasing")
        if offsets[-1] >= table_offset:
            raise BinaryPlistError("binary plist object offset points into the offset table")

        self.offsets = offsets
        self.ends = offsets[1:] + (table_offset,)
        self.reference_size = reference_size
        result = self._decode(0, depth=0)
        if len(self.cache) != object_count:
            unreachable = sorted(set(range(object_count)) - set(self.cache))
            rendered = ", ".join(str(value) for value in unreachable[:8])
            raise BinaryPlistError(f"binary plist contains unreachable objects: {rendered}")
        return result

    def _need(self, cursor: int, size: int, end: int, label: str) -> int:
        if size < 0 or cursor < 0 or cursor + size > end:
            raise BinaryPlistError(f"{label} exceeds its object boundary")
        return cursor + size

    def _read_count(self, low: int, cursor: int, end: int) -> tuple[int, int]:
        if low < 0x0F:
            return low, cursor
        after_token = self._need(cursor, 1, end, "extended length token")
        token = self.data[cursor]
        if token & 0xF0 != 0x10:
            raise BinaryPlistError("extended length must use an integer object")
        exponent = token & 0x0F
        if exponent > 3:
            raise BinaryPlistError("extended length integer is wider than eight bytes")
        width = 1 << exponent
        after_value = self._need(after_token, width, end, "extended length integer")
        value = int.from_bytes(self.data[after_token:after_value], "big")
        if value < 0x0F:
            raise BinaryPlistError("short length was encoded in noncanonical extended form")
        if width != _canonical_width(value):
            raise BinaryPlistError("extended length integer width is not canonical")
        return value, after_value

    def _read_references(
        self, count: int, cursor: int, end: int, label: str
    ) -> tuple[tuple[int, ...], int]:
        if count > self.limits.max_collection_items:
            raise BinaryPlistError(
                f"{label} exceeds the {self.limits.max_collection_items}-item limit"
            )
        self.reference_count += count
        if self.reference_count > self.limits.max_references:
            raise BinaryPlistError(
                f"binary plist exceeds the {self.limits.max_references}-reference limit"
            )
        size = count * self.reference_size
        after = self._need(cursor, size, end, f"{label} references")
        refs = tuple(
            int.from_bytes(
                self.data[cursor + index * self.reference_size:
                          cursor + (index + 1) * self.reference_size],
                "big",
            )
            for index in range(count)
        )
        invalid = next((reference for reference in refs if reference >= len(self.offsets)), None)
        if invalid is not None:
            raise BinaryPlistError(f"{label} references missing object {invalid}")
        return refs, after

    @staticmethod
    def _at_end(cursor: int, end: int) -> None:
        if cursor != end:
            raise BinaryPlistError("binary plist object has trailing or unconsumed bytes")

    def _decode(self, reference: int, depth: int) -> BinaryPlistValue:
        if depth > self.limits.max_depth:
            raise BinaryPlistError(
                f"binary plist exceeds the {self.limits.max_depth}-level nesting limit"
            )
        cached = self.cache.get(reference, _MISSING)
        if cached is not _MISSING:
            return cached  # type: ignore[return-value]
        if reference in self.active:
            raise BinaryPlistError(f"binary plist object graph contains a cycle at {reference}")

        self.active.add(reference)
        try:
            value = self._decode_uncached(reference, depth)
            self.cache[reference] = value
            return value
        finally:
            self.active.remove(reference)

    def _decode_uncached(self, reference: int, depth: int) -> BinaryPlistValue:
        cursor = self.offsets[reference]
        end = self.ends[reference]
        after_token = self._need(cursor, 1, end, "object token")
        token = self.data[cursor]
        high, low = token & 0xF0, token & 0x0F
        cursor = after_token

        if token in (0x08, 0x09):
            self._at_end(cursor, end)
            return token == 0x09

        if high == 0x10:
            if low > 3:
                raise BinaryPlistError("integer object is wider than eight bytes")
            width = 1 << low
            after = self._need(cursor, width, end, "integer object")
            raw = self.data[cursor:after]
            value = int.from_bytes(raw, "big", signed=width == 8)
            expected_width = 8 if value < 0 else _canonical_width(value)
            if width != expected_width:
                raise BinaryPlistError("integer object width is not canonical")
            self._at_end(after, end)
            return value

        if high in (0x50, 0x60):
            count, cursor = self._read_count(low, cursor, end)
            byte_count = count if high == 0x50 else count * 2
            if byte_count > self.limits.max_string_bytes:
                raise BinaryPlistError(
                    f"string exceeds the {self.limits.max_string_bytes}-byte limit"
                )
            after = self._need(cursor, byte_count, end, "string data")
            raw = self.data[cursor:after]
            try:
                value = raw.decode("ascii" if high == 0x50 else "utf-16-be")
            except UnicodeDecodeError as exc:
                raise BinaryPlistError("string data is not valid for its declared encoding") from exc
            if high == 0x60 and value.isascii():
                raise BinaryPlistError("ASCII string was encoded noncanonically as UTF-16BE")
            self._at_end(after, end)
            return value

        if high == 0xA0:
            count, cursor = self._read_count(low, cursor, end)
            references, after = self._read_references(count, cursor, end, "array")
            self._at_end(after, end)
            return [self._decode(child, depth + 1) for child in references]

        if high == 0xD0:
            count, cursor = self._read_count(low, cursor, end)
            key_refs, cursor = self._read_references(count, cursor, end, "dictionary keys")
            value_refs, after = self._read_references(
                count, cursor, end, "dictionary values"
            )
            self._at_end(after, end)
            keys = [self._decode(child, depth + 1) for child in key_refs]
            if any(type(key) is not str for key in keys):
                raise BinaryPlistError("binary plist dictionary key is not a string")
            string_keys = [key for key in keys if isinstance(key, str)]
            if len(set(string_keys)) != len(string_keys):
                raise BinaryPlistError("binary plist dictionary contains duplicate keys")
            if string_keys != sorted(string_keys):
                raise BinaryPlistError("binary plist dictionary keys are not canonical-sorted")
            values = [self._decode(child, depth + 1) for child in value_refs]
            return dict(zip(string_keys, values))

        raise BinaryPlistError(f"unsupported binary plist object token 0x{token:02x}")


def loads_binary_plist(
    data: bytes | bytearray | memoryview,
    *,
    limits: BinaryPlistLimits = DEFAULT_LIMITS,
) -> BinaryPlistValue:
    """Decode canonical binary-plist bytes within the LaunchAgent subset."""
    if not isinstance(limits, BinaryPlistLimits):
        raise TypeError("limits must be a BinaryPlistLimits instance")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("binary plist input must be bytes-like")
    input_size = data.nbytes if isinstance(data, memoryview) else len(data)
    if input_size > limits.max_bytes:
        raise BinaryPlistError(
            f"binary plist exceeds the {limits.max_bytes}-byte limit"
        )
    return _Parser(bytes(data), limits).parse()


def load_binary_plist(
    path: str | os.PathLike[str],
    *,
    limits: BinaryPlistLimits = DEFAULT_LIMITS,
) -> BinaryPlistValue:
    """Read and decode one bounded binary plist without following format-specific helpers."""
    if not isinstance(limits, BinaryPlistLimits):
        raise TypeError("limits must be a BinaryPlistLimits instance")
    try:
        with open(path, "rb") as handle:
            data = handle.read(limits.max_bytes + 1)
    except (OSError, TypeError) as exc:
        raise BinaryPlistError(f"cannot read binary plist {path!r}: {exc}") from exc
    return loads_binary_plist(data, limits=limits)


__all__ = [
    "BinaryPlistError",
    "BinaryPlistLimits",
    "BinaryPlistValue",
    "DEFAULT_LIMITS",
    "load_binary_plist",
    "loads_binary_plist",
]
