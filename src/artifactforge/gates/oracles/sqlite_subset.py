# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Independent byte reader for the small SQLite profile ArtifactForge emits.

This is intentionally not a general SQLite implementation.  It accepts a 4096-byte,
UTF-8, rollback-journal database whose schema and every table/index fit on leaf b-tree root
pages.  Freelist, pointer-map, interior, overflow, WAL and non-canonical record encodings are
red.  The narrowness is what makes this useful as an oracle: accepting a new SQLite feature
requires an explicit parser change rather than inheriting the host ``sqlite3`` library's
opinion.

Depends only on the Python standard library and the public SQLite file-format specification.
It must not import SQLite or ArtifactForge's database writers.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import os
import re
import struct
from types import MappingProxyType
from typing import Mapping, TypeAlias


SQLiteValue: TypeAlias = None | int | float | str | bytes

_PAGE_SIZE = 4096
_MAGIC = b"SQLite format 3\x00"
_TABLE_LEAF = 0x0D
_INDEX_LEAF = 0x0A
_INTERIOR_TYPES = frozenset((0x02, 0x05))
_CREATE_TABLE = re.compile(
    r"^CREATE TABLE ([A-Za-z_][A-Za-z0-9_]*) \((.*)\)$"
)
_COLUMN = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*) (INTEGER|TEXT|REAL|BLOB)( PRIMARY KEY)?$"
)


class SQLiteSubsetError(ValueError):
    """Bytes fall outside the deliberately narrow emitted SQLite profile."""


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class SQLiteLimits:
    """Resource ceilings checked before page structures are traversed."""

    max_bytes: int = 16 * 1024 * 1024
    max_pages: int = 4096

    def __post_init__(self) -> None:
        _positive_integer(self.max_bytes, "max_bytes")
        _positive_integer(self.max_pages, "max_pages")


DEFAULT_SQLITE_LIMITS = SQLiteLimits()


class SQLiteWireProfile(str, Enum):
    """Closed header/value profiles; callers cannot manufacture a weaker policy."""

    SQLITE_RUNTIME_V1 = "sqlite-runtime-leaf-v1"
    ARTIFACTFORGE_OWNED_V1 = "artifactforge-owned-sqlite-leaf-v1"


DEFAULT_SQLITE_WIRE_PROFILE = SQLiteWireProfile.SQLITE_RUNTIME_V1


@dataclass(frozen=True)
class SQLiteHeader:
    page_size: int
    page_count: int
    change_counter: int
    schema_cookie: int
    sqlite_version_number: int


@dataclass(frozen=True)
class SQLiteRecord:
    values: tuple[SQLiteValue, ...]
    serial_types: tuple[int, ...]


@dataclass(frozen=True)
class SchemaObject:
    rowid: int
    kind: str
    name: str
    table_name: str
    root_page: int
    sql: str | None


@dataclass(frozen=True)
class Column:
    name: str
    declared_type: str
    primary_key: bool
    rowid_alias: bool


@dataclass(frozen=True)
class TableRow:
    rowid: int
    values: tuple[SQLiteValue, ...]
    serial_types: tuple[int, ...]


@dataclass(frozen=True)
class Table:
    name: str
    root_page: int
    columns: tuple[Column, ...]
    rows: tuple[TableRow, ...]

    def dictionaries(self) -> tuple[Mapping[str, SQLiteValue], ...]:
        """Rows keyed by declared column name, convenient for a sqlite3 comparison."""
        names = tuple(column.name for column in self.columns)
        return tuple(
            MappingProxyType(dict(zip(names, row.values, strict=True))) for row in self.rows
        )


@dataclass(frozen=True)
class IndexEntry:
    key: tuple[SQLiteValue, ...]
    rowid: int
    serial_types: tuple[int, ...]


@dataclass(frozen=True)
class Index:
    name: str
    table_name: str
    root_page: int
    columns: tuple[str, ...]
    entries: tuple[IndexEntry, ...]


@dataclass(frozen=True)
class SQLiteDatabase:
    header: SQLiteHeader
    schema: tuple[SchemaObject, ...]
    tables: tuple[Table, ...]
    indexes: tuple[Index, ...]

    @classmethod
    def from_bytes(
        cls,
        data: bytes | bytearray | memoryview,
        *,
        limits: SQLiteLimits = DEFAULT_SQLITE_LIMITS,
        wire_profile: SQLiteWireProfile = DEFAULT_SQLITE_WIRE_PROFILE,
    ) -> SQLiteDatabase:
        return loads_sqlite(data, limits=limits, wire_profile=wire_profile)

    def table(self, name: str) -> Table:
        matches = [table for table in self.tables if table.name == name]
        if len(matches) != 1:
            raise KeyError(name)
        return matches[0]

    def index(self, name: str) -> Index:
        matches = [index for index in self.indexes if index.name == name]
        if len(matches) != 1:
            raise KeyError(name)
        return matches[0]


def _error(condition: bool, message: str) -> None:
    if not condition:
        raise SQLiteSubsetError(message)


def decode_varint(data: bytes, offset: int = 0, *, limit: int | None = None) -> tuple[int, int]:
    """Decode one canonical SQLite varint, including the eight-plus-eight-bit ninth byte."""
    if not isinstance(data, bytes):
        raise TypeError("SQLite varint input must be bytes")
    end = len(data) if limit is None else min(limit, len(data))
    _error(0 <= offset < end, "truncated SQLite varint")
    value = 0
    for index in range(8):
        _error(offset + index < end, "truncated SQLite varint")
        byte = data[offset + index]
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            length = index + 1
            if length > 1:
                _error(
                    value >= 1 << (7 * (length - 1)),
                    f"non-canonical {length}-byte SQLite varint",
                )
            return value, offset + length
    _error(offset + 8 < end, "truncated nine-byte SQLite varint")
    value = (value << 8) | data[offset + 8]
    _error(value >= 1 << 56, "non-canonical nine-byte SQLite varint")
    return value, offset + 9


def _signed(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=True)


def _integer_serial_type(value: int) -> int:
    if value == 0:
        return 8
    if value == 1:
        return 9
    for serial_type, bits in ((1, 8), (2, 16), (3, 24), (4, 32), (5, 48), (6, 64)):
        if -(1 << (bits - 1)) <= value < 1 << (bits - 1):
            return serial_type
    raise SQLiteSubsetError(f"integer {value} is outside signed 64-bit SQLite range")


def decode_record(payload: bytes) -> SQLiteRecord:
    """Decode one canonical SQLite record payload into typed Python scalar values."""
    if not isinstance(payload, bytes):
        raise TypeError("SQLite record input must be bytes")
    _error(bool(payload), "empty SQLite record payload")
    header_size, serial_offset = decode_varint(payload)
    _error(
        serial_offset <= header_size <= len(payload),
        f"SQLite record header size {header_size} is outside its payload",
    )
    serial_types = []
    while serial_offset < header_size:
        serial_type, serial_offset = decode_varint(payload, serial_offset, limit=header_size)
        serial_types.append(serial_type)
    _error(serial_offset == header_size, "SQLite record serial types overrun the header")

    content_offset = header_size
    values: list[SQLiteValue] = []
    for serial_type in serial_types:
        if serial_type == 0:
            value: SQLiteValue = None
            size = 0
        elif 1 <= serial_type <= 6:
            size = (1, 2, 3, 4, 6, 8)[serial_type - 1]
            _error(content_offset + size <= len(payload), "truncated SQLite integer field")
            value = _signed(payload[content_offset:content_offset + size])
            _error(
                _integer_serial_type(value) == serial_type,
                f"non-canonical serial type {serial_type} for integer {value}",
            )
        elif serial_type == 7:
            size = 8
            _error(content_offset + size <= len(payload), "truncated SQLite float field")
            value = struct.unpack(">d", payload[content_offset:content_offset + size])[0]
            _error(math.isfinite(value), "non-finite SQLite REAL is outside the emitted profile")
        elif serial_type == 8:
            size = 0
            value = 0
        elif serial_type == 9:
            size = 0
            value = 1
        elif serial_type in (10, 11):
            raise SQLiteSubsetError(f"reserved SQLite serial type {serial_type}")
        elif serial_type % 2 == 0:
            size = (serial_type - 12) // 2
            _error(content_offset + size <= len(payload), "truncated SQLite BLOB field")
            value = payload[content_offset:content_offset + size]
        else:
            size = (serial_type - 13) // 2
            _error(content_offset + size <= len(payload), "truncated SQLite TEXT field")
            raw = payload[content_offset:content_offset + size]
            try:
                value = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise SQLiteSubsetError("SQLite TEXT is not valid UTF-8") from exc
        values.append(value)
        content_offset += size
    _error(content_offset == len(payload), "SQLite record has trailing or unclaimed content")
    return SQLiteRecord(tuple(values), tuple(serial_types))


@dataclass(frozen=True)
class _Cell:
    pointer: int
    end: int
    rowid: int | None
    record: SQLiteRecord


class _Reader:
    def __init__(
        self,
        data: bytes,
        limits: SQLiteLimits = DEFAULT_SQLITE_LIMITS,
        wire_profile: SQLiteWireProfile = DEFAULT_SQLITE_WIRE_PROFILE,
    ):
        if not isinstance(data, bytes):
            raise TypeError("SQLite database input must be bytes")
        self.data = data
        self.limits = limits
        self.wire_profile = wire_profile
        self.header = self._read_header()

    def _u32(self, offset: int) -> int:
        return int.from_bytes(self.data[offset:offset + 4], "big")

    def _read_header(self) -> SQLiteHeader:
        _error(
            len(self.data) <= self.limits.max_bytes,
            f"SQLite database exceeds the {self.limits.max_bytes}-byte limit",
        )
        _error(len(self.data) >= 100, "SQLite file is shorter than its 100-byte header")
        _error(self.data[:16] == _MAGIC, "SQLite magic header is absent")
        page_size = int.from_bytes(self.data[16:18], "big")
        _error(page_size == _PAGE_SIZE, f"SQLite page size is {page_size}, not 4096")
        _error(len(self.data) % page_size == 0, "SQLite file ends inside a page")
        _error(self.data[18] == 1 and self.data[19] == 1,
               "SQLite read/write versions are not rollback-journal mode")
        _error(self.data[20] == 0, "SQLite reserved bytes per page are non-zero")
        _error(self.data[21:24] == b"\x40\x20\x20",
               "SQLite payload fractions are outside the canonical profile")
        change_counter = self._u32(24)
        page_count = self._u32(28)
        _error(page_count == len(self.data) // page_size and page_count > 0,
               "SQLite header page count does not equal the file length")
        _error(
            page_count <= self.limits.max_pages,
            f"SQLite database exceeds the {self.limits.max_pages}-page limit",
        )
        _error(self._u32(32) == 0 and self._u32(36) == 0,
               "SQLite freelist is outside the emitted profile")
        schema_cookie = self._u32(40)
        _error(schema_cookie > 0, "SQLite schema cookie is zero")
        _error(self._u32(44) == 4, "SQLite schema format is not 4")
        _error(self._u32(48) == 0, "SQLite default page-cache field is non-zero")
        _error(self._u32(52) == 0 and self._u32(64) == 0,
               "SQLite auto-vacuum/pointer-map mode is outside the emitted profile")
        _error(self._u32(56) == 1, "SQLite text encoding is not UTF-8")
        _error(self._u32(60) == 0 and self._u32(68) == 0,
               "SQLite user version or application id is non-zero")
        _error(not any(self.data[72:92]), "SQLite reserved header expansion is non-zero")
        _error(self._u32(92) == change_counter and change_counter > 0,
               "SQLite version-valid-for does not equal the change counter")
        sqlite_version = self._u32(96)
        if self.wire_profile is SQLiteWireProfile.SQLITE_RUNTIME_V1:
            _error(
                3_000_000 <= sqlite_version < 4_000_000,
                "SQLite library version number is not a SQLite 3 release",
            )
        elif self.wire_profile is SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1:
            _error(
                sqlite_version == 0,
                "owned SQLite writer sentinel at header offset 96 is not zero",
            )
        else:  # pragma: no cover - public entry points enforce the closed enum.
            raise TypeError("wire_profile must be a SQLiteWireProfile")
        return SQLiteHeader(
            page_size, page_count, change_counter, schema_cookie, sqlite_version
        )

    def _page(self, page_number: int) -> bytes:
        _error(1 <= page_number <= self.header.page_count,
               f"SQLite page {page_number} is outside the database")
        start = (page_number - 1) * _PAGE_SIZE
        return self.data[start:start + _PAGE_SIZE]

    def _freeblocks(self, page: bytes, first: int, content_start: int) -> list[tuple[int, int]]:
        blocks = []
        previous = 0
        offset = first
        while offset:
            _error(content_start <= offset <= _PAGE_SIZE - 4,
                   f"SQLite freeblock offset {offset} is outside cell content")
            _error(offset > previous, "SQLite freeblock chain is not strictly increasing")
            next_offset = int.from_bytes(page[offset:offset + 2], "big")
            size = int.from_bytes(page[offset + 2:offset + 4], "big")
            _error(size >= 4 and offset + size <= _PAGE_SIZE,
                   f"SQLite freeblock at {offset} has invalid size {size}")
            _error(
                not any(page[offset + 4:offset + size]),
                f"SQLite freeblock at {offset} carries non-zero unparsed bytes",
            )
            blocks.append((offset, offset + size))
            previous = offset
            offset = next_offset
            _error(len(blocks) <= _PAGE_SIZE // 4, "SQLite freeblock chain cycles")
        return blocks

    def _leaf_cells(self, page_number: int, expected_type: int) -> tuple[_Cell, ...]:
        page = self._page(page_number)
        header_offset = 100 if page_number == 1 else 0
        page_type = page[header_offset]
        if page_type in _INTERIOR_TYPES:
            raise SQLiteSubsetError(
                f"SQLite page {page_number} is an interior b-tree page; only leaf roots are supported"
            )
        _error(page_type == expected_type,
               f"SQLite page {page_number} has b-tree type {page_type:#x}, "
               f"expected {expected_type:#x}")
        first_freeblock = int.from_bytes(page[header_offset + 1:header_offset + 3], "big")
        cell_count = int.from_bytes(page[header_offset + 3:header_offset + 5], "big")
        content_start = int.from_bytes(page[header_offset + 5:header_offset + 7], "big")
        _error(content_start != 0, "4096-byte SQLite page has zero cell-content offset")
        _error(page[header_offset + 7] == 0,
               "fragmented SQLite page bytes are outside the emitted profile")
        pointer_start = header_offset + 8
        pointer_end = pointer_start + 2 * cell_count
        _error(pointer_end <= content_start <= _PAGE_SIZE,
               f"SQLite page {page_number} pointer array overlaps cell content")
        _error(
            not any(page[pointer_end:content_start]),
            f"SQLite page {page_number} has non-zero bytes in unallocated space",
        )
        pointers = tuple(
            int.from_bytes(page[offset:offset + 2], "big")
            for offset in range(pointer_start, pointer_end, 2)
        )
        _error(len(set(pointers)) == len(pointers),
               f"SQLite page {page_number} has duplicate cell pointers")

        cells = []
        max_local = _PAGE_SIZE - 35 if page_type == _TABLE_LEAF else (
            ((_PAGE_SIZE - 12) * 64) // 255 - 23
        )
        for pointer in pointers:
            _error(content_start <= pointer < _PAGE_SIZE,
                   f"SQLite page {page_number} cell pointer {pointer} is outside content")
            payload_size, cursor = decode_varint(page, pointer, limit=_PAGE_SIZE)
            _error(payload_size <= max_local,
                   f"SQLite page {page_number} cell requires unsupported overflow storage")
            rowid = None
            if page_type == _TABLE_LEAF:
                raw_rowid, cursor = decode_varint(page, cursor, limit=_PAGE_SIZE)
                rowid = raw_rowid - (1 << 64) if raw_rowid >= 1 << 63 else raw_rowid
            end = cursor + payload_size
            _error(end <= _PAGE_SIZE,
                   f"SQLite page {page_number} cell payload extends past the page")
            record = decode_record(page[cursor:end])
            cells.append(_Cell(pointer, end, rowid, record))

        occupied = [(cell.pointer, cell.end, "cell") for cell in cells]
        freeblocks = self._freeblocks(page, first_freeblock, content_start)
        occupied.extend((start, end, "freeblock") for start, end in freeblocks)
        occupied.sort()
        for (_start, end, kind), (next_start, _next_end, next_kind) in zip(
            occupied, occupied[1:]
        ):
            _error(
                end == next_start,
                f"SQLite page {page_number} has an overlap or unclaimed cell-content gap "
                f"between {kind} and {next_kind}",
            )
        if occupied:
            _error(occupied[0][0] == content_start,
                   f"SQLite page {page_number} cell-content boundary is not canonical")
            _error(
                occupied[-1][1] == _PAGE_SIZE,
                f"SQLite page {page_number} has an unclaimed cell-content tail",
            )
        else:
            _error(content_start == _PAGE_SIZE,
                   f"empty SQLite page {page_number} has non-terminal content boundary")
        return tuple(cells)

    def _schema(self) -> tuple[SchemaObject, ...]:
        cells = self._leaf_cells(1, _TABLE_LEAF)
        objects = []
        previous_rowid = -(1 << 63) - 1
        for cell in cells:
            _error(cell.rowid is not None and cell.rowid > previous_rowid,
                   "sqlite_schema rowids are not strictly increasing")
            previous_rowid = cell.rowid
            values = cell.record.values
            _error(len(values) == 5, "sqlite_schema record does not contain five columns")
            kind, name, table_name, root_page, sql = values
            _error(kind in ("table", "index"),
                   f"unsupported sqlite_schema object type {kind!r}")
            _error(isinstance(name, str) and isinstance(table_name, str),
                   "sqlite_schema name fields are not TEXT")
            _error(isinstance(root_page, int) and not isinstance(root_page, bool),
                   "sqlite_schema rootpage is not INTEGER")
            _error(isinstance(sql, str) or sql is None,
                   "sqlite_schema sql field is neither TEXT nor NULL")
            _error(2 <= root_page <= self.header.page_count,
                   f"sqlite_schema root page {root_page} is outside owned data pages")
            objects.append(
                SchemaObject(cell.rowid, kind, name, table_name, root_page, sql)
            )
        names = [obj.name for obj in objects]
        roots = [obj.root_page for obj in objects]
        _error(len(names) == len(set(names)), "sqlite_schema object names are not unique")
        _error(len(roots) == len(set(roots)), "multiple sqlite_schema objects own one root page")
        _error(set(roots) == set(range(2, self.header.page_count + 1)),
               "SQLite pages are unowned or absent from sqlite_schema roots")
        return tuple(objects)

    def _columns(self, schema: SchemaObject) -> tuple[Column, ...]:
        _error(schema.sql is not None, f"table {schema.name!r} has no CREATE TABLE SQL")
        match = _CREATE_TABLE.fullmatch(schema.sql)
        _error(match is not None, f"table {schema.name!r} SQL is outside the emitted grammar")
        assert match is not None
        _error(match.group(1) == schema.name and schema.table_name == schema.name,
               f"table {schema.name!r} schema identity is inconsistent")
        pieces = match.group(2).split(", ")
        columns = []
        for piece in pieces:
            column_match = _COLUMN.fullmatch(piece)
            _error(column_match is not None,
                   f"column declaration {piece!r} is outside the emitted grammar")
            assert column_match is not None
            declared_type = column_match.group(2)
            primary_key = column_match.group(3) is not None
            _error(
                not (primary_key and declared_type == "BLOB"),
                f"column declaration {piece!r} uses an unsupported BLOB PRIMARY KEY",
            )
            columns.append(Column(
                column_match.group(1),
                declared_type,
                primary_key,
                primary_key and declared_type == "INTEGER",
            ))
        _error(columns and len({column.name for column in columns}) == len(columns),
               f"table {schema.name!r} has no columns or duplicate column names")
        _error(sum(column.primary_key for column in columns) <= 1,
               f"table {schema.name!r} has a composite or duplicate primary key")
        return tuple(columns)

    def _normalize_affinity(
        self, table: str, column: Column, value: SQLiteValue
    ) -> SQLiteValue:
        if value is None and not column.rowid_alias:
            _error(
                self.wire_profile is SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
                f"{table}.{column.name} is NULL outside the runtime-written emitted profile",
            )
            return None
        if column.rowid_alias:
            _error(isinstance(value, int) and not isinstance(value, bool),
                   f"{table}.{column.name} INTEGER PRIMARY KEY was not recovered")
        elif column.declared_type == "INTEGER":
            _error(isinstance(value, int) and not isinstance(value, bool),
                   f"{table}.{column.name} is not stored as INTEGER")
        elif column.declared_type == "REAL":
            _error(
                isinstance(value, (int, float)) and not isinstance(value, bool),
                f"{table}.{column.name} is not stored as numeric REAL",
            )
            # SQLite deliberately stores exact REAL values using compact integer serial
            # types, then applies REAL affinity when the row is read.
            value = float(value)
        elif column.declared_type == "TEXT":
            _error(isinstance(value, str), f"{table}.{column.name} is not stored as TEXT")
        elif column.declared_type == "BLOB":
            _error(type(value) is bytes, f"{table}.{column.name} is not stored as BLOB")
        return value

    def _table(self, schema: SchemaObject) -> Table:
        columns = self._columns(schema)
        cells = self._leaf_cells(schema.root_page, _TABLE_LEAF)
        rows = []
        previous_rowid = -(1 << 63) - 1
        rowid_aliases = [index for index, column in enumerate(columns) if column.rowid_alias]
        for cell in cells:
            assert cell.rowid is not None
            _error(cell.rowid > previous_rowid,
                   f"table {schema.name!r} rowids are not strictly increasing")
            previous_rowid = cell.rowid
            _error(len(cell.record.values) == len(columns),
                   f"table {schema.name!r} record width differs from its schema")
            values = list(cell.record.values)
            for index in rowid_aliases:
                _error(values[index] is None and cell.record.serial_types[index] == 0,
                       f"table {schema.name!r} INTEGER PRIMARY KEY is not a rowid alias")
                values[index] = cell.rowid
            values = [
                self._normalize_affinity(schema.name, column, value)
                for column, value in zip(columns, values, strict=True)
            ]
            rows.append(TableRow(cell.rowid, tuple(values), cell.record.serial_types))
        return Table(schema.name, schema.root_page, columns, tuple(rows))

    @staticmethod
    def _sort_value(value: SQLiteValue) -> tuple[int, object]:
        if value is None:
            return (0, 0)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return (1, value)
        if isinstance(value, str):
            return (2, value.encode("utf-8"))
        if isinstance(value, bytes):
            return (3, value)
        raise SQLiteSubsetError(f"unsupported SQLite index key type {type(value).__name__}")

    def _index(self, schema: SchemaObject, table: Table) -> Index:
        primary = tuple(column for column in table.columns
                        if column.primary_key and not column.rowid_alias)
        expected_name = f"sqlite_autoindex_{table.name}_1"
        _error(schema.sql is None and schema.name == expected_name,
               f"index {schema.name!r} is not the emitted PRIMARY KEY autoindex")
        _error(schema.table_name == table.name and len(primary) == 1,
               f"index {schema.name!r} has no single non-rowid PRIMARY KEY owner")
        positions = tuple(table.columns.index(column) for column in primary)
        cells = self._leaf_cells(schema.root_page, _INDEX_LEAF)
        entries = []
        for cell in cells:
            values = cell.record.values
            _error(len(values) == len(primary) + 1,
                   f"index {schema.name!r} record width is not key plus rowid")
            rowid = values[-1]
            _error(isinstance(rowid, int) and not isinstance(rowid, bool),
                   f"index {schema.name!r} row locator is not INTEGER")
            key = tuple(
                self._normalize_affinity(table.name, column, value)
                for column, value in zip(primary, values[:-1], strict=True)
            )
            entries.append(IndexEntry(key, rowid, cell.record.serial_types))

        ordering = [
            (tuple(self._sort_value(value) for value in entry.key), entry.rowid)
            for entry in entries
        ]
        _error(
            all(left < right for left, right in zip(ordering, ordering[1:])),
            f"index {schema.name!r} entries are not in strict SQLite key order",
        )

        expected = {
            (tuple(row.values[position] for position in positions), row.rowid)
            for row in table.rows
        }
        observed = {(entry.key, entry.rowid) for entry in entries}
        _error(len(observed) == len(entries), f"index {schema.name!r} has duplicate entries")
        _error(
            len({entry.key for entry in entries}) == len(entries),
            f"index {schema.name!r} PRIMARY KEY values are not unique",
        )
        _error(observed == expected,
               f"index {schema.name!r} entries do not own every table PRIMARY KEY row")
        return Index(
            schema.name,
            table.name,
            schema.root_page,
            tuple(column.name for column in primary),
            tuple(entries),
        )

    def read(self) -> SQLiteDatabase:
        schema = self._schema()
        table_schemas = tuple(obj for obj in schema if obj.kind == "table")
        index_schemas = tuple(obj for obj in schema if obj.kind == "index")
        tables = tuple(self._table(obj) for obj in table_schemas)
        by_name = {table.name: table for table in tables}
        _error(len(by_name) == len(tables), "duplicate table names")
        indexes = tuple(
            self._index(obj, by_name[obj.table_name])
            if obj.table_name in by_name
            else (_raise_unknown_index_owner(obj))
            for obj in index_schemas
        )
        expected_indexes = {
            f"sqlite_autoindex_{table.name}_1"
            for table in tables
            if any(column.primary_key and not column.rowid_alias for column in table.columns)
        }
        _error({index.name for index in indexes} == expected_indexes,
               "PRIMARY KEY autoindex ownership is incomplete or unexpected")
        return SQLiteDatabase(self.header, schema, tables, indexes)


def _raise_unknown_index_owner(schema: SchemaObject) -> Index:
    raise SQLiteSubsetError(
        f"index {schema.name!r} names unknown table {schema.table_name!r}"
    )


def loads_sqlite(
    data: bytes | bytearray | memoryview,
    *,
    limits: SQLiteLimits = DEFAULT_SQLITE_LIMITS,
    wire_profile: SQLiteWireProfile = DEFAULT_SQLITE_WIRE_PROFILE,
) -> SQLiteDatabase:
    """Decode bounded SQLite bytes in the exact rollback-mode emitted subset."""
    if not isinstance(limits, SQLiteLimits):
        raise TypeError("limits must be a SQLiteLimits instance")
    if not isinstance(wire_profile, SQLiteWireProfile):
        raise TypeError("wire_profile must be a SQLiteWireProfile")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("SQLite database input must be bytes-like")
    input_size = data.nbytes if isinstance(data, memoryview) else len(data)
    if input_size > limits.max_bytes:
        raise SQLiteSubsetError(
            f"SQLite database exceeds the {limits.max_bytes}-byte limit"
        )
    return _Reader(bytes(data), limits, wire_profile).read()


def load_sqlite(
    path: str | os.PathLike[str],
    *,
    limits: SQLiteLimits = DEFAULT_SQLITE_LIMITS,
    wire_profile: SQLiteWireProfile = DEFAULT_SQLITE_WIRE_PROFILE,
) -> SQLiteDatabase:
    """Read and decode one SQLite database without an unbounded path read."""
    if not isinstance(limits, SQLiteLimits):
        raise TypeError("limits must be a SQLiteLimits instance")
    if not isinstance(wire_profile, SQLiteWireProfile):
        raise TypeError("wire_profile must be a SQLiteWireProfile")
    try:
        with open(path, "rb") as handle:
            data = handle.read(limits.max_bytes + 1)
    except (OSError, TypeError) as exc:
        raise SQLiteSubsetError(f"cannot read SQLite database {path!r}: {exc}") from exc
    return loads_sqlite(data, limits=limits, wire_profile=wire_profile)


__all__ = [
    "Column",
    "DEFAULT_SQLITE_LIMITS",
    "DEFAULT_SQLITE_WIRE_PROFILE",
    "Index",
    "IndexEntry",
    "SQLiteDatabase",
    "SQLiteHeader",
    "SQLiteLimits",
    "SQLiteRecord",
    "SQLiteSubsetError",
    "SQLiteValue",
    "SQLiteWireProfile",
    "SchemaObject",
    "Table",
    "TableRow",
    "decode_record",
    "decode_varint",
    "load_sqlite",
    "loads_sqlite",
]
