# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic bytes for ArtifactForge's deliberately small SQLite profile.

This is not a general SQLite implementation.  It emits a 4096-byte, UTF-8,
rollback-journal database in which ``sqlite_schema`` and every declared table or implicit
``TEXT PRIMARY KEY`` index fit on their own leaf root page.  It never emits interior,
overflow, freelist, pointer-map, freeblock, or fragmented-page state.

The writer is deliberately independent of the host SQLite library and of the filesystem.
Consequently database-header offset 96 is zero: no SQLite library wrote these bytes, and
claiming a host-dependent ``SQLITE_VERSION_NUMBER`` there would make cross-runtime output
differ and would misstate provenance.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import struct
from typing import TypeAlias
import unicodedata


SQLiteScalar: TypeAlias = None | int | float | str | bytes

PAGE_SIZE = 4096
# Offset 96 belongs to SQLite's last-writing-library version, not ArtifactForge's ABI.
# Zero is an honest sentinel because no SQLite library emitted these bytes.  The independent
# producer/wire identity below must be bound by callers; the sentinel alone is not provenance.
SQLITE_LIBRARY_VERSION_SENTINEL = 0
OWNED_SQLITE_WIRE_PROFILE = "artifactforge-owned-sqlite-leaf-v1"

_MAGIC = b"SQLite format 3\x00"
_TABLE_LEAF = 0x0D
_INDEX_LEAF = 0x0A
_TABLE_MAX_LOCAL = PAGE_SIZE - 35
_INDEX_MAX_LOCAL = ((PAGE_SIZE - 12) * 64) // 255 - 23
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DECLARED_TYPES = frozenset(("INTEGER", "TEXT", "REAL", "BLOB"))
# The complete 147-token set published by SQLite.  Our raw-reader schema grammar is
# intentionally unquoted, so accepting any of these would let the byte writer construct SQL
# that the real SQLite parser may interpret as syntax rather than an identifier.
_KEYWORDS = frozenset(
    """ABORT ACTION ADD AFTER ALL ALTER ALWAYS ANALYZE AND AS ASC ATTACH AUTOINCREMENT
    BEFORE BEGIN BETWEEN BY CASCADE CASE CAST CHECK COLLATE COLUMN COMMIT CONFLICT CONSTRAINT
    CREATE CROSS CURRENT CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP DATABASE DEFAULT DEFERRABLE
    DEFERRED DELETE DESC DETACH DISTINCT DO DROP EACH ELSE END ESCAPE EXCEPT EXCLUDE EXCLUSIVE
    EXISTS EXPLAIN FAIL FILTER FIRST FOLLOWING FOR FOREIGN FROM FULL GENERATED GLOB GROUP GROUPS
    HAVING IF IGNORE IMMEDIATE IN INDEX INDEXED INITIALLY INNER INSERT INSTEAD INTERSECT INTO IS
    ISNULL JOIN KEY LAST LEFT LIKE LIMIT MATCH MATERIALIZED NATURAL NO NOT NOTHING NOTNULL NULL
    NULLS OF OFFSET ON OR ORDER OTHERS OUTER OVER PARTITION PLAN PRAGMA PRECEDING PRIMARY QUERY
    RAISE RANGE RECURSIVE REFERENCES REGEXP REINDEX RELEASE RENAME REPLACE RESTRICT RETURNING
    RIGHT ROLLBACK ROW ROWS SAVEPOINT SELECT SET TABLE TEMP TEMPORARY THEN TIES TO TRANSACTION
    TRIGGER UNBOUNDED UNION UNIQUE UPDATE USING VACUUM VALUES VIEW VIRTUAL WHEN WHERE WINDOW WITH
    WITHOUT""".split()
)
_MAX_TABLES = 16
_MAX_COLUMNS = 64
_MAX_ROWS = 1024
_MAX_IDENTIFIER_CHARACTERS = 128
_MAX_TEXT_CHARACTERS = _TABLE_MAX_LOCAL
_MAX_BLOB_BYTES = 2048
_MAX_AGGREGATE_SCALARS = 16_384
_MAX_AGGREGATE_TEXT_BYTES = 32 * 1024
_MAX_AGGREGATE_BLOB_BYTES = 32 * 1024


class SQLiteBuildError(ValueError):
    """A schema or value cannot be represented by the owned SQLite profile."""


@dataclass(frozen=True)
class ColumnSpec:
    """One column in the bounded SQL grammar emitted by ArtifactForge's writer."""

    name: str
    declared_type: str
    primary_key: bool = False


@dataclass(frozen=True)
class TableSpec:
    """One rowid table and its rows.

    Rows without an ``INTEGER PRIMARY KEY`` receive rowids 1..N in input order.  When an
    integer primary-key alias exists, its supplied values are the rowids and rows are emitted
    in signed-rowid order.  A single ``TEXT PRIMARY KEY`` receives the one implicit SQLite
    autoindex required by an ordinary rowid table.
    """

    name: str
    columns: tuple[ColumnSpec, ...]
    rows: tuple[tuple[SQLiteScalar, ...], ...]


@dataclass(frozen=True)
class _PreparedTable:
    name: str
    columns: tuple[ColumnSpec, ...]
    rows: tuple[tuple[int, tuple[SQLiteScalar, ...]], ...]
    sql: str
    root_page: int
    index_root_page: int | None
    primary_key_position: int | None


def _identifier(value: object, *, where: str) -> str:
    if (
        type(value) is not str
        or len(value) > _MAX_IDENTIFIER_CHARACTERS
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise SQLiteBuildError(
            f"{where} must be an unquoted ASCII SQLite identifier matching "
            f"[A-Za-z_][A-Za-z0-9_]* within {_MAX_IDENTIFIER_CHARACTERS} characters"
        )
    if value.lower().startswith("sqlite_"):
        raise SQLiteBuildError(f"{where} uses SQLite's reserved sqlite_ prefix")
    if value.upper() in _KEYWORDS:
        raise SQLiteBuildError(f"{where} is an unquoted SQLite keyword")
    return value


def _varint(value: int) -> bytes:
    """Return the shortest SQLite varint for one unsigned 64-bit value."""
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise SQLiteBuildError("SQLite varint value must be an unsigned 64-bit integer")
    if value >= 1 << 56:
        high = value >> 8
        groups = [0] * 8
        for index in range(7, -1, -1):
            groups[index] = 0x80 | (high & 0x7F)
            high >>= 7
        return bytes(groups) + bytes((value & 0xFF,))

    groups = [value & 0x7F]
    value >>= 7
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    groups.reverse()
    return bytes(
        byte | (0x80 if index < len(groups) - 1 else 0)
        for index, byte in enumerate(groups)
    )


def _signed_rowid_varint(value: int) -> bytes:
    if type(value) is not int or not -(1 << 63) <= value < 1 << 63:
        raise SQLiteBuildError("SQLite rowid must be a signed 64-bit integer (not bool)")
    return _varint(value if value >= 0 else value + (1 << 64))


def _integer_field(value: int) -> tuple[int, bytes]:
    if type(value) is not int or not -(1 << 63) <= value < 1 << 63:
        raise SQLiteBuildError("SQLite INTEGER must be a signed 64-bit integer (not bool)")
    if value == 0:
        return 8, b""
    if value == 1:
        return 9, b""
    for serial_type, width in ((1, 1), (2, 2), (3, 3), (4, 4), (5, 6), (6, 8)):
        bits = width * 8
        if -(1 << (bits - 1)) <= value < 1 << (bits - 1):
            return serial_type, value.to_bytes(width, "big", signed=True)
    raise AssertionError("signed 64-bit integer did not select a serial type")


def _field(value: SQLiteScalar) -> tuple[int, bytes]:
    if value is None:
        return 0, b""
    if type(value) is int:
        return _integer_field(value)
    if type(value) is float:
        if not math.isfinite(value):
            raise SQLiteBuildError("SQLite REAL must be finite")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise SQLiteBuildError("negative-zero SQLite REAL is outside the owned profile")
        return 7, struct.pack(">d", value)
    if type(value) is str:
        if len(value) > _MAX_TEXT_CHARACTERS:
            raise SQLiteBuildError(
                f"SQLite TEXT exceeds the {_MAX_TEXT_CHARACTERS}-character input limit"
            )
        if unicodedata.normalize("NFC", value) != value:
            raise SQLiteBuildError("SQLite TEXT must be Unicode NFC")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SQLiteBuildError("SQLite TEXT contains an unpaired Unicode surrogate") from exc
        return 13 + 2 * len(encoded), encoded
    if type(value) is bytes:
        if len(value) > _MAX_BLOB_BYTES:
            raise SQLiteBuildError(
                f"SQLite BLOB exceeds the {_MAX_BLOB_BYTES}-byte input limit"
            )
        return 12 + 2 * len(value), value
    raise SQLiteBuildError(
        f"unsupported SQLite value type {type(value).__name__}; "
        "expected None, int, finite float, str, or exact bytes"
    )


def _record(values: tuple[SQLiteScalar, ...]) -> bytes:
    fields = tuple(_field(value) for value in values)
    serials = b"".join(_varint(serial_type) for serial_type, _content in fields)
    header_size = len(serials) + 1
    while True:
        encoded_size = _varint(header_size)
        actual_size = len(encoded_size) + len(serials)
        if actual_size == header_size:
            break
        header_size = actual_size
    return encoded_size + serials + b"".join(content for _serial, content in fields)


def _table_cell(rowid: int, values: tuple[SQLiteScalar, ...]) -> bytes:
    payload = _record(values)
    if len(payload) > _TABLE_MAX_LOCAL:
        raise SQLiteBuildError(
            f"table record needs {len(payload)} payload bytes; overflow pages are unsupported"
        )
    return _varint(len(payload)) + _signed_rowid_varint(rowid) + payload


def _index_cell(values: tuple[SQLiteScalar, ...]) -> bytes:
    payload = _record(values)
    if len(payload) > _INDEX_MAX_LOCAL:
        raise SQLiteBuildError(
            f"index record needs {len(payload)} payload bytes; overflow pages are unsupported"
        )
    return _varint(len(payload)) + payload


def _leaf_page(page_type: int, cells: tuple[bytes, ...], *, first_page: bool = False) -> bytes:
    if page_type not in (_TABLE_LEAF, _INDEX_LEAF):
        raise AssertionError("owned writer only supports leaf table and index pages")
    header_offset = 100 if first_page else 0
    pointer_end = header_offset + 8 + 2 * len(cells)
    content_start = PAGE_SIZE - sum(map(len, cells))
    if pointer_end > content_start:
        kind = "sqlite_schema" if first_page else "table/index"
        raise SQLiteBuildError(f"{kind} rows do not fit on one 4096-byte leaf root page")

    page = bytearray(PAGE_SIZE)
    page[header_offset] = page_type
    page[header_offset + 3:header_offset + 5] = len(cells).to_bytes(2, "big")
    page[header_offset + 5:header_offset + 7] = content_start.to_bytes(2, "big")

    cursor = PAGE_SIZE
    for index, cell in enumerate(cells):
        cursor -= len(cell)
        page[cursor:cursor + len(cell)] = cell
        pointer = header_offset + 8 + 2 * index
        page[pointer:pointer + 2] = cursor.to_bytes(2, "big")
    assert cursor == content_start
    return bytes(page)


def _validate_scalar(value: object, *, declared_type: str, where: str) -> SQLiteScalar:
    # Calling _field owns all scalar range, NFC, surrogate, float, bool, and type checks.
    _field(value)  # type: ignore[arg-type]
    if value is None:
        return None
    if declared_type == "INTEGER" and type(value) is not int:
        raise SQLiteBuildError(f"{where} must be INTEGER or NULL")
    if declared_type == "TEXT" and type(value) is not str:
        raise SQLiteBuildError(f"{where} must be TEXT or NULL")
    if declared_type == "BLOB" and type(value) is not bytes:
        raise SQLiteBuildError(f"{where} must be exact bytes BLOB or NULL")
    if declared_type == "REAL":
        if type(value) not in (int, float):
            raise SQLiteBuildError(f"{where} must be numeric REAL or NULL")
        if type(value) is int:
            converted = float(value)
            if not math.isfinite(converted) or int(converted) != value:
                raise SQLiteBuildError(
                    f"{where} INTEGER input is not exactly representable as SQLite REAL"
                )
            return converted
    return value  # type: ignore[return-value]


def _prepare(tables: tuple[TableSpec, ...]) -> tuple[_PreparedTable, ...]:
    if type(tables) is not tuple:
        raise SQLiteBuildError("tables must be a tuple of TableSpec values")
    if not 1 <= len(tables) <= _MAX_TABLES:
        raise SQLiteBuildError(f"owned SQLite requires 1..{_MAX_TABLES} tables")

    table_names: set[str] = set()
    schema_names: set[str] = set()
    next_root = 2
    prepared: list[_PreparedTable] = []
    aggregate_scalars = 0
    aggregate_text_bytes = 0
    aggregate_blob_bytes = 0
    for table_index, table in enumerate(tables):
        if type(table) is not TableSpec:
            raise SQLiteBuildError(f"table {table_index} must be a TableSpec")
        name = _identifier(table.name, where=f"table {table_index} name")
        folded_name = name.lower()
        if folded_name in table_names:
            raise SQLiteBuildError(f"duplicate table name {name!r}")
        table_names.add(folded_name)
        schema_names.add(folded_name)

        if type(table.columns) is not tuple or not 1 <= len(table.columns) <= _MAX_COLUMNS:
            raise SQLiteBuildError(
                f"table {name!r} requires 1..{_MAX_COLUMNS} tuple columns"
            )
        columns: list[ColumnSpec] = []
        column_names: set[str] = set()
        primary_positions: list[int] = []
        for column_index, column in enumerate(table.columns):
            if type(column) is not ColumnSpec:
                raise SQLiteBuildError(
                    f"table {name!r} column {column_index} must be a ColumnSpec"
                )
            column_name = _identifier(
                column.name, where=f"table {name!r} column {column_index} name"
            )
            folded_column = column_name.lower()
            if folded_column in column_names:
                raise SQLiteBuildError(
                    f"table {name!r} has duplicate column {column_name!r}"
                )
            column_names.add(folded_column)
            if type(column.declared_type) is not str or column.declared_type not in _DECLARED_TYPES:
                raise SQLiteBuildError(
                    f"table {name!r} column {column_name!r} type must be "
                    "INTEGER, TEXT, REAL, or BLOB"
                )
            if type(column.primary_key) is not bool:
                raise SQLiteBuildError(
                    f"table {name!r} column {column_name!r} primary_key must be bool"
                )
            if column.primary_key:
                primary_positions.append(column_index)
            columns.append(column)
        if len(primary_positions) > 1:
            raise SQLiteBuildError(f"table {name!r} cannot have a composite primary key")
        primary_position = primary_positions[0] if primary_positions else None
        if (
            primary_position is not None
            and columns[primary_position].declared_type in ("REAL", "BLOB")
        ):
            raise SQLiteBuildError(
                f"table {name!r} primary key must be INTEGER or TEXT"
            )

        if type(table.rows) is not tuple or len(table.rows) > _MAX_ROWS:
            raise SQLiteBuildError(
                f"table {name!r} rows must be a tuple with at most {_MAX_ROWS} items"
            )
        rows: list[tuple[int, tuple[SQLiteScalar, ...]]] = []
        seen_rowids: set[int] = set()
        seen_text_keys: set[str] = set()
        for row_index, row in enumerate(table.rows):
            if type(row) is not tuple or len(row) != len(columns):
                raise SQLiteBuildError(
                    f"table {name!r} row {row_index} must be a {len(columns)}-item tuple"
                )
            aggregate_scalars += len(row)
            if aggregate_scalars > _MAX_AGGREGATE_SCALARS:
                raise SQLiteBuildError(
                    "owned SQLite input exceeds the 16384-scalar aggregate budget"
                )
            validated_values: list[SQLiteScalar] = []
            for column, value in zip(columns, row, strict=True):
                validated = _validate_scalar(
                    value,
                    declared_type=column.declared_type,
                    where=f"table {name!r} row {row_index} column {column.name!r}",
                )
                if type(validated) is str:
                    aggregate_text_bytes += len(validated.encode("utf-8"))
                    if aggregate_text_bytes > _MAX_AGGREGATE_TEXT_BYTES:
                        raise SQLiteBuildError(
                            "owned SQLite input exceeds the 32768-byte aggregate TEXT budget"
                        )
                elif type(validated) is bytes:
                    aggregate_blob_bytes += len(validated)
                    if aggregate_blob_bytes > _MAX_AGGREGATE_BLOB_BYTES:
                        raise SQLiteBuildError(
                            "owned SQLite input exceeds the 32768-byte aggregate BLOB budget"
                        )
                validated_values.append(validated)
            values = tuple(validated_values)
            if (
                primary_position is not None
                and columns[primary_position].declared_type == "INTEGER"
            ):
                rowid = values[primary_position]
                if type(rowid) is not int:
                    raise SQLiteBuildError(
                        f"table {name!r} INTEGER PRIMARY KEY row {row_index} cannot be NULL"
                    )
            else:
                rowid = row_index + 1
            assert type(rowid) is int
            _signed_rowid_varint(rowid)
            if rowid <= 0:
                raise SQLiteBuildError(
                    f"table {name!r} INTEGER PRIMARY KEY rowid must be positive"
                )
            if rowid in seen_rowids:
                raise SQLiteBuildError(f"table {name!r} has duplicate rowid {rowid}")
            seen_rowids.add(rowid)

            if (
                primary_position is not None
                and columns[primary_position].declared_type == "TEXT"
            ):
                key = values[primary_position]
                if type(key) is not str:
                    raise SQLiteBuildError(
                        f"table {name!r} TEXT PRIMARY KEY row {row_index} cannot be NULL"
                    )
                if key in seen_text_keys:
                    raise SQLiteBuildError(
                        f"table {name!r} has duplicate TEXT PRIMARY KEY {key!r}"
                    )
                seen_text_keys.add(key)
            rows.append((rowid, values))
        rows.sort(key=lambda item: item[0])

        declarations = ", ".join(
            f"{column.name} {column.declared_type}"
            + (" PRIMARY KEY" if column.primary_key else "")
            for column in columns
        )
        sql = f"CREATE TABLE {name} ({declarations})"
        root_page = next_root
        next_root += 1
        index_root_page = None
        if (
            primary_position is not None
            and columns[primary_position].declared_type == "TEXT"
        ):
            index_name = f"sqlite_autoindex_{name}_1"
            folded_index = index_name.lower()
            if folded_index in schema_names:
                raise SQLiteBuildError(f"duplicate schema object name {index_name!r}")
            schema_names.add(folded_index)
            index_root_page = next_root
            next_root += 1
        prepared.append(
            _PreparedTable(
                name,
                tuple(columns),
                tuple(rows),
                sql,
                root_page,
                index_root_page,
                primary_position,
            )
        )
    return tuple(prepared)


def _schema_cells(tables: tuple[_PreparedTable, ...]) -> tuple[bytes, ...]:
    cells: list[bytes] = []
    rowid = 1
    for table in tables:
        cells.append(
            _table_cell(
                rowid,
                ("table", table.name, table.name, table.root_page, table.sql),
            )
        )
        rowid += 1
        if table.index_root_page is not None:
            index_name = f"sqlite_autoindex_{table.name}_1"
            cells.append(
                _table_cell(
                    rowid,
                    ("index", index_name, table.name, table.index_root_page, None),
                )
            )
            rowid += 1
    return tuple(cells)


def _table_page(table: _PreparedTable) -> bytes:
    cells = []
    for rowid, values in table.rows:
        stored = list(values)
        if (
            table.primary_key_position is not None
            and table.columns[table.primary_key_position].declared_type == "INTEGER"
        ):
            stored[table.primary_key_position] = None
        cells.append(_table_cell(rowid, tuple(stored)))
    return _leaf_page(_TABLE_LEAF, tuple(cells))


def _index_page(table: _PreparedTable) -> bytes:
    position = table.primary_key_position
    if position is None or table.index_root_page is None:
        raise AssertionError("index page requested for a table without a TEXT PRIMARY KEY")
    entries = sorted(
        ((values[position], rowid) for rowid, values in table.rows),
        key=lambda item: (item[0].encode("utf-8"), item[1]),  # type: ignore[union-attr]
    )
    return _leaf_page(
        _INDEX_LEAF,
        tuple(_index_cell((key, rowid)) for key, rowid in entries),
    )


def _database_header(page_count: int, schema_cookie: int) -> bytes:
    header = bytearray(100)
    header[:16] = _MAGIC
    header[16:18] = PAGE_SIZE.to_bytes(2, "big")
    header[18:20] = b"\x01\x01"
    header[21:24] = b"\x40\x20\x20"
    header[24:28] = (1).to_bytes(4, "big")
    header[28:32] = page_count.to_bytes(4, "big")
    header[40:44] = schema_cookie.to_bytes(4, "big")
    header[44:48] = (4).to_bytes(4, "big")
    header[56:60] = (1).to_bytes(4, "big")
    header[92:96] = (1).to_bytes(4, "big")
    header[96:100] = SQLITE_LIBRARY_VERSION_SENTINEL.to_bytes(4, "big")
    return bytes(header)


def build_sqlite(tables: tuple[TableSpec, ...]) -> bytes:
    """Build one deterministic database in the owned leaf-root SQLite profile.

    The API intentionally requires tuples so it cannot accidentally consume an unbounded or
    stateful iterable.  Capacity is then proved by constructing each bounded leaf page; a
    record or collection that would require an overflow or interior page fails closed.
    """
    prepared = _prepare(tables)
    page_count = 1 + sum(1 + (table.index_root_page is not None) for table in prepared)
    schema_page = bytearray(_leaf_page(_TABLE_LEAF, _schema_cells(prepared), first_page=True))
    schema_page[:100] = _database_header(page_count, len(prepared))
    pages = [bytes(schema_page)]
    for table in prepared:
        pages.append(_table_page(table))
        if table.index_root_page is not None:
            pages.append(_index_page(table))
    if len(pages) != page_count:
        raise AssertionError("owned SQLite page allocation drifted from sqlite_schema")
    return b"".join(pages)


__all__ = [
    "ColumnSpec",
    "OWNED_SQLITE_WIRE_PROFILE",
    "PAGE_SIZE",
    "SQLITE_LIBRARY_VERSION_SENTINEL",
    "SQLiteBuildError",
    "SQLiteScalar",
    "TableSpec",
    "build_sqlite",
]
