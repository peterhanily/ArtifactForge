# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Owned SQLite bytes are deterministic, bounded, and accepted by real SQLite."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sqlite3

import pytest

from artifactforge.artifacts.sqlite_owned import (
    ColumnSpec,
    OWNED_SQLITE_WIRE_PROFILE,
    PAGE_SIZE,
    SQLITE_LIBRARY_VERSION_SENTINEL,
    SQLiteBuildError,
    TableSpec,
    build_sqlite,
)
from artifactforge.gates.oracles.sqlite_subset import (
    SQLiteSubsetError,
    SQLiteWireProfile,
    decode_record,
    decode_varint,
    loads_sqlite,
)


MIXED_SPEC = (
    TableSpec(
        "events",
        (
            ColumnSpec("id", "INTEGER", primary_key=True),
            ColumnSpec("label", "TEXT"),
            ColumnSpec("score", "REAL"),
            ColumnSpec("count", "INTEGER"),
        ),
        (
            (127, "edge", 1.5, -129),
            (1, "one", 2.25, 1),
            (1 << 56, "huge", 0.0, 0),
            (128, "wide", 3.5, 127),
        ),
    ),
    TableSpec(
        "lookup",
        (
            ColumnSpec("token", "TEXT", primary_key=True),
            ColumnSpec("value", "INTEGER"),
        ),
        (("é", 1), ("z", 0), ("", -129)),
    ),
)

BLOB_SPEC = (
    TableSpec(
        "payloads",
        (
            ColumnSpec("id", "INTEGER", primary_key=True),
            ColumnSpec("payload", "BLOB"),
            ColumnSpec("label", "TEXT"),
        ),
        (
            (3, b"", "empty"),
            (1, b"\x00\xff", "binary"),
            (4, bytes(range(32)), "range"),
            (2, None, "missing"),
        ),
    ),
)


class _BytesSubclass(bytes):
    """A bytes-compatible object that the exact-type contract must still reject."""


def _query(data: bytes, sql: str) -> tuple[tuple, ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(data)
        connection.execute("PRAGMA query_only=ON")
        return tuple(connection.execute(sql))
    finally:
        connection.close()


def _page(data: bytes, page_number: int) -> bytes:
    start = (page_number - 1) * PAGE_SIZE
    return data[start:start + PAGE_SIZE]


def _cell_payloads(
    data: bytes, page_number: int, *, table_leaf: bool
) -> tuple[tuple[int | None, bytes, int, int], ...]:
    """Independently locate cells; return rowid, payload, physical start, and end."""
    page = _page(data, page_number)
    header = 100 if page_number == 1 else 0
    count = int.from_bytes(page[header + 3:header + 5], "big")
    pointers = tuple(
        int.from_bytes(page[header + 8 + 2 * index:header + 10 + 2 * index], "big")
        for index in range(count)
    )
    result = []
    for pointer in pointers:
        payload_size, cursor = decode_varint(page, pointer)
        rowid = None
        if table_leaf:
            unsigned, cursor = decode_varint(page, cursor)
            rowid = unsigned - (1 << 64) if unsigned >= 1 << 63 else unsigned
        end = cursor + payload_size
        result.append((rowid, page[cursor:end], pointer, end))
    return tuple(result)


def test_owned_database_is_cross_runtime_golden_and_header_is_exact():
    data = build_sqlite(MIXED_SPEC)
    assert data == build_sqlite(MIXED_SPEC)
    assert len(data) == 4 * PAGE_SIZE
    assert hashlib.sha256(data).hexdigest() == (
        "c195e75544c391aaebbb0811b02b8280ed7789fe06e34ee2c124f199e29fdb07"
    )

    expected = bytearray(100)
    expected[:16] = b"SQLite format 3\x00"
    expected[16:18] = b"\x10\x00"
    expected[18:20] = b"\x01\x01"
    expected[21:24] = b"\x40\x20\x20"
    expected[24:28] = b"\x00\x00\x00\x01"
    expected[28:32] = b"\x00\x00\x00\x04"
    expected[40:44] = b"\x00\x00\x00\x02"
    expected[44:48] = b"\x00\x00\x00\x04"
    expected[56:60] = b"\x00\x00\x00\x01"
    expected[92:96] = b"\x00\x00\x00\x01"
    expected[96:100] = SQLITE_LIBRARY_VERSION_SENTINEL.to_bytes(4, "big")
    assert data[:100] == expected
    assert SQLITE_LIBRARY_VERSION_SENTINEL == 0
    assert OWNED_SQLITE_WIRE_PROFILE == "artifactforge-owned-sqlite-leaf-v1"


def test_real_sqlite_accepts_owned_sentinel_schema_indexes_rows_and_integrity():
    data = build_sqlite(MIXED_SPEC)
    assert _query(data, "PRAGMA integrity_check") == (("ok",),)
    assert _query(data, "PRAGMA quick_check") == (("ok",),)
    assert _query(
        data,
        "SELECT rowid, type, name, tbl_name, rootpage, sql "
        "FROM sqlite_schema ORDER BY rowid",
    ) == (
        (
            1,
            "table",
            "events",
            "events",
            2,
            "CREATE TABLE events (id INTEGER PRIMARY KEY, label TEXT, score REAL, "
            "count INTEGER)",
        ),
        (
            2,
            "table",
            "lookup",
            "lookup",
            3,
            "CREATE TABLE lookup (token TEXT PRIMARY KEY, value INTEGER)",
        ),
        (3, "index", "sqlite_autoindex_lookup_1", "lookup", 4, None),
    )
    assert _query(data, "PRAGMA table_info(events)") == (
        (0, "id", "INTEGER", 0, None, 1),
        (1, "label", "TEXT", 0, None, 0),
        (2, "score", "REAL", 0, None, 0),
        (3, "count", "INTEGER", 0, None, 0),
    )
    assert _query(data, "PRAGMA index_info(sqlite_autoindex_lookup_1)") == (
        (0, 0, "token"),
    )
    assert _query(
        data,
        "SELECT rowid, id, label, score, typeof(score), count FROM events ORDER BY rowid",
    ) == (
        (1, 1, "one", 2.25, "real", 1),
        (127, 127, "edge", 1.5, "real", -129),
        (128, 128, "wide", 3.5, "real", 127),
        (1 << 56, 1 << 56, "huge", 0.0, "real", 0),
    )
    assert _query(data, "SELECT token, value FROM lookup ORDER BY token") == (
        ("", -129),
        ("z", 0),
        ("é", 1),
    )


def test_real_sqlite_opens_the_exact_owned_bytes_as_a_read_only_file(tmp_path):
    path = tmp_path / "owned.db"
    path.write_bytes(build_sqlite(MIXED_SPEC))
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT count(*) FROM events").fetchone() == (4,)
    finally:
        connection.close()
    assert path.read_bytes() == build_sqlite(MIXED_SPEC)


def test_raw_reader_accepts_exact_owned_bytes_only_under_the_named_wire_profile():
    data = build_sqlite(MIXED_SPEC)
    with pytest.raises(SQLiteSubsetError, match="SQLite 3 release"):
        loads_sqlite(data)
    parsed = loads_sqlite(
        data,
        wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
    )
    assert parsed.header.page_count == 4
    assert tuple(item.name for item in parsed.schema) == (
        "events",
        "lookup",
        "sqlite_autoindex_lookup_1",
    )
    assert tuple(row.rowid for row in parsed.table("events").rows) == (
        1,
        127,
        128,
        1 << 56,
    )
    assert tuple(entry.key for entry in parsed.index("sqlite_autoindex_lookup_1").entries) == (
        ("",),
        ("z",),
        ("é",),
    )


def test_blob_bytes_are_deterministic_and_real_sqlite_and_raw_records_agree():
    data = build_sqlite(BLOB_SPEC)
    assert data == build_sqlite(BLOB_SPEC)
    assert hashlib.sha256(data).hexdigest() == (
        "9fe3ec47db82c194cdf726c6b1140b0b98fdb74d9dff3b2e7b3382cedb824ca6"
    )
    assert _query(data, "PRAGMA integrity_check") == (("ok",),)

    sqlite_rows = _query(
        data,
        "SELECT rowid, id, payload, typeof(payload), hex(payload), label "
        "FROM payloads ORDER BY rowid",
    )
    assert sqlite_rows == (
        (1, 1, b"\x00\xff", "blob", "00FF", "binary"),
        (2, 2, None, "null", "", "missing"),
        (3, 3, b"", "blob", "", "empty"),
        (4, 4, bytes(range(32)), "blob", bytes(range(32)).hex().upper(), "range"),
    )

    # The independent raw record decoder intentionally shares no writer code.  Correct the
    # INTEGER PRIMARY KEY alias exactly as a full SQLite reader does, then compare values.
    raw_records = tuple(
        (rowid, decode_record(payload))
        for rowid, payload, _start, _end in _cell_payloads(data, 2, table_leaf=True)
    )
    assert tuple(
        (rowid, rowid, record.values[1], record.values[2])
        for rowid, record in raw_records
    ) == tuple(
        (rowid, item_id, payload, label)
        for rowid, item_id, payload, _, _, label in sqlite_rows
    )
    assert tuple(record.serial_types for _rowid, record in raw_records) == (
        (0, 16, 25),
        (0, 0, 27),
        (0, 12, 23),
        (0, 76, 23),
    )


def test_leaf_pages_have_sorted_pointers_contiguous_cells_and_zero_slack():
    data = build_sqlite(MIXED_SPEC)
    assert tuple(_page(data, number)[100 if number == 1 else 0] for number in range(1, 5)) == (
        0x0D,
        0x0D,
        0x0D,
        0x0A,
    )
    for page_number, table_leaf in ((1, True), (2, True), (3, True), (4, False)):
        page = _page(data, page_number)
        header = 100 if page_number == 1 else 0
        count = int.from_bytes(page[header + 3:header + 5], "big")
        content_start = int.from_bytes(page[header + 5:header + 7], "big")
        pointer_end = header + 8 + 2 * count
        assert page[header + 1:header + 3] == b"\x00\x00"  # no freeblocks
        assert page[header + 7] == 0  # no fragments
        assert not any(page[pointer_end:content_start])

        cells = _cell_payloads(data, page_number, table_leaf=table_leaf)
        physical = sorted((start, end) for _rowid, _payload, start, end in cells)
        assert physical[0][0] == content_start
        assert physical[-1][1] == PAGE_SIZE
        assert all(left_end == right_start for (_left, left_end), (right_start, _right) in zip(
            physical, physical[1:]
        ))


def test_rowid_alias_and_canonical_serial_types_are_exact_on_the_wire():
    cells = _cell_payloads(build_sqlite(MIXED_SPEC), 2, table_leaf=True)
    assert tuple(rowid for rowid, _payload, _start, _end in cells) == (
        1,
        127,
        128,
        1 << 56,
    )
    records = tuple(decode_record(payload) for _rowid, payload, _start, _end in cells)
    assert tuple(record.serial_types for record in records) == (
        (0, 19, 7, 9),
        (0, 21, 7, 2),
        (0, 21, 7, 1),
        (0, 21, 7, 8),
    )
    # The first legal nine-byte positive rowid boundary must use the SQLite eight-groups-plus-
    # final-byte form, not a non-canonical ten-byte or signed big-endian shortcut.
    page = _page(build_sqlite(MIXED_SPEC), 2)
    last_pointer = int.from_bytes(page[14:16], "big")
    _payload_size, after_size = decode_varint(page, last_pointer)
    rowid, after_rowid = decode_varint(page, after_size)
    assert rowid == 1 << 56
    assert after_rowid - after_size == 9


def test_schema_rowids_are_contiguous_and_cookie_counts_create_table_statements():
    data = build_sqlite(MIXED_SPEC)
    schema_cells = _cell_payloads(data, 1, table_leaf=True)
    assert tuple(rowid for rowid, _payload, _start, _end in schema_cells) == (1, 2, 3)
    assert int.from_bytes(data[40:44], "big") == 2


def test_text_primary_key_index_is_binary_sorted_key_plus_rowid():
    cells = _cell_payloads(build_sqlite(MIXED_SPEC), 4, table_leaf=False)
    records = tuple(decode_record(payload) for _rowid, payload, _start, _end in cells)
    assert tuple(record.values for record in records) == (("", 3), ("z", 2), ("é", 1))
    assert tuple(record.serial_types for record in records) == ((13, 1), (15, 1), (17, 9))


def test_empty_and_nullable_tables_are_valid_real_sqlite_databases():
    data = build_sqlite(
        (
            TableSpec("empty_items", (ColumnSpec("name", "TEXT"),), ()),
            TableSpec(
                "nullable_items",
                (
                    ColumnSpec("number", "INTEGER"),
                    ColumnSpec("text_value", "TEXT"),
                    ColumnSpec("real_value", "REAL"),
                ),
                ((None, None, None), (1, "", 2), (0, "ok", 2.5)),
            ),
        )
    )
    assert _query(data, "PRAGMA integrity_check") == (("ok",),)
    assert _query(data, "SELECT * FROM empty_items") == ()
    assert _query(
        data,
        "SELECT number, text_value, real_value, typeof(real_value) "
        "FROM nullable_items ORDER BY rowid",
    ) == ((None, None, None, "null"), (1, "", 2.0, "real"), (0, "ok", 2.5, "real"))
    nullable_records = _cell_payloads(data, 3, table_leaf=True)
    assert decode_record(nullable_records[1][1]).serial_types == (9, 13, 7)
    parsed = loads_sqlite(
        data,
        wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
    )
    assert parsed.table("nullable_items").rows[0].values == (None, None, None)


@pytest.mark.parametrize(
    "tables,match",
    [
        ([], "tables must be a tuple"),
        ((), "requires 1..16"),
        ((object(),), "must be a TableSpec"),
        ((TableSpec("bad-name", (ColumnSpec("x", "TEXT"),), ()),), "identifier"),
        ((TableSpec("x" * 129, (ColumnSpec("x", "TEXT"),), ()),), "128 characters"),
        ((TableSpec("select", (ColumnSpec("x", "TEXT"),), ()),), "keyword"),
        ((TableSpec("sqlite_hidden", (ColumnSpec("x", "TEXT"),), ()),), "reserved"),
        (
            (
                TableSpec("Things", (ColumnSpec("x", "TEXT"),), ()),
                TableSpec("things", (ColumnSpec("x", "TEXT"),), ()),
            ),
            "duplicate table",
        ),
        ((TableSpec("things", (), ()),), "1..64"),
        (
            (TableSpec("things", (ColumnSpec("Name", "TEXT"), ColumnSpec("name", "TEXT")), ()),),
            "duplicate column",
        ),
        (
            (TableSpec("things", (ColumnSpec("x", "blob"),), ()),),
            "INTEGER, TEXT, REAL, or BLOB",
        ),
        (
            (TableSpec("things", (ColumnSpec("x", "TEXT", primary_key=1),), ()),),
            "primary_key must be bool",
        ),
        (
            (TableSpec("things", (ColumnSpec("x", "REAL", primary_key=True),), ()),),
            "primary key must be INTEGER or TEXT",
        ),
        (
            (TableSpec("things", (ColumnSpec("x", "BLOB", primary_key=True),), ()),),
            "primary key must be INTEGER or TEXT",
        ),
        (
            (
                TableSpec(
                    "things",
                    (
                        ColumnSpec("x", "INTEGER", primary_key=True),
                        ColumnSpec("y", "TEXT", primary_key=True),
                    ),
                    (),
                ),
            ),
            "composite",
        ),
        ((TableSpec("things", (ColumnSpec("x", "TEXT"),), []),), "rows must be a tuple"),
        ((TableSpec("things", (ColumnSpec("x", "TEXT"),), (("x", "y"),)),), "1-item"),
    ],
)
def test_schema_and_container_contracts_fail_closed(tables, match):
    with pytest.raises(SQLiteBuildError, match=match):
        build_sqlite(tables)


@pytest.mark.parametrize(
    "column,value,match",
    [
        (ColumnSpec("x", "INTEGER"), True, "unsupported"),
        (ColumnSpec("x", "INTEGER"), 1.5, "INTEGER or NULL"),
        (ColumnSpec("x", "INTEGER"), 1 << 63, "signed 64-bit"),
        (ColumnSpec("x", "INTEGER"), -(1 << 63) - 1, "signed 64-bit"),
        (ColumnSpec("x", "TEXT"), b"bytes", "TEXT or NULL"),
        (ColumnSpec("x", "TEXT"), 1, "TEXT or NULL"),
        (ColumnSpec("x", "TEXT"), "e\N{COMBINING ACUTE ACCENT}", "Unicode NFC"),
        (ColumnSpec("x", "TEXT"), "\ud800", "surrogate"),
        (ColumnSpec("x", "TEXT"), "x" * 4062, "character input limit"),
        (ColumnSpec("x", "REAL"), "1.0", "numeric REAL"),
        (ColumnSpec("x", "REAL"), float("nan"), "finite"),
        (ColumnSpec("x", "REAL"), float("inf"), "finite"),
        (ColumnSpec("x", "REAL"), -0.0, "negative-zero"),
        (ColumnSpec("x", "BLOB"), bytearray(b"x"), "unsupported.*bytearray"),
        (ColumnSpec("x", "BLOB"), memoryview(b"x"), "unsupported.*memoryview"),
        (ColumnSpec("x", "BLOB"), True, "unsupported.*bool"),
        (ColumnSpec("x", "BLOB"), "x", "exact bytes BLOB"),
        (ColumnSpec("x", "BLOB"), _BytesSubclass(b"x"), "unsupported.*_BytesSubclass"),
        (ColumnSpec("x", "BLOB"), b"x" * 2049, "2048-byte input limit"),
    ],
)
def test_scalar_types_ranges_and_normal_forms_fail_closed(column, value, match):
    with pytest.raises(SQLiteBuildError, match=match):
        build_sqlite((TableSpec("things", (column,), ((value,),)),))


@pytest.mark.parametrize(
    "column,rows,match",
    [
        (ColumnSpec("id", "INTEGER", primary_key=True), ((None,),), "cannot be NULL"),
        (ColumnSpec("id", "INTEGER", primary_key=True), ((0,),), "must be positive"),
        (ColumnSpec("id", "INTEGER", primary_key=True), ((-1,),), "must be positive"),
        (ColumnSpec("id", "INTEGER", primary_key=True), ((1,), (1,)), "duplicate rowid"),
        (ColumnSpec("token", "TEXT", primary_key=True), ((None,),), "cannot be NULL"),
        (
            ColumnSpec("token", "TEXT", primary_key=True),
            (("same",), ("same",)),
            "duplicate TEXT PRIMARY KEY",
        ),
    ],
)
def test_primary_key_identity_failures_are_rejected(column, rows, match):
    with pytest.raises(SQLiteBuildError, match=match):
        build_sqlite((TableSpec("things", (column,), rows),))


def test_overflow_and_interior_pages_are_never_silently_introduced():
    with pytest.raises(SQLiteBuildError, match="index record.*overflow pages"):
        build_sqlite(
            (
                TableSpec(
                    "things",
                    (ColumnSpec("token", "TEXT", primary_key=True),),
                    (("x" * 1000,),),
                ),
            )
        )
    with pytest.raises(SQLiteBuildError, match="do not fit on one.*leaf root"):
        build_sqlite(
            (
                TableSpec(
                    "things",
                    (ColumnSpec("text_value", "TEXT"),),
                    tuple((f"{index:03d}-" + "x" * 96,) for index in range(100)),
                ),
            )
        )


def test_aggregate_scalar_budget_fails_before_leaf_page_construction():
    columns = tuple(ColumnSpec(f"c{index}", "INTEGER") for index in range(17))
    rows = tuple((0,) * len(columns) for _ in range(1024))
    with pytest.raises(SQLiteBuildError, match="16384-scalar aggregate budget"):
        build_sqlite((TableSpec("things", columns, rows),))


def test_aggregate_utf8_budget_counts_encoded_bytes_across_tables():
    tables = tuple(
        TableSpec(
            f"table_{index}",
            (ColumnSpec("value", "TEXT"),),
            (("x" * 4060,),),
        )
        for index in range(9)
    )
    with pytest.raises(SQLiteBuildError, match="32768-byte aggregate TEXT budget"):
        build_sqlite(tables)


def test_blob_value_and_aggregate_budgets_are_checked_before_page_assembly(monkeypatch):
    boundary = tuple(
        TableSpec(
            f"blob_table_{index}",
            (ColumnSpec("value", "BLOB"),),
            ((bytes((index,)) * 2048,),),
        )
        for index in range(16)
    )
    data = build_sqlite(boundary)
    assert _query(data, "SELECT length(value) FROM blob_table_15") == ((2048,),)

    over_budget = boundary[:-1] + (
        TableSpec(
            "blob_table_15",
            (ColumnSpec("value", "BLOB"),),
            ((b"x" * 2048,), (b"y",)),
        ),
    )

    def reject_page_assembly(*_args, **_kwargs):
        raise AssertionError("page assembly ran before the aggregate BLOB check")

    import artifactforge.artifacts.sqlite_owned as module

    monkeypatch.setattr(module, "_leaf_page", reject_page_assembly)
    with pytest.raises(SQLiteBuildError, match="32768-byte aggregate BLOB budget"):
        build_sqlite(over_budget)


def test_writer_imports_no_sqlite_filesystem_clock_or_entropy_modules():
    import artifactforge.artifacts.sqlite_owned as module

    tree = ast.parse(Path(module.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not imported & {
        "os",
        "pathlib",
        "random",
        "secrets",
        "sqlite3",
        "tempfile",
        "time",
    }
