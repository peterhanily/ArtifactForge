# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The emitted-profile SQLite oracle is independent, strict, and byte bounded."""
from __future__ import annotations

import ast
from pathlib import Path
import sqlite3
import struct

import pytest

from artifactforge.gates.oracles.sqlite_subset import (
    SQLiteDatabase,
    SQLiteLimits,
    SQLiteSubsetError,
    decode_record,
    decode_varint,
    load_sqlite,
    loads_sqlite,
)


ROOT = Path(__file__).parents[1]
SAMPLE_DIR = ROOT / "samples" / "02-macos-quarantined-app"
DATABASES = tuple(
    SAMPLE_DIR / name for name in ("knowledgeC.db", "TCC.db", "QuarantineEventsV2")
)
KNOWLEDGE = DATABASES[0]
QUARANTINE = DATABASES[2]
PAGE_SIZE = 4096


def _varint(value: int) -> bytes:
    """Independent canonical SQLite-varint assembler for boundary vectors."""
    if not 0 <= value < 1 << 64:
        raise ValueError(value)
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


def _test_decode_varint(data: bytes | bytearray, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(8):
        byte = data[offset + index]
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            return value, offset + index + 1
    return (value << 8) | data[offset + 8], offset + 9


def _record(*fields: tuple[int, bytes]) -> bytes:
    """Assemble a record from explicit serial types, independently of the oracle."""
    serials = b"".join(_varint(serial_type) for serial_type, _content in fields)
    header_size = len(serials) + 1
    while len(_varint(header_size)) + len(serials) != header_size:
        header_size = len(_varint(header_size)) + len(serials)
    return _varint(header_size) + serials + b"".join(content for _serial, content in fields)


def _replace(raw: bytes, offset: int, replacement: bytes) -> bytes:
    mutated = bytearray(raw)
    mutated[offset:offset + len(replacement)] = replacement
    return bytes(mutated)


def _page_start(page_number: int) -> int:
    return (page_number - 1) * PAGE_SIZE


def _btree_header(raw: bytes | bytearray, page_number: int) -> int:
    return _page_start(page_number) + (100 if page_number == 1 else 0)


def _cell_pointers(raw: bytes | bytearray, page_number: int) -> list[int]:
    header = _btree_header(raw, page_number)
    count = int.from_bytes(raw[header + 3:header + 5], "big")
    return [
        int.from_bytes(raw[header + 8 + index * 2:header + 10 + index * 2], "big")
        for index in range(count)
    ]


def _swap_pointers(raw: bytes, page_number: int, left: int, right: int) -> bytes:
    mutated = bytearray(raw)
    header = _btree_header(mutated, page_number)
    left_offset = header + 8 + left * 2
    right_offset = header + 8 + right * 2
    left_value = bytes(mutated[left_offset:left_offset + 2])
    right_value = bytes(mutated[right_offset:right_offset + 2])
    mutated[left_offset:left_offset + 2] = right_value
    mutated[right_offset:right_offset + 2] = left_value
    return bytes(mutated)


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _assert_type_exact(left: object, right: object) -> None:
    assert type(left) is type(right)
    assert left == right


@pytest.mark.parametrize("path", DATABASES, ids=lambda path: path.name)
def test_committed_databases_match_sqlite3_row_for_row_and_type_for_type(path):
    database = load_sqlite(path)
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        schema_rows = connection.execute(
            "SELECT rowid, type, name, tbl_name, rootpage, sql "
            "FROM sqlite_schema ORDER BY rowid"
        ).fetchall()
        assert [
            (item.rowid, item.kind, item.name, item.table_name, item.root_page, item.sql)
            for item in database.schema
        ] == schema_rows

        for table in database.tables:
            info = connection.execute(f"PRAGMA table_info({_quote(table.name)})").fetchall()
            assert [
                (column.name, column.declared_type, column.primary_key)
                for column in table.columns
            ] == [(row[1], row[2], bool(row[5])) for row in info]
            expected = connection.execute(
                f"SELECT rowid, * FROM {_quote(table.name)} ORDER BY rowid"
            ).fetchall()
            actual = [(row.rowid, *row.values) for row in table.rows]
            assert len(actual) == len(expected)
            for actual_row, expected_row in zip(actual, expected, strict=True):
                for actual_value, expected_value in zip(
                    actual_row, expected_row, strict=True
                ):
                    _assert_type_exact(actual_value, expected_value)

        for index in database.indexes:
            info = connection.execute(f"PRAGMA index_info({_quote(index.name)})").fetchall()
            assert index.columns == tuple(row[2] for row in info)
            selected = ", ".join(_quote(column) for column in index.columns)
            ordering = ", ".join((*(_quote(column) for column in index.columns), "rowid"))
            expected = connection.execute(
                f"SELECT {selected}, rowid FROM {_quote(index.table_name)} "
                f"ORDER BY {ordering}"
            ).fetchall()
            actual = [(*entry.key, entry.rowid) for entry in index.entries]
            assert actual == expected
    finally:
        connection.close()


def test_integer_primary_key_is_recovered_from_rowid_but_serial_type_is_retained():
    table = load_sqlite(KNOWLEDGE).table("ZOBJECT")
    assert [row.values[0] for row in table.rows] == [row.rowid for row in table.rows]
    assert [row.serial_types[0] for row in table.rows] == [0, 0, 0]
    assert table.columns[0].rowid_alias


def test_real_affinity_normalizes_compact_integer_serials_to_float():
    table = load_sqlite(KNOWLEDGE).table("ZOBJECT")
    assert {row.serial_types[3:5] for row in table.rows} == {(4, 4)}
    assert all(type(value) is float for row in table.rows for value in row.values[3:5])


def test_quarantine_uuid_autoindex_is_discovered_owned_and_complete():
    database = load_sqlite(QUARANTINE)
    table = database.table("LSQuarantineEvent")
    index = database.index("sqlite_autoindex_LSQuarantineEvent_1")
    assert index.table_name == table.name
    assert index.columns == ("LSQuarantineEventIdentifier",)
    assert {(entry.key[0], entry.rowid) for entry in index.entries} == {
        (row.values[0], row.rowid) for row in table.rows
    }
    assert [entry.key for entry in index.entries] == sorted(
        entry.key for entry in index.entries
    )


def test_reader_has_no_sqlite_writer_or_artifact_imports():
    import artifactforge.gates.oracles.sqlite_subset as module

    tree = ast.parse(Path(module.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "sqlite3" not in imported
    assert not [name for name in imported if name.startswith("artifactforge")]


_VARINT_BOUNDARIES = sorted(
    {
        0,
        1,
        127,
        *(value for bits in range(7, 57, 7) for value in ((1 << bits) - 1, 1 << bits)),
        (1 << 63) - 1,
        1 << 63,
        (1 << 64) - 1,
    }
)


@pytest.mark.parametrize("value", _VARINT_BOUNDARIES)
def test_varint_decodes_every_length_boundary_including_nine_bytes(value):
    encoded = _varint(value)
    assert decode_varint(b"prefix" + encoded + b"suffix", 6, limit=6 + len(encoded)) == (
        value,
        6 + len(encoded),
    )
    assert len(encoded) == (9 if value >= 1 << 56 else max(1, (value.bit_length() + 6) // 7))


@pytest.mark.parametrize(
    "raw,match",
    [
        (b"", "truncated"),
        (b"\x80", "truncated"),
        (b"\x80\x00", "non-canonical"),
        (b"\x80" * 8, "truncated"),
        (b"\x80" * 8 + b"\x00", "non-canonical nine-byte"),
    ],
)
def test_varint_rejects_truncated_and_noncanonical_encodings(raw, match):
    with pytest.raises(SQLiteSubsetError, match=match):
        decode_varint(raw)


def test_varint_rejects_wrong_type_offset_and_limit():
    with pytest.raises(TypeError, match="bytes"):
        decode_varint(bytearray(b"\x00"))
    with pytest.raises(SQLiteSubsetError, match="truncated"):
        decode_varint(b"\x00", 1)
    with pytest.raises(SQLiteSubsetError, match="truncated"):
        decode_varint(b"\x81\x00", limit=1)


_INTEGER_SERIALS = (
    (1, 1, (-128, -2, 127)),
    (2, 2, (-32768, -129, 128, 32767)),
    (3, 3, (-(1 << 23), -32769, 32768, (1 << 23) - 1)),
    (4, 4, (-(1 << 31), -(1 << 23) - 1, 1 << 23, (1 << 31) - 1)),
    (5, 6, (-(1 << 47), -(1 << 31) - 1, 1 << 31, (1 << 47) - 1)),
    (6, 8, (-(1 << 63), -(1 << 47) - 1, 1 << 47, (1 << 63) - 1)),
)


@pytest.mark.parametrize(
    "serial_type,width,value",
    [
        (serial_type, width, value)
        for serial_type, width, values in _INTEGER_SERIALS
        for value in values
    ],
)
def test_record_decodes_every_canonical_signed_integer_serial_boundary(
    serial_type, width, value
):
    parsed = decode_record(_record((serial_type, value.to_bytes(width, "big", signed=True))))
    assert parsed.values == (value,)
    assert parsed.serial_types == (serial_type,)


@pytest.mark.parametrize(
    "serial_type,content,expected",
    [
        (0, b"", None),
        (7, struct.pack(">d", 3.25), 3.25),
        (8, b"", 0),
        (9, b"", 1),
        (12, b"", b""),
        (16, b"\x00\xff", b"\x00\xff"),
        (13, b"", ""),
        (15, b"a", "a"),
        (23, "café".encode(), "café"),
        (213, b"x" * 100, "x" * 100),
    ],
)
def test_record_decodes_null_real_constants_blob_text_and_multibyte_serials(
    serial_type, content, expected
):
    parsed = decode_record(_record((serial_type, content)))
    assert parsed.values == (expected,)
    assert type(parsed.values[0]) is type(expected)
    assert parsed.serial_types == (serial_type,)


def test_record_supports_multibyte_header_size_and_empty_record():
    parsed = decode_record(_record(*((0, b""),) * 127))
    assert parsed.values == (None,) * 127
    assert decode_record(b"\x01").values == ()


@pytest.mark.parametrize(
    "raw,match",
    [
        (b"", "empty"),
        (b"\x00", "header size"),
        (b"\x02\x80", "truncated"),
        (b"\x80\x02\x08", "non-canonical"),
        (b"\x03\x80\x08", "non-canonical"),
        (_record((10, b"")), "reserved"),
        (_record((11, b"")), "reserved"),
        (_record((1, b"\x00")), "non-canonical serial type"),
        (_record((2, b"\x00\x7f")), "non-canonical serial type"),
        (_record((7, struct.pack(">d", float("inf")))), "non-finite"),
        (_record((15, b"\xff")), "not valid UTF-8"),
        (_record((1, b"")), "truncated"),
        (_record((8, b"")) + b"\x00", "trailing"),
    ],
)
def test_record_rejects_reserved_noncanonical_invalid_and_unclaimed_bytes(raw, match):
    with pytest.raises(SQLiteSubsetError, match=match):
        decode_record(raw)


def test_record_rejects_wrong_input_type():
    with pytest.raises(TypeError, match="bytes"):
        decode_record(bytearray(b"\x01"))


@pytest.mark.parametrize(
    "offset,replacement,match",
    [
        (0, b"X", "magic"),
        (16, b"\x08\x00", "page size"),
        (18, b"\x02", "rollback-journal"),
        (19, b"\x02", "rollback-journal"),
        (20, b"\x01", "reserved bytes"),
        (21, b"\x20", "payload fractions"),
        (22, b"\x10", "payload fractions"),
        (23, b"\x10", "payload fractions"),
        (24, b"\x00\x00\x00\x00", "version-valid-for"),
        (28, b"\x00\x00\x00\x02", "page count"),
        (32, b"\x00\x00\x00\x01", "freelist"),
        (36, b"\x00\x00\x00\x01", "freelist"),
        (40, b"\x00\x00\x00\x00", "schema cookie"),
        (44, b"\x00\x00\x00\x03", "schema format"),
        (48, b"\x00\x00\x00\x01", "page-cache"),
        (52, b"\x00\x00\x00\x01", "auto-vacuum"),
        (56, b"\x00\x00\x00\x02", "UTF-8"),
        (60, b"\x00\x00\x00\x01", "user version"),
        (64, b"\x00\x00\x00\x01", "auto-vacuum"),
        (68, b"\x00\x00\x00\x01", "application id"),
        (72, b"\x01", "reserved header"),
        (92, b"\x00\x00\x00\x00", "version-valid-for"),
        (96, (2_999_999).to_bytes(4, "big"), "SQLite 3 release"),
    ],
)
def test_database_header_contract_rejects_every_out_of_profile_field(
    offset, replacement, match
):
    with pytest.raises(SQLiteSubsetError, match=match):
        loads_sqlite(_replace(KNOWLEDGE.read_bytes(), offset, replacement))


def test_database_header_rejects_short_partial_and_trailing_pages():
    with pytest.raises(SQLiteSubsetError, match="shorter"):
        loads_sqlite(b"SQLite")
    with pytest.raises(SQLiteSubsetError, match="inside a page"):
        loads_sqlite(KNOWLEDGE.read_bytes()[:-1])
    with pytest.raises(SQLiteSubsetError, match="inside a page"):
        loads_sqlite(KNOWLEDGE.read_bytes() + b"\x00")


def test_interior_table_and_wrong_leaf_page_types_are_rejected():
    raw = KNOWLEDGE.read_bytes()
    with pytest.raises(SQLiteSubsetError, match="interior b-tree"):
        loads_sqlite(_replace(raw, _page_start(2), b"\x05"))
    quarantine = QUARANTINE.read_bytes()
    with pytest.raises(SQLiteSubsetError, match="expected 0xa"):
        loads_sqlite(_replace(quarantine, _page_start(3), b"\x0d"))


def test_table_and_index_overflow_payload_claims_are_rejected_before_reading():
    raw = bytearray(KNOWLEDGE.read_bytes())
    table_pointer = _page_start(3) + _cell_pointers(raw, 3)[0]
    old_size, after = _test_decode_varint(raw, table_pointer)
    assert old_size < 4062 and after - table_pointer == 2
    raw[table_pointer:after] = _varint(4062)
    with pytest.raises(SQLiteSubsetError, match="overflow"):
        loads_sqlite(raw)

    raw = bytearray(QUARANTINE.read_bytes())
    index_pointer = _page_start(3) + _cell_pointers(raw, 3)[0]
    old_size, after = _test_decode_varint(raw, index_pointer)
    assert old_size < 1003 and after - index_pointer == 1
    # 1003 needs two bytes, so preserve the original page by using a table-cell vector above;
    # the index limit is independently exercised by changing the first two bytes and failing
    # before any payload offset is consumed.
    raw[index_pointer:index_pointer + 2] = _varint(1003)
    with pytest.raises(SQLiteSubsetError, match="overflow"):
        loads_sqlite(raw)


def test_duplicate_and_out_of_content_cell_pointers_are_rejected():
    raw = bytearray(KNOWLEDGE.read_bytes())
    header = _btree_header(raw, 2)
    pointers = _cell_pointers(raw, 2)
    raw[header + 10:header + 12] = pointers[0].to_bytes(2, "big")
    with pytest.raises(SQLiteSubsetError, match="duplicate cell pointers"):
        loads_sqlite(raw)

    raw = bytearray(KNOWLEDGE.read_bytes())
    raw[header + 8:header + 10] = b"\x00\x01"
    with pytest.raises(SQLiteSubsetError, match="outside content"):
        loads_sqlite(raw)


def test_fragment_count_freeblock_cycle_gap_and_tail_are_rejected():
    raw = QUARANTINE.read_bytes()
    header = _btree_header(raw, 1)
    first_freeblock = int.from_bytes(raw[header + 1:header + 3], "big")
    assert first_freeblock == 4088

    with pytest.raises(SQLiteSubsetError, match="fragmented"):
        loads_sqlite(_replace(raw, header + 7, b"\x01"))

    cycle = bytearray(raw)
    cycle[first_freeblock:first_freeblock + 2] = first_freeblock.to_bytes(2, "big")
    with pytest.raises(SQLiteSubsetError, match="strictly increasing"):
        loads_sqlite(cycle)

    gap = bytearray(raw)
    shifted = first_freeblock + 1
    gap[header + 1:header + 3] = shifted.to_bytes(2, "big")
    gap[shifted:shifted + 4] = b"\x00\x00" + (PAGE_SIZE - shifted).to_bytes(2, "big")
    with pytest.raises(SQLiteSubsetError, match="unclaimed cell-content gap"):
        loads_sqlite(gap)

    tail = bytearray(raw)
    tail[first_freeblock + 2:first_freeblock + 4] = (7).to_bytes(2, "big")
    with pytest.raises(SQLiteSubsetError, match="unclaimed cell-content tail"):
        loads_sqlite(tail)


def test_every_unparsed_gap_and_freeblock_body_byte_must_remain_zero():
    raw = bytearray(KNOWLEDGE.read_bytes())
    header = _btree_header(raw, 2)
    cell_count = int.from_bytes(raw[header + 3:header + 5], "big")
    pointer_end = header + 8 + 2 * cell_count
    content_start = _page_start(2) + int.from_bytes(raw[header + 5:header + 7], "big")
    assert content_start - pointer_end > 32
    payload = b"PAYLOAD-UNALLOCATED-NOT-PARSED"
    raw[pointer_end:pointer_end + len(payload)] = payload
    with pytest.raises(SQLiteSubsetError, match="non-zero bytes in unallocated space"):
        loads_sqlite(raw)

    raw = bytearray(QUARANTINE.read_bytes())
    header = _btree_header(raw, 1)
    freeblock = int.from_bytes(raw[header + 1:header + 3], "big")
    size = int.from_bytes(raw[freeblock + 2:freeblock + 4], "big")
    assert size == 8
    raw[freeblock + 4:freeblock + size] = b"HIDE"
    with pytest.raises(SQLiteSubsetError, match="non-zero unparsed bytes"):
        loads_sqlite(raw)


def test_table_rowid_and_index_key_pointer_order_are_logically_bound():
    with pytest.raises(SQLiteSubsetError, match="rowids are not strictly increasing"):
        loads_sqlite(_swap_pointers(KNOWLEDGE.read_bytes(), 2, 0, 1))
    with pytest.raises(SQLiteSubsetError, match="strict SQLite key order"):
        loads_sqlite(_swap_pointers(QUARANTINE.read_bytes(), 3, 0, 1))


def test_index_bytes_must_correspond_to_their_owning_table_rows():
    raw = bytearray(QUARANTINE.read_bytes())
    index = load_sqlite(QUARANTINE).index("sqlite_autoindex_LSQuarantineEvent_1")
    first_uuid = index.entries[0].key[0]
    assert isinstance(first_uuid, str) and first_uuid.startswith("1")
    start = _page_start(3)
    offset = raw.find(first_uuid.encode(), start, start + PAGE_SIZE)
    assert offset >= start
    raw[offset] = ord("0")
    with pytest.raises(SQLiteSubsetError, match="own every table PRIMARY KEY row"):
        loads_sqlite(raw)


def test_every_nonheader_page_must_have_one_schema_owner():
    raw = bytearray(KNOWLEDGE.read_bytes() + b"\x00" * PAGE_SIZE)
    raw[28:32] = (4).to_bytes(4, "big")
    with pytest.raises(SQLiteSubsetError, match="unowned or absent"):
        loads_sqlite(raw)


def test_schema_is_discovered_from_page_one_and_sql_grammar_is_bounded():
    raw = KNOWLEDGE.read_bytes()
    create = raw.find(b"CREATE TABLE ZOBJECT")
    assert create >= 0
    with pytest.raises(SQLiteSubsetError, match="outside the emitted grammar"):
        loads_sqlite(_replace(raw, create, b"X"))


def test_bytes_bytearray_memoryview_classmethod_and_path_apis_are_equivalent():
    raw = KNOWLEDGE.read_bytes()
    expected = loads_sqlite(raw)
    assert loads_sqlite(bytearray(raw)) == expected
    assert loads_sqlite(memoryview(raw)) == expected
    assert SQLiteDatabase.from_bytes(raw) == expected
    assert load_sqlite(KNOWLEDGE) == expected


def test_byte_page_and_path_resource_limits_fail_closed(tmp_path):
    raw = KNOWLEDGE.read_bytes()
    with pytest.raises(SQLiteSubsetError, match="byte limit"):
        loads_sqlite(raw, limits=SQLiteLimits(max_bytes=len(raw) - 1))
    with pytest.raises(SQLiteSubsetError, match="page limit"):
        loads_sqlite(raw, limits=SQLiteLimits(max_pages=2))

    oversized = tmp_path / "oversized.db"
    oversized.write_bytes(raw + b"x")
    with pytest.raises(SQLiteSubsetError, match="byte limit"):
        load_sqlite(oversized, limits=SQLiteLimits(max_bytes=len(raw)))


@pytest.mark.parametrize("field", ["max_bytes", "max_pages"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_resource_limits_must_be_positive_integers(field, value):
    with pytest.raises(ValueError, match=field):
        SQLiteLimits(**{field: value})


def test_api_rejects_wrong_input_limit_and_unreadable_path(tmp_path):
    with pytest.raises(TypeError, match="bytes-like"):
        loads_sqlite("not bytes")
    with pytest.raises(TypeError, match="SQLiteLimits"):
        loads_sqlite(b"", limits=object())
    with pytest.raises(SQLiteSubsetError, match="cannot read"):
        load_sqlite(tmp_path / "missing.db")


def test_package_exports_both_sqlite_and_binary_plist_oracles():
    from artifactforge.gates import oracles

    assert oracles.loads_sqlite is loads_sqlite
    assert callable(oracles.loads_binary_plist)
