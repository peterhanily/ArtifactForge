# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The LaunchAgent binary-plist oracle is independent, strict, and resource bounded."""
from __future__ import annotations

import ast
import plistlib
from pathlib import Path
import struct

import pytest

from artifactforge.gates.oracles.bplist_subset import (
    BinaryPlistError,
    BinaryPlistLimits,
    load_binary_plist,
    loads_binary_plist,
)


ROOT = Path(__file__).parents[1]
SAMPLES = sorted((ROOT / "samples" / "02-macos-quarantined-app").glob("*.plist"))


def _width(value: int) -> int:
    if value < 1 << 8:
        return 1
    if value < 1 << 16:
        return 2
    if value < 1 << 32:
        return 4
    return 8


def _bplist(
    objects: list[bytes],
    *,
    top: int = 0,
    offset_size: int | None = None,
    reference_size: int | None = None,
    reserved: bytes = b"\x00" * 6,
) -> bytes:
    """Assemble object-table test vectors without invoking the parser under test."""
    offsets = []
    cursor = 8
    for item in objects:
        offsets.append(cursor)
        cursor += len(item)
    table_offset = cursor
    offset_size = offset_size or _width(table_offset)
    reference_size = reference_size or _width(len(objects))
    table = b"".join(value.to_bytes(offset_size, "big") for value in offsets)
    trailer = (
        reserved
        + bytes((offset_size, reference_size))
        + struct.pack(">QQQ", len(objects), top, table_offset)
    )
    return b"bplist00" + b"".join(objects) + table + trailer


def _ascii(value: str) -> bytes:
    encoded = value.encode("ascii")
    if len(encoded) < 15:
        return bytes((0x50 | len(encoded),)) + encoded
    if len(encoded) < 256:
        return b"\x5f\x10" + bytes((len(encoded),)) + encoded
    return b"\x5f\x11" + len(encoded).to_bytes(2, "big") + encoded


def _same_types(left, right) -> None:
    assert type(left) is type(right)
    if isinstance(left, dict):
        assert list(left) == list(right)
        for key in left:
            _same_types(left[key], right[key])
    elif isinstance(left, list):
        assert len(left) == len(right)
        for left_item, right_item in zip(left, right):
            _same_types(left_item, right_item)
    else:
        assert left == right


@pytest.mark.parametrize("path", SAMPLES, ids=lambda path: path.name)
def test_committed_launchagents_match_plistlib_type_for_type(path):
    raw = path.read_bytes()
    expected = plistlib.loads(raw)
    from_bytes = loads_binary_plist(raw)
    from_path = load_binary_plist(path)

    _same_types(from_bytes, expected)
    _same_types(from_path, expected)
    assert set(from_bytes) == {
        "Label",
        "ProgramArguments",
        "RunAtLoad",
        "StartInterval",
        "artifactforge_synthetic",
        "artifactforge_synthetic_notice",
    }
    assert type(from_bytes["RunAtLoad"]) is bool
    assert type(from_bytes["StartInterval"]) is int


def test_reader_has_no_writer_or_standard_parser_imports():
    import artifactforge.gates.oracles.bplist_subset as module

    tree = ast.parse(Path(module.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "plistlib" not in imported
    assert not [name for name in imported if name.startswith("artifactforge.artifacts")]


def test_supported_scalars_collections_unicode_and_extended_lengths_are_type_exact():
    expected = {
        "array": list(range(20)),
        "false": False,
        "integer": 1,
        "long": "x" * 256,
        "reused": True,
        "true": True,
        "unicode": "café 🚀",
    }
    raw = plistlib.dumps(expected, fmt=plistlib.FMT_BINARY, sort_keys=True)
    actual = loads_binary_plist(raw)
    _same_types(actual, expected)
    assert type(actual["integer"]) is int
    assert type(actual["true"]) is bool


@pytest.mark.parametrize("value", [-1, 0, 255, 256, 65535, 65536, 2**32])
def test_canonical_emitted_integer_widths(value):
    raw = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
    parsed = loads_binary_plist(raw)
    assert parsed == value
    assert type(parsed) is int


def test_bytes_bytearray_and_memoryview_inputs_are_equivalent():
    raw = plistlib.dumps({"a": True}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    assert loads_binary_plist(raw) == {"a": True}
    assert loads_binary_plist(bytearray(raw)) == {"a": True}
    assert loads_binary_plist(memoryview(raw)) == {"a": True}


@pytest.mark.parametrize(
    "raw,match",
    [
        (b"", "too short"),
        (b"notplist" + b"\x00" * 40, "header"),
        (_bplist([b"\x09"], reserved=b"\x00" * 5 + b"\x01"), "reserved"),
        (_bplist([b"\x09"], top=1), "top object"),
        (_bplist([b"\x09"], offset_size=2), "offset width is not canonical"),
        (_bplist([b"\x09"], reference_size=2), "reference width is not canonical"),
    ],
)
def test_header_and_trailer_contract_is_strict(raw, match):
    with pytest.raises(BinaryPlistError, match=match):
        loads_binary_plist(raw)


def test_zero_objects_and_unknown_integer_widths_are_rejected():
    empty = (
        b"bplist00"
        + b"\x09\x08"
        + b"\x00" * 6
        + b"\x01\x01"
        + struct.pack(">QQQ", 0, 0, 8)
    )
    with pytest.raises(BinaryPlistError, match="at least one object"):
        loads_binary_plist(empty)

    raw = bytearray(_bplist([b"\x09"]))
    raw[-26] = 3
    with pytest.raises(BinaryPlistError, match="offset width"):
        loads_binary_plist(raw)
    raw = bytearray(_bplist([b"\x09"]))
    raw[-25] = 3
    with pytest.raises(BinaryPlistError, match="reference width"):
        loads_binary_plist(raw)


def test_offset_table_must_be_exact_bounded_unique_and_increasing():
    canonical = _bplist([b"\x09", b"\x08"])
    table_offset = struct.unpack_from(">Q", canonical, len(canonical) - 8)[0]

    wrong_end = bytearray(canonical)
    struct.pack_into(">Q", wrong_end, len(wrong_end) - 8, table_offset - 1)
    with pytest.raises(BinaryPlistError, match="does not end exactly"):
        loads_binary_plist(wrong_end)

    not_at_eight = bytearray(canonical)
    not_at_eight[table_offset] = 9
    with pytest.raises(BinaryPlistError, match="begin at byte 8"):
        loads_binary_plist(not_at_eight)

    duplicate = bytearray(canonical)
    duplicate[table_offset + 1] = duplicate[table_offset]
    with pytest.raises(BinaryPlistError, match="unique and increasing"):
        loads_binary_plist(duplicate)

    inside_table = bytearray(canonical)
    inside_table[table_offset + 1] = table_offset
    with pytest.raises(BinaryPlistError, match="offset table"):
        loads_binary_plist(inside_table)


@pytest.mark.parametrize(
    "object_bytes,match",
    [
        (b"\x11\x00\x01", "integer object width is not canonical"),
        (b"\x14" + b"\x00" * 16, "wider than eight"),
        (b"\x51\xff", "not valid"),
        (b"\x61\x00a", "noncanonically"),
        (b"\x09\x00", "trailing"),
        (b"\x00", "unsupported"),
        (b"\x22", "unsupported"),
        (b"\x40", "unsupported"),
        (b"\x80", "unsupported"),
    ],
)
def test_noncanonical_trailing_and_unsupported_objects_are_rejected(object_bytes, match):
    with pytest.raises(BinaryPlistError, match=match):
        loads_binary_plist(_bplist([object_bytes]))


def test_extended_lengths_are_supported_but_must_be_strict_and_minimal():
    assert loads_binary_plist(_bplist([b"\x5f\x10\x0f" + b"a" * 15])) == "a" * 15
    assert loads_binary_plist(_bplist([_ascii("a" * 256)])) == "a" * 256

    cases = [
        (b"\x5f\x10\x0e" + b"a" * 14, "short length"),
        (b"\x5f\x11\x00\x0f" + b"a" * 15, "width is not canonical"),
        (b"\x5f\x50", "must use an integer"),
        (b"\x5f\x14", "wider than eight"),
        (b"\x5f\x10", "extended length integer"),
        (b"\xaf\x10\x00", "short length"),
    ]
    for object_bytes, match in cases:
        with pytest.raises(BinaryPlistError, match=match):
            loads_binary_plist(_bplist([object_bytes]))


def test_missing_references_cycles_and_unreachable_objects_are_rejected():
    with pytest.raises(BinaryPlistError, match="missing object 1"):
        loads_binary_plist(_bplist([b"\xa1\x01"]))
    with pytest.raises(BinaryPlistError, match="cycle"):
        loads_binary_plist(_bplist([b"\xa1\x00"]))
    with pytest.raises(BinaryPlistError, match="unreachable objects: 1"):
        loads_binary_plist(_bplist([b"\x09", b"\x08"]))


def test_dictionary_keys_must_be_strings_unique_and_canonical_sorted():
    duplicate = _bplist([
        b"\xd2\x01\x01\x02\x03",
        _ascii("a"),
        b"\x09",
        b"\x08",
    ])
    with pytest.raises(BinaryPlistError, match="duplicate keys"):
        loads_binary_plist(duplicate)

    non_string = _bplist([b"\xd1\x01\x02", b"\x09", b"\x08"])
    with pytest.raises(BinaryPlistError, match="key is not a string"):
        loads_binary_plist(non_string)

    unsorted = _bplist([
        b"\xd2\x01\x02\x03\x04",
        _ascii("b"),
        _ascii("a"),
        b"\x09",
        b"\x08",
    ])
    with pytest.raises(BinaryPlistError, match="canonical-sorted"):
        loads_binary_plist(unsorted)


def test_reused_scalar_references_are_valid_and_do_not_look_like_cycles():
    raw = plistlib.dumps({"a": True, "b": True}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    assert loads_binary_plist(raw) == {"a": True, "b": True}


def test_every_resource_ceiling_fails_closed(tmp_path):
    small = _bplist([b"\x09"])
    with pytest.raises(BinaryPlistError, match="byte limit"):
        loads_binary_plist(small, limits=BinaryPlistLimits(max_bytes=len(small) - 1))
    with pytest.raises(BinaryPlistError, match="object limit"):
        loads_binary_plist(
            _bplist([b"\x09", b"\x08"]),
            limits=BinaryPlistLimits(max_objects=1),
        )
    with pytest.raises(BinaryPlistError, match="item limit"):
        loads_binary_plist(
            _bplist([b"\xa3\x01\x02\x03", b"\x09", b"\x08", b"\x10\x00"]),
            limits=BinaryPlistLimits(max_collection_items=2),
        )
    with pytest.raises(BinaryPlistError, match="reference limit"):
        loads_binary_plist(
            _bplist([b"\xa3\x01\x02\x03", b"\x09", b"\x08", b"\x10\x00"]),
            limits=BinaryPlistLimits(max_references=2),
        )
    with pytest.raises(BinaryPlistError, match="string exceeds"):
        loads_binary_plist(
            _bplist([_ascii("abcd")]),
            limits=BinaryPlistLimits(max_string_bytes=3),
        )

    nested = _bplist([b"\xa1\x01", b"\xa1\x02", b"\xa1\x03", b"\x09"])
    with pytest.raises(BinaryPlistError, match="nesting limit"):
        loads_binary_plist(nested, limits=BinaryPlistLimits(max_depth=2))

    path = tmp_path / "large.plist"
    path.write_bytes(small + b"padding")
    with pytest.raises(BinaryPlistError, match="byte limit"):
        load_binary_plist(path, limits=BinaryPlistLimits(max_bytes=len(small)))


@pytest.mark.parametrize(
    "field",
    [
        "max_bytes",
        "max_objects",
        "max_depth",
        "max_collection_items",
        "max_string_bytes",
        "max_references",
    ],
)
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_resource_limits_must_be_positive_integers(field, value):
    values = {field: value}
    with pytest.raises(ValueError, match=field):
        BinaryPlistLimits(**values)


def test_api_rejects_wrong_input_limit_and_unreadable_path(tmp_path):
    with pytest.raises(TypeError, match="bytes-like"):
        loads_binary_plist("not bytes")
    with pytest.raises(TypeError, match="BinaryPlistLimits"):
        loads_binary_plist(b"", limits=object())
    with pytest.raises(BinaryPlistError, match="cannot read"):
        load_binary_plist(tmp_path / "missing.plist")
