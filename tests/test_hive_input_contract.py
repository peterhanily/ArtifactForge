# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Public hive builders reject inputs that cannot satisfy their Gate 1 profiles."""
from __future__ import annotations

import pytest

from artifactforge.artifacts.hive import build_amcache_hive, build_run_hive


def _run_rows(count: int):
    return [
        (f"Updater {index:02d}", rf"C:\ProgramData\ArtifactForge\agent{index:02d}.exe")
        for index in range(count)
    ]


def _amcache_rows(count: int):
    return [
        (
            f"{index + 1:040x}",
            rf"c:\programdata\artifactforge\agent{index:02d}.exe",
            f"Agent{index:02d}.exe",
            index,
            f"{index + 1:016x}",
        )
        for index in range(count)
    ]


@pytest.mark.parametrize(
    "builder,rows",
    ((build_run_hive, _run_rows), (build_amcache_hive, _amcache_rows)),
)
@pytest.mark.parametrize("count", (1, 64))
def test_public_hive_builders_accept_exact_row_boundaries(builder, rows, count):
    assert builder(rows(count)).startswith(b"regf")


@pytest.mark.parametrize(
    "builder,rows",
    ((build_run_hive, _run_rows), (build_amcache_hive, _amcache_rows)),
)
@pytest.mark.parametrize("count", (0, 65))
def test_public_hive_builders_reject_rows_outside_profile(builder, rows, count):
    with pytest.raises(ValueError, match=r"requires 1\.\.64 rows"):
        builder(rows(count))


@pytest.mark.parametrize(
    "builder,row",
    (
        (build_run_hive, lambda index: _run_rows(index + 1)[-1]),
        (build_amcache_hive, lambda index: _amcache_rows(index + 1)[-1]),
    ),
)
def test_public_hive_builders_consume_at_most_65_outer_items(builder, row):
    class InfiniteRows:
        iter_calls = 0
        yielded = 0

        def __iter__(self):
            self.iter_calls += 1
            while True:
                index = self.yielded
                self.yielded += 1
                yield row(index)

    source = InfiniteRows()
    with pytest.raises(ValueError, match=r"requires 1\.\.64 rows"):
        builder(source)
    assert source.iter_calls == 1
    assert source.yielded == 65


@pytest.mark.parametrize(
    "builder,rows",
    ((build_run_hive, _run_rows), (build_amcache_hive, _amcache_rows)),
)
def test_public_hive_builders_materialize_outer_and_row_generators_once(builder, rows):
    materialized = rows(2)
    expected = builder(materialized)
    generated = (iter(row) for row in materialized)
    assert builder(generated) == expected


@pytest.mark.parametrize("value", (None, "not rows", b"not rows", {"not": "rows"}))
@pytest.mark.parametrize("builder", (build_run_hive, build_amcache_hive))
def test_public_hive_builders_reject_non_row_iterables(builder, value):
    with pytest.raises(ValueError, match="iterable of rows|must be iterable"):
        builder(value)


@pytest.mark.parametrize(
    "builder,row",
    (
        (build_run_hive, ("Updater",)),
        (build_run_hive, ("Updater", r"C:\updater.exe", "extra")),
        (build_amcache_hive, ("a" * 40, r"c:\a.exe", "a.exe")),
        (build_amcache_hive, ("a" * 40, r"c:\a.exe", "a.exe", 1, "a", "extra")),
    ),
)
def test_public_hive_builders_reject_wrong_row_width(builder, row):
    with pytest.raises(ValueError, match="row 0 must contain"):
        builder([row])


def test_run_registry_name_limit_is_counted_in_utf16_code_units():
    ascii_limit = "A" * 255
    supplementary_limit = "A" + "\U0001f600" * 127
    path = r"C:\ProgramData\updater.exe"
    assert build_run_hive([(ascii_limit, path)]).startswith(b"regf")
    assert build_run_hive([(supplementary_limit, path)]).startswith(b"regf")

    for too_long in ("A" * 256, "\U0001f600" * 128):
        with pytest.raises(ValueError, match="255 UTF-16-code-unit"):
            build_run_hive([(too_long, path)])


@pytest.mark.parametrize(
    "name,match",
    (
        ("Cafe\u0301 Updater", "Unicode NFC"),
        ("Bad\nName", "control character"),
        ("Bad\u0085Name", "control character"),
        ("\ud800", "unpaired surrogate"),
    ),
)
def test_run_registry_names_are_canonical_control_safe_text(name, match):
    with pytest.raises(ValueError, match=match):
        build_run_hive([(name, r"C:\updater.exe")])


def test_run_value_names_are_unique_case_insensitively():
    with pytest.raises(ValueError, match="unique case-insensitively"):
        build_run_hive(
            [
                ("Windrow Updater", r"C:\windrow.exe"),
                ("WINDROW UPDATER", r"C:\decoy.exe"),
            ]
        )


def test_windows_path_limit_is_counted_in_utf16_code_units():
    at_limit = "C:\\" + "a" * 255 + "\\b"
    assert len(at_limit.encode("utf-16-le")) // 2 == 260
    assert build_run_hive([("Updater", at_limit)]).startswith(b"regf")

    with pytest.raises(ValueError, match="260 UTF-16-code-unit"):
        build_run_hive([("Updater", at_limit + "b")])


@pytest.mark.parametrize(
    "path",
    (
        r"relative\app.exe",
        r"C:app.exe",
        r"\\server\share\app.exe",
        r"C:/app.exe",
        r"C:\foo\..\app.exe",
        r"C:\foo\.\app.exe",
        r"C:\\app.exe",
        "C:\\app.exe\\",
        r"C:\bad?.exe",
        r"C:\NUL.txt",
        "C:\\bad ",
        r"1:\app.exe",
        "C:\\cafe\u0301.exe",
        "C:\\bad\u0085.exe",
    ),
)
def test_run_program_paths_are_bounded_normal_absolute_windows_paths(path):
    with pytest.raises(ValueError):
        build_run_hive([("Updater", path)])


@pytest.mark.parametrize(
    "sha1",
    (
        "a" * 39,
        "a" * 41,
        "A" * 40,
        "g" * 40,
        1,
    ),
)
def test_amcache_sha1_is_exact_lowercase_hex(sha1):
    with pytest.raises(ValueError, match="exactly 40 lowercase hex digits"):
        build_amcache_hive([(sha1, r"c:\a.exe", "a.exe", 1)])


@pytest.mark.parametrize("size", (True, False, -1, 1 << 32, "1", 1.0))
def test_amcache_size_is_uint32_not_bool(size):
    with pytest.raises(ValueError, match="uint32 integer"):
        build_amcache_hive([("a" * 40, r"c:\a.exe", "a.exe", size)])


@pytest.mark.parametrize("size", (0, 0xFFFFFFFF))
def test_amcache_size_accepts_exact_uint32_boundaries(size):
    assert build_amcache_hive(
        [("a" * 40, r"c:\a.exe", "a.exe", size)]
    ).startswith(b"regf")


@pytest.mark.parametrize(
    "record_key",
    ("", "A", "g", "a" * 65, 1),
)
def test_amcache_record_key_is_bounded_lowercase_hex(record_key):
    with pytest.raises(ValueError, match=r"1\.\.64 lowercase hexadecimal"):
        build_amcache_hive(
            [("a" * 40, r"c:\a.exe", "a.exe", 1, record_key)]
        )


@pytest.mark.parametrize("record_key", ("0", "a" * 64))
def test_amcache_record_key_accepts_exact_length_boundaries(record_key):
    assert build_amcache_hive(
        [("a" * 40, r"c:\a.exe", "a.exe", 1, record_key)]
    ).startswith(b"regf")


@pytest.mark.parametrize(
    "row,match",
    (
        (("a" * 40, r"C:\a.exe", "a.exe", 1), "canonical lowercase"),
        (("a" * 40, r"c:\a.exe", "different.exe", 1), "must match"),
        (("a" * 40, r"c:\a.exe", "a\u0301.exe", 1), "Unicode NFC"),
        (("a" * 40, r"c:\a.exe", "a\n.exe", 1), "control character"),
    ),
)
def test_amcache_path_and_name_identity_is_canonical(row, match):
    with pytest.raises(ValueError, match=match):
        build_amcache_hive([row])


@pytest.mark.parametrize("duplicate", ("file_id", "path", "record_key"))
def test_amcache_identities_are_unique(duplicate):
    first = ["a" * 40, r"c:\a.exe", "a.exe", 1, "01"]
    second = ["b" * 40, r"c:\b.exe", "b.exe", 2, "02"]
    if duplicate == "file_id":
        second[0] = first[0]
    elif duplicate == "path":
        second[1:3] = first[1:3]
    else:
        second[4] = first[4]

    with pytest.raises(ValueError, match="must be unique"):
        build_amcache_hive([first, second])


def test_four_field_amcache_rows_receive_unique_deterministic_record_keys():
    rows = [row[:4] for row in _amcache_rows(64)]
    assert build_amcache_hive(iter(rows)) == build_amcache_hive(rows)
