# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Bounded Chromium download-history bytes and responder query semantics."""
from __future__ import annotations

import dataclasses
import hashlib
import sqlite3

import pytest

from artifactforge.artifacts.windows import (
    WINDOWS_EPOCH_MICROSECONDS,
    ChromiumDownload,
    build_chromium_history,
)
from artifactforge.gates.oracles import SQLiteWireProfile, loads_sqlite


SEED = bytes(range(32))
START = WINDOWS_EPOCH_MICROSECONDS + 1_705_294_800_000_000
PE_ONE = hashlib.sha256(b"first emitted PE bytes").digest()
PE_TWO = hashlib.sha256(b"second emitted PE bytes").digest()
SOURCE_ONE = (
    "https://downloads.artifactforge.invalid/ARTIFACTFORGE/sha256/"
    f"{PE_ONE.hex()}/update.exe"
)
SOURCE_TWO = (
    "https://downloads.artifactforge.invalid/ARTIFACTFORGE/sha256/"
    f"{PE_TWO.hex()}/manual.pdf"
)
DOWNLOADS = (
    ChromiumDownload(
        target_path=r"C:\Users\v\AppData\Local\Temp\update.exe",
        source_url=SOURCE_ONE,
        referrer_url="https://portal.example/ARTIFACTFORGE/software",
        sha256=PE_ONE,
        size=2729,
        start_time_windows_us=START,
        end_time_windows_us=START + 2_000_000,
        opened=True,
        last_access_time_windows_us=START + 4_000_000,
    ),
    ChromiumDownload(
        target_path=r"C:\Users\v\Downloads\manual.pdf",
        source_url=SOURCE_TWO,
        referrer_url="https://portal.example/ARTIFACTFORGE/docs",
        sha256=PE_TWO,
        size=4096,
        start_time_windows_us=START + 10_000_000,
        end_time_windows_us=START + 12_000_000,
        opened=False,
        last_access_time_windows_us=0,
    ),
)


def _sqlite_rows(data: bytes, query: str) -> tuple[tuple, ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(data)
        connection.execute("PRAGMA query_only=ON")
        return tuple(connection.execute(query))
    finally:
        connection.close()


def test_chromium_history_is_deterministic_and_real_sqlite_recovers_the_join():
    data = build_chromium_history(DOWNLOADS, identity_seed=SEED)
    assert data == build_chromium_history(DOWNLOADS, identity_seed=SEED)
    assert len(data) == 4 * 4096

    rows = _sqlite_rows(
        data,
        "SELECT d.id,d.guid,d.target_path,d.hash,d.received_bytes,d.total_bytes,"
        "d.state,d.danger_type,d.start_time,d.end_time,d.opened,d.last_access_time,"
        "u.chain_index,u.url FROM downloads AS d JOIN downloads_url_chains AS u "
        "ON u.id=d.id ORDER BY d.id,u.chain_index",
    )
    assert len(rows) == 2
    assert rows[0][0] == 1
    assert rows[0][2:8] == (
        DOWNLOADS[0].target_path,
        b"",
        2729,
        2729,
        1,
        0,
    )
    assert rows[0][8:] == (
        START,
        START + 2_000_000,
        1,
        START + 4_000_000,
        0,
        DOWNLOADS[0].source_url,
    )
    assert rows[1][11] == 0
    assert rows[1][13] == DOWNLOADS[1].source_url


def test_raw_reader_agrees_on_blob_schema_rows_and_marker():
    data = build_chromium_history(DOWNLOADS, identity_seed=SEED)
    database = loads_sqlite(
        data, wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1
    )
    tables = {table.name: table for table in database.tables}
    assert set(tables) == {
        "downloads",
        "downloads_url_chains",
        "artifactforge_synthetic",
    }
    downloads = tables["downloads"]
    hash_index = [column.name for column in downloads.columns].index("hash")
    assert downloads.columns[hash_index].declared_type == "BLOB"
    assert [row.values[hash_index] for row in downloads.rows] == [b"", b""]
    assert [row.serial_types[hash_index] for row in downloads.rows] == [12, 12]
    assert tables["artifactforge_synthetic"].rows[0].values[0] == "ARTIFACTFORGE"


def test_identity_seed_changes_only_guid_identity_not_download_facts():
    left = build_chromium_history(DOWNLOADS, identity_seed=b"a" * 32)
    right = build_chromium_history(DOWNLOADS, identity_seed=b"b" * 32)
    query = (
        "SELECT guid,target_path,hex(hash),start_time,end_time FROM downloads ORDER BY id"
    )
    left_rows = _sqlite_rows(left, query)
    right_rows = _sqlite_rows(right, query)
    assert [row[0] for row in left_rows] != [row[0] for row in right_rows]
    assert [row[1:] for row in left_rows] == [row[1:] for row in right_rows]


class _OneShot:
    def __init__(self, rows):
        self._rows = rows
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("download builder iterated its input more than once")
        yield from self._rows


def test_download_input_is_materialised_once():
    rows = _OneShot(DOWNLOADS)
    assert build_chromium_history(rows, identity_seed=SEED).startswith(b"SQLite format 3\0")
    assert rows.iterations == 1


def test_unbounded_input_stops_after_the_ninth_pull():
    class Unbounded:
        def __init__(self):
            self.pulls = 0

        def __iter__(self):
            return self

        def __next__(self):
            self.pulls += 1
            return dataclasses.replace(
                DOWNLOADS[0],
                target_path=rf"C:\Users\v\Downloads\item-{self.pulls}.exe",
            )

    rows = Unbounded()
    with pytest.raises(ValueError, match="1..8"):
        build_chromium_history(rows, identity_seed=SEED)
    assert rows.pulls == 9


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("target_path", "relative.exe", "Windows drive path"),
        ("target_path", r"C:\Temp\..\update.exe", "Windows drive path"),
        ("source_url", "http://downloads.example/ARTIFACTFORGE/a", "reserved HTTPS"),
        ("source_url", "https://example.com/ARTIFACTFORGE/a", "reserved HTTPS"),
        ("referrer_url", "https://user@portal.example/ARTIFACTFORGE/a", "reserved HTTPS"),
        (
            "source_url",
            "https://downloads.example/ARTIFACTFORGE/sha256/"
            + (b"x" * 32).hex()
            + "/update.exe",
            "bind the lowercase SHA-256",
        ),
        (
            "source_url",
            SOURCE_ONE.replace(
                "/ARTIFACTFORGE/sha256/",
                "/ARTIFACTFORGE/sha256/" + PE_ONE.hex() + "/extra/sha256/",
            ),
            "bind the lowercase SHA-256",
        ),
        ("sha256", b"x" * 31, "32 immutable bytes"),
        ("sha256", bytearray(32), "32 immutable bytes"),
        ("size", True, "exact integer"),
        ("size", 0, "exact integer"),
        ("start_time_windows_us", True, "Windows timestamp"),
        ("start_time_windows_us", START + 1, "whole-second"),
        ("opened", 1, "must be bool"),
        ("last_access_time_windows_us", True, "Windows timestamp"),
    ),
)
def test_download_builder_rejects_values_outside_its_profile(field, value, match):
    row = dataclasses.replace(DOWNLOADS[0], **{field: value})
    with pytest.raises(ValueError, match=match):
        build_chromium_history((row,), identity_seed=SEED)


@pytest.mark.parametrize("seed", (b"", b"x" * 31, bytearray(32), None))
def test_identity_seed_is_exact_immutable_32_bytes(seed):
    with pytest.raises(ValueError, match="identity_seed"):
        build_chromium_history(DOWNLOADS, identity_seed=seed)


def test_download_builder_rejects_temporal_inversion_and_duplicate_identity():
    inverted = dataclasses.replace(
        DOWNLOADS[0], end_time_windows_us=DOWNLOADS[0].start_time_windows_us
    )
    with pytest.raises(ValueError, match="after start_time"):
        build_chromium_history((inverted,), identity_seed=SEED)

    last_access_inverted = dataclasses.replace(
        DOWNLOADS[0], last_access_time_windows_us=DOWNLOADS[0].start_time_windows_us
    )
    with pytest.raises(ValueError, match="must not precede"):
        build_chromium_history((last_access_inverted,), identity_seed=SEED)

    unopened_with_access = dataclasses.replace(
        DOWNLOADS[1], last_access_time_windows_us=DOWNLOADS[1].end_time_windows_us
    )
    with pytest.raises(ValueError, match="unopened row"):
        build_chromium_history((unopened_with_access,), identity_seed=SEED)

    duplicate = dataclasses.replace(DOWNLOADS[0])
    with pytest.raises(ValueError, match="target/hash identity"):
        build_chromium_history((DOWNLOADS[0], duplicate), identity_seed=SEED)
