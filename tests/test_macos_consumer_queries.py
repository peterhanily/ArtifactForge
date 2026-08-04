# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Consumer-query compatibility for the bounded macOS SQLite profile.

These are query-surface tests, not claims that the reduced databases reproduce every table,
column or CoreData migration from a captured macOS installation.  The selected columns and
joins follow APOLLO's macOS 11--14 app-in-focus module and mac_apt's macOS 11+ TCC branch as
observed on 2026-08-03:

* https://github.com/mac4n6/APOLLO/blob/master/modules/knowledge_app_inFocus.txt
* https://github.com/ydkhatri/mac_apt/blob/master/plugins/tcc.py
"""
from __future__ import annotations

import hashlib
import math
import sqlite3

import pytest

from artifactforge.artifacts import macos
from artifactforge.artifacts.sqlite_owned import ColumnSpec, TableSpec, build_sqlite
from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME
from artifactforge.gates import validity
from artifactforge.gates.oracles.sqlite_subset import SQLiteWireProfile


KNOWLEDGE = (
    ("com.example.one", 100.0, 101.0),
    ("com.example.two", 200.0, 201.0),
    ("com.example.three", 300.0, 301.0),
)
TCC = (
    ("com.example.one", "kTCCServiceCamera", 2, 1_705_294_800),
    ("com.example.two", "kTCCServiceMicrophone", 2, 1_705_294_800),
    ("com.example.three", "kTCCServiceCamera", 0, 1_705_294_800),
    ("com.example.four", "kTCCServiceMicrophone", 0, 1_705_294_800),
)


def _profile_database(name: str, count: int) -> bytes:
    if name == "knowledgeC.db":
        return macos.build_knowledgec(
            tuple(
                (f"com.example.knowledge{i}", float(i * 100), float(i * 100 + 1))
                for i in range(1, count + 1)
            )
        )
    if name == "TCC.db":
        return macos.build_tcc(
            tuple(
                (
                    f"com.example.tcc{i}",
                    f"kTCCServiceSynthetic{i}",
                    2 if i % 2 else 0,
                    1_705_294_800 + i,
                )
                for i in range(1, count + 1)
            )
        )
    if name == "QuarantineEventsV2":
        return macos.build_quarantine_events(
            tuple(
                (
                    f"00000000-0000-4000-8000-{i:012X}",
                    "ArtifactForge",
                    f"https://downloads.example.test/file{i}.pkg",
                    "https://downloads.example.test/",
                    float(i * 100),
                )
                for i in range(1, count + 1)
            )
        )
    raise AssertionError(name)


def _query(data: bytes, sql: str) -> tuple[tuple, ...]:
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(data)
        con.execute("PRAGMA query_only=ON")
        return tuple(con.execute(sql))
    finally:
        con.close()


def test_profile_version_names_the_bounded_consumer_contract():
    assert macos.SQLITE_CONSUMER_PROFILE == "macos-11-14-consumer-v1"


def test_consumer_profile_stays_in_leaf_pages_at_the_public_eight_row_bound():
    knowledge = tuple(
        (
            (prefix := f"com.example.knowledge{i}.") + "k" * (128 - len(prefix)),
            float(100 * i),
            float(100 * i + 1),
        )
        for i in range(1, 9)
    )
    tcc = tuple(
        (
            (client := f"com.example.tcc{i}.") + "c" * (128 - len(client)),
            (service := f"kTCCServiceSynthetic{i}") + "s" * (96 - len(service)),
            2 if i % 2 else 0,
            1_705_294_800 + i,
        )
        for i in range(1, 9)
    )

    knowledge_bytes = macos.build_knowledgec(knowledge)
    tcc_bytes = macos.build_tcc(tcc)
    assert len(knowledge_bytes) == 5 * 4096
    assert len(tcc_bytes) == 3 * 4096
    assert validity._read_sqlite_raw(knowledge_bytes).tables
    assert validity._read_sqlite_raw(tcc_bytes).tables
    assert knowledge_bytes == macos.build_knowledgec(knowledge)
    assert tcc_bytes == macos.build_tcc(tcc)


@pytest.mark.parametrize("count", (1, 8))
@pytest.mark.parametrize(
    ("name", "query"),
    (
        (
            "knowledgeC.db",
            """
            SELECT COUNT(*)
            FROM ZOBJECT AS o
            LEFT JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA = m.Z_PK
            LEFT JOIN ZSOURCE AS s ON o.ZSOURCE = s.Z_PK
            WHERE o.ZSTREAMNAME IS '/app/inFocus'
              AND m.ZMETADATAHASH IS NOT NULL AND s.Z_PK IS NOT NULL
            """,
        ),
        (
            "TCC.db",
            """
            SELECT COUNT(*) FROM (
                SELECT service, client, client_type, auth_value, auth_reason,
                       indirect_object_identifier, last_modified
                FROM access
            )
            """,
        ),
        (
            "QuarantineEventsV2",
            """
            SELECT COUNT(*) FROM LSQuarantineEvent
            WHERE LSQuarantineEventIdentifier IS NOT NULL
            """,
        ),
    ),
)
def test_every_public_sqlite_cardinality_is_inside_the_gate_profile(
    tmp_path, name, query, count
):
    data = _profile_database(name, count)
    (tmp_path / name).write_bytes(data)

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()
    assert _query(data, query) == ((count,),)


def test_apollo_app_in_focus_query_shape_executes_and_resolves_both_joins():
    # This projects the fields in APOLLO's macOS 11--14 module.  ZSOURCE.Z_PK is the one
    # extra projection: APOLLO performs that join without selecting a source field, so the
    # test projects its key to prove the join resolved instead of merely parsing.
    rows = _query(
        macos.build_knowledgec(KNOWLEDGE),
        """
        SELECT
            DATETIME(o.ZSTARTDATE + 978307200, 'UNIXEPOCH'),
            DATETIME(o.ZENDDATE + 978307200, 'UNIXEPOCH'),
            o.ZVALUESTRING,
            o.ZENDDATE - o.ZSTARTDATE,
            (o.ZENDDATE - o.ZSTARTDATE) / 60.00,
            m.Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON,
            m.Z_DKAPPLICATIONMETADATAKEY__EXTENSIONCONTAININGBUNDLEIDENTIFIER,
            m.Z_DKAPPLICATIONMETADATAKEY__EXTENSIONHOSTIDENTIFIER,
            CASE o.ZSTARTDAYOFWEEK
                WHEN 1 THEN 'Sunday' WHEN 2 THEN 'Monday' WHEN 3 THEN 'Tuesday'
                WHEN 4 THEN 'Wednesday' WHEN 5 THEN 'Thursday' WHEN 6 THEN 'Friday'
                WHEN 7 THEN 'Saturday'
            END,
            o.ZSECONDSFROMGMT / 3600,
            DATETIME(o.ZCREATIONDATE + 978307200, 'UNIXEPOCH'),
            o.ZUUID,
            m.ZMETADATAHASH,
            o.Z_PK,
            s.Z_PK
        FROM ZOBJECT AS o
        LEFT JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA = m.Z_PK
        LEFT JOIN ZSOURCE AS s ON o.ZSOURCE = s.Z_PK
        WHERE o.ZSTREAMNAME IS '/app/inFocus'
        ORDER BY o.Z_PK
        """,
    )

    assert tuple(row[2] for row in rows) == tuple(item[0] for item in KNOWLEDGE)
    assert all(row[3] == 1.0 and row[4] == 1.0 / 60.0 for row in rows)
    assert all(row[5:8] == (0, "UNUSED", "UNUSED") for row in rows)
    assert all(row[8] and row[9] == 0 and row[10] == row[0] for row in rows)
    assert all(len(row[11]) == 36 and len(row[12]) == 64 for row in rows)
    assert tuple(row[13] for row in rows) == (1, 2, 3)
    assert tuple(row[14] for row in rows) == (1, 1, 1)


def test_mac_apt_macos11_tcc_query_shape_executes_and_preserves_meaning():
    rows = _query(
        macos.build_tcc(TCC),
        """
        SELECT
            DATETIME(last_modified, 'UNIXEPOCH'),
            service,
            client,
            client_type,
            CASE auth_value WHEN 0 THEN 'False' WHEN 2 THEN 'True' END,
            auth_reason,
            indirect_object_identifier
        FROM access
        ORDER BY rowid
        """,
    )

    assert tuple(row[2] for row in rows) == tuple(item[0] for item in TCC)
    assert tuple(row[4] for row in rows) == ("True", "True", "False", "False")
    assert all(row[0] and row[3] == 0 and row[5:] == (3, "UNUSED") for row in rows)


def test_knowledgec_allows_multiple_intervals_for_one_application(tmp_path):
    data = macos.build_knowledgec(
        (
            ("com.example.recurring", 100.0, 101.0),
            ("com.example.recurring", 200.0, 202.0),
        )
    )
    (tmp_path / "knowledgeC.db").write_bytes(data)

    report = validity.run(str(tmp_path))
    rows = _query(
        data,
        """
        SELECT o.ZVALUESTRING, o.ZSTARTDATE, o.ZENDDATE, m.ZMETADATAHASH
        FROM ZOBJECT AS o
        JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA = m.Z_PK
        ORDER BY o.Z_PK
        """,
    )

    assert report.ok, report.render()
    assert tuple(row[:3] for row in rows) == (
        ("com.example.recurring", 100.0, 101.0),
        ("com.example.recurring", 200.0, 202.0),
    )
    assert rows[0][3] == rows[1][3]


def test_fixture_v2_knowledge_identities_are_seeded_unique_and_self_validating(tmp_path):
    first = macos.build_knowledgec(KNOWLEDGE, identity_seed=b"a" * 32)
    repeated = macos.build_knowledgec(KNOWLEDGE, identity_seed=b"a" * 32)
    second = macos.build_knowledgec(KNOWLEDGE, identity_seed=b"b" * 32)
    legacy = macos.build_knowledgec(KNOWLEDGE)

    assert first == repeated
    assert first != second
    first_rows = _query(
        first,
        """
        SELECT o.Z_PK, o.ZVALUESTRING, o.ZUUID, m.ZMETADATAHASH
        FROM ZOBJECT AS o
        JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA = m.Z_PK
        ORDER BY o.Z_PK
        """,
    )
    second_uuids = {
        row[0] for row in _query(second, "SELECT ZUUID FROM ZOBJECT ORDER BY Z_PK")
    }
    legacy_uuids = {
        row[0] for row in _query(legacy, "SELECT ZUUID FROM ZOBJECT ORDER BY Z_PK")
    }
    first_uuids = {row[2] for row in first_rows}
    assert len(first_uuids) == len(KNOWLEDGE)
    assert first_uuids.isdisjoint(second_uuids)
    assert first_uuids.isdisjoint(legacy_uuids)
    for _rowid, bundle, uuid, metadata_hash in first_rows:
        assert metadata_hash == hashlib.sha256(
            b"artifactforge/knowledgec/metadata/v2\0"
            + uuid.encode("ascii")
            + b"\0"
            + bundle.encode("ascii")
        ).hexdigest()

    (tmp_path / "knowledgeC.db").write_bytes(first)
    report = validity.run(str(tmp_path))
    assert report.ok, report.render()
    detail = validity._validate_sqlite_profile(
        str(tmp_path / "knowledgeC.db"),
        {
            "sqlite3": validity._read_sqlite3(first),
            "sqlite-raw": validity._read_sqlite_raw(first),
        },
    )
    assert "identity=fixture-v2-derived" in detail


@pytest.mark.parametrize("identity_seed", [b"", b"short", b"x" * 31, b"x" * 33, "x" * 32])
def test_knowledge_identity_seed_is_exact(identity_seed):
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        macos.build_knowledgec(KNOWLEDGE, identity_seed=identity_seed)


def test_tcc_allows_one_client_to_have_multiple_distinct_services(tmp_path):
    data = macos.build_tcc(
        (
            ("com.example.multiservice", "kTCCServiceCamera", 2, 1_705_294_801),
            ("com.example.multiservice", "kTCCServiceMicrophone", 0, 1_705_294_802),
        )
    )
    (tmp_path / "TCC.db").write_bytes(data)

    report = validity.run(str(tmp_path))
    rows = _query(
        data,
        """
        SELECT service, client, auth_value, indirect_object_identifier
        FROM access ORDER BY rowid
        """,
    )

    assert report.ok, report.render()
    assert rows == (
        ("kTCCServiceCamera", "com.example.multiservice", 2, "UNUSED"),
        ("kTCCServiceMicrophone", "com.example.multiservice", 0, "UNUSED"),
    )


def _marker_table() -> TableSpec:
    return TableSpec(
        RESERVED_NAME,
        (ColumnSpec("marker", "TEXT"), ColumnSpec("notice", "TEXT")),
        ((MARKER, NOTICE),),
    )


def _knowledgec_with_broken_metadata_join() -> bytes:
    object_rows = []
    metadata_rows = []
    for rowid, (bundle_id, start, end) in enumerate(KNOWLEDGE, start=1):
        unix_day = math.floor((start + 978_307_200) / 86_400)
        day_of_week = ((unix_day + 4) % 7) + 1
        metadata_hash = hashlib.sha256(
            b"artifactforge::knowledgec-metadata\x00" + bundle_id.encode("ascii")
        ).hexdigest()
        object_rows.append(
            (
                rowid,
                "/app/inFocus",
                bundle_id,
                start,
                end,
                day_of_week,
                0,
                start,
                f"00000000-0000-4000-8000-{rowid:012X}",
                0 if rowid == 1 else rowid,
                1,
            )
        )
        metadata_rows.append((rowid, 0, "UNUSED", "UNUSED", metadata_hash))

    return build_sqlite(
        (
            TableSpec(
                "ZOBJECT",
                (
                    ColumnSpec("Z_PK", "INTEGER", primary_key=True),
                    ColumnSpec("ZSTREAMNAME", "TEXT"),
                    ColumnSpec("ZVALUESTRING", "TEXT"),
                    ColumnSpec("ZSTARTDATE", "REAL"),
                    ColumnSpec("ZENDDATE", "REAL"),
                    ColumnSpec("ZSTARTDAYOFWEEK", "INTEGER"),
                    ColumnSpec("ZSECONDSFROMGMT", "INTEGER"),
                    ColumnSpec("ZCREATIONDATE", "REAL"),
                    ColumnSpec("ZUUID", "TEXT"),
                    ColumnSpec("ZSTRUCTUREDMETADATA", "INTEGER"),
                    ColumnSpec("ZSOURCE", "INTEGER"),
                ),
                tuple(object_rows),
            ),
            TableSpec(
                "ZSTRUCTUREDMETADATA",
                (
                    ColumnSpec("Z_PK", "INTEGER", primary_key=True),
                    ColumnSpec(
                        "Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON", "INTEGER"
                    ),
                    ColumnSpec(
                        "Z_DKAPPLICATIONMETADATAKEY__EXTENSIONCONTAININGBUNDLEIDENTIFIER",
                        "TEXT",
                    ),
                    ColumnSpec(
                        "Z_DKAPPLICATIONMETADATAKEY__EXTENSIONHOSTIDENTIFIER", "TEXT"
                    ),
                    ColumnSpec("ZMETADATAHASH", "TEXT"),
                ),
                tuple(metadata_rows),
            ),
            TableSpec(
                "ZSOURCE",
                (ColumnSpec("Z_PK", "INTEGER", primary_key=True),),
                ((1,),),
            ),
            _marker_table(),
        )
    )


def _tcc_with_noncanonical_indirect_identifier() -> bytes:
    return build_sqlite(
        (
            TableSpec(
                "access",
                (
                    ColumnSpec("service", "TEXT"),
                    ColumnSpec("client", "TEXT"),
                    ColumnSpec("client_type", "INTEGER"),
                    ColumnSpec("auth_value", "INTEGER"),
                    ColumnSpec("auth_reason", "INTEGER"),
                    ColumnSpec("indirect_object_identifier", "TEXT"),
                    ColumnSpec("last_modified", "INTEGER"),
                ),
                tuple(
                    (
                        service,
                        client,
                        0,
                        auth_value,
                        3,
                        "BROKEN" if rowid == 1 else "UNUSED",
                        last_modified,
                    )
                    for rowid, (client, service, auth_value, last_modified) in enumerate(
                        TCC, start=1
                    )
                ),
            ),
            _marker_table(),
        )
    )


def _owned_reads(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    standard = validity._read_sqlite3(data)
    raw = validity._read_sqlite_raw(data)
    reads = {"sqlite3": standard, "sqlite-raw": raw}
    consensus = validity._sqlite_pair(reads)
    assert consensus is raw
    assert standard.schema == raw.schema
    assert standard.tables == raw.tables
    assert standard.indexes == raw.indexes
    assert standard.wire_profile is None
    assert raw.wire_profile == SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1.value
    return path, reads


def test_parser_valid_broken_apollo_join_is_semantic_profile_red(tmp_path):
    path, reads = _owned_reads(
        tmp_path,
        "knowledgeC.db",
        _knowledgec_with_broken_metadata_join(),
    )
    with pytest.raises(validity.SemanticError, match="join keys do not resolve"):
        validity._validate_sqlite_profile(str(path), reads)


def test_parser_valid_noncanonical_tcc_indirect_identifier_is_profile_red(tmp_path):
    path, reads = _owned_reads(
        tmp_path,
        "TCC.db",
        _tcc_with_noncanonical_indirect_identifier(),
    )
    with pytest.raises(validity.SemanticError, match="indirect object identifier"):
        validity._validate_sqlite_profile(str(path), reads)
