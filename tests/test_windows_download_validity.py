# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 profile and responder-query checks for Chromium ``History`` bytes."""
from __future__ import annotations

import hashlib

import pytest

from artifactforge.artifacts.sqlite_owned import ColumnSpec, TableSpec, build_sqlite
from artifactforge.artifacts.windows import (
    WINDOWS_EPOCH_MICROSECONDS,
    ChromiumDownload,
    build_chromium_history,
)
from artifactforge.disclosure import RESERVED_NAME
from artifactforge.gates import validity
from artifactforge.gates.oracles import SQLiteWireProfile, loads_sqlite


_START = WINDOWS_EPOCH_MICROSECONDS + 1_705_294_800_000_000
_FIRST_DIGEST = hashlib.sha256(b"first Gate 1 resident PE bytes").digest()
_SECOND_DIGEST = hashlib.sha256(b"second Gate 1 resident PE bytes").digest()
_ROWS = (
    ChromiumDownload(
        target_path=r"C:\Users\v\Downloads\first.exe",
        source_url=(
            "https://downloads.artifactforge.invalid/ARTIFACTFORGE/sha256/"
            f"{_FIRST_DIGEST.hex()}/first.exe"
        ),
        referrer_url="https://portal.example/ARTIFACTFORGE/first",
        sha256=_FIRST_DIGEST,
        size=2729,
        start_time_windows_us=_START,
        end_time_windows_us=_START + 2_000_000,
        opened=True,
        last_access_time_windows_us=_START + 4_000_000,
    ),
    ChromiumDownload(
        target_path=r"C:\Users\v\Downloads\second.exe",
        source_url=(
            "https://downloads.artifactforge.invalid/ARTIFACTFORGE/sha256/"
            f"{_SECOND_DIGEST.hex()}/second.exe"
        ),
        referrer_url="https://portal.example/ARTIFACTFORGE/second",
        sha256=_SECOND_DIGEST,
        size=4096,
        start_time_windows_us=_START + 10_000_000,
        end_time_windows_us=_START + 12_000_000,
        opened=False,
        last_access_time_windows_us=0,
    ),
)


def _history() -> bytes:
    return build_chromium_history(_ROWS, identity_seed=bytes(range(32)))


def _reads(data: bytes) -> dict:
    return {
        "sqlite3": validity._read_sqlite3(data),
        "sqlite-raw": validity._read_sqlite_raw(data),
    }


def _parser_valid_mutation(data: bytes, mutation: str) -> bytes:
    database = loads_sqlite(
        data, wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1
    )
    tables = []
    for table in database.tables:
        columns = tuple(
            ColumnSpec(column.name, column.declared_type, column.primary_key)
            for column in table.columns
        )
        positions = {column.name: index for index, column in enumerate(table.columns)}
        rows = [list(row.values) for row in table.rows]
        if table.name == "downloads":
            if mutation == "uppercase-guid":
                rows[0][positions["guid"]] = rows[0][positions["guid"]].upper()
            elif mutation == "path-identity":
                rows[0][positions["current_path"]] = r"C:\Users\v\Downloads\other.exe"
            elif mutation == "incomplete-state":
                rows[0][positions["state"]] = 0
            elif mutation == "nonempty-hash":
                rows[0][positions["hash"]] = b"not-empty"
            elif mutation == "causal-time":
                rows[0][positions["end_time"]] = rows[0][positions["start_time"]]
            elif mutation == "opened-access":
                rows[0][positions["last_access_time"]] = _START + 1_000_000
            elif mutation == "unmarked-referrer":
                rows[0][positions["referrer"]] = "https://portal.example/no-marker"
                rows[0][positions["tab_url"]] = "https://portal.example/no-marker"
            elif mutation == "placeholder":
                rows[0][positions["by_ext_id"]] = "extension"
            elif mutation == "mime":
                rows[0][positions["mime_type"]] = "application/octet-stream"
        elif table.name == "downloads_url_chains":
            if mutation == "uppercase-source-digest":
                rows[0][positions["url"]] = rows[0][positions["url"]].replace(
                    _FIRST_DIGEST.hex(), _FIRST_DIGEST.hex().upper()
                )
            elif mutation == "source-basename":
                rows[0][positions["url"]] = rows[0][positions["url"]].replace(
                    "/first.exe", "/other.exe"
                )
            elif mutation == "chain-mapping":
                rows[1][positions["id"]] = 1
        elif table.name == RESERVED_NAME and mutation == "marker":
            rows[0][positions["marker"]] = "ARTIFACTFORGf"
        tables.append(
            TableSpec(table.name, columns, tuple(tuple(row) for row in rows))
        )
    return build_sqlite(tuple(tables))


def test_history_gate_separates_consensus_profile_and_responder_query(tmp_path):
    data = _history()
    path = tmp_path / "History"
    path.write_bytes(data)
    reads = _reads(data)

    assert "profile=chromium-completed-download-query-surface-v1" in (
        validity._validate_sqlite_profile(str(path), reads)
    )
    assert validity._validate_sqlite_responder_query(str(path), reads) == (
        "consumer=sqlite3-chromium-download-join,rows=2"
    )

    report = validity.run(str(tmp_path))
    assert report.ok, report.render()
    assert report.metrics == {
        "oracle_reads_passed": 2,
        "oracle_reads_total": 2,
        "semantic_checks_passed": 3,
        "semantic_checks_total": 3,
        "claim_scopes": {
            "container_acceptance": {"passed": 2, "total": 2},
            "semantic_extraction": {"passed": 2, "total": 2},
            "independent_consensus": {"passed": 1, "total": 1},
            "declared_profile_conformance": {"passed": 1, "total": 1},
            "downstream_consumer_compatibility": {"passed": 1, "total": 1},
        },
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("uppercase-guid", "lowercase UUID v4"),
        ("path-identity", "current_path and target_path"),
        ("incomplete-state", "outside profile"),
        ("nonempty-hash", "outside profile"),
        ("causal-time", "end_time must be after"),
        ("opened-access", "must not precede"),
        ("unmarked-referrer", "marked reserved HTTPS"),
        ("placeholder", "placeholder"),
        ("mime", "MIME"),
        ("uppercase-source-digest", "lowercase /sha256"),
        ("source-basename", "basename must match"),
        ("chain-mapping", "one contiguous"),
        ("marker", "canonical marker"),
    ),
)
def test_parser_valid_history_mutations_are_profile_red(
    tmp_path, mutation, message
):
    data = _parser_valid_mutation(_history(), mutation)
    path = tmp_path / "History"
    path.write_bytes(data)
    reads = _reads(data)

    assert validity._validate_sqlite_consensus(str(path), reads).startswith("schema=3")
    with pytest.raises(validity.SemanticError, match=message):
        validity._validate_sqlite_profile(str(path), reads)

    report = validity.run(str(tmp_path))
    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == 2
    assert report.metrics["oracle_reads_total"] == 2
    assert any("sqlite-profile" in failure for failure in report.fails)
    assert not any("sqlite-consensus" in failure for failure in report.fails)
