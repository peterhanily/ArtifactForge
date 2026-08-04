# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Bounded dual-parser and semantic-profile tests for logical Zone.Identifier bytes."""
from __future__ import annotations

import dataclasses

import pytest

from artifactforge.artifacts.zone_identifier import (
    MAX_ZONE_IDENTIFIER_BYTES,
    build_zone_identifier,
    parse_zone_identifier,
)
from artifactforge.disclosure import MARKER
from artifactforge.gates import validity


EXPECTED = (
    b"[ZoneTransfer]\r\n"
    b"ZoneId=3\r\n"
    b"ReferrerUrl=https://artifactforge.invalid/" + MARKER.encode("ascii") + b"\r\n"
    b"HostUrl=https://artifactforge.invalid/" + MARKER.encode("ascii") + b"\r\n"
)


def test_zone_identifier_builder_emits_exact_dynamic_reserved_urls():
    referrer = "https://portal.example/ARTIFACTFORGE/software"
    host = "https://downloads.example/ARTIFACTFORGE/builds/update.exe"
    data = build_zone_identifier(referrer, host)
    assert data == (
        b"[ZoneTransfer]\r\n"
        b"ZoneId=3\r\n"
        b"ReferrerUrl=https://portal.example/ARTIFACTFORGE/software\r\n"
        b"HostUrl=https://downloads.example/ARTIFACTFORGE/builds/update.exe\r\n"
    )
    parsed = parse_zone_identifier(data)
    assert (parsed.referrer_url, parsed.host_url) == (referrer, host)


@pytest.mark.parametrize(
    ("referrer", "host", "zone"),
    (
        ("http://portal.example/", "https://downloads.example/a", 3),
        ("https://example.com/", "https://downloads.example/a", 3),
        ("https://user@portal.example/", "https://downloads.example/a", 3),
        ("https://portal.example/", "https://downloads.example/a#fragment", 3),
        ("https://portal.example/", "https://downloads.example/a", True),
        ("https://portal.example/", "https://downloads.example/a", 2),
    ),
)
def test_zone_identifier_builder_rejects_non_profile_values(referrer, host, zone):
    with pytest.raises(ValueError):
        build_zone_identifier(referrer, host, zone_id=zone)


def test_zone_identifier_parsers_agree_on_the_closed_typed_profile(tmp_path):
    parsed = parse_zone_identifier(EXPECTED)
    production = validity._read_configparser_zone_identifier(EXPECTED)
    raw = validity._read_zone_identifier_raw(EXPECTED)

    assert parsed.zone_id == 3
    assert production == raw
    assert production.key_order == ("ZoneId", "ReferrerUrl", "HostUrl")
    assert production.referrer_url == production.host_url

    (tmp_path / "sample.Zone.Identifier").write_bytes(EXPECTED)
    report = validity.run(str(tmp_path))
    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 2
    assert report.metrics["oracle_reads_total"] == 2
    assert report.metrics["semantic_checks_passed"] == 2
    assert report.metrics["semantic_checks_total"] == 2


@pytest.mark.parametrize(
    "malformed",
    (
        EXPECTED.replace(b"\r\n", b"\n"),
        EXPECTED.replace(b"ZoneId=3\r\n", b"ZoneId=3\r\nZoneId=3\r\n"),
        EXPECTED.replace(b"HostUrl=", b"UnknownUrl="),
        EXPECTED.replace(b"artifactforge.invalid", b"artifactforge.\xffnvalid", 1),
        EXPECTED[:-2],
    ),
    ids=("lf", "duplicate", "unknown-key", "non-ascii", "no-final-crlf"),
)
@pytest.mark.parametrize(
    "reader",
    (validity._read_configparser_zone_identifier, validity._read_zone_identifier_raw),
)
def test_each_zone_identifier_parser_rejects_malformed_framing(malformed, reader):
    with pytest.raises((ValueError, validity.SemanticError)):
        reader(malformed)


def test_zone_identifier_profile_rejects_parseable_non_internet_semantics(tmp_path):
    path = tmp_path / "sample.Zone.Identifier"
    path.write_bytes(EXPECTED.replace(b"ZoneId=3", b"ZoneId=2"))

    report = validity.run(str(tmp_path))

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == 2
    assert report.metrics["semantic_checks_passed"] == 1
    assert any("zone-identifier-profile" in failure for failure in report.fails)


def test_zone_identifier_consensus_is_type_exact(tmp_path, monkeypatch):
    path = tmp_path / "sample.Zone.Identifier"
    path.write_bytes(EXPECTED)
    original = validity.READERS["zone-identifier-raw"]

    def altered(source):
        return dataclasses.replace(original(source), zone_id=True)

    monkeypatch.setitem(validity.READERS, "zone-identifier-raw", altered)
    report = validity.run(str(tmp_path))

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == 2
    assert any("zone-identifier-consensus" in failure for failure in report.fails)


def test_zone_identifier_snapshot_bound_prevents_either_parser_from_running(
    tmp_path, monkeypatch
):
    (tmp_path / "oversized.Zone.Identifier").write_bytes(
        b"[ZoneTransfer]\r\n" + b"X" * MAX_ZONE_IDENTIFIER_BYTES
    )
    called: list[str] = []

    def forbidden(_source):
        called.append("called")
        raise AssertionError("bounded snapshot must reject before parser invocation")

    monkeypatch.setitem(validity.READERS, "configparser", forbidden)
    monkeypatch.setitem(validity.READERS, "zone-identifier-raw", forbidden)
    report = validity.run(str(tmp_path))

    assert not called
    assert report.metrics["oracle_reads_passed"] == 0
    assert report.metrics["oracle_reads_total"] == 2
    assert sum("snapshot limit" in failure for failure in report.fails) == 2
