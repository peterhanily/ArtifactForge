# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 must state exactly which assurance level each passing check establishes."""
from __future__ import annotations

import pytest

from artifactforge.artifacts.hive import build_amcache_hive, build_run_hive
from artifactforge.cli import _merge
from artifactforge.gates import GateReport
from artifactforge.gates import validity


pytest.importorskip("regipy")
pytest.importorskip("pyregf")


def test_every_semantic_validator_has_one_closed_claim_scope():
    names = [
        name
        for validators in validity.SEMANTIC_VALIDATORS.values()
        for name, _validator in validators
    ]
    assert len(names) == len(set(names))
    assert set(names) == set(validity.SEMANTIC_VALIDATOR_SCOPES)
    assert set(validity.SEMANTIC_VALIDATOR_SCOPES.values()) <= set(
        validity.CLAIM_SCOPE_ORDER
    )
    assert "version_fidelity" not in validity.CLAIM_SCOPE_ORDER
    assert "native_conformance" not in validity.CLAIM_SCOPE_ORDER
    assert "realism_calibration" not in validity.CLAIM_SCOPE_ORDER


def test_unscoped_or_stale_validator_registration_fails_closed(monkeypatch):
    monkeypatch.setitem(
        validity.SEMANTIC_VALIDATORS,
        "invented-format",
        (("unscoped-validator", lambda _source, _reads: "not reached"),),
    )
    with pytest.raises(RuntimeError, match="missing=.*unscoped-validator"):
        validity._validate_claim_scope_registry()


def test_hive_gate_reports_extraction_consensus_profile_and_consumer_separately(tmp_path):
    (tmp_path / "Amcache.hve").write_bytes(
        build_amcache_hive(
            [("a" * 40, r"c:\windrow\updater.exe", "updater.exe", 2729)]
        )
    )
    (tmp_path / "SOFTWARE").write_bytes(
        build_run_hive([("Windrow Updater", r"C:\Windrow\updater.exe")])
    )

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()
    assert report.metrics["claim_scopes"] == {
        "container_acceptance": {"passed": 4, "total": 4},
        "semantic_extraction": {"passed": 4, "total": 4},
        "independent_consensus": {"passed": 2, "total": 2},
        "declared_profile_conformance": {"passed": 2, "total": 2},
        "downstream_consumer_compatibility": {"passed": 2, "total": 2},
    }


def test_invalid_observation_shape_keeps_acceptance_distinct_from_extraction(
    tmp_path, monkeypatch
):
    (tmp_path / "Amcache.hve").write_bytes(
        build_amcache_hive(
            [("a" * 40, r"c:\windrow\updater.exe", "updater.exe", 2729)]
        )
    )
    monkeypatch.setitem(validity.READERS, "regipy", lambda _source: "opened-but-untyped")

    report = validity.run(str(tmp_path))

    assert not report.ok
    assert report.metrics["claim_scopes"]["container_acceptance"] == {
        "passed": 2,
        "total": 2,
    }
    assert report.metrics["claim_scopes"]["semantic_extraction"] == {
        "passed": 1,
        "total": 2,
    }
    assert report.metrics["claim_scopes"]["independent_consensus"] == {
        "passed": 0,
        "total": 1,
    }
    assert report.metrics["claim_scopes"]["declared_profile_conformance"] == {
        "passed": 0,
        "total": 1,
    }
    assert report.metrics["claim_scopes"]["downstream_consumer_compatibility"] == {
        "passed": 0,
        "total": 1,
    }


def test_cli_merge_preserves_and_sums_nested_claim_scope_metrics():
    reports = []
    for passed in (2, 3):
        report = GateReport(1, "validity", "test")
        report.metrics = {
            "oracle_reads_passed": passed,
            "claim_scopes": {
                "semantic_extraction": {"passed": passed, "total": 3},
            },
            "diagnostic": "not a measurement",
        }
        reports.append(report)

    merged = _merge(1, "validity", "test", reports)

    assert merged.metrics == {
        "oracle_reads_passed": 5,
        "claim_scopes": {
            "semantic_extraction": {"passed": 5, "total": 6},
        },
    }
