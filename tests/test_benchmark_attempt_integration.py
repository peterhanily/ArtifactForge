# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Genuine Benchmark v3 one-shot lifecycle integration coverage."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from artifactforge import suite
from artifactforge.bench import attempt, submission
from artifactforge.bench.benchmark import frozen_public_tasks
from artifactforge.bench.ceremony import create_evaluator_ceremony
from artifactforge.bench.reference_solver import reference_solve


pytestmark = pytest.mark.skipif(
    not attempt.ATTEMPT_PLATFORM_SUPPORTED,
    reason=attempt.ATTEMPT_PLATFORM_NOTICE,
)


pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def test_real_minimum_v3_suite_completes_one_shot_lifecycle(tmp_path: Path):
    """Exercise all protocol boundaries with 120 real generated scenes and real parsers."""
    evaluator = tmp_path / "evaluator"
    public_root = tmp_path / "solver-export"
    reveal_path = tmp_path / "submission.jsonl"
    ledger = tmp_path / "attempt"

    create_evaluator_ceremony(suite.BENCHMARK_V3_MIN_SCENARIOS, os.fspath(evaluator))
    suite.export_public(os.fspath(evaluator), os.fspath(public_root))

    with frozen_public_tasks(public_root) as (public, tasks):
        assert len(tasks) == suite.BENCHMARK_V3_MIN_SCENARIOS == 120
        assert {task.family for task in tasks} == {"windows", "macos"}
        assert sum(task.family == "windows" for task in tasks) == 60
        assert sum(task.family == "macos" for task in tasks) == 60
        answers = {task.scenario_id: reference_solve(task) for task in tasks}
        reveal = submission.canonical_submission_bytes(public, answers)

    reveal_path.write_bytes(reveal)
    if os.name != "nt":
        reveal_path.chmod(0o600)
    precommit = submission.build_precommit(
        public,
        reveal,
        implementation_sha256=_digest("artifactforge-reference-solver-implementation"),
        configuration_sha256=_digest("artifactforge-reference-solver-configuration"),
        source_sha256=_digest("artifactforge-reference-solver-source"),
    )
    acceptance = attempt.accept_precommit(
        ledger,
        evaluator,
        suite.canonical_public_bytes(precommit),
    )
    assert acceptance["suite_id"] == public["suite_id"]

    receipt = attempt.consume_attempt(ledger, evaluator, reveal_path)
    withheld = suite.canonical_public_bytes(receipt)
    assert receipt["state"] == "consumed-feedback-withheld"
    assert receipt["notice"] == attempt.WITHHELD_RECEIPT_NOTICE
    assert b"correct" not in withheld
    assert b"scored" not in withheld

    retirement = attempt.retire_attempt(ledger)
    report = attempt.retired_report(ledger)

    assert retirement["state"] == "retired-feedback-releasable"
    assert report["schema"] == attempt.REPORT_SCHEMA
    assert report["suite_id"] == public["suite_id"]
    assert report["retirement_record_id"] == retirement["record_id"]
    assert report["outcome"] == "scored"
    assert report["detail"]["correct"] == report["detail"]["total"] == 600
    assert report["reportable"] is False
    assert report["reportability"] == suite.REPORTABILITY_PENDING_EXTERNAL_ATTESTATION
    assert report["trust"] == attempt.ATTEMPT_TRUST
    assert "NOT REPORTABLE" in report["notice"]
    assert "independent witness" in report["notice"]
