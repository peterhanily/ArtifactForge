# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 4 must reject invalid measurement state before fitting or testing models."""

from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
import json

import pytest

from artifactforge import suite
from artifactforge.bench.adversary import blind_solve
from artifactforge.bench.benchmark import generate_suite, grade
from artifactforge.gates import GateReport
from artifactforge.gates import solvability

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")

HOLDOUT_KEY = bytes.fromhex("b7" * 32)


def _suite(tmp_path, name, n, *, key, kind):
    return generate_suite(n, str(tmp_path / name), key=key, kind=kind)


def _must_not_run(label):
    def fail(*_args, **_kwargs):
        raise AssertionError(f"{label} ran after a failed Gate 4 preflight")

    return fail


class _BoundaryTask:
    def public(self):
        return object()


def _boundary_results(kind):
    measured = (1.0, 1.0) if kind == suite.SCORECARD_MEASUREMENT_KIND else (0.0, 0.0)
    return [measured, (1.0, 1.0), (1.0, 1.0), (0.0, 0.0)]


def _run_boundary(monkeypatch, kind, results):
    observed = iter(results)

    def score(*_args, **_kwargs):
        accuracy, coverage = next(observed)
        return accuracy, coverage, {}

    monkeypatch.setattr(solvability, "_score", score)
    report = GateReport(4, "solvability", "boundary control unit test")
    valid = solvability._boundary_controls(
        report,
        [_BoundaryTask()],
        [object()],
        [_BoundaryTask()],
        [object()],
        kind,
    )
    return report, valid


@pytest.mark.parametrize(
    "kind",
    (suite.SCORECARD_MEASUREMENT_KIND, suite.HOLDOUT_SUITE_KIND),
)
def test_boundary_controls_record_exact_score_and_coverage_contracts(monkeypatch, kind):
    report, valid = _run_boundary(monkeypatch, kind, _boundary_results(kind))

    assert valid
    assert report.ok
    expected_measured = 1.0 if kind == suite.SCORECARD_MEASUREMENT_KIND else 0.0
    assert report.metrics["blind_solver_score"] == expected_measured
    assert report.metrics["blind_solver_coverage"] == expected_measured
    assert report.metrics["blind_control_score"] == 1.0
    assert report.metrics["blind_control_coverage"] == 1.0
    assert report.metrics["parent_escape_control_score"] == 1.0
    assert report.metrics["parent_escape_control_coverage"] == 1.0
    assert report.metrics["parent_escape_export_score"] == 0.0
    assert report.metrics["parent_escape_export_coverage"] == 0.0


@pytest.mark.parametrize(
    ("kind", "result_index", "mutated", "failure_fragment"),
    (
        (suite.SCORECARD_MEASUREMENT_KIND, 0, (0.95, 1.0), "scorecard control"),
        (suite.SCORECARD_MEASUREMENT_KIND, 0, (1.0, 0.8), "scorecard control"),
        (suite.HOLDOUT_SUITE_KIND, 0, (0.0, 0.2), "holdout control"),
        (suite.SCORECARD_MEASUREMENT_KIND, 1, (0.95, 1.0), "development control"),
        (suite.SCORECARD_MEASUREMENT_KIND, 1, (1.0, 0.8), "development control"),
        (suite.SCORECARD_MEASUREMENT_KIND, 2, (0.95, 1.0), "co-located"),
        (suite.SCORECARD_MEASUREMENT_KIND, 2, (1.0, 0.8), "co-located"),
        (suite.SCORECARD_MEASUREMENT_KIND, 3, (0.0, 0.2), "exported"),
    ),
)
def test_boundary_controls_reject_partial_reconstruction_and_wrong_value_leakage(
    monkeypatch,
    kind,
    result_index,
    mutated,
    failure_fragment,
):
    results = _boundary_results(kind)
    results[result_index] = mutated

    report, valid = _run_boundary(monkeypatch, kind, results)

    assert not valid
    assert not report.ok
    assert any(failure_fragment in failure for failure in report.fails)


@pytest.mark.parametrize(
    ("measured_count", "development_count", "missing_label"),
    ((1, 2, "measured"), (2, 1, "development")),
)
def test_missing_population_class_reddens_without_inference_or_training(
    tmp_path, monkeypatch, measured_count, development_count, missing_label
):
    measured = _suite(
        tmp_path,
        "measured",
        measured_count,
        key=HOLDOUT_KEY,
        kind=suite.HOLDOUT_SUITE_KIND,
    )
    development = _suite(
        tmp_path,
        "development",
        development_count,
        key=suite.PUBLIC_DEV_KEY,
        kind=suite.DEV_SUITE_KIND,
    )
    for name in (
        "_fit_rank_union",
        "_predict_rank_union",
        "_fit_partial_union",
        "_predict_partial_union",
    ):
        monkeypatch.setattr(solvability, name, _must_not_run(name))
    monkeypatch.setattr(
        solvability,
        "_randomization_tail",
        _must_not_run("randomization inference"),
    )

    report = solvability.run(measured, development)

    assert not report.ok
    metric = f"{missing_label}_macos_quarantine_uuid_event_agreement_v1_scene_count"
    assert report.metrics[metric] == 0
    assert report.metrics["population_contract_valid"] is False
    assert report.metrics["statistical_inference_performed"] is False
    assert "shortcut inference not run" in report.denominator
    assert any(f"{missing_label} corpus scene classes" in failure for failure in report.fails)


def test_invalid_value_contract_stops_controls_that_train_or_infer(tmp_path, monkeypatch):
    measured = _suite(
        tmp_path,
        "measured",
        2,
        key=HOLDOUT_KEY,
        kind=suite.HOLDOUT_SUITE_KIND,
    )
    development = _suite(
        tmp_path,
        "development",
        2,
        key=suite.PUBLIC_DEV_KEY,
        kind=suite.DEV_SUITE_KIND,
    )
    measured[0].questions[0] = replace(
        measured[0].questions[0],
        expected="0" * 64,
    )
    monkeypatch.setattr(solvability, "MIN_SCENES_PER_CLASS", 1)
    monkeypatch.setattr(
        solvability,
        "_positive_control_contract",
        _must_not_run("positive-control model calibration"),
    )
    for name in (
        "_fit_rank_union",
        "_predict_rank_union",
        "_fit_partial_union",
        "_predict_partial_union",
    ):
        monkeypatch.setattr(solvability, name, _must_not_run(name))
    monkeypatch.setattr(
        solvability,
        "_randomization_tail",
        _must_not_run("randomization inference"),
    )

    report = solvability.run(measured, development)

    assert not report.ok
    assert report.metrics["population_contract_valid"] is True
    assert report.metrics["statistical_inference_contract_valid"] is False
    assert report.metrics["statistical_inference_performed"] is False
    assert any("does not re-derive" in failure for failure in report.fails)


@pytest.mark.parametrize(
    ("target", "ensemble", "fit_expected"),
    (
        ("_fit_rank_union", "trained_rank_union", False),
        ("_predict_rank_union", "trained_rank_union", True),
        ("_fit_partial_union", "trained_partial_union", False),
        ("_predict_partial_union", "trained_partial_union", True),
    ),
)
def test_ensemble_fit_and_prediction_exceptions_redden_without_aborting_gate4(
    tmp_path,
    monkeypatch,
    target,
    ensemble,
    fit_expected,
):
    measured = _suite(
        tmp_path,
        "measured",
        2,
        key=HOLDOUT_KEY,
        kind=suite.HOLDOUT_SUITE_KIND,
    )
    development = _suite(
        tmp_path,
        "development",
        2,
        key=suite.PUBLIC_DEV_KEY,
        kind=suite.DEV_SUITE_KIND,
    )
    monkeypatch.setattr(solvability, "MIN_SCENES_PER_CLASS", 1)
    monkeypatch.setattr(solvability, "_positive_control_contract", lambda *_args: None)
    monkeypatch.setattr(solvability, "_randomization_tail", lambda *_args, **_kwargs: Fraction(1))
    monkeypatch.setattr(solvability, target, _must_not_run(target))

    report = solvability.run(measured, development)

    assert not report.ok
    assert report.metrics[f"{ensemble}_fit_valid"] is fit_expected
    assert report.metrics[f"{ensemble}_prediction_valid"] is False
    assert report.metrics[f"{ensemble}_evaluation_performed"] is False
    assert report.metrics[f"{ensemble}_inference_valid"] is False
    assert any("failed closed" in failure and target in failure for failure in report.fails)


@pytest.mark.parametrize("failing_corpus", ("measured", "development"))
def test_raising_registered_attack_suppresses_all_shortcut_inference(
    tmp_path,
    monkeypatch,
    failing_corpus,
):
    measured = _suite(
        tmp_path,
        "measured",
        2,
        key=HOLDOUT_KEY,
        kind=suite.HOLDOUT_SUITE_KIND,
    )
    development = _suite(
        tmp_path,
        "development",
        2,
        key=suite.PUBLIC_DEV_KEY,
        kind=suite.DEV_SUITE_KIND,
    )
    original = solvability.ADVERSARIES["lexical"]

    def raising(public):
        corpus = "development" if public.suite_kind == suite.DEV_SUITE_KIND else "measured"
        if corpus == failing_corpus:
            raise RuntimeError(f"deliberate {corpus} adversary failure")
        return original(public)

    monkeypatch.setattr(solvability, "MIN_SCENES_PER_CLASS", 1)
    monkeypatch.setattr(solvability, "_positive_control_contract", lambda *_args: None)
    monkeypatch.setattr(
        solvability,
        "_randomization_tail",
        _must_not_run("randomization after raising attack"),
    )
    monkeypatch.setitem(solvability.ADVERSARIES, "lexical", raising)

    report = solvability.run(measured, development)

    assert not report.ok
    assert report.metrics["registered_attack_execution_valid"] is False
    assert report.metrics["registered_attack_execution_failed_attack"] == "lexical"
    assert report.metrics["registered_attack_execution_failed_corpus"] == failing_corpus
    assert report.metrics["statistical_inference_performed"] is False
    assert report.metrics["trained_rank_union_fit_valid"] is False
    assert report.metrics["trained_partial_union_fit_valid"] is False
    assert "shortcut inference not run" in report.denominator
    assert any("registered attack 'lexical' failed" in failure for failure in report.fails)


def test_blind_solver_ignores_a_false_suite_kind_for_known_public_keys(tmp_path):
    scorecard_tasks = _suite(
        tmp_path,
        "scorecard",
        2,
        key=suite.scorecard_measurement_key(),
        kind=suite.SCORECARD_MEASUREMENT_KIND,
    )
    disguised = replace(scorecard_tasks[0].public(), suite_kind=suite.HOLDOUT_SUITE_KIND)
    assert grade(scorecard_tasks[0], blind_solve(disguised)).accuracy == 1.0

    holdout_tasks = _suite(
        tmp_path,
        "holdout",
        2,
        key=HOLDOUT_KEY,
        kind=suite.HOLDOUT_SUITE_KIND,
    )
    false_public_label = replace(
        holdout_tasks[0].public(),
        suite_kind=suite.SCORECARD_MEASUREMENT_KIND,
    )
    assert blind_solve(false_public_label) == {}


def test_gate_rejects_scorecard_key_relabelled_as_holdout(tmp_path):
    measured_root = tmp_path / "measured"
    measured = _suite(
        tmp_path,
        "measured",
        2,
        key=suite.scorecard_measurement_key(),
        kind=suite.SCORECARD_MEASUREMENT_KIND,
    )
    development = _suite(
        tmp_path,
        "development",
        2,
        key=suite.PUBLIC_DEV_KEY,
        kind=suite.DEV_SUITE_KIND,
    )

    public_path = measured_root / "public.json"
    document = json.loads(public_path.read_text(encoding="utf-8"))
    relabelled = suite.build_public_document(
        {
            "domain": document["domain"],
            "suite_kind": suite.HOLDOUT_SUITE_KIND,
            "scenarios": document["scenarios"],
        },
        measured_root / "scenarios",
    )
    public_path.write_bytes(suite.canonical_public_bytes(relabelled))

    report = solvability.run(measured, development)

    assert not report.ok
    assert report.metrics["measured_evaluator_key_binding_valid"] is False
    assert report.metrics["statistical_inference_performed"] is False
    assert any("key binding is invalid" in failure for failure in report.fails)
