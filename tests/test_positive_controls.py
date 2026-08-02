# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Power checks for every registered complete shortcut attack."""

from __future__ import annotations

import hashlib

import pytest

from artifactforge.bench import partial_union, positive_controls, rank_union
from artifactforge.bench.adversary import ADVERSARIES, COMPLETE_ADVERSARIES
from artifactforge.bench.benchmark import generate_suite
from artifactforge.bench.positive_controls import (
    EXCLUDED_LOW_CONTROLS,
    calibrate_positive_controls,
)
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.gates import GateReport
from artifactforge.gates import solvability
from artifactforge.inventory import inventory_regular_files

pytest.importorskip("pefile")
pytest.importorskip("lief")
pytest.importorskip("regipy")
pytest.importorskip("pyregf")


KEY = bytes.fromhex("91" * 32)


def _public_pair(tmp_path):
    tasks = generate_suite(2, str(tmp_path / "suite"), key=KEY, kind="holdout")
    assert [task.family for task in tasks] == ["windows", "macos"]
    return tasks[0].public(), tasks[1].public()


def _tree_digest(public) -> dict[str, str]:
    return {
        file.relative_path: hashlib.sha256(file.path.read_bytes()).hexdigest()
        for file in inventory_regular_files(public.directory)
    }


def _wrong_complete_bijection(public):
    """A guaranteed derangement of independently resolved truth."""
    actual = reference_solve(public)
    question_ids = [question.id for question in public.questions]
    values = [actual[question_id] for question_id in question_ids]
    return {
        question_id: values[(index + 1) % len(values)]
        for index, question_id in enumerate(question_ids)
    }


def test_every_complete_attack_has_a_two_family_parser_valid_positive_control(tmp_path):
    windows, macos = _public_pair(tmp_path)
    before = {
        "windows": _tree_digest(windows),
        "macos": _tree_digest(macos),
    }

    report = calibrate_positive_controls(windows, macos, ADVERSARIES)

    assert report.ok, report.failures
    assert report.passed == report.total == len(COMPLETE_ADVERSARIES) + 2
    assert {detail.attack for detail in report.details} == COMPLETE_ADVERSARIES
    for detail in report.details:
        assert detail.passed, (detail.attack, detail.failures)
        assert detail.solver_correct == detail.solver_coverage == detail.total == 10
        assert detail.reference_correct == 10
        assert detail.solver_score == detail.reference_score == 1.0
        assert {control.family for control in detail.families} == {"windows", "macos"}
        assert all(control.passed for control in detail.families)
    assert report.partial_union.passed, report.partial_union.failures
    assert report.partial_union.dev_correct == report.partial_union.dev_total == 30
    assert report.partial_union.measurement_correct == report.partial_union.measurement_total == 30
    assert report.partial_union.mapped_questions == 30
    assert report.partial_union.source_covered == 30
    assert report.partial_union.fallback_count == 0
    assert report.partial_union.selected_attacks == ("footprint", "lexical")
    assert report.partial_union.cross_slot_selections == 10
    assert report.rank_union.passed, report.rank_union.failures
    assert report.rank_union.dev_correct == report.rank_union.dev_total == 30
    assert report.rank_union.measurement_correct == report.rank_union.measurement_total == 30
    assert report.rank_union.mapped_questions == 30
    alternate = next(detail for detail in report.details if detail.attack == "alternate_link")
    macos_alternate = next(control for control in alternate.families if control.family == "macos")
    assert macos_alternate.control == "macos-lexical-fallback-vulnerability"
    assert _tree_digest(windows) == before["windows"]
    assert _tree_digest(macos) == before["macos"]


def test_every_complete_attack_rejects_a_substituted_wrong_bijection(tmp_path):
    windows, macos = _public_pair(tmp_path)

    for attack in sorted(COMPLETE_ADVERSARIES):
        report = calibrate_positive_controls(
            windows,
            macos,
            {attack: _wrong_complete_bijection},
        )
        detail = next(item for item in report.details if item.attack == attack)
        assert not detail.passed, attack
        assert detail.solver_coverage == detail.total == 10
        assert detail.solver_correct == 0
        assert detail.reference_correct == 10
        for control in detail.families:
            assert control.solver_correct == 0
            assert control.solver_coverage == control.total == 5
            assert control.reference_correct == 5
            assert any(
                "recovered 0/5 vulnerable answers" in failure for failure in control.failures
            )


def test_partial_union_control_executes_and_kills_the_production_wrapper(tmp_path, monkeypatch):
    windows, macos = _public_pair(tmp_path)

    assert positive_controls.trained_partial_union is partial_union.trained_partial_union

    def broken_fit(*_args, **_kwargs):
        raise ValueError("mutation killed shared production partial fitting")

    monkeypatch.setattr(partial_union, "fit_partial_union", broken_fit)
    report = calibrate_positive_controls(windows, macos, ADVERSARIES)

    assert not report.partial_union.passed
    assert report.rank_union.passed, report.rank_union.failures
    assert report.passed == report.total - 1
    assert any(
        "mutation killed shared production partial fitting" in failure
        for failure in report.partial_union.failures
    )


def test_low_information_controls_are_explicitly_excluded_and_never_invoked(tmp_path):
    windows, macos = _public_pair(tmp_path)
    solvers = dict(ADVERSARIES)

    def forbidden(_public):
        raise AssertionError("excluded low control was invoked")

    for name in EXCLUDED_LOW_CONTROLS:
        solvers[name] = forbidden

    report = calibrate_positive_controls(windows, macos, solvers)

    assert report.ok, report.failures
    assert report.excluded == ("constant", "listing", "null")
    assert not ({detail.attack for detail in report.details} & set(report.excluded))


def test_a_missing_complete_solver_is_a_returned_failure_not_a_skip(tmp_path):
    windows, macos = _public_pair(tmp_path)
    solvers = dict(ADVERSARIES)
    solvers.pop("metadata")

    report = calibrate_positive_controls(windows, macos, solvers)

    metadata = next(detail for detail in report.details if detail.attack == "metadata")
    assert not report.ok
    assert report.total == len(COMPLETE_ADVERSARIES) + 2
    assert not metadata.passed
    assert metadata.total == 10
    assert metadata.solver_correct == metadata.solver_coverage == 0
    assert len(metadata.failures) == 2
    assert all("missing callable attack" in failure for failure in metadata.failures)
    assert any("metadata" in failure for failure in report.failures)


def test_gate4_records_every_positive_control_and_union_metric(tmp_path):
    windows, macos = _public_pair(tmp_path)
    gate = GateReport(4, "solvability", "positive-control binding")

    solvability._positive_control_contract(gate, [windows, macos])

    assert gate.ok, gate.fails
    assert gate.metrics["positive_control_checks_passed"] == 10
    assert gate.metrics["positive_control_checks_total"] == 10
    assert gate.metrics["positive_control_trained_partial_union_passed"] is True
    assert gate.metrics["positive_control_partial_union_dev_correct"] == 30
    assert gate.metrics["positive_control_partial_union_dev_total"] == 30
    assert gate.metrics["positive_control_partial_union_measurement_correct"] == 30
    assert gate.metrics["positive_control_partial_union_measurement_total"] == 30
    assert gate.metrics["positive_control_partial_union_mapped_questions"] == 30
    assert gate.metrics["positive_control_partial_union_source_covered"] == 30
    assert gate.metrics["positive_control_partial_union_fallback_count"] == 0
    assert gate.metrics["positive_control_partial_union_cross_slot_selections"] == 10
    assert gate.metrics["positive_control_partial_union_selected_attacks"] == [
        "footprint",
        "lexical",
    ]
    assert gate.metrics["positive_control_trained_rank_union_passed"] is True
    assert gate.metrics["positive_control_rank_union_dev_correct"] == 30
    assert gate.metrics["positive_control_rank_union_dev_total"] == 30
    assert gate.metrics["positive_control_rank_union_measurement_correct"] == 30
    assert gate.metrics["positive_control_rank_union_measurement_total"] == 30
    assert gate.metrics["positive_control_rank_union_mapped_questions"] == 30
    for attack in COMPLETE_ADVERSARIES:
        assert gate.metrics[f"positive_control_{attack}_solver_score"] == 1.0
        assert gate.metrics[f"positive_control_{attack}_solver_coverage"] == 1.0
        assert gate.metrics[f"positive_control_{attack}_reference_score"] == 1.0


def test_gate4_positive_control_binding_fails_closed(tmp_path, monkeypatch):
    windows, macos = _public_pair(tmp_path)
    gate = GateReport(4, "solvability", "positive-control binding")

    def broken(*_args, **_kwargs):
        raise ValueError("deliberate calibration failure")

    monkeypatch.setattr(solvability, "calibrate_positive_controls", broken)
    solvability._positive_control_contract(gate, [windows, macos])

    assert not gate.ok
    assert gate.metrics["positive_control_checks_passed"] == 0
    assert gate.metrics["positive_control_checks_total"] == 10
    assert any("failed closed" in failure for failure in gate.fails)


def test_rank_union_control_executes_and_kills_the_production_wrapper(tmp_path, monkeypatch):
    windows, macos = _public_pair(tmp_path)
    assert (
        positive_controls.fit_rank_union is solvability._fit_rank_union is rank_union.fit_rank_union
    )
    assert (
        positive_controls.predict_rank_union
        is solvability._predict_rank_union
        is rank_union.predict_rank_union
    )

    def broken_training(*_args, **_kwargs):
        raise ValueError("mutation killed shared production training")

    monkeypatch.setattr(rank_union, "train_rank_union", broken_training)
    report = calibrate_positive_controls(windows, macos, ADVERSARIES)

    assert report.partial_union.passed, report.partial_union.failures
    assert not report.rank_union.passed
    assert report.passed == report.total - 1
    assert report.rank_union.dev_correct == 0
    assert report.rank_union.measurement_correct == 0
    assert any(
        "mutation killed shared production training" in failure
        for failure in report.rank_union.failures
    )
