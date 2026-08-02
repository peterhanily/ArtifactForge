# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Production partial-output union fitting and public-only prediction."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from artifactforge.bench.benchmark import Question, Task
from artifactforge.bench.partial_union import (
    FALLBACK_SENTINEL,
    fit_partial_union,
    predict_partial_union,
    trained_partial_union,
)


RULE = "amcache-fileid-byte-agreement-v1"


def _task(corpus: str, scene: int = 0) -> Task:
    scenario_id = f"partial-{corpus}-{scene}"
    return Task(
        scenario_id=scenario_id,
        family="windows",
        directory=f"control://{scenario_id}",
        questions=[
            Question(
                id=f"windows_agreement_{slot + 1:02d}",
                prompt=f"control slot {slot}",
                kind="hash",
                rule=RULE,
                selector={"control_slot": slot},
                candidate_count=5,
                expected=f"{corpus}-secret-{scene}-{slot}",
            )
            for slot in range(5)
        ],
    )


def _answers(task: Task) -> dict[str, str]:
    return task.answer_key()


def test_fit_uses_hits_then_coverage_then_attack_name_for_each_slot():
    dev = (_task("dev", 0), _task("dev", 1))
    alpha = {task.scenario_id: {} for task in dev}
    beta = {task.scenario_id: {} for task in dev}
    for task in dev:
        truth = _answers(task)
        # Slot 0: alpha wins on hits.
        alpha[task.scenario_id][task.questions[0].id] = truth[task.questions[0].id]
        beta[task.scenario_id][task.questions[0].id] = (
            truth[task.questions[0].id] if task is dev[0] else "wrong"
        )
        # Slot 1: equal hits, beta wins on coverage.
        if task is dev[0]:
            alpha[task.scenario_id][task.questions[1].id] = truth[task.questions[1].id]
        beta[task.scenario_id][task.questions[1].id] = (
            truth[task.questions[1].id] if task is dev[0] else "wrong"
        )
        # Remaining slots: exact hit/coverage ties go to lexical attack id alpha.
        for question in task.questions[2:]:
            value = truth[question.id] if task is dev[0] else "wrong"
            alpha[task.scenario_id][question.id] = value
            beta[task.scenario_id][question.id] = value

    model = fit_partial_union(dev, {"beta": beta, "alpha": alpha})

    selections = sorted(model.selections, key=lambda selection: selection.slot)
    assert [selection.attack for selection in selections] == [
        "alpha",
        "beta",
        "alpha",
        "alpha",
        "alpha",
    ]
    assert (selections[0].dev_hits, selections[0].dev_source_coverage) == (2, 2)
    assert (selections[1].dev_hits, selections[1].dev_source_coverage) == (1, 2)


def test_frozen_model_stores_no_development_answers():
    dev = (_task("private-development"),)
    model = fit_partial_union(
        dev,
        {"alpha": {dev[0].scenario_id: _answers(dev[0])}},
    )

    with pytest.raises(FrozenInstanceError):
        model.selections = ()
    rendered = repr(model)
    assert "private-development-secret" not in rendered
    assert set(vars(model)) == {"selections"}
    assert all(
        set(vars(selection))
        == {
            "family",
            "rule",
            "slot",
            "attack",
            "source_slot",
            "dev_hits",
            "dev_source_coverage",
            "dev_scene_count",
        }
        for selection in model.selections
    )


def test_prediction_requires_public_tasks_and_is_independent_of_measurement_truth():
    dev = (_task("dev"),)
    measured = _task("measurement")
    dev_outputs = {"alpha": {dev[0].scenario_id: _answers(dev[0])}}
    measured_outputs = {"alpha": {measured.scenario_id: _answers(measured)}}
    model = fit_partial_union(dev, dev_outputs)
    first_public = measured.public()

    first = predict_partial_union(model, (first_public,), measured_outputs)
    with pytest.raises(TypeError, match="PublicTask"):
        predict_partial_union(model, (measured,), measured_outputs)

    measured.questions = [
        replace(question, expected=f"mutated-private-truth-{slot}")
        for slot, question in enumerate(measured.questions)
    ]
    second = predict_partial_union(model, (measured.public(),), measured_outputs)

    assert first.answers == second.answers
    assert all(not hasattr(question, "expected") for question in first_public.questions)


def test_absent_nonstring_and_empty_sources_use_one_fixed_fallback_with_complete_keys():
    dev = (_task("dev"),)
    measured = _task("measurement")
    dev_outputs = {"alpha": {dev[0].scenario_id: _answers(dev[0])}}
    raw = {
        measured.questions[0].id: measured.questions[0].expected,
        measured.questions[1].id: None,
        measured.questions[2].id: "",
        measured.questions[3].id: "   ",
    }

    prediction, model = trained_partial_union(
        dev,
        (measured.public(),),
        dev_outputs,
        {"alpha": {measured.scenario_id: raw}},
    )

    answers = prediction.answers[measured.scenario_id]
    assert set(answers) == {question.id for question in measured.questions}
    assert answers[measured.questions[0].id] == measured.questions[0].expected
    assert all(answers[question.id] == FALLBACK_SENTINEL for question in measured.questions[1:])
    assert prediction.source_covered == 1
    assert prediction.fallback_count == 4
    assert prediction.total == 5
    assert prediction.source_coverage == 0.2
    assert prediction.by_class[0].source_coverage == 0.2
    assert model.attack_ids == ("alpha",)


def test_cross_slot_source_mapping_is_fitted_on_dev_and_frozen_for_measurement():
    dev = (_task("dev", 0), _task("dev", 1))
    measured = _task("measurement", 0)

    def rotated(tasks):
        by_scenario = {}
        for task in tasks:
            truth = [question.expected for question in task.questions]
            by_scenario[task.scenario_id] = {
                question.id: truth[(source_slot - 1) % 5]
                for source_slot, question in enumerate(task.questions)
            }
        return {"alpha": by_scenario}

    model = fit_partial_union(dev, rotated(dev))
    prediction = predict_partial_union(model, (measured.public(),), rotated((measured,)))

    selections = sorted(model.selections, key=lambda selection: selection.slot)
    assert [selection.source_slot for selection in selections] == [1, 2, 3, 4, 0]
    assert prediction.answers[measured.scenario_id] == measured.answer_key()

    mutated_outputs = rotated((measured,))
    mutated_outputs["alpha"][measured.scenario_id].pop(measured.questions[1].id)
    mutated = predict_partial_union(model, (measured.public(),), mutated_outputs)
    assert mutated.answers[measured.scenario_id][measured.questions[0].id] == FALLBACK_SENTINEL
    assert mutated.source_covered == 4
    assert mutated.fallback_count == 1


def test_source_slot_is_the_last_deterministic_tie_break():
    dev = (_task("dev", 0), _task("dev", 1))
    outputs = {"alpha": {}}
    for task in dev:
        truth = task.questions[0].expected
        outputs["alpha"][task.scenario_id] = {
            task.questions[0].id: truth,
            task.questions[1].id: truth,
        }

    model = fit_partial_union(dev, outputs)

    first = min(model.selections, key=lambda selection: selection.slot)
    assert first.slot == 0
    assert first.source_slot == 0


def test_prediction_rejects_a_measurement_class_absent_from_development():
    dev = (_task("dev"),)
    model = fit_partial_union(dev, {"alpha": {dev[0].scenario_id: _answers(dev[0])}})
    measured = _task("measurement")
    measured.family = "macos"

    with pytest.raises(ValueError, match="no selection"):
        predict_partial_union(model, (measured.public(),), {})


def test_fit_rejects_invalid_attack_ids_before_sorting_them():
    dev = (_task("dev"),)

    with pytest.raises(ValueError, match="attack ids"):
        fit_partial_union(dev, {"alpha": {}, 1: {}})
