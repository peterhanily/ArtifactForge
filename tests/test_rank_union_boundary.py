# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The rank ensemble may see measurement public state, never measurement truth."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from artifactforge.bench.benchmark import Question, Task
from artifactforge.bench.rank_union import fit_rank_union, predict_rank_union


RULE = "amcache-fileid-byte-agreement-v1"


def _task(corpus: str, scene: int) -> Task:
    scenario_id = f"rank-{corpus}-{scene}"
    return Task(
        scenario_id=scenario_id,
        family="windows",
        directory=f"control://{scenario_id}",
        questions=[
            Question(
                id=f"windows_agreement_{slot + 1:02d}",
                prompt=f"rank slot {slot}",
                kind="hash",
                rule=RULE,
                selector={"control_slot": slot},
                candidate_count=5,
                expected=f"{corpus}-private-answer-{scene}-{slot}",
            )
            for slot in range(5)
        ],
    )


def _rotated(tasks):
    outputs = {}
    for task in tasks:
        values = [question.expected for question in task.questions]
        outputs[task.scenario_id] = {
            question.id: values[(slot + 2) % 5] for slot, question in enumerate(task.questions)
        }
    return {"lexical": outputs}


def test_rank_fit_is_answer_free_and_prediction_rejects_private_measurement_tasks():
    dev = (_task("dev", 0), _task("dev", 1))
    model = fit_rank_union(dev, _rotated(dev))

    with pytest.raises(FrozenInstanceError):
        model.classes = ()
    assert "dev-private-answer" not in repr(model)

    measured = _task("measurement", 0)
    with pytest.raises(TypeError, match="PublicTask"):
        predict_rank_union(model, (measured,), _rotated((measured,)))


def test_changing_private_measurement_truth_cannot_change_rank_predictions():
    dev = (_task("dev", 0), _task("dev", 1))
    model = fit_rank_union(dev, _rotated(dev))
    measured = _task("measurement", 0)
    outputs = _rotated((measured,))

    first = predict_rank_union(model, (measured.public(),), outputs)
    measured.questions = [
        replace(question, expected=f"mutated-holdout-answer-{slot}")
        for slot, question in enumerate(measured.questions)
    ]
    second = predict_rank_union(model, (measured.public(),), outputs)

    assert first == second
    assert set(first[measured.scenario_id]) == {question.id for question in measured.questions}


def test_rank_prediction_rejects_duplicate_public_scenario_ids():
    dev = (_task("dev", 0), _task("dev", 1))
    model = fit_rank_union(dev, _rotated(dev))
    measured = _task("measurement", 0)

    with pytest.raises(ValueError, match="duplicates scenario"):
        predict_rank_union(
            model,
            (measured.public(), measured.public()),
            _rotated((measured,)),
        )
