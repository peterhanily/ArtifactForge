# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fit rank ensembles on development truth, then predict from public measurement state.

The API deliberately separates the only truth-bearing operation from measurement prediction.
``fit_rank_union`` accepts private development tasks and freezes answer-free statistical
models. ``predict_rank_union`` accepts only :class:`PublicTask` objects at runtime and cannot
grade or inspect measurement truth.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from artifactforge.bench.adversary import COMPLETE_ADVERSARIES
from artifactforge.bench.benchmark import PublicTask, normalize
from artifactforge.bench.statistics import RankUnionModel, train_rank_union


EXPECTED_CANDIDATES = 5


def _task_class(task) -> tuple[str, str]:
    classes = {(task.family, question.rule) for question in task.questions}
    if len(classes) != 1:
        raise ValueError("rank-union scenes must contain exactly one family/rule class")
    return next(iter(classes))


def _answer_vector(task, answers_by_scenario) -> tuple[str, ...]:
    answers = answers_by_scenario.get(task.scenario_id, {})
    if not isinstance(answers, dict):
        answers = {}
    return tuple(normalize(answers.get(question.id), question.kind) for question in task.questions)


def _expected_vector(task) -> tuple[str, ...]:
    return tuple(normalize(question.expected, question.kind) for question in task.questions)


@dataclass(frozen=True)
class ClassRankUnionModel:
    """One answer-free fitted model identified by its public scene class."""

    family: str
    rule: str
    model: RankUnionModel


@dataclass(frozen=True)
class FrozenRankUnionModels:
    """Immutable collection of class models fitted from development only."""

    classes: tuple[ClassRankUnionModel, ...]

    def by_class(self) -> dict[tuple[str, str], RankUnionModel]:
        return {(item.family, item.rule): item.model for item in self.classes}


def fit_rank_union(dev_private, dev_attack_answers) -> FrozenRankUnionModels:
    """Fit complete rank attacks using private development truth only."""
    if not dev_private:
        raise ValueError("rank-union fitting requires private development tasks")
    if not isinstance(dev_attack_answers, Mapping):
        raise TypeError("rank-union development attack outputs must be a mapping")
    seen_scenarios = set()
    for task in dev_private:
        scenario_id = getattr(task, "scenario_id", None)
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("rank-union scenario ids must be non-empty text")
        if scenario_id in seen_scenarios:
            raise ValueError(f"rank-union corpus duplicates scenario {scenario_id!r}")
        seen_scenarios.add(scenario_id)
        if any(not hasattr(question, "expected") for question in task.questions):
            raise TypeError("rank-union fitting requires private development truth")
    classes = sorted({_task_class(task) for task in dev_private})
    fitted = []
    for family, rule in classes:
        key = (family, rule)
        dev_tasks = [task for task in dev_private if _task_class(task) == key]
        expected = tuple(_expected_vector(task) for task in dev_tasks)
        eligible = {}
        for name in sorted(COMPLETE_ADVERSARIES):
            if name not in dev_attack_answers:
                continue
            rows = tuple(_answer_vector(task, dev_attack_answers[name]) for task in dev_tasks)
            if all(
                len(set(row)) == EXPECTED_CANDIDATES and set(row) == set(wanted)
                for row, wanted in zip(rows, expected, strict=True)
            ):
                eligible[name] = rows
        if not eligible:
            raise ValueError(f"no complete rank adversary is eligible for {key!r}")
        fitted.append(
            ClassRankUnionModel(
                family,
                rule,
                train_rank_union(expected, eligible),
            )
        )
    return FrozenRankUnionModels(tuple(fitted))


def predict_rank_union(
    models: FrozenRankUnionModels,
    measured_public,
    measured_attack_answers,
) -> dict[str, dict[str, str]]:
    """Apply frozen models to public measurement tasks without receiving truth."""
    if not isinstance(models, FrozenRankUnionModels):
        raise TypeError("rank-union prediction requires FrozenRankUnionModels")
    if not isinstance(measured_attack_answers, Mapping):
        raise TypeError("rank-union measured attack outputs must be a mapping")
    public_tasks = tuple(measured_public)
    if any(not isinstance(task, PublicTask) for task in public_tasks):
        raise TypeError("rank-union measurement prediction accepts PublicTask objects only")
    model_by_class = models.by_class()
    if len(model_by_class) != len(models.classes):
        raise ValueError("rank-union models duplicate a family/rule class")
    answers = {}
    seen_scenarios = set()
    for task in public_tasks:
        if not isinstance(task.scenario_id, str) or not task.scenario_id:
            raise ValueError("rank-union scenario ids must be non-empty text")
        if task.scenario_id in seen_scenarios:
            raise ValueError(f"rank-union corpus duplicates scenario {task.scenario_id!r}")
        seen_scenarios.add(task.scenario_id)
        question_ids = [question.id for question in task.questions]
        if len(set(question_ids)) != len(question_ids):
            raise ValueError(f"rank-union scenario {task.scenario_id!r} duplicates question ids")
        key = _task_class(task)
        try:
            model = model_by_class[key]
        except KeyError as exc:
            raise ValueError(f"rank-union has no development model for {key!r}") from exc
        attack_vectors = {
            name: _answer_vector(task, measured_attack_answers.get(name, {}))
            for name in {item.attack for item in model.models}
        }
        prediction = model.predict(attack_vectors)
        answers[task.scenario_id] = {
            question.id: answer for question, answer in zip(task.questions, prediction, strict=True)
        }
    return answers


__all__ = [
    "ClassRankUnionModel",
    "EXPECTED_CANDIDATES",
    "FrozenRankUnionModels",
    "fit_rank_union",
    "predict_rank_union",
]
