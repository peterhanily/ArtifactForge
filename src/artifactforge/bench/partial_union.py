# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Development-trained union of raw, potentially partial shortcut outputs.

The fitter sees private development truth.  For each target
``(family, rule, question-slot)`` it chooses the registered ``(attack, source-slot)`` pair
with the lexicographically smallest
``(-correct_hits, -source_coverage, attack_name, source_slot)`` tuple.  The frozen model
retains only class identifiers, slot numbers, attack identifiers and aggregate development
counts.

Measurement prediction accepts public tasks and raw attack outputs only.  It emits every
question key, substituting one fixed sentinel whenever the selected source is absent, is not
text, or is empty after trimming.  Source coverage and fallback counts remain separate from
the deliberately complete output coverage.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from artifactforge.bench.benchmark import PublicTask, normalize


FALLBACK_SENTINEL = "artifactforge:partial-union:fallback:v1"


@dataclass(frozen=True)
class SlotSelection:
    """One frozen per-class, per-slot development choice."""

    family: str
    rule: str
    slot: int
    attack: str
    source_slot: int
    dev_hits: int
    dev_source_coverage: int
    dev_scene_count: int


@dataclass(frozen=True)
class PartialUnionModel:
    """Answer-free fitted state: identifiers and counts only."""

    selections: tuple[SlotSelection, ...]

    @property
    def attack_ids(self) -> tuple[str, ...]:
        return tuple(sorted({selection.attack for selection in self.selections}))


@dataclass(frozen=True)
class ClassSourceMetrics:
    """Selected-source coverage for one measured scene class."""

    family: str
    rule: str
    source_covered: int
    fallback_count: int
    total: int

    @property
    def source_coverage(self) -> float:
        return self.source_covered / self.total if self.total else 0.0


@dataclass(frozen=True)
class PartialUnionPrediction:
    """Complete public answers plus explicit selected-source accounting."""

    answers: dict[str, dict[str, str]]
    source_covered: int
    fallback_count: int
    total: int
    by_class: tuple[ClassSourceMetrics, ...]

    @property
    def source_coverage(self) -> float:
        return self.source_covered / self.total if self.total else 0.0


def _task_class(task) -> tuple[str, str]:
    family = getattr(task, "family", None)
    questions = getattr(task, "questions", None)
    if not isinstance(family, str) or not family:
        raise ValueError("partial-union task family must be non-empty text")
    if not isinstance(questions, list) or not questions:
        raise ValueError("partial-union tasks require a non-empty question list")
    rules = {getattr(question, "rule", None) for question in questions}
    if len(rules) != 1 or not all(isinstance(rule, str) and rule for rule in rules):
        raise ValueError("partial-union tasks must contain exactly one non-empty rule")
    return family, next(iter(rules))


def _validated_tasks(tasks: Sequence, *, private: bool) -> dict[tuple[str, str], list]:
    if isinstance(tasks, (str, bytes)):
        raise TypeError("partial-union tasks must be a sequence of task objects")
    grouped: dict[tuple[str, str], list] = defaultdict(list)
    seen_scenarios = set()
    for task in tasks:
        scenario_id = getattr(task, "scenario_id", None)
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("partial-union scenario ids must be non-empty text")
        if scenario_id in seen_scenarios:
            raise ValueError(f"partial-union corpus duplicates scenario {scenario_id!r}")
        seen_scenarios.add(scenario_id)
        key = _task_class(task)
        question_ids = [getattr(question, "id", None) for question in task.questions]
        if any(not isinstance(question_id, str) or not question_id for question_id in question_ids):
            raise ValueError("partial-union question ids must be non-empty text")
        if len(set(question_ids)) != len(question_ids):
            raise ValueError(f"partial-union scenario {scenario_id!r} duplicates question ids")
        for question in task.questions:
            kind = getattr(question, "kind", None)
            if not isinstance(kind, str) or not kind:
                raise ValueError("partial-union question kinds must be non-empty text")
            if private and not hasattr(question, "expected"):
                raise TypeError("partial-union fitting requires private development truth")
        grouped[key].append(task)
    if not grouped:
        raise ValueError("partial-union fitting requires at least one development task")
    for key, class_tasks in grouped.items():
        question_counts = {len(task.questions) for task in class_tasks}
        if len(question_counts) != 1:
            raise ValueError(f"partial-union class {key!r} has inconsistent question counts")
        kinds_by_slot = {
            slot: {task.questions[slot].kind for task in class_tasks}
            for slot in range(len(class_tasks[0].questions))
        }
        if any(len(kinds) != 1 for kinds in kinds_by_slot.values()):
            raise ValueError(f"partial-union class {key!r} changes answer kind by scene")
    return dict(grouped)


def _attack_ids(attack_outputs: Mapping) -> tuple[str, ...]:
    if not isinstance(attack_outputs, Mapping) or not attack_outputs:
        raise ValueError("partial-union fitting requires raw outputs from registered attacks")
    names = tuple(attack_outputs)
    if any(not isinstance(name, str) or not name for name in names):
        raise ValueError("partial-union attack ids must be non-empty text")
    return tuple(sorted(names))


def _raw_source(
    attack_outputs: Mapping,
    attack: str,
    scenario_id: str,
    question_id: str,
):
    by_scenario = attack_outputs.get(attack)
    if not isinstance(by_scenario, Mapping):
        return None
    answers = by_scenario.get(scenario_id)
    if not isinstance(answers, Mapping):
        return None
    return answers.get(question_id)


def _usable_source(value) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def fit_partial_union(
    dev_private: Sequence,
    dev_attack_answers: Mapping,
) -> PartialUnionModel:
    """Fit deterministic per-slot source choices using development truth only."""
    grouped = _validated_tasks(dev_private, private=True)
    attacks = _attack_ids(dev_attack_answers)
    selections = []
    for (family, rule), tasks in sorted(grouped.items()):
        for slot in range(len(tasks[0].questions)):
            candidates = []
            for attack in attacks:
                for source_slot in range(len(tasks[0].questions)):
                    hits = coverage = 0
                    for task in tasks:
                        target_question = task.questions[slot]
                        source_question = task.questions[source_slot]
                        source = _usable_source(
                            _raw_source(
                                dev_attack_answers,
                                attack,
                                task.scenario_id,
                                source_question.id,
                            )
                        )
                        if source is None:
                            continue
                        coverage += 1
                        hits += int(
                            normalize(source, target_question.kind)
                            == normalize(target_question.expected, target_question.kind)
                        )
                    candidates.append(
                        (
                            (-hits, -coverage, attack, source_slot),
                            attack,
                            source_slot,
                            hits,
                            coverage,
                        )
                    )
            _rank, attack, source_slot, hits, coverage = min(candidates, key=lambda item: item[0])
            selections.append(
                SlotSelection(
                    family=family,
                    rule=rule,
                    slot=slot,
                    attack=attack,
                    source_slot=source_slot,
                    dev_hits=hits,
                    dev_source_coverage=coverage,
                    dev_scene_count=len(tasks),
                )
            )
    return PartialUnionModel(tuple(selections))


def predict_partial_union(
    model: PartialUnionModel,
    measured_public: Sequence[PublicTask],
    measured_attack_answers: Mapping,
) -> PartialUnionPrediction:
    """Predict complete measured outputs without receiving measurement truth."""
    if not isinstance(model, PartialUnionModel):
        raise TypeError("partial-union prediction requires a PartialUnionModel")
    if not isinstance(measured_attack_answers, Mapping):
        raise TypeError("partial-union measured attack outputs must be a mapping")
    public_tasks = tuple(measured_public)
    if any(not isinstance(task, PublicTask) for task in public_tasks):
        raise TypeError("partial-union measurement prediction accepts PublicTask objects only")
    grouped = _validated_tasks(public_tasks, private=False)
    selection_by_slot = {
        (selection.family, selection.rule, selection.slot): selection
        for selection in model.selections
    }
    if len(selection_by_slot) != len(model.selections):
        raise ValueError("partial-union model duplicates a class/slot selection")

    answers: dict[str, dict[str, str]] = {}
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for key, tasks in sorted(grouped.items()):
        for task in tasks:
            selected_answers = {}
            for slot, question in enumerate(task.questions):
                selection = selection_by_slot.get((*key, slot))
                if selection is None:
                    raise ValueError(f"partial-union model has no selection for {(*key, slot)!r}")
                source_question = task.questions[selection.source_slot]
                source = _usable_source(
                    _raw_source(
                        measured_attack_answers,
                        selection.attack,
                        task.scenario_id,
                        source_question.id,
                    )
                )
                counts[key][2] += 1
                if source is None:
                    selected_answers[question.id] = FALLBACK_SENTINEL
                    counts[key][1] += 1
                else:
                    selected_answers[question.id] = source
                    counts[key][0] += 1
            answers[task.scenario_id] = selected_answers

    by_class = tuple(
        ClassSourceMetrics(family, rule, covered, fallback, total)
        for (family, rule), (covered, fallback, total) in sorted(counts.items())
    )
    source_covered = sum(metric.source_covered for metric in by_class)
    fallback_count = sum(metric.fallback_count for metric in by_class)
    total = sum(metric.total for metric in by_class)
    if source_covered + fallback_count != total:
        raise AssertionError("partial-union source accounting does not partition predictions")
    return PartialUnionPrediction(
        answers=answers,
        source_covered=source_covered,
        fallback_count=fallback_count,
        total=total,
        by_class=by_class,
    )


def trained_partial_union(
    dev_private: Sequence,
    measured_public: Sequence[PublicTask],
    dev_attack_answers: Mapping,
    measured_attack_answers: Mapping,
) -> tuple[PartialUnionPrediction, PartialUnionModel]:
    """Fit on private development truth, then predict public measurement tasks."""
    model = fit_partial_union(dev_private, dev_attack_answers)
    return (
        predict_partial_union(model, measured_public, measured_attack_answers),
        model,
    )


__all__ = [
    "ClassSourceMetrics",
    "FALLBACK_SENTINEL",
    "PartialUnionModel",
    "PartialUnionPrediction",
    "SlotSelection",
    "fit_partial_union",
    "predict_partial_union",
    "trained_partial_union",
]
