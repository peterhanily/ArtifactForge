# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Exact inference and development-only ensembles for Benchmark v2.

The five answers in one scene are a bijection, not five independent Bernoulli
trials.  This module therefore treats a scene as the randomization unit:
enumerate its 5! possible answer assignments, then convolve those finite null
distributions across scenes.

The rank/union model has the same trust boundary as the benchmark.  Expected
answers are accepted only while fitting on the public-keyed development corpus.
The frozen result retains ranks, counts and attack names, but no answer values;
prediction on a holdout needs only the attacks' answer vectors.
"""
from __future__ import annotations

from collections.abc import Hashable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from itertools import permutations
from math import comb, factorial


DEFAULT_FAMILYWISE_ALPHA = Fraction(1, 20)
MIN_SCENES_PER_FAMILY = 20
PREDECLARED_SIGNAL_PROBABILITY = Fraction(1, 2)
PREDECLARED_TARGET_POWER = Fraction(99, 100)
SCENE_CANDIDATE_COUNT = 5
SPARSE_POWER_SCENES_PER_FAMILY = 60
ONE_CORRECT_EDGE_EVERY_SCENE = "one-correct-edge-every-scene-v1"
WHOLE_MAPPING_QUARTER_SCENES = "whole-mapping-quarter-scenes-v1"
WHOLE_MAPPING_QUARTER_PROBABILITY = Fraction(1, 4)


def _probability(value, *, name: str, allow_zero: bool = False) -> Fraction:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be a probability, not bool")
    try:
        result = value if isinstance(value, Fraction) else Fraction(str(value))
    except (TypeError, ValueError, ZeroDivisionError) as exc:
        raise TypeError(f"{name} must be an exact probability") from exc
    lower_ok = result >= 0 if allow_zero else result > 0
    if not lower_ok or result > 1:
        boundary = "0 <=" if allow_zero else "0 <"
        raise ValueError(f"{name} must satisfy {boundary} {name} <= 1")
    return result


def _positive_integer(value, *, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _unique(values: tuple[Hashable, ...], *, name: str) -> bool:
    try:
        return len(set(values)) == len(values)
    except TypeError as exc:
        raise TypeError(f"{name} values must be hashable") from exc


@dataclass(frozen=True)
class PermutationScene:
    """One observed and one predicted assignment over a candidate universe."""

    predicted: tuple[Hashable, ...]
    observed: tuple[Hashable, ...]
    candidates: tuple[Hashable, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "predicted", tuple(self.predicted))
        object.__setattr__(self, "observed", tuple(self.observed))
        object.__setattr__(self, "candidates", tuple(self.candidates))
        size = len(self.candidates)
        if size < 2:
            raise ValueError("a permutation scene needs at least two candidates")
        if len(self.predicted) != size or len(self.observed) != size:
            raise ValueError("predicted, observed and candidate vectors must have equal length")
        if not _unique(self.candidates, name="candidate"):
            raise ValueError("candidate values must be unique")
        try:
            observed_matches = set(self.observed) == set(self.candidates)
        except TypeError as exc:
            raise TypeError("observed values must be hashable") from exc
        if not observed_matches or not _unique(self.observed, name="observed"):
            raise ValueError("observed answers must be a bijection over the candidates")


@dataclass(frozen=True)
class ExactPermutationResult:
    """Exact upper-tail inference, retaining the integer null distribution."""

    observed_hits: int
    total_questions: int
    scene_count: int
    null_counts: tuple[int, ...]
    total_assignments: int
    upper_tail: Fraction

    @property
    def p_value(self) -> Fraction:
        return self.upper_tail


def _convolve_counts(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    combined = [0] * (len(left) + len(right) - 1)
    for left_hits, left_count in enumerate(left):
        for right_hits, right_count in enumerate(right):
            combined[left_hits + right_hits] += left_count * right_count
    return tuple(combined)


def scene_permutation_counts(scene: PermutationScene) -> tuple[int, ...]:
    """Count predicted hits across every candidate assignment for one scene."""
    counts = [0] * (len(scene.candidates) + 1)
    for assignment in permutations(scene.candidates):
        hits = sum(
            predicted == assigned
            for predicted, assigned in zip(scene.predicted, assignment, strict=True)
        )
        counts[hits] += 1
    return tuple(counts)


def exact_permutation_inference(
    scenes: Sequence[PermutationScene],
    *,
    candidate_count: int | None = SCENE_CANDIDATE_COUNT,
) -> ExactPermutationResult:
    """Convolve exact within-scene permutation nulls and return an upper-tail test.

    ``candidate_count`` defaults to Benchmark v2's five-way contract.  Passing
    ``None`` permits other complete permutation scene sizes without changing the
    inference method.
    """
    if not scenes:
        raise ValueError("exact permutation inference requires at least one scene")
    if candidate_count is not None:
        _positive_integer(candidate_count, name="candidate_count")

    distribution: tuple[int, ...] = (1,)
    observed_hits = 0
    total_questions = 0
    for scene in scenes:
        if not isinstance(scene, PermutationScene):
            raise TypeError("scenes must contain PermutationScene instances")
        if candidate_count is not None and len(scene.candidates) != candidate_count:
            raise ValueError(
                f"scene has {len(scene.candidates)} candidates; expected {candidate_count}"
            )
        observed_hits += sum(
            predicted == observed
            for predicted, observed in zip(scene.predicted, scene.observed, strict=True)
        )
        total_questions += len(scene.observed)
        distribution = _convolve_counts(distribution, scene_permutation_counts(scene))

    total_assignments = sum(distribution)
    tail_count = sum(distribution[observed_hits:])
    return ExactPermutationResult(
        observed_hits=observed_hits,
        total_questions=total_questions,
        scene_count=len(scenes),
        null_counts=distribution,
        total_assignments=total_assignments,
        upper_tail=Fraction(tail_count, total_assignments),
    )


def bonferroni_alpha(familywise_alpha, comparisons: int) -> Fraction:
    """Return an exact per-comparison alpha under Bonferroni correction."""
    alpha = _probability(familywise_alpha, name="familywise_alpha")
    return alpha / _positive_integer(comparisons, name="comparisons")


def is_bonferroni_significant(
    p_value,
    *,
    familywise_alpha=DEFAULT_FAMILYWISE_ALPHA,
    comparisons: int,
) -> bool:
    """Use the predeclared inclusive rejection rule ``p <= alpha / m``."""
    probability = _probability(p_value, name="p_value", allow_zero=True)
    return probability <= bonferroni_alpha(familywise_alpha, comparisons)


def require_minimum_scene_counts(
    scene_counts: Mapping[Hashable, int],
    *,
    minimum: int = MIN_SCENES_PER_FAMILY,
) -> None:
    """Reject missing or under-sized scene families before any score is reported."""
    minimum = _positive_integer(minimum, name="minimum")
    if not scene_counts:
        raise ValueError("scene counts must contain at least one family")
    invalid = {
        key: count
        for key, count in scene_counts.items()
        if type(count) is not int or count < minimum
    }
    if invalid:
        detail = ", ".join(
            f"{key!r}={count!r}" for key, count in sorted(invalid.items(), key=lambda item: repr(item[0]))
        )
        raise ValueError(f"each family requires at least {minimum} scenes; under minimum: {detail}")


def fixed_point_permutation_counts(candidate_count: int) -> tuple[int, ...]:
    """Number of permutations having each possible count of fixed points."""
    candidate_count = _positive_integer(candidate_count, name="candidate_count")
    derangements = [1]
    if candidate_count >= 1:
        derangements.append(0)
    for size in range(2, candidate_count + 1):
        derangements.append(
            (size - 1) * (derangements[size - 1] + derangements[size - 2])
        )
    return tuple(
        comb(candidate_count, hits) * derangements[candidate_count - hits]
        for hits in range(candidate_count + 1)
    )


def _convolve_probabilities(
    left: Sequence[Fraction], right: Sequence[Fraction]
) -> tuple[Fraction, ...]:
    combined = [Fraction(0)] * (len(left) + len(right) - 1)
    for left_hits, left_probability in enumerate(left):
        for right_hits, right_probability in enumerate(right):
            combined[left_hits + right_hits] += left_probability * right_probability
    return tuple(combined)


@dataclass(frozen=True)
class PermutationPowerContract:
    """Exact power for a predeclared scene-level mixture alternative.

    Under the alternative, a scene's complete mapping is recovered with
    ``signal_probability``; otherwise its mapping is a uniformly random
    permutation.  Dependence inside a scene is retained in both branches.
    """

    scene_count: int
    candidate_count: int
    minimum_scenes: int
    comparisons: int
    familywise_alpha: Fraction
    adjusted_alpha: Fraction
    critical_hits: int | None
    null_upper_tail: Fraction
    signal_probability: Fraction
    target_power: Fraction
    power: Fraction

    @property
    def minimum_met(self) -> bool:
        return self.scene_count >= self.minimum_scenes

    @property
    def target_met(self) -> bool:
        return self.power >= self.target_power

    @property
    def satisfied(self) -> bool:
        return self.minimum_met and self.target_met


def permutation_power_contract(
    scene_count: int,
    *,
    comparisons: int,
    candidate_count: int = SCENE_CANDIDATE_COUNT,
    familywise_alpha=DEFAULT_FAMILYWISE_ALPHA,
    minimum_scenes: int = MIN_SCENES_PER_FAMILY,
    signal_probability=PREDECLARED_SIGNAL_PROBABILITY,
    target_power=PREDECLARED_TARGET_POWER,
) -> PermutationPowerContract:
    """Compute the exact finite-sample power contract without a binomial model."""
    scene_count = _positive_integer(scene_count, name="scene_count")
    candidate_count = _positive_integer(candidate_count, name="candidate_count")
    minimum_scenes = _positive_integer(minimum_scenes, name="minimum_scenes")
    comparisons = _positive_integer(comparisons, name="comparisons")
    alpha = _probability(familywise_alpha, name="familywise_alpha")
    signal = _probability(
        signal_probability, name="signal_probability", allow_zero=True
    )
    target = _probability(target_power, name="target_power")
    adjusted_alpha = alpha / comparisons

    one_scene_counts = fixed_point_permutation_counts(candidate_count)
    null_counts: tuple[int, ...] = (1,)
    for _ in range(scene_count):
        null_counts = _convolve_counts(null_counts, one_scene_counts)
    null_denominator = factorial(candidate_count) ** scene_count

    critical_hits = None
    null_upper_tail = Fraction(0)
    for hits in range(candidate_count * scene_count + 1):
        tail = Fraction(sum(null_counts[hits:]), null_denominator)
        if tail <= adjusted_alpha:
            critical_hits = hits
            null_upper_tail = tail
            break

    random_weight = 1 - signal
    one_scene_alternative = tuple(
        random_weight * Fraction(count, factorial(candidate_count))
        + (signal if hits == candidate_count else 0)
        for hits, count in enumerate(one_scene_counts)
    )
    alternative: tuple[Fraction, ...] = (Fraction(1),)
    for _ in range(scene_count):
        alternative = _convolve_probabilities(alternative, one_scene_alternative)
    power = (
        sum(alternative[critical_hits:], Fraction(0))
        if critical_hits is not None
        else Fraction(0)
    )

    return PermutationPowerContract(
        scene_count=scene_count,
        candidate_count=candidate_count,
        minimum_scenes=minimum_scenes,
        comparisons=comparisons,
        familywise_alpha=alpha,
        adjusted_alpha=adjusted_alpha,
        critical_hits=critical_hits,
        null_upper_tail=null_upper_tail,
        signal_probability=signal,
        target_power=target,
        power=power,
    )


@dataclass(frozen=True)
class NamedSparseAlternativePower:
    """Exact power for one named, predeclared sparse shortcut alternative."""

    name: str
    model: str
    signal_probability: Fraction
    one_scene_probabilities: tuple[Fraction, ...]
    power: Fraction
    minimum_scenes_for_target: int | None
    target_power: Fraction

    @property
    def target_met(self) -> bool:
        return self.power >= self.target_power


@dataclass(frozen=True)
class SparsePermutationPowerContract:
    """Exact family-level power contract over all named sparse alternatives."""

    scene_count: int
    candidate_count: int
    minimum_scenes: int
    comparisons: int
    familywise_alpha: Fraction
    adjusted_alpha: Fraction
    critical_hits: int | None
    null_upper_tail: Fraction
    target_power: Fraction
    alternatives: tuple[NamedSparseAlternativePower, ...]

    @property
    def minimum_met(self) -> bool:
        return self.scene_count >= self.minimum_scenes

    @property
    def target_met(self) -> bool:
        return all(alternative.target_met for alternative in self.alternatives)

    @property
    def satisfied(self) -> bool:
        return self.minimum_met and self.target_met

    @property
    def worst_case_power(self) -> Fraction:
        return min(alternative.power for alternative in self.alternatives)

    def alternative(self, name: str) -> NamedSparseAlternativePower:
        """Return one named alternative or fail rather than silently substituting one."""
        for alternative in self.alternatives:
            if alternative.name == name:
                return alternative
        raise KeyError(name)


@dataclass(frozen=True)
class _SparseAlternativeDefinition:
    name: str
    model: str
    signal_probability: Fraction
    one_scene_probabilities: tuple[Fraction, ...]


def _sparse_alternative_definitions(
    candidate_count: int,
) -> tuple[_SparseAlternativeDefinition, ...]:
    """Build the two exact one-scene alternatives without sampling."""
    remaining_count = candidate_count - 1
    remaining_denominator = factorial(remaining_count)
    one_edge = (Fraction(0),) + tuple(
        Fraction(count, remaining_denominator)
        for count in fixed_point_permutation_counts(remaining_count)
    )

    null_counts = fixed_point_permutation_counts(candidate_count)
    null_denominator = factorial(candidate_count)
    whole_mapping_probability = WHOLE_MAPPING_QUARTER_PROBABILITY
    whole_mapping_quarter = tuple(
        (1 - whole_mapping_probability) * Fraction(count, null_denominator)
        + (whole_mapping_probability if hits == candidate_count else 0)
        for hits, count in enumerate(null_counts)
    )
    return (
        _SparseAlternativeDefinition(
            name=ONE_CORRECT_EDGE_EVERY_SCENE,
            model="one-fixed-edge-plus-uniform-remaining-bijection-v1",
            signal_probability=Fraction(1),
            one_scene_probabilities=one_edge,
        ),
        _SparseAlternativeDefinition(
            name=WHOLE_MAPPING_QUARTER_SCENES,
            model="whole-mapping-recovery-mixture-v1",
            signal_probability=whole_mapping_probability,
            one_scene_probabilities=whole_mapping_quarter,
        ),
    )


def _critical_region(
    null_counts: Sequence[int],
    *,
    null_denominator: int,
    adjusted_alpha: Fraction,
) -> tuple[int | None, Fraction]:
    for hits in range(len(null_counts)):
        tail = Fraction(sum(null_counts[hits:]), null_denominator)
        if tail <= adjusted_alpha:
            return hits, tail
    return None, Fraction(0)


def sparse_permutation_power_contract(
    scene_count: int,
    *,
    comparisons: int,
    candidate_count: int = SCENE_CANDIDATE_COUNT,
    familywise_alpha=DEFAULT_FAMILYWISE_ALPHA,
    minimum_scenes: int = SPARSE_POWER_SCENES_PER_FAMILY,
    target_power=PREDECLARED_TARGET_POWER,
) -> SparsePermutationPowerContract:
    """Evaluate exact power for both predeclared sparse alternatives.

    ``one-correct-edge-every-scene-v1`` fixes one specified edge in every scene and
    uniformly permutes the remaining candidates. ``whole-mapping-quarter-scenes-v1``
    independently recovers the complete mapping with probability one quarter and otherwise
    draws a uniform candidate permutation. The returned minimum for each alternative is the
    first exact scene count, up to the larger of ``scene_count`` and ``minimum_scenes``, whose
    power reaches ``target_power``. A missing minimum means the predeclared evaluated range is
    insufficient; it is never extrapolated from a simulation or asymptotic approximation.
    """
    scene_count = _positive_integer(scene_count, name="scene_count")
    candidate_count = _positive_integer(candidate_count, name="candidate_count")
    if candidate_count < 2:
        raise ValueError("candidate_count must be at least two for a sparse edge alternative")
    comparisons = _positive_integer(comparisons, name="comparisons")
    minimum_scenes = _positive_integer(minimum_scenes, name="minimum_scenes")
    alpha = _probability(familywise_alpha, name="familywise_alpha")
    target = _probability(target_power, name="target_power")
    adjusted_alpha = alpha / comparisons

    definitions = _sparse_alternative_definitions(candidate_count)
    null_one_scene = fixed_point_permutation_counts(candidate_count)
    null_denominator_per_scene = factorial(candidate_count)
    null_counts: tuple[int, ...] = (1,)
    null_denominator = 1
    alternative_distributions = {
        definition.name: (Fraction(1),) for definition in definitions
    }
    minimums: dict[str, int] = {}
    requested_critical_hits: int | None = None
    requested_null_tail = Fraction(0)
    requested_powers: dict[str, Fraction] = {}

    for current_scene_count in range(1, max(scene_count, minimum_scenes) + 1):
        null_counts = _convolve_counts(null_counts, null_one_scene)
        null_denominator *= null_denominator_per_scene
        critical_hits, null_tail = _critical_region(
            null_counts,
            null_denominator=null_denominator,
            adjusted_alpha=adjusted_alpha,
        )
        for definition in definitions:
            distribution = _convolve_probabilities(
                alternative_distributions[definition.name],
                definition.one_scene_probabilities,
            )
            alternative_distributions[definition.name] = distribution
            power = (
                sum(distribution[critical_hits:], Fraction(0))
                if critical_hits is not None
                else Fraction(0)
            )
            if power >= target and definition.name not in minimums:
                minimums[definition.name] = current_scene_count
            if current_scene_count == scene_count:
                requested_powers[definition.name] = power
        if current_scene_count == scene_count:
            requested_critical_hits = critical_hits
            requested_null_tail = null_tail

    alternatives = tuple(
        NamedSparseAlternativePower(
            name=definition.name,
            model=definition.model,
            signal_probability=definition.signal_probability,
            one_scene_probabilities=definition.one_scene_probabilities,
            power=requested_powers[definition.name],
            minimum_scenes_for_target=minimums.get(definition.name),
            target_power=target,
        )
        for definition in definitions
    )
    return SparsePermutationPowerContract(
        scene_count=scene_count,
        candidate_count=candidate_count,
        minimum_scenes=minimum_scenes,
        comparisons=comparisons,
        familywise_alpha=alpha,
        adjusted_alpha=adjusted_alpha,
        critical_hits=requested_critical_hits,
        null_upper_tail=requested_null_tail,
        target_power=target,
        alternatives=alternatives,
    )


@dataclass(frozen=True)
class RankPermutationModel:
    """One attack's fixed rank permutation selected on development scenes."""

    attack: str
    permutation: tuple[int, ...]
    dev_hits_by_slot: tuple[int, ...]
    dev_scene_count: int

    @property
    def dev_hits(self) -> int:
        return sum(self.dev_hits_by_slot)

    @property
    def dev_total(self) -> int:
        return self.dev_scene_count * len(self.permutation)

    @property
    def dev_accuracy(self) -> Fraction:
        return Fraction(self.dev_hits, self.dev_total)

    def predict(self, answers: Sequence[Hashable]) -> tuple[Hashable, ...]:
        """Apply the frozen rank mapping without consulting expected answers."""
        answers = tuple(answers)
        if len(answers) != len(self.permutation):
            raise ValueError(
                f"attack {self.attack!r} supplied {len(answers)} answers; "
                f"expected {len(self.permutation)}"
            )
        return tuple(answers[index] for index in self.permutation)


@dataclass(frozen=True)
class RankUnionModel:
    """Per-slot union of fitted attack rank models, selected only on development."""

    candidate_count: int
    dev_scene_count: int
    models: tuple[RankPermutationModel, ...]
    slot_attacks: tuple[str, ...]

    def _model_map(self) -> dict[str, RankPermutationModel]:
        return {model.attack: model for model in self.models}

    @property
    def dev_hits_by_slot(self) -> tuple[int, ...]:
        models = self._model_map()
        return tuple(
            models[attack].dev_hits_by_slot[slot]
            for slot, attack in enumerate(self.slot_attacks)
        )

    @property
    def dev_accuracy(self) -> Fraction:
        return Fraction(
            sum(self.dev_hits_by_slot), self.dev_scene_count * self.candidate_count
        )

    def predict(
        self, attack_answers: Mapping[str, Sequence[Hashable]]
    ) -> tuple[Hashable, ...]:
        """Choose each slot from its development-selected attack and rank mapping."""
        models = self._model_map()
        corrected: dict[str, tuple[Hashable, ...]] = {}
        for attack in set(self.slot_attacks):
            if attack not in attack_answers:
                raise ValueError(f"holdout answers are missing selected attack {attack!r}")
            corrected[attack] = models[attack].predict(attack_answers[attack])
        return tuple(
            corrected[attack][slot]
            for slot, attack in enumerate(self.slot_attacks)
        )

    def predict_many(
        self, attack_scenes: Mapping[str, Sequence[Sequence[Hashable]]]
    ) -> tuple[tuple[Hashable, ...], ...]:
        """Apply the frozen union to equally-sized holdout attack matrices."""
        selected = set(self.slot_attacks)
        missing = selected - set(attack_scenes)
        if missing:
            raise ValueError(f"holdout answers are missing selected attacks: {sorted(missing)!r}")
        lengths = {len(attack_scenes[attack]) for attack in selected}
        if len(lengths) != 1:
            raise ValueError("selected holdout attack matrices have different scene counts")
        scene_count = lengths.pop()
        return tuple(
            self.predict(
                {attack: attack_scenes[attack][index] for attack in selected}
            )
            for index in range(scene_count)
        )


def _validated_training_matrices(
    expected_scenes: Sequence[Sequence[Hashable]],
    attack_scenes: Mapping[str, Sequence[Sequence[Hashable]]],
    *,
    candidate_count: int,
) -> tuple[tuple[tuple[Hashable, ...], ...], dict[str, tuple[tuple[Hashable, ...], ...]]]:
    expected = tuple(tuple(scene) for scene in expected_scenes)
    if not expected:
        raise ValueError("rank training requires at least one development scene")
    for index, scene in enumerate(expected):
        if len(scene) != candidate_count or not _unique(scene, name="expected"):
            raise ValueError(
                f"development scene {index} is not a {candidate_count}-answer bijection"
            )
    if not attack_scenes:
        raise ValueError("rank training requires at least one attack")

    attacks: dict[str, tuple[tuple[Hashable, ...], ...]] = {}
    for attack, scenes in attack_scenes.items():
        if not isinstance(attack, str) or not attack:
            raise ValueError("attack names must be non-empty strings")
        rows = tuple(tuple(scene) for scene in scenes)
        if len(rows) != len(expected):
            raise ValueError(
                f"attack {attack!r} has {len(rows)} scenes; expected {len(expected)}"
            )
        for index, (observed, predicted) in enumerate(zip(expected, rows, strict=True)):
            if len(predicted) != candidate_count:
                raise ValueError(
                    f"attack {attack!r} scene {index} has {len(predicted)} answers; "
                    f"expected {candidate_count}"
                )
            try:
                complete = set(predicted) == set(observed) and _unique(
                    predicted, name="attack prediction"
                )
            except TypeError as exc:
                raise TypeError(
                    f"attack {attack!r} scene {index} answers must be hashable"
                ) from exc
            if not complete:
                raise ValueError(
                    f"attack {attack!r} scene {index} is not a complete answer bijection"
                )
        attacks[attack] = rows
    return expected, attacks


def train_rank_union(
    expected_scenes: Sequence[Sequence[Hashable]],
    attack_scenes: Mapping[str, Sequence[Sequence[Hashable]]],
    *,
    candidate_count: int = SCENE_CANDIDATE_COUNT,
) -> RankUnionModel:
    """Fit fixed attack permutations, then the strongest attack for each question slot.

    All ``candidate_count!`` rank mappings are evaluated for every complete attack.
    The best aggregate development mapping is frozen (lexicographic permutation breaks
    exact ties), after which each slot selects the fitted attack with the most development
    hits.  Attack name and permutation provide deterministic slot-level tie breaks.
    """
    candidate_count = _positive_integer(candidate_count, name="candidate_count")
    expected, attacks = _validated_training_matrices(
        expected_scenes, attack_scenes, candidate_count=candidate_count
    )

    fitted = []
    for attack in sorted(attacks):
        rows = attacks[attack]
        best_permutation = None
        best_hits_by_slot = None
        best_total = -1
        for permutation in permutations(range(candidate_count)):
            hits_by_slot = tuple(
                sum(
                    predicted[permutation[slot]] == observed[slot]
                    for observed, predicted in zip(expected, rows, strict=True)
                )
                for slot in range(candidate_count)
            )
            total = sum(hits_by_slot)
            if (
                total > best_total
                or total == best_total
                and (best_permutation is None or permutation < best_permutation)
            ):
                best_total = total
                best_permutation = permutation
                best_hits_by_slot = hits_by_slot
        if best_permutation is None or best_hits_by_slot is None:  # pragma: no cover
            raise AssertionError("positive candidate count produced no permutations")
        fitted.append(
            RankPermutationModel(
                attack=attack,
                permutation=best_permutation,
                dev_hits_by_slot=best_hits_by_slot,
                dev_scene_count=len(expected),
            )
        )

    models = tuple(fitted)
    slot_attacks = tuple(
        min(
            models,
            key=lambda model: (
                -model.dev_hits_by_slot[slot],
                model.attack,
                model.permutation,
            ),
        ).attack
        for slot in range(candidate_count)
    )
    return RankUnionModel(
        candidate_count=candidate_count,
        dev_scene_count=len(expected),
        models=models,
        slot_attacks=slot_attacks,
    )


__all__ = [
    "DEFAULT_FAMILYWISE_ALPHA",
    "ExactPermutationResult",
    "MIN_SCENES_PER_FAMILY",
    "NamedSparseAlternativePower",
    "ONE_CORRECT_EDGE_EVERY_SCENE",
    "PREDECLARED_SIGNAL_PROBABILITY",
    "PREDECLARED_TARGET_POWER",
    "PermutationPowerContract",
    "PermutationScene",
    "RankPermutationModel",
    "RankUnionModel",
    "SCENE_CANDIDATE_COUNT",
    "SPARSE_POWER_SCENES_PER_FAMILY",
    "SparsePermutationPowerContract",
    "WHOLE_MAPPING_QUARTER_PROBABILITY",
    "WHOLE_MAPPING_QUARTER_SCENES",
    "bonferroni_alpha",
    "exact_permutation_inference",
    "fixed_point_permutation_counts",
    "is_bonferroni_significant",
    "permutation_power_contract",
    "require_minimum_scene_counts",
    "scene_permutation_counts",
    "sparse_permutation_power_contract",
    "train_rank_union",
]
