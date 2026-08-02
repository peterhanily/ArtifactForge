# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Finite-sample validity checks for Benchmark v2's statistical gate."""
from fractions import Fraction

import pytest

from artifactforge.bench.statistics import (
    MIN_SCENES_PER_FAMILY,
    PermutationScene,
    bonferroni_alpha,
    exact_permutation_inference,
    fixed_point_permutation_counts,
    is_bonferroni_significant,
    permutation_power_contract,
    require_minimum_scene_counts,
    scene_permutation_counts,
    train_rank_union,
)


def _scene(prefix: str, predicted_order=(0, 1, 2, 3, 4)) -> PermutationScene:
    candidates = tuple(f"{prefix}-{index}" for index in range(5))
    return PermutationScene(
        predicted=tuple(candidates[index] for index in predicted_order),
        observed=candidates,
        candidates=candidates,
    )


def _answer_scenes(prefix: str, count: int = 20):
    return tuple(
        tuple(f"{prefix}-{scene}-{slot}" for slot in range(5))
        for scene in range(count)
    )


def test_one_scene_uses_the_exact_five_factorial_fixed_point_null():
    scene = _scene("one")

    assert scene_permutation_counts(scene) == (44, 45, 20, 10, 0, 1)
    result = exact_permutation_inference([scene])
    assert result.observed_hits == result.total_questions == 5
    assert result.scene_count == 1
    assert result.null_counts == (44, 45, 20, 10, 0, 1)
    assert result.total_assignments == 120
    assert result.p_value == Fraction(1, 120)


def test_scene_nulls_are_convolved_instead_of_using_binomial_independence():
    result = exact_permutation_inference([_scene("first"), _scene("second")])

    assert result.total_assignments == 120**2
    assert result.observed_hits == 10
    assert result.p_value == Fraction(1, 120**2)
    # Nine hits would require one four-fixed-point permutation, which cannot exist.
    # An independent-question binomial model assigns this impossible outcome positive mass.
    assert result.null_counts[9] == 0


def test_exact_null_also_handles_predictions_that_are_not_bijections():
    candidates = tuple("abcde")
    scene = PermutationScene(
        predicted=("a",) * 5,
        observed=candidates,
        candidates=candidates,
    )

    assert scene_permutation_counts(scene) == (0, 120, 0, 0, 0, 0)
    result = exact_permutation_inference([scene])
    assert result.observed_hits == 1
    assert result.p_value == 1


def test_permutation_scene_requires_observed_answers_to_be_the_candidate_bijection():
    with pytest.raises(ValueError, match="bijection"):
        PermutationScene(
            predicted=tuple("abcde"),
            observed=("a", "a", "c", "d", "e"),
            candidates=tuple("abcde"),
        )


def test_bonferroni_correction_remains_exact_and_uses_an_inclusive_boundary():
    assert bonferroni_alpha(Fraction(1, 20), 36) == Fraction(1, 720)
    assert is_bonferroni_significant(
        Fraction(1, 720), familywise_alpha=Fraction(1, 20), comparisons=36
    )
    assert not is_bonferroni_significant(
        Fraction(1, 719), familywise_alpha=Fraction(1, 20), comparisons=36
    )
    with pytest.raises(ValueError, match="positive integer"):
        bonferroni_alpha(Fraction(1, 20), 0)


def test_twenty_scene_power_contract_is_exact_at_the_scene_level():
    assert fixed_point_permutation_counts(5) == (44, 45, 20, 10, 0, 1)
    contract = permutation_power_contract(20, comparisons=36)

    assert contract.minimum_scenes == MIN_SCENES_PER_FAMILY == 20
    assert contract.adjusted_alpha == Fraction(1, 720)
    assert contract.critical_hits == 36
    assert contract.null_upper_tail <= contract.adjusted_alpha
    assert contract.power > Fraction(99, 100)
    assert contract.minimum_met
    assert contract.target_met
    assert contract.satisfied


def test_every_family_must_meet_the_twenty_scene_minimum():
    require_minimum_scene_counts({"windows": 20, "macos": 20})
    with pytest.raises(ValueError, match=r"macos.*19"):
        require_minimum_scene_counts({"windows": 20, "macos": 19})


def test_rank_training_finds_a_fixed_permutation_and_reuses_it_on_holdout():
    expected = _answer_scenes("dev")
    rotated = tuple(
        (scene[2], scene[3], scene[4], scene[0], scene[1])
        for scene in expected
    )

    union = train_rank_union(expected, {"rotated": rotated})
    model = union.models[0]
    assert model.attack == "rotated"
    assert model.permutation == (3, 4, 0, 1, 2)
    assert model.dev_accuracy == 1
    assert union.slot_attacks == ("rotated",) * 5

    holdout = tuple(f"holdout-{slot}" for slot in range(5))
    holdout_rotated = (holdout[2], holdout[3], holdout[4], holdout[0], holdout[1])
    assert union.predict({"rotated": holdout_rotated}) == holdout


def test_union_combines_disjoint_partial_rank_attacks_selected_only_on_dev():
    expected = _answer_scenes("dev")
    attack_a = []
    attack_b = []
    for index, scene in enumerate(expected):
        # A always owns slots 0-1. Its other three ranks alternate between inverse cycles.
        order_a = (0, 1, 3, 4, 2) if index % 2 == 0 else (0, 1, 4, 2, 3)
        attack_a.append(tuple(scene[position] for position in order_a))
        # B always owns slots 2-4. The first two alternate between identity and swap.
        order_b = (1, 0, 2, 3, 4) if index % 2 == 0 else (0, 1, 2, 3, 4)
        attack_b.append(tuple(scene[position] for position in order_b))

    union = train_rank_union(expected, {"attack_a": attack_a, "attack_b": attack_b})
    models = {model.attack: model for model in union.models}
    assert models["attack_a"].dev_accuracy < 1
    assert models["attack_b"].dev_accuracy < 1
    assert union.slot_attacks == (
        "attack_a",
        "attack_a",
        "attack_b",
        "attack_b",
        "attack_b",
    )
    assert union.dev_accuracy == 1

    holdout_expected = _answer_scenes("holdout", count=4)
    holdout_a = []
    holdout_b = []
    for index, scene in enumerate(holdout_expected):
        order_a = (0, 1, 3, 4, 2) if index % 2 == 0 else (0, 1, 4, 2, 3)
        order_b = (1, 0, 2, 3, 4) if index % 2 == 0 else (0, 1, 2, 3, 4)
        holdout_a.append(tuple(scene[position] for position in order_a))
        holdout_b.append(tuple(scene[position] for position in order_b))

    assert union.predict_many(
        {"attack_a": holdout_a, "attack_b": holdout_b}
    ) == holdout_expected


def test_rank_training_rejects_an_incomplete_attack_before_fitting():
    expected = _answer_scenes("dev", count=2)
    incomplete = [
        (scene[0], scene[0], scene[2], scene[3], scene[4])
        for scene in expected
    ]
    with pytest.raises(ValueError, match="complete answer bijection"):
        train_rank_union(expected, {"incomplete": incomplete})
