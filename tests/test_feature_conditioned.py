# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Public-key, leave-one-out checks for the feature-conditioned shortcut audit."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import json

import pytest

from artifactforge import suite
from artifactforge.bench import feature_conditioned
from artifactforge.bench.benchmark import frozen_public_tasks, generate_suite
from artifactforge.bench.feature_conditioned import (
    FEATURE_EXTRACTION_DOMAIN,
    MAX_MODEL_BRANCHES,
    POSITIVE_CONTROL_PROVENANCE,
    PUBLIC_DEVELOPMENT_KEYS,
    PUBLIC_DEVELOPMENT_KEY_DOMAIN,
    PUBLIC_DEVELOPMENT_SCENARIOS_PER_KEY,
    build_public_development_corpus,
    fit_feature_conditioned,
    labeled_public_corpus,
    leave_one_key_out,
    predict_feature_conditioned,
)
from artifactforge.bench.positive_controls import calibrate_feature_conditioned_control
from artifactforge.compose.derivation import (
    FIXTURE_V2_CONTENT_DOMAIN,
    FIXTURE_V2_VALUE_DOMAIN,
)
from artifactforge.inventory import inventory_regular_files


EXPECTED_PUBLIC_KEYS = (
    "1fc19b44f4d60f1335980345dfb703b3ae643ba5264a5404ac6b70cd5f48719d",
    "6d65808650cfcc25955502d0884c6e9e53fc5c6f5bb629c108c5a4b0be8c2993",
    "3c3e0bfef43ed6c4a27c2acb9f673301fa1169256f5cc743c14b2ffa71dcaa9f",
    "93d15d1fbbef12b8c1e421900a6c90be8aa4ce4aab5682ac94a4a9a9a160f4f4",
)


@pytest.fixture(scope="module")
def public_feature_corpora(tmp_path_factory):
    root = tmp_path_factory.mktemp("feature-conditioned")
    stack = ExitStack()
    private = []
    corpora = []
    try:
        for key_index, key in enumerate(PUBLIC_DEVELOPMENT_KEYS):
            evaluator = root / f"evaluator-{key_index}"
            exported = root / f"public-{key_index}"
            private.append(
                tuple(
                    generate_suite(
                        PUBLIC_DEVELOPMENT_SCENARIOS_PER_KEY,
                        str(evaluator),
                        key=key,
                        kind=suite.HOLDOUT_SUITE_KIND,
                    )
                )
            )
            suite.export_public(str(evaluator), str(exported))
            document, public_tasks = stack.enter_context(frozen_public_tasks(exported))
            assert document["suite_kind"] == suite.HOLDOUT_SUITE_KIND
            assert not any("_answers" in task.directory for task in public_tasks)
            corpora.append(build_public_development_corpus(key_index, public_tasks))
        yield tuple(corpora), tuple(private)
    finally:
        stack.close()


def _selected_source_digests(corpora):
    digests = {}
    for corpus in corpora:
        selected = {}
        for task in corpus.tasks:
            selected.setdefault(task.family, task)
        for family, task in selected.items():
            digests[(corpus.key_index, family)] = {
                file.relative_path: hashlib.sha256(file.path.read_bytes()).hexdigest()
                for file in inventory_regular_files(task.directory)
            }
    return digests


def test_four_development_keys_are_explicit_stable_and_domain_separated():
    assert tuple(key.hex() for key in PUBLIC_DEVELOPMENT_KEYS) == EXPECTED_PUBLIC_KEYS
    assert len(set(PUBLIC_DEVELOPMENT_KEYS)) == 4
    assert not set(PUBLIC_DEVELOPMENT_KEYS) & {
        suite.PUBLIC_DEV_KEY,
        suite.scorecard_measurement_key(),
    }
    unrelated_domains = {
        suite.DOMAIN,
        suite.BENCHMARK_V3_DOMAIN,
        suite.SCENE_VALUE_DOMAIN,
        suite.SCORECARD_MEASUREMENT_KEY_DOMAIN,
        suite.GENERATOR_ASSURANCE_KEY_DOMAIN,
        FIXTURE_V2_VALUE_DOMAIN.encode(),
        FIXTURE_V2_CONTENT_DOMAIN.encode(),
    }
    assert PUBLIC_DEVELOPMENT_KEY_DOMAIN not in unrelated_domains
    assert FEATURE_EXTRACTION_DOMAIN not in unrelated_domains | {PUBLIC_DEVELOPMENT_KEY_DOMAIN}


def test_leave_one_key_out_has_exact_class_coverage_and_stable_results(
    public_feature_corpora,
):
    corpora, _private = public_feature_corpora
    report = leave_one_key_out(corpora)

    assert report.aggregate.correct == 25
    assert report.aggregate.covered == report.aggregate.total == 160
    assert report.aggregate.accuracy.numerator == 5
    assert report.aggregate.accuracy.denominator == 32
    assert report.aggregate.failures == 0
    assert {
        (metric.family, metric.correct, metric.covered, metric.total, metric.failures)
        for metric in report.by_class
    } == {
        ("windows", 18, 80, 80, 0),
        ("macos", 7, 80, 80, 0),
    }
    assert tuple(
        (fold.held_out_key_index, fold.training_key_indices, fold.aggregate.correct)
        for fold in report.folds
    ) == (
        (0, (1, 2, 3), 6),
        (1, (0, 2, 3), 9),
        (2, (0, 1, 3), 5),
        (3, (0, 1, 2), 5),
    )
    assert tuple(
        tuple(
            (model.family, model.feature, model.training_hits, model.training_total)
            for model in fold.model.classes
        )
        for fold in report.folds
    ) == (
        (("macos", "selector-rank", 25, 60), ("windows", "selector-hash-bucket", 24, 60)),
        (("macos", "question-slot", 21, 60), ("windows", "selector-length-mod-5", 23, 60)),
        (("macos", "question-slot", 22, 60), ("windows", "selector-hash-bucket", 24, 60)),
        (("macos", "selector-hash-bucket", 26, 60), ("windows", "question-id-bucket", 22, 60)),
    )
    assert all(fold.model.branch_count <= MAX_MODEL_BRANCHES for fold in report.folds)


def test_held_out_labels_and_private_tasks_cannot_enter_prediction(
    public_feature_corpora,
):
    corpora, private = public_feature_corpora
    model = fit_feature_conditioned(corpora[1:])
    assert model.training_key_indices == (1, 2, 3)
    before = predict_feature_conditioned(model, corpora[0].tasks)

    rotated_labels = {}
    original = corpora[0].labels_by_scenario()
    for task in corpora[0].tasks:
        values = [original[task.scenario_id][question.id] for question in task.questions]
        rotated_labels[task.scenario_id] = {
            question.id: values[(slot + 1) % len(values)]
            for slot, question in enumerate(task.questions)
        }
    altered = labeled_public_corpus(
        0,
        corpora[0].tasks,
        rotated_labels,
        provenance=POSITIVE_CONTROL_PROVENANCE,
    )
    assert predict_feature_conditioned(model, altered.tasks).answers == before.answers

    model_blob = json.dumps(asdict(model), sort_keys=True)
    assert all(key.hex() not in model_blob for key in PUBLIC_DEVELOPMENT_KEYS)
    assert all(
        answer not in model_blob for answers in original.values() for answer in answers.values()
    )
    with pytest.raises(TypeError, match="PublicTask"):
        predict_feature_conditioned(model, [private[0][0]])
    with pytest.raises(TypeError, match="PublicTask"):
        labeled_public_corpus(
            0,
            [private[0][0]],
            {},
            provenance=POSITIVE_CONTROL_PROVENANCE,
        )


def test_public_key_reconstruction_and_input_bounds_fail_closed(public_feature_corpora):
    corpora, _private = public_feature_corpora
    with pytest.raises(ValueError, match="declared key"):
        build_public_development_corpus(1, corpora[0].tasks)
    with pytest.raises(ValueError, match="1-8 public tasks"):
        predict_feature_conditioned(
            fit_feature_conditioned(corpora[1:]),
            corpora[0].tasks + (corpora[0].tasks[0],),
        )


def test_independent_vulnerable_world_control_passes_without_mutating_sources(
    public_feature_corpora,
):
    corpora, _private = public_feature_corpora
    before = _selected_source_digests(corpora)

    report = calibrate_feature_conditioned_control(corpora)

    assert report.passed, report.failures
    assert report.correct == report.covered == report.reference_correct == report.total == 40
    assert {
        (metric.family, metric.correct, metric.covered, metric.total, metric.failures)
        for metric in report.by_class
    } == {
        ("windows", 20, 20, 20, 0),
        ("macos", 20, 20, 20, 0),
    }
    assert len(report.selected_features) == 8
    assert all(feature == "selector-rank" for *_prefix, feature in report.selected_features)
    assert _selected_source_digests(corpora) == before


def test_positive_control_fails_when_the_production_fitter_is_killed(
    public_feature_corpora,
    monkeypatch,
):
    corpora, _private = public_feature_corpora

    def broken_fit(_corpora):
        raise ValueError("mutation killed production feature fitting")

    monkeypatch.setattr(feature_conditioned, "fit_feature_conditioned", broken_fit)
    report = calibrate_feature_conditioned_control(corpora)

    assert not report.passed
    assert any("mutation killed production feature fitting" in item for item in report.failures)
