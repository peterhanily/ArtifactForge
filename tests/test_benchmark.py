# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The benchmark's validity, from both directions.

The reference solver proves the answers are recoverable from the artifacts. The adversaries
prove they are not recoverable any other way. Only the first of those was ever checked here,
while a solver that opened zero files was scoring 100%.
"""

import json
import os

import pytest

from artifactforge import suite
from artifactforge.bench.adversary import blind_solve
from artifactforge.bench.benchmark import generate_suite, grade
from artifactforge.bench.reference_solver import ALLOWED_RULES, reference_solve, resolve_task
from artifactforge.inventory import MAX_SCENE_FILES, inventory_regular_files

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")

HOLDOUT_KEY = bytes.fromhex("5f" * 32)  # fixed so the test is deterministic, unpublished


def _dev(tmp_path, n=4, name="dev"):
    return generate_suite(n, str(tmp_path / name), key=suite.PUBLIC_DEV_KEY, kind="dev")


def _holdout(tmp_path, n=4, name="holdout"):
    return generate_suite(n, str(tmp_path / name), key=HOLDOUT_KEY, kind="holdout")


def _score(tasks, solver):
    c = t = 0
    for task in tasks:
        s = grade(task, solver(task.public()))
        c += s.correct
        t += s.total
    return c / t


@pytest.mark.parametrize("count", (1, 40, suite.BENCHMARK_MAX_SCENARIOS))
def test_benchmark_scenario_count_contract_accepts_declared_range(count):
    assert suite.validate_benchmark_scenario_count(count) == count


@pytest.mark.parametrize("count", (True, 0, -1, 1.5, "40", 201))
def test_benchmark_scenario_count_contract_rejects_out_of_range_values(count):
    with pytest.raises(ValueError, match="suite size"):
        suite.validate_benchmark_scenario_count(count)


def test_oversized_suite_is_rejected_before_destination_mutation(tmp_path):
    destination = tmp_path / "must-not-exist"
    with pytest.raises(ValueError, match="between 1 and 200"):
        generate_suite(
            suite.BENCHMARK_MAX_SCENARIOS + 1,
            os.fspath(destination),
            key=HOLDOUT_KEY,
            kind="holdout",
        )
    assert not destination.exists()


def test_current_family_file_schedule_fits_the_hard_inventory_limit(tmp_path):
    tasks = _dev(tmp_path, n=2, name="count-contract")
    observed = {task.family: len(inventory_regular_files(task.directory)) for task in tasks}
    assert observed == dict(suite.BENCHMARK_ARTIFACT_FILES_PER_SCENE)
    assert suite.benchmark_public_file_count(2) == 1 + sum(observed.values())
    assert suite.benchmark_public_file_count(suite.BENCHMARK_MAX_SCENARIOS) == 3001
    assert suite.benchmark_public_file_count(suite.BENCHMARK_MAX_SCENARIOS) <= MAX_SCENE_FILES


def test_impossible_population_has_no_scorecard_provenance():
    with pytest.raises(ValueError, match="between 1 and 200"):
        suite.scorecard_measurement_provenance(suite.BENCHMARK_MAX_SCENARIOS + 1)


def test_reference_solver_scores_100(tmp_path):
    for task in _holdout(tmp_path):
        score = grade(task, reference_solve(task.public()))
        assert score.accuracy == 1.0, (task.scenario_id, score.per_question)


def test_registered_adversaries_pass_the_exact_powered_gate(tmp_path):
    from artifactforge.gates import solvability

    tasks = _holdout(tmp_path, n=40)
    assert _score(tasks, blind_solve) == 0.0
    report = solvability.run(tasks, _dev(tmp_path, n=40))
    assert report.ok, report.render()
    assert report.metrics["chance_floor"] == 0.2
    assert report.metrics["randomization_comparisons"] == (
        suite.BENCHMARK_RANDOMIZATION_COMPARISONS
    )
    assert report.metrics["trained_rank_union_inference_valid"] is True
    assert report.metrics["trained_partial_union_inference_valid"] is True
    assert report.metrics["trained_partial_union_output_coverage"] == 1.0
    assert report.metrics["trained_partial_union_source_coverage"] <= 1.0
    for family, rule in suite.BENCHMARK_QUESTION_RULES:
        stem = f"trained_partial_union_{family}_{rule.replace('-', '_')}"
        assert f"{stem}_score" in report.metrics
        assert f"{stem}_randomization_p" in report.metrics
        assert f"{stem}_source_coverage" in report.metrics


def test_the_blind_adversary_does_beat_a_dev_suite(tmp_path):
    """The control. A blind adversary that cannot cheat the suite built with the published
    key is broken, and its zero against a hold-out suite would then prove nothing."""
    assert _score(_dev(tmp_path), blind_solve) == 1.0


def test_every_question_is_a_closed_multi_artifact_resolution(tmp_path):
    for task in _holdout(tmp_path):
        resolved = resolve_task(task.public())
        assert len(task.questions) == 5
        assert {question.rule for question in task.questions} <= set(ALLOWED_RULES)
        universe = None
        for question in task.questions:
            result = resolved[question.id]
            assert len(set(result.artifacts)) >= 2
            assert len(result.candidates) == len(set(result.candidates)) == 5
            assert result.value == question.expected
            assert question.candidate_count == 5
            universe = set(result.candidates) if universe is None else universe
            assert set(result.candidates) == universe
        assert {question.expected for question in task.questions} == universe


def test_public_task_carries_no_answer(tmp_path):
    task = _holdout(tmp_path, n=2)[0]
    blob = json.dumps(task.public(), default=lambda o: getattr(o, "__dict__", str(o)))
    assert "expected" not in blob
    for q in task.questions:
        assert str(q.expected) not in blob, q.id


def test_the_answer_key_is_not_inside_the_served_directory(tmp_path):
    root = str(tmp_path / "holdout")
    tasks = _holdout(tmp_path)
    paths = suite.suite_paths(root)
    for t in tasks:
        served = os.path.realpath(t.directory)
        for private in ("answers", "content", "key"):
            assert not os.path.realpath(paths[private]).startswith(served + os.sep)
        assert not any(f.upper().startswith("JOIN") for f in os.listdir(served))
    assert os.path.exists(os.path.join(paths["answers"], tasks[0].scenario_id + ".json"))


@pytest.mark.parametrize(
    "relative_path",
    (
        "ARTIFACT_ANSWERS.json",
        "private/GroUnd_TrUth.JsOn",
        "nested/deeper/JOIN_MANIFEST.JSON",
        ".metadata/FixTure.Json",
    ),
)
def test_disclosure_filename_cannot_enter_a_served_benchmark_scene(tmp_path, relative_path):
    staging = tmp_path / "staging"
    source = staging / relative_path
    source.parent.mkdir(parents=True)
    source.write_text("private benchmark metadata")

    with pytest.raises(ValueError, match="benchmark disclosure metadata"):
        suite.stage(str(tmp_path / "served"), str(staging), [relative_path])
    assert not (tmp_path / "served").exists()


def test_fixture_manifest_marker_cannot_enter_a_served_benchmark_scene(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "innocent.json").write_text('{"schema":"artifactforge-fixture-manifest-v1"}\n')
    with pytest.raises(ValueError, match="benchmark disclosure metadata"):
        suite.stage(str(tmp_path / "served"), str(staging), ["innocent.json"])
    assert not (tmp_path / "served").exists()


def test_benign_near_disclosure_names_can_enter_a_served_benchmark_scene(tmp_path):
    staging = tmp_path / "staging"
    relative_paths = (
        "ARTIFACT_ANSWER.json",
        "nested/GROUND_TRUTHS.json",
        "nested/deeper/JOIN-MANIFEST.json",
        ".metadata/myfixture.json",
        "fixture.json.bak",
    )
    for relative_path in relative_paths:
        source = staging / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"ordinary artifact: {relative_path}\n")

    staged = suite.stage(str(tmp_path / "served"), str(staging), relative_paths)

    assert staged == sorted(relative_paths)
    for relative_path in relative_paths:
        assert (tmp_path / "served" / relative_path).read_bytes() == (
            staging / relative_path
        ).read_bytes()


def test_public_ids_reveal_nothing_and_differ_by_key(tmp_path):
    dev = [t.scenario_id for t in _dev(tmp_path, n=4)]
    hold = [t.scenario_id for t in _holdout(tmp_path, n=4)]
    assert not set(dev) & set(hold), "two suites must not share a public identifier"
    assert all(i.startswith("af1_") and "scenario" not in i for i in dev + hold)


def test_grade_scores_junk_submissions_zero_without_raising(tmp_path):
    task = _holdout(tmp_path, n=2)[0]
    for junk in (None, "nonsense", [], 42, {"unknown": "key"}):
        assert grade(task, junk).accuracy == 0.0


def test_batch_is_distinct_and_deterministic(tmp_path):
    a = _dev(tmp_path, n=6, name="run1")
    b = _dev(tmp_path, n=6, name="run2")
    assert [t.answer_key() for t in a] == [t.answer_key() for t in b]
    hashes = [
        value for task in a if task.family == "windows" for value in task.answer_key().values()
    ]
    assert len(set(hashes)) == len(hashes)


def test_scorecard_measurement_corpus_is_deterministic_but_not_a_holdout(tmp_path):
    key = suite.scorecard_measurement_key()
    a = generate_suite(
        2, str(tmp_path / "measure-a"), key=key, kind=suite.SCORECARD_MEASUREMENT_KIND
    )
    b = generate_suite(
        2, str(tmp_path / "measure-b"), key=key, kind=suite.SCORECARD_MEASUREMENT_KIND
    )

    assert [t.scenario_id for t in a] == [t.scenario_id for t in b]
    assert [t.answer_key() for t in a] == [t.answer_key() for t in b]
    assert key != HOLDOUT_KEY
    assert suite.SCORECARD_MEASUREMENT_KIND in suite.NON_REPORTABLE_SUITE_KINDS

    for name in ("public.json",):
        assert (tmp_path / "measure-a" / name).read_bytes() == (
            tmp_path / "measure-b" / name
        ).read_bytes()
