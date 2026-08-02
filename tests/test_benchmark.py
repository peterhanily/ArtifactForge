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
from artifactforge.bench.adversary import blind_solve, constant_solve, listing_solve, null_solve
from artifactforge.bench.benchmark import generate_suite, grade
from artifactforge.bench.reference_solver import reference_solve

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")

HOLDOUT_KEY = bytes.fromhex("5f" * 32)      # fixed so the test is deterministic, unpublished


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


def test_reference_solver_scores_100(tmp_path):
    for task in _holdout(tmp_path):
        score = grade(task, reference_solve(task.public()))
        assert score.accuracy == 1.0, (task.scenario_id, score.per_question)


def test_no_adversary_beats_a_holdout_suite(tmp_path):
    tasks = _holdout(tmp_path)
    assert _score(tasks, blind_solve) == 0.0
    assert _score(tasks, listing_solve) == 0.0
    assert _score(tasks, null_solve) == 0.0
    assert _score(tasks, constant_solve) == 0.0


def test_the_blind_adversary_does_beat_a_dev_suite(tmp_path):
    """The control. A blind adversary that cannot cheat the suite built with the published
    key is broken, and its zero against a hold-out suite would then prove nothing."""
    assert _score(_dev(tmp_path), blind_solve) >= 0.5


def test_every_question_spans_at_least_two_artifacts(tmp_path):
    for task in _holdout(tmp_path):
        for q in task.questions:
            assert q.joins >= 2, f"{task.family}/{q.id} is answerable from one file alone"


def test_public_task_carries_no_answer(tmp_path):
    task = _holdout(tmp_path, n=2)[0]
    blob = json.dumps(task.public(), default=lambda o: getattr(o, "__dict__", str(o)))
    assert "expected" not in blob
    for q in task.questions:
        # Short answers (a run count of "3") appear as substrings of anything; the leak that
        # matters is a derived value — a hash, a UUID, a URL, a path, a filename.
        if len(str(q.expected)) >= 4:
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
def test_disclosure_filename_cannot_enter_a_served_benchmark_scene(
    tmp_path, relative_path
):
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
    (staging / "innocent.json").write_text(
        '{"schema":"artifactforge-fixture-manifest-v1"}\n'
    )
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
    hashes = [t.answer_key()["persisted_sha256"] for t in a if t.family == "windows"]
    assert len(set(hashes)) == len(hashes)


def test_scorecard_measurement_corpus_is_deterministic_but_not_a_holdout(tmp_path):
    key = suite.scorecard_measurement_key()
    a = generate_suite(2, str(tmp_path / "measure-a"), key=key,
                       kind=suite.SCORECARD_MEASUREMENT_KIND)
    b = generate_suite(2, str(tmp_path / "measure-b"), key=key,
                       kind=suite.SCORECARD_MEASUREMENT_KIND)

    assert [t.scenario_id for t in a] == [t.scenario_id for t in b]
    assert [t.answer_key() for t in a] == [t.answer_key() for t in b]
    assert key != HOLDOUT_KEY
    assert suite.SCORECARD_MEASUREMENT_KIND in suite.NON_REPORTABLE_SUITE_KINDS

    for name in ("public.json",):
        assert (tmp_path / "measure-a" / name).read_bytes() == \
               (tmp_path / "measure-b" / name).read_bytes()
