"""The benchmark's own validity gates — no score is trustworthy until these pass.

- The reference solver (real parsers) scores 100% -> the artifacts encode the ground truth.
- Null / constant solvers score ~0% -> the scorer is not vacuously passing.
- A corrupted answer key drops the reference score -> the scorer discriminates.
- Batch scenarios are distinct and deterministic -> real scale, not duplicated data.
- The public task view leaks no expected answers.
"""
import pytest

from artifactforge.benchmark import generate_batch, grade
from artifactforge.reference_solver import constant_solve, null_solve, reference_solve

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")


def _batch(tmp_path, n=6):
    return generate_batch(n, str(tmp_path / "bench"))


def test_reference_solver_scores_100(tmp_path):
    for task in _batch(tmp_path):
        score = grade(task, reference_solve(task))
        assert score.accuracy == 1.0, (task.scenario_id, score.per_question)


def test_null_and_constant_solvers_score_low(tmp_path):
    for task in _batch(tmp_path):
        assert grade(task, null_solve(task)).accuracy == 0.0
        # a trivial guesser must be far below the reference solver
        assert grade(task, constant_solve(task)).accuracy < 0.34


def test_corrupted_answer_key_is_caught(tmp_path):
    task = _batch(tmp_path, n=2)[0]
    answers = reference_solve(task)
    # flip one real answer; the grader must now mark it wrong (not a vacuous pass)
    first = task.questions[0].id
    answers[first] = "deadbeef" + "0" * 56
    score = grade(task, answers)
    assert score.per_question[first] is False and score.accuracy < 1.0


def test_batch_is_distinct_and_deterministic(tmp_path):
    a = _batch(tmp_path / "run1", n=8)
    b = _batch(tmp_path / "run2", n=8)
    # deterministic: same answer keys across independent runs
    assert [t.answer_key() for t in a] == [t.answer_key() for t in b]
    # distinct: Windows dropped-hashes differ across scenarios
    win_hashes = [t.answer_key()["dropped_sha256"] for t in a if t.family == "windows"]
    assert len(set(win_hashes)) == len(win_hashes)


def test_public_view_hides_answers(tmp_path):
    task = _batch(tmp_path, n=2)[0]
    pub = task.public()
    blob = str(pub)
    # the public view carries no "expected" field at all
    assert all("expected" not in pq for pq in pub["questions"])
    # derived answers (hashes, imphash, uuids) must not appear — those require reading artifacts
    for q in task.questions:
        if q.kind in ("hash", "imphash", "uuid"):
            assert q.expected not in blob
        assert any(pq["id"] == q.id for pq in pub["questions"])
