# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 4 — solvability: are the benchmark's answers recovered from evidence, or derivable?

A reference solver scoring 100% proves the artifacts *encode* the ground truth. It does not
prove that is the only way to get it — and here it was not: the public scenario identifier
was also the generation seed, so a solver opening zero files reproduced every answer.

The gate measures four things, and the fourth is what keeps the other three honest.

  positive     the reference solver, reading artifacts with real parsers, scores 100%.
  negative     against a HOLD-OUT suite — one whose key the adversary does not have — every
               adversary stays under its threshold.
  necessity    at least one question per family is answerable only by joining two artifacts.
               Without one, the benchmark cannot detect a broken cross-artifact pivot, which
               is the single thing this project exists to provide.
  control      against a DEV suite — built with the key published in the source — the blind
               adversary must score *well*. A blind adversary that cannot cheat the suite
               designed to be cheatable is broken, and its 0% against the hold-out suite
               would then mean nothing. This is what stops the negative direction from
               passing vacuously, which is the failure mode that produced "trivial solvers
               score 0%" while a real one scored 100%.
"""
from __future__ import annotations

import random

from artifactforge.bench.adversary import ADVERSARIES, blind_solve
from artifactforge.bench.benchmark import grade
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.gates import GateReport

#: Below this the blind adversary is not working, and no negative result can be trusted.
CONTROL_FLOOR = 0.50


def _chance_floor(tasks, reps: int = 20) -> float:
    """What a solver scores by guessing uniformly among the candidates it can see.

    Published beside the adversary scores because `null` and `constant` both score 0.0000,
    which is BELOW chance — using them as the only baselines made every number this benchmark
    reported look better than it was. A score is only meaningful against the floor of the same
    corpus, measured in the same round.
    """
    import os
    rng = random.Random(0xA5F)                    # fixed: the floor must be reproducible
    correct = total = 0
    for _ in range(reps):
        for t in tasks:
            try:
                visible = sorted(f for f in os.listdir(t.directory)
                                 if os.path.isfile(os.path.join(t.directory, f)))
            except OSError:
                visible = []
            for q in t.questions:
                total += 1
                # A guesser can only pick among things it can see; for a hash-shaped answer
                # there is nothing to pick from, so it cannot score.
                if q.kind in ("hash", "imphash", "uuid", "url") or not visible:
                    continue
                correct += int(rng.choice(visible).split(".")[0].lower()
                               == str(q.expected).split(".")[0].lower())
    return correct / total if total else 0.0


def _score(tasks, solver) -> float:
    correct = total = 0
    for t in tasks:
        s = grade(t, solver(t.public()))
        correct += s.correct
        total += s.total
    return correct / total if total else 0.0


def run(holdout_tasks: list, dev_tasks: list | None = None) -> GateReport:
    r = GateReport(4, "solvability",
                   "are the benchmark's answers recovered from evidence, or derivable?")
    if not holdout_tasks:
        r.fail("no tasks generated, so nothing was measured")
        return r

    floor = _chance_floor(holdout_tasks)
    r.metrics["chance_floor"] = round(floor, 4)

    # positive — the artifacts must actually encode the answers
    ref = _score(holdout_tasks, reference_solve)
    r.metrics["reference_solver_score"] = round(ref, 4)
    if ref < 1.0:
        r.fail(f"the reference solver scores {ref:.1%}, so some answer is not recoverable "
               f"from the artifacts it ships with")

    # negative — no adversary may do well without the suite key
    for name, (solver, threshold) in ADVERSARIES.items():
        score = _score(holdout_tasks, solver)
        r.metrics[f"{name}_solver_score"] = round(score, 4)
        if score > threshold:
            r.fail(f"the '{name}' adversary scores {score:.1%} against a {threshold:.0%} "
                   f"threshold — that many answers are obtainable without forensic work")

    # control — the blind adversary must be able to cheat the suite meant to be cheatable
    if dev_tasks:
        control = _score(dev_tasks, blind_solve)
        r.metrics["blind_control_score"] = round(control, 4)
        if control < CONTROL_FLOOR:
            r.fail(f"the blind adversary scores only {control:.1%} against the DEV suite, "
                   f"whose key is published — it is broken, so its result against the "
                   f"hold-out suite proves nothing")

    # necessity — at least one question per family must span two artifacts
    for family in sorted({t.family for t in holdout_tasks}):
        joins = [q for t in holdout_tasks if t.family == family
                 for q in t.questions if getattr(q, "joins", 0) >= 2]
        r.metrics[f"join_questions_{family}"] = len(joins)
        if not joins:
            r.fail(f"no {family} question requires joining two artifacts, so the benchmark "
                   f"cannot detect a broken cross-artifact pivot")

    worst = max((r.metrics.get(f"{n}_solver_score", 0.0) for n in ADVERSARIES), default=0.0)
    r.metrics["adversarial_floor"] = round(worst, 4)
    r.denominator = (f"reference {ref:.0%}, adversarial floor {worst:.1%} against a "
                     f"{floor:.1%} chance floor")
    return r
