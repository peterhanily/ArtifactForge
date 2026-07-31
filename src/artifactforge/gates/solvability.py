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

from artifactforge.bench.adversary import ADVERSARIES, blind_solve
from artifactforge.bench.benchmark import grade
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.gates import GateReport

#: Below this the blind adversary is not working, and no negative result can be trusted.
CONTROL_FLOOR = 0.50


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
    r.denominator = (f"reference {ref:.0%}, best hold-out adversary {worst:.0%}, "
                     f"blind-vs-dev control {r.metrics.get('blind_control_score', 0.0):.0%}")
    return r
