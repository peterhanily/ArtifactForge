# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 4 — solvability: are the benchmark's answers recovered from evidence, or derivable?

A reference solver scoring 100% proves the artifacts *encode* the ground truth. It does not
prove the ground truth can only be got that way, and that inference was being made here. It
is false: because the generator is open source and the public scenario identifier is also
its generation seed, a solver that opens no file at all reproduces every answer.

So the gate measures both directions.

  positive   the reference solver, reading artifacts with real parsers, scores 100%
  negative   every adversary — blind, listing, null, constant — scores at or below its
             threshold. A benchmark an adversary can pass is not measuring investigation.
  necessity  at least one question per family is answerable only by joining two artifacts.
             Without one, the benchmark cannot detect a broken cross-artifact hash pivot —
             which is the single thing this project exists to provide, and which it scored
             100% on after that pivot was deliberately destroyed.
"""
from __future__ import annotations

from artifactforge.bench.adversary import ADVERSARIES
from artifactforge.bench.benchmark import grade
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.gates import GateReport


def run(tasks: list) -> GateReport:
    r = GateReport(4, "solvability",
                   "are the benchmark's answers recovered from evidence, or derivable?")
    if not tasks:
        r.fail("no tasks generated, so nothing was measured")
        return r

    # positive — the artifacts must actually encode the answers
    correct = total = 0
    for t in tasks:
        s = grade(t, reference_solve(t))
        correct += s.correct
        total += s.total
    ref = correct / total if total else 0.0
    r.metrics["reference_solver_score"] = round(ref, 4)
    if ref < 1.0:
        r.fail(f"the reference solver scores {ref:.1%}, so some answer is not recoverable "
               f"from the artifacts it ships with")

    # negative — no adversary may do well
    for name, (solver, threshold) in ADVERSARIES.items():
        c = n = 0
        for t in tasks:
            s = grade(t, solver(t.public(), t.directory))
            c += s.correct
            n += s.total
        score = c / n if n else 0.0
        r.metrics[f"{name}_solver_score"] = round(score, 4)
        if score > threshold:
            r.fail(f"the '{name}' adversary scores {score:.1%} against a {threshold:.0%} "
                   f"threshold — that many answers are obtainable without forensic work")

    # necessity — at least one question per family must span two artifacts
    for family in sorted({t.family for t in tasks}):
        joins = [q for t in tasks if t.family == family
                 for q in t.questions if getattr(q, "joins", 0) >= 2]
        r.metrics[f"join_questions_{family}"] = len(joins)
        if not joins:
            r.fail(f"no {family} question requires joining two artifacts, so the benchmark "
                   f"cannot detect a broken cross-artifact pivot")

    worst = max((r.metrics.get(f"{n}_solver_score", 0.0) for n in ADVERSARIES), default=0.0)
    r.denominator = (f"reference {ref:.0%}, best adversary {worst:.0%}, "
                     f"{sum(v for k, v in r.metrics.items() if k.startswith('join_questions_'))}"
                     f" join-requiring questions")
    return r
