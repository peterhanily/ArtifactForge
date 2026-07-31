# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The four gates — the questions a machine answers about every generated scene.

A gate is not a doc and not an assertion. It is a numbered question wired into six places
at once, and it is not built until all six exist:

  1. a module here, whose docstring states the question
  2. a CLI subcommand that exits non-zero when the answer is no
  3. a dedicated pytest file
  4. a `gates.<name>` block in the committed fidelity-scorecard.json
  5. a row in `scorecard._METRICS` giving the metric a direction and a tolerance
  6. a registered mutation in tests/test_gate_mutations.py that turns it red

The sixth is the one that matters. A gate that has never been observed to fail proves
nothing, and this repository previously shipped tests that stayed green when the data they
checked was replaced with the literal string GARBAGE-NOT-A-SHA1.

  Gate 1  validity     Does an independent real parser read every artifact we ship?
  Gate 2  identity     Is every hash-shaped field a genuine digest of one ContentStore blob?
  Gate 3  inertness    Can anything we ship execute, and is every format marked synthetic?
  Gate 4  solvability  Are the benchmark's answers recovered from evidence, or derivable?

Failures block. Declared gaps do not — they are honest, named limitations that travel in the
scorecard's `honest_gaps` so they cannot be forgotten. Anything undeclared is a failure.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GateReport:
    """One gate's answer, in the shape every gate CLI prints and the scorecard stores."""

    gate: int
    name: str
    question: str
    fails: list = field(default_factory=list)     # blocking; each a one-line reason
    gaps: list = field(default_factory=list)      # declared, non-blocking limitations
    metrics: dict = field(default_factory=dict)   # numbers the scorecard tracks
    denominator: str = ""                         # the uncomfortable ratio, printed inline

    def fail(self, reason: str) -> None:
        """Record a blocking reason. Deduped: a batch reports reasons, not instances, so the
        committed scorecard stays a stable baseline instead of churning with filenames."""
        if reason not in self.fails:
            self.fails.append(reason)

    def gap(self, reason: str) -> None:
        """Record a declared, non-blocking limitation. Deduped for the same reason."""
        if reason not in self.gaps:
            self.gaps.append(reason)

    @property
    def ok(self) -> bool:
        """Warnings and declared gaps never block. Only fails do."""
        return not self.fails

    def verdict_line(self) -> str:
        return (f"  VERDICT: {'PASS' if self.ok else 'FAIL'} "
                f"({len(self.fails)} fail, {len(self.gaps)} declared gaps)"
                + (f" — {self.denominator}" if self.denominator else ""))

    def render(self) -> str:
        out = [f"Gate {self.gate} — {self.name}: {self.question}"]
        out += [f"  FAIL  {f}" for f in self.fails]
        out += [f"  gap   {g}" for g in self.gaps]
        out.append(self.verdict_line())
        return "\n".join(out)

    def as_scorecard_block(self) -> dict:
        return {"verdict": "pass" if self.ok else "fail",
                "fails": list(self.fails), "gaps": list(self.gaps), **self.metrics}
