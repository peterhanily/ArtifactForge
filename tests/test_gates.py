"""The gate discipline itself, enforced mechanically.

A gate is only built when all six of its bindings exist. This file is the fifth-and-sixth
binding's keeper: it fails if someone adds a gate module without a CLI subcommand, a
scorecard metric, a CI step or a design-doc section — the four ways a gate quietly becomes
decoration.
"""
import os
import re

import pytest

from artifactforge.bench.benchmark import generate_batch
from artifactforge.cli import GATES
from artifactforge.gates import GateReport, identity, inertness, validity
from artifactforge.scorecard import _METRICS

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_NAMES = ("validity", "identity", "inertness", "solvability")


def _read(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


@pytest.mark.parametrize("name", GATE_NAMES)
def test_every_gate_has_all_six_bindings(name):
    # 1. a module whose docstring states the question
    mod = __import__(f"artifactforge.gates.{name}", fromlist=["run"])
    assert mod.__doc__ and "?" in mod.__doc__.splitlines()[0], "the docstring must ask it"
    assert callable(mod.run)

    # 2. a CLI subcommand
    assert name in GATES, f"gate '{name}' has no CLI subcommand, so it cannot fail a build"

    # 3. a dedicated pytest file (this one, plus the mutation register)
    assert os.path.exists(os.path.join(ROOT, "tests", "test_gate_mutations.py"))

    # 4 + 5. a tracked metric with a direction and a tolerance
    tracked = [m for m in _METRICS if m[0].startswith(f"gates.{name}.")]
    assert tracked, f"gate '{name}' contributes no metric to the scorecard"

    # 6. a named CI step
    ci = _read(".github/workflows/ci.yml")
    assert re.search(rf"Gate \d — {name}", ci), f"gate '{name}' has no named CI step"

    # and a design-doc section
    assert re.search(rf"###.*{name}", _read("docs/DESIGN.md"), re.I), \
        f"gate '{name}' is not described in docs/DESIGN.md"


def test_gate_reports_are_well_formed(tmp_path):
    tasks = generate_batch(2, str(tmp_path / "b"))
    win = next(t for t in tasks if t.family == "windows")
    for report in (validity.run(win.directory), identity.run(win.directory),
                   inertness.run(win.directory)):
        assert isinstance(report, GateReport)
        assert report.denominator, "a verdict with no denominator hides the bad news"
        assert report.verdict_line().startswith("  VERDICT:")
        assert report.ok is (not report.fails), "declared gaps must never block"


def test_identity_gate_holds_on_a_fresh_windows_scene(tmp_path):
    """The keystone, asserted the only way that means anything: re-derived from disk."""
    tasks = generate_batch(2, str(tmp_path / "b"))
    win = next(t for t in tasks if t.family == "windows")
    r = identity.run(win.directory)
    assert r.ok, r.render()
    assert r.metrics["checks_joined"] == r.metrics["checks_total"] >= 8
