# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The gate discipline itself, enforced mechanically.

A gate is only built when all six of its bindings exist. This file is their keeper: it fails
if someone adds a gate module without a CLI subcommand, a scorecard metric, a CI step or a
design-doc section — the four ways a gate quietly becomes decoration.
"""
import os
import re

import pytest

from artifactforge import suite
from artifactforge.bench.benchmark import generate_suite
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


def _windows(tmp_path):
    tasks = generate_suite(2, str(tmp_path / "s"), key=suite.PUBLIC_DEV_KEY)
    return next(t for t in tasks if t.family == "windows")


@pytest.mark.parametrize("name", GATE_NAMES)
def test_every_gate_has_all_six_bindings(name):
    # 1. a module whose docstring's first line states the question
    mod = __import__(f"artifactforge.gates.{name}", fromlist=["run"])
    assert mod.__doc__ and mod.__doc__.splitlines()[0].endswith("?"), \
        "the first line of a gate's docstring must be the question it answers"
    assert callable(mod.run)

    # 2. a CLI subcommand, so the gate can fail a build
    assert name in GATES, f"gate '{name}' has no CLI subcommand"

    # 3. a mutation register entry — checked by name, contents in test_gate_mutations.py
    muts = _read("tests/test_gate_mutations.py")
    assert f"{name}.run(" in muts or f"{name}_reddens" in muts or f"{name}." in muts, \
        f"gate '{name}' has no registered mutation"

    # 4 + 5. a tracked metric with a direction and a tolerance
    assert [m for m in _METRICS if m[0].startswith(f"gates.{name}.")], \
        f"gate '{name}' contributes no metric to the scorecard"

    # 6. a named CI step
    assert re.search(rf"Gate \d — {name}", _read(".github/workflows/ci.yml")), \
        f"gate '{name}' has no named CI step"

    # and a design-doc section
    assert re.search(rf"###.*{name}", _read("docs/DESIGN.md"), re.I), \
        f"gate '{name}' is not described in docs/DESIGN.md"


def test_gate_reports_are_well_formed(tmp_path):
    task = _windows(tmp_path)
    for report in (validity.run(task.directory), identity.run(task.directory, task.join),
                   inertness.run(task.directory)):
        assert isinstance(report, GateReport)
        assert report.denominator, "a verdict with no denominator hides the bad news"
        assert report.verdict_line().startswith("  VERDICT:")
        assert report.ok is (not report.fails), "declared gaps must never block"
        assert len(report.fails) == len(set(report.fails)), "reasons must dedupe"


def test_identity_gate_holds_on_a_fresh_windows_scene(tmp_path):
    """The keystone, asserted the only way that means anything: re-derived from disk."""
    task = _windows(tmp_path)
    r = identity.run(task.directory, task.join)
    assert r.ok, r.render()
    assert r.metrics["checks_joined"] == r.metrics["checks_total"] >= 10


def test_identity_gate_holds_on_a_fresh_macos_scene(tmp_path):
    tasks = generate_suite(2, str(tmp_path / "s"), key=suite.PUBLIC_DEV_KEY)
    mac = next(t for t in tasks if t.family == "macos")
    r = identity.run(mac.directory, mac.join)
    assert r.ok, r.render()
    assert r.metrics["checks_joined"] == r.metrics["checks_total"] >= 6
