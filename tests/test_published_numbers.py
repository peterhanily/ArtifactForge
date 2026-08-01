# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Every figure quoted in prose must be the one the committed scorecard holds.

This exists because the documentation drifted from the measurement in the single worst place
it could have: the README published a chance floor of 3.7% while `fidelity-scorecard.json`
said 4.1%, five lines above the sentence "the committed scorecard is the number of record —
quoting a different run's figure here is how a document starts lying slowly". Nobody had
lied; the scorecard was regenerated twice after the prose was pinned to it, and prose does not
regenerate. That is exactly how a document starts lying slowly.

Updating the number would have fixed the instance. This fixes the class: the two can no longer
diverge without a test going red, so the figures in the README are as maintained as the code.

The check runs in both directions on purpose. A missing figure means the prose stopped citing
something it should; an *extra* percentage in the benchmark section means a number appeared
from somewhere other than the scorecard, which is the failure that actually happened.
"""
import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARD = os.path.join(ROOT, "fidelity-scorecard.json")


@pytest.fixture(scope="module")
def card():
    with open(CARD) as f:
        return json.load(f)


def _read(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


def _published(card):
    """The figures the prose is allowed to quote, rendered the way prose renders them."""
    s = card["gates"]["solvability"]
    return {
        "reference solver": f"{s['reference_solver_score']:.0%}",
        "footprint adversary": f"{s['footprint_solver_score']:.1%}",
        "chance floor": f"{s['chance_floor']:.1%}",
    }


def _benchmark_section(text):
    """The 'Benchmark validity' paragraph — the one whose whole job is being checkable."""
    start = text.index("**Benchmark validity")
    rest = text[start:]
    end = rest.find("\n**")
    return rest[: end if end > 0 else len(rest)]


@pytest.mark.parametrize("doc", ["README.md", "docs/ROADMAP.md"])
def test_every_published_figure_matches_the_committed_scorecard(card, doc):
    text = _read(doc)
    for label, rendered in _published(card).items():
        assert rendered in text, (
            f"{doc} does not quote the committed {label} ({rendered}). Either the scorecard "
            f"was regenerated without re-pinning the prose, or the prose cites a stale run.")


def test_no_percentage_in_the_benchmark_section_comes_from_anywhere_else(card):
    """The failure that actually happened: a figure from a different run, sitting in the one
    section whose credibility depends on the numbers being the committed ones."""
    allowed = set(_published(card).values()) | {"30%", "10%", "0%", "100%"}
    found = set(re.findall(r"\d+(?:\.\d+)?%", _benchmark_section(_read("README.md"))))
    stray = sorted(found - allowed)
    assert not stray, (
        f"the README's benchmark section quotes {stray}, which the committed scorecard does "
        f"not contain. Regenerate the scorecard and re-pin the prose, or delete the figure.")


def test_the_readme_states_the_scorecard_s_actual_verdict(card):
    """`gap` and `fail` mean different things here and the README must not soften one to the
    other: a gap is a limit of the measuring apparatus, a failure is the thing measured being
    broken."""
    text = _read("README.md")
    verdict = card["verdict"]
    assert f"reads `{verdict}`" in text or f"verdict reads `{verdict}`" in text, (
        f"the committed scorecard's verdict is {verdict!r}; the README should say so plainly.")
    for other in {"pass", "gap", "fail"} - {verdict}:
        assert f"headline verdict reads `{other}`" not in text, \
            f"the README claims the headline verdict is {other!r}; it is {verdict!r}"


def test_the_design_doc_does_not_describe_a_red_gate_as_passing(card):
    """docs/DESIGN.md §4 documents the gate discipline; if a gate is red, it must say so."""
    failing = sorted(n for n, b in card["gates"].items() if b["verdict"] == "fail")
    design = _read("docs/DESIGN.md")
    for name in failing:
        assert re.search(rf"{name}.{{0,400}}(red|failing|currently fails)", design,
                         re.I | re.S), \
            f"gate '{name}' is failing but docs/DESIGN.md does not say so"
