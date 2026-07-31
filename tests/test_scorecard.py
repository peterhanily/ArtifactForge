# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The committed fidelity scorecard must stay valid, honest, and leak nothing local.

CI cannot always recompute the scorecard — some oracles are platform-bound — so it guards the
committed artifact instead. These are the three properties that make guarding it worthwhile.
"""
import json
import os

import pytest

from artifactforge.scorecard import _METRICS, SCHEMA_VERSION, regressions

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARD_PATH = os.path.join(ROOT, "fidelity-scorecard.json")


@pytest.fixture(scope="module")
def card():
    with open(CARD_PATH) as f:
        return json.load(f)


def test_committed_scorecard_is_schema_valid(card):
    assert card["schema_version"] == SCHEMA_VERSION
    assert set(card["gates"]) == {"validity", "identity", "inertness", "solvability"}
    for name, block in card["gates"].items():
        assert block["verdict"] in ("pass", "fail"), name
        assert isinstance(block["fails"], list) and isinstance(block["gaps"], list), name
    assert card["verdict"] in ("pass", "gap", "fail")


def test_every_tracked_metric_is_present(card):
    """A metric the scorecard does not carry cannot regress, so its absence is the bug."""
    missing = [label for label, kind, *_ in regressions(card, card) if kind == "missing"]
    assert not missing, f"tracked metrics absent from the committed scorecard: {missing}"
    assert len(_METRICS) >= 8


def test_scorecard_leaks_no_local_path(card):
    """A scorecard is published. It must not carry this machine's filesystem in it."""
    blob = json.dumps(card)
    for needle in ("/Users/", "/private/", "/tmp/", "/home/", "C:\\\\Users"):
        assert needle not in blob, f"the committed scorecard leaks {needle!r}"


def test_scorecard_declares_its_failures_rather_than_hiding_them(card):
    """Every failing gate must appear in honest_gaps. A quiet failure is the thing we fix."""
    gaps = "\n".join(card["honest_gaps"])
    for name, block in card["gates"].items():
        if block["verdict"] == "fail":
            assert f"({name}) FAILING" in gaps, \
                f"gate '{name}' fails but says nothing in honest_gaps"


def test_the_headline_verdict_cannot_hide_an_open_gap(card):
    """"pass" is reserved for a scorecard with nothing left declared.

    A green headline sitting above a list of named limitations is exactly the shape of
    overstatement this project exists to avoid, so the top-level verdict is three-valued.
    """
    any_fail = any(b["verdict"] == "fail" for b in card["gates"].values())
    if any_fail:
        assert card["verdict"] == "fail"
    elif card["honest_gaps"]:
        assert card["verdict"] == "gap", "gaps are declared but the headline says otherwise"
    else:
        assert card["verdict"] == "pass"
