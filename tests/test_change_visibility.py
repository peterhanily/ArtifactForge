# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The snapshot boundary is only as strong as the host's file-time granularity.

These checks own the probe that measures it and the scorecard decision that reports the
shortfall.  Without them a coarse-granularity host would publish a ``pass`` for a rejection
it never performed.
"""

from __future__ import annotations

import types

import pytest

from artifactforge import cli
from artifactforge.inventory import ChangeVisibility, InventoryError, measure_change_visibility


def test_probe_sees_every_rewrite_on_this_host(tmp_path):
    """Positive control: the suite's own filesystem must support what the docs claim."""
    visibility = measure_change_visibility(tmp_path)
    assert visibility.samples == 8
    assert visibility.distinguished == 8
    assert visibility.complete
    assert visibility.minimum_delta_ns is not None
    assert visibility.minimum_delta_ns > 0


def test_probe_leaves_no_residue(tmp_path):
    measure_change_visibility(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_probe_honours_the_requested_sample_count(tmp_path):
    assert measure_change_visibility(tmp_path, samples=3).samples == 3


@pytest.mark.parametrize("samples", [0, -1, 1.0, "8", None, True])
def test_probe_refuses_a_nonsensical_sample_count(tmp_path, samples):
    with pytest.raises(InventoryError, match="positive integer"):
        measure_change_visibility(tmp_path, samples=samples)


def test_probe_fails_closed_on_an_unusable_directory(tmp_path):
    with pytest.raises(InventoryError, match="cannot probe change visibility"):
        measure_change_visibility(tmp_path / "absent")


@pytest.mark.parametrize(
    ("samples", "distinguished", "complete"),
    [(8, 8, True), (8, 7, False), (8, 0, False), (1, 1, True), (1, 0, False)],
)
def test_completeness_requires_every_sample(samples, distinguished, complete):
    visibility = ChangeVisibility(samples=samples, distinguished=distinguished, minimum_delta_ns=1)
    assert visibility.complete is complete


def test_description_names_the_absent_step():
    visibility = ChangeVisibility(samples=8, distinguished=0, minimum_delta_ns=None)
    assert "no timestamp step observed at all" in visibility.describe()
    assert "0 of 8" in visibility.describe()


def test_description_carries_the_observed_step():
    visibility = ChangeVisibility(samples=8, distinguished=8, minimum_delta_ns=16625)
    assert "smallest observed timestamp step 16625 ns" in visibility.describe()


def test_capable_host_declares_no_gap(tmp_path):
    assert cli._host_honest_gaps(types.SimpleNamespace(gen_dir=str(tmp_path))) == []


def test_coarse_host_declares_a_gap(monkeypatch, tmp_path):
    """The mutation that matters: a host that cannot see rewrites must not report a pass."""
    monkeypatch.setattr(
        cli,
        "measure_change_visibility",
        lambda where: ChangeVisibility(samples=8, distinguished=0, minimum_delta_ns=None),
    )
    gaps = cli._host_honest_gaps(types.SimpleNamespace(gen_dir=str(tmp_path)))
    assert len(gaps) == 1
    assert "restored before its second pass" in gaps[0]
    assert "0 of 8" in gaps[0]


def test_a_single_invisible_rewrite_is_enough_to_declare_a_gap(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli,
        "measure_change_visibility",
        lambda where: ChangeVisibility(samples=8, distinguished=7, minimum_delta_ns=1),
    )
    assert cli._host_honest_gaps(types.SimpleNamespace(gen_dir=str(tmp_path)))


def test_an_unprobeable_host_declares_a_gap(monkeypatch, tmp_path):
    def refuse(where):
        raise InventoryError("no")

    monkeypatch.setattr(cli, "measure_change_visibility", refuse)
    gaps = cli._host_honest_gaps(types.SimpleNamespace(gen_dir=str(tmp_path)))
    assert len(gaps) == 1
    assert "could not be probed" in gaps[0]


def test_gaps_flip_the_scorecard_verdict_away_from_pass():
    """honest_gaps is only worth measuring if it actually moves the published verdict."""
    from artifactforge.scorecard import build_scorecard

    class _Report:
        def __init__(self, name, gate):
            self.name = name
            self.gate = gate
            self.ok = True
            self.gaps = ()
            self.fails = ()

        def as_scorecard_block(self):
            return {"gate": self.gate, "ok": True}

    reports = [
        _Report("validity", 1),
        _Report("identity", 2),
        _Report("inertness", 3),
        _Report("solvability", 4),
    ]
    common = {
        "artifactforge_version": "0.0.0",
        "git_commit": "abcdefg",
        "sqlite_version": "3.0.0",
    }
    assert build_scorecard(reports, **common)["verdict"] == "pass"
    gapped = build_scorecard(reports, honest_gaps=["host cannot see rewrites"], **common)
    assert gapped["verdict"] == "gap"
    assert gapped["honest_gaps"] == ["host cannot see rewrites"]
