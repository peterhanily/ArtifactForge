# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Benchmark controls see the same evidence after a layout-only recursive move."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from artifactforge.bench.adversary import ADVERSARIES, listing_solve
from artifactforge.bench import benchmark as benchmark_module
from artifactforge.bench.benchmark import generate_suite, grade
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.gates import solvability
from artifactforge import inventory, suite

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")

HOLDOUT_KEY = bytes.fromhex("a6" * 32)


def _generate(tmp_path: Path, name: str, *, dev: bool = False, n: int = 2):
    return generate_suite(
        n,
        str(tmp_path / name),
        key=suite.PUBLIC_DEV_KEY if dev else HOLDOUT_KEY,
        kind="dev" if dev else "holdout",
    )


def _bury_artifacts(tasks) -> None:
    """Move every served entry below two dot-prefixed directories without changing bytes."""
    for task in tasks:
        root = Path(task.directory)
        original = list(root.iterdir())
        destination = root / ".evidence" / ".nested"
        destination.mkdir(parents=True)
        for entry in original:
            entry.rename(destination / entry.name)


def test_reference_and_adversaries_are_layout_invariant(tmp_path):
    tasks = _generate(tmp_path, "layout")
    reference_before = [reference_solve(task.public()) for task in tasks]
    adversaries_before = {
        name: [solver(task.public()) for task in tasks]
        for name, (solver, _threshold) in ADVERSARIES.items()
    }
    chance_before = solvability._chance_floor(tasks)  # noqa: SLF001 - direct control contract

    _bury_artifacts(tasks)

    assert all(
        path.startswith(".evidence/.nested/")
        for task in tasks
        for path in inventory.list_regular_file_paths(task.directory)
    )
    reference_after = [reference_solve(task.public()) for task in tasks]
    assert reference_after == reference_before
    assert all(
        grade(task, answer).accuracy == 1.0
        for task, answer in zip(tasks, reference_after, strict=True)
    )
    assert {
        name: [solver(task.public()) for task in tasks]
        for name, (solver, _threshold) in ADVERSARIES.items()
    } == adversaries_before
    assert solvability._chance_floor(tasks) == chance_before  # noqa: SLF001


def test_recursive_solvability_metrics_are_byte_for_byte_identical(tmp_path):
    holdout = _generate(tmp_path, "holdout", n=4)
    dev = _generate(tmp_path, "dev", dev=True, n=4)
    before = solvability.run(holdout, dev)

    _bury_artifacts([*holdout, *dev])
    after = solvability.run(holdout, dev)

    assert after.as_scorecard_block() == before.as_scorecard_block()
    assert after.denominator == before.denominator


def test_listing_solver_never_reads_regular_file_contents(tmp_path, monkeypatch):
    task = _generate(tmp_path, "listing", n=1)[0]
    expected = listing_solve(task.public())
    _bury_artifacts([task])
    real_open = inventory.os.open
    directory_flag = getattr(inventory.os, "O_DIRECTORY", 0)

    def forbidden_read(*_args, **_kwargs):
        raise AssertionError("the filename-only adversary read artifact contents")

    def directory_open_only(path, flags, *args, **kwargs):
        if directory_flag:
            assert flags & directory_flag, f"listing adversary opened regular file {path!r}"
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(inventory.os, "read", forbidden_read)
    monkeypatch.setattr(inventory.os, "open", directory_open_only)
    assert listing_solve(task.public()) == expected


def test_every_solver_and_gate_rejects_an_unknown_family_before_reading(tmp_path):
    task = _generate(tmp_path, "unknown", n=1)[0]
    unsupported_task = replace(task, family="linux", directory=str(tmp_path / "absent"))
    public = unsupported_task.public()

    solvers = [reference_solve, *(solver for solver, _threshold in ADVERSARIES.values())]
    for solver in solvers:
        with pytest.raises(ValueError, match="unsupported benchmark family"):
            solver(public)
    with pytest.raises(ValueError, match="unsupported benchmark families"):
        solvability._chance_floor([unsupported_task])  # noqa: SLF001
    with pytest.raises(ValueError, match="unsupported benchmark families"):
        solvability.run([unsupported_task])
    with pytest.raises(ValueError, match="unsupported benchmark family"):
        benchmark_module._profile(b"x" * 32, "linux")  # noqa: SLF001
