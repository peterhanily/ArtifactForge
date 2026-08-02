# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The CLI owns and removes implicit gate/scorecard work directories."""

from pathlib import Path

import pytest

import artifactforge.cli as cli
from artifactforge.gates import GateReport


def _recording_gate(paths: list[Path], *, fail: bool = False, error: bool = False):
    def run(args):
        workdir = Path(cli._workdir(args))
        paths.append(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "private-evaluator-material").write_bytes(b"test")
        if error:
            raise RuntimeError("synthetic gate failure")
        report = GateReport(1, "validity", "test")
        if fail:
            report.fail("synthetic red gate")
        return report

    return run


@pytest.mark.parametrize(("fail", "expected"), ((False, 0), (True, 1)))
def test_implicit_gate_workdir_is_removed_after_any_verdict(monkeypatch, fail, expected):
    paths = []
    monkeypatch.setattr(cli, "GATES", {"validity": _recording_gate(paths, fail=fail)})

    assert cli.main(["gate", "validity", "--n", "1"]) == expected

    assert len(paths) == 1
    assert not paths[0].exists()


def test_implicit_gate_workdir_is_removed_after_exception(monkeypatch):
    paths = []
    monkeypatch.setattr(cli, "GATES", {"validity": _recording_gate(paths, error=True)})

    with pytest.raises(RuntimeError, match="synthetic gate failure"):
        cli.main(["gate", "validity", "--n", "1"])

    assert len(paths) == 1
    assert not paths[0].exists()


def test_explicit_gate_workdir_remains_caller_owned(tmp_path, monkeypatch):
    paths = []
    destination = tmp_path / "inspectable"
    monkeypatch.setattr(cli, "GATES", {"validity": _recording_gate(paths)})

    assert cli.main(["gate", "validity", "--n", "1", "--gen-dir", str(destination)]) == 0

    assert paths == [destination]
    assert (destination / "private-evaluator-material").read_bytes() == b"test"
