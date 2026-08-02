# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Linux extends generator assurance without changing Gate 4's benchmark population."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from artifactforge import suite
from artifactforge import cli as cli_module
from artifactforge.compose.assurance import generate_linux_assurance
from artifactforge.inventory import inventory_regular_files


def _payload(scene):
    return [
        (file.relative_path, file.data)
        for file in inventory_regular_files(scene.directory, capture_bytes=True)
    ]


def test_linux_assurance_is_deterministic_balanced_and_question_free(tmp_path):
    first = generate_linux_assurance(5, str(tmp_path / "first"))
    second = generate_linux_assurance(5, str(tmp_path / "second"))
    assert len(first) == len(second) == 3
    assert all(scene.family == "linux" for scene in first)
    assert [_payload(scene) for scene in first] == [_payload(scene) for scene in second]
    assert [scene.join for scene in first] == [scene.join for scene in second]
    assert not (tmp_path / "first" / "public.json").exists()
    assert not (tmp_path / "first" / "_answers").exists()
    assert not (tmp_path / "first" / "_key").exists()

    provenance = suite.generator_assurance_provenance(5)
    assert provenance["family_counts"] == {"windows": 3, "macos": 2, "linux": 3}
    assert provenance["scenario_count"] == 8
    assert provenance["linux_benchmark_included"] is False
    assert provenance["benchmark_reportable"] is False


def test_gates_one_to_three_use_assurance_but_gate_four_uses_only_windows_macos(
        monkeypatch, tmp_path):
    wm = [SimpleNamespace(directory="wm", join={"family": "windows"})]
    linux = [SimpleNamespace(directory="linux", join={"family": "linux"})]
    monkeypatch.setattr(cli_module, "_dev", lambda _args: wm)
    monkeypatch.setattr(cli_module, "_linux_assurance", lambda _args: linux)
    assert cli_module._assurance(SimpleNamespace()) == [*wm, *linux]

    seen = []
    monkeypatch.setattr(cli_module, "_scorecard_measurement", lambda _args: ["measured-wm"])
    monkeypatch.setattr(cli_module.solvability, "run", lambda measured, dev: seen.append(
        (measured, dev)) or SimpleNamespace())
    cli_module.gate_solvability(SimpleNamespace(_scorecard_measurement_mode=True))
    assert seen == [(["measured-wm"], wm)]
    assert all("linux" not in str(item) for pair in seen for item in pair)


def test_linux_assurance_count_rejects_vacuous_or_malformed_sizes():
    for value in (0, -1, True, 1.5, "4"):
        try:
            suite.linux_assurance_count(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid assurance size {value!r}")


@pytest.mark.parametrize("command", (("gate", "identity"), ("scorecard",), ("bench", "new", "x")))
def test_cli_rejects_vacuous_scenario_counts_before_generation(command, capsys):
    with pytest.raises(SystemExit) as error:
        cli_module.main([*command, "--n", "0"])
    assert error.value.code == 2
    assert "scenario count must be at least 1" in capsys.readouterr().err
