# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Ordinary mistakes get a sentence, not a stack trace.

`main` stays the testable core and keeps raising, so callers that want the exception still get
it. `console_main` is what the installed command runs, and it is what a stranger hits: a
traceback in front of a deliberate refusal adds nothing but the author's source paths. The
solver-facing refusals additionally must not read back the evaluator inventory they exist to
withhold.
"""

from __future__ import annotations

import pytest

from artifactforge import cli


def _raises(monkeypatch, exc):
    """Make the testable core raise, so the console wrapper is what is under test."""

    def boom(_argv=None):
        raise exc

    monkeypatch.setattr(cli, "main", boom)


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("refusing pre-existing evaluator suite destination: /somewhere"),
        OSError("cannot read /somewhere"),
        FileNotFoundError("no such file: /somewhere"),
    ],
)
def test_a_refusal_becomes_a_message_and_exit_two(exc, capsys, monkeypatch):
    monkeypatch.delenv("ARTIFACTFORGE_TRACEBACK", raising=False)
    _raises(monkeypatch, exc)
    assert cli.console_main([]) == 2
    err = capsys.readouterr().err
    assert str(exc) in err
    assert "Traceback" not in err
    assert "ARTIFACTFORGE_TRACEBACK=1" in err


def test_a_missing_oracle_names_the_extra_that_supplies_it(capsys, monkeypatch):
    monkeypatch.delenv("ARTIFACTFORGE_TRACEBACK", raising=False)
    _raises(monkeypatch, ImportError("No module named 'regipy'"))
    assert cli.console_main([]) == 2
    err = capsys.readouterr().err
    assert "regipy" in err
    assert 'pip install "artifactforge[dev]"' in err


def test_the_escape_hatch_re_raises_untouched(monkeypatch):
    monkeypatch.setenv("ARTIFACTFORGE_TRACEBACK", "1")
    _raises(monkeypatch, ValueError("deliberate"))
    with pytest.raises(ValueError, match="deliberate"):
        cli.console_main([])


def test_a_defect_is_not_disguised_as_a_refusal(monkeypatch):
    """Only the expected refusal types are converted; anything else keeps its trace."""
    monkeypatch.delenv("ARTIFACTFORGE_TRACEBACK", raising=False)
    _raises(monkeypatch, TypeError("internal defect"))
    with pytest.raises(TypeError):
        cli.console_main([])


def test_main_itself_still_raises_for_programmatic_callers(monkeypatch):
    """The wrapper is a presentation layer; the core contract is unchanged."""
    monkeypatch.delenv("ARTIFACTFORGE_TRACEBACK", raising=False)
    with pytest.raises(ValueError, match="evaluator root is unsafe"):
        cli.main(["bench", "export", "/nonexistent-evaluator", "/nonexistent-public"])


def test_success_and_failure_codes_pass_through(monkeypatch):
    monkeypatch.delenv("ARTIFACTFORGE_TRACEBACK", raising=False)
    for code in (0, 1, 2):
        monkeypatch.setattr(cli, "main", lambda _argv=None, c=code: c)
        assert cli.console_main([]) == code


def test_the_installed_command_is_the_wrapped_one():
    """A console script pointing at `main` would ship the tracebacks to users."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with open(pyproject, "rb") as stream:
        scripts = tomllib.load(stream)["project"]["scripts"]
    assert scripts == {"artifactforge": "artifactforge.cli:console_main"}


def test_the_solver_refusal_does_not_echo_the_evaluator_inventory(tmp_path):
    """The whole point of the public export is that the private tree stays unread.

    Pointing the solver at an evaluator root is the ordinary mistake, so the refusal must not
    hand back the private filenames — including the key path — as its diagnostic.
    """
    from artifactforge import suite

    root = tmp_path / "evaluator"
    (root / "_key").mkdir(parents=True)
    (root / "_answers").mkdir()
    (root / "scenarios").mkdir()
    (root / "scenarios" / "af1_example.json").write_bytes(b"{}")
    (root / "public.json").write_bytes(b"{}")
    (root / "_key" / "key.hex").write_bytes(b"deadbeef")
    (root / "_answers" / "af1_secret.json").write_bytes(b"{}")

    with pytest.raises(ValueError) as caught:
        suite._capture_public_export(str(root))

    message = str(caught.value)
    assert "key.hex" not in message
    assert "_key" not in message
    assert "af1_secret" not in message
    assert "_answers" not in message
    assert "2 entries" in message
    assert "bench export" in message
