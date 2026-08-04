# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""CLI routing for precommit, one-shot consumption and delayed feedback."""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from artifactforge import cli, suite
from artifactforge.bench import attempt, submission
from artifactforge.cli import (
    cmd_bench_attempt_accept,
    cmd_bench_attempt_consume,
    cmd_bench_attempt_report,
    cmd_bench_attempt_retire,
    cmd_bench_grade,
    cmd_bench_precommit,
)


pytestmark = pytest.mark.skipif(
    not attempt.ATTEMPT_PLATFORM_SUPPORTED,
    reason=attempt.ATTEMPT_PLATFORM_NOTICE,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _public() -> dict:
    origin, _private = suite._build_evaluator_ceremony_documents(
        b"k" * 32,
        ceremony_id="afc1_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        created_at="2026-08-03T12:00:00.000000Z",
    )
    return {
        "domain": suite.BENCHMARK_V3_DOMAIN.decode(),
        "origin": origin,
        "schema": suite.PUBLIC_DOCUMENT_SCHEMA_V3,
        "scenarios": [
            {
                "family": "windows",
                "questions": [
                    {"id": f"q{index}", "kind": "hash"} for index in range(1, 6)
                ],
                "scenario_id": "af1_aaaaaaaaaaaaaaaa",
            },
            {
                "family": "macos",
                "questions": [
                    {"id": f"q{index}", "kind": "url"} for index in range(6, 11)
                ],
                "scenario_id": "af1_bbbbbbbbbbbbbbbb",
            },
        ],
        "suite_id": _digest("1"),
        "suite_kind": suite.HOLDOUT_SUITE_KIND,
    }


def _answers() -> dict[str, dict[str, str]]:
    return {
        "af1_aaaaaaaaaaaaaaaa": {
            f"q{index}": f"hash-{index}" for index in range(1, 6)
        },
        "af1_bbbbbbbbbbbbbbbb": {
            f"q{index}": f"https://example.test/{index}" for index in range(6, 11)
        },
    }


def _private_answers() -> dict[str, dict]:
    return {
        scenario_id: {"answers": values, "scenario_id": scenario_id}
        for scenario_id, values in _answers().items()
    }


def _document_from_stdout(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def test_cli_one_shot_lifecycle_never_prints_feedback_before_retirement(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(suite, "BENCHMARK_V3_MIN_SCENARIOS", 2)
    public = _public()
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir(mode=0o700)
    reveal = submission.canonical_submission_bytes(public, _answers())
    reveal_path = tmp_path / "answers.jsonl"
    reveal_path.write_bytes(reveal)
    precommit = submission.build_precommit(
        public,
        reveal,
        implementation_sha256=_digest("2"),
        configuration_sha256=_digest("3"),
        source_sha256=_digest("4"),
    )
    precommit_path = tmp_path / "precommit.json"
    precommit_path.write_bytes(suite.canonical_public_bytes(precommit))
    ledger = tmp_path / "ledger"

    monkeypatch.setattr(suite, "load_evaluator_public", lambda _root: public)
    monkeypatch.setattr(
        suite,
        "load_evaluator_private",
        lambda _root: (public, _private_answers()),
    )
    monkeypatch.setattr(
        "artifactforge.cli._load_suite",
        lambda _root, *, role, include_private=False: (
            (public, [], _private_answers()) if include_private else (public, [])
        ),
    )

    assert cmd_bench_attempt_accept(
        SimpleNamespace(
            evaluator=str(evaluator),
            precommit=str(precommit_path),
            ledger=str(ledger),
        )
    ) == 0
    assert _document_from_stdout(capsys)["state"] == "precommit-accepted"

    assert cmd_bench_attempt_consume(
        SimpleNamespace(
            evaluator=str(evaluator),
            ledger=str(ledger),
            submission=str(reveal_path),
        )
    ) == 0
    withheld = _document_from_stdout(capsys)
    assert withheld["state"] == "consumed-feedback-withheld"
    assert "correct" not in json.dumps(withheld)
    assert "scored" not in json.dumps(withheld)

    with pytest.raises(attempt.AttemptNotRetiredError):
        cmd_bench_attempt_report(SimpleNamespace(ledger=str(ledger)))
    assert cmd_bench_attempt_retire(SimpleNamespace(ledger=str(ledger))) == 0
    assert _document_from_stdout(capsys)["state"] == "retired-feedback-releasable"
    assert cmd_bench_attempt_report(SimpleNamespace(ledger=str(ledger))) == 0
    report = _document_from_stdout(capsys)
    assert report["outcome"] == "scored"
    assert report["detail"]["correct"] == report["detail"]["total"] == 10


def test_cli_precommit_publishes_exact_canonical_record(tmp_path, monkeypatch, capsys):
    public = _public()
    public_root = tmp_path / "public"
    public_root.mkdir()
    reveal = submission.canonical_submission_bytes(public, _answers())
    reveal_path = tmp_path / "answers.jsonl"
    reveal_path.write_bytes(reveal)
    output = tmp_path / "precommit.json"
    monkeypatch.setattr(
        suite,
        "load_public_export",
        lambda _root, *, pinned_root_fd=None: public,
    )

    assert cmd_bench_precommit(
        SimpleNamespace(
            public=str(public_root),
            submission=str(reveal_path),
            out=str(output),
            implementation_sha256=_digest("2"),
            configuration_sha256=_digest("3"),
            source_sha256=_digest("4"),
        )
    ) == 0

    document = submission.parse_precommit(
        output.read_bytes(), expected_suite_id=public["suite_id"]
    )
    stdout = capsys.readouterr().out
    assert document["commitment_id"] in stdout
    assert "caller assertions, not attestations" in stdout


def test_cli_precommit_output_must_be_outside_public_export(tmp_path):
    public_root = tmp_path / "public"
    public_root.mkdir()
    output = public_root / "precommit.json"

    with pytest.raises(ValueError, match="outside the public export"):
        cmd_bench_precommit(
            SimpleNamespace(
                public=str(public_root),
                submission=str(tmp_path / "unopened.jsonl"),
                out=str(output),
                implementation_sha256=_digest("2"),
                configuration_sha256=_digest("3"),
                source_sha256=_digest("4"),
            )
        )
    assert not output.exists()


def test_cli_precommit_output_rejects_case_insensitive_public_alias(tmp_path):
    public_root = tmp_path / "public"
    public_root.mkdir()
    alias = public_root.with_name(public_root.name.swapcase())
    try:
        aliases_export = alias.exists() and os.path.samefile(alias, public_root)
    except OSError:
        aliases_export = False
    if not aliases_export:
        pytest.skip("test filesystem is case-sensitive")

    output = alias / "precommit.json"
    with pytest.raises(ValueError, match="outside the public export"):
        cmd_bench_precommit(
            SimpleNamespace(
                public=str(public_root),
                submission=str(tmp_path / "unopened.jsonl"),
                out=str(output),
                implementation_sha256=_digest("2"),
                configuration_sha256=_digest("3"),
                source_sha256=_digest("4"),
            )
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("move_inside_export", "message"),
    [
        (True, "outside the public export"),
        (False, "parent path changed during the operation"),
    ],
)
def test_cli_precommit_rechecks_output_parent_after_public_validation(
    tmp_path,
    monkeypatch,
    move_inside_export,
    message,
):
    public = _public()
    public_root = tmp_path / "public"
    public_root.mkdir()
    reveal = submission.canonical_submission_bytes(public, _answers())
    reveal_path = tmp_path / "answers.jsonl"
    reveal_path.write_bytes(reveal)
    output_parent = tmp_path / "precommit-output"
    output_parent.mkdir()
    output = output_parent / "precommit.json"
    moved_parent = (
        public_root / "moved-precommit-output"
        if move_inside_export
        else tmp_path / "renamed-precommit-output"
    )

    def load_and_move(_root, *, pinned_root_fd=None):
        assert pinned_root_fd is not None
        output_parent.rename(moved_parent)
        return public

    monkeypatch.setattr(suite, "load_public_export", load_and_move)
    with pytest.raises(ValueError, match=message):
        cmd_bench_precommit(
            SimpleNamespace(
                public=str(public_root),
                submission=str(reveal_path),
                out=str(output),
                implementation_sha256=_digest("2"),
                configuration_sha256=_digest("3"),
                source_sha256=_digest("4"),
            )
        )
    assert not (moved_parent / output.name).exists()


def test_cli_precommit_removes_exact_output_if_parent_moves_during_publication(
    tmp_path,
    monkeypatch,
):
    public = _public()
    public_root = tmp_path / "public"
    public_root.mkdir()
    reveal = submission.canonical_submission_bytes(public, _answers())
    reveal_path = tmp_path / "answers.jsonl"
    reveal_path.write_bytes(reveal)
    output_parent = tmp_path / "precommit-output"
    output_parent.mkdir()
    output = output_parent / "precommit.json"
    moved_parent = public_root / "moved-precommit-output"

    monkeypatch.setattr(
        suite,
        "load_public_export",
        lambda _root, *, pinned_root_fd=None: public,
    )
    original_write = cli.write_regular_file_at

    def write_then_move(parent_fd, relative, data, *, mode=0o600):
        original_write(parent_fd, relative, data, mode=mode)
        output_parent.rename(moved_parent)

    monkeypatch.setattr(cli, "write_regular_file_at", write_then_move)
    with pytest.raises(ValueError, match="outside the public export"):
        cmd_bench_precommit(
            SimpleNamespace(
                public=str(public_root),
                submission=str(reveal_path),
                out=str(output),
                implementation_sha256=_digest("2"),
                configuration_sha256=_digest("3"),
                source_sha256=_digest("4"),
            )
        )
    assert not (moved_parent / output.name).exists()


def test_legacy_grade_command_refuses_v3_before_opening_reveal(tmp_path, monkeypatch):
    public = _public()
    monkeypatch.setattr(
        "artifactforge.cli._load_suite",
        lambda _root, *, role, include_private=False: (public, [], _private_answers()),
    )
    with pytest.raises(ValueError, match="disables repeat grade feedback"):
        cmd_bench_grade(
            SimpleNamespace(
                suite=str(tmp_path / "evaluator"),
                submission=str(tmp_path / "missing.jsonl"),
            )
        )


def test_cli_missing_reveal_is_consumed_instead_of_rejected_before_claim(
    tmp_path, monkeypatch, capsys
):
    public = _public()
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir(mode=0o700)
    reveal = submission.canonical_submission_bytes(public, _answers())
    precommit_path = tmp_path / "precommit.json"
    precommit_path.write_bytes(
        suite.canonical_public_bytes(
            submission.build_precommit(
                public,
                reveal,
                implementation_sha256=_digest("2"),
                configuration_sha256=_digest("3"),
                source_sha256=_digest("4"),
            )
        )
    )
    ledger = tmp_path / "ledger"
    monkeypatch.setattr(suite, "load_evaluator_public", lambda _root: public)
    monkeypatch.setattr(
        suite,
        "load_evaluator_private",
        lambda _root: (public, _private_answers()),
    )
    monkeypatch.setattr(
        "artifactforge.cli._load_suite",
        lambda _root, *, role, include_private=False: (public, [], _private_answers()),
    )
    cmd_bench_attempt_accept(
        SimpleNamespace(
            evaluator=str(evaluator),
            precommit=str(precommit_path),
            ledger=str(ledger),
        )
    )
    capsys.readouterr()

    assert cmd_bench_attempt_consume(
        SimpleNamespace(
            evaluator=str(evaluator),
            ledger=str(ledger),
            submission=str(tmp_path / "missing.jsonl"),
        )
    ) == 0
    assert _document_from_stdout(capsys)["state"] == "consumed-feedback-withheld"
    with pytest.raises(attempt.AttemptConsumedError):
        cmd_bench_attempt_consume(
            SimpleNamespace(
                evaluator=str(evaluator),
                ledger=str(ledger),
                submission=str(tmp_path / "missing.jsonl"),
            )
        )
