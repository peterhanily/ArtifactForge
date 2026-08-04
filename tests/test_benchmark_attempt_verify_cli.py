# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detached retired-report verification remains bounded, canonical and ledger-free."""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from artifactforge import cli, suite
from artifactforge.bench import attempt, submission


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _record(unsigned: dict) -> dict:
    return {
        **unsigned,
        "record_id": _sha256(suite.canonical_public_bytes(unsigned)),
    }


def _detached_material() -> tuple[bytes, bytes, dict]:
    """Build a valid terminal report without invoking the POSIX live-ledger API."""
    suite_id = "sha256:" + "1" * 64
    attempt_id = "afa1_" + "a" * 26
    reveal = b'{"detached":"reveal"}\n'
    precommit_unsigned = {
        "canonicalization": submission.SUBMISSION_CANONICALIZATION,
        "schema": submission.SUBMISSION_PRECOMMIT_SCHEMA,
        "solver": {
            "configuration_sha256": "sha256:" + "2" * 64,
            "implementation_sha256": "sha256:" + "3" * 64,
            "source_sha256": "sha256:" + "4" * 64,
        },
        "submission": {"sha256": _sha256(reveal), "size": len(reveal)},
        "suite_id": suite_id,
    }
    precommit = {
        **precommit_unsigned,
        "commitment_id": _sha256(suite.canonical_public_bytes(precommit_unsigned)),
    }
    precommit_bytes = suite.canonical_public_bytes(precommit)
    acceptance = _record(
        {
            "accepted_at": "2026-08-03T12:00:00.000000Z",
            "attempt_id": attempt_id,
            "precommit": {
                "commitment_id": precommit["commitment_id"],
                "sha256": _sha256(precommit_bytes),
                "size": len(precommit_bytes),
            },
            "schema": attempt.ACCEPTANCE_SCHEMA,
            "state": "precommit-accepted",
            "suite_id": suite_id,
            "trust": attempt.ATTEMPT_TRUST,
        }
    )
    acceptance_bytes = suite.canonical_public_bytes(acceptance)
    retirement = _record(
        {
            "attempt_id": attempt_id,
            "previous": {
                "file": attempt.ACCEPTANCE_FILE,
                "sha256": _sha256(acceptance_bytes),
            },
            "retired_at": "2026-08-03T12:01:00.000000Z",
            "schema": attempt.RETIREMENT_SCHEMA,
            "state": "retired-feedback-releasable",
            "suite_id": suite_id,
            "trust": attempt.ATTEMPT_TRUST,
        }
    )
    evidence = {
        "acceptance": acceptance,
        "claim": None,
        "precommit": precommit,
        "receipt": None,
        "result": None,
        "retirement": retirement,
        "reveal_commitment": dict(precommit["submission"]),
    }
    unsigned_report = {
        "attempt_id": attempt_id,
        "detail": {"reason": "no-private-result"},
        "evidence": evidence,
        "notice": attempt.RETIRED_REPORT_NOTICE,
        "outcome": "retired-without-result",
        "reportability": suite.REPORTABILITY_PENDING_EXTERNAL_ATTESTATION,
        "reportable": False,
        "retirement_record_id": retirement["record_id"],
        "schema": attempt.REPORT_SCHEMA,
        "suite_id": suite_id,
        "trust": attempt.ATTEMPT_TRUST,
    }
    report = {
        **unsigned_report,
        "report_id": _sha256(suite.canonical_public_bytes(unsigned_report)),
    }
    return suite.canonical_public_bytes(report), reveal, report


def test_cli_verifies_detached_report_without_live_ledger_support(
    tmp_path,
    monkeypatch,
    capsys,
):
    report_bytes, _reveal, report = _detached_material()
    report_path = tmp_path / "retired-report.json"
    report_path.write_bytes(report_bytes)
    monkeypatch.setattr(attempt, "ATTEMPT_PLATFORM_SUPPORTED", False)

    def live_ledger_must_not_be_checked():
        raise AssertionError("detached verification touched the live-ledger platform gate")

    monkeypatch.setattr(attempt, "require_attempt_platform", live_ledger_must_not_be_checked)
    assert cli.main(["bench", "attempt", "verify", os.fspath(report_path)]) == 0
    output = capsys.readouterr().out.encode()
    summary = json.loads(output)
    assert output == suite.canonical_public_bytes(summary)
    assert summary == {
        "attempt_id": report["attempt_id"],
        "chain_records": 2,
        "report_id": report["report_id"],
        "reveal_verified": False,
        "suite_id": report["suite_id"],
    }


def test_cli_verifies_matching_detached_reveal(tmp_path, capsys):
    report_bytes, reveal, report = _detached_material()
    report_path = tmp_path / "retired-report.json"
    reveal_path = tmp_path / "answers.jsonl"
    report_path.write_bytes(report_bytes)
    reveal_path.write_bytes(reveal)

    assert (
        cli.main(
            [
                "bench",
                "attempt",
                "verify",
                os.fspath(report_path),
                "--reveal",
                os.fspath(reveal_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out.encode()
    summary = json.loads(output)
    assert output == suite.canonical_public_bytes(summary)
    assert summary["report_id"] == report["report_id"]
    assert summary["reveal_verified"] is True


def test_cli_rejects_wrong_detached_reveal(tmp_path):
    report_bytes, reveal, _report = _detached_material()
    report_path = tmp_path / "retired-report.json"
    reveal_path = tmp_path / "wrong.jsonl"
    report_path.write_bytes(report_bytes)
    reveal_path.write_bytes(bytes([reveal[0] ^ 1]) + reveal[1:])

    with pytest.raises(attempt.AttemptError, match="detached reveal"):
        cli.main(
            [
                "bench",
                "attempt",
                "verify",
                os.fspath(report_path),
                "--reveal",
                os.fspath(reveal_path),
            ]
        )


@pytest.mark.parametrize("payload", [b"{", b' {"not":"canonical"}\n'])
def test_cli_rejects_malformed_or_noncanonical_report(tmp_path, payload):
    report_path = tmp_path / "retired-report.json"
    report_path.write_bytes(payload)
    with pytest.raises(ValueError, match="detached retired report"):
        cli.main(["bench", "attempt", "verify", os.fspath(report_path)])


def test_cli_rejects_oversized_report_before_parsing(tmp_path, monkeypatch):
    report_bytes, _reveal, _report = _detached_material()
    report_path = tmp_path / "retired-report.json"
    report_path.write_bytes(report_bytes)
    monkeypatch.setattr(cli, "_MAX_RETIRED_REPORT_BYTES", len(report_bytes) - 1)

    with pytest.raises(ValueError, match="exceeds .*byte input limit"):
        cli.main(["bench", "attempt", "verify", os.fspath(report_path)])


def test_cli_refuses_report_symlink(tmp_path):
    report_bytes, _reveal, _report = _detached_material()
    target = tmp_path / "retired-report.json"
    alias = tmp_path / "retired-report-link.json"
    target.write_bytes(report_bytes)
    try:
        alias.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")

    with pytest.raises(ValueError, match="not a link or special file"):
        cli.main(["bench", "attempt", "verify", os.fspath(alias)])


def test_cli_refuses_reveal_symlink(tmp_path):
    report_bytes, reveal, _report = _detached_material()
    report_path = tmp_path / "retired-report.json"
    reveal_target = tmp_path / "answers.jsonl"
    reveal_alias = tmp_path / "answers-link.jsonl"
    report_path.write_bytes(report_bytes)
    reveal_target.write_bytes(reveal)
    try:
        reveal_alias.symlink_to(reveal_target)
    except OSError as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")

    with pytest.raises(ValueError, match="not a link or special file"):
        cli.main(
            [
                "bench",
                "attempt",
                "verify",
                os.fspath(report_path),
                "--reveal",
                os.fspath(reveal_alias),
            ]
        )


def test_cli_rejects_oversized_reveal_before_verification(tmp_path, monkeypatch):
    report_bytes, reveal, _report = _detached_material()
    report_path = tmp_path / "retired-report.json"
    reveal_path = tmp_path / "answers.jsonl"
    report_path.write_bytes(report_bytes)
    reveal_path.write_bytes(reveal)
    monkeypatch.setattr(submission, "MAX_SUBMISSION_BYTES", len(reveal) - 1)

    with pytest.raises(ValueError, match="exceeds .*byte input limit"):
        cli.main(
            [
                "bench",
                "attempt",
                "verify",
                os.fspath(report_path),
                "--reveal",
                os.fspath(reveal_path),
            ]
        )
