# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Canonical submission/precommitment boundaries for the one-shot protocol."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from artifactforge import suite
from artifactforge.bench import submission


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
        "suite_id": "sha256:" + "1" * 64,
        "scenarios": [
            {
                "scenario_id": "af1_aaaaaaaaaaaaaaaa",
                "questions": [{"id": f"q{index}"} for index in range(1, 6)],
            },
            {
                "scenario_id": "af1_bbbbbbbbbbbbbbbb",
                "questions": [{"id": f"q{index}"} for index in range(6, 11)],
            },
        ],
    }


def _answers() -> dict[str, dict[str, str]]:
    return {
        "af1_aaaaaaaaaaaaaaaa": {
            "q1": "one",
            "q2": "two",
            "q3": "three",
            "q4": "four",
            "q5": "five",
        },
        "af1_bbbbbbbbbbbbbbbb": {
            "q6": "six",
            "q7": "seven",
            "q8": "eight",
            "q9": "nine",
            "q10": "ten",
        },
    }


def _digest(byte: str) -> str:
    return "sha256:" + byte * 64


def test_submission_has_one_unique_scenario_ordered_canonical_encoding():
    public = _public()
    answers = _answers()
    reversed_answers = dict(reversed(tuple(answers.items())))

    payload = submission.canonical_submission_bytes(public, reversed_answers)
    parsed = submission.parse_submission(payload, public)

    assert parsed.canonical_bytes == payload
    assert parsed.answers == answers
    assert parsed.sha256 == "sha256:" + hashlib.sha256(payload).hexdigest()
    assert [row["scenario_id"] for row in parsed.rows] == [
        "af1_aaaaaaaaaaaaaaaa",
        "af1_bbbbbbbbbbbbbbbb",
    ]
    assert payload.endswith(b"\n")


@pytest.mark.parametrize(
    "mutate,match",
    (
        (lambda data: data.rstrip(b"\n"), "LF-terminated|exactly one row"),
        (lambda data: b" " + data, "canonical"),
        (lambda data: b"\n" + data, "exactly one row"),
        (
            lambda data: b"\n".join(reversed(data.rstrip(b"\n").splitlines())) + b"\n",
            "canonical",
        ),
    ),
)
def test_submission_refuses_noncanonical_byte_forms(mutate, match):
    payload = submission.canonical_submission_bytes(_public(), _answers())
    with pytest.raises(ValueError, match=match):
        submission.parse_submission(mutate(payload), _public())


def test_submission_refuses_duplicate_members_cross_suite_and_incomplete_answers():
    public = _public()
    payload = submission.canonical_submission_bytes(public, _answers())
    first, second = payload.splitlines(keepends=True)
    duplicate = first[:-2] + b',"suite_id":"sha256:' + b"1" * 64 + b'"}\n' + second
    with pytest.raises(ValueError, match="duplicate object member"):
        submission.parse_submission(duplicate, public)

    rows = [json.loads(line) for line in payload.splitlines()]
    rows[0]["suite_id"] = "sha256:" + "2" * 64
    changed = b"".join(suite.canonical_public_bytes(row) for row in rows)
    with pytest.raises(ValueError, match="suite_id does not match"):
        submission.parse_submission(changed, public)

    answers = _answers()
    answers["af1_aaaaaaaaaaaaaaaa"].pop("q2")
    with pytest.raises(ValueError, match="do not exactly match"):
        submission.canonical_submission_bytes(public, answers)

    answers = _answers()
    answers["af1_aaaaaaaaaaaaaaaa"]["q2"] = ""
    with pytest.raises(ValueError, match="non-empty strings"):
        submission.canonical_submission_bytes(public, answers)


def test_submission_contract_refuses_non_protocol_scenario_and_question_shapes():
    public = _public()
    public["scenarios"][0]["scenario_id"] = "friendly-name"
    with pytest.raises(ValueError, match="invalid scenario_id"):
        submission.canonical_submission_bytes(public, _answers())

    public = _public()
    public["scenarios"][0]["questions"].pop()
    with pytest.raises(ValueError, match="exactly 5 questions"):
        submission.canonical_submission_bytes(public, _answers())


def test_precommit_binds_suite_reveal_and_three_provenance_digests():
    public = _public()
    payload = submission.canonical_submission_bytes(public, _answers())
    document = submission.build_precommit(
        public,
        payload,
        implementation_sha256=_digest("2"),
        configuration_sha256=_digest("3"),
        source_sha256=_digest("4"),
    )
    encoded = suite.canonical_public_bytes(document)

    assert submission.parse_precommit(
        encoded, expected_suite_id=public["suite_id"]
    ) == document
    assert document["submission"] == {
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def test_precommit_rejects_a_legacy_v2_export_before_creating_a_dead_end_record():
    public = _public()
    payload = submission.canonical_submission_bytes(public, _answers())
    public.pop("origin")
    public["domain"] = suite.DOMAIN.decode()
    public["schema"] = suite.PUBLIC_DOCUMENT_SCHEMA_V2

    with pytest.raises(ValueError, match="require a Benchmark v3 public export"):
        submission.build_precommit(
            public,
            payload,
            implementation_sha256=_digest("2"),
            configuration_sha256=_digest("3"),
            source_sha256=_digest("4"),
        )


@pytest.mark.parametrize(
    "mutation,match",
    (
        (lambda value: value.update({"unknown": 1}), "unknown or missing"),
        (
            lambda value: value["submission"].update({"sha256": "sha256:" + "9" * 64}),
            "commitment_id",
        ),
        (lambda value: value.update({"suite_id": "sha256:" + "8" * 64}), "suite_id"),
        (
            lambda value: value["solver"].update({"source_sha256": "not-a-digest"}),
            "labelled lowercase",
        ),
    ),
)
def test_precommit_refuses_shape_binding_and_provenance_mutations(mutation, match):
    public = _public()
    payload = submission.canonical_submission_bytes(public, _answers())
    clean = submission.build_precommit(
        public,
        payload,
        implementation_sha256=_digest("2"),
        configuration_sha256=_digest("3"),
        source_sha256=_digest("4"),
    )
    altered = deepcopy(clean)
    mutation(altered)
    with pytest.raises(ValueError, match=match):
        submission.parse_precommit(
            suite.canonical_public_bytes(altered),
            expected_suite_id=public["suite_id"],
        )


def test_precommit_rejects_noncanonical_and_oversized_inputs_before_trust():
    public = _public()
    payload = submission.canonical_submission_bytes(public, _answers())
    document = submission.build_precommit(
        public,
        payload,
        implementation_sha256=_digest("2"),
        configuration_sha256=_digest("3"),
        source_sha256=_digest("4"),
    )
    encoded = suite.canonical_public_bytes(document)
    with pytest.raises(ValueError, match="canonical"):
        submission.parse_precommit(b" " + encoded, expected_suite_id=public["suite_id"])
    with pytest.raises(ValueError, match="input limit"):
        submission.parse_precommit(
            b"x" * (submission.MAX_PRECOMMIT_BYTES + 1),
            expected_suite_id=public["suite_id"],
        )
