# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Canonical benchmark submissions and solver-side precommitments.

The precommitment is public solver material.  It binds the exact canonical reveal bytes and
three caller-supplied provenance digests to one ``suite_id``; it does not attest that those
digests describe the process that actually produced the answers.  Evaluator attempt state is
implemented separately so parsing this module never mutates an evaluator root.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from artifactforge import suite


SUBMISSION_CANONICALIZATION = "artifactforge-benchmark-submission-jsonl-v1"
SUBMISSION_PRECOMMIT_SCHEMA = "artifactforge-benchmark-submission-precommit-v1"
MAX_SUBMISSION_BYTES = 16 * 1024 * 1024
MAX_SUBMISSION_LINE_BYTES = 1024 * 1024
MAX_PRECOMMIT_BYTES = 16 * 1024
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SCENARIO_ID = re.compile(r"^af1_[a-z2-7]{16}$")


@dataclass(frozen=True)
class ParsedSubmission:
    """One complete canonical reveal, detached from its source pathname."""

    suite_id: str
    rows: tuple[dict, ...]
    answers: dict[str, dict[str, str]]
    canonical_bytes: bytes
    sha256: str


def _suite_contract(public: object) -> tuple[str, tuple[tuple[str, tuple[str, ...]], ...]]:
    if not isinstance(public, dict):
        raise ValueError("benchmark public document must be an object")
    suite_id = public.get("suite_id")
    if not isinstance(suite_id, str) or _SHA256.fullmatch(suite_id) is None:
        raise ValueError("benchmark public suite_id must be a labelled lowercase SHA-256")
    scenarios = public.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("benchmark public scenarios must be a non-empty array")
    if len(scenarios) > suite.BENCHMARK_MAX_SCENARIOS:
        raise ValueError(
            f"benchmark public scenarios exceed the {suite.BENCHMARK_MAX_SCENARIOS}-row limit"
        )
    contract: list[tuple[str, tuple[str, ...]]] = []
    seen_scenarios: set[str] = set()
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise ValueError(f"benchmark public scenario {index} must be an object")
        scenario_id = scenario.get("scenario_id")
        if not isinstance(scenario_id, str) or _SCENARIO_ID.fullmatch(scenario_id) is None:
            raise ValueError(f"benchmark public scenario {index} has an invalid scenario_id")
        if scenario_id in seen_scenarios:
            raise ValueError(f"benchmark public scenario_id {scenario_id!r} is duplicated")
        seen_scenarios.add(scenario_id)
        questions = scenario.get("questions")
        if (
            not isinstance(questions, list)
            or len(questions) != suite.BENCHMARK_QUESTIONS_PER_SCENE
        ):
            raise ValueError(
                f"benchmark scenario {scenario_id!r} must have exactly "
                f"{suite.BENCHMARK_QUESTIONS_PER_SCENE} questions"
            )
        question_ids: list[str] = []
        for question_index, question in enumerate(questions):
            if not isinstance(question, dict):
                raise ValueError(
                    f"benchmark scenario {scenario_id!r} question {question_index} "
                    "must be an object"
                )
            question_id = question.get("id")
            if not isinstance(question_id, str) or not question_id:
                raise ValueError(
                    f"benchmark scenario {scenario_id!r} question {question_index} "
                    "has an invalid id"
                )
            if question_id in question_ids:
                raise ValueError(
                    f"benchmark scenario {scenario_id!r} question id {question_id!r} "
                    "is duplicated"
                )
            question_ids.append(question_id)
        contract.append((scenario_id, tuple(question_ids)))
    return suite_id, tuple(contract)


def canonical_submission_bytes(public: object, answers: object) -> bytes:
    """Encode a complete answer mapping in public scenario order and canonical JSONL."""
    suite_id, contract = _suite_contract(public)
    if not isinstance(answers, dict):
        raise ValueError("benchmark submission answers must be an object keyed by scenario_id")
    expected_scenarios = {scenario_id for scenario_id, _questions in contract}
    if set(answers) != expected_scenarios:
        raise ValueError("benchmark submission scenario rows do not exactly match the suite")
    rendered: list[bytes] = []
    for scenario_id, question_ids in contract:
        row_answers = answers[scenario_id]
        if not isinstance(row_answers, dict) or set(row_answers) != set(question_ids):
            raise ValueError(
                f"benchmark submission answers for {scenario_id!r} do not exactly match "
                "the scenario questions"
            )
        if not all(
            isinstance(value, str)
            and 0 < len(value) <= suite.BENCHMARK_ANSWER_MAX_CHARS
            for value in row_answers.values()
        ):
            raise ValueError(
                f"benchmark submission answers for {scenario_id!r} must be non-empty strings "
                f"no longer than {suite.BENCHMARK_ANSWER_MAX_CHARS} characters"
            )
        row = {
            "answers": {question_id: row_answers[question_id] for question_id in question_ids},
            "scenario_id": scenario_id,
            "suite_id": suite_id,
        }
        encoded = suite.canonical_public_bytes(row)
        if len(encoded) > MAX_SUBMISSION_LINE_BYTES:
            raise ValueError(
                f"benchmark submission row for {scenario_id!r} exceeds the "
                f"{MAX_SUBMISSION_LINE_BYTES}-byte limit"
            )
        rendered.append(encoded)
    payload = b"".join(rendered)
    if len(payload) > MAX_SUBMISSION_BYTES:
        raise ValueError(
            f"benchmark submission exceeds the {MAX_SUBMISSION_BYTES}-byte input limit"
        )
    return payload


def parse_submission(data: object, public: object) -> ParsedSubmission:
    """Validate a complete reveal and require its unique canonical JSONL encoding."""
    if type(data) is not bytes:
        raise ValueError("benchmark submission must be immutable bytes")
    if len(data) > MAX_SUBMISSION_BYTES:
        raise ValueError(
            f"benchmark submission exceeds the {MAX_SUBMISSION_BYTES}-byte input limit"
        )
    suite_id, contract = _suite_contract(public)
    lines = data.splitlines(keepends=True)
    if len(lines) != len(contract):
        raise ValueError("benchmark submission must contain exactly one row per scenario")
    answers: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(lines, 1):
        if len(line) > MAX_SUBMISSION_LINE_BYTES:
            raise ValueError(
                f"benchmark submission line {line_number} exceeds the "
                f"{MAX_SUBMISSION_LINE_BYTES}-byte input limit"
            )
        if not line.endswith(b"\n") or line in {b"\n", b"\r\n"}:
            raise ValueError(
                f"benchmark submission line {line_number} must be non-blank and LF-terminated"
            )
        row = suite._strict_public_document(line, f"benchmark submission line {line_number}")
        if set(row) != {"answers", "scenario_id", "suite_id"}:
            raise ValueError(
                f"benchmark submission line {line_number} must contain exactly "
                "answers/scenario_id/suite_id"
            )
        if row["suite_id"] != suite_id:
            raise ValueError(
                f"benchmark submission line {line_number} suite_id does not match the suite"
            )
        scenario_id = row["scenario_id"]
        if not isinstance(scenario_id, str) or scenario_id in answers:
            raise ValueError(
                f"benchmark submission line {line_number} has an invalid or duplicate "
                "scenario_id"
            )
        row_answers = row["answers"]
        if not isinstance(row_answers, dict):
            raise ValueError(
                f"benchmark submission line {line_number} answers must be an object"
            )
        answers[scenario_id] = row_answers
    canonical = canonical_submission_bytes(public, answers)
    if data != canonical:
        raise ValueError(
            "benchmark submission is not the canonical scenario-ordered JSONL encoding"
        )
    rows = tuple(
        suite._strict_public_document(line, "canonical benchmark submission row")
        for line in canonical.splitlines(keepends=True)
    )
    return ParsedSubmission(
        suite_id=suite_id,
        rows=rows,
        answers={scenario_id: dict(values) for scenario_id, values in answers.items()},
        canonical_bytes=canonical,
        sha256="sha256:" + hashlib.sha256(canonical).hexdigest(),
    )


def _require_sha256(value: object, where: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{where} must be a labelled lowercase SHA-256")
    return value


def build_precommit(
    public: object,
    submission: object,
    *,
    implementation_sha256: str,
    configuration_sha256: str,
    source_sha256: str,
) -> dict:
    """Build a canonical v3 solver precommitment for one already-canonical reveal."""
    if (
        not isinstance(public, dict)
        or public.get("schema") != suite.PUBLIC_DOCUMENT_SCHEMA_V3
        or public.get("domain") != suite.BENCHMARK_V3_DOMAIN.decode()
        or "origin" not in public
    ):
        raise ValueError("benchmark precommitments require a Benchmark v3 public export")
    suite.validate_benchmark_origin(public["origin"])
    parsed = parse_submission(submission, public)
    unsigned = {
        "canonicalization": SUBMISSION_CANONICALIZATION,
        "schema": SUBMISSION_PRECOMMIT_SCHEMA,
        "solver": {
            "configuration_sha256": _require_sha256(
                configuration_sha256, "solver configuration digest"
            ),
            "implementation_sha256": _require_sha256(
                implementation_sha256, "solver implementation digest"
            ),
            "source_sha256": _require_sha256(source_sha256, "solver source digest"),
        },
        "submission": {
            "sha256": parsed.sha256,
            "size": len(parsed.canonical_bytes),
        },
        "suite_id": parsed.suite_id,
    }
    commitment_id = "sha256:" + hashlib.sha256(
        suite.canonical_public_bytes(unsigned)
    ).hexdigest()
    return {**unsigned, "commitment_id": commitment_id}


def parse_precommit(data: object, *, expected_suite_id: str) -> dict:
    """Validate one exact canonical precommitment and its self-commitment."""
    if type(data) is not bytes:
        raise ValueError("benchmark precommitment must be immutable bytes")
    if len(data) > MAX_PRECOMMIT_BYTES:
        raise ValueError(
            f"benchmark precommitment exceeds the {MAX_PRECOMMIT_BYTES}-byte input limit"
        )
    document = suite._strict_public_document(data, "benchmark precommitment")
    if data != suite.canonical_public_bytes(document):
        raise ValueError("benchmark precommitment must use canonical JSON")
    if set(document) != {
        "canonicalization",
        "commitment_id",
        "schema",
        "solver",
        "submission",
        "suite_id",
    }:
        raise ValueError("benchmark precommitment has unknown or missing fields")
    if document["schema"] != SUBMISSION_PRECOMMIT_SCHEMA:
        raise ValueError("benchmark precommitment schema is unsupported")
    if document["canonicalization"] != SUBMISSION_CANONICALIZATION:
        raise ValueError("benchmark precommitment canonicalization is unsupported")
    if document["suite_id"] != expected_suite_id:
        raise ValueError("benchmark precommitment suite_id does not match the evaluator suite")
    solver = document["solver"]
    if not isinstance(solver, dict) or set(solver) != {
        "configuration_sha256",
        "implementation_sha256",
        "source_sha256",
    }:
        raise ValueError("benchmark precommitment solver provenance has an invalid shape")
    for name, value in solver.items():
        _require_sha256(value, f"benchmark precommitment solver.{name}")
    submission = document["submission"]
    if not isinstance(submission, dict) or set(submission) != {"sha256", "size"}:
        raise ValueError("benchmark precommitment submission binding has an invalid shape")
    _require_sha256(submission["sha256"], "benchmark precommitment submission.sha256")
    size = submission["size"]
    if type(size) is not int or not 1 <= size <= MAX_SUBMISSION_BYTES:
        raise ValueError("benchmark precommitment submission.size is outside the input limit")
    commitment_id = _require_sha256(
        document["commitment_id"], "benchmark precommitment commitment_id"
    )
    unsigned = dict(document)
    unsigned.pop("commitment_id")
    expected = "sha256:" + hashlib.sha256(
        suite.canonical_public_bytes(unsigned)
    ).hexdigest()
    if commitment_id != expected:
        raise ValueError("benchmark precommitment commitment_id does not bind its document")
    return document


__all__ = [
    "MAX_PRECOMMIT_BYTES",
    "MAX_SUBMISSION_BYTES",
    "MAX_SUBMISSION_LINE_BYTES",
    "ParsedSubmission",
    "SUBMISSION_CANONICALIZATION",
    "SUBMISSION_PRECOMMIT_SCHEMA",
    "build_precommit",
    "canonical_submission_bytes",
    "parse_precommit",
    "parse_submission",
]
