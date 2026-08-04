# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""One-shot claim, withheld feedback and retirement regressions."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import os
from pathlib import Path
import stat
from threading import Event

import pytest

from artifactforge import suite
from artifactforge.bench import attempt, submission


pytestmark = pytest.mark.skipif(
    not attempt.ATTEMPT_PLATFORM_SUPPORTED,
    reason=attempt.ATTEMPT_PLATFORM_NOTICE,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _public(*, v3: bool = True) -> dict:
    document = {
        "domain": (suite.BENCHMARK_V3_DOMAIN if v3 else suite.DOMAIN).decode(),
        "scenarios": [
            {
                "scenario_id": "af1_aaaaaaaaaaaaaaaa",
                "family": "windows",
                "questions": [
                    {"id": f"q{index}", "kind": "hash"} for index in range(1, 6)
                ],
            },
            {
                "scenario_id": "af1_bbbbbbbbbbbbbbbb",
                "family": "macos",
                "questions": [
                    {"id": f"q{index}", "kind": "url"} for index in range(6, 11)
                ],
            },
        ],
        "schema": suite.PUBLIC_DOCUMENT_SCHEMA_V3 if v3 else suite.PUBLIC_DOCUMENT_SCHEMA_V2,
        "suite_id": _digest("1"),
        "suite_kind": suite.HOLDOUT_SUITE_KIND,
    }
    if v3:
        origin, _private = suite._build_evaluator_ceremony_documents(
            b"k" * 32,
            ceremony_id="afc1_aaaaaaaaaaaaaaaaaaaaaaaaaa",
            created_at="2026-08-03T12:00:00.000000Z",
        )
        document["origin"] = origin
    return document


def _answers() -> dict[str, dict[str, str]]:
    return {
        "af1_aaaaaaaaaaaaaaaa": {
            "q1": "ABC",
            "q2": "def",
            "q3": "123",
            "q4": "456",
            "q5": "789",
        },
        "af1_bbbbbbbbbbbbbbbb": {
            "q6": "https://example.test/6",
            "q7": "https://example.test/7",
            "q8": "https://example.test/8",
            "q9": "https://example.test/9",
            "q10": "https://example.test/10",
        },
    }


def _private_answers() -> dict[str, dict]:
    return {
        scenario_id: {"scenario_id": scenario_id, "answers": values}
        for scenario_id, values in _answers().items()
    }


def _precommit(public: dict, reveal: bytes) -> bytes:
    record = submission.build_precommit(
        public,
        reveal,
        implementation_sha256=_digest("2"),
        configuration_sha256=_digest("3"),
        source_sha256=_digest("4"),
    )
    return suite.canonical_public_bytes(record)


@pytest.fixture(autouse=True)
def _validated_evaluator_loader(monkeypatch):
    # Unit fixtures use two scenarios; the separate integration test exercises the genuine
    # 120-scene v3 minimum without replacing this production contract.
    monkeypatch.setattr(suite, "BENCHMARK_V3_MIN_SCENARIOS", 2)
    monkeypatch.setattr(suite, "load_evaluator_public", lambda _root: _public())
    monkeypatch.setattr(
        suite,
        "load_evaluator_private",
        lambda _root: (_public(), _private_answers()),
    )


def _opened(tmp_path: Path) -> tuple[dict, bytes, Path, Path, Path]:
    public = _public()
    reveal = submission.canonical_submission_bytes(public, _answers())
    reveal_path = tmp_path / "reveal.jsonl"
    reveal_path.write_bytes(reveal)
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir(mode=0o700)
    root = tmp_path / "attempt"
    attempt.accept_precommit(root, evaluator, _precommit(public, reveal))
    return public, reveal, reveal_path, root, evaluator


def test_v3_attempt_withholds_score_until_local_ledger_retirement(tmp_path):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)

    receipt = attempt.consume_attempt(root, evaluator, reveal_path)
    rendered = suite.canonical_public_bytes(receipt)

    assert receipt["state"] == "consumed-feedback-withheld"
    assert receipt["notice"] == attempt.WITHHELD_RECEIPT_NOTICE
    assert "plaintext private result" in receipt["notice"]
    assert b"correct" not in rendered
    assert b"scored" not in rendered
    with pytest.raises(attempt.AttemptNotRetiredError, match="withheld until retirement"):
        attempt.retired_report(root)

    retirement = attempt.retire_attempt(root)
    report = attempt.retired_report(root)
    assert retirement["state"] == "retired-feedback-releasable"
    assert report["outcome"] == "scored"
    assert report["detail"]["correct"] == report["detail"]["total"] == 10
    assert report["retirement_record_id"] == retirement["record_id"]


def test_clock_rollback_refuses_claim_before_publication_and_allows_retry(
    tmp_path, monkeypatch
):
    timestamps = iter(
        (
            "2026-08-03T12:00:00.000000Z",
            "2026-08-03T11:59:59.000000Z",
        )
    )
    monkeypatch.setattr(attempt, "_timestamp", lambda: next(timestamps))
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)

    with pytest.raises(attempt.AttemptError, match="clock predates"):
        attempt.consume_attempt(root, evaluator, reveal_path)
    assert not (root / attempt.CLAIM_FILE).exists()

    monkeypatch.setattr(
        attempt, "_timestamp", lambda: "2026-08-03T12:00:01.000000Z"
    )
    assert attempt.consume_attempt(root, evaluator, reveal_path)["state"] == (
        "consumed-feedback-withheld"
    )


def test_clock_rollback_refuses_retirement_before_publication_and_allows_retry(
    tmp_path, monkeypatch
):
    timestamps = iter(
        (
            "2026-08-03T12:00:00.000000Z",
            "2026-08-03T12:00:01.000000Z",
        )
    )
    monkeypatch.setattr(attempt, "_timestamp", lambda: next(timestamps))
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)
    attempt.consume_attempt(root, evaluator, reveal_path)

    monkeypatch.setattr(
        attempt, "_timestamp", lambda: "2026-08-03T12:00:00.500000Z"
    )
    with pytest.raises(attempt.AttemptError, match="clock predates"):
        attempt.retire_attempt(root)
    assert not (root / attempt.RETIREMENT_FILE).exists()

    monkeypatch.setattr(
        attempt, "_timestamp", lambda: "2026-08-03T12:00:02.000000Z"
    )
    assert attempt.retire_attempt(root)["state"] == "retired-feedback-releasable"


def test_mismatched_reveal_consumes_attempt_and_feedback_stays_withheld(tmp_path):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)
    reveal_path.write_bytes(b"{}\n")

    receipt = attempt.consume_attempt(root, evaluator, reveal_path)
    assert receipt["state"] == "consumed-feedback-withheld"
    with pytest.raises(attempt.AttemptConsumedError, match="claim already exists"):
        attempt.consume_attempt(root, evaluator, reveal_path)
    with pytest.raises(attempt.AttemptNotRetiredError):
        attempt.retired_report(root)

    attempt.retire_attempt(root)
    report = attempt.retired_report(root)
    assert report["outcome"] == "rejected"
    assert report["detail"] == {"reason": "reveal-binding-mismatch"}


def test_unreadable_reveal_is_claimed_before_open_and_cannot_be_retried(tmp_path):
    _public_document, _reveal, _reveal_path, root, evaluator = _opened(tmp_path)
    missing = tmp_path / "missing.jsonl"

    attempt.consume_attempt(root, evaluator, missing)
    with pytest.raises(attempt.AttemptConsumedError):
        attempt.consume_attempt(root, evaluator, missing)
    attempt.retire_attempt(root)
    assert attempt.retired_report(root)["detail"] == {"reason": "unreadable-reveal"}


def test_forbidden_reveal_location_is_checked_only_after_claim(tmp_path):
    _public_document, reveal, _reveal_path, root, evaluator = _opened(tmp_path)
    reveal_path = evaluator / "reveal.jsonl"
    reveal_path.write_bytes(reveal)

    attempt.consume_attempt(root, evaluator, reveal_path)
    with pytest.raises(attempt.AttemptConsumedError):
        attempt.consume_attempt(root, evaluator, reveal_path)
    attempt.retire_attempt(root)
    assert attempt.retired_report(root)["detail"] == {
        "reason": "forbidden-reveal-location"
    }


def test_unexpected_crash_after_claim_bricks_attempt_without_feedback(tmp_path, monkeypatch):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)

    def crash(*_args, **_kwargs):
        raise RuntimeError("injected evaluator crash")

    monkeypatch.setattr(attempt, "_score_reveal", crash)
    with pytest.raises(RuntimeError, match="injected evaluator crash"):
        attempt.consume_attempt(root, evaluator, reveal_path)
    assert (root / attempt.CLAIM_FILE).is_file()
    assert not (root / attempt.RESULT_FILE).exists()
    with pytest.raises(attempt.AttemptConsumedError):
        attempt.consume_attempt(root, evaluator, reveal_path)

    attempt.retire_attempt(root)
    report = attempt.retired_report(root)
    assert report["outcome"] == "retired-without-result"
    assert report["detail"] == {"reason": "no-private-result"}


def test_concurrent_consumers_create_exactly_one_claim(tmp_path):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)

    def consume():
        try:
            attempt.consume_attempt(root, evaluator, reveal_path)
            return "accepted"
        except attempt.AttemptConsumedError:
            return "consumed"
        except attempt.AttemptBusyError:
            return "busy"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: consume(), range(2)))
    assert outcomes.count("accepted") == 1
    assert set(outcomes) <= {"accepted", "busy", "consumed"}
    if "busy" in outcomes:
        with pytest.raises(attempt.AttemptConsumedError):
            attempt.consume_attempt(root, evaluator, reveal_path)
    assert (root / attempt.CLAIM_FILE).is_file()
    assert (root / attempt.RESULT_FILE).is_file()
    assert (root / attempt.RECEIPT_FILE).is_file()


def test_attempt_root_is_no_replace_private_and_hostile_umask_independent(tmp_path):
    public = _public()
    reveal = submission.canonical_submission_bytes(public, _answers())
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir(mode=0o700)
    root = tmp_path / "attempt"
    old_umask = os.umask(0o777)
    try:
        acceptance = attempt.accept_precommit(root, evaluator, _precommit(public, reveal))
    finally:
        os.umask(old_umask)

    if os.name != "nt":
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in root.iterdir())
    with pytest.raises(attempt.AttemptError, match="pre-existing"):
        attempt.accept_precommit(root, evaluator, _precommit(public, reveal))
    assert acceptance["precommit"]["size"] == len(_precommit(public, reveal))


def test_legacy_local_v2_can_never_open_a_one_shot_attempt(tmp_path, monkeypatch):
    public = _public(v3=False)
    reveal = submission.canonical_submission_bytes(public, _answers())
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir(mode=0o700)
    monkeypatch.setattr(suite, "load_evaluator_public", lambda _root: public)
    # Precommit construction itself now refuses v2. Use an otherwise valid v3-bound record
    # with the same synthetic suite id to keep the evaluator-side rejection independently
    # covered against a caller that supplies bytes without using the helper.
    precommit = _precommit(_public(), reveal)
    with pytest.raises(attempt.AttemptError, match="permanently ineligible"):
        attempt.accept_precommit(
            tmp_path / "attempt",
            evaluator,
            precommit,
        )
    assert not (tmp_path / "attempt").exists()


@pytest.mark.parametrize(
    "field,value,match",
    (
        ("domain", suite.DOMAIN.decode(), "v3 derivation domain"),
        ("suite_kind", suite.DEV_SUITE_KIND, "holdout suite kind"),
        ("suite_id", "not-a-digest", "valid suite_id"),
    ),
)
def test_v3_attempt_refuses_cross_protocol_identity_fields(
    tmp_path, monkeypatch, field, value, match
):
    public = _public()
    public[field] = value
    reveal = submission.canonical_submission_bytes(_public(), _answers())
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir(mode=0o700)
    monkeypatch.setattr(suite, "load_evaluator_public", lambda _root: public)
    with pytest.raises(attempt.AttemptError, match=match):
        attempt.accept_precommit(
            tmp_path / f"attempt-{field}",
            evaluator,
            _precommit(_public(), reveal),
        )


def test_chain_tamper_is_detected_after_retirement(tmp_path):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)
    attempt.consume_attempt(root, evaluator, reveal_path)
    attempt.retire_attempt(root)
    result_path = root / attempt.RESULT_FILE
    result = suite._strict_public_document(result_path.read_bytes(), "test result")
    altered = deepcopy(result)
    altered["detail"]["correct"] = 0
    result_path.chmod(0o600)
    result_path.write_bytes(suite.canonical_public_bytes(altered))

    with pytest.raises(attempt.AttemptError, match="record_id"):
        attempt.retired_report(root)


def test_precommit_tamper_and_world_readable_ledger_are_rejected(tmp_path):
    _public_document, _reveal, _reveal_path, root, _evaluator = _opened(tmp_path)
    attempt.retire_attempt(root)
    precommit_path = root / attempt.PRECOMMIT_FILE
    precommit_path.write_bytes(b"{}\n")
    with pytest.raises(attempt.AttemptError, match="precommitment"):
        attempt.retired_report(root)

    if os.name != "nt":
        root.chmod(0o755)
        with pytest.raises(attempt.AttemptError, match="0700"):
            attempt.retired_report(root)


def test_retirement_itself_is_exclusive(tmp_path):
    _public_document, _reveal, _reveal_path, root, _evaluator = _opened(tmp_path)
    attempt.retire_attempt(root)
    with pytest.raises(attempt.AttemptConsumedError, match="already retired"):
        attempt.retire_attempt(root)
    report = attempt.retired_report(root)
    assert report["outcome"] == "retired-without-result"


def test_public_api_refuses_forged_in_memory_evaluator_document(tmp_path):
    public = _public()
    reveal = submission.canonical_submission_bytes(public, _answers())

    with pytest.raises(attempt.AttemptError, match="invalid evaluator root"):
        attempt.accept_precommit(
            tmp_path / "attempt",
            public,
            _precommit(public, reveal),
        )
    assert not (tmp_path / "attempt").exists()


def test_retirement_cannot_race_an_active_consumer(tmp_path, monkeypatch):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)
    entered = Event()
    release = Event()
    original = attempt._read_reveal

    def blocked_read(*args, **kwargs):
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError("test did not release reveal reader")
        return original(*args, **kwargs)

    monkeypatch.setattr(attempt, "_read_reveal", blocked_read)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(attempt.consume_attempt, root, evaluator, reveal_path)
        assert entered.wait(timeout=10)
        try:
            with pytest.raises(attempt.AttemptBusyError, match="transitioning"):
                attempt.retire_attempt(root)
        finally:
            release.set()
        assert future.result(timeout=10)["state"] == "consumed-feedback-withheld"

    retirement = attempt.retire_attempt(root)
    report = attempt.retired_report(root)
    assert report["retirement_record_id"] == retirement["record_id"]
    assert report["outcome"] == "scored"


def test_torn_unpublished_claim_stage_is_recovered_without_false_consumption(
    tmp_path, monkeypatch
):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)
    original = attempt._write_exclusive_record
    injected = False

    def torn_stage(root_fd, name, data):
        nonlocal injected
        if not injected and name.startswith(attempt._record_stage_prefix(attempt.CLAIM_FILE)):
            injected = True
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
            try:
                os.write(descriptor, data[: max(1, len(data) // 2)])
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise attempt.AttemptError("injected torn stage")
        return original(root_fd, name, data)

    monkeypatch.setattr(attempt, "_write_exclusive_record", torn_stage)
    with pytest.raises(attempt.AttemptError, match="injected torn stage"):
        attempt.consume_attempt(root, evaluator, reveal_path)
    assert not (root / attempt.CLAIM_FILE).exists()
    assert any(path.name.startswith(".claim.json.stage-") for path in root.iterdir())

    receipt = attempt.consume_attempt(root, evaluator, reveal_path)
    assert receipt["state"] == "consumed-feedback-withheld"
    assert not any(path.name.startswith(".claim.json.stage-") for path in root.iterdir())


def _rewrite_self_bound_record(path: Path, mutate) -> None:
    document = suite._strict_public_document(path.read_bytes(), f"test {path.name}")
    unsigned = dict(document)
    unsigned.pop("record_id")
    mutate(unsigned)
    path.write_bytes(attempt._record_bytes(unsigned))
    if os.name != "nt":
        path.chmod(0o600)


@pytest.mark.parametrize("record_name", ["acceptance", "claim", "result", "receipt", "retirement"])
def test_semantically_forged_self_bound_records_are_rejected(
    tmp_path, monkeypatch, record_name
):
    case = tmp_path / record_name
    case.mkdir()
    _public_document, _reveal, reveal_path, root, evaluator = _opened(case)

    if record_name == "acceptance":
        target = root / attempt.ACCEPTANCE_FILE
    elif record_name == "claim":
        with monkeypatch.context() as patcher:
            patcher.setattr(
                attempt,
                "_score_reveal",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("stop")),
            )
            with pytest.raises(RuntimeError, match="stop"):
                attempt.consume_attempt(root, evaluator, reveal_path)
        target = root / attempt.CLAIM_FILE
    elif record_name in {"result", "receipt"}:
        attempt.consume_attempt(root, evaluator, reveal_path)
        target = root / (
            attempt.RESULT_FILE if record_name == "result" else attempt.RECEIPT_FILE
        )
    else:
        attempt.retire_attempt(root)
        target = root / attempt.RETIREMENT_FILE

    def mutate(record):
        if record_name == "acceptance":
            record["state"] = "invented"
        elif record_name == "claim":
            record["expected_submission"] = {"sha256": _digest("9"), "size": 1}
        elif record_name == "result":
            record["outcome"] = "banana"
        elif record_name == "receipt":
            record["notice"] = "feedback is public"
        else:
            record["trust"] = "fully attested"

    _rewrite_self_bound_record(target, mutate)
    with pytest.raises(attempt.AttemptError):
        if record_name == "retirement":
            attempt.retired_report(root)
        else:
            attempt.retire_attempt(root)


def test_retired_evidence_bundle_opens_receipt_and_binds_detached_reveal(tmp_path):
    _public_document, reveal, reveal_path, root, evaluator = _opened(tmp_path)
    attempt.consume_attempt(root, evaluator, reveal_path)
    attempt.retire_attempt(root)
    report = attempt.retired_report(root)

    verified = attempt.verify_retired_report(report, reveal=reveal)
    assert verified["report_id"] == report["report_id"]
    assert verified["chain_records"] == 5
    assert verified["reveal_verified"] is True
    assert report["evidence"]["result"]["blinding_nonce"].startswith("sha256:")
    assert report["evidence"]["receipt"]["previous"]["sha256"] == attempt._sha256(
        suite.canonical_public_bytes(report["evidence"]["result"])
    )

    with pytest.raises(attempt.AttemptError, match="detached reveal"):
        attempt.verify_retired_report(report, reveal=reveal + b" ")
    altered = deepcopy(report)
    altered["evidence"]["result"]["detail"]["correct"] = 0
    with pytest.raises(attempt.AttemptError, match="report_id"):
        attempt.verify_retired_report(altered)


def test_detached_verifier_rejects_retirement_that_predates_claim(tmp_path):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)
    attempt.consume_attempt(root, evaluator, reveal_path)
    attempt.retire_attempt(root)
    forged = deepcopy(attempt.retired_report(root))

    retirement_unsigned = dict(forged["evidence"]["retirement"])
    retirement_unsigned.pop("record_id")
    retirement_unsigned["retired_at"] = forged["evidence"]["acceptance"]["accepted_at"]
    forged["evidence"]["retirement"] = attempt._record(retirement_unsigned)
    forged["retirement_record_id"] = forged["evidence"]["retirement"]["record_id"]
    report_unsigned = dict(forged)
    report_unsigned.pop("report_id")
    forged["report_id"] = attempt._sha256(suite.canonical_public_bytes(report_unsigned))

    with pytest.raises(attempt.AttemptError, match="retirement state/trust"):
        attempt.verify_retired_report(forged)


def test_case_aliases_cannot_place_ledger_or_reveal_inside_evaluator(tmp_path):
    evaluator = tmp_path / "EvaluatorCaseBoundary"
    evaluator.mkdir(mode=0o700)
    alias = tmp_path / "evaluatorcaseboundary"
    if not alias.exists() or not os.path.samefile(evaluator, alias):
        pytest.skip("filesystem is case-sensitive")
    public = _public()
    reveal = submission.canonical_submission_bytes(public, _answers())
    precommit = _precommit(public, reveal)

    with pytest.raises(attempt.AttemptError, match="outside the evaluator root"):
        attempt.accept_precommit(alias / "ledger", evaluator, precommit)
    assert not (evaluator / "ledger").exists()

    root = tmp_path / "outside-ledger"
    attempt.accept_precommit(root, evaluator, precommit)
    reveal_path = evaluator / "Reveal.JSONL"
    reveal_path.write_bytes(reveal)
    attempt.consume_attempt(root, evaluator, alias / "reveal.jsonl")
    attempt.retire_attempt(root)
    assert attempt.retired_report(root)["detail"] == {
        "reason": "forbidden-reveal-location"
    }


def _prepare_carrier_case(
    case: Path, record_name: str, monkeypatch
) -> tuple[Path, Path]:
    case.mkdir()
    _public_document, _reveal, reveal_path, root, evaluator = _opened(case)
    if record_name == "claim":
        with monkeypatch.context() as patcher:
            patcher.setattr(
                attempt,
                "_score_reveal",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("stop")),
            )
            with pytest.raises(RuntimeError, match="stop"):
                attempt.consume_attempt(root, evaluator, reveal_path)
    elif record_name in {"result", "receipt"}:
        attempt.consume_attempt(root, evaluator, reveal_path)
    elif record_name == "retirement":
        attempt.retire_attempt(root)
    filenames = {
        "acceptance": attempt.ACCEPTANCE_FILE,
        "claim": attempt.CLAIM_FILE,
        "lock": attempt.LOCK_FILE,
        "precommit": attempt.PRECOMMIT_FILE,
        "receipt": attempt.RECEIPT_FILE,
        "result": attempt.RESULT_FILE,
        "retirement": attempt.RETIREMENT_FILE,
    }
    return root, root / filenames[record_name]


@pytest.mark.parametrize(
    "record_name",
    ["acceptance", "precommit", "lock", "claim", "result", "receipt", "retirement"],
)
def test_every_live_carrier_rejects_malformed_bytes_with_attempt_error(
    tmp_path, monkeypatch, record_name
):
    root, target = _prepare_carrier_case(tmp_path / record_name, record_name, monkeypatch)
    target.write_bytes(b"{\n")
    if os.name != "nt":
        target.chmod(0o600)

    with pytest.raises(attempt.AttemptError) as raised:
        if record_name == "retirement":
            attempt.retired_report(root)
        else:
            attempt.retire_attempt(root)
    assert type(raised.value) is attempt.AttemptError


@pytest.mark.parametrize(
    "record_name",
    ["acceptance", "precommit", "lock", "claim", "result", "receipt", "retirement"],
)
def test_every_live_carrier_rejects_extra_hardlinks(
    tmp_path, monkeypatch, record_name
):
    case = tmp_path / record_name
    root, target = _prepare_carrier_case(case, record_name, monkeypatch)
    os.link(target, case / f"extra-{target.name}")

    with pytest.raises(attempt.AttemptError):
        if record_name == "retirement":
            attempt.retired_report(root)
        else:
            attempt.retire_attempt(root)


@pytest.mark.parametrize(
    "record_name",
    ["acceptance", "precommit", "lock", "claim", "result", "receipt", "retirement"],
)
def test_every_live_carrier_rejects_nonprivate_modes(
    tmp_path, monkeypatch, record_name
):
    root, target = _prepare_carrier_case(tmp_path / record_name, record_name, monkeypatch)
    target.chmod(0o644)

    with pytest.raises(attempt.AttemptError):
        if record_name == "retirement":
            attempt.retired_report(root)
        else:
            attempt.retire_attempt(root)


@pytest.mark.parametrize("record_name", ["claim", "result", "receipt", "retirement"])
def test_every_atomic_record_recovers_a_torn_unpublished_stage(
    tmp_path, monkeypatch, record_name
):
    _public_document, _reveal, reveal_path, root, evaluator = _opened(tmp_path)
    filename = {
        "claim": attempt.CLAIM_FILE,
        "result": attempt.RESULT_FILE,
        "receipt": attempt.RECEIPT_FILE,
        "retirement": attempt.RETIREMENT_FILE,
    }[record_name]
    stage_prefix = attempt._record_stage_prefix(filename)
    original = attempt._write_exclusive_record
    injected = False

    def torn_stage(root_fd, name, data):
        nonlocal injected
        if not injected and name.startswith(stage_prefix):
            injected = True
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
            try:
                os.write(descriptor, data[: max(1, len(data) // 2)])
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise attempt.AttemptError(f"injected torn {record_name} stage")
        return original(root_fd, name, data)

    monkeypatch.setattr(attempt, "_write_exclusive_record", torn_stage)
    with pytest.raises(attempt.AttemptError, match=f"torn {record_name}"):
        if record_name == "retirement":
            attempt.retire_attempt(root)
        else:
            attempt.consume_attempt(root, evaluator, reveal_path)
    assert not (root / filename).exists()
    assert any(path.name.startswith(stage_prefix) for path in root.iterdir())

    if record_name == "claim":
        attempt.consume_attempt(root, evaluator, reveal_path)
        attempt.retire_attempt(root)
    elif record_name == "retirement":
        attempt.retire_attempt(root)
    else:
        with pytest.raises(attempt.AttemptConsumedError):
            attempt.consume_attempt(root, evaluator, reveal_path)
        attempt.retire_attempt(root)
    assert not any(path.name.startswith(stage_prefix) for path in root.iterdir())
    assert attempt.retired_report(root)["outcome"] in {
        "retired-without-result",
        "scored",
    }
