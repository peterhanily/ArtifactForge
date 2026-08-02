# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Parser-valid positive controls for every complete Benchmark-v2 shortcut attack.

A weak score is evidence only when the attack is known to work against a scene carrying the
vulnerability it claims to detect.  This module makes a private temporary copy of one Windows
and one macOS public task for each registered complete attack, introduces that vulnerability,
and requires both the attack and the closed-rule reference solver to recover all ten answers.

The controls never edit their source tasks.  Registry, PE, SQLite and quarantine-xattr changes
reuse the production builders and Gate 1 parser-consensus adapters exposed by the bounded
counterfactual layer.  Low-information listing, null and constant controls are intentionally
outside this calibration: they are not complete selection attacks and have no 100% vulnerable
world to establish.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import tempfile

from artifactforge.artifacts.macos import parse_quarantine_xattr, quarantine_xattr
from artifactforge.bench.adversary import COMPLETE_ADVERSARIES
from artifactforge.bench.benchmark import PublicTask, Question, Task, grade, normalize
from artifactforge.bench.counterfactual import (
    _amcache_row_index,
    _artifact_path,
    _read_amcache,
    _read_quarantine_rows,
    _source_bytes,
    _temporary_task,
    _validate_pe,
    _validate_xattr,
    _write_amcache,
    _write_quarantine_rows,
    _write_xattr_uuid,
)
from artifactforge.bench.partial_union import trained_partial_union
from artifactforge.bench.reference_solver import Resolution, reference_solve, resolve_task
from artifactforge.bench.rank_union import fit_rank_union, predict_rank_union
from artifactforge.inventory import InventoryFile, inventory_regular_files


QUESTION_COUNT = 5
EXCLUDED_LOW_CONTROLS = ("constant", "listing", "null")
RANK_ATTACKS = ("footprint", "lexical", "mechanical", "pool")
_MAC_EPOCH_OFFSET = 978307200


@dataclass(frozen=True)
class FamilyCalibration:
    """One attack against one deliberately vulnerable family control."""

    family: str
    control: str
    solver_correct: int
    solver_coverage: int
    reference_correct: int
    total: int
    failures: tuple[str, ...] = ()

    @property
    def solver_score(self) -> float:
        return self.solver_correct / self.total if self.total else 0.0

    @property
    def reference_score(self) -> float:
        return self.reference_correct / self.total if self.total else 0.0

    @property
    def passed(self) -> bool:
        return (
            not self.failures
            and self.total == QUESTION_COUNT
            and self.solver_correct == self.solver_coverage == self.total
            and self.reference_correct == self.total
        )


@dataclass(frozen=True)
class AttackCalibration:
    """The two-family positive-control result for one registered complete attack."""

    attack: str
    families: tuple[FamilyCalibration, ...]

    @property
    def solver_correct(self) -> int:
        return sum(control.solver_correct for control in self.families)

    @property
    def solver_coverage(self) -> int:
        return sum(control.solver_coverage for control in self.families)

    @property
    def reference_correct(self) -> int:
        return sum(control.reference_correct for control in self.families)

    @property
    def total(self) -> int:
        return sum(control.total for control in self.families)

    @property
    def solver_score(self) -> float:
        return self.solver_correct / self.total if self.total else 0.0

    @property
    def reference_score(self) -> float:
        return self.reference_correct / self.total if self.total else 0.0

    @property
    def failures(self) -> tuple[str, ...]:
        return tuple(
            f"{control.family}: {failure}"
            for control in self.families
            for failure in control.failures
        )

    @property
    def passed(self) -> bool:
        return (
            len(self.families) == 2
            and {control.family for control in self.families} == {"windows", "macos"}
            and all(control.passed for control in self.families)
        )


@dataclass(frozen=True)
class PartialUnionCalibration:
    """Production partial-union wrapper fitted and measured against fixed truth."""

    dev_correct: int
    dev_total: int
    measurement_correct: int
    measurement_total: int
    mapped_questions: int
    source_covered: int
    fallback_count: int
    selected_attacks: tuple[str, ...]
    cross_slot_selections: int
    failures: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return (
            not self.failures
            and self.dev_total > 0
            and self.dev_correct == self.dev_total
            and self.measurement_total > 0
            and self.measurement_correct == self.measurement_total
            and self.mapped_questions == self.measurement_total
            and self.source_covered == self.measurement_total
            and self.fallback_count == 0
            and len(self.selected_attacks) == 2
            and self.cross_slot_selections == QUESTION_COUNT * 2
        )


@dataclass(frozen=True)
class RankUnionCalibration:
    """Production wrapper fitted on fixed dev truth and scored on separate fixed truth."""

    dev_correct: int
    dev_total: int
    measurement_correct: int
    measurement_total: int
    mapped_questions: int
    failures: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return (
            not self.failures
            and self.dev_total > 0
            and self.dev_correct == self.dev_total
            and self.measurement_total > 0
            and self.measurement_correct == self.measurement_total
            and self.mapped_questions == self.measurement_total
        )


@dataclass(frozen=True)
class _ControlOracle:
    """Truth fixed by an implementation independent of the attack being calibrated."""

    expected: dict[str, str]
    fixture: str


@dataclass(frozen=True)
class PositiveControlReport:
    """Complete attacks and two separately mandatory composition controls."""

    details: tuple[AttackCalibration, ...]
    partial_union: PartialUnionCalibration
    rank_union: RankUnionCalibration
    excluded: tuple[str, ...] = EXCLUDED_LOW_CONTROLS

    @property
    def passed(self) -> int:
        return (
            sum(detail.passed for detail in self.details)
            + int(self.partial_union.passed)
            + int(self.rank_union.passed)
        )

    @property
    def total(self) -> int:
        return len(self.details) + 2

    @property
    def ok(self) -> bool:
        return self.passed == self.total

    @property
    def failures(self) -> tuple[str, ...]:
        attack_failures = tuple(
            f"{detail.attack}: {failure}" for detail in self.details for failure in detail.failures
        )
        union_failures = tuple(
            f"trained partial union: {failure}" for failure in self.partial_union.failures
        )
        rank_union_failures = tuple(
            f"trained rank union: {failure}" for failure in self.rank_union.failures
        )
        return attack_failures + union_failures + rank_union_failures


def _validate_task(public: PublicTask, family: str) -> None:
    if not isinstance(public, PublicTask):
        raise TypeError(f"{family} positive control requires a PublicTask")
    if public.family != family:
        raise ValueError(f"expected a {family} PublicTask, received family {public.family!r}")
    if not isinstance(public.questions, list) or len(public.questions) != QUESTION_COUNT:
        raise ValueError(f"{family} positive control requires exactly five questions")
    question_ids = [question.id for question in public.questions]
    if any(not isinstance(value, str) or not value for value in question_ids):
        raise ValueError(f"{family} positive-control question ids must be non-empty text")
    if len(set(question_ids)) != QUESTION_COUNT:
        raise ValueError(f"{family} positive-control question ids must be unique")


def _baseline(
    public: PublicTask,
) -> tuple[dict[str, str], dict[str, Resolution], tuple[str, ...]]:
    resolutions = resolve_task(public)
    expected = {question.id: resolutions[question.id].value for question in public.questions}
    candidate_sets = {resolution.candidates for resolution in resolutions.values()}
    if len(candidate_sets) != 1:
        raise ValueError("positive-control questions disagree on their candidate universe")
    candidates = next(iter(candidate_sets))
    if (
        len(candidates) != QUESTION_COUNT
        or len(set(candidates)) != QUESTION_COUNT
        or set(expected.values()) != set(candidates)
    ):
        raise ValueError("positive-control baseline is not an exact five-way bijection")
    return expected, resolutions, candidates


def _answers(
    public: PublicTask,
    solver: Callable,
    *,
    where: str,
) -> dict:
    value = solver(public)
    if not isinstance(value, dict):
        raise ValueError(f"{where} returned {type(value).__name__}, not a dictionary")
    return value


def _score(public: PublicTask, expected: dict[str, str], answers: dict) -> tuple[int, int]:
    correct = coverage = 0
    for question in public.questions:
        if question.id in answers:
            coverage += 1
        correct += int(
            normalize(answers.get(question.id), question.kind)
            == normalize(expected[question.id], question.kind)
        )
    return correct, coverage


def _require_expected_contract(public: PublicTask, expected: dict[str, str]) -> None:
    question_ids = {question.id for question in public.questions}
    if set(expected) != question_ids:
        raise ValueError("positive-control expected map does not cover exactly five questions")
    resolutions = resolve_task(public)
    actual = {question.id: resolutions[question.id].value for question in public.questions}
    if actual != expected:
        raise ValueError("closed-rule resolver disagrees with the constructed control truth")
    candidates = resolutions[public.questions[0].id].candidates
    if len(candidates) != QUESTION_COUNT or set(expected.values()) != set(candidates):
        raise ValueError("constructed control truth is not a five-way candidate bijection")


def _selected_amcache_rows(public: PublicTask, rows) -> dict[str, int]:
    return {
        question.id: _amcache_row_index(rows, question.selector["lower_case_long_path"])
        for question in public.questions
    }


def _oracle_selector_text(question) -> str:
    return json.dumps(
        question.selector,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _oracle_bytes(file: InventoryFile) -> bytes:
    if file.data is None:
        raise AssertionError("positive-control oracle inventory contains no bytes")
    return file.data


def _oracle_windows_candidates(
    files: tuple[InventoryFile, ...],
) -> list[tuple[InventoryFile, str]]:
    return [
        (file, hashlib.sha256(_oracle_bytes(file)).hexdigest())
        for file in files
        if _oracle_bytes(file)[:2] == b"MZ"
    ]


def _oracle_pair(
    public: PublicTask,
    candidates: list[str],
    *,
    question_key: Callable | None = None,
) -> dict[str, str]:
    if len(candidates) != QUESTION_COUNT or len(set(candidates)) != QUESTION_COUNT:
        raise ValueError("independent rank oracle requires five distinct candidates")
    ranked_questions = sorted(
        public.questions,
        key=question_key or (lambda question: _oracle_selector_text(question)),
    )
    return {
        question.id: candidate
        for question, candidate in zip(ranked_questions, candidates, strict=True)
    }


def _independent_rank_oracle(public: PublicTask, attack: str) -> _ControlOracle:
    """Declare a rank vulnerability without calling the attack under calibration.

    This intentionally duplicates only the observable shortcut relation.  The resulting map
    is fixed before the real FileId/UUID relation is rewritten and before the registered
    attack is invoked.  A broken or substituted attack therefore cannot manufacture its own
    calibration truth.
    """
    files = inventory_regular_files(public.directory, capture_bytes=True)
    blobs = {file.relative_path: _oracle_bytes(file) for file in files}
    if public.family == "windows":
        windows = _oracle_windows_candidates(files)
        candidate_values = [value for _file, value in windows]
    else:
        windows = []
        candidate_values = [
            row.data_url
            for row in _read_quarantine_rows(_artifact_path(public, "QuarantineEventsV2"))
        ]

    effective_attack = "lexical" if attack == "alternate_link" else attack
    if effective_attack == "lexical":
        expected = _oracle_pair(public, sorted(candidate_values))
    elif effective_attack == "mechanical":
        expected = {
            question.id: candidate_values[index] for index, question in enumerate(public.questions)
        }
    elif effective_attack == "pool":
        from artifactforge import pools

        if public.family == "windows":
            ranked = [
                answer
                for file, answer in sorted(
                    windows,
                    key=lambda item: (
                        item[0].name not in pools.MALWARE_NAMES,
                        item[0].name not in pools.BENIGN_NAMES,
                        item[0].name,
                        item[1],
                    ),
                )
            ]

            def question_key(question):
                selector = _oracle_selector_text(question).lower()
                return (
                    not any(name.lower() in selector for name in pools.MALWARE_NAMES),
                    not any(name.lower() in selector for name in pools.BENIGN_NAMES),
                    selector,
                )

        else:
            ranked = sorted(
                candidate_values,
                key=lambda url: (
                    not any(bundle in url for bundle in pools.BUNDLES),
                    not any(bundle in url for bundle in pools.BENIGN_BUNDLES),
                    url,
                ),
            )

            def question_key(question):
                selector = _oracle_selector_text(question)
                return (
                    not any(bundle in selector for bundle in pools.BUNDLES),
                    not any(bundle in selector for bundle in pools.BENIGN_BUNDLES),
                    selector,
                )

        expected = _oracle_pair(public, ranked, question_key=question_key)
    elif effective_attack == "footprint":
        if public.family == "windows":

            def candidate_key(item):
                file, answer = item
                patterns = (
                    file.name.encode(),
                    file.name.lower().encode(),
                    file.name.upper().encode(),
                    file.name.encode("utf-16-le"),
                    file.name.upper().encode("utf-16-le"),
                )
                mentions = sum(
                    1
                    for relative, data in blobs.items()
                    if relative != file.relative_path
                    and any(pattern in data for pattern in patterns)
                )
                return -mentions, answer

            ranked = [answer for _file, answer in sorted(windows, key=candidate_key)]

            def question_key(question):
                selector = _oracle_selector_text(question)
                patterns = (selector.encode(), selector.encode("utf-16-le"))
                incidence = sum(
                    any(pattern in data for pattern in patterns) for data in blobs.values()
                )
                return -incidence, selector

        else:

            def url_key(url: str):
                raw = url.encode()
                return -sum(raw in data for data in blobs.values()), url

            ranked = sorted(candidate_values, key=url_key)

            def question_key(question):
                relative = question.selector.get("xattr_relative_path", "")
                bundle = relative.rsplit("/", 1)[-1].removesuffix(".quarantine.xattr")
                raw = bundle.encode()
                incidence = sum(raw in data for data in blobs.values())
                return -incidence, relative

        expected = _oracle_pair(public, ranked, question_key=question_key)
    else:
        raise ValueError(f"rank oracle does not implement attack {attack!r}")

    question_ids = {question.id for question in public.questions}
    if set(expected) != question_ids or set(expected.values()) != set(candidate_values):
        raise ValueError("independent rank oracle did not declare an exact bijection")
    fixture = (
        "macos-lexical-fallback-vulnerability"
        if attack == "alternate_link"
        else f"independent-{attack}-rank-vulnerability"
    )
    return _ControlOracle(expected, fixture)


def _align_relation(
    public: PublicTask,
    expected: dict[str, str],
    resolutions: dict[str, Resolution],
) -> None:
    if public.family == "windows":
        link_by_answer = {
            resolution.value: resolution.link_value for resolution in resolutions.values()
        }
        path = _artifact_path(public, "Amcache.hve")
        rows = _read_amcache(path)
        selected = _selected_amcache_rows(public, rows)
        for question_id, answer in expected.items():
            index = selected[question_id]
            rows[index] = replace(rows[index], sha1=link_by_answer[answer])
        _write_amcache(path, rows)
        return

    link_by_answer = {
        resolution.value: resolution.link_value for resolution in resolutions.values()
    }
    for question in public.questions:
        relative = question.selector["xattr_relative_path"]
        path = Path(public.directory).joinpath(*relative.split("/"))
        _write_xattr_uuid(path, link_by_answer[expected[question.id]])


def _rank_reassignment(public: PublicTask, attack: str):
    _baseline_expected, resolutions, _candidates = _baseline(public)
    oracle = _independent_rank_oracle(public, attack)
    _align_relation(public, oracle.expected, resolutions)
    return public, oracle.expected, oracle.fixture


def _alternate_link_control(public: PublicTask):
    baseline, resolutions, _candidates = _baseline(public)
    if public.family == "macos":
        oracle = _independent_rank_oracle(public, "alternate_link")
        _align_relation(public, oracle.expected, resolutions)
        return public, oracle.expected, oracle.fixture

    path = _artifact_path(public, "Amcache.hve")
    rows = _read_amcache(path)
    selected = _selected_amcache_rows(public, rows)
    used = set()
    for question_id, index in selected.items():
        record_key = "0000" + resolutions[question_id].link_value[:8]
        if record_key in used:
            raise ValueError("old-style Amcache SHA1 prefixes collided")
        rows[index] = replace(rows[index], record_key=record_key)
        used.add(record_key)
    for index, row in enumerate(rows):
        if index in set(selected.values()):
            continue
        record_key = row.record_key
        nonce = 0
        while record_key in used:
            token = hashlib.sha256(
                f"positive-control/stale-amcache/{public.scenario_id}/{index}/{nonce}".encode()
            ).hexdigest()[:16]
            record_key = "ffff" + token
            nonce += 1
        rows[index] = replace(row, record_key=record_key)
        used.add(record_key)
    _write_amcache(path, rows)
    return public, baseline, "amcache-subkey-sha1-prefix"


def _resident_path(resolution: Resolution) -> str:
    matches = [path for path in resolution.artifacts if path.rsplit("/", 1)[-1] != "Amcache.hve"]
    if len(matches) != 1:
        raise ValueError("Windows control did not resolve through exactly one resident PE")
    return matches[0]


def _selector_control(public: PublicTask):
    baseline, resolutions, _candidates = _baseline(public)
    if public.family == "windows":
        path = _artifact_path(public, "Amcache.hve")
        rows = _read_amcache(path)
        selected = _selected_amcache_rows(public, rows)
        for question_id, index in selected.items():
            filename = _resident_path(resolutions[question_id]).rsplit("/", 1)[-1]
            rows[index] = replace(rows[index], name=filename)
        _write_amcache(path, rows)
        return public, baseline, "selected-amcache-name-disclosure"

    path = _artifact_path(public, "QuarantineEventsV2")
    rows = _read_quarantine_rows(path)
    row_by_uuid = {row.event_uuid: index for index, row in enumerate(rows)}
    expected = {}
    for index, question in enumerate(public.questions):
        relative = question.selector["xattr_relative_path"]
        bundle = relative.rsplit("/", 1)[-1].removesuffix(".quarantine.xattr")
        token = hashlib.sha256(
            f"positive-control/selector/{public.scenario_id}/{question.id}".encode()
        ).hexdigest()[:16]
        url = f"https://selector-control.invalid/{bundle}/{token}.dmg"
        row_index = row_by_uuid[resolutions[question.id].link_value]
        rows[row_index] = replace(rows[row_index], data_url=url)
        expected[question.id] = url
    _write_quarantine_rows(path, rows)
    return public, expected, "quarantine-url-bundle-disclosure"


def _metadata_control(public: PublicTask):
    baseline, _resolutions, _candidates = _baseline(public)
    questions = [
        replace(
            question,
            prompt=f"{question.prompt} Positive-control expected answer: {baseline[question.id]}",
        )
        for question in public.questions
    ]
    return replace(public, questions=questions), baseline, "answer-embedded-in-prompt"


def _scalar_windows(public: PublicTask):
    _baseline_expected, resolutions, _candidates = _baseline(public)
    expected = {}
    used_sizes = set()
    new_identity = {}
    for index, question in enumerate(public.questions):
        relative = _resident_path(resolutions[question.id])
        path = Path(public.directory).joinpath(*relative.split("/"))
        original = path.read_bytes()
        append_size = index + 1
        while len(original) + append_size in used_sizes:
            append_size += QUESTION_COUNT
        filler = b""
        nonce = 0
        while len(filler) < append_size:
            filler += hashlib.sha256(
                original + question.id.encode() + nonce.to_bytes(2, "big")
            ).digest()
            nonce += 1
        mutated = original + filler[:append_size]
        path.write_bytes(mutated)
        _validate_pe(path)
        used_sizes.add(len(mutated))
        sha1 = hashlib.sha1(mutated).hexdigest()  # noqa: S324 - forensic identity
        sha256 = hashlib.sha256(mutated).hexdigest()
        new_identity[question.id] = (sha1, sha256, len(mutated))
        expected[question.id] = sha256

    amcache = _artifact_path(public, "Amcache.hve")
    rows = _read_amcache(amcache)
    selected = _selected_amcache_rows(public, rows)
    for question_id, index in selected.items():
        sha1, _sha256, size = new_identity[question_id]
        rows[index] = replace(rows[index], sha1=sha1, size=size)
    _write_amcache(amcache, rows)
    return public, expected, "unique-amcache-size"


def _scalar_macos(public: PublicTask):
    baseline, resolutions, _candidates = _baseline(public)
    database = _artifact_path(public, "QuarantineEventsV2")
    rows = _read_quarantine_rows(database)
    row_by_uuid = {row.event_uuid: index for index, row in enumerate(rows)}
    for index, question in enumerate(public.questions):
        event_uuid = resolutions[question.id].link_value
        agent = f"AFControl{index:02d}"
        mac_time = 700_000_000 + index * 137
        row_index = row_by_uuid[event_uuid]
        rows[row_index] = replace(rows[row_index], agent=agent, timestamp=float(mac_time))
        relative = question.selector["xattr_relative_path"]
        path = Path(public.directory).joinpath(*relative.split("/"))
        value = parse_quarantine_xattr(path.read_bytes())
        path.write_bytes(
            quarantine_xattr(
                event_uuid,
                agent,
                mac_time + _MAC_EPOCH_OFFSET,
                flags=value.flags,
            ).encode("ascii")
        )
        _validate_xattr(path)
    _write_quarantine_rows(database, rows)
    return public, baseline, "unique-quarantine-time-agent"


def _scalar_control(public: PublicTask):
    return _scalar_windows(public) if public.family == "windows" else _scalar_macos(public)


def _build_control(public: PublicTask, attack: str):
    if attack in RANK_ATTACKS:
        return _rank_reassignment(public, attack)
    if attack == "alternate_link":
        return _alternate_link_control(public)
    if attack == "selector":
        return _selector_control(public)
    if attack == "metadata":
        return _metadata_control(public)
    if attack == "scalar":
        return _scalar_control(public)
    raise ValueError(f"complete attack {attack!r} has no positive-control construction")


def _failed_family(family: str, control: str, failure: str) -> FamilyCalibration:
    return FamilyCalibration(family, control, 0, 0, 0, QUESTION_COUNT, (failure,))


def _calibrate_family(
    source_public: PublicTask,
    source: dict[str, bytes],
    attack: str,
    solver: Callable,
) -> FamilyCalibration:
    try:
        with tempfile.TemporaryDirectory(
            prefix=f"artifactforge-positive-{attack}-{source_public.family}-"
        ) as directory:
            public = _temporary_task(
                source_public,
                source,
                Path(directory) / "scene",
            )
            public, expected, control = _build_control(public, attack)
            _require_expected_contract(public, expected)
            reference_answers = _answers(
                public,
                reference_solve,
                where=f"{attack}/{public.family} reference solver",
            )
            solver_answers = _answers(
                public,
                solver,
                where=f"{attack}/{public.family} calibrated solver",
            )
            reference_correct, _reference_coverage = _score(public, expected, reference_answers)
            solver_correct, solver_coverage = _score(public, expected, solver_answers)
            failures = []
            if reference_correct != QUESTION_COUNT:
                failures.append(
                    f"reference solver recovered {reference_correct}/{QUESTION_COUNT} answers"
                )
            if solver_coverage != QUESTION_COUNT:
                failures.append(f"attack covered {solver_coverage}/{QUESTION_COUNT} questions")
            if solver_correct != QUESTION_COUNT:
                failures.append(
                    f"attack recovered {solver_correct}/{QUESTION_COUNT} vulnerable answers"
                )
            return FamilyCalibration(
                public.family,
                control,
                solver_correct,
                solver_coverage,
                reference_correct,
                QUESTION_COUNT,
                tuple(failures),
            )
    except Exception as exc:  # noqa: BLE001 - calibration failures must be returned
        return _failed_family(
            source_public.family,
            "construction-failed",
            f"{type(exc).__name__}: {exc}",
        )


def _missing_attack(attack: str) -> AttackCalibration:
    failure = f"registered solver mapping is missing callable attack {attack!r}"
    return AttackCalibration(
        attack,
        (
            _failed_family("windows", "missing-solver", failure),
            _failed_family("macos", "missing-solver", failure),
        ),
    )


_COMPOSITION_CONTROL_CLASSES = (
    ("windows", "amcache-fileid-byte-agreement-v1", "hash"),
    ("macos", "quarantine-uuid-event-agreement-v1", "url"),
)

_RANK_CONTROL_PERMUTATIONS = (
    (1, 2, 3, 4, 0),
    (4, 0, 1, 2, 3),
    (1, 0, 3, 4, 2),
    (2, 3, 4, 0, 1),
    (3, 4, 0, 1, 2),
    (2, 0, 4, 1, 3),
    (3, 2, 1, 0, 4),
    (4, 3, 0, 2, 1),
)


def _composition_control_corpus(control: str, label: str) -> tuple[Task, ...]:
    """Fix independent truth before any vulnerable attack output is constructed."""
    tasks = []
    for family, rule, kind in _COMPOSITION_CONTROL_CLASSES:
        for scene in range(3):
            scenario_id = f"{control}-control-{label}-{family}-{scene:02d}"
            questions = []
            for slot in range(QUESTION_COUNT):
                token = f"{scenario_id}/answer/{slot}"
                expected = (
                    hashlib.sha256(token.encode()).hexdigest()
                    if kind == "hash"
                    else f"https://rank-control.invalid/{label}/{family}/{scene}/{slot}"
                )
                questions.append(
                    Question(
                        id=f"{family}_agreement_{slot + 1:02d}",
                        prompt=f"Independent {family} {control}-control answer {slot + 1}",
                        kind=kind,
                        rule=rule,
                        selector={"control_slot": slot},
                        candidate_count=QUESTION_COUNT,
                        expected=expected,
                    )
                )
            tasks.append(
                Task(
                    scenario_id=scenario_id,
                    family=family,
                    directory=f"rank-control://{scenario_id}",
                    questions=questions,
                    suite_kind=label,
                )
            )
    return tuple(tasks)


def _rank_control_attack_answers(tasks: tuple[Task, ...]) -> dict[str, dict[str, dict]]:
    attacks = {}
    for attack_index, attack in enumerate(sorted(COMPLETE_ADVERSARIES)):
        permutation = _RANK_CONTROL_PERMUTATIONS[attack_index]
        by_scenario = {}
        for task in tasks:
            expected = tuple(question.expected for question in task.questions)
            by_scenario[task.scenario_id] = {
                question.id: expected[permutation[slot]]
                for slot, question in enumerate(task.questions)
            }
        attacks[attack] = by_scenario
    return attacks


def _rank_union_model_control() -> RankUnionCalibration:
    """Calibrate the exact production wrapper on fixed dev and measurement corpora.

    Truth is materialized first in two disjoint six-scene corpora.  Only then are complete,
    deliberately rank-permuted attack outputs constructed.  The production wrapper performs
    class filtering, matrix construction, training, frozen prediction, question-id mapping
    and scoring.  An independent final grade checks the score returned by that wrapper.
    """
    dev_tasks = _composition_control_corpus("rank", "dev")
    measurement_tasks = _composition_control_corpus("rank", "measurement")
    dev_truth = tuple(task.answer_key() for task in dev_tasks)
    measurement_truth = tuple(task.answer_key() for task in measurement_tasks)
    dev_total = sum(len(task.questions) for task in dev_tasks)
    measurement_total = sum(len(task.questions) for task in measurement_tasks)
    try:
        dev_attacks = _rank_control_attack_answers(dev_tasks)
        measurement_attacks = _rank_control_attack_answers(measurement_tasks)
        if tuple(task.answer_key() for task in dev_tasks) != dev_truth:
            raise ValueError("vulnerable dev attack construction rewrote fixed truth")
        if tuple(task.answer_key() for task in measurement_tasks) != measurement_truth:
            raise ValueError("vulnerable measurement attack construction rewrote fixed truth")

        frozen_models = fit_rank_union(dev_tasks, dev_attacks)
        selected_answers = predict_rank_union(
            frozen_models,
            tuple(task.public() for task in measurement_tasks),
            measurement_attacks,
        )
        models = frozen_models.by_class()
        expected_classes = {(family, rule) for family, rule, _kind in _COMPOSITION_CONTROL_CLASSES}
        failures = []
        if set(models) != expected_classes:
            failures.append(
                "production wrapper fitted classes "
                f"{sorted(models)!r}, expected {sorted(expected_classes)!r}"
            )
        dev_correct = sum(sum(model.dev_hits_by_slot) for model in models.values())
        observed_dev_total = sum(
            model.dev_scene_count * model.candidate_count for model in models.values()
        )
        if observed_dev_total != dev_total:
            failures.append(
                f"production wrapper fitted {observed_dev_total}/{dev_total} dev answers"
            )

        measurement_correct = mapped_questions = 0
        for task in measurement_tasks:
            answers = selected_answers.get(task.scenario_id, {})
            expected_ids = {question.id for question in task.questions}
            if not isinstance(answers, dict) or set(answers) != expected_ids:
                failures.append(
                    f"production wrapper did not map exactly five ids for {task.scenario_id}"
                )
                answers = answers if isinstance(answers, dict) else {}
            mapped_questions += len(set(answers) & expected_ids)
            measurement_correct += grade(task, answers).correct
        if dev_correct != dev_total:
            failures.append(
                f"trained rank union recovered {dev_correct}/{dev_total} fixed dev answers"
            )
        if measurement_correct != measurement_total:
            failures.append(
                "frozen rank union recovered "
                f"{measurement_correct}/{measurement_total} fixed measurement answers"
            )
        return RankUnionCalibration(
            dev_correct,
            dev_total,
            measurement_correct,
            measurement_total,
            mapped_questions,
            tuple(failures),
        )
    except Exception as exc:  # noqa: BLE001 - model calibration is a fail-closed result
        return RankUnionCalibration(
            0,
            dev_total,
            0,
            measurement_total,
            0,
            (f"production rank-union wrapper failed: {type(exc).__name__}: {exc}",),
        )


_PARTIAL_CONTROL_ATTACKS = ("footprint", "lexical")


def _partial_control_attack_answers(tasks: tuple[Task, ...]) -> dict[str, dict[str, dict]]:
    """Build two complementary partial sources after the corpus truth is fixed."""
    attacks = {attack: {} for attack in _PARTIAL_CONTROL_ATTACKS}
    for task in tasks:
        first = {}
        second = {}
        for slot, question in enumerate(task.questions):
            source_question = task.questions[(slot + 1) % QUESTION_COUNT]
            if slot % 2 == 0:
                first[source_question.id] = question.expected
            else:
                second[source_question.id] = question.expected
        attacks[_PARTIAL_CONTROL_ATTACKS[0]][task.scenario_id] = first
        attacks[_PARTIAL_CONTROL_ATTACKS[1]][task.scenario_id] = second
    return attacks


def _partial_union_model_control() -> PartialUnionCalibration:
    """Calibrate the exact production partial-output wrapper on disjoint fixed truth."""
    dev_tasks = _composition_control_corpus("partial", "dev")
    measurement_tasks = _composition_control_corpus("partial", "measurement")
    dev_truth = tuple(task.answer_key() for task in dev_tasks)
    measurement_truth = tuple(task.answer_key() for task in measurement_tasks)
    dev_total = sum(len(task.questions) for task in dev_tasks)
    measurement_total = sum(len(task.questions) for task in measurement_tasks)
    try:
        dev_attacks = _partial_control_attack_answers(dev_tasks)
        measurement_attacks = _partial_control_attack_answers(measurement_tasks)
        if tuple(task.answer_key() for task in dev_tasks) != dev_truth:
            raise ValueError("partial-union dev attack construction rewrote fixed truth")
        if tuple(task.answer_key() for task in measurement_tasks) != measurement_truth:
            raise ValueError("partial-union measurement construction rewrote fixed truth")

        prediction, model = trained_partial_union(
            dev_tasks,
            tuple(task.public() for task in measurement_tasks),
            dev_attacks,
            measurement_attacks,
        )
        dev_correct = sum(selection.dev_hits for selection in model.selections)
        observed_dev_total = sum(selection.dev_scene_count for selection in model.selections)
        failures = []
        if observed_dev_total != dev_total:
            failures.append(
                f"production wrapper fitted {observed_dev_total}/{dev_total} dev answers"
            )
        measurement_correct = mapped_questions = 0
        for task in measurement_tasks:
            answers = prediction.answers.get(task.scenario_id, {})
            expected_ids = {question.id for question in task.questions}
            if not isinstance(answers, dict) or set(answers) != expected_ids:
                failures.append(
                    f"partial-union wrapper did not map exactly five ids for {task.scenario_id}"
                )
                answers = answers if isinstance(answers, dict) else {}
            mapped_questions += len(set(answers) & expected_ids)
            measurement_correct += grade(task, answers).correct
        if dev_correct != dev_total:
            failures.append(
                f"trained partial union recovered {dev_correct}/{dev_total} fixed dev answers"
            )
        if measurement_correct != measurement_total:
            failures.append(
                "frozen partial union recovered "
                f"{measurement_correct}/{measurement_total} fixed measurement answers"
            )
        if prediction.source_covered != measurement_total or prediction.fallback_count:
            failures.append(
                "partial-union control selected-source accounting was "
                f"{prediction.source_covered} covered/{prediction.fallback_count} fallback"
            )
        selected_attacks = model.attack_ids
        cross_slot_selections = sum(
            selection.source_slot != selection.slot for selection in model.selections
        )
        if selected_attacks != tuple(sorted(_PARTIAL_CONTROL_ATTACKS)):
            failures.append(
                f"partial-union control selected {selected_attacks!r}, expected "
                f"{tuple(sorted(_PARTIAL_CONTROL_ATTACKS))!r}"
            )
        if cross_slot_selections != QUESTION_COUNT * 2:
            failures.append(
                "partial-union control did not exercise every cross-slot selection: "
                f"{cross_slot_selections}/{QUESTION_COUNT * 2}"
            )
        return PartialUnionCalibration(
            dev_correct,
            dev_total,
            measurement_correct,
            measurement_total,
            mapped_questions,
            prediction.source_covered,
            prediction.fallback_count,
            selected_attacks,
            cross_slot_selections,
            tuple(failures),
        )
    except Exception as exc:  # noqa: BLE001 - model calibration is a fail-closed result
        return PartialUnionCalibration(
            0,
            dev_total,
            0,
            measurement_total,
            0,
            0,
            measurement_total,
            (),
            0,
            (f"production partial-union wrapper failed: {type(exc).__name__}: {exc}",),
        )


def calibrate_positive_controls(
    windows: PublicTask,
    macos: PublicTask,
    solvers: Mapping[str, Callable],
) -> PositiveControlReport:
    """Calibrate every registered complete attack without touching either source scene."""
    _validate_task(windows, "windows")
    _validate_task(macos, "macos")
    if not isinstance(solvers, Mapping):
        raise TypeError("positive-control solvers must be a mapping")
    windows_source = _source_bytes(windows)
    macos_source = _source_bytes(macos)

    details = []
    for attack in sorted(COMPLETE_ADVERSARIES):
        solver = solvers.get(attack)
        if not callable(solver):
            details.append(_missing_attack(attack))
            continue
        details.append(
            AttackCalibration(
                attack,
                (
                    _calibrate_family(windows, windows_source, attack, solver),
                    _calibrate_family(macos, macos_source, attack, solver),
                ),
            )
        )

    partial_union = _partial_union_model_control()
    rank_union = _rank_union_model_control()
    return PositiveControlReport(tuple(details), partial_union, rank_union)


__all__ = [
    "AttackCalibration",
    "EXCLUDED_LOW_CONTROLS",
    "FamilyCalibration",
    "PartialUnionCalibration",
    "PositiveControlReport",
    "RankUnionCalibration",
    "calibrate_positive_controls",
]
