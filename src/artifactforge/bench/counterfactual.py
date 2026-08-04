# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Parser-valid counterfactual proofs for Benchmark v2's two closed rules.

A resolver returning the right answer does not by itself prove that it used the claimed
fields.  This module copies one public scene into private temporary directories and changes
only the proposed relation.  All ten unordered pair swaps must swap exactly two answers; an
absent link or a same-size resident-byte replacement must make exactly one answer unavailable.
Every other answer has to remain byte-for-byte identical to the baseline.

The stronger mapping-world proof enumerates all ``5!`` assignments for each independently
mutable identity mechanism.  Every world is rebuilt from the pristine captured source,
accepted by the relevant parser pair and semantic profile, independently resolved across all
five questions, invisible to every registered relation-omitting attack, and visible to a
named relation-aware positive control.  Gate 4 runs that exhaustive proof on one deterministic
representative per mechanism; the local mutations still run on every measurement scene.

Counterfactual artifacts stay inside the declared profiles.  Amcache and
QuarantineEventsV2 are rebuilt with the production builders, replacement PEs come from the
production inert PE writer, and all four formats are passed through Gate 1's parser-consensus
adapters before their answer effects count.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
from itertools import combinations, permutations
import math
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from artifactforge.artifacts.hive import build_amcache_hive
from artifactforge.artifacts.macos import (
    build_quarantine_events,
    parse_quarantine_xattr,
    quarantine_xattr,
)
from artifactforge.bench.adversary import ADVERSARIES
from artifactforge.bench.benchmark import PublicTask
from artifactforge.bench.reference_solver import (
    RULE_FAMILIES,
    Resolution,
    resolve_question_snapshot,
    resolve_task,
)
from artifactforge.compose.scene import MACOS_QUARANTINE_RULE, WINDOWS_AMCACHE_RULE
from artifactforge.content import build_pe_stub
from artifactforge.inventory import captured_regular_tree
from artifactforge.model import deterministic_uuid


QUESTION_COUNT = 5
PAIR_SWAP_COUNT = math.comb(QUESTION_COUNT, 2)
MAPPING_WORLD_COUNT = math.factorial(QUESTION_COUNT)
MAPPING_POSITIVE_CONTROL = "direct-relation-reader-v1"
MAX_RELATION_OMITTING_ATTACKS = 32
WINDOWS_FILEID_RELATION = "windows-amcache-fileid-to-resident-bytes"
MACOS_XATTR_UUID_RELATION = "macos-quarantine-xattr-uuid-to-event-row"
MACOS_DATABASE_UUID_RELATION = "macos-quarantine-database-uuid-to-event-row"
MAPPING_RELATIONS = {
    "windows": (WINDOWS_FILEID_RELATION,),
    "macos": (MACOS_XATTR_UUID_RELATION, MACOS_DATABASE_UUID_RELATION),
}
MAPPING_PARSER_ARTIFACTS_PER_WORLD = {
    WINDOWS_FILEID_RELATION: 1,
    MACOS_XATTR_UUID_RELATION: QUESTION_COUNT,
    MACOS_DATABASE_UUID_RELATION: 1,
}
LOCAL_CHECKS_PER_FAMILY = {
    "windows": PAIR_SWAP_COUNT + QUESTION_COUNT * 2,
    "macos": PAIR_SWAP_COUNT * 2 + QUESTION_COUNT,
}
_AMCACHE_UNAVAILABLE = re.compile(
    r"^Amcache FileId .+ matched 0 resident PE files$"
)
_QUARANTINE_UNAVAILABLE = re.compile(
    r"^quarantine UUID .+ matched 0 event rows$"
)


@dataclass(frozen=True)
class ExpectedOutcome:
    """The exact state and value one question must have after a mutation."""

    question_id: str
    state: str
    value: str | None


@dataclass(frozen=True)
class ObservedOutcome:
    """One independently resolved question after a counterfactual mutation."""

    question_id: str
    state: str
    value: str | None
    error: str | None = None


class RegisteredAttackExecutionError(RuntimeError):
    """A named mapping-world baseline attack failed before invariance could be measured."""

    def __init__(self, name: str, cause: Exception):
        self.name = name
        self.cause = cause
        super().__init__(f"registered attack {name!r}: {type(cause).__name__}: {cause}")


@dataclass(frozen=True)
class CounterfactualDetail:
    """One mutation and its complete five-question observation."""

    mutation: str
    targets: tuple[str, ...]
    passed: bool
    expected: tuple[ExpectedOutcome, ...]
    observed: tuple[ObservedOutcome, ...]
    error: str | None = None


@dataclass(frozen=True)
class MappingWorldDetail:
    """One complete five-way mapping and every check required for it to count."""

    permutation: tuple[int, ...]
    expected: tuple[ExpectedOutcome, ...]
    observed: tuple[ObservedOutcome, ...]
    positive_control_observed: tuple[ObservedOutcome, ...]
    parser_artifacts_passed: int
    parser_artifacts_total: int
    reference_questions_passed: int
    reference_questions_total: int
    attack_invariance_passed: int
    attack_invariance_total: int
    positive_control_questions_passed: int
    positive_control_questions_total: int
    positive_control_change_passed: int
    positive_control_change_total: int
    attack_failures: tuple[str, ...] = ()
    error: str | None = None

    @property
    def passed(self) -> bool:
        return (
            self.error is None
            and self.parser_artifacts_passed == self.parser_artifacts_total
            and self.reference_questions_passed == self.reference_questions_total
            and self.attack_invariance_passed == self.attack_invariance_total
            and self.positive_control_questions_passed
            == self.positive_control_questions_total
            and self.positive_control_change_passed
            == self.positive_control_change_total
        )


@dataclass(frozen=True)
class MappingWorldReport:
    """Exhaustive proof for one mutable identity mechanism in one source scene."""

    relation: str
    positive_control: str
    attack_names: tuple[str, ...]
    details: tuple[MappingWorldDetail, ...]

    @property
    def passed(self) -> int:
        return sum(detail.passed for detail in self.details)

    @property
    def total(self) -> int:
        return len(self.details)

    @property
    def ok(self) -> bool:
        return self.total == MAPPING_WORLD_COUNT and self.passed == self.total

    def metric_counts(self) -> dict[str, int]:
        """Return exact, non-overloaded numerators and denominators for Gate 4."""
        return {
            "mapping_relations_passed": int(self.ok),
            "mapping_relations_total": 1,
            "mapping_worlds_passed": self.passed,
            "mapping_worlds_total": self.total,
            "mapping_parser_artifacts_passed": sum(
                detail.parser_artifacts_passed for detail in self.details
            ),
            "mapping_parser_artifacts_total": sum(
                detail.parser_artifacts_total for detail in self.details
            ),
            "mapping_reference_questions_passed": sum(
                detail.reference_questions_passed for detail in self.details
            ),
            "mapping_reference_questions_total": sum(
                detail.reference_questions_total for detail in self.details
            ),
            "mapping_attack_invariance_passed": sum(
                detail.attack_invariance_passed for detail in self.details
            ),
            "mapping_attack_invariance_total": sum(
                detail.attack_invariance_total for detail in self.details
            ),
            "mapping_positive_control_questions_passed": sum(
                detail.positive_control_questions_passed for detail in self.details
            ),
            "mapping_positive_control_questions_total": sum(
                detail.positive_control_questions_total for detail in self.details
            ),
            "mapping_positive_control_changes_passed": sum(
                detail.positive_control_change_passed for detail in self.details
            ),
            "mapping_positive_control_changes_total": sum(
                detail.positive_control_change_total for detail in self.details
            ),
        }


@dataclass(frozen=True)
class CounterfactualReport:
    """Structured result suitable for direct inclusion in Gate 4 metrics."""

    scenario_id: str
    family: str
    passed: int
    total: int
    details: tuple[CounterfactualDetail, ...]
    mapping_worlds: tuple[MappingWorldReport, ...] = ()
    source_tree_unchanged: bool = True

    @property
    def ok(self) -> bool:
        return (
            self.total > 0
            and self.passed == self.total
            and self.source_tree_unchanged
            and all(report.ok for report in self.mapping_worlds)
        )

    def mapping_metric_counts(self) -> dict[str, int]:
        """Aggregate the exact exhaustive-world counts carried by this report."""
        counts: dict[str, int] = {}
        for report in self.mapping_worlds:
            for name, value in report.metric_counts().items():
                counts[name] = counts.get(name, 0) + value
        return counts


@dataclass(frozen=True)
class _AmcacheRow:
    sha1: str
    lower_path: str
    name: str
    size: int
    record_key: str


@dataclass(frozen=True)
class _QuarantineRow:
    event_uuid: str
    agent: str
    data_url: str
    origin_url: str
    timestamp: float


def _question_id(question) -> str:
    value = getattr(question, "id", None)
    if not isinstance(value, str) or not value:
        raise ValueError("counterfactual questions require non-empty text ids")
    return value


def _validate_public(public: PublicTask) -> None:
    if not isinstance(public, PublicTask):
        raise TypeError("counterfactual evaluation requires a PublicTask")
    if public.family not in {"windows", "macos"}:
        raise ValueError(f"unsupported counterfactual family: {public.family!r}")
    if not isinstance(public.questions, list) or len(public.questions) != QUESTION_COUNT:
        raise ValueError(
            f"counterfactual evaluation requires exactly {QUESTION_COUNT} questions"
        )
    ids = tuple(_question_id(question) for question in public.questions)
    if len(set(ids)) != QUESTION_COUNT:
        raise ValueError("counterfactual question ids must be unique")
    expected_rule = (
        WINDOWS_AMCACHE_RULE if public.family == "windows" else MACOS_QUARANTINE_RULE
    )
    for question in public.questions:
        rule = getattr(question, "rule", None)
        if rule != expected_rule or RULE_FAMILIES.get(rule) != public.family:
            raise ValueError(
                f"counterfactual question {_question_id(question)!r} has the wrong rule"
            )


def _source_bytes(public: PublicTask) -> dict[str, bytes]:
    with captured_regular_tree(public.directory) as files:
        observed = tuple(file.relative_path for file in files)
        if observed != tuple(public.artifacts):
            raise ValueError("public task inventory differs from its captured artifact tree")
        return {
            file.relative_path: file.data
            for file in files
            if file.data is not None
        }


def _materialize(source: dict[str, bytes], destination: Path) -> None:
    destination.mkdir()
    for relative_path, data in source.items():
        target = destination.joinpath(*relative_path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _temporary_task(public: PublicTask, source: dict[str, bytes], parent: Path) -> PublicTask:
    _materialize(source, parent)
    return replace(public, directory=os.fspath(parent))


def _artifact_relative_path(public: PublicTask, basename: str) -> str:
    matches = [
        relative_path
        for relative_path in public.artifacts
        if relative_path.rsplit("/", 1)[-1] == basename
    ]
    if len(matches) != 1:
        raise ValueError(
            f"counterfactual task requires exactly one artifact named {basename!r}"
        )
    return matches[0]


def _artifact_path(public: PublicTask, basename: str) -> Path:
    relative_path = _artifact_relative_path(public, basename)
    return Path(public.directory).joinpath(*relative_path.split("/"))


def _is_unavailable(message: str) -> bool:
    return bool(
        _AMCACHE_UNAVAILABLE.fullmatch(message)
        or _QUARANTINE_UNAVAILABLE.fullmatch(message)
    )


def _outcomes(public: PublicTask) -> tuple[ObservedOutcome, ...]:
    observed = []
    with captured_regular_tree(public.directory) as files:
        for question in public.questions:
            question_id = _question_id(question)
            try:
                resolution = resolve_question_snapshot(question, files)
            except Exception as exc:  # noqa: BLE001 - an unexpected parser error is evidence
                message = str(exc)
                state = "unavailable" if _is_unavailable(message) else "error"
                observed.append(ObservedOutcome(question_id, state, None, message))
            else:
                observed.append(
                    ObservedOutcome(question_id, "resolved", resolution.value)
                )
    return tuple(observed)


def _expectations(
    baseline: dict[str, str], overrides: dict[str, str | None]
) -> tuple[ExpectedOutcome, ...]:
    return tuple(
        ExpectedOutcome(
            question_id,
            "unavailable" if value is None else "resolved",
            value,
        )
        for question_id, value in (
            (question_id, overrides.get(question_id, baseline[question_id]))
            for question_id in baseline
        )
    )


def _matches(
    expected: tuple[ExpectedOutcome, ...], observed: tuple[ObservedOutcome, ...]
) -> bool:
    if len(expected) != len(observed):
        return False
    return all(
        wanted.question_id == actual.question_id
        and wanted.state == actual.state
        and wanted.value == actual.value
        for wanted, actual in zip(expected, observed, strict=True)
    )


def _case(
    public: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    *,
    mutation: str,
    targets: tuple[str, ...],
    overrides: dict[str, str | None],
    mutate: Callable[[PublicTask], None],
) -> CounterfactualDetail:
    expected = _expectations(baseline, overrides)
    try:
        with tempfile.TemporaryDirectory(
            prefix="artifactforge-counterfactual-case-"
        ) as directory:
            task = _temporary_task(public, source, Path(directory) / "scene")
            mutate(task)
            observed = _outcomes(task)
    except Exception as exc:  # noqa: BLE001 - a failed mutation must redden, not abort, Gate 4
        return CounterfactualDetail(
            mutation,
            targets,
            False,
            expected,
            (),
            f"{type(exc).__name__}: {exc}",
        )
    return CounterfactualDetail(
        mutation,
        targets,
        _matches(expected, observed),
        expected,
        observed,
    )


def _unordered_pairs(question_ids: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Every unordered pair, in deterministic question order."""
    if len(question_ids) != QUESTION_COUNT:
        raise ValueError("pair enumeration requires exactly five question ids")
    if len(set(question_ids)) != QUESTION_COUNT:
        raise ValueError("pair enumeration requires five unique question ids")
    result = tuple(combinations(question_ids, 2))
    if len(result) != PAIR_SWAP_COUNT:
        raise AssertionError("five-question pair enumeration is not complete")
    return result


def _read_amcache(path: Path) -> list[_AmcacheRow]:
    from regipy.registry import RegistryHive

    key = RegistryHive(os.fspath(path)).get_key("\\Root\\InventoryApplicationFile")
    rows = []
    for subkey in key.iter_subkeys():
        values = {value.name: value.value for value in subkey.get_values()}
        file_id = values.get("FileId")
        if not isinstance(file_id, str) or re.fullmatch(r"0000[0-9a-f]{40}", file_id) is None:
            raise ValueError("counterfactual Amcache row has an invalid FileId")
        rows.append(
            _AmcacheRow(
                file_id[4:],
                values["LowerCaseLongPath"],
                values["Name"],
                values["Size"],
                subkey.name,
            )
        )
    if len(rows) != 8:
        raise ValueError(f"counterfactual Amcache profile requires 8 rows, got {len(rows)}")
    return rows


def _write_amcache(path: Path, rows: list[_AmcacheRow]) -> None:
    path.write_bytes(
        build_amcache_hive(
            [
                (row.sha1, row.lower_path, row.name, row.size, row.record_key)
                for row in rows
            ]
        )
    )
    from artifactforge.gates import validity

    reads = {
        "regipy": validity._read_regipy(os.fspath(path)),
        "libregf": validity._read_libregf(os.fspath(path)),
    }
    validity._validate_hive_consensus(os.fspath(path), reads)
    validity._validate_windows_hive_profile(os.fspath(path), reads)


def _amcache_row_index(rows: list[_AmcacheRow], lower_path: str) -> int:
    matches = [index for index, row in enumerate(rows) if row.lower_path == lower_path]
    if len(matches) != 1:
        raise ValueError(f"Amcache selector {lower_path!r} matched {len(matches)} rows")
    return matches[0]


def _windows_selector_by_id(public: PublicTask) -> dict[str, str]:
    return {
        _question_id(question): question.selector["lower_case_long_path"]
        for question in public.questions
    }


def _absent_sha1(public: PublicTask, question_id: str, forbidden: set[str]) -> str:
    for nonce in range(256):
        material = (
            f"artifactforge/bench/v2/counterfactual/absent-sha1/"
            f"{public.scenario_id}/{question_id}/{nonce}"
        ).encode()
        value = hashlib.sha1(material).hexdigest()  # noqa: S324 - forensic identity field
        if value not in forbidden:
            return value
    raise ValueError("could not derive an absent counterfactual SHA1")


def _replacement_pe(
    original: bytes,
    question_id: str,
    forbidden_sha1: set[str],
    forbidden_sha256: set[str],
) -> bytes:
    for nonce in range(256):
        seed = hashlib.sha256(
            b"artifactforge/bench/v2/counterfactual/pe\x00"
            + question_id.encode()
            + nonce.to_bytes(2, "big")
            + original
        ).digest()
        candidate = build_pe_stub(seed)
        if (
            len(candidate) == len(original)
            and candidate != original
            and hashlib.sha1(candidate).hexdigest() not in forbidden_sha1  # noqa: S324
            and hashlib.sha256(candidate).hexdigest() not in forbidden_sha256
        ):
            return candidate
    raise ValueError("could not build a distinct same-size counterfactual PE")


def _validate_pe(path: Path) -> None:
    from artifactforge.gates import validity

    reads = {
        "pefile": validity._read_pefile(os.fspath(path)),
        "lief": validity._read_lief(os.fspath(path)),
    }
    validity._validate_pe_consensus(os.fspath(path), reads)


def _windows_details(
    public: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    resolutions: dict[str, Resolution],
) -> list[CounterfactualDetail]:
    details = []
    selectors = _windows_selector_by_id(public)
    question_ids = tuple(baseline)

    for left, right in _unordered_pairs(question_ids):
        def swap_fileids(task: PublicTask, left: str = left, right: str = right) -> None:
            path = _artifact_path(task, "Amcache.hve")
            rows = _read_amcache(path)
            left_index = _amcache_row_index(rows, selectors[left])
            right_index = _amcache_row_index(rows, selectors[right])
            left_row, right_row = rows[left_index], rows[right_index]
            rows[left_index] = replace(left_row, sha1=right_row.sha1)
            rows[right_index] = replace(right_row, sha1=left_row.sha1)
            _write_amcache(path, rows)

        details.append(
            _case(
                public,
                source,
                baseline,
                mutation="windows-fileid-swap",
                targets=(left, right),
                overrides={left: baseline[right], right: baseline[left]},
                mutate=swap_fileids,
            )
        )

    forbidden_sha1 = {resolution.link_value for resolution in resolutions.values()}
    forbidden_sha256 = set(baseline.values())
    for question_id in question_ids:
        def absent_fileid(task: PublicTask, question_id: str = question_id) -> None:
            path = _artifact_path(task, "Amcache.hve")
            rows = _read_amcache(path)
            index = _amcache_row_index(rows, selectors[question_id])
            rows[index] = replace(
                rows[index],
                sha1=_absent_sha1(task, question_id, {row.sha1 for row in rows}),
            )
            _write_amcache(path, rows)

        details.append(
            _case(
                public,
                source,
                baseline,
                mutation="windows-fileid-absent",
                targets=(question_id,),
                overrides={question_id: None},
                mutate=absent_fileid,
            )
        )

        resident_paths = tuple(
            path
            for path in resolutions[question_id].artifacts
            if path.rsplit("/", 1)[-1] != "Amcache.hve"
        )
        if len(resident_paths) != 1:
            raise ValueError(
                f"{question_id!r} did not resolve through exactly one resident PE"
            )
        resident_path = resident_paths[0]

        def replace_resident(
            task: PublicTask,
            question_id: str = question_id,
            resident_path: str = resident_path,
        ) -> None:
            path = Path(task.directory).joinpath(*resident_path.split("/"))
            original = path.read_bytes()
            candidate = _replacement_pe(
                original,
                question_id,
                forbidden_sha1,
                forbidden_sha256,
            )
            if candidate == original:
                raise ValueError("counterfactual PE replacement was a no-op")
            if len(candidate) != len(original):
                raise ValueError("counterfactual PE replacement changed the resident size")
            path.write_bytes(candidate)
            _validate_pe(path)

        details.append(
            _case(
                public,
                source,
                baseline,
                mutation="windows-resident-pe-replacement",
                targets=(question_id,),
                overrides={question_id: None},
                mutate=replace_resident,
            )
        )
    return details


def _read_quarantine_rows(path: Path) -> list[_QuarantineRow]:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    try:
        rows = con.execute(
            "SELECT LSQuarantineEventIdentifier, LSQuarantineAgentName, "
            "LSQuarantineDataURLString, LSQuarantineOriginURLString, "
            "LSQuarantineTimeStamp FROM LSQuarantineEvent ORDER BY rowid"
        ).fetchall()
    finally:
        con.close()
    if len(rows) != QUESTION_COUNT:
        raise ValueError(
            f"counterfactual QuarantineEventsV2 requires {QUESTION_COUNT} rows"
        )
    return [_QuarantineRow(*row) for row in rows]


def _write_quarantine_rows(path: Path, rows: list[_QuarantineRow]) -> None:
    data = build_quarantine_events(
        [
            (
                row.event_uuid,
                row.agent,
                row.data_url,
                row.origin_url,
                row.timestamp,
            )
            for row in rows
        ]
    )
    path.write_bytes(data)
    from artifactforge.gates import validity

    reads = {
        "sqlite3": validity._read_sqlite3(data),
        "sqlite-raw": validity._read_sqlite_raw(data),
    }
    validity._validate_sqlite_consensus(os.fspath(path), reads)
    validity._validate_sqlite_profile(os.fspath(path), reads)


def _validate_xattr(path: Path) -> None:
    data = path.read_bytes()
    from artifactforge.gates import validity

    reads = {
        "macos-xattr": validity._read_macos_xattr(data),
        "quarantine-xattr-raw": validity._read_quarantine_xattr_raw(data),
    }
    validity._validate_quarantine_xattr_consensus(os.fspath(path), reads)
    validity._validate_quarantine_xattr_profile(os.fspath(path), reads)


def _macos_xattr_by_id(public: PublicTask) -> dict[str, str]:
    return {
        _question_id(question): question.selector["xattr_relative_path"]
        for question in public.questions
    }


def _xattr_path(task: PublicTask, relative_path: str) -> Path:
    return Path(task.directory).joinpath(*relative_path.split("/"))


def _write_xattr_uuid(path: Path, event_uuid: str) -> None:
    original = parse_quarantine_xattr(path.read_bytes())
    data = quarantine_xattr(
        event_uuid,
        original.agent,
        original.timestamp_unix,
        flags=original.flags,
    ).encode("ascii")
    path.write_bytes(data)
    _validate_xattr(path)


def _absent_uuid(public: PublicTask, question_id: str, forbidden: set[str]) -> str:
    for nonce in range(256):
        value = deterministic_uuid(
            f"artifactforge/bench/v2/counterfactual/absent-uuid/"
            f"{public.scenario_id}/{question_id}/{nonce}"
        )
        if value not in forbidden:
            return value
    raise ValueError("could not derive an absent counterfactual UUID")


def _macos_details(
    public: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    resolutions: dict[str, Resolution],
) -> list[CounterfactualDetail]:
    details = []
    xattrs = _macos_xattr_by_id(public)
    question_ids = tuple(baseline)

    for left, right in _unordered_pairs(question_ids):
        def swap_xattrs(task: PublicTask, left: str = left, right: str = right) -> None:
            left_path = _xattr_path(task, xattrs[left])
            right_path = _xattr_path(task, xattrs[right])
            left_uuid = parse_quarantine_xattr(left_path.read_bytes()).event_uuid
            right_uuid = parse_quarantine_xattr(right_path.read_bytes()).event_uuid
            _write_xattr_uuid(left_path, right_uuid)
            _write_xattr_uuid(right_path, left_uuid)

        details.append(
            _case(
                public,
                source,
                baseline,
                mutation="macos-xattr-uuid-swap",
                targets=(left, right),
                overrides={left: baseline[right], right: baseline[left]},
                mutate=swap_xattrs,
            )
        )

        def swap_database_uuids(
            task: PublicTask, left: str = left, right: str = right
        ) -> None:
            path = _artifact_path(task, "QuarantineEventsV2")
            rows = _read_quarantine_rows(path)
            left_uuid = resolutions[left].link_value
            right_uuid = resolutions[right].link_value
            left_matches = [index for index, row in enumerate(rows) if row.event_uuid == left_uuid]
            right_matches = [
                index for index, row in enumerate(rows) if row.event_uuid == right_uuid
            ]
            if len(left_matches) != 1 or len(right_matches) != 1:
                raise ValueError("counterfactual database UUID selectors are not unique")
            left_index, right_index = left_matches[0], right_matches[0]
            rows[left_index] = replace(rows[left_index], event_uuid=right_uuid)
            rows[right_index] = replace(rows[right_index], event_uuid=left_uuid)
            _write_quarantine_rows(path, rows)

        details.append(
            _case(
                public,
                source,
                baseline,
                mutation="macos-database-uuid-swap",
                targets=(left, right),
                overrides={left: baseline[right], right: baseline[left]},
                mutate=swap_database_uuids,
            )
        )

    forbidden = {resolution.link_value for resolution in resolutions.values()}
    for question_id in question_ids:
        def absent_xattr(task: PublicTask, question_id: str = question_id) -> None:
            path = _xattr_path(task, xattrs[question_id])
            _write_xattr_uuid(path, _absent_uuid(task, question_id, forbidden))

        details.append(
            _case(
                public,
                source,
                baseline,
                mutation="macos-xattr-uuid-absent",
                targets=(question_id,),
                overrides={question_id: None},
                mutate=absent_xattr,
            )
        )
    return details


def _mapping_permutations() -> tuple[tuple[int, ...], ...]:
    worlds = tuple(permutations(range(QUESTION_COUNT)))
    if (
        len(worlds) != MAPPING_WORLD_COUNT
        or len(set(worlds)) != MAPPING_WORLD_COUNT
        or worlds[0] != tuple(range(QUESTION_COUNT))
    ):
        raise AssertionError("five-question mapping-world enumeration is not exact")
    return worlds


def _reset_paths(
    task: PublicTask,
    source: dict[str, bytes],
    relative_paths: tuple[str, ...],
) -> None:
    if len(set(relative_paths)) != len(relative_paths):
        raise ValueError("mapping-world reset paths must be unique")
    for relative_path in relative_paths:
        try:
            data = source[relative_path]
        except KeyError as exc:
            raise ValueError(
                f"mapping-world reset path is absent from the source: {relative_path!r}"
            ) from exc
        Path(task.directory).joinpath(*relative_path.split("/")).write_bytes(data)


def _permuted_expectations(
    question_ids: tuple[str, ...],
    baseline: dict[str, str],
    permutation: tuple[int, ...],
) -> tuple[ExpectedOutcome, ...]:
    if tuple(sorted(permutation)) != tuple(range(QUESTION_COUNT)):
        raise ValueError(f"mapping world is not a five-way permutation: {permutation!r}")
    return tuple(
        ExpectedOutcome(question_id, "resolved", baseline[question_ids[source_index]])
        for question_id, source_index in zip(question_ids, permutation, strict=True)
    )


def _outcome_match_count(
    expected: tuple[ExpectedOutcome, ...], observed: tuple[ObservedOutcome, ...]
) -> int:
    return sum(
        wanted.question_id == actual.question_id
        and wanted.state == actual.state
        and wanted.value == actual.value
        for wanted, actual in zip(expected, observed, strict=False)
    )


def _answers_as_outcomes(
    question_ids: tuple[str, ...], answers: Mapping[str, object]
) -> tuple[ObservedOutcome, ...]:
    return tuple(
        ObservedOutcome(
            question_id,
            "resolved" if isinstance(answers.get(question_id), str) else "error",
            answers.get(question_id) if isinstance(answers.get(question_id), str) else None,
            None
            if isinstance(answers.get(question_id), str)
            else "positive control did not return a text answer",
        )
        for question_id in question_ids
    )


def _attack_answers(
    public: PublicTask,
    attacks: tuple[tuple[str, Callable[[PublicTask], object]], ...],
) -> dict[str, dict]:
    observed = {}
    for name, attack in attacks:
        try:
            answers = attack(public)
            if not isinstance(answers, dict):
                raise TypeError(f"registered attack {name!r} returned a non-dict result")
        except Exception as exc:  # noqa: BLE001 - surface the named fail-closed contract
            raise RegisteredAttackExecutionError(name, exc) from exc
        observed[name] = dict(answers)
    return observed


def _windows_positive_control(public: PublicTask) -> dict[str, str]:
    """Resolve FileId-to-resident-byte equality independently of the reference wrapper."""
    rows = _read_amcache(_artifact_path(public, "Amcache.hve"))
    rows_by_path = {row.lower_path: row for row in rows}
    if len(rows_by_path) != len(rows):
        raise ValueError("direct Windows control found duplicate Amcache paths")
    residents: dict[str, str] = {}
    with captured_regular_tree(public.directory) as files:
        for file in files:
            data = file.data
            if data is None:
                raise AssertionError("direct Windows control snapshot contains no bytes")
            if data[:2] != b"MZ":
                continue
            sha1 = hashlib.sha1(data).hexdigest()  # noqa: S324 - forensic identity
            if sha1 in residents:
                raise ValueError("direct Windows control found duplicate resident SHA1")
            residents[sha1] = hashlib.sha256(data).hexdigest()
    if len(residents) != QUESTION_COUNT:
        raise ValueError(
            f"direct Windows control requires five resident PEs, got {len(residents)}"
        )
    answers = {}
    for question in public.questions:
        question_id = _question_id(question)
        selector = question.selector["lower_case_long_path"]
        row = rows_by_path.get(selector)
        if row is None or row.sha1 not in residents:
            raise ValueError(
                f"direct Windows control could not resolve selector {selector!r}"
            )
        answers[question_id] = residents[row.sha1]
    return answers


def _macos_positive_control(public: PublicTask) -> dict[str, str]:
    """Resolve serialized-xattr UUID equality through the quarantine database directly."""
    rows = _read_quarantine_rows(_artifact_path(public, "QuarantineEventsV2"))
    rows_by_uuid = {row.event_uuid: row.data_url for row in rows}
    if len(rows_by_uuid) != QUESTION_COUNT:
        raise ValueError("direct macOS control found duplicate quarantine UUIDs")
    answers = {}
    for question in public.questions:
        question_id = _question_id(question)
        relative_path = question.selector["xattr_relative_path"]
        event_uuid = parse_quarantine_xattr(
            _xattr_path(public, relative_path).read_bytes()
        ).event_uuid
        try:
            answers[question_id] = rows_by_uuid[event_uuid]
        except KeyError as exc:
            raise ValueError(
                f"direct macOS control could not resolve UUID {event_uuid!r}"
            ) from exc
    return answers


def _mapping_world_detail(
    task: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    *,
    question_ids: tuple[str, ...],
    permutation: tuple[int, ...],
    reset_paths: tuple[str, ...],
    parser_artifacts_total: int,
    mutate: Callable[[PublicTask, tuple[int, ...]], None],
    attacks: tuple[tuple[str, Callable[[PublicTask], object]], ...],
    baseline_attacks: dict[str, dict],
    positive_control: Callable[[PublicTask], dict[str, str]],
    baseline_positive_control: dict[str, str],
) -> MappingWorldDetail:
    expected = _permuted_expectations(question_ids, baseline, permutation)
    identity = permutation == tuple(range(QUESTION_COUNT))
    change_total = int(not identity)
    try:
        _reset_paths(task, source, reset_paths)
        mutate(task, permutation)
    except Exception as exc:  # noqa: BLE001 - parser/build failure is contract evidence
        return MappingWorldDetail(
            permutation,
            expected,
            (),
            (),
            0,
            parser_artifacts_total,
            0,
            QUESTION_COUNT,
            0,
            len(attacks),
            0,
            QUESTION_COUNT,
            0,
            change_total,
            error=f"{type(exc).__name__}: {exc}",
        )

    observed = _outcomes(task)
    reference_passed = _outcome_match_count(expected, observed)

    attack_passed = 0
    attack_failures = []
    for name, attack in attacks:
        try:
            answers = attack(task)
            if not isinstance(answers, dict):
                raise TypeError("returned a non-dict result")
            if answers == baseline_attacks[name]:
                attack_passed += 1
            else:
                attack_failures.append(f"{name}: output changed")
        except Exception as exc:  # noqa: BLE001 - attack execution must fail closed
            attack_failures.append(f"{name}: {type(exc).__name__}: {exc}")

    positive_error = None
    try:
        positive_answers = positive_control(task)
        positive_observed = _answers_as_outcomes(question_ids, positive_answers)
        positive_passed = _outcome_match_count(expected, positive_observed)
        positive_change_passed = int(
            not identity and positive_answers != baseline_positive_control
        )
    except Exception as exc:  # noqa: BLE001 - control execution must fail closed
        positive_observed = ()
        positive_passed = 0
        positive_change_passed = 0
        positive_error = f"{type(exc).__name__}: {exc}"

    errors = []
    if positive_error is not None:
        errors.append(f"{MAPPING_POSITIVE_CONTROL}: {positive_error}")
    return MappingWorldDetail(
        permutation,
        expected,
        observed,
        positive_observed,
        parser_artifacts_total,
        parser_artifacts_total,
        reference_passed,
        QUESTION_COUNT,
        attack_passed,
        len(attacks),
        positive_passed,
        QUESTION_COUNT,
        positive_change_passed,
        change_total,
        tuple(attack_failures),
        "; ".join(errors) or None,
    )


def _mapping_report(
    public: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    *,
    relation: str,
    reset_paths: tuple[str, ...],
    mutate: Callable[[PublicTask, tuple[int, ...]], None],
    positive_control: Callable[[PublicTask], dict[str, str]],
    attacks: tuple[tuple[str, Callable[[PublicTask], object]], ...],
) -> MappingWorldReport:
    question_ids = tuple(baseline)
    parser_artifacts_total = MAPPING_PARSER_ARTIFACTS_PER_WORLD[relation]
    with tempfile.TemporaryDirectory(
        prefix="artifactforge-counterfactual-mapping-"
    ) as directory:
        task = _temporary_task(public, source, Path(directory) / "scene")
        baseline_positive_control = positive_control(task)
        if baseline_positive_control != baseline:
            raise ValueError(
                f"{relation} positive-control baseline disagrees with the reference"
            )
        baseline_attacks = _attack_answers(task, attacks)
        details = tuple(
            _mapping_world_detail(
                task,
                source,
                baseline,
                question_ids=question_ids,
                permutation=permutation,
                reset_paths=reset_paths,
                parser_artifacts_total=parser_artifacts_total,
                mutate=mutate,
                attacks=attacks,
                baseline_attacks=baseline_attacks,
                positive_control=positive_control,
                baseline_positive_control=baseline_positive_control,
            )
            for permutation in _mapping_permutations()
        )
    return MappingWorldReport(
        relation,
        MAPPING_POSITIVE_CONTROL,
        tuple(name for name, _attack in attacks),
        details,
    )


def _windows_mapping_report(
    public: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    resolutions: dict[str, Resolution],
    attacks: tuple[tuple[str, Callable[[PublicTask], object]], ...],
) -> MappingWorldReport:
    question_ids = tuple(baseline)
    selectors = _windows_selector_by_id(public)
    link_values = tuple(resolutions[question_id].link_value for question_id in question_ids)
    amcache_relative = _artifact_relative_path(public, "Amcache.hve")

    def mutate(task: PublicTask, permutation: tuple[int, ...]) -> None:
        path = _artifact_path(task, "Amcache.hve")
        rows = _read_amcache(path)
        for target_index, source_index in enumerate(permutation):
            row_index = _amcache_row_index(rows, selectors[question_ids[target_index]])
            rows[row_index] = replace(rows[row_index], sha1=link_values[source_index])
        _write_amcache(path, rows)

    return _mapping_report(
        public,
        source,
        baseline,
        relation=WINDOWS_FILEID_RELATION,
        reset_paths=(amcache_relative,),
        mutate=mutate,
        positive_control=_windows_positive_control,
        attacks=attacks,
    )


def _macos_xattr_mapping_report(
    public: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    resolutions: dict[str, Resolution],
    attacks: tuple[tuple[str, Callable[[PublicTask], object]], ...],
) -> MappingWorldReport:
    question_ids = tuple(baseline)
    xattrs = _macos_xattr_by_id(public)
    relative_paths = tuple(xattrs[question_id] for question_id in question_ids)
    link_values = tuple(resolutions[question_id].link_value for question_id in question_ids)

    def mutate(task: PublicTask, permutation: tuple[int, ...]) -> None:
        for target_index, source_index in enumerate(permutation):
            _write_xattr_uuid(
                _xattr_path(task, relative_paths[target_index]),
                link_values[source_index],
            )

    return _mapping_report(
        public,
        source,
        baseline,
        relation=MACOS_XATTR_UUID_RELATION,
        reset_paths=relative_paths,
        mutate=mutate,
        positive_control=_macos_positive_control,
        attacks=attacks,
    )


def _macos_database_mapping_report(
    public: PublicTask,
    source: dict[str, bytes],
    baseline: dict[str, str],
    resolutions: dict[str, Resolution],
    attacks: tuple[tuple[str, Callable[[PublicTask], object]], ...],
) -> MappingWorldReport:
    question_ids = tuple(baseline)
    link_values = tuple(resolutions[question_id].link_value for question_id in question_ids)
    database_relative = _artifact_relative_path(public, "QuarantineEventsV2")

    def mutate(task: PublicTask, permutation: tuple[int, ...]) -> None:
        path = _artifact_path(task, "QuarantineEventsV2")
        rows = _read_quarantine_rows(path)
        row_by_uuid = {row.event_uuid: index for index, row in enumerate(rows)}
        if len(row_by_uuid) != QUESTION_COUNT:
            raise ValueError("mapping-world database UUID selectors are not unique")
        rewritten = list(rows)
        for question_index, answer_index in enumerate(permutation):
            target_row_index = row_by_uuid[link_values[answer_index]]
            rewritten[target_row_index] = replace(
                rows[target_row_index], event_uuid=link_values[question_index]
            )
        _write_quarantine_rows(path, rewritten)

    return _mapping_report(
        public,
        source,
        baseline,
        relation=MACOS_DATABASE_UUID_RELATION,
        reset_paths=(database_relative,),
        mutate=mutate,
        positive_control=_macos_positive_control,
        attacks=attacks,
    )


def _registered_attacks() -> tuple[tuple[str, Callable[[PublicTask], object]], ...]:
    attacks = tuple(sorted(ADVERSARIES.items()))
    if not attacks or len(attacks) > MAX_RELATION_OMITTING_ATTACKS:
        raise ValueError(
            "mapping-world attack registry must contain 1.."
            f"{MAX_RELATION_OMITTING_ATTACKS} attacks"
        )
    if any(not isinstance(name, str) or not name or not callable(attack) for name, attack in attacks):
        raise TypeError("mapping-world attack registry entries must be named callables")
    return attacks


def evaluate_counterfactuals(
    public: PublicTask, *, include_mapping_worlds: bool = True
) -> CounterfactualReport:
    """Prove every Benchmark-v2 question depends on its declared fields and artifacts.

    The source scene is captured once without following links.  All changes occur in new
    system-temporary copies, and the source task is never modified.
    """
    _validate_public(public)
    source = _source_bytes(public)
    with tempfile.TemporaryDirectory(
        prefix="artifactforge-counterfactual-baseline-"
    ) as directory:
        baseline_task = _temporary_task(public, source, Path(directory) / "scene")
        resolutions = resolve_task(baseline_task)
    baseline = {
        _question_id(question): resolutions[_question_id(question)].value
        for question in public.questions
    }
    if len(set(baseline.values())) != QUESTION_COUNT:
        raise ValueError("counterfactual baseline is not a five-answer bijection")

    if type(include_mapping_worlds) is not bool:
        raise TypeError("include_mapping_worlds must be a bool")

    if public.family == "windows":
        details = _windows_details(public, source, baseline, resolutions)
    else:
        details = _macos_details(public, source, baseline, resolutions)
    if len(details) != LOCAL_CHECKS_PER_FAMILY[public.family]:
        raise AssertionError("counterfactual local-check enumeration is not exact")

    mapping_worlds = []
    if include_mapping_worlds:
        attacks = _registered_attacks()
        if public.family == "windows":
            mapping_worlds.append(
                _windows_mapping_report(public, source, baseline, resolutions, attacks)
            )
        else:
            mapping_worlds.extend(
                (
                    _macos_xattr_mapping_report(
                        public, source, baseline, resolutions, attacks
                    ),
                    _macos_database_mapping_report(
                        public, source, baseline, resolutions, attacks
                    ),
                )
            )
    source_tree_unchanged = _source_bytes(public) == source
    result = tuple(details)
    return CounterfactualReport(
        public.scenario_id,
        public.family,
        sum(detail.passed for detail in result),
        len(result),
        result,
        tuple(mapping_worlds),
        source_tree_unchanged,
    )
