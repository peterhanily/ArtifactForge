# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Parser-valid counterfactual proofs for Benchmark v2's two closed rules.

A resolver returning the right answer does not by itself prove that it used the claimed
fields.  This module copies one public scene into private temporary directories and changes
only the proposed relation.  Pair swaps must swap exactly two answers; an absent link or a
same-size resident-byte replacement must make exactly one answer unavailable.  Every other
answer has to remain byte-for-byte identical to the baseline.

Counterfactual artifacts stay inside the declared profiles.  Amcache and
QuarantineEventsV2 are rebuilt with the production builders, replacement PEs come from the
production inert PE writer, and all four formats are passed through Gate 1's parser-consensus
adapters before their answer effects count.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Callable

from artifactforge.artifacts.hive import build_amcache_hive
from artifactforge.artifacts.macos import (
    build_quarantine_events,
    parse_quarantine_xattr,
    quarantine_xattr,
)
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
class CounterfactualReport:
    """Structured result suitable for direct inclusion in Gate 4 metrics."""

    scenario_id: str
    family: str
    passed: int
    total: int
    details: tuple[CounterfactualDetail, ...]

    @property
    def ok(self) -> bool:
        return self.total > 0 and self.passed == self.total


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


def _artifact_path(public: PublicTask, basename: str) -> Path:
    matches = [
        relative_path
        for relative_path in public.artifacts
        if relative_path.rsplit("/", 1)[-1] == basename
    ]
    if len(matches) != 1:
        raise ValueError(
            f"counterfactual task requires exactly one artifact named {basename!r}"
        )
    return Path(public.directory).joinpath(*matches[0].split("/"))


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


def _covering_pairs(question_ids: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """The minimum pair cover for five values; each case still changes exactly two."""
    if len(question_ids) != QUESTION_COUNT:
        raise ValueError("pair cover requires exactly five question ids")
    return (
        (question_ids[0], question_ids[1]),
        (question_ids[2], question_ids[3]),
        (question_ids[4], question_ids[0]),
    )


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

    regipy_result = validity._read_regipy(os.fspath(path))
    libregf_result = validity._read_libregf(os.fspath(path))
    if regipy_result != libregf_result:
        raise ValueError("regipy and libregf disagree on counterfactual Amcache root")


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

    for left, right in _covering_pairs(question_ids):
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
    validity._validate_macos_sqlite_profile(os.fspath(path), reads)


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

    for left, right in _covering_pairs(question_ids):
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


def evaluate_counterfactuals(public: PublicTask) -> CounterfactualReport:
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

    if public.family == "windows":
        details = _windows_details(public, source, baseline, resolutions)
    else:
        details = _macos_details(public, source, baseline, resolutions)
    result = tuple(details)
    return CounterfactualReport(
        public.scenario_id,
        public.family,
        sum(detail.passed for detail in result),
        len(result),
        result,
    )
