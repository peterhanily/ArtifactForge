# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Benchmark v2's positive control and closed value-agreement rule registry.

The solver sees only a public task. Every Windows question follows one selected historical
Amcache row's FileId SHA1 into resident bytes; every macOS question follows one serialized
quarantine UUID into QuarantineEventsV2. Five scalar questions cover all five answer slots in
each family. ``Resolution`` exposes the independently enumerated candidate universe and actual
artifact dependency trace so Gate 4 never trusts answer-key roles or a declared join count.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import sqlite3

from artifactforge.artifacts.macos import parse_quarantine_xattr
from artifactforge.compose.scene import MACOS_QUARANTINE_RULE, WINDOWS_AMCACHE_RULE
from artifactforge.inventory import InventoryFile, captured_regular_tree


@dataclass(frozen=True)
class Resolution:
    """One independently re-derived public question relation.

    ``candidates`` contains answer-shaped alternatives, not private role labels.  Gate 4 can
    therefore derive its exact chance denominator without consulting scene truth.  Artifact
    paths are relative paths from one immutable captured tree and record the actual dependency
    trace rather than trusting a caller-authored ``joins`` count.
    """

    value: str
    candidates: tuple[str, ...]
    artifacts: tuple[str, ...]
    link_value: str


def _question_field(question, name: str):
    if isinstance(question, Mapping):
        value = question.get(name)
    else:
        value = getattr(question, name, None)
    if value is None:
        raise ValueError(f"public question has no {name!r} field")
    return value


def _named(files: tuple[InventoryFile, ...], name: str) -> InventoryFile:
    """Resolve one artifact by basename while refusing recursive ambiguity."""
    matches = [file for file in files if file.name == name]
    if len(matches) != 1:
        locations = [file.relative_path for file in matches]
        raise ValueError(
            f"expected exactly one artifact named {name!r}, found {len(matches)}: {locations}"
        )
    return matches[0]


def _exact_relative(
    files: tuple[InventoryFile, ...], relative_path: str
) -> InventoryFile:
    matches = [file for file in files if file.relative_path == relative_path]
    if len(matches) != 1:
        locations = [file.relative_path for file in matches]
        raise ValueError(
            f"expected exactly one artifact at {relative_path!r}, "
            f"found {len(matches)}: {locations}"
        )
    return matches[0]


def _query(path: str, sql: str):
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _selector(question, key: str) -> str:
    selector = _question_field(question, "selector")
    if not isinstance(selector, Mapping) or set(selector) != {key}:
        raise ValueError(f"question selector must contain exactly {key!r}")
    value = selector[key]
    if not isinstance(value, str) or not value:
        raise ValueError(f"question selector {key!r} must be a non-empty string")
    return value


def _answer_candidates(values, *, rule: str) -> tuple[str, ...]:
    candidates = tuple(sorted(values))
    if len(candidates) != 5 or len(set(candidates)) != 5:
        raise ValueError(
            f"{rule} requires exactly five distinct answer candidates, got {candidates}"
        )
    return candidates


def _resolve_windows_amcache(
    question, files_snapshot: tuple[InventoryFile, ...]
) -> Resolution:
    from regipy.registry import RegistryHive

    historical_path = _selector(question, "lower_case_long_path")
    if historical_path != historical_path.lower():
        raise ValueError("Amcache LowerCaseLongPath selector must be lowercase")

    amcache = _named(files_snapshot, "Amcache.hve")
    key = RegistryHive(os.fspath(amcache.path)).get_key(
        "\\Root\\InventoryApplicationFile"
    )
    selected = []
    for subkey in key.iter_subkeys():
        values = {value.name: value.value for value in subkey.get_values()}
        if values.get("LowerCaseLongPath") == historical_path:
            selected.append(values)
    if len(selected) != 1:
        raise ValueError(
            f"Amcache selector {historical_path!r} matched {len(selected)} rows"
        )
    file_id = selected[0].get("FileId")
    if not isinstance(file_id, str) or re.fullmatch(r"0000[0-9a-f]{40}", file_id) is None:
        raise ValueError("selected Amcache FileId is not 0000 plus lowercase SHA1")
    link_value = file_id[4:]

    residents = []
    for file in files_snapshot:
        data = file.data
        if data is None:
            raise AssertionError("reference-solver snapshot contains no bytes")
        if data[:2] != b"MZ":
            continue
        residents.append((
            file,
            hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic identity
            hashlib.sha256(data).hexdigest(),
        ))
    candidates = _answer_candidates(
        (sha256 for _file, _sha1, sha256 in residents), rule=WINDOWS_AMCACHE_RULE
    )
    matches = [(file, sha256) for file, sha1, sha256 in residents if sha1 == link_value]
    if len(matches) != 1:
        raise ValueError(
            f"Amcache FileId {file_id!r} matched {len(matches)} resident PE files"
        )
    matched_file, answer = matches[0]
    return Resolution(
        value=answer,
        candidates=candidates,
        artifacts=(amcache.relative_path, matched_file.relative_path),
        link_value=link_value,
    )


def _resolve_macos_quarantine(
    question, files_snapshot: tuple[InventoryFile, ...]
) -> Resolution:
    xattr_relative_path = _selector(question, "xattr_relative_path")
    xattr = _exact_relative(files_snapshot, xattr_relative_path)
    if xattr.data is None:
        raise AssertionError("reference-solver snapshot contains no bytes")
    link_value = parse_quarantine_xattr(xattr.data).event_uuid

    quarantine = _named(files_snapshot, "QuarantineEventsV2")
    rows = _query(
        os.fspath(quarantine.path),
        "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString "
        "FROM LSQuarantineEvent",
    )
    candidates = _answer_candidates((row[1] for row in rows), rule=MACOS_QUARANTINE_RULE)
    matches = [row[1] for row in rows if row[0] == link_value]
    if len(matches) != 1:
        raise ValueError(
            f"quarantine UUID {link_value!r} matched {len(matches)} event rows"
        )
    return Resolution(
        value=matches[0],
        candidates=candidates,
        artifacts=(xattr.relative_path, quarantine.relative_path),
        link_value=link_value,
    )


ALLOWED_RULES = {
    WINDOWS_AMCACHE_RULE: _resolve_windows_amcache,
    MACOS_QUARANTINE_RULE: _resolve_macos_quarantine,
}
RULE_FAMILIES = {
    WINDOWS_AMCACHE_RULE: "windows",
    MACOS_QUARANTINE_RULE: "macos",
}


def resolve_question_snapshot(
    question, files_snapshot: tuple[InventoryFile, ...]
) -> Resolution:
    """Resolve one closed-class question from an already captured immutable tree."""
    rule = _question_field(question, "rule")
    try:
        resolver = ALLOWED_RULES[rule]
    except KeyError as exc:
        raise ValueError(f"unsupported benchmark question rule: {rule!r}") from exc
    return resolver(question, files_snapshot)


def resolve_question(public, question) -> Resolution:
    """Capture a public task once and resolve one question inside that snapshot."""
    family = getattr(public, "family", None)
    if family not in set(RULE_FAMILIES.values()):
        raise ValueError(f"unsupported benchmark family: {family!r}")
    rule = _question_field(question, "rule")
    if RULE_FAMILIES.get(rule) != family:
        raise ValueError(f"benchmark rule {rule!r} is not valid for family {family!r}")
    with captured_regular_tree(public.directory) as files_snapshot:
        return resolve_question_snapshot(question, files_snapshot)


def resolve_task(public) -> dict[str, Resolution]:
    """Resolve every public question through one immutable recursive-tree capture."""
    family = getattr(public, "family", None)
    if family not in set(RULE_FAMILIES.values()):
        raise ValueError(f"unsupported benchmark family: {family!r}")
    questions = getattr(public, "questions", None)
    if not isinstance(questions, list):
        raise ValueError("public task questions must be a list")
    resolved = {}
    with captured_regular_tree(public.directory) as files_snapshot:
        for question in questions:
            question_id = _question_field(question, "id")
            if not isinstance(question_id, str) or not question_id:
                raise ValueError("public question id must be a non-empty string")
            if question_id in resolved:
                raise ValueError(f"duplicate public question id: {question_id!r}")
            rule = _question_field(question, "rule")
            if RULE_FAMILIES.get(rule) != family:
                raise ValueError(
                    f"benchmark rule {rule!r} is not valid for family {family!r}"
                )
            resolved[question_id] = resolve_question_snapshot(question, files_snapshot)
    return resolved


def reference_solve(public) -> dict:
    """Answer a Benchmark-v2 PublicTask without seeing private expected values."""
    return {
        question_id: resolution.value
        for question_id, resolution in resolve_task(public).items()
    }
