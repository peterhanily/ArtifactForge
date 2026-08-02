# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Registered shortcut attacks against Benchmark v2.

The old footprint and stored-order solvers both reached 100% once their already-selected
subjects were followed through the omitted downstream lookups. V2 has no downstream answer
fan-out: every question is one scalar value-agreement resolution over five candidates.

The complete attacks below answer *every* question after deliberately selecting candidates
without the declared FileId/SHA-1 or quarantine-UUID relation. An omitted answer can no longer
make a broken attack look reassuringly weak. ``blind`` and ``parent_escape`` are separate trust-
boundary controls: the former must reconstruct public-keyed suites, while the latter must be
able to steal a co-located evaluator key and unable to find one in a public export.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from artifactforge.inventory import (
    InventoryError,
    InventoryFile,
    captured_regular_tree,
    list_regular_file_paths,
)


SUPPORTED_FAMILIES = frozenset(("windows", "macos"))
COMPLETE_ADVERSARIES = frozenset(
    (
        "alternate_link",
        "footprint",
        "lexical",
        "metadata",
        "mechanical",
        "pool",
        "scalar",
        "selector",
    )
)


def _require_supported_family(public) -> str:
    family = getattr(public, "family", None)
    if family not in SUPPORTED_FAMILIES:
        raise ValueError(f"unsupported benchmark family: {family!r}")
    return family


def _by_basename(files: tuple[InventoryFile, ...]) -> dict[str, InventoryFile]:
    indexed: dict[str, InventoryFile] = {}
    ambiguous: set[str] = set()
    for file in files:
        if file.name in indexed or file.name in ambiguous:
            indexed.pop(file.name, None)
            ambiguous.add(file.name)
        else:
            indexed[file.name] = file
    return indexed


def _sqlite_fetchall(path: Path, sql: str, parameters: tuple = ()) -> list[tuple]:
    import sqlite3

    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        return connection.execute(sql, parameters).fetchall()
    finally:
        connection.close()


def _data(file: InventoryFile) -> bytes:
    if file.data is None:
        raise AssertionError("adversary snapshot contains no bytes")
    return file.data


def _windows_candidates(files: tuple[InventoryFile, ...]) -> list[tuple[InventoryFile, str]]:
    return [
        (file, hashlib.sha256(_data(file)).hexdigest())
        for file in files
        if _data(file)[:2] == b"MZ"
    ]


def _macos_urls(files: tuple[InventoryFile, ...]) -> list[str]:
    quarantine = _by_basename(files).get("QuarantineEventsV2")
    if quarantine is None:
        return []
    return [
        row[0]
        for row in _sqlite_fetchall(
            quarantine.path,
            "SELECT LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY rowid",
        )
    ]


def _selector_text(question) -> str:
    return json.dumps(
        question.selector,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _pair_ranked(public, candidates: list[str], *, question_key=None) -> dict:
    """Pair independently observable question and candidate ranks without using the join."""
    if len(candidates) != len(public.questions):
        return {}
    key = question_key or (lambda question: _selector_text(question))
    ranked_questions = sorted(public.questions, key=key)
    return {
        question.id: answer
        for question, answer in zip(ranked_questions, candidates, strict=True)
    }


def lexical_solve(public) -> dict:
    """Pair lexically ranked selectors and candidates, ignoring their declared relation."""
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            if family == "windows":
                candidates = sorted(value for _file, value in _windows_candidates(files))
            else:
                candidates = sorted(_macos_urls(files))
            return _pair_ranked(public, candidates)
    except (InventoryError, OSError, ValueError):
        return {}


def footprint_solve(public) -> dict:
    """Choose the candidate with the largest raw cross-file mention footprint.

    It never reads the declared link value. For Windows it ranks PE filenames by ASCII and
    UTF-16 occurrence in other files. For macOS it ranks candidate URL byte strings. The v2
    scene should make either ranking no better than choosing one candidate for all five
    bijective questions.
    """
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            blobs = {file.relative_path: _data(file) for file in files}
            if family == "windows":
                candidates = _windows_candidates(files)

                def score(item):
                    file, _answer = item
                    name = file.name
                    patterns = (
                        name.encode(),
                        name.lower().encode(),
                        name.upper().encode(),
                        name.encode("utf-16-le"),
                        name.upper().encode("utf-16-le"),
                    )
                    return sum(
                        1
                        for relative, data in blobs.items()
                        if relative != file.relative_path and any(p in data for p in patterns)
                    )

                ranked = [
                    answer
                    for _file, answer in sorted(
                        candidates, key=lambda item: (-score(item), item[1])
                    )
                ]

                def question_key(question):
                    selector = _selector_text(question)
                    patterns = (selector.encode(), selector.encode("utf-16-le"))
                    incidence = sum(any(pattern in data for pattern in patterns) for data in blobs.values())
                    return -incidence, selector
            else:
                candidates = _macos_urls(files)

                def score_url(url: str) -> tuple[int, str]:
                    raw = url.encode()
                    return -sum(raw in data for data in blobs.values()), url

                ranked = sorted(candidates, key=score_url)

                def question_key(question):
                    relative = question.selector.get("xattr_relative_path", "")
                    bundle = relative.rsplit("/", 1)[-1].removesuffix(".quarantine.xattr")
                    raw = bundle.encode()
                    incidence = sum(raw in data for data in blobs.values())
                    return -incidence, relative
            return _pair_ranked(public, ranked, question_key=question_key)
    except (InventoryError, OSError, ValueError):
        return {}


def mechanical_solve(public) -> dict:
    """Pair public question order with stored candidate order, ignoring value agreement."""
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            if family == "windows":
                candidates = [value for _file, value in _windows_candidates(files)]
            else:
                candidates = _macos_urls(files)
            if not candidates:
                return {}
            return {
                question.id: candidates[index % len(candidates)]
                for index, question in enumerate(public.questions)
            }
    except (InventoryError, OSError, ValueError):
        return {}


def pool_solve(public) -> dict:
    """Rank selectors and candidates by source-known name categories, then pair them."""
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            if family == "windows":
                from artifactforge import pools

                candidates = _windows_candidates(files)
                ranked = [
                    answer
                    for file, answer in sorted(
                        candidates,
                        key=lambda item: (
                            item[0].name not in pools.MALWARE_NAMES,
                            item[0].name not in pools.BENIGN_NAMES,
                            item[0].name,
                            item[1],
                        ),
                    )
                ]

                def question_key(question):
                    selector = _selector_text(question).lower()
                    return (
                        not any(name.lower() in selector for name in pools.MALWARE_NAMES),
                        not any(name.lower() in selector for name in pools.BENIGN_NAMES),
                        selector,
                    )
            else:
                from artifactforge import pools

                urls = _macos_urls(files)
                ranked = sorted(
                    urls,
                    key=lambda url: (
                        not any(bundle in url for bundle in pools.BUNDLES),
                        not any(bundle in url for bundle in pools.BENIGN_BUNDLES),
                        url,
                    ),
                )

                def question_key(question):
                    selector = _selector_text(question)
                    return (
                        not any(bundle in selector for bundle in pools.BUNDLES),
                        not any(bundle in selector for bundle in pools.BENIGN_BUNDLES),
                        selector,
                    )
            return _pair_ranked(public, ranked, question_key=question_key)
    except (InventoryError, OSError, ValueError):
        return {}


def scalar_solve(public) -> dict:
    """Try Size or agent/timestamp equality instead of the declared high-entropy relation."""
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            named = _by_basename(files)
            answers: dict[str, str] = {}
            if family == "windows":
                from regipy.registry import RegistryHive

                amcache = named.get("Amcache.hve")
                if amcache is None:
                    return {}
                key = RegistryHive(os.fspath(amcache.path)).get_key(
                    "\\Root\\InventoryApplicationFile"
                )
                rows = {}
                for subkey in key.iter_subkeys():
                    values = {value.name: value.value for value in subkey.get_values()}
                    rows[values.get("LowerCaseLongPath")] = values
                candidates = _windows_candidates(files)
                for question in public.questions:
                    selector = question.selector.get("lower_case_long_path")
                    size = rows.get(selector, {}).get("Size")
                    matches = sorted(
                        answer for file, answer in candidates if len(_data(file)) == size
                    )
                    if matches:
                        answers[question.id] = matches[0]
            else:
                quarantine = named.get("QuarantineEventsV2")
                if quarantine is None:
                    return {}
                rows = _sqlite_fetchall(
                    quarantine.path,
                    "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, "
                    "LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY rowid",
                )
                for question in public.questions:
                    relative = question.selector.get("xattr_relative_path")
                    sidecar = next((file for file in files if file.relative_path == relative), None)
                    if sidecar is None:
                        continue
                    fields = _data(sidecar).decode("ascii").strip().split(";")
                    if len(fields) != 4:
                        continue
                    timestamp = int(fields[1], 16)
                    agent = fields[2]
                    matches = sorted(
                        url
                        for mac_time, row_agent, url in rows
                        if row_agent == agent and int(mac_time) + 978307200 == timestamp
                    )
                    if matches:
                        answers[question.id] = matches[0]
            return answers
    except (InventoryError, OSError, ValueError):
        return {}


def alternate_link_solve(public) -> dict:
    """Try the Amcache subkey name as a hash prefix instead of reading ``FileId``.

    Benchmark v1 accidentally encoded ``sha1[:8]`` there and this attack scored 100% on all
    Windows questions.  V2 record keys are independent.  macOS has no equivalent alternate
    identifier, so the control pairs independent lexical ranks there.
    """
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            if family == "macos":
                return _pair_ranked(public, sorted(_macos_urls(files)))
            from regipy.registry import RegistryHive

            named = _by_basename(files)
            amcache = named.get("Amcache.hve")
            if amcache is None:
                return {}
            key = RegistryHive(os.fspath(amcache.path)).get_key(
                "\\Root\\InventoryApplicationFile"
            )
            rows = {}
            for subkey in key.iter_subkeys():
                values = {value.name: value.value for value in subkey.get_values()}
                rows[values.get("LowerCaseLongPath")] = subkey.name.removeprefix("0000")
            candidates = [
                (hashlib.sha1(_data(file)).hexdigest(), answer)  # noqa: S324 - identity
                for file, answer in _windows_candidates(files)
            ]
            fallback = sorted(answer for _sha1, answer in candidates)
            answers = {}
            for index, question in enumerate(public.questions):
                token = rows.get(question.selector.get("lower_case_long_path"), "")
                matches = sorted(answer for sha1, answer in candidates if token and sha1.startswith(token))
                answers[question.id] = matches[0] if len(matches) == 1 else fallback[index]
            return answers
    except (InventoryError, OSError, ValueError):
        return {}


def selector_solve(public) -> dict:
    """Exploit candidate names copied into selected row fields, paths, or URLs."""
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            if family == "windows":
                from regipy.registry import RegistryHive

                named = _by_basename(files)
                amcache = named.get("Amcache.hve")
                if amcache is None:
                    return {}
                key = RegistryHive(os.fspath(amcache.path)).get_key(
                    "\\Root\\InventoryApplicationFile"
                )
                rows = {}
                for subkey in key.iter_subkeys():
                    values = {value.name: value.value for value in subkey.get_values()}
                    rows[values.get("LowerCaseLongPath")] = values
                candidates = _windows_candidates(files)
                fallback = sorted(answer for _file, answer in candidates)
                answers = {}
                for index, question in enumerate(public.questions):
                    row = rows.get(question.selector.get("lower_case_long_path"), {})
                    text = " ".join(str(row.get(field, "")) for field in ("Name", "LowerCaseLongPath")).lower()
                    matches = sorted(
                        answer for file, answer in candidates if file.name.lower() in text
                    )
                    answers[question.id] = matches[0] if len(matches) == 1 else fallback[index]
                return answers

            urls = _macos_urls(files)
            fallback = sorted(urls)
            answers = {}
            for index, question in enumerate(public.questions):
                relative = question.selector.get("xattr_relative_path", "")
                bundle = relative.rsplit("/", 1)[-1].removesuffix(".quarantine.xattr")
                matches = sorted(url for url in urls if bundle and bundle in url)
                answers[question.id] = matches[0] if len(matches) == 1 else fallback[index]
            return answers
    except (InventoryError, OSError, ValueError):
        return {}


def metadata_solve(public) -> dict:
    """Scan allowed question strings for answer values or candidate-identifying names."""
    family = _require_supported_family(public)
    try:
        with captured_regular_tree(public.directory) as files:
            if family == "windows":
                candidates = _windows_candidates(files)
                ranked = sorted(answer for _file, answer in candidates)
            else:
                candidates = [(None, url) for url in _macos_urls(files)]
                ranked = sorted(answer for _file, answer in candidates)
            if len(ranked) != len(public.questions):
                return {}
            fallback = _pair_ranked(public, ranked)
            answers = {}
            for question in public.questions:
                local = json.dumps(
                    {
                        "id": question.id,
                        "kind": question.kind,
                        "prompt": question.prompt,
                        "rule": question.rule,
                        "selector": question.selector,
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).lower()
                matches = []
                for file, answer in candidates:
                    tokens = [answer.lower()]
                    if file is not None:
                        tokens.extend((file.name.lower(), file.name.rsplit(".", 1)[0].lower()))
                    if any(token and token in local for token in tokens):
                        matches.append(answer)
                answers[question.id] = matches[0] if len(set(matches)) == 1 else fallback[question.id]
            return answers
    except (InventoryError, OSError, ValueError):
        return {}


def blind_solve(public) -> dict:
    """Regenerate a public-keyed scene without reading the target artifact directory."""
    family = _require_supported_family(public)
    from artifactforge import suite

    # ``suite_kind`` is attacker-controlled public metadata, not evidence that a suite key is
    # secret.  Recover the scenario's position from the public manifest and test every known
    # public key against the HMAC-derived id.  In particular, relabelling the reproducible
    # scorecard corpus as ``holdout`` must not make this control report a reassuring zero.
    try:
        public_path = Path(public.directory).parent.parent / "public.json"
        document = json.loads(public_path.read_text(encoding="utf-8"))
        scenarios = document.get("scenarios")
        if not isinstance(scenarios, list):
            return {}
        indices = [
            index
            for index, entry in enumerate(scenarios)
            if isinstance(entry, dict) and entry.get("scenario_id") == public.scenario_id
        ]
        if len(indices) != 1:
            return {}
        index = indices[0]
    except (OSError, ValueError, json.JSONDecodeError):
        return {}

    key = next(
        (
            candidate
            for candidate in (
                suite.PUBLIC_DEV_KEY,
                suite.scorecard_measurement_key(),
            )
            if suite.public_id(candidate, index) == public.scenario_id
        ),
        None,
    )
    if key is None:
        return {}

    from artifactforge.bench.benchmark import _macos_questions, _profile, _windows_questions
    from artifactforge.compose.scene import build_macos_scene, build_windows_scene
    from artifactforge.content import ContentStore

    skey = suite.scenario_key(key, public.scenario_id)
    with tempfile.TemporaryDirectory(prefix="artifactforge-blind-") as directory:
        root = Path(directory)
        store = ContentStore(suite.WINDOWS_MACOS_CONTENT_NAMESPACE, os.fspath(root / "content"))
        arguments = {
            "store": store,
            "skey": skey,
            "profile": _profile(skey, family),
            "scene_dir": os.fspath(root / "scene"),
            "staging_dir": os.fspath(root / "staging"),
        }
        if family == "windows":
            scene = build_windows_scene(**arguments)
            questions = _windows_questions(scene.join)
        else:
            scene = build_macos_scene(**arguments)
            questions = _macos_questions(scene.join)
        return {question.id: question.expected for question in questions}


def parent_escape_solve(public) -> dict:
    """Read the legacy co-located evaluator answer through ``../../_answers``.

    This is a positive control, not a hypothetical attacker: it must score 100% on an
    evaluator root and find nothing in an exact public export.
    """
    _require_supported_family(public)
    try:
        root = Path(public.directory).parents[1]
        path = root / "_answers" / f"{public.scenario_id}.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        answers = value.get("answers")
        return answers if isinstance(answers, dict) else {}
    except (IndexError, OSError, ValueError, json.JSONDecodeError):
        return {}


def listing_solve(public) -> dict:
    """Read only recursive filenames; neither v2 answer is present in one."""
    _require_supported_family(public)
    try:
        list_regular_file_paths(public.directory)
    except InventoryError:
        pass
    return {}


def null_solve(public) -> dict:
    _require_supported_family(public)
    return {}


def constant_solve(public) -> dict:
    _require_supported_family(public)
    return {
        question.id: ("0" * 64 if question.kind == "hash" else "https://unknown.invalid/")
        for question in public.questions
    }


# Complete selection attacks are checked by family/rule, must cover every question, and are
# judged with Gate 4's exact within-scene permutation distribution rather than a magic cutoff.
ADVERSARIES = {
    "alternate_link": alternate_link_solve,
    "footprint": footprint_solve,
    "mechanical": mechanical_solve,
    "metadata": metadata_solve,
    "pool": pool_solve,
    "scalar": scalar_solve,
    "selector": selector_solve,
    "lexical": lexical_solve,
    "listing": listing_solve,
    "null": null_solve,
    "constant": constant_solve,
}
