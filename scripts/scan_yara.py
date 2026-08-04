# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Run XProtect or community YARA with explicit control and coverage evidence.

XProtect has a rule-specific positive/negative control: a harmless synthetic input must match
one named rule, while a one-condition near miss must not match that rule.  Community YARA uses
a separate synthetic engine control.  That control proves yara-python can compile and match a
rule; it does *not* prove anything about the community corpus.  Rule-corpus coverage is instead
accounted for by a manifest fingerprint plus selected/loaded/failed file counts.

The functions return scanner-result fragments consumed by ``scanner_attestation.py``.  The
standalone CLI remains useful for inspecting one YARA source, but an independently checkable
multi-scanner claim must be produced and checked through ``scan-exposure.sh``.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import sys
import time
from pathlib import Path

XPROTECT = ("/Library/Apple/System/Library/CoreServices/XProtect.bundle"
            "/Contents/Resources/XProtect.yara")
RULE_MANIFEST_CANONICALIZATION = "artifactforge-yara-rule-manifest-v1"
ENGINE_CONTROL_RULE = "ArtifactForge_YARA_Engine_Control_v1"
ENGINE_CONTROL_BYTES = b"AF\x00ARTIFACTFORGE-YARA-ENGINE-CONTROL-v1\x00"
YARA_WORK_BUDGET = 250_000
YARA_MATCH_TIMEOUT_SECONDS = 10
YARA_MATCH_TOTAL_TIMEOUT_SECONDS = 600
MAX_YARA_ERRORS = 256
MAX_YARA_MATCHES = 20_000
MAX_YARA_MATCHED_RULES = 1_024
MAX_YARA_RULES_LOADED = 100_000
MAX_ERROR_TEXT = 2_048


def _timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(paths: list[Path], root: Path) -> dict:
    files = []
    for path in sorted(paths):
        data = path.read_bytes()
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        files.append({"path": rel, "sha256": _sha256(data), "size": len(data)})
    payload = {
        "canonicalization": RULE_MANIFEST_CANONICALIZATION,
        "files": files,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {
        **payload,
        "file_count": len(files),
        "tree_sha256": _sha256(encoded),
    }


def _rule_metadata(paths: list[Path], root: Path, *, version: str | None = None) -> dict:
    manifest = _manifest(paths, root)
    return {
        "version": version,
        "fingerprint_sha256": manifest["tree_sha256"],
        "manifest": manifest,
    }


def _bounded_text(value: object, limit: int = MAX_ERROR_TEXT) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 32] + "... [bounded output truncated]"


def _append_error(errors: list[dict], where: object, message: object) -> bool:
    """Append one bounded error; return false once evidence collection is exhausted."""
    if len(errors) < MAX_YARA_ERRORS - 1:
        errors.append({
            "where": _bounded_text(where),
            "message": _bounded_text(message),
        })
        return True
    if len(errors) == MAX_YARA_ERRORS - 1:
        errors.append({
            "where": "YARA error collection",
            "message": f"error evidence exceeded the {MAX_YARA_ERRORS}-entry limit",
        })
    return False


def _merge_errors(*groups: list[dict]) -> list[dict]:
    merged: list[dict] = []
    for group in groups:
        for error in group:
            if not _append_error(merged, error.get("where"), error.get("message")):
                return merged
    return merged


def _load(paths: list[Path], externals: dict[str, str]) -> tuple[dict[Path, object], list[dict]]:
    import yara

    compiled: dict[Path, object] = {}
    errors = []
    for path in paths:
        try:
            # Transitive includes would affect compiled semantics without entering the rule
            # manifest. Fail them closed until an include resolver can inventory every byte.
            compiled[path] = yara.compile(
                filepath=str(path), externals=externals, includes=False
            )
        except Exception as exc:  # noqa: BLE001 — unsupported module/syntax is evidence
            if not _append_error(errors, path.name, f"{type(exc).__name__}: {exc}"):
                break
    return compiled, errors


def _loaded_rule_count(compiled: dict[Path, object]) -> tuple[int, dict | None]:
    count = 0
    try:
        for rules in compiled.values():
            for _rule in rules:
                count += 1
                if count > MAX_YARA_RULES_LOADED:
                    return MAX_YARA_RULES_LOADED, {
                        "where": "YARA rule accounting",
                        "message": (
                            "loaded rule count exceeds the explicit "
                            f"{MAX_YARA_RULES_LOADED}-rule limit"
                        ),
                    }
    except Exception as exc:  # noqa: BLE001 - malformed engine object is red evidence
        return count, {
            "where": "YARA rule accounting",
            "message": _bounded_text(f"{type(exc).__name__}: {exc}"),
        }
    return count, None


def _bounded_control_names(rules: object, data: bytes) -> list[str]:
    """Return bounded control matches using the same engine timeout as corpus scans."""
    import yara

    names: list[str] = []
    exhausted = False

    def callback(details: dict) -> int:
        nonlocal exhausted
        if len(names) >= MAX_YARA_MATCHED_RULES:
            exhausted = True
            return yara.CALLBACK_ABORT
        names.append(_bounded_text(details.get("rule", "<unnamed>"), 1_024))
        return yara.CALLBACK_CONTINUE

    rules.match(
        data=data,
        callback=callback,
        which_callbacks=yara.CALLBACK_MATCHES,
        timeout=YARA_MATCH_TIMEOUT_SECONDS,
    )
    if exhausted:
        raise RuntimeError(
            f"control matches exceed the {MAX_YARA_MATCHED_RULES}-rule collection limit"
        )
    return sorted(names)


def _engine_control() -> dict:
    """Exercise yara-python itself, explicitly not the selected community rule corpus."""
    import yara

    source = f'''rule {ENGINE_CONTROL_RULE} {{
        strings:
            $marker = "ARTIFACTFORGE-YARA-ENGINE-CONTROL-v1" ascii
        condition:
            uint16(0) == 0x4641 and $marker
    }}'''
    near = ENGINE_CONTROL_BYTES.replace(b"ENGINE-CONTROL", b"ENGINE-NEAR-MISS")
    try:
        rules = yara.compile(source=source)
        hit_names = _bounded_control_names(rules, ENGINE_CONTROL_BYTES)
        miss_names = _bounded_control_names(rules, near)
    except Exception as exc:  # noqa: BLE001 — returned as attestation evidence
        return {
            "kind": "synthetic-yara-engine-rule-v1",
            "scope": "engine-only",
            "status": "failed",
            "input_sha256": _sha256(ENGINE_CONTROL_BYTES),
            "input_digest_method": "sha256-in-memory-bytes-v1",
            "near_miss_sha256": _sha256(near),
            "expected": f"{ENGINE_CONTROL_RULE} matches only the positive input",
            "observed": _bounded_text(f"{type(exc).__name__}: {exc}"),
            "demonstrates": "nothing; the YARA engine control could not run",
        }
    passed = ENGINE_CONTROL_RULE in hit_names and ENGINE_CONTROL_RULE not in miss_names
    return {
        "kind": "synthetic-yara-engine-rule-v1",
        "scope": "engine-only",
        "status": "passed" if passed else "failed",
        "input_sha256": _sha256(ENGINE_CONTROL_BYTES),
        "input_digest_method": "sha256-in-memory-bytes-v1",
        "near_miss_sha256": _sha256(near),
        "expected": f"{ENGINE_CONTROL_RULE} matches only the positive input",
        "observed": f"positive={hit_names}; near_miss={miss_names}",
        "demonstrates": (
            "yara-python compiled and executed a synthetic rule; selected community rule "
            "coverage is established separately by the bound manifest and compile accounting"
        ),
    }


def _xprotect_control(compiled: dict[Path, object]) -> dict:
    """Exercise one rule from the selected XProtect file, plus a one-condition near miss."""
    target = "XProtect_MACOS_71915a8"
    body = ("#!" + "/bin/zsh\n" + "\\U00000" * 16 + "${" * 101 + "rev)").encode()
    near = body.replace(("${" * 101).encode(), ("${" * 100).encode())
    try:
        hit_names = sorted({
            name for rules in compiled.values() for name in _bounded_control_names(rules, body)
        })
        miss_names = sorted({
            name for rules in compiled.values() for name in _bounded_control_names(rules, near)
        })
        observed = f"positive={hit_names}; near_miss={miss_names}"
    except Exception as exc:  # noqa: BLE001 — returned as attestation evidence
        hit_names, miss_names = [], []
        observed = _bounded_text(f"{type(exc).__name__}: {exc}")
    passed = target in hit_names and target not in miss_names
    return {
        "kind": "xprotect-rule-specific-hit-and-near-miss-v1",
        "scope": "engine-and-selected-rules",
        "status": "passed" if passed else "failed",
        "input_sha256": _sha256(body),
        "input_digest_method": "sha256-in-memory-bytes-v1",
        "near_miss_sha256": _sha256(near),
        "expected": f"{target} matches the positive input and not the near miss",
        "observed": observed,
        "demonstrates": (
            "the YARA engine executed the selected XProtect rule file and the named rule "
            "distinguished its positive input from a one-condition near miss"
        ),
    }


def _scan_corpus(
    compiled: dict[Path, object], corpus_paths: list[Path], corpus_root: Path
) -> tuple[collections.Counter[str], list[dict], int]:
    """Match exact bytes with per-file externals; every rule match remains a finding.

    Rule names are not a trustworthy severity policy. A caller can supply an arbitrary rule
    named ``domain`` or ``keylogger``, so no global name allowlist may turn its match green.
    """
    import yara

    matched: collections.Counter[str] = collections.Counter()
    errors = []
    total_matches = 0
    completed_files = 0
    deadline = time.monotonic() + YARA_MATCH_TOTAL_TIMEOUT_SECONDS
    for path in corpus_paths:
        if time.monotonic() >= deadline:
            _append_error(
                errors,
                "YARA corpus-match runtime",
                "corpus reads/matching exceeded the explicit "
                f"{YARA_MATCH_TOTAL_TIMEOUT_SECONDS}-second deadline",
            )
            return matched, errors, completed_files
        try:
            data = path.read_bytes()
        except Exception as exc:  # noqa: BLE001 - every unread input invalidates coverage
            if not _append_error(
                errors,
                path,
                f"{type(exc).__name__}: {exc}",
            ):
                break
            continue
        if time.monotonic() >= deadline:
            _append_error(
                errors,
                "YARA corpus-match runtime",
                "a corpus read exhausted the explicit "
                f"{YARA_MATCH_TOTAL_TIMEOUT_SECONDS}-second deadline",
            )
            return matched, errors, completed_files
        relative = path.relative_to(corpus_root).as_posix()
        extension = path.suffix.removeprefix(".").lower()
        externals = {
            "filename": path.name,
            "filepath": relative,
            "extension": extension,
            "filetype": extension,
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        }
        file_complete = True
        for rule_path, rules in compiled.items():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _append_error(
                    errors,
                    "YARA corpus-match runtime",
                    "corpus matching exceeded the explicit "
                    f"{YARA_MATCH_TOTAL_TIMEOUT_SECONDS}-second deadline",
                )
                return matched, errors, completed_files
            operation_exhausted = False
            callback_error: str | None = None

            def callback(details: dict) -> int:
                nonlocal operation_exhausted, callback_error, total_matches
                name = details.get("rule")
                if not isinstance(name, str) or not name or len(name) > 1_024:
                    callback_error = "engine returned an invalid or oversized rule identifier"
                    return yara.CALLBACK_ABORT
                if total_matches >= MAX_YARA_MATCHES or (
                    name not in matched and len(matched) >= MAX_YARA_MATCHED_RULES
                ):
                    operation_exhausted = True
                    return yara.CALLBACK_ABORT
                matched[name] += 1
                total_matches += 1
                return yara.CALLBACK_CONTINUE

            try:
                rules.match(
                    data=data,
                    externals=externals,
                    callback=callback,
                    which_callbacks=yara.CALLBACK_MATCHES,
                    timeout=max(
                        1,
                        min(YARA_MATCH_TIMEOUT_SECONDS, math.ceil(remaining)),
                    ),
                )
            except Exception as exc:  # noqa: BLE001 — scan failures invalidate a clean claim
                file_complete = False
                if not _append_error(
                    errors,
                    f"{rule_path.name} -> {relative}",
                    f"{type(exc).__name__}: {exc}",
                ):
                    return matched, errors, completed_files
                continue
            if time.monotonic() >= deadline:
                _append_error(
                    errors,
                    "YARA corpus-match runtime",
                    "one rule-file match exhausted the explicit "
                    f"{YARA_MATCH_TOTAL_TIMEOUT_SECONDS}-second deadline",
                )
                return matched, errors, completed_files
            if callback_error is not None:
                file_complete = False
                if not _append_error(
                    errors,
                    f"{rule_path.name} -> {relative}",
                    callback_error,
                ):
                    return matched, errors, completed_files
            if operation_exhausted:
                _append_error(
                    errors,
                    "YARA match collection",
                    "match evidence exceeds the explicit "
                    f"{MAX_YARA_MATCHES}-match/{MAX_YARA_MATCHED_RULES}-rule limits",
                )
                return matched, errors, completed_files
        if file_complete:
            completed_files += 1
    return matched, errors, completed_files


def _result(
    *,
    scanner_id: str,
    scanner_name: str,
    engine_version: str,
    rules: dict,
    corpus_binding: dict,
    method_command: list[str],
    method_description: str,
    control: dict,
    coverage: dict,
    exclusions: list[dict],
    errors: list[dict],
    matched: collections.Counter[str],
) -> dict:
    control = dict(control)
    control.setdefault("command", method_command)
    status = "error" if errors or control["status"] != "passed" else (
        "finding" if matched else "clean"
    )
    return {
        "scanner": {
            "id": scanner_id,
            "name": scanner_name,
            "engine_version": engine_version,
            "rules": rules,
        },
        "timestamp": _timestamp(),
        "status": status,
        "corpus_binding": corpus_binding,
        "method": {
            "command": method_command,
            "description": method_description,
        },
        "control": control,
        "coverage": coverage,
        "exclusions": exclusions,
        "errors": errors,
        "summary": {
            "files_scanned": coverage["scanned_corpus_files"],
            "matches": sum(matched.values()),
            "matched_rules": dict(sorted(matched.items())),
        },
        "non_proof": {
            "boundary_id": "signature-snapshot-not-safety-proof",
            "statement": (
                "A clean result applies only to these exact bytes, this engine and this bound "
                "rule snapshot. It does not prove safety, inertness, future scanner behavior, "
                "or absence of detection by any other rule set."
            ),
        },
    }


def scan_xprotect(
    corpus: Path,
    corpus_binding: dict,
    *,
    rules_path: Path = Path(XPROTECT),
    method_command: list[str] | None = None,
) -> dict:
    """Return a complete XProtect scanner-result fragment."""
    try:
        import yara

        engine_version = yara.__version__
    except Exception as exc:  # noqa: BLE001 — represented as a failed attestation
        return unavailable_result(
            "xprotect", "Apple XProtect YARA", corpus_binding,
            f"yara-python unavailable: {type(exc).__name__}: {exc}",
            method_command or [sys.executable, "scripts/scan_yara.py", "--xprotect"],
        )
    if not rules_path.is_file():
        return unavailable_result(
            "xprotect", "Apple XProtect YARA", corpus_binding,
            f"selected rule file does not exist: {rules_path}",
            method_command or [sys.executable, "scripts/scan_yara.py", "--xprotect"],
            engine_version=engine_version,
        )
    corpus_paths = sorted(p for p in corpus.rglob("*") if p.is_file() and not p.is_symlink())
    selected_file_work_items = len(corpus_paths)
    load_errors: list[dict] = []
    if len(corpus_paths) != corpus_binding["file_count"]:
        _append_error(
            load_errors,
            "XProtect corpus accounting",
            f"selected {len(corpus_paths)} files; bound manifest has "
            f"{corpus_binding['file_count']}",
        )
    if selected_file_work_items > YARA_WORK_BUDGET:
        _append_error(
            load_errors,
            "XProtect work budget",
            f"{selected_file_work_items} rule-file/file operations exceed the "
            f"{YARA_WORK_BUDGET} limit",
        )
    externals = {"filename": "", "filepath": "", "extension": "", "filetype": "", "md5": ""}
    compiled: dict[Path, object] = {}
    if selected_file_work_items <= YARA_WORK_BUDGET:
        compiled, compile_errors = _load([rules_path], externals)
        for error in compile_errors:
            if not _append_error(load_errors, error["where"], error["message"]):
                break
    rules_loaded, rule_count_error = _loaded_rule_count(compiled)
    if rule_count_error is not None:
        _append_error(load_errors, rule_count_error["where"], rule_count_error["message"])
    match_work_items = rules_loaded * len(corpus_paths)
    if match_work_items > YARA_WORK_BUDGET:
        _append_error(
            load_errors,
            "XProtect rule-evaluation budget",
            f"{match_work_items} loaded-rule/file evaluations exceed the "
            f"{YARA_WORK_BUDGET} limit",
        )
    control = _xprotect_control(compiled) if compiled else {
        "kind": "xprotect-rule-specific-hit-and-near-miss-v1",
        "scope": "engine-and-selected-rules",
        "status": "failed",
        "input_sha256": "0" * 64,
        "input_digest_method": "no-input-control-did-not-run",
        "near_miss_sha256": "0" * 64,
        "expected": "the selected XProtect control rule loads and distinguishes its near miss",
        "observed": "the selected rule file did not compile",
        "demonstrates": "nothing; no selected XProtect rule was loaded",
    }
    if (
        compiled
        and rule_count_error is None
        and selected_file_work_items <= YARA_WORK_BUDGET
        and match_work_items <= YARA_WORK_BUDGET
    ):
        matched, scan_errors, scanned_files = _scan_corpus(compiled, corpus_paths, corpus)
    else:
        matched, scan_errors, scanned_files = collections.Counter(), [], 0
    rules = _rule_metadata([rules_path], rules_path.parent)
    coverage = {
        "kind": "rule-and-file-accounting",
        "selected_rule_files": 1,
        "loaded_rule_files": len(compiled),
        "failed_rule_files": 1 - len(compiled),
        "rules_loaded": rules_loaded,
        "selected_corpus_files": corpus_binding["file_count"],
        "scanned_corpus_files": scanned_files,
        "selected_file_work_items": selected_file_work_items,
        "match_work_items": match_work_items,
        "match_work_budget": YARA_WORK_BUDGET,
        "match_timeout_seconds": YARA_MATCH_TIMEOUT_SECONDS,
        "match_total_timeout_seconds": YARA_MATCH_TOTAL_TIMEOUT_SECONDS,
        "control_scope_note": "the rule-specific control exercises the selected XProtect file",
    }
    return _result(
        scanner_id="xprotect",
        scanner_name="Apple XProtect YARA",
        engine_version=engine_version,
        rules=rules,
        corpus_binding=corpus_binding,
        method_command=method_command or [
            sys.executable, "scripts/scan_yara.py", "--xprotect", "--corpus", str(corpus),
        ],
        method_description="yara-python matched every selected rule against every corpus file",
        control=control,
        coverage=coverage,
        exclusions=[],
        errors=_merge_errors(load_errors, scan_errors),
        matched=matched,
    )


def _community_paths(root: Path) -> tuple[list[Path], list[Path], list[dict]]:
    discovered = sorted({*root.rglob("*.yar"), *root.rglob("*.yara")})
    selected, exclusions = [], []
    for path in discovered:
        rel = path.relative_to(root).as_posix()
        if "deprecated" in path.parts:
            exclusions.append({"path": rel, "reason": "deprecated rule directory"})
        elif path.name.endswith(("_index.yar", "_index.yara")):
            exclusions.append({"path": rel, "reason": "index/include aggregator"})
        else:
            selected.append(path)
    return discovered, selected, exclusions


def scan_community(
    corpus: Path,
    rules_root: Path,
    corpus_binding: dict,
    *,
    method_command: list[str] | None = None,
) -> dict:
    """Return a community-YARA result with engine control and separate rule accounting."""
    try:
        import yara

        engine_version = yara.__version__
    except Exception as exc:  # noqa: BLE001 — represented as a failed attestation
        return unavailable_result(
            "community-yara", "Community YARA", corpus_binding,
            f"yara-python unavailable: {type(exc).__name__}: {exc}",
            method_command or [sys.executable, "scripts/scan_yara.py", "--rules", str(rules_root)],
        )
    if not rules_root.is_dir():
        return unavailable_result(
            "community-yara", "Community YARA", corpus_binding,
            f"rule directory does not exist: {rules_root}",
            method_command or [sys.executable, "scripts/scan_yara.py", "--rules", str(rules_root)],
            engine_version=engine_version,
        )
    discovered, selected, exclusions = _community_paths(rules_root)
    corpus_paths = sorted(p for p in corpus.rglob("*") if p.is_file() and not p.is_symlink())
    selected_file_work_items = len(selected) * len(corpus_paths)
    load_errors: list[dict] = []
    if len(corpus_paths) != corpus_binding["file_count"]:
        _append_error(
            load_errors,
            "community-YARA corpus accounting",
            f"selected {len(corpus_paths)} files; bound manifest has "
            f"{corpus_binding['file_count']}",
        )
    if selected_file_work_items > YARA_WORK_BUDGET:
        _append_error(
            load_errors,
            "community-YARA work budget",
            f"{selected_file_work_items} selected-rule-file/file operations exceed the "
            f"{YARA_WORK_BUDGET} limit",
        )
    externals = {"filename": "", "filepath": "", "extension": "", "filetype": "", "md5": ""}
    compiled: dict[Path, object] = {}
    if selected_file_work_items <= YARA_WORK_BUDGET:
        compiled, compile_errors = _load(selected, externals)
        for error in compile_errors:
            if not _append_error(load_errors, error["where"], error["message"]):
                break
    rules_loaded, rule_count_error = _loaded_rule_count(compiled)
    if rule_count_error is not None:
        _append_error(load_errors, rule_count_error["where"], rule_count_error["message"])
    match_work_items = rules_loaded * len(corpus_paths)
    if match_work_items > YARA_WORK_BUDGET:
        _append_error(
            load_errors,
            "community-YARA rule-evaluation budget",
            f"{match_work_items} loaded-rule/file evaluations exceed the "
            f"{YARA_WORK_BUDGET} limit",
        )
    control = _engine_control()
    if (
        compiled
        and rule_count_error is None
        and selected_file_work_items <= YARA_WORK_BUDGET
        and match_work_items <= YARA_WORK_BUDGET
    ):
        matched, scan_errors, scanned_files = _scan_corpus(compiled, corpus_paths, corpus)
    else:
        matched, scan_errors, scanned_files = collections.Counter(), [], 0
    if not selected:
        _append_error(load_errors, rules_root, "no selected .yar/.yara files")
    rules = (
        _rule_metadata(selected, rules_root)
        if selected
        else {"version": "no-selected-rules", "fingerprint_sha256": None, "manifest": None}
    )
    coverage = {
        "kind": "rule-and-file-accounting",
        "discovered_rule_files": len(discovered),
        "excluded_rule_files": len(exclusions),
        "selected_rule_files": len(selected),
        "loaded_rule_files": len(compiled),
        "failed_rule_files": len(selected) - len(compiled),
        "rules_loaded": rules_loaded,
        "selected_corpus_files": corpus_binding["file_count"],
        "scanned_corpus_files": scanned_files,
        "selected_file_work_items": selected_file_work_items,
        "match_work_items": match_work_items,
        "match_work_budget": YARA_WORK_BUDGET,
        "match_timeout_seconds": YARA_MATCH_TIMEOUT_SECONDS,
        "match_total_timeout_seconds": YARA_MATCH_TOTAL_TIMEOUT_SECONDS,
        "control_scope_note": (
            "the synthetic control exercises only the YARA engine; selected rule coverage is "
            "the manifest fingerprint plus selected/loaded/failed accounting"
        ),
    }
    return _result(
        scanner_id="community-yara",
        scanner_name="Community YARA",
        engine_version=engine_version,
        rules=rules,
        corpus_binding=corpus_binding,
        method_command=method_command or [
            sys.executable, "scripts/scan_yara.py", "--rules", str(rules_root),
            "--corpus", str(corpus),
        ],
        method_description=(
            "each selected rule file was compiled independently and matched against every "
            "corpus file; unsupported files are errors, not silent skips"
        ),
        control=control,
        coverage=coverage,
        exclusions=exclusions,
        errors=_merge_errors(load_errors, scan_errors),
        matched=matched,
    )


def unavailable_result(
    scanner_id: str,
    scanner_name: str,
    corpus_binding: dict,
    message: str,
    method_command: list[str],
    *,
    engine_version: str = "unavailable",
) -> dict:
    """Represent an unavailable scanner without turning it into a green skip."""
    message = _bounded_text(message)
    engine_version = _bounded_text(engine_version, 1_024)
    control_scope = "engine-only" if scanner_id == "community-yara" else (
        "engine-and-selected-rules"
    )
    return {
        "scanner": {
            "id": scanner_id,
            "name": scanner_name,
            "engine_version": engine_version,
            "rules": {
                "version": "unavailable",
                "fingerprint_sha256": None,
                "manifest": None,
            },
        },
        "timestamp": _timestamp(),
        "status": "error",
        "corpus_binding": corpus_binding,
        "method": {"command": method_command, "description": "scanner unavailable"},
        "control": {
            "kind": f"{scanner_id}-required-control",
            "scope": control_scope,
            "status": "failed",
            "command": method_command,
            "input_sha256": "0" * 64,
            "input_digest_method": "no-input-control-did-not-run",
            "expected": "a positive control passes before corpus results are interpreted",
            "observed": message,
            "demonstrates": "nothing; the required control did not run",
        },
        "coverage": {
            "kind": "unavailable",
            "selected_rule_files": 0,
            "loaded_rule_files": 0,
            "failed_rule_files": 1,
            "rules_loaded": 0,
            "selected_corpus_files": corpus_binding["file_count"],
            "scanned_corpus_files": 0,
            "control_scope_note": "no coverage claim is made",
        },
        "exclusions": [],
        "errors": [{"where": scanner_id, "message": message}],
        "summary": {
            "files_scanned": 0,
            "matches": 0,
            "matched_rules": {},
        },
        "non_proof": {
            "boundary_id": "no-result-no-claim",
            "statement": "The scanner did not complete; no clean or safety claim can be made.",
        },
    }


def _print_result(result: dict) -> None:
    scanner = result["scanner"]
    print(f"{scanner['name']} ({scanner['engine_version']}): {result['status']}")
    print(f"  rules fingerprint: {scanner['rules']['fingerprint_sha256']}")
    print(f"  control: {result['control']['status']} ({result['control']['scope']})")
    print(f"  scanned: {result['summary']['files_scanned']} files")
    print(f"  rule matches: {result['summary']['matches']}")
    if result["errors"]:
        for error in result["errors"]:
            print(f"  ERROR {error['where']}: {error['message']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--rules", type=Path, help="directory containing community rules")
    source.add_argument("--xprotect", action="store_true", help="use Apple's XProtect rule file")
    parser.add_argument("--xprotect-path", type=Path, default=Path(XPROTECT),
                        help=argparse.SUPPRESS)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--result-json", type=Path,
                        help="write this scanner-result fragment as canonical JSON")
    args = parser.parse_args()

    # Local import avoids a module cycle when the full attestation runner imports this file.
    import scanner_attestation

    corpus = scanner_attestation.corpus_inventory(args.corpus)
    binding = scanner_attestation.corpus_binding(corpus)
    command = [sys.executable, *sys.argv]
    if args.xprotect:
        result = scan_xprotect(
            args.corpus, binding, rules_path=args.xprotect_path, method_command=command
        )
    else:
        result = scan_community(args.corpus, args.rules, binding, method_command=command)
    _print_result(result)
    if args.result_json:
        args.result_json.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0 if result["status"] == "clean" else 1


if __name__ == "__main__":
    raise SystemExit(main())
