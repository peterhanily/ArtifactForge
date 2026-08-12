# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fail-closed scanner attestation tests, using local rules and fake platform tools."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ATTESTATION_SCRIPT = ROOT / "scripts" / "scanner_attestation.py"
YARA_SCRIPT = ROOT / "scripts" / "scan_yara.py"
SCHEMA = ROOT / "scanner-attestation.schema.json"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


attestation = _load("artifactforge_scanner_attestation", ATTESTATION_SCRIPT)
yara_scan = _load("artifactforge_scan_yara", YARA_SCRIPT)


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "a.bin").write_bytes(b"one")
    (root / "b.bin").write_bytes(b"two")
    return root


def _rule_manifest():
    files = [{"path": "fixture.yar", "sha256": "a" * 64, "size": 7}]
    canonicalization = yara_scan.RULE_MANIFEST_CANONICALIZATION
    return {
        "canonicalization": canonicalization,
        "file_count": 1,
        "files": files,
        "tree_sha256": attestation._canonical_digest(canonicalization, files),
    }


def _clam_manifest():
    files = [{"path": "fixture.cvd", "sha256": "b" * 64, "size": 17}]
    canonicalization = "artifactforge-clam-database-manifest-v1"
    return {
        "canonicalization": canonicalization,
        "file_count": 1,
        "total_bytes": 17,
        "files": files,
        "tree_sha256": attestation._canonical_digest(canonicalization, files),
    }


def _result(scanner_id, inventory, timestamp):
    binding = attestation.corpus_binding(inventory)
    scopes = {
        "clamav": "engine-and-selected-rules",
        "community-yara": "engine-only",
        "gatekeeper": "engine-and-host-policy",
        "xprotect": "engine-and-selected-rules",
    }
    rules = {
        "version": "fixture-rules-v1",
        "fingerprint_sha256": None,
        "manifest": None,
    }
    coverage = {
        "kind": "engine-reported-file-count",
        "selected_corpus_files": inventory["file_count"],
        "scanned_corpus_files": inventory["file_count"],
        "control_scope_note": "fixture coverage",
    }
    exclusions = []
    errors = []
    status = "clean"
    if scanner_id == "clamav":
        manifest = _clam_manifest()
        rules = {
            "version": "fixture-rules-v1",
            "fingerprint_sha256": manifest["tree_sha256"],
            "manifest": manifest,
        }
    if scanner_id in {"community-yara", "xprotect"}:
        manifest = _rule_manifest()
        rules = {
            "version": None,
            "fingerprint_sha256": manifest["tree_sha256"],
            "manifest": manifest,
        }
        coverage = {
            "kind": "rule-and-file-accounting",
            "selected_rule_files": 1,
            "loaded_rule_files": 1,
            "failed_rule_files": 0,
            "rules_loaded": 1,
            "selected_file_work_items": inventory["file_count"],
            "match_work_items": inventory["file_count"],
            "match_work_budget": attestation.YARA_WORK_BUDGET,
            "match_timeout_seconds": attestation.YARA_MATCH_TIMEOUT_SECONDS,
            "match_total_timeout_seconds": attestation.YARA_MATCH_TOTAL_TIMEOUT_SECONDS,
            "selected_corpus_files": inventory["file_count"],
            "scanned_corpus_files": inventory["file_count"],
            "control_scope_note": "fixture rule and file accounting",
        }
        if scanner_id == "community-yara":
            coverage.update({
                "discovered_rule_files": 1,
                "excluded_rule_files": 0,
            })
    if scanner_id == "gatekeeper":
        coverage = {
            "kind": "unavailable",
            "selected_corpus_files": inventory["file_count"],
            "scanned_corpus_files": 0,
            "control_scope_note": "no loose-file Gatekeeper claim is made",
        }
        exclusions = [{
            "path": "all loose corpus files",
            "reason": "Gatekeeper requires a top-level app-bundle target/control profile",
        }]
        errors = [{
            "where": "gatekeeper",
            "message": "current loose-file corpus is inapplicable to Gatekeeper",
        }]
        status = "error"
    control_kind = {
        "clamav": "eicar-standard-antivirus-test-file",
        "community-yara": "synthetic-yara-engine-rule-v1",
        "gatekeeper": "gatekeeper-known-platform-binary-acceptance-v1",
        "xprotect": "xprotect-rule-specific-hit-and-near-miss-v1",
    }[scanner_id]
    control_input = {
        "clamav": attestation.EICAR,
        "community-yara": attestation.YARA_ENGINE_CONTROL,
        "xprotect": attestation.XPROTECT_CONTROL,
    }.get(scanner_id, b"fixture Gatekeeper platform control")
    control = {
        "kind": control_kind,
        "scope": scopes[scanner_id],
        "status": "passed",
        "command": ["fixture-control", scanner_id],
        "input_sha256": hashlib.sha256(control_input).hexdigest(),
        "input_digest_method": (
            "sha256-file-bytes"
            if scanner_id in {"clamav", "gatekeeper"}
            else "sha256-in-memory-bytes-v1"
        ),
        "expected": "fixture positive control matches",
        "observed": "fixture positive control matched",
        "demonstrates": "fixture engine and the stated control scope executed",
    }
    if scanner_id == "community-yara":
        control["near_miss_sha256"] = hashlib.sha256(
            attestation.YARA_ENGINE_NEAR_MISS
        ).hexdigest()
    elif scanner_id == "xprotect":
        control["near_miss_sha256"] = hashlib.sha256(
            attestation.XPROTECT_NEAR_MISS
        ).hexdigest()
    if scanner_id == "gatekeeper":
        control["status"] = "failed"
        control["observed"] = "top-level app-bundle control did not run"
        control["demonstrates"] = "nothing; loose-file Gatekeeper checks are inapplicable"
    summary = {
        "files_scanned": coverage["scanned_corpus_files"],
        "matches": 0,
        "matched_rules": {},
    }
    method_command = ["fixture-scanner", scanner_id]
    if scanner_id == "clamav":
        method_command = [
            "fixture-clamscan",
            "--database=/private/fixture-database",
            *attestation.CLAMAV_LIMIT_ARGS,
            "--recursive",
            "--infected",
            "/private/fixture-corpus",
        ]
        control["command"] = [
            *method_command[: 2 + len(attestation.CLAMAV_LIMIT_ARGS)],
            "--infected",
            "--no-summary",
            "/private/eicar.com",
        ]
    elif scanner_id == "gatekeeper":
        control["command"][0] = method_command[0]
    return {
        "scanner": {
            "id": scanner_id,
            "name": f"Fixture {scanner_id}",
            "engine_version": "fixture-engine-v1",
            "rules": rules,
        },
        "timestamp": timestamp,
        "status": status,
        "corpus_binding": binding,
        "method": {
            "command": method_command,
            "description": "fixture method",
        },
        "control": control,
        "coverage": coverage,
        "exclusions": exclusions,
        "errors": errors,
        "summary": summary,
        "non_proof": {
            "boundary_id": "fixture-not-proof",
            "statement": "This fixture is not proof of safety or future non-detection.",
        },
    }


def _record(corpus, now=None):
    now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    timestamp = attestation._timestamp(now)
    inventory = attestation.corpus_inventory(corpus)
    return {
        "schema": attestation.SCHEMA_ID,
        "schema_version": 1,
        "generated_at": timestamp,
        "producer": {
            "name": "fixture producer",
            "version": 1,
            "command": ["fixture-producer", "run"],
            "host": {"platform": "fixture", "python": "fixture"},
        },
        "policy": {
            "required_scanners": list(attestation.REQUIRED_SCANNERS),
            "maximum_age_days": attestation.MAX_AGE_DAYS,
            "success_rule": "all fixture controls and coverage must pass",
        },
        "corpus": inventory,
        "results": [_result(scanner_id, inventory, timestamp)
                    for scanner_id in attestation.REQUIRED_SCANNERS],
        "overall_non_proof": "This fixture is not a safety proof.",
    }


def _by_id(record, scanner_id):
    return next(item for item in record["results"] if item["scanner"]["id"] == scanner_id)


def _claim_unsupported_loose_gatekeeper_success(record):
    gatekeeper = _by_id(record, "gatekeeper")
    target = record["corpus"]["files"][0]
    gatekeeper["status"] = "observation"
    gatekeeper["errors"] = []
    gatekeeper["control"]["status"] = "passed"
    gatekeeper["coverage"] = {
        "kind": "single-selected-macho",
        "selected_corpus_files": record["corpus"]["file_count"],
        "scanned_corpus_files": 1,
        "target": target["path"],
        "target_sha256": target["sha256"],
        "target_signature_command": ["codesign", "--verify", target["path"]],
        "target_signature_valid": True,
        "control_scope_note": "unsupported loose-file claim",
    }
    gatekeeper["summary"] = {
        "files_scanned": 1,
        "matches": 0,
        "matched_rules": {},
        "outcome": "rejected",
    }


def test_schema_accepts_red_evidence_but_success_is_impossible_for_loose_profile(corpus):
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$id"] == attestation.SCHEMA_ID
    record = _record(corpus)
    attestation.validate_record(record, require_success=False)
    with pytest.raises(attestation.AttestationError, match="top-level .app"):
        attestation.validate_record(record)
    attestation.verify_corpus_binding(record, corpus)


def test_schema_validator_refuses_to_silently_ignore_a_future_keyword():
    with pytest.raises(attestation.AttestationError, match="unsupported keyword"):
        attestation._audit_supported_schema({
            "type": "object",
            "unevaluatedProperties": False,
        })


def _add_extra_corpus_manifest_file_claim(record):
    corpus = record["corpus"]
    corpus["files"][0]["unvalidated_claim"] = True
    corpus["tree_sha256"] = attestation._canonical_digest(
        corpus["canonicalization"], corpus["files"]
    )
    binding = attestation.corpus_binding(corpus)
    for result in record["results"]:
        result["corpus_binding"] = binding
    gatekeeper = _by_id(record, "gatekeeper")
    target = next(item for item in corpus["files"] if item["path"] == "a.bin")
    gatekeeper["coverage"]["target_sha256"] = target["sha256"]


def _add_extra_rule_manifest_file_claim(record):
    rules = _by_id(record, "community-yara")["scanner"]["rules"]
    manifest = rules["manifest"]
    manifest["files"][0]["unvalidated_claim"] = True
    manifest["tree_sha256"] = attestation._canonical_digest(
        manifest["canonicalization"], manifest["files"]
    )
    rules["fingerprint_sha256"] = manifest["tree_sha256"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(unvalidated_claim={"safety": "certified"}),
        lambda r: r["producer"].update(unvalidated_claim=True),
        lambda r: r["producer"]["host"].update(unvalidated_claim=True),
        lambda r: r["policy"].update(unvalidated_claim=True),
        lambda r: r["corpus"].update(unvalidated_claim=True),
        _add_extra_corpus_manifest_file_claim,
        lambda r: _by_id(r, "clamav").update(unvalidated_claim=True),
        lambda r: _by_id(r, "clamav")["scanner"].update(unvalidated_claim=True),
        lambda r: _by_id(r, "clamav")["scanner"]["rules"].update(
            unvalidated_claim=True
        ),
        _add_extra_rule_manifest_file_claim,
        lambda r: _by_id(r, "clamav")["method"].update(unvalidated_claim=True),
        lambda r: _by_id(r, "clamav")["control"].update(unvalidated_claim=True),
        lambda r: _by_id(r, "clamav")["coverage"].update(unvalidated_claim=True),
        lambda r: _by_id(r, "gatekeeper")["exclusions"][0].update(
            unvalidated_claim=True
        ),
        lambda r: _by_id(r, "clamav")["summary"].update(unvalidated_claim=True),
        lambda r: _by_id(r, "clamav")["non_proof"].update(unvalidated_claim=True),
    ],
)
def test_declared_schema_rejects_extra_claims_at_every_nested_boundary(corpus, mutate):
    record = _record(corpus)
    mutate(record)
    with pytest.raises(attestation.AttestationError, match="outside|undeclared member"):
        attestation.validate_record(record)


def test_declared_schema_rejects_extra_error_member(corpus):
    record = _record(corpus)
    clamav = _by_id(record, "clamav")
    clamav["status"] = "error"
    clamav["errors"] = [{
        "where": "fixture",
        "message": "fixture error",
        "unvalidated_claim": "safe",
    }]
    with pytest.raises(attestation.AttestationError, match="undeclared member"):
        attestation.validate_record(record, require_success=False)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: r.update(schema_version=2), "declared constant"),
        (lambda r: r["policy"].update(required_scanners=["clamav"]), "declared constant"),
        (lambda r: r["results"].pop(), "too few items"),
        (lambda r: _by_id(r, "clamav")["scanner"].update(engine_version=""), "engine_version"),
        (lambda r: _by_id(r, "clamav")["scanner"]["rules"].update(
            version=None, fingerprint_sha256=None), "neither a rule version nor fingerprint"),
        (lambda r: _by_id(r, "clamav")["corpus_binding"].update(tree_sha256="0" * 64),
         "exact corpus"),
        (lambda r: _by_id(r, "clamav")["method"].update(command=[]), "too few items"),
        (lambda r: _by_id(r, "clamav")["control"].update(status="failed"),
         "disagrees with controls"),
        (lambda r: _by_id(r, "community-yara")["control"].update(
            scope="engine-and-selected-rules"), "control scope"),
        (lambda r: _by_id(r, "clamav")["control"].update(kind="not-eicar"),
         "passing control kind"),
        (lambda r: _by_id(r, "clamav")["control"].update(input_sha256="0" * 64),
         "required vector"),
        (lambda r: _by_id(r, "community-yara")["control"].update(
            near_miss_sha256="0" * 64), "near-miss digest"),
        (lambda r: _by_id(r, "clamav")["summary"].update(
            matched_rules={"Known.Malware": 99}), "per-rule arithmetic"),
        (lambda r: _by_id(r, "community-yara")["coverage"].update(loaded_rule_files=0),
         "load every selected rule"),
        (lambda r: _by_id(r, "xprotect")["scanner"]["rules"]["manifest"].update(
            tree_sha256="0" * 64), "tree SHA256"),
        (_claim_unsupported_loose_gatekeeper_success, "top-level .app"),
        (lambda r: _by_id(r, "clamav").pop("exclusions"), "exclusions"),
        (lambda r: _by_id(r, "clamav").pop("errors"), "errors"),
        (lambda r: _by_id(r, "clamav")["non_proof"].update(statement="Safety proof."),
         "non-proof boundary"),
    ],
)
def test_mutations_fail_closed(corpus, mutate, message):
    record = _record(corpus)
    mutate(record)
    with pytest.raises(attestation.AttestationError, match=message):
        attestation.validate_record(record, require_success=False)


def test_stale_future_and_finding_records_fail_closed(corpus):
    now = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
    stale = _record(corpus, now - dt.timedelta(days=31))
    with pytest.raises(attestation.AttestationError, match="stale"):
        attestation.validate_record(stale, now=now)

    future = _record(corpus, now + dt.timedelta(minutes=6))
    with pytest.raises(attestation.AttestationError, match="future"):
        attestation.validate_record(future, now=now)

    finding = _record(corpus, now)
    clamav = _by_id(finding, "clamav")
    clamav["status"] = "finding"
    clamav["summary"]["matches"] = 1
    clamav["summary"]["matched_rules"] = {"fixture finding": 1}
    with pytest.raises(attestation.AttestationError, match="clean controlled result"):
        attestation.validate_record(finding, now=now)

    non_gate_observation = _record(corpus, now)
    _by_id(non_gate_observation, "xprotect")["status"] = "observation"
    with pytest.raises(attestation.AttestationError, match="disagrees with controls"):
        attestation.validate_record(non_gate_observation, now=now, require_success=False)

    unsupported_gatekeeper = _record(corpus, now)
    _claim_unsupported_loose_gatekeeper_success(unsupported_gatekeeper)
    with pytest.raises(attestation.AttestationError, match="top-level .app"):
        attestation.validate_record(
            unsupported_gatekeeper,
            now=now,
            require_success=False,
        )


def test_live_corpus_binding_detects_added_removed_and_changed_bytes(corpus):
    record = _record(corpus)
    (corpus / "a.bin").write_bytes(b"changed")
    with pytest.raises(attestation.AttestationError, match="live corpus"):
        attestation.verify_corpus_binding(record, corpus)


def test_check_cli_rejects_canonical_red_loose_gatekeeper_record(corpus, tmp_path):
    record = _record(corpus)
    path = tmp_path / "attestation.json"
    attestation.write_record(record, path)
    attestation.validate_record(attestation.read_record(path), require_success=False)
    failed = subprocess.run(
        [sys.executable, str(ATTESTATION_SCRIPT), "check", str(path), "--corpus", str(corpus)],
        capture_output=True,
        text=True,
    )
    assert failed.returncode != 0
    assert "top-level .app" in failed.stderr


def test_check_cli_rejects_canonical_json_with_an_extra_safety_claim(corpus, tmp_path):
    record = _record(corpus)
    record["unvalidated_claim"] = {"safety": "certified"}
    path = tmp_path / "extra-claim.json"
    attestation.write_record(record, path)
    failed = subprocess.run(
        [sys.executable, str(ATTESTATION_SCRIPT), "check", str(path)],
        capture_output=True,
        text=True,
    )
    assert failed.returncode != 0
    assert "additional properties forbidden" in failed.stderr


def test_record_reader_rejects_duplicate_members_nonstandard_numbers_and_symlinks(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema": "first", "schema": "second"}', encoding="utf-8")
    with pytest.raises(attestation.AttestationError, match="duplicate member 'schema'"):
        attestation.read_record(duplicate)

    nonstandard = tmp_path / "nonstandard.json"
    nonstandard.write_text('{"value": NaN}', encoding="utf-8")
    with pytest.raises(attestation.AttestationError, match="non-standard numeric"):
        attestation.read_record(nonstandard)

    link = tmp_path / "record-link.json"
    link.symlink_to(duplicate)
    with pytest.raises(attestation.AttestationError, match="cannot open"):
        attestation.read_record(link)


def test_record_reader_is_bounded(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (attestation.MAX_RECORD_BYTES + 1))
    with pytest.raises(attestation.AttestationError, match="byte limit"):
        attestation.read_record(oversized)


def test_community_yara_separates_engine_control_from_bound_rule_coverage(corpus, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "quiet.yar").write_text(
        'rule quiet { condition: filename == "never.bin" }\n', encoding="utf-8"
    )
    deprecated = rules / "deprecated"
    deprecated.mkdir()
    (deprecated / "ignored.yar").write_text(
        "rule ignored { condition: true }\n", encoding="utf-8"
    )
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(corpus, rules, attestation.corpus_binding(inventory))
    assert result["status"] == "clean"
    assert result["control"]["status"] == "passed"
    assert result["control"]["scope"] == "engine-only"
    assert "separately" in result["control"]["demonstrates"]
    assert result["coverage"]["discovered_rule_files"] == 2
    assert result["coverage"]["selected_rule_files"] == 1
    assert result["coverage"]["loaded_rule_files"] == 1
    assert result["coverage"]["failed_rule_files"] == 0
    assert result["scanner"]["rules"]["manifest"]["file_count"] == 1
    assert result["exclusions"] == [{
        "path": "deprecated/ignored.yar",
        "reason": "deprecated rule directory",
    }]


def test_community_yara_never_whitelists_a_match_by_rule_name(corpus, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "misleading.yar").write_text(
        "rule keylogger { condition: true }\n", encoding="utf-8"
    )
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(corpus, rules, attestation.corpus_binding(inventory))
    assert result["status"] == "finding"
    assert result["summary"] == {
        "files_scanned": 2,
        "matches": 2,
        "matched_rules": {"keylogger": 2},
    }


def test_yara_per_file_externals_are_populated_during_matching(corpus, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    a_md5 = hashlib.md5(b"one", usedforsecurity=False).hexdigest()
    rule = (
        "rule external_match { condition: "
        'filename == "a.bin" and filepath == "a.bin" and extension == "bin" '
        f'and filetype == "bin" and md5 == "{a_md5}" }}\n'
    )
    (rules / "externals.yar").write_text(rule, encoding="utf-8")
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(corpus, rules, attestation.corpus_binding(inventory))
    assert result["status"] == "finding"
    assert result["summary"]["matches"] == 1
    assert result["summary"]["matched_rules"] == {"external_match": 1}


def test_community_yara_compile_error_is_an_error_not_an_exclusion(corpus, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "broken.yar").write_text("this is not yara\n", encoding="utf-8")
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(corpus, rules, attestation.corpus_binding(inventory))
    assert result["status"] == "error"
    assert result["coverage"]["selected_rule_files"] == 1
    assert result["coverage"]["loaded_rule_files"] == 0
    assert result["coverage"]["failed_rule_files"] == 1
    assert result["errors"]


def test_community_yara_transitive_include_cannot_escape_rule_manifest(corpus, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "unmanifested.inc").write_text(
        "rule included_rule { condition: true }\n", encoding="utf-8"
    )
    (rules / "main.yar").write_text(
        'include "unmanifested.inc"\n', encoding="utf-8"
    )
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(corpus, rules, attestation.corpus_binding(inventory))
    assert result["status"] == "error"
    assert result["scanner"]["rules"]["manifest"]["file_count"] == 1
    assert result["coverage"]["loaded_rule_files"] == 0
    assert any("include" in error["message"].lower() for error in result["errors"])


def test_xprotect_rule_specific_control_uses_the_selected_rule_file(corpus, tmp_path):
    rules = tmp_path / "XProtect.yara"
    rules.write_text(
        """rule XProtect_MACOS_71915a8 {
        strings:
            $open = "${" ascii
            $tail = "rev)" ascii
        condition:
            uint16(0) == 0x2123 and #open > 100 and $tail
        }
        """,
        encoding="utf-8",
    )
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_xprotect(
        corpus, attestation.corpus_binding(inventory), rules_path=rules
    )
    assert result["status"] == "clean"
    assert result["control"]["status"] == "passed"
    assert result["control"]["scope"] == "engine-and-selected-rules"
    assert "XProtect_MACOS_71915a8" in result["control"]["observed"]
    assert result["coverage"]["loaded_rule_files"] == 1


def test_build_record_scans_only_descriptor_captured_private_snapshots(
    corpus, tmp_path, monkeypatch
):
    original_corpus = (corpus / "a.bin").read_bytes()
    rules = tmp_path / "rules"
    rules.mkdir()
    community_source = rules / "quiet.yar"
    community_source.write_text(
        'rule quiet { condition: filename == "never.bin" }\n', encoding="utf-8"
    )
    original_community = community_source.read_bytes()
    xprotect_source = tmp_path / "XProtect.yara"
    xprotect_source.write_text(
        "rule XProtect_MACOS_71915a8 { condition: false }\n", encoding="utf-8"
    )
    expected_inventory = attestation.corpus_inventory(corpus)
    seen_paths = []

    def result(scanner_id):
        return _result(scanner_id, expected_inventory, attestation._timestamp())

    def fake_clamav(snapshot, binding, *, executable=None, record_evidence_bytes=0):
        del binding, executable, record_evidence_bytes
        seen_paths.append(Path(snapshot))
        assert Path(snapshot) != corpus
        assert (Path(snapshot) / "a.bin").read_bytes() == original_corpus
        (corpus / "a.bin").write_bytes(b"change-scan-restore attack")
        assert (Path(snapshot) / "a.bin").read_bytes() == original_corpus
        (corpus / "a.bin").write_bytes(original_corpus)
        return result("clamav")

    def fake_xprotect(snapshot, binding, *, rules_path, method_command):
        del binding, method_command
        seen_paths.extend([Path(snapshot), Path(rules_path)])
        assert Path(snapshot) != corpus
        assert Path(rules_path) != xprotect_source
        value = result("xprotect")
        value["scanner"]["rules"] = yara_scan._rule_metadata(
            [Path(rules_path)], Path(rules_path).parent
        )
        return value

    def fake_community(snapshot, rules_root, binding, *, method_command):
        del binding, method_command
        seen_paths.extend([Path(snapshot), Path(rules_root)])
        assert Path(snapshot) != corpus
        assert Path(rules_root) != rules
        captured_rule = Path(rules_root) / "quiet.yar"
        assert captured_rule.read_bytes() == original_community
        community_source.write_bytes(b"rule attacker { condition: true }\n")
        assert captured_rule.read_bytes() == original_community
        community_source.write_bytes(original_community)
        _discovered, selected, _exclusions = yara_scan._community_paths(Path(rules_root))
        value = result("community-yara")
        value["scanner"]["rules"] = yara_scan._rule_metadata(selected, Path(rules_root))
        return value

    def fake_gatekeeper(snapshot, inventory, binding, **kwargs):
        del binding, kwargs
        seen_paths.append(Path(snapshot))
        assert Path(snapshot) != corpus
        assert inventory == expected_inventory
        return result("gatekeeper")

    monkeypatch.setitem(sys.modules, "scan_yara", yara_scan)
    monkeypatch.setattr(attestation, "scan_clamav", fake_clamav)
    monkeypatch.setattr(attestation, "scan_gatekeeper", fake_gatekeeper)
    monkeypatch.setattr(yara_scan, "scan_xprotect", fake_xprotect)
    monkeypatch.setattr(yara_scan, "scan_community", fake_community)

    record = attestation.build_record(
        corpus,
        rules,
        producer_command=["fixture-attestation", "run"],
        xprotect_path=xprotect_source,
    )
    assert record["corpus"] == expected_inventory
    assert (corpus / "a.bin").read_bytes() == original_corpus
    assert community_source.read_bytes() == original_community
    assert seen_paths
    assert all(not path.exists() for path in seen_paths)
    attestation.validate_record(record, require_success=False)


def test_build_record_runtime_yara_reads_the_private_snapshots(corpus, tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "quiet.yar").write_text(
        'rule quiet { condition: filename == "never.bin" }\n', encoding="utf-8"
    )
    xprotect = tmp_path / "XProtect.yara"
    xprotect.write_text(
        """rule XProtect_MACOS_71915a8 {
        strings:
            $open = "${" ascii
            $tail = "rev)" ascii
        condition:
            uint16(0) == 0x2123 and #open > 100 and $tail
        }
        """,
        encoding="utf-8",
    )
    inventory = attestation.corpus_inventory(corpus)

    monkeypatch.setitem(sys.modules, "scan_yara", yara_scan)
    monkeypatch.setattr(
        attestation,
        "scan_clamav",
        lambda snapshot, binding, executable=None, record_evidence_bytes=0: _result(
            "clamav", inventory, attestation._timestamp()
        ),
    )
    monkeypatch.setattr(
        attestation,
        "scan_gatekeeper",
        lambda snapshot, captured_inventory, binding, **kwargs: _result(
            "gatekeeper", inventory, attestation._timestamp()
        ),
    )
    record = attestation.build_record(
        corpus,
        rules,
        producer_command=["fixture-attestation", "runtime-yara"],
        xprotect_path=xprotect,
    )
    by_id = {item["scanner"]["id"]: item for item in record["results"]}
    assert by_id["community-yara"]["status"] == "clean"
    assert by_id["community-yara"]["scanner"]["rules"]["manifest"]["files"] == [{
        "path": "quiet.yar",
        "sha256": hashlib.sha256((rules / "quiet.yar").read_bytes()).hexdigest(),
        "size": (rules / "quiet.yar").stat().st_size,
    }]
    assert by_id["xprotect"]["status"] == "clean"
    attestation.validate_record(record, require_success=False)


def test_descriptor_capture_rejects_symlinks_and_non_regular_entries(corpus, tmp_path):
    (corpus / "link.bin").symlink_to(corpus / "a.bin")
    with pytest.raises(attestation.AttestationError, match="symlink"):
        attestation.corpus_inventory(corpus)

    (corpus / "link.bin").unlink()
    fifo = corpus / "input.pipe"
    try:
        fifo.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(fifo)
    except (AttributeError, NotImplementedError, PermissionError):
        pytest.skip("platform cannot create a FIFO fixture")
    with pytest.raises(attestation.AttestationError, match="non-regular"):
        attestation.corpus_inventory(corpus)


def test_descriptor_capture_is_bounded(corpus, monkeypatch):
    monkeypatch.setattr(attestation, "MAX_TREE_FILE_BYTES", 2)
    with pytest.raises(attestation.AttestationError, match="per-file capture limit"):
        attestation.corpus_inventory(corpus)


def test_descriptor_capture_rejects_change_then_restore_directory_race(
    corpus, monkeypatch, requires_visible_rewrites
):
    original_scandir = os.scandir
    raced = False

    def racing_scandir(path):
        nonlocal raced
        entries = list(original_scandir(path))
        if not raced:
            raced = True
            transient = corpus / "transient.bin"
            transient.write_bytes(b"not allowed to disappear around capture")
            transient.unlink()
        return iter(entries)

    monkeypatch.setattr(attestation.os, "scandir", racing_scandir)
    with pytest.raises(attestation.AttestationError, match="directory changed"):
        attestation.corpus_inventory(corpus)


def test_descriptor_capture_rejects_change_then_restore_file_race(
    corpus, monkeypatch, requires_visible_rewrites
):
    original_read = os.read
    original = (corpus / "a.bin").read_bytes()
    raced = False

    def racing_read(fd, count):
        nonlocal raced
        data = original_read(fd, count)
        if data and not raced:
            raced = True
            (corpus / "a.bin").write_bytes(b"transient replacement")
            (corpus / "a.bin").write_bytes(original)
        return data

    monkeypatch.setattr(attestation.os, "read", racing_read)
    with pytest.raises(attestation.AttestationError, match="changed while its descriptor"):
        attestation.corpus_inventory(corpus)


def test_descriptor_capture_normalizes_second_pass_deletion_race(corpus, monkeypatch):
    original_scandir = os.scandir
    scans = 0

    def delete_after_verification_names_are_captured(path):
        nonlocal scans
        entries = list(original_scandir(path))
        scans += 1
        # Root scan 1 inventories names, scan 2 closes the first-pass directory race window,
        # and scan 3 begins the end-of-tree replay. Delete only after replay has retained the
        # old name so its following descriptor-relative stat sees the disappearance.
        if scans == 3:
            (corpus / "a.bin").unlink()
        return iter(entries)

    monkeypatch.setattr(attestation.os, "scandir", delete_after_verification_names_are_captured)
    with pytest.raises(
        attestation.AttestationError,
        match="cannot revalidate input tree snapshot",
    ) as failure:
        attestation.corpus_inventory(corpus)
    assert isinstance(failure.value.__cause__, FileNotFoundError)


def _write_fake_tool(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _write_fake_clam_database(tmp_path: Path) -> Path:
    database = tmp_path / "clam-db"
    database.mkdir()
    (database / "fixture.cvd").write_bytes(b"fixture signature database")
    _write_fake_tool(
        tmp_path / "clamconf",
        f'print("Database directory: {database}")\n',
    )
    return database


def _write_fake_clam(tmp_path: Path, corpus_body: str, *, control_body: str | None = None) -> Path:
    _write_fake_clam_database(tmp_path)
    control = control_body or 'print("EICAR detection"); raise SystemExit(1)'
    return _write_fake_tool(
        tmp_path / "clamscan",
        f'''import sys
if "--version" in sys.argv:
    print("ClamAV 9.8.7/4242/Fri Aug 1 00:00:00 2026")
    raise SystemExit(0)
if any(arg.endswith("eicar.com") for arg in sys.argv):
    {control}
{corpus_body}
''',
    )


def test_clamav_cannot_claim_clean_without_bound_database_bytes(corpus, tmp_path):
    fake = _write_fake_tool(
        tmp_path / "clamscan",
        """import sys
if "--version" in sys.argv:
    print("ClamAV 9.8.7/4242/Fri Aug 1 00:00:00 2026")
    raise SystemExit(0)
if any(arg.endswith("eicar.com") for arg in sys.argv):
    print("eicar.com: Eicar-Test-Signature FOUND")
    raise SystemExit(1)
print("----------- SCAN SUMMARY -----------")
print("Scanned files: 2")
raise SystemExit(0)
""",
    )
    inventory = attestation.corpus_inventory(corpus)
    result = attestation.scan_clamav(
        corpus, attestation.corpus_binding(inventory), executable=str(fake)
    )
    assert result["status"] == "error"
    assert result["control"]["status"] == "failed"
    assert result["summary"]["files_scanned"] == 0
    assert "usable sibling clamconf is absent" in result["errors"][0]["message"]


def test_clamav_binds_and_selects_descriptor_captured_database_bytes(corpus, tmp_path):
    database = tmp_path / "clam-db"
    database.mkdir()
    signature = database / "fixture.cvd"
    signature.write_bytes(b"fixture signature database")
    original = signature.read_bytes()
    fake = _write_fake_tool(
        tmp_path / "clamscan",
        f'''import pathlib, sys
live = pathlib.Path({str(signature)!r})
database_args = [arg for arg in sys.argv if arg.startswith("--database=")]
assert len(database_args) == 1
snapshot = pathlib.Path(database_args[0].partition("=")[2]) / "fixture.cvd"
assert snapshot.read_bytes() == {original!r}
live.write_bytes(b"change-scan-restore database attack")
assert snapshot.read_bytes() == {original!r}
live.write_bytes({original!r})
if "--version" in sys.argv:
    print("ClamAV 9.8.7/4242/Fri Aug 1 00:00:00 2026")
    raise SystemExit(0)
if any(arg.endswith("eicar.com") for arg in sys.argv):
    print("eicar.com: Eicar-Test-Signature FOUND")
    raise SystemExit(1)
print("Scanned files: 2")
raise SystemExit(0)
''',
    )
    _write_fake_tool(
        tmp_path / "clamconf",
        f'print("Database directory: {database}")\n',
    )
    inventory = attestation.corpus_inventory(corpus)
    result = attestation.scan_clamav(
        corpus, attestation.corpus_binding(inventory), executable=str(fake)
    )
    assert result["status"] == "clean"
    manifest = result["scanner"]["rules"]["manifest"]
    assert manifest["canonicalization"] == "artifactforge-clam-database-manifest-v1"
    assert manifest["files"] == [{
        "path": "fixture.cvd",
        "sha256": hashlib.sha256(original).hexdigest(),
        "size": len(original),
    }]
    assert result["scanner"]["rules"]["fingerprint_sha256"] == manifest["tree_sha256"]
    assert signature.read_bytes() == original
    assert "--database=" in " ".join(result["method"]["command"])
    record = _record(corpus)
    record["results"] = [
        result if item["scanner"]["id"] == "clamav" else item
        for item in record["results"]
    ]
    attestation.validate_record(record, require_success=False)


def test_gatekeeper_loose_macho_profile_is_explicitly_red_and_inapplicable(corpus):
    inventory = attestation.corpus_inventory(corpus)
    result = attestation.scan_gatekeeper(
        corpus,
        inventory,
        attestation.corpus_binding(inventory),
        spctl="unused-spctl",
        codesign="unused-codesign",
    )
    assert result["status"] == "error"
    assert result["control"]["status"] == "failed"
    assert result["coverage"]["scanned_corpus_files"] == 0
    assert "top-level .app" in result["errors"][0]["message"]

def test_unexpected_scanner_timeout_is_serialized_as_red_evidence(corpus):
    inventory = attestation.corpus_inventory(corpus)

    def timeout():
        raise subprocess.TimeoutExpired(["fixture-scanner"], 60)

    result = attestation._guarded_scanner_result(
        "gatekeeper",
        "Apple Gatekeeper",
        attestation.corpus_binding(inventory),
        ["fixture-scanner"],
        "engine-and-host-policy",
        timeout,
    )
    assert result["status"] == "error"
    assert result["control"]["status"] == "failed"
    assert result["coverage"]["scanned_corpus_files"] == 0
    assert "TimeoutExpired" in result["errors"][0]["message"]


def test_clamav_exit_one_without_parseable_findings_is_error(corpus, tmp_path):
    fake = _write_fake_clam(
        tmp_path,
        'print("Scanned files: 2"); raise SystemExit(1)',
        control_body='print("détection EICAR"); raise SystemExit(1)',
    )
    inventory = attestation.corpus_inventory(corpus)
    result = attestation.scan_clamav(
        corpus,
        attestation.corpus_binding(inventory),
        executable=str(fake),
    )
    assert result["control"]["status"] == "passed"
    assert result["status"] == "error"
    assert result["summary"]["matches"] == 0
    assert any("exit 1 reports a detection" in item["message"] for item in result["errors"])


def test_clamav_duplicate_and_oversized_finding_lines_keep_exact_bounded_arithmetic(
    corpus, tmp_path
):
    raw_finding = "x" * 2_000 + ": Fixture.Signature FOUND"
    fake = _write_fake_clam(
        tmp_path,
        f'print({raw_finding!r}); print({raw_finding!r}); '
        'print("Scanned files: 2"); raise SystemExit(1)',
    )
    inventory = attestation.corpus_inventory(corpus)
    result = attestation.scan_clamav(
        corpus,
        attestation.corpus_binding(inventory),
        executable=str(fake),
    )
    assert result["status"] == "finding"
    assert result["summary"]["matches"] == 2
    assert list(result["summary"]["matched_rules"].values()) == [2]
    assert max(map(len, result["summary"]["matched_rules"])) <= 1_024
    record = _record(corpus)
    record["results"] = [
        result if item["scanner"]["id"] == "clamav" else item
        for item in record["results"]
    ]
    attestation.validate_record(record, require_success=False)


def test_clamav_limit_diagnostic_is_error_even_with_exit_zero_and_full_file_count(
    corpus, tmp_path
):
    fake = _write_fake_clam(
        tmp_path,
        'print("WARNING: MaxScanSize limit exceeded; input skipped and assumed clean"); '
        'print("Scanned files: 2"); raise SystemExit(0)',
    )
    inventory = attestation.corpus_inventory(corpus)
    result = attestation.scan_clamav(
        corpus,
        attestation.corpus_binding(inventory),
        executable=str(fake),
    )
    assert result["status"] == "error"
    assert any(item["where"] == "clamav corpus scan limits" for item in result["errors"])


@pytest.mark.parametrize(
    "extra",
    [
        ["--max-filesize=1"],
        ["--alert-exceeds-max=no"],
        ["--exclude=.*"],
    ],
)
def test_clamav_validator_rejects_conflicting_or_filtering_argv(corpus, extra):
    record = _record(corpus)
    command = _by_id(record, "clamav")["method"]["command"]
    command[1:1] = extra
    with pytest.raises(attestation.AttestationError, match="exact bound-database/no-skip"):
        attestation.validate_record(record)


def test_clamav_control_must_share_exact_engine_database_and_limit_prefix(corpus):
    record = _record(corpus)
    control = _by_id(record, "clamav")["control"]["command"]
    control[1] = "--database=/different/unbound-database"
    with pytest.raises(attestation.AttestationError, match="positive control is not coupled"):
        attestation.validate_record(record)


def test_validator_rejects_purported_successful_loose_gatekeeper_observation(corpus):
    record = _record(corpus)
    _claim_unsupported_loose_gatekeeper_success(record)
    with pytest.raises(attestation.AttestationError, match="top-level .app"):
        attestation.validate_record(record, require_success=False)


def test_tree_member_cap_counts_directories_and_excluded_files_before_sorting(tmp_path, monkeypatch):
    root = tmp_path / "rules"
    root.mkdir()
    (root / "excluded.txt").write_bytes(b"not selected")
    (root / "nested").mkdir()
    (root / "nested" / "selected.yar").write_bytes(b"rule quiet { condition: false }")
    monkeypatch.setattr(attestation, "MAX_TREE_MEMBERS", 2)
    with pytest.raises(attestation.AttestationError, match="member traversal limit"):
        attestation._tree_inventory(
            root,
            "fixture-tree-v1",
            include_file=lambda parts: parts[-1].endswith(".yar"),
        )


def test_tree_cumulative_size_is_rejected_before_second_file_read(corpus, monkeypatch):
    calls = []
    original = attestation._read_regular_fd

    def observed(fd, where, before, **kwargs):
        calls.append(where)
        return original(fd, where, before, **kwargs)

    monkeypatch.setattr(attestation, "MAX_TREE_BYTES", 5)
    monkeypatch.setattr(attestation, "_read_regular_fd", observed)
    with pytest.raises(attestation.AttestationError, match="5-byte capture limit"):
        attestation.corpus_inventory(corpus)
    assert calls == ["a.bin"]


def test_tree_depth_limit_applies_to_regular_children_not_only_directories(
    corpus, monkeypatch
):
    nested = corpus / "nested"
    nested.mkdir()
    (nested / "too-deep.bin").write_bytes(b"x")
    monkeypatch.setattr(attestation, "MAX_TREE_DEPTH", 1)
    with pytest.raises(attestation.AttestationError, match="maximum depth of 1"):
        attestation.corpus_inventory(corpus)


def test_tree_end_state_rejects_change_restore_of_an_earlier_file(
    corpus, monkeypatch, requires_visible_rewrites
):
    original_reader = attestation._read_regular_fd
    original_a = (corpus / "a.bin").read_bytes()

    def racing_reader(fd, where, before, **kwargs):
        if where == "b.bin":
            (corpus / "a.bin").write_bytes(b"transient old-A/new-B epoch")
            (corpus / "a.bin").write_bytes(original_a)
        return original_reader(fd, where, before, **kwargs)

    monkeypatch.setattr(attestation, "_read_regular_fd", racing_reader)
    with pytest.raises(attestation.AttestationError, match="snapshot completed"):
        attestation.corpus_inventory(corpus)


@pytest.mark.skipif(os.name != "posix", reason="process-group supervision is POSIX-only")
def test_subprocess_deadline_includes_descendant_held_capture_pipes():
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        attestation._run(
            [
                sys.executable,
                "-c",
                "import subprocess; subprocess.Popen(['/bin/sleep', '2']); print('parent done')",
            ],
            timeout=0.2,
        )
    assert time.monotonic() - started < 1.0


@pytest.mark.skipif(os.name != "posix", reason="process-group supervision is POSIX-only")
def test_subprocess_output_limit_cannot_be_extended_by_descendant_pipe(monkeypatch):
    monkeypatch.setattr(attestation, "MAX_SUBPROCESS_OUTPUT_BYTES", 128)
    started = time.monotonic()
    with pytest.raises(attestation.AttestationError, match="stdout/stderr limit"):
        attestation._run(
            [
                sys.executable,
                "-c",
                "import subprocess,sys; subprocess.Popen(['/bin/sleep','2']); "
                "sys.stdout.write('x'*10000); sys.stdout.flush()",
            ],
            timeout=1,
        )
    assert time.monotonic() - started < 1.0


def test_yara_precompile_selected_file_work_budget_fails_closed(corpus, tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "quiet.yar").write_text("rule quiet { condition: false }", encoding="utf-8")
    monkeypatch.setattr(yara_scan, "YARA_WORK_BUDGET", 1)
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(
        corpus,
        rules,
        attestation.corpus_binding(inventory),
    )
    assert result["status"] == "error"
    assert result["coverage"]["selected_file_work_items"] == 2
    assert result["coverage"]["loaded_rule_files"] == 0
    assert result["coverage"]["scanned_corpus_files"] == 0


def test_yara_postcompile_loaded_rule_work_budget_fails_closed(corpus, tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "two.yar").write_text(
        "rule one { condition: false } rule two { condition: false }",
        encoding="utf-8",
    )
    monkeypatch.setattr(yara_scan, "YARA_WORK_BUDGET", 3)
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(
        corpus,
        rules,
        attestation.corpus_binding(inventory),
    )
    assert result["status"] == "error"
    assert result["coverage"]["selected_file_work_items"] == 2
    assert result["coverage"]["rules_loaded"] == 2
    assert result["coverage"]["match_work_items"] == 4
    assert result["coverage"]["scanned_corpus_files"] == 0


def test_yara_match_timeout_is_passed_and_becomes_bounded_red_evidence(corpus):
    seen = {}

    class TimeoutRules:
        def match(self, **kwargs):
            seen.update(kwargs)
            raise RuntimeError("fixture timeout")

    matched, errors, completed = yara_scan._scan_corpus(
        {Path("fixture.yar"): TimeoutRules()},
        [corpus / "a.bin"],
        corpus,
    )
    assert not matched
    assert completed == 0
    assert errors and "fixture timeout" in errors[0]["message"]
    assert 1 <= seen["timeout"] <= yara_scan.YARA_MATCH_TIMEOUT_SECONDS


def test_yara_match_collection_is_bounded_and_aborts(monkeypatch, corpus):
    import yara

    class ManyRules:
        def match(self, **kwargs):
            for index in range(10):
                outcome = kwargs["callback"]({"rule": f"rule_{index}"})
                if outcome == yara.CALLBACK_ABORT:
                    break
            return []

    monkeypatch.setattr(yara_scan, "MAX_YARA_MATCHES", 2)
    matched, errors, completed = yara_scan._scan_corpus(
        {Path("many.yar"): ManyRules()},
        [corpus / "a.bin"],
        corpus,
    )
    assert sum(matched.values()) == 2
    assert completed == 0
    assert any("match evidence exceeds" in item["message"] for item in errors)


def test_empty_community_rule_tree_produces_serializable_red_evidence(corpus, tmp_path):
    rules = tmp_path / "empty-rules"
    rules.mkdir()
    inventory = attestation.corpus_inventory(corpus)
    result = yara_scan.scan_community(
        corpus,
        rules,
        attestation.corpus_binding(inventory),
    )
    assert result["status"] == "error"
    assert result["scanner"]["rules"] == {
        "version": "no-selected-rules",
        "fingerprint_sha256": None,
        "manifest": None,
    }
    record = _record(corpus)
    record["results"] = [
        result if item["scanner"]["id"] == "community-yara" else item
        for item in record["results"]
    ]
    attestation.validate_record(record, require_success=False)


@pytest.mark.parametrize(
    "bad_path",
    ["a//bin", "a\\..\\evil", "./evil", "a/../evil", "control\x01name"],
)
def test_manifest_paths_require_canonical_portable_relative_grammar(corpus, bad_path):
    inventory = attestation.corpus_inventory(corpus)
    inventory["files"][0]["path"] = bad_path
    inventory["files"].sort(key=lambda item: item["path"])
    inventory["tree_sha256"] = attestation._canonical_digest(
        inventory["canonicalization"], inventory["files"]
    )
    with pytest.raises(attestation.AttestationError, match="non-canonical|unsafe"):
        attestation._validate_manifest(
            inventory,
            "fixture manifest",
            attestation.CORPUS_CANONICALIZATION,
        )


def test_record_writer_rejects_output_parent_swap_and_detached_publication(
    corpus, tmp_path, monkeypatch
):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    output = output_dir / "attestation.json"
    detached = tmp_path / "detached-output"
    original_replace = attestation.os.replace

    def swapping_replace(source, destination, **kwargs):
        original_replace(source, destination, **kwargs)
        output_dir.rename(detached)
        output_dir.mkdir()

    monkeypatch.setattr(attestation.os, "replace", swapping_replace)
    with pytest.raises(attestation.AttestationError, match="output directory changed"):
        attestation.write_record(_record(corpus), output)
    assert not output.exists()
    assert (detached / output.name).is_file()


def test_tree_manifest_metadata_is_bounded_before_scanners_run(tmp_path, monkeypatch):
    root = tmp_path / "corpus"
    root.mkdir()
    for index in range(4):
        (root / ("long-name-" + str(index) + "-" + "x" * 40)).write_bytes(b"")
    monkeypatch.setattr(attestation, "MAX_TREE_MANIFEST_BYTES", 200)
    with pytest.raises(attestation.AttestationError, match="manifest metadata"):
        attestation.corpus_inventory(root)


def test_semantically_valid_record_must_fit_writer_envelope(corpus, monkeypatch):
    record = _record(corpus)
    rendered = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    monkeypatch.setattr(attestation, "MAX_RECORD_BYTES", len(rendered) - 1)
    with pytest.raises(attestation.AttestationError, match="record envelope"):
        attestation.validate_record(record)
