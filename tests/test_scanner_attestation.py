# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fail-closed scanner attestation tests, using local rules and fake platform tools."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
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
    status = "clean"
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
        target = inventory["files"][0]
        coverage = {
            "kind": "single-selected-macho",
            "selected_corpus_files": inventory["file_count"],
            "scanned_corpus_files": 1,
            "target": target["path"],
            "target_sha256": target["sha256"],
            "target_signature_command": ["codesign", "-v", target["path"]],
            "target_signature_valid": True,
            "control_scope_note": "fixture host-policy control",
        }
        exclusions = [{"path": "other files", "reason": "single-target observation"}]
        status = "observation"
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
    summary = {
        "files_scanned": coverage["scanned_corpus_files"],
        "matches": 0,
        "matched_rules": {},
    }
    if scanner_id == "gatekeeper":
        summary["outcome"] = "rejected"
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
            "command": ["fixture-scanner", scanner_id],
            "description": "fixture method",
        },
        "control": control,
        "coverage": coverage,
        "exclusions": exclusions,
        "errors": [],
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


def test_schema_and_valid_controlled_fixture(corpus):
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$id"] == attestation.SCHEMA_ID
    record = _record(corpus)
    attestation.validate_record(record)
    attestation.verify_corpus_binding(record, corpus)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: r.update(schema_version=2), "incompatible"),
        (lambda r: r["policy"].update(required_scanners=["clamav"]), "required-scanner"),
        (lambda r: r["results"].pop(), "missing required"),
        (lambda r: _by_id(r, "clamav")["scanner"].update(engine_version=""), "engine_version"),
        (lambda r: _by_id(r, "clamav")["scanner"]["rules"].update(
            version=None, fingerprint_sha256=None), "neither a rule version nor fingerprint"),
        (lambda r: _by_id(r, "clamav")["corpus_binding"].update(tree_sha256="0" * 64),
         "exact corpus"),
        (lambda r: _by_id(r, "clamav")["method"].update(command=[]), "exact non-empty argv"),
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
        (lambda r: _by_id(r, "gatekeeper")["coverage"].update(target_sha256="0" * 64),
         "target is not bound"),
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
        attestation.validate_record(record)


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
        attestation.validate_record(non_gate_observation, now=now)

    ambiguous_gatekeeper = _record(corpus, now)
    _by_id(ambiguous_gatekeeper, "gatekeeper")["summary"]["outcome"] = (
        "not-explicitly-rejected"
    )
    with pytest.raises(attestation.AttestationError, match="explicit controlled rejection"):
        attestation.validate_record(ambiguous_gatekeeper, now=now)

    wrong_gatekeeper_status = _record(corpus, now)
    _by_id(wrong_gatekeeper_status, "gatekeeper")["status"] = "clean"
    with pytest.raises(attestation.AttestationError, match="disagrees with controls"):
        attestation.validate_record(wrong_gatekeeper_status, now=now)


def test_live_corpus_binding_detects_added_removed_and_changed_bytes(corpus):
    record = _record(corpus)
    (corpus / "a.bin").write_bytes(b"changed")
    with pytest.raises(attestation.AttestationError, match="live corpus"):
        attestation.verify_corpus_binding(record, corpus)


def test_check_cli_accepts_only_canonical_fresh_bound_json(corpus, tmp_path):
    record = _record(corpus)
    path = tmp_path / "attestation.json"
    attestation.write_record(record, path)
    passed = subprocess.run(
        [sys.executable, str(ATTESTATION_SCRIPT), "check", str(path), "--corpus", str(corpus)],
        capture_output=True,
        text=True,
    )
    assert passed.returncode == 0, passed.stderr
    assert "VALID, FRESH, CONTROLLED, CLEAN" in passed.stdout

    path.write_text(json.dumps(record), encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(ATTESTATION_SCRIPT), "check", str(path)],
        capture_output=True,
        text=True,
    )
    assert failed.returncode != 0
    assert "not canonical JSON" in failed.stderr


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


def _write_fake_tool(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_clamav_fake_proves_control_version_and_exact_engine_count(corpus, tmp_path):
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
    assert result["status"] == "clean"
    assert result["scanner"]["engine_version"] == "9.8.7"
    assert result["scanner"]["rules"]["version"] == "4242"
    assert result["control"]["status"] == "passed"
    assert result["summary"]["files_scanned"] == inventory["file_count"]


def test_gatekeeper_fakes_require_acceptance_control_rejection_and_codesign(corpus, tmp_path):
    # Make one corpus entry recognizable as the generated thin arm64 Mach-O magic.
    (corpus / "a.bin").write_bytes(bytes.fromhex("cffaedfe") + b"fixture")
    control_binary = tmp_path / "platform-control"
    control_binary.write_bytes(b"known platform input")
    spctl = _write_fake_tool(
        tmp_path / "spctl",
        """import os, sys
if "--version" in sys.argv:
    print("spctl fixture 1")
    raise SystemExit(0)
if os.path.basename(sys.argv[-1]) == "platform-control":
    print("accepted")
    raise SystemExit(0)
print("rejected")
raise SystemExit(3)
""",
    )
    codesign = _write_fake_tool(tmp_path / "codesign", "raise SystemExit(0)\n")
    inventory = attestation.corpus_inventory(corpus)
    result = attestation.scan_gatekeeper(
        corpus,
        inventory,
        attestation.corpus_binding(inventory),
        spctl=str(spctl),
        codesign=str(codesign),
        accepted_control=control_binary,
    )
    assert result["status"] == "observation"
    assert result["control"]["status"] == "passed"
    assert result["coverage"]["target_signature_valid"] is True
    assert result["summary"]["outcome"] == "rejected"
    assert result["coverage"]["scanned_corpus_files"] == 1


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
