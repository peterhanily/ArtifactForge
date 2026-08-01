# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Produce and fail-closed validate scanner attestations for an exact corpus.

The attestation is evidence about one dated scan, not a safety certificate.  A result is usable
only when its scanner and rules are identified, its positive control passed, every selected
input is accounted for, and it is bound to the byte-level corpus manifest in the same record.
Missing tools and failed controls are serialized as errors so a failed run remains auditable;
``check`` never turns those records into skips.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

SCHEMA_ID = "artifactforge-scanner-attestation-v1"
SCHEMA_FILE = "scanner-attestation.schema.json"
CORPUS_CANONICALIZATION = "artifactforge-scanner-corpus-v1"
REQUIRED_SCANNERS = ("clamav", "community-yara", "gatekeeper", "xprotect")
MAX_AGE_DAYS = 30
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
YARA_ENGINE_CONTROL = b"AF\x00ARTIFACTFORGE-YARA-ENGINE-CONTROL-v1\x00"
YARA_ENGINE_NEAR_MISS = YARA_ENGINE_CONTROL.replace(
    b"ENGINE-CONTROL", b"ENGINE-NEAR-MISS"
)
XPROTECT_CONTROL = ("#!" + "/bin/zsh\n" + "\\U00000" * 16 + "${" * 101 + "rev)").encode()
XPROTECT_NEAR_MISS = XPROTECT_CONTROL.replace(
    ("${" * 101).encode(), ("${" * 100).encode()
)


class AttestationError(ValueError):
    """The record cannot support the claim a caller asked it to support."""


def _timestamp(now: dt.datetime | None = None) -> str:
    current = now or dt.datetime.now(dt.timezone.utc)
    return current.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: object, where: str) -> dt.datetime:
    if not isinstance(value, str):
        raise AttestationError(f"{where} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError(f"{where} is not a valid timestamp: {value!r}") from exc
    if parsed.tzinfo is None or not value.endswith("Z"):
        raise AttestationError(f"{where} must use an explicit UTC Z suffix")
    return parsed.astimezone(dt.timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_digest(canonicalization: str, files: list[dict]) -> str:
    payload = {"canonicalization": canonicalization, "files": files}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _sha256(encoded)


def corpus_inventory(root: Path) -> dict:
    """Return the exact recursive file manifest used to bind every scanner result."""
    root = Path(root)
    if not root.is_dir():
        raise AttestationError(f"corpus is not a directory: {root}")
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise AttestationError(f"corpus contains a symlink, which is not attestable: {path}")
        if not path.is_file():
            continue
        data = path.read_bytes()
        files.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256(data),
            "size": len(data),
        })
    if not files:
        raise AttestationError("corpus contains no regular files")
    return {
        "canonicalization": CORPUS_CANONICALIZATION,
        "tree_sha256": _canonical_digest(CORPUS_CANONICALIZATION, files),
        "file_count": len(files),
        "total_bytes": sum(item["size"] for item in files),
        "files": files,
    }


def corpus_binding(inventory: dict) -> dict:
    """Copy the immutable corpus identity into one scanner result."""
    return {
        key: inventory[key]
        for key in ("canonicalization", "tree_sha256", "file_count", "total_bytes")
    }


def _run(command: list[str], *, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def _error(where: str, message: str) -> dict:
    return {"where": where, "message": message}


def _empty_rules(version: str = "unavailable") -> dict:
    return {"version": version, "fingerprint_sha256": None, "manifest": None}


def _unavailable_result(
    scanner_id: str,
    scanner_name: str,
    binding: dict,
    command: list[str],
    message: str,
    *,
    engine_version: str = "unavailable",
    control_scope: str = "engine-and-selected-rules",
) -> dict:
    return {
        "scanner": {
            "id": scanner_id,
            "name": scanner_name,
            "engine_version": engine_version,
            "rules": _empty_rules(),
        },
        "timestamp": _timestamp(),
        "status": "error",
        "corpus_binding": binding,
        "method": {"command": command, "description": "scanner unavailable"},
        "control": {
            "kind": f"{scanner_id}-required-control",
            "scope": control_scope,
            "status": "failed",
            "command": command,
            "input_sha256": "0" * 64,
            "input_digest_method": "no-input-control-did-not-run",
            "expected": "a positive control passes before corpus results are interpreted",
            "observed": message,
            "demonstrates": "nothing; the required control did not run",
        },
        "coverage": {
            "kind": "unavailable",
            "selected_corpus_files": binding["file_count"],
            "scanned_corpus_files": 0,
            "control_scope_note": "no coverage claim is made",
        },
        "exclusions": [],
        "errors": [_error(scanner_id, message)],
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


def _guarded_scanner_result(
    scanner_id: str,
    scanner_name: str,
    binding: dict,
    command: list[str],
    control_scope: str,
    operation: Callable[[], dict],
) -> dict:
    """Turn an unexpected scanner exception into auditable red evidence, never a skip."""
    try:
        return operation()
    except Exception as exc:  # noqa: BLE001 — scanner/library failures belong in the record
        return _unavailable_result(
            scanner_id,
            scanner_name,
            binding,
            command,
            f"scanner raised {type(exc).__name__}: {exc}",
            control_scope=control_scope,
        )


def _clamav_version(output: str) -> tuple[str, str | None]:
    first = output.strip().splitlines()[0] if output.strip() else ""
    match = re.search(r"ClamAV\s+([^/\s]+)/([^/\s]+)", first)
    if match:
        return match.group(1), match.group(2)
    return first or "unknown", None


def scan_clamav(
    corpus: Path,
    binding: dict,
    *,
    executable: str | None = None,
) -> dict:
    """Run ClamAV without losing its exit status or engine-reported file count."""
    binary = executable or shutil.which("clamscan")
    intended = [binary or "clamscan", "--recursive", "--infected", str(corpus)]
    if not binary:
        return _unavailable_result(
            "clamav", "ClamAV", binding, intended, "clamscan is not installed"
        )
    errors = []
    try:
        version_run = _run([binary, "--version"], timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _unavailable_result(
            "clamav", "ClamAV", binding, intended,
            f"could not execute clamscan: {type(exc).__name__}: {exc}",
        )
    engine_version, rules_version = _clamav_version(version_run.stdout + version_run.stderr)
    if version_run.returncode != 0 or engine_version == "unknown":
        errors.append(_error("clamscan --version", "could not identify the engine version"))
    if rules_version is None:
        errors.append(_error(
            "clamscan --version", "could not identify the loaded signature-database version"
        ))

    with tempfile.TemporaryDirectory(prefix="artifactforge-clam-control-") as directory:
        control_path = Path(directory) / "eicar.com"
        control_path.write_bytes(EICAR)
        control_command = [binary, "--infected", "--no-summary", str(control_path)]
        try:
            control_run = _run(control_command, timeout=60)
            control_output = control_run.stdout + control_run.stderr
            control_passed = control_run.returncode == 1 and "FOUND" in control_output
            control_observed = (
                f"exit={control_run.returncode}; FOUND={'FOUND' in control_output}"
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            control_passed = False
            control_observed = f"{type(exc).__name__}: {exc}"

    command = [binary, "--recursive", "--infected", str(corpus)]
    try:
        scan_run = _run(command)
        output = scan_run.stdout + scan_run.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        scan_run = None
        output = ""
        errors.append(_error("clamav corpus scan", f"{type(exc).__name__}: {exc}"))
    findings = []
    scanned_files = 0
    if scan_run is not None:
        findings = sorted(line.strip() for line in output.splitlines() if line.rstrip().endswith("FOUND"))
        count_match = re.search(r"^Scanned files:\s*(\d+)\s*$", output, re.MULTILINE)
        if count_match:
            scanned_files = int(count_match.group(1))
        else:
            errors.append(_error("clamav corpus scan", "summary omitted Scanned files count"))
        if scan_run.returncode not in (0, 1):
            errors.append(_error(
                "clamav corpus scan", f"unexpected exit {scan_run.returncode}"
            ))
        if scanned_files != binding["file_count"]:
            errors.append(_error(
                "clamav corpus scan",
                f"engine reported {scanned_files} files; manifest has {binding['file_count']}",
            ))
    control = {
        "kind": "eicar-standard-antivirus-test-file",
        "scope": "engine-and-selected-rules",
        "status": "passed" if control_passed else "failed",
        "command": control_command,
        "input_sha256": _sha256(EICAR),
        "input_digest_method": "sha256-file-bytes",
        "expected": "clamscan exits 1 and reports FOUND for the harmless EICAR test string",
        "observed": control_observed,
        "demonstrates": (
            "the identified ClamAV engine and loaded signature database detect their standard "
            "harmless positive control"
        ),
    }
    if not control_passed:
        errors.append(_error("ClamAV control", control_observed))
    status = "error" if errors else ("finding" if findings else "clean")
    return {
        "scanner": {
            "id": "clamav",
            "name": "ClamAV",
            "engine_version": engine_version,
            "rules": _empty_rules(rules_version or "unreported"),
        },
        "timestamp": _timestamp(),
        "status": status,
        "corpus_binding": binding,
        "method": {
            "command": command,
            "description": (
                "recursive clamscan with its summary retained so the engine-reported file "
                "count and process exit status are checked"
            ),
        },
        "control": control,
        "coverage": {
            "kind": "engine-reported-file-count",
            "selected_corpus_files": binding["file_count"],
            "scanned_corpus_files": scanned_files,
            "control_scope_note": "EICAR exercises the loaded signature database",
        },
        "exclusions": [],
        "errors": errors,
        "summary": {
            "files_scanned": scanned_files,
            "matches": len(findings),
            "matched_rules": {line: 1 for line in findings},
        },
        "non_proof": {
            "boundary_id": "signature-snapshot-not-safety-proof",
            "statement": (
                "A clean result applies only to these exact bytes and this dated ClamAV "
                "engine/signature version. It does not prove safety, inertness, or future "
                "non-detection."
            ),
        },
    }


def _first_macho(corpus: Path, inventory: dict) -> tuple[Path, dict] | None:
    by_path = {item["path"]: item for item in inventory["files"]}
    for rel in sorted(by_path):
        path = corpus / rel
        if path.read_bytes()[:4] == bytes.fromhex("cffaedfe"):
            return path, by_path[rel]
    return None


def _gatekeeper_positive_control() -> Path:
    candidates = (
        Path("/System/Applications/Calculator.app"),
        Path("/System/Applications/TextEdit.app"),
        Path("/bin/ls"),
    )
    try:
        return next(path for path in candidates if path.exists())
    except StopIteration as exc:
        raise AttestationError("no signed platform Gatekeeper control is available") from exc


def _control_input_digest(path: Path) -> tuple[str, str]:
    if path.is_file():
        return _sha256(path.read_bytes()), "sha256-file-bytes"
    if path.is_dir():
        entries = []
        for current, directories, filenames in os.walk(path, followlinks=False):
            directories.sort()
            current_path = Path(current)
            for name in sorted([*directories, *filenames]):
                candidate = current_path / name
                relative = candidate.relative_to(path).as_posix()
                if candidate.is_symlink():
                    data = os.readlink(candidate).encode()
                    kind = "symlink"
                elif candidate.is_dir():
                    data = b""
                    kind = "directory"
                else:
                    data = candidate.read_bytes()
                    kind = "file"
                entries.append({
                    "kind": kind,
                    "path": relative,
                    "sha256": _sha256(data),
                    "size": len(data),
                })
        entries.sort(key=lambda item: item["path"])
        payload = {
            "canonicalization": "artifactforge-gatekeeper-control-tree-v1",
            "entries": entries,
        }
        digest = _sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode())
        return digest, payload["canonicalization"]
    raise AttestationError(f"Gatekeeper control input does not exist: {path}")


def scan_gatekeeper(
    corpus: Path,
    inventory: dict,
    binding: dict,
    *,
    spctl: str | None = None,
    codesign: str | None = None,
    accepted_control: Path | None = None,
) -> dict:
    """Record a controlled, single-binary Gatekeeper host observation."""
    spctl_bin = spctl or shutil.which("spctl")
    codesign_bin = codesign or shutil.which("codesign")
    intended = [spctl_bin or "spctl", "-a", "-t", "execute", "<selected Mach-O>"]
    if not spctl_bin or not codesign_bin:
        missing = ", ".join(name for name, value in (("spctl", spctl_bin), ("codesign", codesign_bin))
                            if not value)
        return _unavailable_result(
            "gatekeeper", "Apple Gatekeeper", binding, intended,
            f"required macOS tool(s) unavailable: {missing}", control_scope="engine-and-host-policy",
        )
    selected = _first_macho(corpus, inventory)
    if selected is None:
        return _unavailable_result(
            "gatekeeper", "Apple Gatekeeper", binding, intended,
            "corpus contains no thin arm64 Mach-O target", control_scope="engine-and-host-policy",
        )
    target, target_item = selected
    try:
        control_path = accepted_control or _gatekeeper_positive_control()
        control_digest, control_digest_method = _control_input_digest(control_path)
    except AttestationError as exc:
        return _unavailable_result(
            "gatekeeper", "Apple Gatekeeper", binding, intended, str(exc),
            control_scope="engine-and-host-policy",
        )
    version_run = _run([spctl_bin, "--version"], timeout=30)
    reported_spctl_version = (version_run.stdout + version_run.stderr).strip()
    macos_version = "unreported"
    sw_vers = shutil.which("sw_vers")
    if sw_vers:
        sw_run = _run([sw_vers, "-productVersion"], timeout=30)
        if sw_run.returncode == 0 and sw_run.stdout.strip():
            macos_version = sw_run.stdout.strip()
    engine_version = reported_spctl_version or f"spctl bundled with macOS {macos_version}"

    control_command = [
        spctl_bin, "--assess", "--type", "execute", "--verbose=4", str(control_path),
    ]
    control_run = _run(control_command, timeout=60)
    control_output = (control_run.stdout + control_run.stderr).strip()
    control_passed = control_run.returncode == 0
    control = {
        "kind": "gatekeeper-known-platform-binary-acceptance-v1",
        "scope": "engine-and-host-policy",
        "status": "passed" if control_passed else "failed",
        "command": control_command,
        "input_sha256": control_digest,
        "input_digest_method": control_digest_method,
        "expected": "Gatekeeper accepts the selected host platform binary",
        "observed": f"exit={control_run.returncode}; output={control_output!r}",
        "demonstrates": (
            "spctl returned an affirmative policy decision on this host before the synthetic "
            "target was assessed"
        ),
    }
    with tempfile.TemporaryDirectory(prefix="artifactforge-gatekeeper-") as directory:
        executable = Path(directory) / target.name
        shutil.copyfile(target, executable)
        executable.chmod(0o755)
        command = [
            spctl_bin, "--assess", "--type", "execute", "--verbose=4", str(executable),
        ]
        target_run = _run(command, timeout=60)
        target_output = (target_run.stdout + target_run.stderr).strip()
        signature_command = [
            codesign_bin, "--verify", "--strict", "--verbose=4", str(executable),
        ]
        signature_run = _run(signature_command, timeout=60)
    signature_valid = signature_run.returncode == 0
    rejected = target_run.returncode != 0 and "rejected" in target_output.lower()
    errors = []
    if engine_version.endswith("unreported"):
        errors.append(_error("Gatekeeper version", "could not identify spctl or macOS version"))
    if not control_passed:
        errors.append(_error("Gatekeeper control", control["observed"]))
    if not signature_valid:
        errors.append(_error("codesign target validation", f"exit={signature_run.returncode}"))
    if not rejected:
        errors.append(_error(
            "Gatekeeper target assessment",
            f"expected an explicit rejection; exit={target_run.returncode}; output={target_output!r}",
        ))
    return {
        "scanner": {
            "id": "gatekeeper",
            "name": "Apple Gatekeeper",
            "engine_version": engine_version,
            "rules": _empty_rules(f"macOS {macos_version} host policy (opaque)"),
        },
        "timestamp": _timestamp(),
        "status": "error" if errors else "observation",
        "corpus_binding": binding,
        "method": {
            "command": command,
            "description": (
                "one manifest-bound Mach-O was assessed after a known host binary was accepted "
                "and codesign validated the target's on-disk signature"
            ),
        },
        "control": control,
        "coverage": {
            "kind": "single-selected-macho",
            "selected_corpus_files": binding["file_count"],
            "scanned_corpus_files": 1,
            "target": target_item["path"],
            "target_sha256": target_item["sha256"],
            "target_signature_command": signature_command,
            "target_signature_valid": signature_valid,
            "control_scope_note": "the control exercises this host's Gatekeeper decision path",
        },
        "exclusions": [{
            "path": "all corpus files except the selected Mach-O",
            "reason": "Gatekeeper observation is intentionally a single-target platform check",
        }],
        "errors": errors,
        "summary": {
            "files_scanned": 1,
            "matches": 0,
            "matched_rules": {},
            "outcome": "rejected" if rejected else "not-explicitly-rejected",
        },
        "non_proof": {
            "boundary_id": "single-host-policy-observation-not-portable-proof",
            "statement": (
                "This is one target on one dated macOS host. It is not a portable Gatekeeper "
                "guarantee, a whole-corpus scan, or proof that later policy versions reject it."
            ),
        },
    }


def build_record(
    corpus: Path,
    yara_rules: Path,
    *,
    producer_command: list[str],
    clamscan: str | None = None,
    xprotect_path: Path | None = None,
    spctl: str | None = None,
    codesign: str | None = None,
) -> dict:
    """Run every required scanner and bind its result to one corpus inventory."""
    import scan_yara

    inventory = corpus_inventory(corpus)
    binding = corpus_binding(inventory)
    xprotect_rule = xprotect_path or Path(scan_yara.XPROTECT)
    results = [
        _guarded_scanner_result(
            "clamav", "ClamAV", binding,
            [clamscan or "clamscan", "--recursive", "--infected", str(corpus)],
            "engine-and-selected-rules",
            lambda: scan_clamav(corpus, binding, executable=clamscan),
        ),
        _guarded_scanner_result(
            "xprotect", "Apple XProtect YARA", binding, producer_command,
            "engine-and-selected-rules",
            lambda: scan_yara.scan_xprotect(
                corpus, binding, rules_path=xprotect_rule, method_command=producer_command
            ),
        ),
        _guarded_scanner_result(
            "community-yara", "Community YARA", binding, producer_command,
            "engine-only",
            lambda: scan_yara.scan_community(
                corpus, yara_rules, binding, method_command=producer_command
            ),
        ),
        _guarded_scanner_result(
            "gatekeeper", "Apple Gatekeeper", binding,
            [spctl or "spctl", "--assess", "--type", "execute", "<selected Mach-O>"],
            "engine-and-host-policy",
            lambda: scan_gatekeeper(
                corpus, inventory, binding, spctl=spctl, codesign=codesign
            ),
        ),
    ]
    if corpus_inventory(corpus) != inventory:
        raise AttestationError("corpus changed while scanners were reading it")

    xprotect_result = next(item for item in results if item["scanner"]["id"] == "xprotect")
    if (xprotect_rule.is_file()
            and xprotect_result["scanner"]["rules"].get("manifest") is not None):
        current_xprotect = scan_yara._rule_metadata([xprotect_rule], xprotect_rule.parent)
        if xprotect_result["scanner"]["rules"] != current_xprotect:
            raise AttestationError("XProtect rules changed while scanners were reading them")
    community_result = next(
        item for item in results if item["scanner"]["id"] == "community-yara"
    )
    if (yara_rules.is_dir()
            and community_result["scanner"]["rules"].get("manifest") is not None):
        _discovered, selected, _exclusions = scan_yara._community_paths(yara_rules)
        current_community = scan_yara._rule_metadata(selected, yara_rules)
        if community_result["scanner"]["rules"] != current_community:
            raise AttestationError("community YARA rules changed while scanners were reading them")
    return {
        "schema": SCHEMA_ID,
        "schema_version": 1,
        "generated_at": _timestamp(),
        "producer": {
            "name": "ArtifactForge scanner attestation",
            "version": 1,
            "command": producer_command,
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
        },
        "policy": {
            "required_scanners": list(REQUIRED_SCANNERS),
            "maximum_age_days": MAX_AGE_DAYS,
            "success_rule": (
                "all required controls pass, all selected inputs are covered, no scan errors "
                "or scanner/rule matches occur, and the record is fresh and corpus-bound"
            ),
        },
        "corpus": inventory,
        "results": sorted(results, key=lambda item: item["scanner"]["id"]),
        "overall_non_proof": (
            "Even a valid clean attestation is a dated signature-snapshot observation over "
            "exact bytes, not proof that the binaries are safe or inert. The record is "
            "self-reported and unsigned; it does not independently authenticate the host or "
            "scanner binaries."
        ),
    }


def _require_mapping(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise AttestationError(f"{where} must be an object")
    return value


def _require_list(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise AttestationError(f"{where} must be an array")
    return value


def _require_text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttestationError(f"{where} must be non-empty text")
    return value


def _require_sha256(value: object, where: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise AttestationError(f"{where} must be a lowercase SHA256")
    return value


def _validate_manifest(inventory: dict, where: str, canonicalization: str) -> None:
    if inventory.get("canonicalization") != canonicalization:
        raise AttestationError(f"{where} has incompatible canonicalization")
    files = _require_list(inventory.get("files"), f"{where}.files")
    if inventory.get("file_count") != len(files) or not files:
        raise AttestationError(f"{where} file count does not match its manifest")
    previous = None
    total = 0
    for index, raw in enumerate(files):
        item = _require_mapping(raw, f"{where}.files[{index}]")
        path = _require_text(item.get("path"), f"{where}.files[{index}].path")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or path == ".":
            raise AttestationError(f"{where} contains an unsafe path: {path!r}")
        if previous is not None and path <= previous:
            raise AttestationError(f"{where} paths must be unique and sorted")
        previous = path
        size = item.get("size")
        if not isinstance(size, int) or size < 0:
            raise AttestationError(f"{where} has an invalid size for {path!r}")
        total += size
        _require_sha256(item.get("sha256"), f"{where} SHA256 for {path!r}")
    if inventory.get("total_bytes", total) != total:
        raise AttestationError(f"{where} total byte count does not match its manifest")
    expected = _canonical_digest(canonicalization, files)
    if inventory.get("tree_sha256") != expected:
        raise AttestationError(f"{where} tree SHA256 does not match its manifest")


def _validate_rules(rules: dict, scanner_id: str) -> None:
    version = rules.get("version")
    fingerprint = rules.get("fingerprint_sha256")
    if not (isinstance(version, str) and version.strip()) and fingerprint is None:
        raise AttestationError(f"{scanner_id} has neither a rule version nor fingerprint")
    manifest = rules.get("manifest")
    if manifest is not None:
        manifest = _require_mapping(manifest, f"{scanner_id}.scanner.rules.manifest")
        _validate_manifest(manifest, f"{scanner_id} rule manifest", "artifactforge-yara-rule-manifest-v1")
        if fingerprint != manifest.get("tree_sha256"):
            raise AttestationError(f"{scanner_id} rule fingerprint does not match its manifest")
    elif fingerprint is not None:
        _require_sha256(fingerprint, f"{scanner_id} rule fingerprint")


def _validate_control(control: dict, scanner_id: str) -> None:
    for key in (
        "kind", "scope", "status", "input_digest_method", "expected", "observed",
        "demonstrates",
    ):
        _require_text(control.get(key), f"{scanner_id}.control.{key}")
    _require_sha256(control.get("input_sha256"), f"{scanner_id}.control.input_sha256")
    command = _require_list(control.get("command", []), f"{scanner_id}.control.command")
    if not command or not all(isinstance(part, str) and part for part in command):
        raise AttestationError(f"{scanner_id} control must record its command or method")
    expected_scope = {
        "clamav": "engine-and-selected-rules",
        "community-yara": "engine-only",
        "gatekeeper": "engine-and-host-policy",
        "xprotect": "engine-and-selected-rules",
    }[scanner_id]
    if control.get("scope") != expected_scope:
        raise AttestationError(
            f"{scanner_id} control scope must be {expected_scope!r}, not {control.get('scope')!r}"
        )
    expected_kind = {
        "clamav": "eicar-standard-antivirus-test-file",
        "community-yara": "synthetic-yara-engine-rule-v1",
        "gatekeeper": "gatekeeper-known-platform-binary-acceptance-v1",
        "xprotect": "xprotect-rule-specific-hit-and-near-miss-v1",
    }[scanner_id]
    if control.get("status") == "passed" and control.get("kind") != expected_kind:
        raise AttestationError(
            f"{scanner_id} passing control kind must be {expected_kind!r}"
        )
    if control.get("status") != "passed":
        return

    if scanner_id == "gatekeeper":
        if control.get("input_digest_method") not in {
            "sha256-file-bytes", "artifactforge-gatekeeper-control-tree-v1",
        }:
            raise AttestationError("gatekeeper control has an unsupported input digest method")
        return

    expected_input, expected_method = {
        "clamav": (EICAR, "sha256-file-bytes"),
        "community-yara": (YARA_ENGINE_CONTROL, "sha256-in-memory-bytes-v1"),
        "xprotect": (XPROTECT_CONTROL, "sha256-in-memory-bytes-v1"),
    }[scanner_id]
    if control.get("input_sha256") != _sha256(expected_input):
        raise AttestationError(f"{scanner_id} control input digest is not the required vector")
    if control.get("input_digest_method") != expected_method:
        raise AttestationError(f"{scanner_id} control input digest method is wrong")
    if scanner_id in {"community-yara", "xprotect"}:
        near = YARA_ENGINE_NEAR_MISS if scanner_id == "community-yara" else XPROTECT_NEAR_MISS
        if control.get("near_miss_sha256") != _sha256(near):
            raise AttestationError(f"{scanner_id} near-miss digest is not the required vector")


def _validate_summary(summary: dict, scanner_id: str) -> int:
    matches = summary.get("matches")
    if not isinstance(matches, int) or isinstance(matches, bool) or matches < 0:
        raise AttestationError(f"{scanner_id} has an invalid match count")
    matched_rules = _require_mapping(summary.get("matched_rules"),
                                     f"{scanner_id}.summary.matched_rules")
    total = 0
    for name, count in matched_rules.items():
        _require_text(name, f"{scanner_id}.summary matched-rule name")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise AttestationError(f"{scanner_id} matched-rule counts must be positive integers")
        total += count
    if total != matches:
        raise AttestationError(f"{scanner_id} match count disagrees with its per-rule arithmetic")
    return matches


def _validate_exclusions_and_errors(result: dict, scanner_id: str) -> None:
    for field in ("exclusions", "errors"):
        entries = _require_list(result.get(field), f"{scanner_id}.{field}")
        for index, raw in enumerate(entries):
            entry = _require_mapping(raw, f"{scanner_id}.{field}[{index}]")
            needed = ("path", "reason") if field == "exclusions" else ("where", "message")
            for key in needed:
                _require_text(entry.get(key), f"{scanner_id}.{field}[{index}].{key}")


def _validate_coverage(
    result: dict,
    scanner_id: str,
    corpus: dict,
    *,
    allow_incomplete: bool,
) -> None:
    coverage = _require_mapping(result.get("coverage"), f"{scanner_id}.coverage")
    _require_text(coverage.get("kind"), f"{scanner_id}.coverage.kind")
    _require_text(coverage.get("control_scope_note"), f"{scanner_id}.coverage.control_scope_note")
    selected = coverage.get("selected_corpus_files")
    scanned = coverage.get("scanned_corpus_files")
    if selected != corpus["file_count"]:
        raise AttestationError(f"{scanner_id} selected-file count is not the bound corpus count")
    summary = _require_mapping(result.get("summary"), f"{scanner_id}.summary")
    if summary.get("files_scanned") != scanned:
        raise AttestationError(f"{scanner_id} summary and coverage scanned counts disagree")
    if allow_incomplete and result.get("status") == "error":
        if not isinstance(scanned, int) or scanned < 0 or scanned > corpus["file_count"]:
            raise AttestationError(f"{scanner_id} has an invalid incomplete scanned-file count")
        return
    if scanner_id == "gatekeeper":
        if scanned != 1 or coverage.get("kind") != "single-selected-macho":
            raise AttestationError("Gatekeeper must state its single-target coverage")
        target = _require_text(coverage.get("target"), "gatekeeper.coverage.target")
        target_map = {item["path"]: item["sha256"] for item in corpus["files"]}
        if target not in target_map or coverage.get("target_sha256") != target_map[target]:
            raise AttestationError("Gatekeeper target is not bound to the corpus manifest")
        if coverage.get("target_signature_valid") is not True:
            raise AttestationError("Gatekeeper target lacks a passing codesign validation")
        return
    if scanned != corpus["file_count"]:
        raise AttestationError(f"{scanner_id} did not scan every bound corpus file")
    if scanner_id == "clamav":
        if coverage.get("kind") != "engine-reported-file-count":
            raise AttestationError("ClamAV coverage must come from its engine-reported count")
        return
    for key in ("selected_rule_files", "loaded_rule_files", "failed_rule_files", "rules_loaded"):
        if not isinstance(coverage.get(key), int) or coverage[key] < 0:
            raise AttestationError(f"{scanner_id}.coverage.{key} must be a nonnegative integer")
    if coverage["selected_rule_files"] != coverage["loaded_rule_files"]:
        raise AttestationError(f"{scanner_id} did not load every selected rule file")
    if coverage["failed_rule_files"] != 0:
        raise AttestationError(f"{scanner_id} has failed rule files")
    if coverage["rules_loaded"] <= 0:
        raise AttestationError(f"{scanner_id} loaded no rules")
    manifest = result["scanner"]["rules"].get("manifest")
    if not manifest or manifest.get("file_count") != coverage["selected_rule_files"]:
        raise AttestationError(f"{scanner_id} rule coverage is not bound to its manifest")
    if scanner_id == "community-yara":
        discovered = coverage.get("discovered_rule_files")
        excluded = coverage.get("excluded_rule_files")
        if discovered != coverage["selected_rule_files"] + excluded:
            raise AttestationError("community-yara discovered/selected/excluded counts disagree")
        if excluded != len(result["exclusions"]):
            raise AttestationError("community-yara exclusions are not individually recorded")


def validate_record(
    record: dict,
    *,
    now: dt.datetime | None = None,
    require_success: bool = True,
) -> None:
    """Validate schema, freshness, controls, coverage, and (optionally) clean success."""
    record = _require_mapping(record, "record")
    if record.get("schema") != SCHEMA_ID or record.get("schema_version") != 1:
        raise AttestationError("incompatible scanner-attestation schema")
    generated = _parse_timestamp(record.get("generated_at"), "generated_at")
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    age = current - generated
    if age < dt.timedelta(minutes=-5):
        raise AttestationError("scanner attestation is dated in the future")
    if age > dt.timedelta(days=MAX_AGE_DAYS):
        raise AttestationError(
            f"scanner attestation is stale (older than {MAX_AGE_DAYS} days)"
        )
    producer = _require_mapping(record.get("producer"), "producer")
    _require_text(producer.get("name"), "producer.name")
    command = _require_list(producer.get("command"), "producer.command")
    if not command or not all(isinstance(part, str) and part for part in command):
        raise AttestationError("producer.command must record the exact non-empty argv")
    _require_text(record.get("overall_non_proof"), "overall_non_proof")

    policy = _require_mapping(record.get("policy"), "policy")
    if policy.get("required_scanners") != list(REQUIRED_SCANNERS):
        raise AttestationError("record weakens or changes the required-scanner policy")
    if policy.get("maximum_age_days") != MAX_AGE_DAYS:
        raise AttestationError("record weakens or changes the freshness policy")
    _require_text(policy.get("success_rule"), "policy.success_rule")

    corpus = _require_mapping(record.get("corpus"), "corpus")
    _validate_manifest(corpus, "corpus", CORPUS_CANONICALIZATION)
    binding = corpus_binding(corpus)
    results = _require_list(record.get("results"), "results")
    by_id = {}
    for index, raw in enumerate(results):
        result = _require_mapping(raw, f"results[{index}]")
        scanner = _require_mapping(result.get("scanner"), f"results[{index}].scanner")
        scanner_id = _require_text(scanner.get("id"), f"results[{index}].scanner.id")
        if scanner_id in by_id:
            raise AttestationError(f"duplicate scanner result: {scanner_id}")
        if scanner_id not in REQUIRED_SCANNERS:
            raise AttestationError(f"unexpected scanner result: {scanner_id}")
        by_id[scanner_id] = result
        _require_text(scanner.get("name"), f"{scanner_id}.scanner.name")
        _require_text(scanner.get("engine_version"), f"{scanner_id}.scanner.engine_version")
        rules = _require_mapping(scanner.get("rules"), f"{scanner_id}.scanner.rules")
        _validate_rules(rules, scanner_id)
        result_time = _parse_timestamp(result.get("timestamp"), f"{scanner_id}.timestamp")
        if abs(result_time - generated) > dt.timedelta(hours=1):
            raise AttestationError(f"{scanner_id} timestamp is not part of this attestation run")
        if result.get("corpus_binding") != binding:
            raise AttestationError(f"{scanner_id} result is not bound to the exact corpus")
        method = _require_mapping(result.get("method"), f"{scanner_id}.method")
        method_command = _require_list(method.get("command"), f"{scanner_id}.method.command")
        if not method_command or not all(isinstance(part, str) and part for part in method_command):
            raise AttestationError(f"{scanner_id} method must record exact non-empty argv")
        _require_text(method.get("description"), f"{scanner_id}.method.description")
        control = _require_mapping(result.get("control"), f"{scanner_id}.control")
        _validate_control(control, scanner_id)
        _validate_exclusions_and_errors(result, scanner_id)
        _validate_coverage(
            result,
            scanner_id,
            corpus,
            allow_incomplete=not require_success,
        )
        non_proof = _require_mapping(result.get("non_proof"), f"{scanner_id}.non_proof")
        _require_text(non_proof.get("boundary_id"), f"{scanner_id}.non_proof.boundary_id")
        statement = _require_text(non_proof.get("statement"), f"{scanner_id}.non_proof.statement")
        if "not" not in statement.lower():
            raise AttestationError(f"{scanner_id} non-proof boundary is not explicit")
        status = result.get("status")
        if status not in {"clean", "finding", "observation", "error"}:
            raise AttestationError(f"{scanner_id} has invalid status {status!r}")
        matches = _validate_summary(result["summary"], scanner_id)
        if control.get("status") != "passed" or result["errors"]:
            expected_status = "error"
        elif scanner_id == "gatekeeper":
            expected_status = "observation"
        else:
            expected_status = "finding" if matches else "clean"
        if status != expected_status:
            raise AttestationError(
                f"{scanner_id} status {status!r} disagrees with controls, errors and matches"
            )
        if require_success:
            if control.get("status") != "passed":
                raise AttestationError(f"{scanner_id} required control did not pass")
            if result["errors"]:
                raise AttestationError(f"{scanner_id} records scan errors")
            if scanner_id == "gatekeeper":
                if status != "observation" or result["summary"].get("outcome") != "rejected":
                    raise AttestationError(
                        "gatekeeper success requires an explicit controlled rejection observation"
                    )
            elif status != "clean" or matches:
                raise AttestationError(f"{scanner_id} did not produce a clean controlled result")
    if set(by_id) != set(REQUIRED_SCANNERS):
        missing = sorted(set(REQUIRED_SCANNERS) - set(by_id))
        raise AttestationError(f"missing required scanner results: {missing}")


def verify_corpus_binding(record: dict, corpus: Path) -> None:
    """Recompute the live corpus and require byte-for-byte equality with the record."""
    actual = corpus_inventory(corpus)
    if record.get("corpus") != actual:
        raise AttestationError("live corpus does not match the attested manifest and digest")


def write_record(record: dict, output: Path) -> None:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(record, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(rendered)
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_record(path: Path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestationError(f"cannot read scanner attestation {path}: {exc}") from exc


def _print_summary(record: dict) -> None:
    corpus = record["corpus"]
    print(
        f"corpus: {corpus['file_count']} files, {corpus['total_bytes']} bytes, "
        f"sha256={corpus['tree_sha256']}"
    )
    for result in record["results"]:
        scanner = result["scanner"]
        control = result["control"]
        print(
            f"{scanner['id']}: {result['status']}; engine={scanner['engine_version']}; "
            f"control={control['status']} ({control['scope']}); "
            f"scanned={result['summary']['files_scanned']}"
        )
        for error in result["errors"]:
            print(f"  ERROR {error['where']}: {error['message']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run every required scanner and write an attestation")
    run.add_argument("--corpus", required=True, type=Path)
    run.add_argument("--yara-rules", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--clamscan", help=argparse.SUPPRESS)
    run.add_argument("--xprotect-path", type=Path, help=argparse.SUPPRESS)
    run.add_argument("--spctl", help=argparse.SUPPRESS)
    run.add_argument("--codesign", help=argparse.SUPPRESS)
    check = sub.add_parser("check", help="fail closed unless an attestation is fresh and clean")
    check.add_argument("record", type=Path)
    check.add_argument("--corpus", type=Path,
                       help="also require this live corpus to match every attested byte")
    args = parser.parse_args(argv)

    try:
        if args.command == "run":
            command = [sys.executable, str(Path(__file__)), *(argv or sys.argv[1:])]
            record = build_record(
                args.corpus,
                args.yara_rules,
                producer_command=command,
                clamscan=args.clamscan,
                xprotect_path=args.xprotect_path,
                spctl=args.spctl,
                codesign=args.codesign,
            )
            # Structural validation happens before write; unsuccessful scanner results remain
            # serializable evidence but cannot pass the fail-closed success check below.
            validate_record(record, require_success=False)
            write_record(record, args.output)
            _print_summary(record)
            print(f"attestation: {args.output}")
            validate_record(record, require_success=True)
            return 0
        record = read_record(args.record)
        validate_record(record, require_success=True)
        if args.corpus:
            verify_corpus_binding(record, args.corpus)
        canonical = json.dumps(record, indent=2, sort_keys=True) + "\n"
        if args.record.read_text(encoding="utf-8") != canonical:
            raise AttestationError("scanner attestation is not canonical JSON")
        _print_summary(record)
        print("attestation: VALID, FRESH, CONTROLLED, CLEAN")
        return 0
    except AttestationError as exc:
        print(f"scanner attestation FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
