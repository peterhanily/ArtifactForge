#!/usr/bin/env python3
# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Measure EvidenceForge's serialized Sysmon/Zeek hash surface deterministically.

The committed measurement is deliberately derived from files on disk.  This module does not
import EvidenceForge, use its private helpers, or contact the network.  Point ``measure`` at a
completed run and the exact scenario file used to create it; ``render`` turns a record into a
small Markdown table so prose can cite the record instead of copying figures from an ad-hoc
terminal session.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote, urlsplit

SCHEMA_VERSION = 2
METHOD_VERSION = 2

PINNED_EVIDENCEFORGE = {
    "version": "1.13.1",
    "tag": "v1.13.1",
    "git_commit": "c0c619992fa44418a20f9b7d9abbeae750695916",
}
PINNED_SCENARIO = {
    "name": "branch-office-example",
    "repository_path": "scenarios/branch-office-example/scenario.yaml",
    "git_blob_sha1": "415947f6b34c69170a89d953607b0d5ad9848bd8",
    "sha256": "4a46b8e54181be0cf74163e93f849f88d47761338d8a943a2b7a2c93eedbf249",
    "duration": "6h",
    "warmup": "2h",
}

_EVENT = re.compile(r"<Event\b.*?</Event>", re.S)
_EVENT_ID = re.compile(r"<EventID>(\d+)</EventID>")
_DATA = re.compile(r'<Data Name="([^"]+)">([^<]*)<', re.S)
_SCENARIO_NAME = re.compile(r"^name:\s*([^#\n]+?)\s*$", re.M)
_DURATION = re.compile(r'^\s+duration:\s*["\']?([^"\'\s#]+)', re.M)
_WARMUP = re.compile(r'^\s+warmup:\s*["\']?([^"\'\s#]+)', re.M)
_ALGORITHMS = ("md5", "sha1", "sha256")
_SYSMON_ALGORITHMS = (*_ALGORITHMS, "imphash")
_CERTIFICATE_MIME = "application/pkix-cert"
_SEED_FORMS = ("bare", "from_host_metadata", "with_description")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_inventory_bytes(files: list[dict[str, Any]]) -> bytes:
    """Return the versioned canonical representation used for the tree digest."""

    payload = json.dumps(files, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return b"artifactforge-output-tree-v1\0" + payload.encode("utf-8")


def output_tree_inventory(run_root: str | Path) -> dict[str, Any]:
    """Content-address every regular file under an output root.

    Paths are POSIX-style and relative to the supplied root.  Symlinks are rejected rather than
    followed so an inventory cannot silently depend on mutable bytes outside the measured tree.
    File metadata and mtimes are deliberately excluded; only names, lengths, and bytes bind the
    output.
    """

    root = Path(run_root)
    if not root.is_dir():
        raise ValueError(f"output root is not a directory: {root}")
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"output tree contains a symlink: {relative}")
        if path.is_file():
            files.append(
                {
                    "path": relative,
                    "size": path.stat().st_size,
                    "sha256": _file_sha256(path),
                }
            )
    if not files:
        raise ValueError(f"output tree contains no regular files: {root}")
    return {
        "canonicalization": "artifactforge-output-tree-v1",
        "file_count": len(files),
        "total_bytes": sum(item["size"] for item in files),
        "tree_sha256": hashlib.sha256(_canonical_inventory_bytes(files)).hexdigest(),
        "files": files,
    }


def _validated_pinned_producer(version: str, git_commit: str) -> dict[str, str]:
    """Fail closed unless an explicit producer attestation exactly matches the pin."""

    supplied = {"version": version.strip(), "git_commit": git_commit.strip().lower()}
    expected = {
        "version": PINNED_EVIDENCEFORGE["version"],
        "git_commit": PINNED_EVIDENCEFORGE["git_commit"],
    }
    if supplied != expected:
        raise ValueError(
            "producer attestation does not match the pinned EvidenceForge release: "
            f"expected {expected}, got {supplied}"
        )
    return dict(PINNED_EVIDENCEFORGE)


def _git_blob_sha1(path: Path) -> str:
    """Return Git's object ID for the file without requiring a Git checkout."""

    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def _scenario_metadata(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")

    def required(pattern: re.Pattern[str], field: str) -> str:
        match = pattern.search(text)
        if match is None:
            raise ValueError(f"scenario has no parseable {field}: {path}")
        return match.group(1).strip().strip('"\'')

    return {
        "name": required(_SCENARIO_NAME, "name"),
        "repository_path": PINNED_SCENARIO["repository_path"],
        "git_blob_sha1": _git_blob_sha1(path),
        "sha256": _file_sha256(path),
        "duration": required(_DURATION, "duration"),
        "warmup": required(_WARMUP, "warmup"),
    }


def _parse_hashes(raw: str | None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for part in (raw or "").split(","):
        key, separator, value = part.partition("=")
        if separator and key.strip() and value.strip():
            hashes[key.strip().lower()] = value.strip().lower()
    return hashes


def _windows_basename(value: str | None) -> str:
    return PureWindowsPath((value or "").replace("/", "\\")).name.lower()


def _uri_basename(value: str | None) -> str:
    if not value:
        return ""
    try:
        path = urlsplit(value).path
    except ValueError:
        path = value.split("?", 1)[0]
    return PurePosixPath(unquote(path)).name.lower()


def _json_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(paths):
        for line_number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"expected an object at {path}:{line_number}")
            rows.append(row)
    return rows


def _digest_counts(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        algorithm: {
            "rows": sum(bool(row.get(algorithm)) for row in rows),
            "distinct": len(
                {str(row[algorithm]).lower() for row in rows if row.get(algorithm)}
            ),
        }
        for algorithm in _ALGORITHMS
    }


def _sysmon_measurement(run_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    paths = sorted((run_root / "data").glob("*/windows_event_sysmon.xml"))
    records: list[dict[str, Any]] = []
    for path in paths:
        for event in _EVENT.findall(path.read_text(errors="ignore")):
            event_id_match = _EVENT_ID.search(event)
            fields = dict(_DATA.findall(event))
            hashes = _parse_hashes(fields.get("Hashes"))
            if event_id_match is None:
                continue
            event_id = int(event_id_match.group(1))
            if event_id not in {1, 7}:
                continue
            image_field = "ImageLoaded" if event_id == 7 else "Image"
            image = fields.get(image_field, "")
            # Match the adapter's verifiable population exactly: process/image-load records
            # carrying both a named image and a non-empty SHA256.
            if not image or not hashes.get("sha256"):
                continue
            records.append(
                {
                    "event_id": event_id,
                    "image": image,
                    "hashes": hashes,
                }
            )

    def summarize(selected: list[dict[str, Any]]) -> dict[str, Any]:
        basenames = {_windows_basename(row["image"]) for row in selected if row["image"]}
        return {
            "hashed_records": len(selected),
            "distinct_hashes": {
                algorithm: len(
                    {
                        row["hashes"][algorithm]
                        for row in selected
                        if row["hashes"].get(algorithm)
                    }
                )
                for algorithm in _SYSMON_ALGORITHMS
            },
            "distinct_image_basenames": len(basenames),
        }

    event_id_1 = [row for row in records if row["event_id"] == 1]
    event_id_7 = [row for row in records if row["event_id"] == 7]
    measurement = {
        "population_definition": "Sysmon EID1/EID7 with non-empty image and SHA256",
        "host_logs": len(paths),
        **summarize(records),
        "event_id_1": summarize(event_id_1),
        "event_id_7": summarize(event_id_7),
    }
    working = {
        "records": records,
        "event_id_1": event_id_1,
        "event_id_1_basenames": {
            _windows_basename(row["image"]) for row in event_id_1 if row["image"]
        },
    }
    return measurement, working


def _adapter_verification(run_root: Path) -> dict[str, Any]:
    """Recover and verify seed forms from serialized records, independently of EventID.

    ``read_run`` imports no EvidenceForge code.  It tries every transcribed v1.13.1 seed form
    against each emitted SHA256 and accepts a record only when exactly one form reproduces it.
    Keeping this separate from the raw EID counts prevents the tempting but false shortcut that
    EID1 means ``from_host_metadata`` and EID7 means ``with_description``.
    """

    from artifactforge.ingest.evidenceforge import read_run

    run = read_run(str(run_root))
    records_by_form = {form: 0 for form in _SEED_FORMS}
    identities_by_form = {form: 0 for form in _SEED_FORMS}
    for binary in run.binaries.values():
        if binary.seed_form not in records_by_form:
            raise ValueError(f"adapter recovered unknown seed form: {binary.seed_form!r}")
        records_by_form[binary.seed_form] += binary.records
        identities_by_form[binary.seed_form] += 1
    return {
        "method": "artifactforge.ingest.evidenceforge.read_run",
        "evidenceforge_import_required": False,
        "records_with_sha256_and_image": run.records_with_hashes,
        "records_recovered_and_verified": run.records_recovered,
        "unrecovered_records": len(run.unrecovered),
        "distinct_logical_identities": len(run.binaries),
        "verified_records_by_seed_form": records_by_form,
        "distinct_logical_identities_by_verified_seed_form": identities_by_form,
    }


def _zeek_measurement(run_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    data_root = run_root / "data"
    files_paths = sorted(data_root.glob("**/files.json"))
    http_paths = sorted(data_root.glob("**/http.json"))
    rows = _json_rows(files_paths)
    http_rows = _json_rows(http_paths)
    certificates = [row for row in rows if row.get("mime_type") == _CERTIFICATE_MIME]
    non_certificates = [row for row in rows if row.get("mime_type") != _CERTIFICATE_MIME]

    non_certificate_uids = {
        str(uid)
        for row in non_certificates
        for uid in (row.get("conn_uids") or [])
        if uid
    }
    filename_basenames = {
        _windows_basename(str(row.get("filename") or ""))
        for row in non_certificates
        if row.get("filename")
    }
    uri_basenames = {
        _uri_basename(str(row.get("uri") or ""))
        for row in http_rows
        if row.get("uid") in non_certificate_uids and row.get("uri")
    }
    filename_basenames.discard("")
    uri_basenames.discard("")

    measurement = {
        "files_log_paths": len(files_paths),
        "http_log_paths": len(http_paths),
        "rows": len(rows),
        "certificate_rows": len(certificates),
        "non_certificate_rows": len(non_certificates),
        "hashes": _digest_counts(rows),
        "non_certificate_hashes": _digest_counts(non_certificates),
        "distinct_non_certificate_filename_basenames": len(filename_basenames),
        "distinct_non_certificate_http_uri_basenames": len(uri_basenames),
    }
    working = {
        "rows": rows,
        "non_certificates": non_certificates,
        "filename_basenames": filename_basenames,
        "uri_basenames": uri_basenames,
    }
    return measurement, working


def analyze_output(run_root: str | Path) -> dict[str, Any]:
    """Measure one completed EvidenceForge output tree."""

    root = Path(run_root)
    if not (root / "data").is_dir():
        raise ValueError(f"not an EvidenceForge output root (missing data/): {root}")

    sysmon, sysmon_working = _sysmon_measurement(root)
    zeek, zeek_working = _zeek_measurement(root)
    sysmon_records = sysmon_working["records"]
    event_id_1 = sysmon_working["event_id_1"]
    zeek_rows = zeek_working["rows"]
    non_certificates = zeek_working["non_certificates"]

    def values(records: list[dict[str, Any]], algorithm: str, *, sysmon_rows: bool) -> set[str]:
        if sysmon_rows:
            return {
                row["hashes"][algorithm]
                for row in records
                if row["hashes"].get(algorithm)
            }
        return {str(row[algorithm]).lower() for row in records if row.get(algorithm)}

    same_algorithm: dict[str, int] = {}
    eid1_to_all: dict[str, int] = {}
    eid1_to_non_certificate: dict[str, int] = {}
    for algorithm in _ALGORITHMS:
        all_sysmon = values(sysmon_records, algorithm, sysmon_rows=True)
        eid1_sysmon = values(event_id_1, algorithm, sysmon_rows=True)
        all_zeek = values(zeek_rows, algorithm, sysmon_rows=False)
        non_certificate_zeek = values(non_certificates, algorithm, sysmon_rows=False)
        same_algorithm[algorithm] = len(all_sysmon & all_zeek)
        eid1_to_all[algorithm] = len(eid1_sysmon & all_zeek)
        eid1_to_non_certificate[algorithm] = len(eid1_sysmon & non_certificate_zeek)

    any_sysmon_digest = set().union(
        *(values(sysmon_records, algorithm, sysmon_rows=True) for algorithm in _ALGORITHMS)
    )
    any_zeek_digest = set().union(
        *(values(zeek_rows, algorithm, sysmon_rows=False) for algorithm in _ALGORITHMS)
    )
    event_id_1_basenames = sysmon_working["event_id_1_basenames"]
    filename_overlap = sorted(event_id_1_basenames & zeek_working["filename_basenames"])
    uri_overlap = sorted(event_id_1_basenames & zeek_working["uri_basenames"])

    return {
        "sysmon": sysmon,
        "artifactforge_adapter_verification": _adapter_verification(root),
        "zeek_files": zeek,
        "intersections": {
            "same_algorithm_all_sysmon_to_all_zeek": same_algorithm,
            "same_algorithm_event_id_1_to_all_zeek": eid1_to_all,
            "same_algorithm_event_id_1_to_non_certificate_zeek": eid1_to_non_certificate,
            "any_digest_algorithm_all_sysmon_to_all_zeek": len(
                any_sysmon_digest & any_zeek_digest
            ),
            "event_id_1_image_to_non_certificate_filename_basenames": {
                "count": len(filename_overlap),
                "values": filename_overlap,
            },
            "event_id_1_image_to_non_certificate_http_uri_basenames": {
                "count": len(uri_overlap),
                "values": uri_overlap,
            },
        },
    }


def build_record(
    run_root: str | Path,
    scenario_path: str | Path,
    *,
    evidenceforge_version: str,
    evidenceforge_commit: str,
) -> dict[str, Any]:
    """Build a pinned record from an explicit producer attestation and exact output tree."""

    # Validate producer arguments before reading the scenario or output.  A wrong producer must
    # never inherit the pinned constants from a pre-existing record or a default argument.
    generator = _validated_pinned_producer(evidenceforge_version, evidenceforge_commit)
    scenario = _scenario_metadata(Path(scenario_path))
    if scenario != PINNED_SCENARIO:
        raise ValueError(
            "scenario is not the unmodified pinned branch-office example: "
            f"expected {PINNED_SCENARIO}, got {scenario}"
        )

    root = Path(run_root)
    output_tree = output_tree_inventory(root)
    results = analyze_output(root)
    intersections = results["intersections"]
    filename_count = intersections[
        "event_id_1_image_to_non_certificate_filename_basenames"
    ]["count"]
    uri_count = intersections[
        "event_id_1_image_to_non_certificate_http_uri_basenames"
    ]["count"]
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": "evidenceforge-v1.13.1-branch-office-example-full",
        "method": {
            "name": "artifactforge-evidenceforge-hash-surface",
            "version": METHOD_VERSION,
            "script": "scripts/measure_evidenceforge.py",
            "network_required": False,
        },
        "provenance": {
            "evidenceforge": generator,
            "producer_attestation": {
                "source": "required CLI arguments",
                "pin_validation": "exact version and git commit match",
                "automatically_detected_from_output": False,
                "bound_output_tree_sha256": output_tree["tree_sha256"],
                "limitation": (
                    "The serialized output has no producer-commit field. This record binds an "
                    "explicit external attestation to the exact measured bytes; it does not "
                    "independently infer the producer commit from those bytes."
                ),
            },
            "scenario": scenario,
            "generation_command_template": (
                "python -m evidenceforge generate "
                "scenarios/branch-office-example/scenario.yaml -o out"
            ),
            "scenario_input_modified": False,
            "output_tree": output_tree,
        },
        "results": results,
        "qualification": {
            "positive_same_file_pair_demonstrated": False,
            "serialized_transfer_to_execution_identity_field": None,
            "basis": [
                f"EID1 image/non-certificate Zeek filename basename overlaps: {filename_count}",
                f"EID1 image/non-certificate HTTP URI basename overlaps: {uri_count}",
                "The serialized logs expose no explicit transfer-to-execution content identity.",
            ],
            "claim_boundary": (
                "The disjoint hash sets establish that this stock run has no hash join. "
                "They do not, by themselves, establish that two records for a known-identical "
                "file carry different hashes, because the run demonstrates no positive "
                "transfer-to-execution same-file pair."
            ),
        },
    }
    validate_record(record)
    return record


def _expect(mapping: dict[str, Any], key: str, expected_type: type, path: str) -> Any:
    if key not in mapping:
        raise ValueError(f"measurement record is missing {path}.{key}")
    value = mapping[key]
    if not isinstance(value, expected_type):
        raise ValueError(
            f"measurement record field {path}.{key} must be {expected_type.__name__}"
        )
    return value


def _validate_output_tree(inventory: dict[str, Any]) -> None:
    files = _expect(inventory, "files", list, "provenance.output_tree")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"output inventory entry {index} must be an object")
        path = _expect(item, "path", str, f"provenance.output_tree.files[{index}]")
        size = item.get("size")
        sha256 = item.get("sha256")
        pure_path = PurePosixPath(path)
        if (
            not path
            or pure_path.is_absolute()
            or ".." in pure_path.parts
            or pure_path.as_posix() != path
            or path in seen
        ):
            raise ValueError(f"invalid or duplicate output inventory path: {path!r}")
        if type(size) is not int or size < 0:
            raise ValueError(f"invalid output inventory size for {path!r}: {size!r}")
        if not isinstance(sha256, str) or _SHA256_HEX.fullmatch(sha256) is None:
            raise ValueError(f"invalid output inventory SHA256 for {path!r}: {sha256!r}")
        seen.add(path)
        normalized.append({"path": path, "size": size, "sha256": sha256})

    if normalized != sorted(normalized, key=lambda item: item["path"]):
        raise ValueError("output inventory paths must be sorted")
    if inventory.get("canonicalization") != "artifactforge-output-tree-v1":
        raise ValueError("unsupported output-tree canonicalization")
    if inventory.get("file_count") != len(normalized):
        raise ValueError("output inventory file count does not add up")
    if inventory.get("total_bytes") != sum(item["size"] for item in normalized):
        raise ValueError("output inventory byte count does not add up")
    expected_tree_sha256 = hashlib.sha256(_canonical_inventory_bytes(normalized)).hexdigest()
    if inventory.get("tree_sha256") != expected_tree_sha256:
        raise ValueError("output inventory tree SHA256 does not match its file entries")


def validate_record(record: dict[str, Any]) -> None:
    """Validate the measurement schema and its internal arithmetic."""

    if not isinstance(record, dict):
        raise ValueError("measurement record must be a JSON object")
    if record.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported measurement schema: {record.get('schema_version')!r}")

    method = _expect(record, "method", dict, "record")
    provenance = _expect(record, "provenance", dict, "record")
    results = _expect(record, "results", dict, "record")
    qualification = _expect(record, "qualification", dict, "record")
    _expect(method, "script", str, "method")
    generator = _expect(provenance, "evidenceforge", dict, "provenance")
    producer_attestation = _expect(provenance, "producer_attestation", dict, "provenance")
    scenario = _expect(provenance, "scenario", dict, "provenance")
    output_tree = _expect(provenance, "output_tree", dict, "provenance")
    sysmon = _expect(results, "sysmon", dict, "results")
    adapter = _expect(results, "artifactforge_adapter_verification", dict, "results")
    zeek = _expect(results, "zeek_files", dict, "results")
    intersections = _expect(results, "intersections", dict, "results")

    if generator != PINNED_EVIDENCEFORGE:
        raise ValueError("record does not identify the pinned EvidenceForge release")
    if scenario != PINNED_SCENARIO:
        raise ValueError("record does not identify the unmodified pinned scenario")
    if provenance.get("scenario_input_modified") is not False:
        raise ValueError("pinned record must state that the scenario input was unmodified")
    if producer_attestation.get("source") != "required CLI arguments":
        raise ValueError("pinned record must identify its external producer-attestation source")
    if producer_attestation.get("pin_validation") != "exact version and git commit match":
        raise ValueError("pinned record must state the producer pin validation performed")
    if producer_attestation.get("automatically_detected_from_output") is not False:
        raise ValueError("external producer provenance must not claim output auto-detection")
    if not producer_attestation.get("limitation"):
        raise ValueError("external producer attestation must state its limitation")
    _validate_output_tree(output_tree)
    if producer_attestation.get("bound_output_tree_sha256") != output_tree.get("tree_sha256"):
        raise ValueError("producer attestation is not bound to the recorded output tree")

    eid1 = _expect(sysmon, "event_id_1", dict, "results.sysmon")
    eid7 = _expect(sysmon, "event_id_7", dict, "results.sysmon")
    if sysmon.get("population_definition") != (
        "Sysmon EID1/EID7 with non-empty image and SHA256"
    ):
        raise ValueError("Sysmon population definition must be explicit and verifiable")
    if sysmon.get("hashed_records") != eid1.get("hashed_records", 0) + eid7.get(
        "hashed_records", 0
    ):
        raise ValueError("Sysmon EID1 and EID7 counts do not add up to all hashed records")
    if zeek.get("rows") != zeek.get("certificate_rows", 0) + zeek.get(
        "non_certificate_rows", 0
    ):
        raise ValueError("Zeek certificate and non-certificate counts do not add up")

    if adapter.get("records_with_sha256_and_image") != sysmon.get("hashed_records"):
        raise ValueError("adapter and raw parser disagree on hashed Sysmon record count")
    if adapter.get("records_recovered_and_verified") + adapter.get(
        "unrecovered_records", 0
    ) != adapter.get("records_with_sha256_and_image"):
        raise ValueError("adapter recovered/unrecovered counts do not add up")
    records_by_form = _expect(
        adapter,
        "verified_records_by_seed_form",
        dict,
        "results.artifactforge_adapter_verification",
    )
    identities_by_form = _expect(
        adapter,
        "distinct_logical_identities_by_verified_seed_form",
        dict,
        "results.artifactforge_adapter_verification",
    )
    if set(records_by_form) != set(_SEED_FORMS) or set(identities_by_form) != set(_SEED_FORMS):
        raise ValueError(f"adapter seed-form counts must contain exactly {_SEED_FORMS}")
    if sum(records_by_form.values()) != adapter.get("records_recovered_and_verified"):
        raise ValueError("adapter verified seed-form record counts do not add up")
    if sum(identities_by_form.values()) != adapter.get("distinct_logical_identities"):
        raise ValueError("adapter verified seed-form identity counts do not add up")

    for key in (
        "same_algorithm_all_sysmon_to_all_zeek",
        "same_algorithm_event_id_1_to_all_zeek",
        "same_algorithm_event_id_1_to_non_certificate_zeek",
    ):
        values_by_algorithm = _expect(intersections, key, dict, "results.intersections")
        if set(values_by_algorithm) != set(_ALGORITHMS):
            raise ValueError(f"{key} must contain exactly {_ALGORITHMS}")
        if any(not isinstance(value, int) or value < 0 for value in values_by_algorithm.values()):
            raise ValueError(f"{key} contains an invalid intersection count")

    if qualification.get("positive_same_file_pair_demonstrated") is not False:
        raise ValueError("stock-run record must preserve the no-positive-pair qualification")
    if not qualification.get("claim_boundary"):
        raise ValueError("measurement record must state its claim boundary")


def verify_output_binding(record: dict[str, Any], run_root: str | Path) -> None:
    """Verify both the exact output bytes and the measurements derived from them."""

    validate_record(record)
    expected_inventory = record["provenance"]["output_tree"]
    actual_inventory = output_tree_inventory(run_root)
    if actual_inventory != expected_inventory:
        raise ValueError(
            "output tree does not match the record: expected "
            f"{expected_inventory['tree_sha256']}, got {actual_inventory['tree_sha256']}"
        )
    actual_results = analyze_output(run_root)
    if actual_results != record["results"]:
        raise ValueError("output tree bytes match, but derived measurement results do not")


def prose_facts(record: dict[str, Any]) -> dict[str, int]:
    """Return the stable public figures that prose may source from this record."""

    validate_record(record)
    sysmon = record["results"]["sysmon"]
    adapter = record["results"]["artifactforge_adapter_verification"]
    zeek = record["results"]["zeek_files"]
    intersections = record["results"]["intersections"]
    return {
        "sysmon_host_logs": sysmon["host_logs"],
        "sysmon_hashed_records": sysmon["hashed_records"],
        "sysmon_distinct_sha256": sysmon["distinct_hashes"]["sha256"],
        "sysmon_eid1_hashed_records": sysmon["event_id_1"]["hashed_records"],
        "sysmon_eid1_distinct_sha1": sysmon["event_id_1"]["distinct_hashes"]["sha1"],
        "adapter_records_recovered_and_verified": adapter["records_recovered_and_verified"],
        "adapter_distinct_logical_identities": adapter["distinct_logical_identities"],
        "adapter_from_host_metadata_identities": adapter[
            "distinct_logical_identities_by_verified_seed_form"
        ]["from_host_metadata"],
        "adapter_with_description_identities": adapter[
            "distinct_logical_identities_by_verified_seed_form"
        ]["with_description"],
        "zeek_files_rows": zeek["rows"],
        "zeek_certificate_rows": zeek["certificate_rows"],
        "zeek_non_certificate_rows": zeek["non_certificate_rows"],
        "zeek_distinct_sha1": zeek["hashes"]["sha1"]["distinct"],
        "zeek_distinct_sha256": zeek["hashes"]["sha256"]["distinct"],
        "sysmon_zeek_same_sha1_overlap": intersections[
            "same_algorithm_all_sysmon_to_all_zeek"
        ]["sha1"],
        "sysmon_zeek_same_sha256_overlap": intersections[
            "same_algorithm_all_sysmon_to_all_zeek"
        ]["sha256"],
    }


def render_markdown(record: dict[str, Any]) -> str:
    """Render the record's prose-facing facts without duplicating their values."""

    validate_record(record)
    facts = prose_facts(record)
    provenance = record["provenance"]
    scenario = provenance["scenario"]
    generator = provenance["evidenceforge"]
    qualification = record["qualification"]
    rows = [
        ("Sysmon host logs", facts["sysmon_host_logs"]),
        ("Sysmon hashed records", facts["sysmon_hashed_records"]),
        ("Distinct Sysmon SHA256", facts["sysmon_distinct_sha256"]),
        ("Sysmon EID1 hashed records", facts["sysmon_eid1_hashed_records"]),
        ("Distinct Sysmon EID1 SHA1", facts["sysmon_eid1_distinct_sha1"]),
        ("Adapter records recovered and verified", (
            f"{facts['adapter_records_recovered_and_verified']} / "
            f"{facts['sysmon_hashed_records']}"
        )),
        ("Adapter-verified distinct logical identities", (
            facts["adapter_distinct_logical_identities"]
        )),
        ("Verified identities: host-metadata / with-description", (
            f"{facts['adapter_from_host_metadata_identities']} / "
            f"{facts['adapter_with_description_identities']}"
        )),
        ("Zeek files rows", facts["zeek_files_rows"]),
        ("Zeek certificate / non-certificate rows", (
            f"{facts['zeek_certificate_rows']} / {facts['zeek_non_certificate_rows']}"
        )),
        ("Distinct Zeek SHA1 / SHA256", (
            f"{facts['zeek_distinct_sha1']} / {facts['zeek_distinct_sha256']}"
        )),
        ("Sysmon ∩ Zeek SHA1 / SHA256", (
            f"{facts['sysmon_zeek_same_sha1_overlap']} / "
            f"{facts['sysmon_zeek_same_sha256_overlap']}"
        )),
    ]
    lines = [
        f"### EvidenceForge {generator['tag']} — `{scenario['name']}`",
        "",
        (
            f"Pinned commit `{generator['git_commit']}`; unmodified scenario SHA256 "
            f"`{scenario['sha256']}`; duration `{scenario['duration']}`, warmup "
            f"`{scenario['warmup']}`."
        ),
        "",
        "| Measurement | Value |",
        "|---|---:|",
    ]
    lines.extend(f"| {label} | {value} |" for label, value in rows)
    lines.extend(["", f"Qualification: {qualification['claim_boundary']}"])
    return "\n".join(lines) + "\n"


def _load_record(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("measurement record must be a JSON object")
    return value


def _write_or_print(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    measure = subparsers.add_parser("measure", help="measure a completed output tree")
    measure.add_argument("run_root", type=Path)
    measure.add_argument("--scenario", required=True, type=Path)
    measure.add_argument(
        "--evidenceforge-version",
        required=True,
        help="explicit producer version attestation; pinned mode requires exactly 1.13.1",
    )
    measure.add_argument(
        "--evidenceforge-commit",
        required=True,
        help="explicit producer commit attestation; must exactly match the pinned commit",
    )
    measure.add_argument("--output", type=Path)

    render = subparsers.add_parser("render", help="render a record as Markdown")
    render.add_argument("record", type=Path)
    render.add_argument("--output", type=Path)

    check = subparsers.add_parser("check", help="validate a committed measurement record")
    check.add_argument("record", type=Path)
    check.add_argument(
        "--run-root",
        type=Path,
        help="also re-hash and re-measure this output tree against the record",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "measure":
            if args.output is not None:
                try:
                    args.output.resolve().relative_to(args.run_root.resolve())
                except ValueError:
                    pass
                else:
                    raise ValueError(
                        "measurement output must be outside the measured output tree"
                    )
            record = build_record(
                args.run_root,
                args.scenario,
                evidenceforge_version=args.evidenceforge_version,
                evidenceforge_commit=args.evidenceforge_commit,
            )
            _write_or_print(json.dumps(record, indent=2, sort_keys=True) + "\n", args.output)
        elif args.command == "render":
            _write_or_print(render_markdown(_load_record(args.record)), args.output)
        else:
            record = _load_record(args.record)
            validate_record(record)
            if args.run_root is not None:
                verify_output_binding(record, args.run_root)
            print(f"OK: {args.record}")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
