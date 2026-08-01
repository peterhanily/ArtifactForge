#!/usr/bin/env python3
# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Measure the controlled EvidenceForge transfer-to-execution hash witness.

This reads only serialized EvidenceForge output. It binds the exact output tree, proves the
modeled logical-file relation through canonical ground truth, follows Zeek's HTTP/files IDs,
selects the exact Sysmon EID 1 image, and verifies both upstream v1.13.1 seed formulas before
comparing their SHA1 values. It does not claim that EvidenceForge materialized common bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
METHOD_VERSION = 1
PINNED_EVIDENCEFORGE = {
    "version": "1.13.1",
    "tag": "v1.13.1",
    "git_commit": "c0c619992fa44418a20f9b7d9abbeae750695916",
}
PINNED_RUNTIME = {
    "python_version": "3.12.13",
    "constraints_repository_path": "integration/evidenceforge/constraints-v1.13.1.txt",
    "constraints_sha256": "bdfe9e7d6bb412657c33c0337578672b9bbde7a72782bd75be8b322446425b95",
    "upstream_uv_lock_sha256": ("77b8622fe284a3d50972fe3cf0395c5bf9360862f4df0f31c8fd8cc14b10d9ea"),
}
PINNED_SCENARIO = {
    "name": "content-identity-witness-v1-13-1",
    "repository_path": (
        "integration/evidenceforge/scenarios/content-identity-witness-v1.13.1.yaml"
    ),
    "git_blob_sha1": "27c238953bcbbf62fd28016aa11f3ca952a23a8b",
    "sha256": "9869c71144d43ed471588ce7e423eb5f4b092fcfc5fc17204ee9a63d5b57f2e5",
    "duration": "2h",
    "warmup": "1h",
}

CONTROL_STORYLINE = "controlled-download-execute"
CONTROL_URL = "http://203.0.113.10/af-controlled.exe"
CONTROL_PATH = r"C:\Windows\System32\af-controlled.exe"
CONTROL_SOURCE_IP = "192.0.2.10"
NEGATIVE_DOWNLOAD = "unrelated-download#0"
NEGATIVE_EXECUTION = "unrelated-execution#0"

_SCENARIO_NAME = re.compile(r"^name:\s*([^#\n]+?)\s*$", re.M)
_DURATION = re.compile(r'^\s+duration:\s*["\']?([^"\'\s#]+)', re.M)
_WARMUP = re.compile(r'^\s+warmup:\s*["\']?([^"\'\s#]+)', re.M)
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_GROUND_TRUTH = 8 * 1024 * 1024
_MAX_LOG = 64 * 1024 * 1024
_FRACTIONAL_SECONDS = re.compile(r"^(.*\.)(\d{6})\d+(Z|[+-]\d\d:\d\d)$")


def _bounded_bytes(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds {limit} bytes: {path} ({size} bytes)")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError(f"input changed while being read: {path}")
    return data


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def _canonical_inventory_bytes(files: list[dict[str, Any]]) -> bytes:
    payload = json.dumps(files, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return b"artifactforge-output-tree-v1\0" + payload.encode("utf-8")


def output_tree_inventory(run_root: str | Path) -> dict[str, Any]:
    """Bind every regular file by relative path, size and SHA256; reject symlinks."""

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


def _scenario_metadata(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")

    def required(pattern: re.Pattern[str], field: str) -> str:
        match = pattern.search(text)
        if match is None:
            raise ValueError(f"scenario has no parseable {field}: {path}")
        return match.group(1).strip().strip("\"'")

    return {
        "name": required(_SCENARIO_NAME, "name"),
        "repository_path": PINNED_SCENARIO["repository_path"],
        "git_blob_sha1": _git_blob_sha1(path),
        "sha256": _file_sha256(path),
        "duration": required(_DURATION, "duration"),
        "warmup": required(_WARMUP, "warmup"),
    }


def _validated_producer(version: str, git_commit: str) -> dict[str, str]:
    supplied = {"version": version.strip(), "git_commit": git_commit.strip().lower()}
    expected = {
        "version": PINNED_EVIDENCEFORGE["version"],
        "git_commit": PINNED_EVIDENCEFORGE["git_commit"],
    }
    if supplied != expected:
        raise ValueError(
            "producer attestation does not match pinned EvidenceForge: "
            f"expected {expected}, got {supplied}"
        )
    return dict(PINNED_EVIDENCEFORGE)


def _validated_runtime(python_version: str) -> dict[str, str]:
    if python_version.strip() != PINNED_RUNTIME["python_version"]:
        raise ValueError(
            "producer Python does not match the pinned runtime: "
            f"expected {PINNED_RUNTIME['python_version']}, got {python_version!r}"
        )
    constraints_path = (
        Path(__file__).resolve().parents[1] / PINNED_RUNTIME["constraints_repository_path"]
    )
    if _file_sha256(constraints_path) != PINNED_RUNTIME["constraints_sha256"]:
        raise ValueError("EvidenceForge constraint closure does not match its pinned SHA256")
    return dict(PINNED_RUNTIME)


def _object(path: Path, limit: int) -> dict[str, Any]:
    try:
        value = json.loads(_bounded_bytes(path, limit))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object in {path}")
    return value


def _json_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        text = _bounded_bytes(path, _MAX_LOG).decode("utf-8")
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"expected a JSON object at {path}:{line_number}")
            rows.append(value)
    return rows


def _only(values: list[Any], label: str) -> Any:
    if len(values) != 1:
        raise ValueError(f"expected exactly one {label}, found {len(values)}")
    return values[0]


def _parse_hashes(raw: str | None) -> dict[str, str]:
    values: dict[str, str] = {}
    for part in (raw or "").split(","):
        key, separator, value = part.partition("=")
        if separator and key.strip() and value.strip():
            values[key.strip().lower()] = value.strip().lower()
    return values


def _parse_time(value: Any, label: str) -> datetime:
    """Parse RFC 3339 timestamps, including Sysmon's seven fractional digits."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} has no timestamp")
    normalized = _FRACTIONAL_SECONDS.sub(r"\1\2\3", value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{label} has invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp has no UTC offset")
    return parsed.astimezone(timezone.utc)


def _epoch_seconds(value: Any, label: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{label} has no numeric epoch timestamp")
    result = float(value)
    if result <= 0:
        raise ValueError(f"{label} has an invalid epoch timestamp")
    return result


def _ground_truth_relation(root: Path) -> dict[str, Any]:
    document = _object(root / "GROUND_TRUTH.json", _MAX_GROUND_TRUTH)
    events = document.get("events")
    if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
        raise ValueError("GROUND_TRUTH.json events must be a list of objects")

    controlled = [item for item in events if item.get("storyline_id") == CONTROL_STORYLINE]
    if len(controlled) != 2:
        raise ValueError(f"expected two records in {CONTROL_STORYLINE!r}, found {len(controlled)}")
    controlled.sort(key=lambda item: str(item.get("record_id", "")))
    download, execution = controlled
    if [item.get("record_id") for item in controlled] != [
        f"{CONTROL_STORYLINE}#0",
        f"{CONTROL_STORYLINE}#1",
    ]:
        raise ValueError("controlled records do not retain their #0/#1 order")
    if any(item.get("kind") != "process" or item.get("emitted") is not True for item in controlled):
        raise ValueError("controlled ground-truth records must be emitted process records")
    if any(
        download.get(field) != execution.get(field)
        for field in ("storyline_id", "actor", "system", "activity")
    ):
        raise ValueError("controlled records do not belong to one actor/system/activity cluster")

    download_attributes = download.get("attributes")
    execution_attributes = execution.get("attributes")
    if not isinstance(download_attributes, dict) or not isinstance(execution_attributes, dict):
        raise ValueError("controlled records have no attribute objects")
    network_url = download_attributes.get("network_url")
    output_file = download_attributes.get("output_file")
    executed_image = execution_attributes.get("process_name")
    if (network_url, output_file, executed_image) != (CONTROL_URL, CONTROL_PATH, CONTROL_PATH):
        raise ValueError(
            "controlled relation changed: expected URL -> output path == executed image"
        )
    download_time = _parse_time(download.get("time"), "controlled download ground truth")
    execution_time = _parse_time(execution.get("time"), "controlled execution ground truth")
    if not download_time < execution_time:
        raise ValueError("controlled execution does not occur after the download")

    negative_download = _only(
        [item for item in events if item.get("record_id") == NEGATIVE_DOWNLOAD],
        NEGATIVE_DOWNLOAD,
    )
    negative_execution = _only(
        [item for item in events if item.get("record_id") == NEGATIVE_EXECUTION],
        NEGATIVE_EXECUTION,
    )
    negative_download_attributes = negative_download.get("attributes")
    negative_execution_attributes = negative_execution.get("attributes")
    if not isinstance(negative_download_attributes, dict) or not isinstance(
        negative_execution_attributes, dict
    ):
        raise ValueError("negative controls have no attribute objects")
    negative_output = negative_download_attributes.get("output_file")
    negative_url = negative_download_attributes.get("network_url")
    negative_image = negative_execution_attributes.get("process_name")
    if not all(
        isinstance(value, str) and value
        for value in (
            negative_output,
            negative_url,
            negative_image,
        )
    ):
        raise ValueError("negative controls have empty URL/path values")
    executed_images = {
        str(attributes["process_name"])
        for item in events
        if isinstance((attributes := item.get("attributes")), dict)
        and attributes.get("process_name")
        and not attributes.get("output_file")
    }
    output_files = {
        str(attributes["output_file"])
        for item in events
        if isinstance((attributes := item.get("attributes")), dict)
        and attributes.get("output_file")
    }
    if negative_output in executed_images:
        raise ValueError("transfer-only negative control is also executed")
    if negative_image in output_files:
        raise ValueError("process-only negative control is also a download output")
    if len({CONTROL_PATH, negative_output, negative_image}) != 3 or negative_url == CONTROL_URL:
        raise ValueError("negative controls are not distinct from the controlled relation")
    same_basename_decoy = (
        PureWindowsPath(negative_output).name.lower() == PureWindowsPath(CONTROL_PATH).name.lower()
        and negative_output.lower() != CONTROL_PATH.lower()
    )
    if not same_basename_decoy:
        raise ValueError("transfer negative is not a same-basename, different-path decoy")

    positive_pids = (download_attributes.get("pid"), execution_attributes.get("pid"))
    negative_pids = (
        negative_download_attributes.get("pid"),
        negative_execution_attributes.get("pid"),
    )
    if any(type(pid) is not int or pid <= 0 for pid in positive_pids + negative_pids):
        raise ValueError("controlled or negative ground-truth process has an invalid PID")
    if len(set(positive_pids + negative_pids)) != 4:
        raise ValueError("controlled and negative ground-truth PIDs are not distinct")
    if download.get("actor") != "SYSTEM" or download.get("system") != "WS-AF-01":
        raise ValueError("controlled relation is no longer the pinned SYSTEM/WS-AF-01 case")

    return {
        "storyline_id": CONTROL_STORYLINE,
        "download_record_id": download["record_id"],
        "execution_record_id": execution["record_id"],
        "network_url": network_url,
        "output_file": output_file,
        "executed_image": executed_image,
        "actor": download["actor"],
        "system": download["system"],
        "download_process_image": download_attributes.get("process_name"),
        "download_process_id": download_attributes.get("pid"),
        "execution_process_id": execution_attributes.get("pid"),
        "ground_truth_download_time": download["time"],
        "ground_truth_execution_time": execution["time"],
        "download_before_execution": True,
        "same_actor_system_activity_cluster": True,
        "output_path_equals_executed_image": True,
        "negative_controls": {
            "transfer_only_output": negative_output,
            "transfer_only_url": negative_url,
            "transfer_only_process_image": negative_download_attributes.get("process_name"),
            "transfer_only_process_id": negative_download_attributes.get("pid"),
            "transfer_only_output_not_executed": True,
            "transfer_only_same_basename_different_path": True,
            "process_only_image": negative_image,
            "process_only_process_id": negative_execution_attributes.get("pid"),
            "process_only_image_not_downloaded": True,
        },
    }


def _select_http_file_rows(root: Path, url: str) -> dict[str, Any]:
    """Select the HTTP/files pair without reading any digest field."""

    parsed = urlsplit(url)
    expected_host = parsed.hostname or ""
    expected_uri = parsed.path or "/"
    if parsed.query:
        expected_uri = f"{expected_uri}?{parsed.query}"

    data_root = root / "data"
    http_rows = _json_rows(sorted(data_root.glob("**/http.json")))
    files_rows = _json_rows(sorted(data_root.glob("**/files.json")))
    http = _only(
        [
            row
            for row in http_rows
            if row.get("host") == expected_host
            and row.get("uri") == expected_uri
            and row.get("method") == "GET"
            and row.get("status_code") == 200
            and row.get("id.orig_h") == CONTROL_SOURCE_IP
            and row.get("id.resp_h") == expected_host
        ],
        f"Zeek HTTP row for {url}",
    )
    uid = http.get("uid")
    fuids = http.get("resp_fuids")
    if not isinstance(uid, str) or not uid or not isinstance(fuids, list) or len(fuids) != 1:
        raise ValueError("controlled Zeek HTTP row has no unique uid/response fuid")
    fuid = fuids[0]
    file_row = _only(
        [
            row
            for row in files_rows
            if row.get("fuid") == fuid
            and row.get("conn_uids") == [uid]
            and row.get("tx_hosts") == [expected_host]
            and row.get("rx_hosts") == [CONTROL_SOURCE_IP]
        ],
        f"Zeek files row joined by uid={uid!r}, fuid={fuid!r}",
    )
    return {
        "http": http,
        "file": file_row,
        "host": expected_host,
        "source_ip": CONTROL_SOURCE_IP,
        "uri": expected_uri,
    }


def _http_file_observation(root: Path, url: str) -> dict[str, Any]:
    selected = _select_http_file_rows(root, url)
    http = selected["http"]
    file_row = selected["file"]
    expected_host = selected["host"]
    expected_uri = selected["uri"]
    uid = http["uid"]
    fuid = http["resp_fuids"][0]
    sha1 = str(file_row.get("sha1") or "").lower()
    if _SHA1.fullmatch(sha1) is None:
        raise ValueError("joined Zeek file row has no valid SHA1")
    if file_row.get("source") != "HTTP" or file_row.get("mime_type") == "application/pkix-cert":
        raise ValueError("joined Zeek file row is not a non-certificate HTTP response")
    response_body_len = http.get("response_body_len")
    mime_type = file_row.get("mime_type")
    if (
        type(response_body_len) is not int
        or response_body_len <= 0
        or not isinstance(mime_type, str)
    ):
        raise ValueError("joined Zeek rows have invalid response length or MIME type")
    if file_row.get("total_bytes") != response_body_len:
        raise ValueError("HTTP response length and files.log total_bytes disagree")
    if (
        file_row.get("seen_bytes") != response_body_len
        or file_row.get("missing_bytes") != 0
        or file_row.get("overflow_bytes") != 0
        or file_row.get("timedout") is not False
        or file_row.get("analyzers") != ["SHA1"]
    ):
        raise ValueError("joined Zeek file is not a complete SHA1-analyzed response")
    http_time = _epoch_seconds(http.get("ts"), "controlled Zeek HTTP row")
    file_time = _epoch_seconds(file_row.get("ts"), "controlled Zeek files row")
    if file_time < http_time:
        raise ValueError("Zeek files row predates its HTTP row")
    seed = f"http:{expected_host}:{expected_uri}:{response_body_len}:{mime_type}"
    if hashlib.sha1(seed.encode()).hexdigest() != sha1:
        raise ValueError("Zeek SHA1 does not match the pinned v1.13.1 HTTP content seed")
    return {
        "http_uid": uid,
        "file_fuid": fuid,
        "host": expected_host,
        "source_ip": selected["source_ip"],
        "response_ip": http["id.resp_h"],
        "transmitter_hosts": file_row["tx_hosts"],
        "receiver_hosts": file_row["rx_hosts"],
        "uri": expected_uri,
        "source": file_row["source"],
        "mime_type": mime_type,
        "response_body_len": response_body_len,
        "seen_bytes": file_row["seen_bytes"],
        "missing_bytes": file_row["missing_bytes"],
        "overflow_bytes": file_row["overflow_bytes"],
        "timedout": file_row["timedout"],
        "analyzers": file_row["analyzers"],
        "http_time_epoch": http_time,
        "file_time_epoch": file_time,
        "sha1": sha1,
        "seed_material": seed,
        "seed_formula_verified": True,
        "digest_blind_selection": True,
        "digest_fields_used_for_selection": [],
    }


def _sysmon_events(root: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in sorted((root / "data").glob("*/windows_event_sysmon.xml")):
        try:
            document = ET.fromstring(_bounded_bytes(path, _MAX_LOG))
        except ET.ParseError as exc:
            raise ValueError(f"invalid Sysmon XML in {path}: {exc}") from exc
        for event in document.findall("./{*}Event"):
            event_id = event.findtext("./{*}System/{*}EventID")
            time_node = event.find("./{*}System/{*}TimeCreated")
            fields = {
                str(node.get("Name")): node.text or ""
                for node in event.findall("./{*}EventData/{*}Data")
                if node.get("Name")
            }
            if not isinstance(event_id, str) or not event_id.isdigit() or time_node is None:
                raise ValueError(f"Sysmon event has an invalid ID/time in {path}")
            raw_time = time_node.get("SystemTime")
            parsed_time = _parse_time(raw_time, f"Sysmon EID {event_id}")
            events.append(
                {
                    "path": path,
                    "event_id": int(event_id),
                    "time": raw_time,
                    "time_epoch": parsed_time.timestamp(),
                    "fields": fields,
                }
            )
    if not events:
        raise ValueError("output contains no Sysmon events")
    return events


def _select_sysmon_chain(root: Path, relation: dict[str, Any]) -> dict[str, Any]:
    """Select process/create/process events by identity fields, never by Hashes."""

    events = _sysmon_events(root)
    download_image = str(relation["download_process_image"])
    download_pid = str(relation["download_process_id"])
    executed_image = str(relation["executed_image"])
    execution_pid = str(relation["execution_process_id"])
    output_file = str(relation["output_file"])
    downloader = _only(
        [
            event
            for event in events
            if event["event_id"] == 1
            and event["fields"].get("Image") == download_image
            and event["fields"].get("ProcessId") == download_pid
        ],
        "controlled downloader Sysmon EID 1",
    )
    file_create = _only(
        [
            event
            for event in events
            if event["event_id"] == 11
            and event["fields"].get("Image") == download_image
            and event["fields"].get("ProcessId") == download_pid
            and event["fields"].get("TargetFilename") == output_file
        ],
        "controlled output Sysmon EID 11",
    )
    target = _only(
        [
            event
            for event in events
            if event["event_id"] == 1
            and event["fields"].get("Image") == executed_image
            and event["fields"].get("ProcessId") == execution_pid
        ],
        "controlled target Sysmon EID 1",
    )
    download_guid = downloader["fields"].get("ProcessGuid")
    if not download_guid or file_create["fields"].get("ProcessGuid") != download_guid:
        raise ValueError("downloader EID 1 and file-create EID 11 do not share ProcessGuid")
    target_guid = target["fields"].get("ProcessGuid")
    if not target_guid or target_guid == download_guid:
        raise ValueError("target EID 1 has no distinct ProcessGuid")
    if any(event["path"] != target["path"] for event in (downloader, file_create)):
        raise ValueError("controlled Sysmon chain does not come from one host log")
    expected_host_prefix = f"{relation['system']}."
    if not target["path"].parent.name.startswith(expected_host_prefix):
        raise ValueError("controlled Sysmon host log does not match ground truth")
    if any(
        event["fields"].get("User") != r"NT AUTHORITY\SYSTEM"
        for event in (
            downloader,
            file_create,
            target,
        )
    ):
        raise ValueError("controlled Sysmon chain is not attributed to SYSTEM")
    return {"downloader": downloader, "file_create": file_create, "target": target}


def _sysmon_observation(root: Path, relation: dict[str, Any]) -> dict[str, Any]:
    selected = _select_sysmon_chain(root, relation)
    candidate = selected["target"]
    fields = candidate["fields"]
    image = str(relation["executed_image"])
    hashes = _parse_hashes(fields.get("Hashes"))
    sha1 = hashes.get("sha1", "")
    sha256 = hashes.get("sha256", "")
    if _SHA1.fullmatch(sha1) is None or _SHA256.fullmatch(sha256) is None:
        raise ValueError("controlled Sysmon event has invalid SHA1/SHA256")
    normalized_image = image.replace("/", "\\").lower()
    metadata = [
        fields.get("FileVersion", ""),
        fields.get("Product", ""),
        fields.get("Company", ""),
        fields.get("OriginalFileName", ""),
    ]
    if any(not value for value in metadata):
        raise ValueError("controlled Sysmon event omits seed-bearing PE metadata")
    seed = f"{normalized_image}:{':'.join(metadata)}"
    if hashlib.sha1(seed.encode()).hexdigest() != sha1:
        raise ValueError("Sysmon SHA1 does not match the pinned v1.13.1 host-metadata seed")
    return {
        "host_log": candidate["path"].relative_to(root).as_posix(),
        "downloader_event_id": selected["downloader"]["event_id"],
        "downloader_image": selected["downloader"]["fields"]["Image"],
        "downloader_process_id": int(selected["downloader"]["fields"]["ProcessId"]),
        "downloader_process_guid": selected["downloader"]["fields"]["ProcessGuid"],
        "downloader_time": selected["downloader"]["time"],
        "file_create_event_id": selected["file_create"]["event_id"],
        "file_create_target": selected["file_create"]["fields"]["TargetFilename"],
        "file_create_process_id": int(selected["file_create"]["fields"]["ProcessId"]),
        "file_create_process_guid": selected["file_create"]["fields"]["ProcessGuid"],
        "file_create_time": selected["file_create"]["time"],
        "target_event_id": candidate["event_id"],
        "target_image": image,
        "target_process_id": int(fields["ProcessId"]),
        "target_process_guid": fields["ProcessGuid"],
        "target_time": candidate["time"],
        "sha1": sha1,
        "sha256": sha256,
        "seed_material": seed,
        "seed_formula_verified": True,
        "digest_blind_selection": True,
        "digest_fields_used_for_selection": [],
    }


def _negative_sysmon_controls(root: Path, relation: dict[str, Any]) -> dict[str, Any]:
    events = _sysmon_events(root)
    controls = relation["negative_controls"]
    transfer_pid = str(controls["transfer_only_process_id"])
    transfer_image = str(controls["transfer_only_process_image"])
    transfer_output = str(controls["transfer_only_output"])
    process_pid = str(controls["process_only_process_id"])
    process_image = str(controls["process_only_image"])
    transfer_process = _only(
        [
            event
            for event in events
            if event["event_id"] == 1
            and event["fields"].get("Image") == transfer_image
            and event["fields"].get("ProcessId") == transfer_pid
        ],
        "transfer-only downloader Sysmon EID 1",
    )
    transfer_create = _only(
        [
            event
            for event in events
            if event["event_id"] == 11
            and event["fields"].get("Image") == transfer_image
            and event["fields"].get("ProcessId") == transfer_pid
            and event["fields"].get("TargetFilename") == transfer_output
        ],
        "transfer-only file-create Sysmon EID 11",
    )
    if transfer_process["fields"].get("ProcessGuid") != transfer_create["fields"].get(
        "ProcessGuid"
    ):
        raise ValueError("transfer-only Sysmon process/create GUIDs differ")
    if any(
        event["event_id"] == 1 and event["fields"].get("Image") == transfer_output
        for event in events
    ):
        raise ValueError("transfer-only output appears as a Sysmon process image")
    _only(
        [
            event
            for event in events
            if event["event_id"] == 1
            and event["fields"].get("Image") == process_image
            and event["fields"].get("ProcessId") == process_pid
        ],
        "process-only Sysmon EID 1",
    )
    if any(
        event["event_id"] == 11 and event["fields"].get("TargetFilename") == process_image
        for event in events
    ):
        raise ValueError("process-only image appears as a Sysmon file-create target")
    return {
        "transfer_only_file_create_observed": True,
        "transfer_only_execution_absent": True,
        "transfer_only_process_guid": transfer_process["fields"]["ProcessGuid"],
        "process_only_execution_observed": True,
        "process_only_file_create_absent": True,
        "digest_blind_selection": True,
    }


def analyze_output(run_root: str | Path) -> dict[str, Any]:
    root = Path(run_root)
    if not (root / "data").is_dir():
        raise ValueError(f"not an EvidenceForge output root (missing data/): {root}")
    relation = _ground_truth_relation(root)
    zeek = _http_file_observation(root, str(relation["network_url"]))
    sysmon = _sysmon_observation(root, relation)
    negative_zeek = _http_file_observation(
        root, str(relation["negative_controls"]["transfer_only_url"])
    )
    negative_sysmon = _negative_sysmon_controls(root, relation)
    if negative_zeek["file_fuid"] == zeek["file_fuid"] or negative_zeek["sha1"] == zeek["sha1"]:
        raise ValueError("transfer negative control collapsed onto the controlled Zeek file")
    if zeek["sha1"] == sysmon["sha1"]:
        raise ValueError(
            "controlled SHA1 values unexpectedly join; this is no longer a red witness"
        )

    materialized_names = [
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.name.lower() == PureWindowsPath(str(relation["output_file"])).name.lower()
    ]
    if materialized_names:
        raise ValueError(
            f"output unexpectedly materializes controlled filename: {materialized_names}"
        )

    timeline = [
        (
            "ground_truth_download",
            _parse_time(
                relation["ground_truth_download_time"], "ground-truth download"
            ).timestamp(),
        ),
        (
            "sysmon_downloader_eid1",
            _parse_time(sysmon["downloader_time"], "downloader EID 1").timestamp(),
        ),
        ("zeek_http", zeek["http_time_epoch"]),
        ("zeek_files", zeek["file_time_epoch"]),
        (
            "sysmon_file_create_eid11",
            _parse_time(sysmon["file_create_time"], "file-create EID 11").timestamp(),
        ),
        (
            "ground_truth_execution",
            _parse_time(
                relation["ground_truth_execution_time"], "ground-truth execution"
            ).timestamp(),
        ),
        ("sysmon_target_eid1", _parse_time(sysmon["target_time"], "target EID 1").timestamp()),
    ]
    if any(later[1] < earlier[1] for earlier, later in zip(timeline, timeline[1:])):
        raise ValueError(f"controlled event timeline is out of order: {timeline}")
    if timeline[-1][1] - timeline[-2][1] > 5:
        raise ValueError("target Sysmon EID 1 is too far from ground-truth execution time")
    return {
        "relation": relation,
        "zeek_file": zeek,
        "sysmon_process": sysmon,
        "cross_emitter_join": {
            "algorithm": "sha1",
            "zeek_sha1": zeek["sha1"],
            "sysmon_sha1": sysmon["sha1"],
            "equal": False,
        },
        "timeline": {
            "ordered": True,
            "sequence": [label for label, _ in timeline],
            "epoch_seconds": {label: value for label, value in timeline},
        },
        "negative_controls": {
            "zeek_file": negative_zeek,
            "sysmon": negative_sysmon,
            "same_basename_different_path": True,
            "materialized_controlled_filename_present": False,
        },
        "pair_selection": {
            "digest_blind": True,
            "digest_fields_used": [],
            "ground_truth_keys": [
                "storyline_id",
                "record_id",
                "actor",
                "system",
                "network_url",
                "output_file",
                "process_name",
                "pid",
            ],
            "zeek_keys": [
                "id.orig_h",
                "id.resp_h",
                "host",
                "uri",
                "method",
                "status_code",
                "uid",
                "fuid",
                "tx_hosts",
                "rx_hosts",
            ],
            "sysmon_keys": [
                "EventID",
                "Image",
                "ProcessId",
                "ProcessGuid",
                "TargetFilename",
                "User",
            ],
        },
    }


def build_record(
    run_root: str | Path,
    scenario_path: str | Path,
    *,
    evidenceforge_version: str,
    evidenceforge_commit: str,
    python_version: str,
) -> dict[str, Any]:
    producer = _validated_producer(evidenceforge_version, evidenceforge_commit)
    runtime = _validated_runtime(python_version)
    scenario = _scenario_metadata(Path(scenario_path))
    if scenario != PINNED_SCENARIO:
        raise ValueError(
            "scenario is not the exact committed controlled fixture: "
            f"expected {PINNED_SCENARIO}, got {scenario}"
        )
    inventory = output_tree_inventory(run_root)
    witness = analyze_output(run_root)
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": "evidenceforge-v1.13.1-controlled-content-identity-witness",
        "method": {
            "name": "artifactforge-evidenceforge-controlled-hash-witness",
            "version": METHOD_VERSION,
            "script": "scripts/measure_evidenceforge_witness.py",
            "network_required": False,
        },
        "provenance": {
            "evidenceforge": producer,
            "generation_runtime": runtime,
            "producer_attestation": {
                "source": "required CLI arguments",
                "pin_validation": "exact version and git commit match",
                "automatically_detected_from_output": False,
                "bound_output_tree_sha256": inventory["tree_sha256"],
                "limitation": (
                    "EvidenceForge output has no producer-commit field. The explicit external "
                    "attestation is bound to these exact output bytes."
                ),
            },
            "scenario": scenario,
            "scenario_fixture_unmodified": True,
            "generation_command_template": (
                "python -m evidenceforge generate "
                "integration/evidenceforge/scenarios/"
                "content-identity-witness-v1.13.1.yaml -o out"
            ),
            "output_tree": inventory,
        },
        "witness": witness,
        "qualification": {
            "positive_same_logical_file_pair_demonstrated": True,
            "shared_materialized_bytes_demonstrated": False,
            "serialized_cross_event_content_identity_field": None,
            "basis": [
                "One ground-truth storyline cluster writes an HTTP response to output_file.",
                "The next record in that cluster executes process_name == output_file.",
                "Zeek files.log is joined to the exact HTTP row by conn UID and response FUID.",
                "Sysmon downloader EID 1 and file-create EID 11 join by PID and ProcessGuid.",
                "The executed-image EID 1 is selected by exact path and ground-truth PID.",
                "Both emitted SHA1 values reproduce their distinct v1.13.1 seed formulas.",
                "Pair selection never reads a digest field.",
                "Transfer-only, process-only, and same-basename records are negative controls.",
            ],
            "claim_boundary": (
                "This proves one modeled logical file receives different SHA1 values across "
                "Zeek and Sysmon in unmodified EvidenceForge v1.13.1. It does not prove two "
                "digests disagree over shared materialized bytes, because EvidenceForge emits "
                "logs and does not materialize the transferred/executed file. Whether the "
                "logical-file join is required remains an upstream design decision."
            ),
        },
    }
    validate_record(record)
    return record


def _expect(mapping: dict[str, Any], key: str, expected: type, path: str) -> Any:
    value = mapping.get(key)
    if not isinstance(value, expected):
        raise ValueError(f"{path}.{key} must be {expected.__name__}")
    return value


def _validate_inventory(inventory: dict[str, Any]) -> None:
    files = _expect(inventory, "files", list, "provenance.output_tree")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"output inventory entry {index} must be an object")
        path = item.get("path")
        size = item.get("size")
        sha256 = item.get("sha256")
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if (
            not isinstance(path, str)
            or not path
            or pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != path
            or path in seen
        ):
            raise ValueError(f"invalid or duplicate inventory path: {path!r}")
        if type(size) is not int or size < 0:
            raise ValueError(f"invalid inventory size for {path!r}")
        if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
            raise ValueError(f"invalid inventory SHA256 for {path!r}")
        seen.add(path)
        normalized.append({"path": path, "size": size, "sha256": sha256})
    if normalized != sorted(normalized, key=lambda item: item["path"]):
        raise ValueError("output inventory paths are not sorted")
    if inventory.get("canonicalization") != "artifactforge-output-tree-v1":
        raise ValueError("unsupported output-tree canonicalization")
    if inventory.get("file_count") != len(normalized):
        raise ValueError("output inventory file count does not add up")
    if inventory.get("total_bytes") != sum(item["size"] for item in normalized):
        raise ValueError("output inventory byte count does not add up")
    digest = hashlib.sha256(_canonical_inventory_bytes(normalized)).hexdigest()
    if inventory.get("tree_sha256") != digest:
        raise ValueError("output inventory tree SHA256 does not match its entries")


def validate_record(record: dict[str, Any]) -> None:
    if record.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported witness schema")
    if record.get("record_id") != "evidenceforge-v1.13.1-controlled-content-identity-witness":
        raise ValueError("unexpected witness record ID")
    if record.get("method") != {
        "name": "artifactforge-evidenceforge-controlled-hash-witness",
        "version": METHOD_VERSION,
        "script": "scripts/measure_evidenceforge_witness.py",
        "network_required": False,
    }:
        raise ValueError("unexpected witness method declaration")
    provenance = _expect(record, "provenance", dict, "record")
    witness = _expect(record, "witness", dict, "record")
    qualification = _expect(record, "qualification", dict, "record")
    if provenance.get("evidenceforge") != PINNED_EVIDENCEFORGE:
        raise ValueError("record does not identify pinned EvidenceForge")
    if provenance.get("generation_runtime") != PINNED_RUNTIME:
        raise ValueError("record does not identify the pinned generation runtime")
    if provenance.get("scenario") != PINNED_SCENARIO:
        raise ValueError("record does not identify the exact controlled scenario")
    if provenance.get("scenario_fixture_unmodified") is not True:
        raise ValueError("record does not attest the committed scenario fixture")
    inventory = _expect(provenance, "output_tree", dict, "provenance")
    _validate_inventory(inventory)
    attestation = _expect(provenance, "producer_attestation", dict, "provenance")
    if attestation.get("bound_output_tree_sha256") != inventory.get("tree_sha256"):
        raise ValueError("producer attestation is not bound to the output tree")
    if (
        attestation.get("source") != "required CLI arguments"
        or attestation.get("pin_validation") != "exact version and git commit match"
        or attestation.get("automatically_detected_from_output") is not False
    ):
        raise ValueError("producer attestation method changed")

    relation = _expect(witness, "relation", dict, "witness")
    zeek = _expect(witness, "zeek_file", dict, "witness")
    sysmon = _expect(witness, "sysmon_process", dict, "witness")
    join = _expect(witness, "cross_emitter_join", dict, "witness")
    timeline = _expect(witness, "timeline", dict, "witness")
    witness_controls = _expect(witness, "negative_controls", dict, "witness")
    pair_selection = _expect(witness, "pair_selection", dict, "witness")
    controls = _expect(relation, "negative_controls", dict, "witness.relation")
    if relation.get("storyline_id") != CONTROL_STORYLINE:
        raise ValueError("witness lost the controlled storyline")
    if not all(
        relation.get(key) is True
        for key in (
            "download_before_execution",
            "same_actor_system_activity_cluster",
            "output_path_equals_executed_image",
        )
    ):
        raise ValueError("witness lost a causal relation check")
    if relation.get("network_url") != CONTROL_URL:
        raise ValueError("witness URL changed")
    if (
        relation.get("output_file") != CONTROL_PATH
        or relation.get("executed_image") != CONTROL_PATH
    ):
        raise ValueError("witness output/execution path relation changed")
    if relation.get("actor") != "SYSTEM" or relation.get("system") != "WS-AF-01":
        raise ValueError("witness actor/system changed")
    if any(
        type(relation.get(key)) is not int or relation[key] <= 0
        for key in (
            "download_process_id",
            "execution_process_id",
        )
    ):
        raise ValueError("witness ground-truth PIDs are invalid")
    if not all(
        controls.get(key) is True
        for key in (
            "transfer_only_output_not_executed",
            "transfer_only_same_basename_different_path",
            "process_only_image_not_downloaded",
        )
    ):
        raise ValueError("witness negative controls are not satisfied")
    if (
        PureWindowsPath(str(controls.get("transfer_only_output"))).name.lower()
        != PureWindowsPath(CONTROL_PATH).name.lower()
        or str(controls.get("transfer_only_output")).lower() == CONTROL_PATH.lower()
    ):
        raise ValueError("serialized transfer control is not a same-basename path decoy")

    for observation, label in ((zeek, "Zeek"), (sysmon, "Sysmon")):
        sha1 = observation.get("sha1")
        seed = observation.get("seed_material")
        if not isinstance(sha1, str) or _SHA1.fullmatch(sha1) is None:
            raise ValueError(f"{label} witness has invalid SHA1")
        if not isinstance(seed, str) or hashlib.sha1(seed.encode()).hexdigest() != sha1:
            raise ValueError(f"{label} witness seed does not reproduce SHA1")
        if observation.get("seed_formula_verified") is not True:
            raise ValueError(f"{label} witness formula is not verified")
        if (
            observation.get("digest_blind_selection") is not True
            or observation.get("digest_fields_used_for_selection") != []
        ):
            raise ValueError(f"{label} pair selection is not digest-blind")

    if sysmon.get("target_image") != CONTROL_PATH or sysmon.get("target_event_id") != 1:
        raise ValueError("Sysmon witness is not the exact executed EID 1 image")
    if (
        sysmon.get("downloader_event_id") != 1
        or sysmon.get("file_create_event_id") != 11
        or sysmon.get("file_create_target") != CONTROL_PATH
        or sysmon.get("downloader_process_id") != relation.get("download_process_id")
        or sysmon.get("file_create_process_id") != relation.get("download_process_id")
        or sysmon.get("target_process_id") != relation.get("execution_process_id")
        or sysmon.get("downloader_process_guid") != sysmon.get("file_create_process_guid")
        or sysmon.get("target_process_guid") == sysmon.get("downloader_process_guid")
    ):
        raise ValueError("Sysmon process/file-create identity chain is inconsistent")
    if (
        not isinstance(zeek.get("http_uid"), str)
        or not isinstance(zeek.get("file_fuid"), str)
        or zeek.get("analyzers") != ["SHA1"]
        or zeek.get("seen_bytes") != zeek.get("response_body_len")
        or zeek.get("missing_bytes") != 0
        or zeek.get("overflow_bytes") != 0
        or zeek.get("timedout") is not False
    ):
        raise ValueError("Zeek HTTP/files identity or completeness check is inconsistent")
    if (
        zeek.get("host") != "203.0.113.10"
        or zeek.get("source_ip") != CONTROL_SOURCE_IP
        or zeek.get("response_ip") != "203.0.113.10"
        or zeek.get("transmitter_hosts") != ["203.0.113.10"]
        or zeek.get("receiver_hosts") != [CONTROL_SOURCE_IP]
        or zeek.get("uri") != "/af-controlled.exe"
        or zeek.get("source") != "HTTP"
        or zeek.get("mime_type") == "application/pkix-cert"
    ):
        raise ValueError("Zeek witness is not the exact non-certificate HTTP response")
    if join != {
        "algorithm": "sha1",
        "zeek_sha1": zeek["sha1"],
        "sysmon_sha1": sysmon["sha1"],
        "equal": False,
    }:
        raise ValueError("cross-emitter join result is inconsistent")
    if zeek["sha1"] == sysmon["sha1"]:
        raise ValueError("record says unequal but SHA1 values are equal")

    expected_timeline = [
        "ground_truth_download",
        "sysmon_downloader_eid1",
        "zeek_http",
        "zeek_files",
        "sysmon_file_create_eid11",
        "ground_truth_execution",
        "sysmon_target_eid1",
    ]
    epoch_seconds = _expect(timeline, "epoch_seconds", dict, "witness.timeline")
    if timeline.get("ordered") is not True or timeline.get("sequence") != expected_timeline:
        raise ValueError("witness timeline declaration changed")
    expected_epochs = {
        "ground_truth_download": _parse_time(
            relation.get("ground_truth_download_time"), "serialized ground-truth download"
        ).timestamp(),
        "sysmon_downloader_eid1": _parse_time(
            sysmon.get("downloader_time"), "serialized downloader EID 1"
        ).timestamp(),
        "zeek_http": zeek.get("http_time_epoch"),
        "zeek_files": zeek.get("file_time_epoch"),
        "sysmon_file_create_eid11": _parse_time(
            sysmon.get("file_create_time"), "serialized file-create EID 11"
        ).timestamp(),
        "ground_truth_execution": _parse_time(
            relation.get("ground_truth_execution_time"), "serialized ground-truth execution"
        ).timestamp(),
        "sysmon_target_eid1": _parse_time(
            sysmon.get("target_time"), "serialized target EID 1"
        ).timestamp(),
    }
    if epoch_seconds != expected_epochs:
        raise ValueError("witness timeline is not derived from its serialized observations")
    values = [epoch_seconds.get(label) for label in expected_timeline]
    if any(type(value) not in (int, float) for value in values) or any(
        later < earlier for earlier, later in zip(values, values[1:])
    ):
        raise ValueError("witness timeline values are not ordered")
    if values[-1] - values[-2] > 5:
        raise ValueError("serialized target EID 1 is too far from ground-truth execution")
    if pair_selection != {
        "digest_blind": True,
        "digest_fields_used": [],
        "ground_truth_keys": [
            "storyline_id",
            "record_id",
            "actor",
            "system",
            "network_url",
            "output_file",
            "process_name",
            "pid",
        ],
        "zeek_keys": [
            "id.orig_h",
            "id.resp_h",
            "host",
            "uri",
            "method",
            "status_code",
            "uid",
            "fuid",
            "tx_hosts",
            "rx_hosts",
        ],
        "sysmon_keys": [
            "EventID",
            "Image",
            "ProcessId",
            "ProcessGuid",
            "TargetFilename",
            "User",
        ],
    }:
        raise ValueError("witness pair selection is not digest-blind")
    zeek_negative = _expect(witness_controls, "zeek_file", dict, "witness.negative_controls")
    sysmon_negative = _expect(witness_controls, "sysmon", dict, "witness.negative_controls")
    negative_sha1 = zeek_negative.get("sha1")
    negative_seed = zeek_negative.get("seed_material")
    if (
        witness_controls.get("same_basename_different_path") is not True
        or witness_controls.get("materialized_controlled_filename_present") is not False
        or zeek_negative.get("file_fuid") == zeek.get("file_fuid")
        or zeek_negative.get("sha1") == zeek.get("sha1")
        or not isinstance(negative_sha1, str)
        or _SHA1.fullmatch(negative_sha1) is None
        or not isinstance(negative_seed, str)
        or hashlib.sha1(negative_seed.encode()).hexdigest() != negative_sha1
        or zeek_negative.get("seed_formula_verified") is not True
        or zeek_negative.get("digest_blind_selection") is not True
        or zeek_negative.get("digest_fields_used_for_selection") != []
        or not all(
            sysmon_negative.get(key) is True
            for key in (
                "transfer_only_file_create_observed",
                "transfer_only_execution_absent",
                "process_only_execution_observed",
                "process_only_file_create_absent",
                "digest_blind_selection",
            )
        )
    ):
        raise ValueError("serialized negative controls are inconsistent")

    if qualification.get("positive_same_logical_file_pair_demonstrated") is not True:
        raise ValueError("record lost the positive logical-file qualification")
    if qualification.get("shared_materialized_bytes_demonstrated") is not False:
        raise ValueError("record overclaims shared materialized bytes")
    if qualification.get("serialized_cross_event_content_identity_field") is not None:
        raise ValueError("record invents a serialized content-identity field")
    if not qualification.get("claim_boundary"):
        raise ValueError("record has no claim boundary")


def verify_output_binding(record: dict[str, Any], run_root: str | Path) -> None:
    validate_record(record)
    if output_tree_inventory(run_root) != record["provenance"]["output_tree"]:
        raise ValueError("output tree does not match the committed witness record")
    if analyze_output(run_root) != record["witness"]:
        raise ValueError("output bytes match, but the derived witness does not")


def render_markdown(record: dict[str, Any]) -> str:
    validate_record(record)
    witness = record["witness"]
    relation = witness["relation"]
    zeek = witness["zeek_file"]
    sysmon = witness["sysmon_process"]
    lines = [
        "### EvidenceForge v1.13.1 — controlled transfer-to-execution witness",
        "",
        "| Check | Result |",
        "|---|---|",
        f"| Ground-truth cluster | `{relation['storyline_id']}` (#0 writes, #1 executes) |",
        f"| Modeled file path | `{relation['output_file']}` |",
        f"| Zeek HTTP/files join | `{zeek['http_uid']}` → `{zeek['file_fuid']}` |",
        f"| Zeek SHA1 | `{zeek['sha1']}` |",
        f"| Sysmon EID 1 SHA1 | `{sysmon['sha1']}` |",
        "| Same logical-file SHA1 join | **FAIL** (values differ) |",
        "",
        f"Qualification: {record['qualification']['claim_boundary']}",
    ]
    return "\n".join(lines) + "\n"


def _load(path: Path) -> dict[str, Any]:
    return _object(path, _MAX_GROUND_TRUTH)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    measure = commands.add_parser("measure")
    measure.add_argument("run_root", type=Path)
    measure.add_argument("--scenario", required=True, type=Path)
    measure.add_argument("--evidenceforge-version", required=True)
    measure.add_argument("--evidenceforge-commit", required=True)
    measure.add_argument("--python-version", required=True)
    measure.add_argument("--output", type=Path)
    check = commands.add_parser("check")
    check.add_argument("record", type=Path)
    check.add_argument("--run-root", type=Path)
    render = commands.add_parser("render")
    render.add_argument("record", type=Path)
    render.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "measure":
            record = build_record(
                args.run_root,
                args.scenario,
                evidenceforge_version=args.evidenceforge_version,
                evidenceforge_commit=args.evidenceforge_commit,
                python_version=args.python_version,
            )
            text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        elif args.command == "check":
            record = _load(args.record)
            validate_record(record)
            if args.run_root is not None:
                verify_output_binding(record, args.run_root)
            print(f"OK: {args.record}")
            return 0
        else:
            text = render_markdown(_load(args.record))
        if args.output is None:
            sys.stdout.write(text)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
