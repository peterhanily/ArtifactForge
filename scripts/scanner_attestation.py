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
from collections import Counter
from collections.abc import Callable
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Iterator
from pathlib import Path, PurePosixPath

SCHEMA_ID = "artifactforge-scanner-attestation-v1"
SCHEMA_FILE = "scanner-attestation.schema.json"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / SCHEMA_FILE
CORPUS_CANONICALIZATION = "artifactforge-scanner-corpus-v1"
REQUIRED_SCANNERS = ("clamav", "community-yara", "gatekeeper", "xprotect")
MAX_AGE_DAYS = 30
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_TREE_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RECORD_MANIFEST_BYTES = 6 * 1024 * 1024
MAX_PRE_SCAN_EVIDENCE_BYTES = 5 * 1024 * 1024
MAX_TREE_FILES = 20_000
MAX_TREE_MEMBERS = 40_000
MAX_TREE_FILE_BYTES = 128 * 1024 * 1024
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_YARA_RULE_FILE_BYTES = 4 * 1024 * 1024
MAX_YARA_RULE_TREE_BYTES = 128 * 1024 * 1024
MAX_TREE_DEPTH = 32
MAX_PATH_BYTES = 4_096
READ_CHUNK_BYTES = 1024 * 1024
MAX_SUBPROCESS_OUTPUT_BYTES = 64 * 1024
SUBPROCESS_READ_CHUNK_BYTES = 16 * 1024
YARA_WORK_BUDGET = 250_000
YARA_MATCH_TIMEOUT_SECONDS = 10
YARA_MATCH_TOTAL_TIMEOUT_SECONDS = 600
MAX_YARA_RULES_LOADED = 100_000
CLAMAV_SCAN_TIMEOUT_SECONDS = 600
CLAMAV_LIMIT_ARGS = (
    "--alert-exceeds-max=yes",
    f"--max-filesize={MAX_TREE_FILE_BYTES}",
    f"--max-scansize={MAX_TREE_BYTES}",
    f"--max-files={MAX_TREE_FILES}",
    "--max-recursion=100",
    f"--max-dir-recursion={MAX_TREE_DEPTH}",
    "--max-scantime=0",
    f"--pcre-max-filesize={MAX_TREE_FILE_BYTES}",
)
CLAMAV_LIMIT_DIAGNOSTIC = re.compile(
    r"(?im)^.*(?:warning|error).*(?:limit|max|"
    r"scan\s*time|file\s*size|scan\s*size|recurs|skipp|assum(?:e|ed)).*$"
)
DESCRIPTOR_TREE_CAPTURE_SUPPORTED = (
    {os.open, os.stat}.issubset(os.supports_dir_fd) and os.scandir in os.supports_fd
)
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


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise AttestationError(f"JSON object contains duplicate member {key!r}")
        value[key] = item
    return value


def _reject_non_json_number(value: str) -> None:
    raise AttestationError(f"JSON contains non-standard numeric value {value!r}")


def _decode_json(data: bytes, where: str) -> object:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AttestationError(f"{where} is not UTF-8: {exc}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_non_json_number,
        )
    except AttestationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AttestationError(f"{where} is not valid JSON: {exc}") from exc


def _read_bounded_regular(path: Path, limit: int, where: str) -> bytes:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AttestationError(f"cannot open {where} {path}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AttestationError(f"{where} is not a regular file: {path}")
        if before.st_size > limit:
            raise AttestationError(f"{where} exceeds the {limit}-byte limit: {path}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(READ_CHUNK_BYTES, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise AttestationError(f"{where} exceeds the {limit}-byte limit: {path}")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or total != before.st_size:
            raise AttestationError(f"{where} changed while it was being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _json_equal(left: object, right: object) -> bool:
    """Use JSON's type-sensitive equality rather than Python's ``True == 1`` rule."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _schema_type_matches(value: object, expected: str) -> bool:
    return {
        "null": value is None,
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
    }.get(expected, False)


def _resolve_schema_ref(root: dict, reference: str) -> dict:
    if not reference.startswith("#/"):
        raise AttestationError(f"declared schema uses unsupported reference {reference!r}")
    value: object = root
    for encoded in reference[2:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            raise AttestationError(f"declared schema has unresolved reference {reference!r}")
        value = value[part]
    if not isinstance(value, dict):
        raise AttestationError(f"declared schema reference is not an object: {reference!r}")
    return value


def _validate_schema_node(value: object, schema: dict, root: dict, where: str) -> None:
    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str):
            raise AttestationError("declared schema contains a non-text $ref")
        _validate_schema_node(value, _resolve_schema_ref(root, reference), root, where)

    alternatives = schema.get("anyOf")
    if alternatives is not None:
        if not isinstance(alternatives, list) or not alternatives:
            raise AttestationError("declared schema has an invalid anyOf")
        failures = []
        for alternative in alternatives:
            try:
                _validate_schema_node(value, alternative, root, where)
                break
            except AttestationError as exc:
                failures.append(str(exc))
        else:
            raise AttestationError(
                f"{where} does not satisfy any declared schema alternative: {failures[0]}"
            )

    if "const" in schema and not _json_equal(value, schema["const"]):
        raise AttestationError(f"{where} does not equal the declared constant")
    if "enum" in schema and not any(_json_equal(value, item) for item in schema["enum"]):
        raise AttestationError(f"{where} is not one of the declared values")

    declared_type = schema.get("type")
    if declared_type is not None:
        expected_types = [declared_type] if isinstance(declared_type, str) else declared_type
        if not isinstance(expected_types, list) or not all(
            isinstance(item, str) for item in expected_types
        ):
            raise AttestationError("declared schema contains an invalid type")
        if not any(_schema_type_matches(value, item) for item in expected_types):
            raise AttestationError(
                f"{where} has the wrong JSON type; expected {expected_types!r}"
            )

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise AttestationError(f"{where} is shorter than the declared minimum")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise AttestationError(f"{where} exceeds the declared maximum length")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise AttestationError(f"{where} does not match the declared pattern")
        if schema.get("format") == "date-time":
            _parse_timestamp(value, where)

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise AttestationError(f"{where} has too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise AttestationError(f"{where} has too many items")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                _validate_schema_node(item, item_schema, root, f"{where}[{index}]")

    if isinstance(value, dict):
        if len(value) < schema.get("minProperties", 0):
            raise AttestationError(f"{where} has too few members")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            raise AttestationError(f"{where} has too many members")
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise AttestationError(f"{where} is missing declared member(s): {missing}")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                _validate_schema_node(item, properties[key], root, f"{where}.{key}")
                continue
            additional = schema.get("additionalProperties", True)
            if additional is False:
                raise AttestationError(
                    f"{where} contains undeclared member {key!r} (additional properties forbidden)"
                )
            if isinstance(additional, dict):
                _validate_schema_node(item, additional, root, f"{where}.{key}")
        property_names = schema.get("propertyNames")
        if property_names is not None:
            for key in value:
                _validate_schema_node(key, property_names, root, f"{where} member name")

    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise AttestationError(f"{where} is below the declared minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise AttestationError(f"{where} exceeds the declared maximum")


def _audit_supported_schema(schema: dict, where: str = "schema") -> None:
    """Refuse to ignore a keyword added to the declared schema in a later edit."""
    supported = {
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "title",
        "type",
        "const",
        "enum",
        "anyOf",
        "required",
        "properties",
        "additionalProperties",
        "propertyNames",
        "items",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
    }
    unsupported = sorted(set(schema) - supported)
    if unsupported:
        raise AttestationError(
            f"declared scanner schema uses unsupported keyword(s) at {where}: {unsupported}"
        )
    if "format" in schema and schema["format"] != "date-time":
        raise AttestationError(
            f"declared scanner schema uses unsupported format at {where}: {schema['format']!r}"
        )
    declared_type = schema.get("type", [])
    declared_types = [declared_type] if isinstance(declared_type, str) else declared_type
    supported_types = {"null", "object", "array", "string", "integer", "number", "boolean"}
    if not isinstance(declared_types, list) or any(
        item not in supported_types for item in declared_types
    ):
        raise AttestationError(
            f"declared scanner schema uses unsupported type at {where}: {declared_type!r}"
        )
    for keyword in ("$defs", "properties"):
        children = schema.get(keyword, {})
        if not isinstance(children, dict):
            raise AttestationError(f"declared scanner schema {where}.{keyword} is not an object")
        for name, child in children.items():
            if not isinstance(child, dict):
                raise AttestationError(
                    f"declared scanner schema {where}.{keyword}.{name} is not an object"
                )
            _audit_supported_schema(child, f"{where}.{keyword}.{name}")
    for keyword in ("items", "propertyNames"):
        child = schema.get(keyword)
        if child is not None:
            if not isinstance(child, dict):
                raise AttestationError(
                    f"declared scanner schema {where}.{keyword} is not an object"
                )
            _audit_supported_schema(child, f"{where}.{keyword}")
    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        _audit_supported_schema(additional, f"{where}.additionalProperties")
    alternatives = schema.get("anyOf", [])
    if not isinstance(alternatives, list):
        raise AttestationError(f"declared scanner schema {where}.anyOf is not an array")
    for index, child in enumerate(alternatives):
        if not isinstance(child, dict):
            raise AttestationError(
                f"declared scanner schema {where}.anyOf[{index}] is not an object"
            )
        _audit_supported_schema(child, f"{where}.anyOf[{index}]")


_DECLARED_SCHEMA: dict | None = None


def _declared_schema() -> dict:
    global _DECLARED_SCHEMA  # noqa: PLW0603 - one immutable, process-local schema cache
    if _DECLARED_SCHEMA is None:
        raw = _read_bounded_regular(SCHEMA_PATH, 512 * 1024, "scanner schema")
        parsed = _decode_json(raw, "scanner schema")
        if not isinstance(parsed, dict) or parsed.get("$id") != SCHEMA_ID:
            raise AttestationError("declared scanner schema has the wrong identity")
        _audit_supported_schema(parsed)
        _DECLARED_SCHEMA = parsed
    return _DECLARED_SCHEMA


def _validate_declared_schema(record: object) -> None:
    schema = _declared_schema()
    _validate_schema_node(record, schema, schema, "record")


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


def _manifest_metadata_size(canonicalization: str, files: list[dict]) -> int:
    payload = {"canonicalization": canonicalization, "files": files}
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _safe_component(name: str, where: str) -> None:
    encoded = os.fsencode(name)
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AttestationError(
            f"{where} contains a path component that is not valid UTF-8: {name!r}"
        ) from exc
    if (
        not name
        or name in {".", ".."}
        or b"/" in encoded
        or b"\\" in encoded
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise AttestationError(f"{where} contains an unsafe path component: {name!r}")


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_regular_fd(
    fd: int,
    where: str,
    before: os.stat_result,
    *,
    max_bytes: int | None = None,
) -> bytes:
    if max_bytes is None:
        max_bytes = MAX_TREE_FILE_BYTES
    limit_description = (
        f"{MAX_TREE_FILE_BYTES}-byte per-file capture limit"
        if max_bytes == MAX_TREE_FILE_BYTES
        else f"{max_bytes}-byte remaining tree capture budget"
    )
    if before.st_size > max_bytes:
        raise AttestationError(f"{where} exceeds the {limit_description}")
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, min(READ_CHUNK_BYTES, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise AttestationError(f"{where} exceeds the {limit_description}")
        chunks.append(chunk)
    after = os.fstat(fd)
    identity_before = _stat_identity(before)
    identity_after = _stat_identity(after)
    if identity_before != identity_after or total != before.st_size:
        raise AttestationError(f"{where} changed while its descriptor was being captured")
    return b"".join(chunks)


def _write_snapshot_file(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o400)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise AttestationError(f"short write while creating private snapshot {destination}")
            view = view[written:]
        os.fchmod(fd, 0o400)
    finally:
        os.close(fd)


def _tree_inventory(
    root: Path,
    canonicalization: str,
    *,
    snapshot: Path | None = None,
    require_files: bool = True,
    include_file: Callable[[tuple[str, ...]], bool] | None = None,
    max_file_bytes: int | None = None,
    max_total_bytes: int | None = None,
    max_files: int | None = None,
) -> dict:
    """Read a tree through pinned descriptors and optionally materialise those exact bytes."""
    root = Path(root)
    max_file_bytes = MAX_TREE_FILE_BYTES if max_file_bytes is None else max_file_bytes
    max_total_bytes = MAX_TREE_BYTES if max_total_bytes is None else max_total_bytes
    max_files = MAX_TREE_FILES if max_files is None else max_files
    if not DESCRIPTOR_TREE_CAPTURE_SUPPORTED:
        raise AttestationError(
            "this platform cannot provide descriptor-bound scanner input capture"
        )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        raise AttestationError(f"input tree is not an attestable directory: {root}: {exc}") from exc
    if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
        os.close(root_fd)
        raise AttestationError(f"input tree is not a directory: {root}")
    if snapshot is not None:
        snapshot.mkdir(mode=0o700, parents=True, exist_ok=False)

    files: list[dict] = []
    total_bytes = 0
    total_members = 0
    directory_states: dict[tuple[str, ...], tuple[tuple[int, ...], tuple[str, ...]]] = {}
    file_states: dict[tuple[str, ...], tuple[int, ...]] = {}

    def walk(directory_fd: int, parts: tuple[str, ...]) -> None:
        nonlocal total_bytes, total_members
        if len(parts) > MAX_TREE_DEPTH:
            raise AttestationError(
                f"input tree exceeds the maximum depth of {MAX_TREE_DEPTH}: {'/'.join(parts)}"
            )
        directory_before = os.fstat(directory_fd)
        try:
            names = []
            for entry in os.scandir(directory_fd):
                total_members += 1
                if total_members > MAX_TREE_MEMBERS:
                    raise AttestationError(
                        f"input tree exceeds the {MAX_TREE_MEMBERS}-member traversal limit"
                    )
                names.append(entry.name)
            names.sort()
        except OSError as exc:
            raise AttestationError(f"cannot enumerate captured input {'/'.join(parts)!r}: {exc}") from exc
        for name in names:
            _safe_component(name, "input tree")
            child_parts = (*parts, name)
            relative = PurePosixPath(*child_parts).as_posix()
            if len(child_parts) > MAX_TREE_DEPTH:
                raise AttestationError(
                    f"input tree exceeds the maximum depth of {MAX_TREE_DEPTH}: {relative}"
                )
            if len(relative.encode("utf-8", errors="surrogateescape")) > MAX_PATH_BYTES:
                raise AttestationError(
                    f"input tree path exceeds the {MAX_PATH_BYTES}-byte limit: {relative!r}"
                )
            try:
                listed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise AttestationError(f"cannot stat input tree entry {relative!r}: {exc}") from exc
            if stat.S_ISLNK(listed.st_mode):
                raise AttestationError(
                    f"input tree contains a symlink, which is not attestable: {relative}"
                )
            if stat.S_ISDIR(listed.st_mode):
                try:
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise AttestationError(
                        f"cannot pin input directory {relative!r}: {exc}"
                    ) from exc
                try:
                    pinned = os.fstat(child_fd)
                    if (pinned.st_dev, pinned.st_ino) != (listed.st_dev, listed.st_ino):
                        raise AttestationError(
                            f"input directory changed before it could be pinned: {relative!r}"
                        )
                    walk(child_fd, child_parts)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(listed.st_mode):
                raise AttestationError(
                    f"input tree contains a non-regular entry: {relative}"
                )
            file_states[child_parts] = _stat_identity(listed)
            if include_file is not None and not include_file(child_parts):
                continue
            if listed.st_size > max_file_bytes:
                raise AttestationError(
                    f"{relative} exceeds the {max_file_bytes}-byte per-file capture limit"
                )
            if total_bytes + listed.st_size > max_total_bytes:
                raise AttestationError(
                    f"input tree exceeds the {max_total_bytes}-byte capture limit"
                )
            if len(files) >= max_files:
                raise AttestationError(
                    f"input tree exceeds the {max_files}-file capture limit"
                )
            file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                file_fd = os.open(name, file_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise AttestationError(f"cannot pin input file {relative!r}: {exc}") from exc
            try:
                pinned = os.fstat(file_fd)
                listed_identity = _stat_identity(listed)
                pinned_identity = _stat_identity(pinned)
                if not stat.S_ISREG(pinned.st_mode) or pinned_identity != listed_identity:
                    raise AttestationError(
                        f"input file changed before it could be pinned: {relative!r}"
                    )
                data = _read_regular_fd(
                    file_fd,
                    relative,
                    pinned,
                    max_bytes=min(
                        max_file_bytes,
                        max_total_bytes - total_bytes,
                    ),
                )
            finally:
                os.close(file_fd)
            total_bytes += len(data)
            files.append({"path": relative, "sha256": _sha256(data), "size": len(data)})
            if snapshot is not None:
                _write_snapshot_file(snapshot.joinpath(*child_parts), data)
        try:
            names_after = []
            for entry in os.scandir(directory_fd):
                if len(names_after) >= MAX_TREE_MEMBERS:
                    raise AttestationError(
                        f"input directory exceeds the {MAX_TREE_MEMBERS}-member traversal limit"
                    )
                names_after.append(entry.name)
            names_after.sort()
        except OSError as exc:
            raise AttestationError(
                f"cannot re-enumerate captured input {'/'.join(parts)!r}: {exc}"
            ) from exc
        directory_after = os.fstat(directory_fd)
        if names_after != names or (
            directory_before.st_dev,
            directory_before.st_ino,
            directory_before.st_mode,
            directory_before.st_mtime_ns,
            directory_before.st_ctime_ns,
        ) != (
            directory_after.st_dev,
            directory_after.st_ino,
            directory_after.st_mode,
            directory_after.st_mtime_ns,
            directory_after.st_ctime_ns,
        ):
            location = PurePosixPath(*parts).as_posix() if parts else "."
            raise AttestationError(
                f"input directory changed while its descriptor was being captured: {location}"
            )
        directory_states[parts] = (_stat_identity(directory_after), tuple(names))

    verification_members = 0

    def _verify_end_state(directory_fd: int, parts: tuple[str, ...]) -> None:
        nonlocal verification_members
        expected_state, expected_names = directory_states[parts]
        if _stat_identity(os.fstat(directory_fd)) != expected_state:
            location = PurePosixPath(*parts).as_posix() if parts else "."
            raise AttestationError(
                f"input directory changed before the tree snapshot completed: {location}"
            )
        current_names = []
        for entry in os.scandir(directory_fd):
            verification_members += 1
            if verification_members > MAX_TREE_MEMBERS:
                raise AttestationError(
                    f"input tree exceeds the {MAX_TREE_MEMBERS}-member verification limit"
                )
            current_names.append(entry.name)
        current_names.sort()
        if tuple(current_names) != expected_names:
            location = PurePosixPath(*parts).as_posix() if parts else "."
            raise AttestationError(
                f"input directory entries changed before snapshot completion: {location}"
            )
        for name in current_names:
            child_parts = (*parts, name)
            relative = PurePosixPath(*child_parts).as_posix()
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(current.st_mode):
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    verify_end_state(child_fd, child_parts)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(current.st_mode):
                if file_states.get(child_parts) != _stat_identity(current):
                    raise AttestationError(
                        f"input file changed before the tree snapshot completed: {relative}"
                    )
            else:
                raise AttestationError(
                    f"input tree entry changed type before snapshot completion: {relative}"
                )

    def verify_end_state(directory_fd: int, parts: tuple[str, ...]) -> None:
        """Normalize second-pass filesystem races into the public attestation error type."""
        try:
            _verify_end_state(directory_fd, parts)
        except AttestationError:
            raise
        except (NotImplementedError, OSError) as exc:
            location = PurePosixPath(*parts).as_posix() if parts else "."
            raise AttestationError(
                f"cannot revalidate input tree snapshot at {location!r}: {exc}"
            ) from exc

    try:
        walk(root_fd, ())
        verify_end_state(root_fd, ())
    finally:
        os.close(root_fd)
    if require_files and not files:
        raise AttestationError("input tree contains no regular files")
    metadata_bytes = _manifest_metadata_size(canonicalization, files)
    if metadata_bytes > MAX_TREE_MANIFEST_BYTES:
        raise AttestationError(
            "input tree manifest metadata exceeds the "
            f"{MAX_TREE_MANIFEST_BYTES}-byte serialization limit"
        )
    return {
        "canonicalization": canonicalization,
        "tree_sha256": _canonical_digest(canonicalization, files),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "files": files,
    }


def corpus_inventory(root: Path) -> dict:
    """Return a no-follow, bounded manifest of the exact recursive corpus bytes."""
    return _tree_inventory(Path(root), CORPUS_CANONICALIZATION)


def _capture_single_file(
    source: Path,
    destination: Path,
    *,
    max_bytes: int = MAX_TREE_FILE_BYTES,
) -> None:
    """Capture one rule file through a no-follow descriptor rooted at its parent."""
    source = Path(source)
    _safe_component(source.name, "selected rule input")
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(source.parent, parent_flags)
    except OSError as exc:
        raise AttestationError(f"cannot pin rule-file parent {source.parent}: {exc}") from exc
    try:
        parent_before = os.fstat(parent_fd)
        listed = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(listed.st_mode):
            raise AttestationError(f"selected rule input is not a regular file: {source}")
        file_fd = os.open(
            source.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            pinned = os.fstat(file_fd)
            if (pinned.st_dev, pinned.st_ino) != (listed.st_dev, listed.st_ino):
                raise AttestationError(f"selected rule input changed before capture: {source}")
            data = _read_regular_fd(file_fd, str(source), pinned, max_bytes=max_bytes)
        finally:
            os.close(file_fd)
        listed_after = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.fstat(parent_fd)
        if (listed_after.st_dev, listed_after.st_ino) != (listed.st_dev, listed.st_ino) or (
            parent_before.st_dev,
            parent_before.st_ino,
            parent_before.st_mtime_ns,
            parent_before.st_ctime_ns,
        ) != (
            parent_after.st_dev,
            parent_after.st_ino,
            parent_after.st_mtime_ns,
            parent_after.st_ctime_ns,
        ):
            raise AttestationError(f"selected rule input changed during capture: {source}")
    except OSError as exc:
        raise AttestationError(f"cannot capture selected rule input {source}: {exc}") from exc
    finally:
        os.close(parent_fd)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_snapshot_file(destination, data)


class _CapturedInputs:
    __slots__ = ("corpus", "corpus_inventory", "community_rules", "xprotect_rule")

    def __init__(
        self,
        corpus: Path,
        corpus_inventory: dict,
        community_rules: Path,
        xprotect_rule: Path,
    ) -> None:
        self.corpus = corpus
        self.corpus_inventory = corpus_inventory
        self.community_rules = community_rules
        self.xprotect_rule = xprotect_rule

    corpus: Path
    corpus_inventory: dict
    community_rules: Path
    xprotect_rule: Path


@contextmanager
def _captured_inputs(
    corpus: Path,
    community_rules: Path,
    xprotect_rule: Path,
) -> Iterator[_CapturedInputs]:
    """Freeze every scanner-controlled byte before any scanner observes the input."""
    with tempfile.TemporaryDirectory(prefix="artifactforge-scanner-inputs-") as directory:
        private = Path(directory)
        private.chmod(0o700)
        corpus_snapshot = private / "corpus"
        inventory = _tree_inventory(
            corpus,
            CORPUS_CANONICALIZATION,
            snapshot=corpus_snapshot,
        )

        community_snapshot = private / "community-rules"
        try:
            community_mode = community_rules.lstat().st_mode
        except FileNotFoundError:
            community_mode = None
        if community_mode is not None:
            if not stat.S_ISDIR(community_mode):
                raise AttestationError(
                    f"community YARA input is not an attestable directory: {community_rules}"
                )
            _tree_inventory(
                community_rules,
                "artifactforge-private-rule-source-v1",
                snapshot=community_snapshot,
                require_files=False,
                include_file=lambda parts: parts[-1].endswith((".yar", ".yara")),
                max_file_bytes=MAX_YARA_RULE_FILE_BYTES,
                max_total_bytes=MAX_YARA_RULE_TREE_BYTES,
            )

        xprotect_snapshot = private / "xprotect" / xprotect_rule.name
        try:
            xprotect_mode = xprotect_rule.lstat().st_mode
        except FileNotFoundError:
            xprotect_mode = None
        if xprotect_mode is not None:
            if not stat.S_ISREG(xprotect_mode):
                raise AttestationError(
                    f"XProtect rule input is not an attestable regular file: {xprotect_rule}"
                )
            _capture_single_file(
                xprotect_rule,
                xprotect_snapshot,
                max_bytes=MAX_YARA_RULE_FILE_BYTES,
            )

        yield _CapturedInputs(
            corpus=corpus_snapshot,
            corpus_inventory=inventory,
            community_rules=community_snapshot,
            xprotect_rule=xprotect_snapshot,
        )


def corpus_binding(inventory: dict) -> dict:
    """Copy the immutable corpus identity into one scanner result."""
    return {
        key: inventory[key]
        for key in ("canonicalization", "tree_sha256", "file_count", "total_bytes")
    }


def _run(command: list[str], *, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    """Run one scanner with a wall-clock timeout and bounded descriptor pumping.

    ``capture_output=True`` lets a scanner allocate arbitrary parent-process memory before a
    caller can inspect it. Nonblocking reads retain at most one shared byte budget. Supervision
    continues until both pipes reach EOF, so a descendant cannot make a clean parent exit bypass
    the deadline by holding inherited stdout/stderr descriptors open.
    """
    process = subprocess.Popen(  # noqa: S603 - argv is an explicit scanner command
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    assert process.stdout is not None and process.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    retained = 0
    selector = selectors.DefaultSelector()
    for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    timed_out = False
    output_exhausted = False
    capture_error: OSError | None = None
    forced_stop = False

    def kill_process_tree() -> None:
        nonlocal forced_stop
        forced_stop = True
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            elif process.poll() is None:
                process.kill()
        except ProcessLookupError:
            pass

    try:
        # A direct scanner may exit after spawning a descendant that inherited the capture
        # pipes. End normally only after the direct child is reaped *and* both pipes reach EOF.
        while process.poll() is None or selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                kill_process_tree()
                break
            if not selector.get_map():
                time.sleep(min(0.01, remaining))
                continue
            for key, _mask in selector.select(timeout=min(0.05, remaining)):
                try:
                    chunk = os.read(key.fd, SUBPROCESS_READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    capture_error = exc
                    kill_process_tree()
                    break
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                room = max(0, MAX_SUBPROCESS_OUTPUT_BYTES - retained)
                kept = chunk[:room]
                output[key.data].extend(kept)
                retained += len(kept)
                if len(kept) != len(chunk):
                    output_exhausted = True
                    kill_process_tree()
                    break
            if forced_stop:
                break
    finally:
        # Closing read descriptors is constant-time and prevents a double-forked descendant that
        # escaped the process group from extending this call after a forced stop.
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fileobj)
            except Exception:  # noqa: BLE001 - best-effort descriptor teardown
                pass
            try:
                key.fileobj.close()
            except OSError:
                pass
        selector.close()

    if process.poll() is None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)

    stdout = bytes(output["stdout"]).decode("utf-8", errors="replace")
    stderr = bytes(output["stderr"]).decode("utf-8", errors="replace")
    if timed_out:
        raise subprocess.TimeoutExpired(
            command,
            timeout,
            output=stdout,
            stderr=stderr,
        )
    if capture_error is not None:
        raise AttestationError(
            f"scanner subprocess output could not be captured: {capture_error}"
        )
    if output_exhausted:
        raise AttestationError(
            "scanner subprocess output exceeds the "
            f"{MAX_SUBPROCESS_OUTPUT_BYTES}-byte stdout/stderr limit"
        )
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _bounded_text(value: object, limit: int = 4_096) -> str:
    rendered = str(value)
    if len(rendered) <= limit:
        return rendered or "unreported"
    digest = _sha256(rendered.encode("utf-8", errors="replace"))
    suffix = f"... [truncated; sha256={digest}]"
    return rendered[: limit - len(suffix)] + suffix


def _error(where: str, message: str) -> dict:
    return {"where": _bounded_text(where, 2_048), "message": _bounded_text(message)}


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
    message = _bounded_text(message)
    return {
        "scanner": {
            "id": scanner_id,
            "name": scanner_name,
            "engine_version": _bounded_text(engine_version, 1_024),
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
        return _bounded_text(match.group(1), 1_024), _bounded_text(match.group(2), 1_024)
    return _bounded_text(first or "unknown", 1_024), None


def _clamav_finding_key(line: str) -> str:
    """Keep finding arithmetic exact while bounding an attacker-controlled output key."""
    digest = _sha256(line.encode("utf-8", errors="replace"))
    suffix = f" [line-sha256={digest}]"
    return _bounded_text(line, 1_024 - len(suffix)) + suffix


@contextmanager
def _captured_clam_database(binary: str) -> Iterator[tuple[Path, dict]]:
    """Bind the exact ClamAV database bytes or refuse to support a scan claim."""
    resolved = Path(shutil.which(binary) or binary).resolve()
    clamconf = resolved.with_name("clamconf")
    if not clamconf.is_file() or not os.access(clamconf, os.X_OK):
        raise AttestationError(
            f"cannot bind loaded database bytes because usable sibling clamconf is absent: "
            f"{clamconf}"
        )
    try:
        configured = _run([str(clamconf), "-n"], timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AttestationError(
            f"cannot query the ClamAV database directory with {clamconf}: {exc}"
        ) from exc
    if configured.returncode != 0:
        raise AttestationError(
            f"clamconf could not identify the database directory (exit {configured.returncode})"
        )
    output = configured.stdout + configured.stderr
    match = re.search(r"^Database directory:\s*(.+?)\s*$", output, re.MULTILINE)
    if match is None:
        raise AttestationError("clamconf output omitted the loaded database directory")
    database = Path(match.group(1).strip().strip('"'))
    with tempfile.TemporaryDirectory(prefix="artifactforge-clam-database-") as directory:
        snapshot = Path(directory) / "database"
        manifest = _tree_inventory(
            database,
            "artifactforge-clam-database-manifest-v1",
            snapshot=snapshot,
        )
        yield snapshot, manifest
        if _tree_inventory(snapshot, "artifactforge-clam-database-manifest-v1") != manifest:
            raise AttestationError(
                "private ClamAV database snapshot changed while the scanner was reading it"
            )


def _scan_clamav_with_database(
    corpus: Path,
    binding: dict,
    *,
    binary: str,
    database: Path,
    database_manifest: dict,
) -> dict:
    database_args = [f"--database={database}"]
    scan_profile = [*database_args, *CLAMAV_LIMIT_ARGS]
    intended = [binary, *scan_profile, "--recursive", "--infected", str(corpus)]
    errors = []
    try:
        version_run = _run([binary, *database_args, "--version"], timeout=30)
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
        control_command = [
            binary,
            *scan_profile,
            "--infected",
            "--no-summary",
            str(control_path),
        ]
        try:
            control_run = _run(control_command, timeout=60)
            # ClamAV documents exit 1 as "virus(es) found".  The known input is EICAR, so the
            # exit status is both sufficient and independent of the process locale.
            control_passed = control_run.returncode == 1
            control_observed = f"exit={control_run.returncode}"
        except (OSError, subprocess.TimeoutExpired) as exc:
            control_passed = False
            control_observed = f"{type(exc).__name__}: {exc}"

    command = [binary, *scan_profile, "--recursive", "--infected", str(corpus)]
    try:
        scan_run = _run(command, timeout=CLAMAV_SCAN_TIMEOUT_SECONDS)
        output = scan_run.stdout + scan_run.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        scan_run = None
        output = ""
        errors.append(_error("clamav corpus scan", f"{type(exc).__name__}: {exc}"))
    findings = []
    finding_counts: Counter[str] = Counter()
    scanned_files = 0
    if scan_run is not None:
        raw_findings = [
            line.strip() for line in output.splitlines() if line.rstrip().endswith("FOUND")
        ]
        finding_counts = Counter(_clamav_finding_key(line) for line in raw_findings)
        findings = sorted(finding_counts)
        limit_diagnostics = sorted(
            {match.group(0).strip() for match in CLAMAV_LIMIT_DIAGNOSTIC.finditer(output)}
        )
        if limit_diagnostics:
            errors.append(_error(
                "clamav corpus scan limits",
                "scanner reported a limit/skip diagnostic: " + limit_diagnostics[0],
            ))
        count_match = re.search(r"^Scanned files:\s*(\d+)\s*$", output, re.MULTILINE)
        if count_match:
            scanned_files = int(count_match.group(1))
        else:
            errors.append(_error("clamav corpus scan", "summary omitted Scanned files count"))
        if scan_run.returncode == 0 and findings:
            errors.append(_error(
                "clamav corpus scan",
                "exit 0 (clean) disagrees with parsed finding output",
            ))
        elif scan_run.returncode == 1 and not findings:
            errors.append(_error(
                "clamav corpus scan",
                "exit 1 reports a detection, but no finding could be parsed from bounded output",
            ))
        elif scan_run.returncode not in (0, 1):
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
        "expected": "clamscan exits 1 (detection) for the harmless EICAR test string",
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
            "rules": {
                "version": rules_version or "unreported",
                "fingerprint_sha256": database_manifest["tree_sha256"],
                "manifest": database_manifest,
            },
        },
        "timestamp": _timestamp(),
        "status": status,
        "corpus_binding": binding,
        "method": {
            "command": command,
            "description": (
                "recursive clamscan with its summary retained so the engine-reported file "
                "count and documented process exit status are checked; explicit resource "
                "limits cover the bounded corpus, limit overruns alert/fail closed, internal "
                "scan-time clean-skips are disabled, and --database selects the "
                "descriptor-captured database snapshot bound into this result"
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
            "matches": sum(finding_counts.values()),
            "matched_rules": dict(sorted(finding_counts.items())),
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


def scan_clamav(
    corpus: Path,
    binding: dict,
    *,
    executable: str | None = None,
    record_evidence_bytes: int = 0,
) -> dict:
    """Run ClamAV over captured bytes and bind database bytes when observable."""
    binary = executable or shutil.which("clamscan")
    intended = [binary or "clamscan", "--recursive", "--infected", str(corpus)]
    if not binary:
        return _unavailable_result(
            "clamav", "ClamAV", binding, intended, "clamscan is not installed"
        )
    try:
        with _captured_clam_database(binary) as (database, manifest):
            database_evidence = {
                "scanner": "clamav",
                "rules": {
                    "fingerprint_sha256": manifest["tree_sha256"],
                    "manifest": manifest,
                },
            }
            projected = record_evidence_bytes + len(
                json.dumps(database_evidence, indent=2, sort_keys=True).encode()
            )
            if projected > MAX_PRE_SCAN_EVIDENCE_BYTES:
                raise AttestationError(
                    "captured inputs cannot fit the pre-scan attestation evidence budget"
                )
            return _scan_clamav_with_database(
                corpus,
                binding,
                binary=binary,
                database=database,
                database_manifest=manifest,
            )
    except AttestationError as exc:
        return _unavailable_result(
            "clamav",
            "ClamAV",
            binding,
            intended,
            f"could not bind ClamAV database identity/evidence: {exc}",
        )


def scan_gatekeeper(
    corpus: Path,
    inventory: dict,
    binding: dict,
    *,
    spctl: str | None = None,
    codesign: str | None = None,
    accepted_control: Path | None = None,
) -> dict:
    """Refuse to interpret ``spctl`` over ArtifactForge's current loose-file corpus.

    Apple's Gatekeeper assessment profile is a top-level application-bundle check.  The current
    corpus exposes loose Mach-O files, so neither a loose platform binary nor the generated loose
    target is a valid positive/negative vector.  App-bundle capture and assessment belongs to the
    later app-bundle coverage phase; until then this lane is explicitly red/inapplicable.
    """
    del corpus, inventory, codesign, accepted_control
    executable = spctl or shutil.which("spctl") or "spctl"
    command = [
        executable,
        "--assess",
        "--type",
        "execute",
        "<top-level-app-bundle-required>",
    ]
    return _unavailable_result(
        "gatekeeper",
        "Apple Gatekeeper",
        binding,
        command,
        "Gatekeeper assessment is inapplicable to ArtifactForge's current loose Mach-O "
        "corpus; a descriptor-bound top-level .app target and matching .app positive control "
        "are required before this lane can support a policy observation",
        control_scope="engine-and-host-policy",
    )


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
    """Run every scanner over one private, descriptor-captured input snapshot."""
    import scan_yara

    xprotect_rule = xprotect_path or Path(scan_yara.XPROTECT)
    with _captured_inputs(corpus, yara_rules, xprotect_rule) as captured:
        inventory = captured.corpus_inventory
        binding = corpus_binding(inventory)
        _discovered, selected_rules, community_exclusions = scan_yara._community_paths(
            captured.community_rules
        ) if captured.community_rules.is_dir() else ([], [], [])
        community_metadata = (
            scan_yara._rule_metadata(selected_rules, captured.community_rules)
            if selected_rules
            else None
        )
        xprotect_metadata = (
            scan_yara._rule_metadata(
                [captured.xprotect_rule], captured.xprotect_rule.parent
            )
            if captured.xprotect_rule.is_file()
            else None
        )
        projected_inputs = {
            "corpus": inventory,
            "community_rules": community_metadata,
            "community_exclusions": community_exclusions,
            "xprotect_rules": xprotect_metadata,
        }
        projected_input_bytes = len(
            json.dumps(projected_inputs, indent=2, sort_keys=True).encode()
        )
        if projected_input_bytes > MAX_PRE_SCAN_EVIDENCE_BYTES:
            raise AttestationError(
                "captured corpus/rule inputs cannot fit the pre-scan attestation evidence budget"
            )
        results = [
            _guarded_scanner_result(
                "clamav", "ClamAV", binding,
                [
                    clamscan or "clamscan",
                    "--recursive",
                    "--infected",
                    "<private-corpus-snapshot>",
                ],
                "engine-and-selected-rules",
                lambda: scan_clamav(
                    captured.corpus,
                    binding,
                    executable=clamscan,
                    record_evidence_bytes=projected_input_bytes,
                ),
            ),
            _guarded_scanner_result(
                "xprotect", "Apple XProtect YARA", binding, producer_command,
                "engine-and-selected-rules",
                lambda: scan_yara.scan_xprotect(
                    captured.corpus,
                    binding,
                    rules_path=captured.xprotect_rule,
                    method_command=producer_command,
                ),
            ),
            _guarded_scanner_result(
                "community-yara", "Community YARA", binding, producer_command,
                "engine-only",
                lambda: scan_yara.scan_community(
                    captured.corpus,
                    captured.community_rules,
                    binding,
                    method_command=producer_command,
                ),
            ),
            _guarded_scanner_result(
                "gatekeeper", "Apple Gatekeeper", binding,
                [spctl or "spctl", "--assess", "--type", "execute", "<selected Mach-O>"],
                "engine-and-host-policy",
                lambda: scan_gatekeeper(
                    captured.corpus, inventory, binding, spctl=spctl, codesign=codesign
                ),
            ),
        ]
        if corpus_inventory(captured.corpus) != inventory:
            raise AttestationError("private corpus snapshot changed while scanners were reading it")

        xprotect_result = next(
            item for item in results if item["scanner"]["id"] == "xprotect"
        )
        if (
            captured.xprotect_rule.is_file()
            and xprotect_result["scanner"]["rules"].get("manifest") is not None
        ):
            current_xprotect = scan_yara._rule_metadata(
                [captured.xprotect_rule], captured.xprotect_rule.parent
            )
            if xprotect_result["scanner"]["rules"] != current_xprotect:
                raise AttestationError(
                    "private XProtect rule snapshot changed while scanners were reading it"
                )
        community_result = next(
            item for item in results if item["scanner"]["id"] == "community-yara"
        )
        if (
            captured.community_rules.is_dir()
            and community_result["scanner"]["rules"].get("manifest") is not None
        ):
            _discovered, selected, _exclusions = scan_yara._community_paths(
                captured.community_rules
            )
            current_community = scan_yara._rule_metadata(
                selected, captured.community_rules
            )
            if community_result["scanner"]["rules"] != current_community:
                raise AttestationError(
                    "private community-YARA snapshot changed while scanners were reading it"
                )
        record = {
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
                    "all required controls pass over one descriptor-captured private snapshot, "
                    "all selected inputs are covered, no scan errors or scanner/rule matches "
                    "occur, and the record is fresh and corpus-bound"
                ),
            },
            "corpus": inventory,
            "results": sorted(results, key=lambda item: item["scanner"]["id"]),
            "overall_non_proof": (
                "Even a valid clean attestation is a dated signature-snapshot observation over "
                "exact captured bytes, not proof that the binaries are safe or inert. The "
                "record is self-reported and unsigned; it does not independently authenticate "
                "the host, scanner binaries, or a later live source tree."
            ),
        }
    return record


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
    if len(files) > MAX_TREE_FILES:
        raise AttestationError(f"{where} exceeds the {MAX_TREE_FILES}-file manifest limit")
    previous = None
    total = 0
    for index, raw in enumerate(files):
        item = _require_mapping(raw, f"{where}.files[{index}]")
        path = _require_text(item.get("path"), f"{where}.files[{index}].path")
        try:
            encoded_path = path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise AttestationError(f"{where} path is not UTF-8: {path!r}") from exc
        parts = path.split("/")
        if (
            len(encoded_path) > MAX_PATH_BYTES
            or len(parts) > MAX_TREE_DEPTH
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise AttestationError(f"{where} contains a non-canonical path: {path!r}")
        for part in parts:
            _safe_component(part, where)
        if previous is not None and path <= previous:
            raise AttestationError(f"{where} paths must be unique and sorted")
        previous = path
        size = item.get("size")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_TREE_FILE_BYTES
        ):
            raise AttestationError(f"{where} has an invalid size for {path!r}")
        total += size
        if total > MAX_TREE_BYTES:
            raise AttestationError(f"{where} exceeds the {MAX_TREE_BYTES}-byte manifest limit")
        _require_sha256(item.get("sha256"), f"{where} SHA256 for {path!r}")
    if inventory.get("total_bytes", total) != total:
        raise AttestationError(f"{where} total byte count does not match its manifest")
    expected = _canonical_digest(canonicalization, files)
    if inventory.get("tree_sha256") != expected:
        raise AttestationError(f"{where} tree SHA256 does not match its manifest")
    if _manifest_metadata_size(canonicalization, files) > MAX_TREE_MANIFEST_BYTES:
        raise AttestationError(
            f"{where} exceeds the {MAX_TREE_MANIFEST_BYTES}-byte manifest metadata limit"
        )


def _validate_rules(rules: dict, scanner_id: str) -> None:
    version = rules.get("version")
    fingerprint = rules.get("fingerprint_sha256")
    if not (isinstance(version, str) and version.strip()) and fingerprint is None:
        raise AttestationError(f"{scanner_id} has neither a rule version nor fingerprint")
    manifest = rules.get("manifest")
    if manifest is not None:
        manifest = _require_mapping(manifest, f"{scanner_id}.scanner.rules.manifest")
        if scanner_id in {"community-yara", "xprotect"}:
            canonicalization = "artifactforge-yara-rule-manifest-v1"
        elif scanner_id == "clamav":
            canonicalization = "artifactforge-clam-database-manifest-v1"
        else:
            raise AttestationError("gatekeeper opaque host policy cannot carry a rule manifest")
        _validate_manifest(manifest, f"{scanner_id} rule manifest", canonicalization)
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
    allowed = {"files_scanned", "matches", "matched_rules"}
    if scanner_id == "gatekeeper":
        allowed.add("outcome")
    unexpected = sorted(set(summary) - allowed)
    if unexpected:
        raise AttestationError(
            f"{scanner_id}.summary contains fields outside its declared profile: {unexpected}"
        )
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
    generic = {
        "kind",
        "selected_corpus_files",
        "scanned_corpus_files",
        "control_scope_note",
    }
    by_scanner = {
        "clamav": generic,
        "community-yara": generic | {
            "selected_rule_files",
            "loaded_rule_files",
            "failed_rule_files",
            "rules_loaded",
            "selected_file_work_items",
            "match_work_items",
            "match_work_budget",
            "match_timeout_seconds",
            "match_total_timeout_seconds",
            "discovered_rule_files",
            "excluded_rule_files",
        },
        "xprotect": generic | {
            "selected_rule_files",
            "loaded_rule_files",
            "failed_rule_files",
            "rules_loaded",
            "selected_file_work_items",
            "match_work_items",
            "match_work_budget",
            "match_timeout_seconds",
            "match_total_timeout_seconds",
        },
        "gatekeeper": generic | {
            "target",
            "target_sha256",
            "target_signature_command",
            "target_signature_valid",
        },
    }
    unexpected = sorted(set(coverage) - by_scanner[scanner_id])
    if unexpected:
        raise AttestationError(
            f"{scanner_id}.coverage contains fields outside its declared profile: {unexpected}"
        )
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
        raise AttestationError(
            "Gatekeeper success is unsupported for the current loose-file corpus; a bound "
            "top-level .app target/control profile is required"
        )
    if scanned != corpus["file_count"]:
        raise AttestationError(f"{scanner_id} did not scan every bound corpus file")
    if scanner_id == "clamav":
        if coverage.get("kind") != "engine-reported-file-count":
            raise AttestationError("ClamAV coverage must come from its engine-reported count")
        method = _require_mapping(result.get("method"), "clamav.method")
        command = _require_list(method.get("command"), "clamav.method.command")
        expected_length = len(CLAMAV_LIMIT_ARGS) + 5
        if (
            len(command) != expected_length
            or not isinstance(command[1], str)
            or not command[1].startswith("--database=")
            or not command[1].partition("=")[2]
            or command[2 : 2 + len(CLAMAV_LIMIT_ARGS)] != list(CLAMAV_LIMIT_ARGS)
            or command[-3:-1] != ["--recursive", "--infected"]
            or not isinstance(command[-1], str)
            or not command[-1]
        ):
            raise AttestationError(
                "ClamAV command is outside the exact bound-database/no-skip scan profile"
            )
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
    if coverage["rules_loaded"] > MAX_YARA_RULES_LOADED:
        raise AttestationError(
            f"{scanner_id} exceeds the {MAX_YARA_RULES_LOADED}-rule load limit"
        )
    expected_file_work = coverage["selected_rule_files"] * corpus["file_count"]
    if coverage.get("selected_file_work_items") != expected_file_work:
        raise AttestationError(
            f"{scanner_id} selected-file work does not equal rule files x corpus files"
        )
    expected_match_work = coverage["rules_loaded"] * corpus["file_count"]
    if coverage.get("match_work_items") != expected_match_work:
        raise AttestationError(
            f"{scanner_id} match work does not equal loaded rules x corpus files"
        )
    if coverage.get("match_work_budget") != YARA_WORK_BUDGET:
        raise AttestationError(f"{scanner_id} weakens or changes the YARA work budget")
    if expected_file_work > YARA_WORK_BUDGET or expected_match_work > YARA_WORK_BUDGET:
        raise AttestationError(f"{scanner_id} exhausted the YARA match work budget")
    if coverage.get("match_timeout_seconds") != YARA_MATCH_TIMEOUT_SECONDS:
        raise AttestationError(f"{scanner_id} weakens or changes the YARA match timeout")
    if coverage.get("match_total_timeout_seconds") != YARA_MATCH_TOTAL_TIMEOUT_SECONDS:
        raise AttestationError(
            f"{scanner_id} weakens or changes the YARA corpus-match deadline"
        )
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
    # Enforce declared collection/text/type bounds before semantic loops consume the record.
    _validate_declared_schema(record)
    rendered_size = len((json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
    if rendered_size > MAX_RECORD_BYTES:
        raise AttestationError(
            "scanner attestation cannot fit the canonical "
            f"{MAX_RECORD_BYTES}-byte record envelope"
        )
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
    manifest_metadata_total = _manifest_metadata_size(
        corpus["canonicalization"], corpus["files"]
    )
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
        if isinstance(rules.get("manifest"), dict):
            manifest_metadata_total += _manifest_metadata_size(
                rules["manifest"]["canonicalization"],
                rules["manifest"]["files"],
            )
            if manifest_metadata_total > MAX_RECORD_MANIFEST_BYTES:
                raise AttestationError(
                    "combined scanner/corpus manifest metadata exceeds the "
                    f"{MAX_RECORD_MANIFEST_BYTES}-byte record budget"
                )
        if scanner_id == "clamav" and result.get("status") in {"clean", "finding"}:
            manifest = rules.get("manifest")
            if not isinstance(manifest, dict) or rules.get("fingerprint_sha256") is None:
                raise AttestationError(
                    "ClamAV clean/finding results must bind the actual selected database bytes"
                )
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
        if control.get("status") == "passed" and scanner_id == "clamav":
            control_command = _require_list(control.get("command"), "clamav.control.command")
            profile_prefix_length = len(CLAMAV_LIMIT_ARGS) + 2
            if (
                len(control_command) != profile_prefix_length + 3
                or control_command[:profile_prefix_length]
                != method_command[:profile_prefix_length]
                or control_command[-3:-1] != ["--infected", "--no-summary"]
                or not isinstance(control_command[-1], str)
                or not control_command[-1]
            ):
                raise AttestationError(
                    "ClamAV positive control is not coupled to the exact corpus engine/database "
                    "and no-skip limit profile"
                )
        if control.get("status") == "passed" and scanner_id == "gatekeeper":
            control_command = _require_list(
                control.get("command"), "gatekeeper.control.command"
            )
            if control_command[0] != method_command[0]:
                raise AttestationError(
                    "Gatekeeper control and target must use the same spctl executable"
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
    _safe_component(output.name, "scanner attestation output")
    rendered = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    if len(rendered) > MAX_RECORD_BYTES:
        raise AttestationError(
            f"scanner attestation exceeds the {MAX_RECORD_BYTES}-byte output limit"
        )
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        requested_before = os.stat(output.parent, follow_symlinks=False)
        directory_fd = os.open(output.parent, directory_flags)
    except OSError as exc:
        raise AttestationError(
            f"cannot pin scanner attestation output directory {output.parent}: {exc}"
        ) from exc
    pinned_parent = os.fstat(directory_fd)
    if not stat.S_ISDIR(requested_before.st_mode) or (
        requested_before.st_dev,
        requested_before.st_ino,
        requested_before.st_mode,
    ) != (
        pinned_parent.st_dev,
        pinned_parent.st_ino,
        pinned_parent.st_mode,
    ):
        os.close(directory_fd)
        raise AttestationError(
            "scanner attestation output directory changed before it could be pinned"
        )
    temporary = None
    try:
        for index in range(100):
            candidate = f".{output.name}.{os.getpid()}.{index}.tmp"
            try:
                fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        else:
            raise AttestationError("cannot allocate scanner attestation temporary output")
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(rendered)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise AttestationError("short write while serializing scanner attestation")
                view = view[written:]
            os.fsync(fd)
            temporary_stat = os.fstat(fd)
        finally:
            os.close(fd)
        os.replace(
            temporary,
            output.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary = None
        os.fsync(directory_fd)
        final_fd = os.open(
            output.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        try:
            final_before = os.fstat(final_fd)
            if (
                not stat.S_ISREG(final_before.st_mode)
                or stat.S_IMODE(final_before.st_mode) != 0o600
                or (final_before.st_dev, final_before.st_ino)
                != (temporary_stat.st_dev, temporary_stat.st_ino)
            ):
                raise AttestationError(
                    "published scanner attestation is not the pinned temporary regular file"
                )
            published = _read_regular_fd(
                final_fd,
                "published scanner attestation",
                final_before,
            )
            if published != rendered:
                raise AttestationError(
                    "published scanner attestation bytes differ from the serialized record"
                )
        finally:
            os.close(final_fd)
        try:
            requested_after = os.stat(output.parent, follow_symlinks=False)
        except OSError as exc:
            raise AttestationError(
                "scanner attestation output directory disappeared after publication"
            ) from exc
        if (
            requested_after.st_dev,
            requested_after.st_ino,
            requested_after.st_mode,
        ) != (
            pinned_parent.st_dev,
            pinned_parent.st_ino,
            pinned_parent.st_mode,
        ):
            raise AttestationError(
                "scanner attestation output directory changed during publication"
            )
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _read_record_with_bytes(path: Path) -> tuple[dict, bytes]:
    raw = _read_bounded_regular(path, MAX_RECORD_BYTES, "scanner attestation")
    record = _decode_json(raw, f"scanner attestation {path}")
    return _require_mapping(record, "record"), raw


def read_record(path: Path) -> dict:
    record, _raw = _read_record_with_bytes(path)
    return record


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
        record, raw = _read_record_with_bytes(args.record)
        validate_record(record, require_success=True)
        if args.corpus:
            verify_corpus_binding(record, args.corpus)
        canonical = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
        if raw != canonical:
            raise AttestationError("scanner attestation is not canonical JSON")
        _print_summary(record)
        print("attestation: VALID, FRESH, CONTROLLED, CLEAN")
        return 0
    except AttestationError as exc:
        print(f"scanner attestation FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
