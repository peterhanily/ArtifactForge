# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""One deliberately small, exact JSON representation for fixture records.

Fixture digests are useful only if every producer hashes the same bytes.  This module therefore
defines a narrower format than general JSON: UTF-8 without a BOM, NFC strings, integer numbers
only, lexicographically sorted object keys, compact separators, and exactly one trailing LF.
Duplicate object names are rejected while parsing rather than silently keeping the last value.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from typing import TypeAlias
import unicodedata

JSONScalar: TypeAlias = None | bool | int | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class CanonicalJSONError(ValueError):
    """Input cannot be represented by ArtifactForge canonical JSON."""


def _reject_float(token: str) -> None:
    raise CanonicalJSONError(f"floating-point JSON numbers are forbidden: {token}")


def _reject_constant(token: str) -> None:
    raise CanonicalJSONError(f"non-finite JSON numbers are forbidden: {token}")


def _object_from_pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"duplicate object member: {key!r}")
        result[key] = value
    return result


def _validate_string(value: str, where: str) -> None:
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalJSONError(f"{where} is not Unicode NFC")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError(f"{where} contains an unpaired Unicode surrogate") from exc


def _validate_value(value: object, where: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _validate_string(value, where)
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalJSONError(f"{where} is a float; fixture JSON permits integers only")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{where}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(f"{where} has a non-string object member name")
            _validate_string(key, f"{where} object member name")
            _validate_value(item, f"{where}.{key}")
        return
    raise CanonicalJSONError(
        f"{where} has unsupported type {type(value).__name__}; expected a JSON value"
    )


def load_json_strict(data: bytes | str) -> JSONValue:
    """Parse JSON without the lossy behaviours of :func:`json.loads`.

    In particular, duplicate members, floats, non-finite numbers, a UTF-8 BOM, invalid UTF-8,
    non-NFC strings, and trailing input are all errors.
    """
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            raise CanonicalJSONError("a UTF-8 BOM is forbidden")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalJSONError("input is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
        if text.startswith("\ufeff"):
            raise CanonicalJSONError("a Unicode BOM is forbidden")
    else:
        raise TypeError("strict JSON input must be bytes or str")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalJSONError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CanonicalJSONError(f"invalid JSON: {exc}") from exc

    _validate_value(value)
    return value


def canonical_json_bytes(value: object) -> bytes:
    """Return ArtifactForge canonical JSON: compact UTF-8 followed by exactly one LF."""
    _validate_value(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise CanonicalJSONError(f"cannot encode canonical JSON: {exc}") from exc
    return (rendered + "\n").encode("utf-8", errors="strict")


def load_canonical_json(data: bytes) -> JSONValue:
    """Parse a stored machine record and require its bytes to be the canonical spelling."""
    if not isinstance(data, bytes):
        raise TypeError("canonical machine-record input must be bytes")
    value = load_json_strict(data)
    if data != canonical_json_bytes(value):
        raise CanonicalJSONError(
            "stored JSON is not canonical (sorted compact UTF-8 with exactly one LF)"
        )
    return value


def canonical_sha256(value: object) -> str:
    """Return the labelled SHA-256 of :func:`canonical_json_bytes`."""
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()
