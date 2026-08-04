#!/usr/bin/env python3
# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Validate release SBOMs with the hash-pinned official CycloneDX 1.5 schemas.

The schema directory is caller-supplied so CI can fetch the authoritative files from an
immutable upstream commit.  This program does not resolve references over the network: it
requires the complete reviewed three-file schema set, verifies every byte against its pinned
SHA-256 digest, registers those resources locally, and then applies Draft 7 validation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Sequence

from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError, ValidationError
from referencing import Registry, Resource


CYCLONEDX_SPECIFICATION_COMMIT = "c320fc0f0b46873864927d9d5684eea7ba439728"
CYCLONEDX_SCHEMA_BASE_URL = (
    "https://raw.githubusercontent.com/CycloneDX/specification/"
    f"{CYCLONEDX_SPECIFICATION_COMMIT}/schema"
)

SCHEMA_IDENTIFIERS = {
    "bom-1.5.schema.json": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "jsf-0.82.schema.json": "http://cyclonedx.org/schema/jsf-0.82.schema.json",
    "spdx.schema.json": "http://cyclonedx.org/schema/spdx.schema.json",
}
EXPECTED_SCHEMA_SHA256 = {
    "bom-1.5.schema.json": "067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "spdx.schema.json": "4f6e2b05c05d26a4f2dc5879fbc2fca94b0a28db46289d0c51345621b71cfbfc",
}

MAX_SCHEMA_BYTES = 512 * 1024
MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_SBOMS = 16
MAX_ERROR_CHARACTERS = 2_048
MAX_JSON_NODES = 250_000
MAX_JSON_DEPTH = 128
_DRAFT_7 = "http://json-schema.org/draft-07/schema#"


class CycloneDXSchemaError(ValueError):
    """Schema provenance or an SBOM is outside the closed validation profile."""


@dataclass(frozen=True)
class _Observation:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int):
        raise CycloneDXSchemaError(
            f"this platform cannot enforce the required {name} no-follow input boundary"
        )
    return value


def _read_descriptor(
    descriptor: int,
    *,
    opened: os.stat_result,
    maximum: int,
    label: str,
) -> tuple[bytes, os.stat_result]:
    chunks: list[bytes] = []
    observed = 0
    try:
        while True:
            room = maximum + 1 - observed
            chunk = os.read(descriptor, min(1024 * 1024, room))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum:
                raise CycloneDXSchemaError(f"{label} exceeds the {maximum}-byte limit")
        final = os.fstat(descriptor)
    except OSError as exc:
        raise CycloneDXSchemaError(f"cannot read {label}: {exc}") from exc
    if _identity(final) != _identity(opened):
        raise CycloneDXSchemaError(f"{label} changed while it was read")
    payload = b"".join(chunks)
    if len(payload) != opened.st_size:
        raise CycloneDXSchemaError(f"{label} size changed while it was read")
    if not payload:
        raise CycloneDXSchemaError(f"{label} is empty")
    return payload, final


def _observation(state: os.stat_result, payload: bytes) -> _Observation:
    return _Observation(
        device=state.st_dev,
        inode=state.st_ino,
        mode=state.st_mode,
        size=state.st_size,
        modified_ns=state.st_mtime_ns,
        changed_ns=state.st_ctime_ns,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _read_regular(path: Path, *, maximum: int, label: str) -> tuple[bytes, _Observation]:
    path = Path(os.path.abspath(path))
    try:
        before = path.lstat()
    except OSError as exc:
        raise CycloneDXSchemaError(f"cannot inspect {label} {path}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise CycloneDXSchemaError(f"{label} is not a regular file: {path}")
    if before.st_size < 1 or before.st_size > maximum:
        raise CycloneDXSchemaError(f"{label} exceeds the 1..{maximum}-byte profile: {path}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | _required_open_flag("O_NOFOLLOW")
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CycloneDXSchemaError(
            f"cannot open {label} {path} without following links: {exc}"
        ) from exc
    try:
        try:
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise CycloneDXSchemaError(f"cannot inspect opened {label} {path}: {exc}") from exc
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise CycloneDXSchemaError(f"{label} changed while it was opened: {path}")
        payload, final = _read_descriptor(
            descriptor,
            opened=opened,
            maximum=maximum,
            label=f"{label} {path}",
        )
    finally:
        os.close(descriptor)

    try:
        after = path.lstat()
    except OSError as exc:
        raise CycloneDXSchemaError(f"cannot re-inspect {label} {path}: {exc}") from exc
    if _identity(after) != _identity(final):
        raise CycloneDXSchemaError(f"{label} changed while it was read: {path}")
    return payload, _observation(final, payload)


def _read_schema_at(directory: int, name: str) -> tuple[bytes, _Observation]:
    try:
        listed = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise CycloneDXSchemaError(f"cannot inspect schema {name}: {exc}") from exc
    if not stat.S_ISREG(listed.st_mode):
        raise CycloneDXSchemaError(f"schema is not a regular file: {name}")
    if listed.st_size < 1 or listed.st_size > MAX_SCHEMA_BYTES:
        raise CycloneDXSchemaError(f"schema {name} exceeds the 1..{MAX_SCHEMA_BYTES}-byte profile")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | _required_open_flag("O_NOFOLLOW")
    )
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError as exc:
        raise CycloneDXSchemaError(
            f"cannot open schema {name} without following links: {exc}"
        ) from exc
    try:
        try:
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise CycloneDXSchemaError(f"cannot inspect opened schema {name}: {exc}") from exc
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(listed):
            raise CycloneDXSchemaError(f"schema {name} changed while it was opened")
        payload, final = _read_descriptor(
            descriptor,
            opened=opened,
            maximum=MAX_SCHEMA_BYTES,
            label=f"schema {name}",
        )
    finally:
        os.close(descriptor)
    try:
        after = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise CycloneDXSchemaError(f"cannot re-inspect schema {name}: {exc}") from exc
    if _identity(after) != _identity(final):
        raise CycloneDXSchemaError(f"schema {name} changed while it was read")
    return payload, _observation(final, payload)


def _schema_payloads(path: Path) -> dict[str, bytes]:
    path = Path(os.path.abspath(path))
    try:
        before = path.lstat()
    except OSError as exc:
        raise CycloneDXSchemaError(f"cannot inspect schema directory {path}: {exc}") from exc
    if not stat.S_ISDIR(before.st_mode):
        raise CycloneDXSchemaError(f"schema path is not a real directory: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | _required_open_flag("O_DIRECTORY")
        | _required_open_flag("O_NOFOLLOW")
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CycloneDXSchemaError(
            f"cannot open schema directory {path} without following links: {exc}"
        ) from exc
    try:
        try:
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise CycloneDXSchemaError(
                f"cannot inspect opened schema directory {path}: {exc}"
            ) from exc
        if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(before):
            raise CycloneDXSchemaError("schema directory changed while it was opened")
        try:
            names = tuple(sorted(os.listdir(descriptor)))
        except OSError as exc:
            raise CycloneDXSchemaError(f"cannot enumerate schema directory {path}: {exc}") from exc
        expected = tuple(sorted(SCHEMA_IDENTIFIERS))
        if names != expected:
            raise CycloneDXSchemaError(
                f"schema directory must contain exactly {expected!r}; observed {names!r}"
            )
        payloads = {name: _read_schema_at(descriptor, name)[0] for name in expected}
        try:
            final = os.fstat(descriptor)
        except OSError as exc:
            raise CycloneDXSchemaError(f"cannot re-inspect schema directory {path}: {exc}") from exc
        if _identity(final) != _identity(opened):
            raise CycloneDXSchemaError("schema directory changed while its files were read")
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise CycloneDXSchemaError(f"cannot re-inspect schema directory {path}: {exc}") from exc
    if _identity(after) != _identity(opened):
        raise CycloneDXSchemaError("schema directory changed while it was read")
    return payloads


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CycloneDXSchemaError(f"JSON contains duplicate object member {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise CycloneDXSchemaError(f"JSON contains non-finite number {value}")


def _bounded_json_integer(value: str) -> int:
    if len(value) > 20:
        raise CycloneDXSchemaError("JSON integer exceeds the signed 64-bit profile")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise CycloneDXSchemaError("JSON integer is not valid base-10 text") from exc
    if not -(1 << 63) <= parsed < (1 << 63):
        raise CycloneDXSchemaError("JSON integer exceeds the signed 64-bit profile")
    return parsed


def _reject_json_float(value: str) -> object:
    raise CycloneDXSchemaError(f"JSON floating-point values are forbidden: {value[:32]}")


def _bound_json_structure(document: object, *, label: str) -> None:
    pending = [(document, 1)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise CycloneDXSchemaError(
                f"{label} exceeds the {MAX_JSON_NODES}-node JSON structure limit"
            )
        if depth > MAX_JSON_DEPTH:
            raise CycloneDXSchemaError(
                f"{label} exceeds the {MAX_JSON_DEPTH}-level JSON nesting limit"
            )
        if isinstance(value, dict):
            for key in value:
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    raise CycloneDXSchemaError(f"{label} contains a lone Unicode surrogate")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in value
        ):
            raise CycloneDXSchemaError(f"{label} contains a lone Unicode surrogate")


def _decode_json(payload: bytes, *, label: str) -> dict[str, object]:
    try:
        text = payload.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_nonfinite,
            parse_int=_bounded_json_integer,
            parse_float=_reject_json_float,
        )
    except CycloneDXSchemaError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CycloneDXSchemaError(f"{label} is not bounded strict UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CycloneDXSchemaError(f"{label} root must be a JSON object")
    _bound_json_structure(document, label=label)
    return document


def _load_schemas(schema_directory: Path) -> tuple[dict[str, object], Registry]:
    payloads = _schema_payloads(schema_directory)
    schemas: dict[str, dict[str, object]] = {}
    for name in sorted(SCHEMA_IDENTIFIERS):
        observed = hashlib.sha256(payloads[name]).hexdigest()
        expected = EXPECTED_SCHEMA_SHA256[name]
        if observed != expected:
            raise CycloneDXSchemaError(
                f"schema {name} SHA-256 mismatch: expected {expected}, observed {observed}"
            )
        schema = _decode_json(payloads[name], label=f"schema {name}")
        if schema.get("$id") != SCHEMA_IDENTIFIERS[name]:
            raise CycloneDXSchemaError(f"schema {name} has the wrong canonical $id")
        if schema.get("$schema") != _DRAFT_7:
            raise CycloneDXSchemaError(f"schema {name} is not the reviewed Draft 7 resource")
        try:
            Draft7Validator.check_schema(schema)
        except SchemaError as exc:
            raise CycloneDXSchemaError(f"schema {name} is invalid: {exc.message}") from exc
        schemas[name] = schema

    try:
        registry = Registry().with_resources(
            (SCHEMA_IDENTIFIERS[name], Resource.from_contents(schemas[name]))
            for name in sorted(schemas)
        )
    except Exception as exc:
        raise CycloneDXSchemaError(
            f"cannot construct the closed CycloneDX schema registry: {type(exc).__name__}: {exc}"
        ) from exc
    return schemas["bom-1.5.schema.json"], registry


def _render_error(error: ValidationError) -> str:
    path = "$"
    for part in error.absolute_path:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += f"[{json.dumps(part, ensure_ascii=True)}]"
    message = " ".join(error.message.split())
    if len(message) > MAX_ERROR_CHARACTERS:
        message = message[: MAX_ERROR_CHARACTERS - 3] + "..."
    return f"{path}: {message}"


def validate(schema_directory: Path, sboms: Sequence[Path]) -> tuple[Path, ...]:
    if not 1 <= len(sboms) <= MAX_SBOMS:
        raise CycloneDXSchemaError(f"expected 1..{MAX_SBOMS} SBOM inputs, observed {len(sboms)}")
    canonical = tuple(Path(os.path.abspath(path)) for path in sboms)
    if len(set(canonical)) != len(canonical):
        raise CycloneDXSchemaError("the same SBOM path was supplied more than once")

    schema, registry = _load_schemas(schema_directory)
    try:
        validator = Draft7Validator(
            schema,
            registry=registry,
            format_checker=Draft7Validator.FORMAT_CHECKER,
        )
    except Exception as exc:
        raise CycloneDXSchemaError(
            f"cannot initialize the closed CycloneDX validator: {type(exc).__name__}: {exc}"
        ) from exc

    identities: set[tuple[int, int]] = set()
    validated: list[Path] = []
    for path in canonical:
        payload, observation = _read_regular(path, maximum=MAX_SBOM_BYTES, label="SBOM")
        file_identity = (observation.device, observation.inode)
        if file_identity in identities:
            raise CycloneDXSchemaError("the same SBOM file was supplied through multiple paths")
        identities.add(file_identity)
        document = _decode_json(payload, label=f"SBOM {path}")
        try:
            validator.validate(document)
        except ValidationError as exc:
            try:
                rendered = _render_error(exc)
            except RecursionError:
                rendered = "$: validation error exceeds the diagnostic nesting limit"
            raise CycloneDXSchemaError(
                f"SBOM {path} fails the official CycloneDX 1.5 schema at {rendered}"
            ) from exc
        except RecursionError as exc:
            raise CycloneDXSchemaError(f"SBOM {path} exceeds the validator nesting limit") from exc
        except Exception as exc:
            raise CycloneDXSchemaError(
                f"SBOM {path} cannot be validated offline: {type(exc).__name__}: {exc}"
            ) from exc
        validated.append(path)
    return tuple(validated)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schema-dir",
        type=Path,
        required=True,
        help="directory containing exactly the three hash-pinned official schema files",
    )
    parser.add_argument("sbom", nargs="+", type=Path, help="CycloneDX 1.5 JSON SBOM")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validated = validate(args.schema_dir, args.sbom)
    except CycloneDXSchemaError as exc:
        print(f"cyclonedx-schema: error: {exc}", file=sys.stderr)
        return 2
    except (OSError, RecursionError) as exc:
        print(
            f"cyclonedx-schema: error: input validation failed safely: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    for path in validated:
        print(f"CycloneDX 1.5 schema PASS: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
