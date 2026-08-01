# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fixture Core command handlers with stable human/JSON output and three exit classes."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import sys

from artifactforge.fixture.archive import (
    ArchivePublicationUncertain,
    FixtureArchiveError,
    FixtureArchiveMismatch,
    create_release_archive,
)
from artifactforge.fixture.canonical import CanonicalJSONError, canonical_json_bytes
from artifactforge.fixture.model import FixtureSpec, FixtureValidationError
from artifactforge.fixture.operations import (
    FixturePublicationUncertain,
    FixtureUsageError,
    VerificationResult,
    build_fixture,
    verify_fixture,
)

EXIT_OK = 0
EXIT_DIFFERENT = 1
EXIT_USAGE = 2


def _json_requested(args) -> bool:
    return bool(getattr(args, "json", False) or getattr(args, "output_format", None) == "json")


def _emit(args, mapping: Mapping, lines: list[str]) -> None:
    if _json_requested(args):
        sys.stdout.write(canonical_json_bytes(mapping).decode("utf-8"))
    else:
        sys.stdout.write("\n".join(lines) + "\n")


def _usage_error(args, command: str, exc: Exception) -> int:
    mapping = {"command": command, "error": str(exc), "exit_code": EXIT_USAGE, "ok": False}
    if _json_requested(args):
        sys.stderr.write(canonical_json_bytes(mapping).decode("utf-8"))
    else:
        print(f"fixture {command}: {exc}", file=sys.stderr)
    return EXIT_USAGE


def _publication_uncertain(args, exc: FixturePublicationUncertain) -> int:
    manifest = exc.manifest
    mapping = {
        "command": "build",
        "error": str(exc),
        "exit_code": EXIT_USAGE,
        "fixture": str(exc.output),
        "ok": False,
        "published": True,
        "recipe_sha256": manifest.recipe_sha256,
        "tree_sha256": manifest.payload.tree_sha256,
    }
    if _json_requested(args):
        sys.stderr.write(canonical_json_bytes(mapping).decode("utf-8"))
    else:
        print(f"fixture build: PUBLICATION UNCERTAIN — {exc.output}", file=sys.stderr)
        print("  published: true (output exists and verified)", file=sys.stderr)
        print(f"  recipe:    {manifest.recipe_sha256}", file=sys.stderr)
        print(f"  payload:   {manifest.payload.tree_sha256}", file=sys.stderr)
        print(f"  durability: {exc}", file=sys.stderr)
    return EXIT_USAGE


def _archive_publication_uncertain(args, exc: ArchivePublicationUncertain) -> int:
    verification = exc.verification
    mapping = {
        "archive": str(exc.output),
        "command": "release",
        "error": str(exc),
        "exit_code": EXIT_USAGE,
        "ok": False,
        "published": True,
        "sha256": verification.sha256,
        "size": verification.size,
    }
    if _json_requested(args):
        sys.stderr.write(canonical_json_bytes(mapping).decode("utf-8"))
    else:
        print(f"fixture release: PUBLICATION UNCERTAIN — {exc.output}", file=sys.stderr)
        print("  published: true (archive exists and verified)", file=sys.stderr)
        print(f"  sha256:   {verification.sha256}", file=sys.stderr)
        print(f"  bytes:    {verification.size}", file=sys.stderr)
        print(f"  durability: {exc}", file=sys.stderr)
    return EXIT_USAGE


def _gate_report_mapping(report) -> dict:
    return {
        "name": report.name,
        "ok": report.ok,
        "fails": list(report.fails),
        "gaps": list(report.gaps),
        "metrics": dict(sorted(report.metrics.items())),
        "denominator": report.denominator,
    }


def _verification_mapping(result: VerificationResult) -> dict:
    mapping = {
        "ok": result.ok,
        "failures": list(result.failures),
        "recipe_sha256": result.manifest.recipe_sha256,
        "tree_sha256": result.manifest.payload.tree_sha256,
        "file_count": result.manifest.payload.file_count,
        "total_bytes": result.manifest.payload.total_bytes,
    }
    reports = getattr(result, "assurance_reports", ()) or getattr(result, "assurance", ()) or ()
    if reports:
        mapping["assurance"] = [_gate_report_mapping(report) for report in reports]
    summary = getattr(result, "assurance_summary", None)
    if summary is not None:
        mapping["assurance_summary"] = summary
    return mapping


def _negative_verification(args, command: str, fixture: str,
                           result: VerificationResult) -> int:
    mapping = {
        "command": command,
        "fixture": fixture,
        "ok": False,
        "verification": _verification_mapping(result),
    }
    lines = [f"fixture {command}: FAIL — {fixture}"]
    lines.extend(f"  FAIL  {failure}" for failure in result.failures)
    _emit(args, mapping, lines)
    return EXIT_DIFFERENT


def _load_spec(path: str | Path) -> FixtureSpec:
    try:
        return FixtureSpec.from_json(Path(path).read_bytes())
    except OSError as exc:
        raise FixtureUsageError(f"cannot read fixture spec {path}: {exc}") from exc


def cmd_build(args) -> int:
    try:
        spec = _load_spec(args.spec)
        manifest = build_fixture(spec, args.output)
    except FixturePublicationUncertain as exc:
        return _publication_uncertain(args, exc)
    except (CanonicalJSONError, FixtureValidationError, FixtureUsageError, OSError) as exc:
        return _usage_error(args, "build", exc)
    mapping = {
        "command": "build",
        "fixture": str(args.output),
        "fixture_id": manifest.recipe.fixture_id,
        "ok": True,
        "recipe_sha256": manifest.recipe_sha256,
        "tree_sha256": manifest.payload.tree_sha256,
        "file_count": manifest.payload.file_count,
        "total_bytes": manifest.payload.total_bytes,
    }
    _emit(args, mapping, [
        f"fixture build: PASS — {args.output}",
        f"  fixture id:   {manifest.recipe.fixture_id}",
        f"  recipe:      {manifest.recipe_sha256}",
        f"  payload:     {manifest.payload.tree_sha256}",
        f"  files/bytes: {manifest.payload.file_count}/{manifest.payload.total_bytes}",
    ])
    return EXIT_OK


def cmd_verify(args) -> int:
    try:
        result = verify_fixture(args.fixture, assurance=bool(getattr(args, "assurance", False)))
    except (CanonicalJSONError, FixtureValidationError, FixtureUsageError, OSError) as exc:
        return _usage_error(args, "verify", exc)
    if not result.ok:
        return _negative_verification(args, "verify", str(args.fixture), result)
    mapping = {
        "command": "verify",
        "fixture": str(args.fixture),
        "ok": True,
        "verification": _verification_mapping(result),
    }
    _emit(args, mapping, [
        f"fixture verify: PASS — {args.fixture}",
        f"  recipe:      {result.manifest.recipe_sha256}",
        f"  payload:     {result.manifest.payload.tree_sha256}",
        f"  files/bytes: {result.manifest.payload.file_count}/"
        f"{result.manifest.payload.total_bytes}",
        f"  assurance:   {'enabled' if getattr(args, 'assurance', False) else 'not requested'}",
    ])
    return EXIT_OK


def cmd_inspect(args) -> int:
    try:
        result = verify_fixture(args.fixture, assurance=False)
    except (CanonicalJSONError, FixtureValidationError, FixtureUsageError, OSError) as exc:
        return _usage_error(args, "inspect", exc)
    if not result.ok:
        return _negative_verification(args, "inspect", str(args.fixture), result)
    manifest = result.manifest
    mapping = {
        "command": "inspect",
        "fixture": str(args.fixture),
        "fixture_id": manifest.recipe.fixture_id,
        "family": manifest.recipe.family,
        "profile": manifest.recipe.profile.id,
        "generator": manifest.generator.to_mapping(),
        "ok": True,
        "recipe_sha256": manifest.recipe_sha256,
        "payload": {
            "file_count": manifest.payload.file_count,
            "total_bytes": manifest.payload.total_bytes,
            "tree_sha256": manifest.payload.tree_sha256,
        },
    }
    _emit(args, mapping, [
        f"fixture inspect: PASS — {args.fixture}",
        f"  fixture id:   {manifest.recipe.fixture_id}",
        f"  family:       {manifest.recipe.family}",
        f"  profile:      {manifest.recipe.profile.id}",
        f"  generator:    {manifest.generator.name} {manifest.generator.version} "
        f"({manifest.generator.abi})",
        f"  recipe:       {manifest.recipe_sha256}",
        f"  payload:      {manifest.payload.tree_sha256}",
        f"  files/bytes:  {manifest.payload.file_count}/{manifest.payload.total_bytes}",
        "  benchmark:    ineligible (public reproducible fixture)",
    ])
    return EXIT_OK


def _object_changes(left: Mapping, right: Mapping, path: str = "") -> list[dict]:
    changes: list[dict] = []
    for key in sorted(set(left) | set(right)):
        pointer = f"{path}/{key.replace('~', '~0').replace('/', '~1')}"
        left_value = left.get(key)
        right_value = right.get(key)
        if isinstance(left_value, Mapping) and isinstance(right_value, Mapping):
            changes.extend(_object_changes(left_value, right_value, pointer))
        elif left_value != right_value or type(left_value) is not type(right_value):
            changes.append({"path": pointer, "left": left_value, "right": right_value})
    return changes


def _semantic_diff(left, right) -> dict:
    left_files = {entry.path: entry for entry in left.payload.files}
    right_files = {entry.path: entry for entry in right.payload.files}
    common = sorted(set(left_files) & set(right_files))
    changed = []
    for path in common:
        left_entry, right_entry = left_files[path], right_files[path]
        if left_entry != right_entry:
            changed.append({
                "path": path,
                "left": {"size": left_entry.size, "sha256": left_entry.sha256},
                "right": {"size": right_entry.size, "sha256": right_entry.sha256},
            })
    return {
        "recipe_changes": _object_changes(left.recipe.to_mapping(), right.recipe.to_mapping()),
        "generator_changes": _object_changes(
            left.generator.to_mapping(), right.generator.to_mapping()),
        "payload": {
            "added": sorted(set(right_files) - set(left_files)),
            "removed": sorted(set(left_files) - set(right_files)),
            "changed": changed,
        },
    }


def cmd_diff(args) -> int:
    try:
        left_result = verify_fixture(args.left, assurance=False)
        right_result = verify_fixture(args.right, assurance=False)
    except (CanonicalJSONError, FixtureValidationError, FixtureUsageError, OSError) as exc:
        return _usage_error(args, "diff", exc)
    if not left_result.ok or not right_result.ok:
        mapping = {
            "command": "diff",
            "identical": False,
            "left": {"fixture": str(args.left),
                     "verification": _verification_mapping(left_result)},
            "ok": False,
            "right": {"fixture": str(args.right),
                      "verification": _verification_mapping(right_result)},
        }
        lines = [f"fixture diff: FAIL — {args.left} <> {args.right}"]
        lines.extend(f"  LEFT FAIL   {failure}" for failure in left_result.failures)
        lines.extend(f"  RIGHT FAIL  {failure}" for failure in right_result.failures)
        _emit(args, mapping, lines)
        return EXIT_DIFFERENT

    differences = _semantic_diff(left_result.manifest, right_result.manifest)
    identical = not (
        differences["recipe_changes"]
        or differences["generator_changes"]
        or any(differences["payload"].values())
    )
    mapping = {
        "command": "diff",
        **differences,
        "identical": identical,
        "left": str(args.left),
        "ok": identical,
        "right": str(args.right),
    }
    if identical:
        lines = [f"fixture diff: IDENTICAL — {args.left} == {args.right}"]
    else:
        lines = [f"fixture diff: DIFFERENT — {args.left} <> {args.right}"]
        lines.extend(f"  recipe {change['path']}: {change['left']} -> {change['right']}"
                     for change in differences["recipe_changes"])
        lines.extend(f"  generator {change['path']}: {change['left']} -> {change['right']}"
                     for change in differences["generator_changes"])
        lines.extend(f"  payload added: {path}" for path in differences["payload"]["added"])
        lines.extend(f"  payload removed: {path}"
                     for path in differences["payload"]["removed"])
        lines.extend(f"  payload changed: {change['path']}"
                     for change in differences["payload"]["changed"])
    _emit(args, mapping, lines)
    return EXIT_OK if identical else EXIT_DIFFERENT


def cmd_release(args) -> int:
    try:
        result = create_release_archive(
            args.fixture, args.output, assurance=bool(getattr(args, "assurance", False)))
    except ArchivePublicationUncertain as exc:
        return _archive_publication_uncertain(args, exc)
    except FixtureArchiveMismatch as exc:
        mapping = {
            "command": "release",
            "failures": list(exc.failures),
            "fixture": str(args.fixture),
            "ok": False,
        }
        lines = [f"fixture release: FAIL — {args.fixture}"]
        lines.extend(f"  FAIL  {failure}" for failure in exc.failures)
        _emit(args, mapping, lines)
        return EXIT_DIFFERENT
    except (CanonicalJSONError, FixtureArchiveError, FixtureValidationError,
            FixtureUsageError, OSError) as exc:
        return _usage_error(args, "release", exc)
    mapping = {
        "command": "release",
        "fixture": str(args.fixture),
        "fixture_id": result.manifest.recipe.fixture_id,
        "ok": True,
        "release": result.to_mapping(),
    }
    _emit(args, mapping, [
        f"fixture release: PASS — {result.path}",
        f"  fixture id: {result.manifest.recipe.fixture_id}",
        f"  sha256:    {result.sha256}",
        f"  bytes:     {result.size}",
        f"  members:   {len(result.members)}",
        f"  assurance: {'enabled' if getattr(args, 'assurance', False) else 'not requested'}",
    ])
    return EXIT_OK


# The parent parser may prefer fully qualified handler names; keep both spellings stable.
cmd_fixture_build = cmd_build
cmd_fixture_verify = cmd_verify
cmd_fixture_inspect = cmd_inspect
cmd_fixture_diff = cmd_diff
cmd_fixture_release = cmd_release
