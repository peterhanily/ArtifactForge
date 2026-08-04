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
from artifactforge.fixture.abi import MANIFEST_ABIS
from artifactforge.fixture.canonical import CanonicalJSONError, canonical_json_bytes
from artifactforge.fixture import resources
from artifactforge.fixture.model import (
    FixtureSpec,
    FixtureValidationError,
    parse_fixture_spec,
)
from artifactforge.fixture.model_v2 import FixtureManifestV2, FixtureSpecV2
from artifactforge.fixture.operations import (
    FixturePublicationUncertain,
    FixtureUsageError,
    VerificationResult,
    build_fixture,
    inspect_fixture,
    verify_fixture,
)

EXIT_OK = 0
EXIT_DIFFERENT = 1
EXIT_USAGE = 2


FixtureSpecRecord = FixtureSpec | FixtureSpecV2


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
        "checks": {
            "assurance": "not-run",
            "integrity": "pass",
            "reproduction": "pass",
        },
        "command": "build",
        "error": str(exc),
        "exit_code": EXIT_USAGE,
        "fixture": str(exc.output),
        "generator": manifest.generator.to_mapping(),
        "ok": False,
        "payload": _payload_summary(manifest),
        "published": True,
        "producer": _producer_mapping(manifest),
        "recipe_sha256": manifest.recipe_sha256,
        "tree_sha256": manifest.payload.tree_sha256,
        **_payload_counters(manifest),
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
    manifest = verification.manifest
    mapping = {
        "archive": str(exc.output),
        "checks": {
            "archive_integrity": "pass",
            "assurance": (
                "pass" if bool(getattr(args, "assurance", False)) else "not-run"
            ),
            "integrity": "pass",
            "reproduction": "pass",
        },
        "command": "release",
        "error": str(exc),
        "exit_code": EXIT_USAGE,
        "generator": manifest.generator.to_mapping(),
        "ok": False,
        "payload": _payload_summary(manifest),
        "published": True,
        "producer": _producer_mapping(manifest),
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


def _payload_counters(manifest) -> dict[str, int]:
    """Return only counters that belong to the manifest's declared payload ABI."""
    payload = manifest.payload
    if isinstance(manifest, FixtureManifestV2):
        return {
            "directory_count": payload.directory_count,
            "file_count": payload.file_count,
            "regular_file_bytes": payload.regular_file_bytes,
            "metadata_blob_count": payload.metadata_blob_count,
            "metadata_blob_bytes": payload.metadata_blob_bytes,
            "total_bound_bytes": payload.total_bound_bytes,
        }
    return {
        "file_count": payload.file_count,
        "total_bytes": payload.total_bytes,
    }


def _payload_summary(manifest) -> dict:
    return {
        **_payload_counters(manifest),
        "tree_sha256": manifest.payload.tree_sha256,
    }


def _producer_mapping(manifest) -> dict:
    """Describe parser/producer capability separately from stored provenance."""
    contract = MANIFEST_ABIS.get(manifest.schema)
    if contract is None:  # The typed manifest dispatcher makes this unreachable.
        raise FixtureValidationError(
            f"no fixture ABI is registered for manifest schema {manifest.schema!r}"
        )
    return {
        "abi_contract": contract.name,
        "available": contract.producer_available,
        "frozen_release": contract.frozen_release,
        "implementation": contract.producer_implementation,
        "mode": "produce-and-parse" if contract.producer_available else "parse-only",
        "profile": getattr(manifest.generator, "producer_profile", contract.producer_profile),
    }


def _check_verdict(value: bool | None) -> str:
    if value is None:
        return "not-run"
    return "pass" if value else "fail"


def _verification_checks(
    result: VerificationResult,
    *,
    reproduction_requested: bool,
) -> dict[str, str]:
    """Render lifecycle phases without turning inspection into a reproduction claim."""
    integrity_ok = getattr(result, "integrity_ok", None)
    if integrity_ok is None:
        integrity_ok = not result.failures

    result_reproduction_requested = getattr(
        result, "reproduction_requested", reproduction_requested
    )
    if not reproduction_requested:
        result_reproduction_requested = False
    reproduction_ok = (
        getattr(result, "reproduction_ok", None)
        if result_reproduction_requested
        else None
    )
    if result_reproduction_requested and reproduction_ok is None:
        reproduction_ok = not result.failures

    assurance_summary = getattr(result, "assurance_summary", None)
    assurance_verdict = (
        assurance_summary.get("verdict", "not-run")
        if isinstance(assurance_summary, Mapping)
        else "not-run"
    )
    return {
        "integrity": _check_verdict(integrity_ok),
        "reproduction": _check_verdict(reproduction_ok),
        "assurance": str(assurance_verdict),
    }


def _verification_mapping(
    result: VerificationResult,
    *,
    reproduction_requested: bool = True,
) -> dict:
    mapping = {
        "ok": result.ok,
        "failures": list(result.failures),
        "recipe_sha256": result.manifest.recipe_sha256,
        "tree_sha256": result.manifest.payload.tree_sha256,
        **_payload_counters(result.manifest),
        "checks": _verification_checks(
            result, reproduction_requested=reproduction_requested
        ),
        "generator": result.manifest.generator.to_mapping(),
        "payload": _payload_summary(result.manifest),
        "producer": _producer_mapping(result.manifest),
    }
    reports = getattr(result, "assurance_reports", ()) or getattr(result, "assurance", ()) or ()
    if reports:
        mapping["assurance"] = [_gate_report_mapping(report) for report in reports]
    summary = getattr(result, "assurance_summary", None)
    if summary is not None:
        mapping["assurance_summary"] = summary
    return mapping


def _negative_verification(
    args,
    command: str,
    fixture: str,
    result: VerificationResult,
    *,
    reproduction_requested: bool = True,
) -> int:
    mapping = {
        "command": command,
        "fixture": fixture,
        "ok": False,
        "verification": _verification_mapping(
            result, reproduction_requested=reproduction_requested
        ),
    }
    lines = [f"fixture {command}: FAIL — {fixture}"]
    lines.extend(f"  FAIL  {failure}" for failure in result.failures)
    _emit(args, mapping, lines)
    return EXIT_DIFFERENT


def _load_spec(path: str | Path) -> FixtureSpecRecord:
    try:
        raw = resources.read_stable_regular_path(
            Path(path),
            max_bytes=resources.RESOURCE_POLICY.max_input_bytes,
            label=f"fixture spec {path}",
        )
        return parse_fixture_spec(raw)
    except (OSError, resources.FixtureResourceError) as exc:
        raise FixtureUsageError(f"cannot read fixture spec {path}: {exc}") from exc


def _payload_lines(manifest) -> list[str]:
    payload = manifest.payload
    if isinstance(manifest, FixtureManifestV2):
        return [
            f"  directories/files: {payload.directory_count}/{payload.file_count}",
            f"  regular bytes:     {payload.regular_file_bytes}",
            f"  metadata blobs:    {payload.metadata_blob_count}/"
            f"{payload.metadata_blob_bytes} bytes",
            f"  total bound bytes: {payload.total_bound_bytes}",
        ]
    return [f"  files/bytes: {payload.file_count}/{payload.total_bytes}"]


def _producer_lines(manifest) -> list[str]:
    producer = _producer_mapping(manifest)
    profile = producer["profile"] if producer["profile"] is not None else "none"
    if producer["available"]:
        mode = f"produce-and-parse ({producer['implementation']})"
    else:
        mode = f"parse-only (frozen release {producer['frozen_release']})"
    return [f"  producer profile: {profile}", f"  producer mode:    {mode}"]


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
        "checks": {
            "assurance": "not-run",
            "integrity": "pass",
            "reproduction": "pass",
        },
        "fixture": str(args.output),
        "fixture_id": manifest.recipe.fixture_id,
        "generator": manifest.generator.to_mapping(),
        "ok": True,
        "payload": _payload_summary(manifest),
        "producer": _producer_mapping(manifest),
        "recipe_sha256": manifest.recipe_sha256,
        "tree_sha256": manifest.payload.tree_sha256,
        **_payload_counters(manifest),
    }
    _emit(
        args,
        mapping,
        [
            f"fixture build: PASS — {args.output}",
            f"  fixture id:  {manifest.recipe.fixture_id}",
            f"  generator:   {manifest.generator.name} {manifest.generator.version} "
            f"({manifest.generator.abi})",
            *_producer_lines(manifest),
            f"  recipe:      {manifest.recipe_sha256}",
            f"  payload:     {manifest.payload.tree_sha256}",
            *_payload_lines(manifest),
            "  integrity/reproduction: pass/pass",
            "  assurance:   not run",
        ],
    )
    return EXIT_OK


def cmd_verify(args) -> int:
    try:
        result = verify_fixture(args.fixture, assurance=bool(getattr(args, "assurance", False)))
    except (CanonicalJSONError, FixtureValidationError, FixtureUsageError, OSError) as exc:
        return _usage_error(args, "verify", exc)
    if not result.ok:
        return _negative_verification(args, "verify", str(args.fixture), result)
    checks = _verification_checks(result, reproduction_requested=True)
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
        *_payload_lines(result.manifest),
        *_producer_lines(result.manifest),
        "  integrity/reproduction: "
        f"{checks['integrity']}/{checks['reproduction']}",
        f"  assurance:   {checks['assurance']}",
    ])
    return EXIT_OK


def cmd_inspect(args) -> int:
    try:
        result = inspect_fixture(args.fixture)
    except (CanonicalJSONError, FixtureValidationError, FixtureUsageError, OSError) as exc:
        return _usage_error(args, "inspect", exc)
    if not result.ok:
        return _negative_verification(
            args,
            "inspect",
            str(args.fixture),
            result,
            reproduction_requested=False,
        )
    manifest = result.manifest
    mapping = {
        "checks": _verification_checks(result, reproduction_requested=False),
        "command": "inspect",
        "fixture": str(args.fixture),
        "fixture_id": manifest.recipe.fixture_id,
        "family": manifest.recipe.family,
        "profile": manifest.recipe.profile.id,
        "generator": manifest.generator.to_mapping(),
        "ok": True,
        "producer": _producer_mapping(manifest),
        "recipe_sha256": manifest.recipe_sha256,
        "payload": _payload_summary(manifest),
    }
    _emit(
        args,
        mapping,
        [
            f"fixture inspect: PASS — {args.fixture}",
            f"  fixture id:   {manifest.recipe.fixture_id}",
            f"  family:       {manifest.recipe.family}",
            f"  profile:      {manifest.recipe.profile.id}",
            f"  generator:    {manifest.generator.name} {manifest.generator.version} "
            f"({manifest.generator.abi})",
            *_producer_lines(manifest),
            f"  recipe:       {manifest.recipe_sha256}",
            f"  payload:      {manifest.payload.tree_sha256}",
            *_payload_lines(manifest),
            "  integrity:    pass",
            "  reproduction: not run (inspection only)",
            "  assurance:    not run",
            "  benchmark:    ineligible (public reproducible fixture)",
        ],
    )
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


def _manifest_contract_mapping(manifest) -> dict:
    payload = manifest.payload
    value = {
        "manifest_schema": manifest.schema,
        "manifest_canonicalization": manifest.canonicalization,
        "payload_root": payload.root,
        "payload_canonicalization": payload.canonicalization,
        "purpose": manifest.purpose.to_mapping(),
    }
    if hasattr(manifest, "recipe_digest_domain"):
        value["recipe_digest_domain"] = manifest.recipe_digest_domain
    if hasattr(payload, "digest_domain"):
        value["payload_digest_domain"] = payload.digest_domain
    return value


def _node_semantic_mapping(node) -> dict:
    """Key named metadata blobs by name so one insertion cannot shift every diff."""
    mapping = node.to_mapping()
    metadata = mapping.get("metadata")
    if not isinstance(metadata, dict):  # Typed node invariant.
        return mapping
    metadata = dict(metadata)
    for field in ("xattrs", "streams"):
        blobs = metadata.get(field)
        if isinstance(blobs, list):
            metadata[field] = {blob["name"]: blob for blob in blobs}
    mapping = dict(mapping)
    mapping["metadata"] = metadata
    return mapping


def _v2_node_diff(left_nodes, right_nodes) -> dict:
    """Compare logical nodes by carrier identity, never by array position."""
    left_by_path = {node.served_path: node for node in left_nodes}
    right_by_path = {node.served_path: node for node in right_nodes}
    common = sorted(set(left_by_path) & set(right_by_path))
    changed = []
    for served_path in common:
        left_node = left_by_path[served_path]
        right_node = right_by_path[served_path]
        if left_node == right_node:
            continue
        changed.append(
            {
                "served_path": served_path,
                "left_guest_path": left_node.guest_path,
                "right_guest_path": right_node.guest_path,
                "changes": _object_changes(
                    _node_semantic_mapping(left_node),
                    _node_semantic_mapping(right_node),
                ),
            }
        )
    return {
        "added": [right_by_path[path].to_mapping() for path in sorted(
            set(right_by_path) - set(left_by_path)
        )],
        "removed": [left_by_path[path].to_mapping() for path in sorted(
            set(left_by_path) - set(right_by_path)
        )],
        "changed": changed,
    }


def _v1_payload_diff(left, right) -> dict:
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
        "added": sorted(set(right_files) - set(left_files)),
        "removed": sorted(set(left_files) - set(right_files)),
        "changed": changed,
    }


def _mixed_payload_projection(manifest) -> dict:
    if isinstance(manifest, FixtureManifestV2):
        return {
            "kind": "logical-filesystem-v2",
            **_payload_counters(manifest),
            "directories": [node.to_mapping() for node in manifest.payload.directories],
            "files": [node.to_mapping() for node in manifest.payload.files],
        }
    return {
        "kind": "flat-files-v1",
        **_payload_counters(manifest),
        "files": [entry.to_mapping() for entry in manifest.payload.files],
    }


def _semantic_diff(left, right) -> dict:
    both_v2 = isinstance(left, FixtureManifestV2) and isinstance(
        right, FixtureManifestV2
    )
    neither_v2 = not isinstance(left, FixtureManifestV2) and not isinstance(
        right, FixtureManifestV2
    )
    if both_v2:
        payload = {
            "directories": _v2_node_diff(
                left.payload.directories, right.payload.directories
            ),
            "files": _v2_node_diff(left.payload.files, right.payload.files),
        }
    elif neither_v2:
        payload = _v1_payload_diff(left, right)
    else:
        payload = {
            "contract_change": {
                "left": _mixed_payload_projection(left),
                "right": _mixed_payload_projection(right),
            }
        }
    return {
        "contract_changes": _object_changes(
            _manifest_contract_mapping(left), _manifest_contract_mapping(right)
        ),
        "recipe_changes": _object_changes(left.recipe.to_mapping(), right.recipe.to_mapping()),
        "generator_changes": _object_changes(
            left.generator.to_mapping(), right.generator.to_mapping()),
        "payload": payload,
    }


def _collection_has_changes(collection: Mapping) -> bool:
    return any(bool(collection.get(key)) for key in ("added", "removed", "changed"))


def _payload_has_changes(payload: Mapping) -> bool:
    if "contract_change" in payload:
        return True
    if "directories" in payload or "files" in payload:
        return any(
            isinstance(payload.get(kind), Mapping)
            and _collection_has_changes(payload[kind])
            for kind in ("directories", "files")
        )
    return _collection_has_changes(payload)


def _v2_payload_change_lines(payload: Mapping) -> list[str]:
    lines: list[str] = []
    for kind in ("directories", "files"):
        collection = payload[kind]
        singular = kind[:-1]
        lines.extend(
            f"  payload {singular} added: {node['served_path']} "
            f"(guest {node['guest_path']})"
            for node in collection["added"]
        )
        lines.extend(
            f"  payload {singular} removed: {node['served_path']} "
            f"(guest {node['guest_path']})"
            for node in collection["removed"]
        )
        for node in collection["changed"]:
            guest = node["left_guest_path"]
            if guest != node["right_guest_path"]:
                guest = f"{guest} -> {node['right_guest_path']}"
            lines.append(
                f"  payload {singular} changed: {node['served_path']} (guest {guest})"
            )
            lines.extend(
                f"    {change['path']}"
                for change in node["changes"]
            )
    return lines


def _payload_change_lines(payload: Mapping) -> list[str]:
    if "contract_change" in payload:
        change = payload["contract_change"]
        return [
            "  payload contract changed: "
            f"{change['left']['kind']} -> {change['right']['kind']}"
        ]
    if "directories" in payload or "files" in payload:
        return _v2_payload_change_lines(payload)
    lines = [f"  payload added: {path}" for path in payload["added"]]
    lines.extend(f"  payload removed: {path}" for path in payload["removed"])
    lines.extend(
        f"  payload changed: {change['path']}" for change in payload["changed"]
    )
    return lines


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
                     "verification": _verification_mapping(
                         left_result, reproduction_requested=True
                     )},
            "ok": False,
            "right": {"fixture": str(args.right),
                      "verification": _verification_mapping(
                          right_result, reproduction_requested=True
                      )},
        }
        lines = [f"fixture diff: FAIL — {args.left} <> {args.right}"]
        lines.extend(f"  LEFT FAIL   {failure}" for failure in left_result.failures)
        lines.extend(f"  RIGHT FAIL  {failure}" for failure in right_result.failures)
        _emit(args, mapping, lines)
        return EXIT_DIFFERENT

    differences = _semantic_diff(left_result.manifest, right_result.manifest)
    identical = not (
        differences["contract_changes"]
        or
        differences["recipe_changes"]
        or differences["generator_changes"]
        or _payload_has_changes(differences["payload"])
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
        lines.extend(f"  contract {change['path']}: {change['left']} -> {change['right']}"
                     for change in differences["contract_changes"])
        lines.extend(f"  recipe {change['path']}: {change['left']} -> {change['right']}"
                     for change in differences["recipe_changes"])
        lines.extend(f"  generator {change['path']}: {change['left']} -> {change['right']}"
                     for change in differences["generator_changes"])
        lines.extend(_payload_change_lines(differences["payload"]))
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
    checks = _verification_checks(
        result.fixture_verification,
        reproduction_requested=True,
    )
    mapping = {
        "checks": {
            **checks,
            "archive_integrity": "pass",
        },
        "command": "release",
        "fixture": str(args.fixture),
        "fixture_id": result.manifest.recipe.fixture_id,
        "generator": result.manifest.generator.to_mapping(),
        "ok": True,
        "payload": _payload_summary(result.manifest),
        "producer": _producer_mapping(result.manifest),
        "release": result.to_mapping(),
    }
    _emit(
        args,
        mapping,
        [
            f"fixture release: PASS — {result.path}",
            f"  fixture id: {result.manifest.recipe.fixture_id}",
            f"  generator:  {result.manifest.generator.name} "
            f"{result.manifest.generator.version} ({result.manifest.generator.abi})",
            *_producer_lines(result.manifest),
            *_payload_lines(result.manifest),
            f"  sha256:    {result.sha256}",
            f"  bytes:     {result.size}",
            f"  members:   {len(result.members)}",
            "  integrity/reproduction: "
            f"{checks['integrity']}/{checks['reproduction']}",
            "  archive integrity: pass",
            f"  assurance: {checks['assurance']}",
        ],
    )
    return EXIT_OK


# The parent parser may prefer fully qualified handler names; keep both spellings stable.
cmd_fixture_build = cmd_build
cmd_fixture_verify = cmd_verify
cmd_fixture_inspect = cmd_inspect
cmd_fixture_diff = cmd_diff
cmd_fixture_release = cmd_release
