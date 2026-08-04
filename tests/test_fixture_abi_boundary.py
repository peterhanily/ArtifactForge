# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Frozen Fixture ABI v1 stays readable without being silently re-produced."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest

from artifactforge.cli import fixture as fixture_cli
from artifactforge.fixture import operations
from artifactforge.fixture.abi import (
    FIXTURE_ABI_V1,
    SPEC_ABIS,
    FixtureProducerUnavailable,
)
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixturePayload,
    FixtureValidationError,
    GeneratorIdentity,
    compute_tree_sha256,
    parse_fixture_manifest,
    parse_fixture_spec,
)
from artifactforge.fixture.operations import (
    FixtureUsageError,
    build_fixture,
    inspect_fixture,
    require_supported_manifest,
    verify_fixture,
)


ROOT = Path(__file__).parents[1]
EXAMPLE_SPEC = ROOT / "examples" / "fixtures" / "windows-loose-v1.json"
GOLDEN_ROOT = Path(__file__).parent / "fixtures" / "fixture-v1-goldens"

GOLDENS = {
    "windows-v0.5.0.json": {
        "manifest_sha256": "49c68f8ec1197f66b8eaea767a88a506fc9af60e80869727e3f58aa19c784878",
        "recipe_sha256": "sha256:b62fa514ecffff5d847b2abf27f6c8a471b24487a0b595fbeb1a39177c438ff8",
        "tree_sha256": "sha256:137ae0ca86fa660ef112cdf36f0a9192c57e1f7e5b1d736146b71004329f9891",
        "file_count": 11,
        "total_bytes": 36075,
    },
    "macos-v0.5.0.json": {
        "manifest_sha256": "44349a86e6883a40df393dfbab66c87aaebc63818c675b065befe78a28b25cbe",
        "recipe_sha256": "sha256:88020829d2639a39374a18e2178cea4ed2a3d1bd5216c804ea1384f152332dc6",
        "tree_sha256": "sha256:0a05f1639ec88324102cd8552104db00822fb85427704468deac7897c3a7af8b",
        "file_count": 16,
        "total_bytes": 210673,
    },
    "linux-v0.5.0.json": {
        "manifest_sha256": "9c73aeee747de4a6180fc8955ff984bae0344fb5a144f00b2c4fcdc4be9a96ea",
        "recipe_sha256": "sha256:893e029f80a29628420f11ca6b10d4c17b9c37e2e826e8ba8325525e7501c8a3",
        "tree_sha256": "sha256:031ef526d9be376cb03dacb91b3b0dc2e3b1b9f7bafd35e03b58071fb65f9b8f",
        "file_count": 9,
        "total_bytes": 44836,
    },
}


def _args(**values):
    return argparse.Namespace(**values)


def _historical_fixture(root: Path) -> FixtureManifest:
    """Materialise a tiny, self-consistent v1 record without invoking a producer helper."""
    spec = parse_fixture_spec(EXAMPLE_SPEC.read_bytes())
    data = b"pinned historical payload"
    entry = ArtifactEntry.from_bytes("historical.bin", data)
    payload = FixturePayload(
        file_count=1,
        total_bytes=len(data),
        tree_sha256=compute_tree_sha256((entry,)),
        files=(entry,),
    )
    manifest = FixtureManifest(
        generator=GeneratorIdentity(version="0.5.0"),
        recipe=spec,
        recipe_sha256=spec.recipe_sha256,
        payload=payload,
    )
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True)
    (artifacts / entry.path).write_bytes(data)
    (root / "fixture.json").write_bytes(manifest.canonical_bytes())
    return manifest


def test_v1_registry_is_immutable_parse_only_and_not_inferred_from_version(monkeypatch):
    assert FIXTURE_ABI_V1.frozen_release == "0.5.0"
    assert FIXTURE_ABI_V1.producer_available is False
    assert FIXTURE_ABI_V1.producer_implementation is None
    with pytest.raises(TypeError):
        SPEC_ABIS["forged"] = FIXTURE_ABI_V1  # type: ignore[index]

    manifest = parse_fixture_manifest(
        (GOLDEN_ROOT / "windows-v0.5.0.json").read_bytes(),
        require_canonical=True,
    )
    monkeypatch.setattr(operations, "__version__", manifest.generator.version)
    with pytest.raises(FixtureUsageError, match="parse-only.*must not relabel"):
        require_supported_manifest(manifest)


@pytest.mark.parametrize(("filename", "expected"), GOLDENS.items())
def test_complete_v050_manifests_are_byte_pinned_and_parser_compatible(filename, expected):
    raw = (GOLDEN_ROOT / filename).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected["manifest_sha256"]

    # Both the historical class parser and the new lifecycle dispatcher retain v1 support.
    historical = FixtureManifest.from_canonical_json(raw)
    dispatched = parse_fixture_manifest(raw, require_canonical=True)
    assert dispatched == historical
    assert dispatched.canonical_bytes() == raw
    assert dispatched.generator.version == "0.5.0"
    assert dispatched.recipe_sha256 == expected["recipe_sha256"]
    assert dispatched.payload.tree_sha256 == expected["tree_sha256"]
    assert dispatched.payload.file_count == expected["file_count"]
    assert dispatched.payload.total_bytes == expected["total_bytes"]


def test_v1_schema_resource_bytes_are_frozen():
    expected = {
        "fixture-manifest-v1.schema.json": (
            "ad9e8599e6e6539378570663408e1612b05a53e335898f15ac9bccb23da4bf8c"
        ),
        "fixture-spec-v1.schema.json": (
            "dc8a8a5fba41d91e10f0ca982b7e606ec498827908a9de9890c0643d4d08a562"
        ),
    }
    root = ROOT / "src" / "artifactforge" / "fixture" / "schemas"
    assert {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in expected
    } == expected


def test_dispatch_is_exact_and_never_relabels_v1_as_a_future_schema():
    spec = json.loads(EXAMPLE_SPEC.read_text())
    spec["schema"] = "artifactforge-fixture-spec-v2"
    with pytest.raises(FixtureValidationError, match="missing 'causal_clock'"):
        parse_fixture_spec(json.dumps(spec))

    manifest = json.loads((GOLDEN_ROOT / "windows-v0.5.0.json").read_text())
    manifest["schema"] = "artifactforge-fixture-manifest-v2"
    with pytest.raises(FixtureValidationError, match="missing 'recipe_digest_domain'"):
        parse_fixture_manifest(json.dumps(manifest))

    del spec["schema"]
    with pytest.raises(FixtureValidationError, match="spec.schema must be a string"):
        parse_fixture_spec(json.dumps(spec))


def test_v1_payload_and_manifest_construction_helpers_refuse_new_labels():
    spec = parse_fixture_spec(EXAMPLE_SPEC.read_bytes())
    entry = ArtifactEntry.from_bytes("new.bin", b"new writer bytes")
    with pytest.raises(FixtureProducerUnavailable, match="parse-only.*must not relabel"):
        FixturePayload.create((entry,))
    with pytest.raises(FixtureProducerUnavailable, match="parse-only.*must not relabel"):
        FixtureManifest.create(spec, generator_version="0.5.0", entries=(entry,))


def test_lifecycle_refuses_v1_reproduction_but_preserves_read_only_inspection(
    tmp_path, monkeypatch, capsys
):
    root = tmp_path / "historical"
    manifest = _historical_fixture(root)
    generation_calls: list[str] = []

    def forbidden(*_args, **_kwargs):
        generation_calls.append("called")
        raise AssertionError("a v1 writer or reproduction path ran")

    monkeypatch.setattr(operations, "_materialise_publication", forbidden)
    monkeypatch.setattr(operations, "build_windows_scene", forbidden)
    monkeypatch.setattr(operations, "build_macos_scene", forbidden)
    monkeypatch.setattr(operations, "build_linux_scene", forbidden)

    inspected = inspect_fixture(root)
    assert inspected.ok and inspected.manifest == manifest
    assert generation_calls == []

    with pytest.raises(FixtureUsageError, match="parse-only.*must not relabel"):
        verify_fixture(root)
    output = tmp_path / "new-parent" / "fixture"
    with pytest.raises(FixtureUsageError, match="parse-only.*must not relabel"):
        build_fixture(manifest.recipe, output)
    assert not output.parent.exists()
    assert generation_calls == []

    assert fixture_cli.cmd_inspect(_args(fixture=root, json=True)) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    assert fixture_cli.cmd_verify(
        _args(fixture=root, assurance=False, json=True)
    ) == 2
    assert "parse-only" in json.loads(capsys.readouterr().err)["error"]

    assert fixture_cli.cmd_diff(_args(left=root, right=root, json=True)) == 2
    assert "parse-only" in json.loads(capsys.readouterr().err)["error"]

    archive = tmp_path / "release-parent" / "historical.tar"
    assert fixture_cli.cmd_release(
        _args(fixture=root, output=archive, assurance=False, json=True)
    ) == 2
    assert "parse-only" in json.loads(capsys.readouterr().err)["error"]
    assert not archive.exists()
    assert not archive.parent.exists()
    assert generation_calls == []


def test_cli_build_refuses_v1_before_creating_output_or_calling_a_writer(
    tmp_path, monkeypatch, capsys
):
    def forbidden(**_kwargs):
        raise AssertionError("v1 scene builder ran")

    monkeypatch.setattr(operations, "build_windows_scene", forbidden)
    output = tmp_path / "absent" / "fixture"
    assert fixture_cli.cmd_build(
        _args(spec=EXAMPLE_SPEC, output=output, json=True)
    ) == 2
    error = json.loads(capsys.readouterr().err)
    assert "parse-only" in error["error"] and "must not relabel" in error["error"]
    assert not output.parent.exists()
