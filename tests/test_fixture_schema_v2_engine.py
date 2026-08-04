# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Draft 2020-12 schemas stay aligned with the authoritative Fixture v2 model."""
from __future__ import annotations

from copy import deepcopy
from importlib.resources import files as resource_files
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from artifactforge.fixture.model_v2 import (
    FixtureManifestV2,
    FixtureSpecV2,
    FixtureV2ValidationError,
    NamedBlobV2,
)
from artifactforge.fixture.operations import build_fixture


ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples" / "fixtures"


def _schema(name: str) -> dict:
    return json.loads(
        resource_files("artifactforge.fixture.schemas").joinpath(name).read_text()
    )


SPEC_SCHEMA = _schema("fixture-spec-v2.schema.json")
MANIFEST_SCHEMA = _schema("fixture-manifest-v2.schema.json")
SPEC_VALIDATOR = Draft202012Validator(SPEC_SCHEMA)
MANIFEST_VALIDATOR = Draft202012Validator(MANIFEST_SCHEMA)


def _errors(validator: Draft202012Validator, value: object) -> list[str]:
    return [error.message for error in validator.iter_errors(value)]


def _build(family: str, tmp_path: Path) -> FixtureManifestV2:
    names = {
        "windows": "windows-loose-v2.json",
        "macos": "macos-14-loose-v2.json",
        "linux": "linux-glibc-x86_64-loose-v2.json",
    }
    spec = FixtureSpecV2.from_json((EXAMPLES / names[family]).read_bytes())
    return build_fixture(spec, tmp_path / family)


def test_v2_schemas_are_valid_and_accept_every_shipped_recipe_and_generated_manifest(
    tmp_path,
):
    Draft202012Validator.check_schema(SPEC_SCHEMA)
    Draft202012Validator.check_schema(MANIFEST_SCHEMA)

    for path in sorted(EXAMPLES.glob("*-v2.json")):
        mapping = json.loads(path.read_bytes())
        assert _errors(SPEC_VALIDATOR, mapping) == [], path
        assert FixtureSpecV2.from_mapping(mapping).to_mapping() == mapping

    for family in ("windows", "macos", "linux"):
        manifest = _build(family, tmp_path)
        mapping = manifest.to_mapping()
        assert _errors(MANIFEST_VALIDATOR, mapping) == [], family
        assert FixtureManifestV2.from_mapping(mapping) == manifest


@pytest.mark.parametrize("username", ("CON", "COM1", "LPT9", "AUX.txt", "user."))
def test_windows_username_rejections_match_schema_and_model(username):
    mapping = json.loads((EXAMPLES / "windows-loose-v2.json").read_bytes())
    mapping["profile"]["username"] = username

    assert _errors(SPEC_VALIDATOR, mapping)
    with pytest.raises(FixtureV2ValidationError, match="reserved|ending"):
        FixtureSpecV2.from_mapping(mapping)


@pytest.mark.parametrize(
    ("kind", "attributes"),
    (
        ("file", ["ARCHIVE", "NORMAL"]),
        ("file", ["ARCHIVE", "DIRECTORY"]),
        ("directory", ["ARCHIVE"]),
    ),
)
def test_windows_attribute_and_node_kind_rejections_match_schema_and_model(
    tmp_path, kind, attributes
):
    mapping = deepcopy(_build("windows", tmp_path).to_mapping())
    collection = "files" if kind == "file" else "directories"
    mapping["payload"][collection][0]["metadata"]["attributes"] = attributes

    assert _errors(MANIFEST_VALIDATOR, mapping)
    with pytest.raises(FixtureV2ValidationError, match="NORMAL|DIRECTORY"):
        FixtureManifestV2.from_mapping(mapping)


def test_windows_drive_root_file_rejection_matches_schema_and_model(tmp_path):
    mapping = deepcopy(_build("windows", tmp_path).to_mapping())
    mapping["payload"]["files"][0]["guest_path"] = "C:\\"
    mapping["payload"]["files"][0]["served_path"] = "C"

    assert _errors(MANIFEST_VALIDATOR, mapping)
    with pytest.raises(FixtureV2ValidationError, match="drive roots can only be directories"):
        FixtureManifestV2.from_mapping(mapping)


def test_sid_digit_bounds_match_schema_and_never_reach_runtime_integer_limits(tmp_path):
    mapping = deepcopy(_build("windows", tmp_path).to_mapping())
    mapping["payload"]["files"][0]["metadata"]["owner_sid"] = (
        "S-1-" + "9" * 5000 + "-1"
    )

    assert _errors(MANIFEST_VALIDATOR, mapping)
    with pytest.raises(FixtureV2ValidationError, match="184-byte SID limit"):
        FixtureManifestV2.from_mapping(mapping)


def test_model_only_blob_name_uniqueness_and_counter_equations_are_documented(tmp_path):
    mapping = deepcopy(_build("macos", tmp_path).to_mapping())
    node = next(
        item for item in mapping["payload"]["files"] if item["metadata"]["xattrs"]
    )
    node["metadata"]["xattrs"].append(
        NamedBlobV2.from_bytes("com.apple.quarantine", b"different body").to_mapping()
    )

    # Draft 2020-12 uniqueItems compares whole objects, not a selected name field. The
    # published schema says so; the authoritative model closes the alias.
    assert _errors(MANIFEST_VALIDATOR, mapping) == []
    with pytest.raises(FixtureV2ValidationError, match="duplicate name"):
        FixtureManifestV2.from_mapping(mapping)
    xattr_comment = MANIFEST_SCHEMA["$defs"]["macos_metadata"]["properties"][
        "xattrs"
    ]["$comment"]
    assert "uniqueness by blob name" in xattr_comment

    counters = deepcopy(_build("linux", tmp_path).to_mapping())
    counters["payload"]["directory_count"] += 1
    assert _errors(MANIFEST_VALIDATOR, counters) == []
    with pytest.raises(FixtureV2ValidationError, match="does not equal derived"):
        FixtureManifestV2.from_mapping(counters)
    assert "aggregate counters" in MANIFEST_SCHEMA["$comment"]
