# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The Fixture Core v1 byte contract is strict, deterministic and answer-free."""
from __future__ import annotations

from copy import deepcopy
from importlib.resources import files
import json
import os

import pytest

from artifactforge.fixture.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    canonical_sha256,
    load_canonical_json,
    load_json_strict,
)
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixturePayload,
    FixtureSpec,
    FixtureValidationError,
    GeneratorIdentity,
    ProfileSpec,
    artifact_entries_from_tree,
    canonical_artifact_entries,
    compute_tree_sha256,
    validate_artifact_entries,
    validate_artifact_path,
)


def _spec() -> FixtureSpec:
    return FixtureSpec(
        fixture_id="demo_1.0",
        family="windows",
        profile=ProfileSpec(
            id="windows-loose-v1",
            hostname="WKSTN-01",
            username="v_test",
        ),
        seed_hex="ab" * 32,
    )


def _entries() -> tuple[ArtifactEntry, ...]:
    return canonical_artifact_entries(
        [
            ArtifactEntry.from_bytes("z.bin", b""),
            ArtifactEntry.from_bytes("nested/a.bin", b"abc"),
        ]
    )


def _manifest() -> FixtureManifest:
    # Parser-model tests construct a historical value directly.  The public v1 producer
    # helper is intentionally unavailable now that its exact 0.5.0 bytes are frozen.
    spec = _spec()
    entries = _entries()
    return FixtureManifest(
        generator=GeneratorIdentity(version="0.0.3"),
        recipe=spec,
        recipe_sha256=spec.recipe_sha256,
        payload=FixturePayload(
            file_count=len(entries),
            total_bytes=sum(entry.size for entry in entries),
            tree_sha256=compute_tree_sha256(entries),
            files=entries,
        ),
    )


def test_canonical_json_is_sorted_compact_utf8_nfc_with_exactly_one_lf():
    value = {"z": [2, None, True], "é": "café", "a": {"b": 1}}
    assert canonical_json_bytes(value) == (
        '{"a":{"b":1},"z":[2,null,true],"é":"café"}\n'.encode()
    )
    assert canonical_json_bytes(load_json_strict(canonical_json_bytes(value))) == (
        canonical_json_bytes(value)
    )
    assert canonical_sha256({"b": 2, "a": 1}) == (
        "sha256:e8d38819d39f705646bfb643368eca78f7db476c16471dbc33b941b27326410d"
    )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"a":1,"a":2}', "duplicate"),
        (b'{"outer":{"x":1,"x":2}}', "duplicate"),
        (b'{"value":1.0}', "floating-point"),
        (b'{"value":1e3}', "floating-point"),
        (b'{"value":NaN}', "non-finite"),
        (b'{"value":Infinity}', "non-finite"),
        (b"\xef\xbb\xbf{}", "BOM"),
        (b"{} trailing", "invalid JSON"),
        (b'"e\\u0301"', "NFC"),
        (b'{"e\\u0301":1}', "NFC"),
        (b'"\\ud800"', "surrogate"),
        (b'"\xff"', "UTF-8"),
    ],
)
def test_strict_json_rejects_ambiguous_or_noncanonical_domain_values(raw, message):
    with pytest.raises(CanonicalJSONError, match=message):
        load_json_strict(raw)


def test_strict_json_wraps_the_runtime_oversized_integer_limit():
    with pytest.raises(CanonicalJSONError, match="invalid JSON"):
        load_json_strict(b'{"value":' + b"9" * 5000 + b"}")


@pytest.mark.parametrize("value", [1.5, (1, 2), {1: "not-a-json-object"}, object()])
def test_canonical_encoder_accepts_json_domain_only(value):
    with pytest.raises(CanonicalJSONError):
        canonical_json_bytes(value)


def test_machine_record_reader_requires_the_exact_canonical_bytes():
    assert load_canonical_json(b'{"a":1,"b":2}\n') == {"a": 1, "b": 2}
    for alternate in (b'{"b":2,"a":1}\n', b'{"a": 1, "b": 2}\n', b'{"a":1,"b":2}'):
        with pytest.raises(CanonicalJSONError, match="not canonical"):
            load_canonical_json(alternate)


def test_recipe_round_trip_has_exact_fields_and_digest_vector():
    spec = _spec()
    assert set(spec.to_mapping()) == {
        "schema",
        "purpose",
        "fixture_id",
        "family",
        "profile",
        "seed_hex",
    }
    assert FixtureSpec.from_json(spec.canonical_bytes()) == spec
    assert spec.recipe_sha256 == (
        "sha256:30d0bb07a72bf834df372c70ad3718f4187f1e90e5032fc40daa229821664b02"
    )


@pytest.mark.parametrize(
    "fixture_id",
    ["a", "fixture.name", "fixture_name", "fixture-name", "a" * 64],
)
def test_fixture_id_accepts_the_exact_public_slug_language(fixture_id):
    base = _spec()
    assert FixtureSpec(
        fixture_id=fixture_id,
        family=base.family,
        profile=base.profile,
        seed_hex=base.seed_hex,
    ).fixture_id == fixture_id


@pytest.mark.parametrize("fixture_id", ["", "Upper", ".hidden", "-bad", "a" * 65, "space bad"])
def test_fixture_id_rejects_values_outside_the_exact_slug_language(fixture_id):
    base = _spec()
    with pytest.raises(FixtureValidationError, match="fixture_id"):
        FixtureSpec(
            fixture_id=fixture_id,
            family=base.family,
            profile=base.profile,
            seed_hex=base.seed_hex,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "bad/name"),
        ("hostname", "bad_name"),
        ("hostname", "-leading"),
        ("hostname", "é"),
        ("hostname", "a" * 64),
        ("username", "bad/name"),
        ("username", "bad\\name"),
        ("username", "-leading"),
        ("username", "é"),
        ("username", "a" * 65),
    ],
)
def test_profile_values_are_safe_before_deep_format_encoders_run(field, value):
    values = {"id": "windows-loose-v1", "hostname": "WKSTN-01", "username": "v"}
    values[field] = value
    with pytest.raises(FixtureValidationError, match=field):
        ProfileSpec(**values)


def test_profile_family_seed_and_unknown_fields_are_fail_closed():
    spec = _spec().to_mapping()
    spec["profile"] = dict(spec["profile"], id="macos-14-loose-v1")
    with pytest.raises(FixtureValidationError, match="belongs to"):
        FixtureSpec.from_mapping(spec)

    bad_seed = _spec().to_mapping()
    bad_seed["seed_hex"] = "AB" * 32
    with pytest.raises(FixtureValidationError, match="lowercase"):
        FixtureSpec.from_mapping(bad_seed)

    unknown = _spec().to_mapping()
    unknown["answer"] = "must never enter a public recipe"
    with pytest.raises(FixtureValidationError, match="unknown 'answer'"):
        FixtureSpec.from_mapping(unknown)

    nested_unknown = _spec().to_mapping()
    nested_unknown["profile"]["version"] = "10.0"
    with pytest.raises(FixtureValidationError, match="unknown 'version'"):
        FixtureSpec.from_mapping(nested_unknown)


def test_linux_profile_is_valid_and_bound_only_to_the_linux_family():
    spec = FixtureSpec(
        fixture_id="linux-autostart-001",
        family="linux",
        profile=ProfileSpec("linux-glibc-x86_64-loose-v1", "linux-01", "v"),
        seed_hex="03" * 32,
    )
    assert FixtureSpec.from_json(spec.canonical_bytes()) == spec

    with pytest.raises(FixtureValidationError, match="belongs to 'linux'"):
        FixtureSpec(
            fixture_id=spec.fixture_id,
            family="windows",
            profile=spec.profile,
            seed_hex=spec.seed_hex,
        )


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute",
        "../escape",
        "a/../escape",
        "./a",
        "a/./b",
        "a//b",
        "a/",
        "a\\b",
        "line\nbreak",
        "café",
    ],
)
def test_artifact_paths_reject_unsafe_or_nonportable_spellings(path):
    with pytest.raises(FixtureValidationError):
        validate_artifact_path(path)


@pytest.mark.parametrize("path", ["a", "A file.bin", "nested/a.db", "name:stream"])
def test_artifact_paths_accept_printable_ascii_relative_posix_paths(path):
    assert validate_artifact_path(path) == path


def test_artifact_collection_rejects_order_duplicates_casefold_and_file_directory_aliases():
    a = ArtifactEntry.from_bytes("a", b"a")
    b = ArtifactEntry.from_bytes("b", b"b")
    with pytest.raises(FixtureValidationError, match="sorted"):
        validate_artifact_entries((b, a))
    with pytest.raises(FixtureValidationError, match="duplicate"):
        validate_artifact_entries((a, a))
    with pytest.raises(FixtureValidationError, match="case-folding"):
        validate_artifact_entries(
            (
                ArtifactEntry.from_bytes("Dir/a", b"a"),
                ArtifactEntry.from_bytes("dir/b", b"b"),
            )
        )
    with pytest.raises(FixtureValidationError, match="both a file and a directory"):
        validate_artifact_entries((a, ArtifactEntry.from_bytes("a/b", b"b")))


def test_tree_digest_has_a_pinned_independent_vector_and_sorts_input():
    assert compute_tree_sha256(reversed(_entries())) == (
        "sha256:805f67fe23f07a7f263b0fe994f16badd1738f1874601e125b7a0002a7528ee8"
    )


def test_manifest_round_trip_recomputes_every_integrity_equation():
    manifest = _manifest()
    assert FixtureManifest.from_json(manifest.canonical_bytes()) == manifest
    assert FixtureManifest.from_canonical_json(manifest.canonical_bytes()) == manifest
    with pytest.raises(CanonicalJSONError, match="not canonical"):
        FixtureManifest.from_canonical_json(
            json.dumps(manifest.to_mapping(), indent=2, sort_keys=True).encode() + b"\n"
        )
    assert manifest.payload.file_count == 2
    assert manifest.payload.total_bytes == 3
    assert manifest.recipe_sha256 == manifest.recipe.recipe_sha256
    assert manifest.payload.tree_sha256 == compute_tree_sha256(manifest.payload.files)
    assert b"answer" not in manifest.canonical_bytes().lower()
    assert b"join" not in manifest.canonical_bytes().lower()

    cases = []
    for path, replacement in [
        (("recipe_sha256",), "sha256:" + "0" * 64),
        (("payload", "tree_sha256"), "sha256:" + "0" * 64),
        (("payload", "file_count"), 3),
        (("payload", "total_bytes"), 4),
    ]:
        mapping = deepcopy(manifest.to_mapping())
        target = mapping
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = replacement
        cases.append(mapping)
    for mapping in cases:
        with pytest.raises(FixtureValidationError, match="mismatch|does not equal"):
            FixtureManifest.from_mapping(mapping)


def test_manifest_rejects_unknown_fields_at_every_object_boundary():
    clean = _manifest().to_mapping()
    paths = [
        (),
        ("purpose",),
        ("generator",),
        ("recipe",),
        ("recipe", "profile"),
        ("payload",),
        ("payload", "files", 0),
    ]
    for path in paths:
        mapping = deepcopy(clean)
        target = mapping
        for component in path:
            target = target[component]
        target["unexpected"] = True
        with pytest.raises(FixtureValidationError, match="unknown 'unexpected'"):
            FixtureManifest.from_mapping(mapping)


def test_payload_constructor_rejects_unsorted_files_and_false_integer_counts():
    entries = _entries()
    with pytest.raises(FixtureValidationError, match="sorted"):
        FixturePayload(
            file_count=2,
            total_bytes=3,
            tree_sha256=compute_tree_sha256(entries),
            files=tuple(reversed(entries)),
        )
    mapping = _manifest().payload.to_mapping()
    mapping["file_count"] = True
    with pytest.raises(FixtureValidationError, match="integer"):
        FixturePayload.from_mapping(mapping)
    with pytest.raises(FixtureValidationError, match="must be an iterable"):
        FixturePayload(
            file_count=1,
            total_bytes=0,
            tree_sha256="sha256:" + "0" * 64,
            files=None,
        )


def test_filesystem_inventory_is_recursive_sorted_and_byte_derived(tmp_path):
    root = tmp_path / "artifacts"
    (root / "nested").mkdir(parents=True)
    (root / "z.bin").write_bytes(b"")
    (root / "nested" / "a.bin").write_bytes(b"abc")
    assert artifact_entries_from_tree(root) == _entries()
    with pytest.raises(FixtureValidationError, match="filesystem path"):
        artifact_entries_from_tree(None)


def test_filesystem_inventory_rejects_symlinks_and_symlink_roots(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "file").write_bytes(b"data")
    try:
        (root / "link").symlink_to("file")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(FixtureValidationError, match="symlink"):
        artifact_entries_from_tree(root)

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(FixtureValidationError, match="root must not be a symlink"):
        artifact_entries_from_tree(linked_root)


def test_filesystem_inventory_rejects_special_files_and_empty_directories(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    empty = root / "empty"
    empty.mkdir()
    with pytest.raises(FixtureValidationError, match="empty directory"):
        artifact_entries_from_tree(root)
    empty.rmdir()

    fifo = root / "pipe"
    try:
        os.mkfifo(fifo)
    except (AttributeError, NotImplementedError, OSError):
        pytest.skip("FIFOs are unavailable on this platform")
    with pytest.raises(FixtureValidationError, match="special file"):
        artifact_entries_from_tree(root)


def test_both_strict_json_schemas_are_packaged_resources():
    resources = files("artifactforge.fixture.schemas")
    spec_schema = json.loads(resources.joinpath("fixture-spec-v1.schema.json").read_text())
    manifest_schema = json.loads(
        resources.joinpath("fixture-manifest-v1.schema.json").read_text()
    )
    assert spec_schema["$id"] == "urn:artifactforge:schema:fixture-spec:v1"
    assert manifest_schema["$id"] == "urn:artifactforge:schema:fixture-manifest:v1"
    assert spec_schema["additionalProperties"] is False
    assert manifest_schema["additionalProperties"] is False
    assert manifest_schema["properties"]["payload"]["additionalProperties"] is False
    assert manifest_schema["$defs"]["artifact"]["additionalProperties"] is False
    assert "linux" in spec_schema["properties"]["family"]["enum"]
    assert "linux-glibc-x86_64-loose-v1" in (
        spec_schema["properties"]["profile"]["properties"]["id"]["enum"]
    )
    assert "linux" in manifest_schema["$defs"]["recipe"]["properties"]["family"]["enum"]
    assert "linux-glibc-x86_64-loose-v1" in (
        manifest_schema["$defs"]["profile"]["properties"]["id"]["enum"]
    )


def test_public_fixture_schemas_have_no_semantic_answer_or_join_fields():
    """Fixture integrity must not quietly become a published evidence graph."""
    resources = files("artifactforge.fixture.schemas")
    schemas = {
        name: json.loads(resources.joinpath(name).read_text())
        for name in ("fixture-spec-v1.schema.json", "fixture-manifest-v1.schema.json")
    }

    def property_names(value):
        if isinstance(value, dict):
            yield from value.get("properties", {})
            for child in value.values():
                yield from property_names(child)
        elif isinstance(value, list):
            for child in value:
                yield from property_names(child)

    semantic_fields = {
        "answer",
        "answers",
        "caused_by",
        "join",
        "joins",
        "match",
        "pivot",
        "question",
        "role",
        "same_file",
        "subject",
    }
    for name, schema in schemas.items():
        leaked = semantic_fields & set(property_names(schema))
        assert not leaked, f"{name} publishes private semantic fields: {sorted(leaked)}"
