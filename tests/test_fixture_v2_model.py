# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fixture ABI v2 binds one logical guest tree without silently inheriting v1."""
from __future__ import annotations

from copy import deepcopy
from importlib.resources import files as resource_files
import json
from pathlib import Path
import subprocess
import sys

import pytest

from artifactforge.fixture.abi import (
    CANONICALIZATION_V1,
    FIXTURE_ABI_V1,
    FIXTURE_ABI_V2,
    GENERATOR_ABI_V1,
    GENERATOR_ABI_V2,
    MANIFEST_SCHEMA_V1,
    MANIFEST_SCHEMA_V2,
    PRODUCER_PROFILE_V2,
    SPEC_SCHEMA_V1,
    SPEC_SCHEMA_V2,
    TREE_CANONICALIZATION_V1,
    TREE_CANONICALIZATION_V2,
)
from artifactforge.fixture.causal import CausalClockSpec, NANOSECONDS_PER_SECOND
from artifactforge.fixture.model import (
    FixtureValidationError,
    parse_fixture_manifest,
    parse_fixture_spec,
)
from artifactforge.fixture.model_v2 import (
    CLOCK_CONTEXT_DOMAIN_V2,
    CONTENT_STORE_NAMESPACE_V2,
    DirectoryNodeV2,
    FileNodeV2,
    FixtureManifestV2,
    FixturePayloadV2,
    FixtureSpecV2,
    FixtureV2ValidationError,
    GENERATOR_NAME_V2,
    GeneratorIdentityV2,
    LinuxMetadataV2,
    MAX_V2_BLOB_BYTES,
    MAX_V2_GENERATOR_VERSION_BYTES,
    MAX_V2_METADATA_BLOB_BYTES,
    MAX_V2_SID_BYTES,
    MacOSMetadataV2,
    NamedBlobV2,
    ProfileSpecV2,
    RECIPE_DIGEST_DOMAIN_V2,
    SCENE_KEY_DOMAIN_V2,
    TREE_DIGEST_DOMAIN_V2,
    WindowsMetadataV2,
    compute_tree_sha256_v2,
    guest_path_to_served_path,
    served_path_to_guest_path,
    validate_ustar_member_name_v2,
)


FAMILY_PROFILES = {
    "windows": "windows-loose-v2",
    "macos": "macos-14-loose-v2",
    "linux": "linux-glibc-x86_64-loose-v2",
}
FILE_GUEST_PATHS = {
    "windows": r"C:\Users\v\AppData\Local\tool.exe",
    "macos": "/Users/v/Applications/Tool.app/Contents/MacOS/tool",
    "linux": "/home/v/.local/bin/tool",
}


def _spec(
    family: str = "linux",
    *,
    fixture_id: str = "fixture-v2",
    seed_hex: str = "ab" * 32,
    hostname: str | None = None,
    username: str = "v",
) -> FixtureSpecV2:
    return FixtureSpecV2.create(
        fixture_id=fixture_id,
        family=family,
        profile=ProfileSpecV2(
            id=FAMILY_PROFILES[family],
            hostname=hostname or f"{family}-01",
            username=username,
        ),
        seed_hex=seed_hex,
    )


def _metadata(
    family: str,
    kind: str,
    *,
    blobs: tuple[NamedBlobV2, ...] = (),
):
    timestamp = 1_705_294_800 * NANOSECONDS_PER_SECOND
    if family == "linux":
        return LinuxMetadataV2(
            mode=0o755 if kind == "directory" else 0o644,
            uid=1000,
            gid=1000,
            atime_unix_ns=timestamp,
            mtime_unix_ns=timestamp + NANOSECONDS_PER_SECOND,
            ctime_unix_ns=timestamp + 2 * NANOSECONDS_PER_SECOND,
        )
    if family == "macos":
        return MacOSMetadataV2(
            mode=0o755 if kind == "directory" else 0o644,
            uid=501,
            gid=20,
            atime_unix_ns=timestamp,
            mtime_unix_ns=timestamp + NANOSECONDS_PER_SECOND,
            ctime_unix_ns=timestamp + 2 * NANOSECONDS_PER_SECOND,
            birthtime_unix_ns=timestamp - NANOSECONDS_PER_SECOND,
            xattrs=blobs,
        )
    return WindowsMetadataV2(
        owner_sid="S-1-5-21-1000",
        attributes=("DIRECTORY",) if kind == "directory" else ("ARCHIVE",),
        creation_unix_ns=timestamp,
        access_unix_ns=timestamp + NANOSECONDS_PER_SECOND,
        write_unix_ns=timestamp + 2 * NANOSECONDS_PER_SECOND,
        change_unix_ns=timestamp + 3 * NANOSECONDS_PER_SECOND,
        streams=blobs,
    )


def _nodes(family: str):
    blob = NamedBlobV2.from_bytes(
        "com.apple.quarantine" if family == "macos" else "Zone.Identifier",
        b"logical metadata bytes",
    )
    file_guest = FILE_GUEST_PATHS[family]
    file_served = guest_path_to_served_path(family, file_guest)
    parts = file_served.split("/")
    directories = tuple(
        DirectoryNodeV2(
            guest_path=served_path_to_guest_path(
                family, "/".join(parts[:index])
            ),
            served_path="/".join(parts[:index]),
            metadata=_metadata(family, "directory"),
        )
        for index in range(1, len(parts))
    )
    file_node = FileNodeV2.from_bytes(
        guest_path=file_guest,
        served_path=file_served,
        data=b"resident default stream",
        metadata=_metadata(
            family,
            "file",
            blobs=(blob,) if family in {"macos", "windows"} else (),
        ),
    )
    return directories, (file_node,)


def _manifest(family: str = "linux", *, fixture_id: str = "fixture-v2") -> FixtureManifestV2:
    directories, files = _nodes(family)
    payload = FixturePayloadV2.create(
        family=family,
        directories=directories,
        files=files,
    )
    return FixtureManifestV2.create(
        generator_version="0.6.0.dev0",
        recipe=_spec(family, fixture_id=fixture_id),
        payload=payload,
    )


def test_v2_registry_is_disjoint_producible_and_keeps_canonical_json_algorithm():
    assert FIXTURE_ABI_V1.producer_available is False
    assert FIXTURE_ABI_V2.producer_available is True
    assert FIXTURE_ABI_V2.producer_implementation == PRODUCER_PROFILE_V2
    assert FIXTURE_ABI_V2.canonicalization == CANONICALIZATION_V1
    assert {
        FIXTURE_ABI_V1.spec_schema,
        FIXTURE_ABI_V2.spec_schema,
    } == {SPEC_SCHEMA_V1, SPEC_SCHEMA_V2}
    assert FIXTURE_ABI_V1.manifest_schema != FIXTURE_ABI_V2.manifest_schema
    assert FIXTURE_ABI_V1.generator_abi != FIXTURE_ABI_V2.generator_abi
    assert FIXTURE_ABI_V1.tree_canonicalization != FIXTURE_ABI_V2.tree_canonicalization
    assert FIXTURE_ABI_V2.generator_abi == GENERATOR_ABI_V2
    assert FIXTURE_ABI_V2.tree_canonicalization == TREE_CANONICALIZATION_V2
    assert FIXTURE_ABI_V2.producer_profile == PRODUCER_PROFILE_V2
    assert RECIPE_DIGEST_DOMAIN_V2 != TREE_DIGEST_DOMAIN_V2
    assert CLOCK_CONTEXT_DOMAIN_V2 not in {
        RECIPE_DIGEST_DOMAIN_V2,
        TREE_DIGEST_DOMAIN_V2,
    }
    assert SCENE_KEY_DOMAIN_V2.endswith(b"/v2\0")
    assert CONTENT_STORE_NAMESPACE_V2.endswith("/v2")


@pytest.mark.parametrize("family", ["windows", "macos", "linux"])
def test_v2_spec_and_manifest_round_trip_through_exact_top_level_dispatch(family):
    spec = _spec(family)
    assert parse_fixture_spec(spec.canonical_bytes()) == spec
    manifest = _manifest(family)
    raw = manifest.canonical_bytes()
    assert FixtureManifestV2.from_canonical_json(raw) == manifest
    assert parse_fixture_manifest(raw, require_canonical=True) == manifest
    assert manifest.payload.total_bound_bytes == (
        manifest.payload.regular_file_bytes + manifest.payload.metadata_blob_bytes
    )
    assert manifest.payload.tree_sha256 == compute_tree_sha256_v2(
        family=family,
        directories=manifest.payload.directories,
        files=manifest.payload.files,
    )


def test_clock_derivation_binds_seed_and_canonical_answer_free_recipe_context():
    seed = "42" * 32
    first = _spec("linux", fixture_id="first", seed_hex=seed)
    second = _spec("linux", fixture_id="second", seed_hex=seed)
    third = _spec("macos", fixture_id="first", seed_hex=seed)
    fourth = _spec("linux", fixture_id="first", seed_hex=seed, hostname="linux-02")
    assert len(
        {
            first.causal_clock.anchor_unix_ns,
            second.causal_clock.anchor_unix_ns,
            third.causal_clock.anchor_unix_ns,
            fourth.causal_clock.anchor_unix_ns,
        }
    ) == 4

    stale_cases = []
    shifted = deepcopy(first.to_mapping())
    shifted["causal_clock"]["anchor_unix_ns"] += NANOSECONDS_PER_SECOND
    stale_cases.append(shifted)
    changed_seed = deepcopy(first.to_mapping())
    changed_seed["seed_hex"] = "43" * 32
    stale_cases.append(changed_seed)
    changed_context = deepcopy(first.to_mapping())
    changed_context["fixture_id"] = "changed"
    stale_cases.append(changed_context)
    for mapping in stale_cases:
        with pytest.raises(FixtureV2ValidationError, match="seed and canonical recipe context"):
            FixtureSpecV2.from_mapping(mapping)

    rederived = _spec("linux", fixture_id="changed", seed_hex="43" * 32)
    assert FixtureSpecV2.from_json(rederived.canonical_bytes()) == rederived


@pytest.mark.parametrize(
    ("family", "guest", "served"),
    [
        ("linux", "/home/v/a", "home/v/a"),
        ("macos", "/Users/v/A.app", "Users/v/A.app"),
        ("windows", r"C:\Users\v\a.exe", "C/Users/v/a.exe"),
        ("windows", "D:\\", "D"),
    ],
)
def test_guest_served_mapping_is_exact_and_reversible(family, guest, served):
    assert guest_path_to_served_path(family, guest) == served
    assert served_path_to_guest_path(family, served) == guest


@pytest.mark.parametrize(
    ("family", "guest"),
    [
        ("linux", "relative"),
        ("linux", "//double"),
        ("linux", "/a/../b"),
        ("linux", "/a\\b"),
        ("windows", r"c:\lower"),
        ("windows", r"C:/slash"),
        ("windows", r"C:\a\..\b"),
        ("windows", r"C:\NUL.txt"),
        ("windows", "C:\\trailing. "),
    ],
)
def test_guest_paths_reject_aliases_traversal_and_noncanonical_windows_names(family, guest):
    with pytest.raises(FixtureV2ValidationError):
        guest_path_to_served_path(family, guest)


@pytest.mark.parametrize("username", ["NUL", "con.txt", "trailing."])
def test_windows_profile_username_must_be_a_valid_path_component(username):
    with pytest.raises(FixtureV2ValidationError, match="profile.username"):
        ProfileSpecV2("windows-loose-v2", "WKSTN-01", username)


def test_directory_nodes_are_sorted_complete_non_orphaned_and_casefold_safe():
    directories, files = _nodes("linux")
    with pytest.raises(FixtureV2ValidationError, match="sorted"):
        FixturePayloadV2.create(
            family="linux",
            directories=directories,
            files=files,
        ).__class__(
            **dict(
                FixturePayloadV2.create(
                    family="linux", directories=directories, files=files
                ).__dict__,
                directories=tuple(reversed(directories)),
            )
        )

    with pytest.raises(FixtureV2ValidationError, match="missing explicit parent"):
        FixturePayloadV2.create(
            family="linux",
            directories=directories[1:],
            files=files,
        )

    orphan = DirectoryNodeV2(
        guest_path="/orphan",
        served_path="orphan",
        metadata=_metadata("linux", "directory"),
    )
    with pytest.raises(FixtureV2ValidationError, match="orphaned"):
        FixturePayloadV2.create(
            family="linux",
            directories=(*directories, orphan),
            files=files,
        )

    alias_file = FileNodeV2.from_bytes(
        guest_path="/Home/other",
        served_path="Home/other",
        data=b"x",
        metadata=_metadata("linux", "file"),
    )
    alias_directory = DirectoryNodeV2(
        guest_path="/Home",
        served_path="Home",
        metadata=_metadata("linux", "directory"),
    )
    with pytest.raises(FixtureV2ValidationError, match="case-folding"):
        FixturePayloadV2.create(
            family="linux",
            directories=(*directories, alias_directory),
            files=(*files, alias_file),
        )


def test_windows_drive_root_is_directory_only_for_typed_and_parsed_trees():
    directories, files = _nodes("windows")
    payload = FixturePayloadV2.create(
        family="windows", directories=directories, files=files
    )
    assert payload.directories[0].guest_path == "C:\\"
    assert payload.directories[0].served_path == "C"

    root_file = FileNodeV2.from_bytes(
        guest_path="C:\\",
        served_path="C",
        data=b"impossible drive-root file",
        metadata=_metadata("windows", "file"),
    )
    with pytest.raises(FixtureV2ValidationError, match="drive roots can only be directories"):
        FixturePayloadV2.create(
            family="windows", directories=(), files=(root_file,)
        )

    mapping = deepcopy(_manifest("windows").to_mapping())
    mapping["payload"]["files"][0]["guest_path"] = "C:\\"
    mapping["payload"]["files"][0]["served_path"] = "C"
    with pytest.raises(FixtureV2ValidationError, match="drive roots can only be directories"):
        parse_fixture_manifest(json.dumps(mapping))


def test_family_specific_metadata_union_and_windows_directory_attribute_are_closed():
    directories, files = _nodes("linux")
    wrong_file = FileNodeV2(
        guest_path=files[0].guest_path,
        served_path=files[0].served_path,
        size=files[0].size,
        sha256=files[0].sha256,
        metadata=_metadata("macos", "file"),
    )
    with pytest.raises(FixtureV2ValidationError, match="LinuxMetadataV2"):
        FixturePayloadV2.create(
            family="linux", directories=directories, files=(wrong_file,)
        )

    windows_dirs, windows_files = _nodes("windows")
    bad_dir = DirectoryNodeV2(
        guest_path=windows_dirs[0].guest_path,
        served_path=windows_dirs[0].served_path,
        metadata=_metadata("windows", "file"),
    )
    with pytest.raises(FixtureV2ValidationError, match="DIRECTORY"):
        FixturePayloadV2.create(
            family="windows",
            directories=(bad_dir, *windows_dirs[1:]),
            files=windows_files,
        )


def test_named_blobs_are_canonical_bounded_and_bind_redundant_byte_equations():
    clean = NamedBlobV2.from_bytes("Zone.Identifier", b"abc")
    assert clean.data == b"abc"
    mutations = [
        dict(clean.__dict__, data_base64="YWJj="),
        dict(clean.__dict__, data_base64="YW Jj"),
        dict(clean.__dict__, size=4),
        dict(clean.__dict__, sha256="sha256:" + "0" * 64),
    ]
    for mutation in mutations:
        with pytest.raises(FixtureV2ValidationError):
            NamedBlobV2(**mutation)
    with pytest.raises(FixtureV2ValidationError, match="65536-byte limit"):
        NamedBlobV2.from_bytes("large", b"x" * (MAX_V2_BLOB_BYTES + 1))


def test_blob_name_order_exact_xattr_identity_and_casefolded_ads_identity():
    upper = NamedBlobV2.from_bytes("A.name", b"a")
    lower = NamedBlobV2.from_bytes("a.name", b"b")
    # POSIX/macOS xattr names are exact and case-sensitive, so sorted aliases remain distinct.
    mac = _metadata("macos", "file", blobs=(upper, lower))
    assert tuple(blob.name for blob in mac.xattrs) == ("A.name", "a.name")
    with pytest.raises(FixtureV2ValidationError, match="case-folding aliases"):
        _metadata("windows", "file", blobs=(upper, lower))
    with pytest.raises(FixtureV2ValidationError, match="sorted"):
        _metadata("macos", "file", blobs=(lower, upper))


def test_payload_rejects_aggregate_metadata_blob_budget_before_manifest_publication():
    file_guest = "/" + "/".join(f"d{index}" for index in range(17)) + "/file"
    file_served = guest_path_to_served_path("macos", file_guest)
    parts = file_served.split("/")
    blob = NamedBlobV2.from_bytes("x.value", b"x" * MAX_V2_BLOB_BYTES)
    directories = tuple(
        DirectoryNodeV2(
            guest_path=served_path_to_guest_path("macos", "/".join(parts[:index])),
            served_path="/".join(parts[:index]),
            metadata=_metadata("macos", "directory", blobs=(blob,)),
        )
        for index in range(1, len(parts))
    )
    file_node = FileNodeV2.from_bytes(
        guest_path=file_guest,
        served_path=file_served,
        data=b"x",
        metadata=_metadata("macos", "file", blobs=(blob,)),
    )
    with pytest.raises(FixtureV2ValidationError, match="aggregate limit"):
        FixturePayloadV2.create(
            family="macos", directories=directories, files=(file_node,)
        )
    assert MAX_V2_METADATA_BLOB_BYTES == 1024 * 1024


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("generator", "abi"), GENERATOR_ABI_V1),
        (("generator", "producer_profile"), "artifactforge-fixture-producer-v1"),
        (("recipe", "schema"), SPEC_SCHEMA_V1),
        (("recipe", "profile", "id"), "linux-glibc-x86_64-loose-v1"),
        (("recipe", "causal_clock", "profile"), "artifactforge-causal-clock-v2"),
        (("payload", "canonicalization"), TREE_CANONICALIZATION_V1),
        (("payload", "digest_domain"), "artifactforge-fixture-tree-digest-v1"),
        (("recipe_digest_domain",), "artifactforge-fixture-recipe-digest-v1"),
    ],
)
def test_every_v1_v2_identity_axis_mix_is_rejected(path, replacement):
    mapping = deepcopy(_manifest().to_mapping())
    target = mapping
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    with pytest.raises(FixtureValidationError):
        parse_fixture_manifest(json.dumps(mapping))


def test_top_level_schema_relabel_never_auto_migrates_either_direction():
    v2 = _manifest().to_mapping()
    v2["schema"] = MANIFEST_SCHEMA_V1
    with pytest.raises(FixtureValidationError):
        parse_fixture_manifest(json.dumps(v2))

    root = Path(__file__).parent / "fixtures" / "fixture-v1-goldens"
    v1 = json.loads((root / "linux-v0.5.0.json").read_text())
    v1["schema"] = MANIFEST_SCHEMA_V2
    with pytest.raises(FixtureValidationError):
        parse_fixture_manifest(json.dumps(v1))


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("payload", "files", 0, "size"), 24),
        (("payload", "files", 0, "sha256"), "sha256:" + "1" * 64),
        (("payload", "files", 0, "metadata", "uid"), 1001),
        (
            ("payload", "files", 0, "metadata", "mtime_unix_ns"),
            1_705_294_802_000_000_001,
        ),
    ],
)
def test_stale_tree_digest_rejects_each_valid_node_byte_or_metadata_mutation(path, replacement):
    mapping = deepcopy(_manifest("linux").to_mapping())
    target = mapping
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    with pytest.raises(FixtureV2ValidationError, match="tree_sha256|derived value"):
        FixtureManifestV2.from_mapping(mapping)


def test_valid_blob_replacement_changes_tree_digest_even_when_size_is_unchanged():
    manifest = _manifest("macos")
    mapping = deepcopy(manifest.to_mapping())
    replacement = NamedBlobV2.from_bytes("com.apple.quarantine", b"X" * 22)
    mapping["payload"]["files"][0]["metadata"]["xattrs"] = [
        replacement.to_mapping()
    ]
    mapping["payload"]["metadata_blob_bytes"] = replacement.size
    mapping["payload"]["total_bound_bytes"] = (
        mapping["payload"]["regular_file_bytes"] + replacement.size
    )
    with pytest.raises(FixtureV2ValidationError, match="tree_sha256"):
        FixtureManifestV2.from_mapping(mapping)


def test_payload_and_manifest_counters_and_recipe_digest_are_equations():
    mapping = deepcopy(_manifest().to_mapping())
    for field in (
        "directory_count",
        "file_count",
        "regular_file_bytes",
        "metadata_blob_count",
        "metadata_blob_bytes",
        "total_bound_bytes",
    ):
        mutated = deepcopy(mapping)
        mutated["payload"][field] += 1
        with pytest.raises(FixtureV2ValidationError, match="does not equal derived"):
            FixtureManifestV2.from_mapping(mutated)
    mapping["recipe_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(FixtureV2ValidationError, match="recipe_sha256 mismatch"):
        FixtureManifestV2.from_mapping(mapping)


def test_generator_version_and_windows_sid_attribute_boundaries_are_finite():
    assert GeneratorIdentityV2(version="v" * MAX_V2_GENERATOR_VERSION_BYTES).name == (
        GENERATOR_NAME_V2
    )
    with pytest.raises(FixtureV2ValidationError, match="128-byte limit"):
        GeneratorIdentityV2(version="v" * (MAX_V2_GENERATOR_VERSION_BYTES + 1))
    with pytest.raises(FixtureV2ValidationError, match="canonical decimal SID"):
        WindowsMetadataV2(
            **dict(_metadata("windows", "file").__dict__, owner_sid="S-1-05-21")
        )
    with pytest.raises(FixtureV2ValidationError, match=f"{MAX_V2_SID_BYTES}-byte SID limit"):
        WindowsMetadataV2(
            **dict(
                _metadata("windows", "file").__dict__,
                owner_sid="S-1-" + "9" * 5000 + "-1",
            )
        )
    with pytest.raises(FixtureV2ValidationError, match="authority exceeds 48 bits"):
        WindowsMetadataV2(
            **dict(
                _metadata("windows", "file").__dict__,
                owner_sid="S-1-999999999999999-1",
            )
        )
    with pytest.raises(FixtureV2ValidationError, match="subauthority exceeds 32 bits"):
        WindowsMetadataV2(
            **dict(
                _metadata("windows", "file").__dict__,
                owner_sid="S-1-5-9999999999",
            )
        )
    with pytest.raises(FixtureV2ValidationError, match="NORMAL attribute cannot"):
        WindowsMetadataV2(
            **dict(
                _metadata("windows", "file").__dict__,
                attributes=("ARCHIVE", "NORMAL"),
            )
        )


def test_ustar_name_helper_and_manifest_validate_final_prefixed_member_names():
    assert validate_ustar_member_name_v2("a" * 100) == "a" * 100
    split = "p" * 155 + "/" + "n" * 100
    assert validate_ustar_member_name_v2(split) == split
    with pytest.raises(FixtureV2ValidationError, match="PAX/GNU"):
        validate_ustar_member_name_v2("a" * 101)
    with pytest.raises(FixtureV2ValidationError, match="PAX/GNU"):
        validate_ustar_member_name_v2("p" * 156 + "/" + "n" * 100)

    long_name = "a" * 101
    node = FileNodeV2.from_bytes(
        guest_path="/" + long_name,
        served_path=long_name,
        data=b"x",
        metadata=_metadata("linux", "file"),
    )
    payload = FixturePayloadV2.create(
        family="linux", directories=(), files=(node,)
    )
    with pytest.raises(FixtureV2ValidationError, match="PAX/GNU"):
        FixtureManifestV2.create(
            generator_version="v2",
            recipe=_spec("linux", fixture_id="f" * 64),
            payload=payload,
        )


def test_v2_schema_resources_are_closed_bounded_and_have_no_carrier_metadata_fields():
    resources = resource_files("artifactforge.fixture.schemas")
    spec = json.loads(resources.joinpath("fixture-spec-v2.schema.json").read_text())
    manifest = json.loads(
        resources.joinpath("fixture-manifest-v2.schema.json").read_text()
    )
    assert spec["$id"] == "urn:artifactforge:schema:fixture-spec:v2"
    assert manifest["$id"] == "urn:artifactforge:schema:fixture-manifest:v2"
    assert spec["additionalProperties"] is False
    assert manifest["additionalProperties"] is False
    assert manifest["$defs"]["payload"]["additionalProperties"] is False
    assert manifest["$defs"]["blob"]["properties"]["size"]["maximum"] == 65536
    assert manifest["$defs"]["payload"]["properties"]["files"]["maxItems"] == 256
    sid_schema = manifest["$defs"]["windows_metadata"]["properties"]["owner_sid"]
    assert sid_schema["maxLength"] == MAX_V2_SID_BYTES
    assert sid_schema["pattern"].startswith("^S-1-")

    def property_names(value):
        if isinstance(value, dict):
            yield from value.get("properties", {})
            for nested in value.values():
                yield from property_names(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from property_names(nested)

    names = set(property_names(manifest))
    assert not {"carrier", "host_mode", "host_uid", "host_gid", "host_mtime"} & names


def test_closed_models_reject_carrier_metadata_and_unknown_fields_at_every_boundary():
    mapping = deepcopy(_manifest("macos").to_mapping())
    targets = [
        mapping,
        mapping["generator"],
        mapping["recipe"],
        mapping["recipe"]["causal_clock"],
        mapping["payload"],
        mapping["payload"]["directories"][0],
        mapping["payload"]["files"][0]["metadata"],
        mapping["payload"]["files"][0]["metadata"]["xattrs"][0],
    ]
    for target in targets:
        mutated = deepcopy(mapping)
        # Locate the equivalent object by structural equality for a concise boundary matrix.
        if target is mapping:
            destination = mutated
        else:
            destination = None

            def find(value):
                nonlocal destination
                if destination is not None:
                    return
                if value == target:
                    destination = value
                    return
                if isinstance(value, dict):
                    for child in value.values():
                        find(child)
                elif isinstance(value, list):
                    for child in value:
                        find(child)

            find(mutated)
        assert destination is not None
        destination["carrier"] = {"mode": 0o644}
        with pytest.raises(FixtureV2ValidationError, match="unknown 'carrier'"):
            FixtureManifestV2.from_mapping(mutated)


@pytest.mark.parametrize(
    "order",
    [
        ("artifactforge.fixture.model_v2", "artifactforge.fixture.model"),
        ("artifactforge.fixture.model", "artifactforge.fixture.model_v2"),
    ],
)
def test_model_import_order_is_cycle_free_in_a_fresh_interpreter(order):
    code = "; ".join(f"import {module}" for module in order)
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=Path(__file__).parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_clock_context_extension_is_typed_bounded_and_deterministic():
    seed = "01" * 32
    assert CausalClockSpec.from_seed_hex(seed, context=b"a") == (
        CausalClockSpec.from_seed_hex(seed, context=b"a")
    )
    assert CausalClockSpec.from_seed_hex(seed, context=b"a") != (
        CausalClockSpec.from_seed_hex(seed, context=b"b")
    )
    with pytest.raises(ValueError, match="context must be bytes"):
        CausalClockSpec.from_seed_hex(seed, context="a")  # type: ignore[arg-type]
