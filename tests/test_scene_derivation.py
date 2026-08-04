# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Scene derivation is explicit, domain-separated and benchmark-byte compatible."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path

import pytest

from artifactforge import pools, suite
from artifactforge.compose.derivation import (
    BENCHMARK_CONTENT_DOMAIN,
    BENCHMARK_SCENE_DERIVATION,
    BENCHMARK_VALUE_DOMAIN,
    DERIVATION_ALGORITHM,
    FIXTURE_V2_CONTENT_DOMAIN,
    FIXTURE_V2_SCENE_DERIVATION,
    FIXTURE_V2_VALUE_DOMAIN,
    SceneDerivation,
)
from artifactforge.compose.scene import (
    build_linux_scene,
    build_macos_scene,
    build_windows_scene,
)
from artifactforge.content import ContentStore
from artifactforge.model import linux_profile, macos_profile, windows_profile


KEY = b"d" * 32
_DEFAULT = object()
_BUILDERS = {
    "windows": (build_windows_scene, windows_profile()),
    "macos": (build_macos_scene, macos_profile()),
    "linux": (build_linux_scene, linux_profile()),
}
_PINNED_FINGERPRINTS = {
    "windows": (
        "3ea3acf463c7fcc1fe0df75af65ad3fbae51f7ea9e7bfd60ca7c4fa1e95e589c",
        "3f67b8c629f3f2b364310b52c7347eecf9bff04143d6a65ad6d78f71f7c742b7",
        "24a1822fcad98222e28198a644b8bf604f36a72790a277a308477bf0df4b1eab",
        "4b79e49080e5ffcebfb45873300c274b0a51d3dfd7ed3e96d8dd4018ac3eb7eb",
    ),
    "macos": (
        "e3b82fc03a78e08f5ec560b421ac0b232fe3211d8cb0d32928e2c082b8dbf41f",
        "9d8fb85894f3d0b5035187f39a241e3719b3b88864afda1158e206b1e00e42cd",
        "cd6dc0e20ffde8babf714e9b1055be958568e71f6b201253807deb160364b8b6",
        "2f4751c393aab70a49b244124b521d82e7285c7fe50e80f01e4fdd4cad064fc9",
    ),
    "linux": (
        "06da05ee59ccb676a32b1e531cd3c08ddaf4588382ba4f04f127862a869a87b2",
        "bc6fa94730bd3e14dcc1f6dd6e3ffb038d8139128ca11e216ba46f7f23419ba5",
        "89574841acc0299be8247cb7e58ee5775ff317f96ead45ea936de145e7792eb1",
        "c32121c28d9cc38c83356f68a07e2b3eb1f4976a104b51f5550c232496acc937",
    ),
}


def _build(root: Path, family: str, derivation=_DEFAULT):
    builder, profile = _BUILDERS[family]
    arguments = {}
    if derivation is not _DEFAULT:
        arguments["derivation"] = derivation
    return builder(
        ContentStore("derivation-contract", str(root / "content")),
        skey=KEY,
        profile=profile,
        scene_dir=str(root / "scene"),
        staging_dir=str(root / "staging"),
        **arguments,
    )


def _tree(scene) -> tuple[tuple[str, bytes], ...]:
    root = Path(scene.directory)
    return tuple(
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _fingerprints(scene) -> tuple[str, str, str, str]:
    tree_index = [
        (path, len(data), hashlib.sha256(data).hexdigest())
        for path, data in _tree(scene)
    ]
    return (
        _digest(tree_index),
        _digest(scene.join),
        _digest(scene.timestamp_roles),
        _digest(scene.artifacts),
    )


def test_benchmark_derivation_reproduces_the_frozen_suite_formulas_exactly():
    derivation = BENCHMARK_SCENE_DERIVATION
    assert derivation.value(KEY, "alpha", "beta") == suite.scene_value(
        KEY, "alpha", "beta"
    )
    assert derivation.content_seed(KEY, "resident") == suite.content_seed(KEY, "resident")
    assert derivation.pick(KEY, "persisted-name", pools.MALWARE_NAMES) == suite.pick(
        KEY, "persisted-name", pools.MALWARE_NAMES
    )
    assert derivation.pick_many(KEY, "resident", pools.BENIGN_NAMES, 5) == suite.pick_many(
        KEY, "resident", pools.BENIGN_NAMES, 5
    )
    assert derivation.bounded_key_value(
        KEY, "legacy-count", key_index=3, modulus=5, offset=1
    ) == 1 + KEY[3] % 5
    assert derivation.opaque_sha1(KEY, "amcache-decoy:0") == hashlib.sha1(
        KEY + b"amcache-decoy:0"
    ).hexdigest()  # noqa: S324 - frozen synthetic identity formula


def test_derivation_domains_and_json_provenance_are_pinned():
    assert BENCHMARK_VALUE_DOMAIN == BENCHMARK_CONTENT_DOMAIN == "artifactforge/bench/v1"
    assert FIXTURE_V2_VALUE_DOMAIN == "artifactforge/fixture/scene-value/v2"
    assert FIXTURE_V2_CONTENT_DOMAIN == "artifactforge/fixture/content-derivation/v2"
    assert DERIVATION_ALGORITHM == "hmac-sha256-unit-separator-v1"
    assert BENCHMARK_SCENE_DERIVATION.provenance == {
        "name": "artifactforge/benchmark-scene-derivation/v1",
        "algorithm": "hmac-sha256-unit-separator-v1",
        "value_domain": "artifactforge/bench/v1",
        "content_domain": "artifactforge/bench/v1",
        "content_prefix": "content",
    }
    assert FIXTURE_V2_SCENE_DERIVATION.provenance == {
        "name": "artifactforge/fixture-scene-derivation/v2",
        "algorithm": "hmac-sha256-unit-separator-v1",
        "value_domain": "artifactforge/fixture/scene-value/v2",
        "content_domain": "artifactforge/fixture/content-derivation/v2",
        "content_prefix": "content",
    }
    detached = BENCHMARK_SCENE_DERIVATION.provenance
    detached["value_domain"] = "mutated"
    assert BENCHMARK_SCENE_DERIVATION.value_domain == "artifactforge/bench/v1"


@pytest.mark.parametrize("family", tuple(_BUILDERS))
def test_default_and_explicit_benchmark_derivations_are_complete_byte_twins(
    tmp_path, family
):
    implicit = _build(tmp_path / family / "implicit", family)
    explicit = _build(
        tmp_path / family / "explicit", family, BENCHMARK_SCENE_DERIVATION
    )

    assert _tree(implicit) == _tree(explicit)
    assert implicit.artifacts == explicit.artifacts
    assert implicit.join == explicit.join
    assert implicit.timestamp_roles == explicit.timestamp_roles
    assert _fingerprints(implicit) == _PINNED_FINGERPRINTS[family]


@pytest.mark.parametrize("family", tuple(_BUILDERS))
def test_fixture_v2_scenes_are_deterministic_and_disjoint_from_benchmark(
    tmp_path, family
):
    first = _build(tmp_path / family / "fixture-one", family, FIXTURE_V2_SCENE_DERIVATION)
    second = _build(tmp_path / family / "fixture-two", family, FIXTURE_V2_SCENE_DERIVATION)
    benchmark = _build(tmp_path / family / "benchmark", family, BENCHMARK_SCENE_DERIVATION)

    assert _tree(first) == _tree(second)
    assert first.artifacts == second.artifacts
    assert first.join == second.join
    assert first.timestamp_roles == second.timestamp_roles
    assert (_tree(first), first.join) != (_tree(benchmark), benchmark.join)


def test_value_and_content_domain_changes_are_isolated_at_the_derivation_boundary():
    baseline = SceneDerivation("test/baseline", "test/value/a", "test/content/a")
    value_changed = SceneDerivation("test/value-changed", "test/value/b", "test/content/a")
    content_changed = SceneDerivation(
        "test/content-changed", "test/value/a", "test/content/b"
    )

    assert value_changed.value(KEY, "field") != baseline.value(KEY, "field")
    assert value_changed.content_seed(KEY, "role") == baseline.content_seed(KEY, "role")
    assert content_changed.value(KEY, "field") == baseline.value(KEY, "field")
    assert content_changed.content_seed(KEY, "role") != baseline.content_seed(KEY, "role")


@pytest.mark.parametrize(
    "skey",
    (b"short", bytearray(b"x" * 32), "x" * 32, True),
)
def test_scene_keys_fail_closed_on_type_and_width(skey):
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        BENCHMARK_SCENE_DERIVATION.value(skey, "field")


@pytest.mark.parametrize(
    "pool",
    ((), [], "abc", ("same", "same"), ("valid", 1)),
)
def test_derivation_pools_fail_closed(pool):
    with pytest.raises(ValueError, match="pool"):
        BENCHMARK_SCENE_DERIVATION.pick(KEY, "field", pool)


@pytest.mark.parametrize("count", (True, 0, -1, 3))
def test_pick_many_counts_fail_closed(count):
    with pytest.raises(ValueError, match="count"):
        BENCHMARK_SCENE_DERIVATION.pick_many(KEY, "field", ("a", "b"), count)


def test_ordering_requires_unique_typed_identities():
    with pytest.raises(ValueError, match="unique"):
        BENCHMARK_SCENE_DERIVATION.order(
            KEY, "rows", ("first", "second"), identity=lambda _value: "same"
        )
    with pytest.raises(ValueError, match="identity"):
        BENCHMARK_SCENE_DERIVATION.order(
            KEY, "rows", ("first",), identity=lambda _value: 1
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("name", ""),
        ("value_domain", b"not-text"),
        ("content_domain", "not-ascii-\N{SNOWMAN}"),
        ("value_domain", "x\x1fy"),
        ("content_domain", "x" * 129),
    ),
)
def test_derivation_identity_fields_fail_closed(field, value):
    arguments = {
        "name": "test/name",
        "value_domain": "test/value",
        "content_domain": "test/content",
    }
    arguments[field] = value
    with pytest.raises(ValueError):
        SceneDerivation(**arguments)


def test_scene_derivation_is_frozen_and_builders_require_the_exact_type(tmp_path):
    with pytest.raises(FrozenInstanceError):
        setattr(BENCHMARK_SCENE_DERIVATION, "value_domain", "changed")

    builder, profile = _BUILDERS["linux"]
    with pytest.raises(ValueError, match="exact SceneDerivation"):
        builder(
            ContentStore("derivation-contract", str(tmp_path / "content")),
            skey=KEY,
            profile=profile,
            scene_dir=str(tmp_path / "scene"),
            staging_dir=str(tmp_path / "staging"),
            derivation=None,
        )
