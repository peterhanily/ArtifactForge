# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Immutable fixture ABI identities and local producer availability.

Parsing and producing are deliberately separate capabilities.  An old contract can remain
readable after its exact byte producer has been retired; a matching package version is not
evidence that the current source tree still implements those historical bytes.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


SPEC_SCHEMA_V1 = "artifactforge-fixture-spec-v1"
MANIFEST_SCHEMA_V1 = "artifactforge-fixture-manifest-v1"
CANONICALIZATION_V1 = "artifactforge-canonical-json-v1"
TREE_CANONICALIZATION_V1 = "artifactforge-fixture-tree-v1"
GENERATOR_ABI_V1 = "artifactforge-fixture-generator-v1"

SPEC_SCHEMA_V2 = "artifactforge-fixture-spec-v2"
MANIFEST_SCHEMA_V2 = "artifactforge-fixture-manifest-v2"
TREE_CANONICALIZATION_V2 = "artifactforge-fixture-tree-v2"
GENERATOR_ABI_V2 = "artifactforge-fixture-generator-v2"
PRODUCER_PROFILE_V2 = "artifactforge-fixture-producer-v2"


class FixtureProducerUnavailable(ValueError):
    """The requested contract is parseable, but its exact byte producer is absent."""


@dataclass(frozen=True)
class FixtureABI:
    """One mutually consistent fixture spec, manifest, tree and generator contract."""

    name: str
    spec_schema: str
    manifest_schema: str
    canonicalization: str
    tree_canonicalization: str
    generator_abi: str
    producer_profile: str | None
    frozen_release: str
    producer_implementation: str | None

    @property
    def producer_available(self) -> bool:
        return self.producer_implementation is not None

    def require_producer(self, identifier: str) -> str:
        """Return the explicit implementation identity or fail without a fallback."""
        if self.producer_implementation is None:
            if self.frozen_release == "unreleased":
                status = "is not released and has no registered exact producer"
            else:
                status = (
                    f"is frozen at ArtifactForge {self.frozen_release} bytes and its exact "
                    "producer is intentionally unavailable"
                )
            raise FixtureProducerUnavailable(
                f"fixture ABI {self.name} is parse-only in this build: {identifier!r} "
                f"{status}; current writers must not relabel bytes across fixture ABI versions"
            )
        return self.producer_implementation


FIXTURE_ABI_V1 = FixtureABI(
    name="v1",
    spec_schema=SPEC_SCHEMA_V1,
    manifest_schema=MANIFEST_SCHEMA_V1,
    canonicalization=CANONICALIZATION_V1,
    tree_canonicalization=TREE_CANONICALIZATION_V1,
    generator_abi=GENERATOR_ABI_V1,
    producer_profile=None,
    frozen_release="0.5.0",
    # The current writers no longer emit the 0.5.0 bytes, so this slot must stay empty;
    # a future v2 implementation gets a new record rather than reoccupying this one.
    producer_implementation=None,
)

FIXTURE_ABI_V2 = FixtureABI(
    name="v2",
    spec_schema=SPEC_SCHEMA_V2,
    manifest_schema=MANIFEST_SCHEMA_V2,
    # V2 deliberately retains the exact v1 canonical-JSON algorithm.  Sharing an algorithm
    # identifier is not an ABI fallback: every semantic and producer axis below is disjoint.
    canonicalization=CANONICALIZATION_V1,
    tree_canonicalization=TREE_CANONICALIZATION_V2,
    generator_abi=GENERATOR_ABI_V2,
    producer_profile=PRODUCER_PROFILE_V2,
    frozen_release="unreleased",
    # V2 production is one closed lifecycle: isolated scene derivation, logical projection,
    # fixed carrier materialisation, complete-manifest reproduction, and canonical release.
    producer_implementation=PRODUCER_PROFILE_V2,
)

FIXTURE_ABIS: tuple[FixtureABI, ...] = (FIXTURE_ABI_V1, FIXTURE_ABI_V2)
SPEC_ABIS: Mapping[str, FixtureABI] = MappingProxyType(
    {contract.spec_schema: contract for contract in FIXTURE_ABIS}
)
MANIFEST_ABIS: Mapping[str, FixtureABI] = MappingProxyType(
    {contract.manifest_schema: contract for contract in FIXTURE_ABIS}
)
GENERATOR_ABIS: Mapping[str, FixtureABI] = MappingProxyType(
    {contract.generator_abi: contract for contract in FIXTURE_ABIS}
)


def require_spec_producer(schema: str) -> FixtureABI:
    """Require an explicitly registered producer for one already-validated spec schema."""
    contract = SPEC_ABIS.get(schema)
    if contract is None:
        raise FixtureProducerUnavailable(f"no fixture ABI is registered for spec schema {schema!r}")
    contract.require_producer(schema)
    return contract


def require_manifest_producer(
    *, manifest_schema: str, spec_schema: str, generator_abi: str
) -> FixtureABI:
    """Require one producer record that binds all three manifest ABI identities."""
    contract = MANIFEST_ABIS.get(manifest_schema)
    if contract is None:
        raise FixtureProducerUnavailable(
            f"no fixture ABI is registered for manifest schema {manifest_schema!r}"
        )
    if contract.spec_schema != spec_schema or contract.generator_abi != generator_abi:
        raise FixtureProducerUnavailable(
            "fixture manifest mixes incompatible ABI identities: "
            f"manifest={manifest_schema!r}, spec={spec_schema!r}, "
            f"generator={generator_abi!r}"
        )
    contract.require_producer(generator_abi)
    return contract
