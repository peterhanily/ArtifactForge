# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fixture Core v1 — strict public recipes, byte-bound manifests and safe lifecycle APIs."""

from artifactforge.fixture.archive import (
    ArchivePublicationUncertain,
    ArchiveResult,
    ArchiveVerificationResult,
    FixtureArchiveError,
    FixtureArchiveMismatch,
    create_release_archive,
    verify_release_archive,
)
from artifactforge.fixture.model import (
    ArtifactEntry,
    FixtureManifest,
    FixturePayload,
    FixturePurpose,
    FixtureSpec,
    FixtureValidationError,
    GeneratorIdentity,
    ProfileSpec,
)
from artifactforge.fixture.operations import (
    FixturePublicationUncertain,
    FixtureUsageError,
    VerificationResult,
    build_fixture,
    verify_fixture,
)

__all__ = [
    "ArchivePublicationUncertain",
    "ArchiveResult",
    "ArchiveVerificationResult",
    "ArtifactEntry",
    "FixtureArchiveError",
    "FixtureArchiveMismatch",
    "FixtureManifest",
    "FixturePayload",
    "FixturePublicationUncertain",
    "FixturePurpose",
    "FixtureSpec",
    "FixtureUsageError",
    "FixtureValidationError",
    "GeneratorIdentity",
    "ProfileSpec",
    "VerificationResult",
    "build_fixture",
    "create_release_archive",
    "verify_fixture",
    "verify_release_archive",
]
