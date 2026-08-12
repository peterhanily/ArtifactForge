# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The release round trip has to close.

`release` writes canonical USTAR metadata, which normalises modes to 0755/0644 so the archive
bytes are deterministic. A fixture carrier requires 0700/0600. Plain `tar -x` therefore hands
back a tree this project's own `verify` rejects, which made the last command of the documented
quick start produce something unusable. `extract` restores the carrier modes — and refuses to
write anything the verifier did not already accept.
"""

from __future__ import annotations

import os
import stat
import tarfile

import pytest

from artifactforge.fixture.archive import (
    FixtureArchiveError,
    create_release_archive,
    extract_release_archive,
    verify_release_archive,
)
from artifactforge.fixture.model_v2 import FixtureSpecV2, ProfileSpecV2
from artifactforge.fixture.operations import (
    FixtureUsageError,
    build_fixture,
    verify_fixture,
)


@pytest.fixture
def released(tmp_path):
    spec = FixtureSpecV2.create(
        fixture_id="round-trip",
        family="linux",
        story="linux-autostart-v1",
        profile=ProfileSpecV2(
            id="linux-glibc-x86_64-loose-v2", hostname="linux-01", username="v"
        ),
        seed_hex="3c" * 32,
    )
    source = tmp_path / "source"
    build_fixture(spec, source)
    archive = tmp_path / "round-trip.tar"
    create_release_archive(source, archive)
    return archive


def test_plain_tar_extraction_is_what_extract_exists_to_fix(released, tmp_path):
    """Pin the actual defect: the archive's own modes cannot satisfy the carrier contract."""
    loose = tmp_path / "loose"
    loose.mkdir()
    with tarfile.open(released, mode="r:") as handle:
        handle.extractall(loose)  # noqa: S202 - our own canonical archive, in a temp dir
    root = loose / "round-trip"
    assert stat.S_IMODE(root.stat().st_mode) != 0o700
    with pytest.raises(FixtureUsageError, match="carrier directory mode"):
        verify_fixture(root)


def test_extract_produces_a_fixture_that_verifies(released, tmp_path):
    destination = tmp_path / "extracted"
    result = extract_release_archive(released, destination)

    assert result.ok
    assert result.manifest.recipe.fixture_id == "round-trip"
    verified = verify_fixture(destination)
    assert verified.ok
    assert verified.manifest == result.manifest


def test_extract_restores_the_exact_carrier_modes(released, tmp_path):
    destination = tmp_path / "extracted"
    extract_release_archive(released, destination)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    for current, directories, files in os.walk(destination):
        for name in directories:
            assert stat.S_IMODE(os.stat(os.path.join(current, name)).st_mode) == 0o700
        for name in files:
            assert stat.S_IMODE(os.stat(os.path.join(current, name)).st_mode) == 0o600


def test_extract_reproduces_the_original_payload_bytes(released, tmp_path):
    destination = tmp_path / "extracted"
    extract_release_archive(released, destination)
    manifest = verify_fixture(destination).manifest
    for entry in manifest.payload.files:
        path = destination / "artifacts" / entry.served_path
        assert path.read_bytes()
        assert path.stat().st_size == entry.size


def test_extract_refuses_an_existing_destination(released, tmp_path):
    destination = tmp_path / "extracted"
    extract_release_archive(released, destination)
    with pytest.raises(FixtureArchiveError, match="refusing existing extraction destination"):
        extract_release_archive(released, destination)


@pytest.mark.parametrize("offset", [4096, 8192, 12288])
def test_extract_refuses_a_tampered_archive(released, tmp_path, offset):
    """Nothing reaches disk unless verification already accepted it.

    A refusal here is either a raise or a not-ok result depending on which structure the
    flipped byte lands in; both are refusals, and neither may write a destination.
    """
    payload = bytearray(released.read_bytes())
    payload[offset] ^= 0xFF
    tampered = tmp_path / "tampered.tar"
    tampered.write_bytes(bytes(payload))

    try:
        assert not verify_release_archive(tampered).ok
    except FixtureArchiveError:
        pass

    destination = tmp_path / f"never-written-{offset}"
    with pytest.raises(FixtureArchiveError):
        extract_release_archive(tampered, destination)
    assert not destination.exists()
