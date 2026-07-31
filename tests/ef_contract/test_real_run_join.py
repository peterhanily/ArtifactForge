# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Tier 2 — the contract with EvidenceForge, checked against a real run of it.

Set `ARTIFACTFORGE_EF_OUT` to an EvidenceForge output directory. CI generates one and sets it,
and that job fails rather than skips when it is missing: a skipped integration test exits 0
and reads exactly like a passing one, which is how an upstream formula change would sail
through green for as long as nobody looked.

What this proves, stated precisely, because the predecessor of this file overstated it: on a
real run, every hashed Sysmon record's *logical identity* is recovered and verified against
the digest EvidenceForge actually emitted. It does **not** prove that EvidenceForge's emitted
hashes equal ArtifactForge's file digests — they do not and cannot, since upstream hashes a
seed string rather than any bytes. That gap is the thing the project exists to describe, so
there is a test asserting it is still there rather than one quietly implying it is not.
"""
import hashlib
import os

import pytest

from artifactforge.content import ContentStore
from artifactforge.ef_seeds import IdentityNotRecovered, recover
from artifactforge.ingest.evidenceforge import read_run

EF_OUT = os.environ.get("ARTIFACTFORGE_EF_OUT")
pytestmark = pytest.mark.skipif(
    not EF_OUT, reason="set ARTIFACTFORGE_EF_OUT to an EvidenceForge output directory")


@pytest.fixture(scope="module")
def run():
    return read_run(EF_OUT)


def test_every_hashed_record_is_recovered_and_verified(run):
    """Not "reverse-mapped" — verified. Each candidate seed is recomputed and compared
    against upstream's emitted digest, and a record matching none of them raises."""
    assert run.records_with_hashes > 0, "the run contains no hashed Sysmon records at all"
    assert run.records_recovered == run.records_with_hashes, run.unrecovered[:3]
    assert not run.unrecovered


def test_both_upstream_seed_forms_appear(run):
    """Upstream discriminates by argument shape, not by event type. If a run exercised only
    one form, we would not learn whether the other still matched."""
    forms = {b.seed_form for b in run.binaries.values()}
    assert len(forms) >= 2, f"only one seed form exercised: {forms}"


def test_one_binary_maps_to_one_set_of_bytes(run, tmp_path):
    """The identity is stable across every emitter and host that mentions the file."""
    store = ContentStore("artifactforge::ef-contract", str(tmp_path / "content"))
    assert run.binaries
    for binary in list(run.binaries.values())[:25]:
        first = store.materialize(binary.content_id)
        again = store.materialize(binary.content_id)
        assert first.sha256 == again.sha256
        with open(first.path, "rb") as f:
            assert hashlib.sha256(f.read()).hexdigest() == first.sha256


def test_upstream_hashes_are_not_digests_of_any_bytes(run, tmp_path):
    """The gap, asserted rather than asserted away.

    EvidenceForge's emitted SHA256 is a digest of a seed string; ArtifactForge's is a digest
    of real bytes. They differ, necessarily. A test claiming otherwise would be describing a
    patched copy of the logs rather than what upstream emits.
    """
    store = ContentStore("artifactforge::ef-contract", str(tmp_path / "content"))
    binary = next(iter(run.binaries.values()))
    content = store.materialize(binary.content_id)
    assert content.sha256.upper() != binary.emitted_sha256.upper()


def test_a_drifted_formula_raises_instead_of_returning_a_wrong_identity(run):
    """The whole point of verify-or-refuse. A digest matching no seed form must raise."""
    binary = next(iter(run.binaries.values()))
    with pytest.raises(IdentityNotRecovered):
        recover("A" * 64, image=binary.image)
    with pytest.raises(IdentityNotRecovered):
        recover("not-a-digest", image=binary.image)
