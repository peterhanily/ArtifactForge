# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Tier 2 — the contract with EvidenceForge, checked against a real run of it.

Set `ARTIFACTFORGE_EF_OUT` to an EvidenceForge output directory. CI generates one and sets it,
and that job fails rather than skips when it is missing: a skipped integration test exits 0
and reads exactly like a passing one, which is how an upstream formula change would sail
through green for as long as nobody looked.

What this proves, stated precisely, because the predecessor of this file overstated it: on a
real run, every hashed Sysmon record's emitter-local seed identity is recovered and verified
against the digest EvidenceForge actually emitted. It does **not** prove that an emitted hash
identifies ArtifactForge bytes, or that one transferred file and one executed file disagree.
The shipped scenario contains no positive same-file transfer-to-execution witness; that needs
a separate controlled fixture.
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


def test_one_recovered_content_id_maps_deterministically_to_one_blob(run, tmp_path):
    """The adapter's derived content id is a stable input to ArtifactForge's generator.

    This is an adapter determinism check, not evidence that the generated blob is the file an
    EvidenceForge event observed.
    """
    store = ContentStore("artifactforge::ef-contract", str(tmp_path / "content"))
    assert run.binaries
    for binary in list(run.binaries.values())[:25]:
        first = store.materialize(binary.content_id)
        again = store.materialize(binary.content_id)
        assert first.sha256 == again.sha256
        with open(first.path, "rb") as f:
            assert hashlib.sha256(f.read()).hexdigest() == first.sha256


def test_upstream_hash_is_not_the_digest_of_the_artifactforge_blob(run, tmp_path):
    """The current adapter does not reconcile an EF observation with generated file bytes.

    EvidenceForge's emitted SHA256 is derived from emitter-local seed material, while this
    ArtifactForge blob is generated later from the recovered content id. The values differ in
    this pinned construction. That is not a same-file cross-emitter witness.
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
