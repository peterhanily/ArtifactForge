# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Tier 2 — the transcribed seed formulas, checked against upstream's own code.

This is the only file in the repository that imports EvidenceForge, and it exists for one
reason: `artifactforge/ef_seeds.py` reproduces a private upstream function, and a
transcription that is never compared to its source is a copy waiting to rot.

Everything here calls EvidenceForge's real `_generate_hashes` and requires our reproduction
to agree with it exactly. When upstream changes that function — which it may, since nothing
declares it public — this goes red on the next run, in one place, with the diff visible.
"""
import re

import pytest

from artifactforge.ef_seeds import (
    VERIFIED_AGAINST,
    IdentityNotRecovered,
    recover,
    seed_bare,
    seed_from_host_metadata,
    seed_with_description,
)

pytest.importorskip("evidenceforge.generation.emitters.sysmon")
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter  # noqa: E402

IMAGE = r"C:\Windows\System32\svchost.exe"
META = ("10.0.19041.1", "Host Process for Windows Services", "Microsoft Windows",
        "Microsoft Corporation", "svchost.exe")


def _emitted(*args, **kwargs) -> str:
    raw = SysmonEventEmitter._generate_hashes(*args, **kwargs)
    return re.search(r"SHA256=([0-9A-F]+)", raw).group(1)


class _HostContext:
    """Upstream's third branch triggers on a host argument that is not a string."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


def test_the_rendered_identity_form_matches_upstream():
    fv, desc, prod, comp, orig = META
    ours = seed_with_description(IMAGE, fv, desc, prod, comp, orig)
    identity = recover(_emitted(IMAGE, None, META), image=IMAGE, file_version=fv,
                       description=desc, product=prod, company=comp, original_name=orig)
    assert identity.seed == ours
    assert identity.form == "with_description"


def test_the_bare_path_form_matches_upstream():
    """The form ArtifactForge previously could not express at all."""
    identity = recover(_emitted(IMAGE, None, None), image=IMAGE)
    assert identity.seed == seed_bare(IMAGE)
    assert identity.form == "bare"


def test_recovery_refuses_rather_than_guessing_when_nothing_matches():
    with pytest.raises(IdentityNotRecovered, match="0 of 3"):
        recover("F" * 64, image=IMAGE)


def test_the_host_metadata_form_is_reachable_and_matches(monkeypatch):
    """Upstream's `elif host is not None and not isinstance(host, str)` branch: the PE
    metadata is looked up from a host context and the description is dropped."""
    fv, _desc, prod, comp, orig = META
    monkeypatch.setattr(SysmonEventEmitter, "_get_pe_metadata",
                        classmethod(lambda cls, image, host: META), raising=True)
    emitted = _emitted(IMAGE, _HostContext(hostname="WS-01"), None)
    identity = recover(emitted, image=IMAGE, file_version=fv, product=prod, company=comp,
                       original_name=orig)
    assert identity.seed == seed_from_host_metadata(IMAGE, fv, prod, comp, orig)
    assert identity.form == "from_host_metadata"


def test_the_pinned_version_is_recorded():
    """If the formulas are re-verified against a newer tag, the constant moves with them."""
    assert VERIFIED_AGAINST.startswith("v")
