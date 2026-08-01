# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
#
# The seed construction reproduced below is transcribed from EvidenceForge
# (MIT, Copyright (c) 2026 Cisco Systems, Inc. and its affiliates),
# src/evidenceforge/generation/emitters/sysmon.py::_generate_hashes, at tag v1.13.1.
# It is reproduced here to RECOVER identity from EvidenceForge's output, never to
# reimplement EvidenceForge. Upstream: https://github.com/Cisco-Talos/EvidenceForge
"""Recover a Sysmon-local logical identity from EvidenceForge's seed-derived hashes.

EvidenceForge computes these Sysmon fields as digests of seed strings rather than file bytes.
The Zeek path uses a different seed domain, and the measured stock run's same-algorithm sets are
disjoint; because that run has no basename-matched transfer/execution pair, it does not prove
that one logical binary received two inconsistent values. This module has the narrower job of
recovering which Sysmon-local logical file each verified hash denotes.

**Verify or refuse.** Every recovery recomputes the candidate digests and compares them
against the one upstream actually emitted. If none matches, or more than one does, this
raises. Nothing routes an unverified identity onward.

That matters because of how the discrimination works. Upstream selects its seed form by the
*shape of the arguments it was handed*, not by event type — and it has three forms, one of
which had no ArtifactForge counterpart at all. A previous version of this module guessed the
form from the Sysmon EventID, which happens to coincide with upstream's choice today, and
would have gone on returning a wrong identity, silently, the moment that stopped being true.

This is a deliberate anti-corruption layer around a PRIVATE upstream surface, which SemVer
does not protect. Nothing else in the package imports it, it is absent from the public
exports, and its CI job fails rather than skips — so drift breaks loudly, in one file.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

#: The upstream tag these formulas were verified against. Confirmed byte-for-byte identical at
#: v1.12.0 and v1.13.1: the function body and both its call sites are unchanged between them.
VERIFIED_AGAINST = "v1.13.1"


def _normalize(image: str) -> str:
    return image.replace("/", "\\").lower()


def seed_bare(image: str) -> str:
    """Upstream form 1: neither a rendered identity nor a host context was supplied."""
    return _normalize(image)


def seed_with_description(image: str, file_version, description, product, company,
                          original_name) -> str:
    """Upstream form 2: `rendered_identity[:5]`, joined — description included."""
    return (f"{_normalize(image)}:{file_version}:{description}:{product}:{company}:"
            f"{original_name}")


def seed_from_host_metadata(image: str, file_version, product, company,
                            original_name) -> str:
    """Upstream form 3: PE metadata looked up from a host context — description dropped."""
    return f"{_normalize(image)}:{file_version}:{product}:{company}:{original_name}"


def _digest(seed: str) -> str:
    """The SHA256 upstream would emit for a seed — upper-case, matching its output."""
    return hashlib.sha256(seed.encode()).hexdigest().upper()


@dataclass(frozen=True)
class Identity:
    """One logical file, recovered and verified against the digest upstream emitted."""

    content_id: str      # stable across emitters: one binary, one set of bytes
    seed: str            # the upstream seed string that reproduced the emitted digest
    form: str            # which of upstream's three forms matched
    emitted_sha256: str  # the digest we verified against, exactly as it appeared


class IdentityNotRecovered(Exception):
    """The emitted digest matched no candidate seed, or matched more than one.

    Both are drift. Neither is recoverable here, and guessing would put a wrong identity into
    the ContentStore where nothing downstream could tell.
    """


def recover(emitted_sha256: str, *, image: str, file_version=None, description=None,
            product=None, company=None, original_name=None) -> Identity:
    """Recover which logical file an emitted Sysmon hash denotes, or raise.

    Tries every upstream seed form and requires exactly one to reproduce the digest. The
    caller passes whatever fields the record carried; absent ones render as upstream renders
    them, which is `str(None)`.
    """
    emitted = (emitted_sha256 or "").strip().upper()
    if len(emitted) != 64:
        raise IdentityNotRecovered(
            f"{emitted_sha256!r} is not a SHA256 digest, so nothing can be verified against it")

    candidates = {
        "with_description": seed_with_description(image, file_version, description, product,
                                                  company, original_name),
        "from_host_metadata": seed_from_host_metadata(image, file_version, product, company,
                                                      original_name),
        "bare": seed_bare(image),
    }
    matched = {form: seed for form, seed in candidates.items() if _digest(seed) == emitted}

    if len(matched) != 1:
        raise IdentityNotRecovered(
            f"{len(matched)} of {len(candidates)} upstream seed forms reproduce "
            f"{emitted[:16]}... for {image!r}; exactly one must. Either EvidenceForge's seed "
            f"construction has drifted from the {VERIFIED_AGAINST} formulas transcribed in "
            f"this module, or these are not the fields the record was rendered from.")

    form, seed = next(iter(matched.items()))
    return Identity(content_id="pe:" + seed, seed=seed, form=form, emitted_sha256=emitted)
