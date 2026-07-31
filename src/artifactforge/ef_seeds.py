# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
#
# The seed construction reproduced below is transcribed from EvidenceForge
# (MIT, Copyright (c) 2026 Cisco Systems, Inc. and its affiliates),
# src/evidenceforge/generation/emitters/sysmon.py::_generate_hashes, at tag v1.13.1.
# It is reproduced here to RECOVER identity from EvidenceForge's output, never to
# reimplement EvidenceForge. Upstream: https://github.com/Cisco-Talos/EvidenceForge
"""Recover a file's logical identity from EvidenceForge's per-emitter hashes.

EvidenceForge computes file "hashes" as digests of a seed STRING, keyed differently per
event type, so the same binary carries disagreeing hashes across emitters. To bind an
artifact to a log at all, we first have to recover which logical file each hash denotes.

These are upstream's verified Sysmon seed formulas, confirmed by recomputing them against a
real run — every hash matched, and the formulas are unchanged between v1.12.0 and v1.13.1.

This module is a deliberate anti-corruption layer around a PRIVATE upstream surface, which
SemVer does not protect. Nothing in the rest of the package imports it, and it is absent
from the public exports, so the coupling stays in one file that can fail loudly on its own.
"""
from __future__ import annotations

import hashlib


def sysmon_seed(path, file_version, description, product, company, original_name, event_id) -> str:
    ni = path.replace("/", "\\").lower()
    if str(event_id) == "7":  # ImageLoaded: rendered_identity=(fv, desc, prod, comp, orig)
        return f"{ni}:{file_version}:{description}:{product}:{company}:{original_name}"
    return f"{ni}:{file_version}:{product}:{company}:{original_name}"  # ProcessCreate: no desc


def sysmon_sha256(*seed_args) -> str:
    """The SHA256 EF would emit for these fields (upper-case, matching EF)."""
    return hashlib.sha256(sysmon_seed(*seed_args).encode()).hexdigest().upper()


def content_id(*seed_args) -> str:
    """Stable logical-file identity: the tuple EF keys its hash on. One binary -> one bytes."""
    return "pe:" + sysmon_seed(*seed_args)
