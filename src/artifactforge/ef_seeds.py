"""Recover a file's logical identity from EvidenceForge's per-emitter hashes.

EvidenceForge (v1.12.0) computes file "hashes" as digests of a seed STRING, keyed
differently per event type, so the same binary gets disagreeing hashes across emitters.
To bind an artifact to a log we must recover which logical file each hash belongs to.

These are the verified Sysmon seed formulas (src/evidenceforge/.../emitters/sysmon.py
_generate_hashes), confirmed by recomputing them against a real EF run — every hash
matched: EID 1 (ProcessCreate) omits Description; EID 7 (ImageLoaded) includes it.
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
