# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Evaluator-created Benchmark v3 freshness ceremony.

This module is the only public v3 constructor.  It accepts no caller key, ceremony identifier,
origin classification or timestamp.  The resulting record is still local self-attestation;
it cannot prove evaluator independence or solver isolation from inside this process.
"""

from __future__ import annotations

from datetime import datetime, timezone
import secrets

from artifactforge import suite
from artifactforge.bench.benchmark import _generate_protocol_suite


def _created_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def create_evaluator_ceremony(n: int, root: str) -> list:
    """Create one no-replace v3 evaluator suite using internally minted CSPRNG material."""
    n = suite.validate_benchmark_v3_scenario_count(n)
    material = secrets.token_bytes(48)
    if not isinstance(material, bytes) or len(material) != 48:
        raise RuntimeError("secrets.token_bytes did not return the requested ceremony material")
    key = material[:32]
    ceremony_id = suite.ceremony_id_from_entropy(material[32:])
    origin, record = suite._build_evaluator_ceremony_documents(
        key,
        ceremony_id=ceremony_id,
        created_at=_created_at(),
    )
    return _generate_protocol_suite(
        n,
        root,
        key=key,
        kind=suite.HOLDOUT_SUITE_KIND,
        protocol_domain=suite.BENCHMARK_V3_DOMAIN,
        origin=origin,
        ceremony_record=record,
    )
