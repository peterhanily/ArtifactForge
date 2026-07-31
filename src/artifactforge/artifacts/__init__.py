# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Single-format writers. One module per artifact format, each validated by a real parser.

Every writer here is a pure function of its arguments — no wall clock, no entropy, no
filesystem — so a scene composed from them regenerates byte-identical.

Depends on: model, content. Nothing here may import compose, bench or ingest.
"""
from artifactforge.artifacts.hive import build_amcache_hive, build_run_hive
from artifactforge.artifacts.macos import (
    build_knowledgec,
    build_launch_agent,
    build_quarantine_events,
    build_tcc,
    quarantine_xattr,
)
from artifactforge.artifacts.prefetch import build_prefetch, prefetch_name_hash

__all__ = [
    "build_run_hive", "build_amcache_hive",
    "build_prefetch", "prefetch_name_hash",
    "build_knowledgec", "build_tcc", "build_quarantine_events",
    "quarantine_xattr", "build_launch_agent",
]
