# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""ArtifactForge — deterministic forensic-artifact generator.

Layered so dependencies point one way only:

    model <- content <- artifacts <- compose <- bench <- cli

`model` knows nothing about anything else. `content` owns file bytes and their identity.
`artifacts` writes one file format each. `compose` assembles them into a scene on disk.
`bench` turns scenes into gradeable tasks. `gates` and `scorecard` measure the result.

`ingest` — the EvidenceForge companion adapter — sits outside that chain and depends only
on `model`; nothing in the chain may import it, and `ef_seeds` is deliberately absent from
the public surface below so upstream's private seed formulas are not re-exported as
ArtifactForge API. See docs/DESIGN.md.
"""
from artifactforge.artifacts import (
    build_amcache_hive,
    build_knowledgec,
    build_launch_agent,
    build_prefetch,
    build_quarantine_events,
    build_run_hive,
    build_tcc,
    quarantine_xattr,
)
from artifactforge.bench import Question, Score, Task, generate_batch, grade
from artifactforge.compose import CrimeScene, build_crime_scene, build_macos_crime_scene
from artifactforge.content import Content, ContentStore, build_pe_stub, imphash_of
from artifactforge.model import HostProfile, deterministic_uuid, macos_profile, windows_profile

__all__ = [
    # content
    "Content", "ContentStore", "build_pe_stub", "imphash_of",
    # model
    "HostProfile", "windows_profile", "macos_profile", "deterministic_uuid",
    # artifacts
    "build_run_hive", "build_amcache_hive", "build_prefetch",
    "build_knowledgec", "build_tcc", "build_quarantine_events",
    "quarantine_xattr", "build_launch_agent",
    # compose
    "CrimeScene", "build_crime_scene", "build_macos_crime_scene",
    # bench
    "Task", "Question", "Score", "generate_batch", "grade",
]
__version__ = "0.0.1"
