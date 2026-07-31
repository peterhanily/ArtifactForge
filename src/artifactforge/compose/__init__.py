# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Compose single-format writers into a coherent scene on disk.

A scene is what a responder actually receives: a directory of artifacts that all describe
one incident, plus the join manifest recording where the single identity surfaces.

Depends on: model, content, artifacts. Nothing here may import bench or ingest.
"""
from artifactforge.compose.scene import CrimeScene, build_crime_scene, build_macos_crime_scene

__all__ = ["CrimeScene", "build_crime_scene", "build_macos_crime_scene"]
