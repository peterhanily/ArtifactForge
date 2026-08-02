# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Compose single-format writers into a coherent scene on disk.

A scene is what a responder actually receives: a directory of artifacts that all describe one
incident, with decoys, and exactly one thread running through them. The answer key does not
live in it — the served directory is staged by allowlist from a separate build area.

Depends on: model, suite, content, artifacts. Nothing here may import bench or ingest.
"""
from artifactforge.compose.scene import (
    Scene,
    build_linux_scene,
    build_macos_scene,
    build_windows_scene,
)
from artifactforge.compose.assurance import generate_linux_assurance

__all__ = [
    "Scene",
    "build_windows_scene",
    "build_macos_scene",
    "build_linux_scene",
    "generate_linux_assurance",
]
