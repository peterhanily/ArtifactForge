# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic Linux scenes used by generator assurance, never by Gate 4.

The Windows/macOS benchmark corpus predates Linux support and remains a deliberately invalid
measurement population until its question class is redesigned.  This module keeps the scopes
structurally separate: it emits no public questions, answer key, score, or suite key file.  Its
``Scene.join`` values exist only in the caller's memory so Gate 2 can verify the generated
cross-artifact identities.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import shutil

from artifactforge import pools, suite
from artifactforge.compose.scene import Scene, build_linux_scene
from artifactforge.content import ContentStore
from artifactforge.model import linux_profile


def _linux_scene_identity(index: int) -> tuple[str, bytes]:
    key = suite.generator_assurance_key()
    message = suite.GENERATOR_ASSURANCE_SCENE_DOMAIN + b"\x1f" + str(index).encode("ascii")
    digest = hmac.new(key, message, hashlib.sha256).digest()
    public_fragment = base64.b32encode(digest[:10]).decode("ascii").rstrip("=").lower()
    return f"afl1_{public_fragment}", digest


def generate_linux_assurance(windows_macos_scenarios: int, root: str) -> list[Scene]:
    """Generate the Linux share corresponding to a Windows/macOS assurance count."""
    count = suite.linux_assurance_count(windows_macos_scenarios)
    scenarios_root = os.path.join(root, "scenarios")
    staging_root = os.path.join(root, "_staging")
    os.makedirs(scenarios_root, exist_ok=True)
    store = ContentStore(
        suite.GENERATOR_ASSURANCE_LINUX_CONTENT_NAMESPACE,
        os.path.join(root, "_content"),
    )
    scenes = []
    try:
        for index in range(count):
            scene_id, scene_key = _linux_scene_identity(index)
            user = suite.pick(scene_key, "linux-user", pools.USERS)
            host_number = int.from_bytes(scene_key[:2], "big") % 900 + 100
            scene = build_linux_scene(
                store,
                skey=scene_key,
                profile=linux_profile(hostname=f"linux-{host_number:03d}", username=user),
                scene_dir=os.path.join(scenarios_root, scene_id),
                staging_dir=os.path.join(staging_root, scene_id),
            )
            scenes.append(scene)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
    return scenes


__all__ = ["generate_linux_assurance"]
