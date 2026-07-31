# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""HostProfile — OS family, version, and settings as DATA, not code.

The generators read a profile instead of hard-coding host details, so OS versions and
settings become small data records rather than new code paths. This keeps breadth at the
loose-file tier (families parameterized by version) and out of the per-OS block-level trap.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# Mac absolute time epoch (2001-01-01) vs Unix epoch.
_MAC_EPOCH_OFFSET = 978307200
# A pinned canonical scenario time (2024-01-15T05:00:00Z) — deterministic, never wall clock.
PINNED_UNIX = 1705294800


@dataclass(frozen=True)
class HostProfile:
    os_family: str            # "windows" | "macos" | "linux"
    version: str              # e.g. "10.0.19045", "14.4.1", "22.04"
    hostname: str
    username: str
    timezone: str = "UTC"
    # format-version knobs (loose-file tier); defaults suit the family
    prefetch_version: int = 17
    extra: dict = field(default_factory=dict)

    @property
    def home_dir(self) -> str:
        if self.os_family == "windows":
            return f"C:\\Users\\{self.username}"
        if self.os_family == "macos":
            return f"/Users/{self.username}"
        return f"/home/{self.username}"

    def seed_tag(self) -> str:
        return f"{self.os_family}:{self.version}:{self.hostname}:{self.username}"

    def mac_abs_time(self, unix_ts: int = PINNED_UNIX) -> int:
        return unix_ts - _MAC_EPOCH_OFFSET


def deterministic_uuid(seed: str) -> str:
    """A seed-derived RFC-4122 v4 UUID (uppercase, as macOS quarantine records store it)."""
    b = bytearray(hashlib.sha256(seed.encode()).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}".upper()


def windows_profile(hostname="WKSTN-01", username="v", version="10.0.19045") -> HostProfile:
    return HostProfile("windows", version, hostname, username, prefetch_version=17)


def macos_profile(hostname="mac-01", username="v", version="14.4.1") -> HostProfile:
    return HostProfile("macos", version, hostname, username)
