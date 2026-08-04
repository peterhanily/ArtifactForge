# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Integer-only causal clocks for Fixture ABI v2.

The public recipe binds one clock profile and one Unix-nanosecond anchor.  Family-specific
timelines derive named instants from it: Windows creation/persistence/execution/prefetch,
macOS quarantine/install/TCC/LaunchAgent/knowledge, and Linux installation/autostart/history.
Every order is asserted before any bytes are emitted.

Artifact writers expose incompatible time domains.  Registry and prefetch use FILETIME, TCC
and Bash history use Unix seconds, and knowledgeC and QuarantineEventsV2 use seconds since
Apple's 2001 reference date.  Conversions here are integer equations that reject precision
loss.  Floating point appears only after an exact integral Mac-absolute value has been proved.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import re


CAUSAL_PROFILE = "artifactforge-causal-clock-v1"
NANOSECONDS_PER_SECOND = 1_000_000_000
NANOSECONDS_PER_FILETIME_TICK = 100
WINDOWS_TO_UNIX_SECONDS = 11_644_473_600
MAC_TO_UNIX_SECONDS = 978_307_200

# 2024-01-15T05:00:00Z.  This is a public byte-contract input, never a wall-clock read.
PINNED_CAUSAL_ANCHOR_UNIX_NS = 1_705_294_800 * NANOSECONDS_PER_SECOND
_ANCHOR_DOMAIN = b"artifactforge/fixture/causal-anchor/v2\0"
_SEED_HEX = re.compile(r"[0-9a-f]{64}")
# Keep seed-derived examples between 2023-01-01 and 2025-12-31 UTC.  This range is public,
# comfortably representable by every current artifact time field, and intentionally not
# presented as a sampling distribution for real incidents.
_ANCHOR_EPOCH_SECONDS = 1_672_531_200
_ANCHOR_SPAN_SECONDS = 3 * 365 * 86_400


class CausalClockError(ValueError):
    """A clock, event order, or epoch conversion is outside the exact profile."""


@dataclass(frozen=True, order=True)
class CausalInstant:
    """One exact Unix-nanosecond instant with loss-rejecting artifact-domain views."""

    unix_ns: int

    def __post_init__(self) -> None:
        if type(self.unix_ns) is not int:
            raise CausalClockError("causal timestamp must be integer Unix nanoseconds")
        # This broad bound keeps all supported conversions and canonical JSON arithmetic
        # finite without pretending every instant is representable by every artifact field.
        if not -(1 << 63) <= self.unix_ns < 1 << 63:
            raise CausalClockError("causal timestamp is outside signed 64-bit nanoseconds")

    @property
    def unix_seconds(self) -> int:
        if self.unix_ns % NANOSECONDS_PER_SECOND:
            raise CausalClockError("causal timestamp loses precision as Unix seconds")
        value = self.unix_ns // NANOSECONDS_PER_SECOND
        if not -(1 << 63) <= value < 1 << 63:
            raise CausalClockError("causal Unix seconds are outside signed 64-bit range")
        return value

    @property
    def mac_seconds(self) -> int:
        delta_ns = self.unix_ns - MAC_TO_UNIX_SECONDS * NANOSECONDS_PER_SECOND
        if delta_ns % NANOSECONDS_PER_SECOND:
            raise CausalClockError("causal timestamp loses precision as Mac-absolute seconds")
        value = delta_ns // NANOSECONDS_PER_SECOND
        if not 0 <= value < 1 << 53:
            raise CausalClockError("Mac-absolute seconds are outside the exact SQLite REAL range")
        return value

    @property
    def mac_seconds_real(self) -> float:
        """The exact REAL input used by the owned macOS SQLite writer."""
        return float(self.mac_seconds)

    @property
    def filetime(self) -> int:
        adjusted_ns = (
            self.unix_ns + WINDOWS_TO_UNIX_SECONDS * NANOSECONDS_PER_SECOND
        )
        if adjusted_ns % NANOSECONDS_PER_FILETIME_TICK:
            raise CausalClockError("causal timestamp loses precision as Windows FILETIME")
        value = adjusted_ns // NANOSECONDS_PER_FILETIME_TICK
        if not 0 <= value < 1 << 64:
            raise CausalClockError("causal FILETIME is outside the unsigned 64-bit range")
        return value

    @classmethod
    def from_filetime(cls, value: int) -> CausalInstant:
        """Invert an exact uint64 FILETIME without passing through datetime or float."""
        if type(value) is not int or not 0 <= value < 1 << 64:
            raise CausalClockError("FILETIME input must be an unsigned 64-bit integer")
        adjusted_ns = value * NANOSECONDS_PER_FILETIME_TICK
        return cls(
            adjusted_ns - WINDOWS_TO_UNIX_SECONDS * NANOSECONDS_PER_SECOND
        )

    @property
    def quarantine_hex_seconds(self) -> str:
        value = self.unix_seconds
        if not 0 <= value <= 0xFFFFFFFF:
            raise CausalClockError("quarantine xattr seconds are outside uint32")
        return f"{value:08x}"

    @property
    def weekday_sunday_one(self) -> int:
        """Return Sunday=1 ... Saturday=7 without timezone, locale, or float arithmetic."""
        unix_day = self.unix_seconds // 86_400
        return ((unix_day + 4) % 7) + 1  # 1970-01-01 was Thursday.


def _validate_timeline(value: object, label: str) -> None:
    instants = tuple(getattr(value, item.name) for item in fields(value))
    if any(type(instant) is not CausalInstant for instant in instants):
        raise CausalClockError(f"every {label} causal event must be a CausalInstant")
    if not all(
        left < right for left, right in zip(instants[:-1], instants[1:], strict=True)
    ):
        names = " < ".join(item.name for item in fields(value))
        raise CausalClockError(f"{label} causal events must satisfy {names}")


@dataclass(frozen=True)
class WindowsTimeline:
    host_initialized: CausalInstant
    file_created: CausalInstant
    run_configured: CausalInstant
    executed: CausalInstant
    prefetch_updated: CausalInstant
    amcache_observed: CausalInstant

    def __post_init__(self) -> None:
        _validate_timeline(self, "Windows")


@dataclass(frozen=True)
class MacOSTimeline:
    host_initialized: CausalInstant
    downloaded: CausalInstant
    installed: CausalInstant
    tcc_decided: CausalInstant
    launch_agent_written: CausalInstant
    knowledge_started: CausalInstant
    knowledge_ended: CausalInstant

    def __post_init__(self) -> None:
        _validate_timeline(self, "macOS")

    def knowledge_interval(self, index: int, *, count: int) -> CausalInterval:
        """Derive one of 1..8 non-overlapping 120-second app-in-focus intervals."""
        if type(count) is not int or not 1 <= count <= 8:
            raise CausalClockError("knowledge interval count must be 1..8")
        if type(index) is not int or not 0 <= index < count:
            raise CausalClockError("knowledge interval index is outside its row count")
        start = CausalInstant(
            self.knowledge_started.unix_ns + index * 180 * NANOSECONDS_PER_SECOND
        )
        end = CausalInstant(start.unix_ns + 120 * NANOSECONDS_PER_SECOND)
        interval = CausalInterval(start, end)
        if interval.start < self.knowledge_started or interval.end > self.knowledge_ended:
            raise CausalClockError("knowledge interval escapes its declared causal envelope")
        return interval


@dataclass(frozen=True)
class LinuxTimeline:
    host_initialized: CausalInstant
    installed: CausalInstant
    autostart_written: CausalInstant
    history_marker: CausalInstant
    history_subject: CausalInstant
    history_decoy_one: CausalInstant
    history_decoy_two: CausalInstant

    def __post_init__(self) -> None:
        _validate_timeline(self, "Linux")


@dataclass(frozen=True)
class CausalInterval:
    start: CausalInstant
    end: CausalInstant

    def __post_init__(self) -> None:
        if type(self.start) is not CausalInstant or type(self.end) is not CausalInstant:
            raise CausalClockError("causal interval endpoints must be CausalInstant values")
        if not self.start < self.end:
            raise CausalClockError("causal interval start must be before end")


@dataclass(frozen=True)
class CausalClockSpec:
    """The complete answer-free clock input carried by a public Fixture ABI v2 recipe."""

    anchor_unix_ns: int = PINNED_CAUSAL_ANCHOR_UNIX_NS
    profile: str = CAUSAL_PROFILE

    def __post_init__(self) -> None:
        if self.profile != CAUSAL_PROFILE:
            raise CausalClockError(f"causal profile must be {CAUSAL_PROFILE!r}")
        anchor = CausalInstant(self.anchor_unix_ns)
        # All current story fields include whole-second formats.  Refuse an anchor whose
        # distinctions those artifacts could not preserve.
        anchor.unix_seconds

    def _instant(self, seconds_after_anchor: int) -> CausalInstant:
        return CausalInstant(
            self.anchor_unix_ns + seconds_after_anchor * NANOSECONDS_PER_SECOND
        )

    def windows(self) -> WindowsTimeline:
        return WindowsTimeline(
            *(self._instant(value) for value in (0, 60, 120, 180, 240, 300))
        )

    def macos(self) -> MacOSTimeline:
        return MacOSTimeline(
            *(self._instant(value) for value in (0, 60, 120, 180, 240, 300, 1_800))
        )

    def linux(self) -> LinuxTimeline:
        return LinuxTimeline(
            *(self._instant(value) for value in (0, 60, 120, 180, 240, 300, 360))
        )

    @classmethod
    def from_seed_hex(cls, seed_hex: str, *, context: bytes = b"") -> CausalClockSpec:
        """Choose a bounded second-aligned anchor under an explicit Fixture v2 domain.

        ``context`` is an answer-free, canonical recipe projection supplied by Fixture ABI v2.
        Its length prefix makes the seed/context boundary unambiguous.  Keeping the helper in
        this dependency-free module gives construction and parsing one derivation path without
        importing the fixture model back into the clock implementation.
        """
        if type(seed_hex) is not str or _SEED_HEX.fullmatch(seed_hex) is None:
            raise CausalClockError("causal seed must be 64 lowercase hexadecimal digits")
        if type(context) is not bytes:
            raise CausalClockError("causal derivation context must be bytes")
        if len(context) > (1 << 32) - 1:
            raise CausalClockError("causal derivation context is too large")
        digest = hashlib.sha256(
            _ANCHOR_DOMAIN
            + len(context).to_bytes(4, "big")
            + context
            + bytes.fromhex(seed_hex)
        ).digest()
        offset = int.from_bytes(digest[:8], "big") % _ANCHOR_SPAN_SECONDS
        return cls(
            anchor_unix_ns=(
                _ANCHOR_EPOCH_SECONDS + offset
            ) * NANOSECONDS_PER_SECOND
        )

    def to_mapping(self) -> dict[str, object]:
        return {"profile": self.profile, "anchor_unix_ns": self.anchor_unix_ns}


__all__ = [
    "CAUSAL_PROFILE",
    "CausalClockError",
    "CausalClockSpec",
    "CausalInterval",
    "CausalInstant",
    "LinuxTimeline",
    "MAC_TO_UNIX_SECONDS",
    "MacOSTimeline",
    "NANOSECONDS_PER_FILETIME_TICK",
    "NANOSECONDS_PER_SECOND",
    "PINNED_CAUSAL_ANCHOR_UNIX_NS",
    "WINDOWS_TO_UNIX_SECONDS",
    "WindowsTimeline",
]
