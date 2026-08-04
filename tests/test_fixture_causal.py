# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fixture ABI v2 derives each family from one exact public causal anchor."""
from __future__ import annotations

import ast
from dataclasses import fields, replace
from pathlib import Path

import pytest

from artifactforge.fixture.causal import (
    CAUSAL_PROFILE,
    CausalClockError,
    CausalClockSpec,
    CausalInstant,
    CausalInterval,
    LinuxTimeline,
    MAC_TO_UNIX_SECONDS,
    MacOSTimeline,
    NANOSECONDS_PER_SECOND,
    PINNED_CAUSAL_ANCHOR_UNIX_NS,
    WINDOWS_TO_UNIX_SECONDS,
    WindowsTimeline,
)


def _instants(timeline) -> tuple[CausalInstant, ...]:
    return tuple(getattr(timeline, item.name) for item in fields(timeline))


@pytest.mark.parametrize("family", ("windows", "macos", "linux"))
def test_every_family_timeline_has_strict_order_visible_as_whole_seconds(family):
    timeline = getattr(CausalClockSpec(), family)()
    events = _instants(timeline)
    pairs = tuple(zip(events[:-1], events[1:], strict=True))
    assert all(left.unix_ns < right.unix_ns for left, right in pairs)
    assert all(left.unix_seconds < right.unix_seconds for left, right in pairs)


def test_family_event_names_encode_the_declared_causal_stories():
    clock = CausalClockSpec()
    assert tuple(item.name for item in fields(clock.windows())) == (
        "host_initialized", "file_created", "run_configured", "executed",
        "prefetch_updated", "amcache_observed",
    )
    assert tuple(item.name for item in fields(clock.macos())) == (
        "host_initialized", "downloaded", "installed", "tcc_decided",
        "launch_agent_written", "knowledge_started", "knowledge_ended",
    )
    assert tuple(item.name for item in fields(clock.linux())) == (
        "host_initialized", "installed", "autostart_written", "history_marker",
        "history_subject", "history_decoy_one", "history_decoy_two",
    )


def test_epoch_conversions_are_exact_integer_equations():
    instant = CausalInstant(PINNED_CAUSAL_ANCHOR_UNIX_NS)
    assert instant.unix_seconds == 1_705_294_800
    assert instant.mac_seconds == instant.unix_seconds - MAC_TO_UNIX_SECONDS
    assert type(instant.mac_seconds_real) is float
    assert int(instant.mac_seconds_real) == instant.mac_seconds
    assert instant.filetime == (
        instant.unix_seconds + WINDOWS_TO_UNIX_SECONDS
    ) * 10_000_000
    assert instant.filetime == 133_497_684_000_000_000
    assert CausalInstant.from_filetime(instant.filetime) == instant
    assert instant.quarantine_hex_seconds == "65a4bbd0"
    assert instant.weekday_sunday_one == 2  # Monday, 2024-01-15 UTC.
    assert instant.mac_seconds_real.as_integer_ratio() == (instant.mac_seconds, 1)


def test_public_clock_mapping_contains_only_profile_and_anchor():
    clock = CausalClockSpec()
    assert clock.to_mapping() == {
        "profile": CAUSAL_PROFILE,
        "anchor_unix_ns": PINNED_CAUSAL_ANCHOR_UNIX_NS,
    }


def test_seed_derived_anchor_is_domain_bound_varied_bounded_and_second_aligned():
    seeds = ("00" * 32, "01" * 32, "ff" * 32)
    clocks = tuple(CausalClockSpec.from_seed_hex(seed) for seed in seeds)
    assert len({clock.anchor_unix_ns for clock in clocks}) == len(clocks)
    assert clocks == tuple(CausalClockSpec.from_seed_hex(seed) for seed in seeds)
    assert all(clock.anchor_unix_ns % NANOSECONDS_PER_SECOND == 0 for clock in clocks)
    assert all(
        1_672_531_200 <= clock.anchor_unix_ns // NANOSECONDS_PER_SECOND
        < 1_672_531_200 + 3 * 365 * 86_400
        for clock in clocks
    )
    with pytest.raises(CausalClockError, match="seed"):
        CausalClockSpec.from_seed_hex("FF" * 32)


@pytest.mark.parametrize(
    "instant,property_name,match",
    (
        (CausalInstant(PINNED_CAUSAL_ANCHOR_UNIX_NS + 1), "unix_seconds", "Unix seconds"),
        (CausalInstant(PINNED_CAUSAL_ANCHOR_UNIX_NS + 1), "mac_seconds", "Mac-absolute"),
        (CausalInstant(PINNED_CAUSAL_ANCHOR_UNIX_NS + 1), "filetime", "FILETIME"),
        (
            CausalInstant((0x1_0000_0000) * NANOSECONDS_PER_SECOND),
            "quarantine_hex_seconds",
            "uint32",
        ),
    ),
)
def test_converters_reject_precision_loss_and_field_overflow(instant, property_name, match):
    with pytest.raises(CausalClockError, match=match):
        getattr(instant, property_name)


@pytest.mark.parametrize("value", (-1, True, 1.0, 1 << 64))
def test_filetime_inverse_rejects_values_outside_uint64(value):
    with pytest.raises(CausalClockError, match="FILETIME"):
        CausalInstant.from_filetime(value)


@pytest.mark.parametrize("value", (True, 1.0, -(1 << 63) - 1, 1 << 63))
def test_instant_rejects_ambiguous_types_and_out_of_range_nanoseconds(value):
    with pytest.raises(CausalClockError):
        CausalInstant(value)


def test_clock_rejects_unaligned_anchor_and_unknown_profile():
    with pytest.raises(CausalClockError, match="Unix seconds"):
        CausalClockSpec(anchor_unix_ns=PINNED_CAUSAL_ANCHOR_UNIX_NS + 1)
    with pytest.raises(CausalClockError, match="profile"):
        CausalClockSpec(profile="future")


@pytest.mark.parametrize(
    "timeline_type,field_values,label",
    (
        (WindowsTimeline, (0, 60, 120, 120, 240, 300), "Windows"),
        (MacOSTimeline, (0, 60, 120, 180, 240, 1_800, 300), "macOS"),
        (LinuxTimeline, (0, 60, 120, 180, 240, 300, 300), "Linux"),
    ),
)
def test_every_adjacent_family_order_can_turn_red(timeline_type, field_values, label):
    anchor = PINNED_CAUSAL_ANCHOR_UNIX_NS
    instants = tuple(
        CausalInstant(anchor + offset * NANOSECONDS_PER_SECOND)
        for offset in field_values
    )
    with pytest.raises(CausalClockError, match=label):
        timeline_type(*instants)


def test_timeline_rejects_noninstant_even_when_comparison_might_work():
    timeline = CausalClockSpec().windows()
    with pytest.raises(CausalClockError, match="CausalInstant"):
        replace(timeline, prefetch_updated=timeline.prefetch_updated.unix_ns)  # type: ignore[arg-type]


def test_all_eight_knowledge_intervals_fit_exactly_inside_the_named_envelope():
    timeline = CausalClockSpec().macos()
    intervals = tuple(timeline.knowledge_interval(index, count=8) for index in range(8))
    assert intervals[0].start == timeline.knowledge_started
    assert intervals[-1].end < timeline.knowledge_ended
    assert all(interval.end.unix_seconds - interval.start.unix_seconds == 120
               for interval in intervals)
    assert all(left.start < right.start
               for left, right in zip(intervals[:-1], intervals[1:], strict=True))
    assert all(left.end < right.start
               for left, right in zip(intervals[:-1], intervals[1:], strict=True))
    with pytest.raises(CausalClockError, match="count"):
        timeline.knowledge_interval(0, count=9)
    with pytest.raises(CausalClockError, match="index"):
        timeline.knowledge_interval(8, count=8)


def test_causal_interval_rejects_equal_reversed_and_wrong_typed_endpoints():
    instant = CausalInstant(PINNED_CAUSAL_ANCHOR_UNIX_NS)
    with pytest.raises(CausalClockError, match="before"):
        CausalInterval(instant, instant)
    with pytest.raises(CausalClockError, match="CausalInstant"):
        CausalInterval(instant, instant.unix_ns)  # type: ignore[arg-type]


def test_clock_module_has_no_wall_clock_datetime_locale_or_random_dependency():
    import artifactforge.fixture.causal as module

    tree = ast.parse(Path(module.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not imported & {"datetime", "locale", "os", "random", "secrets", "time"}
