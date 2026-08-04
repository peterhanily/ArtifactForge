# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Independent external-parser consensus for ArtifactForge's Shell Link profile."""
from __future__ import annotations

from dataclasses import replace
import importlib.metadata
import struct

import pytest

pytest.importorskip("pylnk")
pytest.importorskip("LnkParse3")

from artifactforge.artifacts.shell_link import (  # noqa: E402
    MAX_PORTABLE_FILETIME,
    MIN_PORTABLE_FILETIME,
    ShellLinkTimestamps,
    build_shell_link,
    parse_shell_link,
)
from artifactforge.disclosure import MARKER  # noqa: E402
from artifactforge.gates.oracles.shell_link_profile import (  # noqa: E402
    MAX_SHELL_LINK_ORACLE_BYTES,
    ShellLinkOracleError,
    ShellLinkOracleView,
    liblnk_shell_link_view,
    lnkparse3_shell_link_view,
    require_shell_link_consensus,
    validate_artifactforge_shell_link_profile,
)


TARGET = r"C:\Users\Analyst\AppData\Local\ArtifactForge\updater.exe"
DISPLAY_NAME = "Updater persistence"
DESCRIPTION = f"{DISPLAY_NAME} [{MARKER} SYNTHETIC]"
TIMESTAMPS = ShellLinkTimestamps(
    creation_filetime=133_497_684_000_000_000,
    access_filetime=133_497_690_000_000_000,
    write_filetime=133_497_687_000_000_000,
)


def _sample(*, timestamps: ShellLinkTimestamps = TIMESTAMPS) -> bytes:
    return build_shell_link(
        TARGET,
        DISPLAY_NAME,
        0x1234,
        timestamps=timestamps,
        volume_serial=0x1234ABCD,
        volume_label="TRAINING",
    )


def _views(data: bytes | None = None) -> tuple[ShellLinkOracleView, ShellLinkOracleView]:
    payload = _sample() if data is None else data
    return liblnk_shell_link_view(payload), lnkparse3_shell_link_view(payload)


def test_exact_external_distribution_contracts_are_installed():
    assert importlib.metadata.version("liblnk-python") == "20260525"
    assert importlib.metadata.version("LnkParse3") == "1.6.0"
    assert importlib.metadata.metadata("liblnk-python")["License-Expression"] == (
        "LGPL-3.0-or-later"
    )
    assert importlib.metadata.metadata("LnkParse3")["License"] == "MIT"


def test_liblnk_and_lnkparse3_agree_on_every_shared_typed_dimension():
    liblnk, lnkparse3 = _views()
    assert liblnk == lnkparse3 == ShellLinkOracleView(
        target_path=TARGET,
        description=DESCRIPTION,
        target_size=0x1234,
        creation_filetime=TIMESTAMPS.creation_filetime,
        access_filetime=TIMESTAMPS.access_filetime,
        write_filetime=TIMESTAMPS.write_filetime,
        volume_serial=0x1234ABCD,
        volume_label="TRAINING",
        drive_type=3,
        link_flags=0x86,
        file_attribute_flags=0x20,
        icon_index=0,
        show_window_value=1,
        hot_key_value=0,
        optional_surfaces=(),
        data_block_count=0,
    )
    consensus = require_shell_link_consensus(
        {"liblnk": liblnk, "LnkParse3": lnkparse3}
    )
    assert validate_artifactforge_shell_link_profile(consensus) == (
        f"profile=local-file-v1,target={TARGET},size=4660,"
        "volume=TRAINING/1234abcd,flags=0x86,blocks=0,description=marked"
    )


def test_external_consensus_matches_the_independent_strict_reader():
    strict = parse_shell_link(_sample())
    consensus = require_shell_link_consensus(
        dict(zip(("liblnk", "LnkParse3"), _views(), strict=True))
    )
    assert consensus.target_path == strict.target_path
    assert consensus.description == strict.name_string
    assert consensus.target_size == strict.target_size
    assert (
        consensus.creation_filetime,
        consensus.access_filetime,
        consensus.write_filetime,
    ) == (
        strict.creation_filetime,
        strict.access_filetime,
        strict.write_filetime,
    )
    assert consensus.volume_serial == strict.volume_serial
    assert consensus.volume_label == strict.volume_label


def test_zero_filetimes_and_zero_uint32_values_remain_exact_not_missing():
    data = build_shell_link(
        r"C:\x.exe",
        "X",
        0,
        timestamps=ShellLinkTimestamps(0, 0, 0),
        volume_serial=0,
    )
    view = require_shell_link_consensus(
        {
            "liblnk": liblnk_shell_link_view(data),
            "LnkParse3": lnkparse3_shell_link_view(data),
        }
    )
    assert view.target_size == view.volume_serial == 0
    assert (view.creation_filetime, view.access_filetime, view.write_filetime) == (0, 0, 0)


@pytest.mark.parametrize("value", [MIN_PORTABLE_FILETIME, MAX_PORTABLE_FILETIME])
def test_portable_filetime_boundaries_round_trip_both_mandatory_oracles(value):
    data = _sample(timestamps=ShellLinkTimestamps(value, value, value))
    liblnk = liblnk_shell_link_view(data)
    lnkparse3 = lnkparse3_shell_link_view(data)

    assert (liblnk.creation_filetime, liblnk.access_filetime, liblnk.write_filetime) == (
        value,
        value,
        value,
    )
    assert lnkparse3 == liblnk


@pytest.mark.parametrize(
    ("field", "changed"),
    (
        ("target_path", r"D:\other.exe"),
        ("description", f"Other [{MARKER} SYNTHETIC]"),
        ("target_size", 0x1235),
        ("creation_filetime", TIMESTAMPS.creation_filetime + 10),
        ("access_filetime", TIMESTAMPS.access_filetime + 10),
        ("write_filetime", TIMESTAMPS.write_filetime + 10),
        ("volume_serial", 0x1234ABCE),
        ("volume_label", "OTHER"),
        ("drive_type", 2),
        ("link_flags", 0x82),
        ("file_attribute_flags", 0x21),
        ("icon_index", 1),
        ("show_window_value", 3),
        ("hot_key_value", 1),
        ("optional_surfaces", ("arguments",)),
        ("data_block_count", 1),
    ),
)
def test_consensus_compares_every_declared_field(field, changed):
    liblnk, lnkparse3 = _views()
    altered = replace(lnkparse3, **{field: changed})
    with pytest.raises(ShellLinkOracleError, match="disagree"):
        require_shell_link_consensus({"liblnk": liblnk, "LnkParse3": altered})


@pytest.mark.parametrize(
    "reads",
    (
        {},
        {"liblnk": object(), "LnkParse3": object()},
        {"liblnk": _views()[0]},
        {"LnkParse3": _views()[1]},
    ),
)
def test_consensus_requires_both_exact_typed_observations(reads):
    with pytest.raises(ShellLinkOracleError, match="both required"):
        require_shell_link_consensus(reads)


def test_lnkparse3_exact_consumption_rejects_payload_liblnk_does_not_expose():
    canonical = _sample()
    appended = canonical + b"PAYLOAD"

    # liblnk 20260525 parses the semantic link and exposes no consumed-size property.
    assert liblnk_shell_link_view(appended) == liblnk_shell_link_view(canonical)
    # LnkParse3 exposes the appended terminal payload; treating parse success as a gate would
    # miss it, so the adapter rejects that observation.
    with pytest.raises(ShellLinkOracleError, match="ExtraData|appended"):
        lnkparse3_shell_link_view(appended)


def test_external_consensus_detects_lnkparse3_filetime_precision_loss():
    data = bytearray(_sample())
    # Bypass the writer contract: LnkParse3 converts through microsecond-resolution datetime,
    # while liblnk exposes the exact 100 ns integer. Mandatory consensus must fail closed.
    struct.pack_into("<Q", data, 28, TIMESTAMPS.creation_filetime + 1)
    liblnk = liblnk_shell_link_view(bytes(data))
    lnkparse3 = lnkparse3_shell_link_view(bytes(data))
    assert liblnk.creation_filetime == TIMESTAMPS.creation_filetime + 1
    assert lnkparse3.creation_filetime != liblnk.creation_filetime
    with pytest.raises(ShellLinkOracleError, match="disagree"):
        require_shell_link_consensus({"liblnk": liblnk, "LnkParse3": lnkparse3})


def test_lnkparse3_warning_is_failure_not_success():
    data = bytearray(_sample())
    data[4] ^= 1  # LinkCLSID: LnkParse3 warns rather than throwing.
    with pytest.raises(ShellLinkOracleError, match="header size or CLSID|warned"):
        lnkparse3_shell_link_view(bytes(data))


def test_lnkparse3_requires_ansi_and_unicode_paths_to_agree():
    data = bytearray(_sample())
    link_start = 0x4C
    unicode_offset = struct.unpack_from("<I", data, link_start + 28)[0]
    data[link_start + unicode_offset] = ord("D")
    with pytest.raises(ShellLinkOracleError, match="local-path observations disagree"):
        lnkparse3_shell_link_view(bytes(data))


def test_pinned_lnkparse3_unicode_suffix_bug_is_excluded_from_consensus():
    from LnkParse3.lnk_file import LnkFile

    parsed = LnkFile(indata=_sample())
    assert parsed.info.common_path_suffix() == ""
    # LnkParse3 1.6.0 incorrectly adds four to CommonPathSuffixOffsetUnicode and reads the
    # following NameString. The adapter intentionally excludes this accessor; the independent
    # strict reader proves the exact empty UTF-16 suffix from bounded bytes instead.
    assert parsed.info.common_path_suffix_unicode() == DESCRIPTION
    assert lnkparse3_shell_link_view(_sample()).target_path == TARGET


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"description": "unmarked"}, "synthetic marker"),
        ({"target_path": r"c:\x.exe"}, "local-path"),
        ({"volume_label": "BAD/LABEL"}, "volume label"),
        ({"link_flags": 0x82}, "flags"),
        ({"file_attribute_flags": 0}, "attributes"),
        ({"drive_type": 2}, "fixed drive"),
        ({"icon_index": 1}, "launch-display"),
        ({"show_window_value": 3}, "launch-display"),
        ({"hot_key_value": 1}, "launch-display"),
        ({"optional_surfaces": ("arguments",)}, "optional execution"),
        ({"data_block_count": 1}, "ExtraData"),
    ),
)
def test_profile_validation_is_stricter_than_parser_consensus(changes, message):
    consensus = require_shell_link_consensus(
        dict(zip(("liblnk", "LnkParse3"), _views(), strict=True))
    )
    with pytest.raises(ShellLinkOracleError, match=message):
        validate_artifactforge_shell_link_profile(replace(consensus, **changes))


@pytest.mark.parametrize("adapter", (liblnk_shell_link_view, lnkparse3_shell_link_view))
@pytest.mark.parametrize("value", (None, bytearray(b"x"), memoryview(b"x")))
def test_adapters_require_bounded_immutable_bytes(adapter, value):
    with pytest.raises(ShellLinkOracleError, match="immutable bytes"):
        adapter(value)


@pytest.mark.parametrize("adapter", (liblnk_shell_link_view, lnkparse3_shell_link_view))
@pytest.mark.parametrize("value", (b"x" * 76, b"x" * (MAX_SHELL_LINK_ORACLE_BYTES + 1)))
def test_adapters_enforce_the_independent_size_bound_before_parsing(adapter, value):
    with pytest.raises(ShellLinkOracleError, match="77..4096"):
        adapter(value)
