# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Closed-profile tests for the standalone Windows Shell Link writer and reader."""
from __future__ import annotations

import hashlib
import struct

import pytest

from artifactforge.artifacts.shell_link import (
    DEFAULT_FILETIME,
    DEFAULT_VOLUME_LABEL,
    DEFAULT_VOLUME_SERIAL,
    LINK_INFO_HEADER_SIZE,
    MAX_PORTABLE_FILETIME,
    MAX_SHELL_LINK_BYTES,
    MIN_PORTABLE_FILETIME,
    SHELL_LINK_CLSID,
    SHELL_LINK_FLAGS,
    SHELL_LINK_HEADER_SIZE,
    ShellLinkTimestamps,
    build_shell_link,
    parse_shell_link,
)
from artifactforge.disclosure import MARKER


TARGET = r"C:\Users\Analyst\AppData\Local\ArtifactForge\updater.exe"
DISPLAY_NAME = "Updater persistence"
TARGET_SIZE = 0x1234
TIMESTAMPS = ShellLinkTimestamps(
    creation_filetime=133497684000000000,
    access_filetime=133497690000000000,
    write_filetime=133497687000000000,
)


def _sample() -> bytes:
    return build_shell_link(
        TARGET,
        DISPLAY_NAME,
        TARGET_SIZE,
        timestamps=TIMESTAMPS,
        volume_serial=0x1234ABCD,
        volume_label="TRAINING",
    )


def _u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _set_u32(data: bytearray, offset: int, value: int) -> bytes:
    struct.pack_into("<I", data, offset, value)
    return bytes(data)


def test_golden_bytes_and_typed_observation():
    data = _sample()
    assert len(data) == 407
    assert hashlib.sha256(data).hexdigest() == (
        "6679d5d6ef06487e05eb7714dbc1b62dbab2b145a84766e63d52f09b287e816b"
    )

    observed = parse_shell_link(data)
    assert observed.target_path == TARGET
    assert observed.display_name == DISPLAY_NAME
    assert observed.name_string == f"{DISPLAY_NAME} [{MARKER} SYNTHETIC]"
    assert observed.target_size == TARGET_SIZE
    assert observed.creation_filetime == TIMESTAMPS.creation_filetime
    assert observed.access_filetime == TIMESTAMPS.access_filetime
    assert observed.write_filetime == TIMESTAMPS.write_filetime
    assert observed.volume_serial == 0x1234ABCD
    assert observed.volume_label == "TRAINING"


def test_header_linkinfo_and_string_extents_are_spec_native_and_contiguous():
    data = _sample()
    header = struct.unpack_from("<I16sIIQQQIiIHHII", data)
    assert struct.calcsize("<I16sIIQQQIiIHHII") == SHELL_LINK_HEADER_SIZE == 76
    assert header[0] == SHELL_LINK_HEADER_SIZE
    assert header[1] == SHELL_LINK_CLSID
    assert header[2] == SHELL_LINK_FLAGS == 0x86
    assert header[3] == 0x20
    assert header[7:] == (TARGET_SIZE, 0, 1, 0, 0, 0, 0)

    link = struct.unpack_from("<9I", data, SHELL_LINK_HEADER_SIZE)
    (
        link_size,
        header_size,
        flags,
        volume_offset,
        local_offset,
        network_offset,
        suffix_offset,
        unicode_offset,
        suffix_unicode_offset,
    ) = link
    assert header_size == LINK_INFO_HEADER_SIZE == 0x24
    assert flags == 1
    assert volume_offset == LINK_INFO_HEADER_SIZE
    assert network_offset == 0
    assert [volume_offset, local_offset, suffix_offset, unicode_offset, suffix_unicode_offset] == (
        sorted([volume_offset, local_offset, suffix_offset, unicode_offset, suffix_unicode_offset])
    )

    link_start = SHELL_LINK_HEADER_SIZE
    volume_size, drive_type, serial, label_offset = struct.unpack_from(
        "<4I", data, link_start + volume_offset
    )
    assert (drive_type, serial, label_offset) == (3, 0x1234ABCD, 16)
    assert volume_offset + volume_size == local_offset
    assert data[link_start + label_offset + volume_offset : link_start + local_offset] == (
        b"TRAINING\x00"
    )
    assert data[link_start + local_offset : link_start + suffix_offset] == (
        TARGET.encode("ascii") + b"\x00"
    )
    assert data[link_start + suffix_offset : link_start + unicode_offset] == b"\x00"
    assert data[link_start + unicode_offset : link_start + suffix_unicode_offset] == (
        TARGET.encode("utf-16-le") + b"\x00\x00"
    )
    assert data[link_start + suffix_unicode_offset : link_start + link_size] == b"\x00\x00"

    count = struct.unpack_from("<H", data, link_start + link_size)[0]
    name_start = link_start + link_size + 2
    name_end = name_start + count * 2
    assert data[name_start:name_end].decode("utf-16-le") == (
        f"{DISPLAY_NAME} [{MARKER} SYNTHETIC]"
    )
    assert data[name_end:] == b"\x00\x00\x00\x00"


def test_defaults_and_determinism():
    first = build_shell_link(TARGET, DISPLAY_NAME, 0)
    second = build_shell_link(TARGET, DISPLAY_NAME, 0)
    assert first == second
    observed = parse_shell_link(first)
    assert observed.volume_serial == DEFAULT_VOLUME_SERIAL
    assert observed.volume_label == DEFAULT_VOLUME_LABEL
    assert observed.creation_filetime == DEFAULT_FILETIME
    assert observed.access_filetime == DEFAULT_FILETIME
    assert observed.write_filetime == DEFAULT_FILETIME


@pytest.mark.parametrize(
    ("path", "message"),
    [
        (None, "must be text"),
        (r"c:\x.exe", "uppercase-drive"),
        (r"C:/x.exe", "uppercase-drive"),
        (r"C:\\x.exe", "non-empty components"),
        ("C:\\x.exe\\", "name a file"),
        (r"C:\a\..\x.exe", "non-canonical Windows component"),
        (r"C:\a\CON", "non-canonical Windows component"),
        (r"C:\a\x?.exe", "non-canonical Windows component"),
        ("C:\\a\\x.exe ", "non-canonical Windows component"),
        ("C:\\Cafe\N{COMBINING ACUTE ACCENT}\\x.exe", "Unicode NFC"),
        ("C:\\Caf\N{LATIN SMALL LETTER E WITH ACUTE}\\x.exe", "portable ASCII"),
        ("C:\\" + "a" * 256, "non-canonical Windows component"),
        ("C:\\" + "a" * 256 + "\\x", "259 characters"),
    ],
)
def test_target_path_input_contract(path, message):
    with pytest.raises(ValueError, match=message):
        build_shell_link(path, DISPLAY_NAME, 1)


@pytest.mark.parametrize(
    ("name", "message"),
    [
        (None, "must be text"),
        ("", "1.."),
        (" leading", "must be trimmed"),
        ("trailing ", "must be trimmed"),
        ("a\\b", "path separator"),
        (MARKER, "unmarked"),
        ("line\nfeed", "control character"),
        ("Cafe\N{COMBINING ACUTE ACCENT}", "Unicode NFC"),
        ("Caf\N{LATIN SMALL LETTER E WITH ACUTE}", "portable ASCII"),
        ("a" * 235, "1..234 characters"),
    ],
)
def test_display_name_input_contract(name, message):
    with pytest.raises(ValueError, match=message):
        build_shell_link(TARGET, name, 1)


@pytest.mark.parametrize(
    ("label", "message"),
    [
        (None, "must be text"),
        ("", "1..32"),
        (" TRAINING", "fixed-volume label"),
        ("TRAINING.", "fixed-volume label"),
        ("BAD/LABEL", "fixed-volume label"),
        ("Caf\N{LATIN SMALL LETTER E WITH ACUTE}", "portable ASCII"),
        ("A" * 33, "1..32"),
    ],
)
def test_volume_label_input_contract(label, message):
    with pytest.raises(ValueError, match=message):
        build_shell_link(TARGET, DISPLAY_NAME, 1, volume_label=label)


@pytest.mark.parametrize("value", [True, -1, 1 << 32, "1"])
def test_target_size_is_exact_unsigned_u32(value):
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        build_shell_link(TARGET, DISPLAY_NAME, value)


@pytest.mark.parametrize("value", [False, -1, 1 << 32, None])
def test_volume_serial_is_exact_unsigned_u32(value):
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        build_shell_link(TARGET, DISPLAY_NAME, 1, volume_serial=value)


@pytest.mark.parametrize("field", ["creation_filetime", "access_filetime", "write_filetime"])
@pytest.mark.parametrize("value", [True, -1, 1 << 64, "0"])
def test_target_filetimes_are_exact_unsigned_u64(field, value):
    values = {
        "creation_filetime": DEFAULT_FILETIME,
        "access_filetime": DEFAULT_FILETIME,
        "write_filetime": DEFAULT_FILETIME,
    }
    values[field] = value
    with pytest.raises(ValueError, match="unsigned 64-bit FILETIME"):
        ShellLinkTimestamps(**values)


@pytest.mark.parametrize("field", ["creation_filetime", "access_filetime", "write_filetime"])
def test_target_filetimes_fit_the_mandatory_external_oracles_exactly(field):
    values = {
        "creation_filetime": DEFAULT_FILETIME,
        "access_filetime": DEFAULT_FILETIME,
        "write_filetime": DEFAULT_FILETIME,
    }
    values[field] += 1
    with pytest.raises(ValueError, match="whole-microsecond FILETIME"):
        ShellLinkTimestamps(**values)


@pytest.mark.parametrize("field", ["creation_filetime", "access_filetime", "write_filetime"])
@pytest.mark.parametrize(
    "value",
    [10, MIN_PORTABLE_FILETIME - 10, MAX_PORTABLE_FILETIME + 10, (1 << 64) - 6],
)
def test_target_filetimes_stay_inside_the_portable_external_oracle_interval(field, value):
    values = {
        "creation_filetime": DEFAULT_FILETIME,
        "access_filetime": DEFAULT_FILETIME,
        "write_filetime": DEFAULT_FILETIME,
    }
    values[field] = value
    with pytest.raises(ValueError, match="portable 1970..2242 LnkParse3 FILETIME interval"):
        ShellLinkTimestamps(**values)


@pytest.mark.parametrize("value", [True, object(), (DEFAULT_FILETIME,) * 3])
def test_timestamp_container_type_is_exact(value):
    with pytest.raises(ValueError, match="ShellLinkTimestamps or None"):
        build_shell_link(TARGET, DISPLAY_NAME, 1, timestamps=value)


@pytest.mark.parametrize(
    ("offset", "value", "message"),
    [
        (0, 0x4D, "header size or CLSID"),
        (20, 0x82, "flags"),
        (24, 0x80, "attributes"),
        (56, 1, "control and reserved"),
        (60, 3, "control and reserved"),
        (68, 1, "control and reserved"),
        (80, 0x1C, "LinkInfo header"),
        (84, 3, "LinkInfo header"),
        (88, 0x28, "VolumeID"),
        (96, 1, "LinkInfo header"),
        (116, 4, "fixed-drive"),
        (124, 20, "fixed-drive"),
    ],
)
def test_high_value_u32_mutations_are_rejected(offset, value, message):
    with pytest.raises(ValueError, match=message):
        parse_shell_link(_set_u32(bytearray(_sample()), offset, value))


def test_clsid_mutation_is_rejected():
    data = bytearray(_sample())
    data[4] ^= 1
    with pytest.raises(ValueError, match="CLSID"):
        parse_shell_link(bytes(data))


def test_linkinfo_size_and_field_reordering_mutations_are_rejected():
    data = bytearray(_sample())
    with pytest.raises(ValueError, match="common suffix|terminal|NAME_STRING|truncated"):
        parse_shell_link(_set_u32(data, 76, _u32(data, 76) - 1))

    data = bytearray(_sample())
    with pytest.raises(ValueError, match="strictly ordered"):
        parse_shell_link(_set_u32(data, 100, _u32(data, 92)))

    data = bytearray(_sample())
    with pytest.raises(ValueError, match="strictly ordered|out of bounds"):
        parse_shell_link(_set_u32(data, 108, len(data)))


def test_ansi_unicode_path_disagreement_is_rejected():
    data = bytearray(_sample())
    link_start = SHELL_LINK_HEADER_SIZE
    unicode_offset = _u32(data, link_start + 28)
    data[link_start + unicode_offset] = ord("D")
    with pytest.raises(ValueError, match="paths disagree"):
        parse_shell_link(bytes(data))


def test_nonempty_common_suffix_is_rejected():
    data = bytearray(_sample())
    link_start = SHELL_LINK_HEADER_SIZE
    suffix_offset = _u32(data, link_start + 24)
    data[link_start + suffix_offset] = ord("X")
    with pytest.raises(ValueError, match="common suffix"):
        parse_shell_link(bytes(data))


def test_marker_and_terminal_mutations_are_rejected():
    data = bytearray(_sample())
    marker = MARKER.encode("utf-16-le")
    marker_offset = data.index(marker)
    data[marker_offset] ^= 1
    with pytest.raises(ValueError, match="synthetic marker"):
        parse_shell_link(bytes(data))

    data = bytearray(_sample())
    data[-1] = 1
    with pytest.raises(ValueError, match="TerminalBlock"):
        parse_shell_link(bytes(data))

    with pytest.raises(ValueError, match="TerminalBlock"):
        parse_shell_link(_sample() + b"\x00")


@pytest.mark.parametrize("data", [bytearray(b"x"), memoryview(b"x"), None])
def test_reader_requires_immutable_bytes(data):
    with pytest.raises(ValueError, match="immutable bytes"):
        parse_shell_link(data)


def test_reader_bounds_every_truncation_and_maximum():
    data = _sample()
    for end in range(len(data)):
        with pytest.raises(ValueError):
            parse_shell_link(data[:end])
    with pytest.raises(ValueError, match=str(MAX_SHELL_LINK_BYTES)):
        parse_shell_link(b"x" * (MAX_SHELL_LINK_BYTES + 1))
