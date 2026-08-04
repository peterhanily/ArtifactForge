# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Independent-reader, dual-parser, and hostile-mutation tests for Prefetch v30."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import struct

import pytest

from artifactforge.gates.oracles.prefetch_profile import (
    PrefetchV30OracleView,
    PrefetchV30ProfileError,
    decode_mam_xpress_huffman,
    dissect_prefetch_v30_view,
    parse_mam_prefetch_v30_variant1,
    parse_prefetch_v30_variant1,
    prefetch_vista_path_hash,
    pyscca_prefetch_v30_view,
    require_prefetch_v30_consensus,
    validate_artifactforge_prefetch_v30_profile,
)


FILETIME = 133_497_684_000_000_000
VOLUME_FILETIME = FILETIME - 864_000_000_000
SERIAL = 0x1234ABCD
DEVICE_PATH = r"\DEVICE\HARDDISKVOLUME1"
EXECUTABLE = "NOTEPAD.EXE"
TAIL = r"\WINDOWS\SYSTEM32\NOTEPAD.EXE"

# Frozen from /private/tmp/pf30_probe.py.  Both external consumers recover the modeled
# executable, but Dissect's EOF-driven raw decoder exposes the post-output symbol as three
# additional bytes.  The expected-size decoder below recovers exactly 736 bytes.  This older
# prototype deliberately retains its incoherent ``\VOLUME{01}`` marker and is not a strict
# ArtifactForge profile-success vector.
FIXED_INTEROP_PROBE = bytes.fromhex(
    "4d414d04e0020000628700000000000000080000008800080008000008006008"
    "8687078807080080606086777700788607678877870007007888080800000080"
    "0000000000808000000000000000000000000008000000000000000800800000"
    "8000000000000000000000000000800000000000000800000808000000800000"
    "0000000000000000880080000080000408000000000000008600000000000000"
    "8500080000000000740800008000000886000000800000007688000000000000"
    "8800800000000007860008000800000500000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000002ca20384c7ea0e81a11b9c659a8211f5833c8ae76227164"
    "f56487780e9c67f95dc8e991d2600c9ac7015aef9cd9f5bbf079223a8d2148ea"
    "9d886bdf187ff8e9563f323d8e8378393ab7a95658b0039d788037cee54b4423"
    "37d0b58d250a0a358f6bf90e7a86f585c9cdc2592e5ee7158692ae62a8116c46"
    "7ec858d094959b54fd618861d0044961d4f2aeb062548a81a6a455b48e943dfc"
    "a5126f664062f3a9aa03d45660a163895b0c1952f87fdc5cb19456da9d88a1b8"
    "09354da80e4200b00000"
)


def _u32(*values: int) -> bytes:
    return b"".join(struct.pack("<I", value) for value in values)


def _utf16z(value: str) -> bytes:
    return (value + "\x00").encode("utf-16-le")


def _conforming_inner(*, tail: str = TAIL, executable: str = EXECUTABLE) -> bytes:
    """Assemble the final one-volume semantics independently of the production writer."""
    volume_token = f"\\VOLUME{{{VOLUME_FILETIME:016x}-{SERIAL:08x}}}"
    recorded_path = volume_token + tail
    marker_path = volume_token + r"\ARTIFACTFORGE-SYNTHETIC-NOT-EVIDENCE"
    strings = _utf16z(recorded_path) + _utf16z(marker_path)
    device = _utf16z(volume_token)
    volumes_offset = 344 + len(strings)
    volumes_size = 96 + len(device)
    file_size = volumes_offset + volumes_size

    executable_field = _utf16z(executable).ljust(60, b"\x00")
    header = _u32(30) + b"SCCA" + _u32(0, file_size)
    header += executable_field + _u32(prefetch_vista_path_hash(DEVICE_PATH + tail), 0)

    information = _u32(304, 1, 336, 1, 344, len(strings), volumes_offset, 1, volumes_size)
    information += b"\x00" * 8
    information += struct.pack("<Q", FILETIME) + b"\x00" * (7 * 8)
    information += b"\x00" * 16
    information += _u32(3, 0, 0, 0, 0) + b"\x00" * 76
    assert len(information) == 220

    metrics = _u32(0, 1, 1, 0, len(recorded_path), 0x200) + struct.pack("<Q", 0)
    trace = b"\x01\x00\x00\x00\x02\x01\x01\x01"
    volume = _u32(96, len(volume_token)) + struct.pack("<Q", VOLUME_FILETIME)
    volume += _u32(SERIAL) + b"\x00" * 76
    result = header + information + metrics + trace + strings + volume + device
    if tail == TAIL and executable == EXECUTABLE:
        assert len(result) == 782
    return result


def _tail_for_device_path_length(length: int) -> str:
    suffix = r"\NOTEPAD.EXE"
    component_length = length - len(DEVICE_PATH) - 1 - len(suffix)
    assert component_length > 0
    tail = "\\" + ("A" * component_length) + suffix
    assert len(DEVICE_PATH + tail) == length
    return tail


def _flip(data: bytes, offset: int, mask: int = 1) -> bytes:
    changed = bytearray(data)
    changed[offset] ^= mask
    return bytes(changed)


def test_fixed_probe_has_stable_digest_and_exact_expected_size() -> None:
    assert len(FIXED_INTEROP_PROBE) == 458
    assert hashlib.sha256(FIXED_INTEROP_PROBE).hexdigest() == (
        "7bd81183dcbecc5e77fbb4a8a4e34c40f27638e86de70310af257ffef8465aaa"
    )

    inner = decode_mam_xpress_huffman(FIXED_INTEROP_PROBE)

    assert len(inner) == 736
    assert hashlib.sha256(inner).hexdigest() == (
        "0536b1f6576d35df2cd33087bf8f7716eff851a073cecf4eb96d281df377ccac"
    )


def test_fixed_probe_is_structurally_variant1_but_not_final_profile() -> None:
    view = parse_mam_prefetch_v30_variant1(FIXED_INTEROP_PROBE)

    assert view.executable_name == EXECUTABLE
    assert view.prefetch_hash == 0xEB1B961A
    assert view.run_count == 3
    assert view.last_run_filetimes == (FILETIME, 0, 0, 0, 0, 0, 0, 0)
    assert view.volume_serial_number == SERIAL
    assert view.filename_strings[1] == r"\VOLUME{01}\ARTIFACTFORGE-SYNTHETIC-NOT-EVIDENCE"

    with pytest.raises(PrefetchV30ProfileError, match="filename strings"):
        validate_artifactforge_prefetch_v30_profile(view, view.oracle_view())


def test_pyscca_and_dissect_recover_the_same_fixed_probe_semantics() -> None:
    pytest.importorskip("pyscca")
    pytest.importorskip("dissect.target.plugins.os.windows.prefetch")
    from dissect.util.compression.lzxpress_huffman import decompress

    pyscca_view = pyscca_prefetch_v30_view(FIXED_INTEROP_PROBE)
    dissect_view = dissect_prefetch_v30_view(FIXED_INTEROP_PROBE)
    consensus = require_prefetch_v30_consensus(
        {"pyscca": pyscca_view, "dissect.target-prefetch": dissect_view}
    )

    assert consensus == parse_mam_prefetch_v30_variant1(FIXED_INTEROP_PROBE).oracle_view()
    assert consensus.metric_filenames == (
        r"\VOLUME{01da476fb1284800-1234abcd}\WINDOWS\SYSTEM32\NOTEPAD.EXE",
    )
    assert len(decompress(FIXED_INTEROP_PROBE[8:])) == 739
    assert len(decode_mam_xpress_huffman(FIXED_INTEROP_PROBE)) == 736


def test_live_writer_round_trips_through_strict_and_external_readers() -> None:
    pytest.importorskip("pyscca")
    pytest.importorskip("dissect.target.plugins.os.windows.prefetch")
    from artifactforge.artifacts.prefetch import build_prefetch_v30

    artifact = build_prefetch_v30(
        "notepad.exe",
        r"\DEVICE\HARDDISKVOLUME1\Windows\System32\notepad.exe",
        3,
    )
    strict = parse_mam_prefetch_v30_variant1(artifact)
    consensus = require_prefetch_v30_consensus(
        {
            "pyscca": pyscca_prefetch_v30_view(artifact),
            "dissect.target-prefetch": dissect_prefetch_v30_view(artifact),
        }
    )

    assert strict.declared_file_size == 782
    assert consensus == strict.oracle_view()
    assert validate_artifactforge_prefetch_v30_profile(strict, consensus).startswith(
        "profile=windows10-v30-variant1,"
    )


def test_conforming_inner_binds_both_strings_to_the_sole_volume() -> None:
    inner = _conforming_inner()
    view = parse_prefetch_v30_variant1(inner)
    volume_token = r"\VOLUME{01da46a686be8800-1234abcd}"

    assert view.volume_device_path == volume_token
    assert view.filename_strings == (
        volume_token + TAIL,
        volume_token + r"\ARTIFACTFORGE-SYNTHETIC-NOT-EVIDENCE",
    )
    assert validate_artifactforge_prefetch_v30_profile(view, view.oracle_view()) == (
        "profile=windows10-v30-variant1,version=30,exe=NOTEPAD.EXE,"
        "hash=eb1b961a,runs=3,"
        "volume=\\VOLUME{01da46a686be8800-1234abcd}/1234abcd,"
        "marker=volume-bound"
    )


def test_profile_accepts_the_exact_260_character_original_device_path_boundary() -> None:
    tail = _tail_for_device_path_length(260)
    view = parse_prefetch_v30_variant1(_conforming_inner(tail=tail))

    assert len(DEVICE_PATH + tail) == 260
    assert validate_artifactforge_prefetch_v30_profile(view, view.oracle_view()).startswith(
        "profile=windows10-v30-variant1,"
    )


def test_profile_rejects_a_261_character_original_device_path() -> None:
    tail = _tail_for_device_path_length(261)
    view = parse_prefetch_v30_variant1(_conforming_inner(tail=tail))

    with pytest.raises(PrefetchV30ProfileError, match="exceeds the profile bound"):
        validate_artifactforge_prefetch_v30_profile(view, view.oracle_view())


@pytest.mark.parametrize(
    "tail",
    [
        r"\WINDOWS\SYS?EM32\NOTEPAD.EXE",
        r"\WINDOWS\SYSTEM32 \NOTEPAD.EXE",
        r"\WINDOWS\CON\NOTEPAD.EXE",
        r"\WINDOWS\NUL.EXE",
    ],
)
def test_profile_rejects_noncanonical_windows_components(tail: str) -> None:
    executable = tail.rsplit("\\", 1)[-1]
    view = parse_prefetch_v30_variant1(_conforming_inner(tail=tail, executable=executable))

    with pytest.raises(PrefetchV30ProfileError, match="non-canonical Windows component"):
        validate_artifactforge_prefetch_v30_profile(view, view.oracle_view())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: b"BAD!" + value[4:],
        lambda value: value[:4] + struct.pack("<I", 735) + value[8:],
        lambda value: value[:8] + (b"\x00" * 256) + value[264:],
        lambda value: value[:-2],
        lambda value: value + b"\x00\x00",
        lambda value: value[:-1] + bytes((value[-1] ^ 1,)),
        lambda value: _flip(value, 455, 0x20),
    ],
    ids=(
        "algorithm",
        "declared-size",
        "empty-tree",
        "missing-zero-word",
        "extra-zero-word",
        "nonzero-post-output-padding",
        "post-output-sentinel",
    ),
)
def test_expected_size_decoder_rejects_hostile_wrapper_and_payload_mutations(mutation) -> None:
    with pytest.raises(PrefetchV30ProfileError):
        decode_mam_xpress_huffman(mutation(FIXED_INTEROP_PROBE))


@pytest.mark.parametrize(
    "offset",
    [
        0,  # version
        4,  # SCCA signature
        8,  # reserved header integer
        12,  # declared inner size
        50,  # non-zero executable-name padding
        80,  # header flag
        84,  # metrics offset
        88,  # metrics count
        92,  # trace offset
        96,  # trace count
        100,  # strings offset
        104,  # strings byte size
        108,  # volumes offset
        112,  # volume count
        116,  # volumes size
        120,  # reserved file-information bytes
        212,  # reserved bytes after run count
        304,  # metrics start time
        308,  # metrics duration
        312,  # metrics average duration
        316,  # metric filename offset
        324,  # metric flags
        328,  # NTFS reference
        336,  # trace-chain bytes
    ],
)
def test_variant1_parser_rejects_fixed_field_mutations(offset: int) -> None:
    with pytest.raises(PrefetchV30ProfileError):
        parse_prefetch_v30_variant1(_flip(_conforming_inner(), offset))


def test_variant1_parser_rejects_hostile_string_and_volume_extents() -> None:
    inner = _conforming_inner()
    volumes_offset = struct.unpack_from("<I", inner, 108)[0]

    hostile = (
        _flip(inner, 344),
        _flip(inner, volumes_offset - 2),
        _flip(inner, volumes_offset),
        _flip(inner, volumes_offset + 4),
        _flip(inner, volumes_offset + 20),
        _flip(inner, len(inner) - 2),
        inner + b"\x00\x00",
    )
    for mutated in hostile:
        with pytest.raises(PrefetchV30ProfileError):
            parse_prefetch_v30_variant1(mutated)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda view: replace(view, run_count=0),
        lambda view: replace(view, last_run_filetimes=(FILETIME,) * 8),
        lambda view: replace(view, prefetch_hash=view.prefetch_hash ^ 1),
        lambda view: replace(view, executable_name="CALC.EXE"),
        lambda view: replace(view, volume_serial_number=0),
        lambda view: replace(view, volume_device_path=r"\VOLUME{01}"),
        lambda view: replace(
            view,
            filename_strings=(
                view.filename_strings[0],
                r"\VOLUME{01}\ARTIFACTFORGE-SYNTHETIC-NOT-EVIDENCE",
            ),
        ),
        lambda view: replace(view, volume_creation_filetime=FILETIME),
    ],
)
def test_profile_validation_rejects_semantic_mutations(mutate) -> None:
    view = mutate(parse_prefetch_v30_variant1(_conforming_inner()))

    with pytest.raises(PrefetchV30ProfileError):
        validate_artifactforge_prefetch_v30_profile(view, view.oracle_view())


def test_consensus_requires_both_named_typed_equal_observations() -> None:
    view = parse_prefetch_v30_variant1(_conforming_inner()).oracle_view()
    disagreement = replace(view, run_count=view.run_count + 1)

    with pytest.raises(PrefetchV30ProfileError, match="both required"):
        require_prefetch_v30_consensus({"pyscca": view})
    with pytest.raises(PrefetchV30ProfileError, match="disagree"):
        require_prefetch_v30_consensus({"pyscca": view, "dissect.target-prefetch": disagreement})
    with pytest.raises(PrefetchV30ProfileError, match="both required"):
        require_prefetch_v30_consensus({"pyscca": view, "dissect.target-prefetch": object()})


def test_input_and_typed_view_contracts_fail_closed() -> None:
    with pytest.raises(PrefetchV30ProfileError, match="immutable bytes"):
        decode_mam_xpress_huffman(bytearray(FIXED_INTEROP_PROBE))  # type: ignore[arg-type]
    with pytest.raises(PrefetchV30ProfileError, match="immutable bytes"):
        parse_prefetch_v30_variant1(bytearray(_conforming_inner()))  # type: ignore[arg-type]
    with pytest.raises(PrefetchV30ProfileError, match="typed strict-reader"):
        validate_artifactforge_prefetch_v30_profile(  # type: ignore[arg-type]
            object(),
            PrefetchV30OracleView(30, EXECUTABLE, 1, 1, (FILETIME,) + (0,) * 7, ("x",)),
        )
