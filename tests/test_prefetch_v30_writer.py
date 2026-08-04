# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Writer tests for ArtifactForge's closed Windows-10 Prefetch profile."""

from __future__ import annotations

import hashlib
import io
import struct

import pytest

from artifactforge.artifacts.prefetch import (
    FILETIME,
    MAM_XPRESS_HUFFMAN_MAGIC,
    PrefetchTimestamps,
    build_prefetch,
    build_prefetch_v17_legacy,
    build_prefetch_v30,
    prefetch_name_hash,
    prefetch_vista_name_hash,
    prefetch_xp_name_hash,
)
from artifactforge.artifacts.xpress_huffman import compress_xpress_huffman
from artifactforge.gates.oracles.prefetch_profile import (
    PrefetchV30ProfileError,
    decode_mam_xpress_huffman,
    dissect_prefetch_v30_view,
    parse_mam_prefetch_v30_variant1,
    prefetch_vista_path_hash,
    pyscca_prefetch_v30_view,
    require_prefetch_v30_consensus,
    validate_artifactforge_prefetch_v30_profile,
)


DEVICE_ROOT = r"\DEVICE\HARDDISKVOLUME1"
DEVICE_PATH = DEVICE_ROOT + r"\WINDOWS\SYSTEM32\NOTEPAD.EXE"
XP_VECTOR_PATH = r"\DEVICE\HARDDISKVOLUME1\WINDOWS\NOTEPAD.EXE"
LAST_RUN = 133_497_684_000_000_000
VOLUME_CREATED = 133_497_000_000_000_000
VOLUME_SERIAL = 0x1234ABCD
VOLUME_TOKEN = r"\VOLUME{01da46d06f949000-1234abcd}"


def _timestamps() -> PrefetchTimestamps:
    return PrefetchTimestamps(
        last_run_filetime=LAST_RUN,
        volume_creation_filetime=VOLUME_CREATED,
    )


def _build(**overrides: object) -> bytes:
    arguments: dict[str, object] = {
        "exe_name": "notepad.exe",
        "full_path": DEVICE_PATH,
        "run_count": 3,
        "timestamps": _timestamps(),
        "volume_serial": VOLUME_SERIAL,
    }
    arguments.update(overrides)
    return build_prefetch_v30(**arguments)  # type: ignore[arg-type]


def _rewrap(inner: bytes) -> bytes:
    return MAM_XPRESS_HUFFMAN_MAGIC + struct.pack("<I", len(inner)) + compress_xpress_huffman(inner)


def _device_path_with_length(length: int) -> str:
    suffix = r"\NOTEPAD.EXE"
    component_length = length - len(DEVICE_ROOT) - 1 - len(suffix)
    assert component_length > 0
    path = DEVICE_ROOT + "\\" + ("A" * component_length) + suffix
    assert len(path) == length
    return path


def test_v30_writer_fixed_vector_and_exact_strict_layout() -> None:
    first = _build()
    second = _build()

    assert first == second
    assert first[:4] == MAM_XPRESS_HUFFMAN_MAGIC
    assert struct.unpack_from("<I", first, 4)[0] == 782
    assert len(first) == 466
    assert hashlib.sha256(first).hexdigest() == (
        "dadd4a30905ef5957cee0f46683d4b438ec2d604d944548a6f664678b90a43c6"
    )

    inner = decode_mam_xpress_huffman(first)
    assert len(inner) == 782
    assert struct.unpack_from("<I", inner, 0)[0] == 30
    assert inner[4:8] == b"SCCA"
    assert struct.unpack_from("<I", inner, 12)[0] == len(inner)
    assert struct.unpack_from("<9I", inner, 84) == (
        304,
        1,
        336,
        1,
        344,
        272,
        616,
        1,
        166,
    )

    view = parse_mam_prefetch_v30_variant1(first)
    assert view.executable_name == "NOTEPAD.EXE"
    assert view.prefetch_hash == 0xEB1B961A
    assert view.run_count == 3
    assert view.last_run_filetimes == (LAST_RUN, 0, 0, 0, 0, 0, 0, 0)
    assert view.metric_filenames == (VOLUME_TOKEN + r"\WINDOWS\SYSTEM32\NOTEPAD.EXE",)
    assert view.filename_strings == (
        VOLUME_TOKEN + r"\WINDOWS\SYSTEM32\NOTEPAD.EXE",
        VOLUME_TOKEN + r"\ARTIFACTFORGE-SYNTHETIC-NOT-EVIDENCE",
    )
    assert view.volume_device_path == VOLUME_TOKEN
    assert view.volume_creation_filetime == VOLUME_CREATED
    assert view.volume_serial_number == VOLUME_SERIAL


def test_pyscca_and_dissect_agree_on_semantics_not_container_extent() -> None:
    from dissect.target.plugins.os.windows.prefetch import Prefetch

    data = _build()
    strict = parse_mam_prefetch_v30_variant1(data)
    pyscca_view = pyscca_prefetch_v30_view(data)
    dissect_view = dissect_prefetch_v30_view(data)
    consensus = require_prefetch_v30_consensus(
        {
            "pyscca": pyscca_view,
            "dissect.target-prefetch": dissect_view,
        }
    )

    assert pyscca_view == dissect_view == strict.oracle_view()
    assert validate_artifactforge_prefetch_v30_profile(strict, consensus).startswith(
        "profile=windows10-v30-variant1"
    )

    # Dissect's decompressor is EOF-driven: symbol 256 after MAM's declared output is
    # interpreted as an ordinary length-three/distance-one match.  Its semantic view is an
    # independent oracle, but its decoded buffer is intentionally not credited as an exact
    # container/framing validation.
    expected_size = struct.unpack_from("<I", data, 4)[0]
    dissect_raw = Prefetch(io.BytesIO(data))
    assert len(dissect_raw.fh.getbuffer()) == expected_size + 3


def test_volume_token_preserves_an_uppercase_device_path_tail() -> None:
    data = _build(
        full_path=r"\DEVICE\HARDDISKVOLUME1\Windows\System32\notepad.exe",
    )
    view = parse_mam_prefetch_v30_variant1(data)

    assert view.metric_filenames == (VOLUME_TOKEN + r"\WINDOWS\SYSTEM32\NOTEPAD.EXE",)
    assert view.prefetch_hash == prefetch_vista_name_hash(DEVICE_PATH)


def test_longest_executable_name_fits_without_truncation() -> None:
    executable_name = ("A" * 25) + ".EXE"
    assert len(executable_name) == 29

    data = _build(
        exe_name=executable_name.lower(),
        full_path=rf"\DEVICE\HARDDISKVOLUME1\TOOLS\{executable_name}",
    )

    assert parse_mam_prefetch_v30_variant1(data).executable_name == executable_name


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"exe_name": b"NOTEPAD.EXE"}, "immutable"),
        ({"exe_name": ""}, "non-empty"),
        ({"exe_name": "NØTEPAD.EXE"}, "portable ASCII"),
        ({"exe_name": ("A" * 26) + ".EXE"}, "too long"),
        ({"exe_name": r"WINDOWS\NOTEPAD.EXE"}, "basename"),
        ({"exe_name": "CALC.EXE"}, "agree"),
        ({"full_path": b"not a path"}, "immutable"),
        ({"full_path": r"\DEVICE\HARDDISKVOLUME10\NOTEPAD.EXE"}, "rooted exactly"),
        ({"full_path": r"\device\harddiskvolume1\NOTEPAD.EXE"}, "rooted exactly"),
        ({"full_path": "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\\\NOTEPAD.EXE"}, "canonical"),
        ({"full_path": "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\"}, "canonical"),
        ({"full_path": r"\DEVICE\HARDDISKVOLUME1\WINDOWS/NOTEPAD.EXE"}, "canonical"),
        ({"full_path": r"\DEVICE\HARDDISKVOLUME1\..\NOTEPAD.EXE"}, "relative"),
        ({"full_path": r"\DEVICE\HARDDISKVOLUME1\WÍNDOWS\NOTEPAD.EXE"}, "portable ASCII"),
        (
            {"full_path": r"\DEVICE\HARDDISKVOLUME1\SYS?EM32\NOTEPAD.EXE"},
            "non-canonical Windows component",
        ),
        (
            {"full_path": r"\DEVICE\HARDDISKVOLUME1\SYSTEM32 \NOTEPAD.EXE"},
            "non-canonical Windows component",
        ),
        (
            {"full_path": r"\DEVICE\HARDDISKVOLUME1\CON\NOTEPAD.EXE"},
            "non-canonical Windows component",
        ),
        (
            {
                "exe_name": "NUL.EXE",
                "full_path": r"\DEVICE\HARDDISKVOLUME1\WINDOWS\NUL.EXE",
            },
            "non-canonical Windows component",
        ),
    ],
)
def test_v30_writer_rejects_noncanonical_names_and_paths(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _build(**overrides)


def test_v30_writer_accepts_the_exact_260_character_device_path_boundary() -> None:
    path = _device_path_with_length(260)

    view = parse_mam_prefetch_v30_variant1(_build(full_path=path))

    assert len(path) == 260
    assert validate_artifactforge_prefetch_v30_profile(view, view.oracle_view()).startswith(
        "profile=windows10-v30-variant1,"
    )


def test_v30_writer_rejects_a_261_character_device_path_instead_of_truncating() -> None:
    oversized = _device_path_with_length(261)

    with pytest.raises(ValueError, match="must not exceed 260 characters"):
        _build(full_path=oversized)


@pytest.mark.parametrize("run_count", [0, -1, 1 << 32, True, 1.0])
def test_v30_writer_rejects_invalid_run_counts(run_count: object) -> None:
    with pytest.raises(ValueError, match="exact nonzero unsigned 32-bit"):
        _build(run_count=run_count)


@pytest.mark.parametrize("volume_serial", [0, -1, 1 << 32, True, 1.0])
def test_v30_writer_rejects_invalid_volume_serials(volume_serial: object) -> None:
    with pytest.raises(ValueError, match="exact nonzero unsigned 32-bit"):
        _build(volume_serial=volume_serial)


@pytest.mark.parametrize("value", [1, (1 << 32) - 1])
def test_u32_boundaries_round_trip(value: int) -> None:
    run_view = parse_mam_prefetch_v30_variant1(_build(run_count=value))
    serial_view = parse_mam_prefetch_v30_variant1(_build(volume_serial=value))

    assert run_view.run_count == value
    assert serial_view.volume_serial_number == value


@pytest.mark.parametrize(
    ("timestamps", "message"),
    [
        (PrefetchTimestamps(LAST_RUN, LAST_RUN), "must precede"),
        (PrefetchTimestamps(VOLUME_CREATED, LAST_RUN), "must precede"),
        (
            PrefetchTimestamps(116_444_736_000_000_001, 116_444_736_000_000_000),
            "whole-microsecond",
        ),
        (
            PrefetchTimestamps(116_444_736_000_000_010, 116_444_735_999_999_990),
            "1970..2242",
        ),
        (
            PrefetchTimestamps(202_344_081_920_000_010, 202_344_081_920_000_000),
            "1970..2242",
        ),
    ],
)
def test_v30_writer_rejects_noncausal_or_nonportable_filetimes(
    timestamps: PrefetchTimestamps,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _build(timestamps=timestamps)


def test_v30_default_timestamps_are_deterministic_and_causal() -> None:
    view = parse_mam_prefetch_v30_variant1(build_prefetch_v30("notepad.exe", DEVICE_PATH, 1))

    assert view.last_run_filetimes[0] == FILETIME
    assert view.volume_creation_filetime == FILETIME - 10_000_000
    assert view.volume_creation_filetime < view.last_run_filetimes[0]


def test_v30_writer_requires_exact_timestamp_container_type() -> None:
    with pytest.raises(ValueError, match="PrefetchTimestamps or None"):
        _build(timestamps=object())


def test_strict_reader_rejects_malformed_wrapper_and_inner_reserved_byte() -> None:
    data = _build()

    with pytest.raises(PrefetchV30ProfileError, match="algorithm 4"):
        parse_mam_prefetch_v30_variant1(b"MAM\x03" + data[4:])

    inner = bytearray(decode_mam_xpress_huffman(data))
    inner[120] = 1
    with pytest.raises(PrefetchV30ProfileError, match="reserved bytes"):
        parse_mam_prefetch_v30_variant1(_rewrap(bytes(inner)))


def test_explicit_hashes_and_legacy_writer_preserve_frozen_v17_abi() -> None:
    legacy = build_prefetch("notepad.exe", XP_VECTOR_PATH, 3)
    explicit = build_prefetch_v17_legacy("notepad.exe", XP_VECTOR_PATH, 3)

    assert legacy == explicit
    assert hashlib.sha256(legacy).hexdigest() == (
        "21ad45c60485907f946877b4e275c971edff7c0892dea3292ebfa72efa76e51d"
    )
    assert prefetch_xp_name_hash(XP_VECTOR_PATH) == 0x189578DA
    assert prefetch_name_hash(XP_VECTOR_PATH) == prefetch_xp_name_hash(XP_VECTOR_PATH)
    assert prefetch_vista_name_hash(XP_VECTOR_PATH) == 0x3D2AFDB4
    assert prefetch_vista_name_hash(DEVICE_PATH) == prefetch_vista_path_hash(DEVICE_PATH)
