# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic Windows Prefetch writers.

``build_prefetch_v30`` emits ArtifactForge's bounded Windows-10 variant: an exact v30 inner
record wrapped in MAM algorithm-4 XPRESS-Huffman compression.  The old uncompressed v17
writer remains available through both ``build_prefetch`` and ``build_prefetch_v17_legacy``;
that compatibility surface intentionally preserves its historical truncation and default
behavior byte-for-byte.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

from artifactforge.disclosure import MARKER
from artifactforge.artifacts.xpress_huffman import compress_xpress_huffman

FILETIME = 133497684000000000  # 2024-01-15T05:00:00Z, pinned

HEADER_SIZE = 84
FILE_INFORMATION_SIZE = 68  # v17; v23/v26/v30 are larger, hence the version field
EXECUTABLE_FILENAME_SIZE = 60  # fixed-width field inside the header
METRICS_ENTRY_SIZE = 20  # v17 file metrics array entry
TRACE_CHAIN_ENTRY_SIZE = 12  # v17 trace chain array entry
VOLUME_INFORMATION_SIZE = 40  # v17 volume information entry

DEVICE_PATH = "\\DEVICE\\HARDDISKVOLUME1"
VOLUME_SERIAL_NUMBER = 0x1234ABCD  # pinned; nothing here derives it from the host

V30_FILE_INFORMATION_SIZE = 220
V30_METRICS_ENTRY_SIZE = 32
V30_TRACE_CHAIN_ENTRY_SIZE = 8
V30_VOLUME_INFORMATION_SIZE = 96
MAM_XPRESS_HUFFMAN_MAGIC = b"MAM\x04"

_MIN_PORTABLE_FILETIME = 116_444_736_000_000_000
_MAX_PORTABLE_FILETIME = 202_344_081_920_000_000
_MAX_V30_INNER_SIZE = 4096
_MAX_V30_DEVICE_PATH_CHARACTERS = 260
_V30_DEFAULT_VOLUME_CREATION_FILETIME = FILETIME - 10_000_000
_INVALID_WINDOWS_COMPONENT_CHARACTERS = frozenset('<>:"/|?*')
_RESERVED_WINDOWS_COMPONENTS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def _filetime(value: object, *, where: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"{where} must be an unsigned 64-bit FILETIME integer (not bool)")
    return value


@dataclass(frozen=True)
class PrefetchTimestamps:
    """The last-run and volume-creation FILETIMEs represented by Prefetch."""

    last_run_filetime: int = FILETIME
    volume_creation_filetime: int = FILETIME

    def __post_init__(self) -> None:
        _filetime(self.last_run_filetime, where="prefetch last-run timestamp")
        _filetime(self.volume_creation_filetime, where="prefetch volume creation timestamp")


def _u32(*vals: int) -> bytes:
    return b"".join(struct.pack("<I", v) for v in vals)


def _utf16_string(value: str) -> bytes:
    """UTF-16LE with the end-of-string character the format requires on every string."""
    return (value + "\x00").encode("utf-16-le")


def prefetch_xp_name_hash(full_path: str) -> int:
    """Return the SCCA XP/Server 2003 hash used by format version 17.

    Windows first uppercases the device path and encodes it as UTF-16LE.  The initial
    multiply-by-37 loop produces only the ``ConvKey`` intermediate; the filename hash also
    applies the XP randomisation constant and prime reduction.  Keeping those stages named
    prevents the intermediate from being mistaken for the final hash again.
    """
    conv_key = 0
    for byte in full_path.upper().encode("utf-16-le"):
        conv_key = (37 * conv_key + byte) & 0xFFFFFFFF

    randomised = (314159269 * conv_key) & 0xFFFFFFFF
    magnitude = 0x100000000 - randomised if randomised > 0x80000000 else randomised
    return magnitude % 1000000007


def prefetch_name_hash(full_path: str) -> int:
    """Compatibility alias for :func:`prefetch_xp_name_hash`."""

    return prefetch_xp_name_hash(full_path)


def prefetch_vista_name_hash(full_path: str) -> int:
    """Return the Vista-and-later Prefetch path hash used by format version 30."""

    result = 314159
    for byte in full_path.upper().encode("utf-16-le"):
        result = (result * 37 + byte) & 0xFFFFFFFF
    return result


def build_prefetch_v17_legacy(
    exe_name: str,
    full_path: str,
    run_count: int,
    *,
    timestamps: PrefetchTimestamps | None = None,
) -> bytes:
    if timestamps is None:
        timestamps = PrefetchTimestamps()
    elif type(timestamps) is not PrefetchTimestamps:
        raise ValueError("prefetch timestamps must be a PrefetchTimestamps or None")
    exe = exe_name.upper()
    path = full_path.upper()

    # The header's executable filename is a fixed 60-byte field holding "an UTF-16
    # little-endian string with end-of-string character", so at most 29 characters fit.
    # libscca scans the field for the NUL pair and falls back to all 30 characters when it
    # finds none, so the terminator is what makes a long name truncate predictably.
    exe_field = (exe.encode("utf-16-le")[: EXECUTABLE_FILENAME_SIZE - 2] + b"\x00\x00").ljust(
        EXECUTABLE_FILENAME_SIZE, b"\x00"
    )

    # libscca splits the filename strings block on NUL pairs, so the end-of-string character
    # is what makes this one entry rather than zero. A second entry carries the in-band
    # synthetic marker: the filename strings array is where a real prefetch record lists paths
    # a process touched, so a path that plainly names this generator is both a natural place
    # to put the disclosure and one `strings` cannot miss. The metrics entry still points at
    # offset 0, so the executed file is unambiguously the first.
    marker_path = f"\\VOLUME{{01}}\\{MARKER}-SYNTHETIC-NOT-EVIDENCE"
    filename_strings = _utf16_string(path) + _utf16_string(marker_path)
    device_path = _utf16_string(DEVICE_PATH)

    # Both counts are in characters and exclude the end-of-string character, per the spec's
    # "Does not include the end-of-string character" on the file metrics entry.
    path_characters = len(_utf16_string(path)) // 2 - 1
    device_path_characters = len(device_path) // 2 - 1

    metrics_offset = HEADER_SIZE + FILE_INFORMATION_SIZE  # spec fixes this at 152 for v17
    trace_chain_offset = metrics_offset + METRICS_ENTRY_SIZE
    filename_strings_offset = trace_chain_offset + TRACE_CHAIN_ENTRY_SIZE
    volumes_offset = filename_strings_offset + len(filename_strings)

    # The device path lives immediately after the volume entry, and the block is sized to
    # include the path's end-of-string character. libscca rejects anything tighter: it takes
    # the character count, doubles it, and requires
    #   device_path_offset < volumes_information_size - (characters * 2)
    # so a block ending exactly at the last counted character is off-by-one and raises
    # "invalid volume device path size value out of bounds". The two bytes of headroom that
    # satisfy the check are the terminator itself.
    device_path_offset = VOLUME_INFORMATION_SIZE
    volumes_size = VOLUME_INFORMATION_SIZE + len(device_path)
    file_size = volumes_offset + volumes_size

    header = _u32(17) + b"SCCA" + _u32(0, file_size)
    header += exe_field + struct.pack("<I", prefetch_xp_name_hash(full_path)) + _u32(0)

    fileinfo = _u32(
        metrics_offset,
        1,
        trace_chain_offset,
        1,
        filename_strings_offset,
        len(filename_strings),
        volumes_offset,
        1,
        volumes_size,
    )
    fileinfo += struct.pack("<Q", timestamps.last_run_filetime) + b"\x00" * 16
    fileinfo += struct.pack("<I", run_count & 0xFFFFFFFF) + _u32(0)

    # The filename string offset is relative to the start of the filename strings block, and
    # libscca resolves it by matching the recorded start offset of a string exactly.
    metrics = _u32(0, 1, 0, path_characters, 0)

    # Only the first field is meaningful here: 0xFFFFFFFF terminates the chain, as it does in
    # the last entry of a real file. libscca reads this array in debug builds only.
    trace_chain = _u32(0xFFFFFFFF, 1) + bytes(4)

    volume = _u32(device_path_offset, device_path_characters)
    volume += struct.pack("<Q", timestamps.volume_creation_filetime) + _u32(VOLUME_SERIAL_NUMBER)
    volume += _u32(0, 0)  # no file references: a zero offset makes libscca skip the block
    volume += _u32(0, 0)  # no directory strings, likewise — a non-zero offset here is
    # bounds-checked against the block and would be rejected
    volume += _u32(0)  # unknown1
    volume += device_path

    return header + fileinfo + metrics + trace_chain + filename_strings + volume


def build_prefetch(
    exe_name: str,
    full_path: str,
    run_count: int,
    *,
    timestamps: PrefetchTimestamps | None = None,
) -> bytes:
    """Preserve the historical uncompressed-v17 ArtifactForge public API."""

    return build_prefetch_v17_legacy(
        exe_name,
        full_path,
        run_count,
        timestamps=timestamps,
    )


def _portable_ascii(value: object, *, where: str, maximum_characters: int) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{where} must be immutable, non-empty, NUL-free text")
    if len(value) > maximum_characters:
        raise ValueError(f"{where} is too long for the bounded Prefetch profile")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must be portable ASCII") from exc
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError(f"{where} must not contain control characters")
    return value


def _canonical_v30_device_path(value: object) -> str:
    path = _portable_ascii(
        value,
        where="prefetch device path",
        maximum_characters=_MAX_V30_INNER_SIZE,
    )
    root = DEVICE_PATH + "\\"
    if not path.startswith(root):
        raise ValueError(f"prefetch device path must be rooted exactly at {DEVICE_PATH}")
    if len(path) > _MAX_V30_DEVICE_PATH_CHARACTERS:
        raise ValueError(
            f"prefetch device path must not exceed {_MAX_V30_DEVICE_PATH_CHARACTERS} characters"
        )
    if path.endswith("\\") or "\\\\" in path or "/" in path:
        raise ValueError("prefetch device path must be a canonical absolute path")
    if any(component in {".", ".."} for component in path.split("\\")):
        raise ValueError("prefetch device path must not contain relative components")
    for component in path[len(root) :].split("\\"):
        stem = component.split(".", 1)[0].upper()
        if (
            not component
            or len(component) > 255
            or component[-1] in {" ", "."}
            or any(character in _INVALID_WINDOWS_COMPONENT_CHARACTERS for character in component)
            or stem in _RESERVED_WINDOWS_COMPONENTS
        ):
            raise ValueError("prefetch device path contains a non-canonical Windows component")
    return path


def _portable_v30_filetime(value: object, *, where: str) -> int:
    converted = _filetime(value, where=where)
    if converted % 10 or not _MIN_PORTABLE_FILETIME <= converted <= _MAX_PORTABLE_FILETIME:
        raise ValueError(
            f"{where} must be a whole-microsecond FILETIME in the portable 1970..2242 range"
        )
    return converted


def _v30_timestamps(
    timestamps: PrefetchTimestamps | None,
) -> tuple[int, int]:
    if timestamps is None:
        last_run = FILETIME
        volume_creation = _V30_DEFAULT_VOLUME_CREATION_FILETIME
    elif type(timestamps) is PrefetchTimestamps:
        last_run = timestamps.last_run_filetime
        volume_creation = timestamps.volume_creation_filetime
    else:
        raise ValueError("prefetch timestamps must be a PrefetchTimestamps or None")

    last_run = _portable_v30_filetime(
        last_run,
        where="prefetch last-run timestamp",
    )
    volume_creation = _portable_v30_filetime(
        volume_creation,
        where="prefetch volume-creation timestamp",
    )
    if volume_creation >= last_run:
        raise ValueError("prefetch volume-creation timestamp must precede the last-run timestamp")
    return last_run, volume_creation


def _exact_nonzero_u32(value: object, *, where: str) -> int:
    if type(value) is not int or not 1 <= value < 1 << 32:
        raise ValueError(f"{where} must be an exact nonzero unsigned 32-bit integer")
    return value


def build_prefetch_v30(
    exe_name: str,
    full_path: str,
    run_count: int,
    *,
    timestamps: PrefetchTimestamps | None = None,
    volume_serial: int = VOLUME_SERIAL_NUMBER,
) -> bytes:
    """Build one compressed Windows-10 v30 variant-1 Prefetch record.

    The supported shape is deliberately closed: one metric, one trace entry, two filename
    strings and one volume.  ``full_path`` is the original canonical device path used for
    the Vista hash; the recorded strings replace its device root with a deterministic volume
    token bound to the supplied volume creation time and serial number.
    """

    exe_name = _portable_ascii(
        exe_name,
        where="prefetch executable name",
        maximum_characters=(EXECUTABLE_FILENAME_SIZE // 2) - 1,
    )
    if any(separator in exe_name for separator in ("\\", "/", ":")):
        raise ValueError("prefetch executable name must be a basename")
    executable_name = exe_name.upper()
    path = _canonical_v30_device_path(full_path)
    path_tail = path[len(DEVICE_PATH) :].upper()
    if executable_name != path_tail.rsplit("\\", 1)[-1]:
        raise ValueError("prefetch executable name must agree with the device-path basename")

    run_count = _exact_nonzero_u32(run_count, where="prefetch run count")
    volume_serial = _exact_nonzero_u32(
        volume_serial,
        where="prefetch volume serial",
    )
    last_run_filetime, volume_creation_filetime = _v30_timestamps(timestamps)

    volume_token = f"\\VOLUME{{{volume_creation_filetime:016x}-{volume_serial:08x}}}"
    recorded_path = volume_token + path_tail
    marker_path = f"{volume_token}\\{MARKER}-SYNTHETIC-NOT-EVIDENCE"
    filename_strings = _utf16_string(recorded_path) + _utf16_string(marker_path)
    volume_device_path = _utf16_string(volume_token)

    metrics_offset = HEADER_SIZE + V30_FILE_INFORMATION_SIZE
    trace_chain_offset = metrics_offset + V30_METRICS_ENTRY_SIZE
    filename_strings_offset = trace_chain_offset + V30_TRACE_CHAIN_ENTRY_SIZE
    volumes_offset = filename_strings_offset + len(filename_strings)

    metrics = _u32(0, 1, 1, 0, len(recorded_path), 0x200) + struct.pack("<Q", 0)
    trace_chain = b"\x01\x00\x00\x00\x02\x01\x01\x01"
    volume = _u32(V30_VOLUME_INFORMATION_SIZE, len(volume_token))
    volume += struct.pack("<Q", volume_creation_filetime)
    volume += _u32(volume_serial) + bytes(V30_VOLUME_INFORMATION_SIZE - 20)
    volume += volume_device_path
    volumes_size = len(volume)
    file_size = volumes_offset + volumes_size
    if file_size > _MAX_V30_INNER_SIZE:
        raise ValueError("prefetch record is too large for the bounded v30 profile")

    executable_field = _utf16_string(executable_name).ljust(
        EXECUTABLE_FILENAME_SIZE,
        b"\x00",
    )
    header = _u32(30) + b"SCCA" + _u32(0, file_size)
    header += executable_field
    header += _u32(prefetch_vista_name_hash(path), 0)

    file_information = _u32(
        metrics_offset,
        1,
        trace_chain_offset,
        1,
        filename_strings_offset,
        len(filename_strings),
        volumes_offset,
        1,
        volumes_size,
    )
    file_information += bytes(8)
    file_information += struct.pack("<Q", last_run_filetime) + bytes(7 * 8)
    file_information += bytes(16)
    file_information += _u32(run_count) + bytes(92)

    if (
        len(header) != HEADER_SIZE
        or len(file_information) != V30_FILE_INFORMATION_SIZE
        or len(metrics) != V30_METRICS_ENTRY_SIZE
        or len(trace_chain) != V30_TRACE_CHAIN_ENTRY_SIZE
        or len(volume) != V30_VOLUME_INFORMATION_SIZE + len(volume_device_path)
    ):
        raise RuntimeError("internal v30 Prefetch layout invariant failed")

    inner = header + file_information + metrics + trace_chain + filename_strings + volume
    if len(inner) != file_size:
        raise RuntimeError("internal v30 Prefetch size invariant failed")
    payload = compress_xpress_huffman(inner)
    return MAM_XPRESS_HUFFMAN_MAGIC + struct.pack("<I", len(inner)) + payload
