# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Minimal deterministic uncompressed SCCA v17 prefetch writer — validated by libscca and windowsprefetch.

Emits an uncompressed (pre-Win10) prefetch carrying the executable name, run count and
referenced-file path — the execution evidence. The layout follows libyal's "Windows Prefetch
File (PF) format" specification for format version 17: an 84-byte file header, a 68-byte file
information block, a 20-byte-per-entry file metrics array, a 12-byte-per-entry trace chains
array, the filename strings, then the volumes information (a 40-byte volume entry followed by
that volume's device path).

Deliberately not implemented: MAM/LZXPRESS compression (real Windows 10 prefetch is
compressed), directory strings, multiple volumes and NTFS file references. Each omission is
signalled to a parser as a zero offset and a zero count, which is the encoding libscca treats
as "absent" and skips — rather than as a truncated block, which it treats as corruption.
"""
from __future__ import annotations

import struct

from artifactforge.disclosure import MARKER

FILETIME = 133497684000000000  # 2024-01-15T05:00:00Z, pinned

HEADER_SIZE = 84
FILE_INFORMATION_SIZE = 68            # v17; v23/v26/v30 are larger, hence the version field
EXECUTABLE_FILENAME_SIZE = 60         # fixed-width field inside the header
METRICS_ENTRY_SIZE = 20               # v17 file metrics array entry
TRACE_CHAIN_ENTRY_SIZE = 12           # v17 trace chain array entry
VOLUME_INFORMATION_SIZE = 40          # v17 volume information entry

DEVICE_PATH = "\\DEVICE\\HARDDISKVOLUME1"
VOLUME_SERIAL_NUMBER = 0x1234ABCD     # pinned; nothing here derives it from the host


def _u32(*vals: int) -> bytes:
    return b"".join(struct.pack("<I", v) for v in vals)


def _utf16_string(value: str) -> bytes:
    """UTF-16LE with the end-of-string character the format requires on every string."""
    return (value + "\x00").encode("utf-16-le")


def prefetch_name_hash(full_path: str) -> int:
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


def build_prefetch(exe_name: str, full_path: str, run_count: int) -> bytes:
    exe = exe_name.upper()
    path = full_path.upper()

    # The header's executable filename is a fixed 60-byte field holding "an UTF-16
    # little-endian string with end-of-string character", so at most 29 characters fit.
    # libscca scans the field for the NUL pair and falls back to all 30 characters when it
    # finds none, so the terminator is what makes a long name truncate predictably.
    exe_field = (exe.encode("utf-16-le")[:EXECUTABLE_FILENAME_SIZE - 2] + b"\x00\x00").ljust(
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

    metrics_offset = HEADER_SIZE + FILE_INFORMATION_SIZE          # spec fixes this at 152 for v17
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
    header += exe_field + struct.pack("<I", prefetch_name_hash(full_path)) + _u32(0)

    fileinfo = _u32(
        metrics_offset, 1,
        trace_chain_offset, 1,
        filename_strings_offset, len(filename_strings),
        volumes_offset, 1, volumes_size,
    )
    fileinfo += struct.pack("<Q", FILETIME) + b"\x00" * 16
    fileinfo += struct.pack("<I", run_count & 0xFFFFFFFF) + _u32(0)

    # The filename string offset is relative to the start of the filename strings block, and
    # libscca resolves it by matching the recorded start offset of a string exactly.
    metrics = _u32(0, 1, 0, path_characters, 0)

    # Only the first field is meaningful here: 0xFFFFFFFF terminates the chain, as it does in
    # the last entry of a real file. libscca reads this array in debug builds only.
    trace_chain = _u32(0xFFFFFFFF, 1) + bytes(4)

    volume = _u32(device_path_offset, device_path_characters)
    volume += struct.pack("<Q", FILETIME) + _u32(VOLUME_SERIAL_NUMBER)
    volume += _u32(0, 0)      # no file references: a zero offset makes libscca skip the block
    volume += _u32(0, 0)      # no directory strings, likewise — a non-zero offset here is
                              # bounds-checked against the block and would be rejected
    volume += _u32(0)         # unknown1
    volume += device_path

    return header + fileinfo + metrics + trace_chain + filename_strings + volume
