"""Minimal deterministic uncompressed SCCA v17 prefetch writer — validated by windowsprefetch.

Emits an uncompressed (pre-Win10) prefetch carrying the executable name, run count and
referenced-file path — the execution evidence. Real Win10 prefetch is MAM-compressed; that
compression is out of scope and disclosed as a Known Tell.
"""
from __future__ import annotations

import struct

FILETIME = 133497684000000000  # 2024-01-15T05:00:00Z, pinned


def _u32(*vals: int) -> bytes:
    return b"".join(struct.pack("<I", v) for v in vals)


def prefetch_name_hash(full_path: str) -> int:
    """A deterministic prefetch-style name hash (value is not verified by parsers)."""
    h = 0
    for ch in full_path.upper():
        h = (h * 37 + ord(ch)) & 0xFFFFFFFF
    return h


def build_prefetch(exe_name: str, full_path: str, run_count: int) -> bytes:
    exe = exe_name.upper()
    exe_field = (exe.encode("utf-16-le")[:58] + b"\x00\x00").ljust(60, b"\x00")[:60]
    filenames = (full_path.upper() + "\x00").encode("utf-16-le")
    volname = "\\DEVICE\\HARDDISKVOLUME1"
    volname_utf16 = volname.encode("utf-16-le")

    HEADER, FILEINFO, METRICS, TRACE = 84, 68, 20, 12
    metrics_off = HEADER + FILEINFO
    trace_off = metrics_off + METRICS
    fnstr_off = trace_off + TRACE
    fnstr_size = len(filenames)
    vol_off = fnstr_off + fnstr_size
    vol_size = 40 + len(volname_utf16)

    header = _u32(17) + b"SCCA" + _u32(0, 0)  # version, signature, unknown0, fileSize (patched)
    header += exe_field + struct.pack("<I", prefetch_name_hash(full_path)) + _u32(0)

    fileinfo = _u32(metrics_off, 1, trace_off, 1, fnstr_off, fnstr_size, vol_off, 1, vol_size)
    fileinfo += struct.pack("<Q", FILETIME) + b"\x00" * 16 + struct.pack("<I", run_count) + b"\x00" * 4

    metrics = _u32(0, 0, 0, len(exe)) + b"\x00" * 4      # one metrics entry
    trace = b"\x00" * 12                                  # one (unparsed) trace-chain entry

    vol = struct.pack("<II", 40, len(volname))           # volPathOffset, volPathLength (chars)
    vol += struct.pack("<Q", FILETIME)                    # volCreationTime
    vol += struct.pack("<I", 0x1234ABCD)                  # volSerialNumber
    vol += _u32(0, 0, 40 + len(volname_utf16), 0, 0)      # fileRefs + dirStrings(count 0) + unknown
    vol += volname_utf16

    body = header + fileinfo + metrics + trace + filenames + vol
    return body[:12] + struct.pack("<I", len(body)) + body[16:]  # patch fileSize @ offset 12
