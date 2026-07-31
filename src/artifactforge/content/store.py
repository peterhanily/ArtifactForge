# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Content-first identity — the keystone.

Synthesize a file's real bytes once from a seed; every hash-shaped field in every artifact —
Amcache FileId, the digest on disk, a YARA target, IMPHASH on Windows, symhash on macOS — is
then a real digest of those same bytes and that same import table. They agree by construction
rather than by assertion, which is the fix for EvidenceForge computing a file's "hashes" as
digests of a per-emitter seed string.

Bytes are a pure function of the seed, so the same identity regenerates byte-identical
forever. Both writers are hand-assembled rather than driven by a toolchain or by LIEF,
neither of which promises determinism.

Everything generated here is inert: the code section is a single return instruction and
nothing else. See artifactforge.gates.inertness, which checks that on the emitted bytes.
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

from artifactforge.content.seed import prng_bytes as _prng_bytes
from artifactforge.content.seed import sub_seed as _sub_seed


# Realistic benign import pool; the seed picks a deterministic subset so IMPHASH varies
# per file while staying a pure function of the seed. Names only (no ordinals).
_IMPORT_POOL = [
    ("kernel32.dll", ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "GetProcAddress",
                      "LoadLibraryA", "VirtualAlloc", "GetModuleHandleA", "ExitProcess", "Sleep"]),
    ("advapi32.dll", ["RegOpenKeyExA", "RegSetValueExA", "RegCloseKey", "OpenProcessToken"]),
    ("user32.dll", ["MessageBoxA", "wsprintfA", "GetDesktopWindow"]),
    ("ws2_32.dll", ["WSAStartup", "socket", "connect", "send", "recv"]),
]


def _pick_imports(content_seed: bytes):
    r = _prng_bytes(_sub_seed(content_seed, "imports"), 64)
    picked = []
    for i, (dll, funcs) in enumerate(_IMPORT_POOL):
        if i == 0 or (r[i] & 1):  # always include kernel32
            chosen = [funcs[j] for j in range(len(funcs)) if (r[16 + i * 8 + j] & 1)]
            if len(chosen) < 2:
                chosen = funcs[:2]
            picked.append((dll, chosen))
    return picked


def imphash_of(imports) -> str:
    """Replicate pefile.get_imphash for a name-only import list (validated against pefile)."""
    parts = []
    for dll, funcs in imports:
        lib = dll.lower()
        head, _, ext = lib.rpartition(".")
        if head and ext in ("ocx", "sys", "dll"):
            lib = head
        for f in funcs:
            parts.append(f"{lib}.{f.lower()}")
    return hashlib.md5(",".join(parts).encode()).hexdigest()


def _assemble_pe(content_seed: bytes, imports) -> bytes:
    IMAGE_BASE = 0x140000000
    RDATA_RVA, RDATA_RAW = 0x2000, 0x600
    n = len(imports)

    # Lay out the import blob at RDATA_RVA: IDT | ILTs | IATs | dll names | hint/name.
    idt_size = (n + 1) * 20
    cur = idt_size
    ilt_off, iat_off, dllname_off, hintname_off = {}, {}, {}, {}
    for i, (dll, funcs) in enumerate(imports):
        ilt_off[i] = cur
        cur += (len(funcs) + 1) * 8
    for i, (dll, funcs) in enumerate(imports):
        iat_off[i] = cur
        cur += (len(funcs) + 1) * 8
    for i, (dll, funcs) in enumerate(imports):
        dllname_off[i] = cur
        cur += len(dll) + 1 + ((len(dll) + 1) & 1)
    for i, (dll, funcs) in enumerate(imports):
        for f in funcs:
            hintname_off[(i, f)] = cur
            cur += 2 + len(f) + 1
            cur += cur & 1
    blob = bytearray(cur)

    def rva(off):
        return RDATA_RVA + off

    for i, (dll, funcs) in enumerate(imports):
        blob[i * 20:i * 20 + 20] = struct.pack("<IIIII", rva(ilt_off[i]), 0, 0, rva(dllname_off[i]), rva(iat_off[i]))
    for i, (dll, funcs) in enumerate(imports):
        for j, f in enumerate(funcs):
            thunk = struct.pack("<Q", rva(hintname_off[(i, f)]))
            blob[ilt_off[i] + j * 8:ilt_off[i] + j * 8 + 8] = thunk
            blob[iat_off[i] + j * 8:iat_off[i] + j * 8 + 8] = thunk
    for i, (dll, funcs) in enumerate(imports):
        blob[dllname_off[i]:dllname_off[i] + len(dll) + 1] = dll.encode() + b"\x00"
        for f in funcs:
            o = hintname_off[(i, f)]
            blob[o:o + 2 + len(f) + 1] = b"\x00\x00" + f.encode() + b"\x00"

    marker = b"ARTIFACTFORGE-SYNTHETIC-" + _prng_bytes(_sub_seed(content_seed, "marker"), 8).hex().encode()
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x0022)  # 2 sections
    opt = struct.pack("<H", 0x20B)              # Magic PE32+
    opt += struct.pack("<BB", 14, 0)            # linker version
    opt += struct.pack("<I", 0x200)             # SizeOfCode
    opt += struct.pack("<I", 0x200)             # SizeOfInitializedData
    opt += struct.pack("<I", 0)                 # SizeOfUninitializedData
    opt += struct.pack("<I", 0x1000)            # AddressOfEntryPoint
    opt += struct.pack("<I", 0x1000)            # BaseOfCode
    opt += struct.pack("<Q", IMAGE_BASE)        # ImageBase
    opt += struct.pack("<I", 0x1000)            # SectionAlignment
    opt += struct.pack("<I", 0x200)             # FileAlignment
    opt += struct.pack("<HH", 6, 0)             # OS version
    opt += struct.pack("<HH", 0, 0)             # Image version
    opt += struct.pack("<HH", 6, 0)             # Subsystem version
    opt += struct.pack("<I", 0)                 # Win32VersionValue
    opt += struct.pack("<I", 0x4000)            # SizeOfImage
    opt += struct.pack("<I", 0x400)             # SizeOfHeaders
    opt += struct.pack("<I", 0)                 # CheckSum
    opt += struct.pack("<H", 3)                 # Subsystem (CUI)
    opt += struct.pack("<H", 0x8160)            # DllCharacteristics
    opt += struct.pack("<Q", 0x100000)          # SizeOfStackReserve
    opt += struct.pack("<Q", 0x1000)            # SizeOfStackCommit
    opt += struct.pack("<Q", 0x100000)          # SizeOfHeapReserve
    opt += struct.pack("<Q", 0x1000)            # SizeOfHeapCommit
    opt += struct.pack("<I", 0)                 # LoaderFlags
    opt += struct.pack("<I", 16)                # NumberOfRvaAndSizes
    dd = [(0, 0)] * 16
    dd[1] = (RDATA_RVA, idt_size)               # Import Table directory
    for a, b in dd:
        opt += struct.pack("<II", a, b)
    assert len(opt) == 240, len(opt)

    def _section(name, vsize, rva_, rawsize, rawptr, chars):
        return name.ljust(8, "\x00").encode() + struct.pack(
            "<IIIIIIHHI", vsize, rva_, rawsize, rawptr, 0, 0, 0, 0, chars)

    rdata_rawsize = ((len(blob) + 0x1FF) // 0x200) * 0x200
    text = _section(".text", 0x200, 0x1000, 0x200, 0x400, 0x60000020)
    rdata = _section(".rdata", max(0x200, len(blob)), RDATA_RVA, rdata_rawsize, RDATA_RAW, 0x40000040)
    hdr = dos + coff + opt + text + rdata
    hdr += b"\x00" * (0x400 - len(hdr))
    code = b"\xC3" + b"\x00" * 0x1FF
    rdata_raw = bytes(blob) + b"\x00" * (rdata_rawsize - len(blob))
    overlay = marker + b"\x00" + _prng_bytes(_sub_seed(content_seed, "filler"), 128)
    return hdr + code + rdata_raw + overlay


def build_pe_stub(content_seed: bytes) -> bytes:
    """A structurally-valid, inert PE (single `ret`) with a real deterministic import table."""
    return _assemble_pe(content_seed, _pick_imports(content_seed))


@dataclass(frozen=True)
class Content:
    """One file's bytes and every identity a forensic artifact might quote about them."""

    bytes: bytes
    path: str
    fmt: str            # "pe" | "macho"
    sha256: str
    sha1: str
    md5: str
    marker: str
    imphash: str = ""   # PE only — md5 of the import table, as pefile computes it
    symhash: str = ""   # Mach-O only — md5 of the sorted undefined external symbols
    cdhash: str = ""    # Mach-O only — what `codesign -d` reports


#: A content_id is "<format>:<...>". The prefix selects the writer, and an unrecognised one
#: raises rather than falling through to PE — a `macho:` id quietly yielding a Windows binary
#: is the kind of bug that only surfaces in a parser months later.
#:
#: A Mach-O id is "macho:<signing identifier>:<...>". The signing identifier has to be part of
#: the identity because it lives inside the CodeDirectory, so it changes the file's length and
#: therefore its SHA256; passing it separately would break the content_id -> bytes contract.
KNOWN_FORMATS = ("pe", "macho")


class ContentStore:
    """content_id -> real bytes, content-addressed by sha256 (git-blob style).

    The cache is shared across every scenario in a suite, so the same logical file appearing
    in two scenes is written once. That makes cache hits real, which is why reads verify:
    a torn write from a full disk or two workers racing would otherwise be trusted forever
    while `Content.sha256` kept reporting the value the bytes no longer have.
    """

    def __init__(self, scenario_seed: str, cache_dir: str):
        self._root = _sub_seed(scenario_seed.encode(), "contentstore")
        self._cache = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _store(self, sha256: str, data: bytes) -> str:
        """Write content-addressed, atomically, and re-verify anything already there."""
        path = os.path.join(self._cache, sha256)
        if os.path.exists(path):
            with open(path, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() == sha256:
                    return path
            # Present but wrong: a torn write. Fall through and replace it.
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)                     # atomic within the same directory
        return path

    def materialize(self, content_id: str) -> Content:
        fmt = content_id.split(":", 1)[0]
        if fmt not in KNOWN_FORMATS:
            raise ValueError(
                f"unknown content_id format {fmt!r} in {content_id!r}; "
                f"known formats: {sorted(KNOWN_FORMATS)}")
        seed = _sub_seed(self._root, content_id)
        marker = "ARTIFACTFORGE-SYNTHETIC-" + _prng_bytes(_sub_seed(seed, "marker"), 8).hex()
        extra = {}
        if fmt == "pe":
            imports = _pick_imports(seed)
            data = _assemble_pe(seed, imports)
            extra["imphash"] = imphash_of(imports)
        else:
            from artifactforge.content import macho
            parts = content_id.split(":")
            if len(parts) < 3 or not parts[1]:
                raise ValueError(
                    f"a Mach-O content_id must be 'macho:<signing identifier>:<...>'; "
                    f"got {content_id!r}")
            imports = macho.pick_imports(seed)
            data = macho.build_macho(seed, imports, sign_identifier=parts[1])
            extra["symhash"] = macho.symhash_of(imports)
            extra["cdhash"] = macho.cdhash_of_file(data)
        sha256 = hashlib.sha256(data).hexdigest()
        return Content(data, self._store(sha256, data), fmt, sha256,
                       hashlib.sha1(data).hexdigest(), hashlib.md5(data).hexdigest(),
                       marker, **extra)
