# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Content-first identity for materialized binaries — the keystone.

Synthesize a binary's bytes once from a seed. SHA256, SHA1 and MD5 are then computed from those
bytes; IMPHASH and symhash are computed from the import or symbol structures written into them,
and cdhash from the embedded CodeDirectory. Callers that reuse one ``Content`` object therefore
reuse one file identity. This claim is deliberately about materialized ``Content`` instances,
not every hash-shaped decoy field a composed scene may carry.

Bytes are pure functions of the seed under the declared content-writer ABI, so the same identity
regenerates byte-identically within that contract. A byte-affecting writer change requires an
explicit ABI transition; this is not a cross-version promise. The writers are hand-assembled
rather than driven by a toolchain or by LIEF, neither of which promises determinism.

The native code emitted here is payload-free: PE ``.text`` is ``ret`` plus zero padding, while
Mach-O ``__text`` is ``mov w0,#0 ; ret`` and ELF ``.text`` is a direct ``exit(0)`` syscall. The
PE also carries the fixed DOS print-and-exit stub. See ``artifactforge.gates.inertness`` for
the exact checks and their current scope.
"""
from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
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

# Every PE in the bounded writer profile reserves the same on-disk .rdata extent.  Import
# selection is intentionally variable (that is what makes IMPHASH useful), but file length is
# not semantic evidence and must not reveal which candidate a benchmark relation names.  The
# complete import pool fits in 0x400 bytes; _assemble_pe checks that invariant before writing.
_PE_RDATA_RAW_SIZE = 0x400


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


# The MS-DOS header and stub every Windows compiler has emitted for thirty years. Reproduced
# byte-for-byte rather than zero-filled, because a PE without them is trivially distinguishable
# from a real one: the community YARA rule `HasModified_DOS_Message` fires on every binary that
# omits the message, and a responder's tooling reads the header fields.
#
# The field values are MSVC's: 3 pages of 0x90 trailing bytes, a 4-paragraph header, a stack
# pointer of 0xB8, and e_lfanew pointing past the stub at 0x80.
DOS_HEADER = (
    b"MZ"                                  # e_magic
    + struct.pack("<13H",
                  0x90,                    # e_cblp      bytes on the last page
                  3,                       # e_cp        pages in the DOS image
                  0,                       # e_crlc      relocations
                  4,                       # e_cparhdr   header size, in 16-byte paragraphs
                  0,                       # e_minalloc
                  0xFFFF,                  # e_maxalloc
                  0,                       # e_ss
                  0xB8,                    # e_sp        initial stack pointer
                  0,                       # e_csum
                  0,                       # e_ip
                  0,                       # e_cs
                  0x40,                    # e_lfarlc    relocation table offset
                  0)                       # e_ovno      overlay number
    + b"\x00" * 8                          # e_res[4]
    + struct.pack("<2H", 0, 0)             # e_oemid, e_oeminfo
    + b"\x00" * 20                         # e_res2[10]
    + struct.pack("<I", 0x80))             # e_lfanew    the PE header, past the stub

# Fixed 16-bit real-mode DOS-stub code, separate from `.text`'s `ret` plus zero padding:
#   push cs / pop ds        DS := CS, so DS:DX addresses the message
#   mov dx, 0x000E          offset of the message within the DOS image
#   mov ah, 9 / int 21h     DOS "print $-terminated string"
#   mov ax, 0x4C01 / int 21h  DOS "terminate with exit code 1"
# It prints a sentence and exits. Gate 3 requires these bytes exactly, so nothing else can be
# smuggled into the one place in a PE where arbitrary code is conventional.
DOS_STUB_CODE = bytes.fromhex("0E1FBA0E00B409CD21B8014CCD21")
DOS_STUB_MESSAGE = b"This program cannot be run in DOS mode.\r\r\n$"
DOS_STUB = (DOS_STUB_CODE + DOS_STUB_MESSAGE).ljust(0x40, b"\x00")


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
    dos = DOS_HEADER + DOS_STUB
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x0022)  # 2 sections
    opt = struct.pack("<H", 0x20B)              # Magic PE32+
    opt += struct.pack("<BB", 14, 0)            # linker version
    opt += struct.pack("<I", 0x200)             # SizeOfCode
    opt += struct.pack("<I", _PE_RDATA_RAW_SIZE)  # SizeOfInitializedData
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

    if len(blob) > _PE_RDATA_RAW_SIZE:
        raise ValueError(
            f"PE import blob is {len(blob)} bytes, outside the fixed "
            f"{_PE_RDATA_RAW_SIZE}-byte .rdata profile"
        )
    rdata_rawsize = _PE_RDATA_RAW_SIZE
    text = _section(".text", 0x200, 0x1000, 0x200, 0x400, 0x60000020)
    rdata = _section(".rdata", max(0x200, len(blob)), RDATA_RVA, rdata_rawsize, RDATA_RAW, 0x40000040)
    hdr = dos + coff + opt + text + rdata
    hdr += b"\x00" * (0x400 - len(hdr))
    code = b"\xC3" + b"\x00" * 0x1FF
    rdata_raw = bytes(blob) + b"\x00" * (rdata_rawsize - len(blob))
    overlay = marker + b"\x00" + _prng_bytes(_sub_seed(content_seed, "filler"), 128)
    return hdr + code + rdata_raw + overlay


def build_pe_stub(content_seed: bytes) -> bytes:
    """A structurally valid, payload-free PE with a real deterministic import table."""
    return _assemble_pe(content_seed, _pick_imports(content_seed))


@dataclass(frozen=True)
class Content:
    """One file's bytes and every identity a forensic artifact might quote about them."""

    bytes: bytes
    path: str
    fmt: str            # "pe" | "macho" | "elf"
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
KNOWN_FORMATS = ("pe", "macho", "elf")

_CACHE_FILE_MODE = 0o600
_CACHE_TEMP_ATTEMPTS = 64
_CACHE_VERIFY_ATTEMPTS = 128
_CACHE_STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _cache_failure(message: str, error: BaseException | None = None) -> RuntimeError:
    failure = RuntimeError(f"unsafe content cache: {message}")
    if error is not None:
        failure.__cause__ = error
    return failure


def _same_state(first: os.stat_result, second: os.stat_result) -> bool:
    return all(
        getattr(first, field) == getattr(second, field)
        for field in _CACHE_STABLE_FIELDS
    )


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise _cache_failure(
            "this platform lacks O_NOFOLLOW/O_DIRECTORY; secure cache I/O is unsupported"
        )
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory


def _file_flags(access: int) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise _cache_failure("this platform lacks O_NOFOLLOW; secure cache I/O is unsupported")
    return access | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0) | nofollow


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise _cache_failure("a temporary-file write made no progress")
        view = view[written:]


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    """Read no more than ``maximum + 1`` bytes from an already-pinned file."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while total <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _sync_directory(descriptor: int) -> None:
    """Persist a directory entry where the host filesystem implements directory fsync."""
    try:
        os.fsync(descriptor)
    except OSError as exc:
        # Some otherwise POSIX-like filesystems reject fsync on a directory. The file inode
        # has already been synced; this is the only durability guarantee unavailable there.
        unsupported = {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}
        if exc.errno not in unsupported:
            raise


def _entry_matches(cache_fd: int, name: str, sha256: str, expected: bytes) -> bool:
    """Verify one named cache entry without ever following or trusting its path."""
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != _CACHE_FILE_MODE
            or before.st_size != len(expected)
        ):
            return False
        descriptor = os.open(name, _file_flags(os.O_RDONLY), dir_fd=cache_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(before, opened):
            return False
        payload = _read_descriptor(descriptor, len(expected))
        after_read = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (NotImplementedError, OSError):
        # A link swap, concurrent replacement or unreadable corrupt entry is a miss. It is
        # repaired only by an atomic rename through the pinned cache descriptor below.
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return (
        _same_state(before, opened)
        and _same_state(opened, after_read)
        and _same_state(after_read, after_path)
        and payload == expected
        and hashlib.sha256(payload).hexdigest() == sha256
    )


def _temporary_is_verified(
    cache_fd: int,
    name: str,
    descriptor: int,
    sha256: str,
    expected: bytes,
) -> bool:
    before_read = os.fstat(descriptor)
    payload = _read_descriptor(descriptor, len(expected))
    after_read = os.fstat(descriptor)
    named = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
    return (
        stat.S_ISREG(after_read.st_mode)
        and after_read.st_nlink == 1
        and stat.S_IMODE(after_read.st_mode) == _CACHE_FILE_MODE
        and after_read.st_size == len(expected)
        and _same_state(before_read, after_read)
        and _same_state(after_read, named)
        and payload == expected
        and hashlib.sha256(payload).hexdigest() == sha256
    )


class ContentStore:
    """content_id -> real bytes, content-addressed by sha256 (git-blob style).

    The cache is shared across every scenario in a suite, so the same logical file appearing
    in two scenes is written once. That makes cache hits real, which is why reads verify:
    a torn write from a full disk or two workers racing would otherwise be trusted forever
    while `Content.sha256` kept reporting the value the bytes no longer have.
    """

    def __init__(self, scenario_seed: str, cache_dir: str):
        self._root = _sub_seed(scenario_seed.encode(), "contentstore")
        self._cache = os.fspath(cache_dir)
        if not isinstance(self._cache, str):
            raise TypeError("content cache path must be text, not bytes")
        requested = os.path.normpath(os.path.abspath(self._cache))
        cache_name = os.path.basename(requested)
        if not cache_name or cache_name in {".", ".."}:
            raise ValueError("content cache must have one non-empty final path component")
        self._cache_name = cache_name
        self._cache_requested = requested
        self._cache_parent = os.path.realpath(os.path.dirname(requested))
        os.makedirs(self._cache, mode=0o700, exist_ok=True)

        # mkdir modes are masked by the process umask.  Repair only the final cache entry
        # through a held parent descriptor and refuse links/replacements around the chmod;
        # this stays usable even under umask 0777 without ever chmodding through a pathname.
        mode_parent_fd = -1
        try:
            mode_parent_fd = os.open(self._cache_parent, _directory_flags())
            before_mode = os.stat(
                self._cache_name,
                dir_fd=mode_parent_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(before_mode.st_mode) or not stat.S_ISDIR(before_mode.st_mode):
                raise _cache_failure("cache path is not a real directory")
            os.chmod(
                self._cache_name,
                0o700,
                dir_fd=mode_parent_fd,
                follow_symlinks=False,
            )
            after_mode = os.stat(
                self._cache_name,
                dir_fd=mode_parent_fd,
                follow_symlinks=False,
            )
            if (
                not _same_identity(before_mode, after_mode)
                or stat.S_IMODE(after_mode.st_mode) != 0o700
            ):
                raise _cache_failure("cache directory changed while setting its mode")
        except RuntimeError:
            raise
        except (NotImplementedError, OSError) as exc:
            raise _cache_failure("cannot set the private cache directory mode", exc) from exc
        finally:
            if mode_parent_fd >= 0:
                os.close(mode_parent_fd)

        parent_fd = cache_fd = -1
        try:
            parent_fd, cache_fd = self._open_cache(expected=False)
            os.fchmod(cache_fd, 0o700)
            parent_state = os.fstat(parent_fd)
            cache_state = os.fstat(cache_fd)
            self._parent_identity = parent_state.st_dev, parent_state.st_ino
            self._cache_identity = cache_state.st_dev, cache_state.st_ino
            self._verify_cache_binding(parent_fd, cache_fd)
        finally:
            if cache_fd >= 0:
                os.close(cache_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    def _open_cache(self, *, expected: bool = True) -> tuple[int, int]:
        """Open the cache and its parent as a stable, non-link descriptor pair."""
        parent_fd = cache_fd = -1
        try:
            parent_before = os.stat(self._cache_parent, follow_symlinks=False)
            if stat.S_ISLNK(parent_before.st_mode) or not stat.S_ISDIR(parent_before.st_mode):
                raise _cache_failure("resolved cache parent is not a real directory")
            parent_fd = os.open(self._cache_parent, _directory_flags())
            parent_opened = os.fstat(parent_fd)
            parent_after = os.stat(self._cache_parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_opened.st_mode)
                or not _same_identity(parent_before, parent_opened)
                or not _same_identity(parent_opened, parent_after)
            ):
                raise _cache_failure("cache parent changed while it was being opened")

            cache_before = os.stat(
                self._cache_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(cache_before.st_mode) or not stat.S_ISDIR(cache_before.st_mode):
                raise _cache_failure("cache path is not a real directory")
            cache_fd = os.open(
                self._cache_name,
                _directory_flags(),
                dir_fd=parent_fd,
            )
            cache_opened = os.fstat(cache_fd)
            cache_after = os.stat(
                self._cache_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(cache_opened.st_mode)
                or not _same_identity(cache_before, cache_opened)
                or not _same_identity(cache_opened, cache_after)
            ):
                raise _cache_failure("cache directory changed while it was being opened")
            if expected and (
                (parent_opened.st_dev, parent_opened.st_ino) != self._parent_identity
                or (cache_opened.st_dev, cache_opened.st_ino) != self._cache_identity
            ):
                raise _cache_failure("cache directory or its parent was replaced")
            return parent_fd, cache_fd
        except RuntimeError:
            if cache_fd >= 0:
                os.close(cache_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
            raise
        except (NotImplementedError, OSError) as exc:
            if cache_fd >= 0:
                os.close(cache_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
            raise _cache_failure(f"cannot safely open {self._cache_requested!r}", exc) from exc

    def _verify_cache_binding(self, parent_fd: int, cache_fd: int) -> None:
        """Prove both held directories still have the names the caller will receive."""
        try:
            parent_opened = os.fstat(parent_fd)
            parent_path = os.stat(self._cache_parent, follow_symlinks=False)
            cache_opened = os.fstat(cache_fd)
            cache_in_parent = os.stat(
                self._cache_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            requested_path = os.stat(self._cache_requested, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise _cache_failure("cannot post-verify the cache directory binding", exc) from exc
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or not stat.S_ISDIR(cache_opened.st_mode)
            or not _same_identity(parent_opened, parent_path)
            or not _same_identity(cache_opened, cache_in_parent)
            or not _same_identity(cache_opened, requested_path)
            or (parent_opened.st_dev, parent_opened.st_ino) != self._parent_identity
            or (cache_opened.st_dev, cache_opened.st_ino) != self._cache_identity
        ):
            raise _cache_failure("cache directory binding changed during I/O")

    @staticmethod
    def _new_temporary(cache_fd: int) -> tuple[str, int]:
        flags = _file_flags(os.O_RDWR) | os.O_CREAT | os.O_EXCL
        for _attempt in range(_CACHE_TEMP_ATTEMPTS):
            name = f".artifactforge-content-{secrets.token_hex(16)}.tmp"
            try:
                return name, os.open(name, flags, _CACHE_FILE_MODE, dir_fd=cache_fd)
            except FileExistsError:
                continue
            except (NotImplementedError, OSError) as exc:
                raise _cache_failure("cannot create an exclusive private temporary file", exc) from exc
        raise _cache_failure("cannot allocate an exclusive private temporary file")

    def _verified_entry(
        self,
        parent_fd: int,
        cache_fd: int,
        sha256: str,
        data: bytes,
        *,
        attempts: int = 1,
    ) -> bool:
        for _attempt in range(attempts):
            if not _entry_matches(cache_fd, sha256, sha256, data):
                continue
            self._verify_cache_binding(parent_fd, cache_fd)
            # The binding check is deliberately bracketed by entry reads. A directory swap
            # after the first read must not turn the returned path into a different object.
            if _entry_matches(cache_fd, sha256, sha256, data):
                # The second entry read itself is a race window because it uses the held old
                # directory descriptor. Recheck the public pathname after that read before
                # returning it. A pathname can of course be replaced after return; callers
                # needing a continuously pinned object must open and retain their own fd.
                self._verify_cache_binding(parent_fd, cache_fd)
                return True
        return False

    def _store(self, sha256: str, data: bytes) -> str:
        """Durably publish one verified inode through a pinned cache directory."""
        if not isinstance(data, bytes):
            raise TypeError("content cache payload must be bytes")
        actual = hashlib.sha256(data).hexdigest()
        if sha256 != actual:
            raise ValueError(
                f"content cache address {sha256!r} does not match payload SHA256 {actual}"
            )
        # Return the absolute, descriptor-bound cache location. Retaining the caller's
        # relative spelling here made an otherwise safe publication appear to move when the
        # process changed working directory after construction.
        path = os.path.join(self._cache_parent, self._cache_name, sha256)
        parent_fd = cache_fd = temporary_fd = -1
        temporary_name: str | None = None
        published = False
        try:
            parent_fd, cache_fd = self._open_cache()
            if self._verified_entry(parent_fd, cache_fd, sha256, data):
                return path

            temporary_name, temporary_fd = self._new_temporary(cache_fd)
            _write_all(temporary_fd, data)
            os.fchmod(temporary_fd, _CACHE_FILE_MODE)
            os.fsync(temporary_fd)
            if not _temporary_is_verified(
                cache_fd,
                temporary_name,
                temporary_fd,
                sha256,
                data,
            ):
                raise _cache_failure("temporary bytes changed before publication")

            # A writer that arrived first may already have published the same bytes. Reusing
            # that verified inode avoids needless replacement while retaining lock-free
            # concurrent generation.
            if self._verified_entry(parent_fd, cache_fd, sha256, data):
                return path
            self._verify_cache_binding(parent_fd, cache_fd)
            try:
                os.replace(
                    temporary_name,
                    sha256,
                    src_dir_fd=cache_fd,
                    dst_dir_fd=cache_fd,
                )
            except (NotImplementedError, OSError) as exc:
                raise _cache_failure("cannot atomically publish content", exc) from exc
            published = True
            _sync_directory(cache_fd)

            # Do not insist that the name still identifies our temporary inode: another safe
            # writer may atomically publish identical bytes immediately after us. The content
            # address, exact bytes, file type, link count and mode are the shared invariant.
            if not self._verified_entry(
                parent_fd,
                cache_fd,
                sha256,
                data,
                attempts=_CACHE_VERIFY_ATTEMPTS,
            ):
                raise _cache_failure("published content failed byte or path verification")
            return path
        except RuntimeError:
            raise
        except (NotImplementedError, OSError) as exc:
            if published:
                raise _cache_failure(
                    "content was published but its verification or durability is uncertain",
                    exc,
                ) from exc
            raise _cache_failure("content publication failed", exc) from exc
        finally:
            if temporary_name is not None and not published and cache_fd >= 0:
                try:
                    named = os.stat(
                        temporary_name,
                        dir_fd=cache_fd,
                        follow_symlinks=False,
                    )
                    held = os.fstat(temporary_fd)
                    if stat.S_ISREG(named.st_mode) and _same_identity(named, held):
                        os.unlink(temporary_name, dir_fd=cache_fd)
                except OSError:
                    pass
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if cache_fd >= 0:
                os.close(cache_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

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
        elif fmt == "macho":
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
        else:
            from artifactforge.content.elf import build_elf

            data = build_elf(seed)
        sha256 = hashlib.sha256(data).hexdigest()
        return Content(data, self._store(sha256, data), fmt, sha256,
                       hashlib.sha1(data).hexdigest(), hashlib.md5(data).hexdigest(),
                       marker, **extra)
