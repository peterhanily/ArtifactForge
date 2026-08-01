# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""A hand-assembled, byte-deterministic arm64 Mach-O — the macOS half of the keystone.

Same discipline as the PE writer next door: pure stdlib, every byte a function of the seed,
so the same content identity regenerates identically forever. Nothing here calls a clock,
reads entropy, or shells out to a toolchain.

It is a real binary rather than a token file. It carries a genuine LC_SYMTAB whose undefined
external symbols yield a real, seed-deterministic **symhash** — the Mach-O analogue of the
PE's IMPHASH, and the same value threatstream/symhash and yara-x compute — and a real ad-hoc
code signature whose **cdhash** is what `codesign -d` reports. LIEF and macholib parse it,
`otool` and `nm` read it, and `codesign -v` certifies it. Without a signature an arm64 binary
is not loadable at all, and signing it afterwards would rewrite the bytes, so the signature is
computed in-process: the CodeDirectory is sized with zeroed hashes first, then the finished
file is hashed in 16 KiB pages and the real blob written into the space reserved for it.

Payload-free by construction: __text is `mov w0, #0 ; ret` and nothing else — the arm64
analogue of the PE's single 0xC3. No other native instructions are emitted; the synthetic
marker string lives in __cstring.

Known tells, disclosed rather than hidden: ld64 on a 2024-era toolchain emits
LC_DYLD_CHAINED_FIXUPS, LC_FUNCTION_STARTS, LC_DATA_IN_CODE and an exports trie, and this
writer emits none of them — it uses the older LC_DYLD_INFO_ONLY bind stream. The binary is
thin arm64 rather than a universal fat file.
"""
from __future__ import annotations

import hashlib
import struct

from artifactforge.content.seed import prng_bytes, sub_seed

# ---------------------------------------------------------------- constants
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0x00000000
MH_EXECUTE = 0x2
MH_DYLDLINK, MH_TWOLEVEL, MH_PIE = 0x4, 0x80, 0x200000

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_LOAD_DYLIB = 0x0C
LC_LOAD_DYLINKER = 0x0E
LC_UUID = 0x1B
LC_SOURCE_VERSION = 0x2A
LC_MAIN = 0x80000028
LC_BUILD_VERSION = 0x32

S_REGULAR = 0x0
S_CSTRING_LITERALS = 0x2
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

N_EXT, N_UNDF, N_SECT = 0x01, 0x00, 0x0E
REFERENCED_DYNAMICALLY = 0x10

PAGE = 0x4000                    # arm64 macOS page size (16 KiB)
VM_BASE = 0x100000000            # standard PIE image base above __PAGEZERO
ARM64_RET = 0xD65F03C0           # `ret`
ARM64_MOV_W0_0 = 0x52800000      # `mov w0, #0` -- deterministic exit status
LD64_DYLIB_TIMESTAMP = 2         # what ld64 hard-codes; NOT a wall clock

# Realistic benign macOS import pool. Names carry the leading `_` exactly as they appear
# in the Mach-O string table (that is the form symhash hashes).
_IMPORT_POOL = [
    ("/usr/lib/libSystem.B.dylib", (1356, 0, 0), (1, 0, 0),
     ["_open", "_read", "_write", "_close", "_malloc", "_free", "_printf",
      "_getpid", "_dlopen", "_dlsym", "_socket", "_connect"]),
    ("/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
     (2503, 1, 0), (150, 0, 0),
     ["_CFRelease", "_CFStringCreateWithCString", "_CFURLCreateWithString",
      "_CFDataGetBytePtr"]),
    ("/System/Library/Frameworks/Security.framework/Versions/A/Security",
     (61439, 0, 0), (1, 0, 0),
     ["_SecItemCopyMatching", "_SecKeychainFindGenericPassword", "_SecCodeCopySigningInformation"]),
    ("/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
     (2503, 1, 0), (300, 0, 0),
     ["_NSLog", "_NSHomeDirectory"]),
]


def pick_imports(content_seed: bytes):
    """Deterministic subset of the pool -> (dylib, cur_ver, compat_ver, [symbols])."""
    r = prng_bytes(sub_seed(content_seed, "macho-imports"), 64)
    picked = []
    for i, (dylib, cur, compat, syms) in enumerate(_IMPORT_POOL):
        if i == 0 or (r[i] & 1):                     # libSystem is always linked
            chosen = [s for j, s in enumerate(syms) if (r[16 + i * 12 + j] & 1)]
            if len(chosen) < 2:
                chosen = syms[:2]
            picked.append((dylib, cur, compat, chosen))
    return picked


def symhash_of(imports) -> str:
    """threatstream/symhash: md5 of the sorted, comma-joined UNDEFINED EXTERNAL symbol names.

    Verbatim from symhash/__init__.py:64 --
        symhash = md5(','.join(sorted(sym_list)).encode()).hexdigest()
    where sym_list holds every LC_SYMTAB symbol with  not is_stab  and  external is True
    and  (n_type & N_TYPE) == N_UNDF.  No lowercasing, no dedup, no dylib name.
    """
    names = [s for (_d, _c, _p, syms) in imports for s in syms]
    return hashlib.md5(",".join(sorted(names)).encode()).hexdigest()


def _ver32(t):
    return (t[0] << 16) | (t[1] << 8) | t[2]


def _macho_uuid(content_seed: bytes) -> bytes:
    """Pinned, seed-derived. Bit-fixed to version 3 / RFC-4122 variant, which is what
    ld64 stamps (see `otool -l` on any clang binary: ...-3CFE-8E31-...)."""
    b = bytearray(hashlib.sha256(sub_seed(content_seed, "macho-uuid")).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x30
    b[8] = (b[8] & 0x3F) | 0x80
    return bytes(b)


def _seg(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, sects, flags=0):
    body = b"".join(sects)
    cmdsize = 72 + len(body)
    return struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, cmdsize, name.encode(),
                       vmaddr, vmsize, fileoff, filesize, maxprot, initprot,
                       len(sects), flags) + body


def _sect(sectname, segname, addr, size, offset, align, flags, r1=0, r2=0):
    return struct.pack("<16s16sQQIIIIIIII", sectname.encode(), segname.encode(),
                       addr, size, offset, align, 0, 0, flags, r1, r2, 0)


def _dylib_cmd(path, cur, compat):
    raw = path.encode() + b"\x00"
    pad = (-len(raw)) % 8
    cmdsize = 24 + len(raw) + pad
    return struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, LD64_DYLIB_TIMESTAMP,
                       _ver32(cur), _ver32(compat)) + raw + b"\x00" * pad


LC_DYLD_INFO_ONLY = 0x80000022


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _bind_opcodes(undef, got_seg_index: int) -> bytes:
    """Classic dyld bind stream that wires each __got slot to its dylib symbol.

    BIND_OPCODE_DO_BIND advances the write cursor by one pointer, so the slots are
    bound in __got order -- the exact order of the indirect symbol table.
    """
    s = bytearray()
    s += bytes([0x50 | 1])                                   # SET_TYPE_IMM  BIND_TYPE_POINTER
    s += bytes([0x70 | got_seg_index]) + _uleb(0)            # SET_SEGMENT_AND_OFFSET_ULEB
    for name, ordinal in undef:
        s += bytes([0x10 | ordinal])                         # SET_DYLIB_ORDINAL_IMM
        s += bytes([0x40 | 0]) + name.encode() + b"\x00"     # SET_SYMBOL_TRAILING_FLAGS_IMM
        s += bytes([0x90])                                   # DO_BIND
    s += bytes([0x00])                                       # DONE
    return bytes(s) + b"\x00" * ((-len(s)) % 8)


LC_CODE_SIGNATURE = 0x1D
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CS_ADHOC = 0x2
CS_EXECSEG_MAIN_BINARY = 0x1
CS_PAGE_LOG2 = 14                # arm64 macOS code-signing page = 16 KiB
CD_FIXED = 88                    # sizeof CodeDirectory header at version 0x20400


def _codedirectory(ident: str, code_limit: int, page_hashes, req_hash: bytes,
                   exec_seg_limit: int) -> bytes:
    ident_b = ident.encode() + b"\x00"
    n_special = 2                                     # -1 Info.plist (zero), -2 Requirements
    n_code = len(page_hashes)
    ident_off = CD_FIXED
    hash_off = ident_off + len(ident_b) + n_special * 32
    length = hash_off + n_code * 32
    cd = struct.pack(">IIIIIIIIIBBBBIIIIQQQQ",
                     CSMAGIC_CODEDIRECTORY, length, 0x20400, CS_ADHOC,
                     hash_off, ident_off, n_special, n_code, code_limit,
                     32, 2, 0, CS_PAGE_LOG2,           # hashSize, hashType=SHA256, platform, pageSize
                     0, 0, 0, 0,                       # spare2, scatterOffset, teamOffset, spare3
                     0, 0, exec_seg_limit, CS_EXECSEG_MAIN_BINARY)
    assert len(cd) == CD_FIXED, len(cd)
    return (cd + ident_b
            + req_hash + b"\x00" * 32                 # slot -2 then slot -1 (Info.plist absent)
            + b"".join(page_hashes))


def _superblob(ident: str, code_limit: int, page_hashes, exec_seg_limit: int) -> bytes:
    req = struct.pack(">III", CSMAGIC_REQUIREMENTS, 12, 0)      # empty requirement set
    sig = struct.pack(">II", CSMAGIC_BLOBWRAPPER, 8)            # ad-hoc: no CMS payload
    cd = _codedirectory(ident, code_limit, page_hashes,
                        hashlib.sha256(req).digest(), exec_seg_limit)
    idx_sz = 12 + 3 * 8
    cd_off = idx_sz
    req_off = cd_off + len(cd)
    sig_off = req_off + len(req)
    total = sig_off + len(sig)
    return (struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, total, 3)
            + struct.pack(">II", 0, cd_off)              # CSSLOT_CODEDIRECTORY
            + struct.pack(">II", 2, req_off)             # CSSLOT_REQUIREMENTS
            + struct.pack(">II", 0x10000, sig_off)       # CSSLOT_SIGNATURESLOT
            + cd + req + sig)


def cdhash_of(blob: bytes) -> str:
    """CDHash as codesign(1) prints it: sha256 of the CodeDirectory blob, truncated to 20 bytes."""
    try:
        magic, total, count = struct.unpack_from(">III", blob, 0)
        if magic != CSMAGIC_EMBEDDED_SIGNATURE or not (12 + count * 8 <= total <= len(blob)):
            return ""
        offsets = [relative for slot, relative in
                   (struct.unpack_from(">II", blob, 12 + index * 8)
                    for index in range(count)) if slot == 0]
        if len(offsets) != 1:
            return ""
        cd_off = offsets[0]
        cd_magic, cd_len = struct.unpack_from(">II", blob, cd_off)
        if cd_magic != CSMAGIC_CODEDIRECTORY or cd_len < 8 or cd_off + cd_len > total:
            return ""
    except struct.error:
        return ""
    return hashlib.sha256(blob[cd_off:cd_off + cd_len]).hexdigest()[:40]


def build_macho(content_seed: bytes, imports=None, *, minos=(14, 0, 0), sdk=(14, 4, 0),
                sign_identifier=None) -> bytes:
    if imports is None:
        imports = pick_imports(content_seed)

    marker = (b"ARTIFACTFORGE-SYNTHETIC-"
              + prng_bytes(sub_seed(content_seed, "marker"), 8).hex().encode())
    cstring = marker + b"\x00"

    undef = [(s, i + 1) for i, (_d, _c, _p, syms) in enumerate(imports) for s in syms]
    n_undef = len(undef)

    # ---- string table (ld64 convention: b" \0" occupies index 0, names follow)
    strtab = bytearray(b" \x00")
    stridx = {}
    for nm in ["__mh_execute_header", "_main"] + [s for s, _o in undef]:
        stridx[nm] = len(strtab)
        strtab += nm.encode() + b"\x00"
    strtab += b"\x00" * ((-len(strtab)) % 8)

    # ---- two passes: load commands have fixed size once the layout constants are known
    n_dylibs = len(imports)
    sizeofcmds = (
        72                                   # __PAGEZERO
        + 72 + 80 * 2                        # __TEXT + __text + __cstring
        + 72 + 80                            # __DATA_CONST + __got
        + 72                                 # __LINKEDIT
        + 24 + 80                            # LC_SYMTAB + LC_DYSYMTAB
        + 32                                 # LC_LOAD_DYLINKER "/usr/lib/dyld"
        + 24 + 24 + 16 + 24                  # LC_UUID, LC_BUILD_VERSION, LC_SOURCE_VERSION, LC_MAIN
        + sum(len(_dylib_cmd(d, c, p)) for d, c, p, _s in imports)
        + (16 if sign_identifier else 0)     # LC_CODE_SIGNATURE
        + 48                                 # LC_DYLD_INFO_ONLY
    )
    ncmds = 5 + 2 + 1 + 4 + n_dylibs + (1 if sign_identifier else 0)

    hdr_end = 32 + sizeofcmds
    text_off = (hdr_end + 3) & ~3
    text_size = 8                       # `mov w0,#0 ; ret` -- the arm64 analogue of the PE's 0xC3
    cstr_off = text_off + text_size
    cstr_size = len(cstring)

    got_off = PAGE
    got_size = 8 * n_undef

    link_off = 2 * PAGE
    bind = _bind_opcodes(undef, 2)          # __DATA_CONST is segment index 2
    bind_off = link_off
    symoff = bind_off + len(bind)
    nsyms = 2 + n_undef
    indirectsymoff = symoff + 16 * nsyms
    stroff = indirectsymoff + 4 * n_undef
    strsize = len(strtab)
    link_size = (stroff + strsize) - link_off

    sig_off = sig_size = 0
    if sign_identifier:
        sig_off = (stroff + strsize + 15) & ~15          # codesign requires 16-byte alignment
        n_pages = -(-sig_off // (1 << CS_PAGE_LOG2))
        sig_size = len(_superblob(sign_identifier, sig_off, [b"\x00" * 32] * n_pages, PAGE))
        sig_size = (sig_size + 15) & ~15
        link_size = (sig_off + sig_size) - link_off

    text_vm = VM_BASE + text_off
    got_vm = VM_BASE + PAGE

    lc = b"".join([
        _seg("__PAGEZERO", 0, VM_BASE, 0, 0, 0, 0, []),
        _seg("__TEXT", VM_BASE, PAGE, 0, PAGE, 5, 5, [
            _sect("__text", "__TEXT", text_vm, text_size, text_off, 2,
                  S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS),
            _sect("__cstring", "__TEXT", VM_BASE + cstr_off, cstr_size, cstr_off, 0,
                  S_CSTRING_LITERALS),
        ]),
        _seg("__DATA_CONST", got_vm, PAGE, PAGE, PAGE, 3, 3, [
            _sect("__got", "__DATA_CONST", got_vm, got_size, got_off, 3,
                  S_NON_LAZY_SYMBOL_POINTERS, r1=0),
        ], flags=0x10),                                   # SG_READ_ONLY, as ld64 emits
        _seg("__LINKEDIT", VM_BASE + link_off, PAGE, link_off, link_size, 1, 1, []),
        struct.pack("<IIIIIIIIIIII", LC_DYLD_INFO_ONLY, 48,
                    0, 0, bind_off, len(bind), 0, 0, 0, 0, 0, 0),
        struct.pack("<IIIIII", LC_SYMTAB, 24, symoff, nsyms, stroff, strsize),
        struct.pack("<II" + "I" * 18, LC_DYSYMTAB, 80,
                    0, 0,                                  # ilocalsym, nlocalsym
                    0, 2,                                  # iextdefsym, nextdefsym
                    2, n_undef,                            # iundefsym, nundefsym
                    0, 0, 0, 0, 0, 0,                      # toc, modtab, extrefsym
                    indirectsymoff, n_undef,               # indirect symbol table
                    0, 0, 0, 0),                           # ext/loc relocs
        struct.pack("<III", LC_LOAD_DYLINKER, 32, 12) + b"/usr/lib/dyld\x00" + b"\x00" * 6,
        struct.pack("<II", LC_UUID, 24) + _macho_uuid(content_seed),
        struct.pack("<IIIIII", LC_BUILD_VERSION, 24, 1, _ver32(minos), _ver32(sdk), 0),
        struct.pack("<IIQ", LC_SOURCE_VERSION, 16, 0),
        struct.pack("<IIQQ", LC_MAIN, 24, text_off, 0),
        b"".join(_dylib_cmd(d, c, p) for d, c, p, _s in imports),
        struct.pack("<IIII", LC_CODE_SIGNATURE, 16, sig_off, sig_size) if sign_identifier else b"",
    ])
    assert len(lc) == sizeofcmds, (len(lc), sizeofcmds)

    header = struct.pack("<IiiIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL,
                         MH_EXECUTE, ncmds, sizeofcmds,
                         MH_DYLDLINK | MH_TWOLEVEL | MH_PIE, 0)

    # ---- nlist_64 table: locals | external defs | undefined  (DYSYMTAB requires this order)
    syms = b""
    syms += struct.pack("<IBBHQ", stridx["__mh_execute_header"], N_SECT | N_EXT, 1,
                        REFERENCED_DYNAMICALLY, VM_BASE)
    syms += struct.pack("<IBBHQ", stridx["_main"], N_SECT | N_EXT, 1, 0, text_vm)
    for nm, ordinal in undef:
        syms += struct.pack("<IBBHQ", stridx[nm], N_UNDF | N_EXT, 0, ordinal << 8, 0)

    indirect = b"".join(struct.pack("<I", 2 + i) for i in range(n_undef))

    out = bytearray(link_off + link_size)
    out[0:32] = header
    out[32:32 + sizeofcmds] = lc
    out[text_off:text_off + 8] = struct.pack("<II", ARM64_MOV_W0_0, ARM64_RET)
    out[cstr_off:cstr_off + cstr_size] = cstring
    # __got: zero-filled non-lazy pointers (never bound; the binary never runs)
    out[bind_off:bind_off + len(bind)] = bind
    out[symoff:symoff + len(syms)] = syms
    out[indirectsymoff:indirectsymoff + len(indirect)] = indirect
    out[stroff:stroff + strsize] = strtab

    if sign_identifier:
        # Every byte before sig_off is now final -> hash it in 16 KiB code pages.
        pages = [hashlib.sha256(bytes(out[i:min(i + (1 << CS_PAGE_LOG2), sig_off)])).digest()
                 for i in range(0, sig_off, 1 << CS_PAGE_LOG2)]
        blob = _superblob(sign_identifier, sig_off, pages, PAGE)
        assert len(blob) <= sig_size, (len(blob), sig_size)
        out[sig_off:sig_off + len(blob)] = blob
    return bytes(out)


def cdhash_of_file(data: bytes) -> str:
    """The cdhash of a finished Mach-O, located from its embedded signature superblob.

    This is the value `codesign -d --verbose=4` prints as CDHash, and the identity Apple's
    own loader keys on — a second, independent handle on the same bytes alongside the SHA256.
    """
    try:
        magic, _cpu, _subtype, _filetype, ncmds, sizeofcmds, _flags, _reserved = \
            struct.unpack_from("<IiiIIIII", data, 0)
        if magic != MH_MAGIC_64 or 32 + sizeofcmds > len(data):
            return ""
        offset = 32
        signatures = []
        for _ in range(ncmds):
            command, command_size = struct.unpack_from("<II", data, offset)
            if command_size < 8 or offset + command_size > 32 + sizeofcmds:
                return ""
            if command == LC_CODE_SIGNATURE:
                if command_size != 16:
                    return ""
                _command, _size, dataoff, datasize = struct.unpack_from("<IIII", data, offset)
                signatures.append((dataoff, datasize))
            offset += command_size
        if offset != 32 + sizeofcmds or len(signatures) != 1:
            return ""
        dataoff, datasize = signatures[0]
        if dataoff + datasize > len(data):
            return ""
    except struct.error:
        return ""
    return cdhash_of(data[dataoff:dataoff + datasize])
