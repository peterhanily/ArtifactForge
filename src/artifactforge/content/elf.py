# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""A hand-assembled, byte-deterministic x86-64 ELF PIE.

The writer is intentionally smaller than a compiler-produced executable, but every structure
it claims is real: ELF and program headers, an interpreter, a dynamic table, a named note, and
section headers.  It has exactly three non-overlapping ``PT_LOAD`` segments (R, RX, RW).  The
RX segment is exactly the nine-byte entry body::

    xor edi, edi
    mov eax, 60
    syscall

That body exits immediately with status zero.  The main object has no other executable bytes,
symbols, relocations, initializers, finalizers, TLS records, or alternate entry surface.
``libc.so.6`` is present as the sole ``DT_NEEDED`` dependency without giving the main object
an imported callable symbol.  External loader/dependency code is out of this entry-body claim
and, on a real execution attempt, the declared loader runs first.

Generation uses only the standard library and is a pure function of ``content_seed``.  LIEF and
pyelftools are independent read-back oracles in the development suite, not runtime dependencies.
"""
from __future__ import annotations

import struct

from artifactforge.content.seed import prng_bytes, sub_seed

# ELF identification and header constants.
ET_DYN = 3
EM_X86_64 = 62
EV_CURRENT = 1

# Program-header types and permissions.
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_PHDR = 6
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4

# Section types and flags.
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Dynamic tags.  The allowlist is deliberately this small.
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_PIE = 0x08000000

ELF_INTERPRETER = b"/lib64/ld-linux-x86-64.so.2\x00"
ELF_NEEDED = b"libc.so.6"
ELF_ENTRY_CODE = bytes.fromhex("31ffb83c0000000f05")
ELF_NOTE_NAME = b"ArtifactForge\x00"
ELF_NOTE_TYPE = 0xAF01

_ELF_HEADER_SIZE = 64
_PROGRAM_HEADER_SIZE = 56
_SECTION_HEADER_SIZE = 64
_PROGRAM_HEADER_COUNT = 9
_SECTION_HEADER_COUNT = 7
_PAGE = 0x1000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _program_header(
    kind: int,
    flags: int,
    offset: int,
    virtual_address: int,
    file_size: int,
    memory_size: int,
    alignment: int,
) -> bytes:
    return struct.pack(
        "<IIQQQQQQ",
        kind,
        flags,
        offset,
        virtual_address,
        virtual_address,  # physical address is ignored for a userspace ELF image
        file_size,
        memory_size,
        alignment,
    )


def _section_header(
    name: int,
    kind: int,
    flags: int,
    address: int,
    offset: int,
    size: int,
    *,
    link: int = 0,
    info: int = 0,
    alignment: int = 1,
    entry_size: int = 0,
) -> bytes:
    return struct.pack(
        "<IIQQQQIIQQ",
        name,
        kind,
        flags,
        address,
        offset,
        size,
        link,
        info,
        alignment,
        entry_size,
    )


def _note(content_seed: bytes) -> tuple[bytes, bytes]:
    marker = (
        b"ARTIFACTFORGE-SYNTHETIC-"
        + prng_bytes(sub_seed(content_seed, "marker"), 8).hex().encode()
    )
    name_padding = b"\x00" * (-len(ELF_NOTE_NAME) % 4)
    description_padding = b"\x00" * (-len(marker) % 4)
    note = (
        struct.pack("<III", len(ELF_NOTE_NAME), len(marker), ELF_NOTE_TYPE)
        + ELF_NOTE_NAME
        + name_padding
        + marker
        + description_padding
    )
    return note, marker


def build_elf(content_seed: bytes) -> bytes:
    """Return a deterministic glibc/x86-64 ``ET_DYN`` executable.

    The first load maps the file header, program headers, interpreter, ArtifactForge note, and
    dynamic string table read-only.  The second load maps only :data:`ELF_ENTRY_CODE` RX.  The
    third maps only the dynamic table RW and is also named by ``PT_GNU_RELRO``.  Section names
    and the section-header table are intentionally outside all loadable segments.
    """
    note, _marker = _note(content_seed)
    dynamic_strings = b"\x00" + ELF_NEEDED + b"\x00"

    program_headers_offset = _ELF_HEADER_SIZE
    program_headers_size = _PROGRAM_HEADER_COUNT * _PROGRAM_HEADER_SIZE
    interpreter_offset = _align(program_headers_offset + program_headers_size, 8)
    note_offset = _align(interpreter_offset + len(ELF_INTERPRETER), 4)
    dynamic_strings_offset = _align(note_offset + len(note), 8)
    read_only_size = dynamic_strings_offset + len(dynamic_strings)

    text_offset = _PAGE
    dynamic_offset = 2 * _PAGE
    dynamic = b"".join(
        [
            struct.pack("<QQ", DT_NEEDED, 1),
            struct.pack("<QQ", DT_STRTAB, dynamic_strings_offset),
            struct.pack("<QQ", DT_STRSZ, len(dynamic_strings)),
            struct.pack("<QQ", DT_FLAGS_1, DF_1_PIE),
            struct.pack("<QQ", DT_NULL, 0),
        ]
    )

    section_names = (
        b"\x00.interp\x00.note.artifactforge\x00.dynstr\x00.text\x00.dynamic\x00.shstrtab\x00"
    )

    def section_name(name: bytes) -> int:
        offset = section_names.find(name + b"\x00")
        assert offset > 0, name
        return offset

    section_names_offset = _align(dynamic_offset + len(dynamic), 8)
    section_headers_offset = _align(section_names_offset + len(section_names), 8)
    file_size = section_headers_offset + _SECTION_HEADER_COUNT * _SECTION_HEADER_SIZE

    identification = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        identification,
        ET_DYN,
        EM_X86_64,
        EV_CURRENT,
        text_offset,
        program_headers_offset,
        section_headers_offset,
        0,
        _ELF_HEADER_SIZE,
        _PROGRAM_HEADER_SIZE,
        _PROGRAM_HEADER_COUNT,
        _SECTION_HEADER_SIZE,
        _SECTION_HEADER_COUNT,
        6,  # .shstrtab
    )

    program_headers = b"".join(
        [
            _program_header(
                PT_PHDR,
                PF_R,
                program_headers_offset,
                program_headers_offset,
                program_headers_size,
                program_headers_size,
                8,
            ),
            _program_header(
                PT_INTERP,
                PF_R,
                interpreter_offset,
                interpreter_offset,
                len(ELF_INTERPRETER),
                len(ELF_INTERPRETER),
                1,
            ),
            _program_header(PT_LOAD, PF_R, 0, 0, read_only_size, read_only_size, _PAGE),
            _program_header(
                PT_LOAD,
                PF_R | PF_X,
                text_offset,
                text_offset,
                len(ELF_ENTRY_CODE),
                len(ELF_ENTRY_CODE),
                _PAGE,
            ),
            _program_header(
                PT_LOAD,
                PF_R | PF_W,
                dynamic_offset,
                dynamic_offset,
                len(dynamic),
                len(dynamic),
                _PAGE,
            ),
            _program_header(
                PT_DYNAMIC,
                PF_R | PF_W,
                dynamic_offset,
                dynamic_offset,
                len(dynamic),
                len(dynamic),
                8,
            ),
            _program_header(
                PT_NOTE,
                PF_R,
                note_offset,
                note_offset,
                len(note),
                len(note),
                4,
            ),
            _program_header(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16),
            _program_header(
                PT_GNU_RELRO,
                PF_R,
                dynamic_offset,
                dynamic_offset,
                len(dynamic),
                len(dynamic),
                1,
            ),
        ]
    )
    assert len(header) == _ELF_HEADER_SIZE
    assert len(program_headers) == program_headers_size

    section_headers = b"".join(
        [
            _section_header(0, SHT_NULL, 0, 0, 0, 0, alignment=0),
            _section_header(
                section_name(b".interp"),
                SHT_PROGBITS,
                SHF_ALLOC,
                interpreter_offset,
                interpreter_offset,
                len(ELF_INTERPRETER),
            ),
            _section_header(
                section_name(b".note.artifactforge"),
                SHT_NOTE,
                SHF_ALLOC,
                note_offset,
                note_offset,
                len(note),
                alignment=4,
            ),
            _section_header(
                section_name(b".dynstr"),
                SHT_STRTAB,
                SHF_ALLOC,
                dynamic_strings_offset,
                dynamic_strings_offset,
                len(dynamic_strings),
            ),
            _section_header(
                section_name(b".text"),
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                text_offset,
                text_offset,
                len(ELF_ENTRY_CODE),
                alignment=16,
            ),
            _section_header(
                section_name(b".dynamic"),
                SHT_DYNAMIC,
                SHF_WRITE | SHF_ALLOC,
                dynamic_offset,
                dynamic_offset,
                len(dynamic),
                link=3,  # .dynstr
                alignment=8,
                entry_size=16,
            ),
            _section_header(
                section_name(b".shstrtab"),
                SHT_STRTAB,
                0,
                0,
                section_names_offset,
                len(section_names),
            ),
        ]
    )
    assert len(section_headers) == _SECTION_HEADER_COUNT * _SECTION_HEADER_SIZE

    out = bytearray(file_size)
    out[:_ELF_HEADER_SIZE] = header
    out[program_headers_offset:interpreter_offset] = program_headers
    out[interpreter_offset:interpreter_offset + len(ELF_INTERPRETER)] = ELF_INTERPRETER
    out[note_offset:note_offset + len(note)] = note
    out[dynamic_strings_offset:read_only_size] = dynamic_strings
    out[text_offset:text_offset + len(ELF_ENTRY_CODE)] = ELF_ENTRY_CODE
    out[dynamic_offset:dynamic_offset + len(dynamic)] = dynamic
    out[section_names_offset:section_names_offset + len(section_names)] = section_names
    out[section_headers_offset:file_size] = section_headers
    return bytes(out)


__all__ = [
    "ELF_ENTRY_CODE",
    "ELF_INTERPRETER",
    "ELF_NEEDED",
    "ELF_NOTE_NAME",
    "ELF_NOTE_TYPE",
    "build_elf",
]
