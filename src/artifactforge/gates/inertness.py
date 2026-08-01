# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 3 — inertness: are binaries payload-free and classified formats marked synthetic?

Two properties, both checked on the emitted bytes rather than asserted in prose.

**Payload-free.** A binary this project generates reproduces the forensic *signal* — a real
import table, a real symbol table, and real content or structural hashes — without a payload.
PE ``.text`` is ``ret`` plus zero padding and its DOS stub is fixed; Mach-O ``__text`` is
``mov w0,#0 ; ret``. Both checks parse the emitted binary structure, locate the declared entry
point and code section, and reject additional executable instruction sections. The Mach-O
check also independently verifies the CodeDirectory page hashes and their coverage boundary.

**Marked.** Every parser-classified structured format carries an in-band anchor identifying it
as ArtifactForge output. A classified format with no marker is a failure. Plain sidecars are
outside that format-marker check; the serialized quarantine xattr value is the notable current
exception.

**Indicators point nowhere real.** Domains must be RFC 2606 reserved (.example, .invalid,
.test) and addresses RFC 5737 / RFC 3849, so no synthetic artifact can label a real host as
attacker infrastructure.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass

from artifactforge.gates import GateReport
from artifactforge.gates.validity import classify_bytes
from artifactforge.inventory import InventoryError, inventory_regular_files

# The in-band anchor each format must carry. A format absent from this table is unmarked,
# and unmarked is a failure — not an omission to be discovered later.
MARKERS = {
    "pe":       [b"ARTIFACTFORGE-SYNTHETIC-"],
    "macho":    [b"ARTIFACTFORGE-SYNTHETIC-"],
    "hive":     ["ArtifactForgeHive".encode("utf-16-le")],
    "prefetch": [b"ARTIFACTFORGE", "ARTIFACTFORGE".encode("utf-16-le")],
    "sqlite":   [b"ARTIFACTFORGE", "ARTIFACTFORGE".encode("utf-16-le")],
    "plist":    [b"ARTIFACTFORGE"],
}

# RFC 2606 reserved TLDs/domains, and RFC 5737 / RFC 3849 documentation address ranges.
_RESERVED_TLD = (".example", ".invalid", ".test", ".localhost")
_RESERVED_DOMAIN = ("example.com", "example.net", "example.org")
_DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:")
# Reverse-DNS prefixes belonging to real organisations. A bundle identifier is a namespaced
# claim of authorship, and on macOS it is embedded in the code signature — so an ad-hoc-signed
# synthetic binary identifying itself as `com.apple.Notes` asserts something false about Apple.
# Windows executable FILENAMES are deliberately not policed: `chrome.exe` is ubiquitous on a
# real host and claims nothing about who wrote it.
_REAL_VENDOR_PREFIXES = (
    "com.apple.", "com.microsoft.", "com.google.", "org.mozilla.", "com.adobe.",
    "com.amazon.", "com.meta.", "com.facebook.", "com.oracle.", "com.docker.",
    "com.spotify.", "us.zoom.", "com.tinyspeck.", "com.figma.", "com.postmanlabs.",
    "com.jetbrains.", "com.vmware.", "com.citrix.", "com.dropbox.", "com.slack.",
)
# Real vendor identifiers that are the PLATFORM'S OWN VOCABULARY rather than a claim of
# authorship. An artifact that avoided these would simply be wrong: the quarantine attribute
# really is called `com.apple.quarantine`, and a scene naming it something else would not be a
# macOS scene. Every exemption carries a reason, and the reason has to say something.
_PLATFORM_IDENTIFIERS = {
    "com.apple.quarantine":
        "the real extended attribute Gatekeeper sets on a downloaded file; the artifact is "
        "named after the attribute, and renaming it would make the scene wrong",
    "com.apple.launchservices.quarantineeventsv2":
        "the real filename of the LaunchServices quarantine database a responder opens",
    "com.apple.tcc":
        "the real directory holding TCC.db; it identifies Apple's subsystem, not an author",
    "com.apple.metadata":
        "the real extended-attribute namespace Spotlight and LaunchServices write under",
}
_BUNDLE_ID = re.compile(rb"\b((?:com|org|io|net|us|uk|de)\.[A-Za-z0-9]+\.[A-Za-z0-9._-]+)")
_URL = re.compile(rb"https?://([A-Za-z0-9._-]+)")
_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# Deliberately repeated from the writer rather than imported from it. Gate 3 is an independent
# statement of the on-disk policy; changing a writer constant must not silently change what the
# verifier accepts.
_MH_MAGIC_64 = 0xFEEDFACF
_CPU_TYPE_ARM64 = 0x0100000C
_MH_EXECUTE = 0x2
_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x2
_LC_DYSYMTAB = 0xB
_LC_LOAD_DYLINKER = 0xE
_LC_UUID = 0x1B
_LC_LOAD_DYLIB = 0xC
_LC_DYLD_INFO_ONLY = 0x80000022
_LC_BUILD_VERSION = 0x32
_LC_SOURCE_VERSION = 0x2A
_LC_MAIN = 0x80000028
_LC_CODE_SIGNATURE = 0x1D
_LC_THREAD = 0x4
_LC_UNIXTHREAD = 0x5
_S_ATTR_PURE_INSTRUCTIONS = 0x80000000
_S_ATTR_SOME_INSTRUCTIONS = 0x00000400
_VM_PROT_EXECUTE = 0x4
_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02
_CSMAGIC_REQUIREMENTS = 0xFADE0C01
_CSMAGIC_BLOBWRAPPER = 0xFADE0B01
_CS_ADHOC = 0x2
_CS_EXECSEG_MAIN_BINARY = 0x1
_CSSLOT_CODEDIRECTORY = 0
_CSSLOT_REQUIREMENTS = 2
_CSSLOT_SIGNATURE = 0x10000
_ARM64_BODY = b"\x00\x00\x80\x52\xc0\x03\x5f\xd6"
_ALLOWED_PE_IMPORTS = {"kernel32.dll", "advapi32.dll", "user32.dll", "ws2_32.dll"}
_PE_DOS_PROFILE_SHA256 = bytes.fromhex(
    "bfdf5e72651b4ec588bd5fc6a9f17e9e0972248146bbacc10478f48d72f29b81"
)
_FIXED_LOAD_COMMAND_COUNTS = {
    _LC_SEGMENT_64: 4,
    _LC_SYMTAB: 1,
    _LC_DYSYMTAB: 1,
    _LC_LOAD_DYLINKER: 1,
    _LC_UUID: 1,
    _LC_DYLD_INFO_ONLY: 1,
    _LC_BUILD_VERSION: 1,
    _LC_SOURCE_VERSION: 1,
    _LC_MAIN: 1,
    _LC_CODE_SIGNATURE: 1,
}
_ALLOWED_DYLIBS = {
    "/usr/lib/libSystem.B.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/Security.framework/Versions/A/Security",
    "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
}


class _MachOSafetyError(ValueError):
    """A structural or cryptographic Mach-O safety invariant did not hold."""


@dataclass(frozen=True)
class _MachOSection:
    name: str
    segment_name: str
    address: int
    size: int
    offset: int
    flags: int


@dataclass(frozen=True)
class _MachOSegment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    sections: tuple[_MachOSection, ...]


def _macho_error(condition: bool, message: str) -> None:
    if not condition:
        raise _MachOSafetyError(message)


def _macho_unpack(fmt: str, data: bytes, offset: int, what: str) -> tuple:
    size = struct.calcsize(fmt)
    _macho_error(0 <= offset <= len(data) - size,
                 f"truncated {what} at file offset {offset:#x}")
    return struct.unpack_from(fmt, data, offset)


def _macho_name(raw: bytes, what: str) -> str:
    try:
        return raw.split(b"\x00", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise _MachOSafetyError(f"{what} is not ASCII") from exc


def _pe_code_is_inert(data: bytes) -> tuple[bool, str]:
    """Bind the PE entry point to its sole executable section and permitted instruction.

    A PE has two places that legitimately hold executable code, and both are checked. The
    second matters more than it looks: the MS-DOS stub is the one region of a Windows binary
    where arbitrary code is conventional and nobody reads it, so requiring it to equal the
    stub every compiler has emitted for thirty years — byte for byte — closes the obvious
    place to hide something.
    """
    import pefile

    # Independent policy constant: importing the writer's bytes would allow a writer edit to
    # redefine what the gate accepts in that same edit.
    if (hashlib.sha256(data[:0x80]).digest() != _PE_DOS_PROFILE_SHA256
            or data[0x80:0x84] != b"PE\x00\x00"):
        return False, ("the MS-DOS stub and header are not the exact standard profile; the "
                       "only permitted 16-bit path is the fixed message-and-exit program")

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as exc:
        return False, f"PE structure is invalid: {exc}"

    executable = [
        section
        for section in pe.sections
        if section.Characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
    ]
    if len(executable) != 1:
        return False, f"expected one executable section, found {len(executable)}"
    text = executable[0]
    if text.Name.rstrip(b"\x00") != b".text":
        return False, "the sole executable section is not .text"
    if not text.Characteristics & 0x20:  # IMAGE_SCN_CNT_CODE
        return False, ".text is executable but is not declared as code"
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if entry_rva != text.VirtualAddress:
        return False, (
            f"AddressOfEntryPoint is {entry_rva:#x}, not the start of .text "
            f"({text.VirtualAddress:#x})"
        )
    populated_directories = {
        index
        for index, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY)
        if directory.VirtualAddress or directory.Size
    }
    if populated_directories != {1}:
        return False, (
            "PE data-directory profile is not import-only; startup-bearing TLS/COM or other "
            f"unexpected directories are present: {sorted(populated_directories)}"
        )
    imported_libraries = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
        try:
            library = descriptor.dll.decode("ascii").lower()
        except UnicodeDecodeError:
            return False, "an imported DLL name is not ASCII"
        imported_libraries.append(library)
    if (not imported_libraries or len(imported_libraries) != len(set(imported_libraries))
            or not set(imported_libraries) <= _ALLOWED_PE_IMPORTS
            or "kernel32.dll" not in imported_libraries):
        return False, f"unexpected, duplicate, or missing system DLL imports: {imported_libraries}"

    body = text.get_data()
    if body[:1] != b"\xc3":
        return False, f".text does not begin with ret (0xC3): {body[:8].hex()}"
    trailing = body[1:].strip(b"\x00")
    if trailing:
        return False, f".text carries {len(trailing)} non-zero bytes past ret"
    return True, "AddressOfEntryPoint -> sole executable .text: ret + padding; standard DOS stub"


def _parse_macho_structure(data: bytes) -> tuple[
        tuple[_MachOSegment, ...], tuple[int, int], tuple[int, int]]:
    """Read just the Mach-O structures Gate 3 needs, without trusting the writer or LIEF.

    Returns ``(segments, LC_MAIN(entryoff, stacksize), LC_CODE_SIGNATURE(dataoff, datasize))``.
    The parser is intentionally strict about the subset ArtifactForge emits. Accepting a novel
    entry-point mechanism or overlapping segment layout here would expand the safety claim.
    """
    header = _macho_unpack("<IiiIIIII", data, 0, "mach_header_64")
    magic, cpu_type, cpu_subtype, filetype, ncmds, sizeofcmds, flags, reserved = header
    _macho_error(magic == _MH_MAGIC_64, "not a little-endian 64-bit Mach-O")
    _macho_error(cpu_type == _CPU_TYPE_ARM64, f"CPU type is not arm64: {cpu_type:#x}")
    _macho_error(filetype == _MH_EXECUTE, f"Mach-O file type is not MH_EXECUTE: {filetype:#x}")
    _macho_error(cpu_subtype == 0, f"unexpected arm64 CPU subtype: {cpu_subtype:#x}")
    _macho_error(flags == 0x200084, f"unexpected Mach-O header flags: {flags:#x}")
    _macho_error(reserved == 0, f"Mach-O reserved header field is non-zero: {reserved:#x}")
    _macho_error(0 < ncmds <= 4096, f"implausible load-command count: {ncmds}")

    commands_end = 32 + sizeofcmds
    _macho_error(commands_end <= len(data), "load-command region extends past end of file")
    offset = 32
    segments: list[_MachOSegment] = []
    main_commands: list[tuple[int, int]] = []
    signature_commands: list[tuple[int, int]] = []
    command_counts: dict[int, int] = {}
    dylibs: list[str] = []
    dynamic_linkers: list[str] = []

    for index in range(ncmds):
        cmd, cmdsize = _macho_unpack("<II", data, offset, f"load command {index}")
        _macho_error(cmdsize >= 8 and cmdsize % 8 == 0,
                     f"load command {index} has invalid size {cmdsize}")
        _macho_error(offset + cmdsize <= commands_end,
                     f"load command {index} extends outside sizeofcmds")
        _macho_error(cmd in {*_FIXED_LOAD_COMMAND_COUNTS, _LC_LOAD_DYLIB},
                     f"load command {cmd:#x} is outside the inert writer profile")
        command_counts[cmd] = command_counts.get(cmd, 0) + 1

        if cmd == _LC_SEGMENT_64:
            values = _macho_unpack("<II16sQQQQIIII", data, offset,
                                   f"LC_SEGMENT_64 command {index}")
            (_cmd, _cmdsize, raw_name, vmaddr, vmsize, fileoff, filesize,
             maxprot, initprot, nsects, _seg_flags) = values
            _macho_error(cmdsize == 72 + nsects * 80,
                         f"segment command {index} has inconsistent section count")
            name = _macho_name(raw_name, f"segment {index} name")
            _macho_error((initprot & ~maxprot) == 0,
                         f"segment {name!r} initial protections exceed maximum protections")
            _macho_error(filesize == 0 or fileoff + filesize <= len(data),
                         f"segment {name!r} file range extends past end of file")

            sections: list[_MachOSection] = []
            section_offset = offset + 72
            for section_index in range(nsects):
                section = _macho_unpack("<16s16sQQIIIIIIII", data, section_offset,
                                        f"section {section_index} in {name}")
                (raw_section_name, raw_segment_name, address, size, file_offset, _align,
                 _reloff, _nreloc, section_flags, _reserved1, _reserved2, _reserved3) = section
                section_name = _macho_name(raw_section_name, "section name")
                section_segment = _macho_name(raw_segment_name, "section segment name")
                _macho_error(section_segment == name,
                             f"section {section_name!r} claims segment {section_segment!r}, "
                             f"not {name!r}")
                _macho_error(file_offset + size <= len(data),
                             f"section {name},{section_name} extends past end of file")
                _macho_error(fileoff <= file_offset and file_offset + size <= fileoff + filesize,
                             f"section {name},{section_name} lies outside its segment")
                _macho_error(address - vmaddr == file_offset - fileoff,
                             f"section {name},{section_name} file and VM offsets disagree")
                sections.append(_MachOSection(section_name, section_segment, address, size,
                                               file_offset, section_flags))
                section_offset += 80
            segments.append(_MachOSegment(name, vmaddr, vmsize, fileoff, filesize,
                                           maxprot, initprot, tuple(sections)))
        elif cmd == _LC_MAIN:
            _macho_error(cmdsize == 24, f"LC_MAIN has invalid size {cmdsize}")
            _cmd, _cmdsize, entryoff, stacksize = _macho_unpack(
                "<IIQQ", data, offset, "LC_MAIN")
            main_commands.append((entryoff, stacksize))
        elif cmd == _LC_CODE_SIGNATURE:
            _macho_error(cmdsize == 16, f"LC_CODE_SIGNATURE has invalid size {cmdsize}")
            _cmd, _cmdsize, dataoff, datasize = _macho_unpack(
                "<IIII", data, offset, "LC_CODE_SIGNATURE")
            signature_commands.append((dataoff, datasize))
        elif cmd in {_LC_LOAD_DYLINKER, _LC_LOAD_DYLIB}:
            minimum = 12 if cmd == _LC_LOAD_DYLINKER else 24
            _macho_error(cmdsize >= minimum, f"load-path command {cmd:#x} is too short")
            string_offset = _macho_unpack(
                "<I", data, offset + 8, f"load-path command {cmd:#x}"
            )[0]
            _macho_error(minimum <= string_offset < cmdsize,
                         f"load-path command {cmd:#x} has an invalid string offset")
            raw_path = data[offset + string_offset:offset + cmdsize]
            terminator = raw_path.find(b"\x00")
            _macho_error(terminator > 0 and not raw_path[terminator:].strip(b"\x00"),
                         f"load-path command {cmd:#x} is not one NUL-terminated path")
            path = _macho_name(raw_path[:terminator], "load-command path")
            (dynamic_linkers if cmd == _LC_LOAD_DYLINKER else dylibs).append(path)
        elif cmd in {_LC_THREAD, _LC_UNIXTHREAD}:
            raise _MachOSafetyError(
                "LC_THREAD/LC_UNIXTHREAD supplies an alternate entry point outside LC_MAIN")

        offset += cmdsize

    _macho_error(offset == commands_end,
                 "ncmds does not consume exactly the declared load-command region")
    _macho_error(len(main_commands) == 1,
                 f"expected exactly one LC_MAIN, found {len(main_commands)}")
    _macho_error(len(signature_commands) == 1,
                 f"expected exactly one LC_CODE_SIGNATURE, found {len(signature_commands)}")
    fixed_counts = {key: command_counts.get(key, 0) for key in _FIXED_LOAD_COMMAND_COUNTS}
    _macho_error(fixed_counts == _FIXED_LOAD_COMMAND_COUNTS,
                 f"load-command profile disagrees with the inert writer: {command_counts}")
    _macho_error(command_counts.get(_LC_LOAD_DYLIB, 0) == len(dylibs) >= 1,
                 "the Mach-O does not declare its expected system libraries")
    _macho_error(dynamic_linkers == ["/usr/lib/dyld"],
                 f"unexpected dynamic linker path: {dynamic_linkers}")
    _macho_error(len(dylibs) == len(set(dylibs)) and set(dylibs) <= _ALLOWED_DYLIBS
                 and "/usr/lib/libSystem.B.dylib" in dylibs,
                 f"unexpected or duplicate dynamic libraries: {dylibs}")
    segment_profile = [(segment.name, segment.maxprot, segment.initprot) for segment in segments]
    _macho_error(segment_profile == [
        ("__PAGEZERO", 0, 0),
        ("__TEXT", 5, 5),
        ("__DATA_CONST", 3, 3),
        ("__LINKEDIT", 1, 1),
    ], f"segment protection profile disagrees with the inert writer: {segment_profile}")

    file_ranges = sorted((segment.fileoff, segment.fileoff + segment.filesize, segment.name)
                         for segment in segments if segment.filesize)
    for (_left_start, left_end, left_name), (right_start, _right_end, right_name) in zip(
            file_ranges, file_ranges[1:]):
        _macho_error(left_end <= right_start,
                     f"file-backed segments {left_name!r} and {right_name!r} overlap")
    return tuple(segments), main_commands[0], signature_commands[0]


def _verify_macho_signature(data: bytes, segments: tuple[_MachOSegment, ...],
                            signature: tuple[int, int]) -> None:
    """Verify the ad-hoc signature covers every byte before its own bounded region."""
    signature_offset, signature_size = signature
    _macho_error(signature_offset % 16 == 0,
                 "LC_CODE_SIGNATURE data offset is not 16-byte aligned")
    _macho_error(signature_size >= 12 and signature_offset + signature_size == len(data),
                 "LC_CODE_SIGNATURE must own the complete tail of the file")

    linkedit = [segment for segment in segments if segment.name == "__LINKEDIT"]
    _macho_error(len(linkedit) == 1, f"expected one __LINKEDIT segment, found {len(linkedit)}")
    linkedit_segment = linkedit[0]
    _macho_error(linkedit_segment.fileoff <= signature_offset
                 and signature_offset + signature_size
                 <= linkedit_segment.fileoff + linkedit_segment.filesize,
                 "LC_CODE_SIGNATURE lies outside __LINKEDIT")
    _macho_error(not (linkedit_segment.initprot & _VM_PROT_EXECUTE),
                 "__LINKEDIT is executable")

    magic, total_size, count = _macho_unpack(
        ">III", data, signature_offset, "embedded-signature SuperBlob")
    _macho_error(magic == _CSMAGIC_EMBEDDED_SIGNATURE,
                 "LC_CODE_SIGNATURE does not point at an embedded-signature SuperBlob")
    _macho_error(12 + count * 8 <= total_size <= signature_size,
                 "embedded-signature SuperBlob has invalid bounds")
    _macho_error(not data[signature_offset + total_size:signature_offset + signature_size].strip(
        b"\x00"), "LC_CODE_SIGNATURE contains non-zero bytes outside its SuperBlob")

    blobs: dict[int, tuple[int, int]] = {}
    ranges: list[tuple[int, int, int]] = []
    for index in range(count):
        slot_type, relative_offset = _macho_unpack(
            ">II", data, signature_offset + 12 + index * 8, f"SuperBlob index {index}")
        _macho_error(slot_type not in blobs, f"duplicate SuperBlob slot {slot_type:#x}")
        _macho_error(relative_offset >= 12 + count * 8,
                     f"SuperBlob slot {slot_type:#x} overlaps its index")
        blob_offset = signature_offset + relative_offset
        _blob_magic, blob_size = _macho_unpack(
            ">II", data, blob_offset, f"SuperBlob slot {slot_type:#x}")
        _macho_error(blob_size >= 8 and relative_offset + blob_size <= total_size,
                     f"SuperBlob slot {slot_type:#x} extends outside the SuperBlob")
        blobs[slot_type] = (blob_offset, blob_size)
        ranges.append((relative_offset, relative_offset + blob_size, slot_type))

    _macho_error(set(blobs) == {
        _CSSLOT_CODEDIRECTORY, _CSSLOT_REQUIREMENTS, _CSSLOT_SIGNATURE,
    }, f"unexpected SuperBlob slots: {sorted(blobs)}")
    ordered_ranges = sorted(ranges)
    _macho_error(ordered_ranges[0][0] == 12 + count * 8,
                 "unindexed bytes appear between the SuperBlob index and first slot")
    for (_left_start, left_end, left_type), (right_start, _right_end, right_type) in zip(
            ordered_ranges, ordered_ranges[1:]):
        _macho_error(left_end == right_start,
                     f"SuperBlob slots {left_type:#x} and {right_type:#x} overlap or leave a gap")
    _macho_error(ordered_ranges[-1][1] == total_size,
                 "unindexed bytes appear at the end of the SuperBlob")

    requirement_offset, requirement_size = blobs[_CSSLOT_REQUIREMENTS]
    requirement_magic, declared_requirement_size, requirement_count = _macho_unpack(
        ">III", data, requirement_offset, "requirements blob")
    _macho_error(requirement_magic == _CSMAGIC_REQUIREMENTS
                 and declared_requirement_size == requirement_size
                 and requirement_size == 12 and requirement_count == 0,
                 "requirements slot is not the empty requirement set")
    wrapper_offset, wrapper_size = blobs[_CSSLOT_SIGNATURE]
    wrapper_magic, declared_wrapper_size = _macho_unpack(
        ">II", data, wrapper_offset, "signature wrapper")
    _macho_error(wrapper_magic == _CSMAGIC_BLOBWRAPPER
                 and declared_wrapper_size == wrapper_size == 8,
                 "ad-hoc signature carries an unexpected CMS wrapper")

    cd_offset, cd_size = blobs[_CSSLOT_CODEDIRECTORY]
    fields = _macho_unpack(">IIIIIIIIIBBBBIIIIQQQQ", data, cd_offset, "CodeDirectory")
    (cd_magic, cd_length, version, flags, hash_offset, ident_offset, n_special, n_code,
     code_limit, hash_size, hash_type, platform, page_log2, _spare2, _scatter_offset,
     _team_offset, _spare3, code_limit_64, exec_segment_base, exec_segment_limit,
     exec_segment_flags) = fields
    _macho_error(cd_magic == _CSMAGIC_CODEDIRECTORY and cd_length == cd_size,
                 "CodeDirectory magic or length is invalid")
    _macho_error(version == 0x20400, f"unexpected CodeDirectory version {version:#x}")
    _macho_error(flags == _CS_ADHOC, f"CodeDirectory is not strictly ad-hoc: flags {flags:#x}")
    _macho_error(hash_size == 32 and hash_type == 2 and page_log2 == 14,
                 "CodeDirectory does not use 16-KiB SHA-256 page hashes")
    _macho_error(platform == 0, f"unexpected CodeDirectory platform value {platform}")
    _macho_error(_spare2 == _scatter_offset == _team_offset == _spare3 == 0,
                 "CodeDirectory carries unsupported scatter, team, or spare fields")
    _macho_error(code_limit == signature_offset and code_limit_64 == 0,
                 "CodeDirectory coverage does not end exactly at LC_CODE_SIGNATURE")

    page_size = 1 << page_log2
    expected_slots = (code_limit + page_size - 1) // page_size
    _macho_error(n_code == expected_slots,
                 f"CodeDirectory has {n_code} code slots; coverage requires {expected_slots}")
    _macho_error(n_special == 2, f"CodeDirectory has {n_special} special slots, expected 2")
    _macho_error(hash_offset + n_code * hash_size == cd_size,
                 "CodeDirectory hash table does not end at its declared boundary")
    special_start = hash_offset - n_special * hash_size
    _macho_error(88 <= ident_offset < special_start,
                 "CodeDirectory identifier or special-slot offsets are invalid")
    identifier_end = data.find(b"\x00", cd_offset + ident_offset,
                               cd_offset + special_start)
    _macho_error(identifier_end >= 0 and identifier_end + 1 == cd_offset + special_start,
                 "CodeDirectory identifier does not end exactly where special slots begin")

    requirement_hash = hashlib.sha256(
        data[requirement_offset:requirement_offset + requirement_size]).digest()
    _macho_error(data[cd_offset + special_start:cd_offset + special_start + 32]
                 == requirement_hash, "CodeDirectory requirements hash is wrong")
    _macho_error(data[cd_offset + special_start + 32:cd_offset + hash_offset]
                 == b"\x00" * 32, "absent Info.plist special slot is not zero")

    for slot in range(n_code):
        page_start = slot * page_size
        expected = hashlib.sha256(data[page_start:min(page_start + page_size, code_limit)]).digest()
        actual_start = cd_offset + hash_offset + slot * hash_size
        actual = data[actual_start:actual_start + hash_size]
        _macho_error(actual == expected, f"CodeDirectory page hash {slot} does not match file")

    executable = [segment for segment in segments if segment.initprot & _VM_PROT_EXECUTE]
    _macho_error(len(executable) == 1,
                 f"expected exactly one executable segment, found {len(executable)}")
    executable_segment = executable[0]
    _macho_error(exec_segment_base == executable_segment.fileoff
                 and exec_segment_limit == executable_segment.filesize,
                 "CodeDirectory executable-segment coverage disagrees with the Mach-O segment")
    _macho_error(exec_segment_flags == _CS_EXECSEG_MAIN_BINARY,
                 f"unexpected CodeDirectory executable-segment flags {exec_segment_flags:#x}")


def _macho_code_is_inert(data: bytes) -> tuple[bool, str]:
    """Prove the LC_MAIN-reachable arm64 sequence is ``mov w0,#0; ret`` and padding.

    This does not search for convenient bytes. It parses the entry point, executable segment,
    instruction section and signature independently, then binds those structures together.
    """
    try:
        segments, (entryoff, stacksize), signature = _parse_macho_structure(data)
        executable = [segment for segment in segments if segment.initprot & _VM_PROT_EXECUTE]
        _macho_error(len(executable) == 1 and executable[0].name == "__TEXT",
                     "the sole executable segment is not __TEXT")
        text_segment = executable[0]

        instruction_sections = [
            section
            for segment in segments
            for section in segment.sections
            if section.flags & (_S_ATTR_PURE_INSTRUCTIONS | _S_ATTR_SOME_INSTRUCTIONS)
        ]
        _macho_error(len(instruction_sections) == 1,
                     f"expected one instruction section, found {len(instruction_sections)}")
        section_profile = {
            (segment.name, section.name): section.flags
            for segment in segments
            for section in segment.sections
        }
        _macho_error(section_profile == {
            ("__TEXT", "__text"): 0x80000400,
            ("__TEXT", "__cstring"): 0x2,
            ("__DATA_CONST", "__got"): 0x6,
        }, f"section profile disagrees with the inert writer: {sorted(section_profile)}")
        text = instruction_sections[0]
        _macho_error(text.segment_name == "__TEXT" and text.name == "__text",
                     "the sole instruction section is not __TEXT,__text")
        _macho_error(text.flags & _S_ATTR_PURE_INSTRUCTIONS
                     and text.flags & _S_ATTR_SOME_INSTRUCTIONS,
                     "__text is not declared pure executable instructions")
        _macho_error(stacksize == 0, f"LC_MAIN requests a non-zero stack size: {stacksize}")
        entry_file_offset = text_segment.fileoff + entryoff
        _macho_error(entry_file_offset == text.offset,
                     f"LC_MAIN points to {entry_file_offset:#x}, not the start of __text")
        _macho_error(text.size >= len(_ARM64_BODY) and text.size % 4 == 0
                     and text.offset % 4 == 0,
                     "__text is too short or not arm64-instruction aligned")
        body = data[text.offset:text.offset + text.size]
        _macho_error(body[:len(_ARM64_BODY)] == _ARM64_BODY,
                     f"entry bytes are {body[:len(_ARM64_BODY)].hex()}, not mov w0,#0 ; ret")
        _macho_error(not body[len(_ARM64_BODY):].strip(b"\x00"),
                     "__text carries non-zero instructions or data after ret")

        _verify_macho_signature(data, segments, signature)
    except (OverflowError, struct.error, _MachOSafetyError) as exc:
        return False, str(exc)
    padding = text.size - len(_ARM64_BODY)
    return True, ("LC_MAIN -> __TEXT,__text: mov w0,#0 ; ret"
                  + (f" + {padding} zero padding bytes" if padding else "")
                  + "; CodeDirectory covers every pre-signature byte")


def _indicator_hygiene(r: GateReport, where: str, data: bytes):
    for host in set(_URL.findall(data)):
        h = host.decode("ascii", "replace").lower().rstrip(".")
        if h.endswith(_RESERVED_TLD) or h in _RESERVED_DOMAIN:
            continue
        r.fail(f"{where}: URL host {h!r} is not an RFC 2606 reserved name — a "
                       f"synthetic artifact must never name a host that could be real")
    for bundle in set(_BUNDLE_ID.findall(data)):
        b = bundle.decode("ascii", "replace")
        low = b.lower().rstrip(".")
        if any(low == k or low.startswith(k + ".") for k in _PLATFORM_IDENTIFIERS):
            continue
        if low.startswith(_REAL_VENDOR_PREFIXES):
            r.fail(f"{where}: bundle identifier {b!r} sits under a real vendor's reverse-DNS "
                   f"prefix — on macOS that is embedded in the code signature, so a synthetic "
                   f"binary would be asserting something false about them")

    for ip in set(_IPV4.findall(data)):
        s = ip.decode()
        if any(s.startswith(n) for n in _DOC_NETS) or s.startswith(("10.", "127.", "192.168.")):
            continue
        if s.startswith("172.") and 16 <= int(s.split(".")[1]) <= 31:
            continue
        r.fail(f"{where}: address {s} is outside the RFC 5737 documentation "
                       f"and RFC 1918 private ranges")


def run(scene_dir: str) -> GateReport:
    r = GateReport(3, "inertness",
                   "are binaries payload-free and classified formats marked synthetic?")
    marked = fmts = binary_safety_passed = binary_safety_total = 0
    inventory_failed = False

    try:
        files = inventory_regular_files(scene_dir, capture_bytes=True)
    except InventoryError as exc:
        files = ()
        inventory_failed = True
        r.fail(f"scene inventory is unsafe: {exc}")

    for file in files:
        name = file.relative_path
        path = os.fspath(file.path)
        data = file.data
        if data is None:  # capture_bytes=True is a construction invariant.
            raise AssertionError("scene inventory did not capture file bytes")

        fmt = classify_bytes(data, path)
        _indicator_hygiene(r, name, data)
        if fmt is None:
            continue                                   # xattr sidecar and other plain text
        fmts += 1

        if fmt == "pe":
            binary_safety_total += 1
            ok, why = _pe_code_is_inert(data)
            if ok:
                binary_safety_passed += 1
            else:
                r.fail(f"{name}: {fmt} PE is not inert — {why}")
        elif fmt == "macho":
            binary_safety_total += 1
            ok, why = _macho_code_is_inert(data)
            if ok:
                binary_safety_passed += 1
            else:
                r.fail(f"{name}: {fmt} Mach-O is not inert — {why}")

        anchors = MARKERS.get(fmt)
        if anchors is None:
            r.fail(f"{name}: {fmt} has no declared synthetic marker")
        elif any(a in data for a in anchors):
            marked += 1
        else:
            r.fail(f"{name}: {fmt} carries no in-band synthetic marker, so a copy that "
                           f"escapes its bundle cannot be recognised as generated")

    if fmts == 0 and not inventory_failed:
        r.fail(f"no artifact in {scene_dir!r} was classified, so nothing was checked for "
               f"inertness or for its synthetic marker")
    r.metrics["formats_marked"] = marked
    r.metrics["formats_total"] = fmts
    r.metrics["binary_safety_checks_passed"] = binary_safety_passed
    r.metrics["binary_safety_checks_total"] = binary_safety_total
    r.denominator = (f"{binary_safety_passed}/{binary_safety_total} binary safety checks pass; "
                     f"{marked}/{fmts} artifacts carry an in-band synthetic marker")
    return r
