# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Typed, claim-scoped observations of ArtifactForge's thin arm64 Mach-O profile.

LIEF and macholib expose materially different interfaces.  The first reader below observes
LIEF's decoded objects.  The second uses macholib's decoded header/load commands and decodes
the nlist/string table, dyld bind opcodes, GOT pointer array, and indirect-symbol table directly
from bounded file bytes.  LIEF exposes semantic bindings and resolved indirect symbols; its
numeric indirect indexes are therefore reconstructed from those resolved symbols, while only
the macholib-side adapter validates the raw uint32 entries.  Sharing frozen value types does
not make the extraction implementations the same.

These observations establish structural extraction, parser consensus, and the exact bounded
profile emitted by :mod:`artifactforge.content.macho`.  They do not establish that macOS will
load the file, that its ad-hoc signature is valid, or that the profile resembles an arbitrary
real-world binary; those are separate native-conformance and realism claims.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct


class MachOProfileError(ValueError):
    """A parser observation is malformed or outside the declared writer profile."""


@dataclass(frozen=True)
class MachOHeaderView:
    magic: int
    cpu_type: int
    cpu_subtype: int
    file_type: int
    command_count: int
    command_bytes: int
    flags: int
    reserved: int


@dataclass(frozen=True)
class MachOLoadCommandView:
    command: int
    offset: int
    size: int


@dataclass(frozen=True)
class MachOSectionView:
    name: str
    segment_name: str
    address: int
    size: int
    file_offset: int
    alignment: int
    relocation_offset: int
    relocation_count: int
    flags: int
    reserved1: int
    reserved2: int
    reserved3: int


@dataclass(frozen=True)
class MachOSegmentView:
    name: str
    virtual_address: int
    virtual_size: int
    file_offset: int
    file_size: int
    max_protection: int
    init_protection: int
    section_count: int
    flags: int
    sections: tuple[MachOSectionView, ...]


@dataclass(frozen=True)
class MachODylibView:
    name: str
    timestamp: int
    current_version: tuple[int, int, int]
    compatibility_version: tuple[int, int, int]


@dataclass(frozen=True)
class MachOBindingView:
    """One standard dyld binding resolved to an exact segment slot and dylib."""

    address: int
    segment_index: int
    segment_name: str
    library_ordinal: int
    library_name: str
    symbol_name: str
    binding_type: int
    addend: int
    weak_import: bool


@dataclass(frozen=True)
class MachOSymbolView:
    name: str
    raw_type: int
    section_number: int
    description: int
    value: int


@dataclass(frozen=True)
class MachOSymtabView:
    symbol_offset: int
    symbol_count: int
    strings_offset: int
    strings_size: int


@dataclass(frozen=True)
class MachODysymtabView:
    values: tuple[int, ...]


@dataclass(frozen=True)
class MachOView:
    """Type-exact structural view shared by the LIEF and macholib adapters."""

    file_size: int
    header: MachOHeaderView
    commands: tuple[MachOLoadCommandView, ...]
    segments: tuple[MachOSegmentView, ...]
    dyld_info: tuple[tuple[int, ...], ...]
    bind_opcode_streams: tuple[bytes, ...]
    bindings: tuple[tuple[MachOBindingView, ...], ...]
    symbol_tables: tuple[MachOSymtabView, ...]
    dynamic_symbol_tables: tuple[MachODysymtabView, ...]
    indirect_symbol_indexes: tuple[tuple[int, ...], ...]
    indirect_symbols: tuple[tuple[MachOSymbolView, ...], ...]
    got_entries: tuple[tuple[int, ...], ...]
    dylinkers: tuple[str, ...]
    uuids: tuple[bytes, ...]
    build_versions: tuple[tuple[int, tuple[int, int, int], tuple[int, int, int], int], ...]
    source_versions: tuple[tuple[int, int, int, int, int], ...]
    entry_points: tuple[tuple[int, int], ...]
    dylibs: tuple[MachODylibView, ...]
    symbols: tuple[MachOSymbolView, ...]
    code_signatures: tuple[tuple[int, int], ...]

    def detail(self) -> str:
        binding_count = sum(len(items) for items in self.bindings)
        indirect_count = sum(len(items) for items in self.indirect_symbol_indexes)
        return (
            f"cpu=arm64,type=execute,commands={len(self.commands)},"
            f"segments={len(self.segments)},dylibs={len(self.dylibs)},"
            f"symbols={len(self.symbols)},bindings={binding_count},"
            f"indirect={indirect_count}"
        )


_MAX_MACHO_BYTES = 16 * 1024 * 1024
_MAX_COMMANDS = 128
_MAX_SECTIONS = 256
_MAX_SYMBOLS = 4096
_MAX_BINDINGS = 4096

_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x02
_LC_DYSYMTAB = 0x0B
_LC_LOAD_DYLIB = 0x0C
_LC_LOAD_DYLINKER = 0x0E
_LC_UUID = 0x1B
_LC_CODE_SIGNATURE = 0x1D
_LC_DYLD_INFO_ONLY = 0x80000022
_LC_MAIN = 0x80000028
_LC_SOURCE_VERSION = 0x2A
_LC_BUILD_VERSION = 0x32


def _integer(value: object, *, where: str) -> int:
    if type(value) is bool:
        raise MachOProfileError(f"{where} is not an integer")
    if type(value) is int:
        return value
    try:
        converted = int(value)
    except (TypeError, ValueError) as exc:
        raise MachOProfileError(f"{where} is not an integer") from exc
    if type(converted) is not int:
        raise MachOProfileError(f"{where} is not an integer")
    return converted


def _boolean(value: object, *, where: str) -> bool:
    if type(value) is not bool:
        raise MachOProfileError(f"{where} is not a boolean")
    return value


def _text(value: object, *, where: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise MachOProfileError(f"{where} is not non-empty NUL-free text")
    try:
        value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise MachOProfileError(f"{where} is not ASCII") from exc
    return value


def _fixed_name(value: object, *, where: str) -> str:
    if not isinstance(value, bytes) or len(value) != 16:
        raise MachOProfileError(f"{where} is not a 16-byte Mach-O name")
    end = value.find(b"\x00")
    if end < 0:
        end = 16
    elif any(value[end:]):
        raise MachOProfileError(f"{where} has non-zero bytes after its terminator")
    try:
        return value[:end].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise MachOProfileError(f"{where} is not ASCII") from exc


def _load_command_text(value: object, *, where: str) -> str:
    if not isinstance(value, bytes):
        raise MachOProfileError(f"{where} load-command data is not bytes")
    end = value.find(b"\x00")
    if end <= 0 or any(value[end:]):
        raise MachOProfileError(f"{where} is not a canonical padded C string")
    try:
        return value[:end].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise MachOProfileError(f"{where} is not ASCII") from exc


def _version_tuple(value: object, *, where: str) -> tuple[int, int, int]:
    try:
        parts = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise MachOProfileError(f"{where} is not a three-part version") from exc
    if len(parts) != 3:
        raise MachOProfileError(f"{where} is not a three-part version")
    result = tuple(_integer(part, where=where) for part in parts)
    if any(part < 0 for part in result):
        raise MachOProfileError(f"{where} contains a negative component")
    return result  # type: ignore[return-value]


def _packed_version(value: int) -> tuple[int, int, int]:
    return value >> 16, (value >> 8) & 0xFF, value & 0xFF


def _source_version(value: int) -> tuple[int, int, int, int, int]:
    return (
        value >> 40,
        (value >> 30) & 0x3FF,
        (value >> 20) & 0x3FF,
        (value >> 10) & 0x3FF,
        value & 0x3FF,
    )


def _decode_got_entries(content: bytes) -> tuple[int, ...]:
    if len(content) % 8 or len(content) // 8 > _MAX_SYMBOLS:
        raise MachOProfileError("Mach-O __got content is not a bounded pointer array")
    return tuple(
        struct.unpack_from("<Q", content, offset)[0]
        for offset in range(0, len(content), 8)
    )


def _lief_section(section: object) -> MachOSectionView:
    return MachOSectionView(
        _text(getattr(section, "name", None), where="LIEF section name"),
        _text(getattr(section, "segment_name", None), where="LIEF section segment name"),
        _integer(getattr(section, "virtual_address", None), where="LIEF section address"),
        _integer(getattr(section, "size", None), where="LIEF section size"),
        _integer(getattr(section, "offset", None), where="LIEF section file offset"),
        _integer(getattr(section, "alignment", None), where="LIEF section alignment"),
        _integer(
            getattr(section, "relocation_offset", 0),
            where="LIEF section relocation offset",
        ),
        _integer(
            getattr(section, "numberof_relocations", 0),
            where="LIEF section relocation count",
        ),
        _integer(getattr(section, "flags", None), where="LIEF section attributes")
        | _integer(getattr(section, "type", None), where="LIEF section type"),
        _integer(getattr(section, "reserved1", None), where="LIEF section reserved1"),
        _integer(getattr(section, "reserved2", None), where="LIEF section reserved2"),
        _integer(getattr(section, "reserved3", None), where="LIEF section reserved3"),
    )


def _lief_segment(segment: object) -> MachOSegmentView:
    sections = tuple(_lief_section(section) for section in getattr(segment, "sections", ()))
    return MachOSegmentView(
        _text(getattr(segment, "name", None), where="LIEF segment name"),
        _integer(getattr(segment, "virtual_address", None), where="LIEF segment address"),
        _integer(getattr(segment, "virtual_size", None), where="LIEF segment size"),
        _integer(getattr(segment, "file_offset", None), where="LIEF segment file offset"),
        _integer(getattr(segment, "file_size", None), where="LIEF segment file size"),
        _integer(getattr(segment, "max_protection", None), where="LIEF segment max protection"),
        _integer(
            getattr(segment, "init_protection", None),
            where="LIEF segment initial protection",
        ),
        _integer(
            getattr(segment, "numberof_sections", None),
            where="LIEF segment section count",
        ),
        _integer(getattr(segment, "flags", None), where="LIEF segment flags"),
        sections,
    )


def _lief_symbol_view(symbol: object, *, where: str) -> MachOSymbolView:
    return MachOSymbolView(
        _text(getattr(symbol, "name", None), where=f"{where} name"),
        _integer(getattr(symbol, "raw_type", None), where=f"{where} type"),
        _integer(
            getattr(symbol, "numberof_sections", None),
            where=f"{where} section number",
        ),
        _integer(getattr(symbol, "description", None), where=f"{where} description"),
        _integer(getattr(symbol, "value", None), where=f"{where} value"),
    )


def _lief_binding_view(
    binding: object,
    segments: tuple[MachOSegmentView, ...],
) -> MachOBindingView:
    for field in ("has_segment", "has_library", "has_symbol"):
        if not _boolean(getattr(binding, field, None), where=f"LIEF binding {field}"):
            raise MachOProfileError(f"LIEF binding has no {field.removeprefix('has_')}")
    segment_name = _text(
        getattr(getattr(binding, "segment", None), "name", None),
        where="LIEF binding segment",
    )
    indexes = [index for index, segment in enumerate(segments) if segment.name == segment_name]
    if len(indexes) != 1:
        raise MachOProfileError("LIEF binding segment does not resolve uniquely")
    return MachOBindingView(
        _integer(getattr(binding, "address", None), where="LIEF binding address"),
        indexes[0],
        segment_name,
        _integer(
            getattr(binding, "library_ordinal", None),
            where="LIEF binding library ordinal",
        ),
        _text(
            getattr(getattr(binding, "library", None), "name", None),
            where="LIEF binding library",
        ),
        _text(
            getattr(getattr(binding, "symbol", None), "name", None),
            where="LIEF binding symbol",
        ),
        _integer(getattr(binding, "binding_type", None), where="LIEF binding type"),
        _integer(getattr(binding, "addend", None), where="LIEF binding addend"),
        _boolean(getattr(binding, "weak_import", None), where="LIEF binding weak-import flag"),
    )


def _resolved_indirect_symbols(
    command: object,
    symbols: tuple[MachOSymbolView, ...],
) -> tuple[tuple[int, ...], tuple[MachOSymbolView, ...]]:
    resolved = tuple(
        _lief_symbol_view(symbol, where="LIEF indirect symbol")
        for symbol in getattr(command, "indirect_symbols", ())
    )
    indexes = []
    for symbol in resolved:
        matches = [index for index, candidate in enumerate(symbols) if candidate == symbol]
        if len(matches) != 1:
            raise MachOProfileError(
                "LIEF indirect symbol does not resolve uniquely into LC_SYMTAB"
            )
        indexes.append(matches[0])
    return tuple(indexes), resolved


_DYSYMTAB_LIEF_FIELDS = (
    "idx_local_symbol",
    "nb_local_symbols",
    "idx_external_define_symbol",
    "nb_external_define_symbols",
    "idx_undefined_symbol",
    "nb_undefined_symbols",
    "toc_offset",
    "nb_toc",
    "module_table_offset",
    "nb_module_table",
    "external_reference_symbol_offset",
    "nb_external_reference_symbols",
    "indirect_symbol_offset",
    "nb_indirect_symbols",
    "external_relocation_offset",
    "nb_external_relocations",
    "local_relocation_offset",
    "nb_local_relocations",
)


def lief_macho_view(binary: object) -> MachOView:
    """Build a typed view only from LIEF's decoded Mach-O objects."""
    header = getattr(binary, "header", None)
    if header is None:
        raise MachOProfileError("LIEF Mach-O has no header")
    commands = tuple(getattr(binary, "commands", ()))
    if not 0 < len(commands) <= _MAX_COMMANDS:
        raise MachOProfileError("LIEF Mach-O command count is outside the bounded profile")

    command_views = []
    segments = []
    got_entries = []
    dyld_info = []
    lief_dyld_commands = []
    symtabs = []
    dysymtabs = []
    lief_dysymtab_commands = []
    dylinkers = []
    uuids = []
    build_versions = []
    source_versions = []
    entry_points = []
    dylibs = []
    signatures = []
    for command in commands:
        command_id = _integer(getattr(command, "command", None), where="LIEF command type")
        command_views.append(
            MachOLoadCommandView(
                command_id,
                _integer(getattr(command, "command_offset", None), where="LIEF command offset"),
                _integer(getattr(command, "size", None), where="LIEF command size"),
            )
        )
        if command_id == _LC_SEGMENT_64:
            segments.append(_lief_segment(command))
            for section in getattr(command, "sections", ()):
                if (
                    getattr(section, "segment_name", None) == "__DATA_CONST"
                    and getattr(section, "name", None) == "__got"
                ):
                    got_entries.append(_decode_got_entries(bytes(section.content)))
        elif command_id == _LC_DYLD_INFO_ONLY:
            lief_dyld_commands.append(command)
            dyld_info.append(
                tuple(
                    _integer(part, where=f"LIEF dyld-info {field}")
                    for field in ("rebase", "bind", "weak_bind", "lazy_bind", "export_info")
                    for part in getattr(command, field)
                )
            )
        elif command_id == _LC_SYMTAB:
            symtabs.append(
                MachOSymtabView(
                    _integer(
                        getattr(command, "symbol_offset", None),
                        where="LIEF symbol-table offset",
                    ),
                    _integer(
                        getattr(command, "numberof_symbols", None),
                        where="LIEF symbol-table count",
                    ),
                    _integer(
                        getattr(command, "strings_offset", None),
                        where="LIEF string-table offset",
                    ),
                    _integer(
                        getattr(command, "strings_size", None),
                        where="LIEF string-table size",
                    ),
                )
            )
        elif command_id == _LC_DYSYMTAB:
            lief_dysymtab_commands.append(command)
            dysymtabs.append(
                MachODysymtabView(
                    tuple(
                        _integer(
                            getattr(command, field, None),
                            where=f"LIEF dynamic-symbol-table {field}",
                        )
                        for field in _DYSYMTAB_LIEF_FIELDS
                    )
                )
            )
        elif command_id == _LC_LOAD_DYLINKER:
            dylinkers.append(
                _text(getattr(command, "name", None), where="LIEF dynamic linker")
            )
        elif command_id == _LC_UUID:
            value = bytes(getattr(command, "uuid", ()))
            if len(value) != 16:
                raise MachOProfileError("LIEF UUID is not 16 bytes")
            uuids.append(value)
        elif command_id == _LC_BUILD_VERSION:
            tools = getattr(command, "tools", ())
            build_versions.append(
                (
                    _integer(getattr(command, "platform", None), where="LIEF build platform"),
                    _version_tuple(getattr(command, "minos", None), where="LIEF minimum OS"),
                    _version_tuple(getattr(command, "sdk", None), where="LIEF SDK"),
                    len(tools),
                )
            )
        elif command_id == _LC_SOURCE_VERSION:
            value = tuple(getattr(command, "version", ()))
            if len(value) != 5:
                raise MachOProfileError("LIEF source version is not five-part")
            source_versions.append(
                tuple(_integer(part, where="LIEF source version") for part in value)
            )
        elif command_id == _LC_MAIN:
            entry_points.append(
                (
                    _integer(getattr(command, "entrypoint", None), where="LIEF entry point"),
                    _integer(getattr(command, "stack_size", None), where="LIEF stack size"),
                )
            )
        elif command_id == _LC_LOAD_DYLIB:
            dylibs.append(
                MachODylibView(
                    _text(getattr(command, "name", None), where="LIEF dylib name"),
                    _integer(getattr(command, "timestamp", None), where="LIEF dylib timestamp"),
                    _version_tuple(
                        getattr(command, "current_version", None),
                        where="LIEF current dylib version",
                    ),
                    _version_tuple(
                        getattr(command, "compatibility_version", None),
                        where="LIEF compatibility dylib version",
                    ),
                )
            )
        elif command_id == _LC_CODE_SIGNATURE:
            signatures.append(
                (
                    _integer(
                        getattr(command, "data_offset", None),
                        where="LIEF code-signature offset",
                    ),
                    _integer(
                        getattr(command, "data_size", None),
                        where="LIEF code-signature size",
                    ),
                )
            )

    # ``binary.symbols`` is a union: LIEF can synthesize additional symbols from the dyld
    # bind stream.  Gate consensus here is specifically over LC_SYMTAB/nlist, which is the
    # table the macholib-side reader decodes.  Retaining DYLD_BIND entries would quietly
    # compare different source structures whenever their names diverge.
    lief_symbols = tuple(
        symbol
        for symbol in getattr(binary, "symbols", ())
        if getattr(getattr(symbol, "origin", None), "name", None) == "SYMTAB"
    )
    symbols = tuple(
        _lief_symbol_view(symbol, where="LIEF LC_SYMTAB symbol") for symbol in lief_symbols
    )
    bind_opcode_streams = tuple(
        bytes(getattr(command, "bind_opcodes", b"")) for command in lief_dyld_commands
    )
    bindings = tuple(
        tuple(
            _lief_binding_view(binding, tuple(segments))
            for binding in getattr(command, "bindings", ())
        )
        for command in lief_dyld_commands
    )
    indirect = tuple(
        _resolved_indirect_symbols(command, symbols)
        for command in lief_dysymtab_commands
    )
    indirect_symbol_indexes = tuple(item[0] for item in indirect)
    indirect_symbols = tuple(item[1] for item in indirect)
    section_count = sum(len(segment.sections) for segment in segments)
    binding_count = sum(len(items) for items in bindings)
    if (
        len(symbols) > _MAX_SYMBOLS
        or section_count > _MAX_SECTIONS
        or binding_count > _MAX_BINDINGS
    ):
        raise MachOProfileError("LIEF Mach-O exceeds the bounded semantic profile")

    return MachOView(
        _integer(getattr(binary, "original_size", None), where="LIEF file size"),
        MachOHeaderView(
            _integer(getattr(header, "magic", None), where="LIEF magic"),
            _integer(getattr(header, "cpu_type", None), where="LIEF CPU type"),
            _integer(getattr(header, "cpu_subtype", None), where="LIEF CPU subtype"),
            _integer(getattr(header, "file_type", None), where="LIEF file type"),
            _integer(getattr(header, "nb_cmds", None), where="LIEF command count"),
            _integer(getattr(header, "sizeof_cmds", None), where="LIEF command bytes"),
            _integer(getattr(header, "flags", None), where="LIEF header flags"),
            _integer(getattr(header, "reserved", None), where="LIEF reserved header value"),
        ),
        tuple(command_views),
        tuple(segments),
        tuple(dyld_info),
        bind_opcode_streams,
        bindings,
        tuple(symtabs),
        tuple(dysymtabs),
        indirect_symbol_indexes,
        indirect_symbols,
        tuple(got_entries),
        tuple(dylinkers),
        tuple(uuids),
        tuple(build_versions),
        tuple(source_versions),
        tuple(entry_points),
        tuple(dylibs),
        symbols,
        tuple(signatures),
    )


def _macholib_section(section: object) -> MachOSectionView:
    return MachOSectionView(
        _fixed_name(getattr(section, "sectname", None), where="macholib section name"),
        _fixed_name(
            getattr(section, "segname", None),
            where="macholib section segment name",
        ),
        _integer(getattr(section, "addr", None), where="macholib section address"),
        _integer(getattr(section, "size", None), where="macholib section size"),
        _integer(getattr(section, "offset", None), where="macholib section file offset"),
        _integer(getattr(section, "align", None), where="macholib section alignment"),
        _integer(getattr(section, "reloff", None), where="macholib relocation offset"),
        _integer(getattr(section, "nreloc", None), where="macholib relocation count"),
        _integer(getattr(section, "flags", None), where="macholib section flags"),
        _integer(getattr(section, "reserved1", None), where="macholib section reserved1"),
        _integer(getattr(section, "reserved2", None), where="macholib section reserved2"),
        _integer(getattr(section, "reserved3", None), where="macholib section reserved3"),
    )


def _macholib_segment(command: object, data: object) -> MachOSegmentView:
    if not isinstance(data, list):
        raise MachOProfileError("macholib segment sections are not a list")
    sections = tuple(_macholib_section(section) for section in data)
    return MachOSegmentView(
        _fixed_name(getattr(command, "segname", None), where="macholib segment name"),
        _integer(getattr(command, "vmaddr", None), where="macholib segment address"),
        _integer(getattr(command, "vmsize", None), where="macholib segment size"),
        _integer(getattr(command, "fileoff", None), where="macholib segment file offset"),
        _integer(getattr(command, "filesize", None), where="macholib segment file size"),
        _integer(getattr(command, "maxprot", None), where="macholib segment max protection"),
        _integer(
            getattr(command, "initprot", None),
            where="macholib segment initial protection",
        ),
        _integer(getattr(command, "nsects", None), where="macholib segment section count"),
        _integer(getattr(command, "flags", None), where="macholib segment flags"),
        sections,
    )


_DYSYMTAB_MACHOLIB_FIELDS = (
    "ilocalsym",
    "nlocalsym",
    "iextdefsym",
    "nextdefsym",
    "iundefsym",
    "nundefsym",
    "tocoff",
    "ntoc",
    "modtaboff",
    "nmodtab",
    "extrefsymoff",
    "nextrefsyms",
    "indirectsymoff",
    "nindirectsyms",
    "extreloff",
    "nextrel",
    "locreloff",
    "nlocrel",
)


def _read_bounded(path: str) -> bytes:
    try:
        with open(path, "rb") as stream:
            data = stream.read(_MAX_MACHO_BYTES + 1)
    except OSError as exc:
        raise MachOProfileError(f"cannot read Mach-O bytes: {exc}") from exc
    if len(data) > _MAX_MACHO_BYTES:
        raise MachOProfileError(
            f"Mach-O exceeds the {_MAX_MACHO_BYTES}-byte semantic-oracle limit"
        )
    return data


def _raw_symbols(data: bytes, symtab: MachOSymtabView) -> tuple[MachOSymbolView, ...]:
    if not 0 <= symtab.symbol_count <= _MAX_SYMBOLS:
        raise MachOProfileError("Mach-O symbol count exceeds the bounded profile")
    symbols_end = symtab.symbol_offset + symtab.symbol_count * 16
    strings_end = symtab.strings_offset + symtab.strings_size
    if (
        symtab.symbol_offset < 0
        or symtab.strings_offset < 0
        or symtab.strings_size < 1
        or symbols_end > len(data)
        or strings_end > len(data)
    ):
        raise MachOProfileError("Mach-O symbol or string table exceeds the file")
    strings = data[symtab.strings_offset:strings_end]
    result = []
    for index in range(symtab.symbol_count):
        string_index, raw_type, section, description, value = struct.unpack_from(
            "<IBBHQ", data, symtab.symbol_offset + index * 16
        )
        if string_index >= len(strings):
            raise MachOProfileError("Mach-O symbol string index exceeds the string table")
        end = strings.find(b"\x00", string_index)
        if end < 0:
            raise MachOProfileError("Mach-O symbol name has no string-table terminator")
        try:
            name = strings[string_index:end].decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise MachOProfileError("Mach-O symbol name is not ASCII") from exc
        if not name:
            raise MachOProfileError("Mach-O symbol name is empty")
        result.append(MachOSymbolView(name, raw_type, section, description, value))
    return tuple(result)


def _bounded_slice(data: bytes, offset: int, size: int, *, where: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise MachOProfileError(f"{where} exceeds the Mach-O file")
    return data[offset:offset + size]


def _read_uleb(stream: bytes, cursor: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if cursor >= len(stream):
            raise MachOProfileError("dyld bind ULEB128 is truncated")
        byte = stream[cursor]
        cursor += 1
        payload = byte & 0x7F
        if shift == 63 and payload > 1:
            raise MachOProfileError("dyld bind ULEB128 overflows uint64")
        value |= payload << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
    raise MachOProfileError("dyld bind ULEB128 exceeds ten bytes")


def _read_sleb(stream: bytes, cursor: int) -> tuple[int, int]:
    value = 0
    shift = 0
    byte = 0
    for _ in range(10):
        if cursor >= len(stream):
            raise MachOProfileError("dyld bind SLEB128 is truncated")
        byte = stream[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value |= -(1 << shift)
            if not -(1 << 63) <= value < (1 << 63):
                raise MachOProfileError("dyld bind SLEB128 overflows int64")
            return value, cursor
    raise MachOProfileError("dyld bind SLEB128 exceeds ten bytes")


def _bind_symbol(stream: bytes, cursor: int) -> tuple[str, int]:
    end = stream.find(b"\x00", cursor, min(len(stream), cursor + 1025))
    if end < 0:
        raise MachOProfileError("dyld bind symbol is unterminated or exceeds 1024 bytes")
    try:
        name = stream[cursor:end].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise MachOProfileError("dyld bind symbol is not ASCII") from exc
    return _text(name, where="dyld bind symbol"), end + 1


def _decode_bind_stream(
    stream: bytes,
    segments: tuple[MachOSegmentView, ...],
    dylibs: tuple[MachODylibView, ...],
) -> tuple[MachOBindingView, ...]:
    """Decode the bounded classic dyld bind opcode language independently of LIEF."""
    cursor = 0
    binding_type = 0
    segment_index = -1
    segment_offset = 0
    library_ordinal = 0
    symbol_name = ""
    symbol_flags = 0
    addend = 0
    result = []

    def emit() -> None:
        nonlocal segment_offset
        if not 0 <= segment_index < len(segments):
            raise MachOProfileError("dyld bind references an invalid segment index")
        if not 1 <= library_ordinal <= len(dylibs):
            raise MachOProfileError("dyld bind references an unsupported library ordinal")
        if not symbol_name:
            raise MachOProfileError("dyld bind occurs before a symbol is selected")
        segment = segments[segment_index]
        if segment_offset < 0 or segment_offset + 8 > segment.virtual_size:
            raise MachOProfileError("dyld bind address lies outside its segment")
        result.append(
            MachOBindingView(
                segment.virtual_address + segment_offset,
                segment_index,
                segment.name,
                library_ordinal,
                dylibs[library_ordinal - 1].name,
                symbol_name,
                binding_type,
                addend,
                bool(symbol_flags & 1),
            )
        )
        if len(result) > _MAX_BINDINGS:
            raise MachOProfileError("dyld bind stream exceeds the binding-count limit")

    while cursor < len(stream):
        byte = stream[cursor]
        cursor += 1
        opcode, immediate = byte & 0xF0, byte & 0x0F
        if opcode == 0x00:  # BIND_OPCODE_DONE, followed by writer padding
            if any(stream[cursor:]):
                raise MachOProfileError("dyld bind stream has opcodes after DONE")
            return tuple(result)
        if opcode == 0x10:  # SET_DYLIB_ORDINAL_IMM
            library_ordinal = immediate
        elif opcode == 0x20:  # SET_DYLIB_ORDINAL_ULEB
            library_ordinal, cursor = _read_uleb(stream, cursor)
        elif opcode == 0x30:  # SET_DYLIB_SPECIAL_IMM
            library_ordinal = immediate | (-16 if immediate & 8 else 0)
        elif opcode == 0x40:  # SET_SYMBOL_TRAILING_FLAGS_IMM
            if immediate & ~0x03:
                raise MachOProfileError("dyld bind symbol flags are unsupported")
            symbol_flags = immediate
            symbol_name, cursor = _bind_symbol(stream, cursor)
        elif opcode == 0x50:  # SET_TYPE_IMM
            binding_type = immediate
        elif opcode == 0x60:  # SET_ADDEND_SLEB
            addend, cursor = _read_sleb(stream, cursor)
        elif opcode == 0x70:  # SET_SEGMENT_AND_OFFSET_ULEB
            segment_index = immediate
            segment_offset, cursor = _read_uleb(stream, cursor)
        elif opcode == 0x80:  # ADD_ADDR_ULEB
            increment, cursor = _read_uleb(stream, cursor)
            segment_offset += increment
        elif opcode == 0x90:  # DO_BIND
            emit()
            segment_offset += 8
        elif opcode == 0xA0:  # DO_BIND_ADD_ADDR_ULEB
            emit()
            increment, cursor = _read_uleb(stream, cursor)
            segment_offset += 8 + increment
        elif opcode == 0xB0:  # DO_BIND_ADD_ADDR_IMM_SCALED
            emit()
            segment_offset += 8 + immediate * 8
        elif opcode == 0xC0:  # DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            count, cursor = _read_uleb(stream, cursor)
            skip, cursor = _read_uleb(stream, cursor)
            if count > _MAX_BINDINGS - len(result):
                raise MachOProfileError("dyld bind repeat count exceeds the binding limit")
            for _ in range(count):
                emit()
                segment_offset += 8 + skip
        else:
            raise MachOProfileError(f"unsupported dyld bind opcode {opcode:#x}")
    raise MachOProfileError("dyld bind stream has no DONE opcode")


def _raw_indirect_symbols(
    data: bytes,
    dysymtab: MachODysymtabView,
    symbols: tuple[MachOSymbolView, ...],
) -> tuple[tuple[int, ...], tuple[MachOSymbolView, ...]]:
    offset, count = dysymtab.values[12:14]
    if not 0 <= count <= _MAX_SYMBOLS:
        raise MachOProfileError("indirect-symbol count exceeds the bounded profile")
    raw = _bounded_slice(data, offset, count * 4, where="indirect-symbol table")
    indexes = tuple(struct.unpack_from("<I", raw, index * 4)[0] for index in range(count))
    if any(index >= len(symbols) for index in indexes):
        raise MachOProfileError(
            "indirect-symbol table uses a special or out-of-range symbol index"
        )
    return indexes, tuple(symbols[index] for index in indexes)


def macholib_macho_view(path: str) -> MachOView:
    """Build a typed view from macholib plus independent bounded nlist decoding."""
    from macholib.MachO import MachO

    data = _read_bounded(path)
    parsed = MachO(path)
    if len(parsed.headers) != 1:
        raise MachOProfileError("macholib did not observe exactly one thin Mach-O header")
    parsed_header = parsed.headers[0]
    header = parsed_header.header
    raw_commands = tuple(parsed_header.commands)
    if not 0 < len(raw_commands) <= _MAX_COMMANDS:
        raise MachOProfileError("macholib command count is outside the bounded profile")

    command_views = []
    segments = []
    dyld_info = []
    symtabs = []
    dysymtabs = []
    dylinkers = []
    uuids = []
    build_versions = []
    source_versions = []
    entry_points = []
    dylibs = []
    signatures = []
    offset = 32
    for load_command, command, command_data in raw_commands:
        command_id = _integer(getattr(load_command, "cmd", None), where="macholib command type")
        command_size = _integer(
            getattr(load_command, "cmdsize", None), where="macholib command size"
        )
        command_views.append(MachOLoadCommandView(command_id, offset, command_size))
        offset += command_size
        if command_id == _LC_SEGMENT_64:
            segments.append(_macholib_segment(command, command_data))
        elif command_id == _LC_DYLD_INFO_ONLY:
            dyld_info.append(
                tuple(
                    _integer(getattr(command, field, None), where=f"macholib {field}")
                    for field in (
                        "rebase_off",
                        "rebase_size",
                        "bind_off",
                        "bind_size",
                        "weak_bind_off",
                        "weak_bind_size",
                        "lazy_bind_off",
                        "lazy_bind_size",
                        "export_off",
                        "export_size",
                    )
                )
            )
        elif command_id == _LC_SYMTAB:
            symtabs.append(
                MachOSymtabView(
                    _integer(getattr(command, "symoff", None), where="macholib symbol offset"),
                    _integer(getattr(command, "nsyms", None), where="macholib symbol count"),
                    _integer(getattr(command, "stroff", None), where="macholib strings offset"),
                    _integer(getattr(command, "strsize", None), where="macholib strings size"),
                )
            )
        elif command_id == _LC_DYSYMTAB:
            dysymtabs.append(
                MachODysymtabView(
                    tuple(
                        _integer(
                            getattr(command, field, None),
                            where=f"macholib dynamic-symbol-table {field}",
                        )
                        for field in _DYSYMTAB_MACHOLIB_FIELDS
                    )
                )
            )
        elif command_id == _LC_LOAD_DYLINKER:
            dylinkers.append(
                _load_command_text(command_data, where="macholib dynamic linker")
            )
        elif command_id == _LC_UUID:
            value = getattr(command, "uuid", None)
            if not isinstance(value, bytes) or len(value) != 16:
                raise MachOProfileError("macholib UUID is not 16 bytes")
            uuids.append(value)
        elif command_id == _LC_BUILD_VERSION:
            build_versions.append(
                (
                    _integer(getattr(command, "platform", None), where="macholib platform"),
                    _packed_version(
                        _integer(getattr(command, "minos", None), where="macholib minimum OS")
                    ),
                    _packed_version(
                        _integer(getattr(command, "sdk", None), where="macholib SDK")
                    ),
                    _integer(getattr(command, "ntools", None), where="macholib tool count"),
                )
            )
        elif command_id == _LC_SOURCE_VERSION:
            source_versions.append(
                _source_version(
                    _integer(
                        getattr(command, "version", None), where="macholib source version"
                    )
                )
            )
        elif command_id == _LC_MAIN:
            entry_points.append(
                (
                    _integer(getattr(command, "entryoff", None), where="macholib entry point"),
                    _integer(getattr(command, "stacksize", None), where="macholib stack size"),
                )
            )
        elif command_id == _LC_LOAD_DYLIB:
            current = getattr(command, "current_version", None)
            compatible = getattr(command, "compatibility_version", None)
            dylibs.append(
                MachODylibView(
                    _load_command_text(command_data, where="macholib dylib name"),
                    _integer(getattr(command, "timestamp", None), where="macholib timestamp"),
                    (
                        _integer(getattr(current, "major", None), where="macholib dylib major"),
                        _integer(getattr(current, "minor", None), where="macholib dylib minor"),
                        _integer(getattr(current, "rev", None), where="macholib dylib revision"),
                    ),
                    (
                        _integer(
                            getattr(compatible, "major", None),
                            where="macholib compatibility major",
                        ),
                        _integer(
                            getattr(compatible, "minor", None),
                            where="macholib compatibility minor",
                        ),
                        _integer(
                            getattr(compatible, "rev", None),
                            where="macholib compatibility revision",
                        ),
                    ),
                )
            )
        elif command_id == _LC_CODE_SIGNATURE:
            signatures.append(
                (
                    _integer(getattr(command, "dataoff", None), where="macholib signature offset"),
                    _integer(getattr(command, "datasize", None), where="macholib signature size"),
                )
            )

    if sum(len(segment.sections) for segment in segments) > _MAX_SECTIONS:
        raise MachOProfileError("macholib Mach-O exceeds the section limit")
    if len(symtabs) != 1:
        symbols = ()
    else:
        symbols = _raw_symbols(data, symtabs[0])
    bind_opcode_streams = tuple(
        _bounded_slice(data, info[2], info[3], where="dyld bind stream")
        for info in dyld_info
    )
    bindings = tuple(
        _decode_bind_stream(stream, tuple(segments), tuple(dylibs))
        for stream in bind_opcode_streams
    )
    indirect = tuple(
        _raw_indirect_symbols(data, dysymtab, symbols) for dysymtab in dysymtabs
    )
    indirect_symbol_indexes = tuple(item[0] for item in indirect)
    indirect_symbols = tuple(item[1] for item in indirect)
    got_entries = tuple(
        _decode_got_entries(
            _bounded_slice(
                data,
                section.file_offset,
                section.size,
                where="Mach-O __got section",
            )
        )
        for segment in segments
        for section in segment.sections
        if (section.segment_name, section.name) == ("__DATA_CONST", "__got")
    )

    return MachOView(
        len(data),
        MachOHeaderView(
            _integer(getattr(header, "magic", None), where="macholib magic"),
            _integer(getattr(header, "cputype", None), where="macholib CPU type"),
            _integer(getattr(header, "cpusubtype", None), where="macholib CPU subtype"),
            _integer(getattr(header, "filetype", None), where="macholib file type"),
            _integer(getattr(header, "ncmds", None), where="macholib command count"),
            _integer(getattr(header, "sizeofcmds", None), where="macholib command bytes"),
            _integer(getattr(header, "flags", None), where="macholib header flags"),
            _integer(getattr(header, "reserved", None), where="macholib reserved header value"),
        ),
        tuple(command_views),
        tuple(segments),
        tuple(dyld_info),
        bind_opcode_streams,
        bindings,
        tuple(symtabs),
        tuple(dysymtabs),
        indirect_symbol_indexes,
        indirect_symbols,
        got_entries,
        tuple(dylinkers),
        tuple(uuids),
        tuple(build_versions),
        tuple(source_versions),
        tuple(entry_points),
        tuple(dylibs),
        symbols,
        tuple(signatures),
    )


_PAGE = 0x4000
_VM_BASE = 0x100000000
_HEADER_FLAGS = 0x200084
_TEXT_FLAGS = 0x80000400
_EXPECTED_DYLIBS = (
    (
        "/usr/lib/libSystem.B.dylib",
        (1356, 0, 0),
        (1, 0, 0),
        (
            "_open",
            "_read",
            "_write",
            "_close",
            "_malloc",
            "_free",
            "_printf",
            "_getpid",
            "_dlopen",
            "_dlsym",
            "_socket",
            "_connect",
        ),
    ),
    (
        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
        (2503, 1, 0),
        (150, 0, 0),
        (
            "_CFRelease",
            "_CFStringCreateWithCString",
            "_CFURLCreateWithString",
            "_CFDataGetBytePtr",
        ),
    ),
    (
        "/System/Library/Frameworks/Security.framework/Versions/A/Security",
        (61439, 0, 0),
        (1, 0, 0),
        (
            "_SecItemCopyMatching",
            "_SecKeychainFindGenericPassword",
            "_SecCodeCopySigningInformation",
        ),
    ),
    (
        "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
        (2503, 1, 0),
        (300, 0, 0),
        ("_NSLog", "_NSHomeDirectory"),
    ),
)


def _profile(condition: bool, message: str) -> None:
    if not condition:
        raise MachOProfileError(message)


def _command_size_for_text(text: str, fixed: int) -> int:
    return fixed + ((len(text.encode("ascii")) + 1 + 7) & ~7)


def _encode_uleb(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def _exact_bind_stream(bindings: tuple[MachOBindingView, ...]) -> bytes:
    stream = bytearray((0x51, 0x72))  # pointer; __DATA_CONST plus ULEB offset zero
    stream.extend(_encode_uleb(0))
    for binding in bindings:
        stream.append(0x10 | binding.library_ordinal)
        stream.append(0x40)
        stream.extend(binding.symbol_name.encode("ascii"))
        stream.extend((0, 0x90))
    stream.append(0x00)
    stream.extend(b"\x00" * (-len(stream) % 8))
    return bytes(stream)


def validate_artifactforge_macho_profile(view: MachOView) -> str:
    """Enforce the exact invariant envelope of the signed arm64 writer profile."""
    header = view.header
    _profile(
        (
            header.magic,
            header.cpu_type,
            header.cpu_subtype,
            header.file_type,
            header.flags,
            header.reserved,
        )
        == (0xFEEDFACF, 0x0100000C, 0, 2, _HEADER_FLAGS, 0),
        "Mach-O header is outside the exact arm64 PIE executable profile",
    )
    _profile(header.command_count == len(view.commands), "Mach-O command count is inconsistent")
    _profile(
        header.command_bytes == sum(command.size for command in view.commands),
        "Mach-O load-command byte count is inconsistent",
    )
    cursor = 32
    for command in view.commands:
        _profile(command.offset == cursor, "Mach-O load commands are not contiguous")
        _profile(command.size >= 8 and command.size % 8 == 0, "Mach-O command size is invalid")
        cursor += command.size
    _profile(cursor == 32 + header.command_bytes, "Mach-O command envelope is inconsistent")

    _profile(1 <= len(view.dylibs) <= len(_EXPECTED_DYLIBS), "Mach-O dylib count is out of profile")
    expected_commands = (
        (_LC_SEGMENT_64,) * 4
        + (
            _LC_DYLD_INFO_ONLY,
            _LC_SYMTAB,
            _LC_DYSYMTAB,
            _LC_LOAD_DYLINKER,
            _LC_UUID,
            _LC_BUILD_VERSION,
            _LC_SOURCE_VERSION,
            _LC_MAIN,
        )
        + (_LC_LOAD_DYLIB,) * len(view.dylibs)
        + (_LC_CODE_SIGNATURE,)
    )
    _profile(
        tuple(command.command for command in view.commands) == expected_commands,
        "Mach-O load-command sequence is outside the exact writer profile",
    )
    expected_fixed_sizes = (72, 232, 152, 72, 48, 24, 80, 32, 24, 24, 16, 24)
    _profile(
        tuple(command.size for command in view.commands[:12]) == expected_fixed_sizes,
        "Mach-O fixed load-command sizes are outside the exact writer profile",
    )
    dylib_commands = view.commands[12:-1]
    _profile(
        tuple(command.size for command in dylib_commands)
        == tuple(_command_size_for_text(dylib.name, 24) for dylib in view.dylibs),
        "Mach-O dylib command padding is outside the exact writer profile",
    )
    _profile(view.commands[-1].size == 16, "Mach-O code-signature command size is not exact")

    _profile(len(view.segments) == 4, "Mach-O must contain exactly four segments")
    pagezero, text, data_const, linkedit = view.segments
    _profile(
        pagezero
        == MachOSegmentView("__PAGEZERO", 0, _VM_BASE, 0, 0, 0, 0, 0, 0, ()),
        "Mach-O __PAGEZERO segment is outside the exact profile",
    )
    _profile(
        (
            text.name,
            text.virtual_address,
            text.virtual_size,
            text.file_offset,
            text.file_size,
            text.max_protection,
            text.init_protection,
            text.section_count,
            text.flags,
        )
        == ("__TEXT", _VM_BASE, _PAGE, 0, _PAGE, 5, 5, 2, 0),
        "Mach-O __TEXT geometry or protections are outside the exact profile",
    )
    _profile(
        (
            data_const.name,
            data_const.virtual_address,
            data_const.virtual_size,
            data_const.file_offset,
            data_const.file_size,
            data_const.max_protection,
            data_const.init_protection,
            data_const.section_count,
            data_const.flags,
        )
        == ("__DATA_CONST", _VM_BASE + _PAGE, _PAGE, _PAGE, _PAGE, 3, 3, 1, 0x10),
        "Mach-O __DATA_CONST geometry or protections are outside the exact profile",
    )
    _profile(
        (
            linkedit.name,
            linkedit.virtual_address,
            linkedit.virtual_size,
            linkedit.file_offset,
            linkedit.max_protection,
            linkedit.init_protection,
            linkedit.section_count,
            linkedit.flags,
            linkedit.sections,
        )
        == ("__LINKEDIT", _VM_BASE + 2 * _PAGE, _PAGE, 2 * _PAGE, 1, 1, 0, 0, ()),
        "Mach-O __LINKEDIT geometry or protections are outside the exact profile",
    )
    _profile(
        linkedit.file_size == view.file_size - 2 * _PAGE and linkedit.file_size > 0,
        "Mach-O __LINKEDIT does not cover the exact file tail",
    )

    _profile(len(text.sections) == 2, "Mach-O __TEXT sections are not exact")
    text_section, cstring = text.sections
    expected_text_offset = (32 + header.command_bytes + 3) & ~3
    _profile(
        text_section
        == MachOSectionView(
            "__text",
            "__TEXT",
            _VM_BASE + expected_text_offset,
            8,
            expected_text_offset,
            2,
            0,
            0,
            _TEXT_FLAGS,
            0,
            0,
            0,
        ),
        "Mach-O __TEXT,__text section is outside the exact profile",
    )
    _profile(
        cstring
        == MachOSectionView(
            "__cstring",
            "__TEXT",
            _VM_BASE + expected_text_offset + 8,
            41,
            expected_text_offset + 8,
            0,
            0,
            0,
            2,
            0,
            0,
            0,
        ),
        "Mach-O __TEXT,__cstring section is outside the exact profile",
    )
    _profile(len(data_const.sections) == 1, "Mach-O __DATA_CONST sections are not exact")
    got = data_const.sections[0]

    _profile(view.dylinkers == ("/usr/lib/dyld",), "Mach-O dynamic linker is not exact")
    _profile(
        view.build_versions == ((1, (14, 0, 0), (14, 4, 0), 0),),
        "Mach-O build-version command is outside the exact macOS 14 profile",
    )
    _profile(
        view.source_versions == ((0, 0, 0, 0, 0),),
        "Mach-O source-version command is not exact",
    )
    _profile(
        view.entry_points == ((expected_text_offset, 0),),
        "Mach-O LC_MAIN does not name the exact __text entry point",
    )
    _profile(
        len(view.uuids) == 1
        and len(view.uuids[0]) == 16
        and view.uuids[0][6] >> 4 == 3
        and view.uuids[0][8] >> 6 == 2,
        "Mach-O UUID is not the writer's RFC-4122 version-3 form",
    )

    selected_library_indexes = []
    for dylib in view.dylibs:
        matches = [
            index
            for index, expected in enumerate(_EXPECTED_DYLIBS)
            if dylib.name == expected[0]
            and dylib.current_version == expected[1]
            and dylib.compatibility_version == expected[2]
            and dylib.timestamp == 2
        ]
        _profile(len(matches) == 1, f"Mach-O dylib {dylib.name!r} is outside the allowlist")
        selected_library_indexes.append(matches[0])
    _profile(
        selected_library_indexes[0] == 0
        and selected_library_indexes == sorted(set(selected_library_indexes)),
        "Mach-O dylib sequence is not the writer's ordered unique subset",
    )

    _profile(len(view.symbol_tables) == 1, "Mach-O must contain exactly one symbol table")
    _profile(
        len(view.dynamic_symbol_tables) == 1,
        "Mach-O must contain exactly one dynamic symbol table",
    )
    _profile(len(view.symbols) >= 4, "Mach-O symbol table is too small")
    undefined = view.symbols[2:]
    _profile(
        view.symbols[:2]
        == (
            MachOSymbolView("__mh_execute_header", 0x0F, 1, 0x10, _VM_BASE),
            MachOSymbolView("_main", 0x0F, 1, 0, _VM_BASE + expected_text_offset),
        ),
        "Mach-O defined symbols are outside the exact profile",
    )
    by_ordinal: dict[int, list[str]] = {index: [] for index in range(1, len(view.dylibs) + 1)}
    for symbol in undefined:
        ordinal = symbol.description >> 8
        _profile(
            symbol.raw_type == 1
            and symbol.section_number == 0
            and symbol.description == ordinal << 8
            and symbol.value == 0
            and ordinal in by_ordinal,
            f"Mach-O undefined symbol {symbol.name!r} has invalid nlist semantics",
        )
        by_ordinal[ordinal].append(symbol.name)
    for ordinal, dylib_index in enumerate(selected_library_indexes, 1):
        allowed = _EXPECTED_DYLIBS[dylib_index][3]
        names = tuple(by_ordinal[ordinal])
        _profile(
            len(names) >= 2
            and len(set(names)) == len(names)
            and names == tuple(name for name in allowed if name in names),
            f"Mach-O undefined symbols for dylib ordinal {ordinal} are outside the exact pool",
        )
    _profile(
        got
        == MachOSectionView(
            "__got",
            "__DATA_CONST",
            _VM_BASE + _PAGE,
            len(undefined) * 8,
            _PAGE,
            3,
            0,
            0,
            6,
            0,
            0,
            0,
        ),
        "Mach-O __got geometry does not match the undefined-symbol count",
    )
    _profile(
        view.got_entries == ((0,) * len(undefined),),
        "Mach-O GOT entries are not the exact zero-initialized slots for undefined symbols",
    )
    expected_bindings = tuple(
        MachOBindingView(
            got.address + index * 8,
            2,
            "__DATA_CONST",
            symbol.description >> 8,
            view.dylibs[(symbol.description >> 8) - 1].name,
            symbol.name,
            1,
            0,
            False,
        )
        for index, symbol in enumerate(undefined)
    )
    _profile(
        view.bindings == (expected_bindings,),
        "Mach-O dyld bindings do not exactly map every undefined symbol to its GOT slot",
    )
    _profile(
        view.bind_opcode_streams == (_exact_bind_stream(expected_bindings),),
        "Mach-O dyld bind opcodes are outside the exact canonical writer sequence",
    )

    symtab = view.symbol_tables[0]
    _profile(symtab.symbol_count == len(view.symbols), "Mach-O LC_SYMTAB count is inconsistent")
    _profile(len(view.dyld_info) == 1, "Mach-O must contain exactly one dyld-info command")
    dyld = view.dyld_info[0]
    _profile(
        dyld[0:2] == (0, 0)
        and dyld[2] == 2 * _PAGE
        and dyld[3] > 0
        and dyld[3] % 8 == 0
        and dyld[4:] == (0, 0, 0, 0, 0, 0),
        "Mach-O dyld-info ranges are outside the exact bind-only profile",
    )
    _profile(
        symtab.symbol_offset == dyld[2] + dyld[3],
        "Mach-O symbol table does not immediately follow the bind stream",
    )
    dysymtab = view.dynamic_symbol_tables[0].values
    expected_dysymtab = (
        0,
        0,
        0,
        2,
        2,
        len(undefined),
        0,
        0,
        0,
        0,
        0,
        0,
        symtab.symbol_offset + 16 * len(view.symbols),
        len(undefined),
        0,
        0,
        0,
        0,
    )
    _profile(dysymtab == expected_dysymtab, "Mach-O dynamic symbol indexes are not exact")
    expected_indirect_indexes = tuple(range(2, 2 + len(undefined)))
    _profile(
        view.indirect_symbol_indexes == (expected_indirect_indexes,),
        "Mach-O indirect-symbol indexes do not map GOT slots to undefined symbols in order",
    )
    _profile(
        view.indirect_symbols == (undefined,),
        "Mach-O resolved indirect symbols disagree with the undefined-symbol sequence",
    )
    _profile(
        symtab.strings_offset == dysymtab[12] + 4 * len(undefined),
        "Mach-O string table does not immediately follow indirect symbols",
    )
    expected_string_bytes = 2 + sum(len(symbol.name.encode("ascii")) + 1 for symbol in view.symbols)
    _profile(
        symtab.strings_size == (expected_string_bytes + 7) & ~7,
        "Mach-O string-table size is outside the exact padded profile",
    )

    _profile(len(view.code_signatures) == 1, "Mach-O must declare exactly one code signature")
    signature_offset, signature_size = view.code_signatures[0]
    _profile(
        signature_offset == (symtab.strings_offset + symtab.strings_size + 15) & ~15
        and signature_offset % 16 == 0
        and signature_size > 0
        and signature_size % 16 == 0
        and signature_offset + signature_size == view.file_size,
        "Mach-O code-signature command does not cover the exact aligned file tail",
    )
    return (
        "profile=artifactforge-arm64-macho-v1,"
        f"commands={len(view.commands)},dylibs={len(view.dylibs)},symbols={len(view.symbols)}"
    )


__all__ = [
    "MachOBindingView",
    "MachODylibView",
    "MachODysymtabView",
    "MachOHeaderView",
    "MachOLoadCommandView",
    "MachOProfileError",
    "MachOSectionView",
    "MachOSegmentView",
    "MachOSymbolView",
    "MachOSymtabView",
    "MachOView",
    "lief_macho_view",
    "macholib_macho_view",
    "validate_artifactforge_macho_profile",
]
