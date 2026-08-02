# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 — validity: do declared parser and semantic oracles validate each artifact?

"Realistic" is not a matter of taste here. Either a parser a responder actually runs opens
the file and the declared structure means what it claims, or it does not. PE, Mach-O,
registry hive and prefetch require two independent implementations because one permissive
parser can hide what a strict one rejects: every prefetch file this project emitted was
accepted by `windowsprefetch` and rejected by `pyscca`, the libyal parser plaso is built on,
for as long as `windowsprefetch` was the only oracle installed. Separate semantic validators
bind PE imports to IMPHASH and the prefetch executable path to its v17 filename hash.

A missing oracle is a FAILURE, never a skip. A skipped check exits 0 and reads exactly like
a passing one.

SQLite databases and binary plists are each read twice: once by the standard-library parser
used to emit them and once by a deliberately narrow, byte-level implementation under
``gates.oracles``.  Typed consensus is a separate semantic check from the macOS artifact
profile, so two parsers agreeing on malformed-but-readable content cannot earn full credit.
Plain sidecars are outside the parser gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import math
import ntpath
import os
from pathlib import PurePosixPath
import re
import struct
import unicodedata
from urllib.parse import urlsplit

from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME
from artifactforge.gates import GateReport
from artifactforge.gates.oracles import (
    loads_bash_history,
    loads_binary_plist,
    loads_desktop_entry,
    loads_sqlite,
)
from artifactforge.inventory import InventoryError, captured_regular_tree

# format -> the oracles that must all read it, plus any declared gap in that oracle set.
ORACLES = {
    "pe":       {"required": ["pefile", "lief"], "gap": None},
    "macho":    {"required": ["lief", "macholib"], "gap": None},
    "hive":     {"required": ["regipy", "libregf"], "gap": None},
    "prefetch": {"required": ["windowsprefetch", "pyscca"], "gap": None},
    "sqlite":   {"required": ["sqlite3", "sqlite-raw"], "gap": None},
    "plist":    {"required": ["plistlib", "bplist-raw"], "gap": None},
    "elf":      {"required": ["lief", "pyelftools"], "gap": None},
    "desktop-entry": {"required": ["pyxdg", "desktop-entry-raw"], "gap": None},
    "bash-history": {"required": ["dissect.target", "bash-history-raw"], "gap": None},
}


#: Files that travel with a scene but are not artifacts: documentation, answer keys, and the
#: quarantine xattr, which is a value emitted as data rather than a format with a parser. They
#: have no oracle because there is nothing to be wrong about. Anything else the gate cannot
#: classify IS a failure — an unidentifiable file in a scene is exactly what should be noticed.
_SIDECAR_SUFFIXES = (".md", ".json", ".txt", ".quarantine.xattr")


class SemanticError(ValueError):
    """A parser opened the container, but its declared semantics did not hold."""


@dataclass(frozen=True)
class _PESemantics:
    imports: tuple[tuple[str, tuple[str, ...]], ...]
    imphash: str

    def detail(self) -> str:
        functions = sum(len(names) for _dll, names in self.imports)
        return f"imports={len(self.imports)}/{functions},imphash={self.imphash}"


@dataclass(frozen=True)
class _SQLiteTableView:
    name: str
    root_page: int
    columns: tuple[tuple[str, str, bool, bool], ...]
    rows: tuple[tuple[int, tuple[tuple[str, object], ...]], ...]


@dataclass(frozen=True)
class _SQLiteIndexView:
    name: str
    table_name: str
    root_page: int
    columns: tuple[str, ...]
    entries: tuple[tuple[tuple[tuple[str, object], ...], int], ...]


@dataclass(frozen=True)
class _SQLiteView:
    schema: tuple[tuple[int, str, str, str, int, str | None], ...]
    tables: tuple[_SQLiteTableView, ...]
    indexes: tuple[_SQLiteIndexView, ...]

    def detail(self) -> str:
        return f"schema={len(self.schema)},tables={len(self.tables)},indexes={len(self.indexes)}"


@dataclass(frozen=True)
class _PlistView:
    value: object
    typed: tuple[str, object]

    def detail(self) -> str:
        if isinstance(self.value, dict):
            return f"keys={','.join(sorted(self.value))}"
        return f"top={self.typed[0]}"


@dataclass(frozen=True)
class _ELFView:
    """Type-exact structural observation shared by LIEF and pyelftools."""

    file_size: int
    header: tuple[object, ...]
    interpreters: tuple[str, ...]
    libraries: tuple[str, ...]
    imported_symbols: tuple[str, ...]
    segments: tuple[tuple[object, ...], ...]
    sections: tuple[tuple[object, ...], ...]
    dynamic: tuple[tuple[str, int, str | None], ...]
    entry_body: bytes
    notes: tuple[tuple[str, int, bytes], ...]

    def detail(self) -> str:
        loads = sum(segment[0] == "LOAD" for segment in self.segments)
        return (
            f"type={self.header[5]},machine={self.header[6]},loads={loads},"
            f"needed={','.join(self.libraries) or '-'}"
        )


@dataclass(frozen=True)
class _DesktopEntryView:
    version: str
    entry_type: str
    name: str
    comment: str
    exec_path: str
    terminal: bool
    hidden: bool
    dbus_activatable: bool
    synthetic_marker: str

    def detail(self) -> str:
        return f"type={self.entry_type},exec={self.exec_path},marker=exact"


@dataclass(frozen=True)
class _BashHistoryView:
    entries: tuple[tuple[int, int, str, str], ...]

    def detail(self) -> str:
        return f"records={len(self.entries)},timestamped={sum(row[0] > 0 for row in self.entries)}"


@dataclass(frozen=True)
class _LinuxArtifactSource:
    """Immutable text bytes plus canonical scene identity for contextual Linux checks."""

    path: str
    relative_path: str
    snapshot: bytes | None
    resident_guest_paths: tuple[str, ...]


_MAX_TYPED_NODES = 256


def _typed_value(value: object) -> tuple[str, object]:
    """Preserve exact scalar types; Python otherwise considers True == 1 == 1.0."""
    visits = 0
    seen_containers: set[int] = set()
    active: set[int] = set()

    def visit(item: object) -> tuple[str, object]:
        nonlocal visits
        visits += 1
        if visits > _MAX_TYPED_NODES:
            raise SemanticError(
                f"parsed object graph exceeds the {_MAX_TYPED_NODES}-node validation limit"
            )
        if item is None:
            return ("null", None)
        if type(item) is bool:
            return ("bool", item)
        if type(item) is int:
            return ("integer", item)
        if type(item) is float:
            if not math.isfinite(item):
                raise SemanticError("parsed value is a non-finite float")
            return ("real", item)
        if type(item) is str:
            return ("text", item)
        if type(item) is bytes:
            return ("blob", item)
        if isinstance(item, (list, tuple, dict)):
            identity = id(item)
            if identity in active:
                raise SemanticError("parsed object graph contains a container cycle")
            if identity in seen_containers:
                raise SemanticError(
                    "parsed object graph reuses a container outside the emitted tree profile"
                )
            seen_containers.add(identity)
            active.add(identity)
            try:
                if isinstance(item, (list, tuple)):
                    return ("array", tuple(visit(child) for child in item))
                if not all(type(key) is str for key in item):
                    raise SemanticError("parsed dictionary has a non-text key")
                return (
                    "dictionary",
                    tuple((key, visit(item[key])) for key in sorted(item)),
                )
            finally:
                active.remove(identity)
        raise SemanticError(f"parsed value has unsupported type {type(item).__name__}")

    return visit(value)


def _scalar(tagged: tuple[str, object], kind: str, where: str):
    if not isinstance(tagged, tuple) or len(tagged) != 2 or tagged[0] != kind:
        observed = tagged[0] if isinstance(tagged, tuple) and tagged else type(tagged).__name__
        raise SemanticError(f"{where} must be {kind}, not {observed}")
    return tagged[1]


def _profile_text(value: object, *, where: str, max_bytes: int) -> str:
    """Gate-local transcription of the emitted ASCII/NFC/no-control text boundary."""
    if type(value) is not str or not value or unicodedata.normalize("NFC", value) != value:
        raise SemanticError(f"{where} must be non-empty NFC text")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise SemanticError(f"{where} contains a control character")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise SemanticError(f"{where} must be ASCII") from exc
    if len(encoded) > max_bytes:
        raise SemanticError(f"{where} exceeds the {max_bytes}-byte profile limit")
    return value


def _classify_head(head: bytes, path: str) -> str | None:
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\xcf\xfa\xed\xfe":
        return "macho"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] == b"regf":
        return "hive"
    if head[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if head[:8] == b"bplist00":
        return "plist"
    if path.lower().endswith(".pf"):
        return "prefetch"
    if path.lower().endswith(".desktop"):
        return "desktop-entry"
    if os.path.basename(path) == ".bash_history":
        return "bash-history"
    return None


def classify(path: str) -> str | None:
    """Which format is this file? Magic first, extension only as a tiebreak."""
    with open(path, "rb") as f:
        return classify_bytes(f.read(16), path)


def classify_bytes(data: bytes, path: str) -> str | None:
    """Classify an already-captured file without reopening a mutable scene path."""
    return _classify_head(data[:16], path)


# --- one reader per oracle. Each returns a short detail value, or raises. ---


def _normalised_imphash(imports: tuple[tuple[str, tuple[str, ...]], ...]) -> str:
    """Compute pefile/VT IMPHASH semantics from one parser's named-import enumeration."""
    parts = []
    for dll, functions in imports:
        library = dll.lower()
        stem, separator, extension = library.rpartition(".")
        if separator and extension in ("ocx", "sys", "dll"):
            library = stem
        parts.extend(f"{library}.{function.lower()}" for function in functions)
    if not parts:
        raise SemanticError("no named imports were enumerated")
    return hashlib.md5(",".join(parts).encode(), usedforsecurity=False).hexdigest()


def _pefile_semantics(pe) -> _PESemantics:
    descriptors = getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
    imports = []
    for descriptor in descriptors:
        dll = descriptor.dll.decode("ascii")
        functions = []
        for entry in descriptor.imports:
            if entry.name is None:
                raise SemanticError(
                    f"ordinal import {entry.ordinal} in {dll} has no stable named semantics"
                )
            functions.append(entry.name.decode("ascii"))
        imports.append((dll, tuple(functions)))
    result = _PESemantics(tuple(imports), pe.get_imphash())
    normalised = _normalised_imphash(result.imports)
    if result.imphash != normalised:
        raise SemanticError(
            f"pefile IMPHASH {result.imphash} != normalised imports {normalised}"
        )
    return result


def _lief_pe_semantics(binary, lief) -> _PESemantics:
    imports = []
    for descriptor in binary.imports:
        functions = []
        for entry in descriptor.entries:
            if entry.is_ordinal or not entry.name:
                raise SemanticError(
                    f"ordinal import {entry.ordinal} in {descriptor.name} has no stable "
                    "named semantics"
                )
            functions.append(entry.name)
        imports.append((descriptor.name, tuple(functions)))
    parser_hash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
    result = _PESemantics(tuple(imports), parser_hash)
    normalised = _normalised_imphash(result.imports)
    if result.imphash != normalised:
        raise SemanticError(
            f"LIEF PEFILE-mode IMPHASH {result.imphash} != normalised imports {normalised}"
        )
    return result


def _read_pefile(path):
    import pefile
    pe = pefile.PE(path)
    return _pefile_semantics(pe)


def _lief_enum_name(value: object, *, where: str) -> str:
    name = getattr(value, "name", None)
    if type(name) is not str or not name:
        raise SemanticError(f"LIEF returned an invalid {where} enum")
    return name


def _elf_kind(value: object, *, prefix: str, where: str) -> str:
    if type(value) is not str or not value.startswith(prefix):
        raise SemanticError(f"pyelftools returned an invalid {where}: {value!r}")
    return value.removeprefix(prefix).rstrip("_")


def _lief_elf_view(binary) -> _ELFView:
    header = binary.header
    abi = _lief_enum_name(header.identity_os_abi, where="ELF OS ABI")
    if abi == "SYSTEMV":
        abi = "SYSV"
    header_view = (
        _lief_enum_name(header.identity_class, where="ELF class"),
        _lief_enum_name(header.identity_data, where="ELF byte order"),
        abi,
        int(header.identity_abi_version),
        _lief_enum_name(header.identity_version, where="ELF identity version"),
        _lief_enum_name(header.file_type, where="ELF file type"),
        _lief_enum_name(header.machine_type, where="ELF machine"),
        _lief_enum_name(header.object_file_version, where="ELF object version"),
        int(header.entrypoint),
        int(header.program_header_offset),
        int(header.section_header_offset),
        int(header.processor_flag),
        int(header.header_size),
        int(header.program_header_size),
        int(header.numberof_segments),
        int(header.section_header_size),
        int(header.numberof_sections),
        int(header.section_name_table_idx),
    )
    segments = tuple(
        (
            _lief_enum_name(segment.type, where="ELF segment type"),
            int(segment.flags),
            int(segment.file_offset),
            int(segment.virtual_address),
            int(segment.physical_size),
            int(segment.virtual_size),
            int(segment.alignment),
        )
        for segment in binary.segments
    )
    sections = tuple(
        (
            section.name,
            _lief_enum_name(section.type, where="ELF section type")
            .removeprefix("SHT_")
            .rstrip("_"),
            int(section.flags),
            int(section.virtual_address),
            int(section.offset),
            int(section.size),
            int(section.link),
            int(section.information),
            int(section.alignment),
            int(section.entry_size),
        )
        for section in binary.sections
    )
    dynamic = []
    for entry in binary.dynamic_entries:
        tag = _lief_enum_name(entry.tag, where="ELF dynamic tag")
        needed = getattr(entry, "name", None) if tag == "NEEDED" else None
        if needed is not None and type(needed) is not str:
            raise SemanticError("LIEF returned a non-text DT_NEEDED value")
        dynamic.append((tag, int(entry.value), needed))
    notes = tuple(
        (note.name.rstrip("\x00"), int(note.original_type), bytes(note.description))
        for note in binary.notes
    )
    text_sections = tuple(section for section in binary.sections if section.name == ".text")
    if len(text_sections) != 1:
        raise SemanticError("LIEF did not find exactly one ELF .text section")
    return _ELFView(
        int(binary.original_size),
        header_view,
        (binary.interpreter,) if binary.interpreter else (),
        tuple(binary.libraries),
        tuple(symbol.name for symbol in binary.imported_symbols),
        segments,
        sections,
        tuple(dynamic),
        bytes(text_sections[0].content),
        notes,
    )


def _read_pyelftools(path):
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as stream:
        file_size = os.fstat(stream.fileno()).st_size
        binary = ELFFile(stream)
        header = binary.header
        identity = header["e_ident"]
        header_view = (
            "ELF" + _elf_kind(
                identity["EI_CLASS"], prefix="ELFCLASS", where="ELF class"
            ),
            _elf_kind(identity["EI_DATA"], prefix="ELFDATA2", where="ELF byte order"),
            _elf_kind(identity["EI_OSABI"], prefix="ELFOSABI_", where="ELF OS ABI"),
            int(identity["EI_ABIVERSION"]),
            _elf_kind(identity["EI_VERSION"], prefix="EV_", where="ELF identity version"),
            _elf_kind(header["e_type"], prefix="ET_", where="ELF file type"),
            _elf_kind(header["e_machine"], prefix="EM_", where="ELF machine"),
            _elf_kind(header["e_version"], prefix="EV_", where="ELF object version"),
            int(header["e_entry"]),
            int(header["e_phoff"]),
            int(header["e_shoff"]),
            int(header["e_flags"]),
            int(header["e_ehsize"]),
            int(header["e_phentsize"]),
            int(header["e_phnum"]),
            int(header["e_shentsize"]),
            int(header["e_shnum"]),
            int(header["e_shstrndx"]),
        )
        segment_objects = tuple(binary.iter_segments())
        segments = tuple(
            (
                _elf_kind(segment.header.p_type, prefix="PT_", where="ELF segment type"),
                int(segment.header.p_flags),
                int(segment.header.p_offset),
                int(segment.header.p_vaddr),
                int(segment.header.p_filesz),
                int(segment.header.p_memsz),
                int(segment.header.p_align),
            )
            for segment in segment_objects
        )
        section_objects = tuple(binary.iter_sections())
        sections = tuple(
            (
                section.name,
                _elf_kind(section.header.sh_type, prefix="SHT_", where="ELF section type"),
                int(section.header.sh_flags),
                int(section.header.sh_addr),
                int(section.header.sh_offset),
                int(section.header.sh_size),
                int(section.header.sh_link),
                int(section.header.sh_info),
                int(section.header.sh_addralign),
                int(section.header.sh_entsize),
            )
            for section in section_objects
        )
        interpreters = []
        dynamic = []
        notes = []
        for segment in segment_objects:
            if segment.header.p_type == "PT_INTERP":
                value = segment.data()
                if not value.endswith(b"\x00") or b"\x00" in value[:-1]:
                    raise SemanticError("pyelftools found a malformed PT_INTERP string")
                interpreters.append(value[:-1].decode("ascii"))
            elif segment.header.p_type == "PT_DYNAMIC":
                for entry in segment.iter_tags():
                    tag = _elf_kind(entry.entry.d_tag, prefix="DT_", where="ELF dynamic tag")
                    needed = entry.needed if tag == "NEEDED" else None
                    if needed is not None and type(needed) is not str:
                        raise SemanticError("pyelftools returned a non-text DT_NEEDED value")
                    dynamic.append((tag, int(entry.entry.d_val), needed))
            elif segment.header.p_type == "PT_NOTE":
                for note in segment.iter_notes():
                    if type(note["n_name"]) is not str or type(note["n_type"]) is not int:
                        raise SemanticError("pyelftools returned an invalid ELF note identity")
                    notes.append((note["n_name"], note["n_type"], bytes(note["n_desc"])))
        dynamic_symbols = binary.get_section_by_name(".dynsym")
        imported_symbols = ()
        if dynamic_symbols is not None:
            imported_symbols = tuple(
                symbol.name
                for symbol in dynamic_symbols.iter_symbols()
                if symbol["st_shndx"] == "SHN_UNDEF" and symbol.name
            )
        libraries = tuple(needed for tag, _value, needed in dynamic if tag == "NEEDED")
        text_section = binary.get_section_by_name(".text")
        if text_section is None:
            raise SemanticError("pyelftools did not find exactly one ELF .text section")
        return _ELFView(
            file_size,
            header_view,
            tuple(interpreters),
            libraries,
            imported_symbols,
            segments,
            sections,
            tuple(dynamic),
            text_section.data(),
            tuple(notes),
        )


def _read_lief(path):
    import lief
    b = lief.parse(path)
    if b is None:
        raise ValueError("lief returned None")
    if isinstance(b, lief.PE.Binary):
        return _lief_pe_semantics(b, lief)
    if isinstance(b, lief.ELF.Binary):
        return _lief_elf_view(b)
    return f"format={b.format}"


def _read_macholib(path):
    from macholib.MachO import MachO
    m = MachO(path)
    return f"headers={len(m.headers)},cmds={len(m.headers[0].commands)}"


def _read_regipy(path):
    from regipy.registry import RegistryHive
    return f"root={RegistryHive(path).root.name}"


def _read_libregf(path):
    import pyregf
    f = pyregf.file()
    f.open(path)
    try:
        return f"root={f.get_root_key().name}"
    finally:
        f.close()


def _read_windowsprefetch(path):
    from windowsprefetch import Prefetch
    return f"exe={Prefetch(path).executableName}"


def _read_pyscca(path):
    import pyscca
    f = pyscca.file()
    f.open(path)
    try:
        return f"exe={f.get_executable_filename()}"
    finally:
        f.close()


def _bounded_rows(cursor, *, limit: int, where: str) -> tuple[tuple, ...]:
    rows = cursor.fetchmany(limit + 1)
    if len(rows) > limit:
        raise SemanticError(f"{where} exceeds the {limit}-row validation limit")
    return tuple(rows)


def _quoted_identifier(value: object) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 256:
        raise SemanticError("SQLite schema contains an invalid or oversized identifier")
    if any(ord(character) < 0x20 for character in value):
        raise SemanticError("SQLite schema identifier contains a control character")
    return '"' + value.replace('"', '""') + '"'


def _sqlite_standard_view(con) -> _SQLiteView:
    integrity = _bounded_rows(
        con.execute("PRAGMA integrity_check"), limit=1, where="SQLite integrity_check"
    )
    if integrity != (("ok",),):
        raise SemanticError(f"SQLite integrity_check was not exactly one ok row: {integrity!r}")

    schema_rows = _bounded_rows(
        con.execute(
            "SELECT rowid, type, name, tbl_name, rootpage, sql "
            "FROM sqlite_schema ORDER BY rowid"
        ),
        limit=32,
        where="SQLite schema",
    )
    schema = []
    for row in schema_rows:
        if (
            len(row) != 6
            or type(row[0]) is not int
            or type(row[1]) is not str
            or type(row[2]) is not str
            or type(row[3]) is not str
            or type(row[4]) is not int
            or (row[5] is not None and type(row[5]) is not str)
        ):
            raise SemanticError("sqlite3 returned a malformed schema observation")
        schema.append(row)

    tables = []
    for _rowid, kind, name, table_name, root_page, _sql in schema:
        if kind != "table":
            continue
        if name != table_name:
            raise SemanticError(f"SQLite table {name!r} has inconsistent ownership")
        quoted = _quoted_identifier(name)
        column_rows = _bounded_rows(
            con.execute(f"PRAGMA table_info({quoted})"),
            limit=32,
            where=f"SQLite table {name!r} columns",
        )
        columns = []
        for column in column_rows:
            if (
                len(column) != 6
                or type(column[0]) is not int
                or type(column[1]) is not str
                or type(column[2]) is not str
                or type(column[5]) is not int
            ):
                raise SemanticError(f"sqlite3 returned malformed columns for {name!r}")
            primary_key = column[5] == 1
            columns.append(
                (column[1], column[2], primary_key, primary_key and column[2] == "INTEGER")
            )
        if not columns:
            raise SemanticError(f"SQLite table {name!r} has no columns")
        row_values = _bounded_rows(
            con.execute(f"SELECT rowid, * FROM {quoted} ORDER BY rowid"),
            limit=64,
            where=f"SQLite table {name!r}",
        )
        observed_rows = []
        for row in row_values:
            if len(row) != len(columns) + 1 or type(row[0]) is not int:
                raise SemanticError(f"sqlite3 returned malformed rows for {name!r}")
            observed_rows.append((row[0], tuple(_typed_value(value) for value in row[1:])))
        tables.append(_SQLiteTableView(name, root_page, tuple(columns), tuple(observed_rows)))

    indexes = []
    table_names = {table.name for table in tables}
    for _rowid, kind, name, table_name, root_page, _sql in schema:
        if kind == "table":
            continue
        if kind != "index" or table_name not in table_names:
            raise SemanticError(f"SQLite schema object {name!r} is not an owned table/index")
        quoted_index = _quoted_identifier(name)
        quoted_table = _quoted_identifier(table_name)
        info = _bounded_rows(
            con.execute(f"PRAGMA index_info({quoted_index})"),
            limit=16,
            where=f"SQLite index {name!r} columns",
        )
        if not info or any(
            len(row) != 3 or type(row[0]) is not int or type(row[2]) is not str
            for row in info
        ):
            raise SemanticError(f"sqlite3 returned malformed index columns for {name!r}")
        columns = tuple(row[2] for row in info)
        select_columns = ", ".join(_quoted_identifier(column) for column in columns)
        entries = _bounded_rows(
            con.execute(
                f"SELECT {select_columns}, rowid FROM {quoted_table} "
                f"INDEXED BY {quoted_index} ORDER BY {select_columns}, rowid"
            ),
            limit=64,
            where=f"SQLite index {name!r}",
        )
        observed_entries = []
        for entry in entries:
            if len(entry) != len(columns) + 1 or type(entry[-1]) is not int:
                raise SemanticError(f"sqlite3 returned malformed entries for index {name!r}")
            observed_entries.append(
                (tuple(_typed_value(value) for value in entry[:-1]), entry[-1])
            )
        indexes.append(
            _SQLiteIndexView(
                name, table_name, root_page, columns, tuple(observed_entries)
            )
        )
    return _SQLiteView(tuple(schema), tuple(tables), tuple(indexes))


def _read_sqlite3(data):
    import sqlite3

    if type(data) is not bytes:
        raise SemanticError("sqlite3 reader requires the gate's immutable byte snapshot")
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(data)
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA trusted_schema=OFF")
        progress_calls = 0

        def bounded_progress():
            nonlocal progress_calls
            progress_calls += 1
            return int(progress_calls > 10_000)

        con.set_progress_handler(bounded_progress, 100)
        return _sqlite_standard_view(con)
    finally:
        con.close()


def _read_sqlite_raw(data):
    if type(data) is not bytes:
        raise SemanticError("raw SQLite reader requires the gate's immutable byte snapshot")
    database = loads_sqlite(data)
    schema = tuple(
        (row.rowid, row.kind, row.name, row.table_name, row.root_page, row.sql)
        for row in database.schema
    )
    tables = tuple(
        _SQLiteTableView(
            table.name,
            table.root_page,
            tuple(
                (
                    column.name,
                    column.declared_type,
                    column.primary_key,
                    column.rowid_alias,
                )
                for column in table.columns
            ),
            tuple(
                (row.rowid, tuple(_typed_value(value) for value in row.values))
                for row in table.rows
            ),
        )
        for table in database.tables
    )
    indexes = tuple(
        _SQLiteIndexView(
            index.name,
            index.table_name,
            index.root_page,
            index.columns,
            tuple(
                (
                    tuple(_typed_value(value) for value in entry.key),
                    entry.rowid,
                )
                for entry in index.entries
            ),
        )
        for index in database.indexes
    )
    return _SQLiteView(schema, tables, indexes)


def _read_plistlib(data):
    import plistlib
    if type(data) is not bytes:
        raise SemanticError("plistlib reader requires the gate's immutable byte snapshot")
    value = plistlib.loads(data)
    return _PlistView(value, _typed_value(value))


def _read_bplist_raw(data):
    if type(data) is not bytes:
        raise SemanticError("raw plist reader requires the gate's immutable byte snapshot")
    value = loads_binary_plist(data)
    return _PlistView(value, _typed_value(value))


def _linux_text_source(source: object, *, where: str) -> _LinuxArtifactSource:
    if not isinstance(source, _LinuxArtifactSource) or type(source.snapshot) is not bytes:
        raise SemanticError(f"{where} requires the gate's bounded immutable text snapshot")
    return source


def _desktop_view(values: tuple[object, ...], *, oracle: str) -> _DesktopEntryView:
    if len(values) != 9:
        raise SemanticError(f"{oracle} returned an invalid desktop-entry field count")
    if any(type(value) is not str for value in (*values[:5], values[8])):
        raise SemanticError(f"{oracle} returned a non-text desktop-entry field")
    if any(type(value) is not bool for value in values[5:8]):
        raise SemanticError(f"{oracle} returned a non-boolean desktop-entry field")
    return _DesktopEntryView(*values)


def _read_pyxdg(source):
    from xdg.DesktopEntry import DesktopEntry

    artifact = _linux_text_source(source, where="PyXDG")
    entry = DesktopEntry(artifact.path)
    # PyXDG 0.28's validate() predates DBusActivatable and rejects that current key.  Its
    # parser and typed getters remain the independent observation; the strict shipped reader
    # below owns exact-profile validation, including duplicate rejection.
    return _desktop_view(
        (
            entry.getVersionString(),
            entry.getType(),
            entry.getName(),
            entry.getComment(),
            entry.getExec(),
            entry.getTerminal(),
            entry.getHidden(),
            entry.get("DBusActivatable", type="boolean"),
            entry.get("X-ArtifactForge-Synthetic"),
        ),
        oracle="PyXDG",
    )


def _read_desktop_entry_raw(source):
    artifact = _linux_text_source(source, where="desktop-entry raw reader")
    entry = loads_desktop_entry(artifact.snapshot)
    return _desktop_view(
        (
            entry.version,
            entry.entry_type,
            entry.name,
            entry.comment,
            entry.exec_path,
            entry.terminal,
            entry.hidden,
            entry.dbus_activatable,
            entry.synthetic_marker,
        ),
        oracle="desktop-entry raw reader",
    )


def _read_dissect_bash_history(source):
    from dissect.target import Target
    from dissect.target.filesystem import VirtualFilesystem

    artifact = _linux_text_source(source, where="dissect.target")
    # Exercise the public bashhistory() plugin on an isolated in-memory target.  The only
    # mapped evidence is the bounded snapshot plus inert identity metadata needed for Linux
    # user discovery; no command is ever handed to a shell or process launcher.
    filesystem = VirtualFilesystem()
    filesystem.map_file_fh("/home/v/.bash_history", BytesIO(artifact.snapshot))
    filesystem.map_file_fh(
        "/etc/passwd",
        BytesIO(b"v:x:1000:1000:ArtifactForge:/home/v:/bin/bash\n"),
    )
    filesystem.map_file_fh("/etc/os-release", BytesIO(b"ID=artifactforge\n"))
    filesystem.makedirs("/var")
    filesystem.makedirs("/run")
    target = Target()
    target.filesystems.add(filesystem)
    target.apply()

    rows = []
    for record in target.bashhistory():
        if record.ts is None:
            raise SemanticError("dissect.target returned an untimestamped Bash record")
        epoch = int(record.ts.timestamp())
        if record.ts != datetime.fromtimestamp(epoch, timezone.utc):
            raise SemanticError("dissect.target returned a non-integral or non-UTC timestamp")
        order = int(record.order)
        command = str(record.command)
        shell = str(record.shell)
        rows.append((epoch, order, command, shell))
    return _BashHistoryView(tuple(rows))


def _read_bash_history_raw(source):
    artifact = _linux_text_source(source, where="Bash-history raw reader")
    entries = loads_bash_history(
        artifact.snapshot,
        resident_paths=artifact.resident_guest_paths,
    )
    return _BashHistoryView(
        tuple((entry.epoch, order, entry.command, "bash") for order, entry in enumerate(entries))
    )


READERS = {
    "pefile": _read_pefile,
    "lief": _read_lief,
    "macholib": _read_macholib,
    "regipy": _read_regipy,
    "libregf": _read_libregf,
    "windowsprefetch": _read_windowsprefetch,
    "pyscca": _read_pyscca,
    "sqlite3": _read_sqlite3,
    "sqlite-raw": _read_sqlite_raw,
    "plistlib": _read_plistlib,
    "bplist-raw": _read_bplist_raw,
    "pyelftools": _read_pyelftools,
    "pyxdg": _read_pyxdg,
    "desktop-entry-raw": _read_desktop_entry_raw,
    "dissect.target": _read_dissect_bash_history,
    "bash-history-raw": _read_bash_history_raw,
}


def _validate_pe_consensus(_path: str, reads: dict) -> str:
    """Require two independent PE parsers to enumerate the same import semantics."""
    pefile_result = reads.get("pefile")
    lief_result = reads.get("lief")
    if not isinstance(pefile_result, _PESemantics) or not isinstance(
        lief_result, _PESemantics
    ):
        raise SemanticError("pefile and LIEF semantic results are both required")
    if pefile_result.imports != lief_result.imports:
        raise SemanticError(
            "pefile and LIEF enumerated different DLL/function import sequences"
        )
    if pefile_result.imphash != lief_result.imphash:
        raise SemanticError(
            f"pefile IMPHASH {pefile_result.imphash} != LIEF PEFILE-mode IMPHASH "
            f"{lief_result.imphash}"
        )
    return pefile_result.detail()


def _independent_scca_xp_hash(path: str) -> int:
    """Gate-local transcription; deliberately does not call the production writer helper."""
    intermediate = 0
    for value in path.upper().encode("utf-16-le"):
        intermediate = (intermediate * 37 + value) % (1 << 32)
    mixed = (intermediate * 314159269) % (1 << 32)
    signed = mixed - (1 << 32) if mixed & (1 << 31) else mixed
    return abs(signed) % 1000000007


def _bounded(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise SemanticError(
            f"{label} range {offset}:{offset + size} exceeds {len(data)} bytes"
        )
    return data[offset:offset + size]


def _validate_scca_v17(path: str, _reads: dict) -> str:
    """Bind the raw v17 executable path to both header hash and on-disk PF name."""
    with open(path, "rb") as file:
        data = file.read()
    _bounded(data, 0, 152, "SCCA v17 fixed header")
    version, signature = struct.unpack_from("<I4s", data)
    if (version, signature) != (17, b"SCCA"):
        raise SemanticError(f"expected uncompressed SCCA v17, got {version}/{signature!r}")
    declared_size = struct.unpack_from("<I", data, 12)[0]
    if declared_size != len(data):
        raise SemanticError(f"header file size {declared_size} != actual size {len(data)}")

    executable = data[16:76].decode("utf-16-le").split("\x00", 1)[0]
    embedded_hash = struct.unpack_from("<I", data, 76)[0]
    metrics_offset, metrics_count = struct.unpack_from("<II", data, 84)
    strings_offset, strings_size = struct.unpack_from("<II", data, 100)
    if metrics_count < 1:
        raise SemanticError("file metrics array carries no executable path")
    _bounded(data, metrics_offset, metrics_count * 20, "file metrics array")
    _bounded(data, strings_offset, strings_size, "filename strings array")

    filename_offset, filename_characters = struct.unpack_from(
        "<II", data, metrics_offset + 8
    )
    path_offset = strings_offset + filename_offset
    path_size = filename_characters * 2
    if filename_offset + path_size + 2 > strings_size:
        raise SemanticError("modeled executable path exceeds the filename strings array")
    raw_path = _bounded(data, path_offset, path_size, "modeled executable path")
    if _bounded(data, path_offset + path_size, 2, "modeled path terminator") != b"\x00\x00":
        raise SemanticError("modeled executable path is not NUL terminated")
    executable_path = raw_path.decode("utf-16-le")
    expected_executable = ntpath.basename(executable_path).upper()
    if executable != expected_executable:
        raise SemanticError(
            f"header executable {executable!r} != path basename {expected_executable!r}"
        )

    calculated_hash = _independent_scca_xp_hash(executable_path)
    if embedded_hash != calculated_hash:
        raise SemanticError(
            f"header hash {embedded_hash:08X} != SCCA XP path hash {calculated_hash:08X}"
        )
    expected_filename = f"{executable}-{calculated_hash:08X}.pf"
    if os.path.basename(path) != expected_filename:
        raise SemanticError(
            f"prefetch filename {os.path.basename(path)!r} != {expected_filename!r}"
        )
    return f"path={executable_path},hash={calculated_hash:08X}"


_MARKER_COLUMNS = (
    ("marker", "TEXT", False, False),
    ("notice", "TEXT", False, False),
)
_MARKER_SQL = f"CREATE TABLE {RESERVED_NAME} (marker TEXT, notice TEXT)"
_KNOWLEDGE_SQL = (
    "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, "
    "ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL)"
)
_TCC_SQL = (
    "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, "
    "auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER)"
)
_QUARANTINE_SQL = (
    "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY, "
    "LSQuarantineTimeStamp REAL, LSQuarantineAgentName TEXT, "
    "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT)"
)
_QUARANTINE_UUID = re.compile(
    r"[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}"
)
_LAUNCH_LABEL = re.compile(
    r"[a-z][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62}){2,}"
)


def _sqlite_pair(reads: dict) -> _SQLiteView:
    standard = reads.get("sqlite3")
    raw = reads.get("sqlite-raw")
    if type(standard) is not _SQLiteView or type(raw) is not _SQLiteView:
        raise SemanticError("typed sqlite3 and raw-reader observations are both required")
    if standard.schema != raw.schema:
        raise SemanticError("sqlite3 and raw reader disagree on schema/root-page/SQL identity")
    if standard.tables != raw.tables:
        raise SemanticError("sqlite3 and raw reader disagree on typed table rows or row order")
    if standard.indexes != raw.indexes:
        raise SemanticError("sqlite3 and raw reader disagree on index columns or entries")
    return raw


def _validate_sqlite_consensus(_path: str, reads: dict) -> str:
    view = _sqlite_pair(reads)
    return view.detail()


def _table(view: _SQLiteView, name: str) -> _SQLiteTableView:
    matches = tuple(table for table in view.tables if table.name == name)
    if len(matches) != 1:
        raise SemanticError(f"SQLite profile requires exactly one {name!r} table")
    return matches[0]


def _marker_table(view: _SQLiteView) -> _SQLiteTableView:
    marker = _table(view, RESERVED_NAME)
    if marker.columns != _MARKER_COLUMNS:
        raise SemanticError("synthetic marker table schema is not exact")
    expected = ((1, (("text", MARKER), ("text", NOTICE))),)
    if marker.rows != expected:
        raise SemanticError("synthetic marker table must carry exactly the canonical marker row")
    return marker


def _require_schema(view: _SQLiteView, expected: tuple) -> None:
    if view.schema != expected:
        raise SemanticError("SQLite schema, root-page ownership, or CREATE SQL is outside profile")


def _knowledge_profile(view: _SQLiteView) -> str:
    _require_schema(
        view,
        (
            (1, "table", "ZOBJECT", "ZOBJECT", 2, _KNOWLEDGE_SQL),
            (2, "table", RESERVED_NAME, RESERVED_NAME, 3, _MARKER_SQL),
        ),
    )
    table = _table(view, "ZOBJECT")
    expected_columns = (
        ("Z_PK", "INTEGER", True, True),
        ("ZSTREAMNAME", "TEXT", False, False),
        ("ZVALUESTRING", "TEXT", False, False),
        ("ZSTARTDATE", "REAL", False, False),
        ("ZENDDATE", "REAL", False, False),
    )
    if table.columns != expected_columns or len(table.rows) != 3:
        raise SemanticError("knowledgeC requires its exact five-column schema and three rows")
    bundles = set()
    for rowid, values in table.rows:
        primary_key = _scalar(values[0], "integer", "knowledgeC Z_PK")
        stream = _scalar(values[1], "text", "knowledgeC ZSTREAMNAME")
        bundle = _scalar(values[2], "text", "knowledgeC ZVALUESTRING")
        start = _scalar(values[3], "real", "knowledgeC ZSTARTDATE")
        end = _scalar(values[4], "real", "knowledgeC ZENDDATE")
        if rowid <= 0 or primary_key != rowid:
            raise SemanticError("knowledgeC Z_PK must be the positive table rowid")
        if stream != "/app/inFocus":
            raise SemanticError("knowledgeC stream must be exactly /app/inFocus")
        _profile_text(bundle, where="knowledgeC bundle identity", max_bytes=128)
        if bundle in bundles:
            raise SemanticError("knowledgeC bundle identities must be non-empty and unique")
        if (
            not math.isfinite(start)
            or not math.isfinite(end)
            or abs(start) >= 2**53
            or abs(end) >= 2**53
            or end <= start
        ):
            raise SemanticError("knowledgeC interval must be finite with end after start")
        bundles.add(bundle)
    _marker_table(view)
    return "rows=3,stream=/app/inFocus,marker=exact"


def _tcc_profile(view: _SQLiteView) -> str:
    _require_schema(
        view,
        (
            (1, "table", "access", "access", 2, _TCC_SQL),
            (2, "table", RESERVED_NAME, RESERVED_NAME, 3, _MARKER_SQL),
        ),
    )
    table = _table(view, "access")
    expected_columns = (
        ("service", "TEXT", False, False),
        ("client", "TEXT", False, False),
        ("client_type", "INTEGER", False, False),
        ("auth_value", "INTEGER", False, False),
        ("auth_reason", "INTEGER", False, False),
        ("last_modified", "INTEGER", False, False),
    )
    if table.columns != expected_columns or len(table.rows) != 4:
        raise SemanticError("TCC requires its exact six-column schema and four rows")
    clients = set()
    auth_values = []
    for _rowid, values in table.rows:
        service = _scalar(values[0], "text", "TCC service")
        client = _scalar(values[1], "text", "TCC client")
        client_type = _scalar(values[2], "integer", "TCC client_type")
        auth_value = _scalar(values[3], "integer", "TCC auth_value")
        auth_reason = _scalar(values[4], "integer", "TCC auth_reason")
        timestamp = _scalar(values[5], "integer", "TCC last_modified")
        _profile_text(service, where="TCC service", max_bytes=96)
        _profile_text(client, where="TCC client", max_bytes=128)
        if client in clients:
            raise SemanticError("TCC service/client values must be non-empty and clients unique")
        if client_type != 0 or auth_value not in {0, 2} or auth_reason != 3:
            raise SemanticError("TCC client_type/auth_value/auth_reason is outside profile")
        if timestamp <= 0:
            raise SemanticError("TCC last_modified must be a positive integer Unix timestamp")
        clients.add(client)
        auth_values.append(auth_value)
    if sorted(auth_values) != [0, 0, 2, 2]:
        raise SemanticError("TCC must contain exactly two grants and two denials")
    _marker_table(view)
    return "rows=4,grants=2,denials=2,marker=exact"


def _https_url(value: str, where: str) -> None:
    _profile_text(value, where=where, max_bytes=256)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise SemanticError(f"{where} must be a bounded HTTPS URL without credentials/fragment")


def _quarantine_profile(view: _SQLiteView) -> str:
    index_name = "sqlite_autoindex_LSQuarantineEvent_1"
    _require_schema(
        view,
        (
            (1, "table", "LSQuarantineEvent", "LSQuarantineEvent", 2, _QUARANTINE_SQL),
            (2, "index", index_name, "LSQuarantineEvent", 3, None),
            (3, "table", RESERVED_NAME, RESERVED_NAME, 4, _MARKER_SQL),
        ),
    )
    table = _table(view, "LSQuarantineEvent")
    expected_columns = (
        ("LSQuarantineEventIdentifier", "TEXT", True, False),
        ("LSQuarantineTimeStamp", "REAL", False, False),
        ("LSQuarantineAgentName", "TEXT", False, False),
        ("LSQuarantineDataURLString", "TEXT", False, False),
        ("LSQuarantineOriginURLString", "TEXT", False, False),
    )
    if table.columns != expected_columns or len(table.rows) != 5:
        raise SemanticError("QuarantineEventsV2 requires its exact schema and five rows")
    expected_entries = []
    identifiers = set()
    for rowid, values in table.rows:
        identifier = _scalar(values[0], "text", "quarantine identifier")
        timestamp = _scalar(values[1], "real", "quarantine timestamp")
        agent = _scalar(values[2], "text", "quarantine agent")
        data_url = _scalar(values[3], "text", "quarantine data URL")
        origin_url = _scalar(values[4], "text", "quarantine origin URL")
        _profile_text(identifier, where="quarantine identifier", max_bytes=36)
        _profile_text(agent, where="quarantine agent", max_bytes=64)
        if not _QUARANTINE_UUID.fullmatch(identifier) or identifier in identifiers:
            raise SemanticError("quarantine identifiers must be unique uppercase RFC 4122 v4 UUIDs")
        if not math.isfinite(timestamp) or timestamp < 0 or timestamp >= 2**53:
            raise SemanticError("quarantine time must be finite Mac time and agent non-empty")
        _https_url(data_url, "quarantine data URL")
        _https_url(origin_url, "quarantine origin URL")
        identifiers.add(identifier)
        expected_entries.append(((("text", identifier),), rowid))
    if len(view.indexes) != 1:
        raise SemanticError("QuarantineEventsV2 must own exactly one primary-key autoindex")
    index = view.indexes[0]
    if (
        index.name != index_name
        or index.table_name != "LSQuarantineEvent"
        or index.root_page != 3
        or index.columns != ("LSQuarantineEventIdentifier",)
        or index.entries != tuple(sorted(expected_entries))
    ):
        raise SemanticError("quarantine primary-key index does not exactly cover table rows")
    _marker_table(view)
    return "rows=5,uuid-v4=5,https=10,index=exact,marker=exact"


def _validate_macos_sqlite_profile(path: str, reads: dict) -> str:
    view = _sqlite_pair(reads)
    name = os.path.basename(path)
    if name == "knowledgeC.db":
        return _knowledge_profile(view)
    if name == "TCC.db":
        return _tcc_profile(view)
    if name == "QuarantineEventsV2":
        return _quarantine_profile(view)
    raise SemanticError(f"SQLite artifact name {name!r} has no declared macOS profile")


def _plist_pair(reads: dict) -> _PlistView:
    standard = reads.get("plistlib")
    raw = reads.get("bplist-raw")
    if type(standard) is not _PlistView or type(raw) is not _PlistView:
        raise SemanticError("typed plistlib and raw-reader observations are both required")
    if standard.typed != raw.typed:
        raise SemanticError("plistlib and raw reader disagree on the type-exact object graph")
    return raw


def _validate_bplist_consensus(_path: str, reads: dict) -> str:
    view = _plist_pair(reads)
    return view.detail()


def _normal_posix_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        value.startswith("/")
        and value != "/"
        and "\\" not in value
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in value.split("/")[1:])
    )


def _validate_launchagent_profile(path: str, reads: dict) -> str:
    view = _plist_pair(reads)
    value = view.value
    expected_keys = {
        "Label",
        "ProgramArguments",
        "RunAtLoad",
        "StartInterval",
        RESERVED_NAME,
        f"{RESERVED_NAME}_notice",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise SemanticError("LaunchAgent must contain exactly the six declared keys")
    label = value["Label"]
    arguments = value["ProgramArguments"]
    if type(label) is not str or label != os.path.basename(path).removesuffix(".plist"):
        raise SemanticError("LaunchAgent Label must exactly match its plist filename")
    _profile_text(label, where="LaunchAgent Label", max_bytes=128)
    if not _LAUNCH_LABEL.fullmatch(label):
        raise SemanticError("LaunchAgent Label must be a lowercase reverse-DNS identifier")
    if (
        type(arguments) is not list
        or len(arguments) != 1
        or type(arguments[0]) is not str
        or not _normal_posix_path(arguments[0])
    ):
        raise SemanticError("LaunchAgent ProgramArguments must be one absolute normal path")
    _profile_text(arguments[0], where="LaunchAgent program path", max_bytes=512)
    if value["RunAtLoad"] is not True:
        raise SemanticError("LaunchAgent RunAtLoad must be the boolean true")
    if type(value["StartInterval"]) is not int or value["StartInterval"] != 3600:
        raise SemanticError("LaunchAgent StartInterval must be the integer 3600")
    if value[RESERVED_NAME] != MARKER or value[f"{RESERVED_NAME}_notice"] != NOTICE:
        raise SemanticError("LaunchAgent synthetic marker and notice must be exact")
    return f"label={label},program={arguments[0]},marker=exact"


_ELF_PROFILE_HEADER = (
    "ELF64", "LSB", "SYSV", 0, "CURRENT", "DYN", "X86_64", "CURRENT",
    4096, 64, 8336, 0, 64, 56, 9, 64, 7, 6,
)
_ELF_PROFILE_SEGMENTS = (
    ("PHDR", 4, 64, 64, 504, 504, 8),
    ("INTERP", 4, 568, 568, 28, 28, 1),
    ("LOAD", 4, 0, 0, 675, 675, 4096),
    ("LOAD", 5, 4096, 4096, 9, 9, 4096),
    ("LOAD", 6, 8192, 8192, 80, 80, 4096),
    ("DYNAMIC", 6, 8192, 8192, 80, 80, 8),
    ("NOTE", 4, 596, 596, 68, 68, 4),
    ("GNU_STACK", 6, 0, 0, 0, 0, 16),
    ("GNU_RELRO", 4, 8192, 8192, 80, 80, 1),
)
_ELF_PROFILE_SECTIONS = (
    ("", "NULL", 0, 0, 0, 0, 0, 0, 0, 0),
    (".interp", "PROGBITS", 2, 568, 568, 28, 0, 0, 1, 0),
    (".note.artifactforge", "NOTE", 2, 596, 596, 68, 0, 0, 4, 0),
    (".dynstr", "STRTAB", 2, 664, 664, 11, 0, 0, 1, 0),
    (".text", "PROGBITS", 6, 4096, 4096, 9, 0, 0, 16, 0),
    (".dynamic", "DYNAMIC", 3, 8192, 8192, 80, 3, 0, 8, 16),
    (".shstrtab", "STRTAB", 0, 0, 8272, 62, 0, 0, 1, 0),
)
_ELF_PROFILE_DYNAMIC = (
    ("NEEDED", 1, "libc.so.6"),
    ("STRTAB", 664, None),
    ("STRSZ", 11, None),
    ("FLAGS_1", 0x08000000, None),
    ("NULL", 0, None),
)
_ELF_PROFILE_MARKER = re.compile(br"ARTIFACTFORGE-SYNTHETIC-[0-9a-f]{16}")
_LINUX_COMPONENT = r"[A-Za-z0-9._+@-]+"
_LINUX_RESIDENT_PATH = re.compile(
    rf"home/(?P<user>{_LINUX_COMPONENT})/\.local/bin/(?P<name>{_LINUX_COMPONENT})"
)
_LINUX_DESKTOP_PATH = re.compile(
    rf"home/(?P<user>{_LINUX_COMPONENT})/\.config/autostart/"
    rf"(?P<name>{_LINUX_COMPONENT})\.desktop"
)
_LINUX_HISTORY_PATH = re.compile(rf"home/(?P<user>{_LINUX_COMPONENT})/\.bash_history")
_LINUX_HISTORY_MARKER = ": 'ARTIFACTFORGE-SYNTHETIC-LINUX'"


def _linux_source(value: object, *, where: str) -> _LinuxArtifactSource:
    if not isinstance(value, _LinuxArtifactSource):
        raise SemanticError(f"{where} requires canonical recursive scene context")
    return value


def _elf_pair(reads: dict) -> _ELFView:
    lief_view = reads.get("lief")
    pyelftools_view = reads.get("pyelftools")
    if type(lief_view) is not _ELFView or type(pyelftools_view) is not _ELFView:
        raise SemanticError("typed LIEF and pyelftools ELF observations are both required")
    if lief_view != pyelftools_view:
        raise SemanticError("LIEF and pyelftools disagree on the type-exact ELF structure")
    return lief_view


def _validate_elf_consensus(_source: object, reads: dict) -> str:
    return _elf_pair(reads).detail()


def _validate_linux_elf_profile(source: object, reads: dict) -> str:
    artifact = _linux_source(source, where="Linux ELF profile")
    match = _LINUX_RESIDENT_PATH.fullmatch(artifact.relative_path)
    if match is None:
        raise SemanticError("Linux ELF must be served at home/<user>/.local/bin/<name>")
    view = _elf_pair(reads)
    if view.file_size != 8784:
        raise SemanticError("ELF file size must be exactly 8784 bytes")
    if view.header != _ELF_PROFILE_HEADER:
        raise SemanticError("ELF header is outside the exact glibc/x86-64 PIE profile")
    if view.interpreters != ("/lib64/ld-linux-x86-64.so.2",):
        raise SemanticError("ELF must declare only the exact x86-64 glibc interpreter")
    if view.libraries != ("libc.so.6",) or view.imported_symbols:
        raise SemanticError("ELF must need only libc.so.6 and import no symbols")
    if view.segments != _ELF_PROFILE_SEGMENTS:
        raise SemanticError("ELF program-header sequence is outside the exact segment profile")
    if view.sections != _ELF_PROFILE_SECTIONS:
        raise SemanticError("ELF section-header sequence is outside the exact section profile")
    if view.dynamic != _ELF_PROFILE_DYNAMIC:
        raise SemanticError("ELF dynamic table is outside the exact tag allowlist")
    if view.entry_body != bytes.fromhex("31ffb83c0000000f05"):
        raise SemanticError("ELF .text is not the exact nine-byte direct-exit entry body")
    if (
        len(view.notes) != 1
        or view.notes[0][:2] != ("ArtifactForge", 0xAF01)
        or _ELF_PROFILE_MARKER.fullmatch(view.notes[0][2]) is None
    ):
        raise SemanticError("ELF must carry exactly one canonical ArtifactForge note")
    return f"profile=glibc-x86_64,guest=/{artifact.relative_path},marker=exact"


def _desktop_pair(reads: dict) -> _DesktopEntryView:
    pyxdg = reads.get("pyxdg")
    raw = reads.get("desktop-entry-raw")
    if type(pyxdg) is not _DesktopEntryView or type(raw) is not _DesktopEntryView:
        raise SemanticError("typed PyXDG and raw desktop-entry observations are both required")
    if pyxdg != raw:
        raise SemanticError("PyXDG and raw reader disagree on typed desktop-entry fields")
    return raw


def _validate_desktop_entry_consensus(_source: object, reads: dict) -> str:
    return _desktop_pair(reads).detail()


def _validate_xdg_plain_text(value: object, *, where: str, max_bytes: int) -> str:
    """Enforce the gate-local UTF-8 text boundary for an emitted XDG field."""
    if type(value) is not str or not value:
        raise SemanticError(f"XDG autostart {where} must be non-empty text")
    if unicodedata.normalize("NFC", value) != value:
        raise SemanticError(f"XDG autostart {where} must be Unicode NFC")
    if value != value.strip():
        raise SemanticError(
            f"XDG autostart {where} cannot have surrounding whitespace"
        )
    if "\\" in value:
        raise SemanticError(f"XDG autostart {where} cannot use escape syntax")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise SemanticError(f"XDG autostart {where} cannot contain control characters")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise SemanticError(f"XDG autostart {where} must be valid UTF-8") from exc
    if len(encoded) > max_bytes:
        raise SemanticError(
            f"XDG autostart {where} exceeds the {max_bytes}-byte profile limit"
        )
    return value


def _validate_xdg_autostart_profile(source: object, reads: dict) -> str:
    artifact = _linux_source(source, where="XDG autostart profile")
    match = _LINUX_DESKTOP_PATH.fullmatch(artifact.relative_path)
    if match is None:
        raise SemanticError(
            "XDG autostart must be served at home/<user>/.config/autostart/<name>.desktop"
        )
    view = _desktop_pair(reads)
    _validate_xdg_plain_text(view.name, where="Name", max_bytes=256)
    _validate_xdg_plain_text(view.comment, where="Comment", max_bytes=1024)
    try:
        exec_size = len(view.exec_path.encode("ascii", errors="strict"))
    except UnicodeEncodeError as exc:
        raise SemanticError("XDG autostart Exec must be an ASCII path") from exc
    if exec_size > 1024:
        raise SemanticError("XDG autostart Exec exceeds the 1024-byte profile limit")
    expected_exec = re.compile(
        rf"/home/{re.escape(match.group('user'))}/\.local/bin/{_LINUX_COMPONENT}"
    )
    if expected_exec.fullmatch(view.exec_path) is None:
        raise SemanticError("XDG autostart Exec must name one same-user local-bin guest path")
    if (
        view.version != "1.5"
        or view.entry_type != "Application"
        or view.terminal is not False
        or view.hidden is not False
        or view.dbus_activatable is not False
        or view.synthetic_marker != MARKER
    ):
        raise SemanticError("XDG autostart typed values are outside the exact inert-data profile")
    return f"profile=xdg-autostart-v1,exec={view.exec_path},marker=exact"


def _bash_pair(reads: dict) -> _BashHistoryView:
    dissect = reads.get("dissect.target")
    raw = reads.get("bash-history-raw")
    if type(dissect) is not _BashHistoryView or type(raw) is not _BashHistoryView:
        raise SemanticError("typed dissect.target and raw Bash-history observations are required")
    if dissect != raw:
        raise SemanticError("dissect.target and raw reader disagree on typed Bash-history rows")
    return raw


def _validate_bash_history_consensus(_source: object, reads: dict) -> str:
    return _bash_pair(reads).detail()


def _validate_bash_history_profile(source: object, reads: dict) -> str:
    artifact = _linux_source(source, where="Bash-history profile")
    match = _LINUX_HISTORY_PATH.fullmatch(artifact.relative_path)
    if match is None:
        raise SemanticError("Bash history must be served at home/<user>/.bash_history")
    view = _bash_pair(reads)
    if len(view.entries) != 4:
        raise SemanticError(
            "Linux scene Bash history must contain exactly four timestamped records"
        )
    for index, (_epoch, order, _command, shell) in enumerate(view.entries):
        if order != index or shell != "bash":
            raise SemanticError("Bash-history order and shell observations must be exact")
    if view.entries[0][2] != _LINUX_HISTORY_MARKER:
        raise SemanticError(
            "Linux scene Bash history must begin with the exact synthetic disclosure record"
        )

    expected_path = re.compile(
        rf"/home/{re.escape(match.group('user'))}/\.local/bin/{_LINUX_COMPONENT}"
    )
    direct_commands = tuple(entry[2] for entry in view.entries[1:])
    if any(expected_path.fullmatch(command) is None for command in direct_commands):
        raise SemanticError(
            "Linux scene Bash history must contain only three direct same-user local-bin paths "
            "after its disclosure record"
        )
    if len(set(direct_commands)) != 3:
        raise SemanticError(
            "Linux scene Bash history direct resident paths must be exactly three and distinct"
        )
    residents = frozenset(artifact.resident_guest_paths)
    if any(command not in residents for command in direct_commands):
        raise SemanticError(
            "Linux scene Bash history direct commands must name resident ELF bytes"
        )
    return "profile=extended-bash-v1,records=4,direct-resident-paths=3,marker=exact"


SEMANTIC_VALIDATORS = {
    "pe": [("import-consensus", _validate_pe_consensus)],
    "prefetch": [("scca-v17-path-hash", _validate_scca_v17)],
    "sqlite": [
        ("sqlite-consensus", _validate_sqlite_consensus),
        ("macos-sqlite-profile", _validate_macos_sqlite_profile),
    ],
    "plist": [
        ("bplist-consensus", _validate_bplist_consensus),
        ("launchagent-profile", _validate_launchagent_profile),
    ],
    "elf": [
        ("elf-consensus", _validate_elf_consensus),
        ("linux-elf-profile", _validate_linux_elf_profile),
    ],
    "desktop-entry": [
        ("desktop-entry-consensus", _validate_desktop_entry_consensus),
        ("xdg-autostart-profile", _validate_xdg_autostart_profile),
    ],
    "bash-history": [
        ("bash-history-consensus", _validate_bash_history_consensus),
        ("bash-history-profile", _validate_bash_history_profile),
    ],
}


_SNAPSHOT_LIMITS = {
    "sqlite": 16 * 1024 * 1024,
    "plist": 1024 * 1024,
    "desktop-entry": 64 * 1024,
    "bash-history": 1024 * 1024,
}
_EXPECTED_RESULTS = {
    ("pe", "pefile"): _PESemantics,
    ("pe", "lief"): _PESemantics,
    ("macho", "lief"): str,
    ("macho", "macholib"): str,
    ("hive", "regipy"): str,
    ("hive", "libregf"): str,
    ("prefetch", "windowsprefetch"): str,
    ("prefetch", "pyscca"): str,
    ("sqlite", "sqlite3"): _SQLiteView,
    ("sqlite", "sqlite-raw"): _SQLiteView,
    ("plist", "plistlib"): _PlistView,
    ("plist", "bplist-raw"): _PlistView,
    ("elf", "lief"): _ELFView,
    ("elf", "pyelftools"): _ELFView,
    ("desktop-entry", "pyxdg"): _DesktopEntryView,
    ("desktop-entry", "desktop-entry-raw"): _DesktopEntryView,
    ("bash-history", "dissect.target"): _BashHistoryView,
    ("bash-history", "bash-history-raw"): _BashHistoryView,
}


def _classify_and_snapshot(path: str) -> tuple[str | None, bytes | None, str | None]:
    """Classify once and snapshot bounded formats from that same open file description."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
            fmt = _classify_head(head, path)
            if fmt not in _SNAPSHOT_LIMITS:
                return fmt, None, None
            limit = _SNAPSHOT_LIMITS[fmt]
            handle.seek(0)
            snapshot = handle.read(limit + 1)
    except OSError as exc:
        return None, None, f"cannot snapshot artifact: {type(exc).__name__}: {exc}"
    if len(snapshot) > limit:
        return fmt, None, f"{fmt} artifact exceeds the {limit}-byte snapshot limit"
    return fmt, snapshot, None


def _run_files(r: GateReport, files) -> tuple[int, int, int, int, set[str]]:
    files = tuple(files)
    checked = passed = 0
    semantic_checked = semantic_passed = 0
    seen_formats = set()
    resident_guest_paths = tuple(
        "/" + file.relative_path
        for file in files
        if type(file.data) is bytes
        and classify_bytes(file.data, file.relative_path) == "elf"
    )

    for file in files:
        name = file.relative_path
        path = os.fspath(file.path)
        fmt, snapshot, snapshot_error = _classify_and_snapshot(path)
        # Sidecar suffixes exempt only genuinely unclassified prose. Magic always wins: a
        # structured artifact cannot evade its parser pair by being named .json/.txt/.md or
        # .quarantine.xattr.
        if fmt is None and name.endswith(_SIDECAR_SUFFIXES):
            continue
        if fmt is None:
            detail = snapshot_error or "no format recognised, so nothing can validate it"
            r.fail(f"{name}: {detail}")
            continue
        if fmt not in ORACLES:
            r.fail(f"{name}: format '{fmt}' has no declared oracle set")
            continue
        seen_formats.add(fmt)
        linux_source = _LinuxArtifactSource(
            path,
            name,
            snapshot,
            resident_guest_paths,
        )
        read_results = {}
        for oracle in ORACLES[fmt]["required"]:
            checked += 1
            if snapshot_error:
                r.fail(f"{fmt}: {oracle} did not run — {snapshot_error}")
                continue
            try:
                if fmt in {"desktop-entry", "bash-history"}:
                    source = linux_source
                else:
                    source = snapshot if fmt in _SNAPSHOT_LIMITS else path
                detail = READERS[oracle](source)
            except ImportError:
                r.fail(f"{fmt}: oracle '{oracle}' is not installed — a missing "
                               f"oracle is a failure, not a skip")
                continue
            except Exception as exc:                     # noqa: BLE001 — any parser refusal
                r.fail(f"{fmt}: {oracle} rejected it — "
                               f"{type(exc).__name__}: {str(exc)[:110]}")
                continue
            expected = _EXPECTED_RESULTS.get((fmt, oracle))
            if expected is None or type(detail) is not expected:
                r.fail(
                    f"{fmt}: {oracle} returned an invalid observation shape "
                    f"{type(detail).__name__}"
                )
                continue
            passed += 1
            read_results[oracle] = detail
            rendered = detail.detail() if hasattr(detail, "detail") else detail
            r.metrics.setdefault("reads", {})[f"{name}:{oracle}"] = rendered

        for validator_name, validator in SEMANTIC_VALIDATORS.get(fmt, ()):
            semantic_checked += 1
            try:
                semantic_source = (
                    linux_source
                    if fmt in {"elf", "desktop-entry", "bash-history"}
                    else path
                )
                detail = validator(semantic_source, read_results)
            except Exception as exc:                     # noqa: BLE001 — a semantic refusal
                r.fail(
                    f"{name}: semantic validator '{validator_name}' failed — "
                    f"{type(exc).__name__}: {str(exc)[:110]}"
                )
                continue
            semantic_passed += 1
            r.metrics.setdefault("semantics", {})[f"{name}:{validator_name}"] = detail
    return checked, passed, semantic_checked, semantic_passed, seen_formats


def run(scene_dir: str) -> GateReport:
    r = GateReport(1, "validity",
                   "do declared parser and semantic oracles validate each artifact?")
    inventory_failed = False
    try:
        with captured_regular_tree(scene_dir) as files:
            checked, passed, semantic_checked, semantic_passed, seen_formats = _run_files(
                r, files
            )
    except InventoryError as exc:
        inventory_failed = True
        checked = passed = semantic_checked = semantic_passed = 0
        seen_formats = set()
        r.fail(f"scene inventory is unsafe: {exc}")

    for fmt in sorted(seen_formats):
        if ORACLES[fmt]["gap"]:
            r.gap(f"{fmt}: {ORACLES[fmt]['gap']}")

    if checked == 0 and not inventory_failed:
        # A gate that classified no artifact has not passed; it has not run. Reporting PASS
        # with 0/0 and exiting 0 is the exact vacuous success this project is built to catch,
        # and it did it to itself.
        r.fail(f"no artifact in {scene_dir!r} was classified, so nothing was validated")
    r.metrics["oracle_reads_passed"] = passed
    r.metrics["oracle_reads_total"] = checked
    r.metrics["semantic_checks_passed"] = semantic_passed
    r.metrics["semantic_checks_total"] = semantic_checked
    r.metrics.pop("reads", None)                          # detail is for humans, not the card
    r.metrics.pop("semantics", None)
    r.denominator = (f"{passed}/{checked} oracle reads succeeded; "
                     f"{semantic_passed}/{semantic_checked} semantic checks succeeded")
    return r
