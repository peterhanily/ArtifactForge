# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 — validity: do declared parser and semantic oracles validate each artifact?

The gate establishes only its named scopes: container acceptance, typed extraction,
implementation consensus, exact artifact profile, or a named downstream consumer. None is a
general realism claim, and a parser opening bytes does not imply that a consumer extracts the
intended facts. PE, Mach-O, registry hive and Prefetch require independent implementations
because one permissive parser can hide what a strict one rejects. The frozen public v17 writer
is read by `windowsprefetch` and `pyscca`; current MAM/v30 scenes require bounded first-party
framing/layout validation, `pyscca` acceptance, and typed `pyscca`/Dissect semantic consensus.
Dissect is semantic-only because its EOF-driven decompressor does not prove MAM's declared
output boundary. Plaso also uses libyal's SCCA support, but ArtifactForge does not currently
run a Plaso extraction and makes no downstream Plaso claim. Separate semantic validators bind
PE imports to IMPHASH and each Prefetch executable path to its profile-specific filename hash;
hive validators additionally bind typed trees and regipy plugin output.

A missing oracle is a FAILURE, never a skip. A skipped check exits 0 and reads exactly like
a passing one.

SQLite databases and binary plists are each read twice: once by the standard-library parser
used to emit them and once by a deliberately narrow, byte-level implementation under
``gates.oracles``. Serialized quarantine xattrs are likewise read by both the artifact
parser and an independently implemented gate-local byte reader. Logical Windows
``Zone.Identifier`` streams pair a production-style ``ConfigParser`` adapter with a separate
raw byte reader. Disabled Scheduled Task XML pairs the standard-library ``ElementTree`` view
with a canonical byte reader, then exercises Dissect's bounded ``ScheduledTasks`` consumer.
Shell Links require independent liblnk and LnkParse3 extraction plus the bounded first-party
layout reader; only fields both external parsers preserve exactly enter their typed consensus.
Typed consensus is a separate semantic check from each declared artifact profile, so two
parsers agreeing on malformed-but-readable content cannot earn full credit. Plain prose
sidecars are outside the parser gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import logging
import math
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import struct
import unicodedata
from urllib.parse import urlsplit

from artifactforge.artifacts.shell_link import ShellLinkValue, parse_shell_link
from artifactforge.artifacts.windows_task import (
    ScheduledTaskXmlValue,
    ScheduledTaskXmlWireValue,
    parse_scheduled_task_xml,
    read_scheduled_task_xml_wire,
)
from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME
from artifactforge.gates import GateReport
from artifactforge.gates.oracles import (
    SQLiteWireProfile,
    loads_bash_history,
    loads_binary_plist,
    loads_desktop_entry,
    loads_sqlite,
)
from artifactforge.gates.oracles.macho_profile import (
    MachOView,
    lief_macho_view,
    macholib_macho_view,
    validate_artifactforge_macho_profile,
)
from artifactforge.gates.oracles.prefetch_profile import (
    PrefetchV30OracleView,
    PrefetchV30ProfileView,
    dissect_prefetch_v30_view,
    parse_mam_prefetch_v30_variant1,
    pyscca_prefetch_v30_view,
    require_prefetch_v30_consensus,
    validate_artifactforge_prefetch_v30_profile,
)
from artifactforge.gates.oracles.shell_link_profile import (
    ShellLinkOracleView,
    liblnk_shell_link_view,
    lnkparse3_shell_link_view,
    require_shell_link_consensus,
    validate_artifactforge_shell_link_profile,
)
from artifactforge.inventory import InventoryError, captured_regular_tree

# format -> the oracles that must all read it, plus any declared gap in that oracle set.
ORACLES = {
    "pe":       {"required": ["pefile", "lief"], "gap": None},
    "macho":    {"required": ["lief", "macholib"], "gap": None},
    "hive":     {"required": ["regipy", "libregf"], "gap": None},
    # The old public v17 writer remains a byte-stable compatibility surface. Current scenes
    # use the separate, compressed v30 profile below. Dissect is deliberately semantic-only:
    # its EOF-driven decompressor ignores MAM's declared output size, so the bounded raw
    # reader and pyscca own container acceptance.
    "prefetch-v17": {"required": ["windowsprefetch", "pyscca"], "gap": None},
    "prefetch": {
        "required": ["pyscca", "dissect.target-prefetch", "prefetch-raw"],
        "gap": None,
    },
    "sqlite":   {"required": ["sqlite3", "sqlite-raw"], "gap": None},
    "plist":    {"required": ["plistlib", "bplist-raw"], "gap": None},
    "elf":      {"required": ["lief", "pyelftools"], "gap": None},
    "desktop-entry": {"required": ["pyxdg", "desktop-entry-raw"], "gap": None},
    "bash-history": {"required": ["dissect.target", "bash-history-raw"], "gap": None},
    "quarantine-xattr": {
        "required": ["macos-xattr", "quarantine-xattr-raw"],
        "gap": None,
    },
    "zone-identifier": {
        "required": ["configparser", "zone-identifier-raw"],
        "gap": None,
    },
    "task-xml": {
        "required": ["elementtree", "task-xml-raw", "dissect.target-tasks"],
        "gap": None,
    },
    "shell-link": {
        "required": ["liblnk", "LnkParse3", "shell-link-raw"],
        "gap": None,
    },
}

# Gate 1 reports the strongest bounded claim made by each check rather than collapsing every
# success into one parser count.  Native conformance and realism calibration are deliberately
# absent: neither can be inferred from a portable parser run.
CLAIM_SCOPE_ORDER = (
    "container_acceptance",
    "semantic_extraction",
    "independent_consensus",
    "declared_profile_conformance",
    "downstream_consumer_compatibility",
)

_DEFAULT_READER_CLAIM_SCOPES = ("container_acceptance", "semantic_extraction")
_READER_CLAIM_SCOPE_OVERRIDES = {
    # Dissect's Prefetch parser recovers inner semantics, but its EOF-driven decompressor
    # neither honors nor proves MAM's declared output boundary.
    ("prefetch", "dissect.target-prefetch"): ("semantic_extraction",),
}

# Reader label -> import names that prove the optional oracle itself is absent. An ImportError
# from any other name is a broken/incompatible oracle and must be reported as a parser failure,
# not mislabeled as "not installed". ``dissect`` is a shared namespace package, so a bare
# environment can miss its root while an environment with another dissect package can miss the
# exact target subpackage.
_ORACLE_ABSENT_IMPORTS = {
    "pefile": frozenset({"pefile"}),
    "lief": frozenset({"lief"}),
    "macholib": frozenset({"macholib"}),
    "regipy": frozenset({"regipy"}),
    "libregf": frozenset({"pyregf"}),
    "windowsprefetch": frozenset({"windowsprefetch"}),
    "pyscca": frozenset({"pyscca"}),
    "pyelftools": frozenset({"elftools"}),
    "pyxdg": frozenset({"xdg"}),
    "dissect.target": frozenset({"dissect", "dissect.target"}),
    "dissect.target-prefetch": frozenset(
        {
            "dissect",
            "dissect.target",
            "dissect.target.plugins.os.windows.prefetch",
        }
    ),
    "dissect.target-tasks": frozenset(
        {
            "dissect",
            "dissect.target",
            "dissect.target.plugins.os.windows.tasks",
            "dissect.target.plugins.os.windows.tasks.xml",
        }
    ),
    "liblnk": frozenset({"pylnk"}),
    "LnkParse3": frozenset({"LnkParse3", "LnkParse3.lnk_file"}),
}


#: Files that travel with a scene but are not artifacts: documentation and answer keys. They
#: have no oracle because there is nothing structural to validate. Anything else the gate
#: cannot classify IS a failure — an unidentifiable file in a scene is exactly what should be
#: noticed. Serialized quarantine xattrs are evidence, not exempt sidecars.
_SIDECAR_SUFFIXES = (".md", ".json", ".txt")


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
class _HiveValueView:
    name: str
    type_code: int
    typed_value: tuple[str, object]


@dataclass(frozen=True)
class _HiveKeyView:
    name: str
    last_written_filetime: int
    values: tuple[_HiveValueView, ...]
    subkeys: tuple["_HiveKeyView", ...]


@dataclass(frozen=True)
class _HiveView:
    """Bounded typed registry observation shared by regipy and libregf."""

    file_name: str
    root: _HiveKeyView

    def detail(self) -> str:
        keys = values = 0
        pending = [self.root]
        while pending:
            key = pending.pop()
            keys += 1
            values += len(key.values)
            pending.extend(key.subkeys)
        return f"file={self.file_name},root={self.root.name},keys={keys},values={values}"


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
    wire_profile: str | None = None

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
class _QuarantineXattrView:
    """Type-exact observation of one serialized ``com.apple.quarantine`` value."""

    flags: str
    timestamp_unix: int
    agent: str
    event_uuid: str

    def detail(self) -> str:
        return (
            f"flags={self.flags},timestamp={self.timestamp_unix},"
            f"agent={self.agent},uuid={self.event_uuid}"
        )


@dataclass(frozen=True)
class _ZoneIdentifierView:
    """Type-exact observation of one logical Windows ``Zone.Identifier`` stream."""

    section: str
    key_order: tuple[str, ...]
    zone_id: int
    referrer_url: str
    host_url: str

    def detail(self) -> str:
        return (
            f"section={self.section},zone={self.zone_id},"
            f"referrer={self.referrer_url},host={self.host_url}"
        )


@dataclass(frozen=True)
class _ScheduledTaskXmlView:
    """Type-exact common observation from the XML and canonical-wire readers."""

    namespace: str
    version: str
    task_name: str
    uri: str
    description: str
    command: str
    enabled: bool
    allow_start_on_demand: bool
    hidden: bool
    trigger_count: int
    action_count: int

    def detail(self) -> str:
        return (
            f"version={self.version},task={self.task_name},command={self.command},"
            "enabled=false,demand-start=false,triggers=0,actions=1"
        )


@dataclass(frozen=True)
class _ScheduledTaskConsumerView:
    """Bounded facts actually extracted by Dissect's ScheduledTasks consumer."""

    version: str
    uri: str
    description: str
    command: str
    arguments: str | None
    working_directory: str | None
    enabled: bool
    allow_start_on_demand: bool
    hidden: bool
    trigger_count: int
    principal_count: int
    action_count: int
    action_context: str | None

    def detail(self) -> str:
        return (
            f"consumer=dissect.target-ScheduledTasks,command={self.command},"
            f"triggers={self.trigger_count},principals={self.principal_count},"
            f"actions={self.action_count}"
        )


@dataclass(frozen=True)
class _LinuxArtifactSource:
    """Immutable text bytes plus canonical scene identity for contextual Linux checks."""

    path: str
    relative_path: str
    snapshot: bytes | None
    resident_guest_paths: tuple[str, ...]


@dataclass(frozen=True)
class _ScheduledTaskArtifactSource:
    """Immutable Task XML bytes plus same-scene resident PE filenames."""

    path: str
    relative_path: str
    snapshot: bytes
    resident_pe_names: tuple[str, ...]


@dataclass(frozen=True)
class _PrefetchArtifactSource:
    """Immutable compressed bytes plus the canonical served filename."""

    relative_path: str
    snapshot: bytes


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
    if head[:8] == b"\x11\x00\x00\x00SCCA":
        return "prefetch-v17"
    if head[:4] == b"MAM\x04":
        return "prefetch"
    if head[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if head[:16] == b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00":
        return "shell-link"
    if head[:16] == b"\xff\xfe<\x00?\x00x\x00m\x00l\x00 \x00v\x00":
        return "task-xml"
    if head[:8] == b"bplist00":
        return "plist"
    if path.lower().endswith(".pf"):
        return "prefetch"
    if path.lower().endswith(".desktop"):
        return "desktop-entry"
    if os.path.basename(path) == ".bash_history":
        return "bash-history"
    if path.endswith(".quarantine.xattr"):
        return "quarantine-xattr"
    if path.lower().endswith(".zone.identifier"):
        return "zone-identifier"
    if path.lower().endswith(".task.xml"):
        return "task-xml"
    if path.lower().endswith(".lnk"):
        return "shell-link"
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
    if isinstance(b, lief.MachO.Binary):
        return lief_macho_view(b)
    return f"format={b.format}"


def _read_macholib(path):
    return macholib_macho_view(path)


_MAX_HIVE_KEYS = 1024
_MAX_HIVE_VALUES = 4096
_MAX_HIVE_DEPTH = 32
_REG_SZ = 1
_REG_DWORD = 4
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _hive_text(value: object, *, where: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise SemanticError(f"{where} must be non-empty NUL-free text")
    if len(value.encode("utf-16-le")) > 4096:
        raise SemanticError(f"{where} exceeds the bounded registry text profile")
    return value


def _filetime_from_datetime(value: object, *, where: str) -> int:
    if not isinstance(value, datetime):
        raise SemanticError(f"{where} is not a datetime")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    delta = value - _FILETIME_EPOCH
    if delta.days < 0:
        raise SemanticError(f"{where} predates the FILETIME epoch")
    return (
        (delta.days * 86_400 + delta.seconds) * 10_000_000
        + delta.microseconds * 10
    )


def _raw_regf_file_name(path: str) -> str:
    """Independently decode the fixed REGF base-block file-name field."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        head = os.read(descriptor, 112)
        state = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(head) != 112 or head[:4] != b"regf" or state.st_size < 4096:
        raise SemanticError("libregf input has no complete REGF base block")
    raw = head[48:112]
    terminator = next(
        (offset for offset in range(0, len(raw), 2) if raw[offset:offset + 2] == b"\x00\x00"),
        len(raw),
    )
    try:
        name = raw[:terminator].decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise SemanticError("REGF base-block file name is not UTF-16LE") from exc
    return _hive_text(name, where="REGF base-block file name")


def _read_regipy(path):
    from regipy.registry import RegistryHive

    hive = RegistryHive(path)
    key_count = value_count = 0

    def walk(key, depth: int) -> _HiveKeyView:
        nonlocal key_count, value_count
        if depth > _MAX_HIVE_DEPTH:
            raise SemanticError(f"regipy hive exceeds the {_MAX_HIVE_DEPTH}-level depth limit")
        key_count += 1
        if key_count > _MAX_HIVE_KEYS:
            raise SemanticError(f"regipy hive exceeds the {_MAX_HIVE_KEYS}-key limit")
        name = _hive_text(key.name, where="regipy key name")
        timestamp = key.header.last_modified
        if type(timestamp) is not int or timestamp < 0:
            raise SemanticError("regipy key timestamp is not a non-negative FILETIME")
        parsed_values = []
        for value in key.iter_values():
            value_count += 1
            if value_count > _MAX_HIVE_VALUES:
                raise SemanticError(
                    f"regipy hive exceeds the {_MAX_HIVE_VALUES}-value limit"
                )
            value_name = _hive_text(value.name, where=f"regipy value under {name!r}")
            if value.value_type == "REG_SZ":
                typed = ("text", _hive_text(value.value, where=f"regipy {value_name!r}"))
                type_code = _REG_SZ
            elif value.value_type == "REG_DWORD" and type(value.value) is int:
                typed = ("integer", value.value)
                type_code = _REG_DWORD
            else:
                raise SemanticError(
                    f"regipy value {value_name!r} has unsupported type {value.value_type!r}"
                )
            parsed_values.append(_HiveValueView(value_name, type_code, typed))
        if len({value.name for value in parsed_values}) != len(parsed_values):
            raise SemanticError(f"regipy key {name!r} contains duplicate value names")
        children = tuple(walk(child, depth + 1) for child in key.iter_subkeys())
        if len({child.name for child in children}) != len(children):
            raise SemanticError(f"regipy key {name!r} contains duplicate subkey names")
        return _HiveKeyView(
            name,
            timestamp,
            tuple(sorted(parsed_values, key=lambda item: item.name)),
            tuple(sorted(children, key=lambda item: item.name)),
        )

    file_name = _hive_text(hive.header.file_name, where="regipy base-block file name")
    return _HiveView(file_name, walk(hive.root, 1))


def _read_libregf(path):
    import pyregf

    f = pyregf.file()
    f.open(path)
    try:
        key_count = value_count = 0

        def walk(key, depth: int) -> _HiveKeyView:
            nonlocal key_count, value_count
            if depth > _MAX_HIVE_DEPTH:
                raise SemanticError(
                    f"libregf hive exceeds the {_MAX_HIVE_DEPTH}-level depth limit"
                )
            key_count += 1
            if key_count > _MAX_HIVE_KEYS:
                raise SemanticError(f"libregf hive exceeds the {_MAX_HIVE_KEYS}-key limit")
            name = _hive_text(key.name, where="libregf key name")
            timestamp = _filetime_from_datetime(
                key.last_written_time, where=f"libregf key {name!r} timestamp"
            )
            parsed_values = []
            for value in key.values:
                value_count += 1
                if value_count > _MAX_HIVE_VALUES:
                    raise SemanticError(
                        f"libregf hive exceeds the {_MAX_HIVE_VALUES}-value limit"
                    )
                value_name = _hive_text(value.name, where=f"libregf value under {name!r}")
                raw = value.data
                if type(raw) is not bytes:
                    raise SemanticError(f"libregf value {value_name!r} did not return bytes")
                if value.type == _REG_SZ:
                    try:
                        decoded = raw.decode("utf-16-le")
                    except UnicodeDecodeError as exc:
                        raise SemanticError(
                            f"libregf text value {value_name!r} is not UTF-16LE"
                        ) from exc
                    typed = (
                        "text",
                        _hive_text(
                            decoded[:-1] if decoded.endswith("\x00") else decoded,
                            where=f"libregf {value_name!r}",
                        ),
                    )
                elif value.type == _REG_DWORD and len(raw) == 4:
                    typed = ("integer", int.from_bytes(raw, "little"))
                else:
                    raise SemanticError(
                        f"libregf value {value_name!r} has unsupported type {value.type!r}"
                    )
                parsed_values.append(_HiveValueView(value_name, value.type, typed))
            if len({value.name for value in parsed_values}) != len(parsed_values):
                raise SemanticError(f"libregf key {name!r} contains duplicate value names")
            children = tuple(walk(child, depth + 1) for child in key.sub_keys)
            if len({child.name for child in children}) != len(children):
                raise SemanticError(f"libregf key {name!r} contains duplicate subkey names")
            return _HiveKeyView(
                name,
                timestamp,
                tuple(sorted(parsed_values, key=lambda item: item.name)),
                tuple(sorted(children, key=lambda item: item.name)),
            )

        root = f.get_root_key()
        if root is None:
            raise SemanticError("libregf returned no root key")
        return _HiveView(_raw_regf_file_name(path), walk(root, 1))
    finally:
        f.close()


def _read_windowsprefetch(path):
    from windowsprefetch import Prefetch
    return f"exe={Prefetch(path).executableName}"


def _read_pyscca(path):
    if type(path) is bytes:
        return pyscca_prefetch_v30_view(path)
    import pyscca
    f = pyscca.file()
    f.open(path)
    try:
        return f"exe={f.get_executable_filename()}"
    finally:
        f.close()


def _read_dissect_prefetch(data):
    return dissect_prefetch_v30_view(data)


def _read_prefetch_raw(data):
    return parse_mam_prefetch_v30_variant1(data)


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
    wire_profile = (
        SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1
        if len(data) >= 100 and data[96:100] == b"\x00\x00\x00\x00"
        else SQLiteWireProfile.SQLITE_RUNTIME_V1
    )
    database = loads_sqlite(data, wire_profile=wire_profile)
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
    return _SQLiteView(schema, tables, indexes, wire_profile.value)


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


def _read_macos_xattr(data):
    """Read through the artifact module's strict parser implementation."""
    from artifactforge.artifacts.macos import parse_quarantine_xattr

    value = parse_quarantine_xattr(data)
    if (
        type(value.flags) is not str
        or type(value.timestamp_unix) is not int
        or type(value.agent) is not str
        or type(value.event_uuid) is not str
    ):
        raise SemanticError("macOS xattr parser returned non-exact field types")
    return _QuarantineXattrView(
        value.flags,
        value.timestamp_unix,
        value.agent,
        value.event_uuid,
    )


def _read_quarantine_xattr_raw(data):
    """Independently parse the exact four-field xattr bytes without regex reuse."""
    if type(data) is not bytes:
        raise SemanticError("raw quarantine xattr reader requires immutable bytes")
    fields = data.split(b";")
    if len(fields) != 4:
        raise SemanticError("quarantine xattr must contain exactly four semicolon fields")
    flags, timestamp, agent, event_uuid = fields
    if flags != b"0181":
        raise SemanticError("quarantine xattr flags must be exactly 0181")
    if len(timestamp) != 8 or any(byte not in b"0123456789abcdef" for byte in timestamp):
        raise SemanticError("quarantine xattr timestamp must be eight lowercase hex digits")
    if not 1 <= len(agent) <= 64:
        raise SemanticError("quarantine xattr agent must contain 1..64 ASCII bytes")
    alnum = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    if agent[0] not in alnum or any(byte not in alnum + b" ._-" for byte in agent):
        raise SemanticError("quarantine xattr agent is outside the exact ASCII profile")
    if len(event_uuid) != 36 or any(
        event_uuid[index] != ord("-") for index in (8, 13, 18, 23)
    ):
        raise SemanticError("quarantine xattr UUID must use canonical hyphen positions")
    uuid_hex = b"0123456789ABCDEF"
    if any(
        byte not in uuid_hex
        for index, byte in enumerate(event_uuid)
        if index not in (8, 13, 18, 23)
    ):
        raise SemanticError("quarantine xattr UUID must use uppercase hexadecimal")
    if event_uuid[14] != ord("4") or event_uuid[19] not in b"89AB":
        raise SemanticError("quarantine xattr UUID must be canonical RFC 4122 v4")
    try:
        agent_text = agent.decode("ascii", errors="strict")
        uuid_text = event_uuid.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:  # Defensive; the byte allowlists already exclude this.
        raise SemanticError("quarantine xattr must be strict ASCII") from exc
    return _QuarantineXattrView(
        "0181",
        int(timestamp, 16),
        agent_text,
        uuid_text,
    )


def _read_configparser_zone_identifier(data):
    """Read a Zone.Identifier through the artifact module's ConfigParser adapter."""
    from artifactforge.artifacts.zone_identifier import parse_zone_identifier

    value = parse_zone_identifier(data)
    if (
        type(value.section) is not str
        or type(value.key_order) is not tuple
        or any(type(key) is not str for key in value.key_order)
        or type(value.zone_id) is not int
        or type(value.referrer_url) is not str
        or type(value.host_url) is not str
    ):
        raise SemanticError("ConfigParser Zone.Identifier adapter returned non-exact types")
    return _ZoneIdentifierView(
        section=value.section,
        key_order=value.key_order,
        zone_id=value.zone_id,
        referrer_url=value.referrer_url,
        host_url=value.host_url,
    )


def _read_zone_identifier_raw(data):
    """Independently parse the bounded ADS bytes without ConfigParser or parser reuse."""
    if type(data) is not bytes:
        raise SemanticError("raw Zone.Identifier reader requires immutable bytes")
    if not 1 <= len(data) <= 2048:
        raise SemanticError("raw Zone.Identifier value must contain 1..2048 bytes")
    lines = data.split(b"\r\n")
    if len(lines) != 5 or lines[-1] != b"":
        raise SemanticError("Zone.Identifier must contain four CRLF-terminated lines")
    if lines[0] != b"[ZoneTransfer]":
        raise SemanticError("Zone.Identifier section must be exactly [ZoneTransfer]")

    declared_keys = (b"ZoneId", b"ReferrerUrl", b"HostUrl")
    values: dict[bytes, bytes] = {}
    key_order: list[str] = []
    for line in lines[1:-1]:
        key, separator, value = line.partition(b"=")
        if separator != b"=" or not value:
            raise SemanticError("Zone.Identifier entries must be non-empty key=value lines")
        if key not in declared_keys:
            raise SemanticError("Zone.Identifier contains an undeclared or noncanonical key")
        if key in values:
            raise SemanticError("Zone.Identifier contains a duplicate key")
        values[key] = value
        key_order.append(key.decode("ascii"))
    if set(values) != set(declared_keys):
        raise SemanticError("Zone.Identifier must contain exactly three declared keys")

    zone_bytes = values[b"ZoneId"]
    if (
        len(zone_bytes) > 10
        or any(byte not in b"0123456789" for byte in zone_bytes)
        or (len(zone_bytes) > 1 and zone_bytes[0] == ord("0"))
    ):
        raise SemanticError("ZoneId must be a bounded canonical decimal integer")

    urls: list[str] = []
    for key in (b"ReferrerUrl", b"HostUrl"):
        raw_url = values[key]
        if len(raw_url) > 512 or any(byte < 0x20 or byte == 0x7F for byte in raw_url):
            raise SemanticError(f"{key.decode('ascii')} is outside the bounded ASCII profile")
        try:
            urls.append(raw_url.decode("ascii", errors="strict"))
        except UnicodeDecodeError as exc:
            raise SemanticError(f"{key.decode('ascii')} must be strict ASCII") from exc
    return _ZoneIdentifierView(
        section="ZoneTransfer",
        key_order=tuple(key_order),
        zone_id=int(zone_bytes, 10),
        referrer_url=urls[0],
        host_url=urls[1],
    )


_TASK_XML_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_TASK_XML_NATIVE_SERVED_PREFIX = "C/Windows/System32/Tasks/ArtifactForge/"


def _read_elementtree_task_xml(data):
    """Adapt the standard-library ElementTree observation to Gate 1's typed view."""
    value = parse_scheduled_task_xml(data)
    if type(value) is not ScheduledTaskXmlValue:
        raise SemanticError("ElementTree task reader returned an invalid observation shape")
    return _ScheduledTaskXmlView(
        namespace=value.namespace,
        version=value.version,
        task_name=value.task_name,
        uri=value.uri,
        description=value.description,
        command=value.command,
        enabled=value.enabled,
        allow_start_on_demand=value.allow_start_on_demand,
        hidden=value.hidden,
        trigger_count=value.trigger_count,
        action_count=value.action_count,
    )


def _read_task_xml_raw(data):
    """Adapt the independently implemented canonical byte reader to a typed view."""
    value = read_scheduled_task_xml_wire(data)
    if type(value) is not ScheduledTaskXmlWireValue:
        raise SemanticError("raw task XML reader returned an invalid observation shape")
    if value.encoding != "UTF-16LE+BOM" or value.line_count != 17:
        raise SemanticError("raw task XML reader did not observe the canonical wire profile")
    return _ScheduledTaskXmlView(
        namespace=_TASK_XML_NAMESPACE,
        version=value.version,
        task_name=value.task_name,
        uri=value.uri,
        description=value.description,
        command=value.command,
        enabled=value.enabled,
        allow_start_on_demand=value.allow_start_on_demand,
        hidden=value.hidden,
        trigger_count=value.trigger_count,
        action_count=value.action_count,
    )


def _read_dissect_task_xml(data):
    """Run Dissect's ScheduledTasks consumer against only the bounded byte snapshot."""
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.plugins.os.windows.tasks.xml import ScheduledTasks

    if type(data) is not bytes or not 1 <= len(data) <= 16 * 1024:
        raise SemanticError("Dissect task reader requires 1..16384 immutable bytes")
    filesystem = VirtualFilesystem()
    filesystem.map_file_fh("/ArtifactForge.task.xml", BytesIO(data))
    tasks = tuple(ScheduledTasks(filesystem.path("/ArtifactForge.task.xml")).tasks)
    if len(tasks) != 1:
        raise SemanticError("Dissect ScheduledTasks must extract exactly one task")
    task = tasks[0]
    actions = tuple(task.get_actions())
    triggers = tuple(task.get_triggers())
    action_elements = tuple(task.task_element.findall("Actions/*"))
    if len(actions) != len(action_elements):
        raise SemanticError("Dissect ScheduledTasks did not extract every action element")
    if len(actions) != 1 or str(actions[0].action_type) != "Exec":
        raise SemanticError("Dissect ScheduledTasks did not extract one Exec action")
    actions_element = task.task_element.find("Actions")
    if actions_element is None:
        raise SemanticError("Dissect ScheduledTasks did not expose the Actions element")

    def required_text(value: object, *, where: str) -> str:
        if not isinstance(value, str) or not value:
            raise SemanticError(f"Dissect ScheduledTasks returned invalid {where}")
        return str(value)

    def optional_text(value: object, *, where: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise SemanticError(f"Dissect ScheduledTasks returned invalid {where}")
        return str(value)

    return _ScheduledTaskConsumerView(
        version=required_text(task.task_element.get("version"), where="version"),
        uri=required_text(task.uri, where="URI"),
        description=required_text(task.description, where="description"),
        command=required_text(actions[0].command, where="Exec Command"),
        arguments=optional_text(actions[0].arguments, where="Exec Arguments"),
        working_directory=optional_text(
            actions[0].working_directory,
            where="Exec WorkingDirectory",
        ),
        enabled=task.enabled,
        allow_start_on_demand=task.allow_start_on_demand,
        hidden=task.hidden,
        trigger_count=len(triggers),
        principal_count=len(task.task_element.findall("Principals/Principal")),
        action_count=len(actions),
        action_context=optional_text(actions_element.get("Context"), where="Actions Context"),
    )


def _read_shell_link_raw(data):
    """Adapt the bounded byte-layout reader to the external parsers' typed intersection."""
    value = parse_shell_link(data)
    if type(value) is not ShellLinkValue:
        raise SemanticError("raw Shell Link reader returned an invalid observation shape")
    return ShellLinkOracleView(
        target_path=value.target_path,
        description=value.name_string,
        target_size=value.target_size,
        creation_filetime=value.creation_filetime,
        access_filetime=value.access_filetime,
        write_filetime=value.write_filetime,
        volume_serial=value.volume_serial,
        volume_label=value.volume_label,
        drive_type=3,
        link_flags=0x86,
        file_attribute_flags=0x20,
        icon_index=0,
        show_window_value=1,
        hot_key_value=0,
        optional_surfaces=(),
        data_block_count=0,
    )


READERS = {
    "pefile": _read_pefile,
    "lief": _read_lief,
    "macholib": _read_macholib,
    "regipy": _read_regipy,
    "libregf": _read_libregf,
    "windowsprefetch": _read_windowsprefetch,
    "pyscca": _read_pyscca,
    "dissect.target-prefetch": _read_dissect_prefetch,
    "prefetch-raw": _read_prefetch_raw,
    "sqlite3": _read_sqlite3,
    "sqlite-raw": _read_sqlite_raw,
    "plistlib": _read_plistlib,
    "bplist-raw": _read_bplist_raw,
    "pyelftools": _read_pyelftools,
    "pyxdg": _read_pyxdg,
    "desktop-entry-raw": _read_desktop_entry_raw,
    "dissect.target": _read_dissect_bash_history,
    "bash-history-raw": _read_bash_history_raw,
    "macos-xattr": _read_macos_xattr,
    "quarantine-xattr-raw": _read_quarantine_xattr_raw,
    "configparser": _read_configparser_zone_identifier,
    "zone-identifier-raw": _read_zone_identifier_raw,
    "elementtree": _read_elementtree_task_xml,
    "task-xml-raw": _read_task_xml_raw,
    "dissect.target-tasks": _read_dissect_task_xml,
    "liblnk": liblnk_shell_link_view,
    "LnkParse3": lnkparse3_shell_link_view,
    "shell-link-raw": _read_shell_link_raw,
}


def _macho_pair(reads: dict) -> MachOView:
    lief_view = reads.get("lief")
    macholib_view = reads.get("macholib")
    if type(lief_view) is not MachOView or type(macholib_view) is not MachOView:
        raise SemanticError("typed LIEF and macholib Mach-O observations are both required")
    if lief_view != macholib_view:
        raise SemanticError(
            "LIEF and macholib disagree on the type-exact Mach-O structure"
        )
    return lief_view


def _validate_macho_consensus(_path: str, reads: dict) -> str:
    """Require two implementations to extract the same typed Mach-O structure."""
    return _macho_pair(reads).detail()


def _validate_macho_profile(_path: str, reads: dict) -> str:
    """Bind parser consensus to the hand-written arm64 Mach-O v1 profile."""
    return validate_artifactforge_macho_profile(_macho_pair(reads))


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
    volumes_offset, volumes_count, volumes_size = struct.unpack_from("<III", data, 108)
    if metrics_count < 1:
        raise SemanticError("file metrics array carries no executable path")
    _bounded(data, metrics_offset, metrics_count * 20, "file metrics array")
    _bounded(data, strings_offset, strings_size, "filename strings array")
    if volumes_count != 1:
        raise SemanticError("bounded SCCA v17 profile requires exactly one volume")
    _bounded(data, volumes_offset, volumes_size, "volumes information")

    last_run_filetime = struct.unpack_from("<Q", data, 120)[0]
    volume_creation_filetime = struct.unpack_from("<Q", data, volumes_offset + 8)[0]
    _validate_causal_filetime(last_run_filetime, where="prefetch last-run timestamp")
    _validate_causal_filetime(
        volume_creation_filetime, where="prefetch volume creation timestamp"
    )
    if volume_creation_filetime > last_run_filetime or (
        volume_creation_filetime == last_run_filetime
        and last_run_filetime != _LEGACY_PROFILE_FILETIME
    ):
        raise SemanticError(
            "prefetch volume creation must precede last execution; equality is legacy-only"
        )

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
    temporal = (
        "legacy" if last_run_filetime == volume_creation_filetime else "causal"
    )
    return f"path={executable_path},hash={calculated_hash:08X},timestamps={temporal}"


def _prefetch_v30_pair(reads: dict) -> PrefetchV30OracleView:
    try:
        return require_prefetch_v30_consensus(reads)
    except ValueError as exc:
        raise SemanticError(str(exc)) from exc


def _validate_prefetch_v30_consensus(
    _source: _PrefetchArtifactSource, reads: dict
) -> str:
    """Require the independent libyal and Dissect parsers to agree on typed semantics."""
    return _prefetch_v30_pair(reads).detail()


def _validate_prefetch_v30_profile(
    source: _PrefetchArtifactSource, reads: dict
) -> str:
    """Bind exact MAM/v30 bytes, dual-parser semantics, path hash and served filename."""
    if type(source) is not _PrefetchArtifactSource:
        raise SemanticError("v30 Prefetch validation requires an immutable artifact source")
    strict = reads.get("prefetch-raw")
    if type(strict) is not PrefetchV30ProfileView:
        raise SemanticError("typed strict v30 Prefetch observation is required")
    try:
        detail = validate_artifactforge_prefetch_v30_profile(
            strict,
            _prefetch_v30_pair(reads),
        )
    except ValueError as exc:
        raise SemanticError(str(exc)) from exc
    expected_filename = (
        f"{strict.executable_name}-{strict.prefetch_hash:08X}.pf"
    )
    if os.path.basename(source.relative_path) != expected_filename:
        raise SemanticError(
            f"prefetch filename {os.path.basename(source.relative_path)!r} "
            f"!= {expected_filename!r}"
        )
    return f"{detail},filename=hash-bound"


_LEGACY_PROFILE_FILETIME = 133497684000000000  # 2024-01-15T05:00:00Z
_FILETIME_TICKS_PER_SECOND = 10_000_000
_WINDOWS_TO_UNIX_SECONDS = 11_644_473_600
_CAUSAL_MIN_UNIX_SECONDS = 1_672_531_200  # 2023-01-01
_CAUSAL_MAX_UNIX_SECONDS = (
    _CAUSAL_MIN_UNIX_SECONDS + 3 * 365 * 86_400 + 3_600
)
_HIVE_HEX = re.compile(r"[0-9a-f]+")
_HIVE_SHA1 = re.compile(r"0000[0-9a-f]{40}")


def _validate_causal_filetime(value: object, *, where: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise SemanticError(f"{where} is not an exact unsigned 64-bit FILETIME")
    if value % _FILETIME_TICKS_PER_SECOND:
        raise SemanticError(f"{where} is not aligned to the causal whole-second profile")
    unix_seconds = value // _FILETIME_TICKS_PER_SECOND - _WINDOWS_TO_UNIX_SECONDS
    if not _CAUSAL_MIN_UNIX_SECONDS <= unix_seconds <= _CAUSAL_MAX_UNIX_SECONDS:
        raise SemanticError(f"{where} is outside the bounded deterministic causal range")
    return unix_seconds


def _hive_pair(reads: dict) -> _HiveView:
    regipy = reads.get("regipy")
    libregf = reads.get("libregf")
    if type(regipy) is not _HiveView or type(libregf) is not _HiveView:
        raise SemanticError("typed regipy and libregf observations are both required")
    if regipy != libregf:
        raise SemanticError("regipy and libregf disagree on typed hive identity/tree/values")
    return libregf


def _validate_hive_consensus(_path: str, reads: dict) -> str:
    return _hive_pair(reads).detail()


def _hive_child(key: _HiveKeyView, name: str) -> _HiveKeyView:
    matches = tuple(child for child in key.subkeys if child.name == name)
    if len(matches) != 1:
        raise SemanticError(f"registry profile requires exactly one {name!r} subkey")
    return matches[0]


def _hive_values(key: _HiveKeyView) -> dict[str, _HiveValueView]:
    values = {value.name: value for value in key.values}
    if len(values) != len(key.values):
        raise SemanticError(f"registry key {key.name!r} has duplicate values")
    return values


def _hive_scalar(value: _HiveValueView, type_code: int, kind: str, where: str):
    if value.type_code != type_code:
        raise SemanticError(f"{where} has registry type {value.type_code}, not {type_code}")
    return _scalar(value.typed_value, kind, where)


def _validate_hive_marker(root: _HiveKeyView) -> None:
    marker = _hive_child(root, RESERVED_NAME)
    if marker.subkeys:
        raise SemanticError("synthetic registry marker key must not have subkeys")
    values = _hive_values(marker)
    if set(values) != {"marker", "notice"}:
        raise SemanticError("synthetic registry marker key must have exactly marker and notice")
    if (
        _hive_scalar(values["marker"], _REG_SZ, "text", "hive marker") != MARKER
        or _hive_scalar(values["notice"], _REG_SZ, "text", "hive notice") != NOTICE
    ):
        raise SemanticError("synthetic registry marker values are not canonical")


def _validate_hive_timestamps(view: _HiveView) -> str:
    pending = [view.root]
    observed = []
    while pending:
        key = pending.pop()
        _validate_causal_filetime(
            key.last_written_filetime,
            where=f"registry key {key.name!r} timestamp",
        )
        observed.append(key.last_written_filetime)
        pending.extend(key.subkeys)
    unique = set(observed)
    if unique == {_LEGACY_PROFILE_FILETIME}:
        return "legacy"
    if len(unique) == 1:
        raise SemanticError(
            "non-legacy registry timestamps collapse the required causal key order"
        )

    marker = _hive_child(view.root, RESERVED_NAME)
    if view.file_name == r"\System32\config\SOFTWARE":
        microsoft = _hive_child(view.root, "Microsoft")
        windows = _hive_child(microsoft, "Windows")
        current = _hive_child(windows, "CurrentVersion")
        run = _hive_child(current, "Run")
        baseline = {
            key.last_written_filetime
            for key in (view.root, microsoft, windows, current)
        }
        if (
            len(baseline) != 1
            or not next(iter(baseline)) < run.last_written_filetime
            or marker.last_written_filetime != run.last_written_filetime
        ):
            raise SemanticError(
                "SOFTWARE key timestamps must place Run configuration after its ancestors"
            )
        return "causal"
    if view.file_name == "Amcache.hve":
        root = _hive_child(view.root, "Root")
        inventory = _hive_child(root, "InventoryApplicationFile")
        baseline = {
            key.last_written_filetime for key in (view.root, root, inventory)
        }
        record_times = {key.last_written_filetime for key in inventory.subkeys}
        if (
            len(baseline) != 1
            or len(record_times) != 1
            or not next(iter(baseline)) < next(iter(record_times))
            or marker.last_written_filetime != next(iter(record_times))
        ):
            raise SemanticError(
                "Amcache key timestamps must place inventory observations after ancestors"
            )
        return "causal"
    raise SemanticError("registry temporal profile has no recognized hive identity")


def _amcache_rows(view: _HiveView) -> tuple[tuple[str, str, str, int], ...]:
    if view.file_name != "Amcache.hve" or view.root.name != "amcache":
        raise SemanticError("Amcache profile requires authentic Amcache.hve base identity")
    if {child.name for child in view.root.subkeys} != {"Root", RESERVED_NAME}:
        raise SemanticError("Amcache root has unexpected or missing profile keys")
    if view.root.values:
        raise SemanticError("Amcache root must not carry direct values")
    root = _hive_child(view.root, "Root")
    if root.values or {child.name for child in root.subkeys} != {
        "InventoryApplicationFile"
    }:
        raise SemanticError("Amcache Root tree is outside InventoryApplicationFile profile")
    inventory = _hive_child(root, "InventoryApplicationFile")
    if inventory.values or not 1 <= len(inventory.subkeys) <= 64:
        raise SemanticError("Amcache inventory must contain 1..64 file records")

    observed = []
    record_names = set()
    file_ids = set()
    lower_paths = set()
    for record in inventory.subkeys:
        if (
            record.name in record_names
            or not 1 <= len(record.name) <= 64
            or _HIVE_HEX.fullmatch(record.name) is None
            or record.subkeys
        ):
            raise SemanticError("Amcache record key identity is not unique lowercase hexadecimal")
        values = _hive_values(record)
        if set(values) != {"FileId", "LowerCaseLongPath", "Name", "Size"}:
            raise SemanticError("Amcache record must have exactly four canonical values")
        file_id = _hive_scalar(values["FileId"], _REG_SZ, "text", "Amcache FileId")
        lower_path = _hive_scalar(
            values["LowerCaseLongPath"], _REG_SZ, "text", "Amcache LowerCaseLongPath"
        )
        name = _hive_scalar(values["Name"], _REG_SZ, "text", "Amcache Name")
        size = _hive_scalar(values["Size"], _REG_DWORD, "integer", "Amcache Size")
        drive, tail = ntpath.splitdrive(lower_path)
        components = tuple(part for part in tail.split("\\") if part)
        if (
            _HIVE_SHA1.fullmatch(file_id) is None
            or file_id in file_ids
            or lower_path != lower_path.lower()
            or lower_path in lower_paths
            or len(drive) != 2
            or not tail.startswith("\\")
            or not components
            or any(part in {".", ".."} for part in components)
            or "/" in lower_path
            # Amcache's LowerCaseLongPath is normalised while Name preserves the spelling
            # observed at the call site (for example ``7zFM.exe``).  They identify the same
            # basename case-insensitively; requiring byte equality rejects valid generated
            # records and is not a Windows-path semantic.
            or ntpath.basename(lower_path).casefold() != name.casefold()
            or not 0 <= size <= 0xFFFFFFFF
        ):
            raise SemanticError("Amcache FileId/path/name/size semantics are outside profile")
        record_names.add(record.name)
        file_ids.add(file_id)
        lower_paths.add(lower_path)
        observed.append((file_id[4:], lower_path, name, size))
    return tuple(sorted(observed))


def _software_run_values(view: _HiveView) -> tuple[tuple[str, str], ...]:
    if view.file_name != r"\System32\config\SOFTWARE" or view.root.name != "ROOT":
        raise SemanticError("SOFTWARE profile requires authentic base-block identity")
    if {child.name for child in view.root.subkeys} != {"Microsoft", RESERVED_NAME}:
        raise SemanticError("SOFTWARE root has unexpected or missing profile keys")
    if view.root.values:
        raise SemanticError("SOFTWARE root must not carry direct values")
    key = _hive_child(view.root, "Microsoft")
    for component in ("Windows", "CurrentVersion", "Run"):
        if key.values or {child.name for child in key.subkeys} != {component}:
            raise SemanticError(f"SOFTWARE path before {component!r} is outside profile")
        key = _hive_child(key, component)
    if key.subkeys or not 1 <= len(key.values) <= 64:
        raise SemanticError("SOFTWARE Run must contain 1..64 values and no subkeys")
    observed = []
    for value in key.values:
        program = _hive_scalar(value, _REG_SZ, "text", f"Run value {value.name!r}")
        drive, tail = ntpath.splitdrive(program.replace("/", "\\"))
        components = tuple(part for part in tail.split("\\") if part)
        if (
            len(drive) != 2
            or not tail.startswith("\\")
            or not components
            or any(part in {".", ".."} for part in components)
        ):
            raise SemanticError(f"Run value {value.name!r} is not an absolute Windows path")
        observed.append((value.name, program))
    return tuple(sorted(observed))


def _validate_windows_hive_profile(_path: str, reads: dict) -> str:
    view = _hive_pair(reads)
    _validate_hive_marker(view.root)
    if view.file_name == "Amcache.hve":
        rows = _amcache_rows(view)
        temporal = _validate_hive_timestamps(view)
        return (
            f"profile=amcache-inventory-v1,rows={len(rows)},marker=exact,"
            f"timestamps={temporal}"
        )
    if view.file_name == r"\System32\config\SOFTWARE":
        values = _software_run_values(view)
        temporal = _validate_hive_timestamps(view)
        return (
            f"profile=software-run-v1,values={len(values)},marker=exact,"
            f"timestamps={temporal}"
        )
    raise SemanticError(f"registry base-block identity {view.file_name!r} has no profile")


def _validate_regipy_hive_consumer(path: str, reads: dict) -> str:
    """Run the artifact-aware plugin and compare its extraction with typed consensus."""
    from regipy.registry import RegistryHive

    view = _hive_pair(reads)
    hive = RegistryHive(path)

    def run_plugin(plugin, *, allowed_diagnostics: frozenset[str] = frozenset()) -> None:
        # regipy probes both its legacy and modern Amcache paths.  Its expected failed legacy
        # probe is logged as ERROR even when the modern InventoryApplicationFile extraction
        # succeeds, which otherwise puts twenty alarming false errors ahead of a green n=40
        # gate.  Capture only this plugin logger, restore it exactly, and fail on any other
        # warning/error rather than hiding consumer diagnostics.
        records: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        logger = logging.getLogger(type(plugin).__module__)
        original_handlers = tuple(logger.handlers)
        original_level = logger.level
        original_propagate = logger.propagate
        logger.handlers = [Capture()]
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        try:
            plugin.run()
        finally:
            logger.handlers = list(original_handlers)
            logger.setLevel(original_level)
            logger.propagate = original_propagate
        unexpected = tuple(
            record.getMessage()
            for record in records
            if record.levelno >= logging.WARNING
            and record.getMessage() not in allowed_diagnostics
        )
        if unexpected:
            raise SemanticError(f"regipy consumer emitted diagnostics: {unexpected!r}")

    if view.file_name == "Amcache.hve":
        from regipy.plugins.amcache.amcache import AmCachePlugin

        expected = _amcache_rows(view)
        plugin = AmCachePlugin(hive, as_json=True)
        if plugin.can_run() is not True:
            raise SemanticError("regipy AmcachePlugin does not recognise the emitted hive")
        run_plugin(plugin, allowed_diagnostics=frozenset({r"Could not find \Root\File subkey"}))
        observed = tuple(
            sorted(
                (
                    entry.get("sha1"),
                    entry.get("lower_case_long_path"),
                    entry.get("name"),
                    entry.get("size"),
                )
                for entry in plugin.entries
            )
        )
        if observed != expected:
            raise SemanticError("regipy AmcachePlugin extraction disagrees with hive consensus")
        return f"consumer=regipy-AmcachePlugin,rows={len(observed)}"
    if view.file_name == r"\System32\config\SOFTWARE":
        from regipy.plugins.software.persistence import SoftwarePersistencePlugin

        expected = _software_run_values(view)
        plugin = SoftwarePersistencePlugin(hive, as_json=True)
        if plugin.can_run() is not True:
            raise SemanticError("regipy SoftwarePersistencePlugin does not recognise the hive")
        run_plugin(plugin)
        result = plugin.entries.get(r"\Microsoft\Windows\CurrentVersion\Run")
        if type(result) is not dict or type(result.get("values")) is not list:
            raise SemanticError("regipy SoftwarePersistencePlugin returned no Run-key values")
        observed = tuple(
            sorted((entry.get("name"), entry.get("value")) for entry in result["values"])
        )
        if observed != expected:
            raise SemanticError(
                "regipy SoftwarePersistencePlugin extraction disagrees with consensus"
            )
        return f"consumer=regipy-SoftwarePersistencePlugin,values={len(observed)}"
    raise SemanticError(f"registry base-block identity {view.file_name!r} has no consumer")


_MARKER_COLUMNS = (
    ("marker", "TEXT", False, False),
    ("notice", "TEXT", False, False),
)
_MARKER_SQL = f"CREATE TABLE {RESERVED_NAME} (marker TEXT, notice TEXT)"
_KNOWLEDGE_OBJECT_SQL = (
    "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, "
    "ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL, "
    "ZSTARTDAYOFWEEK INTEGER, ZSECONDSFROMGMT INTEGER, ZCREATIONDATE REAL, "
    "ZUUID TEXT, ZSTRUCTUREDMETADATA INTEGER, ZSOURCE INTEGER)"
)
_KNOWLEDGE_METADATA_SQL = (
    "CREATE TABLE ZSTRUCTUREDMETADATA (Z_PK INTEGER PRIMARY KEY, "
    "Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON INTEGER, "
    "Z_DKAPPLICATIONMETADATAKEY__EXTENSIONCONTAININGBUNDLEIDENTIFIER TEXT, "
    "Z_DKAPPLICATIONMETADATAKEY__EXTENSIONHOSTIDENTIFIER TEXT, ZMETADATAHASH TEXT)"
)
_KNOWLEDGE_SOURCE_SQL = "CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY)"
_TCC_SQL = (
    "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, "
    "auth_value INTEGER, auth_reason INTEGER, indirect_object_identifier TEXT, "
    "last_modified INTEGER)"
)
_QUARANTINE_SQL = (
    "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY, "
    "LSQuarantineTimeStamp REAL, LSQuarantineAgentName TEXT, "
    "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT)"
)
_CHROMIUM_DOWNLOADS_SQL = (
    "CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, "
    "target_path TEXT, start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, "
    "state INTEGER, danger_type INTEGER, interrupt_reason INTEGER, hash BLOB, "
    "end_time INTEGER, opened INTEGER, last_access_time INTEGER, transient INTEGER, "
    "referrer TEXT, site_url TEXT, embedder_download_data TEXT, tab_url TEXT, "
    "tab_referrer_url TEXT, http_method TEXT, by_ext_id TEXT, by_ext_name TEXT, "
    "by_web_app_id TEXT, etag TEXT, last_modified TEXT, mime_type TEXT, "
    "original_mime_type TEXT)"
)
_CHROMIUM_CHAINS_SQL = (
    "CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT)"
)
_QUARANTINE_UUID = re.compile(
    r"[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}"
)
_CHROMIUM_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_CHROMIUM_CONTENT_PATH = re.compile(
    r".+/sha256/(?P<sha256>[0-9a-f]{64})/(?P<basename>[^/]+)"
)
_WINDOWS_DOWNLOAD_PATH = re.compile(
    r"[A-Z]:\\(?:[^\\/:*?\"<>|\x00-\x1f]+\\)*[^\\/:*?\"<>|\x00-\x1f]+"
)
_WINDOWS_EPOCH_MICROSECONDS = 11_644_473_600_000_000
_MAX_CHROMIUM_DOWNLOAD_BYTES = 1 << 40
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
            (1, "table", "ZOBJECT", "ZOBJECT", 2, _KNOWLEDGE_OBJECT_SQL),
            (
                2,
                "table",
                "ZSTRUCTUREDMETADATA",
                "ZSTRUCTUREDMETADATA",
                3,
                _KNOWLEDGE_METADATA_SQL,
            ),
            (3, "table", "ZSOURCE", "ZSOURCE", 4, _KNOWLEDGE_SOURCE_SQL),
            (4, "table", RESERVED_NAME, RESERVED_NAME, 5, _MARKER_SQL),
        ),
    )
    table = _table(view, "ZOBJECT")
    expected_columns = (
        ("Z_PK", "INTEGER", True, True),
        ("ZSTREAMNAME", "TEXT", False, False),
        ("ZVALUESTRING", "TEXT", False, False),
        ("ZSTARTDATE", "REAL", False, False),
        ("ZENDDATE", "REAL", False, False),
        ("ZSTARTDAYOFWEEK", "INTEGER", False, False),
        ("ZSECONDSFROMGMT", "INTEGER", False, False),
        ("ZCREATIONDATE", "REAL", False, False),
        ("ZUUID", "TEXT", False, False),
        ("ZSTRUCTUREDMETADATA", "INTEGER", False, False),
        ("ZSOURCE", "INTEGER", False, False),
    )
    if table.columns != expected_columns or not 1 <= len(table.rows) <= 8:
        raise SemanticError(
            "knowledgeC requires the exact APOLLO-query surface and 1..8 object rows"
        )
    bundles_by_pk = {}
    uuids_by_pk = {}
    identity_profiles = set()
    seen_uuids = set()
    for rowid, values in table.rows:
        primary_key = _scalar(values[0], "integer", "knowledgeC Z_PK")
        stream = _scalar(values[1], "text", "knowledgeC ZSTREAMNAME")
        bundle = _scalar(values[2], "text", "knowledgeC ZVALUESTRING")
        start = _scalar(values[3], "real", "knowledgeC ZSTARTDATE")
        end = _scalar(values[4], "real", "knowledgeC ZENDDATE")
        day_of_week = _scalar(values[5], "integer", "knowledgeC ZSTARTDAYOFWEEK")
        seconds_from_gmt = _scalar(values[6], "integer", "knowledgeC ZSECONDSFROMGMT")
        creation = _scalar(values[7], "real", "knowledgeC ZCREATIONDATE")
        uuid = _scalar(values[8], "text", "knowledgeC ZUUID")
        metadata_fk = _scalar(values[9], "integer", "knowledgeC ZSTRUCTUREDMETADATA")
        source_fk = _scalar(values[10], "integer", "knowledgeC ZSOURCE")
        if rowid <= 0 or primary_key != rowid:
            raise SemanticError("knowledgeC Z_PK must be the positive table rowid")
        if stream != "/app/inFocus":
            raise SemanticError("knowledgeC stream must be exactly /app/inFocus")
        _profile_text(bundle, where="knowledgeC bundle identity", max_bytes=128)
        if (
            not math.isfinite(start)
            or not math.isfinite(end)
            or abs(start) >= 2**53
            or abs(end) >= 2**53
            or end <= start
        ):
            raise SemanticError("knowledgeC interval must be finite with end after start")
        unix_day = math.floor((start + 978_307_200) / 86_400)
        if day_of_week != ((unix_day + 4) % 7) + 1:
            raise SemanticError("knowledgeC day-of-week must be derived from ZSTARTDATE")
        if seconds_from_gmt != 0 or creation != start:
            raise SemanticError("knowledgeC GMT offset or creation timestamp is outside profile")
        legacy_uuid = f"00000000-0000-4000-8000-{rowid:012X}"
        if uuid == legacy_uuid:
            identity_profiles.add("legacy-rowid")
        elif _QUARANTINE_UUID.fullmatch(uuid):
            identity_profiles.add("fixture-v2-derived")
        else:
            raise SemanticError("knowledgeC ZUUID is not a canonical RFC 4122 v4 value")
        if uuid in seen_uuids:
            raise SemanticError("knowledgeC ZUUID values must be unique")
        seen_uuids.add(uuid)
        if metadata_fk != rowid or source_fk != 1:
            raise SemanticError("knowledgeC APOLLO join keys do not resolve by construction")
        bundles_by_pk[rowid] = bundle
        uuids_by_pk[rowid] = uuid

    if len(identity_profiles) != 1:
        raise SemanticError("knowledgeC mixes incompatible UUID identity profiles")
    identity_profile = next(iter(identity_profiles))

    metadata = _table(view, "ZSTRUCTUREDMETADATA")
    expected_metadata_columns = (
        ("Z_PK", "INTEGER", True, True),
        ("Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON", "INTEGER", False, False),
        (
            "Z_DKAPPLICATIONMETADATAKEY__EXTENSIONCONTAININGBUNDLEIDENTIFIER",
            "TEXT",
            False,
            False,
        ),
        ("Z_DKAPPLICATIONMETADATAKEY__EXTENSIONHOSTIDENTIFIER", "TEXT", False, False),
        ("ZMETADATAHASH", "TEXT", False, False),
    )
    if metadata.columns != expected_metadata_columns or len(metadata.rows) != len(table.rows):
        raise SemanticError("knowledgeC structured metadata query surface is not exact")
    for rowid, values in metadata.rows:
        primary_key = _scalar(values[0], "integer", "knowledgeC metadata Z_PK")
        launch_reason = _scalar(values[1], "integer", "knowledgeC launch reason")
        containing_bundle = _scalar(values[2], "text", "knowledgeC extension bundle")
        host = _scalar(values[3], "text", "knowledgeC extension host")
        metadata_hash = _scalar(values[4], "text", "knowledgeC metadata hash")
        bundle = bundles_by_pk.get(primary_key)
        uuid = uuids_by_pk.get(primary_key)
        if bundle is None or uuid is None:
            expected_hash = None
        elif identity_profile == "legacy-rowid":
            expected_hash = hashlib.sha256(
                b"artifactforge::knowledgec-metadata\x00" + bundle.encode("ascii")
            ).hexdigest()
        else:
            expected_hash = hashlib.sha256(
                b"artifactforge/knowledgec/metadata/v2\x00"
                + uuid.encode("ascii")
                + b"\0"
                + bundle.encode("ascii")
            ).hexdigest()
        if rowid != primary_key or launch_reason != 0:
            raise SemanticError("knowledgeC metadata key or launch reason is outside profile")
        if containing_bundle != "UNUSED" or host != "UNUSED":
            raise SemanticError("knowledgeC extension metadata placeholders are not canonical")
        if metadata_hash != expected_hash:
            raise SemanticError("knowledgeC metadata hash does not bind its app identity")

    source = _table(view, "ZSOURCE")
    expected_source = (("Z_PK", "INTEGER", True, True),)
    if source.columns != expected_source or source.rows != ((1, (("integer", 1),)),):
        raise SemanticError("knowledgeC APOLLO source join must resolve to the one source row")
    _marker_table(view)
    return (
        f"profile=macos-11-14-consumer-v1,rows={len(table.rows)},stream=/app/inFocus,"
        f"identity={identity_profile},apollo-joins=exact,marker=exact"
    )


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
        ("indirect_object_identifier", "TEXT", False, False),
        ("last_modified", "INTEGER", False, False),
    )
    if table.columns != expected_columns or not 1 <= len(table.rows) <= 8:
        raise SemanticError("TCC requires the exact mac_apt query surface and 1..8 rows")
    identities = set()
    auth_values = []
    for _rowid, values in table.rows:
        service = _scalar(values[0], "text", "TCC service")
        client = _scalar(values[1], "text", "TCC client")
        client_type = _scalar(values[2], "integer", "TCC client_type")
        auth_value = _scalar(values[3], "integer", "TCC auth_value")
        auth_reason = _scalar(values[4], "integer", "TCC auth_reason")
        indirect = _scalar(values[5], "text", "TCC indirect_object_identifier")
        timestamp = _scalar(values[6], "integer", "TCC last_modified")
        _profile_text(service, where="TCC service", max_bytes=96)
        _profile_text(client, where="TCC client", max_bytes=128)
        identity = service, client
        if identity in identities:
            raise SemanticError("TCC service/client identities must be unique")
        if client_type != 0 or auth_value not in {0, 2} or auth_reason != 3:
            raise SemanticError("TCC client_type/auth_value/auth_reason is outside profile")
        if indirect != "UNUSED":
            raise SemanticError("TCC indirect object identifier must be canonical UNUSED")
        if timestamp <= 0:
            raise SemanticError("TCC last_modified must be a positive integer Unix timestamp")
        identities.add(identity)
        auth_values.append(auth_value)
    grants = auth_values.count(2)
    denials = auth_values.count(0)
    _marker_table(view)
    return (
        f"profile=macos-11-14-consumer-v1,rows={len(table.rows)},"
        f"grants={grants},denials={denials},"
        "mac-apt-fields=exact,marker=exact"
    )


def _chromium_windows_timestamp(value: object, *, where: str) -> int:
    if (
        type(value) is not int
        or not _WINDOWS_EPOCH_MICROSECONDS <= value < (1 << 63)
        or value % 1_000_000
    ):
        raise SemanticError(
            f"{where} must be a whole-second signed-64 Windows-epoch timestamp"
        )
    return value


def _chromium_windows_path(value: object, *, where: str) -> str:
    path = _profile_text(value, where=where, max_bytes=260)
    if (
        _WINDOWS_DOWNLOAD_PATH.fullmatch(path) is None
        or len(path.encode("utf-16-le")) > 520
    ):
        raise SemanticError(f"{where} must be a bounded absolute normal Windows drive path")
    components = path[3:].split("\\")
    if any(
        component in {"", ".", ".."} or component.endswith((" ", "."))
        for component in components
    ):
        raise SemanticError(f"{where} must be a bounded absolute normal Windows drive path")
    return path


def _chromium_reserved_url(value: object, *, where: str):
    url = _profile_text(value, where=where, max_bytes=512)
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.netloc != host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not host.endswith((".example", ".invalid", ".test"))
        or MARKER not in url
    ):
        raise SemanticError(
            f"{where} must be a marked reserved HTTPS URL without credentials, port, "
            "or fragment"
        )
    return parsed


def _chromium_source_identity(value: object, *, where: str) -> tuple[str, str, str]:
    parsed = _chromium_reserved_url(value, where=where)
    match = _CHROMIUM_CONTENT_PATH.fullmatch(parsed.path)
    if match is None or parsed.path.count("/sha256/") != 1:
        raise SemanticError(
            f"{where} must contain exactly one lowercase /sha256/<64-hex>/<basename> path"
        )
    basename = match.group("basename")
    _profile_text(basename, where=f"{where} basename", max_bytes=260)
    if basename in {".", ".."} or "\\" in basename:
        raise SemanticError(f"{where} basename is not a normal Windows filename component")
    return match.group("sha256"), basename, f"{parsed.scheme}://{parsed.netloc}/"


def _chromium_download_profile(view: _SQLiteView) -> str:
    _require_schema(
        view,
        (
            (1, "table", "downloads", "downloads", 2, _CHROMIUM_DOWNLOADS_SQL),
            (
                2,
                "table",
                "downloads_url_chains",
                "downloads_url_chains",
                3,
                _CHROMIUM_CHAINS_SQL,
            ),
            (3, "table", RESERVED_NAME, RESERVED_NAME, 4, _MARKER_SQL),
        ),
    )
    downloads = _table(view, "downloads")
    expected_columns = (
        ("id", "INTEGER", True, True),
        ("guid", "TEXT", False, False),
        ("current_path", "TEXT", False, False),
        ("target_path", "TEXT", False, False),
        ("start_time", "INTEGER", False, False),
        ("received_bytes", "INTEGER", False, False),
        ("total_bytes", "INTEGER", False, False),
        ("state", "INTEGER", False, False),
        ("danger_type", "INTEGER", False, False),
        ("interrupt_reason", "INTEGER", False, False),
        ("hash", "BLOB", False, False),
        ("end_time", "INTEGER", False, False),
        ("opened", "INTEGER", False, False),
        ("last_access_time", "INTEGER", False, False),
        ("transient", "INTEGER", False, False),
        ("referrer", "TEXT", False, False),
        ("site_url", "TEXT", False, False),
        ("embedder_download_data", "TEXT", False, False),
        ("tab_url", "TEXT", False, False),
        ("tab_referrer_url", "TEXT", False, False),
        ("http_method", "TEXT", False, False),
        ("by_ext_id", "TEXT", False, False),
        ("by_ext_name", "TEXT", False, False),
        ("by_web_app_id", "TEXT", False, False),
        ("etag", "TEXT", False, False),
        ("last_modified", "TEXT", False, False),
        ("mime_type", "TEXT", False, False),
        ("original_mime_type", "TEXT", False, False),
    )
    if downloads.columns != expected_columns or not 1 <= len(downloads.rows) <= 8:
        raise SemanticError(
            "Chromium History requires its exact download schema and 1..8 completed rows"
        )

    identities: dict[int, tuple[str, str, str]] = {}
    guids: set[str] = set()
    for expected_id, (rowid, values) in enumerate(downloads.rows, start=1):
        download_id = _scalar(values[0], "integer", "Chromium download id")
        guid = _scalar(values[1], "text", "Chromium download GUID")
        current_path = _chromium_windows_path(
            _scalar(values[2], "text", "Chromium current path"),
            where="Chromium current path",
        )
        target_path = _chromium_windows_path(
            _scalar(values[3], "text", "Chromium target path"),
            where="Chromium target path",
        )
        start = _chromium_windows_timestamp(
            _scalar(values[4], "integer", "Chromium start time"),
            where="Chromium start time",
        )
        received = _scalar(values[5], "integer", "Chromium received bytes")
        total = _scalar(values[6], "integer", "Chromium total bytes")
        state = _scalar(values[7], "integer", "Chromium state")
        danger = _scalar(values[8], "integer", "Chromium danger type")
        interrupt = _scalar(values[9], "integer", "Chromium interrupt reason")
        stored_hash = _scalar(values[10], "blob", "Chromium hash")
        end = _chromium_windows_timestamp(
            _scalar(values[11], "integer", "Chromium end time"),
            where="Chromium end time",
        )
        opened = _scalar(values[12], "integer", "Chromium opened flag")
        last_access = _scalar(values[13], "integer", "Chromium last access time")
        transient = _scalar(values[14], "integer", "Chromium transient flag")
        referrer = _scalar(values[15], "text", "Chromium referrer")
        site_url = _scalar(values[16], "text", "Chromium site URL")
        embedder = _scalar(values[17], "text", "Chromium embedder data")
        tab_url = _scalar(values[18], "text", "Chromium tab URL")
        tab_referrer = _scalar(values[19], "text", "Chromium tab referrer")
        method = _scalar(values[20], "text", "Chromium HTTP method")
        extension_id = _scalar(values[21], "text", "Chromium extension id")
        extension_name = _scalar(values[22], "text", "Chromium extension name")
        web_app_id = _scalar(values[23], "text", "Chromium web app id")
        etag = _scalar(values[24], "text", "Chromium etag")
        last_modified = _scalar(values[25], "text", "Chromium last-modified")
        mime_type = _scalar(values[26], "text", "Chromium MIME type")
        original_mime = _scalar(values[27], "text", "Chromium original MIME type")

        _profile_text(guid, where="Chromium download GUID", max_bytes=36)
        _chromium_reserved_url(referrer, where="Chromium referrer")
        if rowid != expected_id or download_id != expected_id:
            raise SemanticError("Chromium download rowid/id order must be contiguous from one")
        if _CHROMIUM_UUID.fullmatch(guid) is None or guid in guids:
            raise SemanticError("Chromium download GUIDs must be unique lowercase UUID v4 values")
        if current_path != target_path:
            raise SemanticError("Chromium current_path and target_path must be identical")
        if (
            type(received) is not int
            or not 1 <= received <= _MAX_CHROMIUM_DOWNLOAD_BYTES
            or received != total
        ):
            raise SemanticError("Chromium completed rows require received_bytes=total_bytes")
        if (state, danger, interrupt, stored_hash, transient) != (1, 0, 0, b"", 0):
            raise SemanticError(
                "Chromium completion, danger, interrupt, empty-BLOB hash and transient "
                "fields are outside profile"
            )
        if end <= start:
            raise SemanticError("Chromium download end_time must be after start_time")
        if opened == 1:
            last_access = _chromium_windows_timestamp(
                last_access, where="Chromium last access time"
            )
            if last_access < end:
                raise SemanticError(
                    "Chromium opened download last_access_time must not precede end_time"
                )
        elif opened != 0 or type(last_access) is not int or last_access != 0:
            raise SemanticError(
                "Chromium unopened download requires opened=0 and last_access_time=0"
            )
        if (
            embedder,
            tab_url,
            tab_referrer,
            method,
            extension_id,
            extension_name,
            web_app_id,
            etag,
            last_modified,
            mime_type,
            original_mime,
        ) != (
            "",
            referrer,
            "",
            "GET",
            "",
            "",
            "",
            "",
            "",
            "application/x-msdownload",
            "application/x-msdownload",
        ):
            raise SemanticError(
                "Chromium tab, extension, HTTP placeholder, or MIME fields are outside profile"
            )
        guids.add(guid)
        identities[download_id] = (target_path, site_url, referrer)

    chains = _table(view, "downloads_url_chains")
    expected_chain_columns = (
        ("id", "INTEGER", False, False),
        ("chain_index", "INTEGER", False, False),
        ("url", "TEXT", False, False),
    )
    if chains.columns != expected_chain_columns or len(chains.rows) != len(downloads.rows):
        raise SemanticError(
            "Chromium URL chains require the exact schema and one row per download"
        )
    content_identities: set[tuple[str, str]] = set()
    for expected_id, (rowid, values) in enumerate(chains.rows, start=1):
        download_id = _scalar(values[0], "integer", "Chromium URL-chain id")
        chain_index = _scalar(values[1], "integer", "Chromium URL-chain index")
        source_url = _scalar(values[2], "text", "Chromium source URL")
        if rowid != expected_id or download_id != expected_id or chain_index != 0:
            raise SemanticError(
                "Chromium URL chains must be one contiguous chain_index=0 row per download"
            )
        target_path, site_url, _referrer = identities[download_id]
        digest, source_basename, expected_site_url = _chromium_source_identity(
            source_url, where="Chromium source URL"
        )
        # Gate 1 owns only the lowercase content-address syntax. Gate 2 independently hashes
        # the resident PE bytes and binds that digest component to the download observation.
        if source_basename.casefold() != ntpath.basename(target_path).casefold():
            raise SemanticError("Chromium source URL basename must match its target path")
        if site_url != expected_site_url:
            raise SemanticError("Chromium site_url must be the source URL origin")
        identity = (target_path.casefold(), digest)
        if identity in content_identities:
            raise SemanticError("Chromium target/SHA-256 identities must be unique")
        content_identities.add(identity)

    _marker_table(view)
    return (
        "profile=chromium-completed-download-query-surface-v1,"
        f"rows={len(downloads.rows)},chains=exact,sha256-component=syntactic,marker=exact"
    )


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
    if table.columns != expected_columns or not 1 <= len(table.rows) <= 8:
        raise SemanticError("QuarantineEventsV2 requires its exact schema and 1..8 rows")
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
    row_count = len(table.rows)
    return (
        f"rows={row_count},uuid-v4={row_count},https={row_count * 2},"
        "index=exact,marker=exact"
    )


def _validate_sqlite_profile(path: str, reads: dict) -> str:
    view = _sqlite_pair(reads)
    if view.wire_profile != SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1.value:
        raise SemanticError(
            "SQLite artifact does not conform to the declared owned wire profile"
        )
    name = os.path.basename(path)
    if name == "History":
        return _chromium_download_profile(view)
    if name == "knowledgeC.db":
        return _knowledge_profile(view)
    if name == "TCC.db":
        return _tcc_profile(view)
    if name in {
        "QuarantineEventsV2",
        "com.apple.LaunchServices.QuarantineEventsV2",
    }:
        return _quarantine_profile(view)
    raise SemanticError(f"SQLite artifact name {name!r} has no declared profile")


def _sqlite_query(path: str, sql: str, *, limit: int, where: str) -> tuple[tuple, ...]:
    import sqlite3

    uri = f"{Path(path).resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        progress_calls = 0

        def bounded_progress():
            nonlocal progress_calls
            progress_calls += 1
            return int(progress_calls > 10_000)

        connection.set_progress_handler(bounded_progress, 100)
        return _bounded_rows(connection.execute(sql), limit=limit, where=where)
    finally:
        connection.close()


def _sqlite_untagged_rows(table: _SQLiteTableView) -> tuple[tuple, ...]:
    return tuple(tuple(value[1] for value in values) for _rowid, values in table.rows)


def _validate_sqlite_responder_query(path: str, reads: dict) -> str:
    """Exercise one bounded responder query against each basename-dispatched database."""
    view = _sqlite_pair(reads)
    name = os.path.basename(path)
    if name == "History":
        rows = _sqlite_query(
            path,
            "SELECT d.*,u.chain_index,u.url FROM downloads AS d "
            "JOIN downloads_url_chains AS u ON u.id=d.id "
            "ORDER BY d.id,u.chain_index",
            limit=8,
            where="Chromium completed-download responder query",
        )
        downloads = _sqlite_untagged_rows(_table(view, "downloads"))
        chains = _sqlite_untagged_rows(_table(view, "downloads_url_chains"))
        chain_by_id = {row[0]: row[1:] for row in chains}
        expected = tuple((*row, *chain_by_id.get(row[0], (None, None))) for row in downloads)
        if rows != expected:
            raise SemanticError(
                "Chromium responder join does not recover the consensus download/chain rows"
            )
        return f"consumer=sqlite3-chromium-download-join,rows={len(rows)}"
    if name == "knowledgeC.db":
        rows = _sqlite_query(
            path,
            "SELECT o.Z_PK,o.ZVALUESTRING,o.ZSTARTDATE,o.ZENDDATE,o.ZUUID,"
            "m.ZMETADATAHASH,s.Z_PK FROM ZOBJECT AS o "
            "LEFT JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA=m.Z_PK "
            "LEFT JOIN ZSOURCE AS s ON o.ZSOURCE=s.Z_PK "
            "WHERE o.ZSTREAMNAME IS '/app/inFocus' ORDER BY o.Z_PK",
            limit=8,
            where="APOLLO app-in-focus responder query",
        )
        if len(rows) != len(_table(view, "ZOBJECT").rows) or any(
            row[5] is None or row[6] is None for row in rows
        ):
            raise SemanticError("APOLLO responder query does not resolve every profile row")
        return f"consumer=APOLLO-app-in-focus-query,rows={len(rows)}"
    if name == "TCC.db":
        rows = _sqlite_query(
            path,
            "SELECT service,client,client_type,auth_value,auth_reason,"
            "indirect_object_identifier,last_modified FROM access ORDER BY rowid",
            limit=8,
            where="mac_apt TCC responder query",
        )
        if len(rows) != len(_table(view, "access").rows):
            raise SemanticError("mac_apt TCC responder query misses profile rows")
        return f"consumer=mac_apt-tcc-query,rows={len(rows)}"
    if name in {
        "QuarantineEventsV2",
        "com.apple.LaunchServices.QuarantineEventsV2",
    }:
        rows = _sqlite_query(
            path,
            "SELECT LSQuarantineEventIdentifier,LSQuarantineTimeStamp,"
            "LSQuarantineAgentName,LSQuarantineDataURLString,"
            "LSQuarantineOriginURLString FROM LSQuarantineEvent "
            "ORDER BY LSQuarantineEventIdentifier",
            limit=8,
            where="LaunchServices quarantine responder query",
        )
        if len(rows) != len(_table(view, "LSQuarantineEvent").rows):
            raise SemanticError("quarantine responder query misses profile rows")
        return f"consumer=LaunchServices-quarantine-query,rows={len(rows)}"
    raise SemanticError(f"SQLite artifact name {name!r} has no responder query")


def _quarantine_xattr_typed(view: object, *, where: str) -> tuple[tuple[str, object], ...]:
    if type(view) is not _QuarantineXattrView:
        raise SemanticError(f"{where} observation is not a quarantine-xattr view")
    fields = (
        ("text", view.flags),
        ("integer", view.timestamp_unix),
        ("text", view.agent),
        ("text", view.event_uuid),
    )
    expected_types = (str, int, str, str)
    for (kind, value), expected in zip(fields, expected_types, strict=True):
        if type(value) is not expected:
            raise SemanticError(
                f"{where} {kind} field has non-exact type {type(value).__name__}"
            )
    return fields


def _quarantine_xattr_pair(reads: dict) -> _QuarantineXattrView:
    standard = reads.get("macos-xattr")
    raw = reads.get("quarantine-xattr-raw")
    standard_typed = _quarantine_xattr_typed(standard, where="macOS xattr parser")
    raw_typed = _quarantine_xattr_typed(raw, where="raw xattr reader")
    if standard_typed != raw_typed:
        raise SemanticError(
            "macOS xattr parser and raw reader disagree on type-exact quarantine fields"
        )
    assert type(raw) is _QuarantineXattrView
    return raw


def _validate_quarantine_xattr_consensus(_path: str, reads: dict) -> str:
    return _quarantine_xattr_pair(reads).detail()


def _validate_quarantine_xattr_profile(path: str, reads: dict) -> str:
    view = _quarantine_xattr_pair(reads)
    if not path.endswith(".quarantine.xattr"):
        raise SemanticError("quarantine xattr must use the exact .quarantine.xattr suffix")
    if view.flags != "0181" or not 0 <= view.timestamp_unix <= 0xFFFFFFFF:
        raise SemanticError("quarantine xattr flags/timestamp are outside the exact profile")
    _profile_text(view.agent, where="quarantine xattr agent", max_bytes=64)
    if (
        not view.agent[0].isalnum()
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._-"
               for character in view.agent)
    ):
        raise SemanticError("quarantine xattr agent is outside the exact ASCII profile")
    if _QUARANTINE_UUID.fullmatch(view.event_uuid) is None:
        raise SemanticError("quarantine xattr UUID must be canonical uppercase RFC 4122 v4")
    return "profile=com.apple.quarantine-v1,fields=4,uuid-v4=1"


def _zone_identifier_typed(view: object, *, where: str) -> tuple[tuple[str, object], ...]:
    if type(view) is not _ZoneIdentifierView:
        raise SemanticError(f"{where} observation is not a Zone.Identifier view")
    fields = (
        ("text", view.section),
        ("text-array", view.key_order),
        ("integer", view.zone_id),
        ("text", view.referrer_url),
        ("text", view.host_url),
    )
    expected_types = (str, tuple, int, str, str)
    for (kind, value), expected in zip(fields, expected_types, strict=True):
        if type(value) is not expected:
            raise SemanticError(
                f"{where} {kind} field has non-exact type {type(value).__name__}"
            )
    if any(type(key) is not str for key in view.key_order):
        raise SemanticError(f"{where} key-order member has a non-exact type")
    return fields


def _zone_identifier_pair(reads: dict) -> _ZoneIdentifierView:
    production = reads.get("configparser")
    raw = reads.get("zone-identifier-raw")
    production_typed = _zone_identifier_typed(
        production, where="ConfigParser Zone.Identifier reader"
    )
    raw_typed = _zone_identifier_typed(raw, where="raw Zone.Identifier reader")
    if production_typed != raw_typed:
        raise SemanticError(
            "ConfigParser and raw reader disagree on type-exact Zone.Identifier fields"
        )
    assert type(raw) is _ZoneIdentifierView
    return raw


def _validate_zone_identifier_consensus(_path: str, reads: dict) -> str:
    return _zone_identifier_pair(reads).detail()


def _validate_zone_identifier_profile(path: str, reads: dict) -> str:
    view = _zone_identifier_pair(reads)
    if not path.endswith(".Zone.Identifier"):
        raise SemanticError("logical Zone.Identifier must use the exact stream-name suffix")
    expected_keys = ("ZoneId", "ReferrerUrl", "HostUrl")
    if view.section != "ZoneTransfer" or view.key_order != expected_keys:
        raise SemanticError("Zone.Identifier section/key order is outside the closed profile")
    if view.zone_id != 3:
        raise SemanticError("Zone.Identifier must declare Internet-zone ZoneId=3")
    for label, value in (
        ("ReferrerUrl", view.referrer_url),
        ("HostUrl", view.host_url),
    ):
        _profile_text(value, where=f"Zone.Identifier {label}", max_bytes=512)
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or not hostname.endswith((".example", ".invalid", ".test"))
            or parsed.netloc != hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.fragment
            or MARKER not in value
        ):
            raise SemanticError(
                f"Zone.Identifier {label} is outside the marked reserved URL profile"
            )
    return "profile=chromium-windows-augmented-v1,zone=internet,urls=marked-reserved"


_TASK_XML_DESCRIPTION = (
    f"{MARKER} synthetic inert scheduled-task artifact; disabled and trigger-free."
)
_TASK_XML_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_TASK_XML_DRIVE = re.compile(r"[A-Z]:")
_TASK_XML_INVALID_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*%')
_TASK_XML_RESERVED_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
_TASK_XML_FORBIDDEN_EXECUTABLES = frozenset(
    {
        "bash.exe",
        "bitsadmin.exe",
        "certutil.exe",
        "cmd.exe",
        "cscript.exe",
        "curl.exe",
        "forfiles.exe",
        "installutil.exe",
        "msbuild.exe",
        "mshta.exe",
        "msiexec.exe",
        "node.exe",
        "pcalua.exe",
        "perl.exe",
        "powershell.exe",
        "pwsh.exe",
        "python.exe",
        "python3.exe",
        "reg.exe",
        "regasm.exe",
        "regsvcs.exe",
        "regsvr32.exe",
        "ruby.exe",
        "schtasks.exe",
        "rundll32.exe",
        "wscript.exe",
        "wsl.exe",
    }
)


def _scheduled_task_xml_typed(view: object, *, where: str) -> tuple[tuple[type, object], ...]:
    if type(view) is not _ScheduledTaskXmlView:
        raise SemanticError(f"{where} observation is not a scheduled-task XML view")
    values = (
        view.namespace,
        view.version,
        view.task_name,
        view.uri,
        view.description,
        view.command,
        view.enabled,
        view.allow_start_on_demand,
        view.hidden,
        view.trigger_count,
        view.action_count,
    )
    expected_types = (str, str, str, str, str, str, bool, bool, bool, int, int)
    if any(type(value) is not expected for value, expected in zip(values, expected_types, strict=True)):
        raise SemanticError(f"{where} returned a non-exact scheduled-task field type")
    return tuple((type(value), value) for value in values)


def _scheduled_task_xml_pair(reads: dict) -> _ScheduledTaskXmlView:
    elementtree = reads.get("elementtree")
    raw = reads.get("task-xml-raw")
    elementtree_typed = _scheduled_task_xml_typed(elementtree, where="ElementTree task reader")
    raw_typed = _scheduled_task_xml_typed(raw, where="raw task XML reader")
    if elementtree_typed != raw_typed:
        raise SemanticError(
            "ElementTree and raw reader disagree on type-exact scheduled-task fields"
        )
    assert type(raw) is _ScheduledTaskXmlView
    return raw


def _scheduled_task_source(source: object) -> _ScheduledTaskArtifactSource:
    if type(source) is not _ScheduledTaskArtifactSource:
        raise SemanticError("scheduled-task profile requires an immutable scene source")
    if type(source.snapshot) is not bytes:
        raise SemanticError("scheduled-task source snapshot must be immutable bytes")
    if type(source.resident_pe_names) is not tuple or any(
        type(name) is not str for name in source.resident_pe_names
    ):
        raise SemanticError("scheduled-task resident PE names have an invalid shape")
    return source


def _validate_task_command_path(value: object) -> str:
    if type(value) is not str or not value:
        raise SemanticError("scheduled-task Command must be a non-empty Windows path")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise SemanticError("scheduled-task Command must be strict ASCII") from exc
    if len(encoded) > 260 or any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise SemanticError("scheduled-task Command is outside the 260-code-unit profile")
    drive, tail = ntpath.splitdrive(value)
    if (
        _TASK_XML_DRIVE.fullmatch(drive) is None
        or not tail.startswith("\\")
        or tail.startswith("\\\\")
        or ntpath.normpath(value) != value
    ):
        raise SemanticError(
            "scheduled-task Command must be a normalized absolute drive-letter path"
        )
    components = tail[1:].split("\\")
    if not components or any(component in {"", ".", ".."} for component in components):
        raise SemanticError("scheduled-task Command contains an empty or dot component")
    for component in components:
        if (
            len(component) > 255
            or component[-1] in {" ", "."}
            or any(
                character in _TASK_XML_INVALID_COMPONENT_CHARACTERS
                for character in component
            )
            or component.split(".", 1)[0].upper() in _TASK_XML_RESERVED_STEMS
        ):
            raise SemanticError("scheduled-task Command contains an invalid path component")
    basename = components[-1]
    if not basename.casefold().endswith(".exe"):
        raise SemanticError("scheduled-task Command must name one PE executable")
    if basename.casefold() in _TASK_XML_FORBIDDEN_EXECUTABLES:
        raise SemanticError("scheduled-task Command names a forbidden command utility")
    return basename


def _validate_scheduled_task_xml_consensus(source: object, reads: dict) -> str:
    _scheduled_task_source(source)
    return _scheduled_task_xml_pair(reads).detail()


def _validate_scheduled_task_xml_profile(source: object, reads: dict) -> str:
    artifact = _scheduled_task_source(source)
    view = _scheduled_task_xml_pair(reads)
    if artifact.relative_path.endswith(".task.xml"):
        location_profile = "loose-task-xml"
    elif artifact.relative_path == _TASK_XML_NATIVE_SERVED_PREFIX + view.task_name:
        location_profile = "native-task-store"
    else:
        raise SemanticError(
            "scheduled-task XML must use .task.xml transport naming or its exact native "
            "Task-store served path"
        )
    if view.namespace != _TASK_XML_NAMESPACE or view.version not in {"1.2", "1.3"}:
        raise SemanticError("scheduled-task namespace/version is outside the owned profile")
    if (
        type(view.task_name) is not str
        or _TASK_XML_NAME.fullmatch(view.task_name) is None
        or view.task_name.endswith(".")
        or view.task_name.split(".", 1)[0].upper() in _TASK_XML_RESERVED_STEMS
    ):
        raise SemanticError("scheduled-task name is outside the bounded ASCII profile")
    expected_uri = f"\\ArtifactForge\\{MARKER}-{view.task_name}"
    if view.uri != expected_uri or view.description != _TASK_XML_DESCRIPTION:
        raise SemanticError("scheduled-task URI/description lacks the exact synthetic marker")
    if (
        type(view.enabled) is not bool
        or view.enabled
        or type(view.allow_start_on_demand) is not bool
        or view.allow_start_on_demand
        or type(view.hidden) is not bool
        or view.hidden
        or type(view.trigger_count) is not int
        or view.trigger_count != 0
        or type(view.action_count) is not int
        or view.action_count != 1
    ):
        raise SemanticError(
            "scheduled-task must be visible, disabled, demand-start-disabled, "
            "trigger-free, and contain exactly one action"
        )
    command_basename = _validate_task_command_path(view.command)
    resident_matches = tuple(
        name
        for name in artifact.resident_pe_names
        if name.casefold() == command_basename.casefold()
    )
    if len(resident_matches) != 1:
        raise SemanticError(
            "scheduled-task Command basename must match exactly one resident PE artifact"
        )
    return (
        "profile=windows-task-scheduler-disabled-exec-v1,"
        "enabled=false,demand-start=false,triggers=0,principals=0,"
        "actions=1,args=0,working-directory=0,context=0,resident-basename=1,"
        f"location={location_profile}"
    )


def _validate_scheduled_task_dissect_consumer(source: object, reads: dict) -> str:
    _scheduled_task_source(source)
    expected = _scheduled_task_xml_pair(reads)
    observed = reads.get("dissect.target-tasks")
    if type(observed) is not _ScheduledTaskConsumerView:
        raise SemanticError("typed Dissect ScheduledTasks observation is required")
    if (
        type(observed.version) is not str
        or observed.version != expected.version
        or type(observed.uri) is not str
        or observed.uri != expected.uri
        or type(observed.description) is not str
        or observed.description != expected.description
        or type(observed.command) is not str
        or observed.command != expected.command
        or observed.arguments is not None
        or observed.working_directory is not None
        or type(observed.enabled) is not bool
        or observed.enabled != expected.enabled
        or type(observed.allow_start_on_demand) is not bool
        or observed.allow_start_on_demand != expected.allow_start_on_demand
        or type(observed.hidden) is not bool
        or observed.hidden != expected.hidden
        or type(observed.trigger_count) is not int
        or observed.trigger_count != expected.trigger_count
        or type(observed.principal_count) is not int
        or observed.principal_count != 0
        or type(observed.action_count) is not int
        or observed.action_count != expected.action_count
        or observed.action_context is not None
    ):
        raise SemanticError(
            "Dissect ScheduledTasks extraction disagrees with the disabled task profile"
        )
    return observed.detail()


def _shell_link_pair(reads: dict) -> ShellLinkOracleView:
    external = require_shell_link_consensus(reads)
    raw = reads.get("shell-link-raw")
    if type(raw) is not ShellLinkOracleView:
        raise SemanticError("typed bounded-reader Shell Link observation is required")
    if external != raw:
        raise SemanticError(
            "external parser consensus and the bounded Shell Link reader disagree"
        )
    return raw


def _validate_shell_link_consensus(_path: str, reads: dict) -> str:
    view = _shell_link_pair(reads)
    return f"liblnk=LnkParse3=bounded-reader,{view.detail()}"


def _validate_shell_link_profile(_path: str, reads: dict) -> str:
    return validate_artifactforge_shell_link_profile(_shell_link_pair(reads))


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
    "macho": [
        ("macho-consensus", _validate_macho_consensus),
        ("artifactforge-arm64-macho-v1-profile", _validate_macho_profile),
    ],
    "hive": [
        ("hive-consensus", _validate_hive_consensus),
        ("windows-hive-profile", _validate_windows_hive_profile),
        ("regipy-artifact-consumer", _validate_regipy_hive_consumer),
    ],
    "prefetch-v17": [("scca-v17-path-hash", _validate_scca_v17)],
    "prefetch": [
        ("prefetch-v30-consensus", _validate_prefetch_v30_consensus),
        ("artifactforge-prefetch-v30-profile", _validate_prefetch_v30_profile),
    ],
    "sqlite": [
        ("sqlite-consensus", _validate_sqlite_consensus),
        ("sqlite-profile", _validate_sqlite_profile),
        ("sqlite-responder-query", _validate_sqlite_responder_query),
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
    "quarantine-xattr": [
        ("quarantine-xattr-consensus", _validate_quarantine_xattr_consensus),
        ("quarantine-xattr-profile", _validate_quarantine_xattr_profile),
    ],
    "zone-identifier": [
        ("zone-identifier-consensus", _validate_zone_identifier_consensus),
        ("zone-identifier-profile", _validate_zone_identifier_profile),
    ],
    "task-xml": [
        ("scheduled-task-xml-consensus", _validate_scheduled_task_xml_consensus),
        ("scheduled-task-xml-profile", _validate_scheduled_task_xml_profile),
        ("dissect-scheduled-task-consumer", _validate_scheduled_task_dissect_consumer),
    ],
    "shell-link": [
        ("shell-link-consensus", _validate_shell_link_consensus),
        ("shell-link-profile", _validate_shell_link_profile),
    ],
}

SEMANTIC_VALIDATOR_SCOPES = {
    "import-consensus": "independent_consensus",
    "macho-consensus": "independent_consensus",
    "artifactforge-arm64-macho-v1-profile": "declared_profile_conformance",
    "hive-consensus": "independent_consensus",
    "windows-hive-profile": "declared_profile_conformance",
    "regipy-artifact-consumer": "downstream_consumer_compatibility",
    "scca-v17-path-hash": "declared_profile_conformance",
    "prefetch-v30-consensus": "independent_consensus",
    "artifactforge-prefetch-v30-profile": "declared_profile_conformance",
    "sqlite-consensus": "independent_consensus",
    "sqlite-profile": "declared_profile_conformance",
    "sqlite-responder-query": "downstream_consumer_compatibility",
    "bplist-consensus": "independent_consensus",
    "launchagent-profile": "declared_profile_conformance",
    "elf-consensus": "independent_consensus",
    "linux-elf-profile": "declared_profile_conformance",
    "desktop-entry-consensus": "independent_consensus",
    "xdg-autostart-profile": "declared_profile_conformance",
    "bash-history-consensus": "independent_consensus",
    "bash-history-profile": "declared_profile_conformance",
    "quarantine-xattr-consensus": "independent_consensus",
    "quarantine-xattr-profile": "declared_profile_conformance",
    "zone-identifier-consensus": "independent_consensus",
    "zone-identifier-profile": "declared_profile_conformance",
    "scheduled-task-xml-consensus": "independent_consensus",
    "scheduled-task-xml-profile": "declared_profile_conformance",
    "dissect-scheduled-task-consumer": "downstream_consumer_compatibility",
    "shell-link-consensus": "independent_consensus",
    "shell-link-profile": "declared_profile_conformance",
}


def _validate_claim_scope_registry() -> None:
    names = [name for validators in SEMANTIC_VALIDATORS.values() for name, _ in validators]
    if len(names) != len(set(names)):
        raise RuntimeError("Gate 1 semantic validator names must be globally unique")
    if set(names) != set(SEMANTIC_VALIDATOR_SCOPES):
        missing = sorted(set(names) - set(SEMANTIC_VALIDATOR_SCOPES))
        stale = sorted(set(SEMANTIC_VALIDATOR_SCOPES) - set(names))
        raise RuntimeError(
            f"Gate 1 claim-scope registry mismatch: missing={missing!r}, stale={stale!r}"
        )
    invalid = sorted(set(SEMANTIC_VALIDATOR_SCOPES.values()) - set(CLAIM_SCOPE_ORDER))
    if invalid:
        raise RuntimeError(f"Gate 1 semantic validators use unknown claim scopes: {invalid!r}")


_validate_claim_scope_registry()


_SNAPSHOT_LIMITS = {
    "prefetch": 8192,
    "sqlite": 16 * 1024 * 1024,
    "plist": 1024 * 1024,
    "desktop-entry": 64 * 1024,
    "bash-history": 1024 * 1024,
    "quarantine-xattr": 512,
    "zone-identifier": 2048,
    "task-xml": 16 * 1024,
    "shell-link": 4096,
}
_EXPECTED_RESULTS = {
    ("pe", "pefile"): _PESemantics,
    ("pe", "lief"): _PESemantics,
    ("macho", "lief"): MachOView,
    ("macho", "macholib"): MachOView,
    ("hive", "regipy"): _HiveView,
    ("hive", "libregf"): _HiveView,
    ("prefetch-v17", "windowsprefetch"): str,
    ("prefetch-v17", "pyscca"): str,
    ("prefetch", "pyscca"): PrefetchV30OracleView,
    ("prefetch", "dissect.target-prefetch"): PrefetchV30OracleView,
    ("prefetch", "prefetch-raw"): PrefetchV30ProfileView,
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
    ("quarantine-xattr", "macos-xattr"): _QuarantineXattrView,
    ("quarantine-xattr", "quarantine-xattr-raw"): _QuarantineXattrView,
    ("zone-identifier", "configparser"): _ZoneIdentifierView,
    ("zone-identifier", "zone-identifier-raw"): _ZoneIdentifierView,
    ("task-xml", "elementtree"): _ScheduledTaskXmlView,
    ("task-xml", "task-xml-raw"): _ScheduledTaskXmlView,
    ("task-xml", "dissect.target-tasks"): _ScheduledTaskConsumerView,
    ("shell-link", "liblnk"): ShellLinkOracleView,
    ("shell-link", "LnkParse3"): ShellLinkOracleView,
    ("shell-link", "shell-link-raw"): ShellLinkOracleView,
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


def _new_claim_scope_counts() -> dict[str, dict[str, int]]:
    return {scope: {"passed": 0, "total": 0} for scope in CLAIM_SCOPE_ORDER}


def _run_files(
    r: GateReport, files
) -> tuple[int, int, int, int, set[str], dict[str, dict[str, int]]]:
    files = tuple(files)
    checked = passed = 0
    semantic_checked = semantic_passed = 0
    seen_formats = set()
    claim_scopes = _new_claim_scope_counts()
    resident_guest_paths = tuple(
        "/" + file.relative_path
        for file in files
        if type(file.data) is bytes
        and classify_bytes(file.data, file.relative_path) == "elf"
    )
    resident_pe_names = tuple(
        os.path.basename(file.relative_path)
        for file in files
        if type(file.data) is bytes
        and classify_bytes(file.data, file.relative_path) == "pe"
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
        task_source = _ScheduledTaskArtifactSource(
            path,
            name,
            snapshot if type(snapshot) is bytes else b"",
            resident_pe_names,
        )
        prefetch_source = _PrefetchArtifactSource(
            name,
            snapshot if type(snapshot) is bytes else b"",
        )
        read_results = {}
        for oracle in ORACLES[fmt]["required"]:
            checked += 1
            reader_scopes = _READER_CLAIM_SCOPE_OVERRIDES.get(
                (fmt, oracle), _DEFAULT_READER_CLAIM_SCOPES
            )
            for scope in reader_scopes:
                claim_scopes[scope]["total"] += 1
            if snapshot_error:
                r.fail(f"{fmt}: {oracle} did not run — {snapshot_error}")
                continue
            try:
                if fmt in {"desktop-entry", "bash-history"}:
                    source = linux_source
                else:
                    source = snapshot if fmt in _SNAPSHOT_LIMITS else path
                detail = READERS[oracle](source)
            except Exception as exc:                     # noqa: BLE001 — any parser refusal
                absent_imports = _ORACLE_ABSENT_IMPORTS.get(oracle, frozenset())
                if isinstance(exc, ModuleNotFoundError) and exc.name in absent_imports:
                    r.fail(
                        f"{fmt}: oracle '{oracle}' is not installed — a missing oracle is a "
                        "failure, not a skip"
                    )
                else:
                    r.fail(
                        f"{fmt}: {oracle} rejected it — "
                        f"{type(exc).__name__}: {str(exc)[:110]}"
                    )
                continue
            if "container_acceptance" in reader_scopes:
                claim_scopes["container_acceptance"]["passed"] += 1
            expected = _EXPECTED_RESULTS.get((fmt, oracle))
            if expected is None or type(detail) is not expected:
                r.fail(
                    f"{fmt}: {oracle} returned an invalid observation shape "
                    f"{type(detail).__name__}"
                )
                continue
            passed += 1
            if "semantic_extraction" in reader_scopes:
                claim_scopes["semantic_extraction"]["passed"] += 1
            read_results[oracle] = detail
            rendered = detail.detail() if hasattr(detail, "detail") else detail
            r.metrics.setdefault("reads", {})[f"{name}:{oracle}"] = rendered

        for validator_name, validator in SEMANTIC_VALIDATORS.get(fmt, ()):
            semantic_checked += 1
            scope = SEMANTIC_VALIDATOR_SCOPES[validator_name]
            claim_scopes[scope]["total"] += 1
            try:
                semantic_source = (
                    linux_source
                    if fmt in {"elf", "desktop-entry", "bash-history"}
                    else task_source
                    if fmt == "task-xml"
                    else prefetch_source
                    if fmt == "prefetch"
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
            claim_scopes[scope]["passed"] += 1
            r.metrics.setdefault("semantics", {})[f"{name}:{validator_name}"] = detail
    return checked, passed, semantic_checked, semantic_passed, seen_formats, claim_scopes


def run(scene_dir: str) -> GateReport:
    r = GateReport(1, "validity",
                   "do declared parser and semantic oracles validate each artifact?")
    inventory_failed = False
    try:
        with captured_regular_tree(scene_dir) as files:
            (
                checked,
                passed,
                semantic_checked,
                semantic_passed,
                seen_formats,
                claim_scopes,
            ) = _run_files(r, files)
    except InventoryError as exc:
        inventory_failed = True
        checked = passed = semantic_checked = semantic_passed = 0
        seen_formats = set()
        claim_scopes = _new_claim_scope_counts()
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
    r.metrics["claim_scopes"] = claim_scopes
    r.metrics.pop("reads", None)                          # detail is for humans, not the card
    r.metrics.pop("semantics", None)
    r.denominator = (f"{passed}/{checked} oracle reads succeeded; "
                     f"{semantic_passed}/{semantic_checked} semantic checks succeeded")
    return r
