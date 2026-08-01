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
import hashlib
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
from artifactforge.gates.oracles import loads_binary_plist, loads_sqlite

# format -> the oracles that must all read it, plus any declared gap in that oracle set.
ORACLES = {
    "pe":       {"required": ["pefile", "lief"], "gap": None},
    "macho":    {"required": ["lief", "macholib"], "gap": None},
    "hive":     {"required": ["regipy", "libregf"], "gap": None},
    "prefetch": {"required": ["windowsprefetch", "pyscca"], "gap": None},
    "sqlite":   {"required": ["sqlite3", "sqlite-raw"], "gap": None},
    "plist":    {"required": ["plistlib", "bplist-raw"], "gap": None},
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
    if head[:4] == b"regf":
        return "hive"
    if head[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if head[:8] == b"bplist00":
        return "plist"
    if path.lower().endswith(".pf"):
        return "prefetch"
    return None


def classify(path: str) -> str | None:
    """Which format is this file? Magic first, extension only as a tiebreak."""
    with open(path, "rb") as f:
        return _classify_head(f.read(16), path)


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


def _read_lief(path):
    import lief
    b = lief.parse(path)
    if b is None:
        raise ValueError("lief returned None")
    if isinstance(b, lief.PE.Binary):
        return _lief_pe_semantics(b, lief)
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
}


_SNAPSHOT_LIMITS = {"sqlite": 16 * 1024 * 1024, "plist": 1024 * 1024}
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


def run(scene_dir: str) -> GateReport:
    r = GateReport(1, "validity",
                   "do declared parser and semantic oracles validate each artifact?")
    checked = passed = 0
    semantic_checked = semantic_passed = 0
    seen_formats = set()

    for name in sorted(os.listdir(scene_dir)):
        path = os.path.join(scene_dir, name)
        if not os.path.isfile(path) or name.startswith("."):
            continue
        if name.endswith(_SIDECAR_SUFFIXES):
            continue
        fmt, snapshot, snapshot_error = _classify_and_snapshot(path)
        if fmt is None:
            detail = snapshot_error or "no format recognised, so nothing can validate it"
            r.fail(f"{name}: {detail}")
            continue
        if fmt not in ORACLES:
            r.fail(f"{name}: format '{fmt}' has no declared oracle set")
            continue
        seen_formats.add(fmt)
        read_results = {}
        for oracle in ORACLES[fmt]["required"]:
            checked += 1
            if snapshot_error:
                r.fail(f"{fmt}: {oracle} did not run — {snapshot_error}")
                continue
            try:
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
                detail = validator(path, read_results)
            except Exception as exc:                     # noqa: BLE001 — a semantic refusal
                r.fail(
                    f"{name}: semantic validator '{validator_name}' failed — "
                    f"{type(exc).__name__}: {str(exc)[:110]}"
                )
                continue
            semantic_passed += 1
            r.metrics.setdefault("semantics", {})[f"{name}:{validator_name}"] = detail

    for fmt in sorted(seen_formats):
        if ORACLES[fmt]["gap"]:
            r.gap(f"{fmt}: {ORACLES[fmt]['gap']}")

    if checked == 0:
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
