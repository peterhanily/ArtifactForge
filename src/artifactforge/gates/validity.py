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

SQLite databases and binary plists are read back by the same libraries that wrote them, so
they have no independent second opinion. That is recorded as a declared gap rather than
quietly counted as independent validation. Plain sidecars are outside the parser gate.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ntpath
import os
import struct

from artifactforge.gates import GateReport

# format -> the oracles that must all read it, plus any declared gap in that oracle set.
ORACLES = {
    "pe":       {"required": ["pefile", "lief"], "gap": None},
    "macho":    {"required": ["lief", "macholib"], "gap": None},
    "hive":     {"required": ["regipy", "libregf"], "gap": None},
    "prefetch": {"required": ["windowsprefetch", "pyscca"], "gap": None},
    "sqlite":   {"required": ["sqlite3"],
                 "gap": "sqlite3 both writes and reads these databases, so it is not an "
                        "independent oracle; a second reader is an open gap"},
    "plist":    {"required": ["plistlib"],
                 "gap": "plistlib both writes and reads the LaunchAgent plist, so it is not "
                        "an independent oracle; a second reader is an open gap"},
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


def classify(path: str) -> str | None:
    """Which format is this file? Magic first, extension only as a tiebreak."""
    with open(path, "rb") as f:
        head = f.read(16)
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


def _read_sqlite3(path):
    import sqlite3
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA integrity_check").fetchone()
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        return f"tables={','.join(tables)}"
    finally:
        con.close()


def _read_plistlib(path):
    import plistlib
    with open(path, "rb") as f:
        return f"keys={','.join(sorted(plistlib.load(f)))}"


READERS = {
    "pefile": _read_pefile,
    "lief": _read_lief,
    "macholib": _read_macholib,
    "regipy": _read_regipy,
    "libregf": _read_libregf,
    "windowsprefetch": _read_windowsprefetch,
    "pyscca": _read_pyscca,
    "sqlite3": _read_sqlite3,
    "plistlib": _read_plistlib,
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


SEMANTIC_VALIDATORS = {
    "pe": [("import-consensus", _validate_pe_consensus)],
    "prefetch": [("scca-v17-path-hash", _validate_scca_v17)],
}


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
        fmt = classify(path)
        if fmt is None:
            r.fail(f"{name}: no format recognised, so nothing can validate it")
            continue
        if fmt not in ORACLES:
            r.fail(f"{name}: format '{fmt}' has no declared oracle set")
            continue
        seen_formats.add(fmt)
        read_results = {}
        for oracle in ORACLES[fmt]["required"]:
            checked += 1
            try:
                detail = READERS[oracle](path)
            except ImportError:
                r.fail(f"{fmt}: oracle '{oracle}' is not installed — a missing "
                               f"oracle is a failure, not a skip")
                continue
            except Exception as exc:                     # noqa: BLE001 — any parser refusal
                r.fail(f"{fmt}: {oracle} rejected it — "
                               f"{type(exc).__name__}: {str(exc)[:110]}")
                continue
            passed += 1
            read_results[oracle] = detail
            rendered = detail.detail() if isinstance(detail, _PESemantics) else detail
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
