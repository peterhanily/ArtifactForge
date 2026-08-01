# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Small, read-only format oracles used by ArtifactForge's assurance gates."""

from artifactforge.gates.oracles.bplist_subset import (
    BinaryPlistError,
    BinaryPlistLimits,
    load_binary_plist,
    loads_binary_plist,
)
from artifactforge.gates.oracles.sqlite_subset import (
    Column,
    DEFAULT_SQLITE_LIMITS,
    Index,
    IndexEntry,
    SQLiteDatabase,
    SQLiteHeader,
    SQLiteLimits,
    SQLiteRecord,
    SQLiteSubsetError,
    SQLiteValue,
    SchemaObject,
    Table,
    TableRow,
    decode_record,
    decode_varint,
    load_sqlite,
    loads_sqlite,
)

__all__ = [
    "BinaryPlistError",
    "BinaryPlistLimits",
    "load_binary_plist",
    "loads_binary_plist",
    "Column",
    "DEFAULT_SQLITE_LIMITS",
    "Index",
    "IndexEntry",
    "SQLiteDatabase",
    "SQLiteHeader",
    "SQLiteLimits",
    "SQLiteRecord",
    "SQLiteSubsetError",
    "SQLiteValue",
    "SchemaObject",
    "Table",
    "TableRow",
    "decode_record",
    "decode_varint",
    "load_sqlite",
    "loads_sqlite",
]
