# macOS raw-oracle and semantic-profile contract

Gate 1 treats container readability and artifact meaning as different claims. A SQLite file or
binary plist earns credit only when both parser implementations accept the same bounded byte
snapshot, their type-tagged observations agree, and the filename-specific semantic profile
passes.

## One snapshot, two implementations

The gate classifies and reads each SQLite/plist artifact once from one open file description.
SQLite snapshots are capped at 16 MiB; binary plists at 1 MiB. The same immutable `bytes`
object is passed to both readers. `sqlite3` deserializes that snapshot into a private in-memory
database and runs a complete `PRAGMA integrity_check`; `plistlib` uses `loads`. The raw readers
consume the bytes directly. This prevents a pathname replacement from showing one parser a
different file than the other and bounds the standard parser before it allocates from input.

Parsed values are tagged by exact type. In particular, plist boolean `true`, integer `1` and
real `1.0` are different observations. Container cycles, shared containers and object graphs
beyond the LaunchAgent traversal budget are outside the emitted tree profile and fail closed.

## SQLite subset

`artifactforge.gates.oracles.sqlite_subset` accepts only the profile emitted today:

- 4096-byte pages, UTF-8, rollback journal mode and schema format 4;
- complete schema ownership of every non-header page;
- table-leaf and index-leaf roots with canonical varints and record serial types;
- no freelist, pointer map, auto-vacuum, interior page, overflow or fragmented content;
- exact cell/freeblock tiling, strict rowid and index-key order;
- INTEGER PRIMARY KEY rowid recovery, REAL affinity normalization, and exact primary-key
  index-to-table correspondence.

The raw observation and `sqlite3` observation must agree on schema rowids, object type/name,
owner, root page, SQL text, column metadata, every typed table row in order, and every logical
index entry. This is not a general SQLite reader.

## Binary-plist subset

`artifactforge.gates.oracles.bplist_subset` accepts canonical `bplist00` booleans, bounded
integers, ASCII/UTF-16BE strings, arrays and sorted string-key dictionaries. It validates the
trailer, canonical offset/reference widths, exact object boundaries, reachability, duplicate
keys, cycles and resource ceilings. It imports neither `plistlib` nor the writer.

## Semantic profiles

| Artifact | Profile checks after consensus |
|---|---|
| `knowledgeC.db` | exact schema/roots; three positive rowid-backed app-in-focus rows; bounded finite intervals; exact marker |
| `TCC.db` | exact schema/roots; four typed client rows; two grants and two denials; modeled reason/type/timestamp; exact marker |
| `QuarantineEventsV2` | exact schema/roots/autoindex; five unique uppercase UUIDv4 rows; bounded Mac time and HTTPS text; exact index coverage and marker |
| `<label>.plist` | exact six keys; bounded reverse-DNS label equal to filename; one normal absolute program path; boolean `RunAtLoad`; integer interval; exact marker |

## Extension rule

Changing an emitted format requires one reviewable change that updates all of:

1. the writer's pre-allocation input bound and post-write structural assertion;
2. the independent raw reader without importing the writer or standard parser;
3. typed consensus and the named semantic profile;
4. a standard-parser-valid raw mutation and a both-parsers-valid semantic mutation;
5. focused resource, malformed-input and deterministic-byte tests;
6. scorecard denominators, known tells and release notes.

Until all six move together, the writer must reject the new feature rather than silently
leaving the oracle's supported subset.
