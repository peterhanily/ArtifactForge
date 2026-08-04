# macOS raw-oracle and semantic-profile contract

Gate 1 treats container readability and artifact meaning as different claims. A SQLite file or
binary plist passes only when both parser implementations accept the same bounded byte
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

### Writer and bounds

Current macOS databases are written by ArtifactForge's own deterministic page encoder. It
uses no filesystem, temporary database or host SQLite API, so the same schema and rows do not
inherit the runtime library's release number. Its closed wire identity is
`artifactforge-owned-sqlite-leaf-v1`. Header offset 96 is zero because no SQLite library wrote
the bytes. The fixture generator's producer profile supplies provenance; the zero header field
alone never identifies a producer.

The writer accepts 1..16 rowid tables, 1..64 columns per table, at most 1,024 rows per table,
16,384 aggregate scalar values and 32 KiB of aggregate UTF-8 text. One identifier is at most
128 characters, one text value must fit its leaf payload, and each complete table or implicit
text-primary-key index must fit one root leaf page. It fails before emitting an interior or
overflow page.

### Raw reader and consensus

`artifactforge.gates.oracles.sqlite_subset` has two explicit parse profiles: the historical
runtime-written leaf subset and `artifactforge-owned-sqlite-leaf-v1`. Current declared macOS
artifacts must conform to the owned profile. Both are deliberately limited to:

- 4096-byte pages, UTF-8, rollback journal mode and schema format 4;
- complete schema ownership of every non-header page;
- table-leaf and index-leaf roots with canonical varints and record serial types;
- no freelist, pointer map, auto-vacuum, interior page, overflow or fragmented content;
- exact cell/freeblock tiling, strict rowid and index-key order;
- INTEGER PRIMARY KEY rowid recovery, REAL affinity normalization, and exact primary-key
  index-to-table correspondence.

The raw observation and `sqlite3` observation must agree on schema rowids, object type/name,
owner, root page, SQL text, column metadata, every typed table row in order, and every logical
index entry. The runtime reader deserializes the exact snapshot and runs
`PRAGMA integrity_check`; its SQLite version is oracle-environment provenance, not an emitted
byte input. This is not a general SQLite reader.

### Named consumer query

The named consumer profile is also bounded. `macos-11-14-consumer-v1` executes the selected
column and join shapes of APOLLO's macOS 11–14 app-in-focus query and mac_apt's macOS 11+ TCC
query, returns the intended modeled rows, and applies Gate 1 join/value checks. It is not a
captured or complete knowledgeC/TCC schema, proof of OS-version fidelity, or a promise about
other plugin/query revisions; unmodeled CoreData fields, code-signing blobs and policy tables
remain absent.

## Binary-plist subset

`artifactforge.gates.oracles.bplist_subset` accepts canonical `bplist00` booleans, bounded
integers, ASCII/UTF-16BE strings, arrays and sorted string-key dictionaries. It validates the
trailer, canonical offset/reference widths, exact object boundaries, reachability, duplicate
keys, cycles and resource ceilings. It imports neither `plistlib` nor the writer.

## Semantic profiles

After reader consensus, each artifact must pass its named profile:

- `knowledgeC.db`: exact schema and roots; three positive rowid-backed app-in-focus rows;
  bounded, finite and non-overlapping intervals; one internally consistent UUID identity
  profile; metadata hashes bound to bundle identity; exact marker.
- `TCC.db`: exact schema and roots; four typed client rows; two grants and two denials; modeled
  reason, type and timestamp; exact marker.
- `QuarantineEventsV2`: exact schema, roots and autoindex; five unique uppercase UUIDv4 rows;
  bounded Mac time and HTTPS text; exact index coverage; exact marker.
- `<label>.plist`: exactly six keys; bounded reverse-DNS label equal to its filename; one normal
  absolute program path; boolean `RunAtLoad`; integer interval; exact marker.

Fixture v2 uses a fixture-content-derived knowledgeC identity seed. Its UUIDs are unique,
canonical RFC 4122 v4 values and each structured-metadata hash binds UUID plus bundle. The
historical rowid-shaped UUID/hash profile remains readable for frozen bytes, but a database
that mixes profiles is red.

Quarantine sidecars are a scene representation. Fixture v2 consumes them into logical
`com.apple.quarantine` manifest xattrs without setting host metadata. `fixture verify
--assurance` materializes those inline bytes only in its private assurance workspace, submits
each value to both Gate 1 readers, and requires type-exact consensus plus the strict profile.
Only then does it require their complete UUID set to equal the `QuarantineEventsV2` identifier
set. That is a bounded cross-record consistency assertion, not a Gatekeeper or LaunchServices
observation.
Incidental host xattrs or ADS on the raw carrier are not inventoried by this assurance path;
their absence and inertness are outside the claim.

## Extension rule

Changing an emitted format requires one reviewable change that updates all of:

1. the writer's pre-allocation input bound and post-write structural assertion;
2. the independent raw reader without importing the writer or standard parser;
3. typed consensus and the named semantic profile;
4. a standard-parser-valid raw mutation and a both-parsers-valid semantic mutation;
5. focused resource, malformed-input and deterministic-byte tests;
6. scorecard denominators, known tells and release notes.

The writer must reject a new feature until all six changes are present.
