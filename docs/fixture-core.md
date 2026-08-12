# Fixture Core v2

Fixture Core is ArtifactForge's public, reproducible loose-artifact contract. A JSON recipe
produces a canonical `fixture.json` and an exact declared `artifacts/` namespace. The manifest
binds every default stream and the complete logical guest tree, including paths, directories,
ownership, modes or attributes, timestamps, extended attributes and alternate data streams.

Fixture Core is separate from the benchmark. Its seeds and digests are public, so
`benchmark_eligible` is permanently `false`.

Fixture ABI v2 is the current producible contract. Fixture ABI v1 is frozen at the exact
ArtifactForge 0.5.0 vectors and is parse-only in current source. The parser and `inspect`
command retain v1 for historical integrity work; `build`, reproduction verification, `diff`
and `release` refuse v1 before generation because the exact v1 producer is no longer
registered. Current writers never relabel new bytes as v1.

## Lifecycle and check scopes

### Commands

```sh
artifactforge fixture build examples/fixtures/windows-loose-v2.json out/windows
artifactforge fixture build examples/fixtures/macos-14-loose-v2.json out/macos
artifactforge fixture build examples/fixtures/linux-glibc-x86_64-loose-v2.json out/linux
artifactforge fixture inspect out/windows
artifactforge fixture verify out/windows
artifactforge fixture verify out/windows --assurance
artifactforge fixture diff out/windows another/windows
artifactforge fixture release out/windows dist/windows-dropper-001.tar --assurance
```

### Check scopes

The CLI reports four checks separately:

- **inspection** parses the registered manifest ABI and checks canonical bytes, exact pathname
  inventory, required carrier modes and default-stream sizes/SHA-256 values. It does not inspect
  incidental host xattrs or ADS values, run a producer, or run assurance; reproduction and
  assurance are `not-run`. This is the supported operation for frozen v1.
- **integrity** is the same stored-record and carrier relation used by verification. For v2 it
  also requires fixed private carrier modes where the host exposes POSIX modes.
- **reproduction** invokes the registered v2 producer and compares all default-stream bytes
  and the complete logical manifest. A changed guest path, directory, owner, mode, timestamp,
  xattr or ADS remains red even if an attacker recomputes the tree digest. Package version is
  provenance rather than a byte-compatibility key; generator ABI and producer profile select
  the producer.
- **assurance** is opt-in. It runs Gates 1 and 3 over one bounded, frozen default-stream
  snapshot. It also applies these family-specific checks:

  - macOS: both Gate 1 readers, type-exact consensus and the strict quarantine profile must
    accept every logical `com.apple.quarantine` value before its UUID may join
    `QuarantineEventsV2`.
  - Windows download: a bounded `ConfigParser` adapter and an independent raw reader must agree
    on the one logical `Zone.Identifier` value and its closed Internet-zone and reserved-URL
    profile. The stream then joins the matching Chromium `History` row and binds `HostUrl`,
    `ReferrerUrl`, guest path, byte counts and content-addressed digest to re-hashed PE bytes.
  - Windows references: the extensionless Task Store definition and Start Menu Shell Link must
    pass their closed profiles, resolve to distinct non-persistence resident PEs and bind to
    re-hashed target bytes. ArtifactForge does not register the task, resolve or activate the
    shortcut, or execute either target.

  Assurance consumes declared default streams and logical manifest data. It does not prove
  that the raw carrier has no incidental host metadata. Gate 2 is not claimed because
  answer-bearing scene joins are never published. The narrower fixture relations above are
  re-derived from public artifact and manifest values.

The default zero-dependency installation supports building, inspection, exact verification,
semantic diff and release. `--assurance` requires the development parser-oracle extra
(`uv sync --extra dev` in this checkout). A missing oracle is a normal red assurance result,
not a skip or import traceback.

### Publication and comparison

`build` refuses every existing output, including a broken symlink. It generates beside the
destination, reproduction-verifies the unpublished result, syncs the complete tree and uses an
atomic no-replace rename. Failure before publication leaves no output. If the final parent
directory sync fails after the rename, exit 2 reports `published: true` with the verified
recipe and tree digests: the complete output exists, but crash durability is uncertain. There
is no `--force` switch.

`diff` reproduction-verifies both fixtures, then reports recipe/generator changes and v2
directory/file additions, removals and field-level changes, including guest mappings and named
xattr or ADS values. `release` verifies first, including the v2 source root, manifest, payload,
nested-directory and file carrier modes; a mismatch is rejected rather than normalized away.
Before creating any missing output parent, it resolves the prospective parent, including
existing symlink ancestors, for a non-mutating early check. It then traverses and creates each
parent component relative to held no-follow descriptors and rejects every captured
source-directory inode. This covers case-insensitive fixture aliases and output-ancestor swaps
without creating a child inside the source; publication stays bound to the held parent
descriptor. It then emits the unique canonical uncompressed USTAR representation from one
descriptor-pinned payload snapshot. Standalone archive verification checks the archive
encoding and independently reproduces the embedded recipe.

### Exit codes

Exit code 0 means success (or identical inputs for `diff`); 1 means a meaningful negative
result such as integrity, reproduction or assurance failure, or differing fixtures; 2 means
malformed input, unavailable producer, unsupported ABI, unsafe filesystem state, I/O failure
or an existing destination. Post-publication durability uncertainty also exits 2, with the
published result described explicitly.

## ABI, canonical JSON and producer identity

### Canonical JSON and schemas

The current schemas are `artifactforge-fixture-spec-v2` and
`artifactforge-fixture-manifest-v2`. Their published JSON Schemas declare Draft 2020-12, are
checked as valid Draft 2020-12 schemas, and are tested against every shipped v2 recipe and
freshly generated family manifest. They are structural companions, not the wire authority.
The strict loader and authoritative Python model additionally reject duplicate JSON keys,
non-normalised text, floats and unsafe paths. As the schemas' `$comment` fields record,
canonicalization, digest equations, cross-field relations and uniqueness by xattr/ADS name
remain authoritative model checks. ArtifactForge writes UTF-8, sorted-key, compact, no-NaN
JSON with exactly one trailing line feed. V2 retains the canonical-JSON v1 algorithm but has
distinct spec, manifest, tree, recipe-digest, generator ABI and producer-profile identities;
sharing canonical JSON is not an ABI fallback.

### Producer identity

`generator.version` records the producing ArtifactForge package version, bounded to 128
printable ASCII bytes. It is provenance, not the v2 compatibility decision. Reproduction
requires `artifactforge-fixture-generator-v2` together with
`artifactforge-fixture-producer-v2`; it compares the complete reproducible manifest while
excluding only the informational package-version field. By contrast, historical v1 required
an exact package version and its GeneratorIdentity v1 does not bind that release of the SQLite
producer. V1 therefore remains inspectable but is intentionally not reproduced by current
source; current cross-runtime guarantees apply only to the v2 ABI/profile and tested matrix.

### What the recipe controls

A v2 recipe controls five things and nothing else: `family`, `story`, `profile.hostname`,
`profile.username` and `seed_hex`. `fixture_id` is a label, and `causal_clock` is not an input
at all — the build re-derives it from the seed and the canonical recipe context and rejects any
other anchor. `profile.id` is fixed per family.

`story` names the incident shape. It is a closed enumeration, because an open one would let a
recipe ask for a scene no gate has ever been observed to reject. Each story owns a registered
scene builder, its own logical assurance expectations, and mutations that turn those
expectations red:

| Story | Shape |
|---|---|
| `windows-dropper-v1` | Download, execution, persistence and reference surfaces: 5 PEs, Amcache, SOFTWARE Run key, Prefetch, Chromium `History`, `Zone.Identifier`, Task XML, Shell Link |
| `windows-download-only-v1` | Arrival without execution: 3 PEs, Chromium `History` and one `Zone.Identifier`; Amcache, Run key, Prefetch, Task XML and Shell Link are absent, and that absence is asserted |
| `macos-quarantined-app-v1` | Quarantined download: Mach-O binaries, quarantine xattrs, QuarantineEventsV2, TCC, knowledgeC, LaunchAgents |
| `linux-autostart-v1` | Autostart and shell history: 5 ELF files, 3 XDG autostart entries, one timestamped Bash history |

Story shape is *not* a per-artifact choice. A recipe cannot ask for "these files"; it selects
one registered story, and the story decides its inventory. Within a story, the seed chooses
names, paths, counts drawn from fixed pools, and every derived value — never which artifact
kinds appear.

`windows-download-only-v1` is the case where absence carries the claim. A short inventory is
not evidence that nothing ran: it is equally consistent with a builder that failed to write
one. The scene therefore declares the exact surfaces it withholds, and projection refuses the
build if that declaration is wrong, if the scene carries execution truth, or if any withheld
artifact is served anyway. Its logical assurance then checks each withheld surface by its own
exact guest path and reports it in its own failure. No artifact in that story carries the
execution instant, because a last-access stamped at execution would assert the event the story
withholds: every emitted stamp must be one of the two arrival instants, and the History's own
download rows must record no opened download and no withheld instant.

Stories are a fixture concept. The benchmark keeps calling the scene builders directly: its
scenario shape is frozen at five questions per scene, so a story that changed that shape would
have to re-enter Gate 4's registered attack surface before it could mean anything.

### Derivation domains

The recipe carries a public 256-bit seed and a causal clock. Fixture v2 uses independent,
named derivation boundaries:

- scene key: `artifactforge/fixture/scene-key/v2`;
- scene values: `artifactforge/fixture/scene-value/v2`;
- content derivation: `artifactforge/fixture/content-derivation/v2`;
- content store: `artifactforge::fixture/v2`.

Benchmark compatibility remains under `artifactforge/bench/v1`; it does not silently supply
fixture choices or bytes. The fixture seed is public by design: fixtures are QA assets, not
hold-outs.

## Logical guest tree and carrier boundary

### Path model

Every v2 directory and regular file is explicit and sorted by served path. Every non-root
parent must be declared, every declared directory must lead to a file, and file/directory,
ancestor, case-folding and guest-path aliases are rejected. The tree digest covers the family,
guest and served paths, all directory and file metadata, default-stream size and SHA-256, and
the complete names, base64 bytes, sizes and SHA-256 values of xattrs and ADS values.

Guest paths map reversibly into a portable relative carrier namespace:

| Family | Guest path | Served path |
|---|---|---|
| Windows | `C:\Windows\Prefetch\TOOL.EXE-12345678.pf` | `C/Windows/Prefetch/TOOL.EXE-12345678.pf` |
| macOS | `/Users/v/Library/LaunchAgents/example.plist` | `Users/v/Library/LaunchAgents/example.plist` |
| Linux | `/home/v/.local/bin/tool` | `home/v/.local/bin/tool` |

Windows requires one uppercase drive and canonical backslash components; POSIX guests require
one leading slash. Neither direction normalises or guesses. Served paths are printable ASCII,
POSIX-relative and USTAR-representable under the final `<fixture-id>/artifacts/` prefix.

The current projection routes artifacts without basename inference:

- Windows maps SOFTWARE to `C:\Windows\System32\config\SOFTWARE`, Amcache to
  `C:\Windows\AppCompat\Programs\Amcache.hve`, prefetch records beneath
  `C:\Windows\Prefetch\`, Chromium History to
  `C:\Users\<user>\AppData\Local\Chromium\User Data\Default\History`, the task definition to
  `C:\Windows\System32\Tasks\ArtifactForge\<task-name>`, the Shell Link to
  `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\<link-name>`, and
  each PE to the exact modeled resident path already bound by the scene (Windows, System32,
  Program Files or the modeled user's local Temp directory).
- macOS maps knowledgeC to `/private/var/db/CoreDuet/Knowledge/knowledgeC.db`, TCC to
  `/Users/<user>/Library/Application Support/com.apple.TCC/TCC.db`, quarantine events to
  `/Users/<user>/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`, plists to
  `/Users/<user>/Library/LaunchAgents/<label>.plist`, and each binary to
  `/Users/<user>/Library/Application Support/<bundle>/<bundle-final-component>`.
- Linux preserves the scene's exact `/home/<user>/.local/bin/`,
  `/home/<user>/.config/autostart/` and `/home/<user>/.bash_history` guest paths.

Each becomes the served spelling by the single reversible rule in the table above.

### Logical metadata

The three closed metadata records are:

- Linux: mode, uid/gid and nanosecond atime/mtime/ctime;
- macOS: the Linux fields plus birth time and named xattrs;
- Windows: owner SID, a closed file-attribute set, creation/access/write/change times and
  case-insensitively unique named alternate streams.

Logical modes are integers from 0 through 07777, uid/gid values from 0 through 2^31−1, and
Unix-nanosecond fields from 0 through 2^63−1. Windows SIDs use canonical revision-1 decimal
grammar and are at most 184 ASCII bytes. The authority is at most 15 decimal digits and below
2^48; there are one to 15 subauthorities, each at most 10 decimal digits and below 2^32. The
supported attribute names are a closed allowlist and `NORMAL` cannot be combined with another
flag.

Current projection identities are deliberately bounded rather than host-complete: Linux
uid/gid 1000/1000, macOS uid/gid 501/20 and Windows `S-1-5-18`. These are logical facts, not
ACLs, security descriptors or proof of a complete host. Mac quarantine sidecar bytes from the
scene builder become a `com.apple.quarantine` manifest xattr on the corresponding binary;
exactly one browser-downloaded resident Windows PE receives a logical `Zone.Identifier`
stream. The other four resident PEs receive no such claim. No colon-named carrier files or
`.quarantine.xattr` carrier sidecars remain in a v2 fixture.

### Host carrier

ArtifactForge intentionally does not project logical metadata onto the development host. It
does not call `setxattr`, `chown` or `utime`, create host ADS values, or apply logical
executable modes. Publication uses a fixed private carrier: fixture and payload directories
are 0700, while `fixture.json` and every default-stream file are 0600, independent of umask.
Those carrier modes are transport controls, not guest facts. Filesystems, provenance tooling
or a hostile actor can still attach incidental host xattrs or ADS values. Raw-directory
integrity and assurance do not inventory or assert the absence or inertness of that
out-of-contract inode metadata. A downstream materialiser may use the manifest to construct a
guest filesystem, but that activation step is outside this contract.

## Causal clock

`artifactforge-causal-clock-v1` derives one whole-second Unix-nanosecond anchor from the seed
and an answer-free canonical context containing fixture id, family and profile. A supplied
anchor must equal that derivation. Family timelines then enforce these strict orders before
bytes are emitted:

- Windows: host initialised < download completed/file created < Run key configured < executed
  < prefetch updated < Amcache observed;
- macOS: host initialised < downloaded < installed < TCC decision < LaunchAgent written <
  knowledge interval start < knowledge envelope end;
- Linux: host initialised < installed < autostart written < marker history < subject history <
  two later history records.

Registry and prefetch FILETIMEs, Unix seconds, Apple-epoch seconds, quarantine hexadecimal
seconds and logical nanoseconds are all exact integer conversions. KnowledgeC uses bounded,
non-overlapping 120-second intervals spaced 180 seconds apart. Gate 1 checks the embedded
family-specific chronology; full reproduction also binds every logical timestamp. The task
definition-written and Shell-Link-reference-written roles use the Windows configuration time;
the link header's creation/write FILETIMEs use file creation and its access FILETIME uses the
modeled execution time. These are metadata relations, not evidence that the link itself was
followed or that its target ran because of it.

## Owned SQLite profile

The Windows Chromium History query surface and the three macOS databases are emitted by
ArtifactForge's filesystem-free deterministic writer, not by the host `sqlite3` library. The
closed wire identity is
`artifactforge-owned-sqlite-leaf-v1`: 4096-byte UTF-8 rollback-mode databases, schema format 4,
one leaf root per declared table or implicit text-primary-key index, canonical varints and no
freelist, pointer-map, interior, overflow, fragmented or WAL state. Header offset 96 is zero,
which records that no SQLite library wrote the file. Producer provenance comes from the
fixture producer profile, not that field.

The writer accepts 1..16 tables, 1..64 columns per table, at most 1,024 rows per table, at most
16,384 scalar values, 32 KiB of aggregate UTF-8 text and 32 KiB of aggregate BLOB bytes.
Identifiers are at most 128 ASCII characters; one TEXT input is at most 4,061 characters and
one exact-bytes BLOB at most 2,048 bytes, and either must still fit its leaf payload. BLOB
primary keys remain outside the profile. Capacity is proved while constructing each page and
fails closed instead of growing into an unsupported b-tree shape.

Gate 1 deserializes the same bounded bytes with the runtime SQLite library, runs
`PRAGMA integrity_check`, and compares its exact typed schema/rows/indexes with the independent
raw reader under the declared owned wire profile. The runtime SQLite version is an oracle
environment fact; it no longer affects emitted v2 SQLite bytes. See
[`macos-oracles.md`](macos-oracles.md).

## Resource bounds and canonical USTAR

### Input ceilings

All Fixture Core ingress first applies the shared hostile-input ceiling: a spec or manifest is
at most 4 MiB and 32 JSON container levels; a regular file is at most 64 MiB; observed trees
are at most 4,096 files, 8,192 members, 32 components and 256 MiB of default-stream bytes. The
derived generic uncompressed-USTAR preflight ceiling is 278,927,871 bytes. Reads are bounded
before retention; declared sizes are never allocation authority.

V2 tightens the logical manifest further: at most 256 files, 512 explicit directories and 768
total nodes; served paths are at most 240 ASCII bytes and 32 segments, guest paths at most
1,024 ASCII bytes; each node has at most 16 metadata blobs (12,288 across the maximum tree);
each blob is at most 64 KiB; blob names are at most 255 ASCII bytes; aggregate metadata blob
bytes are at most 1 MiB; and regular default-stream bytes plus metadata blob bytes are at most
64 MiB. The manifest publishes six redundant, derived counters: `directory_count`,
`file_count`, `regular_file_bytes`,
`metadata_blob_count`, `metadata_blob_bytes` and `total_bound_bytes`.

### Archive profile

Raw archive preflight rejects PAX/GNU extensions, links and all non-regular/non-directory
types before `tarfile` sees the input. Canonical release order is lexical and includes explicit
v2 directories. USTAR metadata is always directory 0755 or file 0644, uid/gid 0/0, empty
owner/group names and mtime 0. Logical guest metadata remains inside `fixture.json`, so changing
it changes the manifest and archive bytes without changing `TarInfo` metadata. The archive
contains only `fixture.json`, declared directories and declared default streams; host xattrs,
ADS values and PAX metadata are not encoded. Release rejects required-mode mismatches before
normalization, so an invalid v2 source carrier cannot produce a valid archive.

### Snapshot boundary

After the final byte is read, archive capture performs a full recursive second state pass
through the held directory descriptors. It re-lists every directory and rechecks the complete
observed name and file/directory identity set. This rejects ordinary replacement, growth,
truncation and cross-file rolling mixed snapshots.

It also rejects bytes restored before the second pass, because rewriting them moves ctime and
an unprivileged writer cannot reset ctime the way it can reset mtime. That rejection holds
only where the host filesystem's file-time granularity is finer than the capture window. On a
coarse-granularity filesystem — HFS+, ext3, FAT, or a kernel with jiffy-granularity timestamps
— a same-size in-place rewrite leaves the entire identity tuple unchanged, and the restore is
invisible to the second pass. `artifactforge scorecard` probes the host for this with
`inventory.measure_change_visibility` and records an honest gap instead of a pass where the
capability is absent, so the verdict describes the host it actually ran on.

Capture does not claim a mathematically atomic multi-file instant against a privileged actor
continuously replaying filesystem states; that requires a filesystem-native snapshot or
immutable source.

## Current fidelity profiles

### Windows

`windows-loose-v2` remains a loose-artifact profile, not a Windows disk image or evidence that
Windows created a coherent host capture. Its current exact default-stream inventory is 14
files. Current generation uses deterministic MAM algorithm-4 compressed Prefetch v30 variant
1 with a Vista path hash, exactly one metric and volume, and one creation-time/serial volume
token shared by the recorded executable, marker and volume entry. Assurance gives exact
compressed framing and inner layout to the expected-size reader, requires `pyscca` acceptance,
and requires `pyscca` and Dissect to agree on their typed semantic view. Dissect is
semantic-only because its EOF-driven decompressor can expose fewer or more bytes than MAM
declares.

This is an explicit compatibility reset of the still-unreleased `windows-loose-v2` profile,
not a rename. Earlier v2 output used v17/XP Prefetch and remains bound to the older source that
created it; regenerate it rather than treating it as current-profile output. The released
Fixture ABI v1 vectors and the byte-stable public `build_prefetch`/`prefetch_name_hash` v17/XP
compatibility APIs are unchanged. Current scene generation selects `build_prefetch_v30`
explicitly. The native `RtlDecompressBufferEx` observation was completed by hosted run 30944614694 and does
not claim post-size tail consumption.

The profile's Chromium `History` is a bounded completed-download responder-
query surface, not a full, native or migratable browser database. All three completed rows
retain Chromium's empty `hash` BLOB and use explicitly synthetic content-addressed reserved
final URLs; Gate 1 checks only that digest syntax. Exactly one row names a resident PE. That PE
alone receives logical `Zone.Identifier` bytes with exact CRLF framing and `ZoneId=3`;
`ReferrerUrl` is the marked browser referrer and the distinct `HostUrl` is the History final
URL. Assurance parses both structures and re-hashes the PE while binding path and size. It does
not prove an ADS existed on NTFS, Chromium wrote or migrated the database, or Attachment
Manager processed the file. One extensionless Task Store XML definition is disabled,
trigger-free and argument-free; one Start Menu Shell Link has only a local-file reference
surface. Assurance parses both and binds their distinct non-persistence targets to resident
bytes, but does not register the task, activate the link or execute a target.

### macOS

`macos-14-loose-v2` emits an exact 16-file inventory of arm64 Mach-O binaries, owned-profile
knowledgeC/TCC/quarantine databases and LaunchAgent plists. The v2 knowledgeC identity profile
derives unique canonical UUIDv4 values from the fixture content domain and binds each
structured-metadata hash to its UUID and bundle. Quarantine xattrs are logical manifest
metadata; assurance requires both Gate 1 readers, type-exact consensus and the strict profile
to pass before their UUIDs may join the quarantine database exactly. This is still a reduced
named query profile, not a complete macOS installation or Gatekeeper observation.

### Linux

`linux-glibc-x86_64-loose-v2` emits five minimal ELF64 x86-64 `ET_DYN` files, three XDG 1.5
autostart entries and one extended Bash history beneath exact guest paths. Logical ELF modes
are 0755, desktop records 0644 and history 0600, while the carrier remains non-executable.
Parser acceptance and metadata consistency do not prove that a desktop session launched a
file or that a command ran.

On Ubuntu/x86-64, `scripts/attest_linux_native.py --fixture <root> --out <new.json>` adds
native observations after Fixture Core integrity, reproduction and assurance checks. It never
executes an ELF, invokes `ldd`, launches XDG content or evaluates history.

## Integrity is not authenticity

The manifest and archive detect changes and reproduce the declared logical fixture. They are
not signatures and do not authenticate their creator. Release provenance remains a separate,
source-bound concern; a self-reported digest is not an identity claim.
