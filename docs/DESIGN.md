# ArtifactForge design

ArtifactForge creates deterministic forensic fixture files and tests specific claims about
those files. It does not try to simulate a complete host.

## 1. Scope

ArtifactForge emits loose artifacts that an investigator can open directly:

- Windows PE files, registry hives, Prefetch, Chromium download history, Zone.Identifier,
  Task Scheduler XML, and Shell Links
- macOS Mach-O files, knowledgeC, TCC, QuarantineEventsV2, quarantine xattr values, and
  LaunchAgent plists
- Linux ELF files, XDG autostart entries, and timestamped Bash history

A seed and named profile determine the modeled values. A declared generator ABI and producer
profile determine the bytes. No wall clock, process identifier, or ambient random source enters
the output.

Determinism is a versioned contract, not an unlimited promise. Current Fixture ABI v2 database
bytes come from `artifactforge-owned-sqlite-leaf-v1`, so they do not depend on the host SQLite
release. Historical v1 databases came from the host SQLite library. Fixture ABI v1 does not
bind that producer, so its 0.5.0 vectors are parse-only. Any cross-runtime byte identity claim
is limited to its named ABI, producer profile, and tested runtime matrix.

## 2. Content-first identity

`ContentStore` builds each materialized binary once. Its digests and structural hashes are then
derived from those bytes. Scene composition reuses that identity when it creates Amcache,
Prefetch, browser, task, Shell Link, quarantine, and Linux path relations.

Gate 2 reopens the emitted scene and reconstructs the selected relations. Private truth is the
expected answer, not evidence that the answer is correct. The emitted bytes and their parsed
values provide that evidence.

This rule applies only to relations that claim resident content. Stale and absent decoys are
modeled as stale or absent. EvidenceForge modeled-log identities, public fixture integrity,
private scene truth, and benchmark answers also have different disclosure and evidence
boundaries. ArtifactForge therefore does not publish one catch-all evidence graph. See
[`identity-boundaries.md`](identity-boundaries.md).

## 3. Package structure

Arrows point toward imported lower layers.

![ArtifactForge package layering. Import arrows point toward lower-level dependencies; inventory is the shared bounded filesystem layer, and ingest remains outside the core chain.](assets/layering.svg)

| Package | Responsibility |
|---|---|
| `model` | Host, profile, and time types |
| `inventory` | Canonical paths, bounded no-follow capture, and exclusive publication |
| `content` | Materialized bytes and content identity |
| `artifacts` | Pure format builders |
| `compose` | Scene assembly and evaluator-private relation truth |
| `fixture` | Public recipes, manifests, verification, comparison, and release |
| `bench` | Closed-rule tasks, public exports, solvers, attacks, and attempt evidence |
| `gates`, `scorecard` | Measurement and source-bound results |
| `ingest` | Optional EvidenceForge adapter outside the core dependency chain |

ArtifactForge has no runtime dependency on EvidenceForge. Isolated CI jobs install a pinned
EvidenceForge revision for contract testing and a separate default-branch drift canary.

## 4. Fixture Core

Fixture Core turns a public recipe into a logical filesystem manifest and a private host
carrier. V2 is the current producible ABI. V1 remains readable at its frozen 0.5.0 vectors but
has no current writer.

### Recipe and manifest

A v2 recipe contains a public seed, a named platform profile, and a derived causal clock. Scene
keys, scene values, and content bytes use separate derivation domains. None reuses benchmark
key material.

The manifest records every logical directory, file, default stream, and supported auxiliary
value. It binds reversible guest and served paths, byte sizes, SHA-256 values, logical owners,
modes, timestamps, macOS xattrs, and Windows ADS values. A tree digest covers the complete
logical model.

The path grammar rejects empty components, `.` and `..`, links, special files, case aliases,
file and ancestor collisions, and orphaned directories. Count, depth, component-length, and
total-byte ceilings apply before an untrusted tree can reach a parser.

### Carrier boundary

The carrier is not the logical guest filesystem. It contains default streams under served
paths with fixed private host modes: 0700 for directories and 0600 for files. Construction does
not apply host ownership, timestamps, xattrs, or ADS values. Those values remain data in the
manifest. Incidental host metadata is outside raw-carrier verification and is not inferred to
be absent.

### Verification and assurance

Verification reports distinct results for:

1. canonical structure
2. byte and manifest integrity
3. complete reproduction from the embedded recipe
4. optional parser and inertness assurance

Inspection does not invoke a producer, so historical v1 fixtures remain inspectable. V2
reproduction uses the registered producer profile and compares every default-stream byte and
logical metadata value.

macOS assurance decodes every logical quarantine xattr with both readers before joining its
UUID to QuarantineEventsV2. Windows assurance decodes the one logical Zone.Identifier with two
readers, joins it to the matching Chromium History row, and rehashes the resident PE. It also
re-parses the task and Shell Link and rehashes their distinct resident targets. These are
serialized relations, not activation claims.

### Release

Release validates the source carrier, captures it through held no-follow descriptors, and
performs a complete second state pass after the final byte read. Output parents are traversed
and created through held descriptors. Source-directory inodes, case aliases, replacement
races, and mixed snapshots are rejected.

The archive is normalized USTAR. It contains the manifest, declared directories, and declared
default streams. It contains no host xattrs, native ADS values, PAX metadata, or producer
authentication. See [`fixture-core.md`](fixture-core.md) for the full contract.

### Benchmark separation

Fixture manifests publish their seeds and content digests, so they are always
`benchmark_eligible: false`. Benchmark evaluator roots keep keys and answers private. Public
exports contain only canonical `public.json` and the declared `scenarios/` tree.

An export is a transfer boundary, not a Python sandbox. Arbitrary solver code requires a
separate OS account, container or VM without the evaluator mount, or another machine. Local v3
attempt ledgers cannot prove that external isolation or an independent witness.

## 5. Gate discipline

A gate is complete only when all of these bindings exist:

1. a module whose first docstring line states its question
2. a CLI command with a failing exit status
3. dedicated tests
4. scorecard metrics with a registered direction and tolerance
5. a named CI step
6. a section in this design document
7. a mutation that turns the gate red

`tests/test_gates.py` checks those bindings. A missing oracle is a failure, not a skip.
Declared limitations are recorded separately and never converted into passing checks.

Every filesystem gate first captures one bounded recursive tree through held no-follow
descriptors. Path-only parsers receive a frozen private copy of that capture. Parser pairs
therefore observe the same bytes.

### Gate 1: validity

**Question:** Do the declared readers decode each classified artifact and satisfy its named
profile?

Gate 1 separates five claim levels:

1. container acceptance
2. typed semantic extraction
3. independent agreement
4. declared profile conformance
5. named downstream-consumer compatibility

Passing one level does not imply the next. Two readers accepting a file does not turn
acceptance into realism, native provenance, or whole-format support.

| Format | Readers and claim boundary |
|---|---|
| PE | pefile and LIEF agree on imports and IMPHASH semantics |
| Registry hive | regipy and libregf agree on the complete typed modeled tree; the profile also requires the Amcache and Software-persistence plugins to recognise and extract the declared records |
| Prefetch | A strict expected-size reader owns MAM framing and the v30 inner profile; pyscca and Dissect agree on typed semantics |
| Chromium History and macOS SQLite | sqlite3 is paired with an independent reader for the owned leaf profile |
| Mach-O | LIEF, macholib, and a raw symbol-table decoder agree on the typed writer profile |
| Binary plist | plistlib and an independent reader agree on the complete modeled value |
| Quarantine xattr | Two readers agree on the strict four-field representation |
| Zone.Identifier | ConfigParser and a raw reader agree on the ordered Internet-zone profile |
| Task XML | ElementTree and a UTF-16LE byte reader agree; dissect.target is a separate consumer observation |
| Shell Link | liblnk and LnkParse3 agree on a reliable typed intersection; a strict byte reader owns wire extents and termination |
| ELF | LIEF and pyelftools agree on the declared ELF profile |
| XDG desktop entry | PyXDG and a raw reader agree on the single-group profile |
| Bash history | dissect.target and a raw reader agree on timestamped single-line records |

Current Prefetch scenes use MAM algorithm-4 XPRESS-Huffman compression around SCCA v30
variant 1. The strict reader owns the declared output length, Huffman table, single-chunk
framing, inner layout, path hash, volume token, and canonical 260-character device-path limit.
`pyscca` must accept the record. `pyscca` and Dissect must agree on their typed semantic view.
Dissect is semantic-only because its EOF-driven decoder exposes the current three post-output
bytes. ArtifactForge does not run a Plaso extraction, so pyscca acceptance is not a Plaso
compatibility result.

The public `build_prefetch` and `prefetch_name_hash` functions retain the v17/XP compatibility
contract. Current scenes call `build_prefetch_v30`. The existing `windows-loose-v2` identifier
received a compatibility reset before release; earlier outputs remain bound to the source that
produced them.

Task XML passes only when it is disabled, trigger-free, principal-free, and contains one
argument-free `Exec` action. A Shell Link passes only when it names one local resident target
and has no arguments, working directory, network target, environment block, or ExtraData.
These checks validate stored files. They do not show that Windows registered or activated
them.

The first-party SQLite and binary-plist readers intentionally cover only emitted subsets. They
provide independent implementation, not outside governance or general-format validation.
`KNOWN_TELLS.md` owns the exact format limitations.

### Gate 2: identity

**Question:** Do declared answer-bearing identities and cross-artifact pivots agree with the
emitted bytes?

Gate 2 reparses values and rehashes resident bytes. Its relation classes include:

- PE content digests and import-derived hashes
- five resident Amcache `FileId` SHA-1 joins
- the exact four-file Prefetch set, decoded executable names, path hashes, and volume tokens
- one Chromium completed-download final URL, path, size, and resident PE digest
- one disabled task command and one Shell Link target, each bound to a distinct
  non-persistence PE
- five macOS quarantine xattr UUID joins to QuarantineEventsV2
- Linux XDG and Bash-history paths resolved against the recursive carrier, then rehashed

The task and Shell Link relations prove references only. The browser relation proves a modeled
download record only. None proves registration, activation, download by a native browser, or
execution.

Mutations alter resident bytes, identity values, paths, UUIDs, counts, and reference targets.
Each mutation must turn the affected relation red while leaving unrelated relations intact.

### Gate 3: inertness

**Question:** Are generated executable bytes within their inert profile, and are synthetic
formats disclosed in-band?

The Windows PE executable section is one `ret` instruction plus zero padding. The macOS
Mach-O entry contains `mov w0,#0; ret`. Each Linux ELF has a nine-byte direct `exit(0)` body.
Gate 3 also rejects alternate executable surfaces, initializers, finalizers, unexpected data
directories, executable slack, hidden load commands, and unsupported dynamic behavior.

The Linux dynamic loader executes before the entry body on a real execution attempt. External
loader and dependency code is outside the emitted-byte claim. ArtifactForge does not execute
generated files during portable validation.

Every marker-eligible classified format contains the ASCII `ARTIFACTFORGE` anchor. The strict
serialized quarantine-xattr profile is the only classified marker exemption because its real
four-field grammar has no extension field. The exemption applies only after both readers and
the exact profile pass.

Native lanes add observations without changing the portable claim. The Linux lane inspects a
verified private snapshot with `readelf`, `objdump`, `file`, `desktop-file-validate`, and a
non-executing Bash history round trip. The Windows canaries load task XML into an unregistered
in-memory definition, open a Shell Link without `Save`, `Resolve`, or `Run`, and call
`RtlDecompressBufferEx` only for the declared Prefetch output. Hosted schema-v6 runs on the
preceding source revision were diagnostic and incomplete. Hosted schema-v7 run 30944614694
recorded the first complete passing result.

### Gate 4: solvability

**Question:** Are benchmark answers closed-rule value agreements rather than shortcut
features?

Benchmark v1 is withdrawn. Its answer layout, key disclosure, co-located evaluator state, and
incorrect chance model allowed shortcut recovery without the intended artifact joins.

V2 defines two rules. Windows follows an Amcache `FileId` SHA-1 into five resident PE byte
strings. macOS follows a strict xattr UUID into five QuarantineEventsV2 rows. Each scene has
five scalar questions and a five-answer bijection, so exact candidate chance is 20%.

Gate 4 derives candidates and dependency traces from captured artifacts. It runs registered
attacks and ensembles with vulnerable-world positive controls, evaluates exact within-scene
permutation inference, and enforces the predeclared scene and power contract. Parser-valid
counterfactuals cover every unordered candidate pair. Deterministic representatives exhaust
all 120 mappings for each of the Windows FileId, macOS xattr UUID, and macOS database UUID
mechanisms.

A green result means that no member of the finite registered attack/ensemble surface crossed
its declared corrected threshold after all controls passed. It does not establish equivalence to candidate chance,
cover unregistered strategies, or create a reportable public-corpus performance score.

Every v2 suite is permanently non-reportable because callers provide its raw key. V3 adds an
internally keyed evaluator ceremony, canonical precommitment, one-shot POSIX attempt ledger,
feedback-withholding receipt, and detached retired report. The ledger owner can still read the
private result and can copy evaluator state. Detached verification checks the report chain,
not ceremony authenticity or evaluator correctness. V3 therefore remains `reportable: false`
until an independent witness attests the solver trust boundary and unique attempt procedure.

Linux is generator and Fixture Core material only. It is not part of Gate 4.

See [`benchmark-v2.md`](benchmark-v2.md) and [`benchmark-v3.md`](benchmark-v3.md).

## 6. Scorecards and external evidence

`fidelity-scorecard.json` records the gate results and their declared gaps. Each metric has a
direction and zero tolerance. Current CI creates a fresh scorecard for the checked-out source
and requires every gate to pass.

The committed root scorecard is historical v0.5 evidence. Its smaller counterfactual contract
cannot be compared with the current source contract, so CI does not relabel it as current.

A release scorecard contains a measurement-source record for the Git commit, tree, package
metadata, lock file, and dirty-state digest. It is not a signature, producer authentication,
or proof about a later tag. `--allow-dirty` creates diagnostic evidence only.

Scanner results are independent of all four gates. The latest scanner checkpoint and its exact
provenance live in [`../SECURITY.md`](../SECURITY.md). A scanner slot can be complete while the
overall record is red, and a passing gate cannot fill a missing scanner observation.
