# Changelog

## Unreleased

### Documentation

Recorded the post-Linux consumer audit for a proposed digest-evidence graph. No unmet consumer
exists: Fixture Core already owns public payload integrity, Gate 2 owns private join truth, and
EvidenceForge's non-byte-backed logical identity belongs in its upstream scenario model. A
future external digest-alias consumer may justify an ephemeral view computed inside a held
verified fixture snapshot; resolved edges and causal claims remain out of scope.

## 0.4.0 - 2026-08-01

### Added

A bounded `linux-glibc-x86_64-loose-v1` profile adds recursive Linux loose evidence without
putting Linux into the benchmark. Each scene has five deterministic ELF64 x86-64 `ET_DYN`
files, three XDG 1.5 autostart records and one timestamped Bash history. XDG and history each
name three resident guest paths; their unique intersection identifies one subject, whose
guest path maps exactly to its served relative path and real byte-derived digests.

Gate 1 pairs LIEF with pyelftools, PyXDG with a bounded first-party desktop-entry reader, and
dissect.target with a bounded first-party Bash-history reader. Gate 3 independently binds the
ELF header/tables, exact file geometry and zero-only slack, sole nine-byte direct-exit body,
R/RX/RW file and virtual ranges, NX stack, RELRO, dynamic allowlist and marker. Gate 2 binds
each served desktop file to its parsed `Exec`, binds the complete nine-file inventory and exact
four-row history profile, and re-derives every resident name, digest and ELF-note marker. A
public Fixture Core recipe and a third
committed sample exercise all three parser pairs over the nested loose tree.

A pinned Ubuntu 24.04/x86-64 native CI lane accepts only a complete Fixture Core root, embeds
canonical/integrity/exact-reproduction verification and Gates 1 and 3, then observes a held
private snapshot byte-equal to the verified payload. Its canonical evidence binds source,
fixture, exact gate reports, CPython/parser versions, packages and pre/post native-tool bytes
for GNU `readelf`/`objdump`, `file`, `desktop-file-validate` and Bash. It validates rather than
executes: no ELF, desktop entry or history command is launched, and the Bash history
round-trip includes a positive non-execution control.

Every CI project lane now consumes the committed `uv.lock` with frozen resolution, matching
the lock digest carried by release scorecard provenance.

### Security

Linux generation never executes an ELF, invokes `ldd`, launches a desktop entry or
sources/evaluates history. Desktop `Exec` is one exact resident absolute path without
arguments, field codes or shell syntax. History accepts only strictly timestamped exact
resident paths and one quoted no-op disclosure record, rejecting operators, substitution,
interpreters, network clients and destructive verbs.

Benchmark staging now rejects known answer/evaluation basenames—`ARTIFACT_ANSWERS.json`,
`GROUND_TRUTH.json`, `JOIN_MANIFEST.json` and `fixture.json`—case-insensitively at any depth,
as well as Fixture Core's schema marker under any filename.

### Changed

Generator assurance now covers a deterministic balanced Windows/macOS/Linux population for
Gates 1–3. Gate 4 remains Windows/macOS-only and its deliberately failing reference 100%,
footprint 72.7% and chance 4.2% measurements are unchanged. Linux fixture releases remain
loose evidence rather than activation-ready filesystems: Fixture ABI v1 does not bind modes
and deterministic archives normalize artifact files to 0644. XDG records are naming evidence,
not proof of working persistence; Bash history is not proof of execution; the ELF's dynamic
loader would run before its direct-exit entry, while the main object imports or calls no libc
symbol and exposes no alternate entry surface. External loader/dependency code is out of that
main-object claim.

## 0.3.1 - 2026-08-01

### Added

Loose-file scenes now support canonical nested and dot-prefixed relative POSIX paths. One
shared scene inventory covers staging, Gates 1–3, sample documentation and committed-sample
checks; Fixture Core shares the path grammar while retaining its descriptor-bound recursive
verifier. The scene inventory rejects traversal aliases, duplicate and case-folding paths,
file/directory ancestor conflicts, links, special files, unbound empty directories and trees
outside explicit file, byte and depth limits.

### Security

Scene builders write through pinned directory descriptors and refuse linked intermediate
components. Staging captures every allowlisted source byte first, constructs and verifies a
private sibling tree, pins its inode and parent through publication, then rechecks the
published bytes. A no-replace rename prevents overwrites; failed publications owned by the
stager are removed. Gates 1 and 2 capture the source tree once through no-follow descriptors
and run pathname-only parsers against a private, frozen copy. Snapshot cleanup is likewise
descriptor-bound and never chmods through a replaced link. Gate 3 uses the same captured bytes
directly and no longer exempts a file merely because its leaf is named `JOIN_MANIFEST.json`.

### Changed

Windows and macOS artifact bytes, fixture recipes and payload-tree digests are unchanged.
The deterministic 40-scene scorecard measurements are also unchanged: 880/880 Gate 1 reads,
420/420 semantic checks, 400/400 Gate 2 joins, 200/200 binary checks, 440/440 markers, and the
same deliberately failing 72.7% Gate 4 adversarial floor.

## 0.3.0 - 2026-08-01

### Added

A controlled EvidenceForge v1.13.1 scenario now models an HTTP response written to an exact
path and the later execution of that path. Its verifier selects the pair without reading hash
fields, requires ground-truth, Zeek UID/FUID, Sysmon PID/ProcessGuid and timeline agreement,
recomputes both emitter-local SHA1 seed formulas, and binds every generated output byte to a
canonical measurement record. Transfer-only, process-only and same-basename/different-path
controls plus identity-field mutations prevent accidental pairing.

The CI job pins CPython 3.12.13 and the runtime dependency closure exported from EvidenceForge's
own committed `uv.lock`, rather than resolving transitive dependencies afresh on every run.

An upstream-ready issue draft and an opt-in content-identity RFC distinguish modeled logical
content from materialized bytes, preserve legacy output by default, keep downloader-process and
response-body roles separate, and document certificate, OCSP and byte-backed SMTP exceptions.
Two checksum-bound review patches implement the narrow plaintext-HTTP-to-process prototype and
the independent Event 1/Event 7 Description correction. They clean-apply in order to the pinned
source and pass 508 targeted plus 4,829 runnable upstream unit tests; they are not applied or
continuously tested by ArtifactForge CI and have not been proposed upstream.

### Fixed

The earlier EvidenceForge issue draft's stock cardinalities, unclosed code fence, SHA256-only
"either algorithm" reproducer, and blanket seed-string characterization are replaced by a
pinned stock measurement and the controlled positive witness. The legacy Sysmon Event 1/Event
7 Description seed-layout mismatch is tracked separately from the cross-emitter RFC.

## 0.2.0 - 2026-08-01

### Added

Gate 1 now has independent raw readers for the exact SQLite and `bplist00` subsets emitted by
the macOS profile. The SQLite reader covers canonical varints and records, schema/root-page
ownership, leaf table and index b-trees, rowid aliases, REAL affinity and primary-key index
correspondence. The binary-plist reader covers the canonical bounded scalar, array and
dictionary forms used by LaunchAgents. Both are standard-library-only and import neither the
format writer nor its standard parser.

Typed consensus is separate from semantic-profile validation. knowledgeC, TCC,
QuarantineEventsV2 and LaunchAgent profiles now fix their schemas, value types, row/key counts,
time and URL bounds, marker data, index coverage, filename/label identity and persistence
semantics. Parser-valid meaning mutations and standard-parser-valid raw-format mutations turn
the two layers red independently.

### Security

SQLite/plist parser pairs consume one bounded immutable snapshot, preventing pathname swaps
from splicing two different files into a false consensus. Standard-parser reads are bounded
before allocation; plist graph traversal rejects cycles, shared containers and logical
expansion beyond its profile budget. SQLite generation retains the exclusive inode SQLite
writes and reads that descriptor after close, so pathname replacement fails closed.

Public macOS builders now consume at most nine candidate rows before enforcing their eight-row
leaf limit, reject ambiguous bool/numeric inputs, non-finite or oversized values, duplicate
identities, non-HTTPS/control-bearing quarantine values, non-normal LaunchAgent paths and
non-profile persistence settings. LaunchAgent labels are bounded lowercase reverse-DNS
identifiers.

### Changed

Generator-assurance status is now `pass`: all classified structured formats have two parser
implementations and every declared Gate 1 semantic profile is green. Benchmark-validity
remains `fail`; closing parser gaps does not repair Gate 4's structural shortcut.

Fixture Core keeps schema/ABI v1 and valid v1 recipe payload bytes are unchanged, but
verification deliberately requires the manifest's exact generator version. A fixture or
archive created by 0.1.0 must therefore be verified with 0.1.0, or rebuilt under 0.2.0 before
0.2.0 will accept it.

## 0.1.0 - 2026-08-01

### Added

Fixture Core v1 adds a strict public-reproducible recipe and manifest contract plus
`artifactforge fixture build`, `verify`, `inspect`, `diff` and `release`. Manifests bind an
exact recursive payload inventory and regenerate the embedded recipe before verification;
release archives are deterministic USTAR and are reopened and checked before publication.
Fixture outputs are explicitly ineligible for benchmark use because their public manifests
publish content hashes and their seed is reproducible by design.

The initial named profiles are `windows-loose-v1` and `macos-14-loose-v1`. The Windows name is
deliberately version-neutral: current loose artifacts combine NT6-era paths with XP-family
SCCA v17 prefetch, so calling the fixture a Windows 10 image would overstate consistency.

### Security

Fixture JSON rejects duplicate keys, unknown properties, non-normalised text, floats, unsafe
paths, symbolic links, special files and case-fold collisions. Build and release refuse an
existing destination, stage on the destination filesystem, and atomically publish only after
reproduction or archive verification. Fixture verification pins directory descriptors against
replacement races and requires the exact installed generator version. Build syncs the complete
tree before publication; a failed post-rename parent sync reports the verified output as
published with uncertain durability. Release captures once, reproduction-checks and encodes
that same byte snapshot, writes through a held temporary descriptor, and reports post-link
durability uncertainty explicitly. Archive verification rejects even canonically rehashed
payloads that do not reproduce from the embedded recipe. Manifests and archives provide
integrity and reproducibility, not signatures or producer authentication.

## 0.0.3 - 2026-08-01

### Added

A fail-closed, machine-readable scanner-attestation format binds each observation to an exact
recursive corpus manifest, engine and rules identity, UTC timestamp, invocation, positive
control, coverage, exclusions and errors. ClamAV, XProtect YARA, community YARA and Gatekeeper
have scanner-specific success rules; missing tools, stale records, partial rule loads and
incomplete coverage are failures rather than skips. The community-YARA control is explicitly
engine-only, with selected-rule coverage proven separately. Per-file externals are populated,
transitive includes are refused unless their bytes can be manifested, and every rule match is
red—there is no unbound rule-name allowlist that can relabel a hit as merely descriptive.

A native macOS CI lane validates all committed Mach-O signatures and cdhashes with `codesign`,
all LaunchAgent property lists with `plutil`, and plain plus quarantined Gatekeeper outcomes.
Gatekeeper rejection is reported only after a signed platform positive control succeeds. Its
canonical attestation binds the complete recursive scene, clean source commit and tree, host
build, exact Apple tool bytes and build markers, and proves that source and scene stayed
unchanged throughout the run.

Release scorecards now bind their measurements to a full Git commit and tree, the exact
`pyproject.toml` and `uv.lock` bytes, and a clean worktree. Dirty scorecard output is refused by
default; the explicit non-release override records a digest over the complete tracked diff and
every untracked byte.

### Fixed

SCCA v17 prefetch filenames and headers now carry the real XP/Server 2003 path hash. The old
value stopped after the multiply-by-37 `ConvKey` intermediate and omitted both the XP
randomisation constant and prime reduction. A published XP known-answer vector and an
independent Gate 1 transcription prevent those two stages from collapsing again.

### Changed

Gate 1 now validates semantics after parsing. pefile and LIEF independently enumerate each
PE's named imports, confirm pefile/VT-normalised IMPHASH values and agree with each other; a
raw SCCA v17 verifier binds the referenced executable path to the header and on-disk filename.
Parseable mutations prove both checks turn red.

Gate 3 now parses the arm64 Mach-O entry point, executable segment and instruction sections,
requires the sole reachable body to be `mov w0,#0; ret` plus zero padding, and independently
recomputes CodeDirectory page hashes through the exact pre-signature coverage boundary.
For PE it independently pins the full DOS header/stub, binds `AddressOfEntryPoint` to the sole
executable `.text`, permits only the modeled system DLL imports and rejects every data directory
except imports. Parser-valid mutations cover redirected DOS/native entry, pre-main library
loading and Mach-O initializer-table substitution.

## 0.0.2 - 2026-08-01

### Added

The four gates, and the discipline behind them. A gate is a numbered question wired into six
places at once — a module whose docstring is the question, a CLI subcommand that exits
non-zero, a pytest file, a block in the committed `fidelity-scorecard.json`, a row in the
regression table with a direction and a tolerance, a named CI step, and a registered mutation
that must turn it red. `tests/test_gates.py` enforces those bindings mechanically, so a gate
cannot quietly become decoration. The sixth binding is the one that matters: a gate never
observed to fail proves nothing, and `tests/test_gate_mutations.py` breaks each one on purpose
— truncating a hive, appending a byte to a binary, rewriting an Amcache `FileId`, stripping a
synthetic marker, writing instructions past the `ret`, pointing a URL at a routable domain.

A real arm64 Mach-O, hand-assembled from pure stdlib on the same terms as the PE writer. It
carries a genuine `LC_SYMTAB` whose undefined external symbols yield the symhash that
threatstream/symhash and yara-x compute, and an ad-hoc code signature whose cdhash is what
`codesign -d` reports. LIEF and macholib parse it; on macOS `codesign -v` certifies it. The
signature is computed in-process because an unsigned arm64 binary is not loadable at all and
signing afterwards would rewrite the bytes — which also makes the signing identifier part of
the file's identity, so it is encoded in the content id rather than passed alongside it.

A benchmark that measures investigation. Every answer hangs off a 32-byte suite key; the
public scenario identifier is an HMAC of it, domain-separated from content seeds and from each
variable selection. Suites come in two kinds: a dev suite built with the key published in the
source, cheatable on purpose and never reportable, and a hold-out suite whose key never leaves
the evaluator. Scenes carry decoys and the signals deliberately disagree — persistence launches
one binary while Amcache's recorded hashes match a different one — and every question spans at
least two artifacts.

A companion adapter that reads an EvidenceForge run's output tree without importing
EvidenceForge, recovering which logical binary each Sysmon hash denotes. On an unmodified run
of the shipped branch-office scenario at v1.13.1: 853 of 853 Sysmon records carrying SHA256
recovered and verified, 105 distinct Sysmon logical identities, with seed forms split 78
`from_host_metadata` and 27 `with_description`. Those are Sysmon-local recovery figures; the
stock run contains no basename-matched Sysmon/Zeek pair that could prove a same-file
cross-emitter inconsistency.

A schema-checked EvidenceForge measurement record bound to the exact v1.13.1 scenario input
and a canonical inventory of all 45 output files. The CI contract derives the installed
producer version and commit from distribution metadata, generates a fresh run, byte-compares
the resulting record, and then re-hashes and re-measures the tree. The record states the
remaining boundary explicitly: serialized output does not itself encode its producer commit.

`SECURITY.md`, `docs/inert-by-construction.md`, `docs/DESIGN.md`, `docs/ROADMAP.md`, a
`LICENSE` the packaging metadata had always declared, and SPDX headers throughout.

### Fixed

libyal's `libscca` — which plaso and log2timeline are built on — rejected every prefetch file
this project had ever written. The volumes-information block was sized to end exactly at the
last counted character of the volume device path, but SCCA character counts exclude the
end-of-string character while the terminator must still lie inside the block, so the file was
short by exactly two bytes. A second defect: the directory-strings offset pointed one byte past
the end of the block while declaring a count of zero, and libscca gates that block on the
offset being non-zero rather than on the count. Nobody noticed because `windowsprefetch`, far
more permissive, was the only oracle installed.

CI had never executed a single test. The workflow installed `evidenceforge` where the upstream
distribution is `evidence-forge`, so the step exited 1 before pytest was ever reached, and with
no commits and no remote nothing surfaced it.

The seed transcription picked its formula from the Sysmon EventID; upstream picks by the shape
of the arguments it was handed and has a third form this module could not express. Recovery now
recomputes every candidate against the digest upstream emitted and raises unless exactly one
matches.

The `ContentStore` trusted any file already at a content-addressed path and wrote
non-atomically. Writes are now atomic and cache hits are re-verified, which matters now that
one store is shared across a suite and hits are real.

### Changed

Scorecard measurement now uses a separately domain-separated, deterministic public corpus and
records its complete derivation identity. It is marked non-reportable and cannot be graded as
a bare benchmark score; real hold-out suites remain freshly keyed. `scorecard --check` rejects
incompatible measurement provenance even when no tracked metric regresses. Generator assurance
and experimental benchmark validity now have separate machine-readable statuses while the
legacy aggregate verdict remains available.

`KNOWN_TELLS.md` opened by claiming CI failed if a structured format shipped undisclosed.
Nothing read it, and four of six classified formats carried no marking at all. Every classified
structured format now carries an in-band `ARTIFACTFORGE` anchor, and
`tests/test_known_tells.py` enforces the claim in both directions. Plain sidecars, including the
serialized quarantine xattr value, are outside that format-marker gate.
