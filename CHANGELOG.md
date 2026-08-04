# Changelog

## Unreleased

### Added

Benchmark v3 introduces an evaluator-created local freshness ceremony with an internally
minted CSPRNG suite key and ceremony identifier. Its exact public origin/reportability block
and domain-separated key commitment are bound into `suite_id`; the matching canonical private
record is retained evaluator-side. `artifactforge bench ceremony create` exposes no raw-key or
caller-origin parameter and never prints key material.
The bound v3 protocol identity requires an even 120–200 scenarios, giving at least 60 scenes
per family under the alternating schedule. Its `population_power_contract` serializes the
exact theoretical 39-comparison calculation, both named alternatives and their rational
60-scene powers; construction does not execute Gate 4 or create per-suite attack evidence.
The ceremony CLI defaults to 120 without changing legacy v2 limits.

V3 submissions now use canonical scenario-ordered JSONL plus a precommitment binding the exact
reveal, suite and caller-asserted solver provenance. A designated POSIX attempt ledger accepts
that precommit, claims before reveal access, and serializes consume/retire transitions. Its
private result is plaintext to the ledger owner; a random blinding nonce withholds detail from
the returned receipt until local-ledger retirement, when a self-bound evidence bundle opens it.
The detached verifier checks only internally decidable schema/arithmetic/hash-chain properties
and can bind supplied reveal bytes; it does not authenticate the ceremony or regrade against an
evaluator. Every retired report remains explicitly not reportable pending an independent
witness.

The counterfactual gate now exercises all ten pair swaps per scene and all 120 parser-valid
mapping worlds on one deterministic representative for each of the three mutable identity
mechanisms. Exact sparse-signal power and the four-key leave-one-out feature-conditioned audit
are published qualifications without changing frozen-v2 multiplicity.

Phase 5 adds a conservative CPython 3.14 core lane that binds the real interpreter, builds and
installs the zero-runtime-dependency wheel without dependencies, compiles it, and builds and
verifies all three Fixture ABI v2 families. The full parser-oracle profile remains explicitly
known-blocked by the reproduced `dissect-target==3.25.1` runtime-import failure and the absence
of a reviewed CPython 3.14 binary distribution for `yara-python==4.5.4`.

Windows scenes now include an owned-SQLite Chromium completed-download query surface with the
bounded `downloads` and `downloads_url_chains` tables and a responder-facing join. The three
completed rows preserve Chromium's empty `hash` BLOB and carry their modeled SHA-256 values in
explicitly synthetic content-addressed reserved final URLs. Exactly one row names a resident
PE. Gate 1 requires dual-reader typed consensus, the exact reduced profile and syntactically
valid digest components; Gate 2 independently re-hashes the resident bytes and binds path and
size. The artifact is explicitly not a full, native or Chromium-migratable History database.

Fixture ABI v2 now gives exactly that downloaded PE, rather than every resident PE, one logical
`Zone.Identifier` stream. Its `ReferrerUrl` is the marked browser referrer and its distinct
`HostUrl` is the History final URL. Assurance pairs the `ConfigParser` and raw readers, then
independently joins History, the logical stream, guest path, byte counts, manifest digest and
re-hashed PE bytes. No native ADS is created or claimed.

Phase 6B adds one disabled, trigger-free Task Scheduler 1.2/1.3 XML definition and one
standalone local-file Shell Link to every Windows scene. The task is canonical UTF-16LE,
contains exactly one argument-free `Exec` action and is validated through type-exact
ElementTree/raw-reader consensus plus a separately reported dissect.target consumer. The link
is a bounded fixed-volume local-file profile with no arguments, working directory, network
target or ExtraData. Exact-pinned liblnk and LnkParse3 agree on their reliable typed
intersection while a strict first-party reader owns exact offsets, suffix extents, terminal
position and trailing-data rejection. LnkParse3 1.6.0's defective Unicode common-suffix
accessor is excluded from consensus rather than accommodated in emitted bytes.

Gate 2 and Fixture Core bind both parsed references to distinct non-persistence resident PEs,
including target size and SHA-256; the Shell Link additionally binds its three FILETIMEs and
volume serial. The task projects to an extensionless Task Store guest path and the link to the
modeled user's Start Menu. These are configuration/reference relations, not activation or
execution claims. Current source therefore emits 14 artifact files per Windows scene and 16
per macOS scene, for a maximum 3,001-file public export at 200 alternating scenarios including
`public.json`. Historical release and scorecard counts are unchanged.

Phase 6C switches current generated Windows scenes to deterministic MAM algorithm-4 compressed
Prefetch v30 variant 1. The record carries a Vista path hash, one metric and one volume; its
recorded executable, marker and device strings share a volume token derived from the exact
volume-creation FILETIME and explicit nonzero serial. A bounded expected-size reader owns the
closed XPRESS-Huffman and v30 wire profile, `pyscca` must accept it, and `pyscca` plus Dissect
must agree on their typed semantic view. Dissect is semantic-only because its EOF-driven
decompression can expose fewer or more bytes than MAM declares. The Windows-native
`RtlDecompressBufferEx` canary and corruption control are implemented, but remain conditional
until a hosted Windows run succeeds; they make no claim about consuming or rejecting bits
after the declared output size.

Gate 2 now counts captured `.pf` files, decodes each executable name from its bytes, and
requires the exact scene-declared artifact count and name set before evaluating the persisted
and orphan execution joins. Deleting or substituting a non-pivot Prefetch record therefore
turns the gate red.

The public `build_prefetch` and `prefetch_name_hash` APIs remain byte-stable v17/XP
compatibility surfaces, while current scene generation calls `build_prefetch_v30` explicitly.
Because `windows-loose-v2` is still unreleased, this is a deliberate in-place compatibility
reset rather than a profile rename: earlier v2 outputs remain source-bound and must be
regenerated with current source.

A closed local release-evidence command now binds two inode-distinct byte-identical wheel/sdist
builds, exact raw archive profiles, the current-source-to-sdist-to-wheel byte/mode/metadata
chain, deterministic normalized runtime/development CycloneDX 1.5 documents, checksums and an
exact no-replace output inventory. A separate validator accepts the complete official
CycloneDX schema closure only at one immutable upstream commit and three reviewed SHA-256
digests. A fixed publish rehearsal snapshots uv and the exact subjects, drops ambient
credentials/configuration, and exercises only a loopback dry run.

CI now pins third-party actions by immutable commit, bootstraps uv 0.11.17 from exact hosted-
platform wheel hashes, fixes runner generations and configures Dependabot to propose action
updates for review.
The separate manual exact-tag `release-evidence` workflow can produce GitHub/Sigstore
provenance and SBOM attestations after repository protection and explicit approval; it contains
no tag push, GitHub release or package-publication step. The settled-tree local runtime chain
passed hostile-environment byte comparison, source-pre/post-guarded evidence creation,
closed/offline and repository-refreshed verification, official validation of all three SBOMs,
the real private-copy uv loopback, and exact no-dependency wheel install/version/compile. Its
dirty-source override makes it source-bound non-release evidence. The first protected hosted
attestation remains pending for the current source revision.

### Changed

The public documentation now has one clear entry point and one source of truth for each claim.
The root README starts with installation and fixture verification, uses compact platform and
gate tables, and links to a new documentation index for the detailed contracts. The design and
roadmap no longer repeat benchmark, scanner, and release histories that belong elsewhere.
Two accessible, repository-native SVG diagrams replace the old ASCII sketch and add a concise
generation and assurance overview without raster images, filters, or blur effects.

Generated sample documentation now uses compact reader-result tables and shared profile notes.
It correctly describes Fixture ABI v2 logical modes, macOS records as modeled evidence, and
Task/Shell-Link records as references rather than activation. The EvidenceForge review drafts
and all active technical guides received the same claim-boundary and plain-language pass.

### Fixed

Windows-native observations now use PowerShell's argument-aware `-CommandWithArgs` boundary
whenever a target path is supplied. The previous `-Command` invocation treated the target as
additional PowerShell source, so a valid filename containing an apostrophe failed before the
native Prefetch canary ran. The hosted contract keeps the hostile literal-path control and now
asserts the exact argument transport through a named parameter and `--` separator. The
attestor rejects PowerShell older than 7.5 before its first target-bearing observation and
requires its signed-tool version record to agree with `$PSVersionTable`. This evidence change
advances the Windows native report from schema v4 to v5.

Release evidence now includes the exact liblnk and LnkParse3 oracle requirements already
declared by the project and lock. A repository-backed regression test checks the real
`pyproject.toml` and `uv.lock`, closing the self-consistent synthetic-fixture gap that allowed
the stale 14-requirement contract to pass unit tests.

The CI sample baseline now lives under `RUNNER_TEMP`, outside the checkout. A clean-worktree
preflight runs immediately before Gate 4, so sample regeneration cannot make a valid
source-bound scorecard fail because of its own comparison copy.

The generation overview now places each numbered step badge above its title. The badges and
labels remain separate when GitHub scales the SVG, with no raster layer, filter, shadow, or
blur effect.

The Windows-native bounded reader now compares file times only between observation APIs that
give them the same meaning. On CPython 3.12 and newer, Windows path stats expose creation time
as `st_ctime` while handle stats expose change time there. Comparing those values after an
alternate stream update produced a false race failure. Path and handle observations still bind
file ID, size, modification time and creation time. Same-API ctime comparisons remain in place
without treating ctime as cross-API comparable. Python 3.11 supplies creation time through
`st_ctime`; Python 3.12 and newer use the explicit birth-time field. Missing or zero creation
times, unavailable file identity, and unavailable reparse metadata are rejected. Directory
capture also binds reliable cached-entry fields to a fresh, nonzero path identity instead of
trusting the zero device and inode values returned by `DirEntry.stat()` on Windows.

The path-to-handle comparison now lives in the shared filesystem inventory layer. Detached
Benchmark v3 report verification, Fixture Core path ingress and the publish rehearsal use the
same rule, closing three additional Windows-capable readers that made the same invalid ctime
comparison. Each caller still owns its regular-file, link, reparse, size, exact-length and
same-domain mutation checks.

### Security

Benchmark v2 is frozen as permanently non-reportable, including suites carrying its historical
`holdout` label. V3 ceremony publication is private-mode, no-replace and no-follow; it rejects
pre-existing destinations, symlink/special-file ceremony state, unknown or mutated model
fields, commitment/ID mismatches, same-byte inode replacement, hostile-`umask` mode drift and
concurrent reuse. Its in-band wording is local self-attestation eligible only pending external
evidence; it does not externally attest unique ledger designation, evaluator independence or
solver isolation.

Attempt records are complete-before-publication, no-replace, single-link private files. A
crash-released lock prevents consume/retire races; torn stages recover without replaying a
published claim; inode ancestry rejects evaluator/output containment through case aliases or
parent moves; and semantic chain validation rejects self-rehashed invented states, outcomes,
counts, nonces, notices or trust claims. Live ledger mutation fails closed outside POSIX because
Python does not provide the required directory-descriptor contract on Windows; detached report
verification remains cross-platform.

Release evidence is deliberately classified as unsigned local self-attestation: its digests do
not authenticate a producer or build host, and the command reports signing, package publishing
and reportable-security-result fields as false. Repository-bound SBOM refresh uses uv's locked,
offline, no-source path but cannot prove host-wide network inactivity. Evidence publication's
descriptor/no-replace/durability contract is POSIX-scoped; the release workflow runs on Ubuntu.
Source cleanliness is independently reconstructed from HEAD, index and raw tracked bytes/modes
under a stripped Git environment with replacement objects disabled, rather than trusting
caller-routed Git configuration or one porcelain status line.
The Windows-native observer does not execute emitted PEs and still requires its first hosted
Windows result before supporting a hosted native claim. Its Task canary uses only an
unregistered in-memory definition through `TaskService.Connect`, `NewTask(0)` and
`TaskDefinition.XmlText`; its Shell Link canary uses `WScript.Shell.CreateShortcut` without
`Save`, `Resolve` or `Run`. Neither canary registers, activates or executes the artifact it
observes.

Scanner checkpoints are now separated by corpus revision. The 2026-08-03 Phase 6B record is
historical and does not cover v30/MAM Prefetch. The latest 2026-08-04 Phase 6C record remains
red overall: its ClamAV and XProtect slots are complete, while Gatekeeper is inapplicable and
community YARA did not establish complete coverage. Exact records and limitations are
maintained in [`SECURITY.md`](SECURITY.md#scanner-claims-require-an-attestation); neither
checkpoint supports an overall clean or zero-detection claim.

## 0.5.0 - 2026-08-02

### Added

Benchmark v2 replaces subject-rooted question bundles with five scalar questions per
Windows/macOS scene under two closed rules. Windows follows a selected Amcache `FileId` SHA-1
into one of five resident PE byte strings and returns its SHA-256; macOS strictly parses one
exact-path quarantine xattr UUID and follows it into one of five `QuarantineEventsV2` rows.
Each scene is a five-answer bijection with exact 20% candidate chance. Linux remains a
generator-assurance and Fixture Core family, not a Gate 4 benchmark population.

`artifactforge bench export` publishes a no-replace solver root containing only canonical
`public.json` and declared `scenarios/` artifacts. One aggregate scenarios-tree commitment
keeps answer-bearing per-file digests private; `suite_id` binds the canonical protocol,
questions, inventories and commitment and is mandatory on every submission row. The solver
loader rejects extra/private material, unsafe trees, disclosure files, noncanonical JSON,
inventory drift, commitment mismatches and cross-suite submissions.

Gate 4 now derives five-candidate universes and actual multi-artifact dependency paths through
the closed reference rules. Complete selection adversaries must cover every question and are
tested in aggregate and per family/rule with exact conditional permutation inference over the
`5!` within-scene assignments. A development-trained rank/union attack receives no hold-out
answers. Both development and measured corpora require at least 20 scenes per class and an
exact scene-level power contract with a predeclared alternative and target.

Parser-valid counterfactuals swap Amcache `FileId`s, resident PE bytes, xattr UUIDs and
quarantine-database UUIDs or make one relation absent. Each mutation must have its exact local
five-question effect while rebuilt hives, PEs, databases and xattrs continue to pass their
independent parser/profile checks. Source-aware blind reconstruction and co-located parent
traversal are explicit positive controls.

Serialized quarantine xattrs are now Gate 1 artifacts rather than unparsed sidecars. The
artifact module's strict parser and an independently implemented bounded byte reader require a
type-exact four-field consensus and canonical flags, timestamp, agent and UUID profile. Gate 2
uses the same strict parser with exact relative selectors; Gate 3 grants only strict-valid
non-executable xattr values its single marker exemption.

### Security

The public export is explicitly a transfer boundary, not a Python sandbox. Arbitrary untrusted
solvers must run in a separate OS-enforced account/container/VM/machine with no evaluator path
or mount. The finalized evaluator retains suite keys, answers and content cache; construction
staging is transient and absent after atomic publication. It grades only matching `suite_id`
submissions.

Evaluator/public reads and submissions are bounded, no-follow and schema-exact. Generation is
capped at 200 scenarios before destination mutation; the current maximum public export is
2,701 files under the shared 4,096-file/256 MiB inventory contract. Evaluator truth and
submission values share a 4,096-character answer limit. Final evaluator state is private,
public exports are read-only, and implicit gate/scorecard work directories are removed after
green, red or exceptional command completion.

Benchmark v1 is invalidated: completed footprint and stored-order attacks recovered every
answer on the hostile audit corpus, a co-located parent traversal recovered every answer, the
disclosed-key blind control reconstructed its corpus without target reads, candidate-aware
chance was approximately one in five, and `joins` was self-asserted rather than a parser-derived
dependency trace. Its published numbers are withdrawn, not v2 baselines.

Public development and scorecard-measurement corpora remain deliberately non-reportable. No
v2 performance score is reportable until a fresh-key hold-out is exported, run in a separate
trust domain, graded and audited end to end. At the time of the 0.5.0 release, no fresh scanner
attestation existed for the v2 corpus; earlier scanner prose could not be carried forward.

### Changed

The benchmark derivation domain and public document schema are versioned for v2, preventing
v1 and v2 suites from mixing. The clean-source v0.5 scorecard reports generator assurance,
experimental benchmark validity and the all-gates compatibility verdict as `pass`. Its
reproducible measurement corpus remains explicitly non-reportable, so this status publishes no
agent-performance or shortcut-attack score.
The v2 public development key and question schema also invalidate every pre-release evaluator,
public export, submission and generated sample from the earlier development line; regenerate
them as one unit rather than attempting to migrate or relabel their identities.

Gate 4 now predeclares 39 exact randomization comparisons across eleven registered attacks,
two trained ensembles, two family/rule classes and aggregate. Ten mandatory independently
constructed positive controls cover the eight complete attacks and both production ensemble
wrappers; all registered execution paths fail red. Published-number checks retain protocol
constants and scoped scorecard status while prohibiting public-corpus attack diagnostics from
being promoted into performance prose.

The exact five-candidate chance contract is evaluated with rational arithmetic through the
Gate 4 decision boundary, avoiding Python-version-dependent floating-point reduction. Native
Linux attestation preserves extended Bash-history timestamps by setting a deterministic
`HISTTIMEFORMAT` and activating Bash's special-variable hook inside the isolated shell; a real
Bash subprocess regression proves byte-identical source and control roundtrips without executing
history commands. CI installs its centralized pinned uv version
inside runner-temporary virtual environments rather than modifying PEP 668-managed Python, and
the determinism lane explicitly creates the trusted parent required by fail-closed benchmark
publication.

The isolated PEP 517 producer is now reproducible across time as well as across same-session
environment changes. `pyproject.toml` pins Hatchling exactly; a generated build-constraints
file pins and hashes its complete five-package closure; scorecard source provenance records the
constraint digest; and CI builds sdist-then-wheel twice with hash enforcement, a fixed standard
build epoch, different umasks/hash seeds/timezones/locales and byte comparisons. The no-dependency
packaged-fixture smoke now covers all three platform families and checks the wheel's recorded
backend plus both constraint files in the sdist.

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

Benchmark staging now rejects these known answer/evaluation basenames:
`ARTIFACT_ANSWERS.json`, `GROUND_TRUTH.json`, `JOIN_MANIFEST.json` and `fixture.json`. The check
is case-insensitive at any depth. It also rejects Fixture Core's schema marker under any
filename.

### Changed

Generator assurance now covers a deterministic balanced Windows/macOS/Linux population for
Gates 1–3. At the time, Gate 4 remained Windows/macOS-only and its benchmark-v1 reference
100%, footprint 72.7% and stated chance 4.2% measurements were unchanged. Those historical
v1 figures are now withdrawn and invalidated; they must not be quoted or compared with
benchmark v2. Linux fixture releases remain loose evidence rather than activation-ready
filesystems: Fixture ABI v1 does not bind modes
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
The deterministic 40-scene scorecard measurements were also unchanged at that release:
880/880 Gate 1 reads, 420/420 semantic checks, 400/400 Gate 2 joins, 200/200 binary checks and
440/440 markers, along with its then-recorded 72.7% benchmark-v1 adversarial floor. That v1
benchmark number is now withdrawn and invalidated, not a baseline for v2.

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
deliberately version-neutral: at 0.1.0 those loose artifacts combined NT6-era paths with
XP-family SCCA v17 prefetch, so calling the fixture a Windows 10 image would have overstated
consistency.

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
red. There is no unbound rule-name allowlist that can relabel a hit as merely descriptive.

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
places at once: a module whose docstring is the question, a CLI subcommand that exits
non-zero, a pytest file, a block in the committed `fidelity-scorecard.json`, a row in the
regression table with a direction and a tolerance, a named CI step, and a registered mutation
that must turn it red. `tests/test_gates.py` enforces those bindings mechanically, so a gate
cannot quietly become decoration. The sixth binding is the one that matters: a gate never
observed to fail proves nothing. `tests/test_gate_mutations.py` breaks each one on purpose by
truncating a hive, appending a byte to a binary, rewriting an Amcache `FileId`, stripping a
synthetic marker, writing instructions past the `ret`, pointing a URL at a routable domain.

A real arm64 Mach-O, hand-assembled from pure stdlib on the same terms as the PE writer. It
carries a genuine `LC_SYMTAB` whose undefined external symbols yield the symhash that
threatstream/symhash and yara-x compute, and an ad-hoc code signature whose cdhash is what
`codesign -d` reports. LIEF and macholib parse it; on macOS `codesign -v` certifies it. The
signature is computed in-process because an unsigned arm64 binary is not loadable at all and
signing afterwards would rewrite the bytes. This also makes the signing identifier part of
the file's identity, so it is encoded in the content id rather than passed alongside it.

A benchmark that measures investigation. Every answer hangs off a 32-byte suite key; the
public scenario identifier is an HMAC of it, domain-separated from content seeds and from each
variable selection. Suites come in two kinds: a dev suite built with the key published in the
source, cheatable on purpose and never reportable, and a hold-out suite whose key never leaves
the evaluator. Scenes carry decoys and the signals deliberately disagree: persistence launches
one binary while Amcache's recorded hashes match a different one. Every question spans at
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

libyal's `libscca` (used by plaso and log2timeline) rejected every prefetch file
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
