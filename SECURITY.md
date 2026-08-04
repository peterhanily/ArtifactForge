# Security policy

ArtifactForge generates **synthetic forensic artifacts** for training and evaluation, including
binaries, registry hives, Prefetch records, macOS databases, XDG entries and Bash history. It
ships no service and listens on no port. Fixture commands parse caller-supplied local JSON and
filesystem trees, so those inputs are treated as untrusted. This policy defines the relevant
security boundaries and reporting channels.

## Report privately

**security@peterhanily.com**: please do not open a public issue for any of the first three
categories below.

## What we want to hear about

1. **A shipped binary is not inert, or its synthetic marking can be stripped.**

   Every generated binary reproduces forensic *signals* without a payload: a real import table,
   a real symbol table, and real content or structural hashes. The PE's `.text`
   section is a single `ret` followed by zero padding; the Mach-O writer emits an eight-byte
   `__text` containing `mov w0, #0 ; ret`; the ELF main object has one nine-byte RX body,
   `xor edi,edi ; mov eax,60 ; syscall`. Gate 3 parses and bounds-checks all three formats. For
   PE it binds `AddressOfEntryPoint` to the sole executable `.text` section, admits only the
   modeled system DLL imports, and rejects every data directory except imports, including TLS
   and managed-code startup. For Mach-O it binds `LC_MAIN` to the sole executable instruction
   section, admits only the writer's system-library/load-command/section profile, rejects
   alternate startup mechanisms, and verifies that the CodeDirectory page hashes cover every
   byte before the signature. For ELF it requires the exact file geometry, non-overlapping
   file/virtual loads, zero-only slack, dynamic allowlist and absence of an alternate
   main-object entry surface. Parseable mutations of each property are required to turn the
   gate red.

   The Mach-O is ad-hoc signed and Gate 3 statically binds its `LC_MAIN` entry to the fixed
   two-instruction body. ArtifactForge does not execute it, so loader reachability and process
   return status are not claimed. The fixed 16-bit DOS stub only prints its conventional
   message and exits. A Linux execution attempt enters the declared external loader/dependency
   code before the emitted main object's direct-exit body; that external code is explicitly
   outside the main-object instruction claim. If you can make emitted main-object code execute
   beyond the fixed return/print/direct-exit bodies, or make any generated operation perform
   file, network, persistence or process actions or carry a usable secret, report it privately.
   See
   [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

2. **A generated artifact could be mistaken for genuine evidence, or an indicator points at
   something real.**

   Every parser-classified structured format carries an in-band `ARTIFACTFORGE` anchor so a
   file that escapes its bundle is still recognisable as generated. The sole classified marker
   exemption is the complete serialized `com.apple.quarantine` value, whose real four-field
   grammar has nowhere to carry an extra marker. Gate 1 reads that bounded value through two
   independent strict implementations, and Gate 3 grants the exemption only when its exact
   byte profile is valid. Plain documentation and answer sidecars remain outside the marker
   gate. Domains must be RFC 2606 reserved (`.example`, `.invalid`, `.test`) and addresses RFC
   5737 / RFC 3849 or RFC 1918. If you find a classified format shipping without a marker or
   explicit strict exemption, a marker that a normal workflow strips, or an indicator naming
   something that could plausibly be a real host, domain, bundle identifier or signing
   authority, report it privately.

3. **A benchmark boundary exposes evaluator-private state, permits replay/mix-up, or accepts an
   internally invalid attempt chain.**

   The exact solver export may contain only canonical `public.json` and its declared
   `scenarios/` tree. Suite keys, answers, content caches, construction staging, fixture
   manifests and ground-truth material are evaluator-private; staging is absent from a
   finalized evaluator. The aggregate scenarios-tree commitment and
   canonical public document are bound by `suite_id`, and every submitted row must carry that
   same identity. If an exact public export includes or can reach private state, fails to bind
   the declared bytes, or permits a submission from another suite to be graded, report it
   privately.

   Benchmark v3 adds a stricter local attempt boundary. Precommitment creation is v3-only; the
   attempt API must keep the designated ledger outside the evaluator root, publish the one-shot
   claim before opening the reveal, and return a receipt without validity, score or success
   feedback. The receipt's result hash is computationally blinded by a private random nonce, but
   `result.private.json` is plaintext to the ledger owner; this is feedback withholding from the
   receipt recipient, not encryption. Local retirement may terminate an unclaimed or partially
   completed chain, so a valid retired report can contain a nullable complete prefix of
   claim/result/receipt records. If the API permits a second claim in one intact ledger, reads the
   reveal first, crosses the evaluator boundary, leaks feedback through the receipt, or accepts a
   malformed internal prefix/hash/arithmetic chain, report it privately. The detached verifier
   is intentionally narrower: it has no evaluator or public-suite input and therefore cannot
   authenticate the ceremony, validate the evaluator's questions/answers or regrade the result.
   See [`docs/benchmark-v2.md`](docs/benchmark-v2.md) and
   [`docs/benchmark-v3.md`](docs/benchmark-v3.md).

4. Anything else: a normal public issue is fine.

## What this project is not

It is **not threat intelligence**, and its output is **not evidence**.

Nothing here was observed anywhere. Every forensic hash, UUID, bundle identifier, URL, path and
timestamp embedded in a synthetic artifact is fabricated and deterministic for its bound
seed/key and producer profile. That statement does not cover protocol-operation metadata:
Benchmark v3 ceremony keys, IDs and result-blinding nonces use the OS CSPRNG, while ceremony and
attempt records use the current UTC clock. Those values are also synthetic protocol records,
not observations from a host. Do not submit any generated indicator to
VirusTotal, a blocklist, a detection rule, a SIEM watchlist, or a threat-intelligence
platform. A synthetic SHA256 that acquires a reputation permanently pollutes a third-party
dataset.

Benchmark staging rejects known disclosure basenames case-insensitively at every depth:
`ARTIFACT_ANSWERS.json`, `GROUND_TRUTH.json`, `JOIN_MANIFEST.json` and `fixture.json`. It also
rejects Fixture Core's schema marker regardless of filename. Gallery metadata and fixture
manifests must remain outside every solver-visible scene.

Artifacts are generated for training a responder or evaluating an agent, and they belong in
that context. If you publish results from them, say they are synthetic.

## Benchmark execution boundary

Benchmark v1 is invalid as a performance measurement: completed footprint and stored-order
shortcuts each scored 100%, a co-located parent traversal read answers at 100%, the public-key
blind control scored 100%, candidate-aware chance was approximately 20.45% rather than 4.2%,
and the declared join count was not re-derived from parser dependencies. Those results must
not be quoted as benchmark performance.

Benchmark v2 separates the private evaluator root from an exact public export and binds
submissions to the export's `suite_id`. That filesystem export is a transfer boundary, not a
sandbox. Arbitrary untrusted solvers must run in a separate OS-enforced trust domain, such as a
locked-down account, a container or VM without the evaluator mount, or a separate machine. The
evaluator root must be unavailable there. Running solver code in the evaluator process or under an
account that can walk to `_answers/` recreates the verified 100% parent escape.

Every Benchmark v2 suite is permanently non-reportable, including one carrying the historical
`holdout` label: v2 accepts caller raw keys and records no evaluator-created freshness
ceremony. `bench precommit` rejects v2 rather than creating a dead-end record. Benchmark v3 is a
distinct schema whose constructor internally mints CSPRNG key material and binds an exact
origin/reportability block into `suite_id`. The origin's
`protocol.population_power_contract` is a theoretical exact contract over the declared 39
comparisons and `1/780` adjusted threshold; it is not evidence that Gate 4 ran on that suite.
The private ceremony record and designated one-shot ledger are local self-attestation. The API
enforces that evaluator and ledger roots are disjoint and claims before reveal access; keeping
the solver in a separate OS trust domain remains an orchestration requirement. The plaintext
private result is visible to the ledger owner, while the random nonce prevents its receipt hash
from disclosing low-entropy feedback. Retirement is irreversible only inside that designated
local ledger and can terminate any valid live prefix. It cannot prove evaluator independence,
solver isolation, unique ledger designation or an external witness, so retired evidence is
always marked `reportable: false`.

Live create/consume/retire/report operations require the POSIX descriptor/locking capability
check and are exercised on Ubuntu and macOS CI. Windows fails those live operations closed but
exercises submission/precommit parsing and detached verification. Detached verification is
portable because it checks only the canonical report self-hash, internal record links and
semantics/arithmetic, plus an optional reveal digest/size; it does not authenticate v3 origin or
evaluator correctness. See
[`docs/benchmark-v2.md`](docs/benchmark-v2.md) and
[`docs/benchmark-v3.md`](docs/benchmark-v3.md).

## Scanner claims require an attestation

A terminal line saying "0 detections" is not a publishable result. Any clean or passing scanner
claim must be produced by `scripts/scan-exposure.sh --output <record.json>` and must pass
`scripts/scan-exposure.sh --check <record.json>`. A structurally valid red record may be retained
as a diagnostic, but it fails that clean-success check and supports no passing aggregate claim.
The record format is
[`scanner-attestation.schema.json`](scanner-attestation.schema.json); its stricter semantic
checks live in `scripts/scanner_attestation.py` and are mutation-tested without requiring
ClamAV or macOS tools on the default Linux test host.

The checker fails closed unless the record is at most 30 days old and contains all required
result slots. Each result must identify the engine and rule version or fingerprint, bind to the
exact file manifest and corpus SHA256, record its UTC timestamp and command/method, pass an
applicable positive control, account for exclusions and errors, and state what the observation
does not prove. A missing scanner, failed control, partially loaded rule corpus, scan error,
unbound input, scanner or YARA-rule match, stale record or incompatible schema is a failure,
never a skip.

Corpus, YARA and ClamAV-database inputs are copied through bounded no-follow descriptors into
private snapshots, with a complete end-of-tree state replay before scanning and a second
snapshot check afterward. Subprocess output is capped at 64 KiB and POSIX process groups remain
under the wall-clock deadline even when descendants retain capture pipes. ClamAV clean/finding
records bind the copied database bytes, require the exact no-skip limit argv, reconcile exit
status, findings and engine file counts, and reject limit diagnostics. YARA disables transitive
includes, accounts for both selected-file work and loaded-rules × corpus-files work, applies
per-match and aggregate deadlines, and bounds matches and error evidence. Attestation JSON is
schema-exact, size-bounded and published through a pinned private output inode and parent.
YARA compilation itself remains in-process and outside the corpus-match deadline. Rule sources
are capped at 4 MiB each and 128 MiB in aggregate and any compiler failure is red, but a
pathological compiler/rule can still hang or exhaust the attester; process isolation is a
separate hostile-validation item.

The current loose-Mach-O profile intentionally cannot make the four-slot record green. Apple's
[TN2206](https://developer.apple.com/library/archive/technotes/tn2206/_index.html) assessment
shape is a top-level application bundle; a loose binary is neither
a valid Gatekeeper positive control nor a meaningful negative target. ArtifactForge therefore
does not invoke `spctl` for that slot and rejects a purported successful loose-file observation.
The bundle-shaped target/control profile is deferred until ArtifactForge emits real `.app`
layouts. This red result does not invalidate separately complete ClamAV or YARA observations.

These scans are local. Producing an attestation does not relax the VirusTotal or
threat-intelligence prohibition above. Even a fresh clean attestation is evidence only about
exact bytes against dated signature snapshots, not proof of safety or inertness. The record is
self-reported and unsigned, so it does not independently authenticate the scan host or scanner
executables.

### Historical Phase 6B checkpoint (2026-08-03)

The 2026-08-03 local self-report bound a 20-scene Benchmark v2 batch and generated gallery: 339
files, 3,047,119 bytes, and corpus-tree SHA-256
`20b0ca23048e2f5506d332e55389eaed9060d634a80c121a6d75f11af198a514`. ClamAV 1.5.3 with
signature set 28078 and XProtect YARA rule version 5353 each passed their control and scanned
all 339 files without a detection. These were two complete controlled slots, not an overall
clean result.

The record was red overall. Gatekeeper was inapplicable to the loose-Mach-O profile. The
community checkout selected 489 rule files, loaded 479 containing 12,770 rules, recorded ten
compile failures, and refused 4,329,030 planned evaluations against the 250,000 work ceiling.
A separate bounded Task/Shell-Link diagnostic recorded three rule/file matches: generic
`domain` on both files and generic `url` on the task namespace. Its exact local JSON remained
outside the checkout; SHA-256
`e1c1617073f955714f794a2b7d2c1fdb73742cf7386677193b0b39ca110956ad` identifies the retained
self-reported bytes if supplied separately.

An earlier unbound strict diagnostic was also red: it recorded community-YARA matches and
rule-file load failures, so it did not support a clean claim. The dated Phase 6B record remains
exact historical evidence for its bound corpus, but it predates the Phase 6C Prefetch
regeneration and provides no observation over the v30/MAM bytes.

### Latest Phase 6C checkpoint (2026-08-04)

The latest local self-report, generated at `2026-08-04T00:13:08Z`, binds the regenerated Phase
6C corpus: 339 files, 3,046,265 bytes, and corpus-tree SHA-256
`530357958bb827099d31d02c93c063981b7ac3e9c50a20e25c91374c4dd5b913`. ClamAV 1.5.3 with
signature set 28078 passed its control and scanned all 339 files with no detection. The one
selected XProtect rule file (457 loaded rules; fingerprint
`15650c516cce5f4f6064d67da08b505a16e7085692184c36fe45d735659c6a7a`) passed its rule-specific
control and scanned all 339 files with no detection. These are two complete controlled slots,
not an overall clean result.

The Phase 6C record is red overall. Gatekeeper is inapplicable
to the loose-Mach-O profile, and community YARA selected 489 rule files, loaded 479 containing
12,770 rules, recorded ten compile failures, and refused 4,329,030 planned evaluations against
the 250,000 work ceiling. Its exact local JSON remained outside the checkout; SHA-256
`6b29b4714fdc0d751254d936783966d27f4864bc83a1db56f12a313338085b3e` identifies those retained
self-reported bytes if supplied separately. The checker rejects this record, as required, so
it supports neither an overall clean claim nor a community-YARA coverage claim.

## Release evidence and supply-chain boundary

`scripts/release_evidence.py` produces unsigned local self-attestation. It binds a clean source
snapshot, two separately supplied inode-distinct but byte-identical distribution roots, exact
wheel and sdist archive profiles, the source/sdist/wheel chain, normalized CycloneDX documents,
checksums and a closed output inventory. It does not authenticate its producer or host, sign a
subject, publish a package or produce a reportable security result. `--allow-dirty` is explicitly
a non-release diagnostic and records the dirty source state rather than upgrading it.
Source inspection resolves a fixed system Git executable, drops ambient Git configuration,
routing and replacement-object controls, parses the exact HEAD/index trees, and independently
hashes tracked worktree bytes/modes and untracked content. A caller-controlled Git environment
must not be able to turn a dirty or substituted tree into clean-source evidence.

Evidence creation stages beside a destination outside the repository, pins the destination
parent and stage inode, syncs every output and directory, and publishes the complete directory
without replacement. Inputs and bundle verification are bounded, no-follow and identity-
checked; duplicate JSON members, floats, non-finite numbers, oversized signed integers, unknown
fields, undeclared files and archive aliases/special entries fail closed. This descriptor and
atomic-directory-publication contract is currently POSIX-scoped and the release workflow runs
it on Ubuntu. It is not a Windows release-evidence support claim.

With a repository root, verification repeats a locked/no-config/no-source uv SBOM export in
offline mode and a private cache under a minimal child environment, then byte-compares the
normalized documents. That constrains the exporter invocation and dependency source; it cannot
observe or prove host-wide network inactivity. Official CycloneDX 1.5 validation is a separate
closed-registry pass: all three schemas are fetched from one immutable upstream commit and
accepted only at their reviewed SHA-256 digests. Schema validity is not an independent claim
about producer identity, vulnerability status or semantic completeness outside ArtifactForge's
closed SBOM profile.

`scripts/publish_rehearsal.py` is the only permitted publish-command rehearsal. It accepts
exactly the canonical wheel and sdist, snapshots them and the reviewed uv executable into a
private directory, drops ambient credentials/configuration/proxies/keyring/OIDC/loader state,
and fixes `uv publish` to a loopback URL with `--dry-run`, trusted publishing disabled and the
keyring disabled. It neither authenticates to nor uploads to an index. A successful dry run is
not evidence that real publication would succeed.

The manual tag-only `release-evidence` workflow can create external GitHub/Sigstore attestations
for exact subjects and SBOMs, but only after it actually runs. Its declaration of the
`release-attestation` environment does not configure environment reviewers or tag protection;
repository administrators must do that before an approved run. The workflow never creates or
pushes a tag, creates a GitHub release, or uploads/publishes a package to PyPI. Its bootstrap and
dependency-installation steps may contact their configured package hosts. All actions are
immutable-commit pinned and uv is installed from reviewed platform wheel hashes, but pin
updates and runner-image changes still require review. See
[`docs/releasing.md`](docs/releasing.md).

The full parser-oracle matrix is CPython 3.11–3.13. CPython 3.14 is core-only until the locked
full oracle set passes target installation, imports, positive controls and behavioral tests.
Current reviewed blockers are `dissect-target==3.25.1` at runtime import and the absence of a
reviewed CPython 3.14 binary distribution for `yara-python==4.5.4`; metadata inspection cannot
waive either. The Windows-native observer does not execute generated PE files, but its first
successful hosted Windows run remains required before making a hosted native claim.

Current Windows scenes carry deterministic MAM algorithm-4 compressed Prefetch v30 variant 1.
The portable expected-size reader, rather than an EOF-driven external decoder, owns exact wrapper,
declared-output and inner-layout validation. `pyscca` acceptance and typed
`pyscca`/Dissect agreement are semantic evidence; Dissect can expose fewer or more decoded
bytes than MAM declares and is not a framing oracle. The Windows observer's
`RtlDecompressBufferEx` check remains conditional until a hosted run succeeds. It compares the
declared output and makes no claim that Windows consumed or rejected post-size bits.

## Fixture filesystem boundary

Fixture Core treats recipes, manifests and existing fixture trees as untrusted input. Its
published Draft 2020-12-tested JSON Schemas are structural companions; the strict loader and
authoritative model enforce canonicalization, digest equations, cross-field relations and
name-keyed uniqueness documented in schema `$comment` fields, as well as rejecting duplicate
keys, unknown fields, non-normalised strings and floats.
Artifact inventory rejects absolute or traversing paths, symbolic links, special files and
case-fold collisions. Fixture ABI v2 additionally rejects non-reversible guest/served paths,
missing or orphaned explicit directories, metadata-blob aliases and every resource-counter
mismatch. Build and release refuse any pre-existing destination, stage beside the destination,
and use atomic no-replace publication only after regeneration or archive readback. Release
resolves and rejects an output parent inside the fixture before creating any missing parent,
then checks containment again after creation. Verification pins the opened root and payload
directories, snapshots only through held descriptors, and rejects identity changes. Build
syncs the complete generated tree before the rename; if the final parent sync fails, the API
and CLI explicitly report that the verified output was published but its crash durability is
uncertain.

V2 logical metadata is data, not a request to mutate the development host. Publication never
calls host `setxattr`, ownership or timestamp APIs and never creates native Windows ADS values.
Its declared pathname namespace writes only default streams, using exact private carrier modes:
0700 directories and 0600 files, independent of umask. Logical executable modes, owners,
timestamps, macOS xattrs and Windows streams live only in the canonical manifest. Mac
quarantine sidecars are consumed into that logical record and do not remain as declared
carrier files. The raw-directory verifier does not inventory incidental host xattrs or ADS
values attached by the filesystem, provenance tooling or a hostile host; integrity and
assurance therefore do not prove that all inode metadata is absent or inert. A downstream
filesystem materialiser would be a separate security boundary and is not implemented here.

Release uses a single descriptor-pinned fixture snapshot for reproduction and encoding, keeps
the temporary archive inode open through mode-setting, sync and post-write verification, and
checks that the published hard link names that inode. Archive verification independently
regenerates the embedded recipe; manifest-consistent but non-reproducible payloads are rejected.
After the last source byte is read, capture performs a full recursive descriptor-anchored
second state pass, re-listing directories and rechecking every observed file and directory;
cross-file rolling mixed snapshots are rejected.
Release also validates the captured v2 root, manifest, payload, nested-directory and file modes
before encoding; it rejects a mode-invalid source rather than laundering it through normalized
headers.
Output-parent traversal and creation are relative to held no-follow directory descriptors.
Every directory inode captured from the source is excluded before descending further, so a
case-insensitive alias or concurrently swapped ancestor cannot redirect parent creation into
the fixture; publication remains bound to the held destination-parent descriptor.
The only archive encoding is normalized USTAR: lexical explicit members, directories 0755,
files 0644, uid/gid 0, empty owner/group names and mtime 0. Guest metadata remains inside the
manifest and is never projected through archive headers. Only the manifest, declared
directories and declared default streams are encoded; host xattrs, native ADS and PAX metadata
are excluded.
Post-link directory-sync failure is reported as a published, verified archive with uncertain
crash durability rather than being ambiguously deleted.

Inspection, integrity, reproduction and assurance are separate results. `inspect` never
invokes a producer and is the supported integrity path for Fixture ABI v1, frozen parse-only
at ArtifactForge 0.5.0. V2 reproduction is selected by generator ABI and producer profile, not
by an exact package-version string; that version is provenance. Reproduction compares the
complete logical manifest, excluding only package-version provenance. Optional assurance adds
Gates 1 and 3 and, on v2 macOS, requires both Gate 1 quarantine readers, type-exact consensus
and the strict profile before checking the exact logical xattr UUID/database relation. The raw
carrier's incidental host xattrs and ADS remain outside that assertion. On v2 Windows, every
declared logical `Zone.Identifier` value is bounded before a `ConfigParser` adapter and an
independent raw reader receive the same immutable bytes; either refusal, typed disagreement or
departure from the exact Internet-zone/reserved-marker-URL profile makes assurance red. This
does not extend assurance to incidental native ADS on the carrier.

The manifest is an integrity and reproducibility record, not a signature. Its seed and content
digests are public, and `benchmark_eligible` is permanently false: copying a fixture manifest
into a benchmark scenario would disclose the content answers the benchmark is meant to hide.
See [`docs/fixture-core.md`](docs/fixture-core.md).

## Scope

In scope: the generated artifacts, the generator, Fixture Core's parser/filesystem/archive
boundary, the benchmark's answer-key isolation, the local release-evidence/rehearsal boundary,
and the disclosure mechanisms above.

Out of scope are the DFIR parsers used as CI oracles and EvidenceForge. Report parser issues to
their own maintainers. EvidenceForge is not a declared dependency; isolated contract jobs
install it and one test temporarily monkeypatches an imported private method in memory. Nothing
that ships modifies an EvidenceForge source tree, branch or repository.
