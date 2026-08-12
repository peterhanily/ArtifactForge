# ArtifactForge improvement campaign

This is the working engineering contract for the post-v0.5 improvement campaign. It is not a
release note and it does not upgrade any assurance claim by itself. A claim moves only when a
named test can turn red, the relevant runtime observation has been made, and the evidence is
recorded at the exact source revision that produced it.

## Baseline

- Date: 2026-08-03
- Source: `107fb5273fe08d103db4d5e4bd39307980d0e58c` (`v0.5.0`)
- Local runtime: CPython 3.12.13, SQLite 3.50.4, Darwin arm64
- Portable suite: 1,172 passed, six intentional opt-in EvidenceForge skips
- Worktree at measurement start: clean
- Publication boundary: local changes only; no push or upstream action without explicit
  approval

The green suite is a regression baseline, not evidence that every stated fidelity property is
true. The following consumer-shaped witnesses fail on the baseline:

| Witness | Baseline observation | Closure condition |
|---|---|---|
| mac_apt-shaped TCC query | `access.indirect_object_identifier` is absent | the query executes against freshly generated and committed sample bytes and returns the intended typed values |
| APOLLO-shaped app-in-focus query | `ZSTRUCTUREDMETADATA` is absent | the join executes against fresh/sample bytes and returns the intended bundle/time relation |
| regipy Amcache plugin | hive header is `ArtifactForgeHive`, `hive_type` is `None`, `AmCachePlugin.can_run()` is false | authentic hive identity plus plugin applicability and intended record extraction |
| scanner schema boundary | an undeclared top-level `unvalidated_claim` is accepted by `validate_record` | recursive exact-key validation rejects every schema addition and duplicate member before a clean verdict |

At the 0.5.0 baseline, the macOS SQLite payload was producer-sensitive. A controlled CPython
3.13.13 / SQLite 3.50.4 build and CPython 3.14.6 / SQLite 3.53.3 build produced the same macOS
recipe digest but different payload-tree digests; the differences were confined to the three
SQLite files and the manifest that binds them. At that baseline, Fixture ABI v1 was
reproducible only with that producer held fixed, and its generator identity did not record the
SQLite producer.
Current source keeps those vectors parse-only. Phase 3 closed the gap for the new contract with
an owned deterministic SQLite writer; it did not reinterpret or regenerate v1.

## Assurance vocabulary

ArtifactForge uses a ladder of claim scopes. Higher levels do not follow automatically from
lower ones.

1. **Container acceptance:** a named implementation opens the bytes.
2. **Semantic extraction:** a named implementation returns the intended typed facts.
3. **Independent consensus:** implementations with meaningfully separate code paths agree on
   the same typed facts.
4. **Native conformance:** the target operating system's own tool or API accepts or describes
   the artifact under a recorded host/tool identity.
5. **Downstream consumer compatibility:** a responder-facing consumer executes its real query
   or plugin and extracts the intended facts.
6. **Version fidelity:** paths, schemas, headers, metadata and chronology match a declared OS
   and artifact version profile.
7. **Realism calibration:** a predeclared measurement against an independently sourced real
   corpus supports a bounded similarity claim.

Two parser names are not, by themselves, independent consensus. Consensus is not downstream
consumer compatibility. Native rejection is not evidence of safety. None of these levels is a
general claim that output is “realistic”. Gate and documentation prose must name the exact
level it establishes.

## Phases and exit gates

### Phase 0: truth and regression locks

**Status: complete in current source.** Historical evidence and corrected claim boundaries are
preserved by regression tests and dated documentation.

- Correct claims that exceed current evidence.
- Keep historical measurements scoped to their exact corpus, rules and host.
- Turn each reproduced defect into a named acceptance test or phase witness.
- Preserve the portable baseline apart from intentional prose-contract changes.
- Record the checkpoint in ClaudeWiki.

### Phase 1: existing-format consumer fidelity

**Status: complete in current source.** Current consumer profiles are bounded to named schemas,
queries and typed observations.

- Give knowledgeC and TCC versioned schemas that execute the pinned mac_apt/APOLLO-shaped
  queries and preserve exact typed semantic validation.
- Give Amcache and SOFTWARE authentic base-block identities; move the synthetic marker into a
  harmless dedicated key/value.
- Replace Mach-O and hive string-return “agreement” with typed observations and semantic
  profiles. Keep native and downstream-consumer claims separate.
- Regenerate samples only after all mutations and deterministic rebuilds pass.

### Phase 2: trust-boundary hardening

**Status: complete in current source.** The scanner, content store and fixture input boundaries
implement the listed descriptor, schema and resource controls.

- Scan one descriptor-bound private snapshot of corpus and rules; never inventory one tree and
  scan a later pathname view.
- Make scanner validation enforce the complete JSON schema recursively and bind rule/database
  bytes used by each engine.
- Make ContentStore verify content addresses on hit and publication, tolerate concurrent
  writers safely, and fail on path/symlink/parent-identity races.
- Apply shared file/count/depth/total bounds to fixture specs, manifests and archives before
  allocation.

### Phase 3: Fixture ABI v2 and causal layout

**Status: complete in current source.** This is an engineering checkpoint, not a release or an
expanded realism claim.

- ABI v1 is frozen parse-only at the exact 0.5.0 vectors; v2 has distinct spec, manifest,
  generator, tree and producer identities and is the only current producible fixture ABI.
- The three macOS databases use the filesystem-free
  `artifactforge-owned-sqlite-leaf-v1` writer. The host SQLite library remains an independent
  oracle and no longer affects emitted v2 bytes.
- V2 binds reversible guest/served paths, every parent directory, complete default-stream
  identity and bounded family-specific logical modes/attributes, owners, timestamps, xattrs
  and ADS values. Windows SIDs have finite byte, component-count and numeric-width bounds. Mac
  quarantine sidecars are consumed into manifest xattrs.
- Logical metadata never mutates the development host. Publication uses fixed 0700 directory
  and 0600 file carrier modes; canonical USTAR uses normalized 0755/0644, uid/gid 0 and mtime
  0 while retaining guest metadata in the manifest. Release rejects wrong source carrier
  modes before normalization. Incidental host xattrs/ADS are outside raw-directory
  integrity/assurance and are never encoded into canonical USTAR.
- A recipe-bound causal clock drives artifact fields and logical metadata under enforced
  family inequalities. Fixture scene values, content derivation, scene keys and ContentStore
  use domains distinct from the benchmark.
- Inspection, integrity, complete logical reproduction and optional assurance are separate
  results. V2 compatibility follows ABI/producer profile while package version remains
  provenance; macOS assurance runs both Gate 1 readers, typed consensus and the strict profile
  before the logical quarantine-xattr UUID/database join. Windows assurance requires exactly
  one logical Zone.Identifier value, runs it through a bounded `ConfigParser` adapter and an
  independently implemented raw reader before type-exact consensus and its closed semantic
  profile, then joins it to Chromium History and re-hashes the target PE while binding URLs,
  guest path and byte counts.
- Published v2 JSON Schemas are Draft 2020-12-tested structural companions. Their `$comment`
  fields enumerate canonicalization, digest, cross-field and name-keyed rules retained by the
  authoritative model. Release traverses and creates its output parent through held no-follow
  descriptors, rejects case aliases or races into any captured source-directory inode before
  creating a child there, and performs a full descriptor-anchored second state pass that
  detects rolling mixed snapshots.
- The v2 lifecycle, CLI semantic diff, resource counters, fixed carrier, canonical archive,
  owned SQLite profile and knowledgeC seeded-UUID profile are covered by focused mutation,
  hostile-umask, runtime parser and end-to-end family tests.

### Phase 4: benchmark protocol

**Status: complete in current source.** This creates rigorous local protocol evidence, not a
reportable result; the external witness and OS-enforced solver run remain deliberately outside
the local phase.

- Benchmark v2 remains byte/schema compatible and is permanently non-reportable. Benchmark v3
  is distinct, and its only public ceremony constructor accepts no raw key or caller-selected
  origin.
- The v3 constructor internally mints CSPRNG key/ID material and binds an exact origin,
  provisional reportability class and key commitment into `suite_id`. Its exact private record
  is canonical, mode-checked, no-follow, same-inode checked and published without replacement.
  Both public and private wording identify it as local self-attestation pending external
  evidence. Its exact theoretical `population_power_contract` requires an even 120–200
  scenarios, provides 60 scenes per family under the parity schedule and binds the complete
  39-comparison calculation. Suite construction does not execute Gate 4 or bind per-suite
  adversary measurements.
- Completed: canonical JSONL submissions and precommitments bind the exact reveal, suite and
  caller-asserted solver provenance. An authoritative v3 evaluator loader accepts a new
  designated POSIX ledger; a crash-released lock serializes state; complete no-replace records
  claim before reveal access. Detailed feedback is plaintext to the ledger owner; the private
  result's random blinding nonce withholds it from the returned receipt until local-ledger
  retirement. The retired self-bound evidence bundle always opens acceptance/precommit and
  retirement, with a nullable complete claim/result/receipt prefix after early retirement or a
  crash. It optionally verifies detached reveal bytes and always says `reportable: false`
  pending an independent witness. Inode ancestry closes lexical/case-alias output and
  evaluator-boundary bypasses. Unsupported live-ledger hosts fail closed; detached verification
  remains portable but does not authenticate the ceremony, validate evaluator truth or regrade.
- Preserve the completed exact sparse-signal analysis: 60 scenes per family covers both named
  alternatives, whose exact 99%-power minima are 31 and 58 scenes under 39 comparisons. V3
  now serializes that theoretical population/power contract, while actually executing it in a
  per-suite versioned Gate 4 remains future work; frozen v2 is unchanged.
- Completed: cover all ten local pair swaps and enumerate all 120 parser-valid mapping worlds
  on one deterministic representative for each of the three identity mechanisms. Every world
  is independently re-resolved, checked for invariance across the 11 registered relation-
  omitting attacks and required to move a named relation-aware positive control. The explicit
  bound is three representative mechanisms, not every scene.
- Completed as a standalone qualification: a bounded feature-conditioned attack trains across
  four explicitly public, domain-separated development keys with every leave-one-key-out
  rotation. It reports exact family/aggregate coverage and failures, scores 25/160 on the
  unmodified public corpus, and passes an independently relation-rewritten 40/40 positive
  control. Still open: decide whether a future versioned gate should add it to the multiplicity
  family; frozen v2 remains unchanged.

### Phase 5: compatibility, native CI and supply chain

**Status: complete in current source.** Implementation and local runtime closure are complete.
A hosted schema-v6 Windows run produced partial evidence but failed its Shell Link contract.
Hosted schema-v7 run 30944614694 then passed; protected release attestation remains pending. This is
not a signed release or a package-publication claim.

- The full parser-oracle matrix remains Python 3.11/3.12/3.13. A distinct CPython 3.14 lane
  binds the actual interpreter, builds/installs the zero-dependency wheel without dependencies,
  compiles it, and builds/verifies all three v2 fixture families. Full-oracle promotion remains
  fail-closed on the exact reproduced `dissect-target==3.25.1` runtime-import and
  `yara-python==4.5.4` binary-distribution blockers; metadata and wheel tags are not runtime
  evidence.
- The Windows-native lane prepares an exact portable prerequisite on Ubuntu, transports only
  that bound fixture/report pair, authenticates the Microsoft inspection-tool prerequisites,
  observes private copies and checks post-state without executing emitted PEs. The hosted
  schema-v6 run confirmed the repaired Authenticode control, including WinVerifyTrust, SHA-256
  and post-state checks. It then stopped at the Shell Link contract. Hosted schema-v7 run
  30944614694 produced the complete hosted result.
- CI exercises responder-facing consumers and exact target-runtime controls rather than
  inferring support from lower-level parser imports.
- Every third-party action is pinned to an immutable commit, hosted runner labels are fixed,
  and uv 0.11.17 is bootstrapped from exact reviewed platform wheel hashes. Dependabot may
  propose action updates for review; it does not weaken the pin boundary automatically.
- Local release evidence requires two inode-distinct byte-identical builds, raw canonical
  wheel/gzip/USTAR inspection, an exact current-source-to-sdist-to-wheel chain, closed checksums
  and deterministic normalized runtime/development CycloneDX 1.5 documents. The official
  three-schema closure is pinned by upstream commit and exact SHA-256 before offline validation.
  Source state is derived from exact HEAD/index inventories and raw tracked bytes/modes under a
  stripped Git environment with replacement objects disabled, not from a caller-routed
  porcelain status result.
- Repository-root verification refreshes SBOMs with uv's `--offline --locked --no-config
  --no-sources` path and a minimal child environment, but explicitly cannot prove host-wide
  network inactivity. Local evidence is unsigned self-attestation and performs no signing or
  package publication. Its descriptor/no-replace publication path is POSIX/Linux-workflow
  scoped.
- The only publish-command rehearsal accepts the exact two subjects, strips ambient
  credentials/configuration and performs a fixed loopback `uv publish --dry-run` with trusted
  publishing and keyring access disabled.
- The manual release-evidence workflow is exact-tag-only, declares `release-attestation`, and
  can create GitHub/Sigstore provenance/SBOM attestations. Repository settings must still be
  configured and the protected workflow must actually run before any external-attestation
  claim. It never pushes a tag, creates a GitHub release or publishes a package. See
  [`releasing.md`](releasing.md).
- Runtime closure used two hostile-environment byte-identical builds. The source-pre/post-
  guarded local bundle passed closed/offline and repository-refreshed verification; all three
  SBOMs passed the official schema closure; the private-copy uv loopback command exited green;
  and the exact wheel installed without dependencies, reported its version and compiled. The
  settled campaign tree required `--allow-dirty`, so this remains source-bound non-release
  evidence rather than a clean tagged-release rehearsal.

### Phase 6: Windows coverage

**Status: portable Phases 6A through 6C are complete in current source; hosted schema-v6
Windows evidence was partial, and hosted schema-v7 run 30944614694 then passed.** The Windows scene
now includes an owned-SQLite
`chromium-completed-download-query-surface-v1` History artifact
with three completed rows. Chromium's completed-download `hash` BLOB remains honestly empty;
each row's
modeled SHA-256 instead appears in an explicitly synthetic content-addressed reserved final
URL. This is a reduced responder-query surface, not a full, native or Chromium-migratable
database. Gate 1 validates the exact schema, typed dual-reader consensus, completed-row
semantics, responder join and syntactic digest component. Gate 2 independently re-hashes the
exactly one resident target and binds path and byte counts. Fixture v2 gives that PE alone a
logical Zone.Identifier and independently binds its distinct browser referrer/final URLs,
path, size, manifest digest and bytes back to History. Deterministic vectors, malformed-
schema/profile mutations, public-fixture join mutations and known-tells disclosures cover the
new surface.

Phase 6B adds exactly one disabled, trigger-free Task Scheduler 1.2/1.3 XML definition and one
standalone local-file Shell Link to each Windows scene. The task's ElementTree and canonical
UTF-16LE byte readers require type-exact agreement, while dissect.target is retained as a
separate downstream-consumer result. The Shell Link uses exact-pinned liblnk and LnkParse3
external oracles for their reliable typed intersection; a strict first-party byte reader owns
the offset/extents, terminal block and absence of trailing data neither external surface fully
exposes. LnkParse3 1.6.0's defective Unicode common-suffix accessor is explicitly excluded
from consensus rather than shaping emitted bytes around it.

Both artifacts target distinct non-persistence resident PEs and bind their parsed paths,
sizes and SHA-256 values back to emitted bytes; the link additionally binds FILETIMEs and
volume serial. Fixture projection preserves only public guest paths after validating the
private roles, placing the task at an extensionless Task Store path and the link in the modeled
Start Menu. Gate/profile mutations, deterministic vectors, responder-facing queries and
fixture/scene lifecycle tests cover the new surfaces. The task is configuration/reference
only and the link is reference only: there is no activation or execution claim.

Native canaries are implemented with `TaskService.Connect`/`NewTask(0)`/`XmlText` on an
unregistered in-memory definition and `WScript.Shell.CreateShortcut` without `Save`, `Resolve`
or `Run`. In the hosted schema-v6 run, WSH accepted the LinkInfo-backed Shell Link, which has no
`LinkTargetIDList`, but returned an empty `TargetPath`. Inspection of Microsoft-hosted
`wshom.ocx` and `Windows.Storage.dll` builds for that servicing line, with their matching
public symbols, showed the implementation path consistent with this result: the Shell Link
object has no namespace PIDL for the WSH getter to use. Schema v7 classifies the
native target projection as `exact` or `unavailable-no-link-target-id-list`. It does not weaken
target identity: the strict first-party reader, liblnk, LnkParse3 and the
manifest-to-resident-PE join remain authoritative. Hosted schema-v7 run 30944614694 passed, but the
canaries remain inspection designs and still do not support a native-conformance claim. The
current benchmark scene inventories are 14 Windows files and 16 macOS files; at 200
alternating scenarios the public export is at most 3,001 files including `public.json`.
Historical scorecard counts remain historical.

Scanner evidence remains separate from Phase 6 completion. The latest Phase 6C checkpoint is
red overall, and the older Phase 6B checkpoint applies only to its bound historical corpus.
Exact records, results and limitations are maintained in
[`SECURITY.md`](../SECURITY.md#scanner-claims-require-an-attestation).

Phase 6C's portable implementation is complete. Current Windows scenes explicitly call
`build_prefetch_v30` and emit one deterministic MAM algorithm-4 XPRESS-Huffman chunk carrying
Windows-10 Prefetch v30 variant 1: one metric, two filename strings, one volume, a Vista hash
and one creation-time/serial volume token shared across the modeled paths. A strict
expected-size reader owns the compressed framing and exact inner layout, `pyscca` accepts the
record, and `pyscca` plus Dissect agree on their typed semantic intersection. Dissect remains
semantic-only because its EOF-driven decoder can expose fewer or more bytes than MAM declares.
Gate 2 counts captured `.pf` files, decodes each executable name from its bytes, and requires
the exact scene-declared artifact count and name set before evaluating persisted and orphan
execution joins.

The Windows-native `RtlDecompressBufferEx` proof was completed by hosted run 30944614694. It
compares only the declared output and does not claim that Windows consumed or rejected
post-size bits. Version 31, alternate v30 variants and general multi-chunk
XPRESS-Huffman stay outside the claim. The public `build_prefetch`/`prefetch_name_hash` APIs
remain byte-stable v17/XP compatibility surfaces. The still-unreleased `windows-loose-v2`
profile was deliberately compatibility-reset in place rather than renamed; earlier generated
outputs remain bound to their source revision and require regeneration.

TaskCache and Jump Lists are deferred. The former still depends on undocumented opaque registry
blobs; the latter needs a defended Compound File Binary container on top of the standalone LNK
profile. Neither will be approximated with unauditable plausible bytes.

### Phase 7: macOS, Linux and host context

Add real macOS application bundles and metadata, modern background-task persistence, bounded
shell history, Linux systemd-user/SSH/package state and cross-platform host-context artifacts.
Emitters consume a typed private causal-story model; public benchmark and fixture boundaries
must not leak answer-bearing roles or private derivation state.

### Phase 8: hostile validation and local release readiness

Run differential and metamorphic parsing, stateful race tests, all-mapping counterfactuals,
mutation testing, combinatorial interaction coverage, temporal gates and calibrated real-vs-
synthetic discrimination. Refactor any duplicated truth revealed by those tests. Produce a
local, source-bound readiness report; do not tag, push or publish without approval.

## Deliberate deferrals

Hand-written EVTX, binary journals, unified logs, disk images and memory images remain out of
scope until a native producer or a substantially stronger independent validation strategy is
available. Adding opaque bytes faster than they can be defended would increase surface area,
not assurance.
