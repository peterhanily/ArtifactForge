# Benchmark v2 security and validity contract

## Status

Benchmark v2 is a frozen local diagnostic protocol, not a reportable performance protocol.
The clean-source v0.5 scorecard passes Gate 4 over the finite attack/control and 13-check
Windows / 11-check macOS counterfactual surface implemented by that source. It does not attest
to the current 20/25 all-pair checks or representative all-mapping proof. The root card remains
immutable historical v0.5 evidence. Current CI generates a fresh ephemeral HEAD-bound card with
the live measurement identity and `--require-pass`, while the next release still needs a new
clean-source scorecard. Development, scorecard-measurement and historically named `holdout`
suites are all permanently ineligible: v2 accepts caller-supplied raw keys and records no
evaluator-created freshness ceremony. Loading one with newer ArtifactForge code does not
promote or rewrite that claim. Scanner evidence is independent of benchmark reportability. The
latest local checkpoint remains red overall and supports no clean or zero-detection statement;
exact dated records are maintained in
[`SECURITY.md`](../SECURITY.md#scanner-claims-require-an-attestation).

This document states the validated Gate 4 diagnostic boundary. Benchmark v3 introduces a
separate schema and evaluator-created local ceremony; it does not reinterpret v2 documents.
Passing the finite registry does not cover an unregistered strategy, attest OS isolation or
turn any v2 corpus into a reportable hold-out.

## Why v1 is invalidated

A hostile reimplementation of the v1 shortcuts invalidated its published benchmark framing.
The earlier 72.7% footprint result measured an incomplete adversary, and the 4.2% value called
"chance" did not use the candidate sets exposed by the questions. Completing the attacks and
testing the actual execution boundary established all of the following:

- the completed raw mention-footprint solver answered **220/220 (100%)** on a fresh
  40-scene private-key corpus;
- an independent stored-order/first-record solver also answered **220/220 (100%)** without
  performing the claimed forensic joins;
- a co-located solver reached **100%** by walking from
  `scenarios/<scenario-id>` to `../../_answers/<scenario-id>.json`;
- a source-aware blind solver reached **100%** on the public-key corpus without reading the
  target artifacts, which is the expected positive control for a reproducible public corpus
  and proves that such a corpus cannot produce a performance result;
- candidate-aware mean chance for the v1 questions was approximately **20.45%**, not 4.2%;
  and
- the v1 `joins` count was author-supplied metadata rather than a dependency trace re-derived
  from artifacts read by the solver.

These are structural failures, not a request to choose a more favorable threshold. Every v1
benchmark score and comparison is withdrawn. The loose-file generator is a separate claim and
is not invalidated by this benchmark result.

## Two roots with different roles

The evaluator root is private working state. Once published it contains the suite key, answer
files and content cache as well as `public.json` and `scenarios/`. A solver must never receive
this root or a path inside it:

```text
EVALUATOR/
  public.json
  scenarios/<scenario-id>/...
  _key/key.hex
  _answers/<scenario-id>.json
  _content/...
```

Construction staging exists only before the atomic evaluator publication. A finalized
evaluator has no `_staging/` directory, and that component is forbidden in every served
artifact path.

`artifactforge bench export EVALUATOR PUBLIC` creates a new, no-replace public root. Its
complete recursive allowlist is exactly canonical `public.json` plus the declared scenario
artifacts:

```text
PUBLIC/
  public.json
  scenarios/<scenario-id>/...
```

The solver loader rejects private siblings, extra files, links, special files, unsafe paths,
case-folding aliases, missing artifacts and bytes that disagree with the public commitment.
Forbidden answer/ground-truth/fixture material is rejected recursively. Individual file
digests are not published because some are answers; instead, `public.json` carries one
aggregate canonical scenarios-tree commitment.

Every evaluator read and solver load is a bounded no-follow regular-file operation. Evaluator
truth is independently re-derived from one captured read-only artifact snapshot; a later live
tree mutation cannot change that decision. Solver tasks likewise exist only inside a frozen
public-snapshot context and cannot be retained as live paths after it closes. The disclosure
gate scans the public document and served bytes for the raw key and its common hexadecimal,
Base64, URL-safe Base64 and Base32 serializations, plus private answer-document and question-id
shapes. This is a bounded direct-disclosure detector, not proof against arbitrary reversible
encodings or encryption.

The public `suite_id` is a labelled SHA-256 over the canonical public document without the
`suite_id` field. It therefore binds the protocol domain, suite kind, scenario and question
declarations, exact artifact inventories, export metadata and aggregate tree commitment.
Every submission row must carry that `suite_id`; grading refuses missing or cross-suite
identities. Submissions must contain every scenario exactly once and exactly its five string
answers. The strict JSONL reader rejects duplicate members, floats and non-finite values,
non-NFC strings, Unicode surrogates, blank/extra/missing rows and unknown fields. This is an
integrity and mix-up boundary, not a signature or proof of who created the suite.

On POSIX systems the finalized evaluator root and private directories are mode `0700`, its
private files are `0600`, the exact public export is recursively `0555`/`0444`, and the
reference solver publishes a new `0600` submission without replacement. Modes are set
explicitly rather than inherited from `umask`. Publications use same-parent staging and
no-replace or atomic replacement according to whether the target is new or an owned scorecard;
prepublication failures preserve the old target bytes.

The export is a transfer boundary, **not a Python or process sandbox**. An arbitrary solver
must run in a separate OS-enforced trust domain in which the evaluator root is unavailable:
for example, a separate locked-down account, container/VM with no evaluator mount, or a
different machine. Pointing untrusted code at `PUBLIC/` while the same process, account or
mount namespace can still read `EVALUATOR/` does not satisfy this contract. The 100%
co-located parent escape is the positive control for this requirement.

## Resource and input bounds

Suite generation accepts **1–200 scenarios** and rejects the population before touching the
destination. The current alternating schedule emits 14 artifact files for a Windows scene and
16 for a macOS scene; at 200 scenes the public export therefore contains **3,001 files**
including `public.json`. That remains below the shared **4,096-file** and **256 MiB** recursive
inventory ceilings.

The remaining explicit limits are **16 MiB** public JSON, **1 MiB** per answer document, an
exact 64-byte hexadecimal key file, a 16 MiB complete submission, a 1 MiB JSONL line, at most
200 submission rows and **4,096 characters** per scalar answer. The evaluator enforces the
answer-character ceiling before accepting truth, so it cannot construct a suite whose correct
answer the grader must reject. These are denial-of-service and inventory contracts, not
benchmark evidence, a difficulty claim or permission to allocate every limit simultaneously.

## Closed five-candidate questions

V2 has exactly two allowlisted resolution rules:

| Family | Rule | Evidence resolution | Scalar answer |
|---|---|---|---|
| Windows | `amcache-fileid-byte-agreement-v1` | select one exact Amcache `LowerCaseLongPath`, read its `FileId` SHA-1, hash the five resident PE byte strings and select the unique byte agreement | that resident PE's SHA-256 |
| macOS | `quarantine-uuid-event-agreement-v1` | strictly parse one xattr at an exact relative path, join its event UUID to one `QuarantineEventsV2` row | that row's data URL |

Every scene has exactly five questions, five distinct answer candidates and a bijection from
questions to candidates. Each question resolves one scalar value and must traverse at least
two independently read artifacts. Selectors are unique and rule-specific. Unknown rules,
extra selector fields, wrong family/kind combinations and candidate universes other than five
are hard failures. The exact candidate chance is **20%**.

The reference resolver captures each recursive scene once, enumerates the candidate universe
from those captured artifacts and returns the paths it actually used. Gate 4 re-derives the
private expected scalar and dependency trace from that observation. It does not accept a
private join manifest or author-supplied `joins` number as proof.

## Randomization and adversary requirements

Every selection shortcut declared complete must return a value for every question. Missing
answers cannot make such an attack appear weaker. Intentionally empty listing/null controls
remain labeled negative controls rather than evidence of resistance. Results are evaluated
both in aggregate and separately for every family/rule class, so one broken class cannot be
hidden by another.

The null model is the exact conditional distribution of a five-way bijection within each
scene. The evaluator enumerates all `5!` answer assignments for each scene and convolves those
count distributions; it does not substitute independent Bernoulli trials or an arbitrary
accuracy cutoff. Eleven registered attacks plus the trained partial-union and rank-union
ensembles are evaluated in two family/rule classes and aggregate, yielding **39 predeclared
comparisons**. They share a familywise alpha of **5%** under Bonferroni correction.

All **10 mandatory positive controls** must pass before inference: independent vulnerable
worlds for the eight registered complete attacks, the exact production partial-union wrapper
with cross-slot source selection, and the exact production rank-union wrapper. Every registered
attack invocation and both ensemble paths fail the gate red on execution error. The control
truth is implemented independently of the attack under calibration. The current calibration
uses one derived development scene per family; expanding it across multiple scenes and adding
feature-conditioned trained attacks are explicitly future strengthening, not coverage already
claimed here.

A green Gate 4 is therefore a scoped non-detection statement: **none of the registered
shortcuts was detected at the declared familywise alpha**. Every complete shortcut and each
composition ensemble must first pass its independent vulnerable-world positive control; the
intentionally low-information constant, listing and null baselines are measured but are not
described as independently calibrated detectors. Green does not establish universal shortcut
resistance, cover an unregistered attack, or mean that observed shortcut scores are
statistically equivalent to the 20% candidate-chance expectation.

At least **20 scenes per family/rule class** are required before the validity measurement may
run. With the current alternating Windows/macOS schedule, that means at least 40 benchmark
scenes overall. The associated exact power contract predeclares a scene-level alternative in
which the complete mapping is recovered with probability **50%** and otherwise is a uniform
permutation, and requires at least **99% power** at the multiplicity-adjusted threshold.
Public-key blind reconstruction and co-located answer traversal remain positive controls. A
caller-keyed v2 local suite can diagnose both shortcuts, but the result remains permanently
non-reportable.

The **at least 99% power** statement applies only to that predeclared 50% whole-scene recovery
mixture. It is not a minimum-power guarantee for arbitrary shortcut behavior, weaker effects,
partial-question recovery, different dependence structures or attacks outside the registry.

### Sparse-alternative power qualification

The statistics module also exposes a stronger, separately named qualification with a
predeclared minimum of **60 scenes per family/rule class** (120 scenes under the alternating
two-family schedule). It evaluates two exact alternatives:

- `one-correct-edge-every-scene-v1`: one specified question-to-candidate edge is correct in
  every scene and the other four candidates are uniformly permuted; and
- `whole-mapping-quarter-scenes-v1`: the complete mapping is correct independently with
  probability one quarter, and otherwise is a uniform five-way permutation.

For the current 39-comparison family, the exact Bonferroni threshold is `1/780`. At 60 scenes
the rejection region begins at **86 hits out of 300**; its exact null upper tail is approximately
`0.0009268373`. Exact convolution gives power **99.99997172%** for the one-edge alternative and
**99.11138103%** for the quarter-scene whole-mapping alternative. The first exact scene counts
to reach the predeclared 99% power target are **31** and **58**, respectively, so 60 is a
conservative common minimum rather than a fitted minimum.

These are finite enumerations of the `5!` within-scene worlds, not Monte Carlo estimates or
independent-question binomial approximations. The named alternatives do not imply power
against arbitrary leakage. The frozen v2 Gate 4 protocol still enforces its original 20-scene,
50%-signal contract. Benchmark v3 now binds this exact theoretical population/power contract
into its origin without changing v2; executing the 60-scene attack/control family as a
per-suite v3 gate remains a separate versioned-gate change.

### Four-key feature-conditioned shortcut audit

`bench.feature_conditioned` adds a standalone public-corpus audit beyond the fixed attacks,
partial union and rank union. Four independently derived keys are deliberately published; each
produces eight scenes, four per family. Every leave-one-key-out fold trains on the other three
keys (24 scenes), freezes its model, and evaluates the excluded key (eight scenes). All four
keys rotate through the excluded role.

The public key seed is `artifactforge-feature-conditioned-public-development-v1` and the key
derivation domain is
`artifactforge/bench/feature-conditioned/public-development-key/v1`. For zero-based index `i`,
the exact derivation is
`HMAC-SHA256(key=ASCII(seed), msg=ASCII(domain) || NUL || uint8(i))`; the one-byte index is not
its decimal text. The four raw keys are:

| Index | Public key (hex) |
|---:|---|
| 0 | `1fc19b44f4d60f1335980345dfb703b3ae643ba5264a5404ac6b70cd5f48719d` |
| 1 | `6d65808650cfcc25955502d0884c6e9e53fc5c6f5bb629c108c5a4b0be8c2993` |
| 2 | `3c3e0bfef43ed6c4a27c2acb9f673301fa1169256f5cc743c14b2ffa71dcaa9f` |
| 3 | `93d15d1fbbef12b8c1e421900a6c90be8aa4ce4aab5682ac94a4a9a9a160f4f4` |

Those are calibration inputs, not secrets or benchmark hold-outs. V2 has no serialized
feature-development suite kind, so corpora generated through the compatibility constructor carry
its legacy `holdout` label; the explicit key disclosure and this audit role override any
secrecy implication of that historical string.

Training labels are regenerated from those fixed keys and current generator code. The audit
does not read `_answers`, accept a generic key, or accept private `Task` objects for fitting or
prediction. Prediction sees only the frozen public tasks and their captured artifacts. It
enumerates five PE SHA-256 values or five quarantine URLs without following the declared
FileId/UUID relation, then predicts a lexical candidate rank. Per family/rule, the fitter
chooses one of six predeclared categorical features and at most eight value-to-rank branches;
the complete two-class model is capped at 16 branches. Key derivation, feature hashing,
scorecard measurement and Fixture-v2 derivations all have distinct domains.

On the exact 32-scene public corpus the four excluded-key folds recovered `6/40`, `9/40`,
`5/40` and `5/40` answers. Aggregate recovery was **25/160 (15.625%)**, comprising Windows
**18/80 (22.5%)** and macOS **7/80 (8.75%)**. Coverage was **160/160** with zero missing,
invalid or unexpected outputs. These are exact counts, not a benchmark score or a claim that
the attack is statistically equivalent to chance.

The independently implemented positive control sorts selectors and candidates, rewrites the
real parser-valid FileId/UUID relations to that bijection, and checks the result with the
closed-rule reference solver before invoking the production fitter. The reference and attack
both recover **40/40** answers across the four rotations; every fitted control selects
`selector-rank`. Killing the production fitter makes the control fail.

This is intentionally not registered in frozen v2 Gate 4: doing so would expand the declared
39-comparison family and require a versioned protocol/provenance change. It is also a shallow
categorical probe, not a general learner: it does not cover feature conjunctions, continuous
models, content embeddings, arbitrary parser features or adaptive search over the published
corpus.

## Parser and counterfactual requirements

Reference correctness alone is insufficient: a solver could return the right scalar while
ignoring the field the rule claims to measure. Every rule therefore needs parser-valid
counterfactuals whose effects are checked across all five questions:

- Windows mutations cover all ten unordered Amcache `FileId` swaps, replace each relation in
  turn with an absent SHA-1, and replace each matched resident with a distinct same-size inert
  PE: 20 local checks per scene. Rebuilt hives must agree under regipy and libregf and pass the
  exact Amcache profile; replacement PEs must agree under pefile and LIEF.
- macOS mutations cover all ten unordered xattr UUID swaps, all ten database UUID swaps and
  replace each xattr UUID in turn with an absent value: 25 local checks per scene. Rebuilt
  databases must pass the sqlite3/raw-reader consensus and exact profile; xattrs must pass the
  two strict readers and exact serialized profile.

A pair swap must change exactly the two predicted answers. An absent relation or replaced
resident must make exactly one predicted answer unavailable. Every other answer must remain
byte-for-byte unchanged. A malformed artifact, no-op mutation, unexpected parser error or
additional answer change fails the counterfactual gate.

The exhaustive mapping contract is deliberately mechanism-scoped rather than multiplied by
the corpus size. Gate 4 selects one deterministic representative for Windows and one for
macOS, then builds all `5! = 120` worlds separately for Amcache FileId assignment, serialized
xattr UUID assignment and quarantine-database UUID assignment. Each of the 360 worlds starts
from pristine captured bytes, passes its parser pair and exact profile, and is independently
resolved across all five questions. Every registered relation-omitting attack must be exactly
invariant. The named `direct-relation-reader-v1` positive control must recover the intended
five-answer mapping and must differ from baseline in each of the 119 non-identity worlds per
mechanism. The identity world is validated but cannot honestly count as a change.

The exact Gate 4 denominators are 840 parser-valid artifact rebuilds (five xattrs per xattr
world, one artifact in the other worlds), 1,800 reference-answer checks, 3,960 attack-
invariance checks for the current 11-attack registry, 1,800 positive-control answer checks and
357 positive-control change checks. These counts establish three exhaustive representative
mechanism proofs; they do not establish exhaustive mappings independently for every scene.

## What can be reported

All v2 suite kinds are permanently non-reportable, including the historical `holdout` label.
They may report gate diagnostics such as parser refusals, adversary coverage or randomization
probabilities, clearly labeled as local controls rather than agent performance. A raw key, an exact
public export or later external attestation cannot change the v2 protocol classification.
The one-shot `bench precommit` and `bench attempt` lifecycle is v3-only; precommit creation
rejects a v2 public export instead of producing an unusable record.

The distinct [Benchmark v3 ceremony](benchmark-v3.md) records internally minted key material,
origin and provisional eligibility without changing these bytes or claims. V3's separate local
one-shot ledger still needs the externally witnessed trust-domain evidence described there
before any performance result could be considered.

The benchmark secrecy boundary is intentionally separate from the project's artifact and
fixture identity surfaces. See [Identity boundaries](identity-boundaries.md),
[Fixture Core](fixture-core.md), and the repository [security policy](../SECURITY.md).
