# Benchmark v2 security and validity contract

## Status

Benchmark v2 is a validated experimental protocol, not a reportable performance result. The
clean-source v0.5 scorecard passes Gate 4 over its finite registered attack/control surface.
Numbers produced from the public development corpus or the reproducible scorecard-measurement
corpus are controls and diagnostics, never benchmark results. No fresh scanner attestation
exists for the v2 corpus either; scanner statements from an earlier corpus must not be carried
forward.

This document states both the validated Gate 4 boundary and the stricter boundary a future
performance result must satisfy. Passing the finite registry does not cover an unregistered
strategy, attest OS isolation or turn a reproducible corpus into a hold-out.

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
destination. The current alternating schedule emits 11 artifact files for a Windows scene and
16 for a macOS scene; at 200 scenes the public export therefore contains **2,701 files**
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
permutation, and requires at least **99% power** at the multiplicity-adjusted threshold. Public-key
blind reconstruction and co-located answer traversal remain positive controls. A freshly keyed
hold-out must reject both shortcuts under the boundary described above.

The **at least 99% power** statement applies only to that predeclared 50% whole-scene recovery
mixture. It is not a minimum-power guarantee for arbitrary shortcut behavior, weaker effects,
partial-question recovery, different dependence structures or attacks outside the registry.

## Parser and counterfactual requirements

Reference correctness alone is insufficient: a solver could return the right scalar while
ignoring the field the rule claims to measure. Every rule therefore needs parser-valid
counterfactuals whose effects are checked across all five questions:

- Windows mutations swap two Amcache `FileId` relations, replace one with an absent SHA-1,
  and replace each matched resident with a distinct same-size inert PE. Rebuilt hives must
  agree under regipy and libregf; replacement PEs must agree under pefile and LIEF.
- macOS mutations swap xattr UUIDs, swap database UUIDs and replace one xattr UUID with an
  absent value. Rebuilt databases must pass the sqlite3/raw-reader consensus and exact
  profile; xattrs must pass the two strict readers and exact serialized profile.

A pair swap must change exactly the two predicted answers. An absent relation or replaced
resident must make exactly one predicted answer unavailable. Every other answer must remain
byte-for-byte unchanged. A malformed artifact, no-op mutation, unexpected parser error or
additional answer change fails the counterfactual gate.

## What can be reported

Development and scorecard-measurement suites use disclosed, reproducible derivations. Their
scores are non-reportable even when they use the exact public export, because source-aware
reconstruction is a designed 100% positive control. They may report gate diagnostics such as
parser refusals, adversary coverage or randomization probabilities, clearly labeled as public
corpus controls—not agent performance.

A performance score requires a freshly generated hold-out key that never crosses into the
solver trust domain, an exact public export, execution in a separate OS-enforced trust domain,
submission binding to the matching `suite_id`, evaluator-side grading, and preserved
measurement provenance. Until that complete workflow is executed and audited, **no v2
benchmark performance score is reportable**.

The benchmark secrecy boundary is intentionally separate from the project's artifact and
fixture identity surfaces. See [Identity boundaries](identity-boundaries.md),
[Fixture Core](fixture-core.md), and the repository [security policy](../SECURITY.md).
