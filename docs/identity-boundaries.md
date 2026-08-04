# Identity boundaries

## Decision

ArtifactForge does **not** expose a general digest-evidence graph. No demonstrated consumer
needs one. The current identity surfaces have different evidence bases, audiences and secrecy
requirements, so combining them would remove important distinctions:

| Surface | What it means | Visibility |
|---|---|---|
| `Content` | digests and structural hashes derived from one emitted binary's bytes | generator-internal/library object |
| `fixture.json` | exact payload path, size and SHA-256 observations bound to a reproducible public recipe | published fixture integrity record |
| `Scene.join` | construction-time truth used to test declared cross-artifact relations | evaluator/private; never served |
| benchmark answer key | expected answers derived from private scene truth | server-side only |
| benchmark public export | canonical rule/selectors and artifact inventories plus one aggregate tree commitment, bound by `suite_id` | solver-visible; no per-file digest answers |
| EvidenceForge content reference RFC | explicit modeled logical identity, which may have no materialized bytes | upstream opt-in scenario contract |

Digest equality can support a lookup. By itself it does not prove that two observations are the
same historical file, that a download caused an execution, or that either record is authentic.
SHA-1 and MD5 remain useful forensic lookup values but are not collision-resistant identity
proofs. IMPHASH, symhash and cdhash are structural or platform identities, not additional
whole-file digest algorithms.

## Consumer audit

### Windows digest pivots

The repository has two digest pivots and two path-bound reference consumers on Windows. The
first digest pivot is the Amcache `FileId`-to-resident-file relation. The composer emits the
private expected relation. Gate 2 independently parses Amcache, hashes captured resident bytes
and requires each selected `FileId` to agree with exactly one of five residents. The
benchmark-v2 reference resolver does
the same investigation from its own byte capture and returns the SHA-256 of the uniquely
agreeing resident. A graph would duplicate that lookup, while publishing the resolved edges
would disclose the five question-to-answer mappings.

The second is deliberately narrower: a Chromium completed-download row uses an explicitly
synthetic content-addressed final URL because current Chromium persists an empty `hash` BLOB.
Gate 1 validates the URL's lowercase SHA-256 syntax but has no resident PE bytes in that
single-artifact check. Gate 2 re-hashes the exactly one resident download and binds digest,
path and byte counts to the private scene relation; two absent download rows remain noise.
Fixture Core discards that private relation, then independently re-derives a public-fixture
join among the one `Zone.Identifier`-bearing PE, the History row, host/referrer URLs, guest
path, byte counts, manifest digest and re-hashed default-stream bytes. This is a specific
consumer query that does not require a general graph. The History artifact remains a
reduced responder-query surface, not a full, native or Chromium-migratable database.

### Path-bound references

The two path-bound consumers are a disabled Task Scheduler XML definition and a standalone
Shell Link. Each strict reader extracts an exact target path, Gate 2 resolves that path to one
resident claim and then binds target name, size and SHA-256 to freshly hashed bytes; the link
also binds its FILETIMEs and volume serial. Their targets must be distinct non-persistence
residents and disjoint from the Run-key target, so the new references do not amplify the
benchmark's persistence answer into a mention-count signal. Path agreement is still only a
reference: it does not prove that Task Scheduler registered the XML, that a user activated the
link, or that either target executed. A generalized graph would duplicate this lookup and
disclose private construction roles that the public fixture intentionally drops.

### Other consumers

The remaining consumers do not need a graph:

- Fixture verification already snapshots, re-hashes and regenerates every declared payload
  byte. Its Windows download check consumes those existing capabilities directly; a graph
  containing the same path/SHA-256 pairs would duplicate its manifest.
- Native attestation binds and observes the verified Fixture Core manifest. Its task and link
  canaries receive only the publicly projected path/byte relations and postconditions; they do
  not need or receive private semantic join roles.
- Linux's current relation is an exact guest-path intersection across XDG and Bash history,
  followed by hashing the mapped resident bytes. Neither text artifact emits a digest.
- macOS content digests in private scene truth identify emitted binaries; benchmark-v2's
  public relation instead follows a strict xattr UUID into `QuarantineEventsV2` without
  publishing the resulting URL mapping.
- Gate 4 re-derives closed-rule candidates, dependency paths and parser-valid counterfactual
  effects. Giving it resolved relations would erase the boundary it is meant to test.
- The controlled EvidenceForge witness proves a modeled exact-path transfer-to-execution
  nonjoin without common materialized bytes. Its role-specific content reference belongs in
  EvidenceForge's scenario model; an ArtifactForge byte graph cannot repair or prove it.

## Non-leakage contract

### Fixture and benchmark separation

Fixture Core deliberately discards a composed scene's private join before creating its
manifest. `fixture.json` remains answer-free and fixes `benchmark_eligible` to `false` because
its public seed and byte digests already disqualify it as a hold-out. Benchmark staging rejects
fixture and answer metadata at every depth. Public benchmark tasks carry prompts and question
types, closed rule names, selectors, candidate counts and exact artifact inventories, while
answers and private construction truth stay in the evaluator tree. `bench export` creates a
new root containing only canonical `public.json` and `scenarios/`; one aggregate tree
commitment avoids publishing answer-bearing per-file hashes, and `suite_id` binds that document
to every submission. The export is a transfer boundary, not an in-process sandbox, so arbitrary
solver code still requires a separate OS-enforced trust domain without evaluator access. See
[`benchmark-v2.md`](benchmark-v2.md).

A future feature must preserve those separations. In particular, no public fixture record may
serialize `subject`, `role`, `pivot`, `match`, `same_file`, `caused_by`, question, answer or
join edges merely because two values compare equal.

### Task and Shell Link projection

For the Task and Shell Link, projection validates the private target role and byte identity
before retaining only the public guest paths, serialized default streams and ordinary file
digests. The manifest does not publish `scheduled_task`, `shell_link`, target-role or match
edges. Fixture assurance re-derives the bounded path-to-resident relation from public bytes;
it does not recover or expose the discarded private role labels.

## Reconsideration trigger

Revisit this decision only when a named external consumer supplies all three:

1. an input/output contract it will actually call;
2. a digest observation it cannot cheaply and safely derive from `fixture.json` plus the
   payload bytes; and
3. semantics narrow enough to state without converting equality into provenance or causality.

Two independent consumers should need the same serialized relation before a persistent schema
is considered. An internal refactor or a desire for a more general ontology is not a trigger.

## Smallest acceptable future shape

If a real caller later needs SHA-1 or MD5 aliases for fixture files, the first implementation
should be an ephemeral **digest view**, not a graph and not Fixture Manifest v2. It would return
immutable observations shaped like:

```text
(path, size, algorithm, value, basis="captured-payload-bytes")
```

The view would be bound to the existing recipe SHA-256 and payload-tree SHA-256. Algorithms
would be an explicit allowlist of whole-file SHA-256, SHA-1 and MD5; structural hashes would be
excluded. Duplicate bytes at two paths would produce two observations rather than an invented
single entity. No match edges, roles, source locators or causal language would be emitted.

The computation must run **inside** Fixture Core's held verified snapshot. Calling
`verify_fixture(path)` and then reopening `path` is not equivalent: verification's private
snapshot is gone when it returns, creating a time-of-check/time-of-use boundary. Any future
view therefore needs a verified-snapshot callback/context or an in-verifier derivation followed
by the existing fixture/source postconditions.

Do not add this view until a consumer meets the trigger above.
