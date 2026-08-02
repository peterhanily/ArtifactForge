# Identity boundaries

## Decision

ArtifactForge does **not** expose a general digest-evidence graph. This was reconsidered after
Fixture Core, the controlled EvidenceForge witness and the Linux loose profile existed, and was
deferred because no demonstrated consumer needs one.

This is not a placeholder for an obvious missing abstraction. The current identity surfaces
have different evidence bases, audiences and secrecy requirements. Combining them would lose
meaning:

| Surface | What it means | Visibility |
|---|---|---|
| `Content` | digests and structural hashes derived from one emitted binary's bytes | generator-internal/library object |
| `fixture.json` | exact payload path, size and SHA-256 observations bound to a reproducible public recipe | published fixture integrity record |
| `Scene.join` | construction-time truth used to test declared cross-artifact relations | evaluator/private; never served |
| benchmark answer key | expected answers derived from private scene truth | server-side only |
| EvidenceForge content reference RFC | explicit modeled logical identity, which may have no materialized bytes | upstream opt-in scenario contract |

Digest equality can support a lookup. By itself it does not prove that two observations are the
same historical file, that a download caused an execution, or that either record is authentic.
SHA-1 and MD5 remain useful forensic lookup values but are not collision-resistant identity
proofs. IMPHASH, symhash and cdhash are structural or platform identities, not additional
whole-file digest algorithms.

## Consumer audit

The repository has one genuine cross-artifact digest consumer: the Windows Amcache
`FileId`-to-resident-file pivot. The composer emits the private expected relation; Gate 2
independently parses Amcache, hashes captured resident bytes and requires exactly one match.
The reference solver and committed sample perform the same investigation from their own byte
captures. Hiding that lookup behind a graph would add no capability. Publishing the resolved
edge would disclose the benchmark's surviving `amcache_match_sha256` answer.

The other apparent consumers do not need a graph:

- Fixture verification already snapshots, re-hashes and regenerates every declared payload
  byte. A graph containing the same path/SHA-256 pairs would duplicate its manifest.
- Native attestation binds and observes the verified Fixture Core manifest. It needs a byte
  capability and postconditions, not semantic join edges.
- Linux's current relation is an exact guest-path intersection across XDG and Bash history,
  followed by hashing the mapped resident bytes. Neither text artifact emits a digest.
- macOS content digests in private scene truth identify emitted binaries; the cross-artifact
  joins use bundle identifiers and quarantine UUIDs.
- Gate 4 evaluates whether benchmark questions leak. Giving it resolved relations would erase
  the boundary it is meant to test.
- The controlled EvidenceForge witness proves a modeled exact-path transfer-to-execution
  nonjoin without common materialized bytes. Its role-specific content reference belongs in
  EvidenceForge's scenario model; an ArtifactForge byte graph cannot repair or prove it.

## Non-leakage contract

Fixture Core deliberately discards a composed scene's private join before creating its
manifest. `fixture.json` remains answer-free and fixes `benchmark_eligible` to `false` because
its public seed and byte digests already disqualify it as a hold-out. Benchmark staging rejects
fixture and answer metadata at every depth. Public benchmark tasks carry prompts and question
types, while answers and joins stay in the evaluator tree outside the served scene.

A future feature must preserve those separations. In particular, no public fixture record may
serialize `subject`, `role`, `pivot`, `match`, `same_file`, `caused_by`, question, answer or
join edges merely because two values compare equal.

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

Until that consumer exists, the correct implementation is no implementation.
