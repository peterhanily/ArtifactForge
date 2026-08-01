# Proposed upstream change: content-first file identity in EvidenceForge

**Nothing in this directory ships.** It is excluded from the wheel, imported by no
ArtifactForge module, and exists so the option of merging upstream stays open without the
coupling leaking into a package that otherwise stands alone.

Nothing here has been proposed to the EvidenceForge maintainers. It is a sketch of what a
contribution would look like, written down so it can be evaluated rather than assumed.

## The constraint of record

EvidenceForge is not a declared ArtifactForge dependency. Two isolated CI jobs install it for
the pinned contract and the default-branch drift canary; the standalone job does not. Nothing
that ships vendors or imports EvidenceForge, and no upstream source tree, branch or repository
is modified or pushed. One contract test temporarily monkeypatches an imported private method
in memory to exercise a seed branch; pytest restores it, and no upstream file is changed.

## The observation

EvidenceForge computes these synthetic hash fields as digests of **seed strings**, with seed
construction local to the emitting path:

```python
# src/evidenceforge/generation/emitters/sysmon.py, v1.13.1
seed = normalized_image
if rendered_identity is not None:
    seed = f"{normalized_image}:{':'.join(str(p) for p in rendered_identity[:5])}"
elif host is not None and not isinstance(host, str):
    fv, _desc, prod, company, orig = cls._get_pe_metadata(image, host)
    seed = f"{normalized_image}:{fv}:{prod}:{company}:{orig}"
sha256 = hashlib.sha256(seed.encode(), usedforsecurity=False).hexdigest().upper()
```

Zeek's file-transfer path uses a different seed domain. In the measured stock run the resulting
same-algorithm Sysmon and Zeek sets are disjoint. That observation alone does not show that the
same logical file received two different hashes: there is no basename-matched transfer and
execution in that run. A controlled positive witness is needed to make the causal claim.

This does not make an individual value malformed: the hashes are stable, deterministic and
correctly shaped. Whether separate emitter domains are a defect depends on whether a
cross-emitter content join is an intended invariant; the stock run alone cannot answer that.

## Measured, on a real run

From an unmodified run of `scenarios/branch-office-example` at v1.13.1, read through
`artifactforge/ingest/evidenceforge.py`:

| | |
|---|---|
| Hosts with Sysmon logs | 7 |
| Sysmon records carrying SHA256 (Event IDs 1 and 7) | 853 |
| Records whose Sysmon identity is recoverable and verified | 853 (100%) |
| Distinct Sysmon SHA1 / SHA256 / logical identities | 105 / 105 / 105 |
| Seed forms observed | `from_host_metadata` 78, `with_description` 27 |
| Event ID 1 only | 614 records, 78 distinct SHA1 and 78 distinct SHA256 |

So the adapter can recover the Sysmon-local logical identity from the fields upstream emits and
verify every recovery against its emitted SHA256. This does not bind that identity to a Zeek
file-transfer row or to bytes shared by both emitters.

A second measurement constrains any cross-emitter proposal. The same run's Zeek `files.json`
has 722 rows, 119 distinct SHA1 values and 103 distinct SHA256 values. Of those rows, 525 are
certificates and 197 are not; no non-certificate row carries SHA256, while 21 non-certificate
rows carry SHA1, representing 16 distinct values. The same-algorithm Sysmon/Zeek intersections
are zero, but basename overlap is also zero. A meaningful join therefore has to be designed and
tested around a controlled file that appears in both paths, likely using SHA1 given the fields
the non-certificate rows actually carry.

## What a change would have to touch

Deliberately understated in earlier drafts of this plan, so stated carefully here.

1. **A scenario/world-level content identity object.** One place that maps a logical file to
   bytes and can be referenced by separate transfer and execution events. EvidenceForge has
   per-event `PeContext` data and an HTTP file-download action, but those are distinct
   `SecurityEvent` instances; neither currently proves that a transferred object is the later
   executed object. The shared relation must therefore be explicit cross-event state, not just
   another field surfaced from one event.
2. **Two hash functions rerouted.** `sysmon.py::_generate_hashes` (two call sites) and
   `file_transfer.py::file_transfer_hashes` (three call sites, of which the two SMB seeds are
   not content identity and should stay as they are). A dormant eCAR path is optional.
3. **`GROUND_TRUTH.json`.** It carries no hash labels today, and its schema uses
   `extra="forbid"`, so new fields must be declared and the schema version bumped.

Gated off by default, it changes no existing output. That is the only version worth
proposing: a contribution that silently alters every generated dataset is one no maintainer
should accept.

## Why it is worth doing at all

Because the alternative is a subscription. Recovering identity by reproducing a private seed
construction works — `artifactforge/ef_seeds.py` does it, verifies every recovery against the
emitted digest, and refuses rather than guessing — but it is a private surface that SemVer
does not protect, and it has to be re-verified on every upstream release. Contribution is the
only version of this that stops the clock.

## Before any of it

Build a controlled positive witness in which one independently paired content identity is both
transferred and executed. Only then ask whether the file-identity relation and join are wanted;
the stock-run disjoint sets are not enough to label the current behavior a same-file defect.
