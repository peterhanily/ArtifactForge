# Proposed upstream change: content-first file identity in EvidenceForge

**Nothing in this directory ships.** It is excluded from the wheel, imported by no
ArtifactForge module, and exists so the option of merging upstream stays open without the
coupling leaking into a package that otherwise stands alone.

Nothing here has been proposed to the EvidenceForge maintainers. It is a sketch of what a
contribution would look like, written down so it can be evaluated rather than assumed.

## The constraint of record

ArtifactForge consumes EvidenceForge as an optional development tool. It does not modify it,
does not vendor it, does not monkeypatch it in anything that ships, and does not push
anything to it. This directory is the only place in the repository where in-process patching
of upstream appears at all, and it appears as a demonstration.

## The observation

EvidenceForge computes a file's hashes as digests of a **seed string**, keyed differently per
call site:

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

Zeek's file-transfer path seeds differently again. The consequence is that the same logical
binary carries unrelated hashes depending on which sensor saw it, so the file-hash pivot —
the move a responder reaches for first — does not join anything.

This is not a bug in the sense of a wrong value; every hash is stable, deterministic and
correctly shaped. It is a modelling choice whose cost only appears when someone tries to
pivot on it.

## Measured, on a real run

From `scenarios/branch-office-example` at v1.13.1, read through
`artifactforge/ingest/evidenceforge.py`:

| | |
|---|---|
| Hosts with Sysmon logs | 7 |
| Hashed Sysmon records | 446 |
| Records whose identity is recoverable and verified | 446 (100%) |
| Distinct logical binaries | 93 |
| Seed forms observed | `from_host_metadata` 75, `with_description` 18 |

So the identity *is* fully determined by what upstream already emits — it is simply not
expressed as a digest of anything. That is what makes a change tractable: no information is
missing, only unbound.

A second measurement worth stating, because it constrains any cross-emitter claim: in a stock
run, no non-certificate `files.log` record carries a SHA256 at all. HTTP records carry SHA1 at
best. Any Zeek-side join has to be specified on SHA1.

## What a change would have to touch

Deliberately understated in earlier drafts of this plan, so stated carefully here.

1. **A content identity object.** One place that maps a logical file to bytes, so a digest is
   a digest of something. EvidenceForge already has `PeContext` on its canonical event and an
   HTTP file-download action on the main generation path, so this is surfacing an existing
   internal primitive rather than inventing one.
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

Ask. A one-paragraph issue describing the file-identity event type and the join it enables,
carrying the numbers above, costs nothing and settles whether the rest is worth writing.
