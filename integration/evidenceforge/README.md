# EvidenceForge content-identity witness and proposed upstream change

**Nothing in this directory is installed or imported at runtime.** It is excluded from the
wheel but deliberately retained as review material in source archives. No ArtifactForge module
imports it; it exists so the option of merging upstream stays open without the coupling leaking
into a package that otherwise stands alone.

The pinned CI witness uses CPython 3.12.13 and the exact runtime closure exported from
EvidenceForge's committed `uv.lock`; [`constraints-v1.13.1.txt`](constraints-v1.13.1.txt)
records both the source commit and upstream lock digest. The measurement record binds that
runtime attestation as well as the scenario and complete output tree.

ArtifactForge has already been mentioned in a
[public EvidenceForge #332 follow-up](https://github.com/Cisco-Talos/EvidenceForge/issues/332#issuecomment-5152265897).
This directory holds a controlled reproducer, a still-local issue draft and design RFC, and
review patches so the formal proposal can be evaluated before any new issue or pull request is
opened:

- [`scenarios/content-identity-witness-v1.13.1.yaml`](scenarios/content-identity-witness-v1.13.1.yaml)
  declares one exact download-to-execution relation plus transfer-only, process-only, and
  same-basename controls.
- [`ISSUE_DRAFT.md`](ISSUE_DRAFT.md) states the measured result and asks whether the relation
  belongs in EvidenceForge's model.
- [`CONTENT_IDENTITY_RFC.md`](CONTENT_IDENTITY_RFC.md) specifies a backward-compatible,
  role-specific content identity.
- [`patches/README.md`](patches/README.md) documents two clean-applying review patches, their
  checksums, application order, full test evidence, compatibility boundary and known limits.

## The constraint of record

EvidenceForge is not a declared ArtifactForge dependency. Two isolated CI jobs install it for
the pinned contract and the default-branch drift canary; the standalone job does not. Nothing
that ships vendors or imports EvidenceForge, and no upstream source tree, branch or repository
is modified or pushed. One contract test temporarily monkeypatches an imported private method
in memory to exercise a seed branch; pytest restores it, and no upstream file is changed.

## The observation and its limit

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

The controlled scenario supplies the missing positive relation. In its ground truth, one
PowerShell process downloads `http://203.0.113.10/af-controlled.exe` to
`C:\Windows\System32\af-controlled.exe`, and the next event in the same SYSTEM/host/activity
cluster executes that exact path. The verifier then follows the exact HTTP UID/response FUID,
the downloader's Sysmon Event 1/Event 11 PID and ProcessGuid, and the executed-image Event 1
PID without inspecting any digest field during selection. A same-basename different-path
download and an unrelated execution must remain negative.

On the output tree bound in
[`measurements/evidenceforge-v1.13.1-controlled-content-identity.json`](../../measurements/evidenceforge-v1.13.1-controlled-content-identity.json),
the eligible complete HTTP response has SHA1
`35a96017abff36254a0d4a6399c9fbe0cbd8b6a2`; the later process image has SHA1
`025ee09748833e745cd43c1d333d6910958f3919`. Each value independently reproduces its pinned
v1.13.1 seed formula, but they do not join.

That proves a mismatch for one **modeled logical file**. It does not prove that two hash
implementations disagree over common bytes: EvidenceForge does not materialize the downloaded
executable. The narrow defensible question is whether an explicitly declared logical-content
relation should preserve a joinable digest across source projections.

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

The controlled record can be reproduced without applying either prototype patch:

```sh
uv venv --python 3.12.13 .venv-ef
uv pip install --python .venv-ef/bin/python \
  --constraint integration/evidenceforge/constraints-v1.13.1.txt \
  "evidence-forge @ git+https://github.com/Cisco-Talos/EvidenceForge@v1.13.1"
.venv-ef/bin/python -m evidenceforge generate \
  integration/evidenceforge/scenarios/content-identity-witness-v1.13.1.yaml \
  -o ef-witness-out
.venv/bin/python scripts/measure_evidenceforge_witness.py measure ef-witness-out \
  --scenario integration/evidenceforge/scenarios/content-identity-witness-v1.13.1.yaml \
  --evidenceforge-version 1.13.1 \
  --evidenceforge-commit c0c619992fa44418a20f9b7d9abbeae750695916 \
  --python-version 3.12.13 \
  --output measured.json
.venv/bin/python scripts/measure_evidenceforge_witness.py check measured.json \
  --run-root ef-witness-out
```

A second measurement constrains any cross-emitter proposal. The same run's Zeek `files.json`
has 722 rows, 119 distinct SHA1 values and 103 distinct SHA256 values. Of those rows, 525 are
certificates and 197 are not; no non-certificate row carries SHA256, while 21 non-certificate
rows carry SHA1, representing 16 distinct values. The same-algorithm Sysmon/Zeek intersections
are zero, but basename overlap is also zero. A meaningful join therefore has to be designed and
tested around a controlled file that appears in both paths, likely using SHA1 given the fields
the non-certificate rows actually carry.

## What a change would have to touch

1. **A scenario/world-level content identity object.** One place that maps a declared logical
   file reference to an immutable digest identity, and to bytes only when bytes are actually
   materialized. Separate transfer and execution events can reference that identity. EvidenceForge
   has per-event `PeContext` data and an HTTP file-download action, but those are distinct
   `SecurityEvent` instances; neither currently proves that a transferred object is the later
   executed object. The shared relation must therefore be explicit cross-event state, not just
   another field surfaced from one event.
2. **Two hash functions rerouted.** `sysmon.py::_generate_hashes` (two call sites) and
   `file_transfer.py::file_transfer_hashes` (three call sites, of which the two SMB seeds are
   not content identity and should stay as they are). A dormant eCAR path is optional.
3. **`GROUND_TRUTH.json`.** It carries no hash labels today, and its schema uses
   `extra="forbid"`, so new fields must be declared and the schema version bumped.

The proposed field is opt-in and disabled by default, so it preserves existing output. An
upstream change should not silently alter every generated dataset.

## Maintenance rationale

Recovering identity by reproducing a private seed construction works:
`artifactforge/ef_seeds.py` verifies every recovery against the emitted digest and refuses
rather than guessing. However, SemVer does not protect that private surface, so it must be
re-verified on every upstream release. An explicit upstream identity would remove that recurring
version-specific reconstruction burden.

## Current status

The controlled positive witness, output-tree-bound measurement, digest-blind selector, and
mutation tests are complete. CI regenerates both the stock run and the controlled witness from
the pinned v1.13.1 source. A role-specific content-identity prototype and the independent
Event 1/Event 7 Description correction clean-apply to that pin and passed the upstream suite as
recorded in `patches/README.md`. Both remain review files here. The issue remains a draft: no
new GitHub issue, pull request, upstream branch or upstream commit has been created from this
material. The existing public #332 follow-up above is the only posted ArtifactForge note this
status statement describes.
