# Proposal: explicit content identity for transfer-to-execution hash pivots

Measured against EvidenceForge `v1.13.1`
(`c0c619992fa44418a20f9b7d9abbeae750695916`).

The current hash strings are correctly shaped and deterministic, and the documentation
describes the Sysmon values as synthetic. The missing contract is explicit content
identity: a scenario cannot state that an HTTP or SMB file object is the same logical
content as a later process image, so the observations cannot share hashes by
construction.

## Controlled witness

The two-hour controlled scenario contains one positive pair and two negative controls:

1. PowerShell downloads
   `http://203.0.113.10/af-controlled.exe` to
   `C:\Windows\System32\af-controlled.exe`.
2. Thirty seconds later, the same storyline cluster executes that exact path.
3. A second download uses the same basename but a different output path and is not
   executed.
4. An unrelated process image is executed but was not downloaded.

The verifier checks all of the following before comparing hashes:

- `GROUND_TRUTH.json` records the URL, the download output path, and the later
  process image, with `output_file == process_name` for the positive pair;
- the download precedes execution and belongs to the same actor, system, activity,
  and storyline cluster;
- the Zeek `http.log` row joins to the exact `files.log` row through connection UID
  and response FUID;
- the Sysmon row is Event ID 1 for the exact executed image path;
- both emitted SHA1 values reproduce the corresponding `v1.13.1` seed formula;
- the transfer-only and process-only controls remain unrelated.

The resulting positive-pair values are:

| Observation | SHA1 |
|---|---|
| Zeek HTTP response | `35a96017abff36254a0d4a6399c9fbe0cbd8b6a2` |
| Sysmon Event 1 process image | `025ee09748833e745cd43c1d333d6910958f3919` |
| Equal | **No** |

The Zeek value is SHA1 of:

```text
http:203.0.113.10:/af-controlled.exe:123679176:application/x-msdownload
```

The Sysmon value is SHA1 of:

```text
c:\windows\system32\af-controlled.exe:-:-:-:-
```

Reproducer materials are published in
[`peterhanily/ArtifactForge`](https://github.com/peterhanily/ArtifactForge/tree/v0.3.0):

- [`content-identity-witness-v1.13.1.yaml`](https://github.com/peterhanily/ArtifactForge/blob/v0.3.0/integration/evidenceforge/scenarios/content-identity-witness-v1.13.1.yaml)
- [`measure_evidenceforge_witness.py`](https://github.com/peterhanily/ArtifactForge/blob/v0.3.0/scripts/measure_evidenceforge_witness.py)
- [`controlled-content-identity measurement`](https://github.com/peterhanily/ArtifactForge/blob/v0.3.0/measurements/evidenceforge-v1.13.1-controlled-content-identity.json)

The fixture SHA256 is
`9869c71144d43ed471588ce7e423eb5f4b092fcfc5fc17204ee9a63d5b57f2e5`.

This proves that one **modeled logical file** receives different SHA1 values across
the two sources. It does not prove that two digests disagree over shared materialized
bytes: EvidenceForge emits logs and does not materialize this downloaded executable.
Whether logical-file equality should imply hash equality is the design question.

## Stock-run context

The shipped `scenarios/branch-office-example` was also generated without a format
filter. That exact run produced:

| Measure | Result |
|---|---:|
| Hosts with Sysmon logs | 7 |
| Sysmon records with hashes, Event IDs 1 and 7 | 853 |
| Distinct Sysmon SHA1 / SHA256 | 105 / 105 |
| Sysmon Event ID 1 records | 614 |
| Distinct Event ID 1 SHA1 / SHA256 | 78 / 78 |
| Zeek `files.log` rows | 722 |
| Distinct Zeek SHA1 / SHA256 | 119 / 103 |
| Certificate rows | 525 |
| Non-certificate rows | 197 |
| Non-certificate rows with SHA1 | 21 (16 distinct) |
| Non-certificate rows with SHA256 | 0 |
| Same-algorithm Sysmon/Zeek intersections | 0 |
| Transfer/process basename overlap | 0 |

Those disjoint stock sets are useful context, but they are not themselves a defect
reproducer. Certificates and documents are not process images, and the run contains
no basename-matched transfer/execution pair. The controlled witness above supplies
the missing positive relation. Given current analyzers, SHA1 is the practical join
algorithm: HTTP file analysis emits SHA1 for eligible MIME types, while non-certificate
rows in this run emitted no SHA256.

## Current behavior

The two paths use independent synthetic identity domains:

- [`SysmonEventEmitter._generate_hashes`](https://github.com/Cisco-Talos/EvidenceForge/blob/c0c619992fa44418a20f9b7d9abbeae750695916/src/evidenceforge/generation/emitters/sysmon.py#L885-L911)
  hashes a normalized image path plus rendered PE metadata.
- [`file_transfer_hashes`](https://github.com/Cisco-Talos/EvidenceForge/blob/c0c619992fa44418a20f9b7d9abbeae750695916/src/evidenceforge/generation/actions/file_transfer.py#L162-L173)
  hashes a caller-supplied seed. HTTP uses host, normalized URI, body length, and
  MIME type; generic SMB additionally uses its observation FUID.
- HTTP selects SHA1 only for eligible binary MIME types and suppresses hashes when
  analysis is incomplete or times out. Generic SMB currently selects MD5 and/or
  SHA1, or no hash, according to its analyzer profile.

This description should not be generalized to every `files.log` row:

- certificate rows intentionally keep `files.log.sha1 == x509.fingerprint`; their
  MD5 and SHA256 values use a certificate-specific synthetic derivation;
- plaintext SMTP MIME parts hash the generated payload bytes directly;
- OCSP response rows currently run no file-hash analyzer.

There is also a role distinction that matters. A network event can carry both the
process that owns the connection and the response file. The process is PowerShell,
curl, or a browser; it is not the downloaded body. A single top-level
`SecurityEvent.content_identity` would therefore be ambiguous.

## Proposed opt-in contract

Add an explicit, versioned `FileContentIdentity`, resolve it once in the scenario/world
layer, and attach it under role-specific names:

- `ProcessContext.image_content_identity`
- `FileTransferContext.content_identity`

At the scenario boundary, separate fields such as `image_content_ref` on a process
event and `response_content_ref` on an HTTP connection event would resolve to the
same immutable identity. Existing filename, URL, MIME, and PE metadata remain
descriptive attributes; none should be guessed to mean equal content.

The object would hold a standard digest set (`md5`, `sha1`, `sha256`) and provenance
that distinguishes a versioned synthetic identity from hashes computed over bytes
that EvidenceForge actually materializes. `IMPHASH` should remain separate: it is an
import-table identity, not another digest of the whole file.

Each source would still project only what it observed:

- Sysmon may render MD5, SHA1, and SHA256 from the process image identity;
- HTTP may render only SHA1 when that analyzer ran;
- SMB keeps its configured analyzer selection;
- missing or timed-out analysis still renders no file hash;
- certificate, OCSP, and byte-backed SMTP behavior remains unchanged.

## Compatibility

The narrow version is opt-in by reference:

- no `*_content_ref` means the current `v1.13.1` derivation and output remain
  byte-for-byte unchanged;
- an explicit shared reference requests the new equality invariant;
- the derivation domain is versioned and recorded in the generation manifest or
  ground truth;
- changing a derivation version requires a new explicit mode;
- a global heuristic mode, if added later, should default to `legacy` and should
  not become the default before a major release.

## Independent Sysmon inconsistency

The legacy Sysmon path has an independent call-site inconsistency. Event 1 calls
`_generate_hashes(image, host)`, whose host-derived seed omits `Description`. Event 7
calls the same function with
`(FileVersion, Description, Product, Company, OriginalFileName)`, and that branch
includes all five values. The same image path and rendered metadata can therefore
receive different hashes depending on whether it is projected as Event 1 or Event 7.

That is a narrower call-site consistency bug and should be tested and fixed separately
from this RFC, with an explicit decision about deterministic-output compatibility.

## Acceptance tests

The minimum useful test set would cover:

1. No-reference scenarios retain exact legacy digests and serialized output.
2. One HTTP response and later process image sharing a reference have equal SHA1.
3. The HTTP row may omit SHA256 without failing the SHA1 join.
4. The same basename with different references does not join.
5. The same reference remains stable across URI, FUID, timestamp, and observation
   changes.
6. Missing or timed-out analysis still emits no Zeek digest.
7. Certificates retain their X.509 relationship and SMTP retains byte-backed hashes.
8. Event 1 and Event 7 use one standard digest set when given the same explicit image
   identity.

## Decisions requested

1. Is transfer-to-execution content identity a relationship EvidenceForge wants to
   model explicitly?
2. If so, are role-specific context fields plus scenario references the right level,
   rather than emitter-local changes or filename inference?
3. Is reference-level opt-in sufficient compatibility gating, or would you prefer a
   top-level `legacy` / `content_v1` mode as well?
