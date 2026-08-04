# RFC: explicit file-content identity in EvidenceForge

| Property | Value |
|---|---|
| Status | Proposed |
| Target baseline | EvidenceForge `v1.13.1` |
| Compatibility posture | Opt-in; legacy output preserved by default |

## Summary

EvidenceForge should be able to model an explicit relationship in which a file
observed in a network transfer is the same logical content later observed as a
process image. The relationship should be represented once in the scenario/world
layer and projected into each event through role-specific canonical contexts.

This RFC does not redefine every existing synthetic hash. It introduces an optional,
versioned `FileContentIdentity` for scenarios that declare content equality. The first
implementation covers an HTTP response and a later process image; scenarios without
content references retain their current output.

## Motivation

EvidenceForge currently has several valid but independent notions of file identity:

- Sysmon process and image-load hashes are deterministic digests of image-path and PE
  metadata seeds.
- HTTP file hashes are deterministic digests of host, URI, body length, and MIME type.
- Generic SMB hashes may include the per-observation FUID.
- Staged SMB archive hashes use archive path and transfer size.
- SMTP MIME-part hashes are computed over generated payload bytes.
- X.509 rows preserve the certificate SHA1 fingerprint and synthesize the other
  algorithms through a certificate-specific path.

These rules produce correctly shaped, stable source-local values. They do not provide
a way to state that two events represent the same logical content.

A controlled `v1.13.1` witness makes the missing relationship concrete. One storyline
cluster downloads an HTTP response to
`C:\Windows\System32\af-controlled.exe` and executes that exact path thirty seconds
later. Ground truth, HTTP UID/FUID correlation, and the selected Sysmon Event 1 record
establish the modeled relation. The independently verified SHA1 values are:

- Zeek: `35a96017abff36254a0d4a6399c9fbe0cbd8b6a2`
- Sysmon: `025ee09748833e745cd43c1d333d6910958f3919`

Both reproduce their current seed formulas. No common executable bytes are
materialized, so this is a logical-content witness rather than a claim that two hash
implementations disagree over the same bytes.

## Goals

- Let a scenario explicitly bind transfer content to a later process image.
- Compute the identity once and reuse it across separate `SecurityEvent` instances.
- Keep process-owner identity distinct from response-body identity on network events.
- Preserve source-native analyzer behavior and missing-data behavior.
- Distinguish synthetic identities from hashes computed over materialized bytes.
- Preserve exact legacy output when the feature is not requested.
- Give ground truth and evaluators a stable, versioned relationship to validate.

## Non-goals

- Inferring equality from matching filenames, basenames, paths, URLs, sizes, or MIME
  types.
- Making every generated digest a hash of a shipped file.
- Making a downloader process hash equal to the downloaded response hash.
- Forcing SHA256 into sources whose modeled analyzer ran only SHA1 or MD5.
- Treating `IMPHASH` as a whole-file content digest.
- Replacing certificate fingerprint or SMTP payload semantics.
- Retrofitting unrelated stock traffic so that its global hash-set intersection is
  non-empty.

## Role-specific fields

A canonical connection event can contain both a `ProcessContext` and a
`FileTransferContext`:

```text
PowerShell process identity
          |
          v
HTTP connection event -----> HTTP response file identity
                                  |
                                  v
                         later process image identity
```

The process attached to the connection owns the socket. It is usually PowerShell,
curl, wget, or a browser. The `FileTransferContext` describes the response body. Those
are two different files in the same event, so a top-level
`SecurityEvent.content_identity` cannot represent both safely.

The canonical roles should instead be:

- `ProcessContext.image_content_identity`
- `FileTransferContext.content_identity`

If image-load identity is later migrated to the same model, it should likewise use an
unambiguous field on `ImageLoadContext`, not borrow the owning process identity.

## Data model

Proposed dataclasses:

```python
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class FileDigestSet:
    md5: str
    sha1: str
    sha256: str


@dataclass(frozen=True, slots=True)
class FileContentIdentity:
    identity_id: str
    digests: FileDigestSet
    provenance: Literal["synthetic_v1", "materialized_bytes"]
    derivation_version: int = 1
```

Context additions:

```python
@dataclass(slots=True)
class ProcessContext:
    # Existing fields remain unchanged.
    image_content_identity: FileContentIdentity | None = None


@dataclass(slots=True)
class FileTransferContext:
    # Existing fields remain unchanged during migration.
    content_identity: FileContentIdentity | None = None
```

The existing flat `md5`, `sha1`, and `sha256` fields on `FileTransferContext` can
remain as compatibility projections initially. When `content_identity` is present,
one planner/action helper must populate the projected fields, and validation must
reject disagreement between the object and the flattened values.

`FileDigestSet` excludes `IMPHASH`. A PE import hash is derived from normalized imports,
not from all file bytes. The legacy synthetic IMPHASH may remain as a separate
projection until EvidenceForge has a canonical PE import identity.

## Scenario schema

The minimal explicit schema is:

```yaml
content_identities:
  af-controlled-v1:
    kind: synthetic_file

storyline:
  - id: download
    events:
      - type: connection
        service: http
        # Existing HTTP fields omitted.
        response_content_ref: af-controlled-v1

  - id: execute
    events:
      - type: process
        process_name: 'C:\Windows\System32\af-controlled.exe'
        image_content_ref: af-controlled-v1
```

Names are scenario-scoped. Two references with the same basename are different
content. One reference reused at different URLs, paths, times, or observation FUIDs
is the same content.

The first implementation may derive `synthetic_v1` digests from a domain-separated,
versioned scenario/ref identity. Those values must continue to be documented as
synthetic. When actual bytes exist, as they do for generated SMTP MIME parts, the
registry may construct `materialized_bytes` identities from those bytes instead.
Identity equality is the contract; this RFC does not require inventing unshipped bytes
merely to change the wording around a synthetic digest.

## Ownership and flow

The scenario compiler or world planner owns the scenario-scoped registry:

```text
content reference
      |
      v
scenario/world FileContentIdentity registry
      |                                  |
      v                                  v
HTTP/SMB action bundle             process action bundle
      |                                  |
      v                                  v
FileTransferContext                 ProcessContext
.content_identity                   .image_content_identity
      |                                  |
      v                                  v
Zeek source projection              Sysmon source projection
```

Required invariants:

1. A reference resolves once per scenario to one immutable identity.
2. Emitters do not construct or mutate shared identities.
3. Identical references produce identical standard digests across event instances.
4. Different references do not collapse merely because descriptive metadata matches.
5. Byte-backed identities reject a conflicting digest declaration.
6. Reference and derivation version participate in stable action IDs where changing
   either would change emitted evidence.

## Source projections

### Sysmon

When `ProcessContext.image_content_identity` is present, Event 1 renders MD5, SHA1,
and SHA256 from that identity. Without it, the legacy path remains unchanged.

Signature validation state is not content identity. File version, product, company,
description, original filename, and path remain rendered metadata but do not override
an explicit identity.

`IMPHASH` follows a separate PE import-identity rule. Until that rule exists, an
explicit standard digest identity may coexist with the legacy synthetic IMPHASH.

### Zeek HTTP

When `FileTransferContext.content_identity` is present, the action bundle selects
digests from it according to the analyzers that ran. In `v1.13.1`, eligible HTTP
responses generally expose SHA1 only. The RFC requires the SHA1 to join; it does not
require a fabricated SHA256 field.

If analysis is missing or timed out, no hash is rendered even though the underlying
logical identity is known to the generator. This preserves the distinction between
world truth and sensor observation.

### Zeek SMB

Generic SMB traffic without a content reference keeps its current observation-scoped
behavior. An SMB transfer with an explicit content reference projects the configured
MD5 and/or SHA1 from the canonical identity. The FUID remains an observation ID and
must not alter explicit content digests.

### SMTP

SMTP MIME parts already hash generated payload bytes. They should retain those values
and may be represented as `materialized_bytes` identities if migrated to the common
type.

### X.509 and OCSP

Certificate `files.log.sha1` must remain equal to the corresponding X.509 fingerprint.
Certificate MD5/SHA256 generation is a specialized compatibility path until canonical
DER bytes exist. OCSP response rows currently run no file-hash analyzer and remain
unchanged.

## Ground truth and provenance

Ground truth should serialize enough information to evaluate the declared relation
without exposing the internal registry object:

- the role-specific reference (`image_content_ref` or `response_content_ref`);
- `content_identity_version`;
- the standard expected digests for instructor/evaluation output;
- provenance (`synthetic_v1` or `materialized_bytes`).

Because the ground-truth models reject undeclared fields, these additions require an
explicit schema update and schema-version decision. Student-facing logs continue to
contain only source-native fields; they do not receive a plaintext content reference.

The generation or observation manifest should record the selected identity model and
derivation version. This makes a hash-changing opt-in reproducible and auditable.

## Compatibility

### Default behavior

No content reference means no output change. Existing scenarios, tests, fixtures, and
downstream parsers must continue to receive the exact legacy values.

The reference itself is therefore the compatibility gate for the first release. A
global setting is unnecessary unless heuristic or automatic identity assignment is
introduced.

### Optional global mode

If maintainers prefer an explicit generator-wide switch, use a versioned enum such as:

```yaml
hash_identity_mode: legacy  # legacy | content_v1
```

It must default to `legacy`. The selected value must appear in provenance. Changing the
default belongs in a major release because it would alter deterministic datasets.

### Derivation stability

The synthetic derivation must use a domain string containing its version, for example
`evidenceforge:file-content:v1`. Once released, its output is immutable. A changed
formula becomes `v2`; it does not silently replace `v1`.

## Migration plan

### Phase 1: output-preserving foundation

- Add `FileDigestSet`, `FileContentIdentity`, and a scenario-scoped registry.
- Add the two optional role-specific context fields.
- Add schema support for content declarations and references.
- Keep all no-reference outputs unchanged.
- Record identity mode/version in provenance only when the feature is used.

### Phase 2: controlled HTTP-to-process path

- Resolve `response_content_ref` in the HTTP file-transfer action bundle.
- Resolve `image_content_ref` in the process action bundle.
- Project only algorithms enabled by the source.
- Serialize role-specific references and expected digests in ground truth.
- Add one minimal positive pair plus same-basename and unrelated-process controls.

### Phase 3: broader explicit relationships

- Extend explicit references to SMB transfers and file-system contexts.
- Bind receiver-side file creation to the same identity where the action bundle models
  it.
- Allow later process creation to resolve identity through an explicitly bound local
  file path, without basename heuristics.
- Optionally migrate byte-backed SMTP content to the shared type.

### Phase 4: legacy derivation cleanup

- Move output-preserving legacy hash construction out of emitters and into the owning
  generation/action layer.
- Retain a legacy projection until its documented removal window.
- Consider a future default change only with a major-version migration guide.

## Validation

Scenario validation should:

- reject an unknown content reference;
- reject duplicate declarations with conflicting provenance or digests;
- reject a byte-backed declaration whose computed digests disagree;
- restrict `response_content_ref` to response-bearing file-transfer events;
- restrict `image_content_ref` to process image identity;
- warn when a reference occurs only once because it creates no cross-event relation;
- allow the same reference at multiple paths and URLs;
- require explicit author intent rather than infer equality from metadata.

Runtime validation should:

- assert that flattened `FileTransferContext` digests match its identity;
- compare algorithm names, not values from different algorithms;
- preserve hash absence after analyzer loss or timeout;
- fail generation if one reference resolves to conflicting byte-backed identities.

## Test plan

### Unit tests

- One `synthetic_v1` reference produces stable MD5, SHA1, and SHA256.
- Different references produce different digest sets.
- One byte payload produces the standard library's three expected digests.
- An unknown or conflicting reference fails validation.
- Analyzer projection is case-insensitive and emits only requested algorithms.
- Missing/timed-out analysis emits no hash.
- Explicit process identity overrides path/metadata seed derivation for standard
  digests.
- Standard digests do not change when only signature status changes.
- `IMPHASH` is not sourced from `FileDigestSet`.

### Compatibility tests

- Existing no-reference Sysmon fixtures remain byte-for-byte identical.
- Existing HTTP, SMB, certificate, OCSP, and SMTP fixtures remain identical.
- Current build/version-sensitive legacy Sysmon tests continue to pass.
- Scenario files without the new fields serialize and generate exactly as before.

### Integration tests

- An explicit HTTP response and later process image sharing a reference have equal
  normalized SHA1 values.
- HTTP may lack SHA256 while the SHA1 join remains valid.
- The same content observed under different FUIDs keeps the same digest.
- The same basename with different references does not join.
- A transfer-only reference and process-only reference do not create false pairs.
- Ground truth identifies exactly the declared pair and no unrelated global matches
  are required.
- Certificates are excluded from process-image join assertions.
- SMTP digests still equal hashes of the generated payload bytes.

### Property tests

- For every declared identity and every common enabled algorithm, all source
  projections equal the registry digest after case normalization.
- Observation IDs, timestamps, paths, and URLs cannot change an explicit identity.
- Analyzer suppression cannot reveal a digest that the source did not observe.

## Independent Sysmon seed inconsistency

`v1.13.1` has two seed layouts inside
`SysmonEventEmitter._generate_hashes`:

- Event 1 calls the host-derived branch, which uses image path, FileVersion, Product,
  Company, and OriginalFileName but omits Description.
- Event 7 supplies a rendered identity tuple whose first five values include
  Description.

Consequently, the same image path and rendered PE metadata can hash differently by
event type. This is a direct call-site inconsistency, independent of the
transfer-to-execution feature.

Resolution:

1. Add a focused regression that passes the same path and metadata through both seed
   branches and exposes the mismatch.
2. Define one legacy seed builder and decide which existing projection to preserve.
3. Treat any changed deterministic output as an explicit compatibility decision.
4. In content-identity mode, have Event 1 and a future
   `ImageLoadContext.image_content_identity` consume the same standard digest set when
   they truly refer to the same image content.

Track this bug in a separate issue or PR so the broader RFC does not block the narrower
correction.

## Open questions

1. Should scenario references resolve automatically from their name, or should every
   identity declaration include an explicit stable seed?
2. Should byte-backed content allow user-supplied digests when bytes are unavailable,
   or should that provenance be named separately from `materialized_bytes`?
3. Is reference-level opt-in sufficient, or is a top-level mode preferable for release
   communication?
4. Which receiver-side file actions should participate in the first implementation?
5. Should ground truth expose full expected digests, or only the content reference and
   derivation version?
