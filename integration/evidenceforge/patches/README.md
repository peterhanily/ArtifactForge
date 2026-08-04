# EvidenceForge v1.13.1 review patches

These independent prototypes are for upstream review. They have not been applied to,
committed in, proposed to, or pushed to the EvidenceForge repository. They are not
Cisco-authored or Cisco-endorsed. New files in the patches are copyright Peter Hanily
and MIT-licensed; existing upstream file headers are preserved.

## Source pin and integrity

Both patches target the unmodified `Cisco-Talos/EvidenceForge` v1.13.1 source at:

```text
c0c619992fa44418a20f9b7d9abbeae750695916
```

Patch SHA256 values:

```text
bbbb4b090ba32694d8980bf260a4b671f11065b3f34494c87d6f387fc0821ad5  content-identity-prototype-v1.13.1.patch
0f5232670ac2971568b0e0e7af1ec4efdfd4f2c0ab9ecf4ef1bad74dc47bdf84  sysmon-eid1-eid7-description-v1.13.1.patch
```

## Application order

From a clean EvidenceForge checkout at the pinned commit, apply the content-identity
prototype first and the independent legacy Sysmon correction second:

```bash
test "$(git rev-parse HEAD)" = c0c619992fa44418a20f9b7d9abbeae750695916
git status --short
git apply --check /path/to/ArtifactForge/integration/evidenceforge/patches/content-identity-prototype-v1.13.1.patch
git apply /path/to/ArtifactForge/integration/evidenceforge/patches/content-identity-prototype-v1.13.1.patch
git apply --check /path/to/ArtifactForge/integration/evidenceforge/patches/sysmon-eid1-eid7-description-v1.13.1.patch
git apply /path/to/ArtifactForge/integration/evidenceforge/patches/sysmon-eid1-eid7-description-v1.13.1.patch
git diff --check
```

`git status --short` should be empty before application.

## Patch 1: role-specific file-content identity

`content-identity-prototype-v1.13.1.patch` implements an opt-in join between an HTTP
response and a process image:

- scenarios declare `content_identities`, and unknown references fail validation;
- `response_content_ref` and `image_content_ref` resolve once through a
  scenario-scoped registry using the versioned domain
  `evidenceforge:file-content:v1:{scenario}:{reference}`;
- response identity belongs to `FileTransferContext.content_identity`, while process
  identity belongs to `ProcessContext.image_content_identity`; one downloader event
  may carry distinct values for both roles;
- Zeek projects only standard digests for analyzers that ran, and Sysmon Event 1
  projects the same MD5/SHA1/SHA256 set for an explicitly identified process image;
- Sysmon Event 7 remains on its loaded-image legacy path, and IMPHASH remains the
  separate legacy PE-import projection rather than part of the shared digest set;
- explicit response identities force a `files` observation when the HTTP response can
  carry a body; impossible method/status/body/connection combinations fail instead of
  silently dropping the relation;
- analyzer loss or timeout may still leave the `files` observation without hash fields,
  while canonical world truth remains attached;
- opted-in ground truth and observation manifests use schema version 2 and record
  role-specific reference, derivation version, provenance, and expected digests;
  scenarios without declarations retain schema version 1 and the legacy path.

### Limitations

The digests do not cover materialized executable bytes. `synthetic_v1` hashes a
versioned scenario/reference seed. Patch 1 supports only the controlled direct,
plaintext-HTTP path. HTTPS decryption, explicit proxies, SMB, SMTP migration, content
transformations, and byte-backed identities remain out of scope. The patch rejects
unknown references but does not warn about a reference used only once or prove path
continuity independently of the author's explicit reference.

## Patch 2: legacy Sysmon Description seed consistency

`sysmon-eid1-eid7-description-v1.13.1.patch` is independent. It includes `Description`
in the host-derived Sysmon hash seed so the same path and rendered PE metadata take the
same legacy seed shape in Event 1 and Event 7. Its focused regression also proves that
changing only Description changes the result.

Unlike Patch 1, this correction is not output-preserving: accepting it changes
deterministic legacy Sysmon hashes whose host-derived metadata has a Description. It
therefore needs its own upstream compatibility and migration decision.

## Validation performed

Validation ran manually in temporary detached EvidenceForge worktrees. ArtifactForge CI
does not currently apply these patches.

After applying both patches in the order above:

```bash
ruff check <all changed Python files>
```

Result: `All checks passed!`

The targeted gate covered the new generated-scenario test plus Sysmon, storyline,
schema, ground-truth, manifest, proxy, network-action, DNS-isolation, event-model, and
legacy-output regressions:

```bash
PYTHONPATH=src python -m pytest -q \
  tests/unit/test_content_identity.py \
  tests/unit/test_sysmon_hash_description.py \
  tests/unit/test_dns_realism.py::TestDnsSupportQueryTypes::test_default_ad_site_srv_query_resolves_to_dc \
  tests/unit/test_storyline_command_networks.py \
  tests/unit/test_storyline_http_sizing.py \
  tests/unit/test_storyline_network.py \
  tests/unit/test_sysmon_new_events.py \
  tests/unit/test_sysmon_emitter.py \
  tests/unit/test_ground_truth.py \
  tests/unit/test_observation_manifest.py \
  tests/unit/test_models.py \
  tests/unit/test_network_transaction_contract.py \
  tests/unit/test_explicit_proxy.py \
  tests/unit/test_events.py \
  tests/unit/test_logonid_scoping.py \
  tests/unit/test_output_equivalence.py
```

Result: `508 passed in 4.10s`.

The integration-style unit test constructs a validated scenario, runs
`GenerationEngine.generate()`, and then independently parses emitted Zeek `files.json`,
Sysmon XML, `GROUND_TRUTH.json`, and `OBSERVATION_MANIFEST.json`. It verifies the SHA1
join without using a digest to select the records, verifies distinct downloader-image
and response identities on one event, and restores the mutable DNS registry after the
run.

The exact exported pair then passed the complete runnable unit suite:

```bash
PYTHONPATH=src python -m pytest -q tests/unit \
  --deselect tests/unit/test_splunk_harness.py::test_splunk_runtime_mounts_apps_without_overriding_splunk_etc
```

Result: `4829 passed, 23 skipped, 1 deselected in 109.67s`.

For a separate opt-out compatibility check, Patch 1 alone was applied and the existing
unannotated ArtifactForge controlled scenario was regenerated. Its complete 17-file
output tree was byte-for-byte identical to the tree emitted by unmodified v1.13.1.

The one deselected stock Splunk harness test opens a localhost listening socket; the
validation sandbox rejects that bind with `PermissionError: [Errno 1] Operation not
permitted`. It is unrelated to either patch. This manual gate is not continuous upstream
CI coverage.
