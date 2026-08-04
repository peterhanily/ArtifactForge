# ArtifactForge

[![CI](https://github.com/peterhanily/ArtifactForge/actions/workflows/ci.yml/badge.svg)](https://github.com/peterhanily/ArtifactForge/actions/workflows/ci.yml)

ArtifactForge creates deterministic forensic fixture files for Windows, macOS, and Linux. It
emits real file formats, derives hashes from the emitted bytes, and checks the results with
independent readers.

> [!CAUTION]
> ArtifactForge is experimental. Every artifact is synthetic and was collected from no real
> incident or host. Do not add its values to blocklists, detections, or threat-intelligence
> systems. Do not upload generated samples to public malware services such as VirusTotal.

This is an independent personal project. It is not affiliated with or endorsed by Cisco,
Cisco Talos, EvidenceForge, Microsoft, Apple, or any other organisation named here. The work
began in response to [EvidenceForge issue #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332).

![ArtifactForge turns a recipe and seed into deterministic bytes, then checks format validity, identity joins, and inertness](docs/assets/overview.svg)

## Quick start

ArtifactForge requires Python 3.11 or newer. The examples below use
[uv](https://docs.astral.sh/uv/).

```sh
uv venv
uv pip install -e ".[dev]"

uv run artifactforge fixture build examples/fixtures/windows-loose-v2.json out/windows
uv run artifactforge fixture verify out/windows --assurance
uv run artifactforge fixture release out/windows out/windows.tar --assurance
```

Run the complete test and gate suites with:

```sh
uv run pytest -q
uv run artifactforge scorecard
```

The [`samples/`](samples/) directory contains generated Windows, macOS, and Linux scenes with
parser observations and byte-derived answer keys. These samples are documentation fixtures,
not benchmark data.

## What it produces

| Platform | Artifact files | Validation |
|---|---|---|
| Windows | PE, Amcache and Software hives, MAM-compressed SCCA v30 Prefetch, Chromium `History`, `Zone.Identifier`, disabled Task Scheduler XML, Shell Link | pefile and LIEF; regipy and libregf; pyscca and Dissect; SQLite plus a bounded byte reader; ElementTree plus a byte reader; liblnk and LnkParse3 |
| macOS | arm64 Mach-O, knowledgeC, TCC, QuarantineEventsV2, quarantine xattr values, LaunchAgent plists | LIEF and macholib; SQLite plus a bounded byte reader; plistlib plus an independent binary-plist reader; two quarantine-xattr readers |
| Linux | ELF64 x86-64, XDG autostart entries, timestamped Bash history | LIEF and pyelftools; PyXDG plus a raw reader; dissect.target plus a raw reader |

The current public fixture profiles are:

- `windows-loose-v2`
- `macos-14-loose-v2`
- `linux-glibc-x86_64-loose-v2`

They describe loose artifacts and logical filesystem metadata. They do not describe a disk
image, an installed host, or proof that any persistence mechanism was activated.

## Assurance model

ArtifactForge separates four questions that are often blurred together:

| Gate | Question | Evidence |
|---|---|---|
| 1. Validity | Can independent readers decode the same bytes and agree on the declared profile? | Parser acceptance, typed agreement, and profile checks |
| 2. Identity | Do cross-artifact references resolve to the bytes actually shipped? | Fresh digests, structural hashes, paths, UUIDs, sizes, and mutation tests |
| 3. Inertness | Are executable bytes within the declared inert profile, and are synthetic artifacts disclosed? | Byte inspection, format-specific limits, and in-band markers |
| 4. Solvability | Does the experimental benchmark resist its registered shortcut attacks? | Closed rules, counterfactuals, exact permutation tests, and positive controls |

Gate 1 does not turn parser acceptance into realism. Gate 2 proves only the declared joins.
Gate 3 does not execute generated binaries. Gate 4 validates a finite local benchmark surface;
it does not create a reportable public performance score.

The main identity rule is simple: materialize a file once, then derive its digests and
structural hashes from those bytes. The Amcache `FileId`, PE hashes, browser relation, task
target, Shell Link target, macOS quarantine UUID relation, and Linux guest-path relation are
checked against the files in the scene. Deliberate stale and absent decoys are identified as
such and do not claim to represent resident bytes.

Every executable profile is intentionally narrow. Windows PE and macOS Mach-O code sections
contain only their declared return stub. Linux ELFs contain a direct `exit(0)` body, but their
named dynamic loader would run first if somebody executed them. ArtifactForge never executes
an ELF, runs `ldd`, launches a desktop entry, sources shell history, registers a task, resolves
a Shell Link, or activates a LaunchAgent. See
[`docs/inert-by-construction.md`](docs/inert-by-construction.md) and
[`SECURITY.md`](SECURITY.md) for the exact boundary.

### Important limits

- Parser agreement covers the documented subset of each format. It is not native provenance
  or a general claim about the full format.
- Current Prefetch scenes use deterministic MAM algorithm-4 compression around an SCCA v30
  variant-1 record. A strict expected-size reader owns the compressed framing. `pyscca` and
  Dissect agree on the typed semantic view, but Dissect is not used as a framing oracle because
  its EOF-driven decoder exposes the current three post-output bytes. ArtifactForge does not
  run a Plaso extraction, so pyscca acceptance is not presented as proof of Plaso extraction.
- The public `build_prefetch` and `prefetch_name_hash` APIs remain frozen v17/XP compatibility
  surfaces. Current scene generation calls `build_prefetch_v30` explicitly.
- The Windows Task and Shell Link are configuration and reference evidence. They do not prove
  registration, activation, or execution.
- Current Fixture ABI v2 databases use ArtifactForge's owned SQLite leaf writer. Frozen
  Fixture ABI v1 vectors remain parse-only and retain their older producer boundary.
- Native Windows canaries exist for Prefetch decompression, task loading, and Shell Link
  loading. Hosted schema-v6 runs produced diagnostic failure evidence; the first complete,
  passing hosted observation is still pending schema-v7 confirmation.

The complete format-by-format limitations are in [`KNOWN_TELLS.md`](KNOWN_TELLS.md).

## Samples

| Scene | Main investigation pivot |
|---|---|
| [Windows dropper](samples/01-windows-dropper/) | Resident PE bytes joined to Amcache, Prefetch, browser download evidence, task XML, and a Shell Link |
| [macOS quarantined app](samples/02-macos-quarantined-app/) | Quarantine xattr UUID joined to QuarantineEventsV2, plus modeled TCC and knowledgeC records |
| [Linux autostart and history](samples/03-linux-autostart-history/) | ELF bytes joined to XDG autostart records and timestamped Bash history |

Regenerate the gallery with:

```sh
./scripts/make-samples.sh
```

## EvidenceForge relationship

EvidenceForge is not a runtime or development dependency. ArtifactForge includes an isolated
adapter and contract tests for its synthetic log model. The distribution name is
`evidence-forge`; the import name is `evidenceforge`.

On a fresh, unmodified EvidenceForge v1.13.1 `branch-office-example` run, the adapter observed
**7 hosts, 853 Sysmon records carrying SHA256, all 853
recovered and verified** against the hashes EvidenceForge emitted, resolving to 105
distinct Sysmon logical identities. The verified seed forms were `from_host_metadata` for 78
identities and `with_description` for 27. Event ID 1 gives 614 records and 78 distinct
SHA1/SHA256 values.

The same run's Zeek `files.json` has 722 rows: 525 certificate and 197 non-certificate rows,
with 119 distinct SHA1 and 103 distinct SHA256 values overall. The same-algorithm Sysmon and
Zeek sets are disjoint, but their basenames are also disjoint. That stock scenario therefore
shows separate emitter-local identity domains, not a controlled same-file mismatch.

A separate controlled scenario models one HTTP download to an exact path followed by execution
of that path. It includes same-name and unrelated-path controls and shows that the Zeek and
Sysmon seed formulas do not join for that modeled logical file. This is a relationship between
modeled events, not proof of shared materialized file bytes.

The source records and upstream-ready material are in
[`measurements/`](measurements/) and
[`integration/evidenceforge/`](integration/evidenceforge/). ArtifactForge has already been
mentioned in a
[public EvidenceForge #332 follow-up](https://github.com/Cisco-Talos/EvidenceForge/issues/332#issuecomment-5152265897).
No formal issue or pull request has been opened from the local drafts.

To run the pinned contract locally:

```sh
uv pip install "evidence-forge @ git+https://github.com/Cisco-Talos/EvidenceForge@v1.13.1"
uv run python -m evidenceforge generate scenario.yaml -o ef-out
ARTIFACTFORGE_EF_OUT=ef-out uv run pytest -q tests/ef_contract/
```

## Experimental benchmark

Benchmark v1 is withdrawn because shortcut attacks and answer leakage invalidated it.

V2 asks five scalar questions per scene under two closed rules. Each question resolves one of
five candidates from values parsed out of at least two artifacts. The five answers form a
bijection with exact 20% candidate chance. Gate 4 checks a finite registered attack surface,
parser-valid counterfactuals, and exact permutation inference. Every v2 suite is permanently
non-reportable because callers supply the raw keys.

V3 creates a separate evaluator ceremony, public export, precommitment, one-shot ledger, and
retired evidence report. The API enforces disjoint evaluator and ledger roots on supported
POSIX hosts. It cannot prove solver isolation, unique ledger designation, ceremony
authenticity, or independent witnessing. Every retired report therefore remains
`reportable: false`.

See [`docs/benchmark-v2.md`](docs/benchmark-v2.md) for the frozen diagnostic contract and
[`docs/benchmark-v3.md`](docs/benchmark-v3.md) for the ceremony and trust boundary.

## Release evidence

ArtifactForge can build two independently supplied byte-identical wheel and source archives,
check archive structure, generate normalized CycloneDX SBOMs, and produce a closed local
evidence bundle. This output is unsigned local self-attestation. It does not authenticate the
producer or build host, sign a package, publish to PyPI, create a GitHub release, or produce a
reportable security result.

The manual release-evidence workflow is exact-tag-only and names a protected environment. A
repository administrator must configure that protection, and a real hosted run is required
before making any GitHub or Sigstore attestation claim. See
[`docs/releasing.md`](docs/releasing.md).

## Current status

<!-- scorecard-status:start -->
**Committed scorecard scopes (`0.5.0`).** Generator assurance is `pass`;
experimental benchmark validity is `pass`; the all-gates compatibility verdict is
`pass`. Its reproducible measurement corpus is explicitly non-reportable.
<!-- scorecard-status:end -->

The project is early and experimental. Version 0.5.0 is the latest tagged scorecard source,
and no package has been published to PyPI. The committed scorecard is historical evidence for
that release. CI creates a fresh source-bound scorecard for the current revision instead of
pretending the historical card describes new code.

The latest local scanner checkpoint was generated on 2026-08-04 for the Phase 6C corpus of
339 files and 3,046,265 bytes. ClamAV and the selected XProtect rule file each passed a positive
control and scanned every file with no detection. The overall record is still red: Gatekeeper
is inapplicable to loose Mach-O, and the community YARA run exceeded its declared work ceiling
after ten rule-file load failures. This is not a clean-corpus or zero-detection claim. Exact
scanner provenance and hashes are recorded in [`SECURITY.md`](SECURITY.md).

Portable implementation for Windows coverage phases 6A through 6C is complete. Hosted
schema-v6 Windows-native runs produced partial failure evidence, but no complete passing report.
Schema-v7 confirmation and the first protected hosted release-attestation run are still pending.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/README.md`](docs/README.md) | Documentation map and recommended reading paths |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architecture, gates, and claim discipline |
| [`docs/fixture-core.md`](docs/fixture-core.md) | Fixture schema, lifecycle, verification, and release contract |
| [`KNOWN_TELLS.md`](KNOWN_TELLS.md) | Exact format limitations and synthetic markers |
| [`SECURITY.md`](SECURITY.md) | Safe handling, disclosure, scanner evidence, and supply-chain boundaries |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Work that remains open |
| [`docs/IMPROVEMENT-PLAN.md`](docs/IMPROVEMENT-PLAN.md) | Completed hardening phases and their evidence |
| [`CHANGELOG.md`](CHANGELOG.md) | Release and unreleased history |

Thanks to David Bianco and the EvidenceForge project for the incident model and the issue #332
discussion that prompted this work.

ArtifactForge is available under the [MIT License](LICENSE).
