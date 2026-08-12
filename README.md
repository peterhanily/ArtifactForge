# ArtifactForge

[![CI](https://github.com/peterhanily/ArtifactForge/actions/workflows/ci.yml/badge.svg)](https://github.com/peterhanily/ArtifactForge/actions/workflows/ci.yml)

ArtifactForge builds forensic artifacts to practise on, when you cannot use real ones.

If you teach DFIR, write detections, test a parser, or need a repeatable scene for an exercise,
your options are usually a real disk image you cannot share, or a flat CSV that no forensic tool
will open. ArtifactForge gives you the third option: actual PE files, registry hives, Prefetch
records, SQLite databases and plists that real parsers read, generated from a seed so everyone
gets byte-identical copies.

One command, under a second:

```console
$ artifactforge fixture build examples/fixtures/windows-loose-v2.json out/windows
fixture build: PASS — out/windows
  fixture id:  windows-dropper-001
  recipe:      sha256:283e7ce9cb73e3783495dc75a31d1c8b7e2703c0156766f19105fbfe74391381
  payload:     sha256:12ffbb3a3f6957f37ca6b235fcda0ceb4d688fc9bc961b4397e668c630043d89
  directories/files: 23/14
  integrity/reproduction: pass/pass

$ find out/windows/artifacts -type f | sort
out/windows/artifacts/C/Program Files/acrord32.exe
out/windows/artifacts/C/Users/v/AppData/Local/Chromium/User Data/Default/History
out/windows/artifacts/C/Users/v/AppData/Local/Temp/wmi_perf.exe
out/windows/artifacts/C/Users/v/AppData/Roaming/.../ArtifactForgeMaintenance.lnk
out/windows/artifacts/C/Windows/AppCompat/Programs/Amcache.hve
out/windows/artifacts/C/Windows/Prefetch/WMI_PERF.EXE-E24C367F.pf
out/windows/artifacts/C/Windows/System32/config/SOFTWARE
out/windows/artifacts/C/Windows/System32/Tasks/ArtifactForge/Maintenance-826527787c60
```

Those files are joined the way a real scene is joined: the Amcache `FileId` values are the SHA-1
digests of the PE files actually on disk, the Prefetch record names the program that ran, and the
Chromium download row points at the executable in `Temp`. Nothing is a stub — every byte is
parsed back by `pefile`, LIEF, regipy, libregf, `pyscca` and Dissect before it ships.

Every artifact carries an in-band `ARTIFACTFORGE-SYNTHETIC-<16 hex>` marker, so anything that
escapes into a case file or a rule set can be identified as synthetic later.

> [!CAUTION]
> Every artifact is synthetic and came from no real incident or host. Do not add its values to
> blocklists, detections, or threat-intelligence systems, and do not upload generated samples to
> public malware services such as VirusTotal.

For a guided tour of the whole pipeline in one script, run
[`scripts/demo.sh`](scripts/demo.sh).

This is an independent personal project. It is not affiliated with or endorsed by Cisco,
Cisco Talos, EvidenceForge, Microsoft, Apple, or any other organisation named here. The work
began in response to [EvidenceForge issue #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332).

![ArtifactForge turns a recipe and seed into deterministic bytes, then checks format validity, identity joins, and inertness](docs/assets/overview.svg)

## Quick start

ArtifactForge needs Python 3.11 or newer and, for the `scorecard` command, a git checkout. The
examples below use [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/peterhanily/ArtifactForge && cd ArtifactForge
uv venv
uv pip install -e ".[dev]"     # the parsers that --assurance checks against live in this extra

uv run artifactforge fixture build examples/fixtures/windows-loose-v2.json out/windows
uv run artifactforge fixture verify out/windows --assurance
uv run artifactforge fixture release out/windows out/windows.tar --assurance
uv run artifactforge fixture extract out/windows.tar out/from-archive
```

Use `fixture extract` rather than `tar -x`: the archive normalises file modes so its bytes stay
deterministic, and extraction restores the private carrier modes that `verify` requires.

Four scenes ship as recipes in [`examples/fixtures/`](examples/fixtures/) — a Windows dropper, a
Windows download that never executed, a quarantined macOS app, and a Linux autostart. The
`-v1.json` files beside them are frozen historical vectors that `build` deliberately refuses.

To re-run everything the project checks about itself:

```sh
uv run pytest -q                 # ~15 minutes
uv run artifactforge scorecard   # ~10 minutes; writes the card to stdout, verdict to stderr
```

The [`samples/`](samples/) directory contains generated Windows, macOS, and Linux scenes with
parser observations and byte-derived answer keys, so you can read one without running anything.
These samples are documentation fixtures, not benchmark data.

## What it produces

| Platform | Artifact files | Validation |
|---|---|---|
| Windows | PE, Amcache and Software hives, MAM-compressed SCCA v30 Prefetch, Chromium `History`, `Zone.Identifier`, disabled Task Scheduler XML, Shell Link | pefile and LIEF; regipy and libregf; pyscca and Dissect; SQLite plus a bounded byte reader; ElementTree plus a byte reader; liblnk and LnkParse3 |
| macOS | arm64 Mach-O, knowledgeC, TCC, QuarantineEventsV2, quarantine xattr values, LaunchAgent plists | LIEF and macholib; SQLite plus a bounded byte reader; plistlib plus an independent binary-plist reader; two quarantine-xattr readers |
| Linux | ELF64 x86-64, XDG autostart entries, timestamped Bash history | LIEF and pyelftools; PyXDG plus a raw reader; dissect.target plus a raw reader |

A recipe picks a host profile and a story. The profile is the machine; the story is the
incident shape:

| Profile | Story | What the scene contains |
|---|---|---|
| `windows-loose-v2` | `windows-dropper-v1` | Download, execution, persistence and reference surfaces |
| `windows-loose-v2` | `windows-download-only-v1` | Arrival without execution: the mark of the web on one PE, with every execution and persistence surface absent and asserted absent |
| `macos-14-loose-v2` | `macos-quarantined-app-v1` | Quarantined download with TCC and knowledgeC records |
| `linux-glibc-x86_64-loose-v2` | `linux-autostart-v1` | Autostart entries and timestamped shell history |

Both lists are closed. A recipe selects a registered story; it cannot describe arbitrary
actions, and within a story the seed chooses names, paths and values but never which artifact
kinds appear. See [`docs/fixture-core.md`](docs/fixture-core.md) for the exact recipe surface.

These describe loose artifacts and logical filesystem metadata. They do not describe a disk
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
  loading. Earlier hosted schema-v6 runs produced only diagnostic failure evidence. Hosted
  schema-v7 run 30944614694 recorded the first complete, passing native observation.

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

[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) is Cisco Talos's generator
for synthetic security *logs*; ArtifactForge makes the *files* those logs would describe.
It is not a runtime or development dependency here. The two tools' hashes do not currently
join, and [`docs/evidenceforge.md`](docs/evidenceforge.md) records the measurements that
show why.

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
schema-v6 Windows-native runs produced partial failure evidence; hosted schema-v7 run
30944614694 then passed all ten jobs, including the first complete Windows-native observation.
The first protected hosted release-attestation run is still pending.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/README.md`](docs/README.md) | Documentation map and recommended reading paths |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architecture, gates, and claim discipline |
| [`docs/fixture-core.md`](docs/fixture-core.md) | Fixture schema, lifecycle, verification, and release contract |
| [`KNOWN_TELLS.md`](KNOWN_TELLS.md) | Exact format limitations and synthetic markers |
| [`SECURITY.md`](SECURITY.md) | Safe handling, disclosure, scanner evidence, and supply-chain boundaries |
| [`docs/evidenceforge.md`](docs/evidenceforge.md) | What was measured against EvidenceForge |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Work that remains open |
| [`docs/IMPROVEMENT-PLAN.md`](docs/IMPROVEMENT-PLAN.md) | Completed hardening phases and their evidence |
| [`CHANGELOG.md`](CHANGELOG.md) | Release and unreleased history |

Thanks to David Bianco and the EvidenceForge project for the incident model and the issue #332
discussion that prompted this work.

ArtifactForge is available under the [MIT License](LICENSE).
