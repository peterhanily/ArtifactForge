# ArtifactForge

[![CI](https://github.com/peterhanily/ArtifactForge/actions/workflows/ci.yml/badge.svg)](https://github.com/peterhanily/ArtifactForge/actions/workflows/ci.yml)

Deterministic, **parser-validated** synthetic forensic artifacts — the files a responder finds
on a host once they dig in — consistent with the incident model of
[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge), which generates the logs.

> **Experimental repository.** ArtifactForge exists because of
> **[EvidenceForge issue #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332)**,
> which asked whether artifacts could be generated alongside EvidenceForge's synthetic logs.
> This is an attempt at answering that, shared for the discussion, and it may be restructured
> or taken down. With thanks to **David Bianco** and the **EvidenceForge** project (Cisco
> Talos) for the incident model and the #332 conversation that prompted it.
>
> **Independent and unaffiliated.** A personal project. It is **not** affiliated with,
> endorsed by, sponsored by or authorised by Cisco, Cisco Talos, the EvidenceForge
> maintainers, Microsoft, Apple, or any other organisation named anywhere in this repository.
> Company, product and service names are used only to identify what an artifact depicts and
> are the property of their respective owners.
>
> **Everything here is synthetic.** No artifact in this repository came from a real host. No
> hash, UUID, bundle identifier, URL, path or timestamp in it identifies anything real, and
> none should be added to a blocklist, a detection rule or a threat-intelligence platform.
> Generated binaries are payload-free by construction. Marker-eligible classified artifacts
> disclose themselves in-band; the strict serialized quarantine-xattr profile is the sole
> classified marker exemption. See
> [`SECURITY.md`](SECURITY.md) and
> [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

The premise is a test, not a claim. Synthesize each answer-bearing binary's bytes once, derive
its content digests and structural hashes from those bytes, then run the parsers a responder
actually runs — pefile, LIEF, regipy, libregf, libscca, macholib — and require the selected
cross-artifact pivots to hold in their output. Parser readability and those pivots are pass/fail
properties; broader realism remains partial and is documented below.

```sh
# Evaluator trust domain: keep this complete root and its key/answers private.
artifactforge bench new evaluator --n 40 --kind holdout
artifactforge bench export evaluator public

# Separate OS-enforced solver trust domain: transfer only public/ here.
artifactforge bench solve public --out answers.jsonl

# Evaluator trust domain: transfer only the submission back.
artifactforge bench grade evaluator --submission answers.jsonl
```

The public export contains only canonical `public.json` and `scenarios/`; the solver never
receives the evaluator path. Every submission is bound to the export's `suite_id`. The export
is a transfer boundary, not a Python sandbox: arbitrary solver code still requires a separate
account, container/VM without the evaluator mount, or separate machine. This workflow remains
experimental and no v2 performance score is reportable yet. See
[`docs/benchmark-v2.md`](docs/benchmark-v2.md).

## What's in it

- **Windows artifacts** — a synthetic PE with a real, seed-deterministic IMPHASH that pefile
  and LIEF independently confirm from the import table; registry hives carrying Run-key
  persistence and Amcache installation records
  (for declared resident answer-bearing records, `FileId` is derived from the emitted file's
  SHA1); uncompressed SCCA v17 prefetch that libyal's `libscca` opens, which means plaso reads
  it, with its XP path hash independently re-derived from the modeled device path.
- **macOS artifacts** — a hand-assembled arm64 Mach-O with a real symhash and a real ad-hoc
  code signature whose cdhash `codesign -d` reports; knowledgeC, TCC and QuarantineEventsV2
  databases; the `com.apple.quarantine` xattr value as a sidecar file; LaunchAgent plists.
  SQLite, binary-plist and serialized quarantine-xattr bytes are independently decoded by
  bounded first-party readers, compared type-for-type with their paired implementation, then
  checked against exact macOS profiles.
  EvidenceForge v1.13.1 cannot produce any of this — its documented `os_category` is windows
  or linux, with no macOS at all.
- **Linux loose artifacts** — deterministic ELF64 little-endian x86-64 `ET_DYN` files with a
  real interpreter, dynamic table, three R/RX/RW load segments, NX stack, RELRO and an in-band
  note; XDG 1.5 autostart desktop entries; and timestamped Bash history. LIEF and pyelftools
  independently read each ELF, PyXDG is paired with a bounded raw desktop-entry reader, and
  dissect.target is paired with a bounded raw history reader. The exact assurance profile is
  `linux-glibc-x86_64-loose-v1`.
- **One identity behind the answer-bearing file pivots.** `ContentStore` synthesizes each
  materialized binary's bytes once and derives its content digests and structural hashes from
  them. The five Amcache `FileId`-to-resident agreements, private binary truth and Linux
  guest-path-to-served-byte checks reuse that identity. Deliberate stale and absent Amcache
  decoys do not claim to be resident file bytes. The distinct byte, fixture, evaluator and
  modeled-log boundaries—and the decision not to publish a catch-all graph—are in
  [`docs/identity-boundaries.md`](docs/identity-boundaries.md).
- **Fixture Core v1.** A strict public recipe builds `fixture.json` plus an exact `artifacts/`
  payload; hidden and nested relative paths are ordinary first-class members. Verification
  re-hashes and regenerates every byte, inspection and semantic diff are stable interfaces,
  and release emits a deterministic checked USTAR archive. Fixture manifests publish hashes
  and seeds, so they are explicitly ineligible for benchmark use.
- **One recursive scene-tree contract.** Staging, Gates 1–3, sample documentation and sample
  checks use a canonical relative-POSIX inventory; Fixture Core shares its path grammar while
  retaining its stricter descriptor-bound publication verifier. Dot directories are included;
  links, special files, empty directories, path aliases, case-fold and file/ancestor collisions
  are rejected. Scene capture also enforces count/depth/size ceilings. Scenes are built
  privately and atomically published with no replacement; path-only parsers receive a bounded,
  frozen private copy made from one immutable byte capture rather than reopening the caller's
  tree.
- **Benchmark v2 — experimental and non-reportable.** Every Windows or macOS scene has five
  scalar questions forming a bijection over five candidates. The two closed rules resolve an
  Amcache `FileId` SHA-1 against resident PE bytes, or a strict quarantine-xattr UUID against
  `QuarantineEventsV2`; exact candidate chance is 20%. Public export, `suite_id` binding,
  parser-valid counterfactuals and exact scene-level permutation tests replace v1's invalid
  root-object questions. The finite registered Gate 4 validity surface passes in the committed
  v0.5 scorecard; a separately isolated hold-out run is still required before any performance
  score can be reported.
- **A companion adapter** that reads an EvidenceForge run's output and recovers which logical
  binary each of its Sysmon hashes denotes — verifying every recovery against the digest
  upstream emitted, and refusing rather than guessing. It never imports EvidenceForge.
- **Four gates and a scorecard.** Core generator and benchmark claims map to gates that are
  mutation-tested red; pinned external measurements and scanner observations require separate
  provenance. No fresh scanner attestation exists for the v2 corpus. See
  [`docs/DESIGN.md`](docs/DESIGN.md) §4.

## Try it

```sh
uv venv && uv pip install -e ".[dev]"
uv run artifactforge fixture build examples/fixtures/windows-loose-v1.json out/windows
uv run artifactforge fixture build examples/fixtures/linux-glibc-x86_64-loose-v1.json out/linux
uv run artifactforge fixture verify out/windows --assurance
uv run artifactforge fixture release out/windows out/windows.tar --assurance
uv run pytest -q                          # the whole suite, standalone
uv run artifactforge scorecard            # every gate, and what it measured
```

The committed [`samples/`](samples/) gallery includes one Windows, one macOS and one recursive
Linux scene with parser output and byte-derived answer keys; none is benchmark material.

See [`docs/fixture-core.md`](docs/fixture-core.md) for the schema, lifecycle, exit-code and
integrity boundaries. `windows-loose-v1` is deliberately not branded Windows 10: its loose
artifact set currently combines NT6-era paths with XP-family SCCA v17 prefetch semantics.
The raw-reader subset and semantic extension rule are documented in
[`docs/macos-oracles.md`](docs/macos-oracles.md).

The Linux fixture is evidence, not an installed host. Fixture ABI v1 binds recursive paths,
sizes and digests but not modes; release archives normalize files to 0644. XDG parser
acceptance proves the emitted record shape, not that a desktop session launched it, and Bash
history is not proof a command ran. Each ELF's only executable bytes are a nine-byte direct
`exit(0)` syscall body, but its declared dynamic loader runs before that entry on a real
execution attempt. It names `libc.so.6`, while the main object imports and calls no libc
symbol and is deliberately minimal rather than compiler-shaped. External loader/dependency
code is out of scope and the loader runs first.
ArtifactForge never executes an ELF, runs
`ldd`, launches a desktop entry, or sources history.

The portable gates are complemented by a fixture-bound Ubuntu 24.04/x86-64 CI lane. It first
runs Fixture Core's canonical, integrity and exact-reproduction verification plus Gates 1 and
3, retaining their full reports and the CPython/parser-distribution versions. Native tools then
observe only a held private snapshot byte-equal to that verified manifest. The canonical record
binds exact native-tool bytes/package versions before and after observation, source and fixture
pre/post digests, the normalized three-instruction disassembly, and a byte-identical history
round-trip with a non-execution control. It remains observational: it performs none of the
execution or activation steps excluded above.

EvidenceForge is not a declared runtime or development dependency. Two isolated CI jobs install
it for the pinned contract and the default-branch drift canary; the standalone test job does
not. To run the contract locally, note that the **distribution** is `evidence-forge` even though
it imports as `evidenceforge`:

```sh
uv pip install "evidence-forge @ git+https://github.com/Cisco-Talos/EvidenceForge@v1.13.1"
uv run python -m evidenceforge generate scenario.yaml -o ef-out
ARTIFACTFORGE_EF_OUT=ef-out uv run pytest -q tests/ef_contract/
```

## How it holds up on real data

On an unmodified run of EvidenceForge's shipped `branch-office-example` scenario at v1.13.1,
read through the companion adapter: **7 hosts, 853 Sysmon records carrying SHA256, all 853
recovered and verified** against the digests upstream actually emitted, resolving to 105
distinct Sysmon logical identities. The observed seed forms were `from_host_metadata` for 78
identities and `with_description` for 27. Restricting the count to Event ID 1 gives 614 records
and 78 distinct SHA1/SHA256 values.

The same run's Zeek `files.json` has 722 rows: 525 certificate and 197 non-certificate rows,
with 119 distinct SHA1 and 103 distinct SHA256 values overall. No non-certificate row has
SHA256; 21 such rows have SHA1, representing 16 distinct values. The same-algorithm Sysmon and
Zeek sets are disjoint in this stock run, but their basenames are disjoint too, so this is not a
controlled witness that the same logical transfer and execution received different hashes. It
shows emitter-local synthetic identity domains; a same-file inconsistency claim needs a
positive witness.

The source of record is the schema-checked
[`measurements/evidenceforge-v1.13.1-branch-office-example.json`](measurements/evidenceforge-v1.13.1-branch-office-example.json).
It binds the exact scenario and results to a canonical inventory of all 45 output files. The
output cannot identify its own producer commit, so the record says that plainly; pinned CI
closes the chain by deriving version and commit from the installed distribution, generating a
fresh run, and byte-comparing the complete record. Public prose counts are regression-tested
against that JSON.

A separate controlled scenario closes the stock run's pairing gap. It models one exact HTTP
download-to-path followed by execution of that same path, plus a same-basename/different-path
transfer and an unrelated execution as negative controls. Selection is digest-blind and
requires the ground-truth storyline, exact paths and PIDs, Zeek UID/FUID, Sysmon PID/ProcessGuid
and an ordered Event 1 → HTTP/files → Event 11 → Event 1 timeline. On the pinned output, Zeek's
complete HTTP response SHA1 is `35a96017abff36254a0d4a6399c9fbe0cbd8b6a2`; the later Sysmon
process-image SHA1 is `025ee09748833e745cd43c1d333d6910958f3919`. Both reproduce their
v1.13.1 seed formulas, but do not join. This demonstrates one **modeled logical file**, not
shared materialized bytes. The fixture, output-tree-bound record, issue draft, opt-in design
RFC and clean-applying review patches live under
[`integration/evidenceforge/`](integration/evidenceforge/) and
[`measurements/`](measurements/evidenceforge-v1.13.1-controlled-content-identity.json).

`tests/ef_contract/test_golden_formulas.py` calls EvidenceForge's own `_generate_hashes` and
requires our transcription of it to agree exactly, so drift in a private upstream surface
breaks in one file rather than silently returning wrong identities.

## How honest is it, really?

**Identity — proven within the gate's declared scope.** The answer-bearing materialized file
digests, structural hashes and selected joins are re-derived from the files on disk through
real parsers and only then compared. Mutations append bytes, rewrite resident-file Amcache
`FileId` values, corrupt quarantine UUIDs and alter exact recursive paths, and require Gate 2
to turn red. This does not claim that every stale or absent decoy `FileId` names bytes shipped
in the scene. Determinism is real: a batch regenerates byte-identical across processes, hash
seeds, timezones and locales. Release counts belong to the source-bound scorecard, not prose
written before that scorecard is regenerated.

**Artifact fidelity — partial, and measured.** Every classified structured format is opened
by two independently implemented parsers. ELF uses LIEF plus pyelftools; XDG desktop entries
use PyXDG plus a bounded raw reader; Bash history uses dissect.target plus a bounded raw
reader. For SQLite and binary plists, the second
implementation is a deliberately narrow, bounded raw reader maintained here—not an external
endorsement. Gate 1 first captures the complete bounded scene through held, no-follow file
descriptors and gives pathname-only parsers a frozen private copy of that immutable capture;
each parser pair thus observes the same bytes. Gate 1 separately
requires type-exact consensus and the exact knowledgeC, TCC, QuarantineEventsV2 or LaunchAgent
profile. Serialized quarantine xattrs are now parser-classified: the artifact parser and an
independent byte reader must agree on their exact four-field representation. Beyond that,
every format has real limitations and
[`KNOWN_TELLS.md`](KNOWN_TELLS.md) lists them: minimal registry hives with ASCII-only key names,
uncompressed prefetch where Windows 10 compresses, and a Mach-O using an older linker idiom
than any current clang emits.

**Benchmark validity — redesigned, experimental and not yet reportable.** The v1 measurement
is withdrawn. Completing its footprint and stored-order attacks produced perfect shortcut
recovery, its co-located solver path exposed `_answers/`, its public-key corpus was exactly
reconstructable without reading target artifacts, its candidate-aware chance was about one in
five, and its dependency count was self-asserted. Those are protocol failures, not thresholds
to tune.

V2 asks five scalar questions per scene under two closed rules. Each question resolves one of
five candidates by actual value agreement across at least two captured artifacts; the five
answers form a bijection and exact chance is 20%. Gate 4 independently derives candidate
universes and artifact dependency traces, requires complete shortcut attacks, evaluates
aggregate and family/rule results with exact within-scene permutation inference, and enforces
a predeclared minimum of 20 scenes per class and exact power contract. Parser-valid
counterfactuals must swap exactly the predicted answers or make exactly one relation
unavailable while every other answer remains unchanged.

The development and scorecard-measurement corpora have disclosed derivations and are positive
controls, never agent-performance datasets. A reportable run additionally requires a fresh
hold-out key, exact export, `suite_id`-bound submissions and a separate OS-enforced solver
trust domain. That end-to-end isolated hold-out measurement has not been completed, so no v2
performance score is reportable. Linux remains generator assurance and Fixture Core material;
it is not included in Gate 4 and cannot dilute either benchmark family. See
[`docs/benchmark-v2.md`](docs/benchmark-v2.md).

**What it is not.** Not disk images, not memory, not EVTX, not a live host. The tier is loose
files a responder's tools read directly, and it is not threat intelligence.

## Status

<!-- scorecard-status:start -->
**Committed scorecard scopes (`0.5.0`).** Generator assurance is `pass`;
experimental benchmark validity is `pass`; the all-gates compatibility verdict is
`pass`. Its reproducible measurement corpus is explicitly non-reportable.
<!-- scorecard-status:end -->

Early and experimental at v0.5.0, with nothing published to PyPI. The clean-source scorecard
passes generator assurance, the finite registered Benchmark v2 validity surface and the
all-gates compatibility verdict. That is not a performance result: the reproducible corpus is
a positive-control/diagnostic corpus, and no separately isolated fresh-key hold-out has been
run. Benchmark-v1 figures remain withdrawn rather than carried forward. No fresh scanner
attestation exists for the v2 corpus. MIT licensed, deliberately, so any part of it could be
merged upstream without friction if that ever became useful.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and the gate discipline,
[`docs/fixture-core.md`](docs/fixture-core.md) for the public fixture contract,
[`docs/ROADMAP.md`](docs/ROADMAP.md) for what is not built, and
[`integration/evidenceforge/`](integration/evidenceforge/) for the controlled witness and an
upstream-ready proposal — which has not been posted or proposed to anyone.
