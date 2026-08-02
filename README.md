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
> Generated binaries are payload-free by construction. Classified structured artifacts
> disclose themselves in-band; plain sidecars are the documented exception. See
> [`SECURITY.md`](SECURITY.md) and
> [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

The premise is a test, not a claim. Synthesize each answer-bearing binary's bytes once, derive
its content digests and structural hashes from those bytes, then run the parsers a responder
actually runs — pefile, LIEF, regipy, libregf, libscca, macholib — and require the selected
cross-artifact pivots to hold in their output. Parser readability and those pivots are pass/fail
properties; broader realism remains partial and is documented below.

```
$ artifactforge bench new suite --n 4 --kind holdout
wrote 4 scenarios to suite (holdout suite)
  key: suite/_key/key.hex
       Lose it and this suite can never be regenerated or audited. Never commit it.

$ ls suite/scenarios/af1_o272arbuftpknuil
Amcache.hve                       CODE.EXE-39F3B2A8.pf   javaw.exe
audacity.exe                      code.exe               JAVAW.EXE-1DA9F6E6.pf
CHROME_HELPER.EXE-2DB20320.pf     cmd.exe                smartscrn.exe
SMARTSCRN.EXE-0818EF6A.pf         Software.run.hive

$ artifactforge bench solve suite --out answers.jsonl
wrote 4 submissions to answers.jsonl

$ artifactforge bench grade suite --submission answers.jsonl
  count      2/2
  enum       2/2
  hash       6/6
  imphash    4/4
  name       4/4
  path       2/2
  url        2/2
  SCORE: 22/22 = 100.0%

$ artifactforge gate identity
Gate 2 — identity: do the declared answer-bearing pivots agree with emitted bytes?
  VERDICT: PASS (0 fail, 0 declared gaps) — 130/130 cross-artifact identity checks hold
```

The scene above holds five binaries. Persistence launches one of them; Amcache's recorded
hashes match a *different* one; one prefetch record names a program that is no longer there.
Answering anything about it requires reading two artifacts together, which is the point.

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
  SQLite and binary-plist bytes are independently decoded by bounded first-party raw readers,
  compared type-for-type with `sqlite3`/`plistlib`, then checked against exact macOS profiles.
  EvidenceForge cannot produce any of this — its `os_category` is windows or linux, with no
  macOS at all.
- **Linux loose artifacts** — deterministic ELF64 little-endian x86-64 `ET_DYN` files with a
  real interpreter, dynamic table, three R/RX/RW load segments, NX stack, RELRO and an in-band
  note; XDG 1.5 autostart desktop entries; and timestamped Bash history. LIEF and pyelftools
  independently read each ELF, PyXDG is paired with a bounded raw desktop-entry reader, and
  dissect.target is paired with a bounded raw history reader. The exact assurance profile is
  `linux-glibc-x86_64-loose-v1`.
- **One identity behind the answer-bearing file pivots.** `ContentStore` synthesizes each
  materialized binary's bytes once and derives its content digests and structural hashes from
  them. The selected Amcache-to-disk, answer-key-to-disk and Linux guest-path-to-served-byte
  joins reuse that identity. Deliberate stale and absent Amcache decoys do not claim to be
  resident file bytes. The distinct byte, fixture, evaluator and modeled-log boundaries—and
  the decision not to publish a catch-all graph—are in
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
- **A benchmark for investigation, not recall — experimental, with benchmark-validity status
  red because Gate 4 fails.** Deterministic scenes with decoys, questions that each span two
  artifacts, and answers derived from a suite key the solver never sees. The keyed-suite half
  works; the scene composition leaks, at 72.7% against a 4.2% floor. See *How honest is it,
  really?* below. Do not report a score from it yet.
- **A companion adapter** that reads an EvidenceForge run's output and recovers which logical
  binary each of its Sysmon hashes denotes — verifying every recovery against the digest
  upstream emitted, and refusing rather than guessing. It never imports EvidenceForge.
- **Four gates and a scorecard.** Core generator and benchmark claims map to gates that are
  mutation-tested red; pinned external measurements and dated scanner observations carry
  separate provenance. See [`docs/DESIGN.md`](docs/DESIGN.md) §4.

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
real parsers and only then compared; the 60-scene generator-assurance corpus (40 Windows/macOS
scenes plus 20 Linux assurance scenes) holds all 1,300 of 1,300 checks, and appending a byte,
rewriting the
resident-file Amcache `FileId`, or corrupting a quarantine UUID turns Gate 2 red. This does not
claim that every stale or absent decoy `FileId` names bytes shipped in the scene. Determinism is
real: a batch regenerates byte-identical across processes, hash seeds, timezones and locales.

**Artifact fidelity — partial, and measured.** Every classified structured format is opened
by two independently implemented parsers. ELF uses LIEF plus pyelftools; XDG desktop entries
use PyXDG plus a bounded raw reader; Bash history uses dissect.target plus a bounded raw
reader. For SQLite and binary plists, the second
implementation is a deliberately narrow, bounded raw reader maintained here—not an external
endorsement. Gate 1 first captures the complete bounded scene through held, no-follow file
descriptors and gives pathname-only parsers a frozen private copy of that immutable capture;
each parser pair thus observes the same bytes. Gate 1 separately
requires type-exact consensus and the exact knowledgeC, TCC, QuarantineEventsV2 or LaunchAgent
profile. The quarantine xattr value remains a plain sidecar rather than a separately parsed
format. Generator assurance is `pass`; the aggregate headline reads `fail` because Gate 4
is red. Beyond that, every format has real limitations and
[`KNOWN_TELLS.md`](KNOWN_TELLS.md) lists them: minimal registry hives with ASCII-only key names,
uncompressed prefetch where Windows 10 compresses, and a Mach-O using an older linker idiom
than any current clang emits.

**Benchmark validity — currently failing, and the number is published.** Gate 4 is **red**.
The reference solver scores 100%. The `footprint` adversary first ranks candidates without
understanding any file format — count how many other files mention each name and take the
maximum — then uses ordinary parsers and lookups to complete the answers hanging from that
choice. The committed regression measurement uses a deterministic, public-keyed
`scorecard-measurement` corpus:

| | |
|---|---|
| reference solver (real parsers, real joins) | **100%** |
| `footprint` adversary (format-free ranking, parser-assisted completion) | **72.7%** |
| chance floor (guesses among visible candidates) | **4.2%** |

Those three numbers are the ones in `fidelity-scorecard.json`, measured at `--n 40`.
Reproduce them exactly with `artifactforge scorecard --n 40`. The scorecard records the
full source commit and tree plus digests of `pyproject.toml` and `uv.lock`; release output is
refused from a dirty worktree. `--allow-dirty` exists only for non-release investigation and
binds the resulting card to the complete tracked diff and every untracked byte. It also records
the corpus derivation and marks it `reportable: false`: its published key makes it useful for
repeatable regression, never as a secret hold-out score. Real benchmark evaluation still uses
a fresh key that never leaves the evaluator. Quoting a different corpus's figure here is how
a document starts lying slowly.

An earlier version of this file claimed *"every adversary scores 0%"*. That was true of the
four adversaries then registered and false about the benchmark, because all four were weaker
than five minutes of work. The attack above is not incidental — it is structural. The answer
object is by definition the thing the registry, Amcache, prefetch and disk all talk about,
while a decoy appears in fewer of them, so counting mentions *is* the intended pivot performed
without understanding any of it.

Fixing it means deleting questions rather than patching the generator: for
`persisted_sha256` the declared pivot is "the one Run value naming a resident program", and
balancing the scene so decoys are mentioned equally makes the reference solver itself fail.
Linux assurance scenes are deliberately excluded from Gate 4, so they neither dilute nor
repair this Windows/macOS benchmark result. The question and the leak are the same object.
Until that lands the benchmark is
**experimental** and no score from it should be reported. The generator's three gates pass;
its assurance status is `pass`. That does not make the experimental benchmark valid.

**What it is not.** Not disk images, not memory, not EVTX, not a live host. The tier is loose
files a responder's tools read directly, and it is not threat intelligence.

## Status

Early and experimental, version 0.4.0, nothing published to PyPI. **Gates 1 to 3 pass;
generator-assurance status is `pass`. Benchmark-validity status is `fail` because Gate 4 is
red.** `fidelity-scorecard.json` at the repository root is
the honest record — it ships whatever it actually reads, and right now that includes a
failure. MIT licensed, deliberately, so any part of it could be merged upstream without
friction if that ever became useful.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and the gate discipline,
[`docs/fixture-core.md`](docs/fixture-core.md) for the public fixture contract,
[`docs/ROADMAP.md`](docs/ROADMAP.md) for what is not built, and
[`integration/evidenceforge/`](integration/evidenceforge/) for the controlled witness and an
upstream-ready proposal — which has not been posted or proposed to anyone.
