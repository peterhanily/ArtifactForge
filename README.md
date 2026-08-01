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

$ ls suite/scenarios/af1_a5pq7iqoumv3uglr
7zFM.exe                  Amcache.hve       javaw.exe    putty.exe
7ZFM.EXE-577AB7E4.pf      certmgr_svc.exe   notepad.exe  PUTTY.EXE-F1C28886.pf
CERTMGR_SVC.EXE-8773131B.pf                 Software.run.hive
TASKENG_X.EXE-509F1868.pf

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
  VERDICT: PASS (0 fail, 0 declared gaps) — 40/40 cross-artifact identity checks hold
```

The scene above holds five binaries. Persistence launches one of them; Amcache's recorded
hashes match a *different* one; one prefetch record names a program that is no longer there.
Answering anything about it requires reading two artifacts together, which is the point.

## What's in it

- **Windows artifacts** — a synthetic PE with a real, seed-deterministic IMPHASH that pefile
  computes; registry hives carrying Run-key persistence and Amcache installation records
  (for declared resident answer-bearing records, `FileId` is derived from the emitted file's
  SHA1); uncompressed SCCA v17 prefetch that libyal's `libscca` opens, which means plaso reads
  it.
- **macOS artifacts** — a hand-assembled arm64 Mach-O with a real symhash and a real ad-hoc
  code signature whose cdhash `codesign -d` reports; knowledgeC, TCC and QuarantineEventsV2
  databases; the `com.apple.quarantine` xattr value as a sidecar file; LaunchAgent plists.
  EvidenceForge cannot produce any of this — its `os_category` is windows or linux, with no
  macOS at all.
- **One identity behind the answer-bearing file pivots.** `ContentStore` synthesizes each
  materialized binary's bytes once and derives its content digests and structural hashes from
  them. The selected Amcache-to-disk and answer-key-to-disk joins reuse that identity. Deliberate
  stale and absent Amcache decoys do not claim to be resident file bytes.
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
uv run pytest -q                          # the whole suite, standalone
uv run artifactforge scorecard            # every gate, and what it measured
```

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

`tests/ef_contract/test_golden_formulas.py` calls EvidenceForge's own `_generate_hashes` and
requires our transcription of it to agree exactly, so drift in a private upstream surface
breaks in one file rather than silently returning wrong identities.

## How honest is it, really?

**Identity — proven within the gate's declared scope.** The answer-bearing materialized file
digests, structural hashes and selected joins are re-derived from the files on disk through
real parsers and only then compared; 40 of 40 checks hold, and appending a byte, rewriting the
resident-file Amcache `FileId`, or corrupting a quarantine UUID turns Gate 2 red. This does not
claim that every stale or absent decoy `FileId` names bytes shipped in the scene. Determinism is
real: a batch regenerates byte-identical across processes, hash seeds, timezones and locales.

**Artifact fidelity — partial, and measured.** PE, Mach-O, registry hive and prefetch are each
opened by two independently implemented parsers. The macOS SQLite databases and binary plists
are different: `sqlite3` and `plistlib` write and read their own output, so those formats have
no outside opinion. The quarantine xattr value is a plain sidecar rather than a separately
parsed format. The SQLite and plist limitations are declared gaps in
`fidelity-scorecard.json`; they do not set a gate verdict. (The headline currently reads
`fail`, because of Gate 4 below.) Beyond that, every format has real limitations and
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
corpus derivation and marks it `reportable: false`: its published key makes it useful for
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
The question and the leak are the same object. Until that lands the benchmark is
**experimental** and no score from it should be reported. The generator's three gates have no
failures; its assurance status still reads `gap` because the SQLite and plist second-oracle
gaps remain.

**What it is not.** Not disk images, not memory, not EVTX, not a live host. The tier is loose
files a responder's tools read directly, and it is not threat intelligence.

## Status

Early and experimental, version 0.0.2, nothing published to PyPI. **Gates 1 to 3 have no
failures; generator-assurance status is `gap` because two oracle gaps remain. Benchmark-validity
status is `fail` because Gate 4 is red.** `fidelity-scorecard.json` at the repository root is
the honest record — it ships whatever it actually reads, and right now that includes a
failure. MIT licensed, deliberately, so any part of it could be merged upstream without
friction if that ever became useful.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and the gate discipline,
[`docs/ROADMAP.md`](docs/ROADMAP.md) for what is not built, and
[`integration/evidenceforge/`](integration/evidenceforge/) for a sketch of what an upstream
contribution would involve — which has not been proposed to anyone.
