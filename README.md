# ArtifactForge

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
> Generated binaries are inert by construction and disclose themselves in-band. See
> [`SECURITY.md`](SECURITY.md) and
> [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

The premise is a test, not a claim. Synthesize a file's bytes once, let every artifact quote a
real digest of them, then run the parsers a responder actually runs — pefile, LIEF, regipy,
libregf, libscca, macholib — and require the cross-artifact pivot to hold in their output.
If it holds, the scene is consistent by construction. If it doesn't, it's a bug. "Realistic"
stops being a matter of taste and becomes a pass/fail gate.

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
Gate 2 — identity: is every hash-shaped field a genuine digest of one ContentStore blob?
  VERDICT: PASS (0 fail, 0 declared gaps) — 40/40 cross-artifact identity checks hold
```

The scene above holds five binaries. Persistence launches one of them; Amcache's recorded
hashes match a *different* one; one prefetch record names a program that is no longer there.
Answering anything about it requires reading two artifacts together, which is the point.

## What's in it

- **Windows artifacts** — a synthetic PE with a real, seed-deterministic IMPHASH that pefile
  computes; registry hives carrying Run-key persistence and Amcache installation records
  (`FileId` really is the file's SHA1); uncompressed SCCA v17 prefetch that libyal's
  `libscca` opens, which means plaso reads it.
- **macOS artifacts** — a hand-assembled arm64 Mach-O with a real symhash and a real ad-hoc
  code signature whose cdhash `codesign -d` reports; knowledgeC, TCC and QuarantineEventsV2
  databases; the `com.apple.quarantine` xattr value; LaunchAgent plists. EvidenceForge cannot
  produce any of this — its `os_category` is windows or linux, with no macOS at all.
- **One identity behind all of it.** `ContentStore` synthesizes a file's bytes once. Every
  hash-shaped field anywhere is a real digest of those bytes, so the file-hash pivot works
  because it cannot not work.
- **A benchmark for investigation, not recall — experimental, and currently failing its own
  validity gate.** Deterministic scenes with decoys, questions that each span at least two
  artifacts, and answers derived from a suite key the solver never sees. The keyed-suite half
  works; the scene composition leaks, at 72.7% against a 4.2% floor. See *How honest is it,
  really?* below. Do not report a score from it yet.
- **A companion adapter** that reads an EvidenceForge run's output and recovers which logical
  binary each of its Sysmon hashes denotes — verifying every recovery against the digest
  upstream emitted, and refusing rather than guessing. It never imports EvidenceForge.
- **Four gates and a scorecard.** Every claim in this file maps to a gate that can be watched
  going red. See [`docs/DESIGN.md`](docs/DESIGN.md) §4.

## Try it

```sh
uv venv && uv pip install -e ".[dev]"
uv run pytest -q                          # the whole suite, standalone
uv run artifactforge scorecard            # every gate, and what it measured
```

EvidenceForge is optional and CI-only. Note the **distribution** is `evidence-forge` even
though it imports as `evidenceforge`:

```sh
uv pip install "evidence-forge @ git+https://github.com/Cisco-Talos/EvidenceForge@v1.13.1"
uv run python -m evidenceforge generate scenario.yaml -o ef-out
ARTIFACTFORGE_EF_OUT=ef-out uv run pytest -q tests/ef_contract/
```

## How it holds up on real data

On EvidenceForge's shipped `branch-office-example` scenario at v1.13.1, read through the
companion adapter: **7 hosts, 446 hashed Sysmon records, 446 recovered and verified** against
the digests upstream actually emitted, resolving to 93 distinct logical binaries, with both of
upstream's seed forms exercised.

`tests/ef_contract/test_golden_formulas.py` calls EvidenceForge's own `_generate_hashes` and
requires our transcription of it to agree exactly, so drift in a private upstream surface
breaks in one file rather than silently returning wrong identities.

## How honest is it, really?

**Identity — proven.** Every hash-shaped field is re-derived from the bytes on disk through an
independent parser and only then compared; 40 of 40 cross-artifact checks hold, and breaking
any one of them — appending a byte, rewriting an Amcache `FileId`, corrupting a quarantine
UUID — turns Gate 2 red. Determinism is real: a batch regenerates byte-identical across
processes, hash seeds, timezones and locales.

**Artifact fidelity — partial, and measured.** Every format is read by two independently
implemented parsers, but two of them are not independent at all: `sqlite3` and `plistlib`
write and read their own formats, so the macOS databases and plists have no outside opinion on
them. Both are declared gaps in `fidelity-scorecard.json` — limits of the measuring apparatus
rather than failures of the thing measured, which is why they do not set the verdict. (That
currently reads `fail`, because of Gate 4 below.) Beyond that, every format has real
limitations and [`KNOWN_TELLS.md`](KNOWN_TELLS.md) lists them: minimal registry hives with
ASCII-only key names, uncompressed prefetch where Windows 10 compresses, a Mach-O using an
older linker idiom than any current clang emits.

**Benchmark validity — currently failing, and the number is published.** Gate 4 is **red**.
The reference solver scores 100%, and so does a solver that understands nothing: for each
candidate, count how many other files mention its name, and take the maximum. Measured on a
hold-out suite:

| | |
|---|---|
| reference solver (real parsers, real joins) | **100%** |
| `footprint` adversary (counts substring mentions, parses nothing) | **72.7%** |
| chance floor (guesses among visible candidates) | **4.2%** |

Those three numbers are the ones in `fidelity-scorecard.json`, measured at `--n 40` on one
hold-out suite. Reproduce them with `artifactforge scorecard --n 40`. The floor is a Monte
Carlo estimate and moves slightly with `n`, so the committed scorecard is the number of
record — quoting a different run's figure here is how a document starts lying slowly.

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
**experimental** and no score from it should be reported. The generator, and Gates 1 to 3,
are unaffected.

**What it is not.** Not disk images, not memory, not EVTX, not a live host. The tier is loose
files a responder's tools read directly, and it is not threat intelligence.

## Status

Early and experimental, version 0.0.1, nothing published to PyPI. **Gates 1 to 3 pass; Gate 4
is red and its number is above.** Two declared gaps remain besides. `fidelity-scorecard.json`
at the repository root is the honest record — it ships whatever it actually reads, and right
now that includes a failure. MIT licensed, deliberately, so any part of it
could be merged upstream without friction if that ever became useful.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and the gate discipline,
[`docs/ROADMAP.md`](docs/ROADMAP.md) for what is not built, and
[`integration/evidenceforge/`](integration/evidenceforge/) for a sketch of what an upstream
contribution would involve — which has not been proposed to anyone.
