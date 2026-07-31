# ArtifactForge

Deterministic, seed-regenerable generator of forensic **artifacts** bound to
[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge)'s synthetic **logs** through
one shared file identity — so a hunter's real tools (YARA, pefile, regipy, Velociraptor)
find a crime scene that lines up perfectly with the telemetry.

> "EvidenceForge generates what the sensors saw; ArtifactForge generates what the responder
> finds once they dig in."

Companion to EvidenceForge, following the PacketForge constitution: **output deterministic,
fake data stays fake, labels stay true; augment-not-replace** (EvidenceForge is consumed as
a pinned library, never modified); **consistency-by-construction** (real DFIR tools run in CI
as pass/fail oracles); **never push upstream without explicit approval**.

## The keystone — content-first identity

EvidenceForge computes a file's "hashes" as digests of a **seed string**, keyed differently
per event source. So the same binary gets disagreeing hashes across Sysmon vs Zeek, and a
downloaded-then-executed file has two unrelated identities — the file-hash pivot, the core
move of DFIR, silently never works.

ArtifactForge's `ContentStore` synthesizes a file's **real bytes once**; then every hash-shaped
field everywhere (Sysmon `ImageHash`, Zeek `files.log`, Amcache, on-disk bytes, YARA target)
is a real digest of those same bytes — they agree **by construction**.

## Status — keystone proven + first Windows crime scene (2026-07)

All proofs are green and wired into CI, each artifact validated by an independent real parser:

- **`tests/test_real_run_join.py`** — on a real EvidenceForge run, every Sysmon binary
  reverse-maps to its logical identity (both EF seed formulas recovered) and routes through
  one ContentStore; the four-way join (Sysmon `ImageHash` == disk bytes == Amcache SHA1 ==
  YARA hit) holds. Set `ARTIFACTFORGE_EF_OUT` to an EF output dir to run it.
- **`tests/test_cross_emitter_join.py`** — one dropper, downloaded *and* executed: using
  EvidenceForge's **own** hash functions the two hashes disagree; the ContentStore unifies
  them into a five-way join, byte-identical across a two-clock determinism check.
- **`tests/test_imphash.py`** — the synthetic PE carries a real, deterministic IMPHASH
  (validated against pefile), not a placeholder.
- **`tests/test_crime_scene.py`** — one dropped binary surfaces as a coherent Windows crime
  scene: the PE (pefile), a Run-key persistence value (regipy), an Amcache record whose
  `FileId` is the PE's SHA1 (regipy), and a prefetch execution record (windowsprefetch) —
  join holds, regenerates byte-identical. A `JOIN_MANIFEST.json` answer key ships alongside.
- **`tests/test_macos_scene.py`** — a macOS scene EvidenceForge structurally can't produce
  (its `os_category` is windows|linux): one app, downloaded (QuarantineEventsV2 + matching
  `com.apple.quarantine` xattr UUID), granted a TCC permission, used (knowledgeC), and
  persisted (LaunchAgent) — joined on the quarantine UUID, validated by sqlite3 + plistlib.

### Breadth as data — `HostProfile`

OS family, version, and settings are a `HostProfile` record, not new code paths, so versions
and settings scale as data files. Coverage stays at the loose-file tier (Windows / macOS /
Linux as families); per-OS block-level disk images remain deliberately out of scope.

## Fidelity ladder (build order)

- **T0/T1 — loose files (here first):** synthetic PE/ELF, registry hives, EVTX, prefetch,
  Amcache; macOS knowledgeC/TCC/FSEvents/quarantine. Validated by pip/apt DFIR parsers.
- **T2 — disk images:** ext4, then NTFS (bespoke, deferred until demand-proven).
- **Never:** memory synthesis, live eBPF, real-OS replay.

## Roadmap

0. **Keystone** — ContentStore + EF seed reverse-map. ✅ *proven*
2. **Windows crime scene** — synthetic PE with real IMPHASH, registry Run-key hive, Amcache,
   prefetch — one coherent story, each artifact real-parser validated. ✅ *done*
3. **macOS artifacts + HostProfile** — knowledgeC / TCC / QuarantineEventsV2 / quarantine
   xattr / LaunchAgent, joined on the quarantine UUID; OS/version/settings as data. ✅ *done*
4. **Scale + grade** — deterministic batch generator + machine-checkable answer keys + an
   agent scorer, with validity gates (reference solver 100%, trivial solvers ~0%). ✅ *done*
5. **More artifacts** — EVTX, ShimCache, LNK (Windows); FSEvents, unified logs (macOS); ELF/Mach-O stubs.
6. **MCP** scenario-serving surface.

### The benchmark (`artifactforge.benchmark`)

`generate_batch(n, out)` produces `n` deterministic, distinct labeled scenarios (~2 ms each).
Each `Task.public()` gives an agent the artifact files and questions; the answer key stays
server-side; `grade(task, answers)` scores a submission. `artifactforge.reference_solver` reads the
artifacts with real DFIR parsers and scores **100%** — proving the answers are *recovered*
from the evidence, not asserted — while null/constant solvers score **0%**.

## Develop

```sh
uv venv && uv pip install -e ".[dev]"
uv run pytest -q                       # the whole suite, standalone — EvidenceForge not needed
```

The EvidenceForge contract tests are optional and CI-only. EvidenceForge is not on PyPI, and
its **distribution** name is `evidence-forge` even though it imports as `evidenceforge`:

```sh
uv pip install "evidence-forge @ git+https://github.com/Cisco-Talos/EvidenceForge@v1.13.1"
uv run pytest -q
```

Everything ArtifactForge generates is **inert and synthetic** — structurally-valid but
non-functional stubs, disclosed per bundle. See [KNOWN_TELLS.md](KNOWN_TELLS.md).
