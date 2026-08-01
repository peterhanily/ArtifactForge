# Roadmap

What is not built, and why. Ordered by what would change the most if it existed.

## The benchmark is failing its own validity gate

Gate 4 is red and the number is in the README. A solver that parses nothing — for each
candidate, count how many other files mention its name, take the maximum — scores **72.7%**
against a **4.2%** chance floor, where the reference solver scores 100%.

It is structural. The answer object is by definition the one the registry, Amcache, prefetch
and disk all talk about; a decoy appears in fewer of them. Counting mentions *is* the intended
pivot, performed without understanding. And it cannot be patched in the generator alone: for
`persisted_sha256` the declared pivot is "the one Run value naming a resident program", so
balancing the scene until decoys are mentioned equally makes the reference solver fail with
*"expected exactly one resident autostart, found 5"*. The question and the leak are one object.

What the repair looks like, in order:

1. **A class gate.** Not an exemption list of the leaks found so far — those were found by
   sweeping, and the sweep found families nobody would have enumerated (position inside a
   stored sequence: Run-value order, Amcache subkey order, SQLite rowid). The durable form is
   "no agent-visible quantity predicts any answer above chance, over every candidate slot".
2. **Delete rather than patch.** `persisted_sha256`, `persisted_imphash` and
   `persisted_run_count` go; `orphan_execution` is rewritten to ask for the SHA1 Amcache
   recorded rather than the filename, which takes a listing-only solver from 100% to 0%;
   `amcache_match_sha256` survives, because value agreement between two artifacts is the one
   answer shape that resists a knowledge-free solver.
3. **The rule that falls out**, and which belongs in `docs/DESIGN.md`: an answer must be
   determined by **agreement between two artifacts' values** — never by an extremum, a
   presence test, a name, or a position in a stored sequence.

Until that lands the benchmark is experimental and no score from it should be reported. The
generator and Gates 1 to 3 are unaffected by any of it.

## Open gaps in what already ships

These are the two declared gaps in `fidelity-scorecard.json`. They are limits of the measuring
apparatus rather than failures of the thing measured, which is why they do not set the
verdict — that currently reads `fail`, because of Gate 4 above.

- **No independent oracle for SQLite or plists.** `sqlite3` and `plistlib` write and read
  their own formats, so knowledgeC, TCC, QuarantineEventsV2 and the LaunchAgent plists have no
  outside opinion on them. Every other format has two independently implemented parsers.
  Candidates worth evaluating: `mac_apt`'s readers, Apple's `plutil` (macOS-only, so it cannot
  be the CI oracle), or a from-scratch bplist reader whose only job is to disagree.
- **The prefetch name hash is bespoke.** It is the SCCA Vista algorithm seeded with 0 rather
  than 314159, so it is not the value Windows would compute for the same path. libscca never
  validates it, so nothing rejects the file — but anyone who recomputes the real algorithm
  will notice, and it is listed in `KNOWN_TELLS.md` for that reason.

## Not built

- **Linux.** No ELF writer, no `HostProfile` constructor, no scene. The layering supports it —
  `content/` would gain `elf.py` beside `pe.py` and `macho.py`, and Gate 1 would need two ELF
  parsers, of which `pyelftools` and LIEF are the obvious pair. This is the largest missing
  family and the cheapest of the three to add.
- **More Windows artifacts.** EVTX, ShimCache, LNK, SRUM, USN journal. EVTX is the valuable
  one and also the hardest: the binary XML template model is substantially more work than
  everything currently in `artifacts/` put together.
- **More macOS artifacts.** FSEvents, unified logs, `Spotlight-V100`. Unified logs are
  effectively out of reach — the `tracev3` format is undocumented and its open-source readers
  disagree with each other, so there would be no oracle worth the name.
- **Disk images.** Deliberately excluded. The tier here is loose files a responder's tools
  read directly, and a filesystem writer that no deterministic implementation exists for would
  be a research project rather than a feature. NTFS would be the one to attempt first, being
  the best documented and having the most lenient parsers.
- **Memory.** Not attempted, and not planned. Synthesizing a memory image that Volatility
  believes is a different discipline from synthesizing a file that a file parser believes.

## Benchmark

- **A scoring service.** Grading is a function call reading `_answers/` from disk, which is
  enough while suites are minted locally: the boundary that matters is the key file, not a
  network. If suites are ever distributed, the submission format (`answers.jsonl` plus a suite
  digest) is already the contract an HTTP scorer would wrap.
- **More question shapes.** Everything asked today has one exact string answer. Questions with
  a set-valued answer, or asking for an ordering, would measure something the current shapes
  cannot — and would need a grader that can score partial credit without becoming generous.
- **Difficulty as a dial.** The decoy counts are fixed constants in `compose/scene.py`. Making
  them a parameter is easy; deciding what "harder" should mean, and showing that the harder
  setting is harder for a reason other than more files, is not.

## EvidenceForge

- **The upstream contribution.** Sketched in
  [`integration/evidenceforge/`](../integration/evidenceforge/), not proposed to anyone. The
  next step is a one-paragraph issue asking whether it would be wanted, not code.
- **Zeek-side reconciliation.** Constrained by a measurement: in a stock run, no
  non-certificate `files.log` record carries a SHA256 at all, and HTTP records carry SHA1 at
  best. Any Zeek join has to be specified on SHA1 or it is unfalsifiable.
