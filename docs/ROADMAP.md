# Roadmap

What is not built, and why. Ordered by what would change the most if it existed.

## Open gaps in what already ships

These are the two entries in `fidelity-scorecard.json`'s `honest_gaps`, and the reason its
headline verdict reads `gap`.

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
