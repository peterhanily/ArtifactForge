# Roadmap

What is not built, and why. Ordered by what would change the most if it existed.

## The benchmark-validity status is failing because Gate 4 is red

Gate 4 is red and the number is in the README. The `footprint` adversary ranks candidates
without parsing their formats — for each candidate, count how many other files mention its
name and take the maximum — then uses ordinary parsers and lookups to complete the dependent
answers. On the public, non-reportable scorecard measurement corpus it scores **72.7%** against
the committed scorecard's **4.2%** chance floor, where the reference solver scores 100%.

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
generator's Gates 1 to 3 pass and generator assurance is `pass`; benchmark validity remains a
separate failing status.

## Closed measuring-apparatus gaps

The v0.2.0 work closed the former SQLite and binary-plist second-reader gaps. Deliberately
narrow first-party byte readers now pair with `sqlite3` and `plistlib` over one bounded
snapshot, require type-exact consensus, and then apply named macOS semantic profiles. This is
independent implementation, not outside governance or general-format coverage: interior or
overflow SQLite b-trees and binary-plist values outside the emitted subset remain rejected.
The serialized quarantine xattr is still a plain sidecar, not a parser-gated format.

Any future expansion of either writer must expand both the raw reader and its parser-valid
mutation controls in the same change. Apple's `plutil` remains useful native attestation, not
the portable CI oracle.
## Not built

- **Windows 10 prefetch.** The current uncompressed SCCA v17 writer and XP path hash agree
  with each other, but legacy benchmark/gallery scenes still model a Windows 10 host. Fixture
  Core avoids that overclaim with the explicit `windows-loose-v1` profile. A
  version-consistent replacement
  requires a v30 layout plus deterministic MAM/LZXPRESS compression, with independent parser
  and semantic mutation controls retained.
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
- **Zeek-side reconciliation.** Constrained by an unmodified v1.13.1 branch-office run:
  `files.json` has 722 rows, 525 certificate and 197 non-certificate. No non-certificate row
  carries SHA256; 21 carry SHA1, representing 16 distinct values. The same-algorithm Sysmon
  and Zeek sets are disjoint, but their basenames are also disjoint, so the stock run is not a
  same-file positive witness. Any proposed SHA1 join needs a controlled transfer-to-execution
  case before it can be described as repairing an observed broken pivot.
