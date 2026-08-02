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

The first Linux loose profile is now closed on the same terms: LIEF/pyelftools for ELF,
PyXDG/raw for desktop entries, and dissect.target/raw for Bash history, with independent
meaning and inertness mutations. It is generator assurance and Fixture Core material only;
Gate 4 remains the unchanged Windows/macOS benchmark population.

## Digest-evidence graph deferred after consumer audit

No current consumer needs a new graph. Fixture Core already publishes the complete
path/size/SHA-256 integrity relation; Gate 2 consumes private family-specific scene truth; and
benchmark joins/answers must not cross into served artifacts. EvidenceForge's proposed
role-specific logical-content reference can represent content without materialized bytes and
therefore belongs in its own scenario schema, not in an ArtifactForge byte graph.

The decision and reconsideration trigger are in
[`identity-boundaries.md`](identity-boundaries.md). If a named external caller later needs
additional whole-file digest aliases, the maximum justified first step is an ephemeral view
computed inside Fixture Core's held verified snapshot. It must expose equality observations,
not roles, match edges, provenance, authenticity or causality.

## Not built

- **Windows 10 prefetch.** The current uncompressed SCCA v17 writer and XP path hash agree
  with each other, but legacy benchmark/gallery scenes still model a Windows 10 host. Fixture
  Core avoids that overclaim with the explicit `windows-loose-v1` profile. A
  version-consistent replacement
  requires a v30 layout plus deterministic MAM/LZXPRESS compression, with independent parser
  and semantic mutation controls retained.
- **Broader or activation-ready Linux.** The first profile is deliberately just five minimal
  glibc/x86-64 ELF files, three XDG autostart records and one Bash history. There is no
  compiler-shaped ELF, package metadata, systemd unit, cron, auditd, journald, login/session
  state or alternate shell history. Fixture ABI v1 does not bind POSIX modes, so modeling a
  runnable filesystem or successful autostart would require an explicit ABI v2 rather than a
  quiet reinterpretation of v1.
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

- **The upstream contribution.** A controlled scenario, output-tree-bound measurement,
  mutation-tested verifier, issue draft, role-specific content-identity RFC and two validated
  review patches now live in
  [`integration/evidenceforge/`](../integration/evidenceforge/). Nothing has been posted or
  pushed upstream. The remaining external step is maintainer feedback on whether an explicit,
  opt-in logical-content relationship belongs in EvidenceForge at all.
- **Zeek-side reconciliation.** The unmodified v1.13.1 branch-office run established the
  population boundary:
  `files.json` has 722 rows, 525 certificate and 197 non-certificate. No non-certificate row
  carries SHA256; 21 carry SHA1, representing 16 distinct values. The same-algorithm Sysmon
  and Zeek sets are disjoint, but their basenames are also disjoint. The controlled witness now
  supplies the positive transfer-to-execution pair: exact ground-truth path equality, dual
  Zeek UID/FUID correlation, Sysmon PID/ProcessGuid correlation, timeline ordering and three
  negative controls all pass before its unequal SHA1 values are compared. It proves a modeled
  logical-file nonjoin, not disagreement over common materialized bytes.
