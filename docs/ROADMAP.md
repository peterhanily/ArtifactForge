# Roadmap

What is not built, and why. Ordered by what would change the most if it existed.

## Benchmark v2 needs an isolated hold-out result, not another public score

Benchmark v1 is withdrawn. Completing its shortcut implementations exposed perfect footprint
and stored-order recovery, the co-located task path exposed evaluator answers, a disclosed-key
corpus was reproducible without reading its target artifacts, candidate-aware chance was about
one in five, and the claimed join count was not a parser-derived dependency trace. Changing a
threshold cannot repair those failures.

V2 replaces root-object questions with five scalar closed-rule questions per scene. Windows
resolves an Amcache `FileId` SHA-1 against five resident PE byte strings; macOS resolves a
strict xattr UUID against five `QuarantineEventsV2` rows. Each family forms a five-answer
bijection with exact 20% chance. Exact public export and `suite_id` binding separate solver
bytes from evaluator state. Gate 4 derives actual artifact dependencies, checks complete
selection attacks in aggregate and per class with exact permutation inference, enforces at
least 20 scenes per class and an exact power contract, and requires parser-valid local-effect
counterfactuals.

The v0.5 portable release matrix, packaging/install checks, available native macOS attestation
and source-bound scorecard are complete locally. Hosted CI must independently replay the exact
tagged commit after it is pushed; no hosted result is claimed before that happens. The remaining
benchmark work is operational and evidentiary:

1. **Execute a real hold-out boundary.** Mint a fresh key on the evaluator, transfer only the
   exact public export into a separate OS-enforced account/container/VM/machine with no
   evaluator mount, return only `suite_id`-bound submissions, and grade on the evaluator.
2. **Preserve the hostile controls.** Disclosed-key blind reconstruction and co-located parent
   traversal must remain positive controls; public development and scorecard corpora remain
   non-reportable even when every gate is green.
3. **Audit before quoting.** Preserve corpus/source/export/submission provenance and review the
   per-family/rule randomization and counterfactual results. Until that workflow is complete,
   no v2 performance score is reportable.

No fresh scanner attestation exists for the v2 corpus. Scanner evidence is a separate dated
claim about exact bytes and cannot be inferred from benchmark or generator gates. The full
contract is [`benchmark-v2.md`](benchmark-v2.md).

## Closed measuring-apparatus gaps

The v0.2.0 work closed the former SQLite and binary-plist second-reader gaps. Deliberately
narrow first-party byte readers now pair with `sqlite3` and `plistlib` over one bounded
snapshot, require type-exact consensus, and then apply named macOS semantic profiles. This is
independent implementation, not outside governance or general-format coverage: interior or
overflow SQLite b-trees and binary-plist values outside the emitted subset remain rejected.
The serialized quarantine xattr is now parser-classified. Its artifact parser and an
independently implemented byte reader require type-exact agreement and the exact bounded
four-field profile; Gate 3 grants only strict-valid non-executable values its narrow marker
exemption.

Any future expansion of either writer must expand both the raw reader and its parser-valid
mutation controls in the same change. Apple's `plutil` remains useful native attestation, not
the portable CI oracle.

The first Linux loose profile is now closed on the same terms: LIEF/pyelftools for ELF,
PyXDG/raw for desktop entries, and dissect.target/raw for Bash history, with independent
meaning and inertness mutations. It is generator assurance and Fixture Core material only;
Gate 4 remains the Windows/macOS benchmark population.

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

- **Broader detector calibration.** The current ten mandatory controls use one independently
  derived development scene per family for each registered complete attack and the two
  production ensemble wrappers. A later protocol revision should calibrate across multiple
  independently derived scenes per family, so success cannot depend on one fixture, and add a
  feature-conditioned development-trained attack to probe selector/name/content correlations
  beyond fixed ranks and slot unions. Any added detector expands the predeclared comparison
  family and must carry its own vulnerable-world control and power analysis.
- **Portable hold-out execution receipts.** The local grader correctly refuses to mint a
  reportable result because it cannot attest the solver trust domain. A future runner should
  produce a signed or independently witnessed receipt binding evaluator source, fresh-key
  identity, exact public tree commitment, solver image/configuration, isolation policy,
  submission digest and grader output. The receipt must not disclose the key or answers and
  must remain separate from the reproducible public scorecard.
- **A scoring service.** Evaluator-side local grading is sufficient for the current protocol;
  `_answers/` never enters the public export and every JSONL row carries the exact `suite_id`.
  A future network wrapper must preserve that identity, keep keys/answers server-side, reject
  cross-suite rows and add authentication/rate/retention policy without weakening the existing
  filesystem boundary.
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
