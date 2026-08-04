# Roadmap

This document lists open work. Completed hardening phases are recorded in
[`IMPROVEMENT-PLAN.md`](IMPROVEMENT-PLAN.md), and released history belongs in
[`CHANGELOG.md`](../CHANGELOG.md).

## 1. Hosted evidence and release controls

The local release machinery is complete, but a repository workflow definition is not proof
that a protected release ran. The next external steps are:

1. Configure reviewers and protection for the `release-attestation` environment and exact
   annotated version tags.
2. Run the manual exact-tag workflow and retain its GitHub and Sigstore attestations for the
   wheel, source archive, and SBOM subjects.
3. Obtain the first successful fixed-runner Windows-native result for the current source.
4. Keep CPython 3.14 core-only until the complete locked oracle set installs, imports, and
   passes its controls. `dissect-target==3.25.1` and `yara-python==4.5.4` are the current
   promotion blockers.

Publishing to PyPI, creating a GitHub release, and creating or pushing a tag remain separate
approval-gated actions. See [`releasing.md`](releasing.md).

Scanner evidence is also separate from generator and benchmark gates. The latest Phase 6C
checkpoint remains red overall, while the older Phase 6B checkpoint applies only to its
historical corpus. [`SECURITY.md`](../SECURITY.md#scanner-claims-require-an-attestation) owns
the exact records and limitations.

## 2. Benchmark v3 needs an external witness

Benchmark v1 is withdrawn. Its answer layout, caller-visible evaluator state, disclosed key,
and incorrect chance model allowed shortcut recovery without the intended artifact joins.

V2 replaces root-object questions with five scalar closed-rule questions per scene. It adds a
separate public export, suite binding, parser-valid counterfactuals, exact inference, registered
attacks with positive controls, and representative all-mapping proofs. V2 is still permanently
non-reportable because the caller supplies the raw key.

V3 creates a separate internally keyed ceremony, canonical precommitment, one-shot POSIX
ledger, feedback-withholding receipt, and detached retired report. Those controls close repeat
feedback through one intact local ledger. They cannot prove that the evaluator was hidden from
the solver, that only one ledger existed, or that the ledger owner did not inspect the result.

The remaining work is external:

1. Transfer only the public export to an OS-enforced solver account, container, VM, or machine
   with no evaluator mount.
2. Bind the solver source, configuration, and execution image before the reveal is transferred.
3. Have an independent witness attest the trust boundary, unique designated attempt, accepted
   precommitment, and retired evidence bundle.
4. Preserve the disclosed-key and parent-traversal positive controls.

The v3 ceremony also binds a theoretical population and power contract, but construction does
not run that contract on the realized suite. A future versioned gate should execute and record
the per-suite checks. The standalone feature-conditioned audit should enter a protocol only
after the comparison family and power analysis are recalculated.

Longer-term benchmark work includes broader control calibration, more question shapes, and a
server-side grading service. Any network service must preserve exact suite identity, keep keys
and answers server-side, reject cross-suite submissions, and define authentication, rate, and
retention policy.

## 3. Windows coverage

Portable phases 6A through 6C are complete:

- Chromium completed-download history joined to one logical Zone.Identifier and resident PE
- disabled Task Scheduler XML and a standalone local-file Shell Link, both joined to distinct
  non-persistence resident PEs
- deterministic MAM algorithm-4 compressed SCCA v30 variant-1 Prefetch with an expected-size
  framing reader and pyscca/Dissect semantic agreement

The current v30 Prefetch writer deliberately covers one metric, one volume, one trace entry,
two strings, and a single compression chunk. Open extensions include version 31, alternate v30
layouts, multiple volumes, directory strings, MFT references, and broader XPRESS-Huffman
encodings. A hosted schema-v6 run completed the Windows `RtlDecompressBufferEx` canary before
a later Shell Link contract failure. A complete passing schema-v7 report remains pending.

TaskCache and Jump Lists remain deferred. TaskCache requires defended writers and independent
readers for its Actions, Triggers, DynamicInfo, Hash, and security-descriptor blobs. Automatic
Jump Lists require a defended Compound File Binary container in addition to the existing Shell
Link profile.

Later candidates are EVTX, ShimCache, SRUM, and the USN journal. EVTX has the highest value and
the largest implementation cost because its binary XML template model needs its own writer,
reader, profile, and mutation suite.

## 4. Linux and macOS coverage

The current Linux profile contains five minimal glibc/x86-64 ELF files, three XDG autostart
records, and one timestamped Bash history. Useful extensions include compiler-shaped ELF,
package metadata, systemd, cron, auditd, journald, session state, and alternate shell history.
A claim that autostart succeeded would require a separate native materialization and activation
profile. The loose carrier does not provide that evidence.

Potential macOS additions include FSEvents and Spotlight. Unified logs are deferred because
the `tracev3` format is undocumented and available readers do not provide a stable independent
oracle. A bundle-shaped `.app` profile is also required before Gatekeeper can have a meaningful
target and positive control.

Any new writer must arrive with two read paths, a named semantic profile, inertness and marker
handling, resource bounds, and mutations that turn each new claim red.

## 5. Identity and format infrastructure

Fixture Core already publishes the complete path, size, and SHA-256 integrity relation. Gate 2
uses private family-specific truth, and benchmark answers must not enter served artifacts. No
current consumer needs another digest graph.

If a named external consumer later needs additional whole-file digest aliases, the smallest
acceptable design is an ephemeral view computed inside Fixture Core's held verified snapshot.
It should expose equality observations only, not inferred roles, provenance, causality, or
authenticity. See [`identity-boundaries.md`](identity-boundaries.md).

The owned SQLite and binary-plist readers intentionally cover their emitted subsets. Broader
writers must extend both readers and add parser-valid negative controls in the same change.
Native tools can add observations, but they do not replace the portable oracle contract.

## 6. EvidenceForge

The unmodified v1.13.1 branch-office `files.json` has 722 rows, 525 certificate and 197 non-certificate.
No non-certificate row carries SHA256; 21 carry SHA1, representing 16 distinct values. Its
same-algorithm Sysmon and Zeek sets are disjoint, but their basenames are also disjoint, so the
stock run is not a same-file defect witness.

The controlled scenario supplies the missing transfer-to-execution relation and its negative
controls. It demonstrates a modeled logical-file nonjoin. EvidenceForge does not materialize
common executable bytes, so the proposal is an explicit opt-in content identity rather than a
claim about byte-digest corruption.

The witness, measurement, issue draft, RFC, and two review patches live under
[`integration/evidenceforge/`](../integration/evidenceforge/). ArtifactForge has already been
mentioned in a
[public EvidenceForge #332 follow-up](https://github.com/Cisco-Talos/EvidenceForge/issues/332#issuecomment-5152265897).
The formal issue and patches remain local. The next step is maintainer feedback on whether this
relationship belongs in EvidenceForge.

## 7. Out of scope

- **Disk images:** a deterministic filesystem writer with adequate independent validation is a
  separate research project. NTFS would be the first candidate.
- **Memory images:** making Volatility accept a synthetic memory image is a different discipline
  from creating loose file artifacts and is not planned.
- **Threat intelligence:** ArtifactForge values are synthetic fixtures. They are never
  indicators to publish or block.
