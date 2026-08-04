# ArtifactForge v0.5 corrective follow-up draft

> Status: an earlier ArtifactForge follow-up is already public in
> [EvidenceForge #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332#issuecomment-5152265897).
> This file is local corrective wording, not a claim that no message has been posted.

Hi @DavidJBianco, following up on the loose-artifact demo repo I mentioned:

**https://github.com/peterhanily/ArtifactForge** (MIT, experimental, with the same
temporary-repository caveat as PacketForge)

ArtifactForge generates the files a responder would inspect rather than the logs: synthetic
PEs, registry hives, deterministic MAM algorithm-4 compressed SCCA v30 Prefetch, arm64 Mach-O
files, knowledgeC/TCC/QuarantineEventsV2, serialized quarantine xattrs, LaunchAgent plists, and
Linux ELF/XDG/Bash-history artifacts. The public v17/XP Prefetch functions remain frozen
compatibility APIs; current scenes select the v30 writer explicitly.

The narrow claim is machine-gated. Answer-bearing content hashes are recomputed from the emitted
bytes, and declared cross-artifact relationships are re-derived through parsers. Gate 1 requires
two independent read paths and names the semantic depth checked. The current Mach-O profile
requires typed LIEF/macholib consensus over its bounded load-command, segment, section, import,
entry-point and signature fields. The macholib-side adapter uses bounded raw decoding for fields
its API does not expose, and the exact writer profile is checked after consensus. Gate 2 checks
declared byte/record pivots, and Gate 3 verifies the static inert construction and in-band
disclosure contract. Parser consensus is not a native or runtime claim, and every format
limitation is listed in `KNOWN_TELLS.md`.

I also rebuilt the benchmark after invalidating its first design. Benchmark v1 is withdrawn:
completed shortcut attacks broke its framing, and its candidate-aware chance model was wrong.
The v0.5 Gate 4 validity check passes over a predeclared finite registry of attacks, exact
scene-level randomization tests and parser-valid counterfactuals. Independent positive controls
cover the eight complete attacks and both production ensembles; constant, listing and null are
measured low-information baselines, not calibrated detectors. These are diagnostics, not a
performance score. Every v2 suite is permanently nonreportable because its raw key is supplied
by the caller; a fresh v2 holdout cannot change that protocol boundary. Benchmark v3 is a
distinct internally keyed local ceremony with a one-shot ledger, but it also remains
nonreportable pending an independent witness and OS-enforced solver trust-domain evidence.

Corrections to the earlier description:

- The latest local scanner checkpoint is the 2026-08-04 Phase 6C record described in
  [`SECURITY.md`](../../SECURITY.md#latest-phase-6c-checkpoint-2026-08-04). It is red overall.
  ClamAV and the selected XProtect rules completed controlled no-detection slots, but community
  YARA had compile failures and refused the over-budget corpus scan. Gatekeeper remains
  inapplicable to the loose target. The record supports neither an overall clean claim nor a
  community-YARA coverage claim. ArtifactForge contains no upload path, and I have not submitted
  its artifacts to VirusTotal or another shared threat-intelligence service.
- `pyscca` opens the current v30 Prefetch and agrees with Dissect on the bounded typed semantic
  view; the first-party expected-size reader owns MAM framing because Dissect is semantic-only.
  I have not run a Plaso extraction and do not infer Plaso compatibility from its underlying
  libyal library. Gatekeeper remains inapplicable to the loose target. The Mach-O entry/body
  check is static; ArtifactForge does not execute it and does not claim a runtime return status.
- Fixture ABI v1 does not bind the SQLite producer and remains a producer-sensitive parse-only
  contract, so v1 makes no cross-runtime byte-identity claim. Fixture ABI v2 repairs the current
  contract by binding `artifactforge-owned-sqlite-leaf-v1`; the claim remains scoped to that
  versioned ABI and producer profile.
- The EvidenceForge stock run's disjoint Sysmon/Zeek hash sets were not by themselves a defect
  reproducer: the compared populations had no transfer/execution basename overlap. I added a
  digest-blind controlled witness for one explicitly modeled download-to-execution relation.
  Its SHA1 values do not join, but EvidenceForge does not materialize common file bytes, so the
  defensible question is whether an opt-in logical-content identity belongs in the model.

The EvidenceForge correction is written as an RFC rather than a bug assertion. It proposes
role-specific, opt-in content references that leave legacy datasets byte-for-byte unchanged.
The material is indexed from `integration/evidenceforge/` and stored across that directory,
`measurements/`, `scripts/` and `tests/`; generated output trees are not committed. In local
release validation, I installed the exact v1.13.1 tag, verified that it resolved to the pinned
commit, regenerated the stock run, and byte-compared the complete measurement. ArtifactForge's
formula reproduction matched the upstream implementation, and all 853 hashed stock-run Sysmon
records were recovered and verified. The fresh measurement matched the committed record
byte-for-byte. The producer commit is explicit external provenance; it is not inferred from
the generated bytes.

I also renamed the sample answer files from `GROUND_TRUTH.json` to
`ARTIFACT_ANSWERS.json` after noticing EvidenceForge's evaluator searches the parent directory
for that exact filename. There is no intentional interaction with its loader now.

No action is requested. No upstream EvidenceForge branch or repository is modified or pushed.
EvidenceForge is neither an ArtifactForge runtime nor development dependency; the pinned and
drift-canary contract jobs install it only in isolated CI jobs. The public #332 follow-up
already exists; the formal issue/RFC and patches in this repository have not become a new issue,
pull request, upstream branch or push. Feedback on whether the RFC fits the upstream model is
welcome.
