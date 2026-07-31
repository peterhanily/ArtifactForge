# ArtifactForge — Addressing the Review: Methods + Phased Plan (2026-07-20)

*Grounded in this session's experiments (Method A and B prototyped and measured on the real
EvidenceForge run) and cited web research (augmentation patterns, CAS integrity, binary-writer
testing, reproducible builds, CI-for-external-deps).*

## The shape of the problem

The review's findings split cleanly:

- **Robustness / CI / integrity** (cache atomicity, filename collisions, defensive parsing,
  the silently-skipped real-run test) are *not* architectural — they're "do them." They're
  Phase 0.
- **The one architectural decision** is where file **content-identity** gets reconciled with
  EvidenceForge's **logs**, because the repo currently proves neither the cross-tool join nor
  runs the reverse-map in CI. That decision is a real 3-way fork.

## What the experiments proved this session

| Method | Result | Numbers |
|---|---|---|
| **A. Downstream patch** — rewrite a copy of EF's emitted logs so each hash = ContentStore digest | **Works end-to-end (Sysmon)** | 13,748/13,748 real (non-tautological) joins: patched-log SHA256 == sha256(on-disk bytes); IMPHASH confirmed by pefile as a 2nd parser; negative control 0/64,770 off-diagonal; ~1.8 s whole run; deterministic |
| **B. In-process injection** — patch EF's live hash functions to route through ContentStore at generation time | **Works (cross-emitter)** | Sysmon SHA256 == Zeek SHA256 == on-disk bytes (`ce640b9e…`); 3 `file_transfer_hashes` bindings + Sysmon classmethod |
| **The shared wall** | EF doesn't model "this download *is* this executed file" | Both A and B need a **scenario-level identity link** to join *across* emitters; within one emitter both work today. On a normal run EF emits cert hashes, not PE-download hashes, so no shared Sysmon↔Zeek binary exists without a dropper scenario |

## The three methods (with research-grounded tradeoffs)

**A. Downstream Patcher (anti-corruption adapter).** Read EF output → reverse-map identity →
patch a copy. *Pros:* rides EF's mature stack (66k events, 20+ artifact types) for free; fast;
deterministic; honors never-push; **works today**; is the missing repo proof. *Cons:* depends
on EF's **private, undeclared** seed formulas — the exact surface SemVer refuses to protect
(Hyrum's Law), and the precise pattern that silently broke Microsoft Sentinel when Sysmon's
schema advanced (Azure-Sentinel #387). Sysmon-only in practice; can't add artifacts EF didn't
emit; drift degrades coverage *silently*.

**B. In-process Injection.** Import EF, monkeypatch its hash seams so EF emits content-true
logs natively. *Pros:* real EF logs with true hashes; no reverse-mapping; cross-emitter join
works. *Cons:* monkeypatching private internals is a pattern the industry has **renounced** for
production — Node.js replaced it with `diagnostics_channel`, Shopify/Rails upstreamed and
archived their patch gem, and the Windows-EDR kernel-hooking equivalent (CrowdStrike 2024)
pushed Microsoft to build official extension points. Version-fragile. **Best used as a
prototype, not a product.**

**C. Native Co-generation.** ArtifactForge owns the canonical scenario and emits **both** the
logs and the artifacts from one identity (the benchmark path already does exactly this).
*Pros:* zero coupling to EF internals; the join is real **by construction**; no version
fragility; it's where the defensive-agent purpose actually lives; matches the only validated
prior-art architecture for this (OrgForge-IT, arXiv 2603.22499: "deterministic engine holds
ground truth, generator renders"). *Cons:* re-emits EF-shaped logs (a subset) rather than
inheriting EF's full realism — so pair it with A for enrichment.

**End-state — Upstream ContentIdentity PR.** Contribute content-first identity to EF itself.
Research is unambiguous: **contribution is the only strategy that stops the maintenance clock**
(reverse-mapping/injection are a subscription paid every EF release). Cost: David's buy-in,
3+ subsystems (public API, materialize bytes for executed PEs, thread through the dispatcher,
extend GROUND_TRUTH). Method B is the working prototype that de-risks and *sells* this PR.

## Key research findings that decide the ordering

1. **The private-surface dependency in `ef_seeds.py` is the concentrated risk** (Hyrum's Law;
   SemVer only protects declared APIs). Isolate it as an anti-corruption layer, pin EF exactly,
   and add **version-pinned golden-formula tests** so drift fails *loud*.
2. **Monkeypatching is a renounced production pattern** → Method B is a prototype for the
   upstream PR, not a shipping architecture.
3. **Contribution is the only clock-stopper** → the upstream PR is the strategic end-state.
4. **CAS integrity has one canonical pattern** (restic reference): temp-file-in-same-dir →
   `fsync(file)` → `os.replace()` → **`fsync(dir)`**; keep reads trust-path + one opt-in scrub.
   Content-addressing already gives lock-free concurrent-writer safety.
5. **CI "skip is green" is a real trap** (GitHub: a skipped required check *passes*). Fix:
   generate an EF run in CI, set the env var, convert skip→hard-fail, add an alls-green gate
   job, and a scheduled `latest`-EF canary for drift.
6. **Registry and prefetch have no authoritative parser** (all are clean-room) — so state their
   fidelity conservatively; add Hypothesis `RuleBasedStateMachine` differential tests for the
   stateful writers. PE (the loader) and SQLite (the engine) *do* have ground truth — reach for it.
7. **The determinism half is solved** (reproducible-builds checklist: fixed `PYTHONHASHSEED`,
   `LC_ALL=C` sorted iteration, zeroed padding) — formalize it. The
   byte-reproducible-artifacts + co-generated-logs + shipped-answer-key intersection has **no
   found prior art** — the core bet is novel and sound.

## Final recommendation — phased

**Phase 0 — Unconditional hardening (days). Turns silent failures loud; no architecture change.**
- Cache-integrity fix (H1): atomic `os.replace` + `fsync` + verify-on-hit + one opt-in scrub.
- Robustness: reserve/sanitize artifact filenames (M1) and `bundle_id`/basenames (M2);
  defensive parsing in `grade()` and the Sysmon `Hashes` split (M4/M5); validate `run_count`,
  `out_dir` (M6/L1); UTF-16 registry names or disclose ASCII-only (M3).
- CI: generate a small EF run in CI, set `ARTIFACTFORGE_EF_OUT`, convert the real-run skip to a
  hard failure, add an alls-green gate as the required check, add a `latest`-EF canary.
- Determinism: adopt the reproducible-builds checklist explicitly.
- Testing: add Hypothesis stateful differential tests for the hive/SQLite writers; keep ≥2
  independent parsers (already done for hive/PE); state registry/prefetch fidelity conservatively.
- *Closes:* every 🔴/🟠 robustness finding and the silently-skipped test.

**Phase 1 — Make the real join real in the repo (Method A, productionized). The "before David" gate.**
- Port the validated patcher into the repo as an **isolated anti-corruption adapter**; replace
  the tautological `test_real_run_join` assertion with the true one (patched-log hash ==
  on-disk bytes), which the experiment already demonstrated at 13,748/13,748.
- Add golden-formula tests pinned to EF `@v1.12.0` so a seed-formula change fails loudly.
- Make `content_id()` verify recomputed == emitted and refuse to route unverified identities.
- Fix the README to describe identity-recovery + patched-copy reconciliation accurately.
- *Closes:* the 🔴 overstated-join finding and the 🔴 silent-mis-ID coupling risk.

**Phase 2 — Native co-generation as the primary value path (Method C). Decouple the product from EF's internals.**
- Lean into the benchmark's already-native generation: the defensive-agent eval environment
  needs no EF at all, and its join is real by construction. Make this the headline product;
  use Method A as optional *realism enrichment* on top, never the foundation.
- *Payoff:* the core value stops depending on EF's private surface; the novel, prior-art-free
  capability (byte-reproducible artifacts + consistent logs + shipped answer key) is the pitch.

**Phase 3 — Upstream ContentIdentity contribution (the clock-stopper). The David conversation.**
- Bring Method B's working in-process injection as the **prototype** ("here's the seam, here's
  the win: Sysmon == Zeek == bytes") to motivate a minimal, gated-off-by-default EF PR that
  materializes bytes once and threads one identity through the emitters + GROUND_TRUTH.
- *Payoff:* ends the reverse-map maintenance subscription; makes ArtifactForge-as-patcher
  unnecessary; the only strategy research says stops the clock.

**Why this order:** de-risk silent failures first (Phase 0), then make the headline claim
actually true in the shipped code (Phase 1) so the David conversation rests on real proof,
then decouple the product's core value from the fragile dependency (Phase 2), and only then
invest in the upstream change that ends the treadmill (Phase 3) — carrying a working prototype,
not a proposal.
