# ArtifactForge — design

## §1 What this is

ArtifactForge generates **forensic artifacts**: the files a responder finds on a host once
they dig in. A synthetic PE with a real import table and a real IMPHASH; Windows registry
hives carrying Run-key persistence and an Amcache execution record; a prefetch file; macOS
knowledgeC, TCC and QuarantineEventsV2 databases, a quarantine xattr and a LaunchAgent plist.

Everything is a pure function of a seed. No wall clock, no entropy, no PID. The same scenario
regenerates byte-identical forever, which is the property every other claim rests on.

## §2 The premise is a test, not a claim

The interesting question about synthetic evidence is not "does it look realistic". It is
"does a tool a responder actually runs open it, and do the artifacts agree with each other".
Both are pass/fail, so both are gates rather than adjectives.

The second half is the harder one and the reason this project exists. EvidenceForge — whose
synthetic *logs* this complements — computes a file's hashes as digests of a per-emitter seed
string. The same binary therefore carries disagreeing hashes across sources: on one real run,
its Sysmon file-hashes and its Zeek file-hashes have **zero** overlap, so the file-hash pivot,
the core move of DFIR, silently never works.

ArtifactForge's answer is content-first identity. `ContentStore` synthesizes a file's real
bytes once; every hash-shaped field anywhere — Amcache `FileId`, on-disk digest, YARA target,
IMPHASH — is a genuine digest of those same bytes. They agree by construction, and Gate 2
re-derives all of them from disk to prove it.

## §3 Layering

Dependencies point one way:

    model <- content <- artifacts <- compose <- bench <- cli

- `model` — hosts, profiles, pinned times. Depends on nothing.
- `content` — file bytes and their identity. The ContentStore lives here.
- `artifacts` — one module per format, each a pure function, each validated by a real parser.
- `compose` — assembles formats into a scene directory plus its join manifest.
- `bench` — turns scenes into gradeable tasks, and holds the adversary solvers.
- `gates`, `scorecard` — measurement.
- `ingest` — the EvidenceForge companion adapter, outside the chain. Nothing in the chain may
  import it, and upstream's private seed formulas are never re-exported as ArtifactForge API.

ArtifactForge runs standalone. EvidenceForge is a CI-only dev tool, never a declared
dependency: it is not on PyPI, so naming it would force a git URL into the metadata, which
makes the distribution unbuildable.

## §4 Scope and validation gate

A gate is a numbered question wired into six places, and it is not built until all six exist:

1. a module in `artifactforge/gates/`, whose docstring's first line **is the question**
2. a CLI subcommand that exits non-zero when the answer is no
3. a dedicated pytest file
4. a `gates.<name>` block in the committed `fidelity-scorecard.json`
5. a row in `scorecard._METRICS` giving the metric a direction and a tolerance
6. a registered mutation in `tests/test_gate_mutations.py` that turns it **red**

`tests/test_gates.py::test_every_gate_has_all_six_bindings` enforces this mechanically.

The sixth binding is the one that matters. A gate never observed to fail proves nothing, and
this repository shipped tests that stayed green when the data they checked was replaced with
the literal string `GARBAGE-NOT-A-SHA1`.

Failures block. **Declared gaps do not** — they are named limitations carried in the
scorecard's `honest_gaps` so they cannot be forgotten. Anything undeclared is a failure.

### Gate 1 — validity

*Does an independent real parser read every artifact we ship?*

Two independently-implemented parsers per format, because one permissive parser hides what a
strict one rejects. Every prefetch file this project emitted was accepted by
`windowsprefetch` and refused by `pyscca` — the libyal parser plaso is built on — for
eighteen days, because `windowsprefetch` was the only oracle installed.

A missing oracle is a **failure, never a skip**: a skipped check exits 0 and reads exactly
like a passing one. Where no genuinely independent second implementation exists — SQLite
databases and binary plists are read back by the library that wrote them — that is a declared
gap, not silent credit.

### Gate 2 — identity

*Is every hash-shaped field a genuine digest of one ContentStore blob?*

The keystone. Every value is re-derived from the files on disk, through a real parser, and
only then compared. Nothing is compared against the value that produced it. Every check names
the two artifacts it spans, because a check confined to one artifact cannot detect a broken
pivot.

### Gate 3 — inertness

*Can anything we ship execute, and is every format marked synthetic?*

Generated binaries reproduce the forensic **signal** — a real import table, a real symbol
table, a real hash — and never the offensive **capability**: the code section is a single
return and nothing else, checked on the emitted bytes. Every format carries an in-band
`ARTIFACTFORGE` anchor so a file that escapes its bundle is still recognisable. Domains must
be RFC 2606 reserved and addresses RFC 5737 / RFC 3849, so no artifact can name a host that
might be real.

### Gate 4 — solvability

*Are the benchmark's answers recovered from evidence, or derivable?*

A reference solver scoring 100% proves the artifacts *encode* the ground truth. It does not
prove that is the only way to get it — and here it was not: because the generator is open
source and the public scenario identifier was also its generation seed, a solver opening zero
files reproduced every answer. So the gate measures three things: the reference solver
scores 100%; every adversary (blind, listing, null, constant) stays under its threshold; and
at least one question per family is answerable **only** by joining two artifacts, without
which the benchmark cannot detect a broken pivot at all.

## §5 The scorecard

`fidelity-scorecard.json` is committed at the root and carries what the gates actually
measured, including what they measured badly. It ships reading whatever it honestly reads; a
scorecard saying `pass` on day one would be the least believable thing in the repository.
Regression is enforced by one declarative table, with tolerance 0 on every count: an artifact
that used to be readable and now is not, or a join that used to hold and now does not, is a
regression at any magnitude.
