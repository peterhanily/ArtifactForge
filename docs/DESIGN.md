# ArtifactForge — design

## §1 What this is

ArtifactForge generates **forensic artifacts**: the files a responder finds on a host once
they dig in. A synthetic PE with a real import table and a real IMPHASH; Windows registry
hives carrying Run-key persistence and an Amcache installation record; a prefetch file; macOS
knowledgeC, TCC and QuarantineEventsV2 databases, a quarantine xattr value serialized as a
sidecar file, and a LaunchAgent plist; or nested Linux ELF64 files, XDG autostart entries and
timestamped Bash history.

Everything is a pure function of a seed. No wall clock, no entropy, no PID. The same scenario
regenerates byte-identical forever, which is the property every other claim rests on.

## §2 The premise is a test, not a claim

Two useful questions about synthetic evidence are "does a tool a responder actually runs open
it?" and "do the declared cross-artifact pivots agree?" Both are pass/fail, so both are gates
rather than adjectives. They establish parser readability and selected consistency properties,
not realism in general; `KNOWN_TELLS.md` records the remaining fidelity limits.

The second half is the harder one and the reason this project exists. EvidenceForge — whose
synthetic *logs* this complements — computes these values from emitter-local synthetic seed
domains rather than from file bytes. On one unmodified branch-office run, the same-algorithm
Sysmon and Zeek digest sets have zero overlap. Their basenames have zero overlap as well, so
that stock run does **not** prove that one logical file received inconsistent hashes across two
emitters; a controlled transfer-to-execution witness is required for that causal claim.

ArtifactForge's answer for materialized, answer-bearing binaries is content-first identity.
`ContentStore` synthesizes a binary's bytes once and derives its content digests and structural
hashes from those bytes and their parsed structures. The selected Amcache-to-disk and
answer-key-to-disk pivots reuse that identity, and Gate 2 re-derives those declared checks from
disk. Deliberate stale and absent Amcache decoys are outside that content-blob claim.

## §3 Layering

Dependencies point one way:

    model <- content <- artifacts <- compose <- fixture / bench <- cli
    inventory ---------------------> compose / fixture / bench / gates

- `model` — hosts, profiles, pinned times. Depends on nothing.
- `inventory` — canonical recursive loose-file paths, bounded no-follow capture and exclusive
  scene publication. Depends only on the standard library.
- `content` — file bytes and their identity. The ContentStore lives here.
- `artifacts` — pure builders for the structured formats and plain sidecar values; classified
  formats are validated by their declared readers.
- `compose` — assembles formats into a scene directory plus its join manifest.
- `fixture` — turns a public recipe into a canonical, byte-bound loose-file bundle. It drops
  the private scene join and stays separate from benchmark suites because its manifest
  publishes content digests.
- `bench` — turns Windows/macOS scenes into gradeable tasks, and holds the adversary solvers.
  Linux scenes are generator assurance and Fixture Core inputs only.
- `gates`, `scorecard` — measurement.
- `ingest` — the EvidenceForge companion adapter, outside the chain. Nothing in the chain may
  import it, and upstream's private seed formulas are never re-exported as ArtifactForge API.

ArtifactForge runs standalone. EvidenceForge is never a declared dependency: it is not on
PyPI, so naming it would force a git URL into the metadata, which makes the distribution
unbuildable. Two isolated CI jobs install it for a pinned contract and a default-branch drift
canary; the standalone test job does not.

### Fixture Core contract

Fixture Core is the public-reproducible product surface. A strict v1 recipe carries a public
seed and one named loose-artifact profile. Its canonical manifest embeds that recipe and an
exact sorted inventory of payload paths, sizes and SHA-256 values. Verification checks the
manifest, re-inventories the tree, and independently regenerates the complete payload. An
optional assurance pass runs Gates 1 and 3; Gate 2 is not claimed because the fixture manifest
deliberately omits the private scene join.

Nested and dot-prefixed components are ordinary artifact paths. The shared grammar rejects
literal `.`/`..`, empty components, links, special files, empty directories, case-folding and
file/ancestor conflicts. Scene capture additionally rejects resource-limit violations before
a scene can be certified.

The benchmark boundary is absolute: fixture manifests set `benchmark_eligible` to false and
must never appear under a suite's served `scenarios/` tree. Their hashes and seed are public,
which is useful for reproducibility and disqualifying for a hold-out. Deterministic USTAR
release archives add no authenticity claim; they preserve exact bytes with fixed metadata.
The v1 manifest does not bind POSIX modes and release normalizes artifact files to 0644. That
is sufficient for loose evidence but deliberately cannot represent an activation-ready Linux
filesystem. The full contract is in `docs/fixture-core.md`.

The shared scene stager also rejects the case-insensitive basenames
`ARTIFACT_ANSWERS.json`, `GROUND_TRUTH.json`, `JOIN_MANIFEST.json` and `fixture.json` at any
depth, plus the Fixture Core schema marker under any name. This is defense in depth around the
exact allowlist: a future builder cannot accidentally serve a known answer or evaluation
manifest merely by adding it to that allowlist.

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

*Do declared parser and semantic oracles validate each classified artifact?*

PE, Mach-O, registry hive and prefetch each require two independently implemented parsers,
because one permissive parser can hide what a strict one rejects. Every prefetch file this
project emitted was accepted by `windowsprefetch` and refused by `pyscca` — the libyal parser
plaso is built on — for as long as `windowsprefetch` was the only oracle installed.

A missing oracle is a **failure, never a skip**: a skipped check exits 0 and reads exactly
like a passing one. Before any oracle runs, Gate 1 captures the bounded recursive tree through
held no-follow descriptors and materializes a private frozen snapshot. Its directories are
read/execute-only while the oracles run, and descriptor-bound cleanup never follows a replaced
link. SQLite and binary plists pair
the standard-library implementation with small raw readers derived directly from the published
container layouts. Both implementations
receive one bounded immutable snapshot, return type-tagged observations, and must agree on the
complete modeled object graph before either format's semantic profile can pass. Those raw
readers are independently implemented, but maintained in this repository; that is not an
external validation or a claim about SQLite/plist features outside their strict emitted subset.

Opening a container is necessary but not sufficient for structural claims. For PE, pefile and
LIEF independently enumerate the named import sequence, confirm pefile/VT-normalised IMPHASH
semantics and then agree with each other. For v17 prefetch, a separate raw-structure verifier
recomputes the XP path hash from the referenced UTF-16LE device path and binds it to the header
and filename. Parseable mutations that remove the PE import directory or change the embedded
prefetch hash turn this gate red.

For the macOS databases, container consensus covers schema SQL, root-page ownership, typed
rows, order, duplicates and primary-key index entries; the profile then fixes the marker plus
knowledgeC, TCC or QuarantineEventsV2 meanings. Binary-plist consensus is type-exact—boolean
`true` cannot collapse into integer `1`—and the LaunchAgent profile fixes its six keys,
filename/label, program path, persistence settings and disclosure. Parser-only and
meaning-only mutations prove both layers turn red independently.

For Linux, LIEF and pyelftools independently enumerate the ELF header, interpreter, sole
`DT_NEEDED` library, segments, sections, dynamic allowlist and ArtifactForge note. PyXDG and a
bounded raw reader agree on an exact single-group XDG 1.5 desktop-entry subset; dissect.target
and a bounded raw reader agree on strictly timestamped one-line Bash-history records. The raw
text readers never expand `Exec` or evaluate command text. Their profile checks require exact
resident absolute paths and reject arguments, field codes, shell syntax, multiline history,
unsafe command verbs and non-profile keys. The scene profile further fixes four history rows:
the exact Linux disclosure marker first, followed by three distinct resident paths.

### Gate 2 — identity

*Do the declared answer-bearing identities and cross-artifact pivots agree with the emitted
bytes?*

The keystone. Gate 2 also works from one bounded no-follow capture and private snapshot. Each
declared value in the gate's scope is re-derived from those bytes, through a real parser where
the value is structural, and only then compared. Every check names
the artifacts it spans, because a check confined to one artifact cannot detect a broken pivot.
The gate does not claim that stale or absent decoy Amcache `FileId`s correspond to bytes shipped
in the scene. Linux's join is path-exact rather than basename-based: XDG names three resident
guest paths, Bash history names another three, their unique intersection names the subject,
and `/home/<user>/...` maps to exactly `home/<user>/...` in the served recursive tree before
the subject name, SHA-256, SHA-1, MD5 and ELF-note marker are re-derived from its bytes. The
gate binds each served desktop path to that file's parsed `Exec` value and inventories the
single declared history path, so swapping two valid records cannot preserve the join.

### Gate 3 — inertness

*Are generated binaries payload-free, and is every classified structured format marked
synthetic?*

Generated binaries reproduce the forensic **signal** — a real import table, a real symbol
table, real content and structural hashes — without a payload. PE `.text` is `ret` plus zero
padding and the DOS stub is the fixed print-and-exit stub; Mach-O `__text` is
`mov w0,#0 ; ret`; ELF's sole RX segment is the nine bytes
`xor edi,edi ; mov eax,60 ; syscall`, which directly exits zero. The ELF declares
`/lib64/ld-linux-x86-64.so.2` and `libc.so.6`, so a real execution attempt enters the dynamic
loader before that bounded entry body. The main object imports and calls no libc symbol and
has no alternate entry surface; external loader/dependency code is out of scope. For PE, Gate 3
independently pins the DOS profile, sole executable section,
entry point, import-only data directories and modeled system DLLs. For Mach-O it fixes the
load-command, library, segment and section profile, requires `LC_MAIN` to name the sole
instruction entry, and independently verifies the CodeDirectory's page hashes and exact
pre-signature coverage boundary. For ELF it independently parses the headers and tables,
requires the exact entry body, file size and section geometry, non-overlapping R/RX/RW file
and virtual ranges, zero-only unclaimed slack, NX stack, RELRO and the dynamic-tag allowlist,
and rejects alternate executable sections, initializers, finalizers, TLS, relocations,
imported symbols and hidden payload bytes.
Every classified structured format anywhere in the recursive tree—including beneath a dot
directory—carries an in-band `ARTIFACTFORGE` anchor. Plain sidecars, including the quarantine
xattr value, are not counted by that marker gate, but are still inspected for indicator
hygiene. Domains must be RFC
2606 reserved and addresses RFC 5737 / RFC 3849, so no artifact can name a host that might be
real.

A separate Ubuntu 24.04/x86-64 native lane first verifies a complete Fixture Core root with
exact reproduction and portable Gates 1 and 3, then records GNU `readelf`/`objdump`, `file`,
`desktop-file-validate` and Bash observations only from a held private snapshot byte-equal to
the verified payload manifest. The canonical record binds Git/GitHub-run identity, CPython and
portable-parser versions, package and native-tool bytes before and after observation, exact
fixture/snapshot pre/post state, disassembly and a Bash history read/writeback control. It never
executes an emitted ELF, invokes `ldd`, launches XDG content, or sources/evaluates history;
native acceptance therefore does not expand the portable gate's activation claims.

### Gate 4 — solvability

*Are the benchmark's answers recovered from evidence, or derivable?*

**This gate is currently RED, and deliberately stays red.** The `footprint` adversary ranks
candidates without format parsing — for each candidate, count how many other files mention its
name and take the maximum — then uses ordinary parsers and lookups to complete dependent
answers. On the public, non-reportable scorecard measurement corpus it scores 72.7% against
the committed scorecard's 4.2% chance floor. The number is published in the README and tracked
in the scorecard; `docs/ROADMAP.md` says what the repair
takes. Raising the threshold to make it pass is the one response ruled out: a red gate
reporting a true fact is the system working.

Gate 4's population remains Windows and macOS only. Linux is appended to the deterministic
Gates 1–3 generator-assurance corpus but receives no public question set, benchmark answer or
score. Adding a new parser-valid family therefore cannot dilute the existing 72.7% failure.

A reference solver scoring 100% proves the artifacts *encode* the ground truth. It does not
prove that is the only way to get it — and here it was not: because the generator is open
source and the public scenario identifier was also its generation seed, a solver opening zero
files reproduced every answer. So the gate measures four things: the reference solver scores
100%; every adversary stays under its threshold; at least one question per family is answerable
**only** by joining two artifacts; and the blind solver succeeds against the deliberately
cheatable dev-suite control.

The adversary set is the gate. `null` and `constant` score zero — *below* the chance floor of
a solver guessing among visible candidates — and for a long time they were the only baselines,
which flattered every number the benchmark published. `footprint` and `mechanical` are the two
that actually threaten it, and a measured chance floor is published beside them so a score can
be read against something.

## §5 The scorecard

`fidelity-scorecard.json` is committed at the root and carries what the gates actually
measured, including what they measured badly. It ships reading whatever it honestly reads; a
scorecard saying `pass` on day one would be the least believable thing in the repository.
Regression is enforced by one declarative table, with tolerance 0 on every count: an artifact
that used to be readable and now is not, or a join that used to hold and now does not, is a
regression at any magnitude.

A release scorecard is also a source attestation. It records the full Git commit and tree and
digests of the package metadata and lock file, and the CLI refuses to write it from a dirty
worktree. The explicit `--allow-dirty` escape hatch is for diagnosis, never release: its source
record is marked unclean and binds the complete tracked binary diff plus every untracked path
and byte to one digest.
