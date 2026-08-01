# Changelog

## Unreleased

## 0.0.2 - 2026-08-01

### Added

The four gates, and the discipline behind them. A gate is a numbered question wired into six
places at once — a module whose docstring is the question, a CLI subcommand that exits
non-zero, a pytest file, a block in the committed `fidelity-scorecard.json`, a row in the
regression table with a direction and a tolerance, a named CI step, and a registered mutation
that must turn it red. `tests/test_gates.py` enforces those bindings mechanically, so a gate
cannot quietly become decoration. The sixth binding is the one that matters: a gate never
observed to fail proves nothing, and `tests/test_gate_mutations.py` breaks each one on purpose
— truncating a hive, appending a byte to a binary, rewriting an Amcache `FileId`, stripping a
synthetic marker, writing instructions past the `ret`, pointing a URL at a routable domain.

A real arm64 Mach-O, hand-assembled from pure stdlib on the same terms as the PE writer. It
carries a genuine `LC_SYMTAB` whose undefined external symbols yield the symhash that
threatstream/symhash and yara-x compute, and an ad-hoc code signature whose cdhash is what
`codesign -d` reports. LIEF and macholib parse it; on macOS `codesign -v` certifies it. The
signature is computed in-process because an unsigned arm64 binary is not loadable at all and
signing afterwards would rewrite the bytes — which also makes the signing identifier part of
the file's identity, so it is encoded in the content id rather than passed alongside it.

A benchmark that measures investigation. Every answer hangs off a 32-byte suite key; the
public scenario identifier is an HMAC of it, domain-separated from content seeds and from each
variable selection. Suites come in two kinds: a dev suite built with the key published in the
source, cheatable on purpose and never reportable, and a hold-out suite whose key never leaves
the evaluator. Scenes carry decoys and the signals deliberately disagree — persistence launches
one binary while Amcache's recorded hashes match a different one — and every question spans at
least two artifacts.

A companion adapter that reads an EvidenceForge run's output tree without importing
EvidenceForge, recovering which logical binary each Sysmon hash denotes. On an unmodified run
of the shipped branch-office scenario at v1.13.1: 853 of 853 Sysmon records carrying SHA256
recovered and verified, 105 distinct Sysmon logical identities, with seed forms split 78
`from_host_metadata` and 27 `with_description`. Those are Sysmon-local recovery figures; the
stock run contains no basename-matched Sysmon/Zeek pair that could prove a same-file
cross-emitter inconsistency.

A schema-checked EvidenceForge measurement record bound to the exact v1.13.1 scenario input
and a canonical inventory of all 45 output files. The CI contract derives the installed
producer version and commit from distribution metadata, generates a fresh run, byte-compares
the resulting record, and then re-hashes and re-measures the tree. The record states the
remaining boundary explicitly: serialized output does not itself encode its producer commit.

`SECURITY.md`, `docs/inert-by-construction.md`, `docs/DESIGN.md`, `docs/ROADMAP.md`, a
`LICENSE` the packaging metadata had always declared, and SPDX headers throughout.

### Fixed

libyal's `libscca` — which plaso and log2timeline are built on — rejected every prefetch file
this project had ever written. The volumes-information block was sized to end exactly at the
last counted character of the volume device path, but SCCA character counts exclude the
end-of-string character while the terminator must still lie inside the block, so the file was
short by exactly two bytes. A second defect: the directory-strings offset pointed one byte past
the end of the block while declaring a count of zero, and libscca gates that block on the
offset being non-zero rather than on the count. Nobody noticed because `windowsprefetch`, far
more permissive, was the only oracle installed.

CI had never executed a single test. The workflow installed `evidenceforge` where the upstream
distribution is `evidence-forge`, so the step exited 1 before pytest was ever reached, and with
no commits and no remote nothing surfaced it.

The seed transcription picked its formula from the Sysmon EventID; upstream picks by the shape
of the arguments it was handed and has a third form this module could not express. Recovery now
recomputes every candidate against the digest upstream emitted and raises unless exactly one
matches.

The `ContentStore` trusted any file already at a content-addressed path and wrote
non-atomically. Writes are now atomic and cache hits are re-verified, which matters now that
one store is shared across a suite and hits are real.

### Changed

Scorecard measurement now uses a separately domain-separated, deterministic public corpus and
records its complete derivation identity. It is marked non-reportable and cannot be graded as
a bare benchmark score; real hold-out suites remain freshly keyed. `scorecard --check` rejects
incompatible measurement provenance even when no tracked metric regresses. Generator assurance
and experimental benchmark validity now have separate machine-readable statuses while the
legacy aggregate verdict remains available.

`KNOWN_TELLS.md` opened by claiming CI failed if a structured format shipped undisclosed.
Nothing read it, and four of six classified formats carried no marking at all. Every classified
structured format now carries an in-band `ARTIFACTFORGE` anchor, and
`tests/test_known_tells.py` enforces the claim in both directions. Plain sidecars, including the
serialized quarantine xattr value, are outside that format-marker gate.
