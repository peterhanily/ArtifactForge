# ArtifactForge working notes

## What this is

A deterministic generator of synthetic forensic artifacts: PE and Mach-O binaries, Windows
registry hives, prefetch records, macOS SQLite databases and plists. It is a companion to
EvidenceForge, which generates the logs, and it stands alone.

## Hard constraints

**Determinism is not negotiable.** Every modeled value is a pure function of a seed. No wall
clock, no `os.urandom`, no PID, no dict-ordering dependence. If you need randomness, derive it
from the seed. Byte identity additionally requires a declared byte-producing ABI/runtime.
Fixture ABI v1 does not record its SQLite producer and remains parse-only at the frozen 0.5.0
vectors. Fixture ABI v2 binds `artifactforge-owned-sqlite-leaf-v1`. Any cross-runtime byte
identity claim must name the ABI, producer profile, and tested runtime matrix.

**A gate is not built until every binding exists.** It needs a question-bearing module, a CLI
subcommand with a non-zero failure exit, tests, registered scorecard metrics, a named CI step,
a design section, and a mutation in `tests/test_gate_mutations.py` that turns it red.
`tests/test_gates.py` checks this contract. A gate that has never been observed to fail proves
nothing.

**Claims must be smaller than the code, never larger.** If a test cannot fail when the thing
it checks is broken, delete it and write one that can. If a document describes a mechanism,
something must enforce it. The scorecard ships whatever it honestly reads, including `gap`.

## The validation gate is the definition of done

"The tests pass" is only a floor. Done means an independent real parser reads the
artifact, the cross-artifact identity re-derives from the bytes on disk, nothing ships without
its synthetic marker, and no adversary can answer a benchmark question without doing the work.
`artifactforge scorecard` runs all of it.

## After anything that changes what the gates measure

    artifactforge scorecard --n 40 --out fidelity-scorecard.json
    python scripts/pin-published-numbers.py
    ./scripts/make-samples.sh
    pytest -q

The prose quotes figures from the scorecard, and prose does not regenerate. The README once
published a chance floor the committed scorecard contradicted, five lines above a sentence
warning against exactly that. `tests/test_published_numbers.py` now catches the divergence and
`scripts/pin-published-numbers.py` closes it. Run both, in that order.

## Design values

Dependencies point one way: `model <- content <- artifacts <- compose <- bench <- cli`. The
EvidenceForge adapter sits outside that chain and nothing in it may import the adapter;
`tests/test_isolation.py` enforces this by walking the syntax tree, including string arguments,
because a linter rule that misses `pytest.importorskip("evidenceforge")` reads like coverage
and is not.

Comments say why, not what. Prefer deleting a feature to configuring it. Match the surrounding
style. British spelling. No emoji.
