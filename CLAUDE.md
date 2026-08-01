# ArtifactForge — working notes

## What this is

A deterministic generator of synthetic forensic artifacts: PE and Mach-O binaries, Windows
registry hives, prefetch records, macOS SQLite databases and plists. It is a companion to
EvidenceForge, which generates the logs, and it stands alone.

## Hard constraints

**Determinism is not negotiable.** Every byte is a pure function of a seed. No wall clock, no
`os.urandom`, no PID, no dict-ordering dependence. If you need randomness, derive it from the
seed. Every other property in this repository rests on this one.

**A gate is not built until all six bindings exist.** Module, CLI subcommand with a non-zero
exit, pytest file, `gates.<name>` block in the scorecard, a row in `scorecard._METRICS`, a
named CI step, and a registered mutation in `tests/test_gate_mutations.py` that turns it red.
`tests/test_gates.py` checks this. A gate that has never been observed to fail proves nothing.

**Claims must be smaller than the code, never larger.** If a test cannot fail when the thing
it checks is broken, delete it and write one that can. If a document describes a mechanism,
something must enforce it. The scorecard ships whatever it honestly reads, including `gap`.

## The validation gate is the definition of done

Not "the tests pass" — the tests are a floor. Done means an independent real parser reads the
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
`scripts/pin-published-numbers.py` closes it — run both, in that order.

## Design values

Dependencies point one way: `model <- content <- artifacts <- compose <- bench <- cli`. The
EvidenceForge adapter sits outside that chain and nothing in it may import the adapter;
`tests/test_isolation.py` enforces this by walking the syntax tree, including string arguments,
because a linter rule that misses `pytest.importorskip("evidenceforge")` reads like coverage
and is not.

Comments say why, not what. Prefer deleting a feature to configuring it. Match the surrounding
style. British spelling. No emoji.
