# ArtifactForge documentation

The root [README](../README.md) is the short introduction. This page points to the detailed
contracts behind it.

## Choose a path

### Build or inspect a fixture

1. Read [Fixture Core](fixture-core.md) for the recipe, manifest, verification, and release
   lifecycle.
2. Use the recipes under [`examples/fixtures/`](../examples/fixtures/).
3. Compare your output with the generated [`samples/`](../samples/) gallery.
4. Read [Known Tells](../KNOWN_TELLS.md) before treating a fixture as representative of a
   native host.

### Review the assurance claims

1. Read [Design](DESIGN.md) for the architecture and four gate contracts.
2. Read [Inert by construction](inert-by-construction.md) for executable-byte and marker
   controls.
3. Read [Identity boundaries](identity-boundaries.md) for the distinction between content,
   fixtures, benchmark state, and modeled logs.
4. Read [macOS oracle profiles](macos-oracles.md) for the bounded consumer-query surface.
5. Read the [Security policy](../SECURITY.md) for safe handling, scanner evidence, and release
   boundaries.

### Work on the benchmark

- [Benchmark v2](benchmark-v2.md) documents the frozen, permanently non-reportable local
  diagnostic.
- [Benchmark v3](benchmark-v3.md) documents the evaluator ceremony, one-shot attempt ledger,
  detached report, and missing independent witness.

The benchmark is separate from generator assurance. A fixture can pass format, identity, and
inertness gates without creating a reportable benchmark result.

### Understand the EvidenceForge relationship

- [EvidenceForge relationship](evidenceforge.md) records what was measured between the
  two projects, and why their hashes do not currently join.

### Prepare release evidence

- [Releasing](releasing.md) gives the operator sequence and lists every action the workflow
  does not perform.
- The [Security policy](../SECURITY.md) defines the unsigned local self-attestation boundary.
- The [changelog](../CHANGELOG.md) is the historical record. It is not a current design
  contract.

### Understand project status

- [Roadmap](ROADMAP.md) lists open work and deferred formats.
- [Improvement plan](IMPROVEMENT-PLAN.md) records the completed hardening campaign and the
  evidence produced in each phase.
- [Known Tells](../KNOWN_TELLS.md) is the authoritative format-by-format limitation list.

## Document ownership

To avoid contradictory claims, each subject has one primary document.

| Subject | Source of truth |
|---|---|
| Architecture and gate definitions | [Design](DESIGN.md) |
| Fixture ABI and lifecycle | [Fixture Core](fixture-core.md) |
| Format limitations and markers | [Known Tells](../KNOWN_TELLS.md) |
| Scanner checkpoints and safe handling | [Security](../SECURITY.md) |
| Benchmark v2 protocol | [Benchmark v2](benchmark-v2.md) |
| Benchmark v3 trust boundary | [Benchmark v3](benchmark-v3.md) |
| Release procedure | [Releasing](releasing.md) |
| Open work | [Roadmap](ROADMAP.md) |
| Historical changes | [Changelog](../CHANGELOG.md) |

Short summaries elsewhere should link to these documents instead of copying their full facts.
That keeps dates, counts, hashes, and claim boundaries in one place.
