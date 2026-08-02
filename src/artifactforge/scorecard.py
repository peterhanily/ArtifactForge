# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The fidelity scorecard — the project's honesty artifact.

`fidelity-scorecard.json` is committed at the repo root and carries what the four gates
actually measured, including what they measured badly. It turns "how faithful is this,
really?" into a tracked number that moves as the generator improves, rather than an
adjective in a README.

It ships reading whatever it honestly reads. A scorecard that says `pass` on day one would
be the least believable thing in the repository.

CI cannot always recompute it — some oracles are platform-bound — so CI guards the committed
artifact instead: it must be schema-valid, must not regress against itself, and must leak no
local filesystem path.
"""
from __future__ import annotations

import json

# Metrics tracked for regression. (dotted path, direction, tolerance, label)
#
# Counts get tolerance 0: an artifact that used to be readable and now is not, or a join that
# used to hold and now does not, is a regression at any magnitude.
#
# Ratios get a tolerance sized from MEASURED variance, not from taste. Across five unrelated
# hold-out suite keys at n=40, every adversary metric had sd 0.0000 — the attacks transfer
# between corpora exactly, which is what "effective sample size is the number of structures,
# not the number of rows" means in practice, and why they keep tolerance 0. The exceptions are
# `listing_solver_score` (sd 0.0046, 3 sigma 0.0137) and the Monte-Carlo `chance_floor`
# (sd 0.0034), so the first gets a 3-sigma tolerance and the second is not tracked at all: a
# reference floor moving is not a regression in anything.
#
# A bound sitting inside its own noise gets deleted by whoever it false-fails, taking its real
# coverage with it. Re-measure before tightening any of these.
_METRICS = [
    ("gates.validity.oracle_reads_passed",     "higher_better", 0, "validity: oracle reads passed"),
    ("gates.validity.oracle_reads_total",      "higher_better", 0, "validity: oracle reads declared"),
    ("gates.validity.semantic_checks_passed",  "higher_better", 0, "validity: semantic checks passed"),
    ("gates.validity.semantic_checks_total",   "higher_better", 0, "validity: semantic checks declared"),
    ("gates.identity.checks_joined",           "higher_better", 0, "identity: cross-artifact joins holding"),
    ("gates.identity.checks_total",            "higher_better", 0, "identity: cross-artifact joins declared"),
    ("gates.inertness.formats_marked",         "higher_better", 0, "inertness: formats carrying a marker"),
    ("gates.inertness.formats_total",          "higher_better", 0, "inertness: marked formats declared"),
    ("gates.inertness.binary_safety_checks_passed", "higher_better", 0, "inertness: binary safety checks passed"),
    ("gates.inertness.binary_safety_checks_total", "higher_better", 0, "inertness: binary safety checks declared"),
    ("gates.solvability.reference_solver_score", "higher_better", 0, "solvability: reference solver"),
    ("gates.solvability.adversarial_floor",    "lower_better",  0, "solvability: adversarial floor"),
    ("gates.solvability.footprint_solver_score", "lower_better", 0, "solvability: footprint adversary"),
    ("gates.solvability.mechanical_solver_score", "lower_better", 0, "solvability: mechanical adversary"),
    ("gates.solvability.blind_solver_score",   "lower_better",  0, "solvability: blind adversary"),
    ("gates.solvability.blind_control_score",  "higher_better", 0, "solvability: blind adversary control"),
    ("gates.solvability.listing_solver_score", "lower_better", 0.02, "solvability: listing adversary"),
    ("gates.solvability.join_questions_windows", "higher_better", 0, "solvability: windows join questions"),
    ("gates.solvability.join_questions_macos", "higher_better", 0, "solvability: macos join questions"),
]

SCHEMA_VERSION = "1.0"

# The scorecard has two audiences with different maturity. Gates 1-3 describe the artifact
# generator; Gate 4 describes the explicitly experimental investigation benchmark. Keep the
# legacy aggregate verdict below for existing consumers, while making the two scopes available
# as first-class machine-readable status.
GENERATOR_ASSURANCE_GATES = ("validity", "identity", "inertness")
BENCHMARK_VALIDITY_GATES = ("solvability",)

# A metric comparison is meaningless when the two cards describe different corpora. These
# fields identify the public deterministic measurement without publishing key material.
_MEASUREMENT_IDENTITY = (
    ("measurement.purpose", "benchmark measurement purpose"),
    ("measurement.scope", "benchmark measurement scope"),
    ("measurement.suite_kind", "suite kind"),
    ("measurement.scenario_count", "scenario count"),
    ("measurement.deterministic", "deterministic flag"),
    ("measurement.reportable", "reportable flag"),
    ("measurement.suite_derivation_domain", "suite derivation domain"),
    ("measurement.key_derivation.algorithm", "key derivation algorithm"),
    ("measurement.key_derivation.domain", "key derivation domain"),
    ("measurement.key_derivation.seed_id", "public seed identity"),
    ("measurement.key_derivation.key_id", "measurement key identity"),
    ("measurement.generator_assurance.purpose", "generator assurance purpose"),
    ("measurement.generator_assurance.families", "generator assurance families"),
    ("measurement.generator_assurance.family_counts.windows",
     "generator assurance Windows family count"),
    ("measurement.generator_assurance.family_counts.macos",
     "generator assurance macOS family count"),
    ("measurement.generator_assurance.family_counts.linux",
     "generator assurance Linux family count"),
    ("measurement.generator_assurance.windows_macos_scenario_count",
     "generator assurance Windows/macOS count"),
    ("measurement.generator_assurance.linux_scenario_count",
     "generator assurance Linux count"),
    ("measurement.generator_assurance.scenario_count",
     "generator assurance total count"),
    ("measurement.generator_assurance.deterministic",
     "generator assurance deterministic flag"),
    ("measurement.generator_assurance.benchmark_reportable",
     "generator assurance reportable flag"),
    ("measurement.generator_assurance.linux_benchmark_included",
     "Linux benchmark inclusion flag"),
    ("measurement.generator_assurance.corpora.windows_macos.purpose",
     "Windows/macOS assurance corpus purpose"),
    ("measurement.generator_assurance.corpora.windows_macos.suite_kind",
     "Windows/macOS assurance suite kind"),
    ("measurement.generator_assurance.corpora.windows_macos.families",
     "Windows/macOS assurance families"),
    ("measurement.generator_assurance.corpora.windows_macos.scenario_count",
     "Windows/macOS assurance corpus count"),
    ("measurement.generator_assurance.corpora.windows_macos.family_counts.windows",
     "Windows assurance corpus count"),
    ("measurement.generator_assurance.corpora.windows_macos.family_counts.macos",
     "macOS assurance corpus count"),
    ("measurement.generator_assurance.corpora.windows_macos.deterministic",
     "Windows/macOS assurance deterministic flag"),
    ("measurement.generator_assurance.corpora.windows_macos.benchmark_reportable",
     "Windows/macOS assurance reportable flag"),
    ("measurement.generator_assurance.corpora.windows_macos.suite_derivation_domain",
     "Windows/macOS assurance suite derivation domain"),
    ("measurement.generator_assurance.corpora.windows_macos.public_key.source",
     "Windows/macOS assurance public-key source"),
    ("measurement.generator_assurance.corpora.windows_macos.public_key.identity_algorithm",
     "Windows/macOS assurance public-key identity algorithm"),
    ("measurement.generator_assurance.corpora.windows_macos.public_key.key_id",
     "Windows/macOS assurance public-key identity"),
    ("measurement.generator_assurance.corpora.windows_macos.content_namespace",
     "Windows/macOS assurance content namespace"),
    ("measurement.generator_assurance.corpora.windows_macos.family_schedule.algorithm",
     "Windows/macOS assurance family schedule"),
    ("measurement.generator_assurance.corpora.windows_macos.family_schedule.index_origin",
     "Windows/macOS assurance family schedule origin"),
    ("measurement.generator_assurance.corpora.windows_macos.family_schedule.even_index_family",
     "Windows/macOS assurance even-index family"),
    ("measurement.generator_assurance.corpora.windows_macos.family_schedule.odd_index_family",
     "Windows/macOS assurance odd-index family"),
    ("measurement.generator_assurance.corpora.linux.purpose",
     "Linux assurance corpus purpose"),
    ("measurement.generator_assurance.corpora.linux.corpus_kind",
     "Linux assurance corpus kind"),
    ("measurement.generator_assurance.corpora.linux.family",
     "Linux assurance family"),
    ("measurement.generator_assurance.corpora.linux.scenario_count",
     "Linux assurance corpus count"),
    ("measurement.generator_assurance.corpora.linux.deterministic",
     "Linux assurance deterministic flag"),
    ("measurement.generator_assurance.corpora.linux.benchmark_reportable",
     "Linux assurance corpus reportable flag"),
    ("measurement.generator_assurance.corpora.linux.benchmark_included",
     "Linux assurance benchmark inclusion flag"),
    ("measurement.generator_assurance.corpora.linux.profile",
     "Linux assurance corpus profile"),
    ("measurement.generator_assurance.corpora.linux.scene_derivation_domain",
     "Linux assurance corpus scene derivation domain"),
    ("measurement.generator_assurance.corpora.linux.content_namespace",
     "Linux assurance content namespace"),
    ("measurement.generator_assurance.corpora.linux.count_contract.algorithm",
     "Linux assurance count contract"),
    ("measurement.generator_assurance.corpora.linux.count_contract.windows_macos_scenario_count",
     "Linux assurance count-contract input"),
    ("measurement.generator_assurance.corpora.linux.key_derivation.algorithm",
     "Linux assurance key algorithm"),
    ("measurement.generator_assurance.corpora.linux.key_derivation.domain",
     "Linux assurance key domain"),
    ("measurement.generator_assurance.corpora.linux.key_derivation.seed_id",
     "Linux assurance seed identity"),
    ("measurement.generator_assurance.corpora.linux.key_derivation.key_id",
     "Linux assurance key identity"),
)


def _dig(card: dict, path: str):
    node = card
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _status_block(reports, gate_names, *, experimental: bool) -> dict:
    by_name = {r.name: r for r in reports}
    selected = [by_name[name] for name in gate_names if name in by_name]
    missing = [name for name in gate_names if name not in by_name]
    fails = [f"Gate {r.gate} ({r.name}) FAILING: {reason}"
             for r in selected for reason in r.fails]
    fails += [f"required gate report missing: {name}" for name in missing]
    gaps = [f"Gate {r.gate} ({r.name}): {reason}"
            for r in selected for reason in r.gaps]
    verdict = "fail" if fails else "gap" if gaps else "pass"
    return {
        "verdict": verdict,
        "experimental": experimental,
        "gates": list(gate_names),
        "fails": fails,
        "gaps": gaps,
    }


def build_scorecard(reports, *, artifactforge_version: str, git_commit: str,
                    sqlite_version: str, honest_gaps=None, measurement=None, source=None) -> dict:
    """Assemble the committed artifact from a run of the gates."""
    reports = list(reports)
    gates = {r.name: r.as_scorecard_block() for r in reports}
    gaps = list(honest_gaps or [])
    for r in reports:
        gaps += [f"Gate {r.gate} ({r.name}): {g}" for g in r.gaps]
        gaps += [f"Gate {r.gate} ({r.name}) FAILING: {f}" for f in r.fails]
    card = {
        "schema_version": SCHEMA_VERSION,
        "generator": {
            "artifactforge_version": artifactforge_version,
            "git_commit": git_commit,
            "sqlite_version": sqlite_version,
            "source": dict(source or {
                "git_commit": git_commit,
                "attestation_available": False,
            }),
        },
        "gates": gates,
        "status": {
            "generator_assurance": _status_block(
                reports, GENERATOR_ASSURANCE_GATES, experimental=False),
            "benchmark_validity": _status_block(
                reports, BENCHMARK_VALIDITY_GATES, experimental=True),
        },
        "honest_gaps": gaps,
        # Three-valued on purpose. "pass" would be the wrong headline while a declared gap is
        # open — a gap is a named limitation rather than a failure, but it is still something
        # a reader deserves to see before they trust a number underneath it.
        #   pass  every gate green and nothing left declared
        #   gap   every gate green, but a limitation is named in honest_gaps
        #   fail  a gate is red
        "verdict": ("fail" if not all(r.ok for r in reports)
                    else "gap" if gaps else "pass"),
        "verdict_scope": "all_gates",
    }
    if measurement is not None:
        card["measurement"] = dict(measurement)
    return card


def regressions(baseline: dict, current: dict) -> list:
    """Which tracked metrics got worse. A missing metric is `missing`, never a pass."""
    out = []
    for path, direction, tol, label in _METRICS:
        was, now = _dig(baseline, path), _dig(current, path)
        if was is None or now is None:
            out.append((label, "missing", was, now))
            continue
        worse = (now < was - tol) if direction == "higher_better" else (now > was + tol)
        if worse:
            out.append((label, "regressed", was, now))
    return out


def measurement_incompatibilities(baseline: dict, current: dict) -> list:
    """Identity/provenance differences that make two scorecards incomparable.

    Missing provenance is incompatible even when both sides omit it. Without a scenario
    count, domain and key identity, a claim that metrics did not regress has no defined
    measurement population behind it.
    """
    out = []
    for path, label in _MEASUREMENT_IDENTITY:
        was, now = _dig(baseline, path), _dig(current, path)
        if was is None or now is None:
            out.append((label, "missing", was, now))
        elif was != now:
            out.append((label, "changed", was, now))
    return out


def render_comparison(baseline: dict, current: dict) -> str:
    rows = regressions(baseline, current)
    if not rows:
        return "no tracked metric regressed"
    return "\n".join(f"  {kind.upper():9s} {label}: {was} -> {now}"
                     for label, kind, was, now in rows)


def render_measurement_compatibility(baseline: dict, current: dict) -> str:
    rows = measurement_incompatibilities(baseline, current)
    if not rows:
        return "measurement provenance compatible"
    details = "\n".join(
        f"  {kind.upper():7s} {label}: {was!r} -> {now!r}"
        for label, kind, was, now in rows)
    return "measurement provenance incompatible\n" + details


def load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def save(card: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(card, f, indent=2, sort_keys=False)
        f.write("\n")
