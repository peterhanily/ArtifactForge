# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The fidelity scorecard — the project's honesty artifact.

`fidelity-scorecard.json` is committed at the repo root and carries what the four gates
actually measured, including what they measured badly. It turns "how faithful is this,
really?" into a tracked number that moves as the generator improves, rather than an
adjective in a README.

It ships reading whatever it honestly reads. A passing Gate 4 records that the predeclared
validity checks held; the deterministic scorecard corpus remains explicitly non-reportable
and is not a benchmark performance claim.

CI cannot always recompute it — some oracles are platform-bound — so CI guards the committed
artifact instead: it must be schema-valid, must not regress against itself, and must leak no
local filesystem path.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import secrets
import stat

from artifactforge import suite


SCORECARD_MAX_BYTES = 8 * 1024 * 1024
_STATUS_ORDER = {"pass": 0, "gap": 1, "fail": 2}
_STATUS_SCOPES = {
    "generator_assurance": (False, ("validity", "identity", "inertness")),
    "benchmark_validity": (True, ("solvability",)),
}
_REQUIRED_GATES = tuple(
    gate for _experimental, gates in _STATUS_SCOPES.values() for gate in gates
)
_REQUIRED_GATE_NUMBERS = {
    "validity": 1,
    "identity": 2,
    "inertness": 3,
    "solvability": 4,
}


class ScorecardError(ValueError):
    """A scorecard is unsafe, malformed or outside the release contract."""


class ScorecardPublicationUncertain(ScorecardError):
    """Publication occurred, but its final binding or durability could not be proved."""

    def __init__(self, message: str, *, path: str | os.PathLike[str]):
        super().__init__(message)
        self.published = True
        self.path = os.fspath(path)

# Metrics tracked for regression. (dotted path, direction, tolerance, label)
#
# V2 has no empirical tolerance: its candidate chance, scene-level permutation null and
# public scorecard corpus are deterministic.  Every numerator is paired with its denominator
# or coverage metric. Every complete attack and composition ensemble is paired with an
# independent detector positive control; low-information baselines remain explicitly excluded.
_GENERATOR_METRICS = [
    ("gates.validity.oracle_reads_passed", "higher_better", 0, "validity: oracle reads passed"),
    ("gates.validity.oracle_reads_total", "higher_better", 0, "validity: oracle reads declared"),
    (
        "gates.validity.semantic_checks_passed",
        "higher_better",
        0,
        "validity: semantic checks passed",
    ),
    (
        "gates.validity.semantic_checks_total",
        "higher_better",
        0,
        "validity: semantic checks declared",
    ),
    *(
        (
            f"gates.validity.claim_scopes.{scope}.{counter}",
            "higher_better",
            0,
            f"validity: {scope_label} checks {counter_label}",
        )
        for scope, scope_label in (
            ("container_acceptance", "container acceptance"),
            ("semantic_extraction", "semantic extraction"),
            ("independent_consensus", "independent consensus"),
            ("declared_profile_conformance", "declared profile conformance"),
            (
                "downstream_consumer_compatibility",
                "downstream consumer compatibility",
            ),
        )
        for counter, counter_label in (("passed", "passed"), ("total", "declared"))
    ),
    ("gates.identity.checks_joined", "higher_better", 0, "identity: cross-artifact joins holding"),
    ("gates.identity.checks_total", "higher_better", 0, "identity: cross-artifact joins declared"),
    ("gates.inertness.formats_marked", "higher_better", 0, "inertness: formats carrying a marker"),
    ("gates.inertness.formats_total", "higher_better", 0, "inertness: marked formats declared"),
    (
        "gates.inertness.binary_safety_checks_passed",
        "higher_better",
        0,
        "inertness: binary safety checks passed",
    ),
    (
        "gates.inertness.binary_safety_checks_total",
        "higher_better",
        0,
        "inertness: binary safety checks declared",
    ),
]

_SOLVABILITY_METRICS = [
    (
        "gates.solvability.reference_solver_score",
        "higher_better",
        0,
        "solvability: reference solver",
    ),
    (
        "gates.solvability.reference_solver_coverage",
        "higher_better",
        0,
        "solvability: reference solver coverage",
    ),
    (
        "gates.solvability.resolved_questions_passed",
        "higher_better",
        0,
        "solvability: closed-rule questions resolved",
    ),
    (
        "gates.solvability.resolved_questions_total",
        "higher_better",
        0,
        "solvability: closed-rule questions declared",
    ),
    (
        "gates.solvability.multi_artifact_dependencies_passed",
        "higher_better",
        0,
        "solvability: multi-artifact dependencies passed",
    ),
    (
        "gates.solvability.multi_artifact_dependencies_total",
        "higher_better",
        0,
        "solvability: multi-artifact dependencies declared",
    ),
    (
        "gates.solvability.counterfactual_checks_passed",
        "higher_better",
        0,
        "solvability: counterfactual checks passed",
    ),
    (
        "gates.solvability.counterfactual_checks_total",
        "higher_better",
        0,
        "solvability: counterfactual checks declared",
    ),
    (
        "gates.solvability.counterfactual_windows_passed",
        "higher_better",
        0,
        "solvability: Windows counterfactual checks passed",
    ),
    (
        "gates.solvability.counterfactual_windows_total",
        "higher_better",
        0,
        "solvability: Windows counterfactual checks declared",
    ),
    (
        "gates.solvability.counterfactual_macos_passed",
        "higher_better",
        0,
        "solvability: macOS counterfactual checks passed",
    ),
    (
        "gates.solvability.counterfactual_macos_total",
        "higher_better",
        0,
        "solvability: macOS counterfactual checks declared",
    ),
    (
        "gates.solvability.statistical_inference_contract_valid",
        "higher_better",
        0,
        "solvability: exact inference contract valid",
    ),
    (
        "gates.solvability.registered_attack_execution_valid",
        "higher_better",
        0,
        "solvability: all registered attacks executed on both corpora",
    ),
    (
        "gates.solvability.randomization_comparisons",
        "higher_better",
        0,
        "solvability: exact randomization comparisons",
    ),
    (
        "gates.solvability.randomization_familywise_alpha",
        "lower_better",
        0,
        "solvability: familywise alpha",
    ),
    (
        "gates.solvability.randomization_adjusted_alpha",
        "lower_better",
        0,
        "solvability: Bonferroni-adjusted alpha",
    ),
    ("gates.solvability.chance_floor", "lower_better", 0, "solvability: exact candidate chance"),
    (
        "gates.solvability.worst_shortcut_score",
        "lower_better",
        0,
        "solvability: worst registered shortcut",
    ),
    (
        "gates.solvability.trained_rank_union_score",
        "lower_better",
        0,
        "solvability: development-trained rank union",
    ),
    (
        "gates.solvability.trained_rank_union_randomization_p",
        "higher_better",
        0,
        "solvability: development-trained rank-union exact p-value",
    ),
    (
        "gates.solvability.trained_rank_union_output_coverage",
        "higher_better",
        0,
        "solvability: development-trained rank-union output coverage",
    ),
    (
        "gates.solvability.trained_partial_union_score",
        "lower_better",
        0,
        "solvability: development-trained partial-output union",
    ),
    (
        "gates.solvability.trained_partial_union_randomization_p",
        "higher_better",
        0,
        "solvability: partial-output union exact p-value",
    ),
    (
        "gates.solvability.trained_partial_union_output_coverage",
        "higher_better",
        0,
        "solvability: partial-output union complete-key coverage",
    ),
    (
        "gates.solvability.trained_partial_union_source_coverage",
        "higher_better",
        0,
        "solvability: partial-output union selected-source coverage",
    ),
    (
        "gates.solvability.trained_partial_union_fallback_count",
        "lower_better",
        0,
        "solvability: partial-output union fallback count",
    ),
    (
        "gates.solvability.blind_solver_score",
        "higher_better",
        0,
        "solvability: public scorecard-key blind control",
    ),
    (
        "gates.solvability.blind_solver_coverage",
        "higher_better",
        0,
        "solvability: public scorecard-key blind-control coverage",
    ),
    (
        "gates.solvability.blind_control_score",
        "higher_better",
        0,
        "solvability: public development-key blind control",
    ),
    (
        "gates.solvability.blind_control_coverage",
        "higher_better",
        0,
        "solvability: public development-key blind-control coverage",
    ),
    (
        "gates.solvability.parent_escape_control_score",
        "higher_better",
        0,
        "solvability: co-located parent-escape control",
    ),
    (
        "gates.solvability.parent_escape_control_coverage",
        "higher_better",
        0,
        "solvability: co-located parent-escape coverage",
    ),
    (
        "gates.solvability.parent_escape_export_score",
        "lower_better",
        0,
        "solvability: exported parent-escape attack",
    ),
    (
        "gates.solvability.parent_escape_export_coverage",
        "lower_better",
        0,
        "solvability: exported parent-escape coverage",
    ),
    (
        "gates.solvability.positive_control_checks_passed",
        "higher_better",
        0,
        "solvability: shortcut positive controls passed",
    ),
    (
        "gates.solvability.positive_control_checks_total",
        "higher_better",
        0,
        "solvability: shortcut positive controls declared",
    ),
    (
        "gates.solvability.positive_control_trained_partial_union_passed",
        "higher_better",
        0,
        "solvability: production trained-partial-union wrapper control",
    ),
    (
        "gates.solvability.positive_control_partial_union_dev_correct",
        "higher_better",
        0,
        "solvability: trained-partial-union dev answers recovered",
    ),
    (
        "gates.solvability.positive_control_partial_union_dev_total",
        "higher_better",
        0,
        "solvability: trained-partial-union dev answers declared",
    ),
    (
        "gates.solvability.positive_control_partial_union_measurement_correct",
        "higher_better",
        0,
        "solvability: trained-partial-union measurement answers recovered",
    ),
    (
        "gates.solvability.positive_control_partial_union_measurement_total",
        "higher_better",
        0,
        "solvability: trained-partial-union measurement answers declared",
    ),
    (
        "gates.solvability.positive_control_partial_union_mapped_questions",
        "higher_better",
        0,
        "solvability: trained-partial-union mapped public question ids",
    ),
    (
        "gates.solvability.positive_control_partial_union_source_covered",
        "higher_better",
        0,
        "solvability: trained-partial-union selected-source answers",
    ),
    (
        "gates.solvability.positive_control_partial_union_fallback_count",
        "lower_better",
        0,
        "solvability: trained-partial-union fallback answers",
    ),
    (
        "gates.solvability.positive_control_partial_union_cross_slot_selections",
        "higher_better",
        0,
        "solvability: trained-partial-union cross-slot selections exercised",
    ),
    (
        "gates.solvability.positive_control_trained_rank_union_passed",
        "higher_better",
        0,
        "solvability: production trained-rank-union wrapper control",
    ),
    (
        "gates.solvability.positive_control_rank_union_dev_correct",
        "higher_better",
        0,
        "solvability: independent trained-rank-union dev answers recovered",
    ),
    (
        "gates.solvability.positive_control_rank_union_dev_total",
        "higher_better",
        0,
        "solvability: independent trained-rank-union dev answers declared",
    ),
    (
        "gates.solvability.positive_control_rank_union_measurement_correct",
        "higher_better",
        0,
        "solvability: frozen rank-union measurement answers recovered",
    ),
    (
        "gates.solvability.positive_control_rank_union_measurement_total",
        "higher_better",
        0,
        "solvability: frozen rank-union measurement answers declared",
    ),
    (
        "gates.solvability.positive_control_rank_union_mapped_questions",
        "higher_better",
        0,
        "solvability: production rank-union predictions mapped to public question ids",
    ),
]

for _ensemble in ("trained_rank_union", "trained_partial_union"):
    for _suffix, _label in (
        ("fit_valid", "development fit valid"),
        ("prediction_valid", "public measurement prediction valid"),
        ("evaluation_performed", "measurement evaluation performed"),
        ("inference_valid", "aggregate and per-class inference valid"),
    ):
        _SOLVABILITY_METRICS.append(
            (
                f"gates.solvability.{_ensemble}_{_suffix}",
                "higher_better",
                0,
                f"solvability: {_ensemble.replace('_', ' ')} {_label}",
            )
        )

_ADVERSARIES = suite.BENCHMARK_REGISTERED_ADVERSARIES
_COMPLETE_ADVERSARIES = frozenset(suite.BENCHMARK_COMPLETE_ADVERSARIES)
_RULE_CLASSES = (
    ("windows", suite.WINDOWS_AMCACHE_RULE),
    ("macos", suite.MACOS_QUARANTINE_RULE),
)

for _attack in _ADVERSARIES:
    _SOLVABILITY_METRICS.extend(
        (
            (
                f"gates.solvability.{_attack}_solver_score",
                "lower_better",
                0,
                f"solvability: {_attack} shortcut score",
            ),
            (
                f"gates.solvability.{_attack}_solver_coverage",
                "higher_better",
                0,
                f"solvability: {_attack} shortcut coverage",
            ),
            (
                f"gates.solvability.{_attack}_randomization_p",
                "higher_better",
                0,
                f"solvability: {_attack} exact aggregate p-value",
            ),
        )
    )
    for _family, _rule in _RULE_CLASSES:
        _class_stem = f"{_family}_{_rule.replace('-', '_')}"
        _SOLVABILITY_METRICS.extend(
            (
                (
                    f"gates.solvability.{_attack}_{_class_stem}_score",
                    "lower_better",
                    0,
                    f"solvability: {_attack} {_family} class score",
                ),
                (
                    f"gates.solvability.{_attack}_{_class_stem}_score_randomization_p",
                    "higher_better",
                    0,
                    f"solvability: {_attack} {_family} class exact p-value",
                ),
            )
        )

for _attack in sorted(_COMPLETE_ADVERSARIES):
    _stem = f"gates.solvability.positive_control_{_attack}"
    _SOLVABILITY_METRICS.extend(
        (
            (
                f"{_stem}_solver_score",
                "higher_better",
                0,
                f"solvability: {_attack} positive-control score",
            ),
            (
                f"{_stem}_solver_coverage",
                "higher_better",
                0,
                f"solvability: {_attack} positive-control coverage",
            ),
            (
                f"{_stem}_reference_score",
                "higher_better",
                0,
                f"solvability: {_attack} positive-control reference score",
            ),
        )
    )

for _corpus in ("measured", "development"):
    for _family, _rule in _RULE_CLASSES:
        _stem = f"{_corpus}_{_family}_{_rule.replace('-', '_')}_scene_count"
        _SOLVABILITY_METRICS.append(
            (
                f"gates.solvability.{_stem}",
                "higher_better",
                0,
                f"solvability: {_corpus} {_family} scene count",
            )
        )

for _family, _rule in _RULE_CLASSES:
    _class_stem = f"{_family}_{_rule.replace('-', '_')}"
    _SOLVABILITY_METRICS.extend(
        (
            (
                f"gates.solvability.power_{_class_stem}_achieved",
                "higher_better",
                0,
                f"solvability: {_family} exact power achieved",
            ),
            (
                f"gates.solvability.trained_rank_union_{_class_stem}_randomization_p",
                "higher_better",
                0,
                f"solvability: trained rank union {_family} exact p-value",
            ),
            (
                f"gates.solvability.trained_partial_union_{_class_stem}_score",
                "lower_better",
                0,
                f"solvability: trained partial union {_family} score",
            ),
            (
                f"gates.solvability.trained_partial_union_{_class_stem}_source_coverage",
                "higher_better",
                0,
                f"solvability: trained partial union {_family} source coverage",
            ),
            (
                f"gates.solvability.trained_partial_union_{_class_stem}_fallback_count",
                "lower_better",
                0,
                f"solvability: trained partial union {_family} fallback count",
            ),
            (
                f"gates.solvability.trained_partial_union_{_class_stem}_randomization_p",
                "higher_better",
                0,
                f"solvability: trained partial union {_family} exact p-value",
            ),
        )
    )

_METRICS = [*_GENERATOR_METRICS, *_SOLVABILITY_METRICS]
_NUMERIC_ONLY_METRICS = {
    path for path, _direction, _tolerance, _label in _GENERATOR_METRICS
}

SCHEMA_VERSION = "2.0"

# The scorecard has two audiences with different maturity. Gates 1-3 describe the artifact
# generator; Gate 4 describes the explicitly experimental investigation benchmark. Keep the
# legacy aggregate verdict below for existing consumers, while making the two scopes available
# as first-class machine-readable status.
GENERATOR_ASSURANCE_GATES = ("validity", "identity", "inertness")
BENCHMARK_VALIDITY_GATES = ("solvability",)

# A metric comparison is meaningless when the two cards describe different contracts. Build
# the identity from every provenance leaf so adding a new contract field cannot accidentally
# leave comparisons enabled. Selected labels remain stable for diagnostics and compatibility
# tests; all other leaves receive an unambiguous path-derived label.
_IDENTITY_LABELS = {
    "measurement.scenario_count": "scenario count",
    "measurement.key_derivation.key_id": "measurement key identity",
    "measurement.generator_assurance.corpora.windows_macos.suite_kind": "Windows/macOS assurance suite kind",
    "measurement.generator_assurance.corpora.windows_macos.public_key.key_id": "Windows/macOS assurance public-key identity",
    "measurement.generator_assurance.corpora.windows_macos.content_namespace": "Windows/macOS assurance content namespace",
    "measurement.generator_assurance.corpora.linux.profile": "Linux assurance corpus profile",
    "measurement.generator_assurance.corpora.linux.key_derivation.key_id": "Linux assurance key identity",
}


def _provenance_leaf_paths(value, prefix=""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            yield from _provenance_leaf_paths(child, child_prefix)
    else:
        yield prefix


def _identity_label(path: str) -> str:
    return _IDENTITY_LABELS.get(
        path,
        path.removeprefix("measurement.").replace("_", " ").replace(".", ": "),
    )


_MEASUREMENT_IDENTITY = tuple(
    (path, _identity_label(path))
    for path in _provenance_leaf_paths(
        {
            "measurement": suite.scorecard_measurement_provenance(40),
        }
    )
)


def _dig(card: dict, path: str):
    node = card
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _metric_value(card: dict, path: str) -> tuple[bool, object]:
    """Return presence separately from value so JSON null is not mistaken for absence."""
    node = card
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _status_block(reports, gate_names, *, experimental: bool) -> dict:
    by_name = {r.name: r for r in reports}
    selected = [by_name[name] for name in gate_names if name in by_name]
    missing = [name for name in gate_names if name not in by_name]
    fails = [f"Gate {r.gate} ({r.name}) FAILING: {reason}" for r in selected for reason in r.fails]
    fails += [f"required gate report missing: {name}" for name in missing]
    gaps = [f"Gate {r.gate} ({r.name}): {reason}" for r in selected for reason in r.gaps]
    verdict = "fail" if fails else "gap" if gaps else "pass"
    return {
        "verdict": verdict,
        "experimental": experimental,
        "gates": list(gate_names),
        "fails": fails,
        "gaps": gaps,
    }


def build_scorecard(
    reports,
    *,
    artifactforge_version: str,
    git_commit: str,
    sqlite_version: str,
    honest_gaps=None,
    measurement=None,
    source=None,
) -> dict:
    """Assemble the committed artifact from a run of the gates."""
    reports = list(reports)
    report_errors = []
    by_name = {}
    for index, report in enumerate(reports):
        name = getattr(report, "name", None)
        gate = getattr(report, "gate", None)
        if name not in _REQUIRED_GATE_NUMBERS:
            report_errors.append(f"report {index} has unknown gate name {name!r}")
            continue
        if name in by_name:
            report_errors.append(f"gate report {name!r} is duplicated")
        else:
            by_name[name] = report
        expected_number = _REQUIRED_GATE_NUMBERS[name]
        if type(gate) is not int or gate != expected_number:
            report_errors.append(
                f"gate report {name!r} has number {gate!r}, expected {expected_number}"
            )
    missing = sorted(set(_REQUIRED_GATE_NUMBERS) - set(by_name))
    if missing:
        report_errors.append(f"required gate reports are missing: {missing!r}")
    if len(reports) != len(_REQUIRED_GATE_NUMBERS):
        report_errors.append(
            f"scorecard requires exactly {len(_REQUIRED_GATE_NUMBERS)} gate reports, "
            f"received {len(reports)}"
        )
    if report_errors:
        raise ScorecardError("invalid scorecard gate reports: " + "; ".join(report_errors))
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
            "source": dict(
                source
                or {
                    "git_commit": git_commit,
                    "attestation_available": False,
                }
            ),
        },
        "gates": gates,
        "status": {
            "generator_assurance": _status_block(
                reports, GENERATOR_ASSURANCE_GATES, experimental=False
            ),
            "benchmark_validity": _status_block(
                reports, BENCHMARK_VALIDITY_GATES, experimental=True
            ),
        },
        "honest_gaps": gaps,
        # Three-valued on purpose. "pass" would be the wrong headline while a declared gap is
        # open — a gap is a named limitation rather than a failure, but it is still something
        # a reader deserves to see before they trust a number underneath it.
        #   pass  every gate green and nothing left declared
        #   gap   every gate green, but a limitation is named in honest_gaps
        #   fail  a gate is red
        "verdict": ("fail" if not all(r.ok for r in reports) else "gap" if gaps else "pass"),
        "verdict_scope": "all_gates",
    }
    if measurement is not None:
        card["measurement"] = dict(measurement)
    return card


def regressions(baseline: dict, current: dict) -> list:
    """Which tracked metrics got worse, allowing forward metric introduction.

    A metric absent from the baseline has no earlier value to regress against. This keeps
    published legacy cards comparable when a later release introduces a new tracked metric.
    Once a metric is present in the baseline, removing it is a regression. Explicit malformed
    values are invalid rather than being treated as absence.
    """
    def valid_number(value) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and (not isinstance(value, float) or math.isfinite(value))
        )

    out = []
    for path, direction, tol, label in _METRICS:
        was_present, was = _metric_value(baseline, path)
        now_present, now = _metric_value(current, path)
        if not was_present and not now_present:
            continue
        if not was_present:
            introduced_value_is_valid = (
                valid_number(now)
                if path in _NUMERIC_ONLY_METRICS
                else isinstance(now, bool) or valid_number(now)
            )
            if not introduced_value_is_valid:
                out.append((label, "invalid", None, now))
            continue
        if not now_present:
            out.append((label, "missing", was, now))
            continue
        if path in _NUMERIC_ONLY_METRICS:
            if not valid_number(was) or not valid_number(now):
                out.append((label, "invalid", was, now))
                continue
            worse = (now < was - tol) if direction == "higher_better" else (now > was + tol)
            if worse:
                out.append((label, "regressed", was, now))
            continue
        was_boolean = isinstance(was, bool)
        now_boolean = isinstance(now, bool)
        if was_boolean or now_boolean:
            # Boolean contract assertions are first-class tracked metrics, but Python's bool
            # is also an int subclass. Compare a bool only with a bool so True <-> 1 cannot
            # silently change the scorecard's type contract. Higher-better means True is the
            # passing state; lower-better retains the exact inverse ordering if one is added.
            if not (was_boolean and now_boolean):
                out.append((label, "invalid", was, now))
                continue
            worse = (was and not now) if direction == "higher_better" else (not was and now)
            if worse:
                out.append((label, "regressed", was, now))
            continue
        if not valid_number(was) or not valid_number(now):
            out.append((label, "invalid", was, now))
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
    required_paths = {path for path, _label in _MEASUREMENT_IDENTITY}
    observed_paths = set()
    for card in (baseline, current):
        if isinstance(card, dict) and "measurement" in card:
            observed_paths.update(
                _provenance_leaf_paths({"measurement": card["measurement"]})
            )

    out = []
    for path in sorted(required_paths | observed_paths):
        label = _identity_label(path)
        was, now = _dig(baseline, path), _dig(current, path)
        if was is None or now is None:
            out.append((label, "missing", was, now))
        elif was != now:
            out.append((label, "changed", was, now))
    return out


def scorecard_structure_errors(card: dict, *, where: str = "scorecard") -> list[str]:
    """Validate the required gate and scoped-status release blocks."""
    if not isinstance(card, dict):
        return [f"{where} must be a JSON object"]

    errors = []
    if card.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{where}.schema_version must be {SCHEMA_VERSION!r}")
    honest_gaps = card.get("honest_gaps")
    if not isinstance(honest_gaps, list) or not all(
        isinstance(item, str) for item in honest_gaps
    ):
        errors.append(f"{where}.honest_gaps must be a list of strings")
        honest_gaps = []
    if card.get("verdict_scope") != "all_gates":
        errors.append(f"{where}.verdict_scope must be 'all_gates'")
    gates = card.get("gates")
    if not isinstance(gates, dict):
        errors.append(f"{where}.gates must be an object")
        gates = {}
    if set(gates) != set(_REQUIRED_GATES):
        errors.append(
            f"{where}.gates must contain exactly {list(_REQUIRED_GATES)!r}, "
            f"found {sorted(gates)!r}"
        )

    gate_states = {}
    for gate in _REQUIRED_GATES:
        block = gates.get(gate)
        if not isinstance(block, dict):
            errors.append(f"{where}.gates.{gate} must be an object")
            continue
        verdict = block.get("verdict")
        fails = block.get("fails")
        gaps = block.get("gaps")
        if verdict not in {"pass", "fail"}:
            errors.append(f"{where}.gates.{gate}.verdict must be 'pass' or 'fail'")
        if not isinstance(fails, list) or not all(isinstance(item, str) for item in fails):
            errors.append(f"{where}.gates.{gate}.fails must be a list of strings")
            fails = []
        if not isinstance(gaps, list) or not all(isinstance(item, str) for item in gaps):
            errors.append(f"{where}.gates.{gate}.gaps must be a list of strings")
            gaps = []
        expected_verdict = "fail" if fails else "pass"
        if verdict in {"pass", "fail"} and verdict != expected_verdict:
            errors.append(
                f"{where}.gates.{gate}.verdict is {verdict!r} but its fails list "
                f"requires {expected_verdict!r}"
            )
        gate_states[gate] = (expected_verdict, fails, gaps)

    status = card.get("status")
    if not isinstance(status, dict):
        errors.append(f"{where}.status must be an object")
        status = {}
    if set(status) != set(_STATUS_SCOPES):
        errors.append(
            f"{where}.status must contain exactly {sorted(_STATUS_SCOPES)!r}, "
            f"found {sorted(status)!r}"
        )

    for scope, (experimental, expected_gates) in _STATUS_SCOPES.items():
        block = status.get(scope)
        if not isinstance(block, dict):
            errors.append(f"{where}.status.{scope} must be an object")
            continue
        verdict = block.get("verdict")
        fails = block.get("fails")
        gaps = block.get("gaps")
        if verdict not in _STATUS_ORDER:
            errors.append(
                f"{where}.status.{scope}.verdict must be one of {list(_STATUS_ORDER)!r}"
            )
        if block.get("experimental") is not experimental:
            errors.append(
                f"{where}.status.{scope}.experimental must be {experimental!r}"
            )
        if block.get("gates") != list(expected_gates):
            errors.append(
                f"{where}.status.{scope}.gates must be {list(expected_gates)!r}"
            )
        if not isinstance(fails, list) or not all(isinstance(item, str) for item in fails):
            errors.append(f"{where}.status.{scope}.fails must be a list of strings")
            fails = []
        if not isinstance(gaps, list) or not all(isinstance(item, str) for item in gaps):
            errors.append(f"{where}.status.{scope}.gaps must be a list of strings")
            gaps = []
        local_verdict = "fail" if fails else "gap" if gaps else "pass"
        if verdict in _STATUS_ORDER and verdict != local_verdict:
            errors.append(
                f"{where}.status.{scope}.verdict is {verdict!r} but its status lists "
                f"require {local_verdict!r}"
            )
        if all(gate in gate_states for gate in expected_gates):
            derived_fails = [
                f"Gate {_REQUIRED_GATE_NUMBERS[gate]} ({gate}) FAILING: {reason}"
                for gate in expected_gates
                for reason in gate_states[gate][1]
            ]
            derived_gaps = [
                f"Gate {_REQUIRED_GATE_NUMBERS[gate]} ({gate}): {reason}"
                for gate in expected_gates
                for reason in gate_states[gate][2]
            ]
            gate_verdict = (
                "fail"
                if any(gate_states[gate][0] == "fail" for gate in expected_gates)
                else "gap"
                if any(gate_states[gate][2] for gate in expected_gates)
                else "pass"
            )
            if verdict in _STATUS_ORDER and verdict != gate_verdict:
                errors.append(
                    f"{where}.status.{scope}.verdict is {verdict!r} but its gate blocks "
                    f"require {gate_verdict!r}"
                )
            if fails != derived_fails:
                errors.append(
                    f"{where}.status.{scope}.fails does not exactly mirror its gate failures"
                )
            if gaps != derived_gaps:
                errors.append(
                    f"{where}.status.{scope}.gaps does not exactly mirror its gate gaps"
                )

    if all(gate in gate_states for gate in _REQUIRED_GATES):
        derived_honest_gaps = {
            *(
                f"Gate {_REQUIRED_GATE_NUMBERS[gate]} ({gate}) FAILING: {reason}"
                for gate in _REQUIRED_GATES
                for reason in gate_states[gate][1]
            ),
            *(
                f"Gate {_REQUIRED_GATE_NUMBERS[gate]} ({gate}): {reason}"
                for gate in _REQUIRED_GATES
                for reason in gate_states[gate][2]
            ),
        }
        missing_honest = sorted(derived_honest_gaps - set(honest_gaps))
        if missing_honest:
            errors.append(
                f"{where}.honest_gaps omits gate-derived failures or gaps: "
                f"{missing_honest!r}"
            )
        aggregate = (
            "fail"
            if any(state[0] == "fail" for state in gate_states.values())
            else "gap"
            if honest_gaps
            else "pass"
        )
        if card.get("verdict") != aggregate:
            errors.append(
                f"{where}.verdict is {card.get('verdict')!r} but gate failures and "
                f"honest_gaps require {aggregate!r}"
            )
    return errors


def status_regressions(baseline: dict, current: dict) -> list:
    """Return scoped status deterioration under ``pass < gap < fail``.

    A current failure always blocks release, including an unchanged pre-existing failure.
    Equal gaps remain allowed so a named pre-existing limitation does not make ``--check``
    permanently red.
    """
    out = []
    for scope in _STATUS_SCOPES:
        was = _dig(baseline, f"status.{scope}.verdict")
        now = _dig(current, f"status.{scope}.verdict")
        label = scope.replace("_", " ")
        if was not in _STATUS_ORDER or now not in _STATUS_ORDER:
            out.append((label, "missing", was, now))
        elif now == "fail":
            out.append((label, "failing", was, now))
        elif _STATUS_ORDER[now] > _STATUS_ORDER[was]:
            out.append((label, "regressed", was, now))
    return out


def render_comparison(baseline: dict, current: dict) -> str:
    rows = regressions(baseline, current)
    if not rows:
        return "no tracked metric regressed"
    return "\n".join(
        f"  {kind.upper():9s} {label}: {was} -> {now}" for label, kind, was, now in rows
    )


def render_measurement_compatibility(baseline: dict, current: dict) -> str:
    rows = measurement_incompatibilities(baseline, current)
    if not rows:
        return "measurement provenance compatible"
    details = "\n".join(
        f"  {kind.upper():7s} {label}: {was!r} -> {now!r}" for label, kind, was, now in rows
    )
    return "measurement provenance incompatible\n" + details


def render_status_comparison(baseline: dict, current: dict) -> str:
    rows = status_regressions(baseline, current)
    if not rows:
        return "no scoped status regressed"
    return "\n".join(
        f"  {kind.upper():9s} {label}: {was} -> {now}"
        for label, kind, was, now in rows
    )


def render_structure_errors(errors: list[str]) -> str:
    if not errors:
        return "scorecard release structure valid"
    return "scorecard release structure invalid\n" + "\n".join(
        f"  INVALID   {error}" for error in errors
    )


def _resolved_parent(path: str | os.PathLike[str]) -> tuple[Path, str, int, tuple[int, int]]:
    try:
        requested = Path(path)
    except TypeError as exc:
        raise ScorecardError("scorecard path must be a filesystem path") from exc
    if not requested.name or requested.name in {".", ".."}:
        raise ScorecardError("scorecard path must have one non-empty final component")
    try:
        parent = requested.parent.resolve(strict=True)
        before = parent.lstat()
    except OSError as exc:
        raise ScorecardError(f"cannot inspect scorecard parent directory: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ScorecardError("scorecard parent must resolve to a real directory")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise ScorecardError("safe scorecard I/O requires O_NOFOLLOW and O_DIRECTORY")
    descriptor = -1
    try:
        descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
        )
        opened = os.fstat(descriptor)
        after = parent.lstat()
    except (NotImplementedError, OSError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ScorecardError(f"cannot safely open scorecard parent directory: {exc}") from exc
    identity = (opened.st_dev, opened.st_ino)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or identity != (before.st_dev, before.st_ino)
        or identity != (after.st_dev, after.st_ino)
    ):
        os.close(descriptor)
        raise ScorecardError("scorecard parent changed while it was being opened")
    return parent, requested.name, descriptor, identity


def _verify_parent(parent: Path, descriptor: int, identity: tuple[int, int]) -> None:
    try:
        opened = os.fstat(descriptor)
        current = parent.lstat()
    except OSError as exc:
        raise ScorecardError(f"cannot post-verify scorecard parent: {exc}") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != identity
        or (current.st_dev, current.st_ino) != identity
        or not stat.S_ISDIR(current.st_mode)
    ):
        raise ScorecardError("scorecard parent changed during I/O")


def _read_regular_at(
    parent_descriptor: int,
    name: str,
    *,
    where: str,
    max_bytes: int = SCORECARD_MAX_BYTES,
) -> tuple[bytes, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ScorecardError("safe scorecard reads require O_NOFOLLOW")
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ScorecardError(f"{where} must be a regular file, not a link or special file")
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise ScorecardError(f"{where} changed while it was being opened")
        if opened.st_size > max_bytes:
            raise ScorecardError(f"{where} exceeds the {max_bytes}-byte input limit")
        chunks = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, max_bytes + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ScorecardError(f"{where} exceeds the {max_bytes}-byte input limit")
        after_read = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except ScorecardError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise ScorecardError(f"cannot safely read {where}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(
        getattr(opened, field) != getattr(after_read, field)
        or getattr(after_read, field) != getattr(after_path, field)
        for field in stable
    ):
        raise ScorecardError(f"{where} changed while it was being read")
    data = b"".join(chunks)
    if len(data) != after_read.st_size:
        raise ScorecardError(f"{where} length changed while it was being read")
    return data, after_read


def _strict_scorecard_json(data: bytes) -> dict:
    if not isinstance(data, bytes):
        raise TypeError("scorecard JSON input must be bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ScorecardError("scorecard JSON must not carry a UTF-8 BOM")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ScorecardError("scorecard JSON is not valid UTF-8") from exc

    def object_from_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ScorecardError(f"scorecard JSON has duplicate member {key!r}")
            result[key] = value
        return result

    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise ScorecardError(f"scorecard JSON has non-finite number {token!r}")
        return value

    def reject_constant(token):
        raise ScorecardError(f"scorecard JSON has non-finite constant {token!r}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=object_from_pairs,
            parse_float=finite_float,
            parse_constant=reject_constant,
        )
    except ScorecardError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise ScorecardError(f"invalid scorecard JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ScorecardError("scorecard JSON root must be an object")
    _validate_json_value(value)
    return value


def _validate_json_value(value, where: str = "$") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ScorecardError(f"{where} contains a non-finite number")
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ScorecardError(f"{where} contains an unpaired Unicode surrogate") from exc
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ScorecardError(f"{where} has a non-string object member name")
            _validate_json_value(key, f"{where} object member name")
            _validate_json_value(item, f"{where}.{key}")
        return
    raise ScorecardError(f"{where} contains unsupported JSON type {type(value).__name__}")


def _scorecard_bytes(card: dict) -> bytes:
    if not isinstance(card, dict):
        raise ScorecardError("scorecard must be a dictionary")
    structure_errors = scorecard_structure_errors(card)
    if structure_errors:
        raise ScorecardError(render_structure_errors(structure_errors))
    try:
        data = (
            json.dumps(
                card,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=False,
            )
            + "\n"
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise ScorecardError(f"scorecard cannot be encoded as strict JSON: {exc}") from exc
    if len(data) > SCORECARD_MAX_BYTES:
        raise ScorecardError(
            f"scorecard exceeds the {SCORECARD_MAX_BYTES}-byte output limit"
        )
    if _strict_scorecard_json(data) != card:
        raise ScorecardError("scorecard changes value during strict JSON serialization")
    return data


def validated_bytes(card: dict) -> bytes:
    """Return bounded strict JSON only for a structurally valid release card."""
    return _scorecard_bytes(card)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ScorecardError("scorecard temporary write made no progress")
        view = view[written:]


def _read_open_descriptor(descriptor: int, *, max_bytes: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, max_bytes + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ScorecardError(
                    f"scorecard temporary exceeds the {max_bytes}-byte output limit"
                )
        return b"".join(chunks)
    except ScorecardError:
        raise
    except OSError as exc:
        raise ScorecardError(f"cannot verify scorecard temporary bytes: {exc}") from exc


def _destination_state(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        state = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except (NotImplementedError, OSError) as exc:
        raise ScorecardError(f"cannot inspect scorecard destination: {exc}") from exc
    if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
        raise ScorecardError(
            "scorecard destination must be absent or an existing regular file, "
            "not a link or special file"
        )
    return state


def _same_file_state(first: os.stat_result, second: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(first, field) == getattr(second, field) for field in fields)


def load(path: str | os.PathLike[str]) -> dict:
    """Load one bounded strict-JSON scorecard through a stable no-follow descriptor."""
    parent, name, parent_descriptor, parent_identity = _resolved_parent(path)
    try:
        data, _state = _read_regular_at(
            parent_descriptor,
            name,
            where="scorecard",
        )
        _verify_parent(parent, parent_descriptor, parent_identity)
    finally:
        os.close(parent_descriptor)
    return _strict_scorecard_json(data)


def save(card: dict, path: str | os.PathLike[str]) -> None:
    """Durably publish strict JSON with a same-directory atomic replacement.

    Every fallible encoding, target and temporary-file check occurs before ``os.replace``.
    Therefore an exception before that publication point leaves any existing card unchanged.
    """
    data = _scorecard_bytes(card)
    parent, name, parent_descriptor, parent_identity = _resolved_parent(path)
    temporary_name = None
    temporary_descriptor = -1
    published = False
    try:
        initial = _destination_state(parent_descriptor, name)
        desired_mode = 0o644
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ScorecardError("safe scorecard writes require O_NOFOLLOW")
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | nofollow
        )
        for _attempt in range(64):
            candidate = f".artifactforge-scorecard-{secrets.token_hex(12)}.tmp"
            try:
                temporary_descriptor = os.open(
                    candidate,
                    flags,
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            except (NotImplementedError, OSError) as exc:
                raise ScorecardError(
                    f"cannot create exclusive scorecard temporary file: {exc}"
                ) from exc
            temporary_name = candidate
            break
        if temporary_descriptor < 0 or temporary_name is None:
            raise ScorecardError("cannot allocate an exclusive scorecard temporary file")

        _write_all(temporary_descriptor, data)
        os.fchmod(temporary_descriptor, desired_mode)
        if _read_open_descriptor(
            temporary_descriptor,
            max_bytes=SCORECARD_MAX_BYTES,
        ) != data:
            raise ScorecardError("scorecard temporary bytes differ before publication")
        os.fsync(temporary_descriptor)
        temporary_state = os.fstat(temporary_descriptor)
        named_temporary = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(temporary_state.st_mode)
            or not _same_file_state(temporary_state, named_temporary)
            or temporary_state.st_size != len(data)
            or stat.S_IMODE(temporary_state.st_mode) != desired_mode
        ):
            raise ScorecardError("scorecard temporary file failed pre-publication verification")

        current = _destination_state(parent_descriptor, name)
        if initial is None and current is not None:
            raise ScorecardError("scorecard destination appeared before publication")
        if initial is not None and (
            current is None or not _same_file_state(initial, current)
        ):
            raise ScorecardError("scorecard destination changed before publication")
        _verify_parent(parent, parent_descriptor, parent_identity)
        try:
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        except (NotImplementedError, OSError) as exc:
            raise ScorecardError(f"cannot atomically publish scorecard: {exc}") from exc
        published = True

        published_data, published_state = _read_regular_at(
            parent_descriptor,
            name,
            where="published scorecard",
        )
        if published_data != data:
            raise ScorecardError("published scorecard bytes differ from the verified temporary")
        if stat.S_IMODE(published_state.st_mode) != desired_mode:
            raise ScorecardError("published scorecard mode differs from the verified temporary")
        if (published_state.st_dev, published_state.st_ino) != (
            temporary_state.st_dev,
            temporary_state.st_ino,
        ):
            raise ScorecardError("published scorecard is not the verified temporary inode")
        os.fsync(parent_descriptor)
        _verify_parent(parent, parent_descriptor, parent_identity)
    except ScorecardPublicationUncertain:
        raise
    except ScorecardError as exc:
        if published:
            raise ScorecardPublicationUncertain(
                f"scorecard was published to {parent / name}, but post-publication "
                f"verification or durability is uncertain: {exc}",
                path=parent / name,
            ) from exc
        raise
    except (NotImplementedError, OSError) as exc:
        if published:
            raise ScorecardPublicationUncertain(
                f"scorecard was published to {parent / name}, but post-publication "
                f"verification or durability is uncertain: {exc}",
                path=parent / name,
            ) from exc
        raise ScorecardError(f"scorecard publication failed: {exc}") from exc
    finally:
        if temporary_name is not None and not published:
            try:
                named = os.stat(
                    temporary_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                held = os.fstat(temporary_descriptor)
                if stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino) == (
                    held.st_dev,
                    held.st_ino,
                ):
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        os.close(parent_descriptor)
