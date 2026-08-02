# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 4 — do registered shortcuts evade the bounded v2 validity test?

V1's aggregate score hid two 100% attacks behind incomplete answer dictionaries and called a
4.2% filename lottery "chance" even though guessing one root candidate determined every
dependent answer. V2 permits two closed scalar rules, scores each relation once, re-derives
its five candidates, and computes chance as exactly one in five.

Solvers never receive an evaluator pathname. Each run first creates and reloads an exact public
export containing only canonical ``public.json`` and ``scenarios/``. Parent traversal is a
mandatory positive/negative control: it must steal every answer from the legacy co-located
view and zero from the export. A separate OS account/container/machine remains required for an
actually untrusted external solver; in-process Python is not a security boundary.

A green gate is a scoped non-detection result: no registered shortcut whose detector passed
its independent positive control was detected at the declared familywise alpha. It is not a
claim of universal shortcut resistance, and an observed shortcut score need not equal the
20% candidate-chance expectation. The >=99% power contract is narrower still: it applies only
to the predeclared alternative that recovers a whole scene with probability 0.5 and otherwise
produces a uniformly random five-way permutation.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import ExitStack, contextmanager
from fractions import Fraction
from pathlib import Path
import tempfile

from artifactforge import suite
from artifactforge.bench.adversary import (
    ADVERSARIES,
    COMPLETE_ADVERSARIES,
    blind_solve,
    parent_escape_solve,
)
from artifactforge.bench.benchmark import (
    evaluator_root,
    frozen_public_tasks,
    grade,
    normalize,
)
from artifactforge.bench.counterfactual import evaluate_counterfactuals
from artifactforge.bench.positive_controls import calibrate_positive_controls
from artifactforge.bench.partial_union import (
    fit_partial_union as _fit_partial_union,
    predict_partial_union as _predict_partial_union,
)
from artifactforge.bench.reference_solver import (
    ALLOWED_RULES,
    RULE_FAMILIES,
    reference_solve,
    resolve_task,
)
from artifactforge.bench.rank_union import (
    fit_rank_union as _fit_rank_union,
    predict_rank_union as _predict_rank_union,
)
from artifactforge.bench.statistics import (
    DEFAULT_FAMILYWISE_ALPHA,
    MIN_SCENES_PER_FAMILY,
    PermutationScene,
    bonferroni_alpha,
    exact_permutation_inference,
    permutation_power_contract,
)
from artifactforge.gates import GateReport


SUPPORTED_FAMILIES = frozenset(("windows", "macos"))
EXPECTED_CLASSES = frozenset((family, rule) for rule, family in RULE_FAMILIES.items())
EXPECTED_CANDIDATES = 5
FAMILYWISE_ALPHA = DEFAULT_FAMILYWISE_ALPHA
MIN_SCENES_PER_CLASS = MIN_SCENES_PER_FAMILY


def _require_supported_tasks(tasks, where: str) -> None:
    unsupported = sorted(
        {getattr(task, "family", None) for task in tasks} - SUPPORTED_FAMILIES,
        key=repr,
    )
    if unsupported:
        raise ValueError(f"{where} contains unsupported benchmark families: {unsupported!r}")


def _chance_floor(tasks) -> float:
    """Exact candidate-aware chance, with no special zero for derived scalar values."""
    _require_supported_tasks(tasks, "chance-floor corpus")
    probabilities = []
    for task in tasks:
        for question in task.questions:
            count = getattr(question, "candidate_count", None)
            if type(count) is not int or count < 2:
                raise ValueError(
                    f"{task.family}/{question.id} has no valid candidate-count contract"
                )
            probabilities.append(1 / count)
    return sum(probabilities) / len(probabilities) if probabilities else 0.0


def _scene_class_counts(tasks) -> Counter:
    counts = Counter()
    for task in tasks:
        classes = {(task.family, question.rule) for question in task.questions}
        for key in classes:
            counts[key] += 1
    return counts


def _task_map(tasks) -> dict[str, object]:
    mapped = {task.scenario_id: task for task in tasks}
    if len(mapped) != len(tasks):
        raise ValueError("benchmark corpus contains duplicate scenario ids")
    return mapped


@contextmanager
def _exported(tasks, parent: Path, label: str):
    root = evaluator_root(tasks)
    destination = parent / label
    suite.export_public(str(root), str(destination))
    with frozen_public_tasks(destination) as (document, public_tasks):
        if set(_task_map(public_tasks)) != set(_task_map(tasks)):
            raise ValueError("public export task identities differ from evaluator state")
        yield document, public_tasks


def _solver_answers(public_tasks, solver) -> dict[str, dict]:
    answers = {}
    for public in public_tasks:
        answers[public.scenario_id] = solver(public)
    return answers


def _registered_attack_answers(r: GateReport, public_tasks, corpus: str):
    outputs = {}
    for name, solver in ADVERSARIES.items():
        try:
            outputs[name] = _solver_answers(public_tasks, solver)
        except Exception as exc:  # noqa: BLE001 - one broken attack invalidates inference
            r.metrics["registered_attack_execution_failed_attack"] = name
            r.metrics["registered_attack_execution_failed_corpus"] = corpus
            r.fail(
                f"registered attack {name!r} failed on the {corpus} corpus: "
                f"{type(exc).__name__}: {exc}; shortcut inference was suppressed"
            )
            return None
    return outputs


def _score_answers(private_tasks, public_tasks, answers_by_scenario) -> tuple[float, float, dict]:
    private = _task_map(private_tasks)
    correct = total = attempted = 0
    by_class = defaultdict(lambda: [0, 0, 0])
    for public in public_tasks:
        task = private[public.scenario_id]
        answers = answers_by_scenario.get(public.scenario_id, {})
        if not isinstance(answers, dict):
            answers = {}
        score = grade(task, answers)
        for question in task.questions:
            key = (task.family, question.rule)
            hit = int(score.per_question[question.id])
            supplied = int(question.id in answers)
            by_class[key][0] += hit
            by_class[key][1] += 1
            by_class[key][2] += supplied
            correct += hit
            total += 1
            attempted += supplied
    detail = {
        key: {
            "score": hits / count if count else 0.0,
            "coverage": supplied / count if count else 0.0,
            "correct": hits,
            "total": count,
        }
        for key, (hits, count, supplied) in by_class.items()
    }
    return (
        correct / total if total else 0.0,
        attempted / total if total else 0.0,
        detail,
    )


def _score(private_tasks, public_tasks, solver) -> tuple[float, float, dict]:
    return _score_answers(
        private_tasks,
        public_tasks,
        _solver_answers(public_tasks, solver),
    )


def _randomization_tail(
    private_tasks,
    public_tasks,
    answers_by_scenario,
    *,
    selected_class: tuple[str, str] | None = None,
) -> Fraction:
    """Exact conditional tail probability under independent five-way answer permutations.

    Questions within a scene are not independent Bernoulli trials: their answers are a
    bijection.  Enumerating all 5! assignments per scene, then convolving those exact count
    distributions, avoids the invalid binomial approximation and arbitrary score cutoffs.
    """
    private = _task_map(private_tasks)
    scenes = []
    for public in public_tasks:
        task = private[public.scenario_id]
        questions = [
            question
            for question in task.questions
            if selected_class is None or (task.family, question.rule) == selected_class
        ]
        if not questions:
            continue
        resolutions = resolve_task(public)
        candidates = tuple(resolutions[questions[0].id].candidates)
        if len(questions) != EXPECTED_CANDIDATES or len(candidates) != EXPECTED_CANDIDATES:
            raise ValueError("randomization test requires one complete five-way scene class")
        answers = answers_by_scenario.get(public.scenario_id, {})
        predicted = tuple(
            normalize(answers.get(question.id), question.kind) for question in questions
        )
        actual = tuple(normalize(question.expected, question.kind) for question in questions)
        normalized_candidates = tuple(normalize(value, questions[0].kind) for value in candidates)
        scenes.append(PermutationScene(predicted, actual, normalized_candidates))
    if not scenes:
        raise ValueError("randomization test selected no complete scene classes")
    return exact_permutation_inference(scenes).p_value


def _contract(
    r: GateReport,
    private_tasks,
    public_tasks,
    *,
    metric_prefix: str = "",
) -> bool:
    failures_before = len(r.fails)
    private = _task_map(private_tasks)
    resolved_total = resolved_passed = dependency_total = dependency_passed = 0
    for public in public_tasks:
        task = private[public.scenario_id]
        public_questions = {question.id: question for question in public.questions}
        if set(public_questions) != {question.id for question in task.questions}:
            r.fail(f"{task.scenario_id}: public and private question ids differ")
            continue
        try:
            resolutions = resolve_task(public)
        except Exception as exc:  # noqa: BLE001 - a reference failure is gate evidence
            r.fail(f"{task.scenario_id}: closed rule resolver failed: {exc}")
            continue

        selectors = []
        expected_values = []
        candidate_universe = None
        if len(task.questions) != EXPECTED_CANDIDATES:
            r.fail(
                f"{task.scenario_id}: expected exactly {EXPECTED_CANDIDATES} scalar "
                f"questions, found {len(task.questions)}"
            )
        for question in task.questions:
            resolved_total += 1
            resolution = resolutions.get(question.id)
            public_question = public_questions[question.id]
            if resolution is None:
                r.fail(f"{task.scenario_id}/{question.id}: resolver returned no result")
                continue
            valid = True
            if question.rule not in ALLOWED_RULES or public_question.rule != question.rule:
                r.fail(f"{task.scenario_id}/{question.id}: rule is not in the closed registry")
                valid = False
            if public_question.selector != question.selector:
                r.fail(f"{task.scenario_id}/{question.id}: public selector changed")
                valid = False
            if public_question.prompt != question.prompt or public_question.kind != question.kind:
                r.fail(f"{task.scenario_id}/{question.id}: public prompt or answer kind changed")
                valid = False
            candidates = tuple(resolution.candidates)
            if (
                len(candidates) != EXPECTED_CANDIDATES
                or len(set(candidates)) != EXPECTED_CANDIDATES
                or question.candidate_count != EXPECTED_CANDIDATES
                or public_question.candidate_count != EXPECTED_CANDIDATES
            ):
                r.fail(
                    f"{task.scenario_id}/{question.id}: candidate set is not an exact "
                    f"{EXPECTED_CANDIDATES}-value universe"
                )
                valid = False
            if resolution.value != question.expected or resolution.value not in candidates:
                r.fail(
                    f"{task.scenario_id}/{question.id}: value agreement does not re-derive "
                    "the private scalar answer"
                )
                valid = False
            dependencies = tuple(dict.fromkeys(resolution.artifacts))
            dependency_total += 1
            if len(dependencies) < 2:
                r.fail(
                    f"{task.scenario_id}/{question.id}: resolver used fewer than two "
                    "distinct artifacts"
                )
                valid = False
            else:
                dependency_passed += 1
            if valid:
                resolved_passed += 1
            selectors.append((question.rule, tuple(sorted(question.selector.items()))))
            expected_values.append(question.expected)
            if candidate_universe is None:
                candidate_universe = set(candidates)
            elif set(candidates) != candidate_universe:
                r.fail(f"{task.scenario_id}: questions disagree on the candidate universe")

        if len(set(selectors)) != len(selectors):
            r.fail(f"{task.scenario_id}: selectors are not unique")
        if candidate_universe is None or set(expected_values) != candidate_universe:
            r.fail(f"{task.scenario_id}: five questions are not a bijection over five candidates")

    r.metrics[f"{metric_prefix}resolved_questions_passed"] = resolved_passed
    r.metrics[f"{metric_prefix}resolved_questions_total"] = resolved_total
    r.metrics[f"{metric_prefix}multi_artifact_dependencies_passed"] = dependency_passed
    r.metrics[f"{metric_prefix}multi_artifact_dependencies_total"] = dependency_total
    return len(r.fails) == failures_before


def _counterfactual_contract(r: GateReport, public_tasks) -> bool:
    failures_before = len(r.fails)
    passed = total = 0
    by_family = defaultdict(lambda: [0, 0])
    for public in public_tasks:
        try:
            report = evaluate_counterfactuals(public)
        except Exception as exc:  # noqa: BLE001 - a proof failure is gate evidence
            r.fail(
                f"{public.scenario_id}: parser-valid counterfactual evaluation failed: "
                f"{type(exc).__name__}: {exc}"
            )
            continue
        passed += report.passed
        total += report.total
        by_family[report.family][0] += report.passed
        by_family[report.family][1] += report.total
        for detail in report.details:
            if not detail.passed:
                explanation = detail.error or ", ".join(
                    f"{outcome.question_id}={outcome.state}:{outcome.value!r}"
                    for outcome in detail.observed
                )
                r.fail(
                    f"{public.scenario_id}: counterfactual {detail.mutation} on "
                    f"{detail.targets!r} did not have its exact local effect: {explanation}"
                )
    r.metrics["counterfactual_checks_passed"] = passed
    r.metrics["counterfactual_checks_total"] = total
    for family, (family_passed, family_total) in sorted(by_family.items()):
        r.metrics[f"counterfactual_{family}_passed"] = family_passed
        r.metrics[f"counterfactual_{family}_total"] = family_total
    return len(r.fails) == failures_before


def _positive_control_contract(r: GateReport, public_tasks) -> None:
    """Require every complete shortcut detector to work in a vulnerable world."""
    expected_total = len(COMPLETE_ADVERSARIES) + 2
    r.metrics["positive_control_checks_passed"] = 0
    r.metrics["positive_control_checks_total"] = expected_total
    by_family = {}
    for public in public_tasks:
        by_family.setdefault(public.family, public)
    missing = sorted(SUPPORTED_FAMILIES - set(by_family))
    if missing:
        r.fail(f"positive-control calibration has no development scene for families: {missing!r}")
        return
    try:
        report = calibrate_positive_controls(
            by_family["windows"],
            by_family["macos"],
            ADVERSARIES,
        )
    except Exception as exc:  # noqa: BLE001 - calibration must fail the gate, not abort it
        r.fail(f"positive-control calibration failed closed: {type(exc).__name__}: {exc}")
        return

    r.metrics["positive_control_checks_passed"] = report.passed
    r.metrics["positive_control_excluded_low_information"] = list(report.excluded)
    for detail in report.details:
        stem = f"positive_control_{detail.attack}"
        r.metrics[f"{stem}_solver_score"] = round(detail.solver_score, 4)
        r.metrics[f"{stem}_solver_coverage"] = round(
            detail.solver_coverage / detail.total if detail.total else 0.0,
            4,
        )
        r.metrics[f"{stem}_reference_score"] = round(detail.reference_score, 4)
        if not detail.passed:
            explanation = "; ".join(detail.failures) or "calibration invariant failed"
            r.fail(
                f"the '{detail.attack}' shortcut lacks a passing two-family positive "
                f"control: {explanation}"
            )

    partial_union = report.partial_union
    r.metrics["positive_control_trained_partial_union_passed"] = partial_union.passed
    r.metrics["positive_control_partial_union_dev_correct"] = partial_union.dev_correct
    r.metrics["positive_control_partial_union_dev_total"] = partial_union.dev_total
    r.metrics["positive_control_partial_union_measurement_correct"] = (
        partial_union.measurement_correct
    )
    r.metrics["positive_control_partial_union_measurement_total"] = partial_union.measurement_total
    r.metrics["positive_control_partial_union_mapped_questions"] = partial_union.mapped_questions
    r.metrics["positive_control_partial_union_source_covered"] = partial_union.source_covered
    r.metrics["positive_control_partial_union_fallback_count"] = partial_union.fallback_count
    r.metrics["positive_control_partial_union_selected_attacks"] = list(
        partial_union.selected_attacks
    )
    r.metrics["positive_control_partial_union_cross_slot_selections"] = (
        partial_union.cross_slot_selections
    )
    if not partial_union.passed:
        explanation = "; ".join(partial_union.failures) or "calibration invariant failed"
        r.fail(
            "the production trained-partial-union wrapper lacks a passing positive "
            f"control: {explanation}"
        )

    rank_union = report.rank_union
    r.metrics["positive_control_trained_rank_union_passed"] = rank_union.passed
    r.metrics["positive_control_rank_union_dev_correct"] = rank_union.dev_correct
    r.metrics["positive_control_rank_union_dev_total"] = rank_union.dev_total
    r.metrics["positive_control_rank_union_measurement_correct"] = rank_union.measurement_correct
    r.metrics["positive_control_rank_union_measurement_total"] = rank_union.measurement_total
    r.metrics["positive_control_rank_union_mapped_questions"] = rank_union.mapped_questions
    if not rank_union.passed:
        explanation = "; ".join(rank_union.failures) or "calibration invariant failed"
        r.fail(
            "the production trained-rank-union wrapper lacks a passing positive control: "
            f"{explanation}"
        )
    if report.passed != expected_total:
        r.fail(f"only {report.passed}/{expected_total} mandatory shortcut positive controls pass")


def _validated_evaluator_root(r: GateReport, tasks, label: str) -> Path | None:
    """Validate the evaluator-private key/public binding before anything is exported.

    A Gate 4 invocation owns evaluator tasks, so unlike a solver it can and must prove that
    ``suite_kind`` agrees with the actual key and that scenario ids derive from that key in
    manifest order.  Missing validation is itself a red gate, never permission to continue.
    """
    metric = f"{label}_evaluator_key_binding_valid"
    r.metrics[metric] = False
    try:
        root = evaluator_root(tasks)
    except (OSError, TypeError, ValueError) as exc:
        r.fail(f"{label} evaluator root is invalid: {type(exc).__name__}: {exc}")
        return None
    validator = getattr(suite, "validate_evaluator_key_binding", None)
    if not callable(validator):
        r.fail(f"{label} evaluator key-binding validator is unavailable")
        return None
    try:
        validator(str(root))
    except (OSError, TypeError, ValueError) as exc:
        r.fail(f"{label} evaluator key binding is invalid: {type(exc).__name__}: {exc}")
        return None
    r.metrics[metric] = True
    return root


def _boundary_controls(
    r: GateReport,
    measured_private,
    measured_public,
    dev_private,
    dev_public,
    measured_kind: str,
) -> bool:
    """Run non-statistical leak/reconstructability controls and fail closed on errors."""
    failures_before = len(r.fails)
    try:
        blind_measured, blind_measured_coverage, _ = _score(
            measured_private, measured_public, blind_solve
        )
        r.metrics["blind_solver_score"] = round(blind_measured, 4)
        r.metrics["blind_solver_coverage"] = round(blind_measured_coverage, 4)
        if measured_kind == suite.SCORECARD_MEASUREMENT_KIND:
            if (blind_measured, blind_measured_coverage) != (1.0, 1.0):
                r.fail(
                    "the source-aware blind scorecard control must reconstruct every answer; "
                    f"score={blind_measured:.1%}, coverage={blind_measured_coverage:.1%}"
                )
        elif (blind_measured, blind_measured_coverage) != (0.0, 0.0):
            r.fail(
                "the blind holdout control must return no answers for a fresh key; "
                f"score={blind_measured:.1%}, coverage={blind_measured_coverage:.1%}"
            )

        blind_control, blind_control_coverage, _ = _score(dev_private, dev_public, blind_solve)
        r.metrics["blind_control_score"] = round(blind_control, 4)
        r.metrics["blind_control_coverage"] = round(blind_control_coverage, 4)
        if (blind_control, blind_control_coverage) != (1.0, 1.0):
            r.fail(
                "the blind development control must reconstruct every answer; "
                f"score={blind_control:.1%}, coverage={blind_control_coverage:.1%}"
            )

        co_located_escape, co_located_coverage, _ = _score(
            measured_private,
            [task.public() for task in measured_private],
            parent_escape_solve,
        )
        exported_escape, exported_coverage, _ = _score(
            measured_private, measured_public, parent_escape_solve
        )
        r.metrics["parent_escape_control_score"] = round(co_located_escape, 4)
        r.metrics["parent_escape_control_coverage"] = round(co_located_coverage, 4)
        r.metrics["parent_escape_export_score"] = round(exported_escape, 4)
        r.metrics["parent_escape_export_coverage"] = round(exported_coverage, 4)
        if (co_located_escape, co_located_coverage) != (1.0, 1.0):
            r.fail(
                "the co-located parent-escape control must recover every private answer; "
                f"score={co_located_escape:.1%}, coverage={co_located_coverage:.1%}"
            )
        if (exported_escape, exported_coverage) != (0.0, 0.0):
            r.fail(
                "the exported parent-escape control must return no answers; "
                f"score={exported_escape:.1%}, coverage={exported_coverage:.1%}"
            )
    except Exception as exc:  # noqa: BLE001 - a broken control must redden, not abort, the gate
        r.fail(f"Gate 4 trust-boundary controls failed closed: {type(exc).__name__}: {exc}")
    return len(r.fails) == failures_before


def run(holdout_tasks: list, dev_tasks: list | None = None) -> GateReport:
    r = GateReport(
        4,
        "solvability",
        "does the closed-rule benchmark detect any registered shortcut at the declared "
        "familywise alpha, with complete attacks and composition ensembles independently "
        "calibrated?",
    )
    r.metrics["population_contract_valid"] = False
    r.metrics["statistical_inference_contract_valid"] = False
    r.metrics["statistical_inference_performed"] = False
    r.metrics["registered_attack_execution_valid"] = False
    for ensemble in ("trained_rank_union", "trained_partial_union"):
        r.metrics[f"{ensemble}_fit_valid"] = False
        r.metrics[f"{ensemble}_prediction_valid"] = False
        r.metrics[f"{ensemble}_evaluation_performed"] = False
        r.metrics[f"{ensemble}_inference_valid"] = False
    if not holdout_tasks:
        r.fail("no tasks generated, so nothing was measured")
        r.denominator = "invalid measured population; statistical inference not run"
        return r
    if not dev_tasks:
        r.fail("no public-keyed development control corpus was supplied")
        r.denominator = "invalid development population; statistical inference not run"
        return r
    try:
        _require_supported_tasks(holdout_tasks, "measured corpus")
        _require_supported_tasks(dev_tasks, "development control corpus")
    except (TypeError, ValueError) as exc:
        r.fail(f"benchmark population is invalid: {exc}")
        r.denominator = "invalid benchmark population; statistical inference not run"
        return r

    measured_root = _validated_evaluator_root(r, holdout_tasks, "measured")
    dev_root = _validated_evaluator_root(r, dev_tasks, "development")
    if measured_root is None or dev_root is None:
        r.denominator = "invalid evaluator key binding; statistical inference not run"
        return r

    with (
        tempfile.TemporaryDirectory(prefix="artifactforge-gate4-public-") as directory,
        ExitStack() as public_snapshots,
    ):
        parent = Path(directory)
        try:
            measured_document, measured_public = public_snapshots.enter_context(
                _exported(holdout_tasks, parent, "measured-public")
            )
            dev_document, dev_public = public_snapshots.enter_context(
                _exported(dev_tasks, parent, "dev-public")
            )
        except Exception as exc:  # noqa: BLE001 - malformed evaluator state is gate evidence
            r.fail(
                f"evaluator-to-public export preflight failed closed: {type(exc).__name__}: {exc}"
            )
            r.denominator = "invalid public export; statistical inference not run"
            return r

        population_contract_valid = True
        for label, corpus in (("measured", holdout_tasks), ("development", dev_tasks)):
            try:
                counts = _scene_class_counts(corpus)
            except (AttributeError, TypeError, ValueError) as exc:
                r.fail(f"{label} corpus classes cannot be counted: {exc}")
                population_contract_valid = False
                counts = Counter()
            if set(counts) != EXPECTED_CLASSES:
                r.fail(
                    f"{label} corpus scene classes are {sorted(counts)!r}, not the exact "
                    f"v2 registry {sorted(EXPECTED_CLASSES)!r}"
                )
                population_contract_valid = False
            for family, rule in sorted(EXPECTED_CLASSES | set(counts)):
                count = counts[(family, rule)]
                metric = f"{label}_{family}_{rule.replace('-', '_')}_scene_count"
                r.metrics[metric] = count
                if count < MIN_SCENES_PER_CLASS:
                    population_contract_valid = False
                    r.fail(
                        f"{label} corpus has only {count} {family}/{rule} scenes; "
                        f"at least {MIN_SCENES_PER_CLASS} are required for the predeclared "
                        "Gate 4 power contract"
                    )

        r.metrics["population_contract_valid"] = population_contract_valid
        measured_contract_valid = _contract(r, holdout_tasks, measured_public)
        development_contract_valid = _contract(
            r,
            dev_tasks,
            dev_public,
            metric_prefix="development_",
        )
        counterfactual_valid = _counterfactual_contract(r, measured_public)

        measured_kind = measured_document.get("suite_kind")
        dev_kind = dev_document.get("suite_kind")
        role_contract_valid = True
        if measured_kind not in {
            suite.HOLDOUT_SUITE_KIND,
            suite.SCORECARD_MEASUREMENT_KIND,
        }:
            r.fail(
                "measured corpus must be a holdout or scorecard-measurement suite, "
                f"not {measured_kind!r}"
            )
            role_contract_valid = False
        if dev_kind != suite.DEV_SUITE_KIND:
            r.fail(f"development control corpus must be a dev suite, not {dev_kind!r}")
            role_contract_valid = False
        r.metrics["corpus_role_contract_valid"] = role_contract_valid

        contract_valid = (
            measured_contract_valid
            and development_contract_valid
            and counterfactual_valid
            and role_contract_valid
        )

        positive_control_valid = False
        if population_contract_valid and contract_valid:
            failures_before_controls = len(r.fails)
            _positive_control_contract(r, dev_public)
            positive_control_valid = len(r.fails) == failures_before_controls
        else:
            r.metrics["positive_control_checks_passed"] = 0
            r.metrics["positive_control_checks_total"] = len(COMPLETE_ADVERSARIES) + 2

        try:
            chance = _chance_floor(holdout_tasks)
        except (AttributeError, TypeError, ValueError) as exc:
            chance = 0.0
            contract_valid = False
            r.fail(f"candidate-aware chance contract is invalid: {exc}")
        r.metrics["chance_floor"] = round(chance, 4)
        if chance != 1 / EXPECTED_CANDIDATES:
            r.fail(f"candidate-aware chance is {chance:.1%}, not the exact 20% v2 contract")

        try:
            reference, reference_coverage, _reference_detail = _score(
                holdout_tasks, measured_public, reference_solve
            )
        except Exception as exc:  # noqa: BLE001 - a reference failure must redden the gate
            reference = reference_coverage = 0.0
            contract_valid = False
            r.fail(f"the reference resolver failed closed: {type(exc).__name__}: {exc}")
        r.metrics["reference_solver_score"] = round(reference, 4)
        r.metrics["reference_solver_coverage"] = round(reference_coverage, 4)
        if reference != 1.0 or reference_coverage != 1.0:
            r.fail(
                f"the reference resolver scores {reference:.1%} at "
                f"{reference_coverage:.1%} coverage"
            )

        boundary_controls_valid = _boundary_controls(
            r,
            holdout_tasks,
            measured_public,
            dev_tasks,
            dev_public,
            measured_kind,
        )
        analysis_ready = (
            population_contract_valid
            and contract_valid
            and positive_control_valid
            and boundary_controls_valid
            and chance == 1 / EXPECTED_CANDIDATES
            and reference == 1.0
            and reference_coverage == 1.0
        )
        r.metrics["statistical_inference_contract_valid"] = analysis_ready
        if not analysis_ready:
            r.fail(
                "statistical inference and dev-trained model evaluation were not run "
                "because their population or validity preflight failed"
            )
            r.denominator = (
                f"reference {reference:.0%}; shortcut inference not run; "
                f"candidate chance {chance:.1%}"
            )
            return r

        classes = sorted(
            {(task.family, question.rule) for task in holdout_tasks for question in task.questions}
        )
        comparisons = (len(ADVERSARIES) + 2) * (len(classes) + 1)
        adjusted_alpha = bonferroni_alpha(FAMILYWISE_ALPHA, comparisons)
        r.metrics["randomization_comparisons"] = comparisons
        r.metrics["randomization_familywise_alpha"] = float(FAMILYWISE_ALPHA)
        r.metrics["randomization_adjusted_alpha"] = round(float(adjusted_alpha), 8)
        measured_counts = _scene_class_counts(holdout_tasks)
        for family, rule in classes:
            power = permutation_power_contract(
                measured_counts[(family, rule)], comparisons=comparisons
            )
            stem = f"power_{family}_{rule.replace('-', '_')}"
            r.metrics[f"{stem}_critical_hits"] = power.critical_hits
            r.metrics[f"{stem}_signal_probability"] = float(power.signal_probability)
            r.metrics[f"{stem}_target"] = float(power.target_power)
            r.metrics[f"{stem}_achieved"] = round(float(power.power), 8)
            if not power.satisfied:
                r.fail(
                    f"{family}/{rule} does not satisfy the predeclared permutation-power "
                    f"contract: {power.scene_count} scenes, power={float(power.power):.2%}, "
                    f"target={float(power.target_power):.0%}"
                )

        measured_attack_answers = _registered_attack_answers(r, measured_public, "measured")
        if measured_attack_answers is None:
            r.denominator = "registered measured attack failed; shortcut inference not run"
            return r
        dev_attack_answers = _registered_attack_answers(r, dev_public, "development")
        if dev_attack_answers is None:
            r.denominator = "registered development attack failed; shortcut inference not run"
            return r
        r.metrics["registered_attack_execution_valid"] = True
        r.metrics["statistical_inference_performed"] = True

        for name in ADVERSARIES:
            answer_map = measured_attack_answers[name]
            score, coverage, detail = _score_answers(holdout_tasks, measured_public, answer_map)
            r.metrics[f"{name}_solver_score"] = round(score, 4)
            r.metrics[f"{name}_solver_coverage"] = round(coverage, 4)
            if name in COMPLETE_ADVERSARIES and coverage != 1.0:
                r.fail(
                    f"the complete '{name}' adversary attempted only {coverage:.1%} of "
                    "questions; omissions cannot be counted as resistance"
                )
            if contract_valid:
                aggregate_tail = _randomization_tail(holdout_tasks, measured_public, answer_map)
                r.metrics[f"{name}_randomization_p"] = round(float(aggregate_tail), 8)
                if aggregate_tail <= adjusted_alpha:
                    r.fail(
                        f"the '{name}' adversary scores {score:.1%} with exact conditional "
                        f"randomization p={float(aggregate_tail):.3g} (Bonferroni "
                        f"alpha={float(adjusted_alpha):.3g})"
                    )
            for (family, rule), result in detail.items():
                metric = f"{name}_{family}_{rule.replace('-', '_')}_score"
                r.metrics[metric] = round(result["score"], 4)
                if contract_valid:
                    class_tail = _randomization_tail(
                        holdout_tasks,
                        measured_public,
                        answer_map,
                        selected_class=(family, rule),
                    )
                    r.metrics[f"{metric}_randomization_p"] = round(float(class_tail), 8)
                    if class_tail <= adjusted_alpha:
                        r.fail(
                            f"the '{name}' adversary scores {result['score']:.1%} on "
                            f"{family}/{rule} with exact conditional randomization "
                            f"p={float(class_tail):.3g}; aggregate scores may not hide a "
                            "broken class"
                        )

        rank_union = 0.0
        try:
            rank_models = _fit_rank_union(dev_tasks, dev_attack_answers)
            r.metrics["trained_rank_union_fit_valid"] = True
            rank_answers = _predict_rank_union(
                rank_models,
                measured_public,
                measured_attack_answers,
            )
            r.metrics["trained_rank_union_prediction_valid"] = True
            rank_union, rank_coverage, _rank_detail = _score_answers(
                holdout_tasks,
                measured_public,
                rank_answers,
            )
            r.metrics["trained_rank_union_evaluation_performed"] = True
            r.metrics["trained_rank_union_score"] = round(rank_union, 4)
            r.metrics["trained_rank_union_output_coverage"] = round(rank_coverage, 4)
            if rank_coverage != 1.0:
                raise ValueError(
                    "the dev-trained rank union did not emit every measured question: "
                    f"coverage={rank_coverage:.1%}"
                )
            rank_tail = _randomization_tail(
                holdout_tasks,
                measured_public,
                rank_answers,
            )
            r.metrics["trained_rank_union_randomization_p"] = round(float(rank_tail), 8)
            if rank_tail <= adjusted_alpha:
                r.fail(
                    f"the dev-trained rank/union adversary scores {rank_union:.1%} with exact "
                    f"conditional randomization p={float(rank_tail):.3g}"
                )
            rank_models_by_class = rank_models.by_class()
            for family, rule in classes:
                metric = f"trained_rank_union_{family}_{rule.replace('-', '_')}"
                model = rank_models_by_class[(family, rule)]
                r.metrics[f"{metric}_dev_score"] = round(float(model.dev_accuracy), 4)
                r.metrics[f"{metric}_slot_attacks"] = list(model.slot_attacks)
                class_tail = _randomization_tail(
                    holdout_tasks,
                    measured_public,
                    rank_answers,
                    selected_class=(family, rule),
                )
                r.metrics[f"{metric}_randomization_p"] = round(float(class_tail), 8)
                if class_tail <= adjusted_alpha:
                    r.fail(
                        "the dev-trained rank/union adversary is significant on "
                        f"{family}/{rule} with exact conditional randomization "
                        f"p={float(class_tail):.3g}"
                    )
            r.metrics["trained_rank_union_inference_valid"] = True
        except Exception as exc:  # noqa: BLE001 - ensemble failures must redden Gate 4
            r.fail(f"dev-trained rank-union evaluation failed closed: {type(exc).__name__}: {exc}")

        partial_union = 0.0
        try:
            partial_model = _fit_partial_union(dev_tasks, dev_attack_answers)
            r.metrics["trained_partial_union_fit_valid"] = True
            partial_prediction = _predict_partial_union(
                partial_model,
                measured_public,
                measured_attack_answers,
            )
            r.metrics["trained_partial_union_prediction_valid"] = True
            partial_union, partial_coverage, partial_detail = _score_answers(
                holdout_tasks,
                measured_public,
                partial_prediction.answers,
            )
            r.metrics["trained_partial_union_evaluation_performed"] = True
            r.metrics["trained_partial_union_score"] = round(partial_union, 4)
            r.metrics["trained_partial_union_output_coverage"] = round(partial_coverage, 4)
            r.metrics["trained_partial_union_source_coverage"] = round(
                partial_prediction.source_coverage,
                4,
            )
            r.metrics["trained_partial_union_source_covered"] = partial_prediction.source_covered
            r.metrics["trained_partial_union_fallback_count"] = partial_prediction.fallback_count
            r.metrics["trained_partial_union_source_total"] = partial_prediction.total
            if partial_coverage != 1.0:
                raise ValueError(
                    "the dev-trained partial union did not emit every measured question: "
                    f"coverage={partial_coverage:.1%}"
                )
            partial_tail = _randomization_tail(
                holdout_tasks,
                measured_public,
                partial_prediction.answers,
            )
            r.metrics["trained_partial_union_randomization_p"] = round(
                float(partial_tail),
                8,
            )
            if partial_tail <= adjusted_alpha:
                r.fail(
                    f"the dev-trained partial-output union scores {partial_union:.1%} with "
                    f"exact conditional randomization p={float(partial_tail):.3g}"
                )
            source_by_class = {
                (metric.family, metric.rule): metric for metric in partial_prediction.by_class
            }
            selections_by_class = defaultdict(list)
            for selection in partial_model.selections:
                selections_by_class[(selection.family, selection.rule)].append(selection)
            for family, rule in classes:
                metric = f"trained_partial_union_{family}_{rule.replace('-', '_')}"
                result = partial_detail[(family, rule)]
                source = source_by_class[(family, rule)]
                selections = sorted(
                    selections_by_class[(family, rule)],
                    key=lambda selection: selection.slot,
                )
                r.metrics[f"{metric}_score"] = round(result["score"], 4)
                r.metrics[f"{metric}_source_coverage"] = round(
                    source.source_coverage,
                    4,
                )
                r.metrics[f"{metric}_fallback_count"] = source.fallback_count
                r.metrics[f"{metric}_source_total"] = source.total
                r.metrics[f"{metric}_slot_attacks"] = [selection.attack for selection in selections]
                r.metrics[f"{metric}_source_slots"] = [
                    selection.source_slot for selection in selections
                ]
                r.metrics[f"{metric}_dev_hits"] = [selection.dev_hits for selection in selections]
                r.metrics[f"{metric}_dev_source_coverage"] = [
                    selection.dev_source_coverage for selection in selections
                ]
                class_tail = _randomization_tail(
                    holdout_tasks,
                    measured_public,
                    partial_prediction.answers,
                    selected_class=(family, rule),
                )
                r.metrics[f"{metric}_randomization_p"] = round(float(class_tail), 8)
                if class_tail <= adjusted_alpha:
                    r.fail(
                        "the dev-trained partial-output union is significant on "
                        f"{family}/{rule} with exact conditional randomization "
                        f"p={float(class_tail):.3g}"
                    )
            r.metrics["trained_partial_union_inference_valid"] = True
        except Exception as exc:  # noqa: BLE001 - ensemble failures must redden Gate 4
            r.fail(
                f"dev-trained partial-union evaluation failed closed: {type(exc).__name__}: {exc}"
            )

    attack_scores = [r.metrics.get(f"{name}_solver_score", 0.0) for name in ADVERSARIES]
    worst = max([*attack_scores, rank_union, partial_union], default=0.0)
    r.metrics["adversarial_floor"] = round(worst, 4)
    r.metrics["worst_shortcut_score"] = round(worst, 4)
    r.denominator = (
        f"reference {reference:.0%}; registered shortcuts tested at familywise alpha "
        f"{float(FAMILYWISE_ALPHA):.1%}; every complete attack and composition ensemble "
        f"independently calibrated; worst observed {worst:.1%}; exact candidate chance "
        f"{chance:.1%}; green means no registered shortcut detected, not universal shortcut "
        "resistance or equivalence to chance"
    )
    return r
