# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic feature-conditioned shortcut audit over public development keys.

This is deliberately separate from the frozen Benchmark-v2 attack registry.  It probes a
larger hypothesis class than the fixed-rank and partial-union attacks: for each family/rule it
chooses one bounded public question feature, then learns a candidate lexical rank for every
observed feature value.  Prediction ignores the declared FileId/SHA-1 or quarantine-UUID join.

Training labels are reconstructed from four explicitly published development keys.  The
reconstruction never reads ``_answers`` or accepts a generic key, while fitting and prediction
accept :class:`~artifactforge.bench.benchmark.PublicTask` objects only.  Leave-one-key-out
evaluation rotates all four keys, fitting on three and scoring the fourth.  The resulting
diagnostic is public-corpus evidence, never a benchmark performance result.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from artifactforge import suite
from artifactforge.bench.benchmark import PublicTask, normalize
from artifactforge.inventory import InventoryError, captured_regular_tree


PUBLIC_DEVELOPMENT_KEY_COUNT = 4
PUBLIC_DEVELOPMENT_SCENARIOS_PER_KEY = 8
MAX_PUBLIC_TASKS_PER_CORPUS = PUBLIC_DEVELOPMENT_SCENARIOS_PER_KEY
EXPECTED_QUESTIONS_PER_SCENE = 5
EXPECTED_CANDIDATES = 5
MAX_FEATURE_VALUES = 8
MAX_MODEL_BRANCHES = 16

PUBLIC_DEVELOPMENT_KEY_SEED = b"artifactforge-feature-conditioned-public-development-v1"
PUBLIC_DEVELOPMENT_KEY_DOMAIN = (
    b"artifactforge/bench/feature-conditioned/public-development-key/v1\x00"
)
PUBLIC_DEVELOPMENT_KEY_COMMITMENT_DOMAIN = (
    b"artifactforge/bench/feature-conditioned/public-key-commitment/v1\x00"
)
FEATURE_EXTRACTION_DOMAIN = b"artifactforge/bench/feature-conditioned/features/v1\x00"
PUBLIC_DEVELOPMENT_PROVENANCE = "public-key-reconstruction-v1"
POSITIVE_CONTROL_PROVENANCE = "independent-vulnerable-world-v1"


def _derive_public_development_key(index: int) -> bytes:
    if type(index) is not int or not 0 <= index < PUBLIC_DEVELOPMENT_KEY_COUNT:
        raise ValueError("public development key index must be in [0, 4)")
    return hmac.new(
        PUBLIC_DEVELOPMENT_KEY_SEED,
        PUBLIC_DEVELOPMENT_KEY_DOMAIN + index.to_bytes(1, "big"),
        hashlib.sha256,
    ).digest()


PUBLIC_DEVELOPMENT_KEYS = tuple(
    _derive_public_development_key(index) for index in range(PUBLIC_DEVELOPMENT_KEY_COUNT)
)


def public_development_key(index: int) -> bytes:
    """Return one deliberately public, attack-calibration-only key."""
    return _derive_public_development_key(index)


def _key_commitment(key: bytes) -> str:
    return hashlib.sha256(PUBLIC_DEVELOPMENT_KEY_COMMITMENT_DOMAIN + key).hexdigest()


def public_development_key_commitment(index: int) -> str:
    """Return the public identity retained by models instead of raw key bytes."""
    return _key_commitment(public_development_key(index))


def _selector_text(question) -> str:
    return json.dumps(
        question.selector,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _task_class(task: PublicTask) -> tuple[str, str]:
    rules = {getattr(question, "rule", None) for question in task.questions}
    if task.family not in {"windows", "macos"} or len(rules) != 1:
        raise ValueError("feature-conditioned scenes require one supported family/rule class")
    rule = next(iter(rules))
    if not isinstance(rule, str) or not rule:
        raise ValueError("feature-conditioned scene rule must be non-empty text")
    return task.family, rule


def _validate_public_tasks(
    tasks: Sequence[PublicTask],
    *,
    where: str,
) -> tuple[PublicTask, ...]:
    values = tuple(tasks)
    if not 1 <= len(values) <= MAX_PUBLIC_TASKS_PER_CORPUS:
        raise ValueError(f"{where} must contain 1-{MAX_PUBLIC_TASKS_PER_CORPUS} public tasks")
    if any(not isinstance(task, PublicTask) for task in values):
        raise TypeError(f"{where} accepts PublicTask objects only")
    scenario_ids = [task.scenario_id for task in values]
    if any(not isinstance(value, str) or not value for value in scenario_ids):
        raise ValueError(f"{where} scenario ids must be non-empty text")
    if len(set(scenario_ids)) != len(scenario_ids):
        raise ValueError(f"{where} contains duplicate scenario ids")
    for task in values:
        if (
            not isinstance(task.questions, list)
            or len(task.questions) != EXPECTED_QUESTIONS_PER_SCENE
        ):
            raise ValueError(f"{where} scenes require exactly five questions")
        question_ids = [question.id for question in task.questions]
        if len(set(question_ids)) != EXPECTED_QUESTIONS_PER_SCENE:
            raise ValueError(f"{where} scene {task.scenario_id!r} duplicates question ids")
        if any(question.candidate_count != EXPECTED_CANDIDATES for question in task.questions):
            raise ValueError(f"{where} scenes require exactly five answer candidates")
        _task_class(task)
    return values


@dataclass(frozen=True, slots=True)
class PublicScenarioLabels:
    """Publicly reconstructable labels for one development scene."""

    scenario_id: str
    answers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "answers", tuple(self.answers))
        if not isinstance(self.scenario_id, str) or not self.scenario_id:
            raise ValueError("public scenario label id must be non-empty text")
        if any(
            not isinstance(question_id, str)
            or not question_id
            or not isinstance(answer, str)
            or not answer.strip()
            for question_id, answer in self.answers
        ):
            raise ValueError("public scenario labels must contain non-empty text pairs")
        if len({question_id for question_id, _answer in self.answers}) != len(self.answers):
            raise ValueError("public scenario labels duplicate a question id")

    def mapping(self) -> dict[str, str]:
        return dict(self.answers)


@dataclass(frozen=True, slots=True)
class PublicDevelopmentCorpus:
    """Public tasks plus labels whose non-private provenance is explicit."""

    key_index: int
    key_commitment: str
    provenance: str
    tasks: tuple[PublicTask, ...]
    labels: tuple[PublicScenarioLabels, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "tasks", tuple(self.tasks))
        object.__setattr__(self, "labels", tuple(self.labels))
        _derive_public_development_key(self.key_index)
        if self.key_commitment != public_development_key_commitment(self.key_index):
            raise ValueError("public development corpus key commitment is invalid")
        if self.provenance not in {
            PUBLIC_DEVELOPMENT_PROVENANCE,
            POSITIVE_CONTROL_PROVENANCE,
        }:
            raise ValueError("public development corpus label provenance is invalid")
        tasks = _validate_public_tasks(self.tasks, where="public development corpus")
        if any(not isinstance(label, PublicScenarioLabels) for label in self.labels):
            raise TypeError("public development corpus labels have the wrong type")
        by_scenario = {label.scenario_id: label.mapping() for label in self.labels}
        if len(by_scenario) != len(self.labels) or set(by_scenario) != {
            task.scenario_id for task in tasks
        }:
            raise ValueError("public development labels must cover each scenario exactly once")
        for task in tasks:
            if set(by_scenario[task.scenario_id]) != {question.id for question in task.questions}:
                raise ValueError("public development labels must cover each question exactly")

    def labels_by_scenario(self) -> dict[str, dict[str, str]]:
        return {label.scenario_id: label.mapping() for label in self.labels}


def labeled_public_corpus(
    key_index: int,
    tasks: Sequence[PublicTask],
    labels: Mapping[str, Mapping[str, str]],
    *,
    provenance: str,
) -> PublicDevelopmentCorpus:
    """Validate public-only training material and freeze its answer maps.

    The generic constructor exists for independently built positive controls.  Production
    public-key audit corpora should use :func:`build_public_development_corpus`, which supplies
    labels only through the fixed public-key reconstruction path.
    """
    if provenance not in {PUBLIC_DEVELOPMENT_PROVENANCE, POSITIVE_CONTROL_PROVENANCE}:
        raise ValueError("unsupported feature-conditioned label provenance")
    public_tasks = _validate_public_tasks(tasks, where="feature-conditioned corpus")
    if not isinstance(labels, Mapping):
        raise TypeError("feature-conditioned labels must be a mapping")
    expected_scenarios = {task.scenario_id for task in public_tasks}
    if set(labels) != expected_scenarios:
        raise ValueError("feature-conditioned labels must cover exactly the public scenarios")
    frozen = []
    for task in public_tasks:
        answers = labels[task.scenario_id]
        if not isinstance(answers, Mapping):
            raise TypeError("feature-conditioned scenario labels must be mappings")
        question_ids = {question.id for question in task.questions}
        if set(answers) != question_ids:
            raise ValueError(
                f"feature-conditioned labels for {task.scenario_id!r} must cover five questions"
            )
        if any(not isinstance(value, str) or not value.strip() for value in answers.values()):
            raise ValueError("feature-conditioned labels must be non-empty text")
        frozen.append(
            PublicScenarioLabels(
                task.scenario_id,
                tuple((question.id, answers[question.id]) for question in task.questions),
            )
        )
    return PublicDevelopmentCorpus(
        key_index=key_index,
        key_commitment=public_development_key_commitment(key_index),
        provenance=provenance,
        tasks=public_tasks,
        labels=tuple(frozen),
    )


def _question_public_shape(question) -> tuple:
    return (
        question.id,
        question.prompt,
        question.kind,
        question.rule,
        question.selector,
        question.candidate_count,
    )


def _reconstruct_public_labels(
    key_index: int,
    public_tasks: tuple[PublicTask, ...],
) -> dict[str, dict[str, str]]:
    """Regenerate labels from one fixed public key, never from evaluator answer files."""
    from artifactforge.bench.benchmark import _macos_questions, _profile, _windows_questions
    from artifactforge.compose.scene import build_macos_scene, build_windows_scene
    from artifactforge.content import ContentStore

    key = public_development_key(key_index)
    expected_ids = [suite.public_id(key, index) for index in range(len(public_tasks))]
    if [task.scenario_id for task in public_tasks] != expected_ids:
        raise ValueError(
            "public development tasks are not the ordered corpus derived from the declared key"
        )

    labels = {}
    with tempfile.TemporaryDirectory(prefix="artifactforge-feature-public-labels-") as directory:
        root = Path(directory)
        (root / "scenes").mkdir()
        (root / "staging").mkdir()
        store = ContentStore(
            suite.WINDOWS_MACOS_CONTENT_NAMESPACE,
            os.fspath(root / "content"),
        )
        for index, public in enumerate(public_tasks):
            scenario_id = expected_ids[index]
            skey = suite.scenario_key(key, scenario_id)
            arguments = {
                "store": store,
                "skey": skey,
                "profile": _profile(skey, public.family),
                "scene_dir": os.fspath(root / "scenes" / scenario_id),
                "staging_dir": os.fspath(root / "staging" / scenario_id),
            }
            if public.family == "windows":
                scene = build_windows_scene(**arguments)
                questions = _windows_questions(scene.join)
            elif public.family == "macos":
                scene = build_macos_scene(**arguments)
                questions = _macos_questions(scene.join)
            else:  # already rejected by _validate_public_tasks
                raise AssertionError("unsupported public development family")
            if scene.family != public.family or tuple(
                _question_public_shape(question) for question in questions
            ) != tuple(_question_public_shape(question) for question in public.questions):
                raise ValueError(
                    f"public key reconstruction disagrees with scene {scenario_id!r} metadata"
                )
            labels[scenario_id] = {question.id: question.expected for question in questions}
    return labels


def build_public_development_corpus(
    key_index: int,
    public_tasks: Sequence[PublicTask],
) -> PublicDevelopmentCorpus:
    """Build one eight-scene corpus from its published key and solver-visible export."""
    tasks = _validate_public_tasks(public_tasks, where="public development corpus")
    if len(tasks) != PUBLIC_DEVELOPMENT_SCENARIOS_PER_KEY:
        raise ValueError(
            "public development corpus requires exactly "
            f"{PUBLIC_DEVELOPMENT_SCENARIOS_PER_KEY} ordered scenes"
        )
    labels = _reconstruct_public_labels(key_index, tasks)
    return labeled_public_corpus(
        key_index,
        tasks,
        labels,
        provenance=PUBLIC_DEVELOPMENT_PROVENANCE,
    )


def _captured_candidates(public: PublicTask) -> tuple[str, ...]:
    """Enumerate the answer universe without reading the relation used by the closed rule."""
    try:
        with captured_regular_tree(public.directory) as files:
            if public.family == "windows":
                values = [
                    hashlib.sha256(file.data).hexdigest()
                    for file in files
                    if file.data is not None and file.data[:2] == b"MZ"
                ]
            elif public.family == "macos":
                databases = [file for file in files if file.name == "QuarantineEventsV2"]
                if len(databases) != 1:
                    raise ValueError("macOS scene requires one QuarantineEventsV2 database")
                uri = databases[0].path.resolve().as_uri() + "?mode=ro&immutable=1"
                connection = sqlite3.connect(uri, uri=True)
                try:
                    rows = connection.execute(
                        "SELECT LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY rowid"
                    ).fetchall()
                finally:
                    connection.close()
                values = [row[0] for row in rows]
            else:
                raise ValueError(f"unsupported benchmark family: {public.family!r}")
    except (InventoryError, OSError, sqlite3.Error) as exc:
        raise ValueError(f"cannot enumerate public candidates: {exc}") from exc
    if (
        len(values) != EXPECTED_CANDIDATES
        or len(set(values)) != EXPECTED_CANDIDATES
        or any(not isinstance(value, str) or not value for value in values)
    ):
        raise ValueError("feature-conditioned attack requires five distinct public candidates")
    return tuple(sorted(values))


FEATURE_NAMES = (
    "constant",
    "question-id-bucket",
    "question-slot",
    "selector-hash-bucket",
    "selector-length-mod-5",
    "selector-rank",
)


def _bounded_digest_bucket(label: str, value: str) -> str:
    digest = hashlib.sha256(
        FEATURE_EXTRACTION_DOMAIN + label.encode("ascii") + b"\x00" + value.encode("utf-8")
    ).digest()
    return str(digest[0] % MAX_FEATURE_VALUES)


def _question_features(public: PublicTask) -> tuple[dict[str, str], ...]:
    selectors = tuple(_selector_text(question) for question in public.questions)
    if len(set(selectors)) != EXPECTED_QUESTIONS_PER_SCENE:
        raise ValueError("feature-conditioned attack requires five distinct selectors")
    selector_rank = {value: rank for rank, value in enumerate(sorted(selectors))}
    return tuple(
        {
            "constant": "all",
            "question-id-bucket": _bounded_digest_bucket("question-id", question.id),
            "question-slot": str(slot),
            "selector-hash-bucket": _bounded_digest_bucket("selector", selectors[slot]),
            "selector-length-mod-5": str(len(selectors[slot].encode("utf-8")) % 5),
            "selector-rank": str(selector_rank[selectors[slot]]),
        }
        for slot, question in enumerate(public.questions)
    )


@dataclass(frozen=True, slots=True)
class FeatureBranch:
    """One learned feature value to candidate-rank decision."""

    value: str
    candidate_rank: int
    support: int
    hits: int

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("feature branch values must be non-empty text")
        if (
            type(self.candidate_rank) is not int
            or not 0 <= self.candidate_rank < EXPECTED_CANDIDATES
        ):
            raise ValueError("feature branch candidate rank is out of bounds")
        if type(self.support) is not int or self.support < 1:
            raise ValueError("feature branch support must be positive")
        if type(self.hits) is not int or not 0 <= self.hits <= self.support:
            raise ValueError("feature branch hits must be bounded by support")


@dataclass(frozen=True, slots=True)
class ClassFeatureModel:
    """One bounded categorical model for a family/rule class."""

    family: str
    rule: str
    feature: str
    branches: tuple[FeatureBranch, ...]
    fallback_rank: int
    training_hits: int
    training_total: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "branches", tuple(self.branches))
        if self.feature not in FEATURE_NAMES:
            raise ValueError("class feature model uses an unregistered feature")
        if not 1 <= len(self.branches) <= MAX_FEATURE_VALUES:
            raise ValueError("class feature model exceeds its branch bound")
        if len({branch.value for branch in self.branches}) != len(self.branches):
            raise ValueError("class feature model duplicates a feature branch")
        if type(self.fallback_rank) is not int or not 0 <= self.fallback_rank < EXPECTED_CANDIDATES:
            raise ValueError("class feature model fallback rank is out of bounds")
        if type(self.training_total) is not int or self.training_total < 1:
            raise ValueError("class feature model training total must be positive")
        if (
            type(self.training_hits) is not int
            or not 0 <= self.training_hits <= self.training_total
        ):
            raise ValueError("class feature model hits must be bounded by training total")

    def branch_map(self) -> dict[str, int]:
        return {branch.value: branch.candidate_rank for branch in self.branches}


@dataclass(frozen=True, slots=True)
class FeatureConditionedModel:
    """Answer-free fitted state with public key identities and bounded rank decisions."""

    training_key_indices: tuple[int, ...]
    training_key_commitments: tuple[str, ...]
    classes: tuple[ClassFeatureModel, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "training_key_indices", tuple(self.training_key_indices))
        object.__setattr__(self, "training_key_commitments", tuple(self.training_key_commitments))
        object.__setattr__(self, "classes", tuple(self.classes))
        if (
            len(self.training_key_indices) != PUBLIC_DEVELOPMENT_KEY_COUNT - 1
            or len(set(self.training_key_indices)) != len(self.training_key_indices)
            or any(
                type(index) is not int or not 0 <= index < PUBLIC_DEVELOPMENT_KEY_COUNT
                for index in self.training_key_indices
            )
        ):
            raise ValueError("feature-conditioned model requires three distinct public keys")
        expected_commitments = tuple(
            public_development_key_commitment(index) for index in self.training_key_indices
        )
        if self.training_key_commitments != expected_commitments:
            raise ValueError("feature-conditioned model public key commitments are invalid")
        if len(self.classes) != 2 or len(
            {(model.family, model.rule) for model in self.classes}
        ) != len(self.classes):
            raise ValueError("feature-conditioned model requires two distinct classes")
        if self.branch_count > MAX_MODEL_BRANCHES:
            raise ValueError("feature-conditioned model exceeds its total branch bound")

    @property
    def branch_count(self) -> int:
        return sum(len(model.branches) for model in self.classes)

    def by_class(self) -> dict[tuple[str, str], ClassFeatureModel]:
        return {(model.family, model.rule): model for model in self.classes}


def _candidate_rank(answer: str, candidates: tuple[str, ...], kind: str) -> int:
    normalized = tuple(normalize(value, kind) for value in candidates)
    wanted = normalize(answer, kind)
    matches = [index for index, value in enumerate(normalized) if value == wanted]
    if len(matches) != 1:
        raise ValueError("public development label is not in its five-candidate universe")
    return matches[0]


def _fit_class_model(
    family: str,
    rule: str,
    rows: Sequence[tuple[dict[str, str], int]],
) -> ClassFeatureModel:
    if not rows:
        raise ValueError(f"feature-conditioned training class {(family, rule)!r} is empty")
    global_counts = Counter(rank for _features, rank in rows)
    fallback_rank = min(
        range(EXPECTED_CANDIDATES),
        key=lambda rank: (-global_counts[rank], rank),
    )
    fitted = []
    for feature in FEATURE_NAMES:
        counts_by_value: dict[str, Counter] = defaultdict(Counter)
        for features, rank in rows:
            counts_by_value[features[feature]][rank] += 1
        if len(counts_by_value) > MAX_FEATURE_VALUES:
            raise ValueError(f"feature {feature!r} exceeded its branch bound")
        branches = []
        hits = 0
        for value, counts in sorted(counts_by_value.items()):
            selected_rank = min(
                range(EXPECTED_CANDIDATES),
                key=lambda rank: (-counts[rank], rank),
            )
            selected_hits = counts[selected_rank]
            hits += selected_hits
            branches.append(
                FeatureBranch(value, selected_rank, sum(counts.values()), selected_hits)
            )
        fitted.append(((-hits, len(branches), feature), feature, tuple(branches), hits))
    _rank, feature, branches, hits = min(fitted, key=lambda item: item[0])
    return ClassFeatureModel(
        family=family,
        rule=rule,
        feature=feature,
        branches=branches,
        fallback_rank=fallback_rank,
        training_hits=hits,
        training_total=len(rows),
    )


def fit_feature_conditioned(
    training_corpora: Sequence[PublicDevelopmentCorpus],
) -> FeatureConditionedModel:
    """Fit on exactly three public-key corpora for one leave-one-key-out fold."""
    corpora = tuple(training_corpora)
    if len(corpora) != PUBLIC_DEVELOPMENT_KEY_COUNT - 1:
        raise ValueError("feature-conditioned fitting requires exactly three public key corpora")
    if any(not isinstance(corpus, PublicDevelopmentCorpus) for corpus in corpora):
        raise TypeError("feature-conditioned fitting requires PublicDevelopmentCorpus values")
    key_indices = tuple(sorted(corpus.key_index for corpus in corpora))
    if len(set(key_indices)) != len(key_indices):
        raise ValueError("feature-conditioned training keys must be distinct")
    if any(
        corpus.key_commitment != public_development_key_commitment(corpus.key_index)
        for corpus in corpora
    ):
        raise ValueError("feature-conditioned corpus key commitment is invalid")
    if any(
        corpus.provenance not in {PUBLIC_DEVELOPMENT_PROVENANCE, POSITIVE_CONTROL_PROVENANCE}
        for corpus in corpora
    ):
        raise ValueError("feature-conditioned corpus label provenance is invalid")

    rows_by_class: dict[tuple[str, str], list[tuple[dict[str, str], int]]] = defaultdict(list)
    classes_by_corpus = []
    for corpus in corpora:
        tasks = _validate_public_tasks(corpus.tasks, where="feature-conditioned training")
        labels = corpus.labels_by_scenario()
        classes_by_corpus.append({_task_class(task) for task in tasks})
        for task in tasks:
            candidates = _captured_candidates(task)
            features = _question_features(task)
            expected = labels.get(task.scenario_id, {})
            if set(expected) != {question.id for question in task.questions}:
                raise ValueError("feature-conditioned training labels are incomplete")
            key = _task_class(task)
            for question, question_features in zip(task.questions, features, strict=True):
                rows_by_class[key].append(
                    (
                        question_features,
                        _candidate_rank(expected[question.id], candidates, question.kind),
                    )
                )
    if not classes_by_corpus or any(
        classes != classes_by_corpus[0] for classes in classes_by_corpus
    ):
        raise ValueError("feature-conditioned training corpora disagree on family/rule classes")

    class_models = tuple(
        _fit_class_model(family, rule, rows_by_class[(family, rule)])
        for family, rule in sorted(rows_by_class)
    )
    model = FeatureConditionedModel(
        training_key_indices=key_indices,
        training_key_commitments=tuple(
            public_development_key_commitment(index) for index in key_indices
        ),
        classes=class_models,
    )
    if len(model.classes) != 2 or model.branch_count > MAX_MODEL_BRANCHES:
        raise ValueError("feature-conditioned fitted model exceeds its declared size bound")
    return model


@dataclass(frozen=True, slots=True)
class ClassPredictionMetrics:
    """Public prediction coverage for one family/rule class."""

    family: str
    rule: str
    covered: int
    unseen_feature_values: int
    total: int


@dataclass(frozen=True, slots=True)
class FeatureConditionedPrediction:
    """Complete public predictions plus explicit fallback accounting."""

    answers: dict[str, dict[str, str]]
    covered: int
    unseen_feature_values: int
    total: int
    by_class: tuple[ClassPredictionMetrics, ...]


def predict_feature_conditioned(
    model: FeatureConditionedModel,
    public_tasks: Sequence[PublicTask],
) -> FeatureConditionedPrediction:
    """Predict from public task metadata and candidate artifacts only."""
    if not isinstance(model, FeatureConditionedModel):
        raise TypeError("feature-conditioned prediction requires FeatureConditionedModel")
    tasks = _validate_public_tasks(public_tasks, where="feature-conditioned prediction")
    models = model.by_class()
    if len(models) != len(model.classes):
        raise ValueError("feature-conditioned model duplicates a family/rule class")
    answers = {}
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for task in tasks:
        key = _task_class(task)
        try:
            class_model = models[key]
        except KeyError as exc:
            raise ValueError(f"feature-conditioned model has no class {key!r}") from exc
        candidates = _captured_candidates(task)
        features = _question_features(task)
        branches = class_model.branch_map()
        selected = {}
        for question, question_features in zip(task.questions, features, strict=True):
            value = question_features[class_model.feature]
            unseen = value not in branches
            rank = branches.get(value, class_model.fallback_rank)
            selected[question.id] = candidates[rank]
            counts[key][0] += 1
            counts[key][1] += int(unseen)
            counts[key][2] += 1
        answers[task.scenario_id] = selected
    by_class = tuple(
        ClassPredictionMetrics(family, rule, covered, unseen, total)
        for (family, rule), (covered, unseen, total) in sorted(counts.items())
    )
    return FeatureConditionedPrediction(
        answers=answers,
        covered=sum(metric.covered for metric in by_class),
        unseen_feature_values=sum(metric.unseen_feature_values for metric in by_class),
        total=sum(metric.total for metric in by_class),
        by_class=by_class,
    )


@dataclass(frozen=True, slots=True)
class ExactEvaluationMetrics:
    """Integer scoring and failure accounting; ratios are exact Fractions."""

    family: str
    rule: str
    correct: int
    covered: int
    missing: int
    invalid: int
    unexpected: int
    total: int

    @property
    def accuracy(self) -> Fraction:
        return Fraction(self.correct, self.total) if self.total else Fraction(0)

    @property
    def coverage(self) -> Fraction:
        return Fraction(self.covered, self.total) if self.total else Fraction(0)

    @property
    def failures(self) -> int:
        return self.missing + self.invalid + self.unexpected


@dataclass(frozen=True, slots=True)
class LeaveOneKeyOutFold:
    """One three-key fit evaluated on the excluded public key."""

    held_out_key_index: int
    training_key_indices: tuple[int, ...]
    model: FeatureConditionedModel
    by_class: tuple[ExactEvaluationMetrics, ...]
    aggregate: ExactEvaluationMetrics


@dataclass(frozen=True, slots=True)
class LeaveOneKeyOutReport:
    """Four deterministic folds plus exact class and aggregate counts."""

    folds: tuple[LeaveOneKeyOutFold, ...]
    by_class: tuple[ExactEvaluationMetrics, ...]
    aggregate: ExactEvaluationMetrics


def _score_prediction(
    corpus: PublicDevelopmentCorpus,
    prediction: FeatureConditionedPrediction,
) -> tuple[tuple[ExactEvaluationMetrics, ...], ExactEvaluationMetrics]:
    labels = corpus.labels_by_scenario()
    tasks = {task.scenario_id: task for task in corpus.tasks}
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0, 0])
    unexpected_scenarios = set(prediction.answers) - set(tasks)
    for scenario_id, task in tasks.items():
        key = _task_class(task)
        supplied = prediction.answers.get(scenario_id)
        if not isinstance(supplied, Mapping):
            supplied = {}
        expected = labels[scenario_id]
        question_ids = {question.id for question in task.questions}
        unexpected = len(set(supplied) - question_ids)
        counts[key][4] += unexpected
        for question in task.questions:
            counts[key][5] += 1
            if question.id not in supplied:
                counts[key][2] += 1
                continue
            value = supplied[question.id]
            if not isinstance(value, str) or not value.strip():
                counts[key][3] += 1
                continue
            counts[key][1] += 1
            counts[key][0] += int(
                normalize(value, question.kind) == normalize(expected[question.id], question.kind)
            )
    if unexpected_scenarios:
        raise ValueError("feature-conditioned prediction returned unknown scenarios")
    by_class = tuple(
        ExactEvaluationMetrics(family, rule, *values)
        for (family, rule), values in sorted(counts.items())
    )
    aggregate = _combine_metrics(by_class)
    return by_class, aggregate


def _combine_metrics(metrics: Sequence[ExactEvaluationMetrics]) -> ExactEvaluationMetrics:
    values = tuple(metrics)
    return ExactEvaluationMetrics(
        family="aggregate",
        rule="all",
        correct=sum(metric.correct for metric in values),
        covered=sum(metric.covered for metric in values),
        missing=sum(metric.missing for metric in values),
        invalid=sum(metric.invalid for metric in values),
        unexpected=sum(metric.unexpected for metric in values),
        total=sum(metric.total for metric in values),
    )


def leave_one_key_out(
    corpora: Sequence[PublicDevelopmentCorpus],
) -> LeaveOneKeyOutReport:
    """Train on three public keys and score the excluded fourth, rotating all keys."""
    values = tuple(corpora)
    if len(values) != PUBLIC_DEVELOPMENT_KEY_COUNT:
        raise ValueError("leave-one-key-out requires exactly four public development corpora")
    if any(not isinstance(corpus, PublicDevelopmentCorpus) for corpus in values):
        raise TypeError("leave-one-key-out requires PublicDevelopmentCorpus values")
    by_index = {corpus.key_index: corpus for corpus in values}
    if set(by_index) != set(range(PUBLIC_DEVELOPMENT_KEY_COUNT)):
        raise ValueError("leave-one-key-out requires each public key index exactly once")

    folds = []
    for held_out_index in range(PUBLIC_DEVELOPMENT_KEY_COUNT):
        training = tuple(
            by_index[index]
            for index in range(PUBLIC_DEVELOPMENT_KEY_COUNT)
            if index != held_out_index
        )
        model = fit_feature_conditioned(training)
        if held_out_index in model.training_key_indices:
            raise AssertionError("held-out public key entered feature-conditioned training")
        prediction = predict_feature_conditioned(model, by_index[held_out_index].tasks)
        by_class, aggregate = _score_prediction(by_index[held_out_index], prediction)
        folds.append(
            LeaveOneKeyOutFold(
                held_out_key_index=held_out_index,
                training_key_indices=model.training_key_indices,
                model=model,
                by_class=by_class,
                aggregate=aggregate,
            )
        )
    combined_by_class: dict[tuple[str, str], list[ExactEvaluationMetrics]] = defaultdict(list)
    for fold in folds:
        for metric in fold.by_class:
            combined_by_class[(metric.family, metric.rule)].append(metric)
    by_class = tuple(
        ExactEvaluationMetrics(
            family=family,
            rule=rule,
            correct=sum(metric.correct for metric in metrics),
            covered=sum(metric.covered for metric in metrics),
            missing=sum(metric.missing for metric in metrics),
            invalid=sum(metric.invalid for metric in metrics),
            unexpected=sum(metric.unexpected for metric in metrics),
            total=sum(metric.total for metric in metrics),
        )
        for (family, rule), metrics in sorted(combined_by_class.items())
    )
    return LeaveOneKeyOutReport(tuple(folds), by_class, _combine_metrics(by_class))


__all__ = [
    "EXPECTED_CANDIDATES",
    "EXPECTED_QUESTIONS_PER_SCENE",
    "ExactEvaluationMetrics",
    "FEATURE_EXTRACTION_DOMAIN",
    "FEATURE_NAMES",
    "FeatureBranch",
    "FeatureConditionedModel",
    "FeatureConditionedPrediction",
    "LeaveOneKeyOutFold",
    "LeaveOneKeyOutReport",
    "MAX_FEATURE_VALUES",
    "MAX_MODEL_BRANCHES",
    "MAX_PUBLIC_TASKS_PER_CORPUS",
    "POSITIVE_CONTROL_PROVENANCE",
    "PUBLIC_DEVELOPMENT_KEYS",
    "PUBLIC_DEVELOPMENT_KEY_COMMITMENT_DOMAIN",
    "PUBLIC_DEVELOPMENT_KEY_COUNT",
    "PUBLIC_DEVELOPMENT_KEY_DOMAIN",
    "PUBLIC_DEVELOPMENT_KEY_SEED",
    "PUBLIC_DEVELOPMENT_PROVENANCE",
    "PUBLIC_DEVELOPMENT_SCENARIOS_PER_KEY",
    "PublicDevelopmentCorpus",
    "PublicScenarioLabels",
    "build_public_development_corpus",
    "fit_feature_conditioned",
    "labeled_public_corpus",
    "leave_one_key_out",
    "predict_feature_conditioned",
    "public_development_key",
    "public_development_key_commitment",
]
