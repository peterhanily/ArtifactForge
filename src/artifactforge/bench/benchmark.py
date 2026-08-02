# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Benchmark v2: one scalar question per independently resolved value agreement.

Two properties have to be true at once, and the previous design had only the first.

**Recoverable.** A reference solver reading the artifacts with real DFIR parsers answers
every question. Without this the benchmark is unanswerable.

**Tested against a finite attack registry.** Gate 4 asks whether any registered and
independently calibrated shortcut reaches the same answer at the declared familywise alpha.
That is a non-detection result, not proof that no shortcut exists. The previous design failed
even this bounded test: the public scenario identifier was also the generation seed, so a
solver that opened zero files reproduced every answer, and `JOIN_MANIFEST.json` — the whole
key — sat in the directory the solver was pointed at, hidden only from a listing.

Both halves are structural here. Answers derive from a suite key the solver never sees, and
the served directory is staged by allowlist so the key and the content cache are not merely
filtered out of the view but absent from it.

The v1 questions selected one structurally prominent subject and then awarded five or six
answers derived from it. Completing the negative controls made both the footprint and stored-
order attacks score 100%. V2 removes that multiplier. Every question is one scalar resolution
under a closed rule, and every five-question scene is a bijection over five candidates.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from dataclasses import dataclass, field
from pathlib import Path

from artifactforge import suite
from artifactforge.compose.scene import build_macos_scene, build_windows_scene
from artifactforge.content import ContentStore
from artifactforge.inventory import (
    InventoryError,
    directory_entry_matches_descriptor,
    inventory_regular_files,
    open_real_directory,
    open_real_directory_at,
    remove_pinned_directory_at,
    rename_directory_no_replace,
)
from artifactforge.model import HostProfile, macos_profile, windows_profile


@dataclass(frozen=True)
class Question:
    """Server-side. Carries the answer, so it must never cross into solver code."""

    id: str
    prompt: str
    kind: str  # hash | url
    rule: str
    selector: dict
    candidate_count: int
    expected: str


@dataclass(frozen=True)
class PublicQuestion:
    id: str
    prompt: str
    kind: str
    rule: str
    selector: dict
    candidate_count: int


@dataclass(frozen=True)
class PublicTask:
    """Everything a solver is given, and nothing else. A separate type rather than a filtered
    dict, so passing the wrong object into a solver is a type error and not a silent leak."""

    scenario_id: str
    family: str
    directory: str
    questions: list
    suite_kind: str
    artifacts: tuple[str, ...]


@dataclass
class Task:
    scenario_id: str
    family: str
    directory: str
    questions: list = field(default_factory=list)
    join: dict = field(default_factory=dict)
    suite_kind: str = "dev"
    artifacts: tuple[str, ...] = ()

    def public(self) -> PublicTask:
        return PublicTask(
            self.scenario_id,
            self.family,
            self.directory,
            [
                PublicQuestion(
                    q.id,
                    q.prompt,
                    q.kind,
                    q.rule,
                    dict(q.selector),
                    q.candidate_count,
                )
                for q in self.questions
            ],
            self.suite_kind,
            tuple(self.artifacts),
        )

    def answer_key(self) -> dict:
        return {q.id: q.expected for q in self.questions}


def normalize(value, kind: str) -> str:
    s = ("" if value is None else str(value)).strip()
    return s if kind == "url" else s.lower()


@dataclass
class Score:
    scenario_id: str
    correct: int
    total: int
    per_question: dict

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0


def grade(task: Task, answers) -> Score:
    """Score a submission. A non-dict submission scores zero rather than raising: a grader
    that crashes on malformed input cannot be run unattended over a fleet of agents."""
    if not isinstance(answers, dict):
        answers = {}
    per_q, correct = {}, 0
    for q in task.questions:
        ok = normalize(answers.get(q.id), q.kind) == normalize(q.expected, q.kind)
        per_q[q.id] = ok
        correct += int(ok)
    return Score(task.scenario_id, correct, len(task.questions), per_q)


def _questions(join: dict, family: str) -> list:
    relations = join.get("benchmark_relations")
    if not isinstance(relations, list) or len(relations) != 5:
        raise ValueError(f"{family} benchmark scenes require exactly five relations")
    questions = []
    for index, relation in enumerate(relations, start=1):
        if relation.get("rule") == "amcache-fileid-byte-agreement-v1":
            kind = "hash"
        elif relation.get("rule") == "quarantine-uuid-event-agreement-v1":
            kind = "url"
        else:
            raise ValueError(f"{family} scene declared an unsupported benchmark rule")
        prompt = suite.benchmark_question_prompt(relation["rule"], relation["selector"])
        questions.append(
            Question(
                f"{family}_agreement_{index:02d}",
                prompt,
                kind,
                relation["rule"],
                dict(relation["selector"]),
                5,
                relation["expected"],
            )
        )
    return questions


def _windows_questions(join: dict) -> list:
    return _questions(join, "windows")


def _macos_questions(join: dict) -> list:
    return _questions(join, "macos")


def generate_suite(
    n: int, root: str, *, key: bytes = suite.PUBLIC_DEV_KEY, kind: str = "dev"
) -> list:
    """Build a suite of `n` scenarios under `root`.

    A dev suite uses the published key and is reproducible by anyone, which is what makes it
    good for development and worthless as a score. A hold-out suite uses a key that never
    leaves the evaluator. The internal scorecard-measurement kind also uses a public key, but
    one with separate derivation provenance; it is reproducible and explicitly non-reportable.
    """
    n = suite.validate_benchmark_scenario_count(n)
    suite.validate_suite_key_kind(key, kind)

    requested_output = Path(root)
    if not requested_output.name or requested_output.name in {".", ".."}:
        raise ValueError("evaluator suite root must have one non-empty final component")
    try:
        resolved_parent = requested_output.parent.resolve(strict=True)
        parent_fd = open_real_directory(resolved_parent)
    except (InventoryError, OSError) as exc:
        raise ValueError(f"evaluator suite parent must be a real directory: {exc}") from exc
    output = resolved_parent / requested_output.name
    root_fd = -1
    temporary = None
    published = successful = False
    try:
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except (NotImplementedError, OSError) as exc:
            raise ValueError(f"cannot inspect evaluator suite destination safely: {exc}") from exc
        else:
            raise ValueError(f"refusing pre-existing evaluator suite destination: {output}")
        try:
            temporary = suite._private_stage_directory(parent_fd, resolved_parent, output.name)
        except Exception:
            raise
        root_fd = open_real_directory_at(parent_fd, temporary.name)
        if not directory_entry_matches_descriptor(parent_fd, temporary.name, root_fd):
            raise ValueError("private evaluator staging root changed before generation")
        os.fchmod(root_fd, 0o700)

        build_root = os.fspath(temporary)
        paths = suite.suite_paths(build_root)
        os.mkdir(paths["scenarios"], mode=0o700)
        os.mkdir(paths["answers"], mode=0o700)
        os.mkdir(paths["content"], mode=0o700)
        os.mkdir(paths["staging"], mode=0o700)
        suite.write_key(build_root, key)
        store = ContentStore(suite.WINDOWS_MACOS_CONTENT_NAMESPACE, paths["content"])

        tasks, public = [], []
        for i in range(n):
            pid = suite.public_id(key, i)
            skey = suite.scenario_key(key, pid)
            scene_dir = os.path.join(paths["scenarios"], pid)
            staging = os.path.join(paths["staging"], pid)

            if i % 2 == 0:
                profile = _profile(skey, "windows")
                scene = build_windows_scene(
                    store, skey=skey, profile=profile, scene_dir=scene_dir, staging_dir=staging
                )
                questions = _windows_questions(scene.join)
            else:
                profile = _profile(skey, "macos")
                scene = build_macos_scene(
                    store, skey=skey, profile=profile, scene_dir=scene_dir, staging_dir=staging
                )
                questions = _macos_questions(scene.join)

            task = Task(
                pid,
                scene.family,
                scene_dir,
                questions,
                scene.join,
                kind,
                tuple(scene.artifacts),
            )
            observed_artifacts = [file.relative_path for file in inventory_regular_files(scene_dir)]
            if observed_artifacts != scene.artifacts:
                raise ValueError(
                    "scene's declared artifact inventory does not equal its served recursive tree"
                )
            suite.write_answers(build_root, pid, task.answer_key())
            tasks.append(task)
            public.append(
                {
                    "scenario_id": pid,
                    "family": scene.family,
                    "artifacts": scene.artifacts,
                    "questions": [
                        {
                            "id": q.id,
                            "prompt": q.prompt,
                            "kind": q.kind,
                            "rule": q.rule,
                            "selector": q.selector,
                            "candidate_count": q.candidate_count,
                        }
                        for q in questions
                    ],
                }
            )

        _rmtree(paths["staging"])
        document = suite.build_public_document(
            {"suite_kind": kind, "domain": suite.DOMAIN.decode(), "scenarios": public},
            paths["scenarios"],
        )
        with open(paths["public"], "xb") as file:
            file.write(suite.canonical_public_bytes(document))
        os.chmod(paths["public"], 0o600)
        suite.load_evaluator_private(build_root)
        if not directory_entry_matches_descriptor(parent_fd, temporary.name, root_fd):
            raise ValueError("private evaluator staging root changed during generation")
        if not suite._directory_path_matches_descriptor(resolved_parent, parent_fd):
            raise ValueError("evaluator suite parent changed during generation")
        root_state = os.fstat(root_fd)
        try:
            rename_directory_no_replace(
                temporary,
                output,
                parent_fd=parent_fd,
                expected_source=(root_state.st_dev, root_state.st_ino),
            )
        except FileExistsError as exc:
            raise ValueError(
                f"refusing evaluator suite destination that appeared: {output}"
            ) from exc
        published = True
        if not directory_entry_matches_descriptor(parent_fd, output.name, root_fd):
            raise ValueError("published evaluator suite is not the verified private staging root")
        for task in tasks:
            task.directory = os.fspath(output / "scenarios" / task.scenario_id)
        os.fchmod(root_fd, 0o700)
        successful = True
        return tasks
    finally:
        if root_fd >= 0 and not successful:
            entry_name = output.name if published else temporary.name
            remove_pinned_directory_at(parent_fd, entry_name, root_fd)
        if root_fd >= 0:
            os.close(root_fd)
        elif temporary is not None and not published:
            try:
                os.rmdir(temporary.name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def _profile(skey: bytes, family: str) -> HostProfile:
    from artifactforge import pools

    user = suite.pick(skey, "user", pools.USERS)
    if family == "windows":
        host = suite.pick(skey, "host", pools.HOSTS)
        n = int.from_bytes(suite.scenario_key(skey, "hostnum")[:2], "big") % 900 + 100
        return windows_profile(hostname=f"{host}-{n:03d}", username=user)
    if family == "macos":
        n = int.from_bytes(suite.scenario_key(skey, "hostnum")[:2], "big") % 900 + 100
        return macos_profile(hostname=f"mac-{n:03d}", username=user)
    raise ValueError(f"unsupported benchmark family: {family!r}")


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def generate_batch(n: int, out_root: str) -> list:
    """A dev suite in one call — the shape the gates and the determinism check use."""
    return generate_suite(n, out_root)


def evaluator_root(tasks: list[Task]) -> Path:
    """Recover one exact evaluator root from generated private tasks, or refuse ambiguity."""
    if not tasks:
        raise ValueError("cannot locate an evaluator root for an empty task list")
    roots = set()
    for task in tasks:
        directory = Path(task.directory)
        if directory.name != task.scenario_id or directory.parent.name != "scenarios":
            raise ValueError(
                f"task {task.scenario_id!r} is not rooted at <evaluator>/scenarios/<id>"
            )
        roots.add(directory.parent.parent)
    if len(roots) != 1:
        raise ValueError("tasks span more than one evaluator root")
    return next(iter(roots))


def _tasks_from_validated_public(
    document: dict, public_root: str | os.PathLike[str]
) -> list[PublicTask]:
    """Construct task objects from a document already bound to ``public_root`` bytes."""
    suite_kind = document.get("suite_kind")
    scenarios = document.get("scenarios")
    if not isinstance(suite_kind, str) or not suite_kind:
        raise ValueError("public export suite_kind must be non-empty text")
    if not isinstance(scenarios, list):
        raise ValueError("public export scenarios must be a list")

    tasks = []
    for index, entry in enumerate(scenarios):
        if not isinstance(entry, dict):
            raise ValueError(f"public scenario {index} must be an object")
        try:
            scenario_id = entry["scenario_id"]
            family = entry["family"]
            artifacts = tuple(entry["artifacts"])
            raw_questions = entry["questions"]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"public scenario {index} has an incomplete v2 shape") from exc
        if not isinstance(scenario_id, str) or not isinstance(family, str):
            raise ValueError(f"public scenario {index} has invalid identity fields")
        if not isinstance(raw_questions, list):
            raise ValueError(f"public scenario {scenario_id!r} questions must be a list")
        questions = []
        for question_index, question in enumerate(raw_questions):
            if not isinstance(question, dict):
                raise ValueError(
                    f"public scenario {scenario_id!r} question {question_index} is not an object"
                )
            try:
                public_question = PublicQuestion(
                    question["id"],
                    question["prompt"],
                    question["kind"],
                    question["rule"],
                    dict(question["selector"]),
                    question["candidate_count"],
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"public scenario {scenario_id!r} question {question_index} "
                    "has an invalid v2 shape"
                ) from exc
            if (
                not all(
                    isinstance(value, str) and value
                    for value in (
                        public_question.id,
                        public_question.prompt,
                        public_question.kind,
                        public_question.rule,
                    )
                )
                or type(public_question.candidate_count) is not int
                or public_question.candidate_count < 2
            ):
                raise ValueError(
                    f"public scenario {scenario_id!r} question {question_index} "
                    "has invalid v2 fields"
                )
            questions.append(public_question)
        tasks.append(
            PublicTask(
                scenario_id,
                family,
                os.fspath(Path(public_root) / "scenarios" / scenario_id),
                questions,
                suite_kind,
                artifacts,
            )
        )
    return tasks


def _load_public_tasks_live_unsafe(public_root: str) -> tuple[dict, list[PublicTask]]:
    """Validate a live export, then return paths that can subsequently change.

    This compatibility helper is deliberately private and unsafe. Solver and gate code must
    keep :func:`frozen_public_tasks` open for the full lifetime of every returned task.
    """
    document = suite.load_public_export(public_root)
    return document, _tasks_from_validated_public(document, public_root)


@contextmanager
def frozen_public_tasks(public_root: str | os.PathLike[str]):
    """Yield solver tasks rooted only in one private, immutable export snapshot.

    The task paths are valid only inside the context. The original export can be replaced or
    corrupted after entry without changing either the validated document or artifact bytes
    observed through the yielded tasks.
    """
    with suite.frozen_public_export(os.fspath(public_root)) as (document, snapshot_root):
        yield document, _tasks_from_validated_public(document, snapshot_root)
