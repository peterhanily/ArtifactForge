# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The benchmark: scenes plus questions whose answers only the artifacts hold.

Two properties have to be true at once, and the previous design had only the first.

**Recoverable.** A reference solver reading the artifacts with real DFIR parsers answers
every question. Without this the benchmark is unanswerable.

**Not otherwise obtainable.** No shortcut reaches the same answer. The previous design failed
this completely: the public scenario identifier was also the generation seed, so a solver
that opened zero files reproduced every answer, and `JOIN_MANIFEST.json` — the whole key —
sat in the directory the solver was pointed at, hidden only from a listing.

Both halves are structural here. Answers derive from a suite key the solver never sees, and
the served directory is staged by allowlist so the key and the content cache are not merely
filtered out of the view but absent from it.

Every question also spans at least two artifacts. A question answerable from one file in
isolation cannot tell you whether the cross-artifact pivot works — which is the one thing
this project exists to provide, and which the old questions scored 100% on with the pivot
deliberately broken.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from artifactforge import suite
from artifactforge.compose.scene import build_macos_scene, build_windows_scene
from artifactforge.content import ContentStore
from artifactforge.model import HostProfile, macos_profile, windows_profile


@dataclass(frozen=True)
class Question:
    """Server-side. Carries the answer, so it must never cross into solver code."""

    id: str
    prompt: str
    kind: str            # hash | imphash | path | name | count | uuid | url | enum
    expected: str
    joins: int = 1       # artifacts that must be read together. Gate 4 requires >= 2 for at
                         # least one question per family; a joins=1 question cannot detect a
                         # broken cross-artifact pivot.


@dataclass(frozen=True)
class PublicQuestion:
    id: str
    prompt: str
    kind: str
    joins: int


@dataclass(frozen=True)
class PublicTask:
    """Everything a solver is given, and nothing else. A separate type rather than a filtered
    dict, so passing the wrong object into a solver is a type error and not a silent leak."""

    scenario_id: str
    family: str
    directory: str
    questions: list


@dataclass
class Task:
    scenario_id: str
    family: str
    directory: str
    questions: list = field(default_factory=list)
    join: dict = field(default_factory=dict)

    def public(self) -> PublicTask:
        return PublicTask(self.scenario_id, self.family, self.directory,
                          [PublicQuestion(q.id, q.prompt, q.kind, q.joins)
                           for q in self.questions])

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


def _windows_questions(join: dict) -> list:
    p, a = join["persisted"], join["amcache_match"]
    return [
        Question("persisted_sha256",
                 "Exactly one value under the Run key names a program that is present in "
                 "this image. Give that file's SHA256.",
                 "hash", p["sha256"], joins=2),
        Question("persisted_imphash",
                 "Give the IMPHASH of that same persisted program.",
                 "imphash", p["imphash"], joins=2),
        Question("persisted_run_count",
                 "According to prefetch, how many times was that persisted program executed?",
                 "count", p["run_count"], joins=3),
        Question("amcache_match_sha256",
                 "Exactly one InventoryApplicationFile FileId ends with the SHA1 of a file "
                 "present in this image. Give that file's SHA256. (It is not the persisted "
                 "one — Amcache recorded the persisted program under an earlier hash.)",
                 "hash", a["sha256"], joins=2),
        Question("orphan_execution",
                 "One prefetch record names an executable that is no longer on disk. "
                 "Give its filename.",
                 "name", join["orphan_execution"], joins=2),
    ]


def _macos_questions(join: dict) -> list:
    s = join["subject"]
    return [
        Question("granted_and_used_bundle",
                 "Two clients hold an allowed TCC grant, but only one of them also appears "
                 "in knowledgeC as having been used. Give its bundle identifier.",
                 "enum", s["bundle_id"], joins=2),
        Question("subject_download_url",
                 "Give the URL that application was downloaded from.",
                 "url", s["download_url"], joins=3),
        Question("subject_quarantine_agent",
                 "Which application performed that download?",
                 "name", s["agent"], joins=3),
        Question("subject_persistence_path",
                 "Give the program path its LaunchAgent launches.",
                 "path", s["app_path"], joins=2),
        Question("subject_binary_sha256",
                 "Each application's binary is present, named by its bundle identifier. "
                 "Give the SHA256 of that application's binary.",
                 "hash", s["sha256"], joins=3),
        Question("subject_binary_symhash",
                 "Give that binary's symhash — the md5 of its sorted undefined external "
                 "symbol names, the Mach-O analogue of IMPHASH.",
                 "imphash", s["symhash"], joins=3),
    ]


def generate_suite(n: int, root: str, *, key: bytes = suite.PUBLIC_DEV_KEY,
                   kind: str = "dev") -> list:
    """Build a suite of `n` scenarios under `root`.

    A dev suite uses the published key and is reproducible by anyone, which is what makes it
    good for development and worthless as a score. A hold-out suite uses a key that never
    leaves the evaluator.
    """
    paths = suite.suite_paths(root)
    os.makedirs(paths["scenarios"], exist_ok=True)
    suite.write_key(root, key)
    store = ContentStore("artifactforge::suite", paths["content"])

    tasks, public = [], []
    for i in range(n):
        pid = suite.public_id(key, i)
        skey = suite.scenario_key(key, pid)
        scene_dir = os.path.join(paths["scenarios"], pid)
        staging = os.path.join(paths["staging"], pid)

        if i % 2 == 0:
            profile = _profile(skey, "windows")
            scene = build_windows_scene(store, skey=skey, profile=profile,
                                        scene_dir=scene_dir, staging_dir=staging)
            questions = _windows_questions(scene.join)
        else:
            profile = _profile(skey, "macos")
            scene = build_macos_scene(store, skey=skey, profile=profile,
                                      scene_dir=scene_dir, staging_dir=staging)
            questions = _macos_questions(scene.join)

        task = Task(pid, scene.family, scene_dir, questions, scene.join)
        suite.write_answers(root, pid, task.answer_key(), scene.join)
        tasks.append(task)
        public.append({"scenario_id": pid, "family": scene.family,
                       "artifacts": scene.artifacts,
                       "questions": [{"id": q.id, "prompt": q.prompt, "kind": q.kind,
                                      "joins": q.joins} for q in questions]})

    _rmtree(paths["staging"])
    with open(paths["public"], "w") as f:
        json.dump({"suite_kind": kind, "domain": suite.DOMAIN.decode(),
                   "scenarios": public}, f, indent=2)
        f.write("\n")
    return tasks


def _profile(skey: bytes, family: str) -> HostProfile:
    from artifactforge import pools
    user = suite.pick(skey, "user", pools.USERS)
    if family == "windows":
        host = suite.pick(skey, "host", pools.HOSTS)
        n = int.from_bytes(suite.scenario_key(skey, "hostnum")[:2], "big") % 900 + 100
        return windows_profile(hostname=f"{host}-{n:03d}", username=user)
    n = int.from_bytes(suite.scenario_key(skey, "hostnum")[:2], "big") % 900 + 100
    return macos_profile(hostname=f"mac-{n:03d}", username=user)


def _rmtree(path: str) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def generate_batch(n: int, out_root: str) -> list:
    """A dev suite in one call — the shape the gates and the determinism check use."""
    return generate_suite(n, out_root)
