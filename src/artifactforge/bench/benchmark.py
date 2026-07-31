"""Turn crime scenes into a gradeable defensive-agent benchmark.

Each Task is a generated scenario plus a set of questions whose answers are derivable from
the artifacts. An agent sees only the questions and the artifact files (`Task.public()`); the
answer key stays server-side (`Task.answer_key()`). `grade()` scores submitted answers.

Generation is a pure function of the seed, so a batch is deterministic and embarrassingly
parallel — the scale the "hyper-scale investigations for defensive agents" purpose needs.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from artifactforge.content.store import ContentStore
from artifactforge.model import HostProfile, macos_profile, windows_profile
from artifactforge.compose.scene import build_crime_scene, build_macos_crime_scene


@dataclass(frozen=True)
class Question:
    id: str
    prompt: str
    kind: str            # hash | imphash | path | name | count | uuid | url | enum
    expected: str        # ground truth (server-side only)
    joins: int = 1       # how many artifacts must be read together to answer it. A question
                         # with joins=1 is answerable from one file in isolation and so can
                         # never detect a broken cross-artifact pivot; Gate 4 requires at
                         # least one question per family with joins >= 2.


@dataclass
class Task:
    scenario_id: str
    family: str
    directory: str
    questions: list = field(default_factory=list)

    def public(self) -> dict:
        """What an evaluated agent is given — no expected answers, no internal files."""
        hidden = {"JOIN_MANIFEST.json"}
        artifacts = sorted(
            f for f in os.listdir(self.directory)
            if f not in hidden and not f.startswith(".")
            and os.path.isfile(os.path.join(self.directory, f)))
        return {
            "scenario_id": self.scenario_id,
            "family": self.family,
            "artifacts": artifacts,
            "questions": [{"id": q.id, "prompt": q.prompt, "kind": q.kind} for q in self.questions],
        }

    def answer_key(self) -> dict:
        return {q.id: q.expected for q in self.questions}


def normalize(value, kind: str) -> str:
    s = ("" if value is None else str(value)).strip()
    if kind == "url":
        return s
    return s.lower()


@dataclass
class Score:
    scenario_id: str
    correct: int
    total: int
    per_question: dict

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0


def grade(task: Task, answers: dict) -> Score:
    per_q, correct = {}, 0
    for q in task.questions:
        ok = normalize(answers.get(q.id), q.kind) == normalize(q.expected, q.kind)
        per_q[q.id] = ok
        correct += int(ok)
    return Score(task.scenario_id, correct, len(task.questions), per_q)


def build_windows_task(scenario_id: str, profile: HostProfile, out_dir: str,
                       content_id: str, exec_path: str, run_value_name: str, run_count: int) -> Task:
    store = ContentStore(f"artifactforge::{scenario_id}", os.path.join(out_dir, ".cache"))
    s = build_crime_scene(store, out_dir=out_dir, content_id=content_id, exec_path=exec_path,
                          run_value_name=run_value_name, run_count=run_count)
    j = s.join
    q = [
        Question("dropped_sha256", "SHA256 of the dropped executable?", "hash", j["sha256"]),
        Question("imphash", "IMPHASH of the dropped executable?", "imphash", j["imphash"]),
        Question("amcache_sha1", "SHA1 recorded for the file in Amcache?", "hash", j["sha1"]),
        Question("persistence_path", "Path launched by the Run-key persistence value?", "path", j["exec_path"]),
        Question("exec_name", "Name of the executed binary (per prefetch)?", "name", j["exec_name"]),
        Question("run_count", "How many times was it executed (per prefetch)?", "count", j["run_count"]),
    ]
    return Task(scenario_id, "windows", out_dir, q)


def build_macos_task(scenario_id: str, profile: HostProfile, out_dir: str,
                     bundle_id: str, app_path: str, download_url: str, origin_url: str, agent: str) -> Task:
    s = build_macos_crime_scene(profile, out_dir=out_dir, bundle_id=bundle_id, app_path=app_path,
                                download_url=download_url, origin_url=origin_url, agent=agent)
    j = s.join
    q = [
        Question("quarantine_uuid", "Quarantine event UUID for the downloaded app?", "uuid", j["quarantine_uuid"]),
        Question("download_url", "URL the app was downloaded from?", "url", j["download_url"]),
        Question("tcc_bundle_id", "Bundle ID that was granted a sensitive TCC permission?", "enum", bundle_id),
        Question("persistence_path", "Program path launched by the LaunchAgent?", "path", app_path),
    ]
    return Task(scenario_id, "macos", out_dir, q)


# small deterministic pools so batch scenarios vary by seed
_USERS = ("v", "jdoe", "asmith", "root2", "mchen", "kpatel")
_HOSTS = ("WKSTN", "POS", "FIN", "HR", "DEV", "OPS")
_MALNAMES = ("update.exe", "svc_host.exe", "adobe_up.exe", "chrome_helper.exe", "win_defend.exe")
_BUNDLES = ("com.acme.updater", "io.opncast.helper", "net.zeta.sync", "org.freeware.tool")


def _pick(seed: int, pool):
    return pool[seed % len(pool)]


def generate_batch(n: int, out_root: str) -> list:
    """Generate n deterministic, distinct scenarios (alternating Windows/macOS)."""
    os.makedirs(out_root, exist_ok=True)
    tasks = []
    for i in range(n):
        sid = f"scenario_{i:05d}"
        d = os.path.join(out_root, sid)
        if i % 2 == 0:
            prof = windows_profile(hostname=f"{_pick(i, _HOSTS)}-{i:03d}", username=_pick(i, _USERS))
            name = _pick(i, _MALNAMES)
            exec_path = f"{prof.home_dir}\\AppData\\Local\\Temp\\{name}"
            tasks.append(build_windows_task(sid, prof, d, content_id=f"pe:{sid}:{name}",
                                            exec_path=exec_path, run_value_name="Updater",
                                            run_count=1 + (i % 9)))
        else:
            prof = macos_profile(hostname=f"mac-{i:03d}", username=_pick(i, _USERS))
            bundle = _pick(i, _BUNDLES)
            app_path = f"{prof.home_dir}/Library/Application Support/{bundle}/agent"
            tasks.append(build_macos_task(sid, prof, d, bundle_id=bundle, app_path=app_path,
                                          download_url=f"https://cdn{i}.evil.example/{bundle}.dmg",
                                          origin_url="https://evil.example/dl", agent="Safari"))
    return tasks
