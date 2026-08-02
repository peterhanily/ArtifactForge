# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The CLI binds each public artifact inventory to the exact recursive served tree."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from artifactforge import suite
from artifactforge import cli
from artifactforge.bench.benchmark import generate_suite


SCENARIO_ID = "af1_aaaaaaaaaaaaaaaa"


def _valid_questions() -> list[dict]:
    questions = []
    for index in range(5):
        selector = {"lower_case_long_path": f"c:\\programdata\\candidate-{index}.exe"}
        questions.append(
            {
                "id": f"windows_agreement_{index + 1:02d}",
                "prompt": suite.benchmark_question_prompt(suite.WINDOWS_AMCACHE_RULE, selector),
                "kind": "hash",
                "rule": suite.WINDOWS_AMCACHE_RULE,
                "selector": selector,
                "candidate_count": 5,
            }
        )
    return questions


def _changed_questions(changes: dict, *, remove: str | None = None) -> list[dict]:
    questions = _valid_questions()
    questions[0].update(changes)
    if remove is not None:
        questions[0].pop(remove)
    return questions


def _paths(root: Path) -> dict:
    paths = suite.suite_paths(os.fspath(root))
    Path(paths["scenarios"]).mkdir(parents=True, exist_ok=True)
    Path(paths["answers"]).mkdir(parents=True, exist_ok=True)
    return paths


def _write_manifest(root: Path, artifacts, *, include_artifacts: bool = True) -> dict:
    paths = _paths(root)
    scenario = {
        "scenario_id": SCENARIO_ID,
        "family": "windows",
        "questions": _valid_questions(),
    }
    if include_artifacts:
        scenario["artifacts"] = artifacts
    Path(paths["public"]).write_text(
        json.dumps(
            {
                "domain": suite.DOMAIN.decode(),
                "suite_kind": "dev",
                "scenarios": [scenario],
            }
        ),
        encoding="utf-8",
    )
    return paths


def _write_document(root: Path, document) -> None:
    paths = _paths(root)
    if isinstance(document, dict) and "domain" not in document:
        document = {
            "domain": suite.DOMAIN.decode(),
            "suite_kind": "dev",
            **document,
        }
    Path(paths["public"]).write_text(json.dumps(document), encoding="utf-8")


def _write_scene(root: Path, files: dict[str, bytes]) -> Path:
    paths = _paths(root)
    scene = Path(paths["scenarios"]) / SCENARIO_ID
    scene.mkdir()
    for relative, data in files.items():
        target = scene.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return scene


def _load_document(root: Path) -> dict:
    paths = suite.suite_paths(os.fspath(root))
    document = json.loads(Path(paths["public"]).read_text(encoding="utf-8"))
    return suite.build_public_document(document, paths["scenarios"])


@pytest.mark.parametrize(
    "files",
    (
        {"flat.bin": b"flat"},
        {
            ".evidence/.marker": b"hidden",
            ".evidence/nested/artifact.bin": b"nested",
            "visible/deep/value": b"visible",
        },
    ),
)
def test_load_suite_accepts_exact_flat_and_nested_hidden_inventories(tmp_path, files):
    artifacts = sorted(files)
    scene = _write_scene(tmp_path, files)
    _write_manifest(tmp_path, artifacts)

    public = _load_document(tmp_path)

    assert public["scenarios"][0]["artifacts"] == artifacts
    assert scene == Path(suite.suite_paths(os.fspath(tmp_path))["scenarios"]) / SCENARIO_ID


def test_load_suite_accepts_a_fresh_generated_flat_suite(tmp_path):
    root = tmp_path / "generated"
    generated = generate_suite(2, os.fspath(root), key=suite.PUBLIC_DEV_KEY)

    public, loaded = cli._load_suite(os.fspath(root), role="evaluator")

    assert [task.scenario_id for task in loaded] == [task.scenario_id for task in generated]
    assert [entry["artifacts"] for entry in public["scenarios"]]


@pytest.mark.parametrize(
    "artifacts,match",
    (
        (None, "must be a JSON list"),
        ("artifact.bin", "must be a JSON list"),
        ([], "must not be empty"),
        ([1], "non-empty string"),
        (["../escape"], "must not contain"),
        (["a", "a"], "duplicate"),
        (["Dir/a", "dir/b"], "case-folding"),
        (["a", "a/b"], "both a file and a directory"),
        (["z", "a"], "must be sorted"),
    ),
)
def test_load_suite_rejects_malformed_duplicate_or_colliding_published_paths(
    tmp_path, artifacts, match
):
    _write_scene(tmp_path, {"a": b"a"})
    _write_manifest(tmp_path, artifacts)

    with pytest.raises(ValueError, match=match):
        _load_document(tmp_path)


def test_load_suite_rejects_a_missing_published_artifact(tmp_path):
    _write_scene(tmp_path, {"present": b"present"})
    _write_manifest(tmp_path, ["missing", "present"])

    with pytest.raises(ValueError, match=f"missing: {SCENARIO_ID}/missing"):
        _load_document(tmp_path)


def test_load_suite_rejects_an_extra_nested_hidden_artifact(tmp_path):
    _write_scene(
        tmp_path,
        {"declared": b"declared", ".hidden/nested/extra": b"extra"},
    )
    _write_manifest(tmp_path, ["declared"])

    with pytest.raises(ValueError, match=rf"extra: {SCENARIO_ID}/\.hidden/nested/extra"):
        _load_document(tmp_path)


def test_load_suite_rejects_a_missing_published_inventory_field(tmp_path):
    _write_scene(tmp_path, {"artifact": b"artifact"})
    _write_manifest(tmp_path, None, include_artifacts=False)

    with pytest.raises(ValueError, match="must be a JSON list"):
        _load_document(tmp_path)


def test_load_suite_rejects_an_unsafe_served_tree(tmp_path):
    scene = _write_scene(tmp_path, {"real": b"real"})
    link = scene / "linked"
    try:
        link.symlink_to(scene / "real")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    _write_manifest(tmp_path, ["linked", "real"])

    with pytest.raises(ValueError, match="public scenarios are unsafe:.*symlink"):
        _load_document(tmp_path)


def test_load_suite_rejects_a_symlinked_scene_root(tmp_path):
    paths = _paths(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    (external / "artifact").write_bytes(b"artifact")
    scene = Path(paths["scenarios"]) / SCENARIO_ID
    try:
        scene.symlink_to(external, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    _write_manifest(tmp_path, ["artifact"])

    with pytest.raises(ValueError, match="public scenarios are unsafe:.*symlink"):
        _load_document(tmp_path)


def test_load_suite_rejects_unbound_empty_directories(tmp_path):
    scene = _write_scene(tmp_path, {"artifact": b"artifact"})
    (scene / "empty").mkdir()
    _write_manifest(tmp_path, ["artifact"])

    with pytest.raises(ValueError, match="public scenarios are unsafe:.*empty directory"):
        _load_document(tmp_path)


@pytest.mark.parametrize(
    "scenario_id",
    (
        "../escape",
        "/absolute",
        "af1_aaaaaaaaaaaaaaaa/nested",
        "af1_aaaaaaaaaaaaaaa!",
        "af1_too_short",
    ),
)
def test_load_suite_rejects_unsafe_or_malformed_scenario_ids_before_path_join(
    tmp_path, scenario_id
):
    _write_document(
        tmp_path,
        {
            "scenarios": [
                {
                    "scenario_id": scenario_id,
                    "family": "windows",
                    "artifacts": ["artifact"],
                    "questions": _valid_questions(),
                }
            ],
        },
    )

    with pytest.raises(ValueError, match="invalid scenario_id"):
        _load_document(tmp_path)


def test_load_suite_rejects_duplicate_scenario_ids_before_path_join(tmp_path):
    entry = {
        "scenario_id": SCENARIO_ID,
        "family": "windows",
        "artifacts": ["artifact"],
        "questions": _valid_questions(),
    }
    _write_document(tmp_path, {"scenarios": [entry, dict(entry)]})
    with pytest.raises(ValueError, match="duplicate scenario_id"):
        _load_document(tmp_path)


@pytest.mark.parametrize(
    "document,match",
    (
        (None, "base document must be a JSON object"),
        ([], "base document must be a JSON object"),
        ({}, "scenarios must be a JSON list"),
        ({"scenarios": {}}, "scenarios must be a JSON list"),
        ({"scenarios": [None]}, "scenario 0 must be a JSON object"),
    ),
)
def test_load_suite_rejects_malformed_top_level_and_scenario_types(tmp_path, document, match):
    _write_document(tmp_path, document)

    with pytest.raises(ValueError, match=match):
        _load_document(tmp_path)


@pytest.mark.parametrize(
    "changes,match",
    (
        ({"family": None}, "family must be 'windows'"),
        ({"questions": {}}, "questions must be a JSON list"),
        (
            {"questions": [None, *_valid_questions()[1:]]},
            "question 0 must be a JSON object",
        ),
        (
            {"questions": _changed_questions({}, remove="id")},
            "field 'id' must be a non-empty string",
        ),
        (
            {"questions": _changed_questions({"candidate_count": 0})},
            "field 'candidate_count' must be exactly 5",
        ),
        (
            {"questions": _changed_questions({"selector": []})},
            "field 'selector' must be a JSON object",
        ),
    ),
)
def test_load_suite_rejects_malformed_scenario_fields(tmp_path, changes, match):
    entry = {
        "scenario_id": SCENARIO_ID,
        "family": "windows",
        "artifacts": ["artifact"],
        "questions": _valid_questions(),
    }
    entry.update(changes)
    _write_scene(tmp_path, {"artifact": b"artifact"})
    _write_document(tmp_path, {"scenarios": [entry]})

    with pytest.raises(ValueError, match=match):
        _load_document(tmp_path)


def test_public_schema_rejects_population_above_the_declared_cap(tmp_path):
    entry = {
        "scenario_id": SCENARIO_ID,
        "family": "windows",
        "artifacts": ["artifact"],
        "questions": _valid_questions(),
    }
    _write_document(
        tmp_path,
        {"scenarios": [entry] * (suite.BENCHMARK_MAX_SCENARIOS + 1)},
    )
    with pytest.raises(ValueError, match="exceeds the 200-scenario limit"):
        _load_document(tmp_path)


def test_cli_rejects_oversized_population_before_creating_output(tmp_path):
    destination = tmp_path / "must-not-exist"
    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "bench",
                "new",
                os.fspath(destination),
                "--n",
                str(suite.BENCHMARK_MAX_SCENARIOS + 1),
            ]
        )
    assert raised.value.code == 2
    assert not destination.exists()
