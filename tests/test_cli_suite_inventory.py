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


def _paths(root: Path) -> dict:
    paths = suite.suite_paths(os.fspath(root))
    Path(paths["scenarios"]).mkdir(parents=True, exist_ok=True)
    return paths


def _write_manifest(root: Path, artifacts, *, include_artifacts: bool = True) -> dict:
    paths = _paths(root)
    scenario = {
        "scenario_id": SCENARIO_ID,
        "family": "windows",
        "questions": [],
    }
    if include_artifacts:
        scenario["artifacts"] = artifacts
    Path(paths["public"]).write_text(
        json.dumps({"suite_kind": "dev", "scenarios": [scenario]}),
        encoding="utf-8",
    )
    return paths


def _write_document(root: Path, document) -> None:
    paths = _paths(root)
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

    public, tasks = cli._load_suite(os.fspath(tmp_path))

    assert public["scenarios"][0]["artifacts"] == artifacts
    assert len(tasks) == 1
    assert tasks[0].scenario_id == SCENARIO_ID
    assert tasks[0].directory == os.fspath(scene)


def test_load_suite_accepts_a_fresh_generated_flat_suite(tmp_path):
    root = tmp_path / "generated"
    generated = generate_suite(2, os.fspath(root), key=suite.PUBLIC_DEV_KEY)

    public, loaded = cli._load_suite(os.fspath(root))

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
        cli._load_suite(os.fspath(tmp_path))


def test_load_suite_rejects_a_missing_published_artifact(tmp_path):
    _write_scene(tmp_path, {"present": b"present"})
    _write_manifest(tmp_path, ["missing", "present"])

    with pytest.raises(ValueError, match="missing: missing"):
        cli._load_suite(os.fspath(tmp_path))


def test_load_suite_rejects_an_extra_nested_hidden_artifact(tmp_path):
    _write_scene(
        tmp_path,
        {"declared": b"declared", ".hidden/nested/extra": b"extra"},
    )
    _write_manifest(tmp_path, ["declared"])

    with pytest.raises(ValueError, match=r"extra: \.hidden/nested/extra"):
        cli._load_suite(os.fspath(tmp_path))


def test_load_suite_rejects_a_missing_published_inventory_field(tmp_path):
    _write_scene(tmp_path, {"artifact": b"artifact"})
    _write_manifest(tmp_path, None, include_artifacts=False)

    with pytest.raises(ValueError, match="must be a JSON list"):
        cli._load_suite(os.fspath(tmp_path))


def test_load_suite_rejects_an_unsafe_served_tree(tmp_path):
    scene = _write_scene(tmp_path, {"real": b"real"})
    link = scene / "linked"
    try:
        link.symlink_to(scene / "real")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    _write_manifest(tmp_path, ["linked", "real"])

    with pytest.raises(ValueError, match="served artifact tree is unsafe:.*symlink"):
        cli._load_suite(os.fspath(tmp_path))


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

    with pytest.raises(ValueError, match="served artifact tree is unsafe:.*root.*symlink"):
        cli._load_suite(os.fspath(tmp_path))


def test_load_suite_rejects_unbound_empty_directories(tmp_path):
    scene = _write_scene(tmp_path, {"artifact": b"artifact"})
    (scene / "empty").mkdir()
    _write_manifest(tmp_path, ["artifact"])

    with pytest.raises(ValueError, match="served artifact tree is unsafe:.*empty directory"):
        cli._load_suite(os.fspath(tmp_path))


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
    tmp_path, monkeypatch, scenario_id
):
    _write_document(
        tmp_path,
        {
            "scenarios": [{
                "scenario_id": scenario_id,
                "family": "windows",
                "artifacts": ["artifact"],
                "questions": [],
            }],
        },
    )
    monkeypatch.setattr(
        cli,
        "inventory_regular_files",
        lambda _directory: pytest.fail("invalid scenario_id reached a filesystem inventory"),
    )

    with pytest.raises(ValueError, match="invalid scenario_id"):
        cli._load_suite(os.fspath(tmp_path))


def test_load_suite_rejects_duplicate_scenario_ids_before_path_join(tmp_path, monkeypatch):
    entry = {
        "scenario_id": SCENARIO_ID,
        "family": "windows",
        "artifacts": ["artifact"],
        "questions": [],
    }
    _write_document(tmp_path, {"scenarios": [entry, dict(entry)]})
    monkeypatch.setattr(
        cli,
        "inventory_regular_files",
        lambda _directory: pytest.fail("duplicate scenario_id reached a filesystem inventory"),
    )

    with pytest.raises(ValueError, match="duplicate scenario_id"):
        cli._load_suite(os.fspath(tmp_path))


@pytest.mark.parametrize(
    "document,match",
    (
        (None, "document must be a JSON object"),
        ([], "document must be a JSON object"),
        ({}, "scenarios must be a JSON list"),
        ({"scenarios": {}}, "scenarios must be a JSON list"),
        ({"scenarios": [None]}, "scenario 0 must be a JSON object"),
    ),
)
def test_load_suite_rejects_malformed_top_level_and_scenario_types(
    tmp_path, document, match
):
    _write_document(tmp_path, document)

    with pytest.raises(ValueError, match=match):
        cli._load_suite(os.fspath(tmp_path))


@pytest.mark.parametrize(
    "changes,match",
    (
        ({"family": None}, "family must be a non-empty string"),
        ({"questions": {}}, "questions must be a JSON list"),
        ({"questions": [None]}, "question 0 must be a JSON object"),
        (
            {"questions": [{"prompt": "p", "kind": "name", "joins": 1}]},
            "field 'id' must be a string",
        ),
        (
            {"questions": [{"id": "q", "prompt": "p", "kind": "name", "joins": 0}]},
            "field 'joins' must be a positive integer",
        ),
    ),
)
def test_load_suite_rejects_malformed_scenario_fields(tmp_path, changes, match):
    entry = {
        "scenario_id": SCENARIO_ID,
        "family": "windows",
        "artifacts": ["artifact"],
        "questions": [],
    }
    entry.update(changes)
    _write_document(tmp_path, {"scenarios": [entry]})

    with pytest.raises(ValueError, match=match):
        cli._load_suite(os.fspath(tmp_path))
