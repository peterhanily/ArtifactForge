# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The Gate 4 solver view is an exact, digest-bound root disjoint from evaluation."""

from __future__ import annotations

import hashlib
import base64
import json
import os
from pathlib import Path
import shutil
import stat

import pytest

from artifactforge import cli, suite
from artifactforge.bench.benchmark import frozen_public_tasks, generate_suite
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.inventory import inventory_regular_files, open_real_directory


@pytest.fixture
def evaluator(tmp_path) -> Path:
    root = tmp_path / "evaluator"
    generate_suite(2, os.fspath(root), key=bytes.fromhex("71" * 32), kind="holdout")
    return root


@pytest.fixture
def public_export(tmp_path, evaluator) -> Path:
    root = tmp_path / "public"
    suite.export_public(os.fspath(evaluator), os.fspath(root))
    return root


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _first_artifact(root: Path) -> Path:
    return next(path for path in sorted((root / "scenarios").rglob("*")) if path.is_file())


def _thaw_public_export(root: Path) -> None:
    """Make one isolated test export writable before a deliberate corruption mutation."""
    root.chmod(0o755)
    for current, directories, files in os.walk(root):
        Path(current).chmod(0o755)
        for directory in directories:
            (Path(current) / directory).chmod(0o755)
        for filename in files:
            (Path(current) / filename).chmod(0o644)


@pytest.fixture(autouse=True)
def _restore_test_tree_cleanup_modes(tmp_path):
    """Let pytest remove intentionally read-only exports after every isolated test.

    Production exports stay 0555/0444.  The test owns its complete ``tmp_path`` and restores
    directory write permission only during teardown; links are never followed.
    """
    yield
    for current, directories, _files in os.walk(tmp_path, topdown=False, followlinks=False):
        for directory in directories:
            path = Path(current) / directory
            if not path.is_symlink():
                path.chmod(0o755)
        Path(current).chmod(0o755)


def _rewrite_with_bound_suite_id(path: Path, mutate) -> None:
    _thaw_public_export(path.parent)
    document = json.loads(path.read_text())
    mutate(document)
    unsigned = dict(document)
    unsigned.pop("suite_id")
    document["suite_id"] = "sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()
    path.write_bytes(_canonical(document))


def _valid_submission_row(evaluator: Path, index: int = 0) -> dict:
    document = suite.load_evaluator_public(os.fspath(evaluator))
    entry = document["scenarios"][index]
    answer_document = json.loads(
        (evaluator / "_answers" / f"{entry['scenario_id']}.json").read_text()
    )
    return {
        "suite_id": document["suite_id"],
        "scenario_id": entry["scenario_id"],
        "answers": answer_document["answers"],
    }


def _grade_payload(evaluator: Path, submission: Path, payload: bytes) -> int:
    submission.write_bytes(payload)
    return cli.main(
        [
            "bench",
            "grade",
            os.fspath(evaluator),
            "--submission",
            os.fspath(submission),
        ]
    )


def _declare_added_artifact(evaluator: Path, relative: str, data: bytes) -> None:
    document = json.loads((evaluator / "public.json").read_text())
    entry = document["scenarios"][0]
    target = evaluator / "scenarios" / entry["scenario_id"] / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    entry["artifacts"] = sorted([*entry["artifacts"], relative])
    base = {
        key: value
        for key, value in document.items()
        if key not in {"public_export", "schema", "suite_id"}
    }
    rebound = suite.build_public_document(base, evaluator / "scenarios")
    (evaluator / "public.json").write_bytes(suite.canonical_public_bytes(rebound))


def test_export_is_canonical_exact_aggregate_bound_and_answer_free(evaluator, public_export):
    document = suite.load_public_export(os.fspath(public_export))
    raw = (public_export / "public.json").read_bytes()
    assert raw == _canonical(document)
    assert raw == (evaluator / "public.json").read_bytes()
    assert sorted(path.name for path in public_export.iterdir()) == [
        "public.json",
        "scenarios",
    ]
    assert document["schema"] == suite.PUBLIC_DOCUMENT_SCHEMA
    assert document["domain"] == "artifactforge/bench/v2"
    assert document["suite_id"].startswith("sha256:")
    export = document["public_export"]
    assert export["schema"] == suite.PUBLIC_EXPORT_SCHEMA
    assert export["limitation"] == suite.PUBLIC_EXPORT_LIMITATION
    assert "OS sandbox or separate trust domain" in export["limitation"]
    assert set(export["payload"]) == {
        "canonicalization",
        "file_count",
        "total_size",
        "tree_sha256",
    }
    assert "files" not in export["payload"]

    inventory = inventory_regular_files(public_export)
    expected = {"public.json"}
    for entry in document["scenarios"]:
        expected.update(
            f"scenarios/{entry['scenario_id']}/{relative}" for relative in entry["artifacts"]
        )
    assert {file.relative_path for file in inventory} == expected
    assert export["payload"]["file_count"] == len(expected) - 1
    assert export["payload"]["total_size"] == sum(
        file.path.stat().st_size for file in inventory if file.relative_path != "public.json"
    )

    rendered = raw.decode()
    for answer_path in sorted((evaluator / "_answers").glob("*.json")):
        answers = json.loads(answer_path.read_text())["answers"]
        for value in answers.values():
            assert str(value) not in rendered


def test_public_export_modes_are_read_only_and_independent_of_umask(tmp_path, evaluator):
    if os.name == "nt":
        pytest.skip("POSIX mode assertions do not apply on Windows")
    public = tmp_path / "mode-export"
    previous_umask = os.umask(0)
    try:
        suite.export_public(os.fspath(evaluator), os.fspath(public))
    finally:
        os.umask(previous_umask)
    try:
        assert suite.load_public_export(os.fspath(public))["schema"] == suite.PUBLIC_DOCUMENT_SCHEMA
        for current, directories, files in os.walk(public):
            assert stat.S_IMODE(Path(current).stat().st_mode) == 0o555
            for directory in directories:
                assert stat.S_IMODE((Path(current) / directory).stat().st_mode) == 0o555
            for filename in files:
                assert stat.S_IMODE((Path(current) / filename).stat().st_mode) == 0o444
    finally:
        _thaw_public_export(public)


def test_parent_escape_reads_answers_from_evaluator_but_not_public_export(evaluator, public_export):
    _private, evaluator_tasks = cli._load_suite(os.fspath(evaluator), role="evaluator")

    def escaped_answers(task):
        return json.loads(
            (Path(task.directory) / ".." / ".." / "_answers" / f"{task.scenario_id}.json")
            .resolve()
            .read_text()
        )["answers"]

    assert escaped_answers(evaluator_tasks[0])
    with frozen_public_tasks(public_export) as (_public, solver_tasks):
        with pytest.raises(FileNotFoundError):
            escaped_answers(solver_tasks[0])


def test_cli_cannot_return_solver_tasks_after_the_frozen_context_closes(public_export):
    with pytest.raises(ValueError, match=r"inside frozen_public_tasks\(\)"):
        cli._load_suite(os.fspath(public_export), role="solver")


def test_frozen_public_tasks_are_detached_from_later_export_mutation(
    public_export,
):
    source_artifact = _first_artifact(public_export)
    relative = source_artifact.relative_to(public_export)
    original = source_artifact.read_bytes()

    with frozen_public_tasks(public_export) as (document, tasks):
        snapshot_root = Path(tasks[0].directory).parents[1]
        snapshot_artifact = snapshot_root / relative
        task_directories = [Path(task.directory) for task in tasks]
        assert document == suite.load_public_export(os.fspath(public_export))
        assert snapshot_root != public_export
        assert all(directory.is_relative_to(snapshot_root) for directory in task_directories)
        assert all(not directory.is_relative_to(public_export) for directory in task_directories)
        assert snapshot_artifact.read_bytes() == original

        _thaw_public_export(public_export)
        source_artifact.write_bytes(bytes([original[0] ^ 1]) + original[1:])

        assert snapshot_artifact.read_bytes() == original
        assert all(len(reference_solve(task)) == 5 for task in tasks)

    assert not snapshot_root.exists()


def test_same_path_byte_tamper_breaks_aggregate_commitment(public_export):
    _thaw_public_export(public_export)
    artifact = _first_artifact(public_export)
    original = artifact.read_bytes()
    artifact.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    with pytest.raises(ValueError, match="aggregate payload commitment"):
        suite.load_public_export(os.fspath(public_export))


def test_missing_artifact_is_rejected(public_export):
    _thaw_public_export(public_export)
    _first_artifact(public_export).unlink()
    with pytest.raises(ValueError, match="missing:"):
        suite.load_public_export(os.fspath(public_export))


def test_extra_artifact_is_rejected(public_export):
    _thaw_public_export(public_export)
    extra = next((public_export / "scenarios").iterdir()) / ".hidden" / "extra"
    extra.parent.mkdir()
    extra.write_bytes(b"extra")
    with pytest.raises(ValueError, match="extra:"):
        suite.load_public_export(os.fspath(public_export))


def test_symlinked_artifact_is_rejected(public_export, tmp_path):
    _thaw_public_export(public_export)
    artifact = _first_artifact(public_export)
    target = tmp_path / "outside"
    target.write_bytes(artifact.read_bytes())
    artifact.unlink()
    try:
        artifact.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")
    with pytest.raises(ValueError, match="safe exact public export:.*symlink"):
        suite.load_public_export(os.fspath(public_export))


def test_public_json_must_remain_canonical(public_export):
    _thaw_public_export(public_export)
    public = public_export / "public.json"
    public.write_bytes(public.read_bytes() + b" ")
    with pytest.raises(ValueError, match="not canonical"):
        suite.load_public_export(os.fspath(public_export))


def test_solver_public_document_obeys_the_declared_byte_limit(public_export, monkeypatch):
    size = (public_export / "public.json").stat().st_size
    monkeypatch.setattr(suite, "BENCHMARK_PUBLIC_JSON_MAX_BYTES", size - 1)
    with pytest.raises(ValueError, match="solver public.json exceeds.*input limit"):
        suite.load_public_export(os.fspath(public_export))


@pytest.mark.parametrize("location", ["question", "selector"])
def test_solver_loader_refuses_private_answer_fields_even_with_rebound_suite_id(
    public_export, location
):
    def disclose(document):
        question = document["scenarios"][0]["questions"][0]
        target = question if location == "question" else question["selector"]
        target["expected"] = "answer-material"

    _rewrite_with_bound_suite_id(public_export / "public.json", disclose)
    with pytest.raises(ValueError, match="public question schema|selector must contain only"):
        suite.load_public_export(os.fspath(public_export))


def test_evaluator_loader_rechecks_v2_aggregate_against_source_bytes(evaluator):
    # Prefetch is intentionally outside either closed answer rule, so changing it yields a
    # second structurally valid evaluator document without changing artifact-derived truth.
    artifact = next((evaluator / "scenarios").rglob("*.pf"))
    original = artifact.read_bytes()
    artifact.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    with pytest.raises(ValueError, match="aggregate payload commitment"):
        suite.load_evaluator_public(os.fspath(evaluator))


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_export_refuses_every_preexisting_destination(tmp_path, evaluator, kind):
    output = tmp_path / "occupied"
    if kind == "file":
        output.write_bytes(b"preserve")
    elif kind == "directory":
        output.mkdir()
        (output / "preserve").write_bytes(b"preserve")
    else:
        target = tmp_path / "target"
        target.mkdir()
        try:
            output.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"platform cannot create symlink: {exc}")

    with pytest.raises(ValueError, match="pre-existing public export destination"):
        suite.export_public(os.fspath(evaluator), os.fspath(output))
    if kind == "file":
        assert output.read_bytes() == b"preserve"
    elif kind == "directory":
        assert (output / "preserve").read_bytes() == b"preserve"
    else:
        assert output.is_symlink()


def test_export_must_be_disjoint_from_evaluator(evaluator):
    with pytest.raises(ValueError, match="must be disjoint"):
        suite.export_public(
            os.fspath(evaluator),
            os.fspath(evaluator / "solver-view"),
        )


def test_expected_document_binds_cli_validation_to_export_capture(evaluator, tmp_path):
    expected = suite.load_evaluator_public(os.fspath(evaluator))
    public_path = evaluator / "public.json"
    # Prefetch is outside either answer resolver, so this remains a valid evaluator while
    # changing the aggregate public document captured by the CLI.
    artifact = next((evaluator / "scenarios").rglob("*.pf"))
    original = artifact.read_bytes()
    artifact.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    changed = json.loads(public_path.read_text())
    base = {
        key: value
        for key, value in changed.items()
        if key not in {"public_export", "schema", "suite_id"}
    }
    changed = suite.build_public_document(base, evaluator / "scenarios")
    public_path.write_bytes(suite.canonical_public_bytes(changed))

    output = tmp_path / "must-not-publish"
    with pytest.raises(ValueError, match="changed after CLI validation"):
        suite.export_public(
            os.fspath(evaluator),
            os.fspath(output),
            expected_document=expected,
        )
    assert not output.exists()


def test_cli_export_and_role_refusals(tmp_path, evaluator, capsys):
    public = tmp_path / "public-cli"
    assert cli.main(["bench", "export", os.fspath(evaluator), os.fspath(public)]) == 0
    output = capsys.readouterr().out
    assert "LIMITATION:" in output
    assert suite.PUBLIC_EXPORT_LIMITATION in output

    with pytest.raises(ValueError, match="exact public export|evaluator-private"):
        cli.main(
            [
                "bench",
                "solve",
                os.fspath(evaluator),
                "--out",
                os.fspath(tmp_path / "submission.jsonl"),
            ]
        )
    with pytest.raises(ValueError, match="evaluator root is unsafe|_answers"):
        cli.main(
            [
                "bench",
                "grade",
                os.fspath(public),
                "--submission",
                os.fspath(tmp_path / "submission.jsonl"),
            ]
        )
    with pytest.raises(ValueError, match="outside the public export"):
        cli.main(
            [
                "bench",
                "solve",
                os.fspath(public),
                "--out",
                os.fspath(public / "submission.jsonl"),
            ]
        )


def test_cli_export_solve_grade_round_trip(tmp_path, evaluator, capsys):
    public = tmp_path / "public-round-trip"
    submission = tmp_path / "submission.jsonl"

    assert cli.main(["bench", "export", os.fspath(evaluator), os.fspath(public)]) == 0
    capsys.readouterr()
    assert (
        cli.main(
            [
                "bench",
                "solve",
                os.fspath(public),
                "--out",
                os.fspath(submission),
            ]
        )
        == 0
    )
    capsys.readouterr()
    rows = [json.loads(line) for line in submission.read_text().splitlines()]
    if os.name != "nt":
        assert stat.S_IMODE(submission.stat().st_mode) == 0o600
    document = suite.load_public_export(os.fspath(public))
    assert rows
    assert {row["suite_id"] for row in rows} == {document["suite_id"]}

    assert (
        cli.main(
            [
                "bench",
                "grade",
                os.fspath(evaluator),
                "--submission",
                os.fspath(submission),
            ]
        )
        == 0
    )
    grade_output = capsys.readouterr().out
    assert (
        "RAW SCORE (HOLDOUT - LEGACY V2 LOCAL PROTOCOL; NOT REPORTABLE): "
        "10/10 = 100.0%" in grade_output
    )
    assert f"suite_id: {document['suite_id']}" in grade_output
    assert "population: 2 scenarios / 10 questions" in grade_output
    assert "later attestation cannot promote it" in grade_output
    assert "\n  SCORE:" not in grade_output


def test_submission_suite_id_is_required_and_cross_suite_rows_are_refused(tmp_path):
    evaluator_a = tmp_path / "evaluator-a"
    evaluator_b = tmp_path / "evaluator-b"
    generate_suite(1, os.fspath(evaluator_a), key=bytes.fromhex("81" * 32), kind="holdout")
    generate_suite(1, os.fspath(evaluator_b), key=bytes.fromhex("82" * 32), kind="holdout")
    public_a = suite.load_evaluator_public(os.fspath(evaluator_a))

    submission = tmp_path / "submission.jsonl"
    scenario_b = json.loads((evaluator_b / "public.json").read_text())["scenarios"][0]
    submission.write_text(
        json.dumps(
            {
                "suite_id": public_a["suite_id"],
                "scenario_id": scenario_b["scenario_id"],
                "answers": {},
            }
        )
        + "\n"
    )
    with pytest.raises(ValueError, match="suite_id does not match"):
        cli.main(
            [
                "bench",
                "grade",
                os.fspath(evaluator_b),
                "--submission",
                os.fspath(submission),
            ]
        )

    submission.write_text(
        json.dumps(
            {
                "suite_id": public_a["suite_id"],
                "scenario_id": scenario_b["scenario_id"],
                "answers": {},
            }
        )
        + "\n"
    )
    with pytest.raises(ValueError, match="scenario_id is not in evaluator suite"):
        cli.main(
            [
                "bench",
                "grade",
                os.fspath(evaluator_a),
                "--submission",
                os.fspath(submission),
            ]
        )

    submission.write_text(
        json.dumps(
            {
                "scenario_id": scenario_b["scenario_id"],
                "answers": {},
            }
        )
        + "\n"
    )
    with pytest.raises(ValueError, match="contain exactly answers/scenario_id/suite_id"):
        cli.main(
            [
                "bench",
                "grade",
                os.fspath(evaluator_b),
                "--submission",
                os.fspath(submission),
            ]
        )


def test_grader_refuses_duplicate_scenario_rows(tmp_path):
    evaluator = tmp_path / "evaluator"
    generate_suite(1, os.fspath(evaluator), key=bytes.fromhex("91" * 32), kind="holdout")
    document = suite.load_evaluator_public(os.fspath(evaluator))
    row = {
        "suite_id": document["suite_id"],
        "scenario_id": document["scenarios"][0]["scenario_id"],
        "answers": json.loads(next((evaluator / "_answers").glob("*.json")).read_text())["answers"],
    }
    submission = tmp_path / "duplicate.jsonl"
    submission.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="duplicates scenario_id"):
        cli.main(
            [
                "bench",
                "grade",
                os.fspath(evaluator),
                "--submission",
                os.fspath(submission),
            ]
        )


def test_submission_strict_json_rejects_duplicate_members(tmp_path, evaluator):
    row = _valid_submission_row(evaluator)
    submission = tmp_path / "duplicate-member.jsonl"
    outer = json.dumps(row)[:-1] + f',"suite_id":{json.dumps(row["suite_id"])}' + "}\n"
    with pytest.raises(ValueError, match="duplicate object member"):
        _grade_payload(evaluator, submission, outer.encode())

    first_id, first_value = next(iter(row["answers"].items()))
    answers = json.dumps(row["answers"])
    answers = answers[:-1] + f",{json.dumps(first_id)}:{json.dumps(first_value)}" + "}"
    nested = (
        '{"answers":'
        + answers
        + ',"scenario_id":'
        + json.dumps(row["scenario_id"])
        + ',"suite_id":'
        + json.dumps(row["suite_id"])
        + "}\n"
    )
    with pytest.raises(ValueError, match="duplicate object member"):
        _grade_payload(evaluator, submission, nested.encode())


@pytest.mark.parametrize(
    "invalid,match",
    (
        (b'{"answers":NaN,"scenario_id":"x","suite_id":"x"}\n', "non-finite"),
        (b'{"answers":1.5,"scenario_id":"x","suite_id":"x"}\n', "floating-point"),
        (
            '{"answers":{"q":"e\\u0301"},"scenario_id":"x","suite_id":"x"}\n'.encode(),
            "not Unicode NFC",
        ),
        (
            b'{"answers":{"q":"\\ud800"},"scenario_id":"x","suite_id":"x"}\n',
            "invalid JSON value",
        ),
    ),
)
def test_submission_strict_json_rejects_unsupported_values(tmp_path, evaluator, invalid, match):
    with pytest.raises(ValueError, match=match):
        _grade_payload(evaluator, tmp_path / "invalid.jsonl", invalid)


@pytest.mark.parametrize(
    "mutation,match",
    (
        ("unknown-row", "contain exactly answers/scenario_id/suite_id"),
        ("unknown-answer", "scenario's five question ids"),
        ("missing-answer", "scenario's five question ids"),
        ("non-string-answer", "answer values must be strings"),
        ("non-string-suite", "suite_id does not match"),
        ("unhashable-scenario", "scenario_id is not in evaluator suite"),
    ),
)
def test_submission_schema_is_exact_and_type_bounded(tmp_path, evaluator, mutation, match):
    row = _valid_submission_row(evaluator)
    if mutation == "unknown-row":
        row["extra"] = "field"
    elif mutation == "unknown-answer":
        row["answers"]["unknown"] = "value"
    elif mutation == "missing-answer":
        row["answers"].pop(next(iter(row["answers"])))
    elif mutation == "non-string-answer":
        row["answers"][next(iter(row["answers"]))] = 1
    elif mutation == "non-string-suite":
        row["suite_id"] = 1
    else:
        row["scenario_id"] = []
    with pytest.raises(ValueError, match=match):
        _grade_payload(
            evaluator,
            tmp_path / f"{mutation}.jsonl",
            (json.dumps(row, ensure_ascii=False) + "\n").encode(),
        )


def test_submission_resource_limits_and_blank_lines_fail_closed(tmp_path, evaluator, monkeypatch):
    row = _valid_submission_row(evaluator)
    payload = (json.dumps(row) + "\n").encode()
    submission = tmp_path / "bounded.jsonl"

    monkeypatch.setattr(cli, "_MAX_SUBMISSION_BYTES", len(payload) - 1)
    with pytest.raises(ValueError, match="byte input limit"):
        _grade_payload(evaluator, submission, payload)
    monkeypatch.setattr(cli, "_MAX_SUBMISSION_BYTES", 16 * 1024 * 1024)

    monkeypatch.setattr(cli, "_MAX_SUBMISSION_LINE_BYTES", len(payload) - 2)
    with pytest.raises(ValueError, match="submission line 1 exceeds"):
        _grade_payload(evaluator, submission, payload)
    monkeypatch.setattr(cli, "_MAX_SUBMISSION_LINE_BYTES", 1024 * 1024)

    monkeypatch.setattr(cli, "_MAX_SUBMISSION_ANSWER_CHARS", 1)
    with pytest.raises(ValueError, match="no longer than 1 characters"):
        _grade_payload(evaluator, submission, payload)
    monkeypatch.setattr(cli, "_MAX_SUBMISSION_ANSWER_CHARS", 4096)

    monkeypatch.setattr(cli, "_MAX_SUBMISSION_ROWS", 1)
    with pytest.raises(ValueError, match="1-row input limit"):
        _grade_payload(evaluator, submission, payload + payload)
    monkeypatch.setattr(cli, "_MAX_SUBMISSION_ROWS", suite.BENCHMARK_MAX_SCENARIOS)

    with pytest.raises(ValueError, match="line 1 must not be blank"):
        _grade_payload(evaluator, submission, b"\n" + payload)


def test_submission_requires_every_scenario_row(tmp_path):
    evaluator = tmp_path / "two-scenario-evaluator"
    generate_suite(2, os.fspath(evaluator), key=bytes.fromhex("93" * 32), kind="holdout")
    row = _valid_submission_row(evaluator, 0)
    with pytest.raises(ValueError, match="submission is missing scenario rows"):
        _grade_payload(
            evaluator,
            tmp_path / "partial.jsonl",
            (json.dumps(row) + "\n").encode(),
        )


def test_submission_must_be_a_regular_unlinked_file(tmp_path, evaluator):
    target = tmp_path / "target.jsonl"
    target.write_text("{}\n")
    link = tmp_path / "link.jsonl"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")
    with pytest.raises(ValueError, match="regular file, not a link or special file"):
        cli.main(["bench", "grade", os.fspath(evaluator), "--submission", os.fspath(link)])

    directory = tmp_path / "submission-directory"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular file, not a link or special file"):
        cli.main(
            [
                "bench",
                "grade",
                os.fspath(evaluator),
                "--submission",
                os.fspath(directory),
            ]
        )


def test_solver_refuses_preexisting_submission_without_touching_it(tmp_path, public_export):
    submission = tmp_path / "occupied.jsonl"
    submission.write_bytes(b"preserve")
    with pytest.raises(ValueError, match="cannot publish solver submission safely"):
        cli.main(
            [
                "bench",
                "solve",
                os.fspath(public_export),
                "--out",
                os.fspath(submission),
            ]
        )
    assert submission.read_bytes() == b"preserve"


def test_solver_output_must_be_outside_public_export(public_export):
    submission = public_export / "answers.jsonl"
    with pytest.raises(ValueError, match="outside the public export"):
        cli.main(
            [
                "bench",
                "solve",
                os.fspath(public_export),
                "--out",
                os.fspath(submission),
            ]
        )
    assert not submission.exists()


def test_solver_output_rejects_case_insensitive_public_export_alias(public_export):
    alias = public_export.with_name(public_export.name.swapcase())
    try:
        aliases_export = alias.exists() and os.path.samefile(alias, public_export)
    except OSError:
        aliases_export = False
    if not aliases_export:
        pytest.skip("test filesystem is case-sensitive")

    submission = alias / "answers.jsonl"
    with pytest.raises(ValueError, match="outside the public export"):
        cli.main(
            [
                "bench",
                "solve",
                os.fspath(public_export),
                "--out",
                os.fspath(submission),
            ]
        )
    assert not submission.exists()


@pytest.mark.parametrize(
    ("move_inside_export", "message"),
    [
        (True, "outside the public export"),
        (False, "parent path changed during the operation"),
    ],
)
def test_solver_rechecks_output_parent_after_solving(
    tmp_path,
    public_export,
    monkeypatch,
    move_inside_export,
    message,
):
    output_parent = tmp_path / "solver-output"
    output_parent.mkdir()
    submission = output_parent / "answers.jsonl"
    moved_parent = (
        public_export / "moved-solver-output"
        if move_inside_export
        else tmp_path / "renamed-solver-output"
    )
    original = reference_solve
    moved = False

    def move_parent_during_solve(task):
        nonlocal moved
        if not moved:
            if move_inside_export:
                _thaw_public_export(public_export)
            output_parent.rename(moved_parent)
            moved = True
        return original(task)

    monkeypatch.setattr(
        "artifactforge.bench.reference_solver.reference_solve",
        move_parent_during_solve,
    )
    with pytest.raises(ValueError, match=message):
        cli.main(
            [
                "bench",
                "solve",
                os.fspath(public_export),
                "--out",
                os.fspath(submission),
            ]
        )
    assert moved
    assert not (moved_parent / submission.name).exists()


def test_copying_export_preserves_suite_identity(tmp_path, public_export):
    copy = tmp_path / "copy"
    shutil.copytree(public_export, copy)
    first = suite.load_public_export(os.fspath(public_export))
    second = suite.load_public_export(os.fspath(copy))
    assert first["suite_id"] == second["suite_id"]
    assert first["public_export"]["payload"] == second["public_export"]["payload"]


def test_pinned_public_loader_validates_held_export_after_path_replacement(
    tmp_path,
    public_export,
):
    expected = suite.load_public_export(os.fspath(public_export))
    public_fd = open_real_directory(public_export)
    moved = tmp_path / "held-public"
    try:
        public_export.rename(moved)
        public_export.mkdir()
        observed = suite.load_public_export(
            os.fspath(public_export),
            pinned_root_fd=public_fd,
        )
    finally:
        os.close(public_fd)
    assert observed == expected


def test_evaluator_loader_rejects_public_dev_key_relabelled_as_holdout(tmp_path):
    evaluator = tmp_path / "relabelled"
    generate_suite(1, os.fspath(evaluator), key=suite.PUBLIC_DEV_KEY, kind="dev")

    def relabel(document):
        document["suite_kind"] = "holdout"

    _rewrite_with_bound_suite_id(evaluator / "public.json", relabel)
    with pytest.raises(ValueError, match="holdout.*published reproducible key"):
        cli._load_suite(os.fspath(evaluator), role="evaluator")


def test_evaluator_loader_rejects_answer_value_not_derived_from_artifacts(evaluator):
    answer_path = next((evaluator / "_answers").glob("*.json"))
    document = json.loads(answer_path.read_text())
    question_id = next(iter(document["answers"]))
    document["answers"][question_id] = "0" * 64
    answer_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="do not equal artifact-derived closed-rule truth"):
        cli._load_suite(os.fspath(evaluator), role="evaluator")


def test_evaluator_answer_values_fit_the_submission_contract(evaluator):
    answer_path = next((evaluator / "_answers").glob("*.json"))
    document = json.loads(answer_path.read_text())
    question_id = next(iter(document["answers"]))
    document["answers"][question_id] = "x" * (suite.BENCHMARK_ANSWER_MAX_CHARS + 1)
    answer_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="no longer than 4096 characters"):
        cli._load_suite(os.fspath(evaluator), role="evaluator")


def test_evaluator_answer_truth_uses_only_the_captured_snapshot(evaluator, monkeypatch):
    from artifactforge.bench import reference_solver

    original_resolve = reference_solver.resolve_task
    live_artifact = next((evaluator / "scenarios").rglob("*.exe"))
    original_bytes = live_artifact.read_bytes()
    observed_directories = []

    def mutate_live_after_capture(task):
        observed_directories.append(Path(task.directory))
        if len(observed_directories) == 1:
            live_artifact.write_bytes(bytes([original_bytes[0] ^ 1]) + original_bytes[1:])
        return original_resolve(task)

    monkeypatch.setattr(reference_solver, "resolve_task", mutate_live_after_capture)
    document = suite.load_evaluator_public(os.fspath(evaluator))

    assert document["scenarios"]
    assert live_artifact.read_bytes() != original_bytes
    assert observed_directories
    assert all(
        "artifactforge-evaluator-snapshot-" in os.fspath(path) for path in observed_directories
    )
    assert all(not path.is_relative_to(evaluator) for path in observed_directories)


@pytest.mark.parametrize(
    "mutate,match",
    (
        (
            lambda document: document["scenarios"][0]["questions"].pop(),
            "exactly 5 questions",
        ),
        (
            lambda document: document["scenarios"][0]["questions"][0].update(
                {"candidate_count": 4}
            ),
            "candidate_count.*exactly 5",
        ),
        (
            lambda document: document["scenarios"][0]["questions"][0].update(
                {"prompt": "plausible but non-canonical"}
            ),
            "canonical closed-rule prompt",
        ),
        (
            lambda document: document["scenarios"][0]["questions"][1].update(
                {
                    "selector": dict(document["scenarios"][0]["questions"][0]["selector"]),
                    "prompt": document["scenarios"][0]["questions"][0]["prompt"],
                }
            ),
            "five unique selectors",
        ),
    ),
)
def test_public_loader_enforces_exact_five_by_five_closed_schema(public_export, mutate, match):
    _rewrite_with_bound_suite_id(public_export / "public.json", mutate)
    with pytest.raises(ValueError, match=match):
        suite.load_public_export(os.fspath(public_export))


def test_generate_suite_refuses_preexisting_destination_without_touching_it(tmp_path):
    destination = tmp_path / "occupied"
    destination.mkdir()
    sentinel = destination / "preserve"
    sentinel.write_bytes(b"preserve")

    with pytest.raises(ValueError, match="pre-existing evaluator suite destination"):
        generate_suite(
            1,
            os.fspath(destination),
            key=bytes.fromhex("73" * 32),
            kind="holdout",
        )
    assert sentinel.read_bytes() == b"preserve"
    assert sorted(path.name for path in destination.iterdir()) == ["preserve"]


def test_fresh_evaluator_private_material_has_private_modes(evaluator):
    if os.name == "nt":
        pytest.skip("POSIX mode assertions do not apply on Windows")

    assert stat.S_IMODE(evaluator.stat().st_mode) == 0o700
    for directory in (evaluator / "_answers", evaluator / "_content", evaluator / "_key"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    private_files = [
        evaluator / "public.json",
        evaluator / "_key" / "key.hex",
        *(evaluator / "_answers").glob("*.json"),
        *(evaluator / "_content").iterdir(),
    ]
    assert private_files
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in private_files)


@pytest.mark.parametrize("bounded_input", ("public", "key", "answer"))
def test_evaluator_private_documents_have_explicit_read_bounds(
    evaluator, monkeypatch, bounded_input
):
    if bounded_input == "public":
        size = (evaluator / "public.json").stat().st_size
        monkeypatch.setattr(suite, "BENCHMARK_PUBLIC_JSON_MAX_BYTES", size - 1)
        match = "evaluator public.json exceeds.*input limit"
    elif bounded_input == "key":
        size = (evaluator / "_key" / "key.hex").stat().st_size
        assert size == suite.BENCHMARK_KEY_HEX_BYTES
        monkeypatch.setattr(suite, "BENCHMARK_KEY_HEX_BYTES", size - 1)
        match = "evaluator key exceeds.*input limit"
    else:
        size = next((evaluator / "_answers").glob("*.json")).stat().st_size
        monkeypatch.setattr(suite, "BENCHMARK_ANSWER_FILE_MAX_BYTES", size - 1)
        match = "evaluator public or private inventory is unsafe:.*exceeds"

    with pytest.raises(ValueError, match=match):
        suite.load_evaluator_public(os.fspath(evaluator))


def test_submission_row_limit_is_the_suite_population_limit():
    assert cli._MAX_SUBMISSION_ROWS == suite.BENCHMARK_MAX_SCENARIOS
    assert cli._MAX_SUBMISSION_ANSWER_CHARS == suite.BENCHMARK_ANSWER_MAX_CHARS


@pytest.mark.parametrize(
    "encode",
    (
        lambda key: key,
        lambda key: key.hex().encode(),
        lambda key: key.hex().upper().encode(),
        base64.b64encode,
        base64.urlsafe_b64encode,
        base64.b32encode,
        lambda key: base64.b32encode(key).rstrip(b"="),
        lambda key: base64.b32encode(key).lower(),
        lambda key: base64.b32encode(key).rstrip(b"=").lower(),
    ),
)
def test_export_rejects_evaluator_key_encoded_inside_declared_artifact(tmp_path, evaluator, encode):
    key = bytes.fromhex((evaluator / "_key" / "key.hex").read_text())
    _declare_added_artifact(evaluator, "nested/key-leak.bin", encode(key))

    output = tmp_path / "must-not-export"
    with pytest.raises(ValueError, match="key material appears inside"):
        suite.export_public(os.fspath(evaluator), os.fspath(output))
    assert not output.exists()


def test_export_rejects_private_answer_document_under_artifact_alias(tmp_path, evaluator):
    private = next((evaluator / "_answers").glob("*.json")).read_bytes()
    _declare_added_artifact(evaluator, "nested/innocent-name.bin", private)

    output = tmp_path / "must-not-export"
    with pytest.raises(ValueError, match="answer document appears inside"):
        suite.export_public(os.fspath(evaluator), os.fspath(output))
    assert not output.exists()


def test_export_rejects_evaluator_key_encoded_in_public_selector(tmp_path, evaluator):
    public_path = evaluator / "public.json"
    document = json.loads(public_path.read_text())
    question = document["scenarios"][0]["questions"][0]
    leaked = (evaluator / "_key" / "key.hex").read_text()
    selector = {"lower_case_long_path": leaked}
    question["selector"] = selector
    question["prompt"] = suite.benchmark_question_prompt(question["rule"], selector)
    base = {
        key: value
        for key, value in document.items()
        if key not in {"public_export", "schema", "suite_id"}
    }
    rebound = suite.build_public_document(base, evaluator / "scenarios")
    public_path.write_bytes(suite.canonical_public_bytes(rebound))

    output = tmp_path / "must-not-export"
    with pytest.raises(ValueError, match="key material appears inside public.json"):
        suite.export_public(os.fspath(evaluator), os.fspath(output))
    assert not output.exists()


def test_aggregate_commitment_is_not_a_file_digest(public_export):
    document = suite.load_public_export(os.fspath(public_export))
    artifact = _first_artifact(public_export)
    aggregate = document["public_export"]["payload"]["tree_sha256"]
    assert aggregate != "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
