# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Focused proof that Benchmark v2's claimed relation fields are actually necessary."""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
import hashlib
from itertools import combinations
from pathlib import Path

import pytest

from artifactforge.bench import counterfactual
from artifactforge.bench.benchmark import generate_suite
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.gates import GateReport
from artifactforge.gates import solvability
from artifactforge.inventory import inventory_regular_files

pytest.importorskip("pefile")
pytest.importorskip("lief")
pytest.importorskip("regipy")
pytest.importorskip("pyregf")


KEY = bytes.fromhex("7c" * 32)


def _tasks(tmp_path):
    return generate_suite(2, str(tmp_path / "suite"), key=KEY, kind="holdout")


def _tree_digest(path: str) -> dict[str, str]:
    return {
        file.relative_path: hashlib.sha256(file.path.read_bytes()).hexdigest()
        for file in inventory_regular_files(path)
    }


@pytest.mark.parametrize(
    (
        "index",
        "family",
        "expected_total",
        "expected_mutations",
        "expected_relations",
        "expected_mapping_metrics",
    ),
    (
        (
            0,
            "windows",
            20,
            {
                "windows-fileid-swap": 10,
                "windows-fileid-absent": 5,
                "windows-resident-pe-replacement": 5,
            },
            {counterfactual.WINDOWS_FILEID_RELATION},
            {
                "mapping_relations_passed": 1,
                "mapping_relations_total": 1,
                "mapping_worlds_passed": 120,
                "mapping_worlds_total": 120,
                "mapping_parser_artifacts_passed": 120,
                "mapping_parser_artifacts_total": 120,
                "mapping_reference_questions_passed": 600,
                "mapping_reference_questions_total": 600,
                "mapping_attack_invariance_passed": 1320,
                "mapping_attack_invariance_total": 1320,
                "mapping_positive_control_questions_passed": 600,
                "mapping_positive_control_questions_total": 600,
                "mapping_positive_control_changes_passed": 119,
                "mapping_positive_control_changes_total": 119,
            },
        ),
        (
            1,
            "macos",
            25,
            {
                "macos-xattr-uuid-swap": 10,
                "macos-database-uuid-swap": 10,
                "macos-xattr-uuid-absent": 5,
            },
            {
                counterfactual.MACOS_XATTR_UUID_RELATION,
                counterfactual.MACOS_DATABASE_UUID_RELATION,
            },
            {
                "mapping_relations_passed": 2,
                "mapping_relations_total": 2,
                "mapping_worlds_passed": 240,
                "mapping_worlds_total": 240,
                "mapping_parser_artifacts_passed": 720,
                "mapping_parser_artifacts_total": 720,
                "mapping_reference_questions_passed": 1200,
                "mapping_reference_questions_total": 1200,
                "mapping_attack_invariance_passed": 2640,
                "mapping_attack_invariance_total": 2640,
                "mapping_positive_control_questions_passed": 1200,
                "mapping_positive_control_questions_total": 1200,
                "mapping_positive_control_changes_passed": 238,
                "mapping_positive_control_changes_total": 238,
            },
        ),
    ),
)
def test_parser_valid_counterfactuals_bind_every_question(
    tmp_path,
    index,
    family,
    expected_total,
    expected_mutations,
    expected_relations,
    expected_mapping_metrics,
):
    task = _tasks(tmp_path)[index]
    before = _tree_digest(task.directory)

    report = counterfactual.evaluate_counterfactuals(task.public())

    assert report.family == family
    assert report.ok
    assert report.passed == report.total == expected_total
    assert Counter(detail.mutation for detail in report.details) == expected_mutations
    assert all(len(detail.expected) == len(detail.observed) == 5 for detail in report.details)
    assert all(detail.error is None for detail in report.details)
    assert {target for detail in report.details for target in detail.targets} == {
        question.id for question in task.questions
    }
    question_ids = tuple(question.id for question in task.questions)
    swap_targets = {
        tuple(detail.targets)
        for detail in report.details
        if detail.mutation.endswith("-swap")
    }
    assert swap_targets == set(combinations(question_ids, 2))
    assert {mapping.relation for mapping in report.mapping_worlds} == expected_relations
    assert report.mapping_metric_counts() == expected_mapping_metrics
    for mapping in report.mapping_worlds:
        assert mapping.ok
        assert mapping.positive_control == counterfactual.MAPPING_POSITIVE_CONTROL
        assert mapping.attack_names == tuple(sorted(counterfactual.ADVERSARIES))
        assert len(mapping.details) == counterfactual.MAPPING_WORLD_COUNT
        assert len({detail.permutation for detail in mapping.details}) == 120
        assert mapping.details[0].permutation == (0, 1, 2, 3, 4)
        assert all(detail.passed for detail in mapping.details)
        assert all(len(detail.expected) == len(detail.observed) == 5 for detail in mapping.details)
        assert all(len(detail.positive_control_observed) == 5 for detail in mapping.details)
    assert _tree_digest(task.directory) == before, "counterfactuals must not edit the source"


def test_a_noop_pe_replacement_reddens_only_the_byte_necessity_checks(
    tmp_path, monkeypatch
):
    task = _tasks(tmp_path)[0]

    def unchanged(original, _question_id, _forbidden_sha1, _forbidden_sha256):
        return original

    monkeypatch.setattr(counterfactual, "_replacement_pe", unchanged)
    report = counterfactual.evaluate_counterfactuals(
        task.public(), include_mapping_worlds=False
    )

    failed = [detail for detail in report.details if not detail.passed]
    assert not report.ok
    assert report.passed == 15
    assert report.total == 20
    assert len(failed) == 5
    assert {detail.mutation for detail in failed} == {
        "windows-resident-pe-replacement"
    }
    assert all(detail.error is not None for detail in failed)


def test_counterfactuals_refuse_a_manifest_that_does_not_match_the_tree(tmp_path):
    task = _tasks(tmp_path)[0]
    public = task.public()
    public = replace(public, artifacts=public.artifacts[:-1])

    with pytest.raises(ValueError, match="inventory differs"):
        counterfactual.evaluate_counterfactuals(public)


def test_counterfactuals_are_recursive_layout_invariant(tmp_path):
    task = _tasks(tmp_path)[0]
    source = Path(task.directory)
    nested = source / ".evidence" / "nested"
    nested.mkdir(parents=True)
    prefix = ".evidence/nested/"
    for relative_path in task.artifacts:
        original = source.joinpath(*relative_path.split("/"))
        destination = nested / original.name
        original.rename(destination)

    public = replace(
        task.public(),
        artifacts=tuple(prefix + relative_path for relative_path in task.artifacts),
    )
    report = counterfactual.evaluate_counterfactuals(
        public, include_mapping_worlds=False
    )

    assert report.ok
    assert report.passed == report.total == 20


def test_a_relation_aware_attack_fails_exhaustive_invariance(tmp_path, monkeypatch):
    task = _tasks(tmp_path)[0]
    monkeypatch.setattr(
        counterfactual,
        "ADVERSARIES",
        {"declared_relation": reference_solve},
    )

    report = counterfactual.evaluate_counterfactuals(task.public())

    mapping = report.mapping_worlds[0]
    assert not report.ok
    assert mapping.passed == 1
    assert mapping.total == 120
    assert mapping.details[0].passed
    assert all(
        detail.attack_failures == ("declared_relation: output changed",)
        for detail in mapping.details[1:]
    )
    assert mapping.metric_counts()["mapping_attack_invariance_passed"] == 1
    assert mapping.metric_counts()["mapping_attack_invariance_total"] == 120


def test_gate4_bounds_exhaustive_worlds_to_three_representative_mechanisms(tmp_path):
    tasks = generate_suite(4, str(tmp_path / "gate-suite"), key=KEY, kind="holdout")
    gate = GateReport(4, "solvability", "counterfactual contract")

    assert solvability._counterfactual_contract(
        gate, [task.public() for task in tasks]
    )

    assert gate.ok, gate.fails
    assert gate.metrics["counterfactual_checks_passed"] == 90
    assert gate.metrics["counterfactual_checks_total"] == 90
    assert gate.metrics["counterfactual_windows_total"] == 40
    assert gate.metrics["counterfactual_macos_total"] == 50
    assert gate.metrics["counterfactual_source_trees_passed"] == 4
    assert gate.metrics["counterfactual_source_trees_total"] == 4
    assert gate.metrics["mapping_world_representative_scenes_total"] == 2
    assert gate.metrics["mapping_world_representative_mechanisms_total"] == 3
    assert gate.metrics["mapping_relations_passed"] == 3
    assert gate.metrics["mapping_relations_total"] == 3
    assert gate.metrics["mapping_worlds_passed"] == 360
    assert gate.metrics["mapping_worlds_total"] == 360
    assert gate.metrics["mapping_parser_artifacts_passed"] == 840
    assert gate.metrics["mapping_parser_artifacts_total"] == 840
    assert gate.metrics["mapping_reference_questions_passed"] == 1800
    assert gate.metrics["mapping_reference_questions_total"] == 1800
    assert gate.metrics["mapping_attack_invariance_passed"] == 3960
    assert gate.metrics["mapping_attack_invariance_total"] == 3960
    assert gate.metrics["mapping_positive_control_questions_passed"] == 1800
    assert gate.metrics["mapping_positive_control_questions_total"] == 1800
    assert gate.metrics["mapping_positive_control_changes_passed"] == 357
    assert gate.metrics["mapping_positive_control_changes_total"] == 357
    for relation in (
        counterfactual.WINDOWS_FILEID_RELATION,
        counterfactual.MACOS_XATTR_UUID_RELATION,
        counterfactual.MACOS_DATABASE_UUID_RELATION,
    ):
        stem = relation.replace("-", "_")
        assert gate.metrics[f"mapping_world_{stem}_passed"] == 120
        assert gate.metrics[f"mapping_world_{stem}_total"] == 120
