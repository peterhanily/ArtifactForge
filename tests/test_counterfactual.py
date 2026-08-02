# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Focused proof that Benchmark v2's claimed relation fields are actually necessary."""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
import hashlib
from pathlib import Path

import pytest

from artifactforge.bench import counterfactual
from artifactforge.bench.benchmark import generate_suite
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
    ("index", "family", "expected_total", "expected_mutations"),
    (
        (
            0,
            "windows",
            13,
            {
                "windows-fileid-swap": 3,
                "windows-fileid-absent": 5,
                "windows-resident-pe-replacement": 5,
            },
        ),
        (
            1,
            "macos",
            11,
            {
                "macos-xattr-uuid-swap": 3,
                "macos-database-uuid-swap": 3,
                "macos-xattr-uuid-absent": 5,
            },
        ),
    ),
)
def test_parser_valid_counterfactuals_bind_every_question(
    tmp_path, index, family, expected_total, expected_mutations
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
    assert _tree_digest(task.directory) == before, "counterfactuals must not edit the source"


def test_a_noop_pe_replacement_reddens_only_the_byte_necessity_checks(
    tmp_path, monkeypatch
):
    task = _tasks(tmp_path)[0]

    def unchanged(original, _question_id, _forbidden_sha1, _forbidden_sha256):
        return original

    monkeypatch.setattr(counterfactual, "_replacement_pe", unchanged)
    report = counterfactual.evaluate_counterfactuals(task.public())

    failed = [detail for detail in report.details if not detail.passed]
    assert not report.ok
    assert report.passed == 8
    assert report.total == 13
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
    report = counterfactual.evaluate_counterfactuals(public)

    assert report.ok
    assert report.passed == report.total == 13
