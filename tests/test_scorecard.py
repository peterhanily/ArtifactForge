# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The committed fidelity scorecard must stay valid, honest, and leak nothing local.

CI cannot always recompute the scorecard — some oracles are platform-bound — so it guards the
committed artifact instead. These are the three properties that make guarding it worthwhile.
"""

import hashlib
import json
import math
import os
import stat
import subprocess
import tomllib
from copy import deepcopy
from types import SimpleNamespace

import pytest

from artifactforge import __version__, suite
from artifactforge import cli as cli_module
from artifactforge.gates import GateReport
from artifactforge.scorecard import (
    BENCHMARK_VALIDITY_GATES,
    GENERATOR_ASSURANCE_GATES,
    _MEASUREMENT_IDENTITY,
    _METRICS,
    SCORECARD_MAX_BYTES,
    SCHEMA_VERSION,
    ScorecardError,
    ScorecardPublicationUncertain,
    build_scorecard,
    load,
    measurement_incompatibilities,
    regressions,
    save,
    scorecard_structure_errors,
    status_regressions,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARD_PATH = os.path.join(ROOT, "fidelity-scorecard.json")


@pytest.fixture(scope="module")
def card():
    return load(CARD_PATH)


def test_committed_scorecard_is_schema_valid(card):
    assert card["schema_version"] == SCHEMA_VERSION
    assert set(card["gates"]) == {"validity", "identity", "inertness", "solvability"}
    for name, block in card["gates"].items():
        assert block["verdict"] in ("pass", "fail"), name
        assert isinstance(block["fails"], list) and isinstance(block["gaps"], list), name
    assert card["verdict"] in ("pass", "gap", "fail")
    assert card["verdict_scope"] == "all_gates"

    assert set(card["status"]) == {"generator_assurance", "benchmark_validity"}
    for name, block in card["status"].items():
        assert block["verdict"] in ("pass", "gap", "fail"), name
        assert isinstance(block["experimental"], bool), name
        assert isinstance(block["gates"], list) and block["gates"], name
        assert isinstance(block["fails"], list) and isinstance(block["gaps"], list), name


def test_status_scopes_partition_generator_from_experimental_benchmark(card):
    generator = card["status"]["generator_assurance"]
    benchmark = card["status"]["benchmark_validity"]

    assert generator["gates"] == list(GENERATOR_ASSURANCE_GATES)
    assert benchmark["gates"] == list(BENCHMARK_VALIDITY_GATES)
    assert set(generator["gates"]).isdisjoint(benchmark["gates"])
    assert set(generator["gates"] + benchmark["gates"]) == set(card["gates"])
    assert generator["experimental"] is False
    assert benchmark["experimental"] is True

    # Gate 4 is solvability. "Validity" is Gate 1 and remains generator assurance.
    assert benchmark["gates"] == ["solvability"]
    assert "validity" in generator["gates"]


def test_committed_status_records_a_passing_v2_benchmark_and_generator(card):
    generator = card["status"]["generator_assurance"]
    benchmark = card["status"]["benchmark_validity"]

    assert generator["verdict"] == "pass"
    assert not generator["fails"]
    assert not generator["gaps"]
    assert benchmark["verdict"] == "pass"
    assert not benchmark["fails"]
    assert not benchmark["gaps"]
    assert card["gates"]["solvability"]["verdict"] == "pass"


def test_build_scorecard_preserves_legacy_aggregate_verdict_while_splitting_status():
    reports = [
        GateReport(1, "validity", "validity"),
        GateReport(2, "identity", "identity"),
        GateReport(3, "inertness", "inertness"),
        GateReport(4, "solvability", "solvability"),
    ]
    reports[0].gap("one declared generator limitation")
    reports[3].fail("one measured benchmark shortcut")

    built = build_scorecard(
        reports,
        artifactforge_version="test",
        git_commit="test",
        sqlite_version="test",
    )

    assert built["status"]["generator_assurance"]["verdict"] == "gap"
    assert built["status"]["benchmark_validity"]["verdict"] == "fail"
    assert built["verdict"] == "fail"
    assert built["verdict_scope"] == "all_gates"


def _release_reports(*, generator_gap: bool = False, benchmark_fail: bool = False):
    reports = [
        GateReport(1, "validity", "validity"),
        GateReport(2, "identity", "identity"),
        GateReport(3, "inertness", "inertness"),
        GateReport(4, "solvability", "solvability"),
    ]
    if generator_gap:
        reports[0].gap("stable pre-existing generator gap")
    if benchmark_fail:
        reports[3].fail("registered shortcut detected")
    return reports


def _release_card(*, generator_gap: bool = False, benchmark_fail: bool = False):
    return build_scorecard(
        _release_reports(
            generator_gap=generator_gap,
            benchmark_fail=benchmark_fail,
        ),
        artifactforge_version="test",
        git_commit="test",
        sqlite_version="test",
        measurement=suite.scorecard_measurement_provenance(40),
    )


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    (
        (lambda reports: reports.pop(), "missing"),
        (lambda reports: reports.append(reports[-1]), "duplicated"),
        (
            lambda reports: setattr(reports[-1], "name", "not-a-gate"),
            "unknown gate name",
        ),
        (lambda reports: setattr(reports[-1], "gate", 3), "expected 4"),
    ),
)
def test_build_scorecard_requires_one_exactly_numbered_report_per_gate(mutate, fragment):
    reports = _release_reports()
    mutate(reports)

    with pytest.raises(ScorecardError, match=fragment):
        build_scorecard(
            reports,
            artifactforge_version="test",
            git_commit="test",
            sqlite_version="test",
        )


def test_scoped_status_order_blocks_deterioration_and_every_current_failure():
    passing = _release_card()
    gap = _release_card(generator_gap=True)
    failing = _release_card(benchmark_fail=True)

    assert status_regressions(passing, passing) == []
    assert status_regressions(gap, gap) == []
    assert (
        "generator assurance",
        "regressed",
        "pass",
        "gap",
    ) in status_regressions(passing, gap)
    assert (
        "benchmark validity",
        "failing",
        "pass",
        "fail",
    ) in status_regressions(passing, failing)
    assert (
        "benchmark validity",
        "failing",
        "fail",
        "fail",
    ) in status_regressions(failing, failing)


@pytest.mark.parametrize(
    ("mutation", "fragment"),
    (
        (
            lambda card: card["status"].pop("benchmark_validity"),
            "status must contain exactly",
        ),
        (lambda card: card["gates"].pop("solvability"), "gates must contain exactly"),
        (
            lambda card: card["status"]["generator_assurance"].update({"gates": ["validity"]}),
            "generator_assurance.gates",
        ),
        (
            lambda card: card["gates"]["validity"].update(
                {"verdict": "pass", "fails": ["hidden failure"]}
            ),
            "fails list requires 'fail'",
        ),
        (lambda card: card.update({"schema_version": "old"}), "schema_version"),
        (lambda card: card.update({"honest_gaps": "hidden"}), "honest_gaps"),
        (lambda card: card.update({"verdict": "gap"}), "honest_gaps require 'pass'"),
        (lambda card: card.update({"verdict_scope": "some_gates"}), "verdict_scope"),
        (
            lambda card: (
                card.update({"honest_gaps": [], "verdict": "pass"}),
                card["status"]["generator_assurance"].update(
                    {
                        "verdict": "gap",
                        "gaps": ["Gate 1 (validity): concealed gap"],
                    }
                ),
                card["gates"]["validity"].update({"gaps": ["concealed gap"]}),
            ),
            "honest_gaps omits",
        ),
    ),
)
def test_release_structure_requires_exact_status_and_gate_blocks(mutation, fragment):
    card = _release_card()
    mutation(card)

    errors = scorecard_structure_errors(card)

    assert errors
    assert any(fragment in error for error in errors)
    with pytest.raises(ScorecardError, match="release structure invalid"):
        save(card, os.devnull)


def test_scorecard_measurement_key_has_stable_disclosed_provenance():
    first = suite.scorecard_measurement_key()
    second = suite.scorecard_measurement_key()
    provenance = suite.scorecard_measurement_provenance(40)

    assert first == second
    assert len(first) == 32
    assert first != suite.PUBLIC_DEV_KEY
    assert suite.SCORECARD_MEASUREMENT_KEY_DOMAIN != suite.DOMAIN
    assert provenance["purpose"] == "reproducible-scorecard-measurement"
    assert provenance["scope"] == "benchmark-validity"
    assert provenance["suite_kind"] == "scorecard-measurement"
    assert provenance["scenario_count"] == 40
    assert provenance["deterministic"] is True
    assert provenance["reportable"] is False
    assert provenance["suite_derivation_domain"] == "artifactforge/bench/v2"
    assert provenance["benchmark_contract"] == {
        "protocol": {
            "public_document_schema": "artifactforge-benchmark-public-v2",
            "public_export_schema": "artifactforge-benchmark-public-export-v1",
            "tree_canonicalization": "artifactforge-benchmark-scenarios-tree-v1",
            "suite_derivation_domain": "artifactforge/bench/v2",
            "scene_value_derivation_domain": "artifactforge/bench/v1",
            "public_export_inventory": ["public.json", "scenarios/**"],
            "public_export_limitation": suite.PUBLIC_EXPORT_LIMITATION,
            "same_process_python_is_security_boundary": False,
            "resource_limits": {
                "maximum_scenarios": 200,
                "current_artifact_files_per_scene": {"windows": 14, "macos": 16},
                "public_files_at_maximum": 3001,
                "public_json_bytes": 16 * 1024 * 1024,
                "answer_document_bytes": 1024 * 1024,
                "answer_value_characters": 4096,
                "key_hex_bytes": 64,
                "recursive_file_limit": 4096,
                "recursive_total_bytes_limit": 256 * 1024 * 1024,
            },
        },
        "questions": {
            "rules": [
                {
                    "family": "windows",
                    "rule": "amcache-fileid-byte-agreement-v1",
                },
                {
                    "family": "macos",
                    "rule": "quarantine-uuid-event-agreement-v1",
                },
            ],
            "questions_per_scene": 5,
            "candidates_per_question": 5,
            "answer_assignment": "five-way-bijection-v1",
        },
        "inference": {
            "method": "exact-conditional-scene-permutation-v1",
            "ensembles": ["trained-partial-union-v1", "trained-rank-union-v1"],
            "randomization_unit": "scene",
            "permutations_per_scene": 120,
            "multiple_testing": "bonferroni-v1",
            "comparisons": 39,
            "familywise_alpha": "1/20",
            "minimum_scenes_per_class": 20,
            "alternative": {
                "model": "whole-scene-recovery-mixture-v1",
                "signal_probability": "1/2",
            },
            "target_power": "99/100",
        },
        "counterfactuals": {
            "engine": "parser-valid-local-effect-v1",
            "source_tree_must_remain_unchanged": True,
            "checks_per_scene": {"windows": 20, "macos": 25},
            "representative_mapping_world_contract": {
                "representative_mechanisms": 3,
                "mapping_worlds": 360,
                "parser_valid_artifact_rebuilds": 840,
                "independently_resolved_question_checks": 1800,
                "registered_attack_invariance_checks": 3960,
                "positive_control_answer_checks": 1800,
                "non_identity_control_change_checks": 357,
            },
            "windows_mutations": [
                "windows-fileid-swap",
                "windows-fileid-absent",
                "windows-resident-pe-replacement",
            ],
            "macos_mutations": [
                "macos-xattr-uuid-swap",
                "macos-database-uuid-swap",
                "macos-xattr-uuid-absent",
            ],
        },
        "shortcut_controls": {
            "registered_adversaries": [
                "alternate_link",
                "constant",
                "footprint",
                "lexical",
                "listing",
                "mechanical",
                "metadata",
                "null",
                "pool",
                "scalar",
                "selector",
            ],
            "complete_adversaries": [
                "alternate_link",
                "footprint",
                "lexical",
                "mechanical",
                "metadata",
                "pool",
                "scalar",
                "selector",
            ],
            "mandatory_positive_controls": 10,
            "union_control": "production-partial-wrapper-independent-dev-measurement-v1",
            "truth_construction": "independent-observable-ranking-oracle-v2",
            "partial_union_model_control": (
                "production-partial-wrapper-independent-dev-measurement-v1"
            ),
            "rank_union_model_control": "production-wrapper-independent-dev-measurement-v2",
            "blind_public_key_control": True,
            "parent_escape_control": "co-located-100-exported-0-v1",
        },
    }
    assert provenance["key_derivation"] == {
        "algorithm": "HMAC-SHA256",
        "domain": "artifactforge/scorecard/measurement-key/v1",
        "seed_id": "sha256:" + hashlib.sha256(suite.SCORECARD_MEASUREMENT_SEED).hexdigest(),
        "key_id": suite.scorecard_measurement_key_id(),
    }
    assert provenance["generator_assurance"] == suite.generator_assurance_provenance(40)
    assert provenance["generator_assurance"] == {
        "purpose": "deterministic-generator-assurance",
        "families": ["windows", "macos", "linux"],
        "family_counts": {"windows": 20, "macos": 20, "linux": 20},
        "windows_macos_scenario_count": 40,
        "linux_scenario_count": 20,
        "scenario_count": 60,
        "deterministic": True,
        "benchmark_reportable": False,
        "linux_benchmark_included": False,
        "corpora": {
            "windows_macos": {
                "purpose": "windows-macos-generator-assurance",
                "suite_kind": "dev",
                "families": ["windows", "macos"],
                "scenario_count": 40,
                "maximum_scenario_count": 200,
                "family_counts": {"windows": 20, "macos": 20},
                "deterministic": True,
                "benchmark_reportable": False,
                "suite_derivation_domain": "artifactforge/bench/v2",
                "scene_value_derivation_domain": "artifactforge/bench/v1",
                "public_key": {
                    "source": "PUBLIC_DEV_KEY",
                    "identity_algorithm": "SHA256",
                    "key_id": suite.public_dev_key_id(),
                },
                "content_namespace": "artifactforge::suite",
                "family_schedule": {
                    "algorithm": "zero-based-index-parity-v1",
                    "index_origin": 0,
                    "even_index_family": "windows",
                    "odd_index_family": "macos",
                },
            },
            "linux": {
                "purpose": "linux-generator-assurance",
                "corpus_kind": "generator-assurance-linux",
                "family": "linux",
                "scenario_count": 20,
                "deterministic": True,
                "benchmark_reportable": False,
                "benchmark_included": False,
                "profile": "linux-glibc-x86_64-loose-v1",
                "scene_derivation_domain": ("artifactforge/generator-assurance/linux-scene/v1"),
                "content_namespace": "artifactforge::generator-assurance/linux/v1",
                "count_contract": {
                    "algorithm": "ceil-half-windows-macos-v1",
                    "windows_macos_scenario_count": 40,
                },
                "key_derivation": {
                    "algorithm": "HMAC-SHA256",
                    "domain": "artifactforge/generator-assurance/key/v1",
                    "seed_id": "sha256:"
                    + hashlib.sha256(suite.GENERATOR_ASSURANCE_SEED).hexdigest(),
                    "key_id": suite.generator_assurance_key_id(),
                },
            },
        },
    }
    assert provenance["key_derivation"]["seed_id"].startswith("sha256:")
    assert provenance["key_derivation"]["key_id"].startswith("sha256:")


def test_scorecard_benchmark_contract_is_bound_to_live_v2_registries():
    from fractions import Fraction
    from math import factorial

    from artifactforge.bench import counterfactual, positive_controls, statistics
    from artifactforge.bench.adversary import ADVERSARIES, COMPLETE_ADVERSARIES
    from artifactforge.bench.reference_solver import RULE_FAMILIES
    from artifactforge.compose import scene
    from artifactforge.gates import solvability

    contract = suite.scorecard_measurement_provenance(40)["benchmark_contract"]
    assert contract["questions"]["rules"] == [
        {"family": family, "rule": rule} for rule, family in RULE_FAMILIES.items()
    ]
    assert suite.BENCHMARK_QUESTION_RULES == (
        ("windows", scene.WINDOWS_AMCACHE_RULE),
        ("macos", scene.MACOS_QUARANTINE_RULE),
    )
    assert suite.BENCHMARK_COMPLETE_ADVERSARIES == tuple(sorted(COMPLETE_ADVERSARIES))
    assert suite.BENCHMARK_REGISTERED_ADVERSARIES == tuple(sorted(ADVERSARIES))
    assert contract["shortcut_controls"]["mandatory_positive_controls"] == (
        len(COMPLETE_ADVERSARIES) + 2
    )
    assert contract["shortcut_controls"]["truth_construction"] == (
        suite.BENCHMARK_POSITIVE_CONTROL_ORACLE
    )
    assert contract["shortcut_controls"]["rank_union_model_control"] == (
        suite.BENCHMARK_RANK_UNION_CONTROL
    )
    assert contract["shortcut_controls"]["partial_union_model_control"] == (
        suite.BENCHMARK_PARTIAL_UNION_CONTROL
    )
    assert contract["inference"]["ensembles"] == list(suite.BENCHMARK_ENSEMBLES)
    assert suite.BENCHMARK_QUESTIONS_PER_SCENE == counterfactual.QUESTION_COUNT
    assert suite.BENCHMARK_QUESTIONS_PER_SCENE == positive_controls.QUESTION_COUNT
    assert suite.BENCHMARK_CANDIDATES_PER_QUESTION == solvability.EXPECTED_CANDIDATES
    assert suite.BENCHMARK_CANDIDATES_PER_QUESTION == statistics.SCENE_CANDIDATE_COUNT
    assert contract["inference"]["permutations_per_scene"] == factorial(
        statistics.SCENE_CANDIDATE_COUNT
    )
    assert contract["inference"]["comparisons"] == (
        (len(ADVERSARIES) + len(suite.BENCHMARK_ENSEMBLES)) * (len(RULE_FAMILIES) + 1)
    )
    assert Fraction(contract["inference"]["familywise_alpha"]) == (
        statistics.DEFAULT_FAMILYWISE_ALPHA
    )
    assert contract["inference"]["minimum_scenes_per_class"] == (statistics.MIN_SCENES_PER_FAMILY)
    assert contract["inference"]["minimum_scenes_per_class"] == (solvability.MIN_SCENES_PER_CLASS)
    assert Fraction(contract["inference"]["alternative"]["signal_probability"]) == (
        statistics.PREDECLARED_SIGNAL_PROBABILITY
    )
    assert Fraction(contract["inference"]["target_power"]) == (statistics.PREDECLARED_TARGET_POWER)


def test_scorecard_counterfactual_counts_match_the_live_engine(tmp_path):
    pytest.importorskip("pefile")
    pytest.importorskip("lief")
    pytest.importorskip("regipy")
    pytest.importorskip("pyregf")

    from artifactforge.bench.benchmark import generate_suite
    from artifactforge.bench.counterfactual import evaluate_counterfactuals

    tasks = generate_suite(
        2,
        str(tmp_path / "counterfactual-provenance"),
        key=bytes.fromhex("6d" * 32),
        kind="holdout",
    )
    reports = (
        evaluate_counterfactuals(tasks[0].public()),
        evaluate_counterfactuals(tasks[1].public()),
    )
    observed = {report.family: report.total for report in reports}
    contract = suite.scorecard_measurement_provenance(40)["benchmark_contract"]
    assert observed == contract["counterfactuals"]["checks_per_scene"]
    for report in reports:
        assert sorted({detail.mutation for detail in report.details}) == sorted(
            contract["counterfactuals"][f"{report.family}_mutations"]
        )


def test_committed_scorecard_has_exact_measurement_and_source_provenance(card):
    """The published card must identify both its corpus and a real matching source commit."""
    expected_measurement = suite.scorecard_measurement_provenance(40)
    if card["generator"]["artifactforge_version"] == "0.5.0":
        # The tagged 0.5.0 card predates Phase 4's expanded local swaps and representative
        # all-mapping proof. Preserve what that source commit actually measured instead of
        # silently relabeling its historical evidence with the stronger current contract.
        expected_measurement["benchmark_contract"]["counterfactuals"] = {
            "engine": "parser-valid-local-effect-v1",
            "source_tree_must_remain_unchanged": True,
            "checks_per_scene": {"windows": 13, "macos": 11},
            "windows_mutations": [
                "windows-fileid-swap",
                "windows-fileid-absent",
                "windows-resident-pe-replacement",
            ],
            "macos_mutations": [
                "macos-xattr-uuid-swap",
                "macos-database-uuid-swap",
                "macos-xattr-uuid-absent",
            ],
        }
        historical_limits = expected_measurement["benchmark_contract"]["protocol"][
            "resource_limits"
        ]
        historical_limits["current_artifact_files_per_scene"] = {
            "windows": 11,
            "macos": 16,
        }
        historical_limits["public_files_at_maximum"] = 2701
    assert card["measurement"] == expected_measurement

    generator = card["generator"]
    provenance = generator["source"]
    assert provenance["schema"] == "artifactforge-source-provenance-v1"
    commit = provenance["git_commit"]
    assert generator["git_commit"] == commit[:7]
    assert provenance["worktree_clean"] is True
    assert provenance["dirty_snapshot_sha256"] is None
    assert provenance["untracked_file_count"] == 0

    def git_show(path):
        return subprocess.run(
            ["git", "show", f"{commit}:{path}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout

    source_version = tomllib.loads(git_show("pyproject.toml").decode())["project"]["version"]
    assert source_version == card["generator"]["artifactforge_version"]
    assert (
        provenance["pyproject_sha256"]
        == "sha256:" + hashlib.sha256(git_show("pyproject.toml")).hexdigest()
    )
    assert (
        provenance["uv_lock_sha256"] == "sha256:" + hashlib.sha256(git_show("uv.lock")).hexdigest()
    )
    assert provenance["build_constraints_sha256"] == (
        "sha256:" + hashlib.sha256(git_show("build-constraints.txt")).hexdigest()
    )
    tree = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert provenance["git_tree"] == tree


def test_historical_v05_card_is_an_explicitly_incompatible_phase4_boundary(card):
    historical = card["measurement"]["benchmark_contract"]["counterfactuals"]
    current_measurement = suite.scorecard_measurement_provenance(40)
    current = current_measurement["benchmark_contract"]["counterfactuals"]

    assert card["generator"]["artifactforge_version"] == "0.5.0"
    assert historical["checks_per_scene"] == {"windows": 13, "macos": 11}
    assert "representative_mapping_world_contract" not in historical
    assert current["checks_per_scene"] == {"windows": 20, "macos": 25}
    assert current["representative_mapping_world_contract"] == (
        suite.BENCHMARK_MAPPING_WORLD_CONTRACT
    )
    assert measurement_incompatibilities(
        card,
        {"measurement": current_measurement},
    )


def _clean_source_provenance():
    return {
        "schema": "artifactforge-source-provenance-v1",
        "git_commit": "abcdef0123456789abcdef0123456789abcdef01",
        "git_tree": "1" * 40,
        "worktree_clean": True,
        "dirty_snapshot_sha256": None,
        "untracked_file_count": 0,
        "pyproject_sha256": "sha256:" + "2" * 64,
        "uv_lock_sha256": "sha256:" + "3" * 64,
        "build_constraints_sha256": "sha256:" + "4" * 64,
    }


def test_scorecard_command_is_stable_and_prints_scoped_status(tmp_path, monkeypatch, capsys):
    gates = ("validity", "identity", "inertness", "solvability")
    calls = []

    def run_gate(name, number, args):
        calls.append((name, args._scorecard_measurement_mode))
        report = GateReport(number, name, name)
        if name == "validity":
            report.gap("declared generator gap")
        if name == "solvability":
            report.fail("measured benchmark shortcut")
        return report

    monkeypatch.setattr(
        cli_module,
        "GATES",
        {
            name: (lambda args, name=name, number=number: run_gate(name, number, args))
            for number, name in enumerate(gates, 1)
        },
    )
    source = _clean_source_provenance()
    monkeypatch.setattr(cli_module, "_git_source_provenance", lambda: source)

    paths = [tmp_path / "first.json", tmp_path / "second.json"]
    for path in paths:
        args = SimpleNamespace(n=40, out=str(path), check=None, gen_dir=None, scene=None)
        assert cli_module.cmd_scorecard(args) == 0

    assert paths[0].read_bytes() == paths[1].read_bytes()
    generated = json.loads(paths[0].read_text())
    assert generated["measurement"] == suite.scorecard_measurement_provenance(40)
    assert generated["generator"]["source"] == source
    assert calls == [(name, True) for name in gates] * 2

    output = capsys.readouterr().out
    assert "generator assurance: gap" in output
    assert "experimental benchmark validity: fail" in output
    assert "aggregate (all gates): fail" in output


def _install_scorecard_gate_reports(monkeypatch, reports):
    monkeypatch.setattr(
        cli_module,
        "GATES",
        {report.name: (lambda _args, report=report: report) for report in reports},
    )
    source = _clean_source_provenance()
    monkeypatch.setattr(cli_module, "_git_source_provenance", lambda: source)


def _isolate_status_comparison(monkeypatch):
    import artifactforge.scorecard as scorecard_module

    monkeypatch.setattr(scorecard_module, "regressions", lambda _baseline, _current: [])
    monkeypatch.setattr(
        scorecard_module,
        "measurement_incompatibilities",
        lambda _baseline, _current: [],
    )


def test_scorecard_check_blocks_pass_to_gap_with_unchanged_metrics(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    save(_release_card(), baseline)
    _install_scorecard_gate_reports(monkeypatch, _release_reports(generator_gap=True))
    _isolate_status_comparison(monkeypatch)

    args = SimpleNamespace(
        n=40,
        out=None,
        check=os.fspath(baseline),
        gen_dir=None,
        scene=None,
    )
    assert cli_module.cmd_scorecard(args) == 1
    assert "REGRESSED generator assurance: pass -> gap" in capsys.readouterr().out


def test_scorecard_check_allows_one_unchanged_preexisting_gap(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    save(_release_card(generator_gap=True), baseline)
    _install_scorecard_gate_reports(monkeypatch, _release_reports(generator_gap=True))
    _isolate_status_comparison(monkeypatch)

    args = SimpleNamespace(
        n=40,
        out=None,
        check=os.fspath(baseline),
        gen_dir=None,
        scene=None,
    )
    assert cli_module.cmd_scorecard(args) == 0
    assert "no scoped status regressed" in capsys.readouterr().out


def test_scorecard_check_blocks_a_current_fail_even_when_baseline_already_failed(
    tmp_path, monkeypatch, capsys
):
    baseline = tmp_path / "baseline.json"
    save(_release_card(benchmark_fail=True), baseline)
    _install_scorecard_gate_reports(monkeypatch, _release_reports(benchmark_fail=True))
    _isolate_status_comparison(monkeypatch)

    args = SimpleNamespace(
        n=40,
        out=None,
        check=os.fspath(baseline),
        gen_dir=None,
        scene=None,
    )
    assert cli_module.cmd_scorecard(args) == 1
    assert "FAILING   benchmark validity: fail -> fail" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("generator_gap", "benchmark_fail", "expected_code", "expected_verdict"),
    (
        (False, False, 0, "pass"),
        (True, False, 1, "gap"),
        (False, True, 1, "fail"),
    ),
)
def test_scorecard_require_pass_is_an_absolute_current_source_gate_and_keeps_evidence(
    tmp_path,
    monkeypatch,
    generator_gap,
    benchmark_fail,
    expected_code,
    expected_verdict,
):
    output = tmp_path / "current-source.json"
    _install_scorecard_gate_reports(
        monkeypatch,
        _release_reports(
            generator_gap=generator_gap,
            benchmark_fail=benchmark_fail,
        ),
    )
    args = SimpleNamespace(
        n=40,
        out=os.fspath(output),
        check=None,
        gen_dir=None,
        scene=None,
        require_pass=True,
    )

    assert cli_module.cmd_scorecard(args) == expected_code
    assert load(output)["verdict"] == expected_verdict


def test_scorecard_safe_io_round_trips_and_forces_regular_0644_mode(tmp_path):
    path = tmp_path / "card.json"
    first = _release_card()
    save(first, path)

    assert load(path) == first
    assert stat.S_ISREG(path.stat().st_mode)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644

    path.chmod(0o6755)
    second = _release_card(generator_gap=True)
    save(second, path)
    assert load(path) == second
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_scorecard_load_and_save_refuse_symlink_without_touching_target(tmp_path):
    target = tmp_path / "target.json"
    save(_release_card(), target)
    before = target.read_bytes()
    link = tmp_path / "card.json"
    link.symlink_to(target.name)

    with pytest.raises(ScorecardError, match="regular file|link or special"):
        load(link)
    with pytest.raises(ScorecardError, match="regular file|link or special"):
        save(_release_card(generator_gap=True), link)

    assert target.read_bytes() == before
    assert link.is_symlink()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is a POSIX special file")
def test_scorecard_load_and_save_refuse_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "card.fifo"
    os.mkfifo(fifo)

    with pytest.raises(ScorecardError, match="regular file|link or special"):
        load(fifo)
    with pytest.raises(ScorecardError, match="regular file|link or special"):
        save(_release_card(), fifo)


@pytest.mark.parametrize(
    "payload",
    (
        b'{"duplicate":1,"duplicate":2}\n',
        b'{"value":NaN}\n',
        b'{"value":Infinity}\n',
        b'{"value":1e9999}\n',
        b'{"value":"\\ud800"}\n',
        b"\xef\xbb\xbf{}\n",
        b'{"value":"\xff"}\n',
        b"{} trailing\n",
        b"[]\n",
    ),
)
def test_scorecard_loader_rejects_lossy_or_non_strict_json(tmp_path, payload):
    path = tmp_path / "card.json"
    path.write_bytes(payload)

    with pytest.raises(ScorecardError):
        load(path)


def test_scorecard_loader_accepts_an_ordinary_finite_float(tmp_path):
    path = tmp_path / "card.json"
    path.write_bytes(b'{"value":1.25}\n')
    assert load(path) == {"value": 1.25}


def test_scorecard_input_and_output_bounds_fail_before_publication(tmp_path):
    oversized_input = tmp_path / "oversized.json"
    oversized_input.write_bytes(b"{" + b" " * SCORECARD_MAX_BYTES + b"}")
    with pytest.raises(ScorecardError, match="input limit"):
        load(oversized_input)

    destination = tmp_path / "card.json"
    save(_release_card(), destination)
    before = destination.read_bytes()
    oversized_card = _release_card()
    oversized_card["padding"] = "x" * SCORECARD_MAX_BYTES
    with pytest.raises(ScorecardError, match="output limit"):
        save(oversized_card, destination)
    assert destination.read_bytes() == before


@pytest.mark.parametrize("fault", ("short-write", "file-fsync", "replace"))
def test_prepublication_faults_preserve_old_card_and_remove_owned_temp(
    tmp_path, monkeypatch, fault
):
    import artifactforge.scorecard as scorecard_module

    destination = tmp_path / "card.json"
    save(_release_card(), destination)
    before = destination.read_bytes()

    if fault == "short-write":

        def incomplete(descriptor, data):
            os.write(descriptor, data[: len(data) // 2])

        monkeypatch.setattr(scorecard_module, "_write_all", incomplete)
    elif fault == "file-fsync":
        monkeypatch.setattr(
            scorecard_module.os,
            "fsync",
            lambda _descriptor: (_ for _ in ()).throw(OSError("injected fsync failure")),
        )
    else:
        monkeypatch.setattr(
            scorecard_module.os,
            "replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected replace failure")),
        )

    with pytest.raises(ScorecardError):
        save(_release_card(generator_gap=True), destination)

    assert destination.read_bytes() == before
    assert not list(tmp_path.glob(".artifactforge-scorecard-*.tmp"))


def test_atomic_publication_uses_one_pinned_parent_for_source_and_destination(
    tmp_path, monkeypatch
):
    import artifactforge.scorecard as scorecard_module

    destination = tmp_path / "card.json"
    save(_release_card(), destination)
    before = destination.read_bytes()
    calls = []
    real_replace = os.replace

    def observed_replace(source, target, *, src_dir_fd, dst_dir_fd):
        calls.append((source, target, src_dir_fd, dst_dir_fd, destination.read_bytes()))
        return real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(scorecard_module.os, "replace", observed_replace)
    replacement = _release_card(generator_gap=True)
    save(replacement, destination)

    assert len(calls) == 1
    source, target, source_parent, target_parent, observed_old = calls[0]
    assert source.startswith(".artifactforge-scorecard-")
    assert target == destination.name
    assert source_parent == target_parent
    assert observed_old == before
    assert load(destination) == replacement


def test_postpublication_parent_failure_is_explicitly_uncertain(tmp_path, monkeypatch):
    import artifactforge.scorecard as scorecard_module

    destination = tmp_path / "card.json"
    save(_release_card(), destination)
    replacement = _release_card(generator_gap=True)
    real_verify = scorecard_module._verify_parent
    calls = 0

    def fail_second(parent, descriptor, identity):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ScorecardError("injected post-publication parent failure")
        return real_verify(parent, descriptor, identity)

    monkeypatch.setattr(scorecard_module, "_verify_parent", fail_second)
    with pytest.raises(ScorecardPublicationUncertain) as caught:
        save(replacement, destination)

    assert caught.value.published is True
    assert caught.value.path == os.fspath(destination.resolve())
    assert load(destination) == replacement
    assert stat.S_IMODE(destination.stat().st_mode) == 0o644


@pytest.mark.parametrize("unsafe_kind", ("symlink", "duplicate-json"))
def test_scorecard_check_rejects_unsafe_baseline_before_running_any_gate(
    tmp_path, monkeypatch, capsys, unsafe_kind
):
    baseline = tmp_path / "baseline.json"
    if unsafe_kind == "symlink":
        target = tmp_path / "target.json"
        save(_release_card(), target)
        baseline.symlink_to(target.name)
    else:
        baseline.write_bytes(b'{"duplicate":1,"duplicate":2}\n')

    def forbidden(_args):
        raise AssertionError("gate ran before baseline validation")

    monkeypatch.setattr(
        cli_module,
        "GATES",
        {name: forbidden for name in ("validity", "identity", "inertness", "solvability")},
    )
    monkeypatch.setattr(
        cli_module,
        "_git_source_provenance",
        lambda: (_ for _ in ()).throw(
            AssertionError("source attestation ran before baseline validation")
        ),
    )
    args = SimpleNamespace(
        n=40,
        out=None,
        check=os.fspath(baseline),
        gen_dir=None,
        scene=None,
    )

    assert cli_module.cmd_scorecard(args) == 2
    assert "cannot safely load scorecard baseline" in capsys.readouterr().err


def test_scorecard_cli_refuses_symlink_output_without_truncating_target(
    tmp_path, monkeypatch, capsys
):
    target = tmp_path / "target.json"
    save(_release_card(), target)
    before = target.read_bytes()
    output = tmp_path / "output.json"
    output.symlink_to(target.name)
    _install_scorecard_gate_reports(monkeypatch, _release_reports())
    args = SimpleNamespace(
        n=40,
        out=os.fspath(output),
        check=None,
        gen_dir=None,
        scene=None,
        allow_dirty=False,
    )

    assert cli_module.cmd_scorecard(args) == 2
    assert target.read_bytes() == before
    assert output.is_symlink()
    captured = capsys.readouterr()
    assert "cannot safely publish scorecard" in captured.err
    assert "wrote" not in captured.out


def test_scorecard_check_rejects_invalid_release_structure_before_running_gates(
    tmp_path, monkeypatch, capsys
):
    baseline = tmp_path / "baseline.json"
    invalid = _release_card()
    del invalid["status"]["benchmark_validity"]
    baseline.write_text(json.dumps(invalid) + "\n", encoding="utf-8")

    def forbidden(_args):
        raise AssertionError("gate ran before release-structure validation")

    monkeypatch.setattr(
        cli_module,
        "GATES",
        {name: forbidden for name in ("validity", "identity", "inertness", "solvability")},
    )
    monkeypatch.setattr(
        cli_module,
        "_git_source_provenance",
        lambda: (_ for _ in ()).throw(
            AssertionError("source attestation ran before release-structure validation")
        ),
    )
    args = SimpleNamespace(
        n=40,
        out=None,
        check=os.fspath(baseline),
        gen_dir=None,
        scene=None,
    )

    assert cli_module.cmd_scorecard(args) == 1
    assert "scorecard release structure invalid" in capsys.readouterr().out


def test_scorecard_stdout_mode_refuses_nonfinite_generated_metric(tmp_path, monkeypatch, capsys):
    reports = _release_reports()
    reports[0].metrics["nonfinite"] = float("nan")
    _install_scorecard_gate_reports(monkeypatch, reports)
    args = SimpleNamespace(
        n=40,
        out=None,
        check=None,
        gen_dir=os.fspath(tmp_path),
        scene=None,
    )

    assert cli_module.cmd_scorecard(args) == 2
    captured = capsys.readouterr()
    assert "violates the release contract" in captured.err
    assert "NaN" not in captured.out


def test_scorecard_output_refuses_dirty_source_unless_explicitly_allowed(
    tmp_path, monkeypatch, capsys
):
    dirty = {
        **_clean_source_provenance(),
        "worktree_clean": False,
        "dirty_snapshot_sha256": "sha256:" + "4" * 64,
        "untracked_file_count": 2,
    }
    monkeypatch.setattr(cli_module, "_git_source_provenance", lambda: dirty)
    monkeypatch.setattr(
        cli_module,
        "GATES",
        {
            name: (lambda _args, name=name, gate=gate: GateReport(gate, name, name))
            for gate, name in enumerate(("validity", "identity", "inertness", "solvability"), 1)
        },
    )
    output = tmp_path / "dirty.json"
    args = SimpleNamespace(
        n=1,
        out=str(output),
        check=None,
        gen_dir=None,
        scene=None,
        allow_dirty=False,
    )
    assert cli_module.cmd_scorecard(args) == 2
    assert not output.exists()
    assert "refusing to write a scorecard from a dirty worktree" in capsys.readouterr().err

    args.allow_dirty = True
    assert cli_module.cmd_scorecard(args) == 0
    generated = json.loads(output.read_text())
    assert generated["generator"]["source"] == dirty


def test_scorecard_refuses_when_source_changes_during_measurement(tmp_path, monkeypatch, capsys):
    before = _clean_source_provenance()
    after = {**before, "git_tree": "9" * 40}
    snapshots = iter((before, after))
    monkeypatch.setattr(cli_module, "_git_source_provenance", lambda: next(snapshots))
    monkeypatch.setattr(
        cli_module,
        "GATES",
        {
            name: (lambda _args, report=GateReport(index, name, "question"): report)
            for index, name in enumerate(("validity", "identity", "inertness", "solvability"), 1)
        },
    )
    args = SimpleNamespace(
        n=1,
        out=str(tmp_path / "card.json"),
        check=None,
        allow_dirty=False,
        scene=None,
        gen_dir=None,
    )
    assert cli_module.cmd_scorecard(args) == 2
    assert not (tmp_path / "card.json").exists()
    assert "source changed during measurement" in capsys.readouterr().err


def test_dirty_source_digest_changes_with_the_tracked_diff():
    first = cli_module._dirty_snapshot_sha256(b"first", [])
    second = cli_module._dirty_snapshot_sha256(b"second", [])
    assert first and second and first != second
    assert cli_module._dirty_snapshot_sha256(b"", []) is None


def test_dirty_source_digest_binds_every_untracked_byte(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "_REPOSITORY_ROOT", tmp_path)
    untracked = tmp_path / "new-source.py"
    untracked.write_bytes(b"first")
    first = cli_module._dirty_snapshot_sha256(b"", [untracked.name])
    untracked.write_bytes(b"second")
    second = cli_module._dirty_snapshot_sha256(b"", [untracked.name])
    assert first and second and first != second


def test_solvability_routes_scorecards_to_measurement_and_gates_to_private_holdout(monkeypatch):
    seen = []
    monkeypatch.setattr(cli_module, "_scorecard_measurement", lambda _args: ["measurement"])
    monkeypatch.setattr(cli_module, "_holdout", lambda _args: ["holdout"])
    monkeypatch.setattr(cli_module, "_dev", lambda _args: ["dev"])

    def record(measured, dev):
        seen.append((measured, dev))
        return GateReport(4, "solvability", "solvability")

    monkeypatch.setattr(cli_module.solvability, "run", record)
    cli_module.gate_solvability(SimpleNamespace(_scorecard_measurement_mode=True))
    cli_module.gate_solvability(SimpleNamespace(_scorecard_measurement_mode=False))

    assert seen == [(["measurement"], ["dev"]), (["holdout"], ["dev"])]


def test_scorecard_measurement_generator_uses_only_the_public_measurement_key(
    tmp_path, monkeypatch
):
    calls = []

    def generate(n, root, *, key, kind):
        calls.append((n, root, key, kind))
        return ["generated"]

    monkeypatch.setattr(cli_module, "generate_suite", generate)
    args = SimpleNamespace(n=40, gen_dir=str(tmp_path))

    assert cli_module._scorecard_measurement(args) == ["generated"]
    assert cli_module._scorecard_measurement(args) == ["generated"]
    assert calls == [
        (
            40,
            os.path.join(str(tmp_path), suite.SCORECARD_MEASUREMENT_KIND),
            suite.scorecard_measurement_key(),
            suite.SCORECARD_MEASUREMENT_KIND,
        )
    ]


def _provenance_leaf_paths(value, prefix=""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            yield from _provenance_leaf_paths(child, child_prefix)
    else:
        yield prefix


def _different(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "-changed"
    if isinstance(value, list):
        return [*value, "changed"]
    raise AssertionError(f"no mutation for provenance value {value!r}")


def test_every_measurement_provenance_leaf_is_part_of_compatibility_identity():
    provenance = {"measurement": suite.scorecard_measurement_provenance(40)}
    leaves = set(_provenance_leaf_paths(provenance))
    identity_paths = {path for path, _label in _MEASUREMENT_IDENTITY}
    assert identity_paths == leaves


def test_every_measurement_identity_change_makes_scorecards_incomparable():
    baseline = {"measurement": suite.scorecard_measurement_provenance(40)}
    labels = dict(_MEASUREMENT_IDENTITY)

    for path, label in _MEASUREMENT_IDENTITY:
        current = deepcopy(baseline)
        node = current
        parts = path.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = _different(node[parts[-1]])

        mismatches = measurement_incompatibilities(baseline, current)
        assert (label, "changed") == (mismatches[0][0], mismatches[0][1]), path
        assert labels[path] == label


def test_baseline_only_provenance_leaf_cannot_disappear_from_current_contract():
    baseline = {"measurement": suite.scorecard_measurement_provenance(40)}
    current = deepcopy(baseline)
    baseline["measurement"]["future_release_binding"] = {
        "leaf_added_by_newer_baseline": "bound-value"
    }

    mismatches = measurement_incompatibilities(baseline, current)

    assert (
        "future release binding: leaf added by newer baseline",
        "missing",
        "bound-value",
        None,
    ) in mismatches


def test_pre_corpus_binding_generator_provenance_is_incompatible():
    current = {"measurement": suite.scorecard_measurement_provenance(40)}
    baseline = deepcopy(current)
    del baseline["measurement"]["generator_assurance"]["corpora"]

    mismatches = measurement_incompatibilities(baseline, current)
    assert mismatches
    assert all(kind == "missing" for _label, kind, _was, _now in mismatches)
    assert {label for label, _kind, _was, _now in mismatches} >= {
        "Windows/macOS assurance suite kind",
        "Windows/macOS assurance public-key identity",
        "Windows/macOS assurance content namespace",
        "Linux assurance corpus profile",
        "Linux assurance key identity",
    }


def test_missing_measurement_provenance_is_incompatible():
    current = {"measurement": suite.scorecard_measurement_provenance(40)}
    mismatches = measurement_incompatibilities({}, current)
    assert mismatches
    assert all(kind == "missing" for _label, kind, _was, _now in mismatches)


def test_scorecard_check_rejects_missing_measurement_provenance(tmp_path, monkeypatch, capsys):
    gates = ("validity", "identity", "inertness", "solvability")
    monkeypatch.setattr(
        cli_module,
        "GATES",
        {
            name: (lambda _args, name=name, number=number: GateReport(number, name, name))
            for number, name in enumerate(gates, 1)
        },
    )

    # Isolate this assertion from metric regression coverage: the baseline is rejected even
    # when the numeric comparison itself says it is clean.
    import artifactforge.scorecard as scorecard_module

    monkeypatch.setattr(scorecard_module, "regressions", lambda _baseline, _current: [])
    monkeypatch.setattr(
        scorecard_module,
        "render_comparison",
        lambda _baseline, _current: "no tracked metric regressed",
    )

    baseline = tmp_path / "legacy-scorecard.json"
    legacy = _release_card()
    del legacy["measurement"]
    save(legacy, baseline)
    args = SimpleNamespace(n=40, out=None, check=str(baseline), gen_dir=None, scene=None)
    assert cli_module.cmd_scorecard(args) == 1

    output = capsys.readouterr().out
    assert "no tracked metric regressed" in output
    assert "measurement provenance incompatible" in output
    assert "MISSING scenario count" in output
    assert "MISSING measurement key identity" in output


def test_scorecard_measurement_suite_cannot_print_a_reportable_score(tmp_path, capsys):
    from artifactforge.bench.benchmark import generate_suite
    from artifactforge.bench.reference_solver import reference_solve

    evaluator = tmp_path / "scorecard-measurement"
    tasks = generate_suite(
        1,
        os.fspath(evaluator),
        key=suite.scorecard_measurement_key(),
        kind=suite.SCORECARD_MEASUREMENT_KIND,
    )
    public = suite.load_evaluator_public(os.fspath(evaluator))
    submission = tmp_path / "answers.jsonl"
    submission.write_text(
        json.dumps(
            {
                "suite_id": public["suite_id"],
                "scenario_id": tasks[0].scenario_id,
                "answers": reference_solve(tasks[0].public()),
            }
        )
        + "\n"
    )

    args = SimpleNamespace(suite=os.fspath(evaluator), submission=str(submission))
    assert cli_module.cmd_bench_grade(args) == 0
    output = capsys.readouterr().out
    assert (
        "RAW SCORE (SCORECARD MEASUREMENT - PUBLIC REPRODUCIBLE KEY; "
        "NOT REPORTABLE): 5/5 = 100.0%" in output
    )
    assert f"suite_id: {public['suite_id']}" in output


def test_package_version_is_consistent_with_release_metadata(card):
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        project_version = tomllib.load(f)["project"]["version"]
    with open(os.path.join(ROOT, "uv.lock"), "rb") as f:
        packages = tomllib.load(f)["package"]
    lock_version = next(p["version"] for p in packages if p["name"] == "artifactforge")

    assert project_version == "0.5.0"
    assert __version__ == project_version
    assert lock_version == project_version
    assert card["generator"]["artifactforge_version"] == project_version


def test_ci_consumes_the_frozen_oracle_lock_in_every_project_lane():
    """Fingerprinting uv.lock is meaningful only if CI actually installs from it."""
    with open(os.path.join(ROOT, ".github", "workflows", "ci.yml")) as f:
        workflow = f.read()
    assert 'UV_FROZEN: "1"' in workflow
    assert 'UV_VERSION: "0.11.17"' in workflow
    assert 'uv pip install -e ".[dev]"' not in workflow
    assert workflow.count("sync --frozen --extra dev --python") == 7
    assert "pip install --quiet --user" not in workflow
    assert "--break-system-packages" not in workflow
    assert workflow.count('UV_BOOTSTRAP="$RUNNER_TEMP/artifactforge-uv-bootstrap"') == 7
    assert workflow.count('python3 -m venv "$UV_BOOTSTRAP"') == 7
    assert workflow.count('"$UV_BOOTSTRAP/bin/python" -m pip install') == 7
    assert workflow.count(
        "--no-deps --only-binary=:all: --require-hashes -r ci-bootstrap-requirements.txt"
    ) == 8
    assert '"uv==$UV_VERSION"' not in workflow
    assert workflow.count('echo "$UV_BOOTSTRAP/bin" >> "$GITHUB_PATH"') == 7
    assert workflow.count('"$UV_BOOTSTRAP/bin/uv" --version') == 7


def test_release_build_backend_and_complete_closure_are_pinned_and_hashed():
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        build_system = tomllib.load(f)["build-system"]
    assert build_system == {
        "requires": ["hatchling==1.31.0"],
        "build-backend": "hatchling.build",
    }

    with open(os.path.join(ROOT, "build-constraints.in"), encoding="utf-8") as f:
        requested = [line for line in f.read().splitlines() if line and not line.startswith("#")]
    assert requested == ["hatchling==1.31.0"]

    with open(os.path.join(ROOT, "build-constraints.txt"), encoding="utf-8") as f:
        constraints = f.read()
    pins = {
        line.split()[0]
        for line in constraints.splitlines()
        if line and not line[0].isspace() and not line.startswith("#")
    }
    assert pins == {
        "hatchling==1.31.0",
        "packaging==26.2",
        "pathspec==1.1.1",
        "pluggy==1.6.0",
        "trove-classifiers==2026.6.1.19",
    }
    assert constraints.count("--hash=sha256:") == 2 * len(pins)

    with open(os.path.join(ROOT, ".github", "workflows", "ci.yml")) as f:
        workflow = f.read()
    assert 'SOURCE_DATE_EPOCH: "1580601600"' in workflow
    assert workflow.count("--build-constraint build-constraints.txt --require-hashes") == 3
    assert workflow.count("--no-sources") == 3
    assert "artifactforge-dist-a/artifactforge-*.tar.gz" in workflow
    assert "artifactforge-dist-b/artifactforge-*.tar.gz" in workflow
    assert "artifactforge-dist-a/artifactforge-*.whl" in workflow
    assert "artifactforge-dist-b/artifactforge-*.whl" in workflow
    assert '"Generator: hatchling 1.31.0\\n"' in workflow


def test_published_legacy_scorecard_compares_cleanly_with_itself(card):
    """A scorecard predating newly tracked metrics remains a valid comparison baseline."""
    assert "claim_scopes" not in card["gates"]["validity"]
    assert regressions(card, card) == []
    assert len(_METRICS) >= 8


_CLAIM_SCOPE_METRIC_PATHS = {
    f"gates.validity.claim_scopes.{scope}.{counter}"
    for scope in (
        "container_acceptance",
        "semantic_extraction",
        "independent_consensus",
        "declared_profile_conformance",
        "downstream_consumer_compatibility",
    )
    for counter in ("passed", "total")
}


def _one_metric(path, value):
    node = result = {}
    parts = path.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    return result


def test_all_gate1_claim_scope_leaves_are_tracked_without_tolerance():
    configured = {
        path: (direction, tolerance, label)
        for path, direction, tolerance, label in _METRICS
        if path.startswith("gates.validity.claim_scopes.")
    }

    assert set(configured) == _CLAIM_SCOPE_METRIC_PATHS
    assert all(
        direction == "higher_better" for direction, _tolerance, _label in configured.values()
    )
    assert all(tolerance == 0 for _direction, tolerance, _label in configured.values())


def test_new_claim_scope_metric_is_forward_compatible_with_legacy_baseline():
    path = "gates.validity.claim_scopes.container_acceptance.passed"

    assert regressions({}, {}) == []
    assert regressions({}, _one_metric(path, 7)) == []


def test_removing_introduced_claim_scope_metric_is_a_regression():
    path = "gates.validity.claim_scopes.container_acceptance.passed"
    label = "validity: container acceptance checks passed"

    assert regressions(_one_metric(path, 7), {}) == [(label, "missing", 7, None)]


@pytest.mark.parametrize("bad_value", (None, True, "7", float("nan"), float("inf")))
def test_introduced_claim_scope_metric_rejects_invalid_values(bad_value):
    path = "gates.validity.claim_scopes.container_acceptance.passed"
    label = "validity: container acceptance checks passed"

    mismatch = regressions({}, _one_metric(path, bad_value))
    assert len(mismatch) == 1
    observed_label, kind, was, now = mismatch[0]
    assert (observed_label, kind, was) == (label, "invalid", None)
    if isinstance(bad_value, float) and not math.isfinite(bad_value):
        assert isinstance(now, float) and not math.isfinite(now)
    else:
        assert now == bad_value


_NONVACUOUS_METRIC_CONTRACT = {
    "gates.identity.checks_total": ("higher_better", 0, "identity: cross-artifact joins declared"),
    "gates.inertness.formats_total": ("higher_better", 0, "inertness: marked formats declared"),
    "gates.solvability.reference_solver_coverage": (
        "higher_better",
        0,
        "solvability: reference solver coverage",
    ),
    "gates.solvability.resolved_questions_total": (
        "higher_better",
        0,
        "solvability: closed-rule questions declared",
    ),
    "gates.solvability.multi_artifact_dependencies_total": (
        "higher_better",
        0,
        "solvability: multi-artifact dependencies declared",
    ),
    "gates.solvability.counterfactual_checks_total": (
        "higher_better",
        0,
        "solvability: counterfactual checks declared",
    ),
    "gates.solvability.blind_control_score": (
        "higher_better",
        0,
        "solvability: public development-key blind control",
    ),
    "gates.solvability.blind_solver_coverage": (
        "higher_better",
        0,
        "solvability: public scorecard-key blind-control coverage",
    ),
    "gates.solvability.blind_control_coverage": (
        "higher_better",
        0,
        "solvability: public development-key blind-control coverage",
    ),
    "gates.solvability.parent_escape_control_score": (
        "higher_better",
        0,
        "solvability: co-located parent-escape control",
    ),
    "gates.solvability.parent_escape_control_coverage": (
        "higher_better",
        0,
        "solvability: co-located parent-escape coverage",
    ),
    "gates.solvability.positive_control_checks_total": (
        "higher_better",
        0,
        "solvability: shortcut positive controls declared",
    ),
}


def _metric_value(card, path):
    node = card
    for part in path.split("."):
        node = node[part]
    return node


def _metric_is_present(card, path):
    try:
        _metric_value(card, path)
    except KeyError:
        return False
    return True


def _set_metric(card, path, value):
    node = card
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def test_boolean_metrics_preserve_type_and_order(card):
    boolean_metrics = [
        (path, label)
        for path, _direction, _tolerance, label in _METRICS
        if _metric_is_present(card, path) and isinstance(_metric_value(card, path), bool)
    ]
    assert boolean_metrics, "the Gate 4 boolean-control comparison surface disappeared"

    for path, label in boolean_metrics:
        assert _metric_value(card, path) is True

        regressed = deepcopy(card)
        _set_metric(regressed, path, False)
        assert (label, "regressed", True, False) in regressions(card, regressed)

        type_drifted = deepcopy(card)
        _set_metric(type_drifted, path, 1)
        assert (label, "invalid", True, 1) in regressions(card, type_drifted)


def test_nonvacuous_metrics_have_exact_paths_directions_and_zero_tolerance():
    """A passing numerator cannot stand in for its denominator or positive control."""
    configured = {
        path: (direction, tolerance, label) for path, direction, tolerance, label in _METRICS
    }
    assert len(configured) == len(_METRICS), "tracked metric paths must be unique"
    for path, contract in _NONVACUOUS_METRIC_CONTRACT.items():
        assert configured[path] == contract


@pytest.mark.parametrize("path", sorted(_NONVACUOUS_METRIC_CONTRACT))
def test_committed_scorecard_carries_every_nonvacuous_metric(card, path):
    value = _metric_value(card, path)
    assert isinstance(value, (int, float)) and not isinstance(value, bool)


def test_committed_scorecard_nonvacuous_metrics_have_coherent_denominators_and_control(card):
    identity = card["gates"]["identity"]
    inertness = card["gates"]["inertness"]
    solvability = card["gates"]["solvability"]

    assert identity["checks_total"] >= identity["checks_joined"] > 0
    assert inertness["formats_total"] >= inertness["formats_marked"] > 0
    assert solvability["reference_solver_score"] == 1.0
    assert solvability["reference_solver_coverage"] == 1.0
    assert solvability["resolved_questions_passed"] == solvability["resolved_questions_total"] > 0
    assert (
        solvability["multi_artifact_dependencies_passed"]
        == solvability["multi_artifact_dependencies_total"]
        > 0
    )
    assert (
        solvability["counterfactual_checks_passed"]
        == solvability["counterfactual_checks_total"]
        > 0
    )
    assert 0.0 <= solvability["blind_control_score"] <= 1.0
    assert solvability["blind_solver_coverage"] == 1.0
    assert solvability["blind_control_coverage"] == 1.0
    assert solvability["parent_escape_control_score"] == 1.0
    assert solvability["parent_escape_control_coverage"] == 1.0
    assert solvability["parent_escape_export_score"] == 0.0
    assert solvability["parent_escape_export_coverage"] == 0.0
    assert (
        solvability["positive_control_checks_passed"]
        == solvability["positive_control_checks_total"]
        == suite.BENCHMARK_POSITIVE_CONTROL_CHECKS
    )


@pytest.mark.parametrize("path", sorted(_NONVACUOUS_METRIC_CONTRACT))
def test_nonvacuous_metric_decrease_is_a_regression(card, path):
    current = deepcopy(card)
    baseline_value = _metric_value(card, path)
    decrement = 1 if isinstance(baseline_value, int) else 0.0001
    worse_value = baseline_value - decrement
    _set_metric(current, path, worse_value)

    label = _NONVACUOUS_METRIC_CONTRACT[path][2]
    assert (label, "regressed", baseline_value, worse_value) in regressions(card, current)


def test_exported_parent_escape_coverage_is_tracked_lower_better_and_increase_regresses(card):
    path = "gates.solvability.parent_escape_export_coverage"
    configured = {
        metric_path: (direction, tolerance, label)
        for metric_path, direction, tolerance, label in _METRICS
    }
    contract = (
        "lower_better",
        0,
        "solvability: exported parent-escape coverage",
    )
    assert configured[path] == contract
    baseline_value = 0.0
    baseline = deepcopy(card)
    _set_metric(baseline, path, baseline_value)
    current = deepcopy(baseline)
    _set_metric(current, path, baseline_value + 0.0001)
    assert (contract[2], "regressed", baseline_value, baseline_value + 0.0001) in regressions(
        baseline, current
    )


@pytest.mark.parametrize(
    ("required_path", "lookalike_path"),
    [
        ("gates.identity.checks_total", "gates.identity.checks_joined"),
        ("gates.inertness.formats_total", "gates.inertness.formats_marked"),
        ("gates.solvability.blind_control_score", "gates.solvability.blind_solver_score"),
    ],
)
def test_passing_sibling_metric_cannot_substitute_for_required_metric(
    card, required_path, lookalike_path
):
    current = deepcopy(card)
    node = current
    parts = required_path.split(".")
    for part in parts[:-1]:
        node = node[part]
    del node[parts[-1]]

    # The superficially similar numerator/hold-out metric remains present; it must not make
    # the denominator/DEV positive control disappear cleanly from a comparison.
    assert _metric_value(current, lookalike_path) is not None
    label = _NONVACUOUS_METRIC_CONTRACT[required_path][2]
    assert (label, "missing", _metric_value(card, required_path), None) in regressions(
        card, current
    )


def test_scorecard_leaks_no_local_path(card):
    """A scorecard is published. It must not carry this machine's filesystem in it."""
    blob = json.dumps(card)
    for needle in ("/Users/", "/private/", "/tmp/", "/home/", "C:\\\\Users"):
        assert needle not in blob, f"the committed scorecard leaks {needle!r}"


def test_scorecard_declares_its_failures_rather_than_hiding_them(card):
    """Every failing gate must appear in honest_gaps. A quiet failure is the thing we fix."""
    gaps = "\n".join(card["honest_gaps"])
    for name, block in card["gates"].items():
        if block["verdict"] == "fail":
            assert f"({name}) FAILING" in gaps, (
                f"gate '{name}' fails but says nothing in honest_gaps"
            )


def test_the_legacy_aggregate_verdict_cannot_hide_an_open_gap(card):
    """The backward-compatible aggregate still reflects every gate and declared gap.

    New readers should use the scoped status blocks. Existing readers keep the old `verdict`
    field and its original three-valued semantics.
    """
    any_fail = any(b["verdict"] == "fail" for b in card["gates"].values())
    if any_fail:
        assert card["verdict"] == "fail"
    elif card["honest_gaps"]:
        assert card["verdict"] == "gap", "gaps are declared but the headline says otherwise"
    else:
        assert card["verdict"] == "pass"
