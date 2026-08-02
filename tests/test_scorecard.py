# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The committed fidelity scorecard must stay valid, honest, and leak nothing local.

CI cannot always recompute the scorecard — some oracles are platform-bound — so it guards the
committed artifact instead. These are the three properties that make guarding it worthwhile.
"""
import hashlib
import json
import os
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
    SCHEMA_VERSION,
    build_scorecard,
    measurement_incompatibilities,
    regressions,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARD_PATH = os.path.join(ROOT, "fidelity-scorecard.json")


@pytest.fixture(scope="module")
def card():
    with open(CARD_PATH) as f:
        return json.load(f)


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


def test_committed_status_keeps_benchmark_red_without_failing_generator(card):
    generator = card["status"]["generator_assurance"]
    benchmark = card["status"]["benchmark_validity"]

    assert generator["verdict"] == "pass"
    assert not generator["fails"]
    assert not generator["gaps"]
    assert benchmark["verdict"] == "fail"
    assert benchmark["fails"]
    assert card["gates"]["solvability"]["verdict"] == "fail"


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


def test_scorecard_measurement_key_has_stable_disclosed_provenance():
    first = suite.scorecard_measurement_key()
    second = suite.scorecard_measurement_key()
    provenance = suite.scorecard_measurement_provenance(40)

    assert first == second
    assert len(first) == 32
    assert first != suite.PUBLIC_DEV_KEY
    assert suite.SCORECARD_MEASUREMENT_KEY_DOMAIN != suite.DOMAIN
    assert provenance == {
        "purpose": "reproducible-scorecard-measurement",
        "scope": "benchmark-validity",
        "suite_kind": "scorecard-measurement",
        "scenario_count": 40,
        "deterministic": True,
        "reportable": False,
        "suite_derivation_domain": "artifactforge/bench/v1",
        "key_derivation": {
            "algorithm": "HMAC-SHA256",
            "domain": "artifactforge/scorecard/measurement-key/v1",
            "seed_id": "sha256:" + hashlib.sha256(
                suite.SCORECARD_MEASUREMENT_SEED).hexdigest(),
            "key_id": suite.scorecard_measurement_key_id(),
        },
        "generator_assurance": {
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
                    "family_counts": {"windows": 20, "macos": 20},
                    "deterministic": True,
                    "benchmark_reportable": False,
                    "suite_derivation_domain": "artifactforge/bench/v1",
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
                    "scene_derivation_domain": (
                        "artifactforge/generator-assurance/linux-scene/v1"
                    ),
                    "content_namespace": "artifactforge::generator-assurance/linux/v1",
                    "count_contract": {
                        "algorithm": "ceil-half-windows-macos-v1",
                        "windows_macos_scenario_count": 40,
                    },
                    "key_derivation": {
                        "algorithm": "HMAC-SHA256",
                        "domain": "artifactforge/generator-assurance/key/v1",
                        "seed_id": "sha256:" + hashlib.sha256(
                            suite.GENERATOR_ASSURANCE_SEED
                        ).hexdigest(),
                        "key_id": suite.generator_assurance_key_id(),
                    },
                },
            },
        },
    }
    assert provenance["key_derivation"]["seed_id"].startswith("sha256:")
    assert provenance["key_derivation"]["key_id"].startswith("sha256:")


def test_committed_scorecard_has_exact_measurement_and_source_provenance(card):
    """The published card must identify both its corpus and a real matching source commit."""
    assert card["measurement"] == suite.scorecard_measurement_provenance(40)

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
    assert provenance["pyproject_sha256"] == "sha256:" + hashlib.sha256(
        git_show("pyproject.toml")
    ).hexdigest()
    assert provenance["uv_lock_sha256"] == "sha256:" + hashlib.sha256(
        git_show("uv.lock")
    ).hexdigest()
    tree = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert provenance["git_tree"] == tree


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

    monkeypatch.setattr(cli_module, "GATES", {
        name: (lambda args, name=name, number=number: run_gate(name, number, args))
        for number, name in enumerate(gates, 1)
    })
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


def test_scorecard_output_refuses_dirty_source_unless_explicitly_allowed(
        tmp_path, monkeypatch, capsys):
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
        {name: (lambda _args, name=name, gate=gate: GateReport(gate, name, name))
         for gate, name in enumerate(("validity", "identity", "inertness", "solvability"), 1)},
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
    monkeypatch.setattr(cli_module, "GATES", {
        name: (lambda _args, report=GateReport(index, name, "question"): report)
        for index, name in enumerate(("validity", "identity", "inertness", "solvability"), 1)
    })
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


def test_solvability_routes_scorecards_to_measurement_and_gates_to_private_holdout(
        monkeypatch):
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
        tmp_path, monkeypatch):
    calls = []

    def generate(n, root, *, key, kind):
        calls.append((n, root, key, kind))
        return ["generated"]

    monkeypatch.setattr(cli_module, "generate_suite", generate)
    args = SimpleNamespace(n=40, gen_dir=str(tmp_path))

    assert cli_module._scorecard_measurement(args) == ["generated"]
    assert cli_module._scorecard_measurement(args) == ["generated"]
    assert calls == [(
        40,
        os.path.join(str(tmp_path), suite.SCORECARD_MEASUREMENT_KIND),
        suite.scorecard_measurement_key(),
        suite.SCORECARD_MEASUREMENT_KIND,
    )]


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


def test_scorecard_check_rejects_missing_measurement_provenance(
        tmp_path, monkeypatch, capsys):
    gates = ("validity", "identity", "inertness", "solvability")
    monkeypatch.setattr(cli_module, "GATES", {
        name: (lambda _args, name=name, number=number: GateReport(number, name, name))
        for number, name in enumerate(gates, 1)
    })

    # Isolate this assertion from metric regression coverage: the baseline is rejected even
    # when the numeric comparison itself says it is clean.
    import artifactforge.scorecard as scorecard_module
    monkeypatch.setattr(scorecard_module, "regressions", lambda _baseline, _current: [])
    monkeypatch.setattr(scorecard_module, "render_comparison",
                        lambda _baseline, _current: "no tracked metric regressed")

    baseline = tmp_path / "legacy-scorecard.json"
    baseline.write_text("{}\n")
    args = SimpleNamespace(n=40, out=None, check=str(baseline), gen_dir=None, scene=None)
    assert cli_module.cmd_scorecard(args) == 1

    output = capsys.readouterr().out
    assert "no tracked metric regressed" in output
    assert "measurement provenance incompatible" in output
    assert "MISSING scenario count" in output
    assert "MISSING measurement key identity" in output


def test_scorecard_measurement_suite_cannot_print_a_reportable_score(
        tmp_path, monkeypatch, capsys):
    public = {
        "suite_kind": suite.SCORECARD_MEASUREMENT_KIND,
        "scenarios": [{
            "scenario_id": "af1_test",
            "questions": [{"id": "q", "kind": "name"}],
        }],
    }
    monkeypatch.setattr(cli_module, "_load_suite", lambda _root: (public, []))
    monkeypatch.setattr(
        suite, "read_answers", lambda _root, _pid: {"answers": {"q": "answer"}})
    submission = tmp_path / "answers.jsonl"
    submission.write_text(json.dumps({
        "scenario_id": "af1_test", "answers": {"q": "answer"}}) + "\n")

    args = SimpleNamespace(suite="unused", submission=str(submission))
    assert cli_module.cmd_bench_grade(args) == 0
    output = capsys.readouterr().out
    assert "SCORE (SCORECARD MEASUREMENT - NOT REPORTABLE): 1/1" in output
    assert "= 100.0%" not in output


def test_package_version_is_consistent_with_release_metadata(card):
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        project_version = tomllib.load(f)["project"]["version"]
    with open(os.path.join(ROOT, "uv.lock"), "rb") as f:
        packages = tomllib.load(f)["package"]
    lock_version = next(p["version"] for p in packages if p["name"] == "artifactforge")

    assert project_version == "0.4.0"
    assert __version__ == project_version
    assert lock_version == project_version
    assert card["generator"]["artifactforge_version"] == project_version


def test_ci_consumes_the_frozen_oracle_lock_in_every_project_lane():
    """Fingerprinting uv.lock is meaningful only if CI actually installs from it."""
    with open(os.path.join(ROOT, ".github", "workflows", "ci.yml")) as f:
        workflow = f.read()
    assert 'UV_FROZEN: "1"' in workflow
    assert 'uv pip install -e ".[dev]"' not in workflow
    assert workflow.count("sync --frozen --extra dev --python") == 5


def test_every_tracked_metric_is_present(card):
    """A metric the scorecard does not carry cannot regress, so its absence is the bug."""
    missing = [label for label, kind, *_ in regressions(card, card) if kind == "missing"]
    assert not missing, f"tracked metrics absent from the committed scorecard: {missing}"
    assert len(_METRICS) >= 8


_NONVACUOUS_METRIC_CONTRACT = {
    "gates.identity.checks_total": (
        "higher_better", 0, "identity: cross-artifact joins declared"),
    "gates.inertness.formats_total": (
        "higher_better", 0, "inertness: marked formats declared"),
    "gates.solvability.blind_control_score": (
        "higher_better", 0, "solvability: blind adversary control"),
}


def _metric_value(card, path):
    node = card
    for part in path.split("."):
        node = node[part]
    return node


def _set_metric(card, path, value):
    node = card
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def test_nonvacuous_metrics_have_exact_paths_directions_and_zero_tolerance():
    """A passing numerator cannot stand in for its denominator or positive control."""
    configured = {
        path: (direction, tolerance, label)
        for path, direction, tolerance, label in _METRICS
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
    assert 0.0 <= solvability["blind_control_score"] <= 1.0


@pytest.mark.parametrize("path", sorted(_NONVACUOUS_METRIC_CONTRACT))
def test_nonvacuous_metric_decrease_is_a_regression(card, path):
    current = deepcopy(card)
    baseline_value = _metric_value(card, path)
    decrement = 1 if isinstance(baseline_value, int) else 0.0001
    worse_value = baseline_value - decrement
    _set_metric(current, path, worse_value)

    label = _NONVACUOUS_METRIC_CONTRACT[path][2]
    assert (label, "regressed", baseline_value, worse_value) in regressions(card, current)


@pytest.mark.parametrize(("required_path", "lookalike_path"), [
    ("gates.identity.checks_total", "gates.identity.checks_joined"),
    ("gates.inertness.formats_total", "gates.inertness.formats_marked"),
    ("gates.solvability.blind_control_score", "gates.solvability.blind_solver_score"),
])
def test_passing_sibling_metric_cannot_substitute_for_required_metric(
        card, required_path, lookalike_path):
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
        card, current)


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
            assert f"({name}) FAILING" in gaps, \
                f"gate '{name}' fails but says nothing in honest_gaps"


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
