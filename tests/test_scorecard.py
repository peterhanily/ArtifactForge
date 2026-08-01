# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The committed fidelity scorecard must stay valid, honest, and leak nothing local.

CI cannot always recompute the scorecard — some oracles are platform-bound — so it guards the
committed artifact instead. These are the three properties that make guarding it worthwhile.
"""
import hashlib
import json
import os
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

    assert generator["verdict"] == "gap"
    assert not generator["fails"]
    assert generator["gaps"]
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
    }
    assert provenance["key_derivation"]["seed_id"].startswith("sha256:")
    assert provenance["key_derivation"]["key_id"].startswith("sha256:")


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
    monkeypatch.setattr(cli_module, "_git_commit", lambda: "abcdef0")

    paths = [tmp_path / "first.json", tmp_path / "second.json"]
    for path in paths:
        args = SimpleNamespace(n=40, out=str(path), check=None, gen_dir=None, scene=None)
        assert cli_module.cmd_scorecard(args) == 0

    assert paths[0].read_bytes() == paths[1].read_bytes()
    generated = json.loads(paths[0].read_text())
    assert generated["measurement"] == suite.scorecard_measurement_provenance(40)
    assert calls == [(name, True) for name in gates] * 2

    output = capsys.readouterr().out
    assert "generator assurance: gap" in output
    assert "experimental benchmark validity: fail" in output
    assert "aggregate (all gates): fail" in output


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


@pytest.mark.parametrize(("path", "replacement"), [
    (("suite_kind",), "some-other-kind"),
    (("scenario_count",), 41),
    (("suite_derivation_domain",), "artifactforge/bench/v2"),
    (("key_derivation", "domain"), "artifactforge/scorecard/measurement-key/v2"),
    (("key_derivation", "key_id"), "sha256:different"),
])
def test_measurement_identity_changes_make_scorecards_incomparable(path, replacement):
    baseline = {"measurement": suite.scorecard_measurement_provenance(40)}
    current = deepcopy(baseline)
    node = current["measurement"]
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = replacement

    assert measurement_incompatibilities(baseline, current)


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

    assert project_version == "0.0.2"
    assert __version__ == project_version
    assert lock_version == project_version
    assert card["generator"]["artifactforge_version"] == project_version


def test_every_tracked_metric_is_present(card):
    """A metric the scorecard does not carry cannot regress, so its absence is the bug."""
    missing = [label for label, kind, *_ in regressions(card, card) if kind == "missing"]
    assert not missing, f"tracked metrics absent from the committed scorecard: {missing}"
    assert len(_METRICS) >= 8


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
