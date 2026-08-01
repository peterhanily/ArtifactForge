# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The command line — where a gate becomes a process exit code.

Every gate subcommand prints one verdict line carrying the uncomfortable denominator and
returns 0 or 1, so a workflow step can be a gate without any glue. That is the whole point:
a check that cannot fail a build is a comment.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile

from artifactforge import __version__
from artifactforge import suite
from artifactforge.bench.benchmark import generate_suite
from artifactforge.gates import GateReport, identity, inertness, solvability, validity


def _merge(gate: int, name: str, question: str, reports) -> GateReport:
    """Fold per-scenario reports into one. Metrics sum; reasons are deduped, order kept."""
    out = GateReport(gate, name, question)
    for r in reports:
        for f in r.fails:
            out.fail(f)
        for g in r.gaps:
            out.gap(g)
        for k, v in r.metrics.items():
            if isinstance(v, (int, float)):
                out.metrics[k] = out.metrics.get(k, 0) + v
    return out


def _workdir(args) -> str:
    if not getattr(args, "_wd", None):
        args._wd = getattr(args, "gen_dir", None) or tempfile.mkdtemp(
            prefix="artifactforge-gate-")
    return args._wd


def _dev(args) -> list:
    """A dev suite: the published key, fully reproducible, cheatable on purpose."""
    if not getattr(args, "_dev", None):
        args._dev = generate_suite(args.n, os.path.join(_workdir(args), "dev"),
                                   key=suite.PUBLIC_DEV_KEY, kind="dev")
    return args._dev


def _holdout(args) -> list:
    """A hold-out suite: a key the adversaries do not have, which is the whole test."""
    if not getattr(args, "_holdout", None):
        args._holdout = generate_suite(args.n, os.path.join(_workdir(args), "holdout"),
                                       key=suite.new_key(), kind="holdout")
    return args._holdout


def _scorecard_measurement(args) -> list:
    """The reproducible public corpus used only for scorecard measurement.

    This is deliberately not called a hold-out: its key is derivable from published source,
    and ``bench grade`` refuses to print a reportable score for its suite kind.
    """
    if not getattr(args, "_scorecard_measurement", None):
        root = os.path.join(_workdir(args), suite.SCORECARD_MEASUREMENT_KIND)
        args._scorecard_measurement = generate_suite(
            args.n,
            root,
            key=suite.scorecard_measurement_key(),
            kind=suite.SCORECARD_MEASUREMENT_KIND,
        )
    return args._scorecard_measurement


def _scene_dirs(args) -> list:
    if getattr(args, "scene", None):
        return [args.scene]
    return [t.directory for t in _dev(args)]


def gate_validity(args) -> GateReport:
    r = _merge(1, "validity", "do the declared parser oracles read each classified artifact?",
               [validity.run(d) for d in _scene_dirs(args)])
    r.denominator = (f"{r.metrics.get('oracle_reads_passed', 0)}/"
                     f"{r.metrics.get('oracle_reads_total', 0)} oracle reads succeeded")
    return r


def gate_identity(args) -> GateReport:
    if getattr(args, "scene", None):
        r = GateReport(2, "identity",
                       "do the declared answer-bearing pivots agree with emitted bytes?")
        r.fail("--scene cannot be used with the identity gate: it needs the scene's join, "
               "which lives in the suite's _answers/ and deliberately not in the served "
               "directory. Run without --scene to generate a suite.")
        return r
    r = _merge(2, "identity",
               "do the declared answer-bearing pivots agree with emitted bytes?",
               [identity.run(t.directory, t.join) for t in _dev(args)])
    r.denominator = (f"{r.metrics.get('checks_joined', 0)}/"
                     f"{r.metrics.get('checks_total', 0)} cross-artifact identity checks hold")
    return r


def gate_inertness(args) -> GateReport:
    r = _merge(3, "inertness",
               "are binaries payload-free and classified formats marked synthetic?",
               [inertness.run(d) for d in _scene_dirs(args)])
    r.denominator = (f"{r.metrics.get('formats_marked', 0)}/"
                     f"{r.metrics.get('formats_total', 0)} artifacts carry a synthetic marker")
    return r


def gate_solvability(args) -> GateReport:
    measured = (_scorecard_measurement(args)
                if getattr(args, "_scorecard_measurement_mode", False)
                else _holdout(args))
    return solvability.run(measured, _dev(args))


GATES = {
    "validity": gate_validity,
    "identity": gate_identity,
    "inertness": gate_inertness,
    "solvability": gate_solvability,
}


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:                                     # noqa: BLE001 — not a git checkout
        return "unknown"


def cmd_gate(args) -> int:
    report = GATES[args.name](args)
    print(report.render())
    return 0 if report.ok else 1


def cmd_scorecard(args) -> int:
    from artifactforge.scorecard import (
        build_scorecard,
        load,
        measurement_incompatibilities,
        regressions,
        render_comparison,
        render_measurement_compatibility,
        save,
    )
    # Scorecards are tracked measurements, so their corpus must reproduce. This mode never
    # affects ``gate solvability`` or ``bench new --kind holdout``: both retain fresh keys.
    args._scorecard_measurement_mode = True
    reports = [GATES[n](args) for n in ("validity", "identity", "inertness", "solvability")]
    card = build_scorecard(reports, artifactforge_version=__version__,
                           git_commit=_git_commit(), sqlite_version=sqlite3.sqlite_version,
                           measurement=suite.scorecard_measurement_provenance(args.n))
    if args.check:
        baseline = load(args.check)
        rows = regressions(baseline, card)
        incompatible = measurement_incompatibilities(baseline, card)
        print(render_comparison(baseline, card))
        print(render_measurement_compatibility(baseline, card))
        print(_scorecard_status_summary(card))
        return 1 if rows or incompatible else 0
    if args.out:
        save(card, args.out)
        print(f"wrote {args.out} — {_scorecard_status_summary(card)}, "
              f"{len(card['honest_gaps'])} honest gaps")
    else:
        print(json.dumps(card, indent=2))
    return 0


def _scorecard_status_summary(card: dict) -> str:
    """Render scoped status without presenting experimental Gate 4 as generator failure."""
    status = card["status"]
    generator = status["generator_assurance"]["verdict"]
    benchmark = status["benchmark_validity"]["verdict"]
    return (f"generator assurance: {generator}; "
            f"experimental benchmark validity: {benchmark}; "
            f"aggregate (all gates): {card['verdict']}")


def cmd_bench_new(args) -> int:
    key = suite.PUBLIC_DEV_KEY if args.kind == "dev" else suite.new_key()
    tasks = generate_suite(args.n, args.out, key=key, kind=args.kind)
    print(f"wrote {len(tasks)} scenarios to {args.out} ({args.kind} suite)")
    if args.kind == "dev":
        print("  NOTE: a dev suite is built with the key published in the source. Anyone can\n"
              "        regenerate and cheat it. Scores against it are not reportable.")
    else:
        print(f"  key: {suite.suite_paths(args.out)['key']}\n"
              f"       Lose it and this suite can never be regenerated or audited. "
              f"Never commit it.")
    return 0


def _load_suite(root: str):
    """Read a suite back from disk: what a solver sees, and what the grader knows."""
    from artifactforge.bench.benchmark import PublicQuestion, PublicTask
    with open(suite.suite_paths(root)["public"]) as f:
        public = json.load(f)
    tasks = []
    for entry in public["scenarios"]:
        tasks.append(PublicTask(
            entry["scenario_id"], entry["family"],
            os.path.join(suite.suite_paths(root)["scenarios"], entry["scenario_id"]),
            [PublicQuestion(q["id"], q["prompt"], q["kind"], q["joins"])
             for q in entry["questions"]]))
    return public, tasks


def cmd_bench_solve(args) -> int:
    """Run the reference solver over a suite and write a submission.

    Exactly what an evaluated agent would produce, so the grading path is exercised by the
    same route a real submission takes rather than by a shortcut.
    """
    from artifactforge.bench.reference_solver import reference_solve
    _public, tasks = _load_suite(args.suite)
    with open(args.out, "w") as f:
        for task in tasks:
            f.write(json.dumps({"scenario_id": task.scenario_id,
                                "answers": reference_solve(task)}) + "\n")
    print(f"wrote {len(tasks)} submissions to {args.out}")
    return 0


def cmd_bench_grade(args) -> int:
    from artifactforge.bench.benchmark import normalize
    public, _tasks = _load_suite(args.suite)
    submitted = {}
    with open(args.submission) as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                submitted[row["scenario_id"]] = row.get("answers") or {}

    correct = total = 0
    per_kind = {}
    for entry in public["scenarios"]:
        answers = submitted.get(entry["scenario_id"], {})
        key = suite.read_answers(args.suite, entry["scenario_id"])["answers"]
        for q in entry["questions"]:
            expected = key.get(q["id"])
            ok = (isinstance(answers, dict)
                  and normalize(answers.get(q["id"]), q["kind"])
                  == normalize(expected, q["kind"]))
            hit, seen = per_kind.get(q["kind"], (0, 0))
            per_kind[q["kind"]] = (hit + int(ok), seen + 1)
            correct += int(ok)
            total += 1

    for kind in sorted(per_kind):
        hit, seen = per_kind[kind]
        print(f"  {kind:10s} {hit}/{seen}")
    suite_kind = public.get("suite_kind")
    if suite_kind in suite.NON_REPORTABLE_SUITE_KINDS:
        # Publicly keyed suites are reproducible by anyone. Printing a bare accuracy for one
        # would produce a number someone will eventually quote, and it would mean nothing.
        label = str(suite_kind).upper().replace("-", " ")
        print(f"  SCORE ({label} - NOT REPORTABLE): {correct}/{total}")
        print("  Build a hold-out suite to measure anything: "
              "artifactforge bench new SUITE --kind holdout")
        return 0
    print(f"  SCORE: {correct}/{total} = {correct / total:.1%}" if total else "  no questions")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="artifactforge", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gate", help="run one gate; exits non-zero when the answer is no")
    g.add_argument("name", choices=sorted(GATES))
    g.add_argument("--scene", help="an existing scene directory (validity and inertness only; "
                                   "identity needs a suite and will refuse)")
    g.add_argument("--n", type=int, default=4, help="scenarios to generate (default 4)")
    g.add_argument("--gen-dir", help="where to generate them (default: a temp dir)")
    g.set_defaults(func=cmd_gate)

    s = sub.add_parser("scorecard", help="run every gate and emit the fidelity scorecard")
    s.add_argument("--out", help="write the scorecard to this FILE")
    s.add_argument("--check", help="compare against this baseline; exit 1 on regression")
    s.add_argument("--n", type=int, default=4)
    s.add_argument("--gen-dir")
    s.set_defaults(func=cmd_scorecard, scene=None)

    b = sub.add_parser("bench", help="build a benchmark suite")
    bsub = b.add_subparsers(dest="bench_cmd", required=True)
    bn = bsub.add_parser("new", help="generate a suite")
    bn.add_argument("out", help="suite directory")
    bn.add_argument("--n", type=int, default=20)
    bn.add_argument("--kind", choices=("dev", "holdout"), default="dev",
                    help="dev uses the published key and is not reportable; holdout mints one")
    bn.set_defaults(func=cmd_bench_new)

    bs = bsub.add_parser("solve", help="run the reference solver and write a submission")
    bs.add_argument("suite")
    bs.add_argument("--out", default="answers.jsonl")
    bs.set_defaults(func=cmd_bench_solve)

    bg = bsub.add_parser("grade", help="score a submission against a suite")
    bg.add_argument("suite")
    bg.add_argument("--submission", default="answers.jsonl")
    bg.set_defaults(func=cmd_bench_grade)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
