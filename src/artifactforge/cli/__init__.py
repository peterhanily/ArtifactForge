# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The command line — where a gate becomes a process exit code.

Every gate subcommand prints one verdict line carrying the uncomfortable denominator and
returns 0 or 1, so a workflow step can be a gate without any glue. That is the whole point:
a check that cannot fail a build is a comment.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
import tempfile

from artifactforge import __version__
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


def _scenes(args) -> tuple[list, list]:
    """(scene directories, tasks). Generates a fresh batch unless --scene is given."""
    from artifactforge.bench.benchmark import generate_batch
    if args.scene:
        return [args.scene], []
    gen = getattr(args, "gen_dir", None) or os.path.join(
        tempfile.mkdtemp(prefix="artifactforge-gate-"), "batch")
    tasks = generate_batch(args.n, gen)
    return [t.directory for t in tasks], tasks


def gate_validity(args) -> GateReport:
    dirs, _ = _scenes(args)
    r = _merge(1, "validity", "does an independent real parser read every artifact we ship?",
               [validity.run(d) for d in dirs])
    r.denominator = (f"{r.metrics.get('oracle_reads_passed', 0)}/"
                     f"{r.metrics.get('oracle_reads_total', 0)} oracle reads succeeded")
    return r


def gate_identity(args) -> GateReport:
    dirs, _ = _scenes(args)
    r = _merge(2, "identity",
               "is every hash-shaped field a genuine digest of one ContentStore blob?",
               [identity.run(d) for d in dirs])
    r.denominator = (f"{r.metrics.get('checks_joined', 0)}/"
                     f"{r.metrics.get('checks_total', 0)} cross-artifact identity checks hold")
    return r


def gate_inertness(args) -> GateReport:
    dirs, _ = _scenes(args)
    r = _merge(3, "inertness",
               "can anything we ship execute, and is every format marked synthetic?",
               [inertness.run(d) for d in dirs])
    r.denominator = (f"{r.metrics.get('formats_marked', 0)}/"
                     f"{r.metrics.get('formats_total', 0)} artifacts carry a synthetic marker")
    return r


def gate_solvability(args) -> GateReport:
    _, tasks = _scenes(args)
    if not tasks:
        r = GateReport(4, "solvability", "are the answers recovered, or derivable?")
        r.fails.append("--scene cannot measure solvability; it needs a generated batch")
        return r
    return solvability.run(tasks)


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
    from artifactforge.scorecard import build_scorecard, load, render_comparison, regressions, save
    reports = [GATES[n](args) for n in ("validity", "identity", "inertness", "solvability")]
    card = build_scorecard(reports, artifactforge_version=__version__,
                           git_commit=_git_commit(), sqlite_version=sqlite3.sqlite_version)
    if args.check:
        baseline = load(args.check)
        rows = regressions(baseline, card)
        print(render_comparison(baseline, card))
        return 1 if rows else 0
    if args.out:
        save(card, args.out)
        print(f"wrote {args.out} — verdict: {card['verdict']}, "
              f"{len(card['honest_gaps'])} honest gaps")
    else:
        import json
        print(json.dumps(card, indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="artifactforge", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gate", help="run one gate; exits non-zero when the answer is no")
    g.add_argument("name", choices=sorted(GATES))
    g.add_argument("--scene", help="an existing scene directory (skips generation)")
    g.add_argument("--n", type=int, default=4, help="scenarios to generate (default 4)")
    g.add_argument("--gen-dir", help="where to generate them (default: a temp dir)")
    g.set_defaults(func=cmd_gate)

    s = sub.add_parser("scorecard", help="run every gate and emit the fidelity scorecard")
    s.add_argument("--out", help="write the scorecard to this FILE")
    s.add_argument("--check", help="compare against this committed baseline; exit 1 on regression")
    s.add_argument("--n", type=int, default=4)
    s.set_defaults(func=cmd_scorecard, scene=None)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
