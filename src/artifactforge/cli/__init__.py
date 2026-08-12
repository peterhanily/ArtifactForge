# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The command line — where a gate becomes a process exit code.

Every gate subcommand prints one verdict line carrying the uncomfortable denominator and
returns 0 or 1, so a workflow step can be a gate without any glue. That is the whole point:
a check that cannot fail a build is a comment.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile

from artifactforge import __version__
from artifactforge import suite
from artifactforge.bench.benchmark import generate_suite
from artifactforge.compose.assurance import generate_linux_assurance
from artifactforge.gates import GateReport, identity, inertness, solvability, validity
from artifactforge.inventory import (
    InventoryError,
    canonical_relative_paths,
    directory_ancestry_snapshot,
    directory_path_matches_descriptor,
    inventory_regular_files,
    measure_change_visibility,
    open_real_directory,
    path_handle_file_observations_match,
    write_regular_file_at,
)


_SCENARIO_ID = re.compile(r"af1_[a-z2-7]{16}")
_MAX_SUBMISSION_BYTES = 16 * 1024 * 1024
_MAX_SUBMISSION_LINE_BYTES = 1024 * 1024
_MAX_SUBMISSION_ROWS = suite.BENCHMARK_MAX_SCENARIOS
_MAX_SUBMISSION_ANSWER_CHARS = suite.BENCHMARK_ANSWER_MAX_CHARS
_MAX_RETIRED_REPORT_BYTES = 32 * 1024 * 1024
_SHA256_LABEL = re.compile(r"sha256:[0-9a-f]{64}")
_STABLE_FILE_OBSERVATION_FIELDS = (
    "st_dev",
    "st_ino",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _same_domain_file_observations_match(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    for field in _STABLE_FILE_OBSERVATION_FIELDS:
        first_value = getattr(first, field, None)
        second_value = getattr(second, field, None)
        if (
            type(first_value) is not int
            or type(second_value) is not int
            or first_value != second_value
        ):
            return False
    return True


def _windows_file_identity_available(state: os.stat_result) -> bool:
    if sys.platform != "win32":
        return True
    identity = (getattr(state, "st_dev", None), getattr(state, "st_ino", None))
    return all(type(value) is int and value > 0 for value in identity)


def _positive_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("scenario count must be an integer") from exc
    try:
        return suite.validate_benchmark_scenario_count(count)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _benchmark_v3_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("scenario count must be an integer") from exc
    try:
        return suite.validate_benchmark_v3_scenario_count(count)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _labelled_sha256(value: str) -> str:
    if _SHA256_LABEL.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("digest must be sha256: followed by 64 lowercase hex")
    return value


def _read_cli_regular(path: str | os.PathLike[str], where: str, *, max_bytes: int) -> bytes:
    source = Path(path)
    if not source.name or source.name in {".", ".."}:
        raise ValueError(f"{where} must name one regular file")
    try:
        parent = source.parent.resolve(strict=True)
        parent_fd = open_real_directory(parent)
    except (InventoryError, OSError) as exc:
        raise ValueError(f"{where} parent must be a real directory: {exc}") from exc
    try:
        return suite._read_regular_at(parent_fd, source.name, where, max_bytes=max_bytes)
    finally:
        os.close(parent_fd)


def _read_detached_cli_regular(
    path: str | os.PathLike[str], where: str, *, max_bytes: int
) -> bytes:
    """Read one bounded stable file without requiring live-ledger POSIX primitives.

    The resolved parent and final file must be real filesystem objects, not symlinks or
    Windows reparse points.  Identity is checked before opening, immediately after opening,
    and again after the read.  ``O_NOFOLLOW`` is used where the host exposes it; the identity
    check fails closed on hosts where it does not.
    """
    source = Path(path)
    if not source.name or source.name in {".", ".."}:
        raise ValueError(f"{where} must name one regular file")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError(f"{where} byte limit must be a positive integer")

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

    def is_reparse(value: os.stat_result) -> bool:
        attributes = getattr(value, "st_file_attributes", 0)
        return bool(attributes & reparse_flag)

    descriptor = -1
    try:
        parent = source.parent.resolve(strict=True)
        parent_before = parent.lstat()
        if (
            stat.S_ISLNK(parent_before.st_mode)
            or not stat.S_ISDIR(parent_before.st_mode)
            or is_reparse(parent_before)
            or not _windows_file_identity_available(parent_before)
        ):
            raise ValueError(f"{where} parent must be a real directory")
        candidate = parent / source.name
        before = candidate.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or is_reparse(before)
        ):
            raise ValueError(f"{where} must be a regular file, not a link or special file")
        if before.st_size > max_bytes:
            raise ValueError(f"{where} exceeds the {max_bytes}-byte input limit")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        after_open_path = candidate.lstat()
        parent_after_open = parent.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or is_reparse(opened)
            or not path_handle_file_observations_match(before, opened)
            or not path_handle_file_observations_match(after_open_path, opened)
            or not _same_domain_file_observations_match(before, after_open_path)
            or stat.S_ISLNK(after_open_path.st_mode)
            or not stat.S_ISREG(after_open_path.st_mode)
            or is_reparse(after_open_path)
            or (parent_before.st_dev, parent_before.st_ino)
            != (parent_after_open.st_dev, parent_after_open.st_ino)
            or not stat.S_ISDIR(parent_after_open.st_mode)
            or is_reparse(parent_after_open)
            or not _windows_file_identity_available(parent_after_open)
        ):
            raise ValueError(f"{where} changed while it was being opened")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{where} exceeds the {max_bytes}-byte input limit")
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        after_path = candidate.lstat()
        parent_after = parent.lstat()
    except ValueError:
        raise
    except (NotImplementedError, OSError, RuntimeError) as exc:
        raise ValueError(f"cannot safely read {where}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if (
        not _same_domain_file_observations_match(opened, after_read)
        or not path_handle_file_observations_match(after_path, after_read)
        or not _same_domain_file_observations_match(before, after_path)
        or (parent_before.st_dev, parent_before.st_ino)
        != (parent_after.st_dev, parent_after.st_ino)
        or not stat.S_ISDIR(parent_after.st_mode)
        or is_reparse(parent_after)
        or not _windows_file_identity_available(parent_after)
        or stat.S_ISLNK(after_path.st_mode)
        or not stat.S_ISREG(after_path.st_mode)
        or is_reparse(after_path)
    ):
        raise ValueError(f"{where} changed while it was being read")
    data = b"".join(chunks)
    if len(data) != after_read.st_size:
        raise ValueError(f"{where} length changed while it was being read")
    return data


class _PinnedCliOutput:
    """One held output parent proven outside an exact public-export inode."""

    def __init__(
        self,
        *,
        parent: Path,
        parent_fd: int,
        name: str,
        forbidden_identity: tuple[int, int],
        ancestry: tuple[tuple[int, int], ...],
        where: str,
    ) -> None:
        self.parent = parent
        self.parent_fd = parent_fd
        self.name = name
        self.forbidden_identity = forbidden_identity
        self.ancestry = ancestry
        self.where = where

    def require_stable(self) -> None:
        """Recheck containment, ancestry and pathname binding through held descriptors."""
        try:
            current = directory_ancestry_snapshot(self.parent_fd)
        except InventoryError as exc:
            raise ValueError(
                f"cannot recheck {self.where} parent ancestry safely: {exc}"
            ) from exc
        if self.forbidden_identity in current:
            raise ValueError(
                f"{self.where} output must be outside the public export "
                "validated by its held directory inode"
            )
        if current != self.ancestry:
            raise ValueError(f"{self.where} parent ancestry changed during the operation")
        if not directory_path_matches_descriptor(self.parent, self.parent_fd):
            raise ValueError(f"{self.where} parent path changed during the operation")


@contextmanager
def _pinned_public_output(
    public_root: str | os.PathLike[str],
    output: str | os.PathLike[str],
    where: str,
):
    """Pin the export and an output parent, then enforce their inode disjointness."""
    destination = Path(output)
    if not destination.name or destination.name in {".", ".."}:
        raise ValueError(f"{where} must have one non-empty final component")
    public_fd = parent_fd = -1
    try:
        try:
            public_fd = open_real_directory(public_root)
            parent = destination.parent.resolve(strict=True)
            parent_fd = open_real_directory(parent)
            public_state = os.fstat(public_fd)
            ancestry = directory_ancestry_snapshot(parent_fd)
            boundary = _PinnedCliOutput(
                parent=parent,
                parent_fd=parent_fd,
                name=destination.name,
                forbidden_identity=(public_state.st_dev, public_state.st_ino),
                ancestry=ancestry,
                where=where,
            )
            boundary.require_stable()
        except InventoryError as exc:
            raise ValueError(
                f"cannot establish safe {where} output boundary: {exc}"
            ) from exc
        except OSError as exc:
            raise ValueError(f"{where} parent must be a real directory: {exc}") from exc
        yield public_fd, boundary
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        if public_fd >= 0:
            os.close(public_fd)


def _publish_private_cli_file(
    boundary: _PinnedCliOutput, payload: bytes, where: str
) -> None:
    """Publish below a held parent only while its export boundary remains unchanged."""
    boundary.require_stable()
    try:
        write_regular_file_at(boundary.parent_fd, boundary.name, payload, mode=0o600)
        published = os.stat(
            boundary.name,
            dir_fd=boundary.parent_fd,
            follow_symlinks=False,
        )
    except InventoryError as exc:
        raise ValueError(f"cannot publish {where} safely: {exc}") from exc
    except (NotImplementedError, OSError) as exc:
        raise ValueError(f"cannot inspect published {where} safely: {exc}") from exc
    try:
        boundary.require_stable()
    except ValueError as boundary_error:
        cleanup_succeeded = False
        try:
            current = os.stat(
                boundary.name,
                dir_fd=boundary.parent_fd,
                follow_symlinks=False,
            )
            if (
                (current.st_dev, current.st_ino) == (published.st_dev, published.st_ino)
                and current.st_size == published.st_size
            ):
                os.unlink(boundary.name, dir_fd=boundary.parent_fd)
                cleanup_succeeded = True
        except (NotImplementedError, OSError):
            pass
        if not cleanup_succeeded:
            raise ValueError(
                f"{where} output boundary changed after publication and exact cleanup "
                "could not be confirmed"
            ) from boundary_error
        raise


def _require_disjoint_roots(
    evaluator: str | os.PathLike[str], other: str | os.PathLike[str], *, other_exists: bool
) -> None:
    """Reject an attempt/reveal path nested in the exact private evaluator root."""
    evaluator_root = Path(evaluator).resolve(strict=True)
    candidate = Path(other)
    if other_exists:
        other_path = candidate.resolve(strict=True)
    else:
        other_path = candidate.parent.resolve(strict=True) / candidate.name
    try:
        other_path.relative_to(evaluator_root)
    except ValueError:
        pass
    else:
        raise ValueError("attempt state and reveal files must be outside the evaluator root")
    if other_exists:
        try:
            evaluator_root.relative_to(other_path)
        except ValueError:
            pass
        else:
            raise ValueError("attempt state must not contain the evaluator root")


def _merge(gate: int, name: str, question: str, reports) -> GateReport:
    """Fold per-scenario reports into one. Numeric leaves sum at any declared depth."""

    def merge_metrics(target: dict, source: dict, prefix: str = "metrics") -> None:
        for key, value in source.items():
            where = f"{prefix}.{key}"
            if isinstance(value, (int, float)):
                existing = target.get(key, 0)
                if not isinstance(existing, (int, float)):
                    raise TypeError(f"metric shape changed at {where}")
                target[key] = existing + value
            elif isinstance(value, dict):
                existing = target.setdefault(key, {})
                if not isinstance(existing, dict):
                    raise TypeError(f"metric shape changed at {where}")
                merge_metrics(existing, value, where)

    out = GateReport(gate, name, question)
    for r in reports:
        for f in r.fails:
            out.fail(f)
        for g in r.gaps:
            out.gap(g)
        merge_metrics(out.metrics, r.metrics)
    return out


def _workdir(args) -> str:
    if getattr(args, "_wd", None):
        return args._wd
    if getattr(args, "gen_dir", None):
        args._wd = args.gen_dir
        return args._wd
    raise RuntimeError("temporary gate workdir lifecycle was not initialized by main()")


def _dev(args) -> list:
    """A dev suite: the published key, fully reproducible, cheatable on purpose."""
    if not getattr(args, "_dev", None):
        args._dev = generate_suite(
            args.n, os.path.join(_workdir(args), "dev"), key=suite.PUBLIC_DEV_KEY, kind="dev"
        )
    return args._dev


def _holdout(args) -> list:
    """A private-key v2 corpus for local Gate 4 diagnostics, never performance reporting."""
    if not getattr(args, "_holdout", None):
        args._holdout = generate_suite(
            args.n, os.path.join(_workdir(args), "holdout"), key=suite.new_key(), kind="holdout"
        )
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


def _linux_assurance(args) -> list:
    """Linux scenes for Gates 1-3 only; never questions, scores, or Gate 4 input."""
    if not getattr(args, "_linux_assurance", None):
        args._linux_assurance = generate_linux_assurance(
            args.n, os.path.join(_workdir(args), "generator-assurance-linux")
        )
    return args._linux_assurance


def _assurance(args) -> list:
    """The deterministic W/M/L corpus over which generator assurance is measured."""
    return [*_dev(args), *_linux_assurance(args)]


def _scene_dirs(args) -> list:
    if getattr(args, "scene", None):
        return [args.scene]
    return [scene.directory for scene in _assurance(args)]


def gate_validity(args) -> GateReport:
    r = _merge(
        1,
        "validity",
        "do declared parser and semantic oracles validate each artifact?",
        [validity.run(d) for d in _scene_dirs(args)],
    )
    r.denominator = (
        f"{r.metrics.get('oracle_reads_passed', 0)}/"
        f"{r.metrics.get('oracle_reads_total', 0)} oracle reads succeeded; "
        f"{r.metrics.get('semantic_checks_passed', 0)}/"
        f"{r.metrics.get('semantic_checks_total', 0)} semantic checks succeeded"
    )
    return r


def gate_identity(args) -> GateReport:
    if getattr(args, "scene", None):
        r = GateReport(
            2, "identity", "do the declared answer-bearing pivots agree with emitted bytes?"
        )
        r.fail(
            "--scene cannot be used with the identity gate: it needs the scene's join, "
            "which exists only in construction-time evaluator state and is deliberately "
            "not persisted in the served directory or answer key. Run without --scene "
            "to generate a suite."
        )
        return r
    r = _merge(
        2,
        "identity",
        "do the declared answer-bearing pivots agree with emitted bytes?",
        [identity.run(scene.directory, scene.join) for scene in _assurance(args)],
    )
    r.denominator = (
        f"{r.metrics.get('checks_joined', 0)}/"
        f"{r.metrics.get('checks_total', 0)} cross-artifact identity checks hold"
    )
    return r


def gate_inertness(args) -> GateReport:
    r = _merge(
        3,
        "inertness",
        "are binaries payload-free and classified formats marked synthetic?",
        [inertness.run(d) for d in _scene_dirs(args)],
    )
    r.denominator = (
        f"{r.metrics.get('binary_safety_checks_passed', 0)}/"
        f"{r.metrics.get('binary_safety_checks_total', 0)} binary safety checks pass; "
        f"{r.metrics.get('formats_marked', 0)}/"
        f"{r.metrics.get('formats_total', 0)} artifacts carry a synthetic marker"
    )
    return r


def gate_solvability(args) -> GateReport:
    measured = (
        _scorecard_measurement(args)
        if getattr(args, "_scorecard_measurement_mode", False)
        else _holdout(args)
    )
    return solvability.run(measured, _dev(args))


GATES = {
    "validity": gate_validity,
    "identity": gate_identity,
    "inertness": gate_inertness,
    "solvability": gate_solvability,
}


_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _git(*arguments: str, text: bool = True):
    return subprocess.run(
        ["git", *arguments],
        cwd=_REPOSITORY_ROOT,
        capture_output=True,
        text=text,
        check=True,
    ).stdout


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dirty_snapshot_sha256(diff: bytes, untracked: list[str]) -> str | None:
    """Bind allowed dirty output to both the tracked diff and every untracked byte."""
    if not diff and not untracked:
        return None
    digest = hashlib.sha256(b"artifactforge/scorecard/dirty-source/v1\0")
    digest.update(len(diff).to_bytes(8, "big"))
    digest.update(diff)
    for relative in sorted(untracked):
        path = _REPOSITORY_ROOT / relative
        payload = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def _git_source_provenance() -> dict:
    """Describe the exact committed source, plus a content binding if it is dirty."""
    commit = _git("rev-parse", "HEAD").strip()
    tree = _git("rev-parse", "HEAD^{tree}").strip()
    diff = _git("diff", "--binary", "HEAD", text=False)
    raw_untracked = _git("ls-files", "--others", "--exclude-standard", "-z", text=False)
    untracked = [part.decode("utf-8") for part in raw_untracked.split(b"\0") if part]
    dirty_digest = _dirty_snapshot_sha256(diff, untracked)
    return {
        "schema": "artifactforge-source-provenance-v1",
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": dirty_digest is None,
        "dirty_snapshot_sha256": dirty_digest,
        "untracked_file_count": len(untracked),
        "pyproject_sha256": "sha256:" + _file_sha256(_REPOSITORY_ROOT / "pyproject.toml"),
        "uv_lock_sha256": "sha256:" + _file_sha256(_REPOSITORY_ROOT / "uv.lock"),
        "build_constraints_sha256": "sha256:"
        + _file_sha256(_REPOSITORY_ROOT / "build-constraints.txt"),
    }


def cmd_gate(args) -> int:
    report = GATES[args.name](args)
    print(report.render())
    return 0 if report.ok else 1


def _host_honest_gaps(args) -> list[str]:
    """Name the host limitations the gates cannot see, so a run does not inherit an
    unearned pass.

    The snapshot boundary's change-and-restore rejection is only as strong as the
    filesystem's timestamp granularity. Where a same-size rewrite leaves the stat tuple
    unchanged, the check is silently weaker on this host than the documented claim, and the
    verdict should read ``gap`` rather than ``pass``.
    """
    where = getattr(args, "gen_dir", None) or tempfile.gettempdir()
    try:
        visibility = measure_change_visibility(where)
    except InventoryError as exc:
        return [f"Host filesystem change visibility could not be probed at {where}: {exc}"]
    if visibility.complete:
        return []
    return [
        f"Host filesystem at {where} does not expose same-size in-place rewrites through "
        f"stat timestamps ({visibility.describe()}), so archive capture cannot detect bytes "
        f"restored before its second pass"
    ]


def cmd_scorecard(args) -> int:
    from artifactforge.scorecard import (
        ScorecardError,
        build_scorecard,
        load,
        measurement_incompatibilities,
        regressions,
        render_comparison,
        render_measurement_compatibility,
        render_status_comparison,
        render_structure_errors,
        save,
        scorecard_structure_errors,
        status_regressions,
        validated_bytes,
    )

    baseline = None
    if args.check:
        try:
            baseline = load(args.check)
        except (OSError, ScorecardError, TypeError) as exc:
            print(f"cannot safely load scorecard baseline: {exc}", file=sys.stderr)
            return 2
        baseline_errors = scorecard_structure_errors(baseline, where="baseline")
        if baseline_errors:
            print(render_structure_errors(baseline_errors))
            return 1

    try:
        source = _git_source_provenance()
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        print(f"cannot attest scorecard source: {exc}", file=sys.stderr)
        return 2
    if args.out and not source["worktree_clean"] and not getattr(args, "allow_dirty", False):
        print(
            "refusing to write a scorecard from a dirty worktree; commit the source or pass "
            "--allow-dirty for an explicitly dirty, non-release record",
            file=sys.stderr,
        )
        return 2

    # Scorecards are tracked measurements, so their corpus must reproduce. This mode never
    # affects ``gate solvability`` or ``bench new --kind holdout``: both retain fresh keys.
    args._scorecard_measurement_mode = True
    reports = [GATES[n](args) for n in ("validity", "identity", "inertness", "solvability")]
    try:
        source_after = _git_source_provenance()
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        print(f"cannot re-attest scorecard source after measurement: {exc}", file=sys.stderr)
        return 2
    if source_after != source:
        print(
            "refusing scorecard result because the source changed during measurement",
            file=sys.stderr,
        )
        return 2
    card = build_scorecard(
        reports,
        artifactforge_version=__version__,
        git_commit=source["git_commit"][:7],
        sqlite_version=sqlite3.sqlite_version,
        honest_gaps=_host_honest_gaps(args),
        measurement=suite.scorecard_measurement_provenance(args.n),
        source=source,
    )
    # A red gate is a failure whether or not the caller asked for strictness; anything else
    # would make the command that defines "done" the one command that cannot fail a build.
    # ``gap`` stays green on its own: a declared limitation is honest, not broken, and
    # --require-pass is what rejects it.
    verdict_failed = card.get("verdict") == "fail"
    require_pass_failed = bool(
        getattr(args, "require_pass", False) and card.get("verdict") != "pass"
    )
    try:
        rendered_card = validated_bytes(card)
    except (ScorecardError, TypeError) as exc:
        print(f"generated scorecard violates the release contract: {exc}", file=sys.stderr)
        return 2
    if args.check:
        structure_errors = scorecard_structure_errors(card, where="current")
        print(render_structure_errors(structure_errors))
        if structure_errors:
            print("metric, provenance and status comparisons not run against invalid current")
            print(_scorecard_status_summary(card))
            return 1
        rows = regressions(baseline, card)
        incompatible = measurement_incompatibilities(baseline, card)
        status_rows = status_regressions(baseline, card)
        print(render_comparison(baseline, card))
        print(render_measurement_compatibility(baseline, card))
        print(render_status_comparison(baseline, card))
        print(_scorecard_status_summary(card))
        return (
            1
            if rows or incompatible or status_rows or require_pass_failed or verdict_failed
            else 0
        )
    if args.out:
        try:
            save(card, args.out)
        except (OSError, ScorecardError, TypeError) as exc:
            print(f"cannot safely publish scorecard: {exc}", file=sys.stderr)
            return 2
        print(
            f"wrote {args.out} — {_scorecard_status_summary(card)}, "
            f"{len(card['honest_gaps'])} honest gaps"
        )
    else:
        # The card goes to stdout so it stays pipeable; the verdict goes to stderr so a
        # reader who ran this without redirecting still sees the answer.
        sys.stdout.write(rendered_card.decode("utf-8"))
        print(
            f"{_scorecard_status_summary(card)}, {len(card['honest_gaps'])} honest gaps",
            file=sys.stderr,
        )
    return 1 if require_pass_failed or verdict_failed else 0


def _scorecard_status_summary(card: dict) -> str:
    """Render scoped status without presenting experimental Gate 4 as generator failure."""
    status = card["status"]
    generator = status["generator_assurance"]["verdict"]
    benchmark = status["benchmark_validity"]["verdict"]
    return (
        f"generator assurance: {generator}; "
        f"experimental benchmark validity: {benchmark}; "
        f"aggregate (all gates): {card['verdict']}"
    )


def cmd_bench_new(args) -> int:
    key = suite.PUBLIC_DEV_KEY if args.kind == "dev" else suite.new_key()
    tasks = generate_suite(args.n, args.out, key=key, kind=args.kind)
    print(f"wrote {len(tasks)} scenarios to {args.out} ({args.kind} legacy v2 local suite)")
    if args.kind == "dev":
        print(
            "  NOTE: a dev suite is built with the key published in the source. Anyone can\n"
            "        regenerate and cheat it. Scores against it are not reportable."
        )
    else:
        print(
            f"  key: {suite.suite_paths(args.out)['key']}\n"
            f"       Lose it and this suite can never be regenerated or audited. "
            "Never commit it. This v2 local suite is permanently non-reportable."
        )
    return 0


def cmd_bench_ceremony_create(args) -> int:
    """Create one self-attested v3 evaluator root without accepting caller key material."""
    from artifactforge.bench.ceremony import create_evaluator_ceremony

    tasks = create_evaluator_ceremony(args.n, args.out)
    document = suite.load_evaluator_public(args.out)
    origin = document["origin"]
    print(f"wrote {len(tasks)} scenarios to {args.out} (benchmark v3 evaluator ceremony)")
    print(f"  ceremony_id: {origin['ceremony_id']}")
    print(f"  suite_id: {document['suite_id']}")
    print(f"  reportability: {origin['reportability']} (not itself a reportable result)")
    print(f"  TRUST: {origin['trust']}")
    return 0


def _load_suite(root: str, *, role: str, include_private: bool = False):
    """Load one evaluator-private root; solver tasks require a scoped frozen loader."""
    from artifactforge.bench.benchmark import (
        PublicQuestion,
        PublicTask,
    )

    if role == "solver":
        raise ValueError(
            "solver tasks must be consumed inside frozen_public_tasks(), not returned live"
        )
    if role != "evaluator":
        raise ValueError(f"unknown benchmark load role: {role!r}")
    paths = suite.suite_paths(root)
    public, private_answers = suite.load_evaluator_private(root)
    if not isinstance(public, dict):
        raise ValueError("public suite document must be a JSON object")
    scenarios = public.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("public suite scenarios must be a JSON list")
    suite_kind = public.get("suite_kind")
    if not isinstance(suite_kind, str) or not suite_kind:
        raise ValueError("public suite suite_kind must be a non-empty string")

    validated = []
    seen_scenario_ids = set()
    for index, entry in enumerate(scenarios):
        if not isinstance(entry, dict):
            raise ValueError(f"public suite scenario {index} must be a JSON object")
        scenario_id = entry.get("scenario_id")
        if not isinstance(scenario_id, str) or _SCENARIO_ID.fullmatch(scenario_id) is None:
            raise ValueError(
                f"public suite scenario {index} has an invalid scenario_id: {scenario_id!r}"
            )
        if scenario_id in seen_scenario_ids:
            raise ValueError(f"public suite has duplicate scenario_id {scenario_id!r}")
        seen_scenario_ids.add(scenario_id)

        family = entry.get("family")
        if not isinstance(family, str) or not family:
            raise ValueError(f"scenario {scenario_id!r} family must be a non-empty string")
        questions_raw = entry.get("questions")
        if not isinstance(questions_raw, list):
            raise ValueError(f"scenario {scenario_id!r} questions must be a JSON list")
        seen_question_ids = set()
        for question_index, question in enumerate(questions_raw):
            if not isinstance(question, dict):
                raise ValueError(
                    f"scenario {scenario_id!r} question {question_index} must be a JSON object"
                )
            for field in ("id", "prompt", "kind", "rule"):
                if not isinstance(question.get(field), str) or not question[field]:
                    raise ValueError(
                        f"scenario {scenario_id!r} question {question_index} "
                        f"field {field!r} must be a non-empty string"
                    )
            question_id = question["id"]
            if question_id in seen_question_ids:
                raise ValueError(
                    f"scenario {scenario_id!r} has duplicate question id {question_id!r}"
                )
            seen_question_ids.add(question_id)
            selector = question.get("selector")
            if not isinstance(selector, dict):
                raise ValueError(
                    f"scenario {scenario_id!r} question {question_index} "
                    "field 'selector' must be a JSON object"
                )
            candidate_count = question.get("candidate_count")
            if type(candidate_count) is not int or candidate_count < 1:
                raise ValueError(
                    f"scenario {scenario_id!r} question {question_index} "
                    "field 'candidate_count' must be a positive integer"
                )

        published_raw = entry.get("artifacts")
        if not isinstance(published_raw, list):
            raise ValueError(f"scenario {scenario_id!r} published artifacts must be a JSON list")
        try:
            published = canonical_relative_paths(published_raw, require_sorted=True)
        except InventoryError as exc:
            raise ValueError(
                f"scenario {scenario_id!r} has an invalid published artifact inventory: {exc}"
            ) from exc
        if not published:
            raise ValueError(
                f"scenario {scenario_id!r} published artifact inventory must not be empty"
            )
        validated.append((scenario_id, family, questions_raw, published))

    tasks = []
    for scenario_id, family, questions_raw, published in validated:
        directory = os.path.join(paths["scenarios"], scenario_id)
        try:
            observed = tuple(file.relative_path for file in inventory_regular_files(directory))
        except InventoryError as exc:
            raise ValueError(
                f"scenario {scenario_id!r} served artifact tree is unsafe: {exc}"
            ) from exc
        if published != observed:
            missing = sorted(set(published) - set(observed))
            extra = sorted(set(observed) - set(published))
            differences = []
            if missing:
                differences.append("missing: " + ", ".join(missing))
            if extra:
                differences.append("extra: " + ", ".join(extra))
            raise ValueError(
                f"scenario {scenario_id!r} published artifact inventory does not match "
                f"the served tree ({'; '.join(differences)})"
            )

        tasks.append(
            PublicTask(
                scenario_id=scenario_id,
                family=family,
                directory=directory,
                questions=[
                    PublicQuestion(
                        q["id"],
                        q["prompt"],
                        q["kind"],
                        q["rule"],
                        dict(q["selector"]),
                        q["candidate_count"],
                    )
                    for q in questions_raw
                ],
                suite_kind=suite_kind,
                artifacts=published,
            )
        )
    if include_private:
        return public, tasks, private_answers
    return public, tasks


def cmd_bench_solve(args) -> int:
    """Run the reference solver over a suite and write a submission.

    Exactly what an evaluated agent would produce, so the grading path is exercised by the
    same route a real submission takes rather than by a shortcut.
    """
    from artifactforge.bench.benchmark import frozen_public_tasks
    from artifactforge.bench.reference_solver import reference_solve
    from artifactforge.bench.submission import canonical_submission_bytes

    with _pinned_public_output(
        args.suite,
        args.out,
        "solver submission",
    ) as (public_fd, output):
        with frozen_public_tasks(args.suite, pinned_root_fd=public_fd) as (public, tasks):
            answers = {}
            for task in tasks:
                answers[task.scenario_id] = reference_solve(task)
            payload = canonical_submission_bytes(public, answers)
        _publish_private_cli_file(output, payload, "solver submission")
    print(f"wrote {len(tasks)} submissions to {args.out}")
    return 0


def cmd_bench_precommit(args) -> int:
    """Bind canonical reveal bytes and solver-supplied provenance before evaluator receipt."""
    from artifactforge.bench.submission import MAX_SUBMISSION_BYTES, build_precommit

    with _pinned_public_output(
        args.public,
        args.out,
        "benchmark precommitment",
    ) as (public_fd, output):
        public = suite.load_public_export(
            args.public,
            pinned_root_fd=public_fd,
        )
        reveal = _read_cli_regular(
            args.submission,
            "benchmark submission",
            max_bytes=MAX_SUBMISSION_BYTES,
        )
        document = build_precommit(
            public,
            reveal,
            implementation_sha256=args.implementation_sha256,
            configuration_sha256=args.configuration_sha256,
            source_sha256=args.source_sha256,
        )
        _publish_private_cli_file(
            output,
            suite.canonical_public_bytes(document),
            "benchmark precommitment",
        )
    print(f"wrote precommitment {document['commitment_id']} to {args.out}")
    print(f"  suite_id: {document['suite_id']}")
    print("  LIMITATION: solver provenance digests are caller assertions, not attestations.")
    return 0


def cmd_bench_attempt_accept(args) -> int:
    from artifactforge.bench.attempt import accept_precommit
    from artifactforge.bench.submission import MAX_PRECOMMIT_BYTES

    _require_disjoint_roots(args.evaluator, args.ledger, other_exists=False)
    precommit = _read_cli_regular(
        args.precommit,
        "benchmark precommitment",
        max_bytes=MAX_PRECOMMIT_BYTES,
    )
    acceptance = accept_precommit(args.ledger, args.evaluator, precommit)
    sys.stdout.buffer.write(suite.canonical_public_bytes(acceptance))
    return 0


def cmd_bench_attempt_consume(args) -> int:
    from artifactforge.bench.attempt import consume_attempt

    _require_disjoint_roots(args.evaluator, args.ledger, other_exists=True)
    receipt = consume_attempt(
        args.ledger,
        args.evaluator,
        args.submission,
    )
    sys.stdout.buffer.write(suite.canonical_public_bytes(receipt))
    return 0


def cmd_bench_attempt_retire(args) -> int:
    from artifactforge.bench.attempt import retire_attempt

    retirement = retire_attempt(args.ledger)
    sys.stdout.buffer.write(suite.canonical_public_bytes(retirement))
    return 0


def cmd_bench_attempt_report(args) -> int:
    from artifactforge.bench.attempt import retired_report

    report = retired_report(args.ledger)
    sys.stdout.buffer.write(suite.canonical_public_bytes(report))
    return 0


def cmd_bench_attempt_verify(args) -> int:
    """Verify one detached retired report without opening or mutating a live ledger."""
    from artifactforge.bench.attempt import verify_retired_report
    from artifactforge.bench.submission import MAX_SUBMISSION_BYTES

    report_bytes = _read_detached_cli_regular(
        args.report,
        "detached retired report",
        max_bytes=_MAX_RETIRED_REPORT_BYTES,
    )
    report = suite._strict_public_document(report_bytes, "detached retired report")
    if report_bytes != suite.canonical_public_bytes(report):
        raise ValueError("detached retired report must use canonical JSON")
    reveal = None
    if args.reveal is not None:
        reveal = _read_detached_cli_regular(
            args.reveal,
            "detached benchmark reveal",
            max_bytes=MAX_SUBMISSION_BYTES,
        )
    summary = verify_retired_report(report, reveal=reveal)
    sys.stdout.buffer.write(suite.canonical_public_bytes(summary))
    return 0


def cmd_bench_grade(args) -> int:
    from artifactforge.bench.benchmark import normalize

    public, tasks, private_answers = _load_suite(args.suite, role="evaluator", include_private=True)
    if suite.benchmark_reportability(public) != suite.REPORTABILITY_PERMANENTLY_INELIGIBLE:
        raise ValueError(
            "Benchmark v3 disables repeat grade feedback; use bench precommit and "
            "bench attempt accept/consume/retire/report"
        )
    expected_suite_id = public["suite_id"]
    expected_scenarios = {
        entry["scenario_id"]: {question["id"] for question in entry["questions"]}
        for entry in public["scenarios"]
    }
    submission_path = Path(args.submission)
    try:
        submission_parent = submission_path.parent.resolve(strict=True)
        submission_parent_fd = open_real_directory(submission_parent)
    except (InventoryError, OSError) as exc:
        raise ValueError(f"submission parent must be a real directory: {exc}") from exc
    try:
        submission_bytes = suite._read_regular_at(
            submission_parent_fd,
            submission_path.name,
            "benchmark submission",
            max_bytes=_MAX_SUBMISSION_BYTES,
        )
    finally:
        os.close(submission_parent_fd)

    lines = submission_bytes.splitlines()
    if len(lines) > _MAX_SUBMISSION_ROWS:
        raise ValueError(f"submission exceeds the {_MAX_SUBMISSION_ROWS}-row input limit")
    submitted = {}
    for line_number, line in enumerate(lines, 1):
        if not line:
            raise ValueError(f"submission line {line_number} must not be blank")
        if len(line) > _MAX_SUBMISSION_LINE_BYTES:
            raise ValueError(
                f"submission line {line_number} exceeds the "
                f"{_MAX_SUBMISSION_LINE_BYTES}-byte input limit"
            )
        row = suite._strict_public_document(line, f"submission line {line_number}")
        if set(row) != {"answers", "scenario_id", "suite_id"}:
            raise ValueError(
                f"submission line {line_number} must contain exactly answers/scenario_id/suite_id"
            )
        if not isinstance(row["suite_id"], str) or row["suite_id"] != expected_suite_id:
            raise ValueError(
                f"submission line {line_number} suite_id does not match evaluator suite"
            )
        scenario_id = row["scenario_id"]
        if not isinstance(scenario_id, str) or scenario_id not in expected_scenarios:
            raise ValueError(f"submission line {line_number} scenario_id is not in evaluator suite")
        if scenario_id in submitted:
            raise ValueError(
                f"submission line {line_number} duplicates scenario_id {scenario_id!r}"
            )
        answers = row["answers"]
        if not isinstance(answers, dict):
            raise ValueError(f"submission line {line_number} answers must be a JSON object")
        if set(answers) != expected_scenarios[scenario_id]:
            raise ValueError(
                f"submission line {line_number} answers must contain exactly the "
                "scenario's five question ids"
            )
        if not all(
            isinstance(value, str) and len(value) <= _MAX_SUBMISSION_ANSWER_CHARS
            for value in answers.values()
        ):
            raise ValueError(
                f"submission line {line_number} answer values must be strings no longer "
                f"than {_MAX_SUBMISSION_ANSWER_CHARS} characters"
            )
        submitted[scenario_id] = answers
    missing_scenarios = sorted(set(expected_scenarios) - set(submitted))
    if missing_scenarios:
        raise ValueError("submission is missing scenario rows: " + ", ".join(missing_scenarios))

    correct = total = 0
    per_kind = {}
    for entry in public["scenarios"]:
        answers = submitted[entry["scenario_id"]]
        key = private_answers[entry["scenario_id"]]["answers"]
        for q in entry["questions"]:
            expected = key.get(q["id"])
            ok = isinstance(answers, dict) and normalize(
                answers.get(q["id"]), q["kind"]
            ) == normalize(expected, q["kind"])
            hit, seen = per_kind.get(q["kind"], (0, 0))
            per_kind[q["kind"]] = (hit + int(ok), seen + 1)
            correct += int(ok)
            total += 1

    for kind in sorted(per_kind):
        hit, seen = per_kind[kind]
        print(f"  {kind:10s} {hit}/{seen}")
    suite_kind = public.get("suite_kind")
    label = str(suite_kind).upper().replace("-", " ")
    population = len(public["scenarios"])
    rendered_score = f"{correct}/{total} = {correct / total:.1%}" if total else "no questions"
    reportability = suite.benchmark_reportability(public)
    if suite_kind in suite.NON_REPORTABLE_SUITE_KINDS:
        # Publicly keyed suites are reproducible by anyone. Printing a bare accuracy for one
        # would produce a number someone will eventually quote, and it would mean nothing.
        reason = "PUBLIC REPRODUCIBLE KEY"
    elif reportability == suite.REPORTABILITY_PERMANENTLY_INELIGIBLE:
        reason = "LEGACY V2 LOCAL PROTOCOL"
    else:
        # The local grader can validate a fresh key and exact suite identity, but cannot
        # observe whether an untrusted solver was OS-isolated from the evaluator root or
        # whether this exact export crossed the claimed trust boundary. Never mint a
        # reportable performance claim from evidence the process does not possess.
        reason = "TRUST DOMAIN UNATTESTED"
    print(f"  RAW SCORE ({label} - {reason}; NOT REPORTABLE): {rendered_score}")
    print(f"  suite_id: {expected_suite_id}")
    print(f"  population: {population} scenarios / {total} questions")
    if reportability == suite.REPORTABILITY_PERMANENTLY_INELIGIBLE:
        print("  This protocol classification is permanent; later attestation cannot promote it.")
    elif suite_kind in suite.NON_REPORTABLE_SUITE_KINDS:
        print("  A freshly keyed holdout is necessary, but not sufficient, for reporting.")
    else:
        print(
            "  Reporting additionally requires preserved external OS trust-domain, "
            "export, gate, and provenance attestation."
        )
    return 0


def cmd_bench_export(args) -> int:
    """Publish the exact solver view while leaving all grading material evaluator-side."""
    public, _tasks = _load_suite(args.evaluator, role="evaluator")
    result = suite.export_public(
        args.evaluator,
        args.public,
        expected_document=public,
    )
    payload = result["payload"]
    print(
        f"wrote public export {args.public}: {result['suite_id']}, "
        f"{payload['file_count']} files/{payload['total_size']} bytes"
    )
    print(f"  LIMITATION: {result['limitation']}")
    return 0


def console_main(argv=None) -> int:
    """The installed command: turn an expected refusal into a message, not a stack trace.

    ``main`` stays the testable core and keeps raising, so callers that want the exception
    still get it. This wrapper is what the console script runs, and the refusals it catches
    already carry the useful sentence — a traceback in front of one adds only the author's
    source paths. Genuine defects still need their trace, so ``ARTIFACTFORGE_TRACEBACK``
    re-raises everything untouched.
    """
    if os.environ.get("ARTIFACTFORGE_TRACEBACK"):
        return main(argv)
    try:
        return main(argv)
    except ImportError as exc:
        print(
            f"artifactforge: this command needs the parser oracles ({exc}).\n"
            '  install them with: pip install "artifactforge[dev]"',
            file=sys.stderr,
        )
        return 2
    except (ValueError, OSError) as exc:
        print(f"artifactforge: {exc}", file=sys.stderr)
        print(
            "  set ARTIFACTFORGE_TRACEBACK=1 to see where this came from",
            file=sys.stderr,
        )
        return 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="artifactforge", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gate", help="run one gate; exits non-zero when the answer is no")
    g.add_argument("name", choices=sorted(GATES))
    g.add_argument(
        "--scene",
        help="an existing scene directory (validity and inertness only; "
        "identity needs a suite and will refuse)",
    )
    g.add_argument(
        "--n",
        type=_positive_count,
        default=40,
        help=(
            "Windows/macOS scenario count (default 40); Gates 1-3 append enough Linux "
            "scenes to balance the three-family assurance corpus"
        ),
    )
    g.add_argument("--gen-dir", help="where to generate them (default: a temp dir)")
    g.set_defaults(func=cmd_gate)

    s = sub.add_parser("scorecard", help="run every gate and emit the fidelity scorecard")
    s.add_argument("--out", help="write the scorecard to this FILE")
    s.add_argument(
        "--check",
        help=(
            "compare against an identical-measurement baseline; exit 1 on regression "
            "or incompatibility"
        ),
    )
    s.add_argument(
        "--require-pass",
        action="store_true",
        help="exit 1 unless the freshly generated all-gates verdict is pass",
    )
    s.add_argument(
        "--n",
        type=_positive_count,
        default=40,
        help=(
            "Windows/macOS measurement count; Gates 1-3 append balanced Linux assurance "
            "scenes while Gate 4 remains Windows/macOS-only"
        ),
    )
    s.add_argument("--gen-dir")
    s.add_argument(
        "--allow-dirty",
        action="store_true",
        help="write an explicitly dirty, non-release record bound to the current diff",
    )
    s.set_defaults(func=cmd_scorecard, scene=None)

    from artifactforge.cli import fixture as fixture_commands

    f = sub.add_parser(
        "fixture",
        help="build, verify, inspect, compare and release public reproducible fixtures",
    )
    fsub = f.add_subparsers(dest="fixture_cmd", required=True)

    fb = fsub.add_parser("build", help="build a fixture from a strict supported JSON recipe")
    fb.add_argument("spec", help="fixture recipe JSON")
    fb.add_argument("output", help="new fixture directory (must not already exist)")
    fb.add_argument("--json", action="store_true", help="emit canonical machine-readable JSON")
    fb.set_defaults(func=fixture_commands.cmd_fixture_build)

    fv = fsub.add_parser("verify", help="verify integrity and exact recipe reproduction")
    fv.add_argument("fixture", help="fixture directory")
    fv.add_argument(
        "--assurance",
        action="store_true",
        help="require installed dev parser oracles for Gates 1 and 3; missing is red (exit 1)",
    )
    fv.add_argument("--json", action="store_true", help="emit canonical machine-readable JSON")
    fv.set_defaults(func=fixture_commands.cmd_fixture_verify)

    fi = fsub.add_parser(
        "inspect",
        help="validate stored integrity and summarize a fixture without reproduction",
    )
    fi.add_argument("fixture", help="fixture directory")
    fi.add_argument("--json", action="store_true", help="emit canonical machine-readable JSON")
    fi.set_defaults(func=fixture_commands.cmd_fixture_inspect)

    fd = fsub.add_parser("diff", help="verify and semantically compare two fixtures")
    fd.add_argument("left", help="first fixture directory")
    fd.add_argument("right", help="second fixture directory")
    fd.add_argument("--json", action="store_true", help="emit canonical machine-readable JSON")
    fd.set_defaults(func=fixture_commands.cmd_fixture_diff)

    fr = fsub.add_parser("release", help="verify and publish a deterministic USTAR archive")
    fr.add_argument("fixture", help="fixture directory")
    fr.add_argument("output", help="new uncompressed .tar path (must not already exist)")
    fr.add_argument(
        "--assurance",
        action="store_true",
        help="require installed dev parser oracles for Gates 1 and 3; missing is red (exit 1)",
    )
    fr.add_argument("--json", action="store_true", help="emit canonical machine-readable JSON")
    fr.set_defaults(func=fixture_commands.cmd_fixture_release)

    fe = fsub.add_parser(
        "extract", help="verify a release archive and write it back as a usable fixture"
    )
    fe.add_argument("archive", help="uncompressed .tar produced by 'fixture release'")
    fe.add_argument("output", help="new fixture directory (must not already exist)")
    fe.add_argument("--json", action="store_true", help="emit canonical machine-readable JSON")
    fe.set_defaults(func=fixture_commands.cmd_fixture_extract)

    b = sub.add_parser(
        "bench", help="manage legacy diagnostics and Benchmark v3 one-shot evaluation"
    )
    bsub = b.add_subparsers(dest="bench_cmd", required=True)
    bn = bsub.add_parser("new", help="generate a permanently non-reportable legacy v2 suite")
    bn.add_argument("out", help="suite directory")
    bn.add_argument("--n", type=_positive_count, default=40)
    bn.add_argument(
        "--kind",
        choices=("dev", "holdout"),
        default="dev",
        help="legacy v2 only: dev uses the public key; holdout mints a local diagnostic key",
    )
    bn.set_defaults(func=cmd_bench_new)

    bc = bsub.add_parser(
        "ceremony",
        help="manage self-attested Benchmark v3 evaluator ceremonies",
    )
    bcsub = bc.add_subparsers(dest="ceremony_cmd", required=True)
    bcc = bcsub.add_parser(
        "create",
        help="mint a private v3 evaluator suite (destination must not exist)",
    )
    bcc.add_argument("out", help="new private evaluator directory")
    bcc.add_argument(
        "--n",
        type=_benchmark_v3_count,
        default=suite.BENCHMARK_V3_MIN_SCENARIOS,
        help="balanced even population from 120 through 200 (default 120)",
    )
    bcc.set_defaults(func=cmd_bench_ceremony_create)

    bs = bsub.add_parser("solve", help="run the reference solver and write a submission")
    bs.add_argument("suite", help="exact public export created by 'bench export'")
    bs.add_argument("--out", default="answers.jsonl")
    bs.set_defaults(func=cmd_bench_solve)

    bp = bsub.add_parser(
        "precommit",
        help="bind a canonical submission and solver provenance before evaluator receipt",
    )
    bp.add_argument("public", help="exact public export used by the solver")
    bp.add_argument("submission", help="canonical JSONL reveal to commit")
    bp.add_argument("--out", default="precommit.json", help="new precommitment path")
    bp.add_argument("--implementation-sha256", type=_labelled_sha256, required=True)
    bp.add_argument("--configuration-sha256", type=_labelled_sha256, required=True)
    bp.add_argument("--source-sha256", type=_labelled_sha256, required=True)
    bp.set_defaults(func=cmd_bench_precommit)

    ba = bsub.add_parser(
        "attempt",
        help="manage one designated one-shot evaluator ledger",
    )
    basub = ba.add_subparsers(dest="attempt_cmd", required=True)
    baa = basub.add_parser("accept", help="accept the first precommit into a new ledger")
    baa.add_argument("evaluator", help="private Benchmark v3 evaluator root")
    baa.add_argument("precommit", help="solver precommitment created before reveal transfer")
    baa.add_argument("ledger", help="new evaluator-private ledger outside the suite")
    baa.set_defaults(func=cmd_bench_attempt_accept)

    bac = basub.add_parser(
        "consume",
        help="claim once, then read a reveal and emit only a feedback-withholding receipt",
    )
    bac.add_argument("evaluator", help="private Benchmark v3 evaluator root")
    bac.add_argument("ledger", help="accepted evaluator-private ledger")
    bac.add_argument("submission", help="reveal file; unreadable or malformed still consumes")
    bac.set_defaults(func=cmd_bench_attempt_consume)

    bar = basub.add_parser(
        "retire", help="irreversibly retire this designated local-ledger state"
    )
    bar.add_argument("ledger", help="evaluator-private attempt ledger")
    bar.set_defaults(func=cmd_bench_attempt_retire)

    bap = basub.add_parser(
        "report",
        help="show detailed private feedback only after retirement",
    )
    bap.add_argument("ledger", help="retired evaluator-private attempt ledger")
    bap.set_defaults(func=cmd_bench_attempt_report)

    bav = basub.add_parser(
        "verify",
        help="verify a detached retired report without accessing a live ledger",
    )
    bav.add_argument("report", help="canonical detached retired-report JSON")
    bav.add_argument(
        "--reveal",
        help="optional exact reveal bytes whose digest and size must match the report",
    )
    bav.set_defaults(func=cmd_bench_attempt_verify)

    bg = bsub.add_parser(
        "grade", help="legacy-v2 local diagnostics only; Benchmark v3 refuses repeat grading"
    )
    bg.add_argument("suite", help="private evaluator root, never a public export")
    bg.add_argument("--submission", default="answers.jsonl")
    bg.set_defaults(func=cmd_bench_grade)

    be = bsub.add_parser(
        "export",
        help="publish an exact solver root with no evaluator-private material",
    )
    be.add_argument("evaluator", help="private evaluator root")
    be.add_argument("public", help="new disjoint public directory (must not exist)")
    be.set_defaults(func=cmd_bench_export)

    args = p.parse_args(argv)
    if hasattr(args, "gen_dir") and args.gen_dir is None:
        # Gates and scorecards generate private evaluator material.  Own the default
        # directory for the full command lifetime so success, a red gate, and exceptions
        # all remove it.  An explicit --gen-dir remains caller-owned for inspection.
        with tempfile.TemporaryDirectory(prefix="artifactforge-gate-") as workdir:
            args._wd = workdir
            return args.func(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
