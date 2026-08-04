# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Python support remains a policy preflight until a real runtime lane passes."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
from types import SimpleNamespace

import pytest

from artifactforge.fixture import (
    FixtureSpecV2,
    build_fixture,
    parse_fixture_spec,
    verify_fixture,
)


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "check_python_support.py"
GLOBALS = runpy.run_path(str(SCRIPT))
FIXTURE_EVIDENCE_SCHEMA = GLOBALS["FIXTURE_EVIDENCE_SCHEMA"]
REQUIRED_ORACLE_DISTRIBUTIONS = GLOBALS["REQUIRED_ORACLE_DISTRIBUTIONS"]
STATUS_KNOWN_BLOCKED = GLOBALS["STATUS_KNOWN_BLOCKED"]
STATUS_RUNTIME_CANDIDATE = GLOBALS["STATUS_RUNTIME_CANDIDATE"]
FixtureEvidenceError = GLOBALS["FixtureEvidenceError"]
SupportAuditError = GLOBALS["SupportAuditError"]
_hashed_sdist = GLOBALS["_hashed_sdist"]
_runtime_binding = GLOBALS["_runtime_binding"]
_validate_dependency_references = GLOBALS["_validate_dependency_references"]
audit_core = GLOBALS["audit_core"]
audit_full_oracles = GLOBALS["audit_full_oracles"]
fixture_tree_evidence = GLOBALS["fixture_tree_evidence"]
main = GLOBALS["main"]


EXPECTED_FIXTURE_DIGESTS = {
    "windows-loose-v2.json": ("d2d3865e7eca534c6b1102a77106270a19e10b502c5e4c4cbe0878270ef95ef4"),
    "macos-14-loose-v2.json": ("da227fd866a0c1b70471be4c5a7a49c06c5af498598821a065ebd1165bd2dea6"),
    "linux-glibc-x86_64-loose-v2.json": (
        "1ec6bfc7caa38a6c0e43988d9e8028a80a85c3a25a103d8f9d420a463a375759"
    ),
}


def _audit_full(python):
    return audit_full_oracles(
        ROOT / "uv.lock", python=python, pyproject_path=ROOT / "pyproject.toml"
    )


def _copy(path: Path, destination: Path, transform=lambda value: value) -> Path:
    destination.write_text(transform(path.read_text(encoding="utf-8")), encoding="utf-8")
    return destination


def test_python314_core_is_only_a_runtime_candidate():
    pyproject = ROOT / "pyproject.toml"
    lock = ROOT / "uv.lock"
    report = audit_core(pyproject, lock, python=(3, 14))
    assert report == {
        "profile": "core-preflight",
        "target_python": "3.14",
        "declared_floor": "3.11",
        "pyproject_sha256": hashlib.sha256(pyproject.read_bytes()).hexdigest(),
        "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "runtime_dependency_count": 0,
        "build_backend": "hatchling.build",
        "build_requirement": "hatchling==1.31.0",
        "claim_scope": (
            "metadata/dependency preflight; build, installation, and runtime execution remain "
            "required"
        ),
        "blockers": {},
        "status": STATUS_RUNTIME_CANDIDATE,
    }
    assert "ready" not in report


@pytest.mark.parametrize("python", ((3, 11), (3, 12), (3, 13)))
def test_committed_full_oracle_matrix_is_a_runtime_candidate(python):
    report = _audit_full(python)
    assert report["profile"] == "full-oracle-preflight"
    assert report["claim_scope"] == (
        "policy preflight; target installation, imports, positive controls, and behavioural "
        "tests remain required"
    )
    assert report["status"] == STATUS_RUNTIME_CANDIDATE
    assert report["blockers"] == {}
    assert set(report["required_oracles"]) == REQUIRED_ORACLE_DISTRIBUTIONS
    assert set(report["lane_tools"]) == {"pytest", "ruff"}
    assert set(report["source_install_required"]) == {"windowsprefetch"}
    assert "ready" not in report
    assert "targets" not in report
    assert not any("compatible" in key for key in report)


def test_python314_preflight_names_both_exact_reviewed_blockers():
    report = _audit_full((3, 14))
    assert report["status"] == STATUS_KNOWN_BLOCKED
    assert report["blockers"] == {
        "dissect-target": {
            "version": "3.25.1",
            "kind": "runtime-import",
            "reason": (
                "import fails because its Python 3.13 pathlib compatibility layer imports "
                "glob._Globber, which CPython 3.14 replaced"
            ),
        },
        "yara-python": {
            "version": "4.5.4",
            "kind": "binary-distribution",
            "reason": (
                "the reviewed lock contains no CPython 3.14 wheel; an unexecuted source build "
                "is not interpreter compatibility evidence"
            ),
        },
    }
    source = report["source_install_required"]["windowsprefetch"]
    assert source["version"] == "4.0.3"
    assert source["sha256"] == "9bbc69059bf5dc2e37411d3156c0d176c4a20a72ee980a8436a885e0f65ecce1"
    assert source["size"] == 10136
    assert source["url"].endswith("/windowsprefetch-4.0.3.tar.gz")


def test_python314_cli_is_an_exact_known_blocker_gate(capsys):
    assert (
        main(
            [
                "--profile",
                "full-oracles",
                "--python",
                "3.14",
                "--pyproject",
                str(ROOT / "pyproject.toml"),
                "--lock",
                str(ROOT / "uv.lock"),
                "--json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "artifactforge-python-support-audit-v2"
    assert report["status"] == STATUS_KNOWN_BLOCKED
    assert list(report["blockers"]) == ["dissect-target", "yara-python"]
    assert report["runtime_binding"] == {"mode": "metadata-only"}


def test_runtime_binding_accepts_the_executing_cpython(capsys):
    target = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert (
        main(
            [
                "--profile",
                "core",
                "--python",
                target,
                "--pyproject",
                str(ROOT / "pyproject.toml"),
                "--lock",
                str(ROOT / "uv.lock"),
                "--require-current-cpython",
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    binding = report["runtime_binding"]
    assert binding["mode"] == "current-cpython-bound"
    assert binding["implementation"] == "cpython"
    assert binding["major_minor"] == target
    assert binding["version"] == "{}.{}.{}".format(*sys.version_info[:3])
    assert Path(binding["executable"]).resolve() == Path(sys.executable).resolve()


def test_runtime_binding_rejects_a_different_target(capsys):
    different = (sys.version_info.major, sys.version_info.minor + 1)
    assert _runtime_binding(different, required=False) == {"mode": "metadata-only"}
    with pytest.raises(SupportAuditError, match="executing interpreter"):
        _runtime_binding(different, required=True)
    assert (
        main(
            [
                "--profile",
                "core",
                "--python",
                f"{different[0]}.{different[1]}",
                "--require-current-cpython",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "executing interpreter" in captured.err


def test_runtime_binding_rejects_a_non_cpython_implementation(monkeypatch):
    monkeypatch.setattr(GLOBALS["sys"], "implementation", SimpleNamespace(name="pypy"))
    with pytest.raises(SupportAuditError, match="requires CPython"):
        _runtime_binding(sys.version_info[:2], required=True)


def test_full_and_core_preflights_enforce_the_declared_floor():
    core = audit_core(ROOT / "pyproject.toml", ROOT / "uv.lock", python=(3, 10))
    full = _audit_full((3, 10))
    for report in (core, full):
        assert report["status"] == STATUS_KNOWN_BLOCKED
        assert report["blockers"]["python-floor"] == {
            "kind": "declared-floor",
            "required": ">=3.11",
            "reason": "target is below the project and lock Python floor",
        }


def test_python_support_audit_refuses_project_lock_floor_drift(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        (
            '[project]\nrequires-python = ">=3.12"\ndependencies = []\n'
            '[build-system]\nrequires = ["hatchling==1.31.0"]\n'
            'build-backend = "hatchling.build"\n'
        ),
        encoding="utf-8",
    )
    lock = tmp_path / "uv.lock"
    lock.write_text('version = 1\nrevision = 3\nrequires-python = ">=3.11"\n', encoding="utf-8")
    with pytest.raises(SupportAuditError, match="floors disagree"):
        audit_core(pyproject, lock, python=(3, 14))


@pytest.mark.parametrize(
    ("old", "new", "match"),
    (
        ("dependencies = []", 'dependencies = ["not-core"]', "zero-dependency"),
        ('build-backend = "hatchling.build"', 'build-backend = "other.build"', "backend"),
        ('requires = ["hatchling==1.31.0"]', 'requires = ["hatchling>=1"]', "must be exact"),
    ),
)
def test_core_preflight_refuses_dependency_or_build_contract_drift(tmp_path, old, new, match):
    pyproject = _copy(
        ROOT / "pyproject.toml",
        tmp_path / "pyproject.toml",
        lambda text: text.replace(old, new, 1),
    )
    with pytest.raises(SupportAuditError, match=match):
        audit_core(pyproject, ROOT / "uv.lock", python=(3, 14))


@pytest.mark.parametrize(
    ("field", "replacement"), (("version = 1", "version = 2"), ("revision = 3", "revision = 4"))
)
def test_python_support_audit_refuses_unknown_lock_schema(tmp_path, field, replacement):
    lock = _copy(
        ROOT / "uv.lock",
        tmp_path / "uv.lock",
        lambda text: text.replace(field, replacement, 1),
    )
    with pytest.raises(SupportAuditError, match=r"uv\.lock (version|revision) must be exactly"):
        audit_core(ROOT / "pyproject.toml", lock, python=(3, 14))


def test_full_preflight_refuses_project_oracle_inventory_removal(tmp_path):
    pyproject = _copy(
        ROOT / "pyproject.toml",
        tmp_path / "pyproject.toml",
        lambda text: text.replace('    "yara-python",\n', "", 1),
    )
    with pytest.raises(SupportAuditError, match=r"missing=\['yara-python'\]"):
        audit_full_oracles(ROOT / "uv.lock", python=(3, 14), pyproject_path=pyproject)


def test_full_preflight_refuses_locked_oracle_inventory_removal(tmp_path):
    lock = _copy(
        ROOT / "uv.lock",
        tmp_path / "uv.lock",
        lambda text: text.replace('    { name = "yara-python" },\n', "", 1),
    )
    with pytest.raises(SupportAuditError, match=r"missing=\['yara-python'\]"):
        audit_full_oracles(lock, python=(3, 14), pyproject_path=ROOT / "pyproject.toml")


def test_dependency_references_fail_closed_when_a_locked_record_is_absent():
    records = {
        "artifactforge": {
            "name": "artifactforge",
            "version": "0.5.0",
            "dependencies": [{"name": "missing-oracle"}],
        }
    }
    with pytest.raises(SupportAuditError, match="absent locked distribution 'missing-oracle'"):
        _validate_dependency_references(records)


@pytest.mark.parametrize(
    "sdist",
    (
        None,
        {},
        {"url": "https://example.invalid/x.tar.gz", "hash": "sha256:bad", "size": 1},
        {
            "url": "https://example.invalid/x.tar.gz",
            "hash": "sha256:" + "0" * 64,
            "size": 0,
        },
        {
            "url": "https://example.invalid/not-an-archive",
            "hash": "sha256:" + "0" * 64,
            "size": 1,
        },
    ),
)
def test_source_only_exception_requires_a_complete_hashed_sdist(sdist):
    package = {} if sdist is None else {"sdist": sdist}
    with pytest.raises(SupportAuditError, match="locked sdist|source-only contract"):
        _hashed_sdist(package, name="windowsprefetch", version="4.0.3")


def test_source_only_exception_requires_review_if_wheels_appear():
    package = {
        "wheels": [{"url": "https://example.invalid/windowsprefetch.whl"}],
        "sdist": {
            "url": "https://example.invalid/windowsprefetch.tar.gz",
            "hash": "sha256:" + "0" * 64,
            "size": 1,
        },
    }
    with pytest.raises(SupportAuditError, match="now contains locked wheels"):
        _hashed_sdist(package, name="windowsprefetch", version="4.0.3")


def test_blocker_versions_are_review_bound_runtime_candidates(tmp_path):
    lock = _copy(
        ROOT / "uv.lock",
        tmp_path / "uv.lock",
        lambda text: text.replace(
            'name = "dissect-target"\nversion = "3.25.1"',
            'name = "dissect-target"\nversion = "99.0"',
            1,
        ).replace(
            'name = "yara-python"\nversion = "4.5.4"',
            'name = "yara-python"\nversion = "99.0"',
            1,
        ),
    )
    report = audit_full_oracles(lock, python=(3, 14), pyproject_path=ROOT / "pyproject.toml")
    assert report["status"] == STATUS_RUNTIME_CANDIDATE
    assert report["blockers"] == {}
    assert "ready" not in report


def test_report_digests_bind_the_exact_policy_inputs():
    report = _audit_full((3, 14))
    assert (
        report["pyproject_sha256"]
        == hashlib.sha256((ROOT / "pyproject.toml").read_bytes()).hexdigest()
    )
    assert report["lock_sha256"] == hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()


def test_fixture_tree_evidence_is_deterministic_and_length_delimited(tmp_path):
    root = tmp_path / "fixture"
    (root / "nested").mkdir(parents=True)
    (root / "a").write_bytes(b"bc")
    (root / "nested" / "d").write_bytes(b"ef")
    first = fixture_tree_evidence(root)
    second = fixture_tree_evidence(root)
    assert first == second
    assert first["file_count"] == 2
    assert first["directory_count"] == 1
    assert first["regular_file_bytes"] == 4
    assert [entry["path"] for entry in first["entries"]] == ["a", "nested", "nested/d"]

    # The same concatenated path/content text under a different tree framing must not collide.
    other = tmp_path / "other"
    other.mkdir()
    (other / "a").write_bytes(b"bcnested/d\0ef")
    assert fixture_tree_evidence(other)["tree_sha256"] != first["tree_sha256"]


def test_fixture_tree_evidence_detects_byte_path_and_mode_changes(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    payload = root / "payload"
    payload.write_bytes(b"one")
    original = fixture_tree_evidence(root)["tree_sha256"]
    payload.write_bytes(b"two")
    content_changed = fixture_tree_evidence(root)["tree_sha256"]
    assert content_changed != original
    payload.rename(root / "renamed")
    path_changed = fixture_tree_evidence(root)["tree_sha256"]
    assert path_changed != content_changed
    if os.name == "posix":
        os.chmod(root / "renamed", 0o600)
        assert fixture_tree_evidence(root)["tree_sha256"] != path_changed


def test_fixture_tree_evidence_accepts_windows_executable_mode_projection(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "fixture"
    root.mkdir()
    payload = root / "payload.exe"
    payload.write_bytes(b"inert executable bytes")
    payload.chmod(0o777)
    path_mode = payload.lstat().st_mode
    real_fstat = fixture_tree_evidence.__globals__["os"].fstat
    observed_handle_modes = []

    def windows_handle_fstat(descriptor):
        state = real_fstat(descriptor)
        handle_mode = state.st_mode & ~0o111
        observed_handle_modes.append(handle_mode)
        return SimpleNamespace(
            st_dev=state.st_dev,
            st_ino=state.st_ino,
            st_mode=handle_mode,
            st_size=state.st_size,
        )

    monkeypatch.setattr(
        fixture_tree_evidence.__globals__["os"],
        "fstat",
        windows_handle_fstat,
    )
    monkeypatch.setitem(
        fixture_tree_evidence.__globals__,
        "sys",
        SimpleNamespace(platform="win32"),
    )

    evidence = fixture_tree_evidence(root)
    entry = next(item for item in evidence["entries"] if item["path"] == payload.name)
    assert observed_handle_modes
    assert all(stat.S_IFMT(mode) == stat.S_IFREG for mode in observed_handle_modes)
    assert all(mode != path_mode for mode in observed_handle_modes)
    assert entry["mode"] == f"{stat.S_IMODE(path_mode):04o}"


def test_fixture_tree_evidence_retains_handle_mode_mutation_check(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "fixture"
    root.mkdir()
    payload = root / "payload.exe"
    payload.write_bytes(b"inert executable bytes")
    payload.chmod(0o777)
    real_fstat = fixture_tree_evidence.__globals__["os"].fstat
    observations = 0

    def changing_handle_fstat(descriptor):
        nonlocal observations
        state = real_fstat(descriptor)
        observations += 1
        handle_mode = state.st_mode & ~0o111
        if observations > 1:
            handle_mode &= ~0o022
        return SimpleNamespace(
            st_dev=state.st_dev,
            st_ino=state.st_ino,
            st_mode=handle_mode,
            st_size=state.st_size,
        )

    monkeypatch.setattr(
        fixture_tree_evidence.__globals__["os"],
        "fstat",
        changing_handle_fstat,
    )
    monkeypatch.setitem(
        fixture_tree_evidence.__globals__,
        "sys",
        SimpleNamespace(platform="win32"),
    )

    with pytest.raises(FixtureEvidenceError, match="changed while reading"):
        fixture_tree_evidence(root)
    assert observations == 2


def test_fixture_tree_evidence_retains_posix_cross_api_mode_check(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "fixture"
    root.mkdir()
    payload = root / "payload.bin"
    payload.write_bytes(b"fixture bytes")
    payload.chmod(0o600)
    real_fstat = fixture_tree_evidence.__globals__["os"].fstat

    def changed_handle_fstat(descriptor):
        state = real_fstat(descriptor)
        return SimpleNamespace(
            st_dev=state.st_dev,
            st_ino=state.st_ino,
            st_mode=stat.S_IFREG | 0o644,
            st_size=state.st_size,
        )

    monkeypatch.setattr(
        fixture_tree_evidence.__globals__["os"],
        "fstat",
        changed_handle_fstat,
    )
    monkeypatch.setitem(
        fixture_tree_evidence.__globals__,
        "sys",
        SimpleNamespace(platform="linux"),
    )

    with pytest.raises(FixtureEvidenceError, match="changed while opening"):
        fixture_tree_evidence(root)


def test_fixture_tree_evidence_rejects_symlinks(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    target = root / "target"
    target.write_bytes(b"bytes")
    link = root / "link"
    try:
        link.symlink_to(target.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this test host")
    with pytest.raises(FixtureEvidenceError, match="rejects symlink"):
        fixture_tree_evidence(root)


def test_fixture_evidence_cli_verifies_and_rejects_digest_mismatch(tmp_path, capsys):
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "payload").write_bytes(b"bytes")
    digest = fixture_tree_evidence(root)["tree_sha256"]
    common = ["--fixture-evidence", f"sample={root}", "--json"]
    assert main([*common, "--expect-fixture-digest", f"sample={digest}"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == FIXTURE_EVIDENCE_SCHEMA
    assert report["status"] == "verified"
    assert report["fixtures"]["sample"]["matches_expected"] is True

    assert main([*common, "--expect-fixture-digest", f"sample={'0' * 64}"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "mismatch"
    assert report["fixtures"]["sample"]["matches_expected"] is False


def test_fixture_evidence_cli_requires_an_expectation_for_every_tree(tmp_path, capsys):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    digest = fixture_tree_evidence(first)["tree_sha256"]
    assert (
        main(
            [
                "--fixture-evidence",
                f"first={first}",
                "--fixture-evidence",
                f"second={second}",
                "--expect-fixture-digest",
                f"first={digest}",
                "--json",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "has no expected digest" in captured.err


@pytest.mark.skipif(
    sys.version_info[:2] != (3, 14),
    reason="the CPython 3.14 fixture-core lane owns this runtime evidence",
)
@pytest.mark.parametrize("spec_name", tuple(EXPECTED_FIXTURE_DIGESTS))
def test_python314_builds_reproduces_and_matches_fixture_evidence(tmp_path, spec_name):
    spec_path = ROOT / "examples" / "fixtures" / spec_name
    spec = parse_fixture_spec(spec_path.read_bytes())
    assert type(spec) is FixtureSpecV2
    output = tmp_path / spec.family
    manifest = build_fixture(spec, output)
    result = verify_fixture(output)
    assert result.ok
    assert result.manifest == manifest
    evidence = fixture_tree_evidence(output)
    assert evidence["tree_sha256"] == EXPECTED_FIXTURE_DIGESTS[spec_name]
