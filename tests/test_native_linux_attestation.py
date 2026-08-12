# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Platform-independent tests for the fail-closed native Linux attestation lane."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import runpy
import shutil
import sys
from pathlib import Path

import pytest

from artifactforge.fixture import (
    FixtureSpecV2,
    ProfileSpecV2,
    VerificationResult,
    build_fixture,
    parse_fixture_manifest,
)
from artifactforge.fixture.operations import verify_fixture
from artifactforge.gates import GateReport


_SCRIPT = Path(__file__).parents[1] / "scripts" / "attest_linux_native.py"
_SCRIPT_GLOBALS = runpy.run_path(str(_SCRIPT))
_BASH_CONTROL_MARKER = _SCRIPT_GLOBALS["_BASH_CONTROL_MARKER"]
_BASH_SCRIPT = _SCRIPT_GLOBALS["_BASH_SCRIPT"]
_EXPECTED_DISASSEMBLY = _SCRIPT_GLOBALS["_EXPECTED_DISASSEMBLY"]
_bash_attestation = _SCRIPT_GLOBALS["_bash_attestation"]
_canonical_json_bytes = _SCRIPT_GLOBALS["_canonical_json_bytes"]
_captured_scene = _SCRIPT_GLOBALS["_captured_scene"]
_classify_scene = _SCRIPT_GLOBALS["_classify_scene"]
_desktop_attestation = _SCRIPT_GLOBALS["_desktop_attestation"]
_elf_attestation = _SCRIPT_GLOBALS["_elf_attestation"]
_file_identity = _SCRIPT_GLOBALS["_file_identity"]
_fixture_postcondition = _SCRIPT_GLOBALS["_fixture_postcondition"]
_fixture_state = _SCRIPT_GLOBALS["_fixture_state"]
_inside = _SCRIPT_GLOBALS["_inside"]
_native_tools = _SCRIPT_GLOBALS["_native_tools"]
_normalized_disassembly = _SCRIPT_GLOBALS["_normalized_disassembly"]
_portable_verifier_environment = _SCRIPT_GLOBALS["_portable_verifier_environment"]
_run = _SCRIPT_GLOBALS["_run"]
_scene_manifest = _SCRIPT_GLOBALS["_scene_manifest"]
_scene_postcondition = _SCRIPT_GLOBALS["_scene_postcondition"]
_timestamp = _SCRIPT_GLOBALS["_timestamp"]
_tools_postcondition = _SCRIPT_GLOBALS["_tools_postcondition"]
_verified_fixture_evidence = _SCRIPT_GLOBALS["_verified_fixture_evidence"]
captured_regular_tree = _SCRIPT_GLOBALS["captured_regular_tree"]
attest = _SCRIPT_GLOBALS["attest"]
main = _SCRIPT_GLOBALS["main"]


def _result(returncode: int = 0, *, stdout: str = "", stderr: str = "") -> dict:
    return {
        "argv": [],
        "returncode": returncode,
        "stderr": stderr,
        "stdout": stdout,
    }


def _linux_scene(root: Path) -> Path:
    scene = root / "scene"
    executable_root = scene / "home" / "v" / ".local" / "bin"
    desktop_root = scene / "home" / "v" / ".config" / "autostart"
    executable_root.mkdir(parents=True)
    desktop_root.mkdir(parents=True)
    for index in range(5):
        (executable_root / f"helper-{index}").write_bytes(b"\x7fELF" + bytes([index]))
    for index in range(3):
        (desktop_root / f"helper-{index}.desktop").write_text("[Desktop Entry]\n")
    (scene / "home" / "v" / ".bash_history").write_bytes(
        b"#1705294800\n: 'ARTIFACTFORGE-SYNTHETIC-LINUX'\n"
    )
    return scene


@pytest.fixture(scope="module")
def linux_fixture(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("native-linux-fixture") / "fixture"
    spec = FixtureSpecV2.create(
        fixture_id="native-linux-attestation-test",
        family="linux",
        story="linux-autostart-v1",
        profile=ProfileSpecV2(
            id="linux-glibc-x86_64-loose-v2",
            hostname="ws-lnx-17",
            username="v",
        ),
        seed_hex="d1" * 32,
    )
    build_fixture(spec, root)
    return root


def _patch_successful_native_environment(monkeypatch, tmp_path, fixture, bash_observer):
    good = verify_fixture(fixture, assurance=True)
    monkeypatch.setattr(attest.__globals__["sys"], "platform", "linux")
    monkeypatch.setitem(
        attest.__globals__, "verify_fixture", lambda _fixture, *, assurance: good
    )
    source = {
        "git_commit": "a" * 40,
        "git_tree": "b" * 40,
        "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
        "worktree_clean": True,
    }
    monkeypatch.setitem(attest.__globals__, "_source_provenance", lambda _repo: source)
    monkeypatch.setitem(
        attest.__globals__,
        "_source_postcondition",
        lambda initial, _repo: {**initial, "unchanged": True},
    )
    monkeypatch.setitem(attest.__globals__, "_github_run_identity", lambda _env: None)

    paths = {}
    versions = {}
    for name in (
        "readelf",
        "objdump",
        "file",
        "desktop-file-validate",
        "bash",
        "dpkg-query",
        "uname",
    ):
        path = tmp_path / "tools" / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(f"{name}-binary".encode())
        paths[name] = str(path)
        version_stdout = "GNU bash, version 5.2.0" if name == "bash" else f"{name} version"
        versions[name] = {
            **_file_identity(path),
            "version": _result(stdout=version_stdout),
            "version_method": "mocked native tool version",
        }
    tool_evidence = {
        "support_tools": {name: versions[name] for name in ("dpkg-query", "uname")},
        "validation_tools": {
            name: versions[name]
            for name in ("readelf", "objdump", "file", "desktop-file-validate", "bash")
        },
    }
    monkeypatch.setitem(
        attest.__globals__, "_native_tools", lambda _runner: (paths, tool_evidence)
    )
    monkeypatch.setitem(
        attest.__globals__,
        "_platform_evidence",
        lambda _paths, _runner: {
            "machine": "x86_64",
            "os_release": {"fields": {"ID": "ubuntu", "VERSION_ID": "24.04"}},
            "package_database": {
                "packages": [
                    {"architecture": "amd64", "package": name, "version": "test"}
                    for name in ("bash", "binutils", "desktop-file-utils", "file")
                ],
                "result": _result(),
            },
            "release": "test",
            "system": "Linux",
            "uname": _result(stdout="Linux test x86_64"),
        },
    )
    monkeypatch.setitem(
        attest.__globals__,
        "_elf_attestation",
        lambda path, scene, _tools, _runner: (
            {"file": path.relative_to(scene).as_posix()},
            [],
        ),
    )
    monkeypatch.setitem(
        attest.__globals__,
        "_desktop_attestation",
        lambda path, scene, _tool, _runner: (
            {"file": path.relative_to(scene).as_posix()},
            [],
        ),
    )
    monkeypatch.setitem(attest.__globals__, "_bash_attestation", bash_observer)
    return paths


def test_timestamp_and_canonical_json_are_stable():
    value = dt.datetime(2026, 8, 2, 13, 14, 15, 999999, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    assert _timestamp(value) == "2026-08-02T12:14:15Z"
    with pytest.raises(ValueError, match="timezone-aware"):
        _timestamp(dt.datetime(2026, 8, 2))

    document = {"z": [3, 2], "accent": "é", "nested": {"b": False, "a": None}}
    expected = b'{"accent":"\xc3\xa9","nested":{"a":null,"b":false},"z":[3,2]}\n'
    assert _canonical_json_bytes(document) == expected
    assert json.loads(expected) == document


def test_recursive_manifest_and_exact_linux_scene_classification(tmp_path):
    scene = _linux_scene(tmp_path)
    manifest = _scene_manifest(scene)
    classes = _classify_scene(scene)
    assert manifest["file_count"] == 9
    assert manifest["total_bytes"] == sum(item["size"] for item in manifest["files"])
    assert [item["path"] for item in manifest["files"]] == sorted(
        item["path"] for item in manifest["files"]
    )
    digest = _canonical_json_bytes({"files": manifest["files"]})
    assert manifest["tree_sha256"] == hashlib.sha256(digest).hexdigest()
    assert len(classes["elf"]) == 5
    assert len(classes["desktop"]) == 3
    assert len(classes["history"]) == 1
    assert classes["unknown"] == []
    assert classes["users"] == ["v"]

    outside_profile = scene / "helper-unknown"
    outside_profile.write_bytes(b"\x7fELFwrong-place")
    classes = _classify_scene(scene)
    assert classes["unknown"] == [outside_profile]


def test_manifest_rejects_symlink_and_postcondition_detects_same_size_mutation(tmp_path):
    scene = tmp_path / "scene"
    scene.mkdir()
    artifact = scene / "artifact"
    artifact.write_bytes(b"before")
    initial = _scene_manifest(scene)
    artifact.write_bytes(b"AFTER!")
    assert _scene_postcondition(initial, scene)["unchanged"] is False

    target = tmp_path / "outside"
    target.write_bytes(b"outside")
    try:
        (scene / "link").symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create test symlink: {exc}")
    with pytest.raises(ValueError, match="symlink"):
        _scene_manifest(scene)


def test_fixture_core_verification_is_embedded_and_byte_bound(linux_fixture):
    evidence, state = _verified_fixture_evidence(linux_fixture)
    manifest = evidence["manifest"]
    portable = evidence["portable_verification"]

    assert evidence["manifest_file"]["sha256"] == hashlib.sha256(
        (linux_fixture / "fixture.json").read_bytes()
    ).hexdigest()
    assert manifest["generator"]["name"] == "artifactforge"
    assert manifest["generator"]["abi"] == "artifactforge-fixture-generator-v2"
    assert manifest["generator"]["producer_profile"] == (
        "artifactforge-fixture-producer-v2"
    )
    assert manifest["recipe"]["family"] == "linux"
    assert manifest["recipe"]["profile"] == {
        "hostname": "ws-lnx-17",
        "id": "linux-glibc-x86_64-loose-v2",
        "username": "v",
    }
    assert manifest["payload"]["file_count"] == 9
    assert manifest["payload"]["directory_count"] == 6
    assert manifest["payload"]["regular_file_bytes"] == state["scene"]["total_bytes"]
    assert manifest["payload"]["metadata_blob_count"] == 0
    assert manifest["payload"]["metadata_blob_bytes"] == 0
    assert manifest["payload"]["total_bound_bytes"] == state["scene"]["total_bytes"]
    assert [
        {
            "path": item["served_path"],
            "sha256": item["sha256"].removeprefix("sha256:"),
            "size": item["size"],
        }
        for item in manifest["payload"]["files"]
    ] == state["scene"]["files"]
    assert all(
        item["guest_path"] == f"/{item['served_path']}"
        for item in manifest["payload"]["files"]
    )
    assert portable["verdict"] == "pass"
    assert portable["failures"] == []
    assert portable["environment"]["python"]["implementation"] == "CPython"
    assert portable["environment"]["python"]["version"]
    assert set(portable["environment"]["distributions"]) == {
        "PyXDG",
        "artifactforge",
        "dissect.target",
        "lief",
        "pyelftools",
    }
    assert portable["environment"]["distributions"]["artifactforge"] == (
        manifest["generator"]["version"]
    )
    assert all(portable["environment"]["distributions"].values())
    assert [(item["gate"], item["name"], item["verdict"]) for item in portable["reports"]] == [
        (1, "validity", "pass"),
        (3, "inertness", "pass"),
    ]
    assert portable["checks"] == {
        "assurance": "pass",
        "integrity": "pass",
        "reproduction": "pass",
    }
    assert "complete v2 logical manifest" in portable["contract"]
    assert portable["payload"] == {
        "directory_count": 6,
        "file_count": 9,
        "metadata_blob_bytes": 0,
        "metadata_blob_count": 0,
        "regular_file_bytes": state["scene"]["total_bytes"],
        "total_bound_bytes": state["scene"]["total_bytes"],
    }
    compatibility = portable["producer_compatibility"]
    assert compatibility["generator_abi"] == "artifactforge-fixture-generator-v2"
    assert compatibility["producer_profile"] == "artifactforge-fixture-producer-v2"
    assert "package versions are provenance" in compatibility["basis"]


def test_native_attestation_requires_v2_even_if_v1_result_is_presented_as_good(
    tmp_path, linux_fixture
):
    golden = (
        Path(__file__).parent
        / "fixtures"
        / "fixture-v1-goldens"
        / "linux-v0.5.0.json"
    )
    historical = parse_fixture_manifest(golden.read_bytes(), require_canonical=True)
    good = verify_fixture(linux_fixture, assurance=True)
    forged = VerificationResult(
        historical,
        assurance_reports=good.assurance_reports,
        reproduction_requested=True,
    )
    with pytest.raises(RuntimeError, match="historical v1 fixtures are inspection-only"):
        _verified_fixture_evidence(tmp_path, verifier=lambda *_args, **_kwargs: forged)


def test_generator_package_version_is_provenance_not_v2_compatibility_identity(
    monkeypatch, linux_fixture
):
    environment = _portable_verifier_environment()
    environment["distributions"] = dict(environment["distributions"])
    environment["distributions"]["artifactforge"] = "different-package-version"
    monkeypatch.setitem(
        _verified_fixture_evidence.__globals__,
        "_portable_verifier_environment",
        lambda: environment,
    )

    evidence, _state = _verified_fixture_evidence(linux_fixture)
    compatibility = evidence["portable_verification"]["producer_compatibility"]
    assert compatibility["verifier_distribution_version"] == "different-package-version"
    assert compatibility["manifest_generator_version"] != (
        compatibility["verifier_distribution_version"]
    )


def test_missing_portable_distribution_version_is_a_hard_failure(monkeypatch):
    metadata = _portable_verifier_environment.__globals__["importlib"].metadata
    real_version = metadata.version

    def version(name):
        if name == "lief":
            raise metadata.PackageNotFoundError(name)
        return real_version(name)

    monkeypatch.setattr(metadata, "version", version)
    with pytest.raises(RuntimeError, match="missing portable verifier distribution version: lief"):
        _portable_verifier_environment()


@pytest.mark.parametrize(
    "failure_kind", ["fixture", "reproduction-not-run", "gate1", "gate3"]
)
def test_attest_cannot_reach_native_tools_when_portable_verification_fails(
    monkeypatch, linux_fixture, failure_kind
):
    good = verify_fixture(linux_fixture, assurance=True)
    reports = list(good.assurance_reports)
    failures: tuple[str, ...] = ()
    reproduction_requested = True
    if failure_kind == "fixture":
        failures = ("payload bytes do not reproduce",)
    elif failure_kind == "reproduction-not-run":
        reproduction_requested = False
    else:
        index = 0 if failure_kind == "gate1" else 1
        source = reports[index]
        failed = GateReport(
            gate=source.gate,
            name=source.name,
            question=source.question,
            fails=[f"injected {failure_kind} mutation"],
            gaps=list(source.gaps),
            metrics=dict(source.metrics),
            denominator=source.denominator,
        )
        reports[index] = failed
    failed_result = VerificationResult(
        good.manifest,
        failures,
        tuple(reports),
        reproduction_requested=reproduction_requested,
    )

    monkeypatch.setattr(attest.__globals__["sys"], "platform", "linux")
    monkeypatch.setitem(
        attest.__globals__, "verify_fixture", lambda _fixture, *, assurance: failed_result
    )

    def native_tools_must_not_run(_runner):
        raise AssertionError("native tools ran after a failed portable prerequisite")

    monkeypatch.setitem(attest.__globals__, "_native_tools", native_tools_must_not_run)
    with pytest.raises(RuntimeError, match="Fixture Core verification failed"):
        attest(linux_fixture)


@pytest.mark.parametrize("changed_part", ["scene", "manifest"])
def test_attest_cannot_pass_if_verified_fixture_changes_before_native_walk(
    monkeypatch, tmp_path, linux_fixture, changed_part
):
    fixture = tmp_path / "fixture"
    shutil.copytree(linux_fixture, fixture)
    verified = verify_fixture(fixture, assurance=True)
    if changed_part == "scene":
        artifact = next((fixture / "artifacts").rglob(".bash_history"))
        original = artifact.read_bytes()
        artifact.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    else:
        manifest = fixture / "fixture.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")

    monkeypatch.setattr(attest.__globals__["sys"], "platform", "linux")
    monkeypatch.setitem(
        attest.__globals__, "verify_fixture", lambda _fixture, *, assurance: verified
    )

    def native_tools_must_not_run(_runner):
        raise AssertionError("native tools ran after the verified fixture changed")

    monkeypatch.setitem(attest.__globals__, "_native_tools", native_tools_must_not_run)
    expected = "artifacts changed" if changed_part == "scene" else "fixture.json changed"
    with pytest.raises(RuntimeError, match=expected):
        attest(fixture)


def test_fixture_postcondition_detects_scene_and_manifest_changes(tmp_path, linux_fixture):
    fixture = tmp_path / "fixture"
    shutil.copytree(linux_fixture, fixture)
    initial = _fixture_state(fixture)

    artifact = next((fixture / "artifacts").rglob(".bash_history"))
    original = artifact.read_bytes()
    artifact.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    changed_scene = _fixture_postcondition(initial, fixture)
    assert changed_scene["unchanged"] is False
    assert changed_scene["scene"]["unchanged"] is False

    artifact.write_bytes(original)
    manifest = fixture / "fixture.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    changed_manifest = _fixture_postcondition(initial, fixture)
    assert changed_manifest["unchanged"] is False
    assert changed_manifest["scene"]["unchanged"] is True
    assert changed_manifest["manifest_file"]["unchanged"] is False


def test_fixture_postcondition_rejects_added_empty_directory(tmp_path, linux_fixture):
    fixture = tmp_path / "fixture"
    shutil.copytree(linux_fixture, fixture)
    initial = _fixture_state(fixture)
    (fixture / "artifacts" / "unbound-empty").mkdir()
    with pytest.raises(ValueError, match="empty directory"):
        _fixture_postcondition(initial, fixture)


def test_source_swap_and_restore_cannot_change_the_held_native_snapshot(
    monkeypatch, tmp_path, linux_fixture
):
    fixture = tmp_path / "fixture"
    shutil.copytree(linux_fixture, fixture)
    source_history = fixture / "artifacts" / "home" / "v" / ".bash_history"
    original = source_history.read_bytes()
    observed = {}

    def bash_observer(history, scene, _bash, _runner):
        observed["path"] = history
        observed["before"] = history.read_bytes()
        source_history.write_bytes(b"X" * len(original))
        try:
            observed["during"] = history.read_bytes()
        finally:
            source_history.write_bytes(original)
        return {"file": history.relative_to(scene).as_posix()}, []

    _patch_successful_native_environment(
        monkeypatch, tmp_path, fixture, bash_observer
    )
    report = attest(fixture)

    assert report["verdict"] == "pass", report["failures"]
    assert observed["before"] == original
    assert observed["during"] == original
    assert fixture / "artifacts" not in observed["path"].parents
    assert "artifactforge-scene-snapshot-" in str(observed["path"])
    assert report["scene"]["post_attestation"]["unchanged"] is True
    assert report["fixture"]["post_attestation"]["unchanged"] is True


def test_attestation_fails_if_a_native_tool_changes_during_observation(
    monkeypatch, tmp_path, linux_fixture
):
    fixture = tmp_path / "fixture"
    shutil.copytree(linux_fixture, fixture)
    paths = {}

    def bash_observer(history, scene, _bash, _runner):
        Path(paths["readelf"]).write_bytes(b"mutated-readelf-binary")
        return {"file": history.relative_to(scene).as_posix()}, []

    paths.update(
        _patch_successful_native_environment(
            monkeypatch, tmp_path, fixture, bash_observer
        )
    )
    report = attest(fixture)

    assert report["verdict"] == "fail"
    assert report["tools"]["post_attestation"]["unchanged"] is False
    assert report["tools"]["post_attestation"]["tools"]["readelf"]["unchanged"] is False
    assert "native or support tool bytes changed during attestation" in report["failures"]


def test_objdump_normalization_is_exact_and_detects_additional_instructions():
    output = """
Disassembly of section .text:

0000000000001000 <.text>:
    1000:\t31 ff                \txor    %edi,%edi
    1002:\tb8 3c 00 00 00       \tmov    $0x3c,%eax
    1007:\t0f 05                \tsyscall
"""
    assert _normalized_disassembly(output) == _EXPECTED_DISASSEMBLY
    assert _normalized_disassembly(output + "    1009:\t90                   \tnop\n") != (
        _EXPECTED_DISASSEMBLY
    )


def test_elf_lane_invokes_only_read_only_native_parsers_and_requires_exact_body(tmp_path):
    scene = tmp_path / "scene"
    elf = scene / "home" / "v" / ".local" / "bin" / "helper"
    elf.parent.mkdir(parents=True)
    elf.write_bytes(b"\x7fELFsynthetic")
    commands = []
    objdump_output = """
    1000:\t31 ff                \txor    %edi,%edi
    1002:\tb8 3c 00 00 00       \tmov    $0x3c,%eax
    1007:\t0f 05                \tsyscall
"""

    def runner(command, **kwargs):
        commands.append((command, kwargs))
        if command[0] == "/tools/readelf":
            return _result(
                stdout=(
                    "  Class: ELF64\n"
                    "  Type: DYN (Position-Independent Executable file)\n"
                    "  Machine: Advanced Micro Devices X86-64\n"
                    "  [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n"
                    " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
                    " 0x000000006ffffffb (FLAGS_1) Flags: PIE\n"
                    " .note.artifactforge"
                )
            )
        if command[0] == "/tools/objdump":
            return _result(stdout=objdump_output)
        return _result(stdout="ELF 64-bit LSB pie executable, x86-64, dynamically linked")

    evidence, failures = _elf_attestation(
        elf,
        scene,
        {"readelf": "/tools/readelf", "objdump": "/tools/objdump", "file": "/tools/file"},
        runner,
    )
    assert failures == []
    assert evidence["disassembly"] == list(_EXPECTED_DISASSEMBLY)
    assert [command[:8] for command, _kwargs in commands] == [
        ["/tools/readelf", "-h", "-l", "-d", "-S", "-n", "--wide", str(elf)],
        ["/tools/objdump", "-d", "-j", ".text", str(elf)],
        ["/tools/file", "--brief", "--", str(elf)],
    ]
    assert all(command[0] != str(elf) for command, _kwargs in commands)
    assert all("ldd" not in command for command, _kwargs in commands)


def test_desktop_lane_only_invokes_validator_and_never_launches_entry(tmp_path):
    scene = tmp_path / "scene"
    desktop = scene / "home" / "v" / ".config" / "autostart" / "helper.desktop"
    desktop.parent.mkdir(parents=True)
    desktop.write_text("[Desktop Entry]\n")
    observed = []

    def runner(command, **kwargs):
        observed.append((command, kwargs))
        return _result()

    evidence, failures = _desktop_attestation(
        desktop, scene, "/usr/bin/desktop-file-validate", runner
    )
    assert failures == []
    assert evidence["file"] == "home/v/.config/autostart/helper.desktop"
    assert observed[0][0] == ["/usr/bin/desktop-file-validate", str(desktop)]
    assert observed[0][1]["recorded_argv"] == [
        "desktop-file-validate",
        "home/v/.config/autostart/helper.desktop",
    ]
    assert observed[0][0][0] != str(desktop)


def test_bash_roundtrip_mock_proves_nonexecution_and_never_sources_history(tmp_path):
    scene = tmp_path / "scene"
    history = scene / "home" / "v" / ".bash_history"
    history.parent.mkdir(parents=True)
    history.write_bytes(
        b"#1705294800\n: 'ARTIFACTFORGE-SYNTHETIC-LINUX'\n"
        b"#1705294801\n/home/v/.local/bin/helper\n"
    )
    observed = {}

    def runner(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        assert command[:4] == ["/bin/bash", "--noprofile", "--norc", "-c"]
        assert "history -r" in command[4]
        assert "history -w" in command[4]
        assert command[4].index("HISTTIMEFORMAT=${HISTTIMEFORMAT:?}") < command[4].index(
            'history -r "$control_history"'
        )
        assert command[4].index('history -r "$control_history"') < command[4].index(
            'history -r "$source_history"'
        )
        assert "\nsource " not in f"\n{command[4]}"
        assert "eval" not in command[4]
        source, roundtrip, control, control_roundtrip, sentinel, status = map(
            Path, command[6:12]
        )
        roundtrip.write_bytes(source.read_bytes())
        control_roundtrip.write_bytes(control.read_bytes())
        status.write_bytes(b"history-read-did-not-execute\n")
        sentinel.write_bytes(_BASH_CONTROL_MARKER)
        return _result()

    evidence, failures = _bash_attestation(history, scene, "/bin/bash", runner)
    assert failures == [], evidence
    assert evidence["byte_identical_roundtrip"] is True
    control = evidence["nonexecution_control"]
    assert control["control_roundtrip_byte_identical"] is True
    assert control["control_roundtrip_sha256"] == control["control_history_sha256"]
    assert control["history_command_was_not_executed"] is True
    assert control["injected_history_command"] == (
        "printf ARTIFACTFORGE-HISTORY-COMMAND-EXECUTED > <sentinel>"
    )
    assert control["method"] == (
        "history -r must leave the sentinel absent; the same shell builtin and "
        "redirection then write a distinct positive-control marker"
    )
    assert control["positive_control_marker_sha256"] == hashlib.sha256(
        _BASH_CONTROL_MARKER
    ).hexdigest()
    assert control["positive_control_observed"] is True
    assert observed["kwargs"]["env"]["HOME"].endswith("/home")
    assert observed["kwargs"]["env"]["HISTFILE"] == "/dev/null"
    assert observed["kwargs"]["env"]["HISTTIMEFORMAT"] == "%s "
    assert observed["kwargs"]["env"]["BASH_ENV"] == "/dev/null"


@pytest.mark.skipif(shutil.which("bash") is None, reason="GNU Bash is unavailable")
def test_bash_roundtrip_real_shell_preserves_extended_timestamps(tmp_path):
    scene = tmp_path / "scene"
    history = scene / "home" / "v" / ".bash_history"
    history.parent.mkdir(parents=True)
    history.write_bytes(
        b"#1705294800\n: 'ARTIFACTFORGE-SYNTHETIC-LINUX'\n"
        b"#1705294801\n/home/v/.local/bin/helper\n"
    )

    evidence, failures = _bash_attestation(
        history,
        scene,
        shutil.which("bash"),
        _run,
    )

    assert failures == [], evidence
    assert evidence["result"]["returncode"] == 0
    assert evidence["byte_identical_roundtrip"] is True
    assert evidence["roundtrip_sha256"] == evidence["source_sha256"]
    control = evidence["nonexecution_control"]
    assert control["control_roundtrip_byte_identical"] is True
    assert control["control_roundtrip_sha256"] == control["control_history_sha256"]
    assert control["history_command_was_not_executed"] is True
    assert control["positive_control_observed"] is True


def test_bash_lane_cannot_false_pass_when_runner_returns_zero_without_evidence(tmp_path):
    scene = tmp_path / "scene"
    history = scene / "home" / "v" / ".bash_history"
    history.parent.mkdir(parents=True)
    history.write_bytes(b"#1705294800\n: 'ARTIFACTFORGE-SYNTHETIC-LINUX'\n")

    evidence, failures = _bash_attestation(
        history,
        scene,
        "/bin/bash",
        lambda _command, **_kwargs: _result(),
    )
    assert evidence["byte_identical_roundtrip"] is False
    assert evidence["nonexecution_control"]["control_roundtrip_byte_identical"] is False
    assert evidence["nonexecution_control"]["history_command_was_not_executed"] is False
    assert failures == [
        "GNU Bash history roundtrip changed bytes for home/v/.bash_history",
        "GNU Bash ignored or changed the injected history control for home/v/.bash_history",
        "GNU Bash history non-execution control failed for home/v/.bash_history",
    ]


def test_missing_native_tool_is_a_hard_error_not_a_skip(monkeypatch):
    monkeypatch.setattr(
        _native_tools.__globals__["shutil"],
        "which",
        lambda name: None if name == "readelf" else f"/tools/{name}",
    )
    with pytest.raises(RuntimeError, match="missing required native tools: readelf"):
        _native_tools(lambda _command, **_kwargs: _result(stdout="version"))


def test_native_tools_bind_resolved_bytes_and_mocked_versions(monkeypatch, tmp_path):
    tool_paths = {}
    for name in (
        "readelf",
        "objdump",
        "file",
        "desktop-file-validate",
        "bash",
        "dpkg-query",
        "uname",
    ):
        path = tmp_path / name
        path.write_bytes(f"{name}-binary".encode())
        tool_paths[name] = str(path)
    monkeypatch.setattr(
        _native_tools.__globals__["shutil"], "which", lambda name: tool_paths[name]
    )
    commands = []
    events = []
    real_file_identity = _native_tools.__globals__["_file_identity"]

    def identity(path):
        events.append(("identity", path.name))
        return real_file_identity(path)

    monkeypatch.setitem(_native_tools.__globals__, "_file_identity", identity)

    def runner(command, **kwargs):
        events.append(("command", Path(command[0]).name))
        commands.append((command, kwargs))
        return _result(stdout=f"{Path(command[0]).name} version")

    paths, evidence = _native_tools(runner)
    assert paths == tool_paths
    assert sorted(evidence["validation_tools"]) == [
        "bash",
        "desktop-file-validate",
        "file",
        "objdump",
        "readelf",
    ]
    assert sorted(evidence["support_tools"]) == ["dpkg-query", "uname"]
    assert [kind for kind, _name in events[:7]] == ["identity"] * 7
    assert [kind for kind, _name in events[7:]] == ["command"] * 7
    for group in evidence.values():
        for item in group.values():
            assert len(item["sha256"]) == 64
            assert item["size"] > 0
            assert item["version"]["returncode"] == 0
    assert len(commands) == 7
    desktop_version = evidence["validation_tools"]["desktop-file-validate"]
    assert desktop_version["version_method"] == "Ubuntu desktop-file-utils package version"
    assert desktop_version["version"]["argv"] == []  # supplied by the deliberately tiny fake
    desktop_command, desktop_kwargs = commands[3]
    assert desktop_command == [
        tool_paths["dpkg-query"],
        "--show",
        "--showformat=${Version}\\n",
        "desktop-file-utils",
    ]
    assert desktop_kwargs["recorded_argv"] == [
        "dpkg-query",
        "--show",
        "--showformat=<version>",
        "desktop-file-utils",
    ]


def test_attest_rejects_non_linux_before_native_tool_discovery(monkeypatch, tmp_path):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    monkeypatch.setattr(attest.__globals__["sys"], "platform", "darwin")
    with pytest.raises(RuntimeError, match="must run on Linux"):
        attest(fixture)


def test_attest_rejects_fixture_root_symlink_before_verification(
    monkeypatch, tmp_path, linux_fixture
):
    alias = tmp_path / "fixture-link"
    try:
        alias.symlink_to(linux_fixture, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"platform cannot create test symlink: {exc}")
    monkeypatch.setattr(attest.__globals__["sys"], "platform", "linux")
    with pytest.raises(RuntimeError, match="real directory, not a link"):
        attest(alias)


def test_output_inside_fixture_is_rejected_and_main_writes_canonical_json(
    monkeypatch, tmp_path
):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    assert _inside(fixture / "attestation.json", fixture)
    assert not _inside(tmp_path / "attestation.json", fixture)

    output = tmp_path / "attestation.json"
    fake_report = {"failures": [], "schema": "fixture", "verdict": "pass", "z": 1}
    monkeypatch.setitem(main.__globals__, "attest", lambda _fixture: fake_report)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(_SCRIPT), "--fixture", str(fixture), "--out", str(output)],
    )
    assert main() == 0
    assert output.read_bytes() == _canonical_json_bytes(fake_report)
    original_output = output.read_bytes()
    assert main() == 2
    assert output.read_bytes() == original_output

    inside = fixture / "must-not-exist.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [str(_SCRIPT), "--fixture", str(fixture), "--out", str(inside)],
    )
    assert main() == 2
    assert not inside.exists()


def test_main_retains_missing_tool_failure_and_returns_nonzero(monkeypatch, tmp_path):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    output = tmp_path / "failed-attestation.json"

    def unavailable(_fixture):
        raise RuntimeError("missing required native tools: readelf")

    monkeypatch.setitem(main.__globals__, "attest", unavailable)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(_SCRIPT), "--fixture", str(fixture), "--out", str(output)],
    )
    assert main() == 1
    raw = output.read_bytes()
    report = json.loads(raw)
    assert raw == _canonical_json_bytes(report)
    assert report["schema"] == "artifactforge-native-linux-attestation-v2"
    assert report["schema_version"] == 2
    assert report["verdict"] == "fail"
    assert report["failures"] == ["missing required native tools: readelf"]


def test_main_never_follows_or_replaces_existing_output(monkeypatch, tmp_path):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    target = tmp_path / "outside-target.json"
    target.write_bytes(b"preserve-me")
    output = tmp_path / "attestation-link.json"
    try:
        output.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create test symlink: {exc}")
    monkeypatch.setitem(
        main.__globals__,
        "attest",
        lambda _fixture: {"failures": [], "verdict": "pass"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(_SCRIPT), "--fixture", str(fixture), "--out", str(output)],
    )
    assert main() == 2
    assert output.is_symlink()
    assert target.read_bytes() == b"preserve-me"


def test_main_refuses_output_inside_source_repository(monkeypatch, tmp_path):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    output = (
        Path(main.__globals__["_REPOSITORY_ROOT"])
        / f".artifactforge-must-not-create-{tmp_path.name}.json"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(_SCRIPT), "--fixture", str(fixture), "--out", str(output)],
    )
    assert main() == 2
    assert not output.exists()


def test_v1_detached_scene_cli_is_explicitly_incompatible(monkeypatch, tmp_path):
    scene = _linux_scene(tmp_path)
    output = tmp_path / "must-not-exist.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [str(_SCRIPT), "--scene", str(scene), "--out", str(output)],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert not output.exists()
