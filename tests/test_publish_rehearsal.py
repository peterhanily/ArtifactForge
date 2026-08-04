# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The publish rehearsal has one closed, credential-free command surface."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from artifactforge import inventory


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "artifactforge_publish_rehearsal",
    ROOT / "scripts" / "publish_rehearsal.py",
)
assert SPEC is not None and SPEC.loader is not None
rehearsal = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rehearsal
SPEC.loader.exec_module(rehearsal)


VERSION = "0.5.0"
SDIST = f"artifactforge-{VERSION}.tar.gz"
WHEEL = f"artifactforge-{VERSION}-py3-none-any.whl"


def _release_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "pyproject.toml"
    project.write_text('[project]\nname = "artifactforge"\nversion = "0.5.0"\n')
    monkeypatch.setattr(rehearsal, "PROJECT_FILE", project)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / SDIST).write_bytes(b"closed sdist")
    (dist / WHEEL).write_bytes(b"closed wheel")
    monkeypatch.setattr(
        rehearsal,
        "_run_bounded_version_command",
        lambda command, **_kwargs: _version_result(command),
    )
    return dist


def _reviewed_uv(tmp_path: Path, payload: bytes = b"reviewed uv executable") -> Path:
    executable = tmp_path / "reviewed-uv"
    executable.write_bytes(payload)
    executable.chmod(0o700)
    return executable


def _version_result(command, *, version: str = "0.11.17") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        command,
        0,
        stdout=f"uv {version} (reviewed fixture)\n".encode(),
        stderr=b"",
    )


def test_bounded_reader_uses_cross_observation_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "reviewed-uv.exe"
    expected = b"distribution bytes"
    path.write_bytes(expected)
    comparisons: list[tuple[str, str]] = []
    real_match = rehearsal.path_handle_file_observations_match
    path_mode = stat.S_IFREG | 0o777
    handle_mode = stat.S_IFREG | 0o666
    path_state = SimpleNamespace(
        observation_domain="path",
        st_birthtime_ns=100,
        st_ctime_ns=100,
        st_dev=11,
        st_ino=22,
        st_mode=path_mode,
        st_mtime_ns=300,
        st_size=len(expected),
    )
    handle_state = SimpleNamespace(
        observation_domain="handle",
        st_birthtime_ns=100,
        st_ctime_ns=200,
        st_dev=11,
        st_ino=22,
        st_mode=handle_mode,
        st_mtime_ns=300,
        st_size=len(expected),
    )

    def observed_match(path_state, handle_state):
        comparisons.append(
            (path_state.observation_domain, handle_state.observation_domain)
        )
        return real_match(path_state, handle_state)

    monkeypatch.setattr(Path, "lstat", lambda _path: path_state)
    monkeypatch.setattr(rehearsal.os, "fstat", lambda _descriptor: handle_state)
    monkeypatch.setattr(
        inventory,
        "sys",
        SimpleNamespace(platform="win32", version_info=(3, 12, 13, "final", 0)),
    )
    monkeypatch.setattr(rehearsal, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(rehearsal, "path_handle_file_observations_match", observed_match)
    payload, observation = rehearsal._read_regular(
        path,
        maximum=len(expected),
        label="test distribution",
    )

    assert payload == expected
    assert path_state.st_birthtime_ns == handle_state.st_birthtime_ns
    assert path_state.st_ctime_ns != handle_state.st_ctime_ns
    assert path_state.st_mode != handle_state.st_mode
    assert stat.S_IFMT(path_state.st_mode) == stat.S_IFMT(handle_state.st_mode)
    assert comparisons == [("path", "handle"), ("path", "handle")]
    assert observation.device == 11
    assert observation.inode == 22
    assert observation.size == len(payload)
    assert observation.modified_ns == 300
    assert observation.changed_ns == 200


def test_bounded_reader_retains_posix_cross_observation_mode_check(monkeypatch):
    path_state = SimpleNamespace(
        st_ctime_ns=100,
        st_dev=11,
        st_ino=22,
        st_mode=stat.S_IFREG | 0o600,
        st_mtime_ns=300,
        st_size=4,
    )
    handle_state = SimpleNamespace(
        st_ctime_ns=100,
        st_dev=11,
        st_ino=22,
        st_mode=stat.S_IFREG | 0o644,
        st_mtime_ns=300,
        st_size=4,
    )
    monkeypatch.setattr(
        inventory,
        "sys",
        SimpleNamespace(platform="linux", version_info=(3, 12, 13, "final", 0)),
    )
    monkeypatch.setattr(rehearsal, "sys", SimpleNamespace(platform="linux"))

    assert not rehearsal._path_handle_observations_match(path_state, handle_state)


def test_rehearsal_uses_one_fixed_command_and_a_strict_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    hostile = {
        "UV_PUBLISH_INDEX": "attacker-index",
        "UV_PUBLISH_FUTURE_CREDENTIAL": "future-secret",
        "Uv_PuBlIsH_MiXeD": "mixed-secret",
        "UV_CONFIG_FILE": "/attacker/uv.toml",
        "UV_INDEX": "attacker-index",
        "UV_INDEX_FUTURE": "attacker-index",
        "UV_DEFAULT_INDEX": "attacker-index",
        "UV_EXTRA_INDEX_URL": "https://attacker.invalid/simple",
        "UV_KEYRING_PROVIDER": "subprocess",
        "UV_CREDENTIALS_DIR": "/attacker/credentials",
        "HTTPS_PROXY": "https://attacker.invalid:4443",
        "http_proxy": "http://attacker.invalid:8080",
        "NO_PROXY": "127.0.0.1",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-secret",
        "HOME": "/attacker/home",
        "PYTHONPATH": "/attacker/python",
    }
    for key, value in hostile.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("PATH", "/reviewed/bin")
    reviewed_uv = _reviewed_uv(tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_version(command, **kwargs):
        private_uv = Path(command[0])
        assert private_uv.is_absolute()
        assert private_uv != reviewed_uv
        assert private_uv.read_bytes() == b"reviewed uv executable"
        assert kwargs["working_directory"] == private_uv.parent
        environment = kwargs["environment"]
        assert isinstance(environment, dict)
        assert "PATH" not in environment and "PATHEXT" not in environment
        assert not ({key.upper() for key in hostile} & {key.upper() for key in environment})
        assert environment["LANG"] == "C" and environment["LC_ALL"] == "C"
        assert environment["TEMP"] == str(private_uv.parent)
        assert environment["TMP"] == str(private_uv.parent)
        assert environment["TMPDIR"] == str(private_uv.parent)
        return _version_result(command)

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        private_uv = Path(command[0])
        assert private_uv.is_absolute()
        assert private_uv != reviewed_uv
        assert private_uv.read_bytes() == b"reviewed uv executable"
        if os.name != "nt":
            assert private_uv.stat().st_mode & 0o777 == 0o500
        assert kwargs["cwd"] == private_uv.parent
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert "PATH" not in environment and "PATHEXT" not in environment
        assert not ({key.upper() for key in hostile} & {key.upper() for key in environment})
        assert environment["LANG"] == "C" and environment["LC_ALL"] == "C"
        assert environment["TEMP"] == str(private_uv.parent)
        assert environment["TMP"] == str(private_uv.parent)
        assert environment["TMPDIR"] == str(private_uv.parent)
        assert set(environment) <= {
            "LANG",
            "LC_ALL",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "WINDIR",
        }
        assert Path(command[-2]).read_bytes() == b"closed sdist"
        assert Path(command[-1]).read_bytes() == b"closed wheel"
        if os.name != "nt":
            assert Path(command[-2]).stat().st_mode & 0o777 == 0o400
            assert Path(command[-1]).stat().st_mode & 0o777 == 0o400
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(rehearsal, "_run_bounded_version_command", fake_version)
    monkeypatch.setattr(rehearsal.subprocess, "run", fake_run)

    assert rehearsal.run(dist, uv_executable=reviewed_uv) == 0
    assert len(calls) == 1
    observed, options = calls[0]
    assert Path(observed[0]).name == "uv"
    assert observed[1:-2] == [
        "publish",
        "--no-config",
        "--dry-run",
        "--trusted-publishing",
        "never",
        "--keyring-provider",
        "disabled",
        "--publish-url",
        "http://127.0.0.1:9",
    ]
    assert [Path(item).name for item in observed[-2:]] == [SDIST, WHEEL]
    assert options["check"] is False
    assert options["close_fds"] is True
    assert options["stdin"] is subprocess.DEVNULL
    assert options["timeout"] == rehearsal.COMMAND_TIMEOUT_SECONDS


@pytest.mark.parametrize("mutation", ["missing", "extra", "directory", "oversized"])
def test_rehearsal_rejects_noncanonical_or_unsafe_distribution_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    if mutation == "missing":
        (dist / SDIST).unlink()
    elif mutation == "extra":
        (dist / "attacker.txt").write_text("not a distribution")
    elif mutation == "directory":
        (dist / WHEEL).unlink()
        (dist / WHEEL).mkdir()
    else:
        monkeypatch.setattr(rehearsal, "MAX_DISTRIBUTION_BYTES", 4)

    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("unsafe input reached uv")

    monkeypatch.setattr(rehearsal.subprocess, "run", fake_run)
    assert rehearsal.main([str(dist)]) == 2
    assert called is False


def test_rehearsal_rejects_a_distribution_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    target = tmp_path / "outside.whl"
    target.write_bytes(b"outside")
    (dist / WHEEL).unlink()
    try:
        (dist / WHEEL).symlink_to(target)
    except OSError as exc:  # pragma: no cover - depends on Windows developer-mode policy
        pytest.skip(f"symlinks are unavailable: {exc}")

    monkeypatch.setattr(
        rehearsal.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("symlink reached uv"),
    )
    assert rehearsal.main([str(dist)]) == 2


def test_rehearsal_detects_distribution_mutation_during_uv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)
    copied_payloads: tuple[bytes, bytes] | None = None

    def fake_run(command, **_kwargs):
        nonlocal copied_payloads
        copied_payloads = (Path(command[-2]).read_bytes(), Path(command[-1]).read_bytes())
        (dist / WHEEL).write_bytes(b"mutated wheel")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(rehearsal.subprocess, "run", fake_run)
    assert rehearsal.main([str(dist), "--uv", str(reviewed_uv)]) == 2
    assert copied_payloads == (b"closed sdist", b"closed wheel")


def test_rehearsal_propagates_the_uv_dry_run_status_after_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)

    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(rehearsal.subprocess, "run", fake_run)
    assert rehearsal.main([str(dist), "--uv", str(reviewed_uv)]) == 7


def test_rehearsal_rejects_a_symlinked_distribution_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    alias = tmp_path / "dist-alias"
    try:
        alias.symlink_to(dist, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on Windows developer-mode policy
        pytest.skip(f"symlinks are unavailable: {exc}")
    assert rehearsal.main([str(alias)]) == 2


def test_project_metadata_must_be_a_bounded_regular_artifactforge_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    rehearsal.PROJECT_FILE.write_text('[project]\nname = "other"\nversion = "0.5.0"\n')
    assert rehearsal.main([str(dist)]) == 2

    rehearsal.PROJECT_FILE.write_text('[project]\nname = "artifactforge"\nversion = "../evil"\n')
    assert rehearsal.main([str(dist)]) == 2

    for hostile in (
        b"x=" + (b"[" * 500) + b"0" + (b"]" * 500),
        b"x=" + (b"1" * 5000),
    ):
        rehearsal.PROJECT_FILE.write_bytes(hostile)
        assert rehearsal.main([str(dist)]) == 2

    monkeypatch.setattr(rehearsal, "MAX_PROJECT_BYTES", 3)
    assert rehearsal.main([str(dist)]) == 2


def test_uv_must_report_the_exact_reviewed_version_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)
    calls = []

    def fake_version(command, **_kwargs):
        calls.append(command)
        return _version_result(command, version="0.11.18")

    monkeypatch.setattr(rehearsal, "_run_bounded_version_command", fake_version)
    monkeypatch.setattr(
        rehearsal.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("publish ran after a uv version mismatch"),
    )
    assert rehearsal.main([str(dist), "--uv", str(reviewed_uv)]) == 2
    assert len(calls) == 1


@pytest.mark.parametrize(
    "mutation", ["relative", "directory", "symlink", "non-executable", "oversized"]
)
def test_uv_input_must_be_absolute_regular_bounded_unlinked_and_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)
    requested = reviewed_uv
    if mutation == "relative":
        requested = Path("reviewed-uv")
    elif mutation == "directory":
        requested = tmp_path / "uv-directory"
        requested.mkdir()
    elif mutation == "symlink":
        requested = tmp_path / "uv-alias"
        try:
            requested.symlink_to(reviewed_uv)
        except OSError as exc:  # pragma: no cover - Windows developer-mode dependent
            pytest.skip(f"symlinks are unavailable: {exc}")
    elif mutation == "non-executable":
        reviewed_uv.chmod(0o600)
    else:
        monkeypatch.setattr(rehearsal, "MAX_UV_EXECUTABLE_BYTES", 4)

    monkeypatch.setattr(
        rehearsal.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("unsafe uv input was executed"),
    )
    assert rehearsal.main([str(dist), "--uv", str(requested)]) == 2


def test_default_resolution_is_one_time_and_the_child_never_receives_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)
    shim_directory = tmp_path / "shim-bin"
    shim_directory.mkdir()
    shim = shim_directory / "uv"
    shim.write_bytes(b"hostile shim")
    shim.chmod(0o700)
    monkeypatch.setenv("PATH", str(shim_directory))
    resolutions = []

    def fake_which(name):
        resolutions.append(name)
        return str(reviewed_uv)

    monkeypatch.setattr(rehearsal.shutil, "which", fake_which)

    def fake_run(command, **kwargs):
        assert Path(command[0]).read_bytes() == b"reviewed uv executable"
        assert "PATH" not in kwargs["env"]
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(rehearsal.subprocess, "run", fake_run)
    assert rehearsal.run(dist) == 0
    assert resolutions == ["uv"]


def test_original_uv_identity_mutation_is_rejected_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)
    calls = []

    def fake_version(command, **_kwargs):
        calls.append(command)
        assert command[1:] == ["--version"]
        reviewed_uv.write_bytes(b"swapped after private capture")
        reviewed_uv.chmod(0o700)
        return _version_result(command)

    monkeypatch.setattr(rehearsal, "_run_bounded_version_command", fake_version)
    monkeypatch.setattr(
        rehearsal.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("mutated original reached publish"),
    )
    assert rehearsal.main([str(dist), "--uv", str(reviewed_uv)]) == 2
    assert len(calls) == 1


def test_original_uv_swap_during_publish_cannot_change_the_executed_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)
    executed_payload = None

    def fake_run(command, **_kwargs):
        nonlocal executed_payload
        executed_payload = Path(command[0]).read_bytes()
        reviewed_uv.write_bytes(b"attacker replacement")
        reviewed_uv.chmod(0o700)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(rehearsal.subprocess, "run", fake_run)
    assert rehearsal.main([str(dist), "--uv", str(reviewed_uv)]) == 2
    assert executed_payload == b"reviewed uv executable"


def test_private_distribution_mutation_by_uv_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)

    def fake_run(command, **_kwargs):
        private_wheel = Path(command[-1])
        private_wheel.chmod(0o600)
        private_wheel.write_bytes(b"uv-mutated snapshot")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(rehearsal.subprocess, "run", fake_run)
    assert rehearsal.main([str(dist), "--uv", str(reviewed_uv)]) == 2
    assert (dist / WHEEL).read_bytes() == b"closed wheel"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support is unavailable")
def test_regular_file_to_fifo_race_is_nonblocking_and_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _release_tree(tmp_path, monkeypatch)
    reviewed_uv = _reviewed_uv(tmp_path)
    target = dist / WHEEL
    real_open = os.open
    raced = False

    def racing_open(path, flags, *args, **kwargs):
        nonlocal raced
        if not raced and Path(path) == target:
            raced = True
            target.unlink()
            os.mkfifo(target)
            assert flags & os.O_NONBLOCK
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(rehearsal.os, "open", racing_open)
    monkeypatch.setattr(
        rehearsal.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("raced FIFO input reached uv"),
    )
    started = time.monotonic()
    assert rehearsal.main([str(dist), "--uv", str(reviewed_uv)]) == 2
    assert raced is True
    assert time.monotonic() - started < 2


def test_uv_version_output_is_stopped_at_the_shared_runtime_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rehearsal, "MAX_VERSION_OUTPUT_BYTES", 64)
    monkeypatch.setattr(rehearsal, "COMMAND_TIMEOUT_SECONDS", 10)
    flood_both_streams = (
        "import os, threading\n"
        "def flood(descriptor):\n"
        "    while True:\n"
        "        os.write(descriptor, b'x' * 4096)\n"
        "threads = [threading.Thread(target=flood, args=(fd,)) for fd in (1, 2)]\n"
        "[thread.start() for thread in threads]\n"
        "[thread.join() for thread in threads]\n"
    )
    environment = rehearsal._child_environment(os.environ, private_directory=tmp_path)

    started = time.monotonic()
    with pytest.raises(
        rehearsal.PublishRehearsalError,
        match="output exceeds the bounded diagnostic profile",
    ):
        rehearsal._run_bounded_version_command(
            [sys.executable, "-c", flood_both_streams],
            environment=environment,
            working_directory=tmp_path,
        )
    assert time.monotonic() - started < 5


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics are required")
def test_uv_version_cap_terminates_pipe_inheriting_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rehearsal, "MAX_VERSION_OUTPUT_BYTES", 64)
    monkeypatch.setattr(rehearsal, "COMMAND_TIMEOUT_SECONDS", 10)
    descendant_pid_file = tmp_path / "descendant.pid"
    spawn_and_flood = (
        "import os, pathlib, subprocess, sys, time\n"
        "descendant = subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(30)'])\n"
        "pathlib.Path(sys.argv[1]).write_text(str(descendant.pid))\n"
        "os.write(1, b'x' * 4096)\n"
        "time.sleep(30)\n"
    )
    environment = rehearsal._child_environment(os.environ, private_directory=tmp_path)

    started = time.monotonic()
    try:
        with pytest.raises(
            rehearsal.PublishRehearsalError,
            match="output exceeds the bounded diagnostic profile",
        ):
            rehearsal._run_bounded_version_command(
                [sys.executable, "-c", spawn_and_flood, str(descendant_pid_file)],
                environment=environment,
                working_directory=tmp_path,
            )
        lingering_readers = [
            thread
            for thread in threading.enumerate()
            if thread.name.startswith("artifactforge-uv-version-")
        ]
    finally:
        if descendant_pid_file.exists():
            descendant_pid = int(descendant_pid_file.read_text())
            try:
                os.kill(descendant_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    assert time.monotonic() - started < 5
    assert lingering_readers == []


def test_partial_uv_version_reader_start_failure_cleans_up_process_and_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rehearsal, "COMMAND_TIMEOUT_SECONDS", 10)
    real_popen = rehearsal.subprocess.Popen
    spawned: list[subprocess.Popen] = []

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    real_start = rehearsal.threading.Thread.start

    def fail_stderr_reader_start(thread):
        if thread.name == "artifactforge-uv-version-stderr":
            raise RuntimeError("forced second-reader start failure")
        return real_start(thread)

    monkeypatch.setattr(rehearsal.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(rehearsal.threading.Thread, "start", fail_stderr_reader_start)
    environment = rehearsal._child_environment(os.environ, private_directory=tmp_path)

    started = time.monotonic()
    try:
        with pytest.raises(
            rehearsal.PublishRehearsalError,
            match="cannot start private uv diagnostic readers",
        ):
            rehearsal._run_bounded_version_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                environment=environment,
                working_directory=tmp_path,
            )
        lingering_readers = [
            thread
            for thread in threading.enumerate()
            if thread.name.startswith("artifactforge-uv-version-")
        ]
    finally:
        for process in spawned:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    assert time.monotonic() - started < 5
    assert all(process.poll() is not None for process in spawned)
    assert lingering_readers == []
