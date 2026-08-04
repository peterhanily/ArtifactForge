#!/usr/bin/env python3
# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Run the one permitted package-publish rehearsal without ambient credentials.

This is deliberately a closed wrapper rather than a flexible ``uv publish`` front end.  It
accepts one distribution directory, derives the exact two release filenames from the reviewed
project metadata, validates the directory and files without following links, and invokes only a
credential-free loopback dry run.  Callers cannot add flags, choose an index, or choose a URL.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from typing import Sequence

from artifactforge.inventory import path_handle_file_observations_match


PROJECT_FILE = Path(__file__).resolve().parents[1] / "pyproject.toml"
MAX_PROJECT_BYTES = 256 * 1024
MAX_DISTRIBUTION_BYTES = 32 * 1024 * 1024
MAX_UV_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_VERSION_OUTPUT_BYTES = 4 * 1024
MAX_DIRECTORY_ENTRIES = 8
COMMAND_TIMEOUT_SECONDS = 60
PUBLISH_URL = "http://127.0.0.1:9"
EXPECTED_UV_VERSION = "0.11.17"
_VERSION = re.compile(r"[0-9][0-9A-Za-z.]*")

# A strict allowlist is easier to audit than an ever-growing denylist.  In particular it drops
# every present and future UV_PUBLISH_* name, all uv config/index/keyring settings, credential
# sources, OIDC variables, proxy settings (including mixed-case spellings), and loader injection
# variables.  The command uses a private absolute executable snapshot, so PATH and PATHEXT are
# deliberately absent. Windows only retains the system-root names needed to start a process.
_CHILD_ENVIRONMENT = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
    }
)


class PublishRehearsalError(ValueError):
    """The requested rehearsal is unsafe or outside the closed release profile."""


@dataclass(frozen=True)
class _FileObservation:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _path_handle_observations_match(
    path_state: os.stat_result,
    handle_state: os.stat_result,
) -> bool:
    return (
        path_state.st_mode == handle_state.st_mode
        and path_handle_file_observations_match(path_state, handle_state)
    )


def _read_regular(
    path: Path,
    *,
    maximum: int,
    label: str,
    allow_empty: bool = False,
) -> tuple[bytes, _FileObservation]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise PublishRehearsalError(f"cannot inspect {label} {path}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise PublishRehearsalError(f"{label} is not a regular file: {path}")
    if before.st_size < 0 or before.st_size > maximum:
        raise PublishRehearsalError(f"{label} exceeds the {maximum}-byte limit: {path}")

    # O_NONBLOCK closes the regular-file-to-FIFO race between lstat and open: a swapped FIFO
    # is opened without waiting for a writer and is then rejected by the descriptor fstat.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublishRehearsalError(f"cannot open {label} {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _path_handle_observations_match(
            before,
            opened,
        ):
            raise PublishRehearsalError(f"{label} changed while it was opened: {path}")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum:
                raise PublishRehearsalError(f"{label} exceeds the {maximum}-byte limit: {path}")
        final = os.fstat(descriptor)
    except OSError as exc:
        raise PublishRehearsalError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(descriptor)

    try:
        after = path.lstat()
    except OSError as exc:
        raise PublishRehearsalError(f"cannot re-inspect {label} {path}: {exc}") from exc
    if (
        _stat_identity(final) != _stat_identity(opened)
        or not _path_handle_observations_match(after, opened)
        or _stat_identity(before) != _stat_identity(after)
    ):
        raise PublishRehearsalError(f"{label} changed while it was read: {path}")
    payload = b"".join(chunks)
    if len(payload) != opened.st_size:
        raise PublishRehearsalError(f"{label} size changed while it was read: {path}")
    if not payload and not allow_empty:
        raise PublishRehearsalError(f"{label} is empty: {path}")
    return payload, _FileObservation(
        device=opened.st_dev,
        inode=opened.st_ino,
        mode=opened.st_mode,
        size=opened.st_size,
        modified_ns=opened.st_mtime_ns,
        changed_ns=opened.st_ctime_ns,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _project_version() -> tuple[str, _FileObservation]:
    payload, observation = _read_regular(
        PROJECT_FILE,
        maximum=MAX_PROJECT_BYTES,
        label="project metadata",
    )
    try:
        project = tomllib.loads(payload.decode("utf-8"))["project"]
    except (
        KeyError,
        TypeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise PublishRehearsalError("pyproject.toml has no readable [project] table") from exc
    if not isinstance(project, dict) or project.get("name") != "artifactforge":
        raise PublishRehearsalError("project name must be exactly artifactforge")
    version = project.get("version")
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        raise PublishRehearsalError("project version is outside the canonical release profile")
    return version, observation


def _directory_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise PublishRehearsalError(f"cannot inspect distribution directory {path}: {exc}") from exc
    if not stat.S_ISDIR(observed.st_mode):
        raise PublishRehearsalError(f"distribution path is not a real directory: {path}")
    return _stat_identity(observed)


def _validate_distribution_directory(
    directory: Path,
    *,
    version: str,
) -> tuple[
    tuple[Path, Path],
    tuple[_FileObservation, _FileObservation],
    tuple[bytes, bytes],
]:
    directory_before = _directory_identity(directory)
    expected_names = (
        f"artifactforge-{version}.tar.gz",
        f"artifactforge-{version}-py3-none-any.whl",
    )
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        raise PublishRehearsalError(
            f"cannot enumerate distribution directory {directory}: {exc}"
        ) from exc
    if len(entries) > MAX_DIRECTORY_ENTRIES:
        raise PublishRehearsalError(
            f"distribution directory exceeds the {MAX_DIRECTORY_ENTRIES}-entry limit"
        )
    observed_names = tuple(sorted(entry.name for entry in entries))
    if observed_names != tuple(sorted(expected_names)):
        raise PublishRehearsalError(
            "distribution directory must contain exactly the canonical sdist and wheel; "
            f"observed {observed_names!r}"
        )
    if _directory_identity(directory) != directory_before:
        raise PublishRehearsalError("distribution directory changed while it was enumerated")

    paths = tuple(directory / name for name in expected_names)
    captured = tuple(
        _read_regular(
            path,
            maximum=MAX_DISTRIBUTION_BYTES,
            label="distribution",
        )
        for path in paths
    )
    if _directory_identity(directory) != directory_before:
        raise PublishRehearsalError("distribution directory changed while its files were read")
    payloads = (captured[0][0], captured[1][0])
    observations = (captured[0][1], captured[1][1])
    return (paths[0], paths[1]), observations, payloads


def _child_environment(source: Mapping[str, str], *, private_directory: Path) -> dict[str, str]:
    environment = {key: source[key] for key in sorted(_CHILD_ENVIRONMENT) if key in source}
    environment.update(
        {
            "LANG": "C",
            "LC_ALL": "C",
            "TEMP": str(private_directory),
            "TMP": str(private_directory),
            "TMPDIR": str(private_directory),
        }
    )
    return environment


def _resolve_uv_executable(
    requested: Path | None,
) -> tuple[Path, bytes, _FileObservation]:
    if requested is None:
        discovered = shutil.which("uv")
        if discovered is None:
            raise PublishRehearsalError(
                "cannot resolve uv; pass the reviewed absolute executable with --uv"
            )
        path = Path(os.path.abspath(discovered))
    else:
        path = Path(requested)
        if not path.is_absolute():
            raise PublishRehearsalError("--uv must name an absolute executable path")
        path = Path(os.path.abspath(path))
    payload, observation = _read_regular(
        path,
        maximum=MAX_UV_EXECUTABLE_BYTES,
        label="uv executable",
    )
    if os.name != "nt" and not observation.mode & 0o111:
        raise PublishRehearsalError(f"uv executable has no executable mode bit: {path}")
    return path, payload, observation


def _write_private_copy(
    path: Path,
    payload: bytes,
    *,
    executable: bool,
) -> _FileObservation:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    mode = 0o500 if executable else 0o400
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise PublishRehearsalError(f"cannot create private rehearsal input {path}: {exc}") from exc
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise PublishRehearsalError(f"short write creating private rehearsal input {path}")
            written += count
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except OSError as exc:
        raise PublishRehearsalError(f"cannot write private rehearsal input {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    copied, observation = _read_regular(
        path,
        maximum=max(MAX_UV_EXECUTABLE_BYTES, MAX_DISTRIBUTION_BYTES),
        label="private rehearsal input",
    )
    if copied != payload:
        raise PublishRehearsalError(f"private rehearsal copy differs from validated bytes: {path}")
    if os.name != "nt" and stat.S_IMODE(observation.mode) != mode:
        raise PublishRehearsalError(f"private rehearsal input has the wrong mode: {path}")
    return observation


def _command(uv_executable: Path, distributions: tuple[Path, Path]) -> list[str]:
    return [
        str(uv_executable),
        "publish",
        "--no-config",
        "--dry-run",
        "--trusted-publishing",
        "never",
        "--keyring-provider",
        "disabled",
        "--publish-url",
        PUBLISH_URL,
        str(distributions[0]),
        str(distributions[1]),
    ]


def _run_uv_version(
    uv_executable: Path,
    *,
    environment: Mapping[str, str],
    working_directory: Path,
) -> None:
    command = [str(uv_executable), "--version"]
    completed = _run_bounded_version_command(
        command,
        environment=environment,
        working_directory=working_directory,
    )
    stdout = completed.stdout if isinstance(completed.stdout, bytes) else b""
    stderr = completed.stderr if isinstance(completed.stderr, bytes) else b""
    try:
        version_line = stdout.decode("utf-8").strip()
        diagnostic = stderr.decode("utf-8").strip()
    except UnicodeError as exc:
        raise PublishRehearsalError("uv --version output is not UTF-8") from exc
    expected = re.compile(rf"uv {re.escape(EXPECTED_UV_VERSION)}(?: \([^\r\n]{{1,512}}\))?")
    if completed.returncode != 0 or diagnostic or expected.fullmatch(version_line) is None:
        raise PublishRehearsalError(
            f"uv must report exactly version {EXPECTED_UV_VERSION}; "
            f"returncode={completed.returncode}, stdout={version_line!r}, stderr={diagnostic!r}"
        )


def _run_bounded_version_command(
    command: list[str],
    *,
    environment: Mapping[str, str],
    working_directory: Path,
) -> subprocess.CompletedProcess[bytes]:
    """Run the version probe while retaining at most the shared output budget.

    ``subprocess.run(..., stdout=PIPE, stderr=PIPE)`` buffers both streams without a limit
    before returning.  The two daemon readers below drain concurrently, but admit bytes to the
    shared capture only while the combined stdout/stderr budget has room.  Reading a single byte
    from unbuffered pipes makes the limit exact rather than a post-hoc size check.
    """

    try:
        process = subprocess.Popen(
            command,
            bufsize=0,
            close_fds=True,
            cwd=working_directory,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise PublishRehearsalError(f"cannot verify the private uv executable: {exc}") from exc
    if process.stdout is None or process.stderr is None:  # pragma: no cover - fixed Popen profile
        process.kill()
        process.wait()
        raise PublishRehearsalError("cannot capture private uv executable diagnostics")

    stdout = bytearray()
    stderr = bytearray()
    capture_lock = threading.Lock()
    state_changed = threading.Event()
    overflow = threading.Event()
    reader_failed = threading.Event()
    reader_errors: list[Exception] = []
    captured = 0

    def read_stream(stream, destination: bytearray) -> None:
        nonlocal captured
        try:
            while True:
                chunk = stream.read(1)
                if not chunk:
                    return
                if not isinstance(chunk, bytes):
                    raise TypeError("uv diagnostic stream returned non-bytes data")
                with capture_lock:
                    remaining = MAX_VERSION_OUTPUT_BYTES - captured
                    if remaining <= 0:
                        overflow.set()
                        return
                    admitted = chunk[:remaining]
                    destination.extend(admitted)
                    captured += len(admitted)
                    if len(chunk) > len(admitted):
                        overflow.set()
                        return
        except (OSError, TypeError, ValueError) as exc:
            with capture_lock:
                reader_errors.append(exc)
            reader_failed.set()
        finally:
            state_changed.set()

    readers = (
        threading.Thread(
            target=read_stream,
            args=(process.stdout, stdout),
            daemon=True,
            name="artifactforge-uv-version-stdout",
        ),
        threading.Thread(
            target=read_stream,
            args=(process.stderr, stderr),
            daemon=True,
            name="artifactforge-uv-version-stderr",
        ),
    )
    started_readers: list[threading.Thread] = []
    failure: PublishRehearsalError | None = None
    failure_cause: BaseException | None = None
    cleanup_failure: PublishRehearsalError | None = None
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        for reader in readers:
            try:
                reader.start()
            except (OSError, RuntimeError) as exc:
                failure = PublishRehearsalError(
                    f"cannot start private uv diagnostic readers: {exc}"
                )
                failure_cause = exc
                break
            started_readers.append(reader)

        while failure is None:
            if overflow.is_set():
                failure = PublishRehearsalError(
                    "uv --version output exceeds the bounded diagnostic profile"
                )
                break
            if reader_failed.is_set():
                with capture_lock:
                    observed_error = reader_errors[0]
                failure = PublishRehearsalError(
                    f"cannot read private uv executable diagnostics: {observed_error}"
                )
                failure_cause = observed_error
                break
            if process.poll() is not None and all(
                not reader.is_alive() for reader in started_readers
            ):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = PublishRehearsalError(
                    "cannot verify the private uv executable: "
                    f"command exceeded the {COMMAND_TIMEOUT_SECONDS}-second limit"
                )
                break
            state_changed.wait(min(remaining, 0.05))
            state_changed.clear()
    finally:
        # POSIX children run in a private session, so killing its process group also closes pipes
        # inherited by a malicious grandchild.  The unconditional cleanup path covers partial
        # reader startup and any unexpected exception after Popen succeeds.
        cleanup_needed = (
            failure is not None
            or sys.exc_info()[0] is not None
            or process.poll() is None
            or any(reader.is_alive() for reader in started_readers)
        )
        if cleanup_needed:
            _terminate_version_process_tree(process)
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired) as exc:
            cleanup_failure = PublishRehearsalError(
                f"cannot reap the private uv executable after termination: {exc}"
            )

        join_deadline = time.monotonic() + 1.0
        for reader in started_readers:
            reader.join(timeout=max(0.0, join_deadline - time.monotonic()))
        readers_alive = any(reader.is_alive() for reader in started_readers)
        if readers_alive:
            _terminate_version_process_tree(process)
            join_deadline = time.monotonic() + 1.0
            for reader in started_readers:
                reader.join(timeout=max(0.0, join_deadline - time.monotonic()))
            readers_alive = any(reader.is_alive() for reader in started_readers)
        if readers_alive:
            cleanup_failure = PublishRehearsalError(
                "private uv diagnostic readers did not stop after process-tree termination"
            )
        else:
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass

    if cleanup_failure is not None:
        if failure is not None:
            raise cleanup_failure from failure
        raise cleanup_failure
    if failure is not None:
        raise failure from failure_cause
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
    )


def _terminate_version_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _revalidate_original_inputs(
    *,
    directory: Path,
    version: str,
    project_before: _FileObservation,
    distributions_before: tuple[Path, Path],
    files_before: tuple[_FileObservation, _FileObservation],
    payloads_before: tuple[bytes, bytes],
    uv_path: Path,
    uv_before: _FileObservation,
    uv_payload_before: bytes,
) -> None:
    version_after, project_after = _project_version()
    distributions_after, files_after, payloads_after = _validate_distribution_directory(
        directory,
        version=version,
    )
    uv_payload_after, uv_after = _read_regular(
        uv_path,
        maximum=MAX_UV_EXECUTABLE_BYTES,
        label="uv executable",
    )
    if (
        version_after != version
        or project_after != project_before
        or distributions_after != distributions_before
        or files_after != files_before
        or payloads_after != payloads_before
        or uv_after != uv_before
        or uv_payload_after != uv_payload_before
    ):
        raise PublishRehearsalError(
            "project metadata, uv executable, or distributions changed during rehearsal"
        )


def run(directory: Path, *, uv_executable: Path | None = None) -> int:
    directory = Path(os.path.abspath(directory))
    version, project_before = _project_version()
    distributions, files_before, payloads_before = _validate_distribution_directory(
        directory,
        version=version,
    )
    uv_path, uv_payload, uv_before = _resolve_uv_executable(uv_executable)

    with tempfile.TemporaryDirectory(prefix="artifactforge-publish-rehearsal-") as private_name:
        private_directory = Path(private_name)
        try:
            private_directory.chmod(0o700)
        except OSError as exc:
            raise PublishRehearsalError(
                f"cannot secure private rehearsal directory: {exc}"
            ) from exc
        private_uv = private_directory / ("uv.exe" if os.name == "nt" else "uv")
        private_uv_before = _write_private_copy(private_uv, uv_payload, executable=True)
        private_distributions = (
            private_directory / distributions[0].name,
            private_directory / distributions[1].name,
        )
        private_files_before = (
            _write_private_copy(private_distributions[0], payloads_before[0], executable=False),
            _write_private_copy(private_distributions[1], payloads_before[1], executable=False),
        )
        environment = _child_environment(os.environ, private_directory=private_directory)
        _run_uv_version(
            private_uv,
            environment=environment,
            working_directory=private_directory,
        )
        _revalidate_original_inputs(
            directory=directory,
            version=version,
            project_before=project_before,
            distributions_before=distributions,
            files_before=files_before,
            payloads_before=payloads_before,
            uv_path=uv_path,
            uv_before=uv_before,
            uv_payload_before=uv_payload,
        )
        try:
            completed = subprocess.run(
                _command(private_uv, private_distributions),
                check=False,
                close_fds=True,
                cwd=private_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PublishRehearsalError(
                f"cannot complete fixed uv publish rehearsal: {exc}"
            ) from exc

        private_uv_payload_after, private_uv_after = _read_regular(
            private_uv,
            maximum=MAX_UV_EXECUTABLE_BYTES,
            label="private uv executable",
        )
        private_files_after = tuple(
            _read_regular(
                path,
                maximum=MAX_DISTRIBUTION_BYTES,
                label="private distribution",
            )
            for path in private_distributions
        )
        if (
            private_uv_payload_after != uv_payload
            or private_uv_after != private_uv_before
            or tuple(item[0] for item in private_files_after) != payloads_before
            or tuple(item[1] for item in private_files_after) != private_files_before
        ):
            raise PublishRehearsalError(
                "uv mutated the private executable or distribution snapshots"
            )
        _revalidate_original_inputs(
            directory=directory,
            version=version,
            project_before=project_before,
            distributions_before=distributions,
            files_before=files_before,
            payloads_before=payloads_before,
            uv_path=uv_path,
            uv_before=uv_before,
            uv_payload_before=uv_payload,
        )
        return completed.returncode


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ArtifactForge's closed, credential-free loopback publish rehearsal."
    )
    parser.add_argument(
        "distribution_directory",
        type=Path,
        help="directory containing exactly the canonical ArtifactForge sdist and wheel",
    )
    parser.add_argument(
        "--uv",
        type=Path,
        help="reviewed absolute uv executable (otherwise resolve uv once from the caller's PATH)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return run(args.distribution_directory, uv_executable=args.uv)
    except PublishRehearsalError as exc:
        print(f"publish rehearsal rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
