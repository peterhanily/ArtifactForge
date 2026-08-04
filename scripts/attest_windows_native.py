#!/usr/bin/env python3
# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Build a byte-bound prerequisite and observe a Windows Fixture v2 natively.

This lane has two deliberately separate stages. ``prepare`` runs ArtifactForge's complete
Fixture ABI v2 verification on the portable Linux CI host: canonical integrity, exact recipe
reproduction, Gate 1 validity, logical Zone.Identifier validation, and Gate 3 inertness.
``observe`` runs on Windows and accepts only the exact fixture/source identity bound by that
canonical prerequisite. The split is explicit because the current Fixture Core publication
and verification boundary uses Unix descriptor-relative filesystem primitives; pretending
those primitives exist in native CPython on Windows would weaken the claim.

The Windows stage copies only manifest-bound default streams into a private temporary tree.
It never executes an emitted PE. PowerShell observes every PE with Get-FileHash and
Get-AuthenticodeSignature using LiteralPath, Microsoft's dumpbin reads /HEADERS, and a bounded
byte parser verifies that the sole executable section and entry point are exactly ``ret`` plus
zero padding. The four MAM algorithm-4 Prefetch records are decompressed through ntdll's
RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx interface and compared with an independent
exact-output decode. The one disabled task XML is accepted only by an in-memory TaskDefinition
made with TaskService.Connect/NewTask/XmlText; it is never registered. The one Shell Link is
opened from the private copy through WScript.Shell without Save, Resolve, or Run. A fixed set of
signed Windows files is the mandatory Authenticode positive control. Each manifest-bound
Zone.Identifier is projected only as an NTFS alternate stream on the private copy, read back
with Get-Content -LiteralPath -Stream, removed, and checked against the manifest bytes. Source,
fixture, prerequisite, private default streams, and tool binaries are hashed before and after
observation.

Both outputs are canonical, bounded JSON. Native observations are complementary evidence;
the embedded portable report carries the complete structural and inertness claims.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

from artifactforge.artifacts.shell_link import parse_shell_link
from artifactforge.artifacts.windows_task import (
    parse_scheduled_task_xml,
    validate_scheduled_task_xml,
)
from artifactforge.fixture.abi import (
    GENERATOR_ABI_V2,
    MANIFEST_SCHEMA_V2,
    PRODUCER_PROFILE_V2,
)
from artifactforge.fixture.model import parse_fixture_manifest
from artifactforge.fixture.model_v2 import (
    FixtureManifestV2,
    WindowsMetadataV2,
)
from artifactforge.fixture.operations import VerificationResult, verify_fixture
from artifactforge.gates.oracles.prefetch_profile import decode_mam_xpress_huffman
from artifactforge.inventory import canonical_relative_paths, validate_relative_path


PORTABLE_SCHEMA_ID = "artifactforge-native-windows-portable-prerequisite-v1"
SCHEMA_ID = "artifactforge-native-windows-attestation-v4"
CANONICALIZATION = "UTF-8 JSON, sorted keys, compact separators, no NaN, one trailing LF"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PORTABLE_DISTRIBUTIONS = (
    "LnkParse3",
    "artifactforge",
    "dissect.target",
    "lief",
    "liblnk-python",
    "libregf-python",
    "libscca-python",
    "pefile",
    "regipy",
    "windowsprefetch",
)
_POWERSHELL = "pwsh"
_ZONE_STREAM = "Zone.Identifier"
_PE_MAGIC = b"MZ"
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_COMMAND_ARGUMENTS = 64
MAX_COMMAND_ARGUMENT_BYTES = 64 * 1024
OUTPUT_DRAIN_JOIN_SECONDS = 2.0
MAX_SCENE_FILES = 64
MAX_SCENE_FILE_BYTES = 64 * 1024 * 1024
MAX_SCENE_BYTES = 128 * 1024 * 1024
MAX_SCENE_DEPTH = 16
EXPECTED_TOTAL_FILES = 14
EXPECTED_PE_FILES = 5
EXPECTED_PREFETCH_FILES = 4
EXPECTED_ZONE_STREAMS = 1
EXPECTED_SCHEDULED_TASK_XML = 1
EXPECTED_SHELL_LINKS = 1
_TASK_STORE_COMPONENTS = ("c", "windows", "system32", "tasks", "artifactforge")
_SHELL_LINK_SOURCE = "ArtifactForgeMaintenance.lnk"
_TASK_API_SEQUENCE = "TaskService.Connect;NewTask(0);TaskDefinition.XmlText"
_TASK_OBSERVATION_LABEL = "TaskService-Connect-NewTask-XmlText-parse-only"
_SHELL_LINK_API_SEQUENCE = "WScript.Shell.CreateShortcut-read-only"
_SHELL_LINK_OBSERVATION_LABEL = "WScript-Shell-CreateShortcut-read-only"
_MAM_XPRESS_HUFFMAN_MAGIC = b"MAM\x04"
_MAM_HEADER_BYTES = 8
_XPRESS_HUFFMAN_TABLE_BYTES = 256
_MIN_XPRESS_HUFFMAN_BITSTREAM_BYTES = 4
_MIN_PREFETCH_V30_INNER_BYTES = 448
_MAX_PREFETCH_V30_INNER_BYTES = 4096
_MAX_PREFETCH_V30_MAM_BYTES = 8192
_MAX_PREFETCH_WORKSPACE_BYTES = 64 * 1024 * 1024
_COMPRESSION_FORMAT_XPRESS_HUFF = 4
_PREFETCH_NATIVE_API_SEQUENCE = "ntdll.RtlGetCompressionWorkSpaceSize;ntdll.RtlDecompressBufferEx"
_PREFETCH_CONTROL_TABLE_OFFSET = 15
_ACTIVATION_SCOPE = (
    "The scheduled task is parsed only in an unregistered in-memory TaskDefinition using "
    "TaskService.Connect, NewTask(0), and XmlText. The Shell Link is read only with "
    "WScript.Shell.CreateShortcut; neither artifact is saved, resolved, registered, or run."
)
_PREFETCH_SCOPE = (
    "The MAM wrapper and exact expected output are checked independently. The native API "
    "evidence covers NTSTATUS, FinalUncompressedSize, and returned output bytes; it does not "
    "claim that RtlDecompressBufferEx consumed or rejected post-size bits."
)

CommandRunner = Callable[..., dict]
PrefetchDecompressor = Callable[[bytes, int], dict]


def _canonical_json_bytes(value: object) -> bytes:
    rendered = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    result = f"{rendered}\n".encode()
    if len(result) > MAX_RECORD_BYTES:
        raise RuntimeError(f"attestation JSON exceeds the {MAX_RECORD_BYTES}-byte output limit")
    return result


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _timestamp(now: dt.datetime | None = None) -> str:
    value = now or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("attestation timestamp must be timezone-aware")
    return (
        value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _create_windows_kill_job() -> int | None:
    """Create a configured Job Object before the bounded child is launched."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    job_object_extended_limit_information = 9
    job_object_limit_kill_on_job_close = 0x00002000

    class JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JobObjectBasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise RuntimeError(f"CreateJobObjectW failed with Windows error {ctypes.get_last_error()}")
    try:
        limits = JobObjectExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = job_object_limit_kill_on_job_close
        if not kernel32.SetInformationJobObject(
            job,
            job_object_extended_limit_information,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise RuntimeError(
                f"SetInformationJobObject failed with Windows error {ctypes.get_last_error()}"
            )
        return int(job)
    except Exception:
        kernel32.CloseHandle(job)
        raise


def _assign_windows_kill_job(process: subprocess.Popen, windows_job: int | None) -> bool:
    """Assign a just-created child to its preconfigured Job Object."""
    if windows_job is None:
        return True
    import ctypes
    from ctypes import wintypes

    process_set_quota = 0x0100
    process_terminate = 0x0001
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    # CPython retains the PROCESS_INFORMATION process handle for Popen.wait().
    # It remains valid if a very fast child exits, unlike reopening by PID.
    retained = getattr(process, "_handle", None)
    process_handle = wintypes.HANDLE(int(retained)) if retained is not None else None
    opened_handle = None
    try:
        if not process_handle:
            opened_handle = kernel32.OpenProcess(
                process_set_quota | process_terminate,
                False,
                process.pid,
            )
            process_handle = opened_handle
        if process_handle and kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(windows_job), process_handle
        ):
            return True
        windows_error = ctypes.get_last_error()
        # A command that completed inside the unavoidable CreateProcess/assignment
        # window has no live primary process left to contain. Its inherited-pipe
        # descendants are still bounded by the drain deadline below.
        if process.poll() is not None:
            return False
        raise RuntimeError(f"AssignProcessToJobObject failed with Windows error {windows_error}")
    finally:
        if opened_handle:
            kernel32.CloseHandle(opened_handle)


def _terminate_process_tree(process: subprocess.Popen, windows_job: int | None) -> None:
    if sys.platform == "win32" and windows_job is not None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject(wintypes.HANDLE(windows_job), 1)
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
        return
    try:
        process.kill()
    except OSError:
        pass


def _close_windows_job(windows_job: int | None) -> None:
    if windows_job is None:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(wintypes.HANDLE(windows_job))


def _capture_bounded_process(
    command: list[str],
    *,
    env: Mapping[str, str] | None,
    timeout: int,
    maximum: int,
) -> tuple[int, bytes, bytes]:
    """Capture stdout/stderr without ever retaining more than ``maximum`` bytes."""
    windows_job = _create_windows_kill_job()
    try:
        process = subprocess.Popen(  # noqa: S603 - argv is a fixed-list native-tool boundary
            command,
            env=None if env is None else dict(env),
            start_new_session=os.name == "posix",
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
    except Exception:
        _close_windows_job(windows_job)
        raise
    try:
        if not _assign_windows_kill_job(process, windows_job):
            _close_windows_job(windows_job)
            windows_job = None
    except Exception:
        try:
            _terminate_process_tree(process, windows_job)
            process.kill()
            process.wait(timeout=5)
        finally:
            _close_windows_job(windows_job)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        raise
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen invariant
        process.kill()
        raise RuntimeError("native command did not expose bounded output pipes")
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    lock = threading.Lock()
    overflow = threading.Event()

    def drain(name: str, stream) -> None:
        nonlocal total
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                with lock:
                    room = max(0, maximum - total)
                    buffers[name].extend(chunk[:room])
                    total += min(len(chunk), room)
                    exceeded = len(chunk) > room
                if exceeded:
                    overflow.set()
                    _terminate_process_tree(process, windows_job)
        finally:
            stream.close()

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out: subprocess.TimeoutExpired | None = None
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        timed_out = exc
        returncode = -1
    finally:
        # A command can exit after spawning a descendant that inherited the output
        # pipes. Terminate the whole group/job even after a normal parent exit so
        # those descendants cannot hold the drain threads open indefinitely.
        try:
            _terminate_process_tree(process, windows_job)
            try:
                process.wait(timeout=OUTPUT_DRAIN_JOIN_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=OUTPUT_DRAIN_JOIN_SECONDS)
        finally:
            _close_windows_job(windows_job)
    deadline = time.monotonic() + OUTPUT_DRAIN_JOIN_SECONDS
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    if timed_out is not None:
        raise RuntimeError(f"native command exceeded the {timeout}-second timeout") from timed_out
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError("native command output pipes did not close after process termination")
    if overflow.is_set():
        raise RuntimeError(f"native command stdout/stderr exceeds {maximum} bytes")
    return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def _run(
    command: list[str],
    *,
    recorded_argv: list[str] | None = None,
    redactions: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int = 60,
) -> dict:
    if not command or len(command) > MAX_COMMAND_ARGUMENTS:
        raise RuntimeError("native command has an invalid argument count")
    if (
        any(type(argument) is not str or "\0" in argument for argument in command)
        or type(timeout) is not int
        or not 1 <= timeout <= 600
    ):
        raise RuntimeError("native command has an invalid argument or timeout")
    if sum(len(os.fsencode(argument)) for argument in command) > MAX_COMMAND_ARGUMENT_BYTES:
        raise RuntimeError("native command exceeds the argument-byte limit")
    returncode, raw_stdout, raw_stderr = _capture_bounded_process(
        command,
        env=env,
        timeout=timeout,
        maximum=MAX_COMMAND_OUTPUT_BYTES,
    )
    stdout = raw_stdout.decode("utf-8", errors="replace").strip()
    stderr = raw_stderr.decode("utf-8", errors="replace").strip()
    for original, replacement in (redactions or {}).items():
        stdout = stdout.replace(original, replacement)
        stderr = stderr.replace(original, replacement)
    return {
        "argv": list(recorded_argv or command),
        "returncode": returncode,
        "stderr": stderr,
        "stdout": stdout,
    }


def _git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    returncode, stdout, stderr_bytes = _capture_bounded_process(
        ["git", "-C", str(repo), *arguments],
        env=None,
        timeout=60,
        maximum=MAX_GIT_OUTPUT_BYTES,
    )
    if returncode != 0:
        stderr = stderr_bytes.decode(errors="replace").strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {stderr}")
    return stdout.decode(errors="strict").strip() if text else stdout


def _source_provenance(repo: Path = _REPOSITORY_ROOT) -> dict:
    commit = str(_git(repo, "rev-parse", "HEAD"))
    tree = str(_git(repo, "rev-parse", "HEAD^{tree}"))
    if not _HEX_40.fullmatch(commit) or not _HEX_40.fullmatch(tree):
        raise RuntimeError("Git did not return full SHA-1 commit and tree identifiers")
    status = bytes(
        _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all", text=False)
    )
    result = {
        "git_commit": commit,
        "git_tree": tree,
        "status_porcelain_sha256": hashlib.sha256(status).hexdigest(),
        "worktree_clean": not status,
    }
    return {**result, "identity_sha256": _canonical_digest(result)}


def _source_postcondition(initial: dict, repo: Path) -> dict:
    final = _source_provenance(repo)
    return {**final, "unchanged": final == initial}


def _github_run_identity(environ: Mapping[str, str] | None = None) -> dict | None:
    values = os.environ if environ is None else environ
    if values.get("GITHUB_ACTIONS", "").lower() != "true":
        return None
    names = {
        "event_name": "GITHUB_EVENT_NAME",
        "git_sha": "GITHUB_SHA",
        "job": "GITHUB_JOB",
        "ref": "GITHUB_REF",
        "repository": "GITHUB_REPOSITORY",
        "run_attempt": "GITHUB_RUN_ATTEMPT",
        "run_id": "GITHUB_RUN_ID",
        "server_url": "GITHUB_SERVER_URL",
        "workflow": "GITHUB_WORKFLOW",
        "workflow_ref": "GITHUB_WORKFLOW_REF",
    }
    result = {field: values.get(variable, "") for field, variable in names.items()}
    if result["server_url"] and result["repository"] and result["run_id"]:
        result["run_url"] = (
            f"{result['server_url'].rstrip('/')}/{result['repository']}/actions/runs/"
            f"{result['run_id']}"
        )
    return result


_GITHUB_IDENTITY_FIELDS = {
    "event_name",
    "git_sha",
    "job",
    "ref",
    "repository",
    "run_attempt",
    "run_id",
    "run_url",
    "server_url",
    "workflow",
    "workflow_ref",
}
_GITHUB_CROSS_JOB_FIELDS = _GITHUB_IDENTITY_FIELDS - {"job"}


def _validate_source_identity(source: object, where: str) -> None:
    if type(source) is not dict or set(source) != {
        "git_commit",
        "git_tree",
        "identity_sha256",
        "status_porcelain_sha256",
        "worktree_clean",
    }:
        raise RuntimeError(f"{where} has invalid source evidence")
    base = {name: value for name, value in source.items() if name != "identity_sha256"}
    if (
        _HEX_40.fullmatch(str(source["git_commit"])) is None
        or _HEX_40.fullmatch(str(source["git_tree"])) is None
        or _HEX_64.fullmatch(str(source["status_porcelain_sha256"])) is None
        or source["status_porcelain_sha256"] != hashlib.sha256(b"").hexdigest()
        or source["identity_sha256"] != _canonical_digest(base)
        or source["worktree_clean"] is not True
    ):
        raise RuntimeError(f"{where} has self-inconsistent source evidence")


def _validate_utc_timestamp(value: object, where: str) -> None:
    if type(value) is not str or _UTC_SECONDS.fullmatch(value) is None:
        raise RuntimeError(f"{where} has an invalid UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RuntimeError(f"{where} has an invalid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise RuntimeError(f"{where} has a non-canonical UTC timestamp")


def _validate_github_identity(record: object, source: Mapping[str, object], where: str) -> None:
    if record is None:
        return
    if (
        type(record) is not dict
        or set(record) != _GITHUB_IDENTITY_FIELDS
        or any(type(record[name]) is not str or not record[name] for name in record)
        or _HEX_40.fullmatch(record["git_sha"]) is None
        or record["git_sha"] != source.get("git_commit")
        or not record["run_id"].isdigit()
        or int(record["run_id"]) <= 0
        or not record["run_attempt"].isdigit()
        or int(record["run_attempt"]) <= 0
        or record["run_url"]
        != (
            f"{record['server_url'].rstrip('/')}/{record['repository']}/actions/runs/"
            f"{record['run_id']}"
        )
    ):
        raise RuntimeError(f"{where} has invalid GitHub Actions provenance")


def _require_related_github_runs(portable: object, native: object) -> None:
    if portable is None and native is None:
        return
    if type(portable) is not dict or type(native) is not dict:
        raise RuntimeError("portable and native GitHub Actions provenance are not both present")
    mismatched = [
        field for field in sorted(_GITHUB_CROSS_JOB_FIELDS) if portable[field] != native[field]
    ]
    if mismatched:
        raise RuntimeError(
            "portable and native GitHub Actions provenance differ: " + ", ".join(mismatched)
        )


def _github_failures(github_run: dict | None, source: dict) -> list[str]:
    if github_run is None:
        return []
    missing = [name for name, value in github_run.items() if name != "run_url" and not value]
    failures = []
    if missing:
        failures.append(f"GitHub Actions identity is incomplete: {', '.join(sorted(missing))}")
    if github_run["git_sha"] and github_run["git_sha"] != source["git_commit"]:
        failures.append("GitHub Actions GITHUB_SHA does not match source HEAD")
    return failures


def _is_linklike(path: Path, state: os.stat_result) -> bool:
    if stat.S_ISLNK(state.st_mode):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None and isjunction(path):
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(getattr(state, "st_file_attributes", 0) & reparse)


_STABLE_FILE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")


def _filesystem_identity(state: os.stat_result) -> dict:
    return {"device": state.st_dev, "inode": state.st_ino}


def _read_regular(
    path: Path,
    *,
    where: str,
    maximum: int = MAX_SCENE_FILE_BYTES,
    expected_state: os.stat_result | None = None,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"cannot inspect {where}: {exc}") from exc
    if _is_linklike(path, before) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{where} must be a regular file, not a link or special file")
    if expected_state is not None and any(
        getattr(expected_state, field) != getattr(before, field) for field in _STABLE_FILE_FIELDS
    ):
        raise RuntimeError(f"{where} changed between inventory and open")
    if before.st_size > maximum:
        raise RuntimeError(f"{where} exceeds the {maximum}-byte limit")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(maximum + 1)
        after_read = os.fstat(stream.fileno())
    after = path.lstat()
    if any(
        getattr(before, field) != getattr(opened, field)
        or getattr(opened, field) != getattr(after_read, field)
        or getattr(after_read, field) != getattr(after, field)
        for field in _STABLE_FILE_FIELDS
    ):
        raise RuntimeError(f"{where} changed while it was being read")
    if len(data) != before.st_size:
        raise RuntimeError(f"{where} length changed while it was being read")
    return data


def _regular_file_identity(path: Path, where: str) -> dict:
    data = _read_regular(path, where=where)
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _scene_capture(scene: Path) -> tuple[dict, dict[str, bytes]]:
    try:
        root_state = scene.lstat()
    except OSError as exc:
        raise RuntimeError(f"cannot inspect fixture artifacts: {exc}") from exc
    if _is_linklike(scene, root_state) or not stat.S_ISDIR(root_state.st_mode):
        raise RuntimeError("fixture artifacts must be a real directory, not a link")
    files: dict[str, bytes] = {}
    directories = []

    def visit(directory: Path, parts: tuple[str, ...]) -> int:
        if len(parts) > MAX_SCENE_DEPTH:
            raise RuntimeError(
                f"fixture artifacts exceed the {MAX_SCENE_DEPTH}-component depth limit"
            )
        before = directory.lstat()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise RuntimeError(f"cannot list fixture artifacts directory: {exc}") from exc
        below = 0
        for entry in entries:
            child_parts = (*parts, entry.name)
            relative = validate_relative_path("/".join(child_parts))
            path = Path(entry.path)
            state = entry.stat(follow_symlinks=False)
            if _is_linklike(path, state):
                raise RuntimeError(f"fixture artifacts contain a link: {relative!r}")
            if stat.S_ISDIR(state.st_mode):
                directories.append(relative)
                nested = visit(path, child_parts)
                if nested == 0:
                    raise RuntimeError(
                        f"fixture artifacts contain an empty directory: {relative!r}"
                    )
                below += nested
                continue
            if not stat.S_ISREG(state.st_mode):
                raise RuntimeError(f"fixture artifacts contain a special file: {relative!r}")
            if len(files) >= MAX_SCENE_FILES:
                raise RuntimeError(f"fixture artifacts exceed the {MAX_SCENE_FILES}-file limit")
            data = _read_regular(
                path,
                where=f"fixture artifact {relative!r}",
                expected_state=state,
            )
            if sum(map(len, files.values())) + len(data) > MAX_SCENE_BYTES:
                raise RuntimeError(
                    f"fixture artifacts exceed the {MAX_SCENE_BYTES}-byte total limit"
                )
            files[relative] = data
            below += 1
        after = directory.lstat()
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise RuntimeError("fixture artifacts directory changed during capture")
        final_names = sorted(item.name for item in os.scandir(directory))
        if [entry.name for entry in entries] != final_names:
            raise RuntimeError("fixture artifacts directory entries changed during capture")
        return below

    visit(scene, ())
    root_after = scene.lstat()
    if any(
        getattr(root_state, field) != getattr(root_after, field) for field in ("st_dev", "st_ino")
    ):
        raise RuntimeError("fixture artifacts root changed during capture")
    ordered_paths = canonical_relative_paths(files, require_sorted=False)
    ordered_files = [
        {
            "path": relative,
            "sha256": hashlib.sha256(files[relative]).hexdigest(),
            "size": len(files[relative]),
        }
        for relative in ordered_paths
    ]
    digest_input = {"files": ordered_files}
    manifest = {
        "canonicalization": CANONICALIZATION,
        "directories": sorted(directories),
        "directory_count": len(directories),
        "file_count": len(ordered_files),
        "files": ordered_files,
        "total_bytes": sum(item["size"] for item in ordered_files),
        "tree_sha256": hashlib.sha256(_canonical_json_bytes(digest_input)).hexdigest(),
    }
    return manifest, {relative: files[relative] for relative in ordered_paths}


def _fixture_state(fixture: Path) -> tuple[dict, dict[str, bytes]]:
    root_before = fixture.lstat()
    if _is_linklike(fixture, root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise RuntimeError("fixture root must be a real directory, not a link")
    names = sorted(path.name for path in fixture.iterdir())
    if names != ["artifacts", "fixture.json"]:
        raise RuntimeError(
            "fixture root inventory must be exactly artifacts/ and fixture.json; found "
            + ", ".join(names)
        )
    manifest_path = fixture / "fixture.json"
    manifest_state = manifest_path.lstat()
    manifest_bytes = _read_regular(
        manifest_path,
        where="fixture.json",
        maximum=MAX_RECORD_BYTES,
        expected_state=manifest_state,
    )
    manifest = parse_fixture_manifest(manifest_bytes, require_canonical=True)
    if type(manifest) is not FixtureManifestV2:
        raise RuntimeError("Windows native attestation requires Fixture ABI v2")
    artifacts_path = fixture / "artifacts"
    artifacts_before = artifacts_path.lstat()
    scene, captured = _scene_capture(artifacts_path)
    artifacts_after = artifacts_path.lstat()
    root_after = fixture.lstat()
    final_names = sorted(path.name for path in fixture.iterdir())
    if names != final_names or any(
        getattr(root_before, field) != getattr(root_after, field) for field in ("st_dev", "st_ino")
    ):
        raise RuntimeError("fixture root changed during capture")
    if any(
        getattr(artifacts_before, field) != getattr(artifacts_after, field)
        for field in ("st_dev", "st_ino")
    ):
        raise RuntimeError("fixture artifacts directory changed during capture")
    return {
        "filesystem_identity": {
            "artifacts": _filesystem_identity(artifacts_after),
            "fixture": _filesystem_identity(root_after),
            "manifest": _filesystem_identity(manifest_state),
        },
        "manifest": manifest,
        "manifest_file": {
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "size": len(manifest_bytes),
        },
        "root_inventory": names,
        "scene": scene,
    }, captured


def _fixture_postcondition(initial: dict, fixture: Path) -> dict:
    final, _captured = _fixture_state(fixture)
    comparable = {**final, "manifest": final["manifest"].to_mapping()}
    expected = {**initial, "manifest": initial["manifest"].to_mapping()}
    return {
        "manifest_file": {
            **final["manifest_file"],
            "unchanged": final["manifest_file"] == initial["manifest_file"],
        },
        "filesystem_identity": {
            **final["filesystem_identity"],
            "unchanged": final["filesystem_identity"] == initial["filesystem_identity"],
        },
        "scene": {
            **{
                name: final["scene"][name]
                for name in ("directory_count", "file_count", "total_bytes", "tree_sha256")
            },
            "unchanged": final["scene"] == initial["scene"],
        },
        "unchanged": comparable == expected,
    }


def _validate_manifest_binding(state: dict) -> None:
    manifest = state["manifest"]
    if (
        manifest.schema != MANIFEST_SCHEMA_V2
        or manifest.generator.abi != GENERATOR_ABI_V2
        or manifest.generator.producer_profile != PRODUCER_PROFILE_V2
        or manifest.recipe.family != "windows"
        or manifest.recipe.profile.id != "windows-loose-v2"
    ):
        raise RuntimeError(
            "native Windows attestation requires the complete windows-loose-v2 contract"
        )
    expected_files = [
        {
            "path": entry.served_path,
            "sha256": entry.sha256.removeprefix("sha256:"),
            "size": entry.size,
        }
        for entry in manifest.payload.files
    ]
    if state["scene"]["files"] != expected_files:
        raise RuntimeError("fixture default streams disagree with the v2 payload manifest")
    expected_directories = [entry.served_path for entry in manifest.payload.directories]
    if state["scene"]["directories"] != expected_directories:
        raise RuntimeError("fixture carrier directories disagree with the v2 payload manifest")
    payload = manifest.payload
    if (
        payload.file_count != state["scene"]["file_count"]
        or payload.directory_count != state["scene"]["directory_count"]
        or payload.regular_file_bytes != state["scene"]["total_bytes"]
        or payload.total_bound_bytes != payload.regular_file_bytes + payload.metadata_blob_bytes
    ):
        raise RuntimeError("fixture v2 payload counters disagree with the carrier")


def _portable_verifier_environment() -> dict:
    distributions = {}
    for name in _PORTABLE_DISTRIBUTIONS:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(f"missing portable verifier distribution version: {name}") from exc
        if not version:
            raise RuntimeError(f"empty portable verifier distribution version: {name}")
        distributions[name] = version
    implementation = platform.python_implementation()
    version = platform.python_version()
    if implementation != "CPython" or not version:
        raise RuntimeError(
            f"portable verifier requires versioned CPython, found {implementation} {version}"
        )
    return {
        "distributions": distributions,
        "python": {"implementation": implementation, "version": version},
    }


def _portable_host_evidence(environ: Mapping[str, str] | None = None) -> dict:
    values = os.environ if environ is None else environ
    result = {
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "release": platform.release(),
        "runner_image": {
            name: values.get(name, "")
            for name in ("ImageOS", "ImageVersion", "RUNNER_ARCH", "RUNNER_OS")
        },
        "system": platform.system(),
        "version": platform.version(),
    }
    if not all(result[name] for name in ("machine", "platform", "release", "system")):
        raise RuntimeError("portable prerequisite host identity is incomplete")
    return {**result, "identity_sha256": _canonical_digest(result)}


def _gate_report_evidence(report: object) -> dict:
    return {
        "denominator": report.denominator,
        "fails": list(report.fails),
        "gaps": list(report.gaps),
        "gate": report.gate,
        "metrics": report.metrics,
        "name": report.name,
        "question": report.question,
        "verdict": "pass" if report.ok else "fail",
    }


def _verified_fixture_evidence(
    fixture: Path,
    *,
    verifier: Callable[..., VerificationResult] | None = None,
) -> tuple[dict, dict, dict[str, bytes]]:
    """Run complete portable assurance and bind it to one stable carrier capture."""
    environment = _portable_verifier_environment()
    verification = (verifier or verify_fixture)(fixture, assurance=True)
    reports = tuple(verification.assurance_reports)
    if [(report.gate, report.name) for report in reports] != [
        (1, "validity"),
        (3, "inertness"),
    ]:
        raise RuntimeError(
            "Fixture Core assurance did not return exactly Gate 1 validity and Gate 3 inertness"
        )
    checks = {
        "assurance": (
            "not-run"
            if verification.assurance_ok is None
            else "pass"
            if verification.assurance_ok
            else "fail"
        ),
        "integrity": "pass" if verification.integrity_ok else "fail",
        "reproduction": (
            "not-run"
            if verification.reproduction_ok is None
            else "pass"
            if verification.reproduction_ok
            else "fail"
        ),
    }
    if not verification.ok or set(checks.values()) != {"pass"}:
        details = list(verification.failures)
        details.extend(
            f"Gate {report.gate} ({report.name}): " + "; ".join(report.fails)
            for report in reports
            if not report.ok
        )
        suffix = ": " + " | ".join(dict.fromkeys(details)) if details else ""
        raise RuntimeError(f"Fixture Core verification failed{suffix}")

    state, captured = _fixture_state(fixture)
    _validate_manifest_binding(state)
    manifest = verification.manifest
    if manifest != state["manifest"]:
        raise RuntimeError("verified manifest differs from the canonical fixture manifest")
    manifest_bytes = manifest.canonical_bytes()
    manifest_identity = {
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "size": len(manifest_bytes),
    }
    if state["manifest_file"] != manifest_identity:
        raise RuntimeError("fixture.json changed after portable verification")
    payload = manifest.payload
    return (
        {
            "carrier": state["scene"],
            "filesystem_identity": state["filesystem_identity"],
            "manifest": manifest.to_mapping(),
            "manifest_file": state["manifest_file"],
            "portable_verification": {
                "checks": checks,
                "contract": (
                    "verify_fixture(fixture, assurance=True): canonical manifest and payload "
                    "integrity, exact complete logical reproduction, Gate 1 validity including "
                    "logical Zone.Identifier bytes plus Task/LNK parser consensus, and Gate 3 "
                    "inertness"
                ),
                "environment": environment,
                "failures": list(verification.failures),
                "payload": {
                    "directory_count": payload.directory_count,
                    "file_count": payload.file_count,
                    "metadata_blob_bytes": payload.metadata_blob_bytes,
                    "metadata_blob_count": payload.metadata_blob_count,
                    "regular_file_bytes": payload.regular_file_bytes,
                    "total_bound_bytes": payload.total_bound_bytes,
                },
                "producer_compatibility": {
                    "basis": (
                        "exact generator ABI and producer profile plus successful complete "
                        "logical reproduction; package versions are provenance, not ABI identity"
                    ),
                    "generator_abi": manifest.generator.abi,
                    "manifest_generator_version": manifest.generator.version,
                    "producer_profile": manifest.generator.producer_profile,
                    "verifier_distribution_version": environment["distributions"]["artifactforge"],
                },
                "reports": [_gate_report_evidence(report) for report in reports],
                "verdict": "pass",
            },
        },
        state,
        captured,
    )


def prepare(
    fixture: Path,
    *,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
    repository_root: Path = _REPOSITORY_ROOT,
    verifier: Callable[..., VerificationResult] | None = None,
) -> dict:
    """Create the canonical portable prerequisite consumed by the Windows job."""
    fixture = Path(os.path.abspath(fixture))
    repository_root = repository_root.resolve(strict=True)
    source = _source_provenance(repository_root)
    github_run = _github_run_identity(environ)
    fixture_evidence, initial_state, _captured = _verified_fixture_evidence(
        fixture, verifier=verifier
    )
    failures = _github_failures(github_run, source)
    if not source["worktree_clean"]:
        failures.append("portable prerequisite source worktree is not clean")
    fixture_post = _fixture_postcondition(initial_state, fixture)
    if not fixture_post["unchanged"]:
        failures.append("fixture changed while the portable prerequisite was prepared")
    source_post = _source_postcondition(source, repository_root)
    if not source_post["unchanged"]:
        failures.append("source changed while the portable prerequisite was prepared")
    report = {
        "canonicalization": CANONICALIZATION,
        "claim_scope": {
            "complete_portable_assurance": True,
            "cross_host_boundary": (
                "This prerequisite binds complete Fixture v2 verification on its recorded "
                "host. The Windows report must independently match source, manifest, and "
                "default-stream tree digests before making complementary native observations."
            ),
            "native_windows_observations": False,
        },
        "failures": failures,
        "fixture": {**fixture_evidence, "post_preparation": fixture_post},
        "generated_at_utc": _timestamp(now),
        "github_actions": github_run,
        "host": _portable_host_evidence(environ),
        "producer": {
            "name": "ArtifactForge",
            "source": source,
            "source_post_preparation": source_post,
        },
        "schema": PORTABLE_SCHEMA_ID,
        "schema_version": 1,
    }
    report["verdict"] = "pass" if not failures else "fail"
    return report


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def _passing_ratio(passed: object, total: object) -> bool:
    return type(passed) is int and type(total) is int and total > 0 and passed == total


def _valid_assurance_report(report: dict) -> bool:
    """Validate the two schema-v1 gate records, including their stated ratios."""
    if (
        report["fails"] != []
        or type(report["gaps"]) is not list
        or any(type(gap) is not str or not gap for gap in report["gaps"])
        or type(report["metrics"]) is not dict
        or type(report["question"]) is not str
        or not report["question"]
        or type(report["denominator"]) is not str
        or not report["denominator"]
    ):
        return False
    metrics = report["metrics"]
    if report["gate"] == 1:
        if set(metrics) != {
            "claim_scopes",
            "oracle_reads_passed",
            "oracle_reads_total",
            "semantic_checks_passed",
            "semantic_checks_total",
        } or not _passing_ratio(metrics["oracle_reads_passed"], metrics["oracle_reads_total"]):
            return False
        if not _passing_ratio(metrics["semantic_checks_passed"], metrics["semantic_checks_total"]):
            return False
        scopes = metrics["claim_scopes"]
        expected_scopes = {
            "container_acceptance",
            "declared_profile_conformance",
            "downstream_consumer_compatibility",
            "independent_consensus",
            "semantic_extraction",
        }
        if (
            type(scopes) is not dict
            or set(scopes) != expected_scopes
            or any(
                type(scope) is not dict
                or set(scope) != {"passed", "total"}
                or not _passing_ratio(scope["passed"], scope["total"])
                for scope in scopes.values()
            )
        ):
            return False
        expected_denominator = (
            f"{metrics['oracle_reads_passed']}/{metrics['oracle_reads_total']} oracle reads "
            f"succeeded; {metrics['semantic_checks_passed']}/"
            f"{metrics['semantic_checks_total']} semantic checks succeeded"
        )
        return report["denominator"] == expected_denominator
    if report["gate"] == 3:
        if set(metrics) != {
            "binary_safety_checks_passed",
            "binary_safety_checks_total",
            "formats_marked",
            "formats_total",
        } or not _passing_ratio(
            metrics["binary_safety_checks_passed"], metrics["binary_safety_checks_total"]
        ):
            return False
        if not _passing_ratio(metrics["formats_marked"], metrics["formats_total"]):
            return False
        expected_denominator = (
            f"{metrics['binary_safety_checks_passed']}/"
            f"{metrics['binary_safety_checks_total']} binary safety checks pass; "
            f"{metrics['formats_marked']}/{metrics['formats_total']} marker-eligible artifacts "
            "carry an in-band synthetic marker"
        )
        return report["denominator"] == expected_denominator
    return False


def _load_prerequisite(path: Path) -> tuple[dict, dict]:
    data = _read_regular(path, where="portable prerequisite", maximum=MAX_RECORD_BYTES)
    try:
        value = json.loads(data, object_pairs_hook=_strict_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"portable prerequisite is not strict JSON: {exc}") from exc
    if type(value) is not dict:
        raise RuntimeError("portable prerequisite root must be a JSON object")
    if _canonical_json_bytes(value) != data:
        raise RuntimeError("portable prerequisite is not canonical JSON")
    expected_root = {
        "canonicalization",
        "claim_scope",
        "failures",
        "fixture",
        "generated_at_utc",
        "github_actions",
        "host",
        "producer",
        "schema",
        "schema_version",
        "verdict",
    }
    if (
        set(value) != expected_root
        or value.get("canonicalization") != CANONICALIZATION
        or value.get("schema") != PORTABLE_SCHEMA_ID
        or value.get("schema_version") != 1
        or value.get("verdict") != "pass"
        or value.get("failures") != []
    ):
        raise RuntimeError("portable prerequisite is not a passing supported record")
    _validate_utc_timestamp(value["generated_at_utc"], "portable prerequisite")
    claim_scope = value.get("claim_scope")
    if (
        type(claim_scope) is not dict
        or claim_scope.get("complete_portable_assurance") is not True
        or claim_scope.get("native_windows_observations") is not False
        or type(claim_scope.get("cross_host_boundary")) is not str
        or not claim_scope["cross_host_boundary"]
    ):
        raise RuntimeError("portable prerequisite has an invalid claim scope")
    portable_host = value.get("host")
    if type(portable_host) is not dict or type(portable_host.get("identity_sha256")) is not str:
        raise RuntimeError("portable prerequisite has invalid host evidence")
    portable_host_base = {
        name: item for name, item in portable_host.items() if name != "identity_sha256"
    }
    if portable_host["identity_sha256"] != _canonical_digest(portable_host_base):
        raise RuntimeError("portable prerequisite host evidence is self-inconsistent")
    fixture = value.get("fixture")
    producer = value.get("producer")
    if type(fixture) is not dict or type(producer) is not dict:
        raise RuntimeError("portable prerequisite omits fixture or producer evidence")
    if set(fixture) != {
        "carrier",
        "filesystem_identity",
        "manifest",
        "manifest_file",
        "portable_verification",
        "post_preparation",
    } or set(producer) != {"name", "source", "source_post_preparation"}:
        raise RuntimeError("portable prerequisite has an unexpected evidence shape")
    source = producer.get("source")
    if type(source) is not dict or set(source) != {
        "git_commit",
        "git_tree",
        "identity_sha256",
        "status_porcelain_sha256",
        "worktree_clean",
    }:
        raise RuntimeError("portable prerequisite has invalid source evidence")
    source_base = {name: item for name, item in source.items() if name != "identity_sha256"}
    source_post = producer.get("source_post_preparation")
    _validate_source_identity(source, "portable prerequisite")
    if (
        producer.get("name") != "ArtifactForge"
        or _HEX_40.fullmatch(str(source.get("git_commit", ""))) is None
        or _HEX_40.fullmatch(str(source.get("git_tree", ""))) is None
        or _HEX_64.fullmatch(str(source.get("status_porcelain_sha256", ""))) is None
        or source.get("identity_sha256") != _canonical_digest(source_base)
        or source.get("worktree_clean") is not True
        or type(source_post) is not dict
        or source_post.get("unchanged") is not True
        or {name: value for name, value in source_post.items() if name != "unchanged"} != source
    ):
        raise RuntimeError("portable prerequisite source evidence is self-inconsistent")
    _validate_github_identity(
        value["github_actions"],
        source,
        "portable prerequisite",
    )
    verification = fixture.get("portable_verification")
    if type(verification) is not dict or set(verification) != {
        "checks",
        "contract",
        "environment",
        "failures",
        "payload",
        "producer_compatibility",
        "reports",
        "verdict",
    }:
        raise RuntimeError("portable prerequisite omits full verification evidence")
    if (
        verification.get("checks")
        != {
            "assurance": "pass",
            "integrity": "pass",
            "reproduction": "pass",
        }
        or verification.get("verdict") != "pass"
        or verification.get("failures") != []
    ):
        raise RuntimeError("portable prerequisite does not bind all passing checks")
    if type(verification.get("contract")) is not str or not verification["contract"]:
        raise RuntimeError("portable prerequisite verification contract is invalid")
    reports = verification.get("reports")
    report_fields = {
        "denominator",
        "fails",
        "gaps",
        "gate",
        "metrics",
        "name",
        "question",
        "verdict",
    }
    if (
        type(reports) is not list
        or len(reports) != 2
        or any(type(report) is not dict or set(report) != report_fields for report in reports)
        or [(report["gate"], report["name"], report["verdict"]) for report in reports]
        != [(1, "validity", "pass"), (3, "inertness", "pass")]
        or any(not _valid_assurance_report(report) for report in reports)
    ):
        raise RuntimeError("portable prerequisite does not bind both passing assurance gates")
    try:
        manifest_bytes = _canonical_json_bytes(fixture["manifest"])
        manifest = parse_fixture_manifest(manifest_bytes, require_canonical=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"portable prerequisite manifest is invalid: {exc}") from exc
    if type(manifest) is not FixtureManifestV2:
        raise RuntimeError("portable prerequisite must bind Fixture ABI v2")
    synthetic_state = {
        "manifest": manifest,
        "manifest_file": fixture.get("manifest_file"),
        "scene": fixture.get("carrier"),
    }
    _validate_manifest_binding(synthetic_state)
    carrier = fixture["carrier"]
    if (
        type(carrier) is not dict
        or set(carrier)
        != {
            "canonicalization",
            "directories",
            "directory_count",
            "file_count",
            "files",
            "total_bytes",
            "tree_sha256",
        }
        or carrier["tree_sha256"]
        != hashlib.sha256(_canonical_json_bytes({"files": carrier["files"]})).hexdigest()
    ):
        raise RuntimeError("portable prerequisite carrier identity is self-inconsistent")
    manifest_identity = {
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "size": len(manifest_bytes),
    }
    if (
        set(synthetic_state["manifest_file"] or {}) != {"sha256", "size"}
        or synthetic_state["manifest_file"] != manifest_identity
    ):
        raise RuntimeError("portable prerequisite manifest identity is self-inconsistent")
    payload = manifest.payload
    if verification.get("payload") != {
        "directory_count": payload.directory_count,
        "file_count": payload.file_count,
        "metadata_blob_bytes": payload.metadata_blob_bytes,
        "metadata_blob_count": payload.metadata_blob_count,
        "regular_file_bytes": payload.regular_file_bytes,
        "total_bound_bytes": payload.total_bound_bytes,
    }:
        raise RuntimeError("portable prerequisite payload counters are self-inconsistent")
    environment = verification.get("environment")
    if (
        type(environment) is not dict
        or set(environment) != {"distributions", "python"}
        or type(environment["distributions"]) is not dict
        or type(environment["python"]) is not dict
        or set(environment["distributions"]) != set(_PORTABLE_DISTRIBUTIONS)
        or any(type(item) is not str or not item for item in environment["distributions"].values())
        or environment["python"].get("implementation") != "CPython"
        or type(environment["python"].get("version")) is not str
        or not environment["python"]["version"]
    ):
        raise RuntimeError("portable prerequisite verifier environment is invalid")
    compatibility = verification.get("producer_compatibility")
    if (
        type(compatibility) is not dict
        or set(compatibility)
        != {
            "basis",
            "generator_abi",
            "manifest_generator_version",
            "producer_profile",
            "verifier_distribution_version",
        }
        or type(compatibility["basis"]) is not str
        or not compatibility["basis"]
        or compatibility["generator_abi"] != manifest.generator.abi
        or compatibility["manifest_generator_version"] != manifest.generator.version
        or compatibility["producer_profile"] != manifest.generator.producer_profile
        or compatibility["verifier_distribution_version"]
        != environment["distributions"]["artifactforge"]
    ):
        raise RuntimeError("portable prerequisite producer compatibility is invalid")
    fixture_post = fixture.get("post_preparation")
    if type(fixture_post) is not dict or fixture_post.get("unchanged") is not True:
        raise RuntimeError("portable prerequisite lacks a passing fixture postcondition")
    initial_filesystem = fixture.get("filesystem_identity")
    if (
        type(initial_filesystem) is not dict
        or set(initial_filesystem) != {"artifacts", "fixture", "manifest"}
        or any(
            type(value) is not dict
            or set(value) != {"device", "inode"}
            or any(type(number) is not int or number < 0 for number in value.values())
            for value in initial_filesystem.values()
        )
    ):
        raise RuntimeError("portable prerequisite fixture filesystem identity is invalid")
    if (
        set(fixture_post)
        != {
            "filesystem_identity",
            "manifest_file",
            "scene",
            "unchanged",
        }
        or type(fixture_post.get("manifest_file")) is not dict
        or type(fixture_post.get("scene")) is not dict
        or type(fixture_post.get("filesystem_identity")) is not dict
        or set(fixture_post["filesystem_identity"])
        != {"artifacts", "fixture", "manifest", "unchanged"}
        or fixture_post.get("manifest_file", {}).get("unchanged") is not True
        or {name: fixture_post["manifest_file"].get(name) for name in ("sha256", "size")}
        != manifest_identity
        or fixture_post.get("scene", {}).get("unchanged") is not True
        or any(
            fixture_post["scene"].get(name) != fixture["carrier"].get(name)
            for name in ("directory_count", "file_count", "total_bytes", "tree_sha256")
        )
        or fixture_post.get("filesystem_identity", {}).get("unchanged") is not True
        or {
            name: item
            for name, item in fixture_post["filesystem_identity"].items()
            if name != "unchanged"
        }
        != initial_filesystem
    ):
        raise RuntimeError("portable prerequisite fixture postcondition is self-inconsistent")
    return value, {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


@contextmanager
def _private_scene(captured: Mapping[str, bytes], expected: dict) -> Iterator[tuple[Path, dict]]:
    """Create a fresh default-stream-only snapshot using portable Windows-safe paths."""
    with tempfile.TemporaryDirectory(prefix="artifactforge-windows-native-") as temporary:
        root = Path(temporary) / "artifacts"
        root.mkdir()
        for relative in expected["directories"]:
            validated = validate_relative_path(relative)
            (root / Path(*validated.split("/"))).mkdir(parents=True, exist_ok=True)
        for relative in canonical_relative_paths(captured, require_sorted=False):
            validated = validate_relative_path(relative)
            destination = root / Path(*validated.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(captured[relative])
        observed, private_bytes = _scene_capture(root)
        if observed != expected or private_bytes != dict(captured):
            raise RuntimeError(
                "private Windows snapshot does not byte-match the prerequisite carrier"
            )
        yield root, observed


def _pe_inert_profile(data: bytes) -> dict:
    """Verify the exact x64 PE32+ one-ret code profile without executing the image."""
    if len(data) < 0x40 or data[:2] != _PE_MAGIC:
        raise RuntimeError("synthetic PE does not begin with an in-bounds DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 24 or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise RuntimeError("synthetic PE has no in-bounds PE signature")
    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    section_table = optional + optional_size
    if machine != 0x8664:
        raise RuntimeError(f"synthetic PE machine is 0x{machine:04x}, not AMD64")
    if section_count < 1 or section_count > 16:
        raise RuntimeError("synthetic PE section count is outside the bounded profile")
    if optional_size < 0x70 or section_table + section_count * 40 > len(data):
        raise RuntimeError("synthetic PE optional/section headers are out of bounds")
    optional_magic = struct.unpack_from("<H", data, optional)[0]
    entry_rva = struct.unpack_from("<I", data, optional + 16)[0]
    if optional_magic != 0x20B:
        raise RuntimeError("synthetic PE is not PE32+")
    sections = []
    executable = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = data[offset : offset + 8]
        try:
            name = raw_name.rstrip(b"\0").decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise RuntimeError("synthetic PE section name is not ASCII") from exc
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
            raise RuntimeError(f"synthetic PE section {name!r} raw bytes are out of bounds")
        item = {
            "characteristics_hex": f"0x{characteristics:08x}",
            "name": name,
            "raw_offset": raw_offset,
            "raw_size": raw_size,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
        }
        sections.append(item)
        if characteristics & 0x20000000:
            executable.append((item, characteristics))
    if len(executable) != 1:
        raise RuntimeError("synthetic PE must have exactly one executable section")
    code, characteristics = executable[0]
    if code["name"] != ".text" or not characteristics & 0x20:
        raise RuntimeError("synthetic PE executable section must be .text code")
    if entry_rva != code["virtual_address"]:
        raise RuntimeError("synthetic PE entry point is not the start of .text")
    body = data[code["raw_offset"] : code["raw_offset"] + code["raw_size"]]
    if len(body) != 0x200 or body != b"\xc3" + b"\0" * 0x1FF:
        raise RuntimeError(
            "synthetic PE executable bytes are not exactly one RET plus zero padding"
        )
    return {
        "architecture": "AMD64",
        "entry_point_rva": entry_rva,
        "executable_section_count": 1,
        "executable_section_sha256": hashlib.sha256(body).hexdigest(),
        "instruction_profile": [{"bytes": "c3", "instruction": "ret"}],
        "optional_header": "PE32+",
        "section_count": section_count,
        "sections": sections,
        "zero_padding_bytes": len(body) - 1,
    }


def _logical_zone_map(
    manifest: FixtureManifestV2, captured: Mapping[str, bytes]
) -> dict[str, bytes]:
    streams = {}
    pe_paths = {path for path, data in captured.items() if data.startswith(_PE_MAGIC)}
    for node in manifest.payload.files:
        metadata = node.metadata
        if type(metadata) is not WindowsMetadataV2:
            raise RuntimeError("Windows fixture file has non-Windows logical metadata")
        for blob in metadata.streams:
            if blob.name != _ZONE_STREAM:
                raise RuntimeError(
                    f"unsupported logical stream {blob.name!r} on {node.served_path!r}"
                )
            if node.served_path in streams:
                raise RuntimeError(f"duplicate Zone.Identifier for {node.served_path!r}")
            streams[node.served_path] = blob.data
    if len(captured) != EXPECTED_TOTAL_FILES:
        raise RuntimeError(
            f"Windows v2 profile must carry {EXPECTED_TOTAL_FILES} default-stream files"
        )
    if len(pe_paths) != EXPECTED_PE_FILES or len(streams) != EXPECTED_ZONE_STREAMS:
        raise RuntimeError("Windows v2 PE/Zone.Identifier population is incomplete")
    if not set(streams) < pe_paths:
        raise RuntimeError("Zone.Identifier population is not a strict subset of synthetic PEs")
    return {path: streams[path] for path in sorted(streams)}


def _served_windows_path(relative: str) -> str:
    """Map one manifest carrier path to its canonical drive-letter Windows path."""
    validated = validate_relative_path(relative)
    parts = validated.split("/")
    if (
        len(parts) < 2
        or len(parts[0]) != 1
        or not "A" <= parts[0] <= "Z"
        or any(not component for component in parts[1:])
    ):
        raise RuntimeError(f"Windows fixture path is not drive-relative: {relative!r}")
    return f"{parts[0]}:\\" + "\\".join(parts[1:])


def _is_task_store_path(relative: str) -> bool:
    parts = relative.casefold().split("/")
    return (
        len(parts) == len(_TASK_STORE_COMPONENTS) + 1
        and tuple(parts[: len(_TASK_STORE_COMPONENTS)]) == _TASK_STORE_COMPONENTS
        and bool(parts[-1])
    )


def _profile_artifacts(
    manifest: FixtureManifestV2,
    captured: Mapping[str, bytes],
) -> dict[str, dict]:
    """Discover Task/LNK records from manifest paths and enforce their strict byte profiles."""
    manifest_paths = {node.served_path for node in manifest.payload.files}
    if manifest_paths != set(captured):
        raise RuntimeError("Windows profile discovery requires the complete manifest byte set")

    resident_by_windows_path = {
        _served_windows_path(relative): {
            "path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
        for relative, data in captured.items()
        if data.startswith(_PE_MAGIC)
    }
    if len(resident_by_windows_path) != EXPECTED_PE_FILES:
        raise RuntimeError("Windows profile discovery found an incomplete PE population")
    task_paths = sorted(relative for relative in captured if _is_task_store_path(relative))
    if len(task_paths) != EXPECTED_SCHEDULED_TASK_XML:
        raise RuntimeError("Windows profile requires exactly one Task Scheduler store path")
    task_path = task_paths[0]
    task_data = captured[task_path]
    if not task_data.startswith(b"\xff\xfe"):
        raise RuntimeError("Task Scheduler store artifact lacks its UTF-16LE byte profile")
    try:
        task_profile = parse_scheduled_task_xml(task_data)
        if task_profile.command not in resident_by_windows_path:
            raise RuntimeError("Task Scheduler command does not join one manifest-resident PE")
        task_profile = validate_scheduled_task_xml(
            task_data,
            resident_pe_paths=(task_profile.command,),
        )
    except ValueError as exc:
        raise RuntimeError(
            f"Task Scheduler store artifact fails portable assurance: {exc}"
        ) from exc
    task_target = resident_by_windows_path.get(task_profile.command)
    if task_target is None:
        raise RuntimeError("Task Scheduler command does not join one manifest-resident PE")
    expected_task_path = "C/Windows/System32/Tasks/ArtifactForge/" + task_profile.task_name
    if task_path != expected_task_path:
        raise RuntimeError("Task Scheduler store path disagrees with its parsed task name")

    shell_paths = sorted(relative for relative in captured if relative.casefold().endswith(".lnk"))
    if len(shell_paths) != EXPECTED_SHELL_LINKS:
        raise RuntimeError("Windows profile requires exactly one .lnk manifest path")
    shell_path = shell_paths[0]
    shell_data = captured[shell_path]
    try:
        shell_profile = parse_shell_link(shell_data)
    except ValueError as exc:
        raise RuntimeError(f"Shell Link artifact fails portable assurance: {exc}") from exc
    shell_target = resident_by_windows_path.get(shell_profile.target_path)
    if shell_target is None:
        raise RuntimeError("Shell Link target does not join one manifest-resident PE")
    if shell_profile.target_size != shell_target["size"]:
        raise RuntimeError("Shell Link target size disagrees with its manifest-resident PE")
    expected_shell_path = (
        f"C/Users/{manifest.recipe.profile.username}/AppData/Roaming/Microsoft/Windows/"
        f"Start Menu/Programs/{_SHELL_LINK_SOURCE}"
    )
    if shell_path != expected_shell_path:
        raise RuntimeError("Shell Link manifest path is outside the canonical Start Menu profile")

    zone_targets = {
        node.served_path
        for node in manifest.payload.files
        if isinstance(node.metadata, WindowsMetadataV2)
        and any(blob.name == _ZONE_STREAM for blob in node.metadata.streams)
    }
    if (
        task_target["path"] == shell_target["path"]
        or task_target["path"] in zone_targets
        or shell_target["path"] in zone_targets
    ):
        raise RuntimeError(
            "Task and Shell Link must target distinct non-download manifest-resident PEs"
        )

    return {
        "scheduled_task_xml": {
            "data": task_data,
            "path": task_path,
            "profile": task_profile,
            "target": task_target,
        },
        "shell_link": {
            "data": shell_data,
            "path": shell_path,
            "profile": shell_profile,
            "target": shell_target,
        },
    }


def _prefetch_inner_header(data: bytes, declared_size: int) -> dict:
    """Read the native canary's deliberately small v30/SCCA header contract."""
    if type(data) is not bytes or len(data) != declared_size or len(data) < 16:
        raise RuntimeError("Prefetch native output does not equal its MAM declared size")
    version, signature, reserved, header_size = struct.unpack_from("<I4sII", data, 0)
    if version != 30:
        raise RuntimeError("Prefetch native output version is not exactly 30")
    if signature != b"SCCA":
        raise RuntimeError("Prefetch native output lacks the SCCA signature")
    if reserved != 0:
        raise RuntimeError("Prefetch native output has a non-zero reserved header field")
    if header_size != declared_size:
        raise RuntimeError("Prefetch inner header size disagrees with its decoded bytes")
    return {
        "file_size": header_size,
        "signature": "SCCA",
        "version": version,
    }


def _prefetch_artifacts(captured: Mapping[str, bytes]) -> list[dict]:
    """Classify exactly four bounded MAM algorithm-4 Prefetch default streams."""
    paths = sorted(path for path in captured if path.casefold().endswith(".pf"))
    if len(paths) != EXPECTED_PREFETCH_FILES:
        raise RuntimeError(
            f"Windows profile requires exactly {EXPECTED_PREFETCH_FILES} .pf manifest paths"
        )
    disguised = sorted(
        path
        for path, data in captured.items()
        if not path.casefold().endswith(".pf") and data.startswith(b"MAM")
    )
    if disguised:
        raise RuntimeError("Windows profile carries a MAM stream outside a .pf manifest path")

    artifacts = []
    minimum_mam_size = (
        _MAM_HEADER_BYTES + _XPRESS_HUFFMAN_TABLE_BYTES + _MIN_XPRESS_HUFFMAN_BITSTREAM_BYTES
    )
    for relative in paths:
        data = captured[relative]
        if type(data) is not bytes:
            raise RuntimeError(f"Prefetch {relative!r} is not immutable bytes")
        if not minimum_mam_size <= len(data) <= _MAX_PREFETCH_V30_MAM_BYTES:
            raise RuntimeError(f"Prefetch {relative!r} is outside the bounded MAM profile")
        if data[:4] != _MAM_XPRESS_HUFFMAN_MAGIC:
            raise RuntimeError(f"Prefetch {relative!r} is not MAM algorithm 4")
        declared_size = struct.unpack_from("<I", data, 4)[0]
        if not _MIN_PREFETCH_V30_INNER_BYTES <= declared_size <= _MAX_PREFETCH_V30_INNER_BYTES:
            raise RuntimeError(
                f"Prefetch {relative!r} declared output size is outside the v30 profile"
            )
        try:
            expected_output = decode_mam_xpress_huffman(data)
        except ValueError as exc:
            raise RuntimeError(
                f"Prefetch {relative!r} fails the independent exact-output decoder: {exc}"
            ) from exc
        inner_header = _prefetch_inner_header(expected_output, declared_size)
        artifacts.append(
            {
                "data": data,
                "declared_uncompressed_size": declared_size,
                "expected_output": expected_output,
                "inner_header": inner_header,
                "path": relative,
                "payload": data[_MAM_HEADER_BYTES:],
            }
        )
    return artifacts


def _ntstatus_hex(value: int, *, where: str) -> tuple[int, str]:
    if type(value) is not int or not -(1 << 31) <= value < 1 << 32:
        raise RuntimeError(f"{where} is not a 32-bit NTSTATUS")
    unsigned = value & 0xFFFFFFFF
    return unsigned, f"0x{unsigned:08x}"


def _rtl_decompress_xpress_huffman(payload: bytes, output_capacity: int) -> dict:
    """Call the two ntdll routines without importing Windows ctypes surfaces elsewhere."""
    if sys.platform != "win32":
        raise RuntimeError("ntdll Prefetch decompression is available only on Windows")
    if (
        type(payload) is not bytes
        or not _XPRESS_HUFFMAN_TABLE_BYTES + _MIN_XPRESS_HUFFMAN_BITSTREAM_BYTES
        <= len(payload)
        <= _MAX_PREFETCH_V30_MAM_BYTES - _MAM_HEADER_BYTES
        or type(output_capacity) is not int
        or not _MIN_PREFETCH_V30_INNER_BYTES <= output_capacity <= _MAX_PREFETCH_V30_INNER_BYTES
    ):
        raise RuntimeError("invalid bounded XPRESS-Huffman native-call input")

    import ctypes

    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ulong_pointer = ctypes.POINTER(ctypes.c_ulong)
    byte_pointer = ctypes.POINTER(ctypes.c_ubyte)
    get_workspace = ntdll.RtlGetCompressionWorkSpaceSize
    get_workspace.argtypes = [ctypes.c_ushort, ulong_pointer, ulong_pointer]
    get_workspace.restype = ctypes.c_long
    decompress = ntdll.RtlDecompressBufferEx
    decompress.argtypes = [
        ctypes.c_ushort,
        byte_pointer,
        ctypes.c_ulong,
        byte_pointer,
        ctypes.c_ulong,
        ulong_pointer,
        ctypes.c_void_p,
    ]
    decompress.restype = ctypes.c_long

    compress_workspace_size = ctypes.c_ulong(0)
    fragment_workspace_size = ctypes.c_ulong(0)
    workspace_status = int(
        get_workspace(
            _COMPRESSION_FORMAT_XPRESS_HUFF,
            ctypes.byref(compress_workspace_size),
            ctypes.byref(fragment_workspace_size),
        )
    )
    workspace_unsigned, workspace_hex = _ntstatus_hex(
        workspace_status,
        where="RtlGetCompressionWorkSpaceSize result",
    )
    if workspace_unsigned != 0:
        raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed with {workspace_hex}")
    workspace_size = max(compress_workspace_size.value, fragment_workspace_size.value)
    if not 1 <= workspace_size <= _MAX_PREFETCH_WORKSPACE_BYTES:
        raise RuntimeError("ntdll returned an unsafe Prefetch workspace size")

    compressed_buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    output_buffer = (ctypes.c_ubyte * output_capacity)()
    workspace_buffer = (ctypes.c_ubyte * workspace_size)()
    final_size = ctypes.c_ulong(0)
    decompression_status = int(
        decompress(
            _COMPRESSION_FORMAT_XPRESS_HUFF,
            output_buffer,
            output_capacity,
            compressed_buffer,
            len(payload),
            ctypes.byref(final_size),
            ctypes.cast(workspace_buffer, ctypes.c_void_p),
        )
    )
    decompression_unsigned, _decompression_hex = _ntstatus_hex(
        decompression_status,
        where="RtlDecompressBufferEx result",
    )
    if decompression_unsigned == 0 and final_size.value <= output_capacity:
        output = bytes(output_buffer[: final_size.value])
    else:
        output = b""
    return {
        "compress_workspace_size": int(compress_workspace_size.value),
        "decompress_ntstatus": decompression_status,
        "final_uncompressed_size": int(final_size.value),
        "fragment_workspace_size": int(fragment_workspace_size.value),
        "output": output,
        "workspace_query_ntstatus": workspace_status,
    }


def _prefetch_native_observation(
    payload: bytes,
    output_capacity: int,
    decompressor: PrefetchDecompressor,
) -> tuple[bytes, dict, int]:
    raw = decompressor(payload, output_capacity)
    if type(raw) is not dict or set(raw) != {
        "compress_workspace_size",
        "decompress_ntstatus",
        "final_uncompressed_size",
        "fragment_workspace_size",
        "output",
        "workspace_query_ntstatus",
    }:
        raise RuntimeError("Prefetch native decompressor returned an invalid record")
    compress_workspace = raw["compress_workspace_size"]
    fragment_workspace = raw["fragment_workspace_size"]
    final_size = raw["final_uncompressed_size"]
    output = raw["output"]
    if (
        type(compress_workspace) is not int
        or type(fragment_workspace) is not int
        or min(compress_workspace, fragment_workspace) < 0
        or not 1 <= max(compress_workspace, fragment_workspace) <= _MAX_PREFETCH_WORKSPACE_BYTES
        or type(final_size) is not int
        or not 0 <= final_size < 1 << 32
        or type(output) is not bytes
        or len(output) > output_capacity
    ):
        raise RuntimeError("Prefetch native decompressor returned unsafe sizes or output")
    workspace_status, workspace_hex = _ntstatus_hex(
        raw["workspace_query_ntstatus"],
        where="RtlGetCompressionWorkSpaceSize result",
    )
    decompression_status, decompression_hex = _ntstatus_hex(
        raw["decompress_ntstatus"],
        where="RtlDecompressBufferEx result",
    )
    if workspace_status != 0:
        raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed with {workspace_hex}")
    if decompression_status == 0 and (final_size > output_capacity or len(output) != final_size):
        raise RuntimeError("successful RtlDecompressBufferEx output length is inconsistent")
    if decompression_status != 0 and output:
        raise RuntimeError("failed RtlDecompressBufferEx call returned publishable output bytes")
    observation = {
        "allocated_workspace_size": max(compress_workspace, fragment_workspace),
        "api_sequence": _PREFETCH_NATIVE_API_SEQUENCE,
        "compress_workspace_size": compress_workspace,
        "compression_format": _COMPRESSION_FORMAT_XPRESS_HUFF,
        "decompress_ntstatus": decompression_hex,
        "final_uncompressed_size": final_size,
        "fragment_workspace_size": fragment_workspace,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "returned_output_size": len(output),
        "workspace_query_ntstatus": workspace_hex,
    }
    return output, observation, decompression_status


def _prefetch_attestation(
    artifact: Mapping[str, object],
    decompressor: PrefetchDecompressor,
) -> dict:
    relative = artifact["path"]
    data = artifact["data"]
    payload = artifact["payload"]
    expected_output = artifact["expected_output"]
    declared_size = artifact["declared_uncompressed_size"]
    inner_header = artifact["inner_header"]
    if (
        type(relative) is not str
        or type(data) is not bytes
        or type(payload) is not bytes
        or type(expected_output) is not bytes
        or type(declared_size) is not int
        or type(inner_header) is not dict
    ):
        raise RuntimeError("invalid Prefetch discovery record")
    output, native, decompression_status = _prefetch_native_observation(
        payload,
        declared_size,
        decompressor,
    )
    if decompression_status != 0:
        raise RuntimeError(
            f"RtlDecompressBufferEx rejected {relative!r} with {native['decompress_ntstatus']}"
        )
    if native["final_uncompressed_size"] != declared_size:
        raise RuntimeError(f"RtlDecompressBufferEx returned the wrong size for {relative!r}")
    if output != expected_output:
        raise RuntimeError(
            f"RtlDecompressBufferEx output disagrees with the exact decoder for {relative!r}"
        )
    observed_header = _prefetch_inner_header(output, declared_size)
    if observed_header != inner_header:
        raise RuntimeError(f"native Prefetch header observation changed for {relative!r}")
    return {
        "inner_header": observed_header,
        "native_decompression": native,
        "path": relative,
        "portable_assurance": {"bytes_base64": base64.b64encode(data).decode("ascii")},
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "verdict": "pass",
        "wrapper": {
            "algorithm": _COMPRESSION_FORMAT_XPRESS_HUFF,
            "compressed_payload_size": len(payload),
            "declared_uncompressed_size": declared_size,
            "magic_hex": _MAM_XPRESS_HUFFMAN_MAGIC.hex(),
        },
    }


def _prefetch_corruption_control(
    artifact: Mapping[str, object],
    decompressor: PrefetchDecompressor,
) -> dict:
    """Prove the native call is live with a mutation that removes literal symbol 30."""
    relative = artifact["path"]
    payload = artifact["payload"]
    expected_output = artifact["expected_output"]
    declared_size = artifact["declared_uncompressed_size"]
    if (
        type(relative) is not str
        or type(payload) is not bytes
        or type(expected_output) is not bytes
        or type(declared_size) is not int
        or len(payload) <= _PREFETCH_CONTROL_TABLE_OFFSET
    ):
        raise RuntimeError("invalid Prefetch corruption-control record")
    original_byte = payload[_PREFETCH_CONTROL_TABLE_OFFSET]
    if original_byte & 0x0F == 0:
        raise RuntimeError("Prefetch code table unexpectedly omits mandatory literal symbol 30")
    corrupted = bytearray(payload)
    corrupted[_PREFETCH_CONTROL_TABLE_OFFSET] &= 0xF0
    corrupted_payload = bytes(corrupted)
    output, native, decompression_status = _prefetch_native_observation(
        corrupted_payload,
        declared_size,
        decompressor,
    )
    if decompression_status == 0 and output == expected_output:
        raise RuntimeError("corrupted Prefetch payload reproduced the exact expected output")
    outcome = "native-error" if decompression_status != 0 else "nonmatching-exact-output"
    return {
        "artifact_path": relative,
        "expected_output_sha256": hashlib.sha256(expected_output).hexdigest(),
        "mutation": {
            "corrupted_payload_sha256": hashlib.sha256(corrupted_payload).hexdigest(),
            "mutated_byte_hex": f"{corrupted_payload[_PREFETCH_CONTROL_TABLE_OFFSET]:02x}",
            "operation": "clear-low-nibble-for-v30-version-literal",
            "original_byte_hex": f"{original_byte:02x}",
            "payload_offset": _PREFETCH_CONTROL_TABLE_OFFSET,
            "wrapper_offset": _MAM_HEADER_BYTES + _PREFETCH_CONTROL_TABLE_OFFSET,
        },
        "native_decompression": native,
        "outcome": outcome,
        "verdict": "pass",
    }


_SIGNATURE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $args[0]
$certificate = $signature.SignerCertificate
[ordered]@{
  Status = $signature.Status.ToString()
  StatusMessage = [string]$signature.StatusMessage
  SignerThumbprint = if ($null -eq $certificate) { '' } else { [string]$certificate.Thumbprint }
  SignerSubject = if ($null -eq $certificate) { '' } else { [string]$certificate.Subject }
  SignerIssuer = if ($null -eq $certificate) { '' } else { [string]$certificate.Issuer }
  SignatureType = [string]$signature.SignatureType
  IsOSBinary = [bool]$signature.IsOSBinary
} | ConvertTo-Json -Compress
""".strip()

_FILE_HASH_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$hash = Get-FileHash -LiteralPath $args[0] -Algorithm SHA256
[ordered]@{Algorithm = [string]$hash.Algorithm; Hash = [string]$hash.Hash} |
  ConvertTo-Json -Compress
""".strip()

_ADS_READ_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$bytes = [byte[]](Get-Content -LiteralPath $args[0] -Stream 'Zone.Identifier' -AsByteStream -Raw)
[ordered]@{Length = $bytes.Length; Base64 = [Convert]::ToBase64String($bytes)} |
  ConvertTo-Json -Compress
""".strip()

_ADS_EXISTS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$stream = Get-Item -LiteralPath $args[0] -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
[ordered]@{Exists = ($null -ne $stream)} | ConvertTo-Json -Compress
""".strip()

_TASK_XML_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
function Get-Sha256Hex([byte[]]$Bytes) {
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { $digest = $hasher.ComputeHash($Bytes) } finally { $hasher.Dispose() }
  return [BitConverter]::ToString($digest).Replace('-', '')
}
$bytes = [IO.File]::ReadAllBytes($args[0])
if ($bytes.Length -lt 4 -or $bytes[0] -ne 0xff -or $bytes[1] -ne 0xfe) {
  throw 'Task XML is not UTF-16LE with a BOM'
}
$xml = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$definition = $service.NewTask(0)
$definition.XmlText = $xml
$roundTrip = [string]$definition.XmlText
$roundTripBytes = [Text.Encoding]::Unicode.GetBytes($roundTrip)
[ordered]@{
  Accepted = $true
  ApiSequence = 'TaskService.Connect;NewTask(0);TaskDefinition.XmlText'
  InputByteLength = $bytes.Length
  InputSha256 = Get-Sha256Hex $bytes
  RoundTripUtf16LeByteLength = $roundTripBytes.Length
  RoundTripUtf16LeSha256 = Get-Sha256Hex $roundTripBytes
  XmlTextCharacterLength = $roundTrip.Length
} | ConvertTo-Json -Compress
""".strip()

_SHELL_LINK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
function Get-Sha256Hex([byte[]]$Bytes) {
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { $digest = $hasher.ComputeHash($Bytes) } finally { $hasher.Dispose() }
  return [BitConverter]::ToString($digest).Replace('-', '')
}
$bytes = [IO.File]::ReadAllBytes($args[0])
$shell = New-Object -ComObject 'WScript.Shell'
$shortcut = $shell.CreateShortcut($args[0])
[ordered]@{
  ApiSequence = 'WScript.Shell.CreateShortcut-read-only'
  Arguments = [string]$shortcut.Arguments
  Description = [string]$shortcut.Description
  Hotkey = [string]$shortcut.Hotkey
  IconLocation = [string]$shortcut.IconLocation
  InputByteLength = $bytes.Length
  InputSha256 = Get-Sha256Hex $bytes
  TargetPath = [string]$shortcut.TargetPath
  WindowStyle = [int]$shortcut.WindowStyle
  WorkingDirectory = [string]$shortcut.WorkingDirectory
} | ConvertTo-Json -Compress
""".strip()

_PLATFORM_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[ordered]@{
  Culture = [Globalization.CultureInfo]::CurrentCulture.Name
  Is64BitOperatingSystem = [Environment]::Is64BitOperatingSystem
  Is64BitProcess = [Environment]::Is64BitProcess
  OSVersion = [Environment]::OSVersion.VersionString
  PowerShellEdition = [string]$PSVersionTable.PSEdition
  PowerShellVersion = [string]$PSVersionTable.PSVersion
  UICulture = [Globalization.CultureInfo]::CurrentUICulture.Name
} | ConvertTo-Json -Compress
""".strip()


def _json_stdout(record: dict, where: str) -> dict:
    if record.get("returncode") != 0:
        raise RuntimeError(
            f"{where} failed with exit {record.get('returncode')}: {record.get('stderr', '')}"
        )
    stdout = record.get("stdout")
    if type(stdout) is not str or not stdout:
        raise RuntimeError(f"{where} returned no JSON")
    try:
        value = json.loads(stdout, object_pairs_hook=_strict_object_pairs)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"{where} returned invalid JSON: {exc}") from exc
    if type(value) is not dict:
        raise RuntimeError(f"{where} JSON root must be an object")
    return value


def _powershell_json(
    powershell: str,
    script: str,
    label: str,
    command_runner: CommandRunner,
    *,
    target: Path | None = None,
) -> tuple[dict, dict]:
    command = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]
    recorded = [
        "<pwsh>",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"<fixed:{label}>",
    ]
    redactions = {}
    if target is not None:
        target_text = str(target)
        command.append(target_text)
        recorded.append("<target>")
        redactions[target_text] = "<target>"
    record = command_runner(
        command,
        recorded_argv=recorded,
        redactions=redactions,
    )
    value = _json_stdout(record, label)
    return value, {
        "argv": record["argv"],
        "result_sha256": _canonical_digest(value),
        "returncode": record["returncode"],
        "stderr": record["stderr"],
        "stdout_sha256": hashlib.sha256(record["stdout"].encode()).hexdigest(),
        "stdout_size": len(record["stdout"].encode()),
    }


def _file_identity(path: Path, where: str = "native tool") -> dict:
    original = path.lstat()
    if _is_linklike(path, original) or not stat.S_ISREG(original.st_mode):
        raise RuntimeError(f"{where} must be a real regular file")
    resolved = path.resolve(strict=True)
    data = _read_regular(resolved, where=where, expected_state=original)
    return {
        "filesystem_identity": _filesystem_identity(original),
        "path": str(path),
        "resolved_path": str(resolved),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = "00aac56b-cd44-11d0-8cc2-00c04fc295ee"
_MICROSOFT_PUBLISHERS = {
    "microsoft 3rd party application component",
    "microsoft corporation",
    "microsoft windows",
    "microsoft windows publisher",
}
_SIGNATURE_FIELD_TYPES = {
    "IsOSBinary": bool,
    "SignatureType": str,
    "SignerIssuer": str,
    "SignerSubject": str,
    "SignerThumbprint": str,
    "Status": str,
    "StatusMessage": str,
}
_SIGNED_SIGNATURE_TYPES = {"Authenticode", "Catalog"}


def _winverifytrust(path: Path) -> dict:
    """Verify Authenticode through WinVerifyTrust and extract its verified leaf certificate."""
    if sys.platform != "win32":
        raise RuntimeError("WinVerifyTrust is available only on Windows")
    import ctypes
    from ctypes import wintypes

    class Guid(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WintrustFileInfo(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(Guid)),
        ]

    class WintrustChoice(ctypes.Union):
        _fields_ = [("pFile", ctypes.POINTER(WintrustFileInfo))]

    class WintrustData(ctypes.Structure):
        _anonymous_ = ("choice",)
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", wintypes.LPVOID),
            ("pSIPClientData", wintypes.LPVOID),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("choice", WintrustChoice),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", wintypes.LPVOID),
        ]

    class CryptProviderCert(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", wintypes.LPVOID)]

    class CryptProviderSigner(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("sftVerifyAsOf", wintypes.FILETIME),
            ("csCertChain", wintypes.DWORD),
            ("pasCertChain", ctypes.POINTER(CryptProviderCert)),
        ]

    action = Guid(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = WintrustFileInfo(
        ctypes.sizeof(WintrustFileInfo),
        str(path),
        None,
        None,
    )
    data = WintrustData()
    data.cbStruct = ctypes.sizeof(WintrustData)
    data.dwUIChoice = 2  # WTD_UI_NONE
    data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
    data.dwUnionChoice = 1  # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x00001000  # WTD_CACHE_ONLY_URL_RETRIEVAL

    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    wintrust.WinVerifyTrust.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(Guid),
        ctypes.POINTER(WintrustData),
    ]
    wintrust.WinVerifyTrust.restype = wintypes.LONG
    wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    wintrust.WTHelperProvDataFromStateData.restype = wintypes.LPVOID
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(CryptProviderSigner)
    wintrust.WTHelperGetProvCertFromChain.argtypes = [
        ctypes.POINTER(CryptProviderSigner),
        wintypes.DWORD,
    ]
    wintrust.WTHelperGetProvCertFromChain.restype = ctypes.POINTER(CryptProviderCert)
    crypt32.CertGetNameStringW.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetCertificateContextProperty.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    crypt32.CertGetCertificateContextProperty.restype = wintypes.BOOL

    status = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    normalized_status = ctypes.c_uint32(status).value
    try:
        if normalized_status != 0:
            raise RuntimeError(
                f"WinVerifyTrust rejected {path.name!r} with status 0x{normalized_status:08x}"
            )
        provider = wintrust.WTHelperProvDataFromStateData(data.hWVTStateData)
        if not provider:
            raise RuntimeError("WinVerifyTrust returned no provider state")
        signer = wintrust.WTHelperGetProvSignerFromChain(provider, 0, False, 0)
        if not signer or signer.contents.csCertChain < 1 or not signer.contents.pasCertChain:
            raise RuntimeError("WinVerifyTrust returned no signer certificate chain")
        provider_certificate = wintrust.WTHelperGetProvCertFromChain(signer, 0)
        if not provider_certificate:
            raise RuntimeError("WinVerifyTrust could not select its leaf signer certificate")
        certificate = provider_certificate.contents.pCert
        if not certificate:
            raise RuntimeError("WinVerifyTrust returned an empty signer certificate")
        length = crypt32.CertGetNameStringW(certificate, 4, 0, None, None, 0)
        if length <= 1:
            raise RuntimeError("CryptoAPI returned no signer display name")
        publisher_buffer = ctypes.create_unicode_buffer(length)
        if (
            crypt32.CertGetNameStringW(
                certificate,
                4,
                0,
                None,
                publisher_buffer,
                length,
            )
            != length
        ):
            raise RuntimeError("CryptoAPI could not read the signer display name")
        hash_size = wintypes.DWORD(0)
        if (
            not crypt32.CertGetCertificateContextProperty(
                certificate,
                3,  # CERT_SHA1_HASH_PROP_ID; recorded for cross-observer equality, never pinned
                None,
                ctypes.byref(hash_size),
            )
            or hash_size.value != 20
        ):
            raise RuntimeError("CryptoAPI could not size the signer certificate SHA-1")
        hash_buffer = (ctypes.c_ubyte * hash_size.value)()
        if not crypt32.CertGetCertificateContextProperty(
            certificate,
            3,
            hash_buffer,
            ctypes.byref(hash_size),
        ):
            raise RuntimeError("CryptoAPI could not read the signer certificate SHA-1")
        return {
            "action_guid": _WINTRUST_ACTION_GENERIC_VERIFY_V2,
            "network_retrieval": False,
            "policy": "WINTRUST_ACTION_GENERIC_VERIFY_V2",
            "publisher": publisher_buffer.value,
            "signer_certificate_sha1": bytes(hash_buffer).hex(),
            "status": normalized_status,
            "status_hex": f"0x{normalized_status:08x}",
            "verdict": "valid",
        }
    finally:
        if data.hWVTStateData:
            data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))


def _require_microsoft_wintrust(trust: object, where: str) -> None:
    if (
        type(trust) is not dict
        or set(trust)
        != {
            "action_guid",
            "network_retrieval",
            "policy",
            "publisher",
            "signer_certificate_sha1",
            "status",
            "status_hex",
            "verdict",
        }
        or trust["action_guid"] != _WINTRUST_ACTION_GENERIC_VERIFY_V2
        or trust["network_retrieval"] is not False
        or trust["policy"] != "WINTRUST_ACTION_GENERIC_VERIFY_V2"
        or type(trust["publisher"]) is not str
        or trust["publisher"].strip().casefold() not in _MICROSOFT_PUBLISHERS
        or _HEX_40.fullmatch(str(trust["signer_certificate_sha1"])) is None
        or trust["status"] != 0
        or trust["status_hex"] != "0x00000000"
        or trust["verdict"] != "valid"
    ):
        raise RuntimeError(f"{where} is not independently trusted as a Microsoft binary")


def _independent_trust_observation(path: Path, initial: Mapping[str, object], where: str) -> dict:
    trust = _winverifytrust(path)
    _require_microsoft_wintrust(trust, where)
    final = _file_identity(path, f"{where} WinVerifyTrust postcondition")
    if any(
        final[field] != initial[field]
        for field in ("filesystem_identity", "resolved_path", "sha256", "size")
    ):
        raise RuntimeError(f"{where} changed during independent trust verification")
    return trust


def _find_powershell() -> Path:
    fixed_root = None
    if sys.platform == "win32":
        program_files = os.environ.get("ProgramFiles")
        if not program_files:
            raise RuntimeError("ProgramFiles is unavailable on the Windows runner")
        fixed_root = Path(program_files).resolve(strict=True)
        candidates = [fixed_root / "PowerShell" / "7" / "pwsh.exe"]
    else:
        located = shutil.which("pwsh.exe") or shutil.which(_POWERSHELL)
        candidates = [Path(located)] if located else []
    for candidate in candidates:
        try:
            state = candidate.lstat()
        except OSError:
            continue
        if not _is_linklike(candidate, state) and stat.S_ISREG(state.st_mode):
            resolved = candidate.resolve(strict=True)
            if fixed_root is None or _inside(resolved, fixed_root):
                return resolved
    raise RuntimeError("fixed PowerShell 7 installation was not found")


def _find_vswhere() -> Path:
    candidates = []
    fixed_root = None
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if program_files_x86:
        fixed_root = Path(program_files_x86).resolve(strict=True)
        candidates.append(fixed_root / "Microsoft Visual Studio" / "Installer" / "vswhere.exe")
    if sys.platform != "win32":
        located = shutil.which("vswhere.exe") or shutil.which("vswhere")
        if located:
            candidates.append(Path(located))
    for candidate in candidates:
        try:
            state = candidate.lstat()
        except OSError:
            continue
        if not _is_linklike(candidate, state) and stat.S_ISREG(state.st_mode):
            resolved = candidate.resolve(strict=True)
            if sys.platform != "win32" or (
                fixed_root is not None and _inside(resolved, fixed_root)
            ):
                return resolved
    raise RuntimeError("vswhere.exe was not found in the fixed Visual Studio Installer location")


def _native_tools(command_runner: CommandRunner = _run) -> tuple[dict[str, str], dict]:
    powershell = _find_powershell()
    vswhere = _find_vswhere()
    initial = {
        "powershell": _file_identity(powershell),
        "vswhere": _file_identity(vswhere),
    }
    trust = {
        name: _independent_trust_observation(path, initial[name], f"native tool {name}")
        for name, path in (("powershell", powershell), ("vswhere", vswhere))
    }
    authenticode = {}
    for name, path in (("powershell", powershell), ("vswhere", vswhere)):
        signature, observation = _authenticode(path, str(powershell), command_runner)
        _require_microsoft_signature(
            signature,
            f"native tool {name}",
            independent_trust=trust[name],
        )
        authenticode[name] = {"observation": observation, "result": signature}
    discovery = command_runner(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        recorded_argv=[
            "<vswhere>",
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
    )
    if discovery["returncode"] != 0 or not discovery["stdout"].strip():
        raise RuntimeError("vswhere could not locate Visual C++ tools: " + discovery["stderr"])
    installation_lines = discovery["stdout"].splitlines()
    if len(installation_lines) != 1:
        raise RuntimeError("vswhere returned an ambiguous Visual Studio installation path")
    installation = Path(installation_lines[0]).resolve(strict=True)
    if sys.platform == "win32":
        allowed_roots = [
            Path(value).resolve(strict=True)
            for name in ("ProgramFiles", "ProgramFiles(x86)")
            if (value := os.environ.get(name))
        ]
        if not allowed_roots or not any(_inside(installation, root) for root in allowed_roots):
            raise RuntimeError(
                "vswhere returned a Visual Studio installation outside Program Files"
            )
    dumpbin_candidates = list(installation.glob("VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"))
    if not dumpbin_candidates:
        raise RuntimeError("the selected Visual Studio installation has no x64 dumpbin.exe")
    if len(dumpbin_candidates) > 32:
        raise RuntimeError("unexpectedly many dumpbin.exe candidates")

    def toolset_key(candidate: Path) -> tuple[tuple[int, ...], str]:
        version = candidate.parents[3].name
        components = version.split(".")
        numeric = (
            tuple(int(component) for component in components)
            if components and all(component.isdigit() for component in components)
            else ()
        )
        return numeric, version

    dumpbin = max(dumpbin_candidates, key=toolset_key).resolve(strict=True)
    if not _inside(dumpbin, installation):
        raise RuntimeError("the selected dumpbin.exe resolves outside Visual Studio")
    initial["dumpbin"] = _file_identity(dumpbin)
    trust["dumpbin"] = _independent_trust_observation(
        dumpbin,
        initial["dumpbin"],
        "native tool dumpbin",
    )
    signature, observation = _authenticode(dumpbin, str(powershell), command_runner)
    _require_microsoft_signature(
        signature,
        "native tool dumpbin",
        independent_trust=trust["dumpbin"],
    )
    authenticode["dumpbin"] = {"observation": observation, "result": signature}

    toolchain_version = command_runner(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationVersion",
        ],
        recorded_argv=[
            "<vswhere>",
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationVersion",
        ],
    )
    if toolchain_version["returncode"] != 0 or not toolchain_version["stdout"]:
        raise RuntimeError("vswhere could not report the Visual Studio installation version")

    version_commands = {
        "powershell": [str(powershell), "--version"],
        "vswhere": [str(vswhere), "-?"],
        "dumpbin": [str(dumpbin), "/?"],
    }
    evidence = {}
    for name, command in version_commands.items():
        record = command_runner(
            command,
            recorded_argv=[f"<{name}>", *command[1:]],
        )
        if record["returncode"] != 0 or not record["stdout"]:
            raise RuntimeError(f"cannot obtain {name} version evidence: {record['stderr']}")
        evidence[name] = {
            **initial[name],
            "authenticode": authenticode[name],
            "version_observation": record,
            "version_stdout": record["stdout"],
            "version_stdout_sha256": hashlib.sha256(record["stdout"].encode()).hexdigest(),
            "winverifytrust": trust[name],
        }
    evidence["discovery"] = {
        "argv": discovery["argv"],
        "installation_version": toolchain_version["stdout"],
        "installation_version_argv": toolchain_version["argv"],
        "installation_version_stdout_sha256": hashlib.sha256(
            toolchain_version["stdout"].encode()
        ).hexdigest(),
        "returncode": discovery["returncode"],
        "selected_toolchain": installation.name,
        "stdout_sha256": hashlib.sha256(discovery["stdout"].encode()).hexdigest(),
    }
    return {
        "dumpbin": str(dumpbin),
        "powershell": str(powershell),
        "vswhere": str(vswhere),
    }, evidence


def _tools_postcondition(tools: Mapping[str, str], initial: Mapping[str, dict]) -> dict:
    evidence = {}
    unchanged = True
    for name in ("dumpbin", "powershell", "vswhere"):
        try:
            final = _file_identity(Path(tools[name]))
            matched = all(
                final[field] == initial[name][field]
                for field in ("filesystem_identity", "resolved_path", "sha256", "size")
            )
            evidence[name] = {**final, "unchanged": matched}
        except Exception as exc:  # noqa: BLE001 - post-state failures belong in evidence
            matched = False
            evidence[name] = {"error": str(exc), "unchanged": False}
        unchanged = unchanged and matched
    return {"tools": evidence, "unchanged": unchanged}


def _platform_evidence(powershell: str, command_runner: CommandRunner) -> dict:
    native, command = _powershell_json(powershell, _PLATFORM_SCRIPT, "platform", command_runner)
    required = {
        "Culture": str,
        "Is64BitOperatingSystem": bool,
        "Is64BitProcess": bool,
        "OSVersion": str,
        "PowerShellEdition": str,
        "PowerShellVersion": str,
        "UICulture": str,
    }
    if any(type(native.get(name)) is not kind for name, kind in required.items()):
        raise RuntimeError("PowerShell platform evidence has unexpected types")
    if not native["Is64BitOperatingSystem"] or not native["Is64BitProcess"]:
        raise RuntimeError("Windows native attestation requires a 64-bit OS and process")
    result = {
        "native": native,
        "observation": command,
        "python": {
            "implementation": platform.python_implementation(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "version": platform.python_version(),
        },
        "runner_image": {
            name: os.environ.get(name, "")
            for name in ("ImageOS", "ImageVersion", "RUNNER_ARCH", "RUNNER_OS")
        },
    }
    return {**result, "identity_sha256": _canonical_digest(result)}


def _authenticode(path: Path, powershell: str, command_runner: CommandRunner) -> tuple[dict, dict]:
    value, command = _powershell_json(
        powershell,
        _SIGNATURE_SCRIPT,
        "Get-AuthenticodeSignature-LiteralPath",
        command_runner,
        target=path,
    )
    if set(value) != set(_SIGNATURE_FIELD_TYPES) or any(
        type(value[name]) is not kind for name, kind in _SIGNATURE_FIELD_TYPES.items()
    ):
        raise RuntimeError("Get-AuthenticodeSignature returned an unexpected record")
    return value, command


def _subject_names_publisher(subject: str, publisher: str) -> bool:
    """Require the verified simple display name as an exact subject CN component."""
    return (
        re.search(
            rf"(?:^|,\s*)CN\s*=\s*{re.escape(publisher)}\s*(?:,|$)",
            subject,
            flags=re.IGNORECASE,
        )
        is not None
    )


def _require_microsoft_signature(
    signature: Mapping[str, object],
    where: str,
    *,
    independent_trust: object,
    require_os_binary: bool = False,
) -> None:
    if (
        type(signature) is not dict
        or set(signature) != set(_SIGNATURE_FIELD_TYPES)
        or any(type(signature[name]) is not kind for name, kind in _SIGNATURE_FIELD_TYPES.items())
    ):
        raise RuntimeError(f"{where} has an invalid Authenticode record")
    thumbprint = signature.get("SignerThumbprint")
    _require_microsoft_wintrust(independent_trust, where)
    publisher = independent_trust["publisher"]
    if (
        signature.get("Status") != "Valid"
        or not isinstance(thumbprint, str)
        or re.fullmatch(r"[0-9A-Fa-f]{40}", thumbprint) is None
        or thumbprint.casefold() != independent_trust["signer_certificate_sha1"].casefold()
        or not _subject_names_publisher(signature["SignerSubject"], publisher)
        or signature.get("SignatureType") not in _SIGNED_SIGNATURE_TYPES
        or (require_os_binary and signature.get("IsOSBinary") is not True)
    ):
        raise RuntimeError(f"{where} is not a valid Microsoft-signed binary")


def _native_file_hash(
    path: Path, powershell: str, command_runner: CommandRunner
) -> tuple[str, dict]:
    value, command = _powershell_json(
        powershell,
        _FILE_HASH_SCRIPT,
        "Get-FileHash-LiteralPath-SHA256",
        command_runner,
        target=path,
    )
    if (
        set(value) != {"Algorithm", "Hash"}
        or value["Algorithm"] != "SHA256"
        or type(value["Hash"]) is not str
        or re.fullmatch(r"[0-9A-Fa-f]{64}", value["Hash"]) is None
    ):
        raise RuntimeError("Get-FileHash returned an unexpected SHA256 record")
    return value["Hash"].lower(), {"result": value, "observation": command}


def _dumpbin_markers(stdout: str) -> dict[str, bool]:
    output = stdout.lower()
    return {
        "amd64_machine": "8664 machine" in output,
        "entry_point_0x1000": re.search(r"\b1000 entry point\b", output) is not None,
        "pe32_plus_magic": re.search(r"\b20b magic\b", output) is not None,
        "text_section": ".text name" in output,
    }


def _dumpbin_headers(path: Path, dumpbin: str, command_runner: CommandRunner) -> dict:
    target = str(path)
    record = command_runner(
        [dumpbin, "/NOLOGO", "/HEADERS", target],
        recorded_argv=["<dumpbin>", "/NOLOGO", "/HEADERS", "<target>"],
        redactions={target: "<target>"},
    )
    if record["returncode"] != 0:
        raise RuntimeError(
            f"dumpbin /HEADERS failed with exit {record['returncode']}: {record['stderr']}"
        )
    markers = _dumpbin_markers(record["stdout"])
    if not all(markers.values()):
        missing = ", ".join(name for name, present in markers.items() if not present)
        raise RuntimeError(f"dumpbin /HEADERS omitted required PE markers: {missing}")
    stdout_bytes = record["stdout"].encode()
    return {
        "markers": markers,
        "observation": {
            "argv": record["argv"],
            "returncode": record["returncode"],
            "stderr": record["stderr"],
            "stdout": record["stdout"],
            "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stdout_size": len(stdout_bytes),
        },
    }


def _signed_positive_control(powershell: str, command_runner: CommandRunner) -> tuple[dict, Path]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates = (
        ("WindowsPowerShell", system_root / "System32/WindowsPowerShell/v1.0/powershell.exe"),
        ("notepad", system_root / "System32/notepad.exe"),
        ("kernel32", system_root / "System32/kernel32.dll"),
        ("cmd", system_root / "System32/cmd.exe"),
    )
    attempts = []
    for label, candidate in candidates:
        try:
            identity = _file_identity(candidate, f"Authenticode positive control {label}")
            trust = _independent_trust_observation(
                candidate,
                identity,
                f"Authenticode positive control {label}",
            )
            signature, observation = _authenticode(candidate, powershell, command_runner)
            attempt = {
                "identity": identity,
                "label": label,
                "observation": observation,
                "signature": signature,
                "winverifytrust": trust,
            }
            attempts.append(attempt)
            try:
                _require_microsoft_signature(
                    signature,
                    f"Authenticode positive control {label}",
                    independent_trust=trust,
                    require_os_binary=True,
                )
            except RuntimeError:
                pass
            else:
                native_hash, hash_evidence = _native_file_hash(
                    candidate, powershell, command_runner
                )
                if native_hash != identity["sha256"]:
                    raise RuntimeError(
                        "positive-control Get-FileHash disagrees with its bound bytes"
                    )
                return {
                    "attempts": attempts,
                    "hash": hash_evidence,
                    "selected": attempt,
                    "verdict": "pass",
                }, candidate
        except Exception as exc:  # noqa: BLE001 - retain each fixed-control failure
            attempts.append({"error": str(exc), "label": label})
    raise RuntimeError(
        "no fixed Windows positive control produced a Valid Authenticode signature: "
        + "; ".join(
            f"{attempt['label']}={attempt.get('signature', {}).get('Status', attempt.get('error', 'invalid'))}"
            for attempt in attempts
        )
    )


def _positive_control_postcondition(path: Path, initial: dict) -> dict:
    try:
        final = _file_identity(path, "Authenticode positive control postcondition")
        unchanged = all(
            final[field] == initial[field]
            for field in ("filesystem_identity", "resolved_path", "sha256", "size")
        )
        return {**final, "unchanged": unchanged}
    except Exception as exc:  # noqa: BLE001 - post-state errors are evidence
        return {"error": str(exc), "unchanged": False}


def _pe_attestation(
    relative: str,
    path: Path,
    data: bytes,
    tools: Mapping[str, str],
    command_runner: CommandRunner,
) -> tuple[dict, str]:
    expected_sha256 = hashlib.sha256(data).hexdigest()
    native_sha256, hash_evidence = _native_file_hash(path, tools["powershell"], command_runner)
    if native_sha256 != expected_sha256:
        raise RuntimeError(f"Get-FileHash disagrees with bytes for {relative!r}")
    signature, signature_observation = _authenticode(path, tools["powershell"], command_runner)
    if signature["Status"] != "NotSigned":
        raise RuntimeError(
            f"synthetic PE {relative!r} Authenticode status is "
            f"{signature['Status']!r}, not 'NotSigned'"
        )
    if signature["SignerThumbprint"] or signature["SignerSubject"]:
        raise RuntimeError(f"unsigned synthetic PE {relative!r} reported a signer")
    evidence = {
        "byte_profile": _pe_inert_profile(data),
        "dumpbin_headers": _dumpbin_headers(path, tools["dumpbin"], command_runner),
        "get_file_hash": hash_evidence,
        "path": relative,
        "sha256": expected_sha256,
        "signature": {
            "observation": signature_observation,
            "result": signature,
        },
        "size": len(data),
        "verdict": "pass",
    }
    return evidence, native_sha256


def _validate_native_input_binding(
    result: object,
    *,
    expected_sha256: str,
    expected_size: int,
    where: str,
) -> None:
    if (
        type(result) is not dict
        or result.get("InputByteLength") != expected_size
        or type(result.get("InputSha256")) is not str
        or result["InputSha256"].casefold() != expected_sha256
    ):
        raise RuntimeError(f"{where} did not hash the exact manifest-bound input bytes")


def _validate_task_native_result(
    result: object,
    *,
    expected_sha256: str,
    expected_size: int,
) -> None:
    expected_fields = {
        "Accepted",
        "ApiSequence",
        "InputByteLength",
        "InputSha256",
        "RoundTripUtf16LeByteLength",
        "RoundTripUtf16LeSha256",
        "XmlTextCharacterLength",
    }
    _validate_native_input_binding(
        result,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        where="Task Scheduler native parse",
    )
    if (
        set(result) != expected_fields
        or result["Accepted"] is not True
        or result["ApiSequence"] != _TASK_API_SEQUENCE
        or type(result["XmlTextCharacterLength"]) is not int
        or not 1 <= result["XmlTextCharacterLength"] <= MAX_COMMAND_OUTPUT_BYTES // 2
        or type(result["RoundTripUtf16LeByteLength"]) is not int
        or result["RoundTripUtf16LeByteLength"] != 2 * result["XmlTextCharacterLength"]
        or result["RoundTripUtf16LeByteLength"] > MAX_COMMAND_OUTPUT_BYTES
        or type(result["RoundTripUtf16LeSha256"]) is not str
        or _HEX_64.fullmatch(result["RoundTripUtf16LeSha256"].casefold()) is None
    ):
        raise RuntimeError("Task Scheduler returned an invalid in-memory XmlText parse record")


def _validate_shell_link_native_result(
    result: object,
    *,
    expected_sha256: str,
    expected_size: int,
    profile,
) -> None:
    expected_fields = {
        "ApiSequence",
        "Arguments",
        "Description",
        "Hotkey",
        "IconLocation",
        "InputByteLength",
        "InputSha256",
        "TargetPath",
        "WindowStyle",
        "WorkingDirectory",
    }
    _validate_native_input_binding(
        result,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        where="Shell Link native parse",
    )
    if (
        set(result) != expected_fields
        or result["ApiSequence"] != _SHELL_LINK_API_SEQUENCE
        or result["TargetPath"] != profile.target_path
        or result["Description"] != profile.name_string
        or result["Arguments"] != ""
        or result["WorkingDirectory"] != ""
        or result["Hotkey"] != ""
        or result["IconLocation"] not in {"", ",0"}
        or type(result["WindowStyle"]) is not int
        or result["WindowStyle"] != 1
    ):
        raise RuntimeError("WScript.Shell returned an invalid read-only Shell Link record")


def _portable_artifact_assurance(data: bytes, profile) -> dict:
    return {
        "bytes_base64": base64.b64encode(data).decode("ascii"),
        "profile": asdict(profile),
    }


def _scheduled_task_xml_attestation(
    artifact: Mapping[str, object],
    path: Path,
    powershell: str,
    command_runner: CommandRunner,
) -> dict:
    relative = artifact["path"]
    data = artifact["data"]
    profile = artifact["profile"]
    target = artifact["target"]
    if type(relative) is not str or type(data) is not bytes or type(target) is not dict:
        raise RuntimeError("invalid scheduled-task discovery record")
    expected_sha256 = hashlib.sha256(data).hexdigest()
    result, observation = _powershell_json(
        powershell,
        _TASK_XML_SCRIPT,
        _TASK_OBSERVATION_LABEL,
        command_runner,
        target=path,
    )
    _validate_task_native_result(
        result,
        expected_sha256=expected_sha256,
        expected_size=len(data),
    )
    return {
        "native_parse": {"observation": observation, "result": result},
        "path": relative,
        "portable_assurance": _portable_artifact_assurance(data, profile),
        "sha256": expected_sha256,
        "size": len(data),
        "target": target,
        "verdict": "pass",
    }


def _shell_link_attestation(
    artifact: Mapping[str, object],
    path: Path,
    powershell: str,
    command_runner: CommandRunner,
) -> dict:
    relative = artifact["path"]
    data = artifact["data"]
    profile = artifact["profile"]
    target = artifact["target"]
    if type(relative) is not str or type(data) is not bytes or type(target) is not dict:
        raise RuntimeError("invalid Shell Link discovery record")
    expected_sha256 = hashlib.sha256(data).hexdigest()
    result, observation = _powershell_json(
        powershell,
        _SHELL_LINK_SCRIPT,
        _SHELL_LINK_OBSERVATION_LABEL,
        command_runner,
        target=path,
    )
    _validate_shell_link_native_result(
        result,
        expected_sha256=expected_sha256,
        expected_size=len(data),
        profile=profile,
    )
    return {
        "native_parse": {"observation": observation, "result": result},
        "path": relative,
        "portable_assurance": _portable_artifact_assurance(data, profile),
        "sha256": expected_sha256,
        "size": len(data),
        "target": target,
        "verdict": "pass",
    }


def _ads_exists(path: Path, powershell: str, command_runner: CommandRunner) -> tuple[bool, dict]:
    value, command = _powershell_json(
        powershell,
        _ADS_EXISTS_SCRIPT,
        "Get-Item-LiteralPath-Zone-Identifier-existence",
        command_runner,
        target=path,
    )
    if set(value) != {"Exists"} or type(value["Exists"]) is not bool:
        raise RuntimeError("PowerShell returned an invalid ADS-existence record")
    return value["Exists"], command


def _zone_attestation(
    relative: str,
    path: Path,
    logical_bytes: bytes,
    expected_default_sha256: str,
    powershell: str,
    command_runner: CommandRunner,
) -> dict:
    before = _file_identity(path, f"private default stream {relative!r}")
    if before["sha256"] != expected_default_sha256:
        raise RuntimeError(f"private default stream {relative!r} changed before ADS projection")
    existed_before, before_observation = _ads_exists(path, powershell, command_runner)
    if existed_before:
        raise RuntimeError(f"private file {relative!r} unexpectedly already has Zone.Identifier")
    stream_path = Path(f"{path}:{_ZONE_STREAM}")
    created = False
    read_value = None
    read_observation = None
    try:
        with stream_path.open("xb") as stream:
            created = True
            stream.write(logical_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        read_value, read_observation = _powershell_json(
            powershell,
            _ADS_READ_SCRIPT,
            "Get-Content-LiteralPath-Zone-Identifier-AsByteStream-Raw",
            command_runner,
            target=path,
        )
        if (
            set(read_value) != {"Base64", "Length"}
            or type(read_value["Base64"]) is not str
            or type(read_value["Length"]) is not int
        ):
            raise RuntimeError("PowerShell returned an invalid Zone.Identifier byte record")
        try:
            observed = base64.b64decode(read_value["Base64"], validate=True)
        except ValueError as exc:
            raise RuntimeError("PowerShell returned invalid Zone.Identifier base64") from exc
        if read_value["Length"] != len(logical_bytes) or observed != logical_bytes:
            raise RuntimeError(
                f"native Zone.Identifier bytes disagree with manifest for {relative!r}"
            )
    finally:
        if created:
            try:
                stream_path.unlink()
            except OSError as exc:
                raise RuntimeError(
                    f"could not remove private Zone.Identifier for {relative!r}: {exc}"
                ) from exc
    existed_after, after_observation = _ads_exists(path, powershell, command_runner)
    after = _file_identity(path, f"private default stream {relative!r}")
    native_after, hash_evidence = _native_file_hash(path, powershell, command_runner)
    signature_after, signature_observation = _authenticode(path, powershell, command_runner)
    if existed_after:
        raise RuntimeError(f"private Zone.Identifier remained after reading {relative!r}")
    stable_default = all(
        after[field] == before[field]
        for field in ("filesystem_identity", "resolved_path", "sha256", "size")
    )
    if not stable_default or native_after != expected_default_sha256:
        raise RuntimeError(f"default stream changed during ADS projection for {relative!r}")
    if (
        signature_after["Status"] != "NotSigned"
        or signature_after["SignerThumbprint"]
        or signature_after["SignerSubject"]
    ):
        raise RuntimeError(f"synthetic PE {relative!r} did not remain unsigned after ADS removal")
    return {
        "authenticode_postcondition": {
            "observation": signature_observation,
            "result": signature_after,
        },
        "default_stream_postcondition": {
            **after,
            "native_sha256": native_after,
            "unchanged": True,
        },
        "get_file_hash_postcondition": hash_evidence,
        "logical_stream": {
            "sha256": hashlib.sha256(logical_bytes).hexdigest(),
            "size": len(logical_bytes),
        },
        "path": relative,
        "private_projection": {
            "after": {"exists": existed_after, "observation": after_observation},
            "before": {"exists": existed_before, "observation": before_observation},
            "materialized": True,
            "removed": True,
        },
        "readback": {"observation": read_observation, "result": read_value},
        "verdict": "pass",
    }


def attest(
    fixture: Path,
    prerequisite: Path,
    *,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
    repository_root: Path = _REPOSITORY_ROOT,
    command_runner: CommandRunner = _run,
    prefetch_decompressor: PrefetchDecompressor = _rtl_decompress_xpress_huffman,
) -> dict:
    """Make native, non-executing observations of one prerequisite-bound fixture."""
    if sys.platform != "win32":
        raise RuntimeError("native Windows observation must run on Windows")
    fixture = Path(os.path.abspath(fixture))
    prerequisite = Path(os.path.abspath(prerequisite))
    repository_root = repository_root.resolve(strict=True)
    source = _source_provenance(repository_root)
    portable, prerequisite_identity = _load_prerequisite(prerequisite)
    initial_prerequisite = _file_identity(prerequisite, "portable prerequisite")
    if any(
        initial_prerequisite[name] != prerequisite_identity[name] for name in ("sha256", "size")
    ):
        raise RuntimeError("portable prerequisite changed during canonical parsing")

    portable_source = portable["producer"]["source"]
    if source != portable_source:
        raise RuntimeError(
            "native checkout source identity does not exactly match the portable prerequisite"
        )
    if not source["worktree_clean"]:
        raise RuntimeError("native checkout source worktree is not clean")
    github_run = _github_run_identity(environ)
    github_failures = _github_failures(github_run, source)
    if github_failures:
        raise RuntimeError("; ".join(github_failures))
    _validate_github_identity(github_run, source, "native observation")
    _require_related_github_runs(portable["github_actions"], github_run)

    initial_state, captured = _fixture_state(fixture)
    _validate_manifest_binding(initial_state)
    portable_fixture = portable["fixture"]
    if (
        initial_state["manifest"].to_mapping() != portable_fixture["manifest"]
        or initial_state["manifest_file"] != portable_fixture["manifest_file"]
        or initial_state["scene"] != portable_fixture["carrier"]
    ):
        raise RuntimeError(
            "native fixture manifest/default streams do not exactly match the prerequisite"
        )
    zones = _logical_zone_map(initial_state["manifest"], captured)
    profile_artifacts = _profile_artifacts(initial_state["manifest"], captured)
    prefetch_artifacts = _prefetch_artifacts(captured)
    report = {
        "artifacts": {
            "pe": [],
            "prefetch": [],
            "scheduled_task_xml": [],
            "shell_link": [],
            "zone_identifier": [],
        },
        "canonicalization": CANONICALIZATION,
        "claim_scope": {
            "activation_scope": _ACTIVATION_SCOPE,
            "ads_scope": (
                "Manifest-bound Zone.Identifier bytes are materialized only on a private "
                "temporary copy, read through PowerShell's LiteralPath/Stream byte interface, "
                "then removed before snapshot postconditions."
            ),
            "cross_host_boundary": portable["claim_scope"]["cross_host_boundary"],
            "emitted_pe_execution": False,
            "native_observations": (
                "Get-FileHash, Get-AuthenticodeSignature, dumpbin /HEADERS, Task Scheduler's "
                "in-memory XmlText parser, WScript.Shell's shortcut reader, and ntdll's "
                "RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx are parse-only "
                "observations. Byte parsing, not process execution or disassembly, proves the "
                "one-RET executable profile; portable strict readers prove the Task/LNK byte "
                "profiles and their joins to manifest-resident PEs."
            ),
            "portable_assurance_is_prerequisite": True,
            "prefetch_scope": _PREFETCH_SCOPE,
        },
        "failures": [],
        "fixture": {
            "carrier": initial_state["scene"],
            "filesystem_identity": initial_state["filesystem_identity"],
            "manifest_file": initial_state["manifest_file"],
        },
        "generated_at_utc": _timestamp(now),
        "github_actions": github_run,
        "portable_prerequisite": {
            "identity": prerequisite_identity,
            "local_initial": initial_prerequisite,
            "record": portable,
        },
        "producer": {"name": "ArtifactForge", "source": source},
        "schema": SCHEMA_ID,
        "schema_version": 4,
    }

    tools: dict[str, str] | None = None
    tool_evidence: dict | None = None
    control_path: Path | None = None
    control_initial: dict | None = None
    try:
        with _private_scene(captured, initial_state["scene"]) as (
            private_root,
            private_initial,
        ):
            report["private_scene"] = {"initial": private_initial}
            try:
                tools, tool_evidence = _native_tools(command_runner)
                report["tools"] = {"initial": tool_evidence}
                report["host"] = _platform_evidence(tools["powershell"], command_runner)
                positive_control, control_path = _signed_positive_control(
                    tools["powershell"], command_runner
                )
                control_initial = positive_control["selected"]["identity"]
                report["positive_control"] = positive_control
                native_pe_sha256 = {}
                for relative, data in sorted(captured.items()):
                    if not data.startswith(_PE_MAGIC):
                        continue
                    path = private_root / Path(*relative.split("/"))
                    pe_evidence, native_sha256 = _pe_attestation(
                        relative,
                        path,
                        data,
                        tools,
                        command_runner,
                    )
                    report["artifacts"]["pe"].append(pe_evidence)
                    native_pe_sha256[relative] = native_sha256
                for prefetch_artifact in prefetch_artifacts:
                    report["artifacts"]["prefetch"].append(
                        _prefetch_attestation(prefetch_artifact, prefetch_decompressor)
                    )
                report["prefetch_positive_control"] = _prefetch_corruption_control(
                    prefetch_artifacts[0],
                    prefetch_decompressor,
                )
                task_artifact = profile_artifacts["scheduled_task_xml"]
                task_relative = task_artifact["path"]
                report["artifacts"]["scheduled_task_xml"].append(
                    _scheduled_task_xml_attestation(
                        task_artifact,
                        private_root / Path(*task_relative.split("/")),
                        tools["powershell"],
                        command_runner,
                    )
                )
                shell_artifact = profile_artifacts["shell_link"]
                shell_relative = shell_artifact["path"]
                report["artifacts"]["shell_link"].append(
                    _shell_link_attestation(
                        shell_artifact,
                        private_root / Path(*shell_relative.split("/")),
                        tools["powershell"],
                        command_runner,
                    )
                )
                for relative, logical_bytes in zones.items():
                    path = private_root / Path(*relative.split("/"))
                    report["artifacts"]["zone_identifier"].append(
                        _zone_attestation(
                            relative,
                            path,
                            logical_bytes,
                            native_pe_sha256[relative],
                            tools["powershell"],
                            command_runner,
                        )
                    )
                report["artifact_counts"] = {
                    "default_stream_files": len(captured),
                    "prefetch": len(report["artifacts"]["prefetch"]),
                    "scheduled_task_xml": len(report["artifacts"]["scheduled_task_xml"]),
                    "shell_link": len(report["artifacts"]["shell_link"]),
                    "synthetic_pe": len(report["artifacts"]["pe"]),
                    "zone_identifier": len(report["artifacts"]["zone_identifier"]),
                }
                if report["artifact_counts"] != {
                    "default_stream_files": EXPECTED_TOTAL_FILES,
                    "prefetch": EXPECTED_PREFETCH_FILES,
                    "scheduled_task_xml": EXPECTED_SCHEDULED_TASK_XML,
                    "shell_link": EXPECTED_SHELL_LINKS,
                    "synthetic_pe": EXPECTED_PE_FILES,
                    "zone_identifier": EXPECTED_ZONE_STREAMS,
                }:
                    raise RuntimeError("native observation counts are incomplete")
            except Exception as exc:  # noqa: BLE001 - retain native failures in JSON
                report["failures"].append(f"native observation failed: {exc}")

            try:
                private_final, _private_bytes = _scene_capture(private_root)
                private_unchanged = private_final == private_initial
                report["private_scene"]["post_observation"] = {
                    **private_final,
                    "unchanged": private_unchanged,
                }
            except Exception as exc:  # noqa: BLE001 - post-state failure is evidence
                private_unchanged = False
                report["private_scene"]["post_observation"] = {
                    "error": str(exc),
                    "unchanged": False,
                }
            if not private_unchanged:
                report["failures"].append("private default-stream snapshot changed")
            if tools is not None and tool_evidence is not None:
                tool_post = _tools_postcondition(tools, tool_evidence)
                report["tools"]["post_observation"] = tool_post
                if not tool_post["unchanged"]:
                    report["failures"].append("native tool bytes changed during observation")
            if control_path is not None and control_initial is not None:
                control_post = _positive_control_postcondition(control_path, control_initial)
                report["positive_control"]["post_observation"] = control_post
                if not control_post["unchanged"]:
                    report["failures"].append(
                        "Authenticode positive-control bytes changed during observation"
                    )
    except Exception as exc:  # noqa: BLE001 - snapshot setup/cleanup failure is evidence
        report["failures"].append(f"private snapshot failed: {exc}")

    try:
        fixture_post = _fixture_postcondition(initial_state, fixture)
    except Exception as exc:  # noqa: BLE001 - post-state failure is evidence
        fixture_post = {"error": str(exc), "unchanged": False}
    report["fixture"]["post_observation"] = fixture_post
    if not fixture_post["unchanged"]:
        report["failures"].append("fixture changed during native observation")
    try:
        prerequisite_post = _file_identity(prerequisite, "portable prerequisite postcondition")
        prerequisite_post = {
            **prerequisite_post,
            "unchanged": all(
                prerequisite_post[field] == initial_prerequisite[field]
                for field in (
                    "filesystem_identity",
                    "resolved_path",
                    "sha256",
                    "size",
                )
            ),
        }
    except Exception as exc:  # noqa: BLE001 - post-state failure is evidence
        prerequisite_post = {"error": str(exc), "unchanged": False}
    report["portable_prerequisite"]["post_observation"] = prerequisite_post
    if not prerequisite_post["unchanged"]:
        report["failures"].append("portable prerequisite changed during native observation")
    try:
        source_post = _source_postcondition(source, repository_root)
    except Exception as exc:  # noqa: BLE001 - post-state failure is evidence
        source_post = {"error": str(exc), "unchanged": False}
    report["producer"]["source_post_observation"] = source_post
    if not source_post["unchanged"]:
        report["failures"].append("source changed during native observation")
    report["verdict"] = "pass" if not report["failures"] else "fail"
    _validate_native_report(report)
    return report


def _validate_powershell_observation(
    observation: object,
    where: str,
    *,
    label: str,
    result: object,
) -> None:
    expected_argv = [
        "<pwsh>",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"<fixed:{label}>",
        "<target>",
    ]
    if (
        type(observation) is not dict
        or set(observation)
        != {
            "argv",
            "result_sha256",
            "returncode",
            "stderr",
            "stdout_sha256",
            "stdout_size",
        }
        or observation["argv"] != expected_argv
        or observation["result_sha256"] != _canonical_digest(result)
        or observation["returncode"] != 0
        or type(observation["stderr"]) is not str
        or _HEX_64.fullmatch(str(observation["stdout_sha256"])) is None
        or type(observation["stdout_size"]) is not int
        or not 1 <= observation["stdout_size"] <= MAX_COMMAND_OUTPUT_BYTES
    ):
        raise RuntimeError(f"passing native attestation has invalid {where} observation")


def _validate_native_hash_evidence(evidence: object, expected_sha256: str, where: str) -> None:
    if type(evidence) is not dict or set(evidence) != {"observation", "result"}:
        raise RuntimeError(f"passing native attestation has invalid {where} hash evidence")
    result = evidence["result"]
    if (
        type(result) is not dict
        or set(result) != {"Algorithm", "Hash"}
        or result["Algorithm"] != "SHA256"
        or type(result["Hash"]) is not str
        or result["Hash"].casefold() != expected_sha256
    ):
        raise RuntimeError(f"passing native attestation has inconsistent {where} hash")
    _validate_powershell_observation(
        evidence["observation"],
        f"{where} Get-FileHash",
        label="Get-FileHash-LiteralPath-SHA256",
        result=result,
    )


def _validate_unsigned_signature_evidence(evidence: object, where: str) -> None:
    if type(evidence) is not dict or set(evidence) != {"observation", "result"}:
        raise RuntimeError(f"passing native attestation has invalid {where} signature evidence")
    result = evidence["result"]
    if (
        type(result) is not dict
        or set(result) != set(_SIGNATURE_FIELD_TYPES)
        or any(type(result[name]) is not kind for name, kind in _SIGNATURE_FIELD_TYPES.items())
        or result["Status"] != "NotSigned"
        or result["SignatureType"] != "None"
        or result["SignerThumbprint"]
        or result["SignerSubject"]
        or result["SignerIssuer"]
        or result["IsOSBinary"] is not False
    ):
        raise RuntimeError(f"passing native attestation has inconsistent {where} signature")
    _validate_powershell_observation(
        evidence["observation"],
        f"{where} Authenticode",
        label="Get-AuthenticodeSignature-LiteralPath",
        result=result,
    )


def _validate_signed_signature_evidence(
    evidence: object,
    where: str,
    *,
    independent_trust: object,
    require_os_binary: bool = False,
) -> None:
    if type(evidence) is not dict or set(evidence) != {"observation", "result"}:
        raise RuntimeError(f"passing native attestation has invalid {where} signature evidence")
    _require_microsoft_signature(
        evidence["result"],
        where,
        independent_trust=independent_trust,
        require_os_binary=require_os_binary,
    )
    _validate_powershell_observation(
        evidence["observation"],
        f"{where} Authenticode",
        label="Get-AuthenticodeSignature-LiteralPath",
        result=evidence["result"],
    )


def _validate_pe_byte_profile(profile: object, file_size: int, where: str) -> None:
    if (
        type(profile) is not dict
        or set(profile)
        != {
            "architecture",
            "entry_point_rva",
            "executable_section_count",
            "executable_section_sha256",
            "instruction_profile",
            "optional_header",
            "section_count",
            "sections",
            "zero_padding_bytes",
        }
        or profile["architecture"] != "AMD64"
        or profile["optional_header"] != "PE32+"
        or profile["entry_point_rva"] != 0x1000
        or profile["executable_section_count"] != 1
        or profile["instruction_profile"] != [{"bytes": "c3", "instruction": "ret"}]
        or profile["zero_padding_bytes"] != 511
        or profile["executable_section_sha256"]
        != hashlib.sha256(b"\xc3" + b"\0" * 0x1FF).hexdigest()
        or type(profile["section_count"]) is not int
        or not 1 <= profile["section_count"] <= 16
        or type(profile["sections"]) is not list
        or len(profile["sections"]) != profile["section_count"]
    ):
        raise RuntimeError(f"passing native attestation has invalid {where} byte profile")
    section_fields = {
        "characteristics_hex",
        "name",
        "raw_offset",
        "raw_size",
        "virtual_address",
        "virtual_size",
    }
    executable = []
    names = []
    for section in profile["sections"]:
        if type(section) is not dict or set(section) != section_fields:
            raise RuntimeError(f"passing native attestation has invalid {where} section profile")
        names.append(section["name"])
        numeric = [
            section["raw_offset"],
            section["raw_size"],
            section["virtual_address"],
            section["virtual_size"],
        ]
        try:
            characteristics = int(section["characteristics_hex"], 16)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"passing native attestation has invalid {where} section flags"
            ) from exc
        if (
            type(section["name"]) is not str
            or not section["name"]
            or any(type(value) is not int or value < 0 for value in numeric)
            or section["raw_offset"] + section["raw_size"] > file_size
        ):
            raise RuntimeError(f"passing native attestation has invalid {where} section bounds")
        if characteristics & 0x20000000:
            executable.append((section, characteristics))
    if len(names) != len(set(names)) or len(executable) != 1:
        raise RuntimeError(f"passing native attestation has invalid {where} executable sections")
    text, characteristics = executable[0]
    if (
        text["name"] != ".text"
        or text["raw_size"] != 0x200
        or text["virtual_address"] != 0x1000
        or text["virtual_size"] != 0x200
        or characteristics & 0x20 == 0
    ):
        raise RuntimeError(f"passing native attestation has inconsistent {where} .text profile")


def _validate_dumpbin_evidence(evidence: object, where: str) -> None:
    if type(evidence) is not dict or set(evidence) != {"markers", "observation"}:
        raise RuntimeError(f"passing native attestation has invalid {where} dumpbin evidence")
    expected_markers = {
        "amd64_machine": True,
        "entry_point_0x1000": True,
        "pe32_plus_magic": True,
        "text_section": True,
    }
    if evidence["markers"] != expected_markers:
        raise RuntimeError(f"passing native attestation has incomplete {where} dumpbin markers")
    observation = evidence["observation"]
    if (
        type(observation) is not dict
        or set(observation)
        != {"argv", "returncode", "stderr", "stdout", "stdout_sha256", "stdout_size"}
        or observation["argv"] != ["<dumpbin>", "/NOLOGO", "/HEADERS", "<target>"]
        or observation["returncode"] != 0
        or type(observation["stderr"]) is not str
        or type(observation["stdout"]) is not str
        or observation["stdout_size"] != len(observation["stdout"].encode())
        or not 1 <= observation["stdout_size"] <= MAX_COMMAND_OUTPUT_BYTES
        or observation["stdout_sha256"]
        != hashlib.sha256(observation["stdout"].encode()).hexdigest()
        or _dumpbin_markers(observation["stdout"]) != expected_markers
    ):
        raise RuntimeError(f"passing native attestation has inconsistent {where} dumpbin output")


def _embedded_windows_expectations(portable_record: dict) -> tuple[dict, dict[str, bytes]]:
    fixture = portable_record.get("fixture")
    if type(fixture) is not dict:
        raise RuntimeError("passing native attestation omits its embedded fixture")
    try:
        manifest = parse_fixture_manifest(
            _canonical_json_bytes(fixture["manifest"]),
            require_canonical=True,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("passing native attestation embeds an invalid fixture manifest") from exc
    if type(manifest) is not FixtureManifestV2:
        raise RuntimeError("passing native attestation does not embed Fixture ABI v2")
    if (
        manifest.schema != MANIFEST_SCHEMA_V2
        or manifest.generator.abi != GENERATOR_ABI_V2
        or manifest.generator.producer_profile != PRODUCER_PROFILE_V2
        or manifest.recipe.family != "windows"
        or manifest.recipe.profile.id != "windows-loose-v2"
    ):
        raise RuntimeError("passing native attestation embeds the wrong fixture profile")
    carrier = fixture.get("carrier")
    expected_files = [
        {
            "path": node.served_path,
            "sha256": node.sha256.removeprefix("sha256:"),
            "size": node.size,
        }
        for node in manifest.payload.files
    ]
    expected_directories = [node.served_path for node in manifest.payload.directories]
    if (
        type(carrier) is not dict
        or set(carrier)
        != {
            "canonicalization",
            "directories",
            "directory_count",
            "file_count",
            "files",
            "total_bytes",
            "tree_sha256",
        }
        or carrier["canonicalization"] != CANONICALIZATION
        or carrier["files"] != expected_files
        or carrier["directories"] != expected_directories
        or carrier["file_count"] != len(expected_files)
        or carrier["directory_count"] != len(expected_directories)
        or carrier["total_bytes"] != sum(item["size"] for item in expected_files)
        or carrier["tree_sha256"]
        != hashlib.sha256(_canonical_json_bytes({"files": expected_files})).hexdigest()
    ):
        raise RuntimeError("passing native attestation embeds an inconsistent fixture carrier")
    zones = {}
    for node in manifest.payload.files:
        if type(node.metadata) is not WindowsMetadataV2:
            raise RuntimeError("passing native attestation embeds non-Windows file metadata")
        for blob in node.metadata.streams:
            if blob.name != _ZONE_STREAM or node.served_path in zones:
                raise RuntimeError("passing native attestation embeds unsupported logical streams")
            zones[node.served_path] = blob.data
    if len(expected_files) != EXPECTED_TOTAL_FILES or len(zones) != EXPECTED_ZONE_STREAMS:
        raise RuntimeError("passing native attestation embeds an incomplete Windows profile")
    return {item["path"]: item for item in expected_files}, zones


def _portable_assured_bytes(
    assurance: object,
    expected: Mapping[str, object],
    *,
    where: str,
) -> tuple[bytes, dict]:
    if (
        type(assurance) is not dict
        or set(assurance) != {"bytes_base64", "profile"}
        or type(assurance["bytes_base64"]) is not str
        or type(assurance["profile"]) is not dict
    ):
        raise RuntimeError(f"passing native attestation has invalid {where} portable assurance")
    try:
        data = base64.b64decode(assurance["bytes_base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"passing native attestation has invalid {where} portable bytes"
        ) from exc
    if (
        base64.b64encode(data).decode("ascii") != assurance["bytes_base64"]
        or len(data) != expected["size"]
        or hashlib.sha256(data).hexdigest() != expected["sha256"]
    ):
        raise RuntimeError(
            f"passing native attestation does not bind {where} portable bytes to the manifest"
        )
    return data, assurance["profile"]


def _typed_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _typed_equal(left[name], right[name]) for name in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _typed_equal(left_item, right_item) for left_item, right_item in zip(left, right)
        )
    return left == right


def _validate_scheduled_task_artifact(
    item: object,
    expected: Mapping[str, object],
    resident_by_windows_path: Mapping[str, Mapping[str, object]],
) -> None:
    where = f"scheduled task {expected['path']!r}"
    if (
        type(item) is not dict
        or set(item)
        != {
            "native_parse",
            "path",
            "portable_assurance",
            "sha256",
            "size",
            "target",
            "verdict",
        }
        or item["path"] != expected["path"]
        or item["sha256"] != expected["sha256"]
        or item["size"] != expected["size"]
        or item["verdict"] != "pass"
    ):
        raise RuntimeError(f"passing native attestation does not bind {where}")
    data, reported_profile = _portable_assured_bytes(
        item["portable_assurance"],
        expected,
        where=where,
    )
    try:
        profile = parse_scheduled_task_xml(data)
        if profile.command not in resident_by_windows_path:
            raise RuntimeError(f"passing native attestation has invalid {where} PE join")
        profile = validate_scheduled_task_xml(
            data,
            resident_pe_paths=(profile.command,),
        )
    except ValueError as exc:
        raise RuntimeError(
            f"passing native attestation has invalid {where} strict byte profile"
        ) from exc
    if not _typed_equal(reported_profile, asdict(profile)):
        raise RuntimeError(f"passing native attestation has inconsistent {where} portable profile")
    target = resident_by_windows_path.get(profile.command)
    if target is None or not _typed_equal(item["target"], target):
        raise RuntimeError(f"passing native attestation has invalid {where} PE join")
    native = item["native_parse"]
    if type(native) is not dict or set(native) != {"observation", "result"}:
        raise RuntimeError(f"passing native attestation has invalid {where} native parse")
    _validate_task_native_result(
        native["result"],
        expected_sha256=expected["sha256"],
        expected_size=expected["size"],
    )
    _validate_powershell_observation(
        native["observation"],
        where,
        label=_TASK_OBSERVATION_LABEL,
        result=native["result"],
    )


def _validate_shell_link_artifact(
    item: object,
    expected: Mapping[str, object],
    resident_by_windows_path: Mapping[str, Mapping[str, object]],
) -> None:
    where = f"Shell Link {expected['path']!r}"
    if (
        type(item) is not dict
        or set(item)
        != {
            "native_parse",
            "path",
            "portable_assurance",
            "sha256",
            "size",
            "target",
            "verdict",
        }
        or item["path"] != expected["path"]
        or item["sha256"] != expected["sha256"]
        or item["size"] != expected["size"]
        or item["verdict"] != "pass"
    ):
        raise RuntimeError(f"passing native attestation does not bind {where}")
    data, reported_profile = _portable_assured_bytes(
        item["portable_assurance"],
        expected,
        where=where,
    )
    try:
        profile = parse_shell_link(data)
    except ValueError as exc:
        raise RuntimeError(
            f"passing native attestation has invalid {where} strict byte profile"
        ) from exc
    if not _typed_equal(reported_profile, asdict(profile)):
        raise RuntimeError(f"passing native attestation has inconsistent {where} portable profile")
    target = resident_by_windows_path.get(profile.target_path)
    if (
        target is None
        or not _typed_equal(item["target"], target)
        or profile.target_size != target["size"]
    ):
        raise RuntimeError(f"passing native attestation has invalid {where} PE join")
    native = item["native_parse"]
    if type(native) is not dict or set(native) != {"observation", "result"}:
        raise RuntimeError(f"passing native attestation has invalid {where} native parse")
    _validate_shell_link_native_result(
        native["result"],
        expected_sha256=expected["sha256"],
        expected_size=expected["size"],
        profile=profile,
    )
    _validate_powershell_observation(
        native["observation"],
        where,
        label=_SHELL_LINK_OBSERVATION_LABEL,
        result=native["result"],
    )


def _validate_prefetch_native_record(
    observation: object,
    *,
    output_capacity: int,
    expected_output_sha256: str | None,
    where: str,
) -> int:
    expected_fields = {
        "allocated_workspace_size",
        "api_sequence",
        "compress_workspace_size",
        "compression_format",
        "decompress_ntstatus",
        "final_uncompressed_size",
        "fragment_workspace_size",
        "output_sha256",
        "returned_output_size",
        "workspace_query_ntstatus",
    }
    if type(observation) is not dict or set(observation) != expected_fields:
        raise RuntimeError(f"passing native attestation has invalid {where} observation")
    compress_workspace = observation["compress_workspace_size"]
    fragment_workspace = observation["fragment_workspace_size"]
    allocated_workspace = observation["allocated_workspace_size"]
    final_size = observation["final_uncompressed_size"]
    returned_size = observation["returned_output_size"]
    if (
        observation["api_sequence"] != _PREFETCH_NATIVE_API_SEQUENCE
        or observation["compression_format"] != _COMPRESSION_FORMAT_XPRESS_HUFF
        or observation["workspace_query_ntstatus"] != "0x00000000"
        or type(compress_workspace) is not int
        or type(fragment_workspace) is not int
        or min(compress_workspace, fragment_workspace) < 0
        or type(allocated_workspace) is not int
        or allocated_workspace != max(compress_workspace, fragment_workspace)
        or not 1 <= allocated_workspace <= _MAX_PREFETCH_WORKSPACE_BYTES
        or type(final_size) is not int
        or not 0 <= final_size < 1 << 32
        or type(returned_size) is not int
        or not 0 <= returned_size <= output_capacity
        or type(observation["output_sha256"]) is not str
        or _HEX_64.fullmatch(observation["output_sha256"]) is None
        or type(observation["decompress_ntstatus"]) is not str
        or re.fullmatch(r"0x[0-9a-f]{8}", observation["decompress_ntstatus"]) is None
    ):
        raise RuntimeError(f"passing native attestation has inconsistent {where} observation")
    decompression_status = int(observation["decompress_ntstatus"], 16)
    if decompression_status == 0:
        if final_size > output_capacity or returned_size != final_size:
            raise RuntimeError(
                f"passing native attestation has inconsistent successful {where} output size"
            )
    elif returned_size != 0 or observation["output_sha256"] != hashlib.sha256(b"").hexdigest():
        raise RuntimeError(f"passing native attestation publishes failed {where} output bytes")
    if expected_output_sha256 is not None and (
        decompression_status != 0
        or final_size != output_capacity
        or returned_size != output_capacity
        or observation["output_sha256"] != expected_output_sha256
    ):
        raise RuntimeError(f"passing native attestation has non-exact {where} output")
    return decompression_status


def _prefetch_assured_bytes(item: Mapping[str, object], expected: Mapping[str, object]) -> bytes:
    assurance = item.get("portable_assurance")
    if (
        type(assurance) is not dict
        or set(assurance) != {"bytes_base64"}
        or type(assurance["bytes_base64"]) is not str
    ):
        raise RuntimeError("passing native attestation has invalid Prefetch portable assurance")
    try:
        data = base64.b64decode(assurance["bytes_base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "passing native attestation has invalid Prefetch portable bytes"
        ) from exc
    if (
        base64.b64encode(data).decode("ascii") != assurance["bytes_base64"]
        or len(data) != expected["size"]
        or hashlib.sha256(data).hexdigest() != expected["sha256"]
    ):
        raise RuntimeError("passing native attestation does not bind Prefetch portable bytes")
    return data


def _validate_prefetch_artifact(
    item: object,
    expected: Mapping[str, object],
    parsed: Mapping[str, object],
) -> None:
    where = f"Prefetch {expected['path']!r}"
    if (
        type(item) is not dict
        or set(item)
        != {
            "inner_header",
            "native_decompression",
            "path",
            "portable_assurance",
            "sha256",
            "size",
            "verdict",
            "wrapper",
        }
        or item["path"] != expected["path"]
        or item["sha256"] != expected["sha256"]
        or item["size"] != expected["size"]
        or item["verdict"] != "pass"
    ):
        raise RuntimeError(f"passing native attestation does not bind {where}")
    data = _prefetch_assured_bytes(item, expected)
    if data != parsed["data"]:
        raise RuntimeError(f"passing native attestation has inconsistent {where} bytes")
    expected_output = parsed["expected_output"]
    declared_size = parsed["declared_uncompressed_size"]
    payload = parsed["payload"]
    if (
        type(expected_output) is not bytes
        or type(declared_size) is not int
        or type(payload) is not bytes
    ):
        raise RuntimeError(f"passing native attestation has invalid {where} parse state")
    if item["wrapper"] != {
        "algorithm": _COMPRESSION_FORMAT_XPRESS_HUFF,
        "compressed_payload_size": len(payload),
        "declared_uncompressed_size": declared_size,
        "magic_hex": _MAM_XPRESS_HUFFMAN_MAGIC.hex(),
    }:
        raise RuntimeError(f"passing native attestation has invalid {where} wrapper")
    if item["inner_header"] != parsed["inner_header"]:
        raise RuntimeError(f"passing native attestation has invalid {where} inner header")
    _validate_prefetch_native_record(
        item["native_decompression"],
        output_capacity=declared_size,
        expected_output_sha256=hashlib.sha256(expected_output).hexdigest(),
        where=where,
    )


def _validate_prefetch_corruption_control(
    control: object,
    parsed: Mapping[str, object],
) -> None:
    if (
        type(control) is not dict
        or set(control)
        != {
            "artifact_path",
            "expected_output_sha256",
            "mutation",
            "native_decompression",
            "outcome",
            "verdict",
        }
        or control["verdict"] != "pass"
        or control["artifact_path"] != parsed["path"]
    ):
        raise RuntimeError("passing native attestation has invalid Prefetch corruption control")
    payload = parsed["payload"]
    expected_output = parsed["expected_output"]
    declared_size = parsed["declared_uncompressed_size"]
    if (
        type(payload) is not bytes
        or type(expected_output) is not bytes
        or type(declared_size) is not int
        or len(payload) <= _PREFETCH_CONTROL_TABLE_OFFSET
        or payload[_PREFETCH_CONTROL_TABLE_OFFSET] & 0x0F == 0
    ):
        raise RuntimeError("passing native attestation has invalid Prefetch control source")
    corrupted = bytearray(payload)
    corrupted[_PREFETCH_CONTROL_TABLE_OFFSET] &= 0xF0
    corrupted_payload = bytes(corrupted)
    expected_sha256 = hashlib.sha256(expected_output).hexdigest()
    expected_mutation = {
        "corrupted_payload_sha256": hashlib.sha256(corrupted_payload).hexdigest(),
        "mutated_byte_hex": f"{corrupted_payload[_PREFETCH_CONTROL_TABLE_OFFSET]:02x}",
        "operation": "clear-low-nibble-for-v30-version-literal",
        "original_byte_hex": f"{payload[_PREFETCH_CONTROL_TABLE_OFFSET]:02x}",
        "payload_offset": _PREFETCH_CONTROL_TABLE_OFFSET,
        "wrapper_offset": _MAM_HEADER_BYTES + _PREFETCH_CONTROL_TABLE_OFFSET,
    }
    if (
        control["mutation"] != expected_mutation
        or control["expected_output_sha256"] != expected_sha256
    ):
        raise RuntimeError("passing native attestation has unbound Prefetch control mutation")
    status = _validate_prefetch_native_record(
        control["native_decompression"],
        output_capacity=declared_size,
        expected_output_sha256=None,
        where="Prefetch corruption control",
    )
    native = control["native_decompression"]
    if status != 0:
        if control["outcome"] != "native-error":
            raise RuntimeError("passing native attestation misstates Prefetch control rejection")
    elif control["outcome"] != "nonmatching-exact-output" or (
        native["final_uncompressed_size"] == declared_size
        and native["returned_output_size"] == declared_size
        and native["output_sha256"] == expected_sha256
    ):
        raise RuntimeError("passing native attestation lacks a red Prefetch corruption control")


def _validate_artifact_evidence(report: dict, portable_record: dict) -> None:
    expected_files, logical_zones = _embedded_windows_expectations(portable_record)
    expected_pe_paths = sorted(path for path in expected_files if path.casefold().endswith(".exe"))
    expected_prefetch_paths = sorted(
        path for path in expected_files if path.casefold().endswith(".pf")
    )
    expected_task_paths = sorted(path for path in expected_files if _is_task_store_path(path))
    expected_shell_paths = sorted(
        path for path in expected_files if path.casefold().endswith(".lnk")
    )
    expected_zone_paths = sorted(logical_zones)
    if (
        len(expected_pe_paths) != EXPECTED_PE_FILES
        or len(expected_prefetch_paths) != EXPECTED_PREFETCH_FILES
        or len(expected_task_paths) != EXPECTED_SCHEDULED_TASK_XML
        or len(expected_shell_paths) != EXPECTED_SHELL_LINKS
    ):
        raise RuntimeError("passing native attestation embeds incomplete Task/LNK paths")
    resident_by_windows_path = {
        _served_windows_path(path): expected_files[path] for path in expected_pe_paths
    }
    artifacts = report["artifacts"]
    if [item["path"] for item in artifacts["pe"]] != expected_pe_paths:
        raise RuntimeError("passing native attestation PE paths disagree with the fixture")
    if [item["path"] for item in artifacts["prefetch"]] != expected_prefetch_paths:
        raise RuntimeError("passing native attestation Prefetch paths disagree with the fixture")
    if [item["path"] for item in artifacts["scheduled_task_xml"]] != expected_task_paths:
        raise RuntimeError(
            "passing native attestation scheduled-task paths disagree with the fixture"
        )
    if [item["path"] for item in artifacts["shell_link"]] != expected_shell_paths:
        raise RuntimeError("passing native attestation Shell Link paths disagree with the fixture")
    if [item["path"] for item in artifacts["zone_identifier"]] != expected_zone_paths:
        raise RuntimeError("passing native attestation stream paths disagree with the fixture")
    task_target = artifacts["scheduled_task_xml"][0].get("target")
    shell_target = artifacts["shell_link"][0].get("target")
    task_target_path = task_target.get("path") if type(task_target) is dict else None
    shell_target_path = shell_target.get("path") if type(shell_target) is dict else None
    if (
        task_target_path == shell_target_path
        or task_target_path in expected_zone_paths
        or shell_target_path in expected_zone_paths
    ):
        raise RuntimeError(
            "passing native attestation does not keep Task/Shell Link targets distinct "
            "from each other and the downloaded PE"
        )
    _validate_scheduled_task_artifact(
        artifacts["scheduled_task_xml"][0],
        expected_files[expected_task_paths[0]],
        resident_by_windows_path,
    )
    _validate_shell_link_artifact(
        artifacts["shell_link"][0],
        expected_files[expected_shell_paths[0]],
        resident_by_windows_path,
    )
    assured_prefetch = {
        path: _prefetch_assured_bytes(item, expected_files[path])
        for path, item in zip(expected_prefetch_paths, artifacts["prefetch"])
    }
    parsed_prefetch = _prefetch_artifacts(assured_prefetch)
    for item, parsed in zip(artifacts["prefetch"], parsed_prefetch):
        _validate_prefetch_artifact(item, expected_files[parsed["path"]], parsed)
    _validate_prefetch_corruption_control(
        report["prefetch_positive_control"],
        parsed_prefetch[0],
    )
    for pe in artifacts["pe"]:
        expected = expected_files[pe["path"]]
        if (
            set(pe)
            != {
                "byte_profile",
                "dumpbin_headers",
                "get_file_hash",
                "path",
                "sha256",
                "signature",
                "size",
                "verdict",
            }
            or pe["sha256"] != expected["sha256"]
            or pe["size"] != expected["size"]
        ):
            raise RuntimeError(f"passing native attestation does not bind PE {pe['path']!r}")
        _validate_pe_byte_profile(pe["byte_profile"], expected["size"], pe["path"])
        _validate_dumpbin_evidence(pe["dumpbin_headers"], pe["path"])
        _validate_native_hash_evidence(pe["get_file_hash"], expected["sha256"], pe["path"])
        _validate_unsigned_signature_evidence(pe["signature"], pe["path"])
    for zone in artifacts["zone_identifier"]:
        path = zone["path"]
        expected = expected_files[path]
        logical = logical_zones[path]
        if set(zone) != {
            "authenticode_postcondition",
            "default_stream_postcondition",
            "get_file_hash_postcondition",
            "logical_stream",
            "path",
            "private_projection",
            "readback",
            "verdict",
        } or zone["logical_stream"] != {
            "sha256": hashlib.sha256(logical).hexdigest(),
            "size": len(logical),
        }:
            raise RuntimeError(f"passing native attestation does not bind stream {path!r}")
        default = zone["default_stream_postcondition"]
        if (
            type(default) is not dict
            or set(default)
            != {
                "filesystem_identity",
                "native_sha256",
                "path",
                "resolved_path",
                "sha256",
                "size",
                "unchanged",
            }
            or default.get("sha256") != expected["sha256"]
            or default.get("native_sha256") != expected["sha256"]
            or default.get("size") != expected["size"]
            or default.get("unchanged") is not True
        ):
            raise RuntimeError(f"passing native attestation does not bind {path!r} default stream")
        _validate_native_hash_evidence(
            zone["get_file_hash_postcondition"], expected["sha256"], path
        )
        _validate_unsigned_signature_evidence(zone["authenticode_postcondition"], path)
        readback = zone["readback"]
        if (
            type(readback) is not dict
            or set(readback) != {"observation", "result"}
            or readback["result"]
            != {
                "Base64": base64.b64encode(logical).decode(),
                "Length": len(logical),
            }
        ):
            raise RuntimeError(f"passing native attestation has invalid {path!r} ADS readback")
        _validate_powershell_observation(
            readback["observation"],
            f"{path} ADS readback",
            label="Get-Content-LiteralPath-Zone-Identifier-AsByteStream-Raw",
            result=readback["result"],
        )
        projection = zone["private_projection"]
        if (
            type(projection) is not dict
            or set(projection) != {"after", "before", "materialized", "removed"}
            or projection["materialized"] is not True
            or projection["removed"] is not True
        ):
            raise RuntimeError(f"passing native attestation has invalid {path!r} ADS projection")
        for moment in ("before", "after"):
            state = projection[moment]
            if type(state) is not dict or set(state) != {"exists", "observation"}:
                raise RuntimeError(f"passing native attestation has invalid {path!r} ADS state")
            if state["exists"] is not False:
                raise RuntimeError(f"passing native attestation left an ADS on {path!r}")
            _validate_powershell_observation(
                state["observation"],
                f"{path} ADS {moment}",
                label="Get-Item-LiteralPath-Zone-Identifier-existence",
                result={"Exists": state["exists"]},
            )


def _validate_native_report(report: object) -> None:
    """Fail closed on contradictions before a native report can be published."""
    if type(report) is not dict:
        raise RuntimeError("native attestation report must be an object")
    if (
        report.get("canonicalization") != CANONICALIZATION
        or report.get("schema") != SCHEMA_ID
        or report.get("schema_version") != 4
        or report.get("verdict") not in {"pass", "fail"}
        or type(report.get("failures")) is not list
        or not all(type(item) is str and item for item in report["failures"])
        or _UTC_SECONDS.fullmatch(str(report.get("generated_at_utc", ""))) is None
    ):
        raise RuntimeError("native attestation report has an invalid envelope")
    _validate_utc_timestamp(report["generated_at_utc"], "native attestation report")
    if report["verdict"] == "fail":
        if not report["failures"]:
            raise RuntimeError("failing native attestation report has no failure evidence")
        return
    if report["failures"]:
        raise RuntimeError("passing native attestation report contains failures")
    if set(report) != {
        "artifact_counts",
        "artifacts",
        "canonicalization",
        "claim_scope",
        "failures",
        "fixture",
        "generated_at_utc",
        "github_actions",
        "host",
        "portable_prerequisite",
        "prefetch_positive_control",
        "positive_control",
        "private_scene",
        "producer",
        "schema",
        "schema_version",
        "tools",
        "verdict",
    }:
        raise RuntimeError("passing native attestation report has an unexpected shape")
    claim_scope = report.get("claim_scope")
    if (
        type(claim_scope) is not dict
        or set(claim_scope)
        != {
            "activation_scope",
            "ads_scope",
            "cross_host_boundary",
            "emitted_pe_execution",
            "native_observations",
            "portable_assurance_is_prerequisite",
            "prefetch_scope",
        }
        or claim_scope["activation_scope"] != _ACTIVATION_SCOPE
        or claim_scope["emitted_pe_execution"] is not False
        or claim_scope["portable_assurance_is_prerequisite"] is not True
        or claim_scope["prefetch_scope"] != _PREFETCH_SCOPE
        or any(
            type(claim_scope[name]) is not str or not claim_scope[name]
            for name in (
                "activation_scope",
                "ads_scope",
                "cross_host_boundary",
                "native_observations",
                "prefetch_scope",
            )
        )
    ):
        raise RuntimeError("passing native attestation report has an invalid claim scope")
    if report.get("artifact_counts") != {
        "default_stream_files": EXPECTED_TOTAL_FILES,
        "prefetch": EXPECTED_PREFETCH_FILES,
        "scheduled_task_xml": EXPECTED_SCHEDULED_TASK_XML,
        "shell_link": EXPECTED_SHELL_LINKS,
        "synthetic_pe": EXPECTED_PE_FILES,
        "zone_identifier": EXPECTED_ZONE_STREAMS,
    }:
        raise RuntimeError("passing native attestation report has incomplete artifact counts")
    artifacts = report.get("artifacts")
    if (
        type(artifacts) is not dict
        or set(artifacts)
        != {"pe", "prefetch", "scheduled_task_xml", "shell_link", "zone_identifier"}
        or type(artifacts["pe"]) is not list
        or type(artifacts["prefetch"]) is not list
        or type(artifacts["scheduled_task_xml"]) is not list
        or type(artifacts["shell_link"]) is not list
        or type(artifacts["zone_identifier"]) is not list
        or len(artifacts["pe"]) != EXPECTED_PE_FILES
        or len(artifacts["prefetch"]) != EXPECTED_PREFETCH_FILES
        or len(artifacts["scheduled_task_xml"]) != EXPECTED_SCHEDULED_TASK_XML
        or len(artifacts["shell_link"]) != EXPECTED_SHELL_LINKS
        or len(artifacts["zone_identifier"]) != EXPECTED_ZONE_STREAMS
        or any(type(item) is not dict or item.get("verdict") != "pass" for item in artifacts["pe"])
        or any(
            type(item) is not dict or item.get("verdict") != "pass"
            for item in artifacts["prefetch"]
        )
        or any(
            type(item) is not dict or item.get("verdict") != "pass"
            for item in artifacts["scheduled_task_xml"]
        )
        or any(
            type(item) is not dict or item.get("verdict") != "pass"
            for item in artifacts["shell_link"]
        )
        or any(
            type(item) is not dict or item.get("verdict") != "pass"
            for item in artifacts["zone_identifier"]
        )
    ):
        raise RuntimeError("passing native attestation report has invalid artifact evidence")
    pe_paths = [item.get("path") for item in artifacts["pe"]]
    prefetch_paths = [item.get("path") for item in artifacts["prefetch"]]
    task_paths = [item.get("path") for item in artifacts["scheduled_task_xml"]]
    shell_paths = [item.get("path") for item in artifacts["shell_link"]]
    zone_paths = [item.get("path") for item in artifacts["zone_identifier"]]
    if (
        any(
            type(path) is not str or not path
            for path in pe_paths + prefetch_paths + task_paths + shell_paths + zone_paths
        )
        or pe_paths != sorted(pe_paths)
        or prefetch_paths != sorted(prefetch_paths)
        or task_paths != sorted(task_paths)
        or shell_paths != sorted(shell_paths)
        or zone_paths != sorted(zone_paths)
        or not set(zone_paths) < set(pe_paths)
        or any(not path.casefold().endswith(".pf") for path in prefetch_paths)
        or any(not _is_task_store_path(path) for path in task_paths)
        or any(not path.casefold().endswith(".lnk") for path in shell_paths)
        or len(set(pe_paths)) != EXPECTED_PE_FILES
        or len(set(prefetch_paths)) != EXPECTED_PREFETCH_FILES
        or len(set(task_paths)) != EXPECTED_SCHEDULED_TASK_XML
        or len(set(shell_paths)) != EXPECTED_SHELL_LINKS
        or len(set(zone_paths)) != EXPECTED_ZONE_STREAMS
    ):
        raise RuntimeError("passing native attestation report has inconsistent artifact paths")
    checks = (
        (report.get("fixture", {}).get("post_observation"), "fixture"),
        (report.get("private_scene", {}).get("post_observation"), "private scene"),
        (
            report.get("portable_prerequisite", {}).get("post_observation"),
            "portable prerequisite",
        ),
        (report.get("producer", {}).get("source_post_observation"), "source"),
        (report.get("tools", {}).get("post_observation"), "native tools"),
        (
            report.get("positive_control", {}).get("post_observation"),
            "Authenticode positive control",
        ),
    )
    if any(type(value) is not dict or value.get("unchanged") is not True for value, _ in checks):
        failed = ", ".join(
            name
            for value, name in checks
            if type(value) is not dict or value.get("unchanged") is not True
        )
        raise RuntimeError(
            f"passing native attestation report has a failed postcondition: {failed}"
        )
    if report.get("positive_control", {}).get("verdict") != "pass":
        raise RuntimeError("passing native attestation report lacks its positive control")
    if report.get("prefetch_positive_control", {}).get("verdict") != "pass":
        raise RuntimeError("passing native attestation report lacks its Prefetch positive control")
    producer = report.get("producer", {})
    source = producer.get("source")
    source_post = producer.get("source_post_observation")
    prerequisite = report.get("portable_prerequisite", {})
    portable_record = prerequisite.get("record")
    _validate_source_identity(source, "native attestation report")
    if (
        producer.get("name") != "ArtifactForge"
        or type(source) is not dict
        or type(source_post) is not dict
        or {name: value for name, value in source_post.items() if name != "unchanged"} != source
        or type(portable_record) is not dict
        or portable_record.get("schema") != PORTABLE_SCHEMA_ID
        or portable_record.get("schema_version") != 1
        or portable_record.get("verdict") != "pass"
        or portable_record.get("failures") != []
        or portable_record.get("producer", {}).get("source") != source
    ):
        raise RuntimeError("passing native attestation report does not bind source post-state")
    _validate_utc_timestamp(
        portable_record.get("generated_at_utc"),
        "embedded portable prerequisite",
    )
    _validate_github_identity(
        portable_record.get("github_actions"),
        source,
        "embedded portable prerequisite",
    )
    _validate_github_identity(
        report.get("github_actions"),
        source,
        "native attestation report",
    )
    _require_related_github_runs(
        portable_record.get("github_actions"),
        report.get("github_actions"),
    )
    local_initial = prerequisite.get("local_initial")
    prerequisite_identity = prerequisite.get("identity")
    prerequisite_post = prerequisite.get("post_observation")
    portable_bytes = _canonical_json_bytes(portable_record)
    if (
        type(local_initial) is not dict
        or type(prerequisite_identity) is not dict
        or type(prerequisite_post) is not dict
        or prerequisite_identity.get("sha256") != hashlib.sha256(portable_bytes).hexdigest()
        or prerequisite_identity.get("size") != len(portable_bytes)
        or any(
            prerequisite_identity.get(field) != local_initial.get(field)
            for field in ("sha256", "size")
        )
        or any(
            prerequisite_post.get(field) != local_initial.get(field)
            for field in ("filesystem_identity", "resolved_path", "sha256", "size")
        )
    ):
        raise RuntimeError(
            "passing native attestation report does not bind prerequisite post-state"
        )
    fixture = report.get("fixture", {})
    portable_fixture = portable_record.get("fixture", {})
    fixture_post = fixture.get("post_observation")
    if (
        fixture.get("carrier") != portable_fixture.get("carrier")
        or fixture.get("manifest_file") != portable_fixture.get("manifest_file")
        or type(fixture.get("filesystem_identity")) is not dict
        or type(fixture_post) is not dict
        or fixture_post.get("manifest_file", {}).get("sha256")
        != fixture.get("manifest_file", {}).get("sha256")
        or fixture_post.get("manifest_file", {}).get("size")
        != fixture.get("manifest_file", {}).get("size")
        or {
            name: value
            for name, value in fixture_post.get("filesystem_identity", {}).items()
            if name != "unchanged"
        }
        != fixture.get("filesystem_identity")
        or any(
            fixture_post.get("scene", {}).get(name) != fixture.get("carrier", {}).get(name)
            for name in ("directory_count", "file_count", "total_bytes", "tree_sha256")
        )
    ):
        raise RuntimeError("passing native attestation report does not bind fixture post-state")
    private_scene = report.get("private_scene", {})
    private_initial = private_scene.get("initial")
    private_post = private_scene.get("post_observation")
    if (
        private_initial != fixture.get("carrier")
        or type(private_post) is not dict
        or {name: value for name, value in private_post.items() if name != "unchanged"}
        != private_initial
    ):
        raise RuntimeError("passing native attestation report does not bind private-scene state")
    _validate_artifact_evidence(report, portable_record)
    host = report.get("host")
    if type(host) is not dict or host.get("identity_sha256") != _canonical_digest(
        {name: value for name, value in host.items() if name != "identity_sha256"}
    ):
        raise RuntimeError("passing native attestation report has invalid host evidence")
    tool_record = report.get("tools", {})
    tool_initial = tool_record.get("initial")
    tool_post = tool_record.get("post_observation", {}).get("tools")
    if type(tool_initial) is not dict or type(tool_post) is not dict:
        raise RuntimeError("passing native attestation report has invalid tool evidence")
    for name in ("dumpbin", "powershell", "vswhere"):
        initial = tool_initial.get(name)
        final = tool_post.get(name)
        if (
            type(initial) is not dict
            or type(final) is not dict
            or any(
                final.get(field) != initial.get(field)
                for field in ("filesystem_identity", "resolved_path", "sha256", "size")
            )
        ):
            raise RuntimeError(f"passing native attestation report does not bind {name}")
        authenticode = initial.get("authenticode")
        if type(authenticode) is not dict:
            raise RuntimeError(f"passing native attestation report omits {name} authenticity")
        _validate_signed_signature_evidence(
            authenticode,
            f"reported native tool {name}",
            independent_trust=initial.get("winverifytrust"),
        )
    positive = report.get("positive_control")
    if type(positive) is not dict:
        raise RuntimeError("passing native attestation has invalid positive-control evidence")
    selected = positive.get("selected")
    if (
        set(positive) != {"attempts", "hash", "post_observation", "selected", "verdict"}
        or type(positive["attempts"]) is not list
        or type(selected) is not dict
        or set(selected) != {"identity", "label", "observation", "signature", "winverifytrust"}
        or selected not in positive["attempts"]
        or selected["label"] not in {"WindowsPowerShell", "notepad", "kernel32", "cmd"}
    ):
        raise RuntimeError("passing native attestation has invalid positive-control evidence")
    selected_identity = selected.get("identity")
    positive_post = positive.get("post_observation")
    if (
        type(selected_identity) is not dict
        or type(positive_post) is not dict
        or any(
            positive_post.get(field) != selected_identity.get(field)
            for field in ("filesystem_identity", "resolved_path", "sha256", "size")
        )
    ):
        raise RuntimeError(
            "passing native attestation report does not bind positive-control post-state"
        )
    _validate_signed_signature_evidence(
        {"observation": selected["observation"], "result": selected["signature"]},
        "reported Authenticode positive control",
        independent_trust=selected["winverifytrust"],
        require_os_binary=True,
    )
    _validate_native_hash_evidence(
        positive["hash"],
        selected_identity["sha256"],
        "reported Authenticode positive control",
    )
    encoded = _canonical_json_bytes(report)
    parsed = json.loads(encoded, object_pairs_hook=_strict_object_pairs)
    if parsed != report:
        raise RuntimeError("native attestation report does not round-trip canonically")


def _validated_report_bytes(report: object) -> bytes:
    if type(report) is dict and report.get("schema") == SCHEMA_ID:
        _validate_native_report(report)
    return _canonical_json_bytes(report)


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _write_new_output(
    output: Path,
    data: bytes,
    *,
    forbidden_roots: tuple[Path, ...],
) -> Path:
    """Exclusively create one bounded output and recheck its parent and file identity."""
    if len(data) > MAX_RECORD_BYTES:
        raise RuntimeError("attestation output exceeds the record limit")
    if not output.name or output.name in {".", ".."}:
        raise RuntimeError("--out must name a new regular file")
    if ":" in output.name:
        raise RuntimeError("--out must not address a Windows alternate data stream")
    parent = output.parent.resolve(strict=True)
    parent_before = parent.lstat()
    if _is_linklike(parent, parent_before) or not stat.S_ISDIR(parent_before.st_mode):
        raise RuntimeError("--out parent must be a real directory")
    destination = parent / output.name
    for root in forbidden_roots:
        resolved_root = root.resolve(strict=True)
        if _inside(destination, resolved_root):
            raise RuntimeError("--out resolved inside a protected fixture or source root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = -1
    created = False
    opened_identity = None
    try:
        descriptor = os.open(destination, flags, 0o600)
        created = True
        opened = os.fstat(descriptor)
        opened_identity = (opened.st_dev, opened.st_ino)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("--out did not create a regular file")
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise RuntimeError("short write while creating --out")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        entry = destination.lstat()
        parent_after = parent.lstat()
        if (
            _is_linklike(destination, entry)
            or not stat.S_ISREG(entry.st_mode)
            or (entry.st_dev, entry.st_ino) != opened_identity
            or entry.st_size != len(data)
            or any(
                getattr(parent_before, field) != getattr(parent_after, field)
                for field in ("st_dev", "st_ino")
            )
        ):
            raise RuntimeError("--out or its parent changed while writing")
        if (
            _read_regular(
                destination,
                where="published attestation output",
                maximum=MAX_RECORD_BYTES,
                expected_state=entry,
            )
            != data
        ):
            raise RuntimeError("published attestation output bytes disagree after fsync")
        parent_final = parent.lstat()
        if any(
            getattr(parent_before, field) != getattr(parent_final, field)
            for field in ("st_dev", "st_ino")
        ):
            raise RuntimeError("--out parent changed during read-back verification")
        return destination
    except Exception:
        if created:
            try:
                entry = destination.lstat()
                if (entry.st_dev, entry.st_ino) == opened_identity:
                    destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="stage", required=True)
    for stage in ("prepare", "observe"):
        command = subparsers.add_parser(stage)
        command.add_argument("--fixture", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        if stage == "observe":
            command.add_argument("--prerequisite", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(os.path.abspath(args.fixture))
    output = Path(os.path.abspath(args.out))
    fixture_root = fixture.resolve(strict=False)
    source_root = _REPOSITORY_ROOT.resolve(strict=True)
    output_candidate = output.parent.resolve(strict=False) / output.name
    if _inside(output_candidate, fixture_root) or _inside(output_candidate, source_root):
        print(
            "FAIL: --out must be outside --fixture and the source repository",
            file=sys.stderr,
        )
        return 2
    prerequisite = None
    try:
        if args.stage == "prepare":
            report = prepare(fixture)
            schema_version = 1
            schema = PORTABLE_SCHEMA_ID
        else:
            prerequisite = Path(os.path.abspath(args.prerequisite))
            report = attest(fixture, prerequisite)
            schema_version = 4
            schema = SCHEMA_ID
    except Exception as exc:  # noqa: BLE001 - emit a canonical machine-readable failure
        report = {
            "canonicalization": CANONICALIZATION,
            "failures": [str(exc)],
            "generated_at_utc": _timestamp(),
            "schema": schema
            if "schema" in locals()
            else (PORTABLE_SCHEMA_ID if args.stage == "prepare" else SCHEMA_ID),
            "schema_version": schema_version
            if "schema_version" in locals()
            else (1 if args.stage == "prepare" else 4),
            "verdict": "fail",
        }
    try:
        written = _write_new_output(
            output,
            _validated_report_bytes(report),
            forbidden_roots=(fixture_root, source_root),
        )
    except Exception as exc:  # noqa: BLE001 - output safety failure is a usage failure
        print(f"FAIL: cannot safely write --out: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {written}: {report['verdict']}")
    for failure in report.get("failures", []):
        print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
