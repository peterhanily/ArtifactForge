# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Create and verify bounded local release-rehearsal evidence.

This module deliberately does not sign, upload, or publish anything.  It binds two separately
supplied, inode-distinct distribution copies, normalized CycloneDX documents, and exact source/build
materials into one canonical local record.  A protected external builder can subsequently attest
the byte-identical subjects; this local record is not a substitute for that signature.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import csv
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import uuid
import zipfile
import zlib
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath
from typing import Any

from artifactforge import __version__
from artifactforge.inventory import (
    InventoryError,
    canonical_relative_paths,
    inventory_regular_files,
    rename_directory_no_replace,
    validate_relative_path,
)


SCHEMA = "artifactforge-local-release-evidence-v1"
SCHEMA_VERSION = 1
CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"
CYCLONEDX_SPEC_VERSION = "1.5"
EXPECTED_UV_VERSION = "0.11.17"
EXPECTED_WHEEL_GENERATOR = "hatchling 1.31.0"
EXPECTED_DESCRIPTION = (
    "Deterministic, parser-gated synthetic forensic artifacts with byte-derived identity."
)
EXPECTED_WHEEL_METADATA = (
    b"Wheel-Version: 1.0\nGenerator: hatchling 1.31.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
)
EXPECTED_ARCHIVE_EPOCH = 1_580_601_600
EXPECTED_ZIP_DATETIME = (2020, 2, 2, 0, 0, 0)
EXPECTED_ZIP_DOS_TIME = 0
EXPECTED_ZIP_DOS_DATE = 20_546
EXPECTED_ARCHIVE_TIMESTAMP = "2020-02-02T00:00:00Z"
EXPECTED_DEV_REQUIREMENTS = (
    "dissect-target==3.25.1",
    "jsonschema>=4.23,<5",
    "libregf-python",
    "libscca-python==20260527",
    "lief",
    "macholib",
    "pefile",
    "pyelftools==0.33",
    "pytest>=8",
    "PyXDG==0.28",
    "regipy",
    "ruff>=0.6,<0.16",
    "windowsprefetch",
    "yara-python",
)
EXPECTED_METADATA_REQUIREMENTS = (
    "dissect-target==3.25.1",
    "jsonschema<5,>=4.23",
    "libregf-python",
    "libscca-python==20260527",
    "lief",
    "macholib",
    "pefile",
    "pyelftools==0.33",
    "pytest>=8",
    "pyxdg==0.28",
    "regipy",
    "ruff<0.16,>=0.6",
    "windowsprefetch",
    "yara-python",
)
MAX_DISTRIBUTION_BYTES = 32 * 1024 * 1024
MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_LOCK_BYTES = 8 * 1024 * 1024
MAX_UV_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SIMPLE_REQUIREMENT_RE = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<specifiers>.*)")
_SIMPLE_SPECIFIER_RE = re.compile(r"(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9][A-Za-z0-9._*+!-]*")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LIMITATIONS = (
    "local evidence does not authenticate its producer or build host",
    "GitHub/Sigstore attestation requires a separate protected hosted run",
    "development-oracle inventory is not a runtime dependency claim",
    "verification without a repository root checks the closed bundle but cannot refresh its source or SBOM exports",
    "offline uv export does not prove host-wide network inactivity",
    "this command performs no signing or package-publishing operation",
)
CLASSIFICATION = {
    "evidence_kind": "local-self-attestation",
    "external_authentication": False,
    "package_publishing_performed_by_command": False,
    "reportable_security_result": False,
    "signing_performed_by_command": False,
}


class ReleaseEvidenceError(ValueError):
    """Release evidence is unsafe, malformed, or inconsistent."""


@dataclass(frozen=True)
class _DistributionInput:
    """Bytes and inode identities captured through one held directory descriptor."""

    files: dict[str, bytes]
    root_identity: tuple[int, int]
    file_identities: dict[str, tuple[int, int]]


@dataclass(frozen=True)
class _UvExecutableSnapshot:
    original_path: Path
    original_observation: tuple[int, int, int, int, int, int]
    private_path: Path
    private_observation: tuple[int, int, int, int, int, int]
    payload_sha256: str


def _canonical_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise ReleaseEvidenceError(f"value is not strict JSON: {exc}") from exc
    try:
        return (rendered + "\n").encode("utf-8")
    except UnicodeError as exc:
        raise ReleaseEvidenceError(
            "value contains text outside strict Unicode scalar values"
        ) from exc


def _reject_constant(value: str) -> None:
    raise ReleaseEvidenceError(f"non-finite JSON number is forbidden: {value}")


def _bounded_json_integer(value: str) -> int:
    if len(value) > 20:
        raise ReleaseEvidenceError("JSON integer exceeds the signed 64-bit profile")
    parsed = int(value)
    if not -(1 << 63) <= parsed < (1 << 63):
        raise ReleaseEvidenceError("JSON integer exceeds the signed 64-bit profile")
    return parsed


def _reject_json_float(value: str) -> None:
    raise ReleaseEvidenceError(f"JSON floating-point values are forbidden: {value[:32]}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseEvidenceError(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def _bounded_json_nodes(value: Any) -> None:
    count = 0
    stack = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        count += 1
        if count > MAX_JSON_NODES:
            raise ReleaseEvidenceError("JSON node limit exceeded")
        if depth > MAX_JSON_DEPTH:
            raise ReleaseEvidenceError("JSON nesting limit exceeded")
        if isinstance(current, dict):
            for key in current:
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    raise ReleaseEvidenceError("JSON object key contains a lone surrogate")
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in current
        ):
            raise ReleaseEvidenceError("JSON string contains a lone surrogate")


def _strict_json(payload: bytes, *, label: str, maximum: int) -> Any:
    if len(payload) > maximum:
        raise ReleaseEvidenceError(f"{label} exceeds {maximum} bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_int=_bounded_json_integer,
            parse_float=_reject_json_float,
        )
    except ReleaseEvidenceError:
        raise
    except (RecursionError, ValueError, json.JSONDecodeError) as exc:
        raise ReleaseEvidenceError(f"{label} is not strict JSON: {exc}") from exc
    try:
        _bounded_json_nodes(value)
    except RecursionError as exc:
        raise ReleaseEvidenceError(f"{label} exceeds the JSON nesting limit") from exc
    return value


def _stat_observation(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_regular_observed(
    path: str | os.PathLike[str],
    *,
    maximum: int,
    label: str,
    dir_fd: int | None = None,
    display_path: Path | None = None,
) -> tuple[bytes, tuple[int, int]]:
    # O_NONBLOCK is inert for regular files and prevents a regular-to-FIFO path race from
    # hanging before the descriptor type can be checked with fstat().
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    shown = display_path if display_path is not None else Path(path)
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except (NotImplementedError, OSError) as exc:
        raise ReleaseEvidenceError(f"cannot open {label} safely: {shown}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseEvidenceError(f"{label} is not a regular file: {shown}")
        if before.st_size > maximum:
            raise ReleaseEvidenceError(f"{label} exceeds {maximum} bytes: {shown}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ReleaseEvidenceError(f"{label} exceeds {maximum} bytes: {shown}")
        after = os.fstat(fd)
        identity_before = _stat_observation(before)
        identity_after = _stat_observation(after)
        if identity_before != identity_after or total != after.st_size:
            raise ReleaseEvidenceError(f"{label} changed while it was read: {shown}")
        return b"".join(chunks), (after.st_dev, after.st_ino)
    finally:
        os.close(fd)


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    payload, _identity = _read_regular_observed(path, maximum=maximum, label=label)
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_field(payload: bytes) -> str:
    return "sha256:" + _sha256(payload)


def _expect_keys(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(f"{where} must be an object")
    actual = set(value)
    if actual != keys:
        raise ReleaseEvidenceError(
            f"{where} members differ: missing={sorted(keys - actual)}, "
            f"unexpected={sorted(actual - keys)}"
        )
    return value


def _expect_string(value: Any, where: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReleaseEvidenceError(f"{where} must be a non-empty string <= {maximum} chars")
    return value


def _expect_sha256(value: Any, where: str) -> str:
    text = _expect_string(value, where, maximum=71)
    if not text.startswith("sha256:") or not _SHA256_RE.fullmatch(text[7:]):
        raise ReleaseEvidenceError(f"{where} must be labelled lowercase SHA-256")
    return text


def _safe_relative_name(name: str, where: str) -> PurePosixPath:
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in name)
    ):
        raise ReleaseEvidenceError(f"unsafe {where}: {name!r}")
    pure = PurePosixPath(name)
    if (
        pure.is_absolute()
        or pure.as_posix() != name
        or any(part in ("", ".", "..") for part in pure.parts)
    ):
        raise ReleaseEvidenceError(f"unsafe {where}: {name!r}")
    if pure.parts[0].endswith(":"):
        raise ReleaseEvidenceError(f"unsafe {where}: {name!r}")
    try:
        validate_relative_path(name)
    except InventoryError as exc:
        raise ReleaseEvidenceError(f"unsafe {where}: {name!r}") from exc
    return pure


def _kill_bounded_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - exercised by the hosted Windows lane
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _run_bounded_process_posix(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    """Use nonblocking descriptors so hostile descendants cannot strand reader threads."""
    deadline = time.monotonic() + timeout
    selector: selectors.BaseSelector | None = None
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        bufsize=0,
        start_new_session=True,
    )
    try:
        streams = (process.stdout, process.stderr)
        selector = selectors.DefaultSelector()
        captures = [bytearray(), bytearray()]
        exceeded: list[str] = []
        timed_out = False
        if any(stream is None for stream in streams):  # pragma: no cover - Popen contract
            raise ReleaseEvidenceError(f"cannot capture {label} output")
        for index, (stream, limit, stream_name) in enumerate(
            zip(streams, (stdout_limit, stderr_limit), ("stdout", "stderr"), strict=True)
        ):
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (index, limit, stream_name))

        while True:
            if exceeded:
                break
            if process.poll() is not None and not selector.get_map():
                break
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                timed_out = True
                break
            if not selector.get_map():
                try:
                    process.wait(timeout=remaining_time)
                except subprocess.TimeoutExpired:
                    timed_out = True
                continue
            events = selector.select(remaining_time)
            if not events:
                timed_out = True
                break
            for key, _mask in events:
                stream = key.fileobj
                index, limit, stream_name = key.data
                remaining_capture = limit + 1 - len(captures[index])
                try:
                    chunk = os.read(stream.fileno(), min(64 * 1024, max(remaining_capture, 1)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                captures[index].extend(chunk)
                if len(captures[index]) > limit:
                    exceeded.append(stream_name)

        if timed_out or exceeded:
            _kill_bounded_process(process)
        if process.poll() is None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_bounded_process(process)
        if timed_out:
            raise subprocess.TimeoutExpired(command, timeout)
        if exceeded:
            joined = " and ".join(sorted(set(exceeded)))
            raise ReleaseEvidenceError(f"{label} {joined} exceeded its bounded capture limit")
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout=bytes(captures[0]),
            stderr=bytes(captures[1]),
        )
    finally:
        if process.poll() is None:
            _kill_bounded_process(process)
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if selector is not None:
            selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _run_bounded_process_threaded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    """Portable pipe fallback for platforms whose selectors cannot observe process pipes."""
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        bufsize=0,
    )
    captures = [bytearray(), bytearray()]
    exceeded: list[str] = []
    reader_errors: list[OSError] = []
    changed = threading.Event()
    readers: list[threading.Thread] = []

    def consume(stream, index: int, limit: int, stream_name: str) -> None:
        try:
            while True:
                remaining = limit + 1 - len(captures[index])
                chunk = os.read(stream.fileno(), min(64 * 1024, max(remaining, 1)))
                if not chunk:
                    return
                captures[index].extend(chunk)
                if len(captures[index]) > limit:
                    exceeded.append(stream_name)
                    return
        except OSError as exc:
            reader_errors.append(exc)
        finally:
            changed.set()

    timed_out = False
    try:
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
            raise ReleaseEvidenceError(f"cannot capture {label} output")
        for index, (stream, limit, stream_name) in enumerate(
            zip(
                (process.stdout, process.stderr),
                (stdout_limit, stderr_limit),
                ("stdout", "stderr"),
                strict=True,
            )
        ):
            reader = threading.Thread(
                target=consume,
                args=(stream, index, limit, stream_name),
                daemon=True,
            )
            reader.start()
            readers.append(reader)
        while process.poll() is None and not exceeded and not reader_errors:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                timed_out = True
                break
            changed.wait(min(remaining_time, 0.05))
            changed.clear()
        if exceeded or reader_errors or timed_out:
            _kill_bounded_process(process)
        cleanup_deadline = min(deadline, time.monotonic() + 1)
        for reader in readers:
            reader.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            timed_out = True
        if timed_out:
            raise subprocess.TimeoutExpired(command, timeout)
        if reader_errors:
            raise OSError(f"cannot read {label} output") from reader_errors[0]
        if exceeded:
            joined = " and ".join(sorted(set(exceeded)))
            raise ReleaseEvidenceError(f"{label} {joined} exceeded its bounded capture limit")
        return subprocess.CompletedProcess(
            command,
            process.wait(timeout=max(0.0, deadline - time.monotonic())),
            stdout=bytes(captures[0]),
            stderr=bytes(captures[1]),
        )
    finally:
        if process.poll() is None:
            _kill_bounded_process(process)
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    """Capture child output under byte and wall-clock limits."""
    if stdout_limit < 0 or stderr_limit < 0 or timeout <= 0:
        raise ReleaseEvidenceError(
            "subprocess output limits must be non-negative and timeout must be positive"
        )
    runner = _run_bounded_process_posix if os.name == "posix" else _run_bounded_process_threaded
    return runner(
        command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        label=label,
    )


def _run_git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    candidate = shutil.which("git", path=os.defpath)
    if candidate is None:
        raise ReleaseEvidenceError("cannot locate Git for source inspection")
    executable = Path(candidate).resolve()
    try:
        before = executable.stat()
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseEvidenceError("Git executable is not a regular file")
        command = [
            str(executable),
            "--no-pager",
            "--literal-pathspecs",
            "--no-replace-objects",
            *arguments,
        ]
        result = _run_bounded_process(
            command,
            cwd=repo,
            env=_git_environment(),
            timeout=30,
            stdout_limit=32 * 1024 * 1024,
            stderr_limit=MAX_GIT_STDERR_BYTES,
            label="Git source observation",
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                command,
                output=result.stdout,
                stderr=result.stderr,
            )
        after = executable.stat()
    except ReleaseEvidenceError:
        raise
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ReleaseEvidenceError(f"cannot inspect Git source: git {' '.join(arguments)}") from exc
    if _stat_observation(before) != _stat_observation(after):
        raise ReleaseEvidenceError("Git executable changed during source inspection")
    if not text:
        return result.stdout
    try:
        return result.stdout.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseEvidenceError("Git source observation is not UTF-8") from exc


def _git_environment() -> dict[str, str]:
    """Use no ambient Git routing, config, credential, object, or executable overrides."""
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _parse_git_tree(raw: bytes, *, where: str) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for record in (part for part in raw.split(b"\0") if part):
        try:
            header, raw_path = record.split(b"\t", 1)
            fields = header.split(b" ")
            if where == "HEAD tree":
                mode_raw, kind, object_id_raw = fields
                if kind != b"blob":
                    raise ValueError
            else:
                mode_raw, object_id_raw, stage = fields
                if stage != b"0":
                    raise ValueError
            path = raw_path.decode("utf-8")
            mode = mode_raw.decode("ascii")
            object_id = object_id_raw.decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseEvidenceError(f"Git {where} record is malformed") from exc
        if mode not in {"100644", "100755"} or not re.fullmatch(
            r"[0-9a-f]{40}|[0-9a-f]{64}", object_id
        ):
            raise ReleaseEvidenceError(f"Git {where} contains a non-release entry")
        normalized = _safe_relative_name(path, f"Git {where} path").as_posix()
        if normalized in result:
            raise ReleaseEvidenceError(f"Git {where} repeats a source path")
        result[normalized] = (mode, object_id)
    if not result:
        raise ReleaseEvidenceError(f"Git {where} inventory is empty")
    widths = {len(object_id) for _mode, object_id in result.values()}
    if len(widths) != 1:
        raise ReleaseEvidenceError(f"Git {where} mixes object-id algorithms")
    return dict(sorted(result.items()))


def _git_blob_oid(payload: bytes, *, width: int) -> str:
    return _git_object_oid("blob", payload, width=width)


def _git_object_oid(kind: str, payload: bytes, *, width: int) -> str:
    if kind not in {"blob", "tree"}:
        raise ReleaseEvidenceError("unsupported Git object kind")
    framed = kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0" + payload
    if width == 40:
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    if width == 64:
        return hashlib.sha256(framed).hexdigest()
    raise ReleaseEvidenceError("Git object-id width is unsupported")


def _git_tree_oid(
    source_files: dict[str, bytes], source_modes: dict[str, int], *, width: int
) -> str:
    if not source_files or set(source_files) != set(source_modes):
        raise ReleaseEvidenceError("sdist source tree inventory/modes are inconsistent")
    root: dict[str, Any] = {}
    for relative in sorted(source_files):
        pure = _safe_relative_name(relative, "sdist Git-tree source path")
        if pure.parts[0] == ".git":
            raise ReleaseEvidenceError("sdist cannot contain Git administrative source paths")
        node = root
        for part in pure.parts[:-1]:
            existing = node.setdefault(part, {})
            if not isinstance(existing, dict):
                raise ReleaseEvidenceError("sdist source tree has a file/directory collision")
            node = existing
        leaf = pure.parts[-1]
        if leaf in node:
            raise ReleaseEvidenceError("sdist source tree repeats a path")
        mode = source_modes[relative]
        if mode not in {0o644, 0o755}:
            raise ReleaseEvidenceError("sdist source mode is outside the Git tree profile")
        node[leaf] = (mode, source_files[relative])

    def render(node: dict[str, Any]) -> str:
        records: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            encoded_name = name.encode("ascii")
            if isinstance(value, dict):
                object_id = render(value)
                mode = b"40000"
                ordering = encoded_name + b"/"
            else:
                mode_value, file_payload = value
                object_id = _git_blob_oid(file_payload, width=width)
                mode = b"100755" if mode_value == 0o755 else b"100644"
                ordering = encoded_name
            record = mode + b" " + encoded_name + b"\0" + bytes.fromhex(object_id)
            records.append((ordering, record))
        body = b"".join(record for _ordering, record in sorted(records))
        return _git_object_oid("tree", body, width=width)

    return render(root)


def _raw_tracked_state(repo: Path) -> tuple[bytes, int]:
    """Return an empty marker only when HEAD, index, modes, and raw tracked bytes agree."""
    raw_head = _run_git(repo, "ls-tree", "-r", "-z", "HEAD", text=False)
    raw_index = _run_git(repo, "ls-files", "--stage", "-z", text=False)
    assert isinstance(raw_head, bytes) and isinstance(raw_index, bytes)
    head = _parse_git_tree(raw_head, where="HEAD tree")
    index = _parse_git_tree(raw_index, where="index")
    worktree: list[dict[str, Any]] = []
    bytes_match_index = True
    for relative, (expected_mode, expected_oid) in index.items():
        path = repo.joinpath(*PurePosixPath(relative).parts)
        try:
            payload = _read_regular(path, maximum=MAX_DISTRIBUTION_BYTES, label="tracked source")
            mode = _source_file_mode(path, where="tracked source")
        except ReleaseEvidenceError:
            bytes_match_index = False
            worktree.append({"path": relative, "present": False})
            continue
        git_oid = _git_blob_oid(payload, width=len(expected_oid))
        rendered_mode = "100755" if mode == 0o755 else "100644"
        if (rendered_mode, git_oid) != (expected_mode, expected_oid):
            bytes_match_index = False
        worktree.append(
            {
                "git_blob_oid": git_oid,
                "mode": rendered_mode,
                "path": relative,
                "sha256": _sha256_field(payload),
                "size": len(payload),
            }
        )
    if head == index and bytes_match_index:
        return b"", len(index)
    state = {
        "head": [
            {"mode": mode, "object_id": object_id, "path": path}
            for path, (mode, object_id) in head.items()
        ],
        "index": [
            {"mode": mode, "object_id": object_id, "path": path}
            for path, (mode, object_id) in index.items()
        ],
        "worktree": worktree,
    }
    return _canonical_bytes(state), len(index)


def _dirty_digest(repo: Path, diff: bytes, untracked: list[str]) -> str | None:
    if not diff and not untracked:
        return None
    digest = hashlib.sha256(b"artifactforge/release-evidence/dirty-source/v1\0")
    digest.update(len(diff).to_bytes(8, "big"))
    digest.update(diff)
    for relative in sorted(untracked):
        pure = _safe_relative_name(relative, "untracked source path")
        path = repo.joinpath(*pure.parts)
        if path.is_symlink():
            # Preserve raw target bytes, including names decoded through surrogateescape.
            payload = os.fsencode(os.readlink(path))
        else:
            payload = _read_regular(path, maximum=MAX_DISTRIBUTION_BYTES, label="source file")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


_MATERIAL_NAMES = (
    "pyproject.toml",
    "uv.lock",
    "build-constraints.in",
    "build-constraints.txt",
    "ci-bootstrap-requirements.txt",
    ".github/workflows/ci.yml",
    ".github/workflows/release-evidence.yml",
    "src/artifactforge/release_evidence.py",
    "scripts/release_evidence.py",
    "scripts/publish_rehearsal.py",
    "scripts/validate_cyclonedx.py",
    "scripts/attest_windows_native.py",
    "scripts/check_python_support.py",
    "tests/test_release_evidence.py",
    "tests/test_publish_rehearsal.py",
    "tests/test_cyclonedx_schema.py",
    "tests/test_native_windows_attestation.py",
    "tests/test_python_support.py",
    "tests/test_workflow_supply_chain.py",
)


def source_snapshot(repo: Path) -> dict[str, Any]:
    repo = repo.resolve()
    commit = str(_run_git(repo, "rev-parse", "HEAD")).strip()
    tree = str(_run_git(repo, "rev-parse", "HEAD^{tree}")).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ReleaseEvidenceError("Git commit is not a lowercase object id")
    if not re.fullmatch(r"[0-9a-f]{40,64}", tree):
        raise ReleaseEvidenceError("Git tree is not a lowercase object id")
    tracked_state, _tracked_file_count = _raw_tracked_state(repo)
    raw_untracked = _run_git(
        repo,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        text=False,
    )
    assert isinstance(raw_untracked, bytes)
    try:
        untracked = [part.decode("utf-8") for part in raw_untracked.split(b"\0") if part]
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError("untracked source path is not UTF-8") from exc
    dirty = _dirty_digest(repo, tracked_state, untracked)
    materials = []
    for relative in _MATERIAL_NAMES:
        path = repo / relative
        if not path.exists():
            raise ReleaseEvidenceError(f"required source material is missing: {relative}")
        payload = _read_regular(path, maximum=MAX_DISTRIBUTION_BYTES, label="source material")
        materials.append({"path": relative, "sha256": _sha256_field(payload), "size": len(payload)})
    return {
        "schema": "artifactforge-source-provenance-v1",
        "git_commit": commit,
        "git_tree": tree,
        "worktree_clean": dirty is None,
        "dirty_snapshot_sha256": dirty,
        "untracked_file_count": len(untracked),
        "materials": materials,
    }


def _project_contract(payload: bytes, *, expected_version: str) -> dict[str, Any]:
    try:
        document = tomllib.loads(payload.decode("utf-8"))
        project = document["project"]
    except (
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ReleaseEvidenceError("cannot read project identity from pyproject.toml") from exc
    if not isinstance(project, dict):
        raise ReleaseEvidenceError("pyproject project table must be an object")
    expected_project_keys = {
        "name",
        "version",
        "description",
        "requires-python",
        "license",
        "license-files",
        "dependencies",
        "optional-dependencies",
        "scripts",
    }
    if set(project) != expected_project_keys:
        raise ReleaseEvidenceError("pyproject project table is not the closed release profile")
    name = _expect_string(project.get("name"), "project.name", maximum=128)
    version = _expect_string(project.get("version"), "project.version", maximum=128)
    if name != "artifactforge" or version != expected_version:
        raise ReleaseEvidenceError("pyproject identity differs from the expected distribution")
    if project.get("requires-python") != ">=3.11":
        raise ReleaseEvidenceError("pyproject has the wrong Python boundary")
    if (
        project.get("description") != EXPECTED_DESCRIPTION
        or project.get("license") != {"text": "MIT"}
        or project.get("license-files") != ["LICENSE"]
    ):
        raise ReleaseEvidenceError("pyproject descriptive/license metadata is wrong")
    if project.get("dependencies") != []:
        raise ReleaseEvidenceError("pyproject must retain an empty runtime dependency list")
    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or set(optional) != {"dev"}:
        raise ReleaseEvidenceError("pyproject must declare exactly the dev optional dependency set")
    dev = optional["dev"]
    if not isinstance(dev, list) or any(not isinstance(item, str) for item in dev):
        raise ReleaseEvidenceError("pyproject dev requirements must be text")
    if _requirement_contract(dev, where="pyproject dev requirements") != _requirement_contract(
        EXPECTED_DEV_REQUIREMENTS,
        where="expected dev requirements",
    ):
        raise ReleaseEvidenceError("pyproject dev requirements differ from the release contract")
    if project.get("scripts") != {"artifactforge": "artifactforge.cli:main"}:
        raise ReleaseEvidenceError("pyproject console-script contract is wrong")
    if document.get("build-system") != {
        "requires": [f"hatchling=={EXPECTED_WHEEL_GENERATOR.removeprefix('hatchling ')}"],
        "build-backend": "hatchling.build",
    }:
        raise ReleaseEvidenceError("pyproject build backend is not the pinned Hatchling profile")
    expected_tooling = {
        "hatch": {
            "build": {
                "targets": {
                    "wheel": {
                        "packages": ["src/artifactforge"],
                        "exclude": ["integration"],
                    }
                }
            }
        },
        "pytest": {"ini_options": {"testpaths": ["tests"]}},
        "ruff": {"line-length": 100, "target-version": "py311"},
    }
    if set(document) != {"project", "build-system", "tool"}:
        raise ReleaseEvidenceError("pyproject top-level tables are not the closed release profile")
    if document.get("tool") != expected_tooling:
        raise ReleaseEvidenceError("pyproject tool configuration is not the closed release profile")
    return {
        "name": name,
        "version": version,
        "requires_python": ">=3.11",
        "runtime_dependency_count": 0,
        "dev_requirements": _requirement_contract(dev, where="pyproject dev requirements"),
        "scripts": project["scripts"],
    }


def _project_metadata(repo: Path) -> tuple[str, str]:
    payload = _read_regular(repo / "pyproject.toml", maximum=1024 * 1024, label="pyproject.toml")
    contract = _project_contract(payload, expected_version=__version__)
    return contract["name"], contract["version"]


def _distribution_files(directory: Path) -> _DistributionInput:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(directory, flags)
    except (NotImplementedError, OSError) as exc:
        raise ReleaseEvidenceError(
            f"cannot open distribution directory through a descriptor: {directory}"
        ) from exc
    try:
        before = os.fstat(root_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise ReleaseEvidenceError(f"distribution input is not a real directory: {directory}")
        try:
            names = sorted(os.listdir(root_fd))
        except (NotImplementedError, OSError) as exc:
            raise ReleaseEvidenceError(
                "platform cannot enumerate a descriptor-bound distribution directory"
            ) from exc
        result: dict[str, bytes] = {}
        identities: dict[str, tuple[int, int]] = {}
        for name in names:
            pure = _safe_relative_name(name, "distribution-directory entry")
            if (
                len(pure.parts) != 1
                or not name.startswith("artifactforge-")
                or not (name.endswith(".whl") or name.endswith(".tar.gz"))
            ):
                raise ReleaseEvidenceError(f"unexpected distribution-directory entry: {name}")
            result[name], identities[name] = _read_regular_observed(
                name,
                maximum=MAX_DISTRIBUTION_BYTES,
                label="distribution",
                dir_fd=root_fd,
                display_path=directory / name,
            )
        after = os.fstat(root_fd)
        if (
            _stat_observation(before) != _stat_observation(after)
            or sorted(os.listdir(root_fd)) != names
        ):
            raise ReleaseEvidenceError("distribution directory changed while it was observed")
    finally:
        os.close(root_fd)
    wheels = [name for name in result if name.endswith(".whl")]
    sdists = [name for name in result if name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(result) != 2:
        raise ReleaseEvidenceError(
            "each build directory must contain exactly one wheel and one sdist"
        )
    return _DistributionInput(
        files=result,
        root_identity=(before.st_dev, before.st_ino),
        file_identities=identities,
    )


def _require_distinct_distribution_inputs(
    primary: _DistributionInput,
    comparison: _DistributionInput,
) -> None:
    if primary.root_identity == comparison.root_identity:
        raise ReleaseEvidenceError("distribution inputs must use distinct directory inodes")
    for name in sorted(primary.files):
        if primary.file_identities[name] == comparison.file_identities[name]:
            raise ReleaseEvidenceError(
                f"distribution inputs share one subject inode instead of two copies: {name}"
            )


def _requirement_identity(value: str, *, where: str) -> tuple[str, tuple[str, ...]]:
    text = value.strip()
    match = _SIMPLE_REQUIREMENT_RE.fullmatch(text)
    if match is None:
        raise ReleaseEvidenceError(f"{where} is not a simple name/specifier requirement")
    name = re.sub(r"[-_.]+", "-", match.group("name")).lower()
    raw_specifiers = match.group("specifiers")
    specifiers: list[str] = []
    if raw_specifiers:
        for specifier in raw_specifiers.split(","):
            normalized = specifier.strip()
            if not _SIMPLE_SPECIFIER_RE.fullmatch(normalized):
                raise ReleaseEvidenceError(f"{where} has an invalid version specifier")
            specifiers.append(normalized)
    if len(specifiers) != len(set(specifiers)):
        raise ReleaseEvidenceError(f"{where} repeats a version specifier")
    return name, tuple(sorted(specifiers))


def _requirement_contract(values: Any, *, where: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not isinstance(values, (list, tuple)) or any(not isinstance(item, str) for item in values):
        raise ReleaseEvidenceError(f"{where} must be a string array")
    identities = [_requirement_identity(item, where=where) for item in values]
    if len(identities) != len(set(identities)):
        raise ReleaseEvidenceError(f"{where} contains duplicate requirements")
    return tuple(sorted(identities))


def _numeric_version(value: str, *, where: str) -> tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise ReleaseEvidenceError(f"{where} is not in the bounded numeric version profile")
    return tuple(int(part) for part in value.split("."))


def _compare_numeric_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _require_locked_version(
    name: str, version: str, specifiers: tuple[str, ...], *, where: str
) -> None:
    if not specifiers:
        return
    observed = _numeric_version(version, where=where)
    for specifier in specifiers:
        match = re.fullmatch(r"(==|>=|<)([0-9]+(?:\.[0-9]+)*)", specifier)
        if match is None:
            raise ReleaseEvidenceError("release lock uses an unsupported direct specifier")
        expected = _numeric_version(match.group(2), where=f"{where} constraint")
        comparison = _compare_numeric_versions(observed, expected)
        satisfied = {
            "==": comparison == 0,
            ">=": comparison >= 0,
            "<": comparison < 0,
        }[match.group(1)]
        if not satisfied:
            raise ReleaseEvidenceError(
                f"locked {name} {version} does not satisfy direct requirement {specifier}"
            )


def _locked_development_contract(payload: bytes, *, project_version: str) -> dict[str, Any]:
    if len(payload) > MAX_LOCK_BYTES:
        raise ReleaseEvidenceError("uv.lock exceeds the release-evidence bound")
    try:
        lock = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError, ValueError, RecursionError) as exc:
        raise ReleaseEvidenceError("uv.lock is not bounded readable TOML") from exc
    if not isinstance(lock, dict) or set(lock) != {
        "version",
        "revision",
        "requires-python",
        "package",
    }:
        raise ReleaseEvidenceError("uv.lock top-level profile is not closed")
    if (
        type(lock["version"]) is not int
        or lock["version"] != 1
        or type(lock["revision"]) is not int
        or lock["revision"] != 3
        or lock["requires-python"] != ">=3.11"
    ):
        raise ReleaseEvidenceError("uv.lock schema/Python boundary is unexpected")
    packages = lock["package"]
    if not isinstance(packages, list) or not 2 <= len(packages) <= 1024:
        raise ReleaseEvidenceError("uv.lock package inventory is outside the release bound")
    package_by_name: dict[str, dict[str, Any]] = {}
    versions: dict[str, str] = {}
    dependency_names: dict[str, list[str]] = {}
    marker_by_child: dict[str, set[str]] = {}
    for index, item in enumerate(packages):
        if not isinstance(item, dict):
            raise ReleaseEvidenceError(f"uv.lock package[{index}] is not an object")
        name = _expect_string(item.get("name"), f"uv.lock package[{index}].name", maximum=256)
        normalized_name = _requirement_identity(name, where="uv.lock package name")[0]
        if name != normalized_name or name in package_by_name:
            raise ReleaseEvidenceError("uv.lock package names must be canonical and unique")
        version = _expect_string(
            item.get("version"), f"uv.lock package[{index}].version", maximum=128
        )
        source = item.get("source")
        expected_source = (
            {"editable": "."}
            if name == "artifactforge"
            else {"registry": "https://pypi.org/simple"}
        )
        if source != expected_source:
            raise ReleaseEvidenceError("uv.lock package source is outside the release profile")
        raw_dependencies = item.get("dependencies", [])
        if not isinstance(raw_dependencies, list) or len(raw_dependencies) > 1024:
            raise ReleaseEvidenceError("uv.lock dependency inventory is outside the release bound")
        children: list[str] = []
        for dependency_index, dependency in enumerate(raw_dependencies):
            if not isinstance(dependency, dict) or set(dependency) not in (
                {"name"},
                {"name", "marker"},
            ):
                raise ReleaseEvidenceError("uv.lock dependency row is outside the closed profile")
            child = _expect_string(
                dependency.get("name"),
                f"uv.lock package[{index}].dependencies[{dependency_index}].name",
                maximum=256,
            )
            if child != _requirement_identity(child, where="uv.lock dependency name")[0]:
                raise ReleaseEvidenceError("uv.lock dependency name is not canonical")
            children.append(child)
            if "marker" in dependency:
                marker = _expect_string(
                    dependency["marker"], "uv.lock dependency marker", maximum=4096
                )
                marker_by_child.setdefault(child, set()).add(marker)
        if children != sorted(children) or len(children) != len(set(children)):
            raise ReleaseEvidenceError("uv.lock dependencies are not canonical and unique")
        package_by_name[name] = item
        versions[name] = version
        dependency_names[name] = children
    root = package_by_name.get("artifactforge")
    if root is None or versions["artifactforge"] != project_version:
        raise ReleaseEvidenceError("uv.lock lacks the exact ArtifactForge root")
    optional = root.get("optional-dependencies")
    if not isinstance(optional, dict) or set(optional) != {"dev"}:
        raise ReleaseEvidenceError("uv.lock root optional dependency profile is not closed")
    direct_rows = optional["dev"]
    if not isinstance(direct_rows, list) or any(
        not isinstance(row, dict) or set(row) != {"name"} for row in direct_rows
    ):
        raise ReleaseEvidenceError("uv.lock dev dependency rows are malformed")
    direct_names = [row["name"] for row in direct_rows]
    expected_requirements = _requirement_contract(
        EXPECTED_DEV_REQUIREMENTS, where="expected dev requirements"
    )
    expected_direct_names = [name for name, _specifiers in expected_requirements]
    if direct_names != expected_direct_names:
        raise ReleaseEvidenceError("uv.lock direct dev dependency set/order is unexpected")
    metadata = root.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {"requires-dist", "provides-extras"}:
        raise ReleaseEvidenceError("uv.lock root metadata profile is not closed")
    if metadata["provides-extras"] != ["dev"] or not isinstance(metadata["requires-dist"], list):
        raise ReleaseEvidenceError("uv.lock root dev metadata is malformed")
    locked_requirements: list[str] = []
    for row in metadata["requires-dist"]:
        if not isinstance(row, dict) or set(row) not in (
            {"name", "marker"},
            {"name", "marker", "specifier"},
        ):
            raise ReleaseEvidenceError("uv.lock root requirement row is malformed")
        if row.get("marker") != "extra == 'dev'":
            raise ReleaseEvidenceError("uv.lock root requirement marker is unexpected")
        requirement = _expect_string(row.get("name"), "uv.lock root requirement name", maximum=256)
        if "specifier" in row:
            requirement += _expect_string(
                row["specifier"], "uv.lock root requirement specifier", maximum=128
            )
        locked_requirements.append(requirement)
    if (
        _requirement_contract(locked_requirements, where="uv.lock root requirements")
        != expected_requirements
    ):
        raise ReleaseEvidenceError("uv.lock root requirements differ from the release contract")
    for name, specifiers in expected_requirements:
        if name not in versions:
            raise ReleaseEvidenceError(f"uv.lock omits direct requirement {name}")
        _require_locked_version(
            name, versions[name], specifiers, where=f"uv.lock package {name} version"
        )
    for parent, children in dependency_names.items():
        missing = sorted(set(children) - set(package_by_name))
        if missing:
            raise ReleaseEvidenceError(f"uv.lock {parent} has dangling dependencies: {missing}")
    dependency_names["artifactforge"] = direct_names
    refs = {name: f"pkg:pypi/{name}@{version}" for name, version in versions.items()}
    dependencies: list[dict[str, Any]] = []
    for name in sorted(refs, key=lambda item: refs[item]):
        row: dict[str, Any] = {"ref": refs[name]}
        children = sorted(refs[child] for child in dependency_names[name])
        if children:
            row["dependsOn"] = children
        dependencies.append(row)
    components = {
        name: {
            "ref": refs[name],
            "version": versions[name],
            "properties": [
                {"name": "uv:package:marker", "value": marker}
                for marker in sorted(marker_by_child.get(name, set()))
            ],
        }
        for name in versions
        if name != "artifactforge"
    }
    graph_digest = _sha256_field(_canonical_bytes(dependencies))
    return {
        "component_count": len(components),
        "components": components,
        "dependencies": dependencies,
        "graph_sha256": graph_digest,
    }


def _validate_development_sbom_against_lock(
    document: dict[str, Any], contract: dict[str, Any]
) -> None:
    observed_components = {
        component["name"]: {
            "ref": component["bom-ref"],
            "version": component["version"],
            "properties": component.get("properties", []),
        }
        for component in document["components"]
    }
    if observed_components != contract["components"]:
        raise ReleaseEvidenceError("development SBOM components/markers differ from uv.lock")
    if document["dependencies"] != contract["dependencies"]:
        raise ReleaseEvidenceError("development SBOM dependency graph differs from uv.lock")


def _expected_package_metadata(version: str) -> bytes:
    lines = [
        "Metadata-Version: 2.4",
        "Name: artifactforge",
        f"Version: {version}",
        f"Summary: {EXPECTED_DESCRIPTION}",
        "License: MIT",
        "License-File: LICENSE",
        "Requires-Python: >=3.11",
        "Provides-Extra: dev",
        *(f"Requires-Dist: {item}; extra == 'dev'" for item in EXPECTED_METADATA_REQUIREMENTS),
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _metadata_runtime_contract(payload: bytes, *, version: str, where: str) -> dict[str, Any]:
    if payload != _expected_package_metadata(version):
        raise ReleaseEvidenceError(
            f"{where} package metadata bytes differ from the pinned Hatchling profile"
        )
    message = BytesParser(policy=compat32).parsebytes(payload)
    if message.defects:
        raise ReleaseEvidenceError(f"{where} package metadata has parser defects")
    if message.get_all("Metadata-Version") != ["2.4"]:
        raise ReleaseEvidenceError(f"{where} has the wrong Metadata-Version")
    if message.get_all("Name") != ["artifactforge"] or message.get_all("Version") != [version]:
        raise ReleaseEvidenceError(f"{where} package identity is wrong")
    if message.get_all("Provides-Extra", []) != ["dev"]:
        raise ReleaseEvidenceError(f"{where} must declare exactly the dev extra")
    requires = message.get_all("Requires-Dist", [])
    malformed = []
    optional_requirements = []
    for line in requires:
        requirement, separator, marker = line.rpartition(";")
        if (
            not separator
            or not requirement.strip()
            or marker.strip() not in {'extra == "dev"', "extra == 'dev'"}
        ):
            malformed.append(line)
        else:
            optional_requirements.append(requirement.strip())
    if malformed:
        raise ReleaseEvidenceError(
            f"{where} has a dependency outside the exact dev-extra marker: {malformed}"
        )
    if _requirement_contract(
        optional_requirements, where=f"{where} dev requirements"
    ) != _requirement_contract(EXPECTED_DEV_REQUIREMENTS, where="expected dev requirements"):
        raise ReleaseEvidenceError(f"{where} dev requirements differ from pyproject contract")
    if message.get_all("Requires-Python") != [">=3.11"]:
        raise ReleaseEvidenceError(f"{where} has the wrong Requires-Python boundary")
    return {
        "name": message["Name"],
        "version": message["Version"],
        "requires_python": message["Requires-Python"],
        "runtime_dependency_count": 0,
        "optional_requirement_count": len(requires),
    }


def _urlsafe_digest(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")


def _validate_zip_container(
    payload: bytes,
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
) -> None:
    eocd_offset = payload.rfind(b"PK\x05\x06", max(0, len(payload) - 65_557))
    if eocd_offset < 0 or eocd_offset + 22 > len(payload):
        raise ReleaseEvidenceError("wheel lacks a complete ZIP end record")
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = struct.unpack_from("<4s4H2LH", payload, eocd_offset)
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or central_disk != 0
        or disk_entries != len(infos)
        or total_entries != len(infos)
        or comment_size != 0
        or eocd_offset + 22 != len(payload)
        or central_offset != archive.start_dir
        or central_offset + central_size != eocd_offset
        or archive.comment
    ):
        raise ReleaseEvidenceError("wheel ZIP container is not single-disk and exactly closed")
    ordered = sorted(infos, key=lambda item: item.header_offset)
    if [item.header_offset for item in infos] != [item.header_offset for item in ordered]:
        raise ReleaseEvidenceError("wheel central and local member orders differ")
    if ordered[0].header_offset != 0:
        raise ReleaseEvidenceError("wheel has data before its first local record")
    for index, info in enumerate(ordered):
        if info.header_offset < 0 or info.header_offset + 30 > central_offset:
            raise ReleaseEvidenceError("wheel local-header offset is outside the ZIP payload")
        (
            local_signature,
            extract_version,
            flags,
            compression,
            dos_time,
            dos_date,
            crc,
            compressed_size,
            file_size,
            filename_size,
            extra_size,
        ) = struct.unpack_from("<4s5H3L2H", payload, info.header_offset)
        name_start = info.header_offset + 30
        name_end = name_start + filename_size
        data_start = name_end + extra_size
        data_end = data_start + compressed_size
        expected_end = (
            ordered[index + 1].header_offset if index + 1 < len(ordered) else central_offset
        )
        if (
            local_signature != b"PK\x03\x04"
            or extract_version != 20
            or flags != 0
            or compression != info.compress_type
            or dos_time != EXPECTED_ZIP_DOS_TIME
            or dos_date != EXPECTED_ZIP_DOS_DATE
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or extra_size != 0
            or payload[name_start:name_end] != info.filename.encode("utf-8")
            or data_end != expected_end
        ):
            raise ReleaseEvidenceError("wheel local records are not canonical and contiguous")
    central_cursor = central_offset
    for info in infos:
        if central_cursor + 46 > eocd_offset:
            raise ReleaseEvidenceError("wheel central-directory record is truncated")
        (
            central_signature,
            create_version,
            extract_version,
            flags,
            compression,
            dos_time,
            dos_date,
            crc,
            compressed_size,
            file_size,
            filename_size,
            extra_size,
            member_comment_size,
            disk_start,
            internal_attr,
            external_attr,
            local_offset,
        ) = struct.unpack_from("<4s6H3L5H2L", payload, central_cursor)
        name_start = central_cursor + 46
        name_end = name_start + filename_size
        record_end = name_end + extra_size + member_comment_size
        expected_external = info.external_attr
        if (
            central_signature != b"PK\x01\x02"
            or create_version != (3 << 8) | 20
            or extract_version != 20
            or flags != 0
            or compression != zipfile.ZIP_DEFLATED
            or dos_time != EXPECTED_ZIP_DOS_TIME
            or dos_date != EXPECTED_ZIP_DOS_DATE
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or extra_size != 0
            or member_comment_size != 0
            or disk_start != 0
            or internal_attr != 0
            or external_attr != expected_external
            or local_offset != info.header_offset
            or payload[name_start:name_end] != info.filename.encode("ascii")
            or record_end > eocd_offset
        ):
            raise ReleaseEvidenceError("wheel central-directory records are not canonical")
        central_cursor = record_end
    if central_cursor != eocd_offset:
        raise ReleaseEvidenceError("wheel central directory contains unparsed data")


def _inspect_wheel(name: str, payload: bytes, *, version: str) -> dict[str, Any]:
    if name != f"artifactforge-{version}-py3-none-any.whl":
        raise ReleaseEvidenceError("wheel filename is not the canonical project/version/tag name")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
        infos = archive.infolist()
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReleaseEvidenceError("wheel is not a readable ZIP archive") from exc
    if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
        raise ReleaseEvidenceError("wheel member count is outside the release bound")
    _validate_zip_container(payload, archive, infos)
    dist_info = f"artifactforge-{version}.dist-info"
    names: list[str] = []
    expanded = 0
    payloads: dict[str, bytes] = {}
    for info in infos:
        pure = _safe_relative_name(info.filename.rstrip("/"), "wheel member")
        normalized = pure.as_posix()
        encoded_type = stat.S_IFMT(info.external_attr >> 16)
        if info.is_dir():
            raise ReleaseEvidenceError(
                f"wheel contains an undeclared directory entry: {normalized}"
            )
        if encoded_type not in {0, stat.S_IFREG}:
            raise ReleaseEvidenceError(f"wheel contains a link or special file: {normalized}")
        encoded_mode = info.external_attr >> 16
        expected_mode = (
            encoded_mode == 0o644
            if normalized.startswith(f"{dist_info}/")
            else encoded_mode in {stat.S_IFREG | 0o644, stat.S_IFREG | 0o755}
        )
        if (
            info.compress_type != zipfile.ZIP_DEFLATED
            or info.flag_bits != 0
            or info.date_time != EXPECTED_ZIP_DATETIME
            or info.extra
            or info.comment
            or info.create_system != 3
            or info.create_version != 20
            or info.extract_version != 20
            or info.reserved != 0
            or info.internal_attr != 0
            or info.volume != 0
            or not expected_mode
        ):
            raise ReleaseEvidenceError(f"wheel member metadata is not canonical: {normalized}")
        if normalized in payloads:
            raise ReleaseEvidenceError(f"duplicate wheel member: {normalized}")
        expanded += info.file_size
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ReleaseEvidenceError("wheel expanded-size limit exceeded")
        try:
            member = archive.read(info)
        except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            raise ReleaseEvidenceError(f"cannot read wheel member: {normalized}") from exc
        if len(member) != info.file_size:
            raise ReleaseEvidenceError(f"wheel member size changed: {normalized}")
        names.append(normalized)
        payloads[normalized] = member
    try:
        canonical_relative_paths(names)
    except InventoryError as exc:
        raise ReleaseEvidenceError("wheel member paths are not portable and unique") from exc
    metadata_name = f"{dist_info}/METADATA"
    wheel_name = f"{dist_info}/WHEEL"
    record_name = f"{dist_info}/RECORD"
    for required in (metadata_name, wheel_name, record_name):
        if required not in payloads:
            raise ReleaseEvidenceError(f"wheel lacks {required}")
    metadata = _metadata_runtime_contract(payloads[metadata_name], version=version, where="wheel")
    try:
        wheel_text = payloads[wheel_name].decode("utf-8")
        wheel_headers = BytesParser(policy=compat32).parsebytes(payloads[wheel_name])
    except (UnicodeDecodeError, UnicodeError) as exc:
        raise ReleaseEvidenceError("wheel WHEEL metadata is not valid UTF-8") from exc
    if wheel_headers.defects or set(wheel_headers.keys()) != {
        "Wheel-Version",
        "Generator",
        "Root-Is-Purelib",
        "Tag",
    }:
        raise ReleaseEvidenceError("wheel WHEEL headers are malformed or unexpected")
    if payloads[wheel_name] != EXPECTED_WHEEL_METADATA:
        raise ReleaseEvidenceError("wheel WHEEL bytes differ from the pinned backend profile")
    if wheel_headers.get_all("Wheel-Version") != ["1.0"]:
        raise ReleaseEvidenceError("wheel format version is not 1.0")
    if wheel_headers.get_all("Generator") != [EXPECTED_WHEEL_GENERATOR]:
        raise ReleaseEvidenceError("wheel generator does not match the pinned backend")
    if wheel_headers.get_all("Root-Is-Purelib") != ["true"] or wheel_headers.get_all("Tag") != [
        "py3-none-any"
    ]:
        raise ReleaseEvidenceError("wheel is not the expected pure-Python py3-none-any artifact")
    try:
        record_text = payloads[record_name].decode("utf-8")
        rows = list(csv.reader(io.StringIO(record_text, newline=""), strict=True))
    except (UnicodeDecodeError, UnicodeError, csv.Error) as exc:
        raise ReleaseEvidenceError("wheel RECORD is not strict UTF-8 CSV") from exc
    if len(rows) != len(payloads):
        raise ReleaseEvidenceError("wheel RECORD cardinality does not match archive members")
    recorded: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise ReleaseEvidenceError("wheel RECORD row must have three columns")
        member_name, digest, size = row
        _safe_relative_name(member_name, "wheel RECORD path")
        if member_name in recorded or member_name not in payloads:
            raise ReleaseEvidenceError(f"wheel RECORD path is duplicate or absent: {member_name}")
        recorded.add(member_name)
        if member_name == record_name:
            if digest or size:
                raise ReleaseEvidenceError("wheel RECORD must leave its own hash and size empty")
            continue
        expected = payloads[member_name]
        if digest != "sha256=" + _urlsafe_digest(expected) or size != str(len(expected)):
            raise ReleaseEvidenceError(f"wheel RECORD digest/size mismatch: {member_name}")
    if recorded != set(payloads):
        raise ReleaseEvidenceError("wheel RECORD does not cover every archive member")
    expected_record_rows = []
    for member_name in names:
        if member_name == record_name:
            expected_record_rows.append([member_name, "", ""])
        else:
            member = payloads[member_name]
            expected_record_rows.append(
                [member_name, "sha256=" + _urlsafe_digest(member), str(len(member))]
            )
    expected_record = io.StringIO(newline="")
    csv.writer(expected_record, lineterminator="\n").writerows(expected_record_rows)
    if payloads[record_name] != expected_record.getvalue().encode("utf-8"):
        raise ReleaseEvidenceError(
            "wheel RECORD bytes/order differ from the pinned backend profile"
        )
    return {
        "archive_member_count": len(payloads),
        "expanded_bytes": expanded,
        "member_timestamp_utc": EXPECTED_ARCHIVE_TIMESTAMP,
        "metadata": metadata,
        "record_verified": True,
        "wheel_generator": wheel_headers["Generator"],
        "wheel_tag": wheel_headers["Tag"],
        "package_metadata_sha256": _sha256_field(payloads[metadata_name]),
        "wheel_descriptor_sha256": _sha256_field(wheel_text.encode("utf-8")),
    }


def _tar_octal(value: int, width: int) -> bytes:
    rendered = f"{value:0{width - 1}o}".encode("ascii") + b"\0"
    if len(rendered) != width:
        raise ReleaseEvidenceError("tar numeric field exceeds the canonical profile")
    return rendered


def _pax_path_record(path: str) -> bytes:
    suffix = f" path={path}\n".encode("ascii")
    length = len(suffix) + 1
    while True:
        record = str(length).encode("ascii") + suffix
        if len(record) == length:
            return record
        length = len(record)


def _validate_raw_tar_header(
    header: bytes,
    *,
    raw_name: bytes,
    mode: int,
    size: int,
    mtime: int,
    typeflag: bytes,
) -> None:
    if len(header) != 512 or len(raw_name) > 100 or len(typeflag) != 1:
        raise ReleaseEvidenceError("sdist tar header is structurally invalid")
    checksum = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
    expected = bytearray(512)
    expected[: len(raw_name)] = raw_name
    expected[100:108] = _tar_octal(mode, 8)
    expected[108:116] = _tar_octal(0, 8)
    expected[116:124] = _tar_octal(0, 8)
    expected[124:136] = _tar_octal(size, 12)
    expected[136:148] = _tar_octal(mtime, 12)
    expected[148:156] = f"{checksum:06o}".encode("ascii") + b"\0 "
    expected[156:157] = typeflag
    expected[257:265] = b"ustar\x0000"
    if header != bytes(expected):
        raise ReleaseEvidenceError("sdist raw tar header is not the canonical ustar profile")


def _inspect_sdist(name: str, payload: bytes, *, version: str) -> dict[str, Any]:
    if name != f"artifactforge-{version}.tar.gz":
        raise ReleaseEvidenceError("sdist filename is not the canonical project/version name")
    expected_header = b"\x1f\x8b\x08\x00" + struct.pack("<I", EXPECTED_ARCHIVE_EPOCH) + b"\x02\xff"
    if len(payload) < 18 or payload[:10] != expected_header:
        raise ReleaseEvidenceError("sdist gzip header is not the pinned deterministic profile")
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        tar_payload = decompressor.decompress(payload, MAX_ARCHIVE_EXPANDED_BYTES + 1)
        if len(tar_payload) <= MAX_ARCHIVE_EXPANDED_BYTES:
            tar_payload += decompressor.flush()
    except (OSError, EOFError, zlib.error) as exc:
        raise ReleaseEvidenceError("sdist is not a readable gzip stream") from exc
    if len(tar_payload) > MAX_ARCHIVE_EXPANDED_BYTES:
        raise ReleaseEvidenceError("sdist expanded-size limit exceeded")
    if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        raise ReleaseEvidenceError("sdist must contain exactly one closed gzip member")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:")
        members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseEvidenceError("sdist is not a readable tar archive") from exc
    if not members or len(members) > MAX_ARCHIVE_MEMBERS:
        raise ReleaseEvidenceError("sdist member count is outside the release bound")
    expected_root = f"artifactforge-{version}"
    names: list[str] = []
    files: dict[str, bytes] = {}
    expanded = 0
    last_payload_end = 0
    for member in members:
        pure = _safe_relative_name(member.name.rstrip("/"), "sdist member")
        normalized = pure.as_posix()
        if pure.parts[0] != expected_root:
            raise ReleaseEvidenceError("sdist member escapes the single versioned root")
        if not member.isfile():
            raise ReleaseEvidenceError(f"sdist contains a non-file member: {normalized}")
        if (
            member.uid != 0
            or member.gid != 0
            or member.uname != ""
            or member.gname != ""
            or member.mtime != EXPECTED_ARCHIVE_EPOCH
            or member.mode not in {0o644, 0o755}
            or member.pax_headers not in ({}, {"path": normalized})
        ):
            raise ReleaseEvidenceError(f"sdist member metadata is not canonical: {normalized}")
        if normalized in names:
            raise ReleaseEvidenceError(f"duplicate sdist member: {normalized}")
        if member.offset != last_payload_end:
            raise ReleaseEvidenceError("sdist tar members are not physically contiguous")
        encoded_name = normalized.encode("ascii")
        expected_pax = {"path": normalized} if len(encoded_name) > 100 else {}
        if member.pax_headers != expected_pax:
            raise ReleaseEvidenceError(f"sdist PAX metadata is not canonical: {normalized}")
        header_offset = member.offset
        if expected_pax:
            pax_record = _pax_path_record(normalized)
            pax_header = tar_payload[header_offset : header_offset + 512]
            _validate_raw_tar_header(
                pax_header,
                raw_name=b"././@PaxHeader",
                mode=0,
                size=len(pax_record),
                mtime=0,
                typeflag=b"x",
            )
            pax_data_start = header_offset + 512
            pax_data_end = pax_data_start + len(pax_record)
            padded_pax_end = pax_data_start + ((len(pax_record) + 511) // 512) * 512
            if tar_payload[pax_data_start:pax_data_end] != pax_record or any(
                tar_payload[pax_data_end:padded_pax_end]
            ):
                raise ReleaseEvidenceError(f"sdist PAX payload is not canonical: {normalized}")
            header_offset = padded_pax_end
        if member.offset_data != header_offset + 512:
            raise ReleaseEvidenceError("sdist file data is not adjacent to its raw header")
        _validate_raw_tar_header(
            tar_payload[header_offset : header_offset + 512],
            raw_name=encoded_name[:100],
            mode=member.mode,
            size=member.size,
            mtime=member.mtime,
            typeflag=b"0",
        )
        names.append(normalized)
        if member.isfile():
            expanded += member.size
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                raise ReleaseEvidenceError("sdist expanded-size limit exceeded")
            handle = archive.extractfile(member)
            if handle is None:
                raise ReleaseEvidenceError(f"cannot read sdist member: {normalized}")
            content = handle.read(member.size + 1)
            if len(content) != member.size:
                raise ReleaseEvidenceError(f"sdist member size mismatch: {normalized}")
            files[normalized] = content
        data_end = member.offset_data + member.size
        last_payload_end = member.offset_data + ((member.size + 511) // 512) * 512
        if any(tar_payload[data_end:last_payload_end]):
            raise ReleaseEvidenceError(f"sdist member padding is nonzero: {normalized}")
    try:
        canonical_relative_paths(names)
    except InventoryError as exc:
        raise ReleaseEvidenceError("sdist member paths are not portable and unique") from exc
    trailer = tar_payload[last_payload_end:]
    minimum_end = last_payload_end + 1024
    expected_tar_size = ((minimum_end + 10_239) // 10_240) * 10_240
    if len(tar_payload) != expected_tar_size or any(trailer):
        raise ReleaseEvidenceError("sdist tar stream has noncanonical trailing data")
    required = {
        f"{expected_root}/PKG-INFO",
        f"{expected_root}/LICENSE",
        f"{expected_root}/pyproject.toml",
        f"{expected_root}/build-constraints.in",
        f"{expected_root}/build-constraints.txt",
        f"{expected_root}/src/artifactforge/release_evidence.py",
    }
    missing = sorted(required - set(files))
    if missing:
        raise ReleaseEvidenceError(f"sdist is missing release materials: {missing}")
    metadata = _metadata_runtime_contract(
        files[f"{expected_root}/PKG-INFO"], version=version, where="sdist"
    )
    return {
        "archive_member_count": len(members),
        "expanded_bytes": expanded,
        "gzip_timestamp_utc": EXPECTED_ARCHIVE_TIMESTAMP,
        "member_timestamp_utc": EXPECTED_ARCHIVE_TIMESTAMP,
        "metadata": metadata,
        "single_root": expected_root,
    }


def _validated_archive_payloads(
    wheel_payload: bytes,
    sdist_payload: bytes,
    *,
    version: str,
) -> tuple[dict[str, bytes], dict[str, int], dict[str, bytes], dict[str, int]]:
    """Return file payloads after both callers have passed the bounded archive inspectors."""
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_payload)) as wheel:
            wheel_files = {
                info.filename: wheel.read(info) for info in wheel.infolist() if not info.is_dir()
            }
            wheel_modes = {
                info.filename: stat.S_IMODE(info.external_attr >> 16)
                for info in wheel.infolist()
                if not info.is_dir()
            }
        with gzip.GzipFile(fileobj=io.BytesIO(sdist_payload), mode="rb") as stream:
            tar_payload = stream.read(MAX_ARCHIVE_EXPANDED_BYTES + 1)
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as sdist:
            sdist_files = {
                member.name.removeprefix(f"artifactforge-{version}/"): sdist.extractfile(
                    member
                ).read()
                for member in sdist.getmembers()
                if member.isfile()
            }
            sdist_modes = {
                member.name.removeprefix(f"artifactforge-{version}/"): member.mode
                for member in sdist.getmembers()
                if member.isfile()
            }
    except (
        OSError,
        EOFError,
        RuntimeError,
        tarfile.TarError,
        zipfile.BadZipFile,
        zlib.error,
    ) as exc:
        raise ReleaseEvidenceError(
            "validated distribution changed during chain inspection"
        ) from exc
    return wheel_files, wheel_modes, sdist_files, sdist_modes


def _validated_sdist_member(
    sdist_payload: bytes, *, version: str, relative: str, maximum: int
) -> bytes:
    """Read one file only after the caller has passed the complete sdist inspector."""
    expected = f"artifactforge-{version}/{relative}"
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(sdist_payload), mode="rb") as stream:
            tar_payload = stream.read(MAX_ARCHIVE_EXPANDED_BYTES + 1)
        if len(tar_payload) > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ReleaseEvidenceError("sdist expanded-size limit exceeded")
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            matches = [member for member in archive.getmembers() if member.name == expected]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > maximum:
                raise ReleaseEvidenceError(f"sdist lacks bounded regular member {relative}")
            handle = archive.extractfile(matches[0])
            if handle is None:
                raise ReleaseEvidenceError(f"cannot read sdist member {relative}")
            payload = handle.read(maximum + 1)
    except ReleaseEvidenceError:
        raise
    except (OSError, EOFError, tarfile.TarError, zlib.error) as exc:
        raise ReleaseEvidenceError(f"cannot extract validated sdist member {relative}") from exc
    if len(payload) != matches[0].size or len(payload) > maximum:
        raise ReleaseEvidenceError(f"sdist member {relative} exceeds its bound")
    return payload


def _source_file_mode(path: Path, *, where: str) -> int:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot inspect {where}: {path}") from exc
    if not stat.S_ISREG(observed.st_mode):
        raise ReleaseEvidenceError(f"{where} is not a regular file: {path}")
    mode = stat.S_IMODE(observed.st_mode)
    if mode not in {0o644, 0o755}:
        raise ReleaseEvidenceError(f"{where} mode is outside the release profile: {path}")
    return mode


def _repository_source_paths(repo: Path) -> dict[str, int]:
    observed: dict[str, int] = {}
    raw_stage = _run_git(repo, "ls-files", "--stage", "-z", text=False)
    assert isinstance(raw_stage, bytes)
    for record in (part for part in raw_stage.split(b"\0") if part):
        try:
            header, raw_path = record.split(b"\t", 1)
            mode_text, object_id, stage = header.split(b" ", 2)
            name = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseEvidenceError("Git stage inventory record is malformed") from exc
        if (
            stage != b"0"
            or mode_text not in {b"100644", b"100755"}
            or not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", object_id)
        ):
            raise ReleaseEvidenceError("Git stage contains a non-release file entry")
        pure = _safe_relative_name(name, "Git source inventory path")
        path = repo.joinpath(*pure.parts)
        if not path.exists() and not path.is_symlink():
            continue
        mode = _source_file_mode(path, where="tracked source")
        expected_mode = 0o755 if mode_text == b"100755" else 0o644
        if mode != expected_mode:
            raise ReleaseEvidenceError(f"tracked source mode differs from the Git index: {name}")
        observed[pure.as_posix()] = mode

    raw_untracked = _run_git(repo, "ls-files", "--others", "--exclude-standard", "-z", text=False)
    assert isinstance(raw_untracked, bytes)
    for raw_path in (part for part in raw_untracked.split(b"\0") if part):
        try:
            name = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseEvidenceError("Git source inventory path is not UTF-8") from exc
        pure = _safe_relative_name(name, "Git source inventory path")
        if pure.as_posix() in observed:
            raise ReleaseEvidenceError("Git tracked/untracked source inventories overlap")
        observed[pure.as_posix()] = _source_file_mode(
            repo.joinpath(*pure.parts), where="untracked source"
        )
    if any(PurePosixPath(relative).parts[0] == ".git" for relative in observed):
        raise ReleaseEvidenceError("Git administrative paths cannot be release sources")
    if len(observed) != len(set(observed)):
        raise ReleaseEvidenceError("Git tracked/untracked source inventories overlap")
    try:
        canonical_relative_paths(observed)
    except InventoryError as exc:
        raise ReleaseEvidenceError("Git source inventory is not portable and unique") from exc
    return dict(sorted(observed.items()))


def _bind_distribution_chain(
    wheel_payload: bytes,
    sdist_payload: bytes,
    *,
    version: str,
    repository_root: Path | None,
    source_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind current source bytes to the sdist and the sdist's package bytes to the wheel."""
    wheel_files, wheel_modes, sdist_files, sdist_modes = _validated_archive_payloads(
        wheel_payload,
        sdist_payload,
        version=version,
    )
    source_members = sorted(set(sdist_files) - {"PKG-INFO"})
    materials_match = False
    if source_record is not None:
        materials = source_record.get("materials")
        if not isinstance(materials, list):
            raise ReleaseEvidenceError("source material record is not an array")
        for index, item in enumerate(materials):
            row = _expect_keys(item, {"path", "sha256", "size"}, f"source.materials[{index}]")
            relative = _expect_string(row["path"], f"source.materials[{index}].path", maximum=255)
            payload = sdist_files.get(relative)
            if payload is None:
                raise ReleaseEvidenceError(f"sdist omits a recorded source material: {relative}")
            if (
                type(row["size"]) is not int
                or row["size"] != len(payload)
                or _expect_sha256(row["sha256"], f"source.materials[{index}].sha256")
                != _sha256_field(payload)
            ):
                raise ReleaseEvidenceError(
                    f"source material record differs from the sdist: {relative}"
                )
        materials_match = True
    if repository_root is not None:
        source_inventory = _repository_source_paths(repository_root)
        allowed_sources = sorted(source_inventory)
        unexpected_sources = sorted(set(source_members) - set(allowed_sources))
        missing_sources = sorted(set(allowed_sources) - set(source_members))
        if unexpected_sources or missing_sources:
            raise ReleaseEvidenceError(
                "sdist/Git source inventories differ: "
                f"unexpected={unexpected_sources}, missing={missing_sources}"
            )
        for relative in source_members:
            source = _read_regular(
                repository_root.joinpath(*PurePosixPath(relative).parts),
                maximum=MAX_DISTRIBUTION_BYTES,
                label="sdist source member",
            )
            if source != sdist_files[relative]:
                raise ReleaseEvidenceError(
                    f"sdist member does not match current source: {relative}"
                )
            if sdist_modes[relative] != source_inventory[relative]:
                raise ReleaseEvidenceError(
                    f"sdist member mode does not match current source: {relative}"
                )
        package_sources = sorted(
            relative for relative in allowed_sources if relative.startswith("src/artifactforge/")
        )
        if not package_sources:
            raise ReleaseEvidenceError("Git package source inventory is empty")
        missing_package_sources = sorted(set(package_sources) - set(source_members))
        if missing_package_sources:
            raise ReleaseEvidenceError(
                f"sdist omits current package sources: {missing_package_sources}"
            )
    else:
        package_sources = sorted(
            relative for relative in source_members if relative.startswith("src/artifactforge/")
        )
    expected_wheel_files = {
        relative.removeprefix("src/"): sdist_files[relative] for relative in package_sources
    }
    dist_info = f"artifactforge-{version}.dist-info"
    expected_dist_info = {
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/RECORD",
    }
    observed_dist_info = {
        relative for relative in wheel_files if relative.startswith(f"{dist_info}/")
    }
    if observed_dist_info != expected_dist_info:
        raise ReleaseEvidenceError("wheel dist-info inventory is not the exact release profile")
    observed_wheel_files = {
        relative: payload
        for relative, payload in wheel_files.items()
        if not relative.startswith(f"{dist_info}/")
    }
    if set(observed_wheel_files) != set(expected_wheel_files):
        raise ReleaseEvidenceError("wheel package inventory does not exactly match sdist sources")
    mismatches = sorted(
        relative
        for relative in expected_wheel_files
        if observed_wheel_files[relative] != expected_wheel_files[relative]
    )
    if mismatches:
        raise ReleaseEvidenceError(f"wheel package bytes differ from sdist sources: {mismatches}")
    mode_mismatches = sorted(
        wheel_relative
        for wheel_relative in expected_wheel_files
        if wheel_modes[wheel_relative] != sdist_modes[f"src/{wheel_relative}"]
    )
    if mode_mismatches:
        raise ReleaseEvidenceError(
            f"wheel package modes differ from sdist sources: {mode_mismatches}"
        )
    if wheel_files[f"{dist_info}/METADATA"] != sdist_files["PKG-INFO"]:
        raise ReleaseEvidenceError("wheel METADATA differs from sdist PKG-INFO")
    project = _project_contract(sdist_files["pyproject.toml"], expected_version=version)
    locked_development = _locked_development_contract(
        sdist_files["uv.lock"], project_version=version
    )
    sdist_git_tree_match: bool | None = None
    if source_record is not None and source_record.get("worktree_clean") is True:
        expected_tree = _expect_string(source_record.get("git_tree"), "source.git_tree", maximum=64)
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_tree):
            raise ReleaseEvidenceError("source.git_tree is not a canonical Git object id")
        observed_tree = _git_tree_oid(
            {relative: sdist_files[relative] for relative in source_members},
            {relative: sdist_modes[relative] for relative in source_members},
            width=len(expected_tree),
        )
        if observed_tree != expected_tree:
            raise ReleaseEvidenceError("sdist source bytes/modes do not reproduce source.git_tree")
        sdist_git_tree_match = True
    expected_entry_points = (
        f"[console_scripts]\nartifactforge = {project['scripts']['artifactforge']}\n"
    ).encode("utf-8")
    if wheel_files[f"{dist_info}/entry_points.txt"] != expected_entry_points:
        raise ReleaseEvidenceError("wheel console entry point differs from source pyproject")
    if wheel_files[f"{dist_info}/licenses/LICENSE"] != sdist_files["LICENSE"]:
        raise ReleaseEvidenceError("wheel license bytes differ from the sdist source license")
    if any(wheel_modes[relative] != 0o644 for relative in expected_dist_info):
        raise ReleaseEvidenceError("wheel dist-info modes are not canonical read-only data")
    result = {
        "sdist_source_file_count": len(source_members),
        "sdist_package_source_file_count": len(package_sources),
        "locked_development_component_count": locked_development["component_count"],
        "locked_development_graph_sha256": locked_development["graph_sha256"],
        "wheel_package_file_count": len(expected_wheel_files),
        "wheel_package_matches_sdist": True,
        "wheel_package_modes_match_sdist": True,
        "wheel_metadata_matches_sdist": True,
        "wheel_entry_point_matches_pyproject": True,
        "wheel_license_matches_sdist": True,
        "wheel_dist_info_modes_canonical": True,
    }
    if materials_match:
        result = {"source_materials_match_sdist": True, **result}
    if source_record is not None:
        result = {"clean_sdist_matches_git_tree": sdist_git_tree_match, **result}
    if repository_root is not None:
        result = {
            "current_source_matches_sdist": True,
            "current_source_modes_match_sdist": True,
            "current_package_source_file_count": len(package_sources),
            **result,
        }
    return result


def _uv_version(uv_executable: str) -> str:
    candidate = shutil.which(uv_executable)
    if candidate is None:
        raise ReleaseEvidenceError("cannot locate the pinned uv exporter")
    executable = Path(candidate).resolve()
    try:
        before = executable.stat()
    except OSError as exc:
        raise ReleaseEvidenceError("cannot inspect the pinned uv exporter") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ReleaseEvidenceError("the pinned uv exporter is not a regular file")
    try:
        command = [str(executable), "--version"]
        result = _run_bounded_process(
            command,
            cwd=executable.parent,
            env=_uv_environment(),
            timeout=15,
            stdout_limit=4096,
            stderr_limit=4096,
            label="uv version response",
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                command,
                output=result.stdout,
                stderr=result.stderr,
            )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ReleaseEvidenceError("cannot execute the pinned uv exporter") from exc
    try:
        stdout = result.stdout.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseEvidenceError("uv version response is not UTF-8") from exc
    match = re.fullmatch(r"uv ([0-9]+(?:\.[0-9]+){2})(?: \([^\n]+\))?\n?", stdout)
    if not match:
        raise ReleaseEvidenceError("cannot parse uv version response")
    try:
        after = executable.stat()
    except OSError as exc:
        raise ReleaseEvidenceError("pinned uv disappeared after execution") from exc
    if _stat_observation(before) != _stat_observation(after):
        raise ReleaseEvidenceError("pinned uv changed while it was executed")
    return match.group(1)


def _uv_environment() -> dict[str, str]:
    """Return a minimal child environment with no uv/config/index/credential overrides."""
    allowed = ("LANG", "LC_ALL", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR")
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _observe_uv_executable(
    path: Path, *, label: str
) -> tuple[bytes, tuple[int, int, int, int, int, int]]:
    try:
        before = path.stat()
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ReleaseEvidenceError(f"{label} is not a regular file")
    if not before.st_mode & 0o111:
        raise ReleaseEvidenceError(f"{label} is not executable")
    payload = _read_regular(path, maximum=MAX_UV_EXECUTABLE_BYTES, label=label)
    try:
        after = path.stat()
    except OSError as exc:
        raise ReleaseEvidenceError(f"{label} disappeared while it was inspected") from exc
    observation = _stat_observation(before)
    if observation != _stat_observation(after):
        raise ReleaseEvidenceError(f"{label} changed while it was inspected")
    return payload, observation


def _revalidate_uv_executable(
    path: Path,
    *,
    expected_observation: tuple[int, int, int, int, int, int],
    expected_sha256: str,
    label: str,
) -> None:
    payload, observation = _observe_uv_executable(path, label=label)
    if observation != expected_observation or _sha256(payload) != expected_sha256:
        raise ReleaseEvidenceError(f"{label} changed while release evidence was generated")


@contextmanager
def _uv_executable_snapshot(uv_executable: str):
    candidate = shutil.which(uv_executable)
    if candidate is None:
        raise ReleaseEvidenceError("cannot locate the pinned uv exporter")
    original = Path(candidate).resolve()
    payload, original_observation = _observe_uv_executable(original, label="pinned uv exporter")
    payload_sha256 = _sha256(payload)
    with tempfile.TemporaryDirectory(prefix="artifactforge-pinned-uv-") as temporary:
        private_root = Path(temporary)
        os.chmod(private_root, 0o700)
        private = private_root / original.name
        _write_exclusive(private, payload, mode=0o500)
        os.chmod(private, 0o500)
        private_payload, private_observation = _observe_uv_executable(
            private, label="private uv exporter snapshot"
        )
        if private_payload != payload:
            raise ReleaseEvidenceError("private uv exporter snapshot differs from its source")
        snapshot = _UvExecutableSnapshot(
            original_path=original,
            original_observation=original_observation,
            private_path=private,
            private_observation=private_observation,
            payload_sha256=payload_sha256,
        )
        try:
            yield snapshot
        finally:
            _revalidate_uv_executable(
                snapshot.original_path,
                expected_observation=snapshot.original_observation,
                expected_sha256=snapshot.payload_sha256,
                label="pinned uv exporter",
            )
            _revalidate_uv_executable(
                snapshot.private_path,
                expected_observation=snapshot.private_observation,
                expected_sha256=snapshot.payload_sha256,
                label="private uv exporter snapshot",
            )


def _uv_export(repo: Path, uv_executable: str, *, include_dev: bool) -> dict[str, Any]:
    candidate = shutil.which(uv_executable)
    if candidate is None:
        raise ReleaseEvidenceError("cannot locate the pinned uv exporter")
    executable = str(Path(candidate).resolve())
    with tempfile.TemporaryDirectory(prefix="artifactforge-sbom-uv-") as cache:
        command = [
            executable,
            "export",
            "--cache-dir",
            cache,
            "--offline",
            "--locked",
            "--no-config",
            "--no-sources",
            "--project",
            str(repo),
            "--preview-features",
            "sbom-export",
            "--format",
            "cyclonedx1.5",
            "--no-dev",
        ]
        if include_dev:
            command.extend(("--extra", "dev"))
        try:
            result = _run_bounded_process(
                command,
                cwd=repo,
                env=_uv_environment(),
                timeout=60,
                stdout_limit=MAX_SBOM_BYTES,
                stderr_limit=64 * 1024,
                label="uv CycloneDX export",
            )
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    command,
                    output=result.stdout,
                    stderr=result.stderr,
                )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ReleaseEvidenceError("pinned uv could not export the frozen SBOM") from exc
    return _strict_json(result.stdout, label="uv CycloneDX export", maximum=MAX_SBOM_BYTES)


def _bound_uv_exports(
    repo: Path,
    uv_executable: str,
    *,
    runtime_repetitions: int,
    development_repetitions: int,
) -> tuple[str, str, list[dict[str, Any]], list[dict[str, Any]]]:
    if runtime_repetitions < 1 or development_repetitions < 1:
        raise ReleaseEvidenceError("uv export repetition counts must be positive")
    with _uv_executable_snapshot(uv_executable) as snapshot:
        private = str(snapshot.private_path)
        uv_version = _uv_version(private)
        if uv_version != EXPECTED_UV_VERSION:
            raise ReleaseEvidenceError(
                f"uv {EXPECTED_UV_VERSION} is required; observed {uv_version}"
            )
        runtime = [_uv_export(repo, private, include_dev=False) for _ in range(runtime_repetitions)]
        development = [
            _uv_export(repo, private, include_dev=True) for _ in range(development_repetitions)
        ]
        return uv_version, "sha256:" + snapshot.payload_sha256, runtime, development


def _normalized_ref(component: dict[str, Any], *, root: bool, version: str) -> str:
    if root:
        return f"pkg:pypi/artifactforge@{version}"
    purl = component.get("purl")
    if not isinstance(purl, str) or not purl.startswith("pkg:pypi/") or "@" not in purl:
        raise ReleaseEvidenceError("uv SBOM component lacks a stable PyPI package URL")
    return purl


def _sbom_properties(
    source: dict[str, Any],
    *,
    profile_name: str,
    subject: dict[str, Any] | None,
) -> list[dict[str, str]]:
    git_tree = _expect_string(source.get("git_tree"), "source.git_tree", maximum=64)
    properties = [
        {"name": "artifactforge:sbom:profile", "value": profile_name},
        {"name": "artifactforge:source:git-tree", "value": git_tree},
    ]
    materials = source.get("materials")
    if not isinstance(materials, list):
        raise ReleaseEvidenceError("source materials must be an array")
    material_map: dict[str, dict[str, Any]] = {}
    for item in materials:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            material_map[item["path"]] = item
    for material in ("uv.lock", "build-constraints.txt"):
        item = material_map.get(material)
        if item is None:
            raise ReleaseEvidenceError(f"source snapshot lacks {material}")
        properties.append(
            {
                "name": f"artifactforge:material:{material}:sha256",
                "value": _expect_sha256(item.get("sha256"), f"source material {material}"),
            }
        )
    if subject is not None:
        name = _expect_string(subject.get("name"), "subject.name", maximum=255)
        size = subject.get("size")
        if type(size) is not int or size < 0:
            raise ReleaseEvidenceError("subject.size must be a non-negative integer")
        properties.extend(
            (
                {"name": "artifactforge:distribution:name", "value": name},
                {"name": "artifactforge:distribution:size", "value": str(size)},
            )
        )
    return sorted(properties, key=lambda item: (item["name"], item["value"]))


def _component_properties(value: Any, *, where: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ReleaseEvidenceError(f"{where} properties must be an array")
    result: list[dict[str, str]] = []
    for index, item in enumerate(value):
        row = _expect_keys(item, {"name", "value"}, f"{where}.properties[{index}]")
        name = _expect_string(row["name"], f"{where}.properties[{index}].name", maximum=256)
        text = _expect_string(row["value"], f"{where}.properties[{index}].value", maximum=4096)
        if name != "uv:package:marker":
            raise ReleaseEvidenceError(f"{where} has an unexpected component property")
        result.append({"name": name, "value": text})
    ordered = sorted(result, key=lambda item: (item["name"], item["value"]))
    if result != ordered or len({(item["name"], item["value"]) for item in result}) != len(result):
        raise ReleaseEvidenceError(f"{where} properties must be sorted and unique")
    return result


def _normalize_uv_sbom(
    raw: dict[str, Any],
    *,
    profile_name: str,
    source: dict[str, Any],
    project_version: str,
    uv_version: str,
    subject: dict[str, Any] | None,
) -> dict[str, Any]:
    _expect_keys(
        raw,
        {
            "bomFormat",
            "specVersion",
            "version",
            "serialNumber",
            "metadata",
            "components",
            "dependencies",
        },
        "uv SBOM",
    )
    if raw["bomFormat"] != "CycloneDX" or raw["specVersion"] != CYCLONEDX_SPEC_VERSION:
        raise ReleaseEvidenceError("uv emitted an unexpected CycloneDX version")
    if (
        type(raw["version"]) is not int
        or raw["version"] != 1
        or not isinstance(raw["components"], list)
    ):
        raise ReleaseEvidenceError("uv emitted an invalid CycloneDX document")
    _expect_string(raw["serialNumber"], "uv SBOM serialNumber", maximum=64)
    metadata = _expect_keys(raw["metadata"], {"timestamp", "tools", "component"}, "uv metadata")
    _expect_string(metadata["timestamp"], "uv metadata.timestamp", maximum=64)
    if metadata["tools"] != [
        {"vendor": "Astral Software Inc.", "name": "uv", "version": uv_version}
    ]:
        raise ReleaseEvidenceError("uv SBOM creation tool identity is wrong")
    raw_root = _expect_keys(
        metadata["component"],
        {"type", "bom-ref", "name", "version", "properties"},
        "uv root component",
    )
    if (
        raw_root["type"] != "library"
        or raw_root["name"] != "artifactforge"
        or raw_root["version"] != project_version
        or raw_root["properties"] != [{"name": "uv:package:is_project_root", "value": "true"}]
    ):
        raise ReleaseEvidenceError("uv SBOM root does not match this project")
    old_root = _expect_string(raw_root.get("bom-ref"), "uv root bom-ref", maximum=512)
    root_ref = _normalized_ref(raw_root, root=True, version=project_version)
    ref_map = {old_root: root_ref}
    components: list[dict[str, Any]] = []
    seen_refs = {root_ref}
    for index, item in enumerate(raw["components"]):
        if not isinstance(item, dict):
            raise ReleaseEvidenceError(f"uv SBOM component {index} is not an object")
        allowed = {"type", "bom-ref", "name", "version", "purl"}
        if "properties" in item:
            allowed.add("properties")
        component = _expect_keys(item, allowed, f"uv component {index}")
        name = _expect_string(component.get("name"), "uv component name", maximum=256)
        component_version = _expect_string(
            component.get("version"), "uv component version", maximum=256
        )
        if component.get("type") != "library":
            raise ReleaseEvidenceError("uv SBOM component is not a library")
        old_ref = _expect_string(component.get("bom-ref"), "uv component bom-ref", maximum=512)
        new_ref = _normalized_ref(component, root=False, version=project_version)
        if new_ref != f"pkg:pypi/{name}@{component_version}":
            raise ReleaseEvidenceError("uv SBOM component purl/name/version are inconsistent")
        if new_ref in seen_refs or old_ref in ref_map:
            raise ReleaseEvidenceError("uv SBOM has duplicate component identity")
        seen_refs.add(new_ref)
        ref_map[old_ref] = new_ref
        normalized_component: dict[str, Any] = {
            "type": "library",
            "bom-ref": new_ref,
            "name": name,
            "version": component_version,
            "purl": new_ref,
            "scope": "optional",
        }
        if "properties" in component:
            normalized_component["properties"] = _component_properties(
                component["properties"], where=f"uv component {index}"
            )
        components.append(normalized_component)
    components.sort(key=lambda component: component["bom-ref"])
    dependencies: list[dict[str, Any]] = []
    raw_dependencies = raw["dependencies"]
    if not isinstance(raw_dependencies, list):
        raise ReleaseEvidenceError("uv SBOM dependencies must be an array")
    for item in raw_dependencies:
        if not isinstance(item, dict) or set(item) not in ({"ref"}, {"ref", "dependsOn"}):
            raise ReleaseEvidenceError("uv SBOM dependency has unexpected members")
        old_dependency_ref = _expect_string(item.get("ref"), "uv SBOM dependency ref", maximum=512)
        ref = ref_map.get(old_dependency_ref)
        if ref is None:
            raise ReleaseEvidenceError("uv SBOM dependency references an unknown component")
        depends_on = item.get("dependsOn", [])
        if not isinstance(depends_on, list):
            raise ReleaseEvidenceError("uv SBOM dependsOn must be an array")
        mapped = []
        for child in depends_on:
            old_child_ref = _expect_string(child, "uv SBOM dependsOn ref", maximum=512)
            if old_child_ref not in ref_map:
                raise ReleaseEvidenceError("uv SBOM dependency edge is dangling")
            mapped.append(ref_map[old_child_ref])
        if ref in mapped or len(mapped) != len(set(mapped)):
            raise ReleaseEvidenceError("uv SBOM dependency edges must be unique and non-self")
        row: dict[str, Any] = {"ref": ref}
        if mapped:
            row["dependsOn"] = sorted(mapped)
        dependencies.append(row)
    dependencies.sort(key=lambda item: item["ref"])
    if {item["ref"] for item in dependencies} != seen_refs:
        raise ReleaseEvidenceError("uv SBOM dependency rows do not cover every component")
    root: dict[str, Any] = {
        "type": "library",
        "bom-ref": root_ref,
        "name": "artifactforge",
        "version": project_version,
        "purl": root_ref,
        "licenses": [{"license": {"id": "MIT"}}],
    }
    if subject is not None:
        digest = _expect_sha256(subject.get("sha256"), "subject.sha256")
        root["hashes"] = [{"alg": "SHA-256", "content": digest[7:]}]
    root["properties"] = _sbom_properties(source, profile_name=profile_name, subject=subject)
    document: dict[str, Any] = {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "lifecycles": [{"phase": "post-build" if subject is not None else "build"}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "uv",
                        "version": uv_version,
                    },
                    {
                        "type": "application",
                        "name": "artifactforge-release-evidence",
                        "version": __version__,
                    },
                ]
            },
            "component": root,
        },
        "components": components,
        "dependencies": dependencies,
    }
    identity = hashlib.sha256(_canonical_bytes(document)).hexdigest()
    document["serialNumber"] = "urn:uuid:" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"https://artifactforge.dev/sbom/v1/{identity}")
    )
    validate_cyclonedx(
        document,
        profile_name=profile_name,
        subject=subject,
        source=source,
        project_version=project_version,
    )
    return document


def validate_cyclonedx(
    document: Any,
    *,
    profile_name: str,
    subject: dict[str, Any] | None,
    source: dict[str, Any],
    project_version: str,
) -> None:
    expected_top = {
        "$schema",
        "bomFormat",
        "specVersion",
        "serialNumber",
        "version",
        "metadata",
        "components",
        "dependencies",
    }
    doc = _expect_keys(document, expected_top, "CycloneDX document")
    if (
        doc["$schema"] != CYCLONEDX_SCHEMA
        or doc["bomFormat"] != "CycloneDX"
        or doc["specVersion"] != CYCLONEDX_SPEC_VERSION
        or type(doc["version"]) is not int
        or doc["version"] != 1
    ):
        raise ReleaseEvidenceError("CycloneDX document identity is wrong")
    if not re.fullmatch(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        doc["serialNumber"] if isinstance(doc["serialNumber"], str) else "",
    ):
        raise ReleaseEvidenceError("CycloneDX serialNumber is not an RFC 4122 UUID URN")
    unsigned = dict(doc)
    serial_number = unsigned.pop("serialNumber")
    identity = hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    expected_serial = "urn:uuid:" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"https://artifactforge.dev/sbom/v1/{identity}")
    )
    if serial_number != expected_serial:
        raise ReleaseEvidenceError("CycloneDX serialNumber does not bind the canonical document")
    metadata = _expect_keys(
        doc["metadata"], {"lifecycles", "tools", "component"}, "CycloneDX metadata"
    )
    expected_tools = {
        "components": [
            {"type": "application", "name": "uv", "version": EXPECTED_UV_VERSION},
            {
                "type": "application",
                "name": "artifactforge-release-evidence",
                "version": __version__,
            },
        ]
    }
    if metadata.get("tools") != expected_tools:
        raise ReleaseEvidenceError("CycloneDX creation tools are inconsistent")
    expected_phase = "post-build" if subject is not None else "build"
    if metadata["lifecycles"] != [{"phase": expected_phase}]:
        raise ReleaseEvidenceError("CycloneDX lifecycle is inconsistent")
    root_ref = f"pkg:pypi/artifactforge@{project_version}"
    expected_root: dict[str, Any] = {
        "type": "library",
        "bom-ref": root_ref,
        "name": "artifactforge",
        "version": project_version,
        "purl": root_ref,
        "licenses": [{"license": {"id": "MIT"}}],
        "properties": _sbom_properties(source, profile_name=profile_name, subject=subject),
    }
    if subject is not None:
        digest = _expect_sha256(subject.get("sha256"), "subject.sha256")
        expected_root["hashes"] = [{"alg": "SHA-256", "content": digest[7:]}]
    if metadata["component"] != expected_root:
        raise ReleaseEvidenceError("CycloneDX root identity/properties are inconsistent")
    components = doc["components"]
    dependencies = doc["dependencies"]
    if not isinstance(components, list) or not isinstance(dependencies, list):
        raise ReleaseEvidenceError("CycloneDX components/dependencies must be arrays")
    refs = [root_ref]
    component_refs: list[str] = []
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ReleaseEvidenceError("CycloneDX component is not an object")
        expected_keys = {"type", "bom-ref", "name", "version", "purl", "scope"}
        if "properties" in component:
            expected_keys.add("properties")
        _expect_keys(component, expected_keys, f"CycloneDX components[{index}]")
        name = _expect_string(component["name"], "CycloneDX component name", maximum=256)
        version = _expect_string(component["version"], "CycloneDX component version", maximum=256)
        if (
            component["type"] != "library"
            or component["scope"] != "optional"
            or component["bom-ref"] != component["purl"]
            or component["purl"] != f"pkg:pypi/{name}@{version}"
        ):
            raise ReleaseEvidenceError("CycloneDX component lacks stable matching ref/purl")
        if "properties" in component:
            _component_properties(component["properties"], where=f"CycloneDX components[{index}]")
        component_refs.append(component["bom-ref"])
        refs.append(component["bom-ref"])
    if component_refs != sorted(component_refs):
        raise ReleaseEvidenceError("CycloneDX components are not canonically ordered")
    if len(refs) != len(set(refs)):
        raise ReleaseEvidenceError("CycloneDX bom-ref values are not unique")
    dependency_refs: list[str] = []
    graph: dict[str, list[str]] = {}
    for row in dependencies:
        if not isinstance(row, dict) or set(row) not in ({"ref"}, {"ref", "dependsOn"}):
            raise ReleaseEvidenceError("CycloneDX dependency row is malformed")
        if row.get("ref") not in refs:
            raise ReleaseEvidenceError("CycloneDX dependency row has a dangling ref")
        dependency_refs.append(row["ref"])
        children = row.get("dependsOn", [])
        if not isinstance(children, list):
            raise ReleaseEvidenceError("CycloneDX dependsOn is malformed")
        typed_children = [
            _expect_string(child, "CycloneDX dependsOn reference", maximum=512)
            for child in children
        ]
        if (
            children != sorted(typed_children)
            or len(children) != len(set(children))
            or row["ref"] in children
        ):
            raise ReleaseEvidenceError("CycloneDX dependsOn is malformed")
        if any(child not in refs for child in children):
            raise ReleaseEvidenceError("CycloneDX dependsOn edge is dangling")
        graph[row["ref"]] = children
    if set(dependency_refs) != set(refs) or len(dependency_refs) != len(refs):
        raise ReleaseEvidenceError("CycloneDX dependency graph does not cover each component once")
    if dependency_refs != sorted(dependency_refs):
        raise ReleaseEvidenceError("CycloneDX dependency rows are not canonically ordered")
    reachable = {root_ref}
    pending = [root_ref]
    while pending:
        current = pending.pop()
        for child in graph[current]:
            if child not in reachable:
                reachable.add(child)
                pending.append(child)
    if reachable != set(refs):
        raise ReleaseEvidenceError("CycloneDX contains components unreachable from the project")
    if profile_name == "runtime-distribution":
        if subject is None:
            raise ReleaseEvidenceError("runtime distribution SBOM must bind a distribution subject")
        if components or dependencies != [{"ref": root_ref}]:
            raise ReleaseEvidenceError(
                "runtime distribution SBOM must have an empty dependency closure"
            )
    elif profile_name == "development-oracle-closure":
        if subject is not None:
            raise ReleaseEvidenceError(
                "development-oracle SBOM must not bind a distribution subject"
            )
        component_by_ref = {component["bom-ref"]: component for component in components}
        direct_refs = graph[root_ref]
        direct_names = [
            _requirement_identity(
                component_by_ref[ref]["name"], where="development SBOM direct requirement"
            )[0]
            for ref in direct_refs
        ]
        expected_direct_names = {
            name
            for name, _specifiers in _requirement_contract(
                EXPECTED_DEV_REQUIREMENTS, where="expected dev requirements"
            )
        }
        if len(direct_names) != len(set(direct_names)):
            raise ReleaseEvidenceError(
                "development SBOM root repeats a normalized direct requirement"
            )
        if set(direct_names) != expected_direct_names:
            raise ReleaseEvidenceError(
                "development SBOM root does not contain the exact direct requirement set"
            )
    else:
        raise ReleaseEvidenceError("CycloneDX profile is not a recognized release profile")


def _write_exclusive(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ReleaseEvidenceError(f"short write while publishing {path}")
            view = view[written:]
        os.fsync(fd)
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size != len(payload):
            raise ReleaseEvidenceError(f"published file failed its postcondition: {path}")
    finally:
        os.close(fd)
    readback = _read_regular(path, maximum=max(len(payload), 1), label="published evidence")
    if readback != payload:
        raise ReleaseEvidenceError(f"published file readback mismatch: {path}")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except (NotImplementedError, OSError) as exc:
        raise ReleaseEvidenceError(
            f"cannot open evidence directory for durability: {path}"
        ) from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ReleaseEvidenceError(f"evidence path is not a directory: {path}")
        os.fsync(descriptor)
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot make evidence directory durable: {path}") from exc
    finally:
        os.close(descriptor)


def _remove_stage_if_owned(
    stage: Path,
    *,
    parent_fd: int,
    expected_identity: tuple[int, int],
) -> None:
    """Remove only the unpublished staging inode created by this process."""
    try:
        anchored = os.stat(stage.name, dir_fd=parent_fd, follow_symlinks=False)
        lexical = stage.lstat()
    except (NotImplementedError, OSError):
        return
    if (
        stat.S_ISDIR(anchored.st_mode)
        and stat.S_ISDIR(lexical.st_mode)
        and (anchored.st_dev, anchored.st_ino) == expected_identity
        and (lexical.st_dev, lexical.st_ino) == expected_identity
    ):
        shutil.rmtree(stage, ignore_errors=True)


def _bundle_inventory(root: Path) -> list[str]:
    try:
        inventory = inventory_regular_files(
            root,
            max_files=8,
            max_file_bytes=MAX_DISTRIBUTION_BYTES,
            max_total_bytes=(2 * MAX_DISTRIBUTION_BYTES) + (3 * MAX_SBOM_BYTES) + (2 * 1024 * 1024),
            max_depth=2,
        )
    except InventoryError as exc:
        raise ReleaseEvidenceError(f"release evidence inventory is unsafe: {exc}") from exc
    return [item.relative_path for item in inventory]


def _subject_record(name: str, payload: bytes, kind: str) -> dict[str, Any]:
    return {"kind": kind, "name": name, "sha256": _sha256_field(payload), "size": len(payload)}


def _expect_int(
    value: Any,
    where: str,
    *,
    minimum: int = 0,
    maximum: int = 1_000_000_000,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReleaseEvidenceError(f"{where} must be an integer in [{minimum}, {maximum}]")
    return value


def _expect_true(value: Any, where: str) -> None:
    if value is not True:
        raise ReleaseEvidenceError(f"{where} must be true")


def _validate_source_record(value: Any) -> dict[str, Any]:
    source = _expect_keys(
        value,
        {
            "schema",
            "git_commit",
            "git_tree",
            "worktree_clean",
            "dirty_snapshot_sha256",
            "untracked_file_count",
            "materials",
        },
        "source",
    )
    if source["schema"] != "artifactforge-source-provenance-v1":
        raise ReleaseEvidenceError("source schema identity is wrong")
    for field in ("git_commit", "git_tree"):
        identifier = _expect_string(source[field], f"source.{field}", maximum=64)
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", identifier):
            raise ReleaseEvidenceError(f"source.{field} is not a canonical Git object id")
    if type(source["worktree_clean"]) is not bool:
        raise ReleaseEvidenceError("source.worktree_clean must be boolean")
    untracked_count = _expect_int(source["untracked_file_count"], "source.untracked_file_count")
    dirty = source["dirty_snapshot_sha256"]
    if source["worktree_clean"]:
        if dirty is not None or untracked_count != 0:
            raise ReleaseEvidenceError("clean source carries dirty-worktree observations")
    elif dirty is None:
        raise ReleaseEvidenceError("dirty source lacks a dirty snapshot digest")
    else:
        _expect_sha256(dirty, "source.dirty_snapshot_sha256")
    materials = source["materials"]
    if not isinstance(materials, list) or len(materials) != len(_MATERIAL_NAMES):
        raise ReleaseEvidenceError("source materials do not match the required inventory")
    observed_paths: list[str] = []
    for index, item in enumerate(materials):
        row = _expect_keys(item, {"path", "sha256", "size"}, f"source.materials[{index}]")
        path = _expect_string(row["path"], f"source.materials[{index}].path", maximum=255)
        _safe_relative_name(path, "source material path")
        observed_paths.append(path)
        _expect_sha256(row["sha256"], f"source.materials[{index}].sha256")
        _expect_int(row["size"], f"source.materials[{index}].size", maximum=MAX_DISTRIBUTION_BYTES)
    if observed_paths != list(_MATERIAL_NAMES):
        raise ReleaseEvidenceError("source materials are missing, reordered, or unexpected")
    return source


def _validate_package_metadata_record(
    value: Any,
    *,
    where: str,
    version: str,
) -> None:
    metadata = _expect_keys(
        value,
        {
            "name",
            "version",
            "requires_python",
            "runtime_dependency_count",
            "optional_requirement_count",
        },
        where,
    )
    if (
        metadata["name"] != "artifactforge"
        or metadata["version"] != version
        or metadata["requires_python"] != ">=3.11"
    ):
        raise ReleaseEvidenceError(f"{where} package identity is wrong")
    if (
        type(metadata["runtime_dependency_count"]) is not int
        or metadata["runtime_dependency_count"] != 0
    ):
        raise ReleaseEvidenceError(f"{where} claims runtime dependencies")
    if type(metadata["optional_requirement_count"]) is not int or metadata[
        "optional_requirement_count"
    ] != len(EXPECTED_DEV_REQUIREMENTS):
        raise ReleaseEvidenceError(f"{where} optional requirement count is wrong")


def _validate_build_and_validation(manifest: dict[str, Any]) -> str:
    build = _expect_keys(manifest["build"], {"supplied_distribution_root_count", "tools"}, "build")
    if (
        type(build["supplied_distribution_root_count"]) is not int
        or build["supplied_distribution_root_count"] != 2
    ):
        raise ReleaseEvidenceError("build must bind exactly two distribution roots")
    tools = _expect_keys(
        build["tools"],
        {
            "artifactforge",
            "python",
            "python_implementation",
            "uv",
            "uv_executable_sha256",
            "wheel_generator",
        },
        "build.tools",
    )
    version = _expect_string(tools["artifactforge"], "build.tools.artifactforge", maximum=128)
    if version != __version__:
        raise ReleaseEvidenceError("release evidence was not made for this ArtifactForge version")
    python_version = _expect_string(tools["python"], "build.tools.python", maximum=64)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", python_version):
        raise ReleaseEvidenceError("build Python version is not canonical")
    if tools["python_implementation"] != "CPython":
        raise ReleaseEvidenceError("release evidence requires a CPython build")
    if tools["uv"] != EXPECTED_UV_VERSION or tools["wheel_generator"] != EXPECTED_WHEEL_GENERATOR:
        raise ReleaseEvidenceError("build tools differ from the pinned release toolchain")
    _expect_sha256(tools["uv_executable_sha256"], "build.tools.uv_executable_sha256")

    validation = _expect_keys(
        manifest["validation"],
        {
            "byte_identical_supplied_distributions",
            "distinct_distribution_input_inodes",
            "runtime_dependency_count",
            "wheel",
            "sdist",
            "distribution_chain",
            "normalized_sbom_repetitions",
            "development_component_count",
        },
        "validation",
    )
    _expect_true(
        validation["byte_identical_supplied_distributions"],
        "validation.byte_identical_supplied_distributions",
    )
    _expect_true(
        validation["distinct_distribution_input_inodes"],
        "validation.distinct_distribution_input_inodes",
    )
    if (
        type(validation["runtime_dependency_count"]) is not int
        or validation["runtime_dependency_count"] != 0
    ):
        raise ReleaseEvidenceError("validation runtime dependency count is wrong")
    if (
        type(validation["normalized_sbom_repetitions"]) is not int
        or validation["normalized_sbom_repetitions"] != 2
    ):
        raise ReleaseEvidenceError("SBOM repetition count is wrong")
    _expect_int(
        validation["development_component_count"],
        "validation.development_component_count",
        minimum=1,
        maximum=MAX_ARCHIVE_MEMBERS,
    )

    wheel = _expect_keys(
        validation["wheel"],
        {
            "archive_member_count",
            "expanded_bytes",
            "member_timestamp_utc",
            "metadata",
            "record_verified",
            "wheel_generator",
            "wheel_tag",
            "package_metadata_sha256",
            "wheel_descriptor_sha256",
        },
        "validation.wheel",
    )
    _expect_int(wheel["archive_member_count"], "validation.wheel.archive_member_count", minimum=1)
    _expect_int(
        wheel["expanded_bytes"],
        "validation.wheel.expanded_bytes",
        maximum=MAX_ARCHIVE_EXPANDED_BYTES,
    )
    if (
        wheel["member_timestamp_utc"] != EXPECTED_ARCHIVE_TIMESTAMP
        or wheel["record_verified"] is not True
        or wheel["wheel_generator"] != EXPECTED_WHEEL_GENERATOR
        or wheel["wheel_tag"] != "py3-none-any"
    ):
        raise ReleaseEvidenceError("wheel validation profile is wrong")
    _expect_sha256(wheel["package_metadata_sha256"], "validation.wheel.package_metadata_sha256")
    _expect_sha256(wheel["wheel_descriptor_sha256"], "validation.wheel.wheel_descriptor_sha256")
    _validate_package_metadata_record(
        wheel["metadata"], where="validation.wheel.metadata", version=version
    )

    sdist = _expect_keys(
        validation["sdist"],
        {
            "archive_member_count",
            "expanded_bytes",
            "gzip_timestamp_utc",
            "member_timestamp_utc",
            "metadata",
            "single_root",
        },
        "validation.sdist",
    )
    _expect_int(sdist["archive_member_count"], "validation.sdist.archive_member_count", minimum=1)
    _expect_int(
        sdist["expanded_bytes"],
        "validation.sdist.expanded_bytes",
        maximum=MAX_ARCHIVE_EXPANDED_BYTES,
    )
    if (
        sdist["gzip_timestamp_utc"] != EXPECTED_ARCHIVE_TIMESTAMP
        or sdist["member_timestamp_utc"] != EXPECTED_ARCHIVE_TIMESTAMP
        or sdist["single_root"] != f"artifactforge-{version}"
    ):
        raise ReleaseEvidenceError("sdist validation profile is wrong")
    _validate_package_metadata_record(
        sdist["metadata"], where="validation.sdist.metadata", version=version
    )

    chain = _expect_keys(
        validation["distribution_chain"],
        {
            "current_source_matches_sdist",
            "current_source_modes_match_sdist",
            "clean_sdist_matches_git_tree",
            "source_materials_match_sdist",
            "sdist_source_file_count",
            "sdist_package_source_file_count",
            "locked_development_component_count",
            "locked_development_graph_sha256",
            "current_package_source_file_count",
            "wheel_package_file_count",
            "wheel_package_matches_sdist",
            "wheel_package_modes_match_sdist",
            "wheel_metadata_matches_sdist",
            "wheel_entry_point_matches_pyproject",
            "wheel_license_matches_sdist",
            "wheel_dist_info_modes_canonical",
        },
        "validation.distribution_chain",
    )
    for key in (
        "current_source_matches_sdist",
        "current_source_modes_match_sdist",
        "source_materials_match_sdist",
        "wheel_package_matches_sdist",
        "wheel_package_modes_match_sdist",
        "wheel_metadata_matches_sdist",
        "wheel_entry_point_matches_pyproject",
        "wheel_license_matches_sdist",
        "wheel_dist_info_modes_canonical",
    ):
        _expect_true(chain[key], f"validation.distribution_chain.{key}")
    if manifest["source"]["worktree_clean"]:
        _expect_true(
            chain["clean_sdist_matches_git_tree"],
            "validation.distribution_chain.clean_sdist_matches_git_tree",
        )
    elif chain["clean_sdist_matches_git_tree"] is not None:
        raise ReleaseEvidenceError("dirty source cannot claim a clean Git-tree reconstruction")
    for key in (
        "sdist_source_file_count",
        "sdist_package_source_file_count",
        "locked_development_component_count",
        "current_package_source_file_count",
        "wheel_package_file_count",
    ):
        _expect_int(
            chain[key],
            f"validation.distribution_chain.{key}",
            minimum=1,
            maximum=MAX_ARCHIVE_MEMBERS,
        )
    _expect_sha256(
        chain["locked_development_graph_sha256"],
        "validation.distribution_chain.locked_development_graph_sha256",
    )
    if not (
        chain["current_package_source_file_count"]
        == chain["sdist_package_source_file_count"]
        == chain["wheel_package_file_count"]
    ):
        raise ReleaseEvidenceError("source/sdist/wheel package file counts disagree")
    if chain["locked_development_component_count"] != validation["development_component_count"]:
        raise ReleaseEvidenceError("development SBOM/lock component counts disagree")
    return version


def create_release_evidence(
    primary_dist: str | os.PathLike[str],
    comparison_dist: str | os.PathLike[str],
    output: str | os.PathLike[str],
    *,
    repository_root: str | os.PathLike[str] = _REPOSITORY_ROOT,
    uv_executable: str = "uv",
    allow_dirty: bool = False,
) -> dict[str, Any]:
    repo = Path(repository_root).resolve()
    # Resolve existing parent aliases once before any staging operation.  macOS exposes /tmp as
    # a system symlink to /private/tmp; retaining the lexical parent would reject that normal
    # safe case while adding no protection because publication already targets the resolved
    # directory inode.
    output_path = Path(output).resolve(strict=False)
    try:
        output_path.resolve().relative_to(repo)
    except ValueError:
        pass
    else:
        raise ReleaseEvidenceError("release evidence output must be outside the source repository")
    if output_path.exists() or output_path.is_symlink():
        raise ReleaseEvidenceError("release evidence destination already exists")
    parent = output_path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ReleaseEvidenceError("release evidence parent must be a real directory")
    source = source_snapshot(repo)
    if not source["worktree_clean"] and not allow_dirty:
        raise ReleaseEvidenceError(
            "refusing release evidence from a dirty worktree; use --allow-dirty only for a "
            "non-release diagnostic"
        )
    project_name, project_version = _project_metadata(repo)
    if project_name != "artifactforge":
        raise ReleaseEvidenceError("release evidence supports only ArtifactForge")
    primary_path = Path(primary_dist)
    comparison_path = Path(comparison_dist)
    first = _distribution_files(primary_path)
    second = _distribution_files(comparison_path)
    if set(first.files) != set(second.files):
        raise ReleaseEvidenceError("supplied distribution roots contain different subject names")
    _require_distinct_distribution_inputs(first, second)
    mismatches = [name for name in sorted(first.files) if first.files[name] != second.files[name]]
    if mismatches:
        raise ReleaseEvidenceError(f"supplied distributions are not byte-identical: {mismatches}")
    wheel_name = next(name for name in first.files if name.endswith(".whl"))
    sdist_name = next(name for name in first.files if name.endswith(".tar.gz"))
    if f"-{project_version}-" not in wheel_name or f"-{project_version}.tar.gz" not in sdist_name:
        raise ReleaseEvidenceError("distribution filenames do not match the project version")
    wheel_validation = _inspect_wheel(wheel_name, first.files[wheel_name], version=project_version)
    sdist_validation = _inspect_sdist(sdist_name, first.files[sdist_name], version=project_version)
    distribution_chain = _bind_distribution_chain(
        first.files[wheel_name],
        first.files[sdist_name],
        version=project_version,
        repository_root=repo,
        source_record=source,
    )
    development_lock = _locked_development_contract(
        _validated_sdist_member(
            first.files[sdist_name],
            version=project_version,
            relative="uv.lock",
            maximum=MAX_LOCK_BYTES,
        ),
        project_version=project_version,
    )
    subjects = [
        _subject_record(sdist_name, first.files[sdist_name], "sdist"),
        _subject_record(wheel_name, first.files[wheel_name], "wheel"),
    ]
    subjects.sort(key=lambda item: item["name"])
    uv_version, uv_executable_sha256, runtime_exports, development_exports = _bound_uv_exports(
        repo,
        uv_executable,
        runtime_repetitions=2,
        development_repetitions=2,
    )
    runtime_raw_a, runtime_raw_b = runtime_exports
    dev_raw_a, dev_raw_b = development_exports
    sboms: dict[str, bytes] = {}
    for subject in subjects:
        normalized_a = _normalize_uv_sbom(
            runtime_raw_a,
            profile_name="runtime-distribution",
            source=source,
            project_version=project_version,
            uv_version=uv_version,
            subject=subject,
        )
        normalized_b = _normalize_uv_sbom(
            runtime_raw_b,
            profile_name="runtime-distribution",
            source=source,
            project_version=project_version,
            uv_version=uv_version,
            subject=subject,
        )
        first_bytes = _canonical_bytes(normalized_a)
        if first_bytes != _canonical_bytes(normalized_b):
            raise ReleaseEvidenceError("normalized runtime SBOM is not deterministic")
        sboms[f"sbom/{subject['kind']}.cdx.json"] = first_bytes
    dev_a = _normalize_uv_sbom(
        dev_raw_a,
        profile_name="development-oracle-closure",
        source=source,
        project_version=project_version,
        uv_version=uv_version,
        subject=None,
    )
    dev_b = _normalize_uv_sbom(
        dev_raw_b,
        profile_name="development-oracle-closure",
        source=source,
        project_version=project_version,
        uv_version=uv_version,
        subject=None,
    )
    _validate_development_sbom_against_lock(dev_a, development_lock)
    _validate_development_sbom_against_lock(dev_b, development_lock)
    dev_bytes = _canonical_bytes(dev_a)
    if dev_bytes != _canonical_bytes(dev_b):
        raise ReleaseEvidenceError("normalized development SBOM is not deterministic")
    if not dev_a["components"]:
        raise ReleaseEvidenceError("development-oracle SBOM unexpectedly has no components")
    sboms["sbom/development-oracles.cdx.json"] = dev_bytes
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(parent, parent_flags)
    except (NotImplementedError, OSError) as exc:
        raise ReleaseEvidenceError("cannot hold the release-evidence parent directory") from exc
    held_parent = os.fstat(parent_fd)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_path.name}.stage-", dir=parent))
    stage_info = stage.lstat()
    try:
        anchored_stage = os.stat(stage.name, dir_fd=parent_fd, follow_symlinks=False)
    except (NotImplementedError, OSError) as exc:
        os.close(parent_fd)
        raise ReleaseEvidenceError("cannot bind the evidence staging directory") from exc
    stage_identity = (stage_info.st_dev, stage_info.st_ino)
    if stage_identity != (anchored_stage.st_dev, anchored_stage.st_ino):
        os.close(parent_fd)
        raise ReleaseEvidenceError("release-evidence parent changed during staging")
    published = False
    try:
        os.chmod(stage, 0o700)
        (stage / "dist").mkdir(mode=0o700)
        (stage / "sbom").mkdir(mode=0o700)
        for subject in subjects:
            _write_exclusive(stage / "dist" / subject["name"], first.files[subject["name"]])
        for relative, payload in sorted(sboms.items()):
            _write_exclusive(stage.joinpath(*PurePosixPath(relative).parts), payload)
        checksum_rows = []
        byproducts = []
        for relative in sorted([f"dist/{item['name']}" for item in subjects] + list(sboms)):
            payload = _read_regular(
                stage.joinpath(*PurePosixPath(relative).parts),
                maximum=MAX_SBOM_BYTES if relative.startswith("sbom/") else MAX_DISTRIBUTION_BYTES,
                label="release-evidence byproduct",
            )
            digest = _sha256(payload)
            checksum_rows.append(f"{digest} *{relative}\n")
            byproducts.append(
                {"path": relative, "sha256": "sha256:" + digest, "size": len(payload)}
            )
        checksums = "".join(checksum_rows).encode("utf-8")
        _write_exclusive(stage / "checksums.txt", checksums)
        source_after = source_snapshot(repo)
        if source_after != source:
            raise ReleaseEvidenceError("source changed while release evidence was generated")
        manifest: dict[str, Any] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "verdict": "pass",
            "classification": CLASSIFICATION,
            "limitations": list(LIMITATIONS),
            "source": source,
            "build": {
                "supplied_distribution_root_count": 2,
                "tools": {
                    "artifactforge": project_version,
                    "python": platform.python_version(),
                    "python_implementation": platform.python_implementation(),
                    "uv": uv_version,
                    "uv_executable_sha256": uv_executable_sha256,
                    "wheel_generator": EXPECTED_WHEEL_GENERATOR,
                },
            },
            "subjects": subjects,
            "validation": {
                "byte_identical_supplied_distributions": True,
                "distinct_distribution_input_inodes": True,
                "runtime_dependency_count": 0,
                "wheel": wheel_validation,
                "sdist": sdist_validation,
                "distribution_chain": distribution_chain,
                "normalized_sbom_repetitions": 2,
                "development_component_count": len(dev_a["components"]),
            },
            "byproducts": byproducts,
            "checksums": {
                "path": "checksums.txt",
                "sha256": _sha256_field(checksums),
                "size": len(checksums),
            },
        }
        _write_exclusive(stage / "release-evidence.json", _canonical_bytes(manifest))
        expected_inventory = sorted(
            ["release-evidence.json", "checksums.txt"]
            + [f"dist/{item['name']}" for item in subjects]
            + list(sboms)
        )
        if _bundle_inventory(stage) != expected_inventory:
            raise ReleaseEvidenceError("staged evidence inventory is not closed")
        _fsync_directory(stage / "dist")
        _fsync_directory(stage / "sbom")
        _fsync_directory(stage)
        current_parent = parent.lstat()
        if (current_parent.st_dev, current_parent.st_ino) != (
            held_parent.st_dev,
            held_parent.st_ino,
        ):
            raise ReleaseEvidenceError("release-evidence parent changed before publication")
        try:
            rename_directory_no_replace(
                stage,
                output_path,
                parent_fd=parent_fd,
                expected_source=stage_identity,
            )
        except (FileExistsError, InventoryError) as exc:
            raise ReleaseEvidenceError(
                "cannot atomically publish release evidence without replacing a destination"
            ) from exc
        os.fsync(parent_fd)
        published = True
    finally:
        if not published:
            _remove_stage_if_owned(stage, parent_fd=parent_fd, expected_identity=stage_identity)
        os.close(parent_fd)
    verified = verify_release_evidence(
        output_path, repository_root=repo, uv_executable=uv_executable
    )
    if verified != manifest:
        raise ReleaseEvidenceError("published release evidence did not round-trip exactly")
    return manifest


def _load_manifest(root: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(
        root / "release-evidence.json", maximum=MAX_SBOM_BYTES, label="release manifest"
    )
    manifest = _strict_json(raw, label="release manifest", maximum=MAX_SBOM_BYTES)
    if _canonical_bytes(manifest) != raw:
        raise ReleaseEvidenceError("release manifest is not canonical JSON plus LF")
    keys = {
        "schema",
        "schema_version",
        "verdict",
        "classification",
        "limitations",
        "source",
        "build",
        "subjects",
        "validation",
        "byproducts",
        "checksums",
    }
    _expect_keys(manifest, keys, "release manifest")
    if (
        manifest["schema"] != SCHEMA
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != SCHEMA_VERSION
    ):
        raise ReleaseEvidenceError("release manifest schema identity is wrong")
    if manifest["verdict"] != "pass":
        raise ReleaseEvidenceError("release manifest is not a passing rehearsal")
    classification = _expect_keys(manifest["classification"], set(CLASSIFICATION), "classification")
    if classification["evidence_kind"] != CLASSIFICATION["evidence_kind"] or any(
        classification[key] is not False for key in CLASSIFICATION if key != "evidence_kind"
    ):
        raise ReleaseEvidenceError("release classification exceeds local evidence")
    if manifest["limitations"] != list(LIMITATIONS):
        raise ReleaseEvidenceError("release limitations differ from the fixed trust boundary")
    _validate_source_record(manifest["source"])
    _validate_build_and_validation(manifest)
    return manifest, raw


def verify_release_evidence(
    root: str | os.PathLike[str],
    *,
    repository_root: str | os.PathLike[str] | None = None,
    uv_executable: str = "uv",
) -> dict[str, Any]:
    root_path = Path(root)
    try:
        info = root_path.lstat()
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot inspect release evidence: {root_path}") from exc
    if not stat.S_ISDIR(info.st_mode) or root_path.is_symlink():
        raise ReleaseEvidenceError("release evidence root must be a real directory")
    manifest, _raw = _load_manifest(root_path)
    subjects = manifest["subjects"]
    if not isinstance(subjects, list) or len(subjects) != 2:
        raise ReleaseEvidenceError("release evidence must bind exactly wheel and sdist subjects")
    names: set[str] = set()
    subject_by_kind: dict[str, dict[str, Any]] = {}
    expected_files = {"release-evidence.json", "checksums.txt"}
    for index, subject in enumerate(subjects):
        row = _expect_keys(subject, {"kind", "name", "sha256", "size"}, f"subjects[{index}]")
        kind = _expect_string(row["kind"], f"subjects[{index}].kind", maximum=16)
        name = _expect_string(row["name"], f"subjects[{index}].name", maximum=255)
        _safe_relative_name(name, "distribution filename")
        if kind not in {"wheel", "sdist"} or kind in subject_by_kind or name in names:
            raise ReleaseEvidenceError("subject kinds/names must be unique wheel and sdist")
        if (kind == "wheel") != name.endswith(".whl"):
            raise ReleaseEvidenceError("subject kind and filename disagree")
        if (kind == "sdist") != name.endswith(".tar.gz"):
            raise ReleaseEvidenceError("subject kind and filename disagree")
        size = _expect_int(row["size"], f"subjects[{index}].size", maximum=MAX_DISTRIBUTION_BYTES)
        payload = _read_regular(
            root_path / "dist" / name,
            maximum=MAX_DISTRIBUTION_BYTES,
            label="release subject",
        )
        if size != len(payload) or _expect_sha256(row["sha256"], "subject.sha256") != _sha256_field(
            payload
        ):
            raise ReleaseEvidenceError(f"release subject digest/size mismatch: {name}")
        names.add(name)
        subject_by_kind[kind] = row
        expected_files.add(f"dist/{name}")
    if set(subject_by_kind) != {"wheel", "sdist"}:
        raise ReleaseEvidenceError("release evidence must contain wheel and sdist")
    if [subject["name"] for subject in subjects] != sorted(names):
        raise ReleaseEvidenceError("release subjects are not canonically ordered by filename")
    version = manifest["build"]["tools"]["artifactforge"]
    wheel_payload = _read_regular(
        root_path / "dist" / subject_by_kind["wheel"]["name"],
        maximum=MAX_DISTRIBUTION_BYTES,
        label="wheel",
    )
    sdist_payload = _read_regular(
        root_path / "dist" / subject_by_kind["sdist"]["name"],
        maximum=MAX_DISTRIBUTION_BYTES,
        label="sdist",
    )
    wheel_validation = _inspect_wheel(
        subject_by_kind["wheel"]["name"],
        wheel_payload,
        version=version,
    )
    sdist_validation = _inspect_sdist(
        subject_by_kind["sdist"]["name"],
        sdist_payload,
        version=version,
    )
    if manifest["validation"]["wheel"] != wheel_validation:
        raise ReleaseEvidenceError("wheel validation record is not reproducible")
    if manifest["validation"]["sdist"] != sdist_validation:
        raise ReleaseEvidenceError("sdist validation record is not reproducible")
    repository = Path(repository_root).resolve() if repository_root is not None else None
    distribution_chain = _bind_distribution_chain(
        wheel_payload,
        sdist_payload,
        version=version,
        repository_root=repository,
        source_record=manifest["source"],
    )
    development_lock = _locked_development_contract(
        _validated_sdist_member(
            sdist_payload,
            version=version,
            relative="uv.lock",
            maximum=MAX_LOCK_BYTES,
        ),
        project_version=version,
    )
    recorded_chain = manifest["validation"].get("distribution_chain")
    if not isinstance(recorded_chain, dict) or any(
        recorded_chain.get(key) != value for key, value in distribution_chain.items()
    ):
        raise ReleaseEvidenceError("distribution source chain does not reproduce")
    if manifest["validation"]["runtime_dependency_count"] != 0:
        raise ReleaseEvidenceError("release evidence claims runtime dependencies")
    for kind in ("wheel", "sdist"):
        relative = f"sbom/{kind}.cdx.json"
        payload = _read_regular(
            root_path / "sbom" / f"{kind}.cdx.json",
            maximum=MAX_SBOM_BYTES,
            label="runtime SBOM",
        )
        document = _strict_json(payload, label="runtime SBOM", maximum=MAX_SBOM_BYTES)
        if _canonical_bytes(document) != payload:
            raise ReleaseEvidenceError("runtime SBOM is not canonical JSON plus LF")
        validate_cyclonedx(
            document,
            profile_name="runtime-distribution",
            subject=subject_by_kind[kind],
            source=manifest["source"],
            project_version=version,
        )
        expected_files.add(relative)
    dev_relative = "sbom/development-oracles.cdx.json"
    dev_payload = _read_regular(
        root_path / "sbom" / "development-oracles.cdx.json",
        maximum=MAX_SBOM_BYTES,
        label="development SBOM",
    )
    dev_document = _strict_json(dev_payload, label="development SBOM", maximum=MAX_SBOM_BYTES)
    if _canonical_bytes(dev_document) != dev_payload:
        raise ReleaseEvidenceError("development SBOM is not canonical JSON plus LF")
    validate_cyclonedx(
        dev_document,
        profile_name="development-oracle-closure",
        subject=None,
        source=manifest["source"],
        project_version=version,
    )
    _validate_development_sbom_against_lock(dev_document, development_lock)
    if len(dev_document["components"]) != manifest["validation"]["development_component_count"]:
        raise ReleaseEvidenceError("development SBOM component count is inconsistent")
    expected_files.add(dev_relative)
    byproducts = manifest["byproducts"]
    if not isinstance(byproducts, list):
        raise ReleaseEvidenceError("byproducts must be an array")
    for index, item in enumerate(byproducts):
        row = _expect_keys(item, {"path", "sha256", "size"}, f"byproducts[{index}]")
        _safe_relative_name(
            _expect_string(row["path"], f"byproducts[{index}].path", maximum=512),
            "byproduct path",
        )
        _expect_sha256(row["sha256"], f"byproducts[{index}].sha256")
        _expect_int(
            row["size"],
            f"byproducts[{index}].size",
            maximum=max(MAX_SBOM_BYTES, MAX_DISTRIBUTION_BYTES),
        )
    observed_byproducts = []
    checksum_rows = []
    for relative in sorted(expected_files - {"release-evidence.json", "checksums.txt"}):
        pure = _safe_relative_name(relative, "byproduct path")
        maximum = MAX_SBOM_BYTES if relative.startswith("sbom/") else MAX_DISTRIBUTION_BYTES
        payload = _read_regular(
            root_path.joinpath(*pure.parts), maximum=maximum, label="release byproduct"
        )
        digest = _sha256(payload)
        observed_byproducts.append(
            {"path": relative, "sha256": "sha256:" + digest, "size": len(payload)}
        )
        checksum_rows.append(f"{digest} *{relative}\n")
    if byproducts != observed_byproducts:
        raise ReleaseEvidenceError("byproduct inventory/digests do not reproduce")
    expected_checksums = "".join(checksum_rows).encode("utf-8")
    actual_checksums = _read_regular(
        root_path / "checksums.txt", maximum=1024 * 1024, label="checksums"
    )
    if actual_checksums != expected_checksums:
        raise ReleaseEvidenceError("checksums.txt is not canonical or does not match the bundle")
    checksums_record = _expect_keys(
        manifest["checksums"], {"path", "sha256", "size"}, "checksums record"
    )
    _expect_sha256(checksums_record["sha256"], "checksums.sha256")
    _expect_int(checksums_record["size"], "checksums.size", maximum=1024 * 1024)
    if checksums_record != {
        "path": "checksums.txt",
        "sha256": _sha256_field(actual_checksums),
        "size": len(actual_checksums),
    }:
        raise ReleaseEvidenceError("checksums record does not bind checksums.txt")
    if _bundle_inventory(root_path) != sorted(expected_files):
        raise ReleaseEvidenceError("release evidence contains an undeclared file")
    if repository_root is not None:
        current = source_snapshot(repository)
        if current != manifest["source"]:
            raise ReleaseEvidenceError("release evidence source does not match the repository")
        uv_version, uv_sha256, runtime_exports, development_exports = _bound_uv_exports(
            repository,
            uv_executable,
            runtime_repetitions=1,
            development_repetitions=1,
        )
        if uv_sha256 != manifest["build"]["tools"]["uv_executable_sha256"]:
            raise ReleaseEvidenceError("pinned uv exporter digest differs from release evidence")
        runtime_raw = runtime_exports[0]
        for kind in ("wheel", "sdist"):
            expected = _canonical_bytes(
                _normalize_uv_sbom(
                    runtime_raw,
                    profile_name="runtime-distribution",
                    source=current,
                    project_version=version,
                    uv_version=uv_version,
                    subject=subject_by_kind[kind],
                )
            )
            observed = _read_regular(
                root_path / "sbom" / f"{kind}.cdx.json",
                maximum=MAX_SBOM_BYTES,
                label="runtime SBOM",
            )
            if observed != expected:
                raise ReleaseEvidenceError(
                    "runtime SBOM does not match a fresh locked no-source uv export"
                )
        expected_dev = _canonical_bytes(
            _normalize_uv_sbom(
                development_exports[0],
                profile_name="development-oracle-closure",
                source=current,
                project_version=version,
                uv_version=uv_version,
                subject=None,
            )
        )
        if dev_payload != expected_dev:
            raise ReleaseEvidenceError(
                "development SBOM does not match a fresh locked no-source uv export"
            )
    return manifest


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="artifactforge-release-evidence",
        description="create or verify bounded local release-rehearsal evidence",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser(
        "create", help="bind two separately supplied, inode-distinct distribution copies"
    )
    create.add_argument("--primary-dist", required=True)
    create.add_argument("--comparison-dist", required=True)
    create.add_argument("--out", required=True)
    create.add_argument("--repository-root", default=str(_REPOSITORY_ROOT))
    create.add_argument("--uv", default="uv")
    create.add_argument(
        "--allow-dirty",
        action="store_true",
        help="create a source-bound non-release diagnostic from a dirty worktree",
    )
    verify = sub.add_parser(
        "verify",
        help="verify the closed bundle; refresh source/SBOM bindings with --repository-root",
    )
    verify.add_argument("evidence")
    verify.add_argument(
        "--repository-root",
        help="also refresh the source snapshot and frozen uv SBOM exports",
    )
    verify.add_argument("--uv", default="uv")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "create":
            manifest = create_release_evidence(
                args.primary_dist,
                args.comparison_dist,
                args.out,
                repository_root=args.repository_root,
                uv_executable=args.uv,
                allow_dirty=args.allow_dirty,
            )
            print(
                f"wrote {args.out}: {manifest['verdict']} local self-attestation; "
                "command-signing=false command-publishing=false reportable=false"
            )
        else:
            manifest = verify_release_evidence(
                args.evidence,
                repository_root=args.repository_root,
                uv_executable=args.uv,
            )
            print(
                f"verified {args.evidence}: {manifest['verdict']} local self-attestation; "
                "command-signing=false command-publishing=false reportable=false"
            )
    except (OSError, ReleaseEvidenceError) as exc:
        print(f"release evidence error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
