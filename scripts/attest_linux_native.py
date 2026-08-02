#!/usr/bin/env python3
# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Create a source- and Fixture-Core-bound native Linux validation attestation.

The lane is deliberately observational.  It asks GNU ``readelf`` and ``objdump``,
``file``, ``desktop-file-validate``, and GNU Bash to parse freshly generated loose
artifacts.  It never executes an emitted ELF, invokes ``ldd``, launches a desktop
entry, or sources/evaluates a history file.  Bash receives history only through
``history -r`` and writes it back with ``history -w`` in an isolated temporary home.

The input is a complete Fixture Core root, not a detached scene.  Before native tools
are discovered, ArtifactForge verifies its canonical manifest, exact byte reproduction,
and assurance-equivalent Gates 1 and 3 in-process.  The canonical JSON result binds that
exact verification report and fixture manifest to the recursive scene, validation-tool
binaries and versions, Ubuntu package evidence, Git source state, normalized ELF
disassembly, and a byte-identical Bash-history round trip.  The fixture, scene, and source
are inventoried again after validation, as are all native/support tool binaries.  Native
results are complementary presence and acceptance evidence; the embedded portable reports,
not the native observations alone, carry the exact structural and inertness claims.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping

from artifactforge.fixture.operations import VerificationResult, verify_fixture
from artifactforge.inventory import (
    InventoryFile,
    captured_regular_tree,
    inventory_regular_files,
    open_real_directory,
)


SCHEMA_ID = "artifactforge-native-linux-attestation-v2"
CANONICALIZATION = "UTF-8 JSON, sorted keys, compact separators, no NaN, one trailing LF"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_ELF_MAGIC = b"\x7fELF"
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_PATH_USER = r"(?P<user>[A-Za-z0-9._+@-]+)"
_ELF_PATH = re.compile(rf"^home/{_PATH_USER}/\.local/bin/[A-Za-z0-9._+@-]+$")
_DESKTOP_PATH = re.compile(
    rf"^home/{_PATH_USER}/\.config/autostart/[A-Za-z0-9._+@-]+\.desktop$"
)
_HISTORY_PATH = re.compile(rf"^home/{_PATH_USER}/\.bash_history$")
_EXPECTED_DISASSEMBLY = (
    {"address": "0x1000", "bytes": "31ff", "instruction": "xor %edi,%edi"},
    {"address": "0x1002", "bytes": "b83c000000", "instruction": "mov $0x3c,%eax"},
    {"address": "0x1007", "bytes": "0f05", "instruction": "syscall"},
)
_VALIDATION_TOOLS = ("readelf", "objdump", "file", "desktop-file-validate", "bash")
_SUPPORT_TOOLS = ("dpkg-query", "uname")
_REQUIRED_PACKAGES = ("bash", "binutils", "desktop-file-utils", "file")
_PORTABLE_DISTRIBUTIONS = (
    "artifactforge",
    "lief",
    "pyelftools",
    "PyXDG",
    "dissect.target",
)
_BASH_CONTROL_MARKER = b"ARTIFACTFORGE-HISTORY-NONEXECUTION-CONTROL\n"

CommandRunner = Callable[..., dict]


def _portable_verifier_environment() -> dict:
    """Bind interpreter and installed parser versions used by portable assurance."""
    distributions = {}
    for name in _PORTABLE_DISTRIBUTIONS:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(
                f"missing portable verifier distribution version: {name}"
            ) from exc
        if not version:
            raise RuntimeError(f"empty portable verifier distribution version: {name}")
        distributions[name] = version
    implementation = platform.python_implementation()
    version = platform.python_version()
    if not implementation or not version:
        raise RuntimeError("missing CPython implementation/version evidence")
    if implementation != "CPython":
        raise RuntimeError(f"portable verifier requires CPython, found {implementation}")
    return {
        "distributions": distributions,
        "python": {
            "implementation": implementation,
            "version": version,
        },
    }


def _canonical_json_bytes(value: object) -> bytes:
    rendered = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"{rendered}\n".encode()


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _regular_file_identity(path: Path, where: str) -> dict:
    """Hash one stable regular file without accepting a symlink or mid-read change."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"cannot inspect {where}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{where} must be a regular file, not a link or special file")
    sha256, size = _sha256_and_size(path)
    try:
        after = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"cannot recheck {where}: {exc}") from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise RuntimeError(f"{where} changed while it was being hashed")
    return {"sha256": sha256, "size": size}


def _timestamp(now: dt.datetime | None = None) -> str:
    value = now or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("attestation timestamp must be timezone-aware")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _run(
    command: list[str],
    *,
    recorded_argv: list[str] | None = None,
    redactions: dict[str, str] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict:
    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
        env=None if env is None else dict(env),
        text=True,
    )
    stdout, stderr = completed.stdout.strip(), completed.stderr.strip()
    for original, replacement in (redactions or {}).items():
        stdout = stdout.replace(original, replacement)
        stderr = stderr.replace(original, replacement)
    return {
        "argv": recorded_argv or command,
        "returncode": completed.returncode,
        "stderr": stderr,
        "stdout": stdout,
    }


def _git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        check=False,
        text=text,
    )
    if completed.returncode != 0:
        stderr = (
            completed.stderr.strip()
            if text
            else completed.stderr.decode(errors="replace").strip()
        )
        raise RuntimeError(f"git {' '.join(arguments)} failed: {stderr}")
    return completed.stdout.strip() if text else completed.stdout


def _source_provenance(repo: Path = _REPOSITORY_ROOT) -> dict:
    commit = str(_git(repo, "rev-parse", "HEAD"))
    tree = str(_git(repo, "rev-parse", "HEAD^{tree}"))
    if not _HEX_40.fullmatch(commit) or not _HEX_40.fullmatch(tree):
        raise RuntimeError("Git did not return full SHA-1 commit and tree object identifiers")
    status = bytes(
        _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all", text=False)
    )
    return {
        "git_commit": commit,
        "git_tree": tree,
        "status_porcelain_sha256": hashlib.sha256(status).hexdigest(),
        "worktree_clean": not status,
    }


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


def _relative_label(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _scene_manifest(scene: Path) -> dict:
    files = []
    for item in inventory_regular_files(scene, capture_bytes=True):
        if item.data is None:
            raise AssertionError("captured scene inventory contains no bytes")
        files.append(
            {
                "path": item.relative_path,
                "sha256": hashlib.sha256(item.data).hexdigest(),
                "size": len(item.data),
            }
        )
    digest_input = {"files": files}
    return {
        "canonicalization": CANONICALIZATION,
        "file_count": len(files),
        "files": files,
        "total_bytes": sum(item["size"] for item in files),
        "tree_sha256": hashlib.sha256(_canonical_json_bytes(digest_input)).hexdigest(),
    }


def _captured_scene(files: tuple[InventoryFile, ...]) -> tuple[Path, dict]:
    """Locate and inventory the private snapshot yielded by captured_regular_tree."""
    if not files:
        raise RuntimeError("captured Linux scene is empty")
    roots = set()
    manifest_files = []
    for item in files:
        if item.data is None:
            raise AssertionError("private scene snapshot contains no captured bytes")
        root = item.path
        for _part in item.relative_path.split("/"):
            root = root.parent
        roots.add(root)
        manifest_files.append(
            {
                "path": item.relative_path,
                "sha256": hashlib.sha256(item.data).hexdigest(),
                "size": len(item.data),
            }
        )
    if len(roots) != 1:
        raise RuntimeError("captured Linux files do not share one private snapshot root")
    manifest_files.sort(key=lambda item: item["path"])
    digest_input = {"files": manifest_files}
    return roots.pop(), {
        "canonicalization": CANONICALIZATION,
        "file_count": len(manifest_files),
        "files": manifest_files,
        "total_bytes": sum(item["size"] for item in manifest_files),
        "tree_sha256": hashlib.sha256(_canonical_json_bytes(digest_input)).hexdigest(),
    }


def _scene_postcondition(initial: dict, scene: Path) -> dict:
    final = _scene_manifest(scene)
    return {
        "file_count": final["file_count"],
        "total_bytes": final["total_bytes"],
        "tree_sha256": final["tree_sha256"],
        "unchanged": final == initial,
    }


def _fixture_state(fixture: Path) -> dict:
    """Inventory the two-entry Fixture Core root and its exact recursive payload."""
    try:
        root_state = fixture.lstat()
    except OSError as exc:
        raise RuntimeError(f"cannot inspect fixture root: {exc}") from exc
    if stat.S_ISLNK(root_state.st_mode) or not stat.S_ISDIR(root_state.st_mode):
        raise RuntimeError("fixture root must be a real directory, not a link")
    try:
        inventory = sorted(path.name for path in fixture.iterdir())
    except OSError as exc:
        raise RuntimeError(f"cannot inventory fixture root: {exc}") from exc
    if inventory != ["artifacts", "fixture.json"]:
        raise RuntimeError(
            "fixture root inventory must be exactly artifacts/ and fixture.json; found "
            + ", ".join(inventory)
        )
    scene = fixture / "artifacts"
    try:
        scene_state = scene.lstat()
    except OSError as exc:
        raise RuntimeError(f"cannot inspect fixture artifacts directory: {exc}") from exc
    if stat.S_ISLNK(scene_state.st_mode) or not stat.S_ISDIR(scene_state.st_mode):
        raise RuntimeError("fixture artifacts must be a real directory, not a link")
    return {
        "manifest_file": _regular_file_identity(
            fixture / "fixture.json", "fixture.json"
        ),
        "root_inventory": inventory,
        "scene": _scene_manifest(scene),
    }


def _fixture_postcondition(initial: dict, fixture: Path) -> dict:
    final = _fixture_state(fixture)
    return {
        "manifest_file": {
            **final["manifest_file"],
            "unchanged": final["manifest_file"] == initial["manifest_file"],
        },
        "root_inventory": final["root_inventory"],
        "scene": {
            "file_count": final["scene"]["file_count"],
            "total_bytes": final["scene"]["total_bytes"],
            "tree_sha256": final["scene"]["tree_sha256"],
            "unchanged": final["scene"] == initial["scene"],
        },
        "unchanged": final == initial,
    }


def _gate_report_evidence(report: object) -> dict:
    """Serialize every stable field of one in-process GateReport without weakening it."""
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
) -> tuple[dict, dict]:
    """Run Fixture Core's strongest verifier and bind its result to the native tree."""
    environment = _portable_verifier_environment()
    verification = (verifier or verify_fixture)(fixture, assurance=True)
    reports = tuple(verification.assurance_reports)
    report_identity = [(report.gate, report.name) for report in reports]
    if report_identity != [(1, "validity"), (3, "inertness")]:
        raise RuntimeError(
            "Fixture Core assurance did not return exactly Gate 1 validity and Gate 3 inertness"
        )
    if not verification.ok:
        details = list(verification.failures)
        details.extend(
            f"Gate {report.gate} ({report.name}): " + "; ".join(report.fails)
            for report in reports
            if not report.ok
        )
        raise RuntimeError(
            "Fixture Core verification failed"
            + (": " + " | ".join(dict.fromkeys(details)) if details else "")
        )

    manifest = verification.manifest
    if environment["distributions"]["artifactforge"] != manifest.generator.version:
        raise RuntimeError(
            "installed artifactforge distribution version does not match fixture generator: "
            f"{environment['distributions']['artifactforge']!r} != "
            f"{manifest.generator.version!r}"
        )
    if (
        manifest.recipe.family != "linux"
        or manifest.recipe.profile.id != "linux-glibc-x86_64-loose-v1"
    ):
        raise RuntimeError(
            "native Linux attestation requires profile linux-glibc-x86_64-loose-v1"
        )

    state = _fixture_state(fixture)
    manifest_bytes = manifest.canonical_bytes()
    manifest_identity = {
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "size": len(manifest_bytes),
    }
    if state["manifest_file"] != manifest_identity:
        raise RuntimeError("fixture.json changed after Fixture Core verification")

    expected_files = [
        {
            "path": entry.path,
            "sha256": entry.sha256.removeprefix("sha256:"),
            "size": entry.size,
        }
        for entry in manifest.payload.files
    ]
    if state["scene"]["files"] != expected_files:
        raise RuntimeError(
            "fixture artifacts changed or disagree with the verified payload manifest"
        )

    return {
        "manifest": manifest.to_mapping(),
        "manifest_file": state["manifest_file"],
        "portable_verification": {
            "contract": (
                "verify_fixture(fixture, assurance=True): canonical manifest and payload "
                "integrity, exact recipe byte reproduction, then Gate 1 validity and Gate 3 "
                "inertness over byte-bound bounded captures"
            ),
            "environment": environment,
            "failures": list(verification.failures),
            "reports": [_gate_report_evidence(report) for report in reports],
            "verdict": "pass",
        },
    }, state


def _file_identity(path: Path) -> dict:
    resolved = path.resolve(strict=True)
    identity = _regular_file_identity(resolved, f"native tool {path}")
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        **identity,
    }


def _native_tools(command_runner: CommandRunner = _run) -> tuple[dict[str, str], dict]:
    names = (*_VALIDATION_TOOLS, *_SUPPORT_TOOLS)
    found = {name: shutil.which(name) for name in names}
    missing = [name for name, path in found.items() if path is None]
    if missing:
        raise RuntimeError(f"missing required native tools: {', '.join(missing)}")
    paths = {name: str(Path(path).resolve(strict=True)) for name, path in found.items() if path}
    version_commands = {
        "readelf": [paths["readelf"], "--version"],
        "objdump": [paths["objdump"], "--version"],
        "file": [paths["file"], "--version"],
        "desktop-file-validate": [
            paths["dpkg-query"],
            "--show",
            "--showformat=${Version}\\n",
            "desktop-file-utils",
        ],
        "bash": [paths["bash"], "--version"],
        "dpkg-query": [paths["dpkg-query"], "--version"],
        "uname": [paths["uname"], "--version"],
    }
    # Complete the first byte-identity sample before invoking even a version command. This
    # keeps every command, including version discovery, inside the documented before/after
    # observation interval.
    identities = {
        name: _file_identity(Path(paths[name]))
        for name in names
    }
    evidence = {}
    for name in names:
        if name == "desktop-file-validate":
            recorded_argv = [
                "dpkg-query",
                "--show",
                "--showformat=<version>",
                "desktop-file-utils",
            ]
            version_method = "Ubuntu desktop-file-utils package version"
        else:
            recorded_argv = [name, *version_commands[name][1:]]
            version_method = "native tool version output"
        version = command_runner(
            version_commands[name],
            recorded_argv=recorded_argv,
        )
        evidence[name] = {
            **identities[name],
            "version": version,
            "version_method": version_method,
        }
    return paths, {
        "support_tools": {name: evidence[name] for name in _SUPPORT_TOOLS},
        "validation_tools": {name: evidence[name] for name in _VALIDATION_TOOLS},
    }


def _tools_postcondition(paths: dict[str, str], initial: dict) -> dict:
    """Re-hash every resolved native/support tool after all observations."""
    tools = {}
    unchanged = True
    for group_name in ("validation_tools", "support_tools"):
        for name, evidence in initial[group_name].items():
            try:
                final = _file_identity(Path(paths[name]))
                same = all(
                    final[field] == evidence[field]
                    for field in ("path", "resolved_path", "sha256", "size")
                )
                tools[name] = {**final, "unchanged": same}
            except Exception as exc:  # noqa: BLE001 - record an unreadable/replaced tool
                same = False
                tools[name] = {"error": str(exc), "unchanged": False}
            unchanged = unchanged and same
    return {
        "identity_scope": (
            "resolved tool bytes are hashed before and after native observations; a transient "
            "swap restored between those samples is outside this attestation"
        ),
        "tools": tools,
        "unchanged": unchanged,
    }


def _parse_os_release(path: Path) -> dict[str, str]:
    fields = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        fields[key] = value
    return fields


def _package_rows(output: str) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not all(parts):
            raise RuntimeError("dpkg-query returned malformed package-version evidence")
        rows.append({"architecture": parts[2], "package": parts[0], "version": parts[1]})
    return rows


def _platform_evidence(paths: dict[str, str], command_runner: CommandRunner = _run) -> dict:
    os_release_path = Path("/etc/os-release")
    if not os_release_path.is_file():
        raise RuntimeError("missing required Linux platform evidence: /etc/os-release")
    package_result = command_runner(
        [
            paths["dpkg-query"],
            "--show",
            "--showformat=${binary:Package}\\t${Version}\\t${Architecture}\\n",
            *_REQUIRED_PACKAGES,
        ],
        recorded_argv=[
            "dpkg-query",
            "--show",
            "--showformat=<package-tab-version-tab-architecture>",
            *_REQUIRED_PACKAGES,
        ],
    )
    rows = _package_rows(package_result["stdout"]) if package_result["returncode"] == 0 else []
    uname = command_runner([paths["uname"], "-a"], recorded_argv=["uname", "-a"])
    return {
        "machine": platform.machine(),
        "os_release": {
            **_file_identity(os_release_path),
            "fields": _parse_os_release(os_release_path),
        },
        "package_database": {
            "packages": rows,
            "result": package_result,
        },
        "release": platform.release(),
        "system": platform.system(),
        "uname": uname,
    }


def _classify_scene(scene: Path) -> dict[str, list[Path]]:
    classes: dict[str, list[Path]] = {"desktop": [], "elf": [], "history": [], "unknown": []}
    users = set()
    for path in sorted(scene.rglob("*"), key=lambda item: item.relative_to(scene).as_posix()):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(scene).as_posix()
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic == _ELF_MAGIC:
            match = _ELF_PATH.fullmatch(relative)
            kind = "elf" if match else "unknown"
        elif path.suffix == ".desktop":
            match = _DESKTOP_PATH.fullmatch(relative)
            kind = "desktop" if match else "unknown"
        elif path.name == ".bash_history":
            match = _HISTORY_PATH.fullmatch(relative)
            kind = "history" if match else "unknown"
        else:
            match = None
            kind = "unknown"
        classes[kind].append(path)
        if match is not None:
            users.add(match.group("user"))
    classes["users"] = sorted(users)  # type: ignore[assignment]
    return classes


def _normalized_disassembly(output: str) -> tuple[dict[str, str], ...]:
    instructions = []
    for line in output.splitlines():
        fields = [field.strip() for field in line.split("\t") if field.strip()]
        if len(fields) < 3 or not fields[0].endswith(":"):
            continue
        address = fields[0][:-1]
        octets = fields[1].split()
        if not re.fullmatch(r"[0-9a-fA-F]+", address) or not octets:
            continue
        if any(re.fullmatch(r"[0-9a-fA-F]{2}", octet) is None for octet in octets):
            continue
        instruction = " ".join(" ".join(fields[2:]).split())
        instruction = re.sub(r"\s*,\s*", ",", instruction)
        instructions.append(
            {
                "address": f"0x{int(address, 16):x}",
                "bytes": "".join(octet.lower() for octet in octets),
                "instruction": instruction,
            }
        )
    return tuple(instructions)


def _elf_attestation(
    path: Path,
    scene: Path,
    tools: dict[str, str],
    command_runner: CommandRunner,
) -> tuple[dict, list[str]]:
    relative = path.relative_to(scene).as_posix()
    redactions = {str(path): relative}
    readelf = command_runner(
        [tools["readelf"], "-h", "-l", "-d", "-S", "-n", "--wide", str(path)],
        recorded_argv=["readelf", "-h", "-l", "-d", "-S", "-n", "--wide", relative],
        redactions=redactions,
    )
    objdump = command_runner(
        [tools["objdump"], "-d", "-j", ".text", str(path)],
        recorded_argv=["objdump", "-d", "-j", ".text", relative],
        redactions=redactions,
    )
    file_result = command_runner(
        [tools["file"], "--brief", "--", str(path)],
        recorded_argv=["file", "--brief", "--", relative],
        redactions=redactions,
    )
    disassembly = _normalized_disassembly(objdump["stdout"])
    failures = []
    if readelf["returncode"] != 0:
        failures.append(f"readelf rejected {relative}")
    required_readelf = (
        r"^\s*Class:\s+ELF64\s*$",
        r"^\s*Type:\s+DYN\b",
        r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$",
        r"Requesting program interpreter:\s*/lib64/ld-linux-x86-64\.so\.2",
        r"\(NEEDED\).*Shared library:\s*\[libc\.so\.6\]",
        r"\(FLAGS_1\).*\bPIE\b",
        r"\.note\.artifactforge",
    )
    if not all(
        re.search(pattern, readelf["stdout"], re.MULTILINE) for pattern in required_readelf
    ):
        failures.append(f"readelf output lacks required native ELF observations for {relative}")
    if objdump["returncode"] != 0:
        failures.append(f"objdump rejected {relative}")
    if disassembly != _EXPECTED_DISASSEMBLY:
        failures.append(f"objdump disassembly disagrees with the exact inert entry body for {relative}")
    file_output = file_result["stdout"]
    if (
        file_result["returncode"] != 0
        or "ELF 64-bit LSB" not in file_output
        or "x86-64" not in file_output
        or "dynamically linked" not in file_output
    ):
        failures.append(f"file did not recognise the required ELF class for {relative}")
    return {
        "claim": (
            "complementary GNU/binutils and file recognition plus exact entry-body "
            "disassembly; the bound portable Gates 1 and 3 prove the full structural and "
            "inertness profile"
        ),
        "disassembly": list(disassembly),
        "file": relative,
        "file_identification": file_result,
        "objdump": objdump,
        "readelf": readelf,
    }, failures


def _desktop_attestation(
    path: Path,
    scene: Path,
    tool: str,
    command_runner: CommandRunner,
) -> tuple[dict, list[str]]:
    relative = path.relative_to(scene).as_posix()
    result = command_runner(
        [tool, str(path)],
        recorded_argv=["desktop-file-validate", relative],
        redactions={str(path): relative},
    )
    failures = [] if result["returncode"] == 0 else [
        f"desktop-file-validate rejected {relative}"
    ]
    return {
        "claim": (
            "complementary desktop-file-validate syntax acceptance; the bound portable "
            "Gate 1 report proves the exact XDG desktop-entry profile"
        ),
        "file": relative,
        "validation": result,
    }, failures


_BASH_SCRIPT = r"""
set -eu
umask 077
source_history=$1
roundtrip=$2
control_history=$3
control_roundtrip=$4
sentinel=$5
status_file=$6
test ! -e "$sentinel"
history -c
history -r "$control_history"
history -w "$control_roundtrip"
test ! -e "$sentinel"
printf '%s\n' history-read-did-not-execute > "$status_file"
history -c
history -r "$source_history"
history -w "$roundtrip"
test ! -e "$sentinel"
printf '%s\n' ARTIFACTFORGE-HISTORY-NONEXECUTION-CONTROL > "$sentinel"
test -s "$sentinel"
""".strip()


def _bash_attestation(
    history: Path,
    scene: Path,
    bash: str,
    command_runner: CommandRunner,
) -> tuple[dict, list[str]]:
    relative = history.relative_to(scene).as_posix()
    original = history.read_bytes()
    with tempfile.TemporaryDirectory(prefix="artifactforge-linux-history-") as temporary:
        work = Path(temporary)
        home = work / "home"
        home.mkdir(mode=0o700)
        roundtrip = work / "roundtrip.history"
        control_history = work / "nonexecution-control.history"
        control_roundtrip = work / "nonexecution-control.roundtrip"
        sentinel = home / "history-command-executed.sentinel"
        status_file = work / "history-read.status"
        control_history.write_bytes(
            b"#2147483646\n"
            + b"printf '%s\\n' ARTIFACTFORGE-HISTORY-COMMAND-EXECUTED > "
            + b'"$HOME/history-command-executed.sentinel"\n'
        )
        arguments = [
            bash,
            "--noprofile",
            "--norc",
            "-c",
            _BASH_SCRIPT,
            "artifactforge-history-attestation",
            str(history),
            str(roundtrip),
            str(control_history),
            str(control_roundtrip),
            str(sentinel),
            str(status_file),
        ]
        redactions = {
            str(history): relative,
            str(roundtrip): "<temporary>/roundtrip.history",
            str(control_history): "<temporary>/nonexecution-control.history",
            str(control_roundtrip): "<temporary>/nonexecution-control.roundtrip",
            str(sentinel): "<temporary>/history-command-executed.sentinel",
            str(status_file): "<temporary>/history-read.status",
        }
        result = command_runner(
            arguments,
            recorded_argv=[
                "bash",
                "--noprofile",
                "--norc",
                "-c",
                "<fixed history-read/writeback script; never source or eval>",
                "artifactforge-history-attestation",
                relative,
                "<temporary>/roundtrip.history",
                "<temporary>/nonexecution-control.history",
                "<temporary>/nonexecution-control.roundtrip",
                "<temporary>/history-command-executed.sentinel",
                "<temporary>/history-read.status",
            ],
            redactions=redactions,
            env={
                "BASH_ENV": "/dev/null",
                "ENV": "/dev/null",
                "HISTCONTROL": "",
                "HISTFILE": "/dev/null",
                "HISTFILESIZE": "4096",
                "HISTIGNORE": "",
                "HISTSIZE": "4096",
                "HISTTIMEFORMAT": "%s ",
                "HOME": str(home),
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TZ": "UTC",
            },
        )
        roundtrip_bytes = roundtrip.read_bytes() if roundtrip.is_file() else b""
        source_roundtrip_identical = roundtrip_bytes == original
        control_source_bytes = control_history.read_bytes()
        control_roundtrip_bytes = (
            control_roundtrip.read_bytes() if control_roundtrip.is_file() else b""
        )
        control_roundtrip_identical = control_roundtrip_bytes == control_source_bytes
        status = status_file.read_bytes() if status_file.is_file() else b""
        sentinel_bytes = sentinel.read_bytes() if sentinel.is_file() else b""
        nonexecution_control_passed = (
            result["returncode"] == 0
            and control_roundtrip_identical
            and status == b"history-read-did-not-execute\n"
            and sentinel_bytes == _BASH_CONTROL_MARKER
        )
        failures = []
        if result["returncode"] != 0:
            failures.append(f"GNU Bash history read/writeback failed for {relative}")
        if not source_roundtrip_identical:
            failures.append(f"GNU Bash history roundtrip changed bytes for {relative}")
        if not control_roundtrip_identical:
            failures.append(
                f"GNU Bash ignored or changed the injected history control for {relative}"
            )
        if not nonexecution_control_passed:
            failures.append(f"GNU Bash history non-execution control failed for {relative}")
        return {
            "byte_identical_roundtrip": source_roundtrip_identical,
            "claim": (
                "complementary GNU Bash history-read/write acceptance and a non-execution "
                "control; the bound portable Gates 1 and 3 prove the exact history profile "
                "and in-band marker"
            ),
            "file": relative,
            "nonexecution_control": {
                "control_history_sha256": hashlib.sha256(control_source_bytes).hexdigest(),
                "control_roundtrip_byte_identical": control_roundtrip_identical,
                "control_roundtrip_sha256": hashlib.sha256(
                    control_roundtrip_bytes
                ).hexdigest(),
                "history_command_was_not_executed": nonexecution_control_passed,
                "injected_history_command": (
                    "printf ARTIFACTFORGE-HISTORY-COMMAND-EXECUTED > <sentinel>"
                ),
                "method": (
                    "history -r must leave the sentinel absent; the same shell builtin and "
                    "redirection then write a distinct positive-control marker"
                ),
                "positive_control_marker_sha256": hashlib.sha256(sentinel_bytes).hexdigest(),
                "positive_control_observed": sentinel_bytes == _BASH_CONTROL_MARKER,
            },
            "result": result,
            "roundtrip_sha256": hashlib.sha256(roundtrip_bytes).hexdigest(),
            "source_sha256": hashlib.sha256(original).hexdigest(),
        }, failures


def _observe_native_snapshot(
    *,
    command_runner: CommandRunner,
    fixture: Path,
    fixture_evidence: dict,
    github_run: dict | None,
    initial_manifest: dict,
    now: dt.datetime | None,
    platform_evidence: dict,
    repository_root: Path,
    scene: Path,
    source: dict,
    tool_evidence: dict,
    tools: dict[str, str],
) -> dict:
    """Collect native observations strictly from one held private scene snapshot."""
    classes = _classify_scene(scene)

    report = {
        "artifacts": {
            "bash_history": [],
            "desktop_entries": [],
            "elf_files": [],
        },
        "canonicalization": CANONICALIZATION,
        "claim_scope": (
            "Fixture Core first proves canonical integrity, exact recipe byte reproduction, "
            "Gate 1 validity, and Gate 3 inertness. Native results are complementary "
            "presence, recognition, syntax-acceptance, disassembly, and Bash read/write "
            "observations over a frozen private snapshot that byte-matches the verified "
            "payload manifest. No emitted ELF is executed; ldd is never invoked; desktop "
            "entries are not launched; Bash history is read with history -r and never "
            "sourced or evaluated. Tool bytes are sampled before and after observation; "
            "transient tool swap-and-restore between samples is outside this attestation."
        ),
        "failures": [],
        "fixture": {
            **fixture_evidence,
            "path": _relative_label(fixture, repository_root),
        },
        "generated_at_utc": _timestamp(now),
        "platform": platform_evidence,
        "producer": {
            "name": "scripts/attest_linux_native.py",
            "source": source,
            "version": 2,
        },
        "scene": {
            "expected_profile": {
                "desktop_entries": 3,
                "elf_files": 5,
                "history_files": 1,
                "total_files": 9,
            },
            "manifest": initial_manifest,
            "path": "<private-frozen-snapshot>",
        },
        "schema": SCHEMA_ID,
        "schema_version": 2,
        "tools": tool_evidence,
    }
    if github_run is not None:
        report["producer"]["github_run"] = github_run

    if not source["worktree_clean"]:
        report["failures"].append("source worktree is not clean")
    if github_run is not None:
        missing = [name for name, value in github_run.items() if name != "run_url" and not value]
        if missing:
            report["failures"].append(
                f"GitHub Actions identity is incomplete: {', '.join(sorted(missing))}"
            )
        if github_run["git_sha"] and github_run["git_sha"] != source["git_commit"]:
            report["failures"].append("GitHub Actions GITHUB_SHA does not match source HEAD")
    if platform_evidence["system"] != "Linux":
        report["failures"].append("platform.system() did not report Linux")
    if platform_evidence["machine"].lower() not in {"amd64", "x86_64"}:
        report["failures"].append("native lane is not running on x86-64")
    if platform_evidence["uname"]["returncode"] != 0:
        report["failures"].append("uname platform evidence failed")
    package_database = platform_evidence["package_database"]
    if package_database["result"]["returncode"] != 0:
        report["failures"].append("dpkg-query package evidence failed")
    found_packages = {row["package"].split(":", 1)[0] for row in package_database["packages"]}
    missing_packages = sorted(set(_REQUIRED_PACKAGES) - found_packages)
    if missing_packages:
        report["failures"].append(
            f"package evidence is missing: {', '.join(missing_packages)}"
        )
    for name, evidence in {
        **tool_evidence["validation_tools"],
        **tool_evidence["support_tools"],
    }.items():
        if evidence["version"]["returncode"] != 0 or not evidence["version"]["stdout"]:
            report["failures"].append(f"no native version evidence for {name}")
    bash_version = tool_evidence["validation_tools"]["bash"]["version"]["stdout"]
    match = re.search(r"GNU bash, version (\d+)\.", bash_version)
    if match is None or int(match.group(1)) < 5:
        report["failures"].append("native history lane requires GNU Bash 5 or newer")

    counts = {name: len(classes[name]) for name in ("elf", "desktop", "history", "unknown")}
    report["scene"]["observed_profile"] = {
        "desktop_entries": counts["desktop"],
        "elf_files": counts["elf"],
        "history_files": counts["history"],
        "total_files": initial_manifest["file_count"],
        "unknown_files": counts["unknown"],
        "users": classes["users"],
    }
    if counts != {"elf": 5, "desktop": 3, "history": 1, "unknown": 0}:
        report["failures"].append(
            "scene is not the exact five-ELF/three-desktop/one-history Linux profile"
        )
    if initial_manifest["file_count"] != 9:
        report["failures"].append("Linux native scene must contain exactly nine files")
    if len(classes["users"]) != 1:
        report["failures"].append("Linux native scene paths do not name exactly one user")

    try:
        for elf in classes["elf"]:
            evidence, failures = _elf_attestation(elf, scene, tools, command_runner)
            report["artifacts"]["elf_files"].append(evidence)
            report["failures"].extend(failures)
        for desktop in classes["desktop"]:
            evidence, failures = _desktop_attestation(
                desktop,
                scene,
                tools["desktop-file-validate"],
                command_runner,
            )
            report["artifacts"]["desktop_entries"].append(evidence)
            report["failures"].extend(failures)
        for history in classes["history"]:
            evidence, failures = _bash_attestation(
                history,
                scene,
                tools["bash"],
                command_runner,
            )
            report["artifacts"]["bash_history"].append(evidence)
            report["failures"].extend(failures)
    except Exception as exc:  # noqa: BLE001 - retain native execution failures in JSON
        report["failures"].append(f"native attestation execution failed: {exc}")
    return report


def attest(
    fixture: Path,
    *,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
    repository_root: Path = _REPOSITORY_ROOT,
    command_runner: CommandRunner = _run,
) -> dict:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("native Linux attestation must run on Linux")
    fixture = Path(fixture)
    try:
        requested_state = fixture.lstat()
    except OSError as exc:
        raise RuntimeError(f"fixture does not exist: {fixture}: {exc}") from exc
    if stat.S_ISLNK(requested_state.st_mode) or not stat.S_ISDIR(requested_state.st_mode):
        raise RuntimeError("fixture root must be a real directory, not a link")

    # Keep the final component lexical so Fixture Core can reject links rather than having
    # Path.resolve() erase that evidence before its descriptor-bound open.
    fixture = Path(os.path.abspath(fixture))
    repository_root = repository_root.resolve()
    fixture_evidence, initial_fixture_state = _verified_fixture_evidence(fixture)
    verified_manifest = initial_fixture_state["scene"]
    source = _source_provenance(repository_root)
    github_run = _github_run_identity(environ)

    with captured_regular_tree(fixture / "artifacts") as captured_files:
        scene, captured_manifest = _captured_scene(captured_files)
        if captured_manifest != verified_manifest:
            raise RuntimeError(
                "private native snapshot does not byte-match the verified fixture manifest"
            )
        tools, tool_evidence = _native_tools(command_runner)
        platform_evidence = _platform_evidence(tools, command_runner)
        report = _observe_native_snapshot(
            command_runner=command_runner,
            fixture=fixture,
            fixture_evidence=fixture_evidence,
            github_run=github_run,
            initial_manifest=captured_manifest,
            now=now,
            platform_evidence=platform_evidence,
            repository_root=repository_root,
            scene=scene,
            source=source,
            tool_evidence=tool_evidence,
            tools=tools,
        )
        try:
            snapshot_postcondition = _scene_postcondition(captured_manifest, scene)
        except Exception as exc:  # noqa: BLE001 - a changed snapshot is a failed check
            snapshot_postcondition = {"error": str(exc), "unchanged": False}
        report["scene"]["post_attestation"] = snapshot_postcondition
        if not snapshot_postcondition["unchanged"]:
            report["failures"].append("private native scene snapshot changed")

        tool_postcondition = _tools_postcondition(tools, tool_evidence)
        report["tools"]["post_attestation"] = tool_postcondition
        if not tool_postcondition["unchanged"]:
            report["failures"].append("native or support tool bytes changed during attestation")

    try:
        fixture_postcondition = _fixture_postcondition(initial_fixture_state, fixture)
    except Exception as exc:  # noqa: BLE001 - vanished/corrupt fixture is a failed check
        fixture_postcondition = {"error": str(exc), "unchanged": False}
    report["fixture"]["post_attestation"] = fixture_postcondition
    if not fixture_postcondition["unchanged"]:
        report["failures"].append("fixture or source scene changed during native attestation")
    try:
        source_postcondition = _source_postcondition(source, repository_root)
    except Exception as exc:  # noqa: BLE001 - changed/unreadable source is a failure
        source_postcondition = {"error": str(exc), "unchanged": False}
    report["producer"]["source_post_attestation"] = source_postcondition
    if not source_postcondition["unchanged"]:
        report["failures"].append("source changed during native attestation")

    report["verdict"] = "pass" if not report["failures"] else "fail"
    return report


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
    """Exclusively create one output through a pinned, rechecked real parent directory."""
    if not output.name or output.name in {".", ".."}:
        raise RuntimeError("--out must name a new regular file")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("--out parent must already exist") from exc
    if not parent.is_dir():
        raise RuntimeError("--out parent must be a directory")
    destination = parent / output.name
    for root in forbidden_roots:
        if _inside(destination, root.resolve(strict=True)):
            raise RuntimeError("--out resolved inside a protected fixture or source root")

    parent_fd = open_real_directory(parent)
    file_fd = -1
    created_identity: tuple[int, int] | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            file_fd = os.open(output.name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise RuntimeError("refusing to replace or follow an existing --out entry") from exc
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("--out did not create a regular file")
        created_identity = opened.st_dev, opened.st_ino
        remaining = memoryview(data)
        while remaining:
            written = os.write(file_fd, remaining)
            if written <= 0:
                raise RuntimeError("short write while creating --out")
            remaining = remaining[written:]
        os.fsync(file_fd)
        entry = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(entry.st_mode)
            or (entry.st_dev, entry.st_ino) != created_identity
            or entry.st_size != len(data)
        ):
            raise RuntimeError("--out changed while it was being written")
        os.fsync(parent_fd)
        return destination
    except Exception:
        if created_identity is not None:
            try:
                entry = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
                if (entry.st_dev, entry.st_ino) == created_identity:
                    os.unlink(output.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="new canonical JSON file in an existing directory outside fixture and source",
    )
    args = parser.parse_args()
    fixture = Path(os.path.abspath(args.fixture))
    fixture_for_containment = fixture.resolve(strict=False)
    output = Path(os.path.abspath(args.out))
    output_for_containment = output.parent.resolve(strict=False) / output.name
    if _inside(output_for_containment, fixture_for_containment):
        print(
            "FAIL: --out must be outside --fixture so the attestation cannot mutate its corpus",
            file=sys.stderr,
        )
        return 2
    if _inside(output_for_containment, _REPOSITORY_ROOT.resolve()):
        print(
            "FAIL: --out must be outside the source repository so post-state remains bound",
            file=sys.stderr,
        )
        return 2
    try:
        report = attest(fixture)
    except Exception as exc:  # noqa: BLE001 - emit a machine-readable failure before exiting
        report = {
            "canonicalization": CANONICALIZATION,
            "failures": [str(exc)],
            "generated_at_utc": _timestamp(),
            "schema": SCHEMA_ID,
            "schema_version": 2,
            "verdict": "fail",
        }
    try:
        written = _write_new_output(
            output,
            _canonical_json_bytes(report),
            forbidden_roots=(fixture_for_containment, _REPOSITORY_ROOT.resolve()),
        )
    except Exception as exc:  # noqa: BLE001 - output safety failures are usage failures
        print(f"FAIL: cannot safely write --out: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {written}: {report['verdict']}")
    for failure in report.get("failures", []):
        print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
