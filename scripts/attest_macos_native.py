#!/usr/bin/env python3
# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Create a source- and corpus-bound native macOS validation attestation.

``codesign`` and ``plutil`` are hard assertions. Gatekeeper is different: CI hosts can have an
installed ``spctl`` whose assessment service is disabled. A non-zero result on a synthetic
binary is therefore called a rejection only when a signed platform application passes first.
Otherwise the same bytes are recorded as an inconclusive non-acceptance observation.

The output is canonical JSON. It binds the complete scene, the clean Git source tree, the
native executable bytes and Apple build markers, and (when present) the GitHub Actions run.
The scene is inventoried again after all native commands and any change makes the record fail.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping

from artifactforge.content.macho import cdhash_of_file

SCHEMA_ID = "artifactforge-native-macos-attestation-v2"
CANONICALIZATION = "UTF-8 JSON, sorted keys, compact separators, no NaN, one trailing LF"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_MACHO_MAGIC = b"\xcf\xfa\xed\xfe"
_CDHASH = re.compile(r"^CDHash=([0-9a-fA-F]{40})$", re.MULTILINE)
_PROJECT_MARKER = re.compile(r"PROGRAM:(?P<program>\S+)\s+PROJECT:(?P<project>\S+)")
_TOOLS = ("codesign", "plutil", "spctl", "xattr")
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")


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
) -> dict:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
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
        stderr = completed.stderr.strip() if text else completed.stderr.decode(errors="replace").strip()
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
    for path in sorted(scene.rglob("*"), key=lambda item: item.relative_to(scene).as_posix()):
        relative = path.relative_to(scene).as_posix()
        if path.is_symlink():
            raise RuntimeError(f"scene contains unsupported symbolic link: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError(f"scene contains unsupported non-regular file: {relative}")
        sha256, size = _sha256_and_size(path)
        files.append({"path": relative, "sha256": sha256, "size": size})
    digest_input = {"files": files}
    return {
        "canonicalization": CANONICALIZATION,
        "file_count": len(files),
        "files": files,
        "total_bytes": sum(item["size"] for item in files),
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


def _file_identity(path: Path) -> dict:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise RuntimeError(f"native tool is not a regular file: {path}")
    sha256, size = _sha256_and_size(resolved)
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "sha256": sha256,
        "size": size,
    }


def _project_markers(output: str) -> list[dict[str, str]]:
    return [
        {"program": program, "project": project}
        for program, project in sorted(set(_PROJECT_MARKER.findall(output)))
    ]


def _native_tools() -> tuple[dict[str, str], dict]:
    found = {name: shutil.which(name) for name in (*_TOOLS, "what")}
    missing = [name for name, path in found.items() if path is None]
    if missing:
        raise RuntimeError(f"missing required native tools: {', '.join(missing)}")

    paths = {name: str(Path(path).resolve(strict=True)) for name, path in found.items() if path}
    version_extractor = _file_identity(Path(paths["what"]))
    evidence = {}
    for name in _TOOLS:
        identity = _file_identity(Path(paths[name]))
        version = _run(
            [paths["what"], "-s", paths[name]],
            recorded_argv=["what", "-s", paths[name]],
        )
        markers = _project_markers(f"{version['stdout']}\n{version['stderr']}")
        evidence[name] = {
            **identity,
            "version_evidence": {
                "apple_build_markers": markers,
                "method": "SCCS identification strings reported by Apple's what(1)",
                "result": version,
            },
        }
    return {name: paths[name] for name in _TOOLS}, {
        "validation_tools": evidence,
        "version_extractor": version_extractor,
    }


def _platform_evidence() -> dict:
    sw_vers = shutil.which("sw_vers")
    if sw_vers is None:
        raise RuntimeError("missing required native tool: sw_vers")
    product_version = _run(
        [sw_vers, "-productVersion"], recorded_argv=["sw_vers", "-productVersion"]
    )
    build_version = _run(
        [sw_vers, "-buildVersion"], recorded_argv=["sw_vers", "-buildVersion"]
    )
    return {
        "build_version": build_version,
        "machine": platform.machine(),
        "product_version": product_version,
        "release": platform.release(),
        "system": platform.system(),
    }


def _gatekeeper_conclusion(result: dict, *, control_working: bool) -> str:
    if result["returncode"] == 0:
        return "accepted_unexpectedly"
    output = f"{result['stdout']}\n{result['stderr']}".lower()
    if control_working and "rejected" in output:
        return "rejected"
    return "inconclusive_non_acceptance"


def _positive_control() -> Path:
    candidates = (
        Path("/System/Applications/Calculator.app"),
        Path("/System/Applications/TextEdit.app"),
        Path("/bin/ls"),
    )
    try:
        return next(path for path in candidates if path.exists())
    except StopIteration as exc:
        raise RuntimeError("no signed platform executable is available as a Gatekeeper control") from exc


def _macho_files(scene: Path) -> list[Path]:
    return [
        path
        for path in sorted(scene.rglob("*"), key=lambda item: item.relative_to(scene).as_posix())
        if path.is_file() and not path.is_symlink() and path.read_bytes()[:4] == _MACHO_MAGIC
    ]


def attest(
    scene: Path,
    *,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
    repository_root: Path = _REPOSITORY_ROOT,
) -> dict:
    if sys.platform != "darwin":
        raise RuntimeError("native macOS attestation must run on Darwin")
    if not scene.is_dir():
        raise RuntimeError(f"scene does not exist: {scene}")

    scene = scene.resolve()
    repository_root = repository_root.resolve()
    initial_manifest = _scene_manifest(scene)
    source = _source_provenance(repository_root)
    github_run = _github_run_identity(environ)
    tools, tool_evidence = _native_tools()
    machos = _macho_files(scene)
    plists = sorted(scene.rglob("*.plist"), key=lambda item: item.relative_to(scene).as_posix())
    if not machos:
        raise RuntimeError(f"no thin arm64 Mach-O files found in {scene}")
    if not plists:
        raise RuntimeError(f"no property lists found in {scene}")

    report = {
        "canonicalization": CANONICALIZATION,
        "code_signatures": [],
        "failures": [],
        "gatekeeper": {
            "assessments": [],
            "claim_scope": (
                "A rejection is recorded only if the platform positive control succeeds; "
                "otherwise non-zero is inconclusive, never evidence that Gatekeeper rejected it."
            ),
            "expectation": "ArtifactForge ad-hoc binaries are not accepted for execution",
        },
        "generated_at_utc": _timestamp(now),
        "platform": _platform_evidence(),
        "producer": {
            "name": "scripts/attest_macos_native.py",
            "source": source,
            "version": 2,
        },
        "property_lists": [],
        "scene": {
            "manifest": initial_manifest,
            "path": _relative_label(scene, repository_root),
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
    for name, evidence in tool_evidence["validation_tools"].items():
        version = evidence["version_evidence"]
        if version["result"]["returncode"] != 0 or not version["apple_build_markers"]:
            report["failures"].append(f"no Apple build-version evidence for {name}")
    for field in ("product_version", "build_version"):
        result = report["platform"][field]
        if result["returncode"] != 0 or not result["stdout"]:
            report["failures"].append(f"sw_vers did not report macOS {field}")

    try:
        for plist in plists:
            relative = plist.relative_to(scene).as_posix()
            result = _run(
                [tools["plutil"], "-lint", str(plist)],
                recorded_argv=["plutil", "-lint", relative],
                redactions={str(plist): relative},
            )
            report["property_lists"].append({"file": relative, "lint": result})
            if result["returncode"] != 0:
                report["failures"].append(f"plutil rejected {relative}")

        with tempfile.TemporaryDirectory(prefix="artifactforge-native-") as temporary:
            work = Path(temporary)
            for index, source_file in enumerate(machos):
                relative = source_file.relative_to(scene).as_posix()
                target = work / f"{index:04d}-{source_file.name}"
                shutil.copyfile(source_file, target)
                target.chmod(0o755)
                verify = _run(
                    [tools["codesign"], "--verify", "--strict", "--verbose=4", str(target)],
                    recorded_argv=[
                        "codesign",
                        "--verify",
                        "--strict",
                        "--verbose=4",
                        relative,
                    ],
                    redactions={str(target): relative},
                )
                describe = _run(
                    [tools["codesign"], "--display", "--verbose=4", str(target)],
                    recorded_argv=["codesign", "--display", "--verbose=4", relative],
                    redactions={str(target): relative},
                )
                match = _CDHASH.search(f"{describe['stdout']}\n{describe['stderr']}")
                reported_cdhash = match.group(1).lower() if match else ""
                computed_cdhash = cdhash_of_file(source_file.read_bytes())
                report["code_signatures"].append(
                    {
                        "computed_cdhash": computed_cdhash,
                        "describe": describe,
                        "file": relative,
                        "reported_cdhash": reported_cdhash,
                        "verify": verify,
                    }
                )
                if verify["returncode"] != 0:
                    report["failures"].append(
                        f"codesign rejected the signature on {relative}"
                    )
                if not computed_cdhash or reported_cdhash != computed_cdhash:
                    report["failures"].append(f"codesign cdhash disagrees for {relative}")

            control_path = _positive_control()
            control = _run(
                [tools["spctl"], "--assess", "--type", "execute", "--verbose=4", str(control_path)],
                recorded_argv=[
                    "spctl",
                    "--assess",
                    "--type",
                    "execute",
                    "--verbose=4",
                    str(control_path),
                ],
            )
            control_working = control["returncode"] == 0
            report["gatekeeper"]["positive_control"] = {
                "result": control,
                "target": str(control_path),
                "working": control_working,
            }

            for index, source_file in enumerate(machos):
                relative = source_file.relative_to(scene).as_posix()
                for quarantined in (False, True):
                    suffix = "quarantined" if quarantined else "plain"
                    target = work / f"{index:04d}-{source_file.name}.{suffix}"
                    shutil.copyfile(source_file, target)
                    target.chmod(0o755)
                    quarantine_setup = None
                    if quarantined:
                        sidecar = source_file.with_name(f"{source_file.name}.quarantine.xattr")
                        if not sidecar.is_file():
                            report["failures"].append(
                                f"missing quarantine xattr sidecar for {relative}"
                            )
                            continue
                        quarantine_setup = _run(
                            [
                                tools["xattr"],
                                "-w",
                                "com.apple.quarantine",
                                sidecar.read_text().strip(),
                                str(target),
                            ],
                            recorded_argv=[
                                "xattr",
                                "-w",
                                "com.apple.quarantine",
                                "<value-from-sidecar>",
                                f"{relative}.quarantined",
                            ],
                            redactions={str(target): f"{relative}.quarantined"},
                        )
                        if quarantine_setup["returncode"] != 0:
                            report["failures"].append(
                                f"could not apply quarantine xattr to {relative}"
                            )
                            continue
                    result = _run(
                        [
                            tools["spctl"],
                            "--assess",
                            "--type",
                            "execute",
                            "--verbose=4",
                            str(target),
                        ],
                        recorded_argv=[
                            "spctl",
                            "--assess",
                            "--type",
                            "execute",
                            "--verbose=4",
                            f"{relative}.{suffix}",
                        ],
                        redactions={str(target): f"{relative}.{suffix}"},
                    )
                    conclusion = _gatekeeper_conclusion(
                        result, control_working=control_working
                    )
                    assessment = {
                        "conclusion": conclusion,
                        "file": relative,
                        "quarantined": quarantined,
                        "result": result,
                    }
                    if quarantine_setup is not None:
                        assessment["quarantine_setup"] = quarantine_setup
                    report["gatekeeper"]["assessments"].append(assessment)
                    if conclusion == "accepted_unexpectedly":
                        report["failures"].append(
                            f"Gatekeeper unexpectedly accepted {relative} ({suffix})"
                        )
    except Exception as exc:  # noqa: BLE001 - failures belong in the retained attestation
        report["failures"].append(f"native attestation execution failed: {exc}")
    finally:
        try:
            postcondition = _scene_postcondition(initial_manifest, scene)
        except Exception as exc:  # noqa: BLE001 - a vanished/corrupt scene is a failed postcondition
            postcondition = {"error": str(exc), "unchanged": False}
        report["scene"]["post_attestation"] = postcondition
        if not postcondition["unchanged"]:
            report["failures"].append("scene changed during native attestation")
        try:
            source_postcondition = _source_postcondition(source, repository_root)
        except Exception as exc:  # noqa: BLE001 - a changed/unreadable source tree is a failure
            source_postcondition = {"error": str(exc), "unchanged": False}
        report["producer"]["source_post_attestation"] = source_postcondition
        if not source_postcondition["unchanged"]:
            report["failures"].append("source changed during native attestation")

    conclusions = {item["conclusion"] for item in report["gatekeeper"]["assessments"]}
    if conclusions == {"rejected"}:
        report["gatekeeper"]["verdict"] = "rejected_with_working_positive_control"
    elif "accepted_unexpectedly" in conclusions:
        report["gatekeeper"]["verdict"] = "fail"
    else:
        report["gatekeeper"]["verdict"] = "inconclusive_non_acceptance_observation"
    report["verdict"] = "pass" if not report["failures"] else "fail"
    return report


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scene", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    scene = args.scene.resolve()
    output = args.out.resolve()
    if _inside(output, scene):
        print("FAIL: --out must be outside --scene so the attestation cannot mutate its corpus", file=sys.stderr)
        return 2
    try:
        report = attest(scene)
    except Exception as exc:  # noqa: BLE001 - emit a machine-readable failure before exiting
        report = {
            "canonicalization": CANONICALIZATION,
            "failures": [str(exc)],
            "generated_at_utc": _timestamp(),
            "schema": SCHEMA_ID,
            "schema_version": 2,
            "verdict": "fail",
        }
    output.write_bytes(_canonical_json_bytes(report))
    print(f"wrote {output}: {report['verdict']}")
    if report.get("gatekeeper"):
        print(f"Gatekeeper: {report['gatekeeper']['verdict']}")
    for failure in report.get("failures", []):
        print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
