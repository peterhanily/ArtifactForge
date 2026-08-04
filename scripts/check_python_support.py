# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Audit Python-support policy or record canonical evidence for generated fixture trees.

The support audit is deliberately a metadata preflight.  It can identify reviewed blockers and
decide whether a target is a candidate for a real runtime lane, but it cannot promote an
interpreter by inspecting wheel filenames.  Installation on the actual target, imports, parser
positive controls, and behavioural tests remain the authority for runtime support.

Fixture evidence is a separate zero-dependency operation.  It binds every relative path, entry
kind, carrier mode, file size, and file byte with length-delimited hashing, rejects links and
special files, and can fail CI against caller-supplied expected digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tomllib
from urllib.parse import urlparse


SUPPORT_SCHEMA = "artifactforge-python-support-audit-v2"
FIXTURE_EVIDENCE_SCHEMA = "artifactforge-fixture-tree-evidence-v1"
LOCK_FORMAT_VERSION = 1
LOCK_REVISION = 3
STATUS_KNOWN_BLOCKED = "known_blocked"
STATUS_RUNTIME_CANDIDATE = "runtime_candidate"

# This is an intentional review boundary, not merely whatever happens to remain in uv.lock.
# pytest and ruff are lane tooling; every other member is an independent format/schema oracle.
REQUIRED_ORACLE_DISTRIBUTIONS = frozenset(
    {
        "dissect-target",
        "jsonschema",
        "libregf-python",
        "liblnk-python",
        "libscca-python",
        "lief",
        "lnkparse3",
        "macholib",
        "pefile",
        "pyelftools",
        "pyxdg",
        "regipy",
        "windowsprefetch",
        "yara-python",
    }
)
REQUIRED_LANE_TOOLS = frozenset({"pytest", "ruff"})
REQUIRED_ROOT_DEV_DISTRIBUTIONS = REQUIRED_ORACLE_DISTRIBUTIONS | REQUIRED_LANE_TOOLS

SOURCE_ONLY_PURE = {
    "windowsprefetch": {
        "version": "4.0.3",
        "basis": (
            "reviewed source-only pure-Python parser; target runtime behaviour remains required"
        ),
    }
}

# These records capture findings already reproduced against exact locked versions.  A version
# change intentionally removes the known finding and yields a runtime candidate, which forces CI
# and reviewers to perform the real target install/import/control lane before promotion.
KNOWN_PROMOTION_BLOCKERS = {
    ("dissect-target", "3.25.1", (3, 14)): {
        "kind": "runtime-import",
        "reason": (
            "import fails because its Python 3.13 pathlib compatibility layer imports "
            "glob._Globber, which CPython 3.14 replaced"
        ),
    },
    ("yara-python", "4.5.4", (3, 14)): {
        "kind": "binary-distribution",
        "reason": (
            "the reviewed lock contains no CPython 3.14 wheel; an unexecuted source build is "
            "not interpreter compatibility evidence"
        ),
    },
}

MAX_EVIDENCE_ENTRIES = 16_384
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_EVIDENCE_PATH_BYTES = 16_384
_REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class SupportAuditError(ValueError):
    """The project or lock cannot support a meaningful compatibility preflight."""


class FixtureEvidenceError(ValueError):
    """A tree cannot support canonical fixture evidence."""


def _normalise_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_toml(path: Path) -> tuple[dict, str]:
    try:
        payload = path.read_bytes()
        parsed = tomllib.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SupportAuditError(f"cannot read {path}: {exc}") from exc
    return parsed, hashlib.sha256(payload).hexdigest()


def _minimum_python(specifier: object, *, where: str) -> tuple[int, int]:
    if not isinstance(specifier, str):
        raise SupportAuditError(f"{where} requires-python must be text")
    match = re.fullmatch(r">=(\d+)\.(\d+)", specifier)
    if match is None:
        raise SupportAuditError(
            f"{where} requires-python {specifier!r} is outside the audited >=MAJOR.MINOR form"
        )
    return int(match.group(1)), int(match.group(2))


def _validate_lock_header(lock: dict) -> tuple[int, int]:
    if lock.get("version") != LOCK_FORMAT_VERSION:
        raise SupportAuditError(
            f"uv.lock version must be exactly {LOCK_FORMAT_VERSION} for this audit"
        )
    if lock.get("revision") != LOCK_REVISION:
        raise SupportAuditError(f"uv.lock revision must be exactly {LOCK_REVISION} for this audit")
    return _minimum_python(lock.get("requires-python"), where="uv.lock")


def _requirement_names(requirements: object, *, where: str) -> tuple[str, ...]:
    if not isinstance(requirements, list):
        raise SupportAuditError(f"{where} must be an array")
    names = []
    for index, requirement in enumerate(requirements):
        if not isinstance(requirement, str):
            raise SupportAuditError(f"{where}[{index}] must be text")
        match = _REQUIREMENT_NAME.match(requirement)
        if match is None:
            raise SupportAuditError(f"{where}[{index}] has no distribution name")
        names.append(_normalise_name(match.group(1)))
    if len(names) != len(set(names)):
        raise SupportAuditError(f"{where} contains a duplicate distribution")
    return tuple(names)


def _project_record(pyproject: dict) -> dict:
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise SupportAuditError("pyproject.toml has no [project] table")
    return project


def _project_dev_inventory(project: dict) -> frozenset[str]:
    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict):
        raise SupportAuditError("pyproject.toml has no [project.optional-dependencies] table")
    return frozenset(
        _requirement_names(optional.get("dev"), where="project.optional-dependencies.dev")
    )


def _validate_exact_inventory(actual: frozenset[str], *, where: str) -> None:
    missing = sorted(REQUIRED_ROOT_DEV_DISTRIBUTIONS - actual)
    unexpected = sorted(actual - REQUIRED_ROOT_DEV_DISTRIBUTIONS)
    if missing or unexpected:
        raise SupportAuditError(
            f"{where} differs from the reviewed dev/oracle inventory: "
            f"missing={missing!r}, unexpected={unexpected!r}"
        )


def _dependency_names(entries: object, *, where: str) -> tuple[str, ...]:
    if not isinstance(entries, list):
        raise SupportAuditError(f"{where} must be an array")
    names = []
    for index, entry in enumerate(entries):
        if isinstance(entry, str):
            name = entry
        elif isinstance(entry, dict):
            name = entry.get("name")
        else:
            raise SupportAuditError(f"{where}[{index}] must be text or an object")
        if not isinstance(name, str) or not name:
            raise SupportAuditError(f"{where}[{index}] has no distribution name")
        names.append(_normalise_name(name))
    if len(names) != len(set(names)):
        raise SupportAuditError(f"{where} contains a duplicate distribution")
    return tuple(names)


def _locked_records(lock: dict) -> dict[str, dict]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise SupportAuditError("uv.lock package closure must be a list")
    records: dict[str, dict] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise SupportAuditError(f"uv.lock package[{index}] must be an object")
        name = package.get("name")
        version = package.get("version")
        if (
            not isinstance(name, str)
            or _LABEL.fullmatch(name) is None
            or not isinstance(version, str)
            or not version
        ):
            raise SupportAuditError("locked package identity must contain text name/version")
        normalised = _normalise_name(name)
        if normalised in records:
            raise SupportAuditError(f"duplicate locked package identity: {normalised}")
        records[normalised] = package
    return records


def _locked_root_dev_inventory(records: dict[str, dict]) -> frozenset[str]:
    root = records.get("artifactforge")
    if root is None:
        raise SupportAuditError("uv.lock has no artifactforge root package")
    optional = root.get("optional-dependencies")
    if not isinstance(optional, dict):
        raise SupportAuditError("locked artifactforge package has no optional-dependencies")
    return frozenset(
        _dependency_names(optional.get("dev"), where="artifactforge.optional-dependencies.dev")
    )


def _validate_dependency_references(records: dict[str, dict]) -> None:
    known = set(records)
    for package_name, package in sorted(records.items()):
        references: list[tuple[str, str]] = []
        if "dependencies" in package:
            references.extend(
                (name, f"{package_name}.dependencies")
                for name in _dependency_names(
                    package["dependencies"], where=f"{package_name}.dependencies"
                )
            )
        optional = package.get("optional-dependencies", {})
        if not isinstance(optional, dict):
            raise SupportAuditError(f"{package_name}.optional-dependencies must be an object")
        for extra, entries in sorted(optional.items()):
            where = f"{package_name}.optional-dependencies.{extra}"
            references.extend((name, where) for name in _dependency_names(entries, where=where))
        for dependency, where in references:
            if dependency not in known:
                raise SupportAuditError(
                    f"{where} references absent locked distribution {dependency!r}"
                )


def _hashed_sdist(package: dict, *, name: str, version: str) -> dict:
    if package.get("wheels") not in (None, []):
        raise SupportAuditError(
            f"{name}=={version} reviewed source-only contract now contains locked wheels"
        )
    sdist = package.get("sdist")
    if not isinstance(sdist, dict):
        raise SupportAuditError(f"{name}=={version} source-only contract has no locked sdist")
    url = sdist.get("url")
    digest = sdist.get("hash")
    size = sdist.get("size")
    parsed_url = urlparse(url) if isinstance(url, str) else None
    if (
        parsed_url is None
        or parsed_url.scheme != "https"
        or not parsed_url.netloc
        or not Path(parsed_url.path).name
        or not Path(parsed_url.path).name.endswith((".tar.gz", ".zip"))
    ):
        raise SupportAuditError(f"{name}=={version} locked sdist has no valid URL")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SupportAuditError(f"{name}=={version} locked sdist has no exact SHA-256")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise SupportAuditError(f"{name}=={version} locked sdist has no positive size")
    return {"url": url, "sha256": digest.removeprefix("sha256:"), "size": size}


def audit_core(pyproject_path: Path, lock_path: Path, *, python: tuple[int, int]) -> dict:
    """Return a metadata-only zero-dependency core preflight."""
    pyproject, pyproject_sha256 = _read_toml(pyproject_path)
    lock, lock_sha256 = _read_toml(lock_path)
    lock_floor = _validate_lock_header(lock)
    project = _project_record(pyproject)
    dependencies = project.get("dependencies")
    if dependencies != []:
        raise SupportAuditError(
            "ArtifactForge core is only zero-dependency while project.dependencies is exactly empty"
        )
    build_system = pyproject.get("build-system")
    if not isinstance(build_system, dict):
        raise SupportAuditError("pyproject.toml has no [build-system] table")
    if build_system.get("build-backend") != "hatchling.build":
        raise SupportAuditError("the audited build backend must be hatchling.build")
    if build_system.get("requires") != ["hatchling==1.31.0"]:
        raise SupportAuditError("the audited Hatchling build requirement must be exact")
    project_floor = _minimum_python(project.get("requires-python"), where="pyproject.toml")
    if project_floor != lock_floor:
        raise SupportAuditError(
            f"project/lock Python floors disagree: {project_floor!r} != {lock_floor!r}"
        )
    blockers = {}
    if python < project_floor:
        blockers["python-floor"] = {
            "kind": "declared-floor",
            "required": f">={project_floor[0]}.{project_floor[1]}",
            "reason": "target is below the project and lock Python floor",
        }
    return {
        "profile": "core-preflight",
        "target_python": f"{python[0]}.{python[1]}",
        "declared_floor": f"{project_floor[0]}.{project_floor[1]}",
        "pyproject_sha256": pyproject_sha256,
        "lock_sha256": lock_sha256,
        "runtime_dependency_count": 0,
        "build_backend": "hatchling.build",
        "build_requirement": "hatchling==1.31.0",
        "claim_scope": (
            "metadata/dependency preflight; build, installation, and runtime execution remain "
            "required"
        ),
        "blockers": blockers,
        "status": STATUS_KNOWN_BLOCKED if blockers else STATUS_RUNTIME_CANDIDATE,
    }


def audit_full_oracles(
    lock_path: Path,
    *,
    python: tuple[int, int],
    pyproject_path: Path = Path("pyproject.toml"),
) -> dict:
    """Return a conservative full-oracle policy preflight without platform emulation."""
    pyproject, pyproject_sha256 = _read_toml(pyproject_path)
    lock, lock_sha256 = _read_toml(lock_path)
    lock_floor = _validate_lock_header(lock)
    project = _project_record(pyproject)
    project_floor = _minimum_python(project.get("requires-python"), where="pyproject.toml")
    if project_floor != lock_floor:
        raise SupportAuditError(
            f"project/lock Python floors disagree: {project_floor!r} != {lock_floor!r}"
        )
    project_inventory = _project_dev_inventory(project)
    _validate_exact_inventory(project_inventory, where="project.optional-dependencies.dev")
    records = _locked_records(lock)
    locked_inventory = _locked_root_dev_inventory(records)
    _validate_exact_inventory(locked_inventory, where="artifactforge.optional-dependencies.dev")
    if project_inventory != locked_inventory:
        raise SupportAuditError("project and locked ArtifactForge dev inventories disagree")
    _validate_dependency_references(records)

    source_installs = {}
    for name, policy in sorted(SOURCE_ONLY_PURE.items()):
        package = records.get(name)
        if package is None:
            raise SupportAuditError(f"required source-only oracle is absent: {name}")
        version = package["version"]
        if version != policy["version"]:
            raise SupportAuditError(
                f"source-only oracle {name} changed from reviewed version "
                f"{policy['version']} to {version}"
            )
        source_installs[name] = {
            "version": version,
            "basis": policy["basis"],
            **_hashed_sdist(package, name=name, version=version),
        }

    blockers = {}
    if python < project_floor:
        blockers["python-floor"] = {
            "kind": "declared-floor",
            "required": f">={project_floor[0]}.{project_floor[1]}",
            "reason": "target is below the project and lock Python floor",
        }
    for name, package in sorted(records.items()):
        policy = KNOWN_PROMOTION_BLOCKERS.get((name, package["version"], python))
        if policy is not None:
            blockers[name] = {"version": package["version"], **policy}

    oracle_versions = {
        name: records[name]["version"] for name in sorted(REQUIRED_ORACLE_DISTRIBUTIONS)
    }
    return {
        "profile": "full-oracle-preflight",
        "target_python": f"{python[0]}.{python[1]}",
        "declared_floor": f"{project_floor[0]}.{project_floor[1]}",
        "pyproject_sha256": pyproject_sha256,
        "lock_sha256": lock_sha256,
        "claim_scope": (
            "policy preflight; target installation, imports, positive controls, and behavioural "
            "tests remain required"
        ),
        "required_oracles": oracle_versions,
        "lane_tools": {name: records[name]["version"] for name in sorted(REQUIRED_LANE_TOOLS)},
        "source_install_required": source_installs,
        "blockers": dict(sorted(blockers.items())),
        "status": STATUS_KNOWN_BLOCKED if blockers else STATUS_RUNTIME_CANDIDATE,
    }


def _runtime_binding(target: tuple[int, int], *, required: bool) -> dict:
    if not required:
        return {"mode": "metadata-only"}
    implementation = sys.implementation.name
    running = sys.version_info[:2]
    if implementation != "cpython":
        raise SupportAuditError(f"runtime binding requires CPython, not {implementation!r}")
    if running != target:
        raise SupportAuditError(
            f"runtime binding requested Python {target[0]}.{target[1]}, but the executing "
            f"interpreter is {running[0]}.{running[1]}"
        )
    return {
        "mode": "current-cpython-bound",
        "implementation": implementation,
        "major_minor": f"{running[0]}.{running[1]}",
        "version": platform.python_version(),
        "executable": sys.executable,
    }


def _field(digest: "hashlib._Hash", payload: bytes) -> None:
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def fixture_tree_evidence(root: Path) -> dict:
    """Return a canonical, bounded inventory digest for one hostile fixture tree."""
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise FixtureEvidenceError(f"cannot inspect fixture root {root}: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise FixtureEvidenceError("fixture evidence root must be a real directory")

    entries: list[dict] = []
    total_bytes = 0

    def visit(directory: Path, relative: tuple[str, ...]) -> None:
        nonlocal total_bytes
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda entry: entry.name.encode("utf-8"))
        except (OSError, UnicodeError) as exc:
            raise FixtureEvidenceError(
                f"cannot enumerate fixture directory {directory}: {exc}"
            ) from exc
        initial_names = tuple(child.name for child in children)
        for child in children:
            try:
                relative_path = "/".join((*relative, child.name))
                encoded_path = relative_path.encode("utf-8")
            except UnicodeError as exc:
                raise FixtureEvidenceError("fixture path is not valid UTF-8") from exc
            if not relative_path or "\x00" in relative_path:
                raise FixtureEvidenceError("fixture contains an invalid relative path")
            if len(encoded_path) > MAX_EVIDENCE_PATH_BYTES:
                raise FixtureEvidenceError(
                    f"fixture path exceeds evidence bound: {relative_path!r}"
                )
            if len(entries) >= MAX_EVIDENCE_ENTRIES:
                raise FixtureEvidenceError("fixture exceeds evidence entry bound")
            try:
                before = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise FixtureEvidenceError(
                    f"cannot inspect fixture entry {relative_path!r}: {exc}"
                ) from exc
            mode = stat.S_IMODE(before.st_mode)
            if stat.S_ISLNK(before.st_mode):
                raise FixtureEvidenceError(f"fixture evidence rejects symlink {relative_path!r}")
            if stat.S_ISDIR(before.st_mode):
                entries.append({"path": relative_path, "kind": "directory", "mode": mode})
                visit(Path(child.path), (*relative, child.name))
                try:
                    after_directory = child.stat(follow_symlinks=False)
                except OSError as exc:
                    raise FixtureEvidenceError(
                        f"cannot recheck fixture directory {relative_path!r}: {exc}"
                    ) from exc
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                ) != (
                    after_directory.st_dev,
                    after_directory.st_ino,
                    after_directory.st_mode,
                ):
                    raise FixtureEvidenceError(
                        f"fixture directory changed while reading {relative_path!r}"
                    )
                continue
            if not stat.S_ISREG(before.st_mode):
                raise FixtureEvidenceError(
                    f"fixture evidence rejects special file {relative_path!r}"
                )
            if before.st_size < 0 or total_bytes + before.st_size > MAX_EVIDENCE_BYTES:
                raise FixtureEvidenceError("fixture exceeds evidence byte bound")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(child.path, flags)
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode):
                        raise FixtureEvidenceError(
                            f"fixture entry changed type while opening {relative_path!r}"
                        )
                    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                        raise FixtureEvidenceError(
                            f"fixture entry changed while opening {relative_path!r}"
                        )
                    file_digest = hashlib.sha256()
                    observed_size = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        observed_size += len(chunk)
                        if total_bytes + observed_size > MAX_EVIDENCE_BYTES:
                            raise FixtureEvidenceError("fixture exceeds evidence byte bound")
                        file_digest.update(chunk)
                    finished = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            except FixtureEvidenceError:
                raise
            except OSError as exc:
                raise FixtureEvidenceError(
                    f"cannot read fixture entry {relative_path!r}: {exc}"
                ) from exc
            identity_before = (before.st_dev, before.st_ino, before.st_mode, before.st_size)
            identity_after = (finished.st_dev, finished.st_ino, finished.st_mode, finished.st_size)
            if identity_before != identity_after or observed_size != finished.st_size:
                raise FixtureEvidenceError(f"fixture entry changed while reading {relative_path!r}")
            try:
                final_path = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise FixtureEvidenceError(
                    f"cannot recheck fixture entry {relative_path!r}: {exc}"
                ) from exc
            final_identity = (
                final_path.st_dev,
                final_path.st_ino,
                final_path.st_mode,
                final_path.st_size,
            )
            if identity_before != final_identity:
                raise FixtureEvidenceError(f"fixture entry changed after reading {relative_path!r}")
            total_bytes += observed_size
            entries.append(
                {
                    "path": relative_path,
                    "kind": "file",
                    "mode": mode,
                    "size": observed_size,
                    "sha256": file_digest.hexdigest(),
                }
            )
        try:
            with os.scandir(directory) as iterator:
                final_names = tuple(
                    sorted(
                        (entry.name for entry in iterator), key=lambda name: name.encode("utf-8")
                    )
                )
        except (OSError, UnicodeError) as exc:
            raise FixtureEvidenceError(
                f"cannot recheck fixture directory {directory}: {exc}"
            ) from exc
        if initial_names != final_names:
            raise FixtureEvidenceError(f"fixture directory changed while reading {directory}")

    visit(root, ())
    try:
        root_final = root.lstat()
    except OSError as exc:
        raise FixtureEvidenceError(f"cannot recheck fixture root {root}: {exc}") from exc
    if (root_stat.st_dev, root_stat.st_ino, root_stat.st_mode) != (
        root_final.st_dev,
        root_final.st_ino,
        root_final.st_mode,
    ):
        raise FixtureEvidenceError("fixture root changed while reading")
    entries.sort(key=lambda entry: entry["path"].encode("utf-8"))
    tree_digest = hashlib.sha256()
    tree_digest.update((FIXTURE_EVIDENCE_SCHEMA + "\0").encode("ascii"))
    file_count = 0
    directory_count = 0
    public_entries = []
    for entry in entries:
        _field(tree_digest, entry["kind"].encode("ascii"))
        _field(tree_digest, entry["path"].encode("utf-8"))
        _field(tree_digest, entry["mode"].to_bytes(4, "big"))
        public = {**entry, "mode": f"{entry['mode']:04o}"}
        if entry["kind"] == "directory":
            directory_count += 1
        else:
            file_count += 1
            _field(tree_digest, entry["size"].to_bytes(8, "big"))
            _field(tree_digest, bytes.fromhex(entry["sha256"]))
        public_entries.append(public)
    return {
        "root": str(root),
        "tree_sha256": tree_digest.hexdigest(),
        "file_count": file_count,
        "directory_count": directory_count,
        "regular_file_bytes": total_bytes,
        "entries": public_entries,
    }


def _python_version(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)", value)
    if match is None:
        raise argparse.ArgumentTypeError("Python version must be MAJOR.MINOR")
    return int(match.group(1)), int(match.group(2))


def _labelled_path(value: str) -> tuple[str, Path]:
    label, separator, raw_path = value.partition("=")
    if not separator or _LABEL.fullmatch(label) is None or not raw_path:
        raise argparse.ArgumentTypeError("fixture evidence must be LABEL=PATH")
    return label, Path(raw_path)


def _labelled_digest(value: str) -> tuple[str, str]:
    label, separator, digest = value.partition("=")
    if not separator or _LABEL.fullmatch(label) is None or _SHA256.fullmatch(digest) is None:
        raise argparse.ArgumentTypeError("expected fixture digest must be LABEL=SHA256")
    return label, digest


def _unique_mapping(values: list[tuple[str, object]], *, where: str) -> dict:
    result = {}
    for label, value in values:
        if label in result:
            raise FixtureEvidenceError(f"duplicate {where} label: {label}")
        result[label] = value
    return result


def _fixture_evidence_main(args: argparse.Namespace) -> int:
    try:
        roots = _unique_mapping(args.fixture_evidence, where="fixture evidence")
        expected = _unique_mapping(args.expect_fixture_digest, where="expected digest")
        unexpected = sorted(set(expected) - set(roots))
        if unexpected:
            raise FixtureEvidenceError(f"expected digest has no fixture root: {unexpected!r}")
        missing = sorted(set(roots) - set(expected)) if expected else []
        if missing:
            raise FixtureEvidenceError(f"fixture root has no expected digest: {missing!r}")
        fixtures = {}
        mismatches = {}
        for label, root in sorted(roots.items()):
            evidence = fixture_tree_evidence(root)
            expected_digest = expected.get(label)
            matches = expected_digest is None or evidence["tree_sha256"] == expected_digest
            fixtures[label] = {
                **evidence,
                "expected_tree_sha256": expected_digest,
                "matches_expected": matches if expected_digest is not None else None,
            }
            if expected_digest is not None and not matches:
                mismatches[label] = {
                    "expected": expected_digest,
                    "observed": evidence["tree_sha256"],
                }
    except FixtureEvidenceError as exc:
        print(f"fixture evidence error: {exc}", file=sys.stderr)
        return 2
    status = "mismatch" if mismatches else "verified" if expected else "observed"
    document = {
        "schema": FIXTURE_EVIDENCE_SCHEMA,
        "claim_scope": (
            "path/type/mode/byte inventory; fixture semantic verification remains separate"
        ),
        "status": status,
        "mismatches": mismatches,
        "fixtures": fixtures,
    }
    if args.json:
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    else:
        print(f"fixture tree evidence: {status}")
        for label, evidence in fixtures.items():
            print(f"  {label}: {evidence['tree_sha256']}")
    return 1 if mismatches else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("core", "full-oracles"))
    parser.add_argument("--python", type=_python_version)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--require-current-cpython", action="store_true")
    parser.add_argument("--fixture-evidence", action="append", type=_labelled_path, default=[])
    parser.add_argument(
        "--expect-fixture-digest", action="append", type=_labelled_digest, default=[]
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.fixture_evidence:
        if args.profile is not None or args.python is not None or args.require_current_cpython:
            parser.error("fixture evidence mode cannot be combined with support-audit options")
        return _fixture_evidence_main(args)
    if args.expect_fixture_digest:
        parser.error("--expect-fixture-digest requires --fixture-evidence")
    if args.profile is None or args.python is None:
        parser.error("support audit requires --profile and --python")

    try:
        binding = _runtime_binding(args.python, required=args.require_current_cpython)
        if args.profile == "core":
            report = audit_core(args.pyproject, args.lock, python=args.python)
        else:
            report = audit_full_oracles(
                args.lock, python=args.python, pyproject_path=args.pyproject
            )
    except SupportAuditError as exc:
        print(f"python-support audit error: {exc}", file=sys.stderr)
        return 2
    document = {"schema": SUPPORT_SCHEMA, **report, "runtime_binding": binding}
    if args.json:
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    else:
        print(f"python {report['target_python']} {report['profile']}: {report['status']}")
        for name, detail in report["blockers"].items():
            version = f"=={detail['version']}" if "version" in detail else ""
            print(f"  {name}{version}: {detail['reason']}")
        for name, detail in report.get("source_install_required", {}).items():
            print(f"  source install: {name}=={detail['version']} ({detail['basis']})")
    return 1 if report["status"] == STATUS_KNOWN_BLOCKED else 0


if __name__ == "__main__":
    raise SystemExit(main())
