# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Release evidence is deterministic, closed, and honest about its trust boundary."""

from __future__ import annotations

import base64
import csv
from functools import lru_cache
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile
import pytest

from artifactforge import release_evidence as release


def _sha256_b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()


def _rebind_sbom_serial(document: dict) -> None:
    unsigned = dict(document)
    unsigned.pop("serialNumber")
    identity = hashlib.sha256(release._canonical_bytes(unsigned)).hexdigest()
    document["serialNumber"] = "urn:uuid:" + str(
        release.uuid.uuid5(
            release.uuid.NAMESPACE_URL,
            f"https://artifactforge.dev/sbom/v1/{identity}",
        )
    )


def _mutate_first_tar_header(payload: bytes, offset: int, replacement: bytes) -> bytes:
    tar_payload = bytearray(gzip.decompress(payload))
    tar_payload[offset : offset + len(replacement)] = replacement
    tar_payload[148:156] = b"        "
    checksum = sum(tar_payload[:512])
    tar_payload[148:156] = f"{checksum:06o}".encode() + b"\0 "
    return gzip.compress(bytes(tar_payload), mtime=release.EXPECTED_ARCHIVE_EPOCH)


def _rewrite_closed_bundle(evidence, relative: str, document: dict) -> None:
    target = evidence / relative
    target.write_bytes(release._canonical_bytes(document))
    manifest_path = evidence / "release-evidence.json"
    manifest = json.loads(manifest_path.read_bytes())
    for item in manifest["byproducts"]:
        payload = (evidence / item["path"]).read_bytes()
        item["sha256"] = release._sha256_field(payload)
        item["size"] = len(payload)
    checksum_rows = [
        f"{release._sha256((evidence / item['path']).read_bytes())} *{item['path']}\n"
        for item in manifest["byproducts"]
    ]
    checksums = "".join(checksum_rows).encode()
    (evidence / "checksums.txt").write_bytes(checksums)
    manifest["checksums"] = {
        "path": "checksums.txt",
        "sha256": release._sha256_field(checksums),
        "size": len(checksums),
    }
    manifest_path.write_bytes(release._canonical_bytes(manifest))


def _set_nested(document: dict, path: tuple[str, ...], value) -> None:
    current = document
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value


def _metadata_payload(requirements: tuple[str, ...] | None = None) -> bytes:
    if requirements is None:
        return release._expected_package_metadata("0.5.0")
    selected = release.EXPECTED_DEV_REQUIREMENTS if requirements is None else requirements
    lines = [
        "Metadata-Version: 2.4",
        "Name: artifactforge",
        "Version: 0.5.0",
        "Requires-Python: >=3.11",
        "Provides-Extra: dev",
        *(f"Requires-Dist: {item}; extra == 'dev'" for item in selected),
        "",
        "",
    ]
    return "\n".join(lines).encode()


def _pyproject_payload() -> bytes:
    requirements = ",\n    ".join(repr(item) for item in release.EXPECTED_DEV_REQUIREMENTS)
    return (
        "[project]\n"
        "name='artifactforge'\n"
        "version='0.5.0'\n"
        f"description={release.EXPECTED_DESCRIPTION!r}\n"
        "requires-python='>=3.11'\n"
        "license={text='MIT'}\n"
        "license-files=['LICENSE']\n"
        "dependencies=[]\n"
        f"optional-dependencies.dev=[\n    {requirements},\n]\n"
        "[project.scripts]\n"
        "artifactforge='artifactforge.cli:main'\n"
        "[build-system]\n"
        "requires=['hatchling==1.31.0']\n"
        "build-backend='hatchling.build'\n"
        "[tool.hatch.build.targets.wheel]\n"
        "packages=['src/artifactforge']\n"
        "exclude=['integration']\n"
        "[tool.pytest.ini_options]\n"
        "testpaths=['tests']\n"
        "[tool.ruff]\n"
        "line-length=100\n"
        "target-version='py311'\n"
    ).encode()


def _fixture_locked_version(name: str) -> str:
    return {
        "dissect-target": "3.25.1",
        "jsonschema": "4.23.0",
        "liblnk-python": "20260525",
        "libscca-python": "20260527",
        "lnkparse3": "1.6.0",
        "pyelftools": "0.33",
        "pytest": "8.0.0",
        "pyxdg": "0.28",
        "ruff": "0.6.0",
    }.get(name, "1.0.0")


def _lock_payload() -> bytes:
    requirements = release._requirement_contract(
        release.EXPECTED_DEV_REQUIREMENTS, where="test requirements"
    )
    lines = [
        "version = 1",
        "revision = 3",
        'requires-python = ">=3.11"',
        "",
        "[[package]]",
        'name = "artifactforge"',
        'version = "0.5.0"',
        'source = { editable = "." }',
        "",
        "[package.optional-dependencies]",
        "dev = [",
        *(f'    {{ name = "{name}" }},' for name, _specifiers in requirements),
        "]",
        "",
        "[package.metadata]",
        "requires-dist = [",
    ]
    for name, specifiers in requirements:
        specifier = f', specifier = "{",".join(specifiers)}"' if specifiers else ""
        lines.append(f'    {{ name = "{name}", marker = "extra == \'dev\'"{specifier} }},')
    lines.extend(("]", 'provides-extras = ["dev"]', ""))
    for name, _specifiers in requirements:
        lines.extend(
            (
                "[[package]]",
                f'name = "{name}"',
                f'version = "{_fixture_locked_version(name)}"',
                'source = { registry = "https://pypi.org/simple" }',
                "",
            )
        )
    return ("\n".join(lines) + "\n").encode()


def _material_payloads() -> dict[str, bytes]:
    payloads = {
        "pyproject.toml": _pyproject_payload(),
        "uv.lock": _lock_payload(),
        "build-constraints.in": b"hatchling==1.31.0\n",
        "build-constraints.txt": b"hatchling==1.31.0 --hash=sha256:" + b"0" * 64 + b"\n",
        "ci-bootstrap-requirements.txt": b"uv==0.11.17 --hash=sha256:" + b"1" * 64 + b"\n",
        ".github/workflows/ci.yml": b"name: CI\n",
        ".github/workflows/release-evidence.yml": b"name: Release evidence\n",
    }
    for relative in release._MATERIAL_NAMES:
        payloads.setdefault(relative, f"# release material: {relative}\n".encode())
    payloads["src/artifactforge/release_evidence.py"] = b"# verifier\n"
    return payloads


def _wheel(
    *,
    requirements: tuple[str, ...] | None = None,
    release_payload: bytes = b"# verifier\n",
    link_member: bool = False,
    entry_point: bytes = b"[console_scripts]\nartifactforge = artifactforge.cli:main\n",
    release_mode: int = 0o644,
    extra_directory: bool = False,
    reverse_record: bool = False,
) -> bytes:
    dist_info = "artifactforge-0.5.0.dist-info"
    files = {
        f"{dist_info}/METADATA": _metadata_payload(requirements),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: hatchling 1.31.0\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        "artifactforge/__init__.py": b'__version__ = "0.5.0"\n',
        "artifactforge/release_evidence.py": release_payload,
        f"{dist_info}/entry_points.txt": entry_point,
        f"{dist_info}/licenses/LICENSE": b"MIT\n",
    }
    record_name = f"{dist_info}/RECORD"
    archive_names = sorted([*files, record_name], key=lambda name: (".dist-info/" in name, name))
    record_names = list(reversed(archive_names)) if reverse_record else archive_names
    rows = []
    for name in record_names:
        if name == record_name:
            rows.append([name, "", ""])
        else:
            member = files[name]
            rows.append([name, "sha256=" + _sha256_b64(member), str(len(member))])
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(rows)
    files[record_name] = stream.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if extra_directory:
            directory = zipfile.ZipInfo("surprise/", date_time=release.EXPECTED_ZIP_DATETIME)
            directory.external_attr = 0o40755 << 16
            archive.writestr(directory, b"")
        # Hatchling writes package members before dist-info metadata.  Archive order is not a
        # content-safety property; reproducibility is checked on the complete distribution bytes.
        backend_order = sorted(files.items(), key=lambda item: (".dist-info/" in item[0], item[0]))
        for name, payload in backend_order:
            info = zipfile.ZipInfo(name, date_time=release.EXPECTED_ZIP_DATETIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            if link_member and name.endswith("/__init__.py"):
                info.external_attr = 0o120777 << 16
            elif ".dist-info/" in name:
                info.external_attr = 0o644 << 16
            else:
                mode = release_mode if name.endswith("/release_evidence.py") else 0o644
                info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, payload)
    return output.getvalue()


def _sdist(
    *,
    extra_files: dict[str, bytes] | None = None,
    release_mode: int = 0o644,
) -> bytes:
    root = "artifactforge-0.5.0"
    files = {
        f"{root}/LICENSE": b"MIT\n",
        f"{root}/PKG-INFO": _metadata_payload(),
        f"{root}/src/artifactforge/__init__.py": b'__version__ = "0.5.0"\n',
        f"{root}/src/artifactforge/release_evidence.py": b"# verifier\n",
    }
    files.update({f"{root}/{name}": payload for name, payload in _material_payloads().items()})
    files.update(extra_files or {})
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        # Preserve a safe but intentionally non-lexical backend order.
        backend_order = sorted(
            files.items(), key=lambda item: ("/PKG-INFO" not in item[0], item[0])
        )
        for name, payload in backend_order:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = release_mode if name.endswith("/release_evidence.py") else 0o644
            info.mtime = release.EXPECTED_ARCHIVE_EPOCH
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(tar_bytes.getvalue(), mtime=release.EXPECTED_ARCHIVE_EPOCH)


def _raw_sbom(*, development: bool) -> dict:
    root_ref = "artifactforge-1@0.5.0"
    components = []
    dependencies = [{"ref": root_ref}]
    if development:
        direct_names = [
            name
            for name, _specifiers in release._requirement_contract(
                release.EXPECTED_DEV_REQUIREMENTS, where="test requirements"
            )
        ]
        components = []
        direct_refs = []
        for index, name in enumerate(direct_names):
            version = _fixture_locked_version(name)
            ref = f"{name}-{index}@{version}"
            direct_refs.append(ref)
            components.append(
                {
                    "type": "library",
                    "bom-ref": ref,
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{name}@{version}",
                }
            )
        dependencies = [{"ref": root_ref, "dependsOn": direct_refs}]
        dependencies.extend({"ref": ref} for ref in direct_refs)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "metadata": {
            "timestamp": "2026-08-03T00:00:00Z",
            "tools": [
                {
                    "vendor": "Astral Software Inc.",
                    "name": "uv",
                    "version": "0.11.17",
                }
            ],
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": "artifactforge",
                "version": "0.5.0",
                "properties": [{"name": "uv:package:is_project_root", "value": "true"}],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }


@lru_cache(maxsize=1)
def _fixture_git_tree() -> str:
    _wheel_files, _wheel_modes, sdist_files, sdist_modes = release._validated_archive_payloads(
        _wheel(), _sdist(), version="0.5.0"
    )
    source_files = {name: payload for name, payload in sdist_files.items() if name != "PKG-INFO"}
    source_modes = {name: mode for name, mode in sdist_modes.items() if name != "PKG-INFO"}
    return release._git_tree_oid(source_files, source_modes, width=40)


def _source(*, clean: bool = True) -> dict:
    return {
        "schema": "artifactforge-source-provenance-v1",
        "git_commit": "1" * 40,
        "git_tree": _fixture_git_tree(),
        "worktree_clean": clean,
        "dirty_snapshot_sha256": None if clean else "sha256:" + "3" * 64,
        "untracked_file_count": 0 if clean else 1,
        "materials": [
            {
                "path": path,
                "sha256": release._sha256_field(_material_payloads()[path]),
                "size": len(_material_payloads()[path]),
            }
            for path in release._MATERIAL_NAMES
        ],
    }


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    files = {
        "LICENSE": b"MIT\n",
        "src/artifactforge/__init__.py": b'__version__ = "0.5.0"\n',
        "src/artifactforge/release_evidence.py": b"# verifier\n",
    }
    files.update(_material_payloads())
    for relative, payload in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return root


@pytest.fixture
def dist_pair(tmp_path):
    first = tmp_path / "dist-a"
    second = tmp_path / "dist-b"
    first.mkdir()
    second.mkdir()
    payloads = {
        "artifactforge-0.5.0-py3-none-any.whl": _wheel(),
        "artifactforge-0.5.0.tar.gz": _sdist(),
    }
    for directory in (first, second):
        for name, payload in payloads.items():
            (directory / name).write_bytes(payload)
    return first, second


def _patch_inputs(monkeypatch, *, clean=True):
    observed_source = _source(clean=clean)
    monkeypatch.setattr(release, "source_snapshot", lambda _repo: observed_source)
    monkeypatch.setattr(
        release,
        "_repository_source_paths",
        lambda repo: {
            path.relative_to(repo).as_posix(): 0o644
            for path in sorted(repo.rglob("*"))
            if path.is_file()
        },
    )

    def bound_exports(_repo, _uv, *, runtime_repetitions, development_repetitions):
        return (
            "0.11.17",
            "sha256:" + "a" * 64,
            [_raw_sbom(development=False) for _ in range(runtime_repetitions)],
            [_raw_sbom(development=True) for _ in range(development_repetitions)],
        )

    monkeypatch.setattr(release, "_bound_uv_exports", bound_exports)
    return observed_source


def test_repository_dependency_files_match_the_closed_release_contract():
    repository = Path(__file__).resolve().parents[1]
    project = release._project_contract(
        (repository / "pyproject.toml").read_bytes(),
        expected_version=release.__version__,
    )
    locked = release._locked_development_contract(
        (repository / "uv.lock").read_bytes(),
        project_version=release.__version__,
    )
    assert project["dev_requirements"] == release._requirement_contract(
        release.EXPECTED_METADATA_REQUIREMENTS,
        where="expected wheel metadata requirements",
    )
    assert locked["component_count"] >= len(release.EXPECTED_DEV_REQUIREMENTS)


def test_bound_uv_exports_uses_one_private_snapshot_and_rejects_original_swap(
    tmp_path, monkeypatch
):
    original = tmp_path / "uv"
    original.write_bytes(b"first exporter payload")
    original.chmod(0o755)
    observed_private_paths = []

    def fake_version(private):
        private_path = Path(private)
        observed_private_paths.append(private_path)
        assert private_path != original.resolve()
        assert private_path.read_bytes() == b"first exporter payload"
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"second exporter payload")
        replacement.chmod(0o755)
        os.replace(replacement, original)
        return release.EXPECTED_UV_VERSION

    def fake_export(_repo, private, *, include_dev):
        private_path = Path(private)
        observed_private_paths.append(private_path)
        assert private_path.read_bytes() == b"first exporter payload"
        return _raw_sbom(development=include_dev)

    monkeypatch.setattr(release, "_uv_version", fake_version)
    monkeypatch.setattr(release, "_uv_export", fake_export)
    with pytest.raises(release.ReleaseEvidenceError, match="pinned uv exporter changed"):
        release._bound_uv_exports(
            tmp_path,
            str(original),
            runtime_repetitions=1,
            development_repetitions=1,
        )
    assert len(observed_private_paths) == 3
    assert len(set(observed_private_paths)) == 1


@pytest.mark.parametrize("stream", ("stdout", "stderr"))
def test_bounded_subprocess_kills_output_at_the_configured_cap(tmp_path, stream):
    descriptor = "1" if stream == "stdout" else "2"
    with pytest.raises(release.ReleaseEvidenceError, match=f"{stream} exceeded"):
        release._run_bounded_process(
            [
                release.sys.executable,
                "-c",
                f"import os; os.write({descriptor}, b'x' * 65536)",
            ],
            cwd=tmp_path,
            env={},
            timeout=5,
            stdout_limit=1024,
            stderr_limit=1024,
            label="hostile child",
        )


@pytest.mark.skipif(os.name != "posix", reason="process-group regression is POSIX-specific")
def test_bounded_subprocess_kills_pipe_inheriting_descendants_at_deadline(tmp_path):
    child = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)']); "
        "time.sleep(2)"
    )
    baseline = {thread.ident for thread in release.threading.enumerate()}
    started = release.time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        release._run_bounded_process(
            [release.sys.executable, "-c", child],
            cwd=tmp_path,
            env={},
            timeout=0.1,
            stdout_limit=1024,
            stderr_limit=1024,
            label="descendant probe",
        )
    assert release.time.monotonic() - started < 1
    assert {thread.ident for thread in release.threading.enumerate()} == baseline


def test_create_and_verify_are_canonical_deterministic_and_nonreportable(
    tmp_path, repository, dist_pair, monkeypatch
):
    _patch_inputs(monkeypatch)
    first = tmp_path / "evidence-a"
    second = tmp_path / "evidence-b"
    one = release.create_release_evidence(
        *dist_pair, first, repository_root=repository, uv_executable="pinned-uv"
    )
    two = release.create_release_evidence(
        *dist_pair, second, repository_root=repository, uv_executable="pinned-uv"
    )
    assert one == two == release.verify_release_evidence(first)
    assert one["classification"] == release.CLASSIFICATION
    assert one["validation"]["runtime_dependency_count"] == 0
    assert one["validation"]["development_component_count"] == len(
        release.EXPECTED_DEV_REQUIREMENTS
    )
    for relative in release._bundle_inventory(first):
        assert (first / relative).read_bytes() == (second / relative).read_bytes()
    for path in first.rglob("*.json"):
        raw = path.read_bytes()
        assert (
            raw.endswith(b"\n")
            and json.dumps(
                json.loads(raw),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
            == raw
        )


def test_create_refuses_dirty_source_without_explicit_diagnostic_flag(
    tmp_path, repository, dist_pair, monkeypatch
):
    _patch_inputs(monkeypatch, clean=False)
    with pytest.raises(release.ReleaseEvidenceError, match="dirty worktree"):
        release.create_release_evidence(
            *dist_pair, tmp_path / "blocked", repository_root=repository
        )
    manifest = release.create_release_evidence(
        *dist_pair,
        tmp_path / "diagnostic",
        repository_root=repository,
        allow_dirty=True,
    )
    assert manifest["source"]["worktree_clean"] is False
    assert manifest["classification"]["reportable_security_result"] is False


def test_source_snapshot_hashes_raw_tracked_bytes_despite_git_textconv(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    files = {
        **_material_payloads(),
        ".gitattributes": b"src/artifactforge/release_evidence.py diff=hide\n",
        "src/artifactforge/release_evidence.py": b"# verifier\n",
    }
    for relative, payload in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    for command in (
        ("init", "--quiet"),
        ("config", "user.email", "artifactforge@example.invalid"),
        ("config", "user.name", "ArtifactForge Test"),
        ("add", "."),
        ("commit", "--quiet", "-m", "fixture"),
        ("config", "diff.hide.textconv", shutil.which("true") or "/usr/bin/true"),
    ):
        subprocess.run(
            ["git", *command],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    hostile_bin = tmp_path / "hostile-bin"
    hostile_bin.mkdir()
    fake_git = hostile_bin / "git"
    fake_git.write_text("#!/bin/sh\necho 0000000000000000000000000000000000000000\n")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(hostile_bin))
    assert release.source_snapshot(repo)["worktree_clean"] is True
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "attacker-git-dir"))
    (repo / "src/artifactforge/release_evidence.py").write_bytes(b"# MUTATED BUT CLAIMED CLEAN\n")
    if os.name == "posix":
        os.symlink(b"\xff", os.fsencode(repo / "hostile-link"))
    observed = release.source_snapshot(repo)
    assert observed["worktree_clean"] is False
    assert observed["dirty_snapshot_sha256"].startswith("sha256:")


def test_create_refuses_nonidentical_builds(tmp_path, repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    (dist_pair[1] / "artifactforge-0.5.0-py3-none-any.whl").write_bytes(b"different")
    with pytest.raises(release.ReleaseEvidenceError, match="not byte-identical"):
        release.create_release_evidence(
            *dist_pair, tmp_path / "evidence", repository_root=repository
        )


def test_create_refuses_same_root_and_stale_source(tmp_path, repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    with pytest.raises(release.ReleaseEvidenceError, match="distinct directory inodes"):
        release.create_release_evidence(
            dist_pair[0], dist_pair[0], tmp_path / "same-root", repository_root=repository
        )
    (repository / "src/artifactforge/release_evidence.py").write_bytes(b"# current source\n")
    with pytest.raises(release.ReleaseEvidenceError, match="does not match current source"):
        release.create_release_evidence(*dist_pair, tmp_path / "stale", repository_root=repository)


def test_create_refuses_hardlinked_subjects(tmp_path, repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    for name in (path.name for path in dist_pair[0].iterdir()):
        (dist_pair[1] / name).unlink()
        os.link(dist_pair[0] / name, dist_pair[1] / name)
    with pytest.raises(release.ReleaseEvidenceError, match="share one subject inode"):
        release.create_release_evidence(
            *dist_pair, tmp_path / "hardlinked", repository_root=repository
        )


def test_create_cannot_replace_a_destination_that_appears_at_publication(
    tmp_path, repository, dist_pair, monkeypatch
):
    _patch_inputs(monkeypatch)
    output = tmp_path / "evidence"
    real_publish = release.rename_directory_no_replace

    def race(source, destination, **arguments):
        destination.mkdir()
        (destination / "attacker-owned").write_bytes(b"preserve me")
        return real_publish(source, destination, **arguments)

    monkeypatch.setattr(release, "rename_directory_no_replace", race)
    with pytest.raises(release.ReleaseEvidenceError, match="without replacing"):
        release.create_release_evidence(*dist_pair, output, repository_root=repository)
    assert (output / "attacker-owned").read_bytes() == b"preserve me"
    assert not list(tmp_path.glob(".evidence.stage-*"))


def test_create_refuses_output_inside_source(repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    with pytest.raises(release.ReleaseEvidenceError, match="outside the source repository"):
        release.create_release_evidence(
            *dist_pair, repository / "evidence", repository_root=repository
        )


def test_wheel_record_tamper_is_detected():
    wheel = bytearray(_wheel())
    wheel[len(wheel) // 3] ^= 1
    with pytest.raises(release.ReleaseEvidenceError):
        release._inspect_wheel(
            "artifactforge-0.5.0-py3-none-any.whl", bytes(wheel), version="0.5.0"
        )


def test_wheel_dependency_marker_cannot_hide_an_unconditional_runtime_branch():
    wheel = _wheel(requirements=('definitely-evil; extra == "dev" or python_version >= "3.11"',))
    with pytest.raises(release.ReleaseEvidenceError, match="metadata|dev requirements"):
        release._inspect_wheel("artifactforge-0.5.0-py3-none-any.whl", wheel, version="0.5.0")


def test_distribution_names_and_archive_paths_must_be_canonical():
    with pytest.raises(release.ReleaseEvidenceError, match="wheel filename"):
        release._inspect_wheel(
            "artifactforge-EVIL-0.5.0-py3-none-any.whl", _wheel(), version="0.5.0"
        )


def test_sdist_cannot_smuggle_a_repository_file_outside_git_inventory(repository, monkeypatch):
    hidden = repository / ".git/config"
    hidden.parent.mkdir()
    hidden.write_bytes(b"secret repository configuration\n")
    allowed = {
        path.relative_to(repository).as_posix(): 0o644
        for path in repository.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }
    monkeypatch.setattr(release, "_repository_source_paths", lambda _repo: allowed)
    hostile = _sdist(
        extra_files={
            "artifactforge-0.5.0/.git/config": hidden.read_bytes(),
        }
    )
    release._inspect_sdist("artifactforge-0.5.0.tar.gz", hostile, version="0.5.0")
    with pytest.raises(release.ReleaseEvidenceError, match="sdist/Git source inventories differ"):
        release._bind_distribution_chain(
            _wheel(), hostile, version="0.5.0", repository_root=repository
        )
    with pytest.raises(release.ReleaseEvidenceError, match="sdist filename"):
        release._inspect_sdist("artifactforge-EVIL-0.5.0.tar.gz", _sdist(), version="0.5.0")
    with pytest.raises(release.ReleaseEvidenceError, match="unsafe test path"):
        release._safe_relative_name("safe//but-noncanonical", "test path")
    with pytest.raises(release.ReleaseEvidenceError, match="wheel package bytes differ"):
        release._bind_distribution_chain(
            _wheel(release_payload=b"# different wheel source\n"),
            _sdist(),
            version="0.5.0",
            repository_root=None,
        )
    with pytest.raises(release.ReleaseEvidenceError, match="console entry point"):
        release._bind_distribution_chain(
            _wheel(entry_point=b"[console_scripts]\nartifactforge = attacker:main\n"),
            _sdist(),
            version="0.5.0",
            repository_root=None,
        )


def test_sdist_traversal_is_rejected():
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
        info = tarfile.TarInfo("../escape")
        info.size = 1
        info.mtime = release.EXPECTED_ARCHIVE_EPOCH
        archive.addfile(info, io.BytesIO(b"x"))
    hostile = gzip.compress(tar_bytes.getvalue(), mtime=release.EXPECTED_ARCHIVE_EPOCH)
    with pytest.raises(release.ReleaseEvidenceError, match="unsafe sdist member"):
        release._inspect_sdist("artifactforge-0.5.0.tar.gz", hostile, version="0.5.0")


def test_distribution_containers_reject_hidden_bytes_and_link_entries():
    wheel = _wheel()
    for hostile in (b"hidden-prefix" + wheel, wheel + b"hidden-suffix"):
        with pytest.raises(release.ReleaseEvidenceError, match="ZIP"):
            release._inspect_wheel("artifactforge-0.5.0-py3-none-any.whl", hostile, version="0.5.0")
    with pytest.raises(release.ReleaseEvidenceError, match="link or special"):
        release._inspect_wheel(
            "artifactforge-0.5.0-py3-none-any.whl",
            _wheel(link_member=True),
            version="0.5.0",
        )
    with pytest.raises(release.ReleaseEvidenceError, match="directory|central"):
        release._inspect_wheel(
            "artifactforge-0.5.0-py3-none-any.whl",
            _wheel(extra_directory=True),
            version="0.5.0",
        )
    with pytest.raises(release.ReleaseEvidenceError, match="canonical"):
        release._inspect_wheel(
            "artifactforge-0.5.0-py3-none-any.whl",
            _wheel(release_mode=0o4644),
            version="0.5.0",
        )
    with pytest.raises(release.ReleaseEvidenceError, match="RECORD bytes/order"):
        release._inspect_wheel(
            "artifactforge-0.5.0-py3-none-any.whl",
            _wheel(reverse_record=True),
            version="0.5.0",
        )

    for central_offset, replacement in ((4, b"\x15\x03"), (36, b"\x01\x00")):
        hostile = bytearray(_wheel())
        central = hostile.index(b"PK\x01\x02")
        hostile[central + central_offset : central + central_offset + 2] = replacement
        with pytest.raises(release.ReleaseEvidenceError, match="central"):
            release._inspect_wheel(
                "artifactforge-0.5.0-py3-none-any.whl", bytes(hostile), version="0.5.0"
            )

    sdist = _sdist()
    for hostile in (
        sdist + sdist,
        gzip.compress(
            gzip.decompress(sdist) + b"hidden-tar-suffix",
            mtime=release.EXPECTED_ARCHIVE_EPOCH,
        ),
    ):
        with pytest.raises(release.ReleaseEvidenceError, match="gzip member|trailing data"):
            release._inspect_sdist("artifactforge-0.5.0.tar.gz", hostile, version="0.5.0")
    for hostile in (
        gzip.compress(
            gzip.decompress(sdist) + (b"\0" * 512),
            mtime=release.EXPECTED_ARCHIVE_EPOCH,
        ),
        _mutate_first_tar_header(sdist, 156, b"\0"),
        _mutate_first_tar_header(sdist, 157, b"x"),
        _mutate_first_tar_header(sdist, 329, b"0000001\0"),
    ):
        with pytest.raises(release.ReleaseEvidenceError, match="tar|noncanonical"):
            release._inspect_sdist("artifactforge-0.5.0.tar.gz", hostile, version="0.5.0")


def test_distribution_chain_binds_source_sdist_and_wheel_modes(repository, monkeypatch):
    inventory = {
        path.relative_to(repository).as_posix(): 0o644
        for path in repository.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(release, "_repository_source_paths", lambda _repo: inventory)
    with pytest.raises(release.ReleaseEvidenceError, match="mode does not match current source"):
        release._bind_distribution_chain(
            _wheel(release_mode=0o755),
            _sdist(release_mode=0o755),
            version="0.5.0",
            repository_root=repository,
        )


def test_offline_distribution_chain_binds_recorded_materials_to_sdist_bytes():
    source = _source()
    source["materials"][0]["sha256"] = "sha256:" + "1" * 64
    with pytest.raises(release.ReleaseEvidenceError, match="record differs from the sdist"):
        release._bind_distribution_chain(
            _wheel(),
            _sdist(),
            version="0.5.0",
            repository_root=None,
            source_record=source,
        )


def test_offline_clean_distribution_reconstructs_the_recorded_git_tree():
    source = _source()
    source["git_tree"] = "0" * 40
    with pytest.raises(release.ReleaseEvidenceError, match="do not reproduce source.git_tree"):
        release._bind_distribution_chain(
            _wheel(),
            _sdist(),
            version="0.5.0",
            repository_root=None,
            source_record=source,
        )


def test_runtime_sbom_rejects_a_dependency():
    subject = {
        "kind": "wheel",
        "name": "artifactforge-0.5.0-py3-none-any.whl",
        "sha256": "sha256:" + "6" * 64,
        "size": 10,
    }
    document = release._normalize_uv_sbom(
        _raw_sbom(development=False),
        profile_name="runtime-distribution",
        source=_source(),
        project_version="0.5.0",
        uv_version="0.11.17",
        subject=subject,
    )
    document["components"].append(
        {
            "type": "library",
            "name": "surprise",
            "version": "1",
            "bom-ref": "pkg:pypi/surprise@1",
            "purl": "pkg:pypi/surprise@1",
            "scope": "optional",
        }
    )
    document["dependencies"].append({"ref": "pkg:pypi/surprise@1"})
    _rebind_sbom_serial(document)
    with pytest.raises(release.ReleaseEvidenceError, match="unreachable|empty dependency closure"):
        release.validate_cyclonedx(
            document,
            profile_name="runtime-distribution",
            subject=subject,
            source=_source(),
            project_version="0.5.0",
        )


def test_development_sbom_requires_every_direct_oracle_requirement():
    raw = _raw_sbom(development=True)
    retained = raw["components"][:1]
    retained_ref = retained[0]["bom-ref"]
    raw["components"] = retained
    raw["dependencies"] = [
        {"ref": raw["metadata"]["component"]["bom-ref"], "dependsOn": [retained_ref]},
        {"ref": retained_ref},
    ]
    with pytest.raises(release.ReleaseEvidenceError, match="exact direct requirement set"):
        release._normalize_uv_sbom(
            raw,
            profile_name="development-oracle-closure",
            source=_source(),
            project_version="0.5.0",
            uv_version="0.11.17",
            subject=None,
        )


def test_development_sbom_versions_and_edges_are_bound_to_the_bundled_lock():
    contract = release._locked_development_contract(_lock_payload(), project_version="0.5.0")
    document = release._normalize_uv_sbom(
        _raw_sbom(development=True),
        profile_name="development-oracle-closure",
        source=_source(),
        project_version="0.5.0",
        uv_version="0.11.17",
        subject=None,
    )
    target = next(item for item in document["components"] if item["name"] == "dissect-target")
    old_ref = target["bom-ref"]
    new_ref = "pkg:pypi/dissect-target@999.0"
    target["version"] = "999.0"
    target["bom-ref"] = target["purl"] = new_ref
    for row in document["dependencies"]:
        if row["ref"] == old_ref:
            row["ref"] = new_ref
        if old_ref in row.get("dependsOn", []):
            row["dependsOn"] = sorted(
                new_ref if child == old_ref else child for child in row["dependsOn"]
            )
    document["components"].sort(key=lambda item: item["bom-ref"])
    document["dependencies"].sort(key=lambda item: item["ref"])
    _rebind_sbom_serial(document)
    release.validate_cyclonedx(
        document,
        profile_name="development-oracle-closure",
        subject=None,
        source=_source(),
        project_version="0.5.0",
    )
    with pytest.raises(release.ReleaseEvidenceError, match="differ from uv.lock"):
        release._validate_development_sbom_against_lock(document, contract)


def test_lock_rejects_a_direct_version_outside_its_declared_constraint():
    hostile = _lock_payload().replace(
        b'name = "dissect-target"\nversion = "3.25.1"',
        b'name = "dissect-target"\nversion = "999.0"',
        1,
    )
    with pytest.raises(release.ReleaseEvidenceError, match="does not satisfy"):
        release._locked_development_contract(hostile, project_version="0.5.0")


@pytest.mark.parametrize("location", ("ref", "child"))
def test_raw_uv_dependency_references_reject_unhashable_values(location):
    raw = _raw_sbom(development=True)
    if location == "ref":
        raw["dependencies"][0]["ref"] = []
    else:
        raw["dependencies"][0]["dependsOn"][0] = []
    with pytest.raises(release.ReleaseEvidenceError, match="must be a non-empty string"):
        release._normalize_uv_sbom(
            raw,
            profile_name="development-oracle-closure",
            source=_source(),
            project_version="0.5.0",
            uv_version="0.11.17",
            subject=None,
        )


@pytest.mark.parametrize(
    "addition",
    (
        b"\n[tool.hatch.build.hooks.custom]\npath='build_hook.py'\n",
        b"\n[tool.uv.sources]\npytest={path='../attacker'}\n",
        b"\n[project.entry-points.rogue]\nx='attacker:run'\n",
    ),
)
def test_project_contract_rejects_build_and_dependency_override_surfaces(addition):
    with pytest.raises(release.ReleaseEvidenceError, match="closed release profile"):
        release._project_contract(_pyproject_payload() + addition, expected_version="0.5.0")


def test_verifier_rejects_every_byproduct_tamper(tmp_path, repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    pristine = tmp_path / "pristine"
    release.create_release_evidence(*dist_pair, pristine, repository_root=repository)
    targets = [
        relative
        for relative in release._bundle_inventory(pristine)
        if relative != "release-evidence.json"
    ]
    for index, relative in enumerate(targets):
        mutant = tmp_path / f"mutant-{index}"
        os.mkdir(mutant)
        for source in pristine.rglob("*"):
            destination = mutant / source.relative_to(pristine)
            if source.is_dir():
                destination.mkdir()
            else:
                destination.write_bytes(source.read_bytes())
        path = mutant / relative
        path.write_bytes(path.read_bytes() + b"x")
        with pytest.raises(release.ReleaseEvidenceError):
            release.verify_release_evidence(mutant)


def test_verifier_rejects_manifest_claim_escalation_and_undeclared_file(
    tmp_path, repository, dist_pair, monkeypatch
):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    manifest_path = evidence / "release-evidence.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["classification"]["signing_performed_by_command"] = True
    manifest_path.write_bytes(release._canonical_bytes(manifest))
    with pytest.raises(release.ReleaseEvidenceError, match="classification"):
        release.verify_release_evidence(evidence)
    manifest["classification"]["signing_performed_by_command"] = False
    manifest_path.write_bytes(release._canonical_bytes(manifest))
    (evidence / "surprise").write_bytes(b"x")
    with pytest.raises(release.ReleaseEvidenceError, match="undeclared"):
        release.verify_release_evidence(evidence)


def test_verifier_rejects_noncanonical_subject_order(tmp_path, repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    manifest_path = evidence / "release-evidence.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["subjects"].reverse()
    manifest_path.write_bytes(release._canonical_bytes(manifest))
    with pytest.raises(release.ReleaseEvidenceError, match="canonically ordered"):
        release.verify_release_evidence(evidence)


def test_offline_verifier_recomputes_sdist_inventory_counts(
    tmp_path, repository, dist_pair, monkeypatch
):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    manifest_path = evidence / "release-evidence.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["validation"]["distribution_chain"]["sdist_source_file_count"] = 1
    manifest_path.write_bytes(release._canonical_bytes(manifest))
    with pytest.raises(release.ReleaseEvidenceError, match="does not reproduce"):
        release.verify_release_evidence(evidence)


def test_subject_kind_type_error_is_closed_at_the_cli(tmp_path, repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    manifest_path = evidence / "release-evidence.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["subjects"][0]["kind"] = []
    manifest_path.write_bytes(release._canonical_bytes(manifest))
    assert release.main(["verify", str(evidence)]) == 2


def test_sbom_depends_on_type_error_is_closed_at_the_cli(
    tmp_path, repository, dist_pair, monkeypatch, capsys
):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    relative = "sbom/development-oracles.cdx.json"
    document = json.loads((evidence / relative).read_bytes())
    document["dependencies"][0]["dependsOn"][0] = []
    _rebind_sbom_serial(document)
    _rewrite_closed_bundle(evidence, relative, document)
    assert release.main(["verify", str(evidence)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_verifier_rejects_duplicate_json_member(tmp_path, repository, dist_pair, monkeypatch):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    path = evidence / "release-evidence.json"
    raw = path.read_bytes()
    path.write_bytes(raw.replace(b'{"build":', b'{"build":{},"build":', 1))
    with pytest.raises(release.ReleaseEvidenceError, match="duplicate JSON member"):
        release.verify_release_evidence(evidence)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("schema_version",), True),
        (("limitations",), []),
        (("build",), []),
        (("build", "supplied_distribution_root_count"), 999),
        (("build", "tools", "python"), "0.0"),
        (("validation", "byte_identical_supplied_distributions"), "not actually"),
        (("validation", "distinct_distribution_input_inodes"), False),
        (("validation", "normalized_sbom_repetitions"), 0),
        (("source", "git_tree"), "f" * 40),
    ),
)
def test_verifier_rejects_every_nested_manifest_claim_mutation(
    tmp_path, repository, dist_pair, monkeypatch, path, value
):
    _patch_inputs(monkeypatch)
    pristine = tmp_path / "pristine"
    release.create_release_evidence(*dist_pair, pristine, repository_root=repository)
    mutant = tmp_path / "mutant"
    shutil.copytree(pristine, mutant)
    manifest_path = mutant / "release-evidence.json"
    manifest = json.loads(manifest_path.read_bytes())
    _set_nested(manifest, path, value)
    manifest_path.write_bytes(release._canonical_bytes(manifest))
    with pytest.raises(release.ReleaseEvidenceError):
        release.verify_release_evidence(mutant)


@pytest.mark.parametrize(
    "mutation",
    (
        "boolean-version",
        "missing-lifecycle",
        "wrong-root-version",
        "missing-source-property",
        "disconnected-self-cycle",
        "false-component-type",
        "nonstring-root-ref",
    ),
)
def test_verifier_rejects_self_consistent_dishonest_sboms(
    tmp_path, repository, dist_pair, monkeypatch, mutation
):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    relative = "sbom/development-oracles.cdx.json"
    document = json.loads((evidence / relative).read_bytes())
    if mutation == "boolean-version":
        document["version"] = True
    elif mutation == "missing-lifecycle":
        document["metadata"].pop("lifecycles")
    elif mutation == "wrong-root-version":
        document["metadata"]["component"]["version"] = "999"
    elif mutation == "missing-source-property":
        document["metadata"]["component"]["properties"] = [
            item
            for item in document["metadata"]["component"]["properties"]
            if item["name"] != "artifactforge:source:git-tree"
        ]
    elif mutation == "disconnected-self-cycle":
        ref = "pkg:pypi/surprise@1"
        document["components"].append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": "surprise",
                "version": "1",
                "purl": ref,
                "scope": "optional",
            }
        )
        document["components"].sort(key=lambda item: item["bom-ref"])
        document["dependencies"].append({"ref": ref, "dependsOn": [ref]})
        document["dependencies"].sort(key=lambda item: item["ref"])
    elif mutation == "false-component-type":
        document["components"][0]["type"] = False
    else:
        document["metadata"]["component"]["bom-ref"] = []
    _rebind_sbom_serial(document)
    _rewrite_closed_bundle(evidence, relative, document)
    with pytest.raises(release.ReleaseEvidenceError):
        release.verify_release_evidence(evidence)


def test_verifier_rejects_an_undeclared_empty_directory(
    tmp_path, repository, dist_pair, monkeypatch
):
    _patch_inputs(monkeypatch)
    evidence = tmp_path / "evidence"
    release.create_release_evidence(*dist_pair, evidence, repository_root=repository)
    (evidence / "undeclared-empty").mkdir()
    with pytest.raises(release.ReleaseEvidenceError, match="empty directory"):
        release.verify_release_evidence(evidence)


def test_malformed_json_and_toml_fail_closed_without_tracebacks(tmp_path, capsys):
    with pytest.raises(release.ReleaseEvidenceError, match="integer"):
        release._strict_json(b"1" * 5000, label="hostile", maximum=6000)
    with pytest.raises(release.ReleaseEvidenceError, match="surrogate"):
        release._strict_json(b'{"x":"\\ud800"}', label="hostile", maximum=6000)
    with pytest.raises(release.ReleaseEvidenceError, match="project table"):
        release._project_contract(b"project=[]\n", expected_version="0.5.0")
    for hostile_toml in (
        b"x=" + (b"[" * 500) + b"0" + (b"]" * 500),
        b"x=" + (b"1" * 5000),
    ):
        with pytest.raises(release.ReleaseEvidenceError, match="project identity"):
            release._project_contract(hostile_toml, expected_version="0.5.0")
    evidence = tmp_path / "bad"
    evidence.mkdir()
    manifest_path = evidence / "release-evidence.json"
    for hostile_json in (
        b"1" * 5000,
        b'{"x":"\\udfff"}',
        b'{"\\ud800":1,"\\ud800":2}',
    ):
        manifest_path.write_bytes(hostile_json)
        assert release.main(["verify", str(evidence)]) == 2
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO test requires POSIX mkfifo")
def test_regular_file_reader_rejects_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "raced-input"
    os.mkfifo(fifo)
    with pytest.raises(release.ReleaseEvidenceError, match="not a regular file"):
        release._read_regular(fifo, maximum=1024, label="hostile input")
