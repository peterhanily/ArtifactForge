# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Platform-independent contract and mutation tests for the Windows native lane."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import runpy
import shutil
import stat
import struct
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifactforge.artifacts.shell_link import parse_shell_link
from artifactforge.artifacts.prefetch import build_prefetch_v30
from artifactforge.content import build_pe_stub
from artifactforge.fixture import FixtureSpecV2, ProfileSpecV2, build_fixture


_SCRIPT = Path(__file__).parents[1] / "scripts" / "attest_windows_native.py"
_GLOBALS = runpy.run_path(str(_SCRIPT))
_authenticode = _GLOBALS["_authenticode"]
_canonical_digest = _GLOBALS["_canonical_digest"]
_canonical_json_bytes = _GLOBALS["_canonical_json_bytes"]
_cross_api_file_state_matches = _GLOBALS["_cross_api_file_state_matches"]
_file_identity = _GLOBALS["_file_identity"]
_find_powershell = _GLOBALS["_find_powershell"]
_fixture_state = _GLOBALS["_fixture_state"]
_inventory_path_state_matches = _GLOBALS["_inventory_path_state_matches"]
_load_prerequisite = _GLOBALS["_load_prerequisite"]
_logical_zone_map = _GLOBALS["_logical_zone_map"]
_native_file_hash = _GLOBALS["_native_file_hash"]
_native_tools = _GLOBALS["_native_tools"]
_powershell_json = _GLOBALS["_powershell_json"]
_pe_attestation = _GLOBALS["_pe_attestation"]
_pe_inert_profile = _GLOBALS["_pe_inert_profile"]
_prefetch_artifacts = _GLOBALS["_prefetch_artifacts"]
_prefetch_attestation = _GLOBALS["_prefetch_attestation"]
_prefetch_corruption_control = _GLOBALS["_prefetch_corruption_control"]
_profile_artifacts = _GLOBALS["_profile_artifacts"]
_read_regular = _GLOBALS["_read_regular"]
_require_related_github_runs = _GLOBALS["_require_related_github_runs"]
_require_microsoft_signature = _GLOBALS["_require_microsoft_signature"]
_require_command_with_args_version = _GLOBALS["_require_command_with_args_version"]
_run = _GLOBALS["_run"]
_scene_capture = _GLOBALS["_scene_capture"]
_stat_fields_match = _GLOBALS["_stat_fields_match"]
_timestamp = _GLOBALS["_timestamp"]
_signed_positive_control = _GLOBALS["_signed_positive_control"]
_verified_fixture_evidence = _GLOBALS["_verified_fixture_evidence"]
_validate_native_report = _GLOBALS["_validate_native_report"]
_write_new_output = _GLOBALS["_write_new_output"]
_zone_attestation = _GLOBALS["_zone_attestation"]
main = _GLOBALS["main"]
_SHELL_LINK_SCRIPT = _GLOBALS["_SHELL_LINK_SCRIPT"]
_TASK_XML_SCRIPT = _GLOBALS["_TASK_XML_SCRIPT"]
attest = _GLOBALS["attest"]
prepare = _GLOBALS["prepare"]

_MAM_XPRESS_HUFFMAN_MAGIC = _GLOBALS["_MAM_XPRESS_HUFFMAN_MAGIC"]
_MAX_PREFETCH_V30_INNER_BYTES = _GLOBALS["_MAX_PREFETCH_V30_INNER_BYTES"]
_STABLE_FILE_FIELDS = _GLOBALS["_STABLE_FILE_FIELDS"]
_decode_mam_xpress_huffman = _GLOBALS["decode_mam_xpress_huffman"]


def _valid_wintrust(*, publisher: str = "Microsoft Corporation") -> dict:
    return {
        "action_guid": "00aac56b-cd44-11d0-8cc2-00c04fc295ee",
        "network_retrieval": False,
        "policy": "WINTRUST_ACTION_GENERIC_VERIFY_V2",
        "publisher": publisher,
        "signer_certificate_sha1": "a" * 40,
        "status": 0,
        "status_hex": "0x00000000",
        "verdict": "valid",
    }


def _powershell_observation(result: object, label: str) -> dict:
    stdout = _canonical_json_bytes(result)
    return {
        "argv": [
            "<pwsh>",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-CommandWithArgs",
            f"<fixed:{label}>",
            "--",
            "<target>",
        ],
        "result_sha256": _canonical_digest(result),
        "returncode": 0,
        "stderr": "",
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stdout_size": len(stdout),
    }


def _fake_prefetch_decompressor(payload: bytes, output_capacity: int) -> dict:
    wrapper = _MAM_XPRESS_HUFFMAN_MAGIC + struct.pack("<I", output_capacity) + payload
    try:
        output = _decode_mam_xpress_huffman(wrapper)
    except ValueError:
        status = 0xC0000242  # STATUS_BAD_COMPRESSION_BUFFER
        output = b""
    else:
        status = 0
    return {
        "compress_workspace_size": 65536,
        "decompress_ntstatus": status,
        "final_uncompressed_size": len(output),
        "fragment_workspace_size": 4096,
        "output": output,
        "workspace_query_ntstatus": 0,
    }


def _mock_windows_reader_on_posix(monkeypatch) -> None:
    """Keep the end-to-end observer mock on POSIX stat semantics."""
    module = attest.__globals__
    monkeypatch.setitem(
        module,
        "_cross_api_file_state_matches",
        lambda first, second: _stat_fields_match(first, second, _STABLE_FILE_FIELDS),
    )
    monkeypatch.setitem(
        module,
        "_inventory_path_state_matches",
        lambda first, second: (
            stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
            and _stat_fields_match(first, second, _STABLE_FILE_FIELDS)
        ),
    )


def _four_v30_prefetches() -> dict[str, bytes]:
    result = {}
    for index, name in enumerate(("agent.exe", "cache.exe", "helper.exe", "worker.exe"), 1):
        result[f"C/Windows/Prefetch/{name.upper()}-{index:08X}.pf"] = build_prefetch_v30(
            name,
            rf"\DEVICE\HARDDISKVOLUME1\TOOLS\{name}",
            index,
        )
    return result


@pytest.fixture(scope="module")
def windows_fixture(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("native-windows-fixture") / "fixture"
    spec = FixtureSpecV2.create(
        fixture_id="native-windows-attestation-test",
        family="windows",
        profile=ProfileSpecV2(
            id="windows-loose-v2",
            hostname="WKSTN-17",
            username="v",
        ),
        seed_hex="d5" * 32,
    )
    build_fixture(spec, root)
    return root


def _source() -> dict:
    base = {
        "git_commit": "a" * 40,
        "git_tree": "b" * 40,
        "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
        "worktree_clean": True,
    }
    return {**base, "identity_sha256": _canonical_digest(base)}


def _patch_source(monkeypatch) -> dict:
    source = _source()
    monkeypatch.setitem(prepare.__globals__, "_source_provenance", lambda _repo: source)
    monkeypatch.setitem(
        prepare.__globals__,
        "_source_postcondition",
        lambda initial, _repo: {**initial, "unchanged": True},
    )
    monkeypatch.setitem(prepare.__globals__, "_github_run_identity", lambda _environ: None)
    return source


def test_timestamp_and_canonical_json_are_stable():
    value = dt.datetime(
        2026,
        8,
        3,
        13,
        14,
        15,
        999999,
        tzinfo=dt.timezone(dt.timedelta(hours=1)),
    )
    assert _timestamp(value) == "2026-08-03T12:14:15Z"
    with pytest.raises(ValueError, match="timezone-aware"):
        _timestamp(dt.datetime(2026, 8, 3))
    value = {"z": 2, "accent": "é", "a": [False, None]}
    assert _canonical_json_bytes(value) == (b'{"a":[false,null],"accent":"\xc3\xa9","z":2}\n')


def test_native_command_output_is_bounded_while_streaming():
    with pytest.raises(RuntimeError, match="stdout/stderr exceeds"):
        _run(
            [
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * (1024 * 1024 + 1))",
            ]
        )


def test_native_overflow_reaps_a_descendant_that_inherits_output_pipes():
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="stdout/stderr exceeds"):
        _run(
            [
                sys.executable,
                "-c",
                (
                    "import os,subprocess,sys; "
                    "subprocess.Popen([sys.executable,'-c','import time; time.sleep(4)']); "
                    "os.write(1,b'x'*(1024*1024+1))"
                ),
            ]
        )
    assert time.monotonic() - started < 3.5


def test_native_timeout_is_bounded_when_a_descendant_inherits_output_pipes():
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="exceeded the 1-second timeout"):
        _run(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess,sys,time; "
                    "subprocess.Popen([sys.executable,'-c','import time; time.sleep(4)']); "
                    "time.sleep(4)"
                ),
            ],
            timeout=1,
        )
    assert time.monotonic() - started < 3.5


def test_native_normal_exit_reaps_a_descendant_that_inherits_output_pipes():
    started = time.monotonic()
    result = _run(
        [
            sys.executable,
            "-c",
            (
                "import subprocess,sys; "
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(4)'])"
            ),
        ],
        timeout=5,
    )
    assert result["returncode"] == 0
    assert time.monotonic() - started < 3.5


def test_regular_read_rejects_same_byte_inode_replacement(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"same bytes")
    expected = target.lstat()
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"same bytes")
    replacement.replace(target)
    with pytest.raises(RuntimeError, match="between inventory and open"):
        _read_regular(target, where="test target", expected_state=expected)


def test_windows_cross_api_state_uses_birth_time_not_ctime(monkeypatch):
    common = {
        "st_birthtime_ns": 100,
        "st_ctime_ns": 100,
        "st_dev": 1,
        "st_ino": 2,
        "st_mtime_ns": 300,
        "st_size": 4,
    }
    path_state = SimpleNamespace(**common)
    handle_state = SimpleNamespace(**{**common, "st_ctime_ns": 200})
    module_sys = _cross_api_file_state_matches.__globals__["sys"]
    monkeypatch.setattr(module_sys, "platform", "win32")
    monkeypatch.setattr(module_sys, "version_info", (3, 12, 0, "final", 0))

    assert _cross_api_file_state_matches(path_state, handle_state)
    assert not _stat_fields_match(path_state, handle_state, _STABLE_FILE_FIELDS)
    changed_handle = SimpleNamespace(**{**vars(handle_state), "st_ctime_ns": 201})
    assert not _stat_fields_match(handle_state, changed_handle, _STABLE_FILE_FIELDS)
    for field in ("st_birthtime_ns", "st_dev", "st_ino", "st_mtime_ns", "st_size"):
        mutated = SimpleNamespace(**{**vars(handle_state), field: getattr(handle_state, field) + 1})
        assert not _cross_api_file_state_matches(path_state, mutated), field
    for field in ("st_dev", "st_ino"):
        zeroed = SimpleNamespace(**{**vars(handle_state), field: 0})
        assert not _cross_api_file_state_matches(path_state, zeroed), field
    for state in (path_state, handle_state):
        zeroed = SimpleNamespace(**{**vars(state), "st_birthtime_ns": 0})
        other = handle_state if state is path_state else path_state
        assert not _cross_api_file_state_matches(zeroed, other)
        missing_values = vars(state).copy()
        del missing_values["st_birthtime_ns"]
        missing = SimpleNamespace(**missing_values)
        assert not _cross_api_file_state_matches(missing, other)


def test_windows_cross_api_state_uses_ctime_as_creation_time_on_python_311(monkeypatch):
    common = {
        "st_ctime_ns": 100,
        "st_dev": 1,
        "st_ino": 2,
        "st_mtime_ns": 300,
        "st_size": 4,
    }
    path_state = SimpleNamespace(**common)
    handle_state = SimpleNamespace(**common)
    module_sys = _cross_api_file_state_matches.__globals__["sys"]
    monkeypatch.setattr(module_sys, "platform", "win32")
    monkeypatch.setattr(module_sys, "version_info", (3, 11, 9, "final", 0))

    assert _cross_api_file_state_matches(path_state, handle_state)
    changed = SimpleNamespace(**{**common, "st_ctime_ns": 101})
    assert not _cross_api_file_state_matches(path_state, changed)
    zeroed = SimpleNamespace(**{**common, "st_ctime_ns": 0})
    assert not _cross_api_file_state_matches(path_state, zeroed)
    unexpected_birth = SimpleNamespace(**{**common, "st_birthtime_ns": 100})
    assert not _cross_api_file_state_matches(path_state, unexpected_birth)


def test_windows_directory_inventory_binds_reliable_fields(monkeypatch):
    inventory = SimpleNamespace(
        st_birthtime_ns=100,
        st_ctime_ns=100,
        st_dev=0,
        st_file_attributes=32,
        st_ino=0,
        st_mode=stat.S_IFREG | 0o444,
        st_mtime_ns=200,
        st_reparse_tag=0,
        st_size=300,
    )
    current = SimpleNamespace(
        **{
            **vars(inventory),
            "st_dev": 1,
            "st_ino": 2,
            "st_mode": stat.S_IFREG | 0o600,
        }
    )
    module_sys = _inventory_path_state_matches.__globals__["sys"]
    monkeypatch.setattr(module_sys, "platform", "win32")
    monkeypatch.setattr(module_sys, "version_info", (3, 12, 0, "final", 0))

    assert _inventory_path_state_matches(inventory, current)
    for field in (
        "st_birthtime_ns",
        "st_file_attributes",
        "st_mtime_ns",
        "st_reparse_tag",
        "st_size",
    ):
        mutated = SimpleNamespace(**{**vars(current), field: getattr(current, field) + 1})
        assert not _inventory_path_state_matches(inventory, mutated), field
    changed_type = SimpleNamespace(**{**vars(current), "st_mode": stat.S_IFDIR | 0o700})
    assert not _inventory_path_state_matches(inventory, changed_type)
    for field in ("st_dev", "st_ino"):
        zeroed = SimpleNamespace(**{**vars(current), field: 0})
        assert not _inventory_path_state_matches(inventory, zeroed), field
    matching_identity = SimpleNamespace(
        **{**vars(inventory), "st_dev": current.st_dev, "st_ino": current.st_ino}
    )
    assert _inventory_path_state_matches(matching_identity, current)
    mismatched_identity = SimpleNamespace(**{**vars(matching_identity), "st_ino": 3})
    assert not _inventory_path_state_matches(mismatched_identity, current)
    partial_identity = SimpleNamespace(**{**vars(inventory), "st_dev": current.st_dev})
    assert not _inventory_path_state_matches(partial_identity, current)
    for field in ("st_birthtime_ns", "st_file_attributes", "st_reparse_tag"):
        for state in (inventory, current):
            missing_values = vars(state).copy()
            del missing_values[field]
            missing = SimpleNamespace(**missing_values)
            first, second = (missing, current) if state is inventory else (inventory, missing)
            assert not _inventory_path_state_matches(first, second), field
    zero_birth = SimpleNamespace(**{**vars(current), "st_birthtime_ns": 0})
    assert not _inventory_path_state_matches(inventory, zero_birth)


def test_windows_directory_inventory_uses_ctime_as_creation_time_on_python_311(monkeypatch):
    inventory = SimpleNamespace(
        st_ctime_ns=100,
        st_dev=0,
        st_file_attributes=32,
        st_ino=0,
        st_mode=stat.S_IFREG | 0o444,
        st_mtime_ns=200,
        st_reparse_tag=0,
        st_size=300,
    )
    current = SimpleNamespace(
        **{
            **vars(inventory),
            "st_dev": 1,
            "st_ino": 2,
            "st_mode": stat.S_IFREG | 0o600,
        }
    )
    module_sys = _inventory_path_state_matches.__globals__["sys"]
    monkeypatch.setattr(module_sys, "platform", "win32")
    monkeypatch.setattr(module_sys, "version_info", (3, 11, 9, "final", 0))

    assert _inventory_path_state_matches(inventory, current)
    changed = SimpleNamespace(**{**vars(current), "st_ctime_ns": 101})
    assert not _inventory_path_state_matches(inventory, changed)
    unexpected_birth = SimpleNamespace(**{**vars(current), "st_birthtime_ns": 100})
    assert not _inventory_path_state_matches(inventory, unexpected_birth)


def test_complete_portable_verification_binds_windows_v2(windows_fixture):
    evidence, state, captured = _verified_fixture_evidence(windows_fixture)
    portable = evidence["portable_verification"]
    manifest = state["manifest"]
    assert portable["checks"] == {
        "assurance": "pass",
        "integrity": "pass",
        "reproduction": "pass",
    }
    assert [(item["gate"], item["name"], item["verdict"]) for item in portable["reports"]] == [
        (1, "validity", "pass"),
        (3, "inertness", "pass"),
    ]
    assert manifest.recipe.family == "windows"
    assert manifest.recipe.profile.id == "windows-loose-v2"
    assert state["scene"]["file_count"] == 14
    assert len(captured) == 14
    assert portable["payload"]["metadata_blob_count"] == 1
    assert portable["payload"]["metadata_blob_bytes"] > 0
    assert {
        "LnkParse3",
        "dissect.target",
        "liblnk-python",
    } <= set(portable["environment"]["distributions"])


def test_prefetch_native_canary_classifies_decompresses_and_runs_red_control():
    captured = _four_v30_prefetches()
    artifacts = _prefetch_artifacts(captured)
    assert len(artifacts) == 4
    assert [item["path"] for item in artifacts] == sorted(captured)
    for artifact in artifacts:
        assert artifact["data"][:4] == b"MAM\x04"
        assert artifact["declared_uncompressed_size"] == len(artifact["expected_output"])
        assert artifact["inner_header"] == {
            "file_size": len(artifact["expected_output"]),
            "signature": "SCCA",
            "version": 30,
        }
        evidence = _prefetch_attestation(artifact, _fake_prefetch_decompressor)
        native = evidence["native_decompression"]
        assert native["workspace_query_ntstatus"] == "0x00000000"
        assert native["decompress_ntstatus"] == "0x00000000"
        assert native["final_uncompressed_size"] == artifact["declared_uncompressed_size"]
        assert native["output_sha256"] == hashlib.sha256(artifact["expected_output"]).hexdigest()

    control = _prefetch_corruption_control(artifacts[0], _fake_prefetch_decompressor)
    assert control["verdict"] == "pass"
    assert control["outcome"] == "native-error"
    assert control["native_decompression"]["decompress_ntstatus"] == "0xc0000242"
    assert control["mutation"]["payload_offset"] == 15
    assert control["mutation"]["wrapper_offset"] == 23

    def successful_but_wrong(_payload: bytes, capacity: int) -> dict:
        output = b"\x00" * capacity
        return {
            "compress_workspace_size": 65536,
            "decompress_ntstatus": 0,
            "final_uncompressed_size": capacity,
            "fragment_workspace_size": 4096,
            "output": output,
            "workspace_query_ntstatus": 0,
        }

    mismatch = _prefetch_corruption_control(artifacts[0], successful_but_wrong)
    assert mismatch["outcome"] == "nonmatching-exact-output"
    assert (
        mismatch["native_decompression"]["final_uncompressed_size"]
        == artifacts[0]["declared_uncompressed_size"]
    )


def test_prefetch_native_canary_fails_closed_on_population_wrapper_and_control():
    captured = _four_v30_prefetches()
    with pytest.raises(RuntimeError, match="exactly 4"):
        _prefetch_artifacts(dict(list(captured.items())[:3]))

    path = sorted(captured)[0]
    wrong_algorithm = dict(captured)
    wrong_algorithm[path] = b"MAM\x03" + wrong_algorithm[path][4:]
    with pytest.raises(RuntimeError, match="not MAM algorithm 4"):
        _prefetch_artifacts(wrong_algorithm)

    oversized = dict(captured)
    data = bytearray(oversized[path])
    struct.pack_into("<I", data, 4, _MAX_PREFETCH_V30_INNER_BYTES + 1)
    oversized[path] = bytes(data)
    with pytest.raises(RuntimeError, match="declared output size"):
        _prefetch_artifacts(oversized)

    disguised = {**captured, "C/Windows/not-prefetch.bin": captured[path]}
    with pytest.raises(RuntimeError, match="outside a .pf"):
        _prefetch_artifacts(disguised)

    artifact = _prefetch_artifacts(captured)[0]

    def ignores_corruption(_payload: bytes, _capacity: int) -> dict:
        output = artifact["expected_output"]
        return {
            "compress_workspace_size": 65536,
            "decompress_ntstatus": 0,
            "final_uncompressed_size": len(output),
            "fragment_workspace_size": 4096,
            "output": output,
            "workspace_query_ntstatus": 0,
        }

    with pytest.raises(RuntimeError, match="reproduced the exact expected output"):
        _prefetch_corruption_control(artifact, ignores_corruption)


def test_all_pe_bytes_have_exact_one_ret_profile(windows_fixture):
    state, captured = _fixture_state(windows_fixture)
    profiles = {
        path: _pe_inert_profile(data) for path, data in captured.items() if data.startswith(b"MZ")
    }
    assert len(profiles) == 5
    for profile in profiles.values():
        assert profile["architecture"] == "AMD64"
        assert profile["optional_header"] == "PE32+"
        assert profile["entry_point_rva"] == 0x1000
        assert profile["instruction_profile"] == [{"bytes": "c3", "instruction": "ret"}]
        assert profile["zero_padding_bytes"] == 511
        assert profile["executable_section_count"] == 1
    zones = _logical_zone_map(state["manifest"], captured)
    assert len(zones) == 1
    assert set(zones) < set(profiles)
    profile_artifacts = _profile_artifacts(state["manifest"], captured)
    assert set(profile_artifacts) == {"scheduled_task_xml", "shell_link"}
    assert profile_artifacts["scheduled_task_xml"]["target"]["path"] in profiles
    assert profile_artifacts["shell_link"]["target"]["path"] in profiles
    assert (
        profile_artifacts["scheduled_task_xml"]["target"]["path"]
        != profile_artifacts["shell_link"]["target"]["path"]
    )
    assert {
        profile_artifacts["scheduled_task_xml"]["target"]["path"],
        profile_artifacts["shell_link"]["target"]["path"],
    }.isdisjoint(zones)
    task_profile = profile_artifacts["scheduled_task_xml"]["profile"]
    assert profile_artifacts["scheduled_task_xml"]["path"] == (
        "C/Windows/System32/Tasks/ArtifactForge/" + task_profile.task_name
    )
    assert profile_artifacts["shell_link"]["path"] == (
        "C/Users/v/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/"
        "ArtifactForgeMaintenance.lnk"
    )


def test_pe_profile_rejects_a_second_nonzero_code_byte(windows_fixture):
    _state, captured = _fixture_state(windows_fixture)
    data = bytearray(next(data for data in captured.values() if data.startswith(b"MZ")))
    profile = _pe_inert_profile(bytes(data))
    text = next(section for section in profile["sections"] if section["name"] == ".text")
    data[text["raw_offset"] + 1] = 0x90
    with pytest.raises(RuntimeError, match="one RET plus zero padding"):
        _pe_inert_profile(bytes(data))


def test_scene_capture_detects_same_size_mutation_and_rejects_links(tmp_path):
    scene = tmp_path / "scene"
    scene.mkdir()
    artifact = scene / "artifact.bin"
    artifact.write_bytes(b"before")
    initial, _captured = _scene_capture(scene)
    artifact.write_bytes(b"AFTER!")
    final, _captured = _scene_capture(scene)
    assert final["tree_sha256"] != initial["tree_sha256"]

    target = tmp_path / "outside.bin"
    target.write_bytes(b"outside")
    try:
        (scene / "link.bin").symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create a test link: {exc}")
    with pytest.raises(RuntimeError, match="contain a link"):
        _scene_capture(scene)


def test_portable_prerequisite_is_canonical_and_mutation_closed(
    windows_fixture, tmp_path, monkeypatch
):
    _patch_source(monkeypatch)
    report = prepare(
        windows_fixture,
        now=dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc),
        repository_root=tmp_path,
    )
    assert report["verdict"] == "pass"
    path = tmp_path / "portable.json"
    path.write_bytes(_canonical_json_bytes(report))
    loaded, identity = _load_prerequisite(path)
    assert loaded == report
    assert identity["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(json.dumps(report, indent=2) + "\n")
    with pytest.raises(RuntimeError, match="not canonical"):
        _load_prerequisite(noncanonical)

    tampered = json.loads(path.read_bytes())
    tampered["fixture"]["portable_verification"]["reports"][0]["verdict"] = "fail"
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_bytes(_canonical_json_bytes(tampered))
    with pytest.raises(RuntimeError, match="both passing assurance gates"):
        _load_prerequisite(tampered_path)

    extra_report = json.loads(path.read_bytes())
    extra_report["fixture"]["portable_verification"]["reports"].append("not-a-report")
    extra_report_path = tmp_path / "extra-report.json"
    extra_report_path.write_bytes(_canonical_json_bytes(extra_report))
    with pytest.raises(RuntimeError, match="both passing assurance gates"):
        _load_prerequisite(extra_report_path)

    invalid_time = json.loads(path.read_bytes())
    invalid_time["generated_at_utc"] = "2026-02-31T12:00:00Z"
    invalid_time_path = tmp_path / "invalid-time.json"
    invalid_time_path.write_bytes(_canonical_json_bytes(invalid_time))
    with pytest.raises(RuntimeError, match="invalid UTC timestamp"):
        _load_prerequisite(invalid_time_path)

    arbitrary_run = json.loads(path.read_bytes())
    arbitrary_run["github_actions"] = {"run_id": "1"}
    arbitrary_run_path = tmp_path / "arbitrary-run.json"
    arbitrary_run_path.write_bytes(_canonical_json_bytes(arbitrary_run))
    with pytest.raises(RuntimeError, match="GitHub Actions provenance"):
        _load_prerequisite(arbitrary_run_path)

    false_clean = json.loads(path.read_bytes())
    source = false_clean["producer"]["source"]
    source["status_porcelain_sha256"] = hashlib.sha256(b"unreported change").hexdigest()
    source["identity_sha256"] = _canonical_digest(
        {name: value for name, value in source.items() if name != "identity_sha256"}
    )
    false_clean["producer"]["source_post_preparation"] = {**source, "unchanged": True}
    false_clean_path = tmp_path / "false-clean.json"
    false_clean_path.write_bytes(_canonical_json_bytes(false_clean))
    with pytest.raises(RuntimeError, match="self-inconsistent source evidence"):
        _load_prerequisite(false_clean_path)


def test_cross_job_github_provenance_requires_the_same_run():
    portable = {
        "event_name": "push",
        "git_sha": "a" * 40,
        "job": "windows-native-prepare",
        "ref": "refs/heads/main",
        "repository": "example/ArtifactForge",
        "run_attempt": "1",
        "run_id": "123",
        "run_url": "https://github.com/example/ArtifactForge/actions/runs/123",
        "server_url": "https://github.com",
        "workflow": "CI",
        "workflow_ref": "example/ArtifactForge/.github/workflows/ci.yml@refs/heads/main",
    }
    native = {**portable, "job": "windows-native"}
    _require_related_github_runs(portable, native)
    with pytest.raises(RuntimeError, match="run_id"):
        _require_related_github_runs(portable, {**native, "run_id": "456"})
    with pytest.raises(RuntimeError, match="not both present"):
        _require_related_github_runs(portable, None)


def test_powershell_observations_pass_target_separately_and_use_literal_path(tmp_path):
    assert all(
        "-LiteralPath" in _GLOBALS[name]
        for name in (
            "_ADS_EXISTS_SCRIPT",
            "_ADS_READ_SCRIPT",
            "_FILE_HASH_SCRIPT",
            "_SIGNATURE_SCRIPT",
        )
    )
    target = tmp_path / "name [literal].exe"
    target.write_bytes(b"MZ")
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        if "Get-FileHash" in command[-3]:
            stdout = json.dumps({"Algorithm": "SHA256", "Hash": "A" * 64})
        else:
            stdout = json.dumps(
                {
                    "Status": "NotSigned",
                    "StatusMessage": "not signed",
                    "SignerThumbprint": "",
                    "SignerSubject": "",
                    "SignerIssuer": "",
                    "SignatureType": "None",
                    "IsOSBinary": False,
                }
            )
        return {
            "argv": kwargs["recorded_argv"],
            "returncode": 0,
            "stderr": "",
            "stdout": stdout,
        }

    digest, _evidence = _native_file_hash(target, "pwsh.exe", runner)
    signature, _evidence = _authenticode(target, "pwsh.exe", runner)
    assert digest == "a" * 64
    assert signature["Status"] == "NotSigned"
    for command, kwargs in calls:
        assert command[-4] == "-CommandWithArgs"
        assert "-LiteralPath" in command[-3]
        assert command[-2] == "--"
        assert command[-1] == str(target)
        assert command[0] != str(target)
        assert kwargs["recorded_argv"][-4] == "-CommandWithArgs"
        assert kwargs["recorded_argv"][-2] == "--"
        assert kwargs["recorded_argv"][-1] == "<target>"

    leading_dash = Path("-leading [literal] & apostrophe' target.bin")
    _native_file_hash(leading_dash, "pwsh.exe", runner)
    command, kwargs = calls[-1]
    assert command[-2:] == ["--", str(leading_dash)]
    assert kwargs["recorded_argv"][-2:] == ["--", "<target>"]

    if sys.platform == "win32":
        powershell = shutil.which("pwsh.exe") or shutil.which("pwsh")
        assert powershell, "hosted Windows native lane requires pwsh"
        literal = tmp_path / "literal [brackets] & apostrophe' space.exe"
        payload = build_pe_stub(
            hashlib.sha256(b"windows-hostile-literal-path-control").digest()
        )
        logical = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://artifactforge.invalid/\r\n"
        literal.write_bytes(payload)
        real_digest, _ = _native_file_hash(literal, powershell, _run)
        assert real_digest == hashlib.sha256(payload).hexdigest()
        real_signature, _ = _authenticode(literal, powershell, _run)
        assert real_signature["Status"] == "NotSigned"
        zone = _zone_attestation(
            literal.name,
            literal,
            logical,
            real_digest,
            powershell,
            _run,
        )
        assert zone["private_projection"]["removed"] is True
        assert literal.read_bytes() == payload


def test_powershell_without_target_keeps_command_as_the_final_switch():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return {
            "argv": kwargs["recorded_argv"],
            "returncode": 0,
            "stderr": "",
            "stdout": '{"Ok":true}',
        }

    value, _evidence = _powershell_json(
        "pwsh.exe",
        "[ordered]@{Ok = $true} | ConvertTo-Json -Compress",
        "no-target-control",
        runner,
    )
    assert value == {"Ok": True}
    command, kwargs = calls[0]
    assert command[-2] == "-Command"
    assert command[-1].startswith("[ordered]")
    assert kwargs["recorded_argv"][-2:] == ["-Command", "<fixed:no-target-control>"]

    def noisy_runner(_command, **noisy_kwargs):
        return {
            "argv": noisy_kwargs["recorded_argv"],
            "returncode": 0,
            "stderr": "unexpected diagnostic",
            "stdout": '{"Ok":true}',
        }

    with pytest.raises(RuntimeError, match="unexpected stderr"):
        _powershell_json(
            "pwsh.exe",
            "[ordered]@{Ok = $true} | ConvertTo-Json -Compress",
            "stderr-control",
            noisy_runner,
        )


def test_command_with_args_requires_supported_powershell_version():
    assert _require_command_with_args_version(
        {"returncode": 0, "stdout": "PowerShell 7.5.0", "stderr": ""}
    ) == (7, 5, 0)
    assert _require_command_with_args_version(
        {"returncode": 0, "stdout": "PowerShell 7.6.4", "stderr": ""}
    ) == (7, 6, 4)
    with pytest.raises(RuntimeError, match="7.5 or later"):
        _require_command_with_args_version(
            {"returncode": 0, "stdout": "PowerShell 7.4.7", "stderr": ""}
        )
    with pytest.raises(RuntimeError, match="parse"):
        _require_command_with_args_version(
            {"returncode": 0, "stdout": "PowerShell unknown", "stderr": ""}
        )
    with pytest.raises(RuntimeError, match="parse"):
        _require_command_with_args_version(
            {"returncode": 0, "stdout": "PowerShell 7.7.0-preview.1", "stderr": ""}
        )


def test_task_and_shell_link_native_scripts_have_no_activation_surface():
    assert "$service.Connect()" in _TASK_XML_SCRIPT
    assert "$service.NewTask(0)" in _TASK_XML_SCRIPT
    assert "$definition.XmlText = $xml" in _TASK_XML_SCRIPT
    for forbidden in (
        ".GetFolder(",
        ".RegisterTask(",
        ".RegisterTaskDefinition(",
        "schtasks",
    ):
        assert forbidden.casefold() not in _TASK_XML_SCRIPT.casefold()

    assert "$shell.CreateShortcut($TargetPath)" in _SHELL_LINK_SCRIPT
    for forbidden in (".Save(", ".Resolve(", ".Run("):
        assert forbidden.casefold() not in _SHELL_LINK_SCRIPT.casefold()


def test_windows_powershell_discovery_ignores_path_and_uses_fixed_installation(
    tmp_path, monkeypatch
):
    program_files = tmp_path / "Program Files"
    fixed = program_files / "PowerShell/7/pwsh.exe"
    fixed.parent.mkdir(parents=True)
    fixed.write_bytes(b"fixed")
    monkeypatch.setenv("ProgramFiles", str(program_files))
    monkeypatch.setattr(_find_powershell.__globals__["sys"], "platform", "win32")
    monkeypatch.setattr(
        _find_powershell.__globals__["shutil"],
        "which",
        lambda _name: str(tmp_path / "PATH-poisoned-pwsh.exe"),
    )
    assert _find_powershell() == fixed.resolve()


def test_independent_trust_failure_blocks_tools_before_any_command(tmp_path, monkeypatch):
    powershell = tmp_path / "pwsh.exe"
    vswhere = tmp_path / "vswhere.exe"
    powershell.write_bytes(b"powershell")
    vswhere.write_bytes(b"vswhere")
    monkeypatch.setitem(_native_tools.__globals__, "_find_powershell", lambda: powershell)
    monkeypatch.setitem(_native_tools.__globals__, "_find_vswhere", lambda: vswhere)
    monkeypatch.setitem(
        _native_tools.__globals__,
        "_winverifytrust",
        lambda _path: (_ for _ in ()).throw(RuntimeError("independent trust rejected")),
    )
    called = False

    def runner(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("no command may run before independent trust")

    with pytest.raises(RuntimeError, match="independent trust rejected"):
        _native_tools(runner)
    assert called is False


def test_publisher_policy_uses_verified_leaf_identity_not_a_microsoft_substring():
    signature = {
        "IsOSBinary": False,
        "SignatureType": "Authenticode",
        "SignerIssuer": "CN=Example Root",
        "SignerSubject": "CN=Microsoft Corporation",
        "SignerThumbprint": "A" * 40,
        "Status": "Valid",
        "StatusMessage": "valid",
    }
    _require_microsoft_signature(
        signature,
        "control",
        independent_trust=_valid_wintrust(),
    )
    hostile = _valid_wintrust(publisher="Not Microsoft Corporation Consulting")
    with pytest.raises(RuntimeError, match="independently trusted"):
        _require_microsoft_signature(
            signature,
            "control",
            independent_trust=hostile,
        )

    misleading_subject = {**signature, "SignerSubject": "CN=Not Microsoft Corporation Consulting"}
    with pytest.raises(RuntimeError, match="valid Microsoft-signed"):
        _require_microsoft_signature(
            misleading_subject,
            "control",
            independent_trust=_valid_wintrust(),
        )

    mismatched_certificate = _valid_wintrust()
    mismatched_certificate["signer_certificate_sha1"] = "b" * 40
    with pytest.raises(RuntimeError, match="valid Microsoft-signed"):
        _require_microsoft_signature(
            signature,
            "control",
            independent_trust=mismatched_certificate,
        )

    unsupported_type = {**signature, "SignatureType": "Embedded"}
    with pytest.raises(RuntimeError, match="valid Microsoft-signed"):
        _require_microsoft_signature(
            unsupported_type,
            "control",
            independent_trust=_valid_wintrust(),
        )


def test_tool_discovery_uses_vswhere_and_numeric_latest_toolset(tmp_path, monkeypatch):
    powershell = tmp_path / "pwsh.exe"
    vswhere = tmp_path / "vswhere.exe"
    installation = tmp_path / "Visual Studio"
    powershell.write_bytes(b"powershell")
    vswhere.write_bytes(b"vswhere")
    for version in ("14.9.1", "14.10.2"):
        dumpbin = installation / f"VC/Tools/MSVC/{version}/bin/Hostx64/x64/dumpbin.exe"
        dumpbin.parent.mkdir(parents=True)
        dumpbin.write_bytes(version.encode())
    monkeypatch.setitem(_native_tools.__globals__, "_find_powershell", lambda: powershell)
    monkeypatch.setitem(_native_tools.__globals__, "_find_vswhere", lambda: vswhere)
    monkeypatch.setitem(
        _native_tools.__globals__,
        "_winverifytrust",
        lambda _path: _valid_wintrust(),
    )

    def runner(command, **kwargs):
        if "installationPath" in command:
            stdout = str(installation)
        elif "installationVersion" in command:
            stdout = "17.14.37502.11"
        elif "-CommandWithArgs" in command and "Get-AuthenticodeSignature" in command[-3]:
            stdout = json.dumps(
                {
                    "Status": "Valid",
                    "StatusMessage": "valid",
                    "SignerThumbprint": "A" * 40,
                    "SignerSubject": "CN=Microsoft Corporation",
                    "SignerIssuer": "CN=Microsoft Root",
                    "SignatureType": "Authenticode",
                    "IsOSBinary": False,
                }
            )
        elif command[0] == str(powershell):
            stdout = "PowerShell 7.6.3"
        elif command[0] == str(vswhere):
            stdout = "Visual Studio Locator version 3.1.7"
        else:
            stdout = "Microsoft COFF/PE Dumper Version 14.10.2"
        return {
            "argv": kwargs["recorded_argv"],
            "returncode": 0,
            "stderr": "",
            "stdout": stdout,
        }

    tools, evidence = _native_tools(runner)
    assert Path(tools["dumpbin"]).parents[3].name == "14.10.2"
    assert evidence["discovery"]["installation_version"] == "17.14.37502.11"
    assert evidence["powershell"]["version_stdout"] == "PowerShell 7.6.3"
    assert evidence["vswhere"]["version_stdout"].startswith("Visual Studio Locator")
    assert evidence["dumpbin"]["sha256"] == hashlib.sha256(b"14.10.2").hexdigest()


def test_synthetic_pe_rejects_a_valid_signature(windows_fixture, tmp_path, monkeypatch):
    _state, captured = _fixture_state(windows_fixture)
    relative, data = next(
        (path, value) for path, value in captured.items() if value.startswith(b"MZ")
    )
    path = tmp_path / "synthetic.exe"
    path.write_bytes(data)
    monkeypatch.setitem(
        _pe_attestation.__globals__,
        "_native_file_hash",
        lambda *_args: (hashlib.sha256(data).hexdigest(), {}),
    )
    monkeypatch.setitem(
        _pe_attestation.__globals__,
        "_authenticode",
        lambda *_args: (
            {
                "Status": "Valid",
                "SignerThumbprint": "A" * 40,
                "SignerSubject": "CN=unexpected",
            },
            {},
        ),
    )
    with pytest.raises(RuntimeError, match="not 'NotSigned'"):
        _pe_attestation(
            relative,
            path,
            data,
            {"dumpbin": "dumpbin.exe", "powershell": "pwsh.exe"},
            lambda *_args, **_kwargs: {},
        )


def test_authenticode_positive_control_requires_valid_signed_bytes(tmp_path, monkeypatch):
    control = tmp_path / "System32/WindowsPowerShell/v1.0/powershell.exe"
    control.parent.mkdir(parents=True)
    control.write_bytes(b"signed-control")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    valid = {
        "IsOSBinary": True,
        "SignerIssuer": "CN=Microsoft Root",
        "SignatureType": "Authenticode",
        "Status": "Valid",
        "StatusMessage": "valid",
        "SignerThumbprint": "A" * 40,
        "SignerSubject": "CN=Microsoft Windows",
    }
    monkeypatch.setitem(
        _signed_positive_control.__globals__,
        "_winverifytrust",
        lambda _path: _valid_wintrust(publisher="Microsoft Windows"),
    )
    monkeypatch.setitem(
        _signed_positive_control.__globals__,
        "_authenticode",
        lambda *_args: (valid, {"argv": ["<positive-control>"]}),
    )
    monkeypatch.setitem(
        _signed_positive_control.__globals__,
        "_native_file_hash",
        lambda path, *_args: (hashlib.sha256(path.read_bytes()).hexdigest(), {}),
    )
    evidence, selected = _signed_positive_control("pwsh.exe", lambda *_args: {})
    assert selected == control
    assert evidence["selected"]["signature"]["Status"] == "Valid"

    unsigned = {**valid, "Status": "NotSigned", "SignerThumbprint": ""}
    monkeypatch.setitem(
        _signed_positive_control.__globals__,
        "_authenticode",
        lambda *_args: (unsigned, {}),
    )
    with pytest.raises(RuntimeError, match="no fixed Windows positive control"):
        _signed_positive_control("pwsh.exe", lambda *_args: {})


@pytest.mark.parametrize("corrupt_readback", [False, True])
def test_private_zone_identifier_is_removed_even_on_readback_failure(tmp_path, corrupt_readback):
    target = tmp_path / "synthetic.exe"
    default_bytes = b"MZ-default-stream"
    logical_bytes = b"[ZoneTransfer]\r\nZoneId=3\r\n"
    target.write_bytes(default_bytes)

    def runner(command, **kwargs):
        script = command[-3]
        path = Path(command[-1])
        stream = Path(f"{path}:Zone.Identifier")
        if "Get-Item" in script:
            value = {"Exists": stream.exists()}
        elif "Get-Content" in script:
            observed = b"wrong" if corrupt_readback else stream.read_bytes()
            value = {
                "Base64": base64.b64encode(observed).decode(),
                "Length": len(observed),
            }
        elif "Get-FileHash" in script:
            value = {
                "Algorithm": "SHA256",
                "Hash": hashlib.sha256(path.read_bytes()).hexdigest().upper(),
            }
        elif "Get-AuthenticodeSignature" in script:
            value = {
                "Status": "NotSigned",
                "StatusMessage": "not signed",
                "SignerThumbprint": "",
                "SignerSubject": "",
                "SignerIssuer": "",
                "SignatureType": "None",
                "IsOSBinary": False,
            }
        else:
            raise AssertionError("unexpected PowerShell script")
        stdout = json.dumps(value, separators=(",", ":"))
        return {
            "argv": kwargs["recorded_argv"],
            "returncode": 0,
            "stderr": "",
            "stdout": stdout,
        }

    expected = hashlib.sha256(default_bytes).hexdigest()
    if corrupt_readback:
        with pytest.raises(RuntimeError, match="disagree with manifest"):
            _zone_attestation(
                "synthetic.exe",
                target,
                logical_bytes,
                expected,
                "pwsh.exe",
                runner,
            )
    else:
        evidence = _zone_attestation(
            "synthetic.exe",
            target,
            logical_bytes,
            expected,
            "pwsh.exe",
            runner,
        )
        assert evidence["private_projection"]["removed"] is True
        assert evidence["default_stream_postcondition"]["unchanged"] is True
    assert not Path(f"{target}:Zone.Identifier").exists()
    assert target.read_bytes() == default_bytes


def test_full_native_report_with_mocked_windows_observers(windows_fixture, tmp_path, monkeypatch):
    _patch_source(monkeypatch)
    portable = prepare(windows_fixture, repository_root=tmp_path)
    prerequisite = tmp_path / "portable.json"
    prerequisite.write_bytes(_canonical_json_bytes(portable))
    monkeypatch.setattr(attest.__globals__["sys"], "platform", "win32")
    _mock_windows_reader_on_posix(monkeypatch)

    tools = {}
    tool_evidence = {}
    valid_tool_signature = {
        "IsOSBinary": False,
        "SignerIssuer": "CN=Microsoft Root",
        "SignatureType": "Authenticode",
        "Status": "Valid",
        "StatusMessage": "valid",
        "SignerThumbprint": "A" * 40,
        "SignerSubject": "CN=Microsoft Corporation",
    }
    for name in ("dumpbin", "powershell", "vswhere"):
        path = tmp_path / f"{name}.exe"
        path.write_bytes(name.encode())
        tools[name] = str(path)
        tool_evidence[name] = {
            **_file_identity(path),
            "authenticode": {
                "observation": _powershell_observation(
                    valid_tool_signature,
                    "Get-AuthenticodeSignature-LiteralPath",
                ),
                "result": valid_tool_signature,
            },
            "winverifytrust": _valid_wintrust(),
        }
    powershell_version = "PowerShell 7.6.3"
    powershell_version_observation = {
        "argv": ["<powershell>", "--version"],
        "returncode": 0,
        "stderr": "",
        "stdout": powershell_version,
    }
    tool_evidence["powershell"].update(
        {
            "version_observation": powershell_version_observation,
            "version_stdout": powershell_version,
            "version_stdout_sha256": hashlib.sha256(powershell_version.encode()).hexdigest(),
        }
    )
    tool_evidence["discovery"] = {"returncode": 0}
    monkeypatch.setitem(attest.__globals__, "_native_tools", lambda _runner: (tools, tool_evidence))
    host = {
        "native": {
            "OSVersion": "mocked Windows",
            "PowerShellVersion": "7.6.3",
        }
    }
    monkeypatch.setitem(
        attest.__globals__,
        "_platform_evidence",
        lambda _powershell, _runner: {**host, "identity_sha256": _canonical_digest(host)},
    )
    control = tmp_path / "signed-control.exe"
    control.write_bytes(b"signed-control")
    control_identity = _file_identity(control, "control")
    control_signature = {
        **valid_tool_signature,
        "IsOSBinary": True,
        "SignerSubject": "CN=Microsoft Windows",
    }
    control_selected = {
        "identity": control_identity,
        "label": "WindowsPowerShell",
        "observation": _powershell_observation(
            control_signature,
            "Get-AuthenticodeSignature-LiteralPath",
        ),
        "signature": control_signature,
        "winverifytrust": _valid_wintrust(publisher="Microsoft Windows"),
    }
    control_hash = {
        "Algorithm": "SHA256",
        "Hash": control_identity["sha256"].upper(),
    }
    monkeypatch.setitem(
        attest.__globals__,
        "_signed_positive_control",
        lambda _powershell, _runner: (
            {
                "attempts": [control_selected],
                "hash": {
                    "observation": _powershell_observation(
                        control_hash,
                        "Get-FileHash-LiteralPath-SHA256",
                    ),
                    "result": control_hash,
                },
                "selected": control_selected,
                "verdict": "pass",
            },
            control,
        ),
    )

    observed_commands = []

    def runner(command, **kwargs):
        observed_commands.append(command)
        if "-CommandWithArgs" in command:
            script = command[-3]
            path = Path(command[-1])
            stream = Path(f"{path}:Zone.Identifier")
            if "Schedule.Service" in script:
                task_bytes = path.read_bytes()
                xml_text = task_bytes[2:].decode("utf-16-le")
                round_trip = xml_text.encode("utf-16-le")
                value = {
                    "Accepted": True,
                    "ApiSequence": "TaskService.Connect;NewTask(0);TaskDefinition.XmlText",
                    "InputByteLength": len(task_bytes),
                    "InputSha256": hashlib.sha256(task_bytes).hexdigest().upper(),
                    "RoundTripUtf16LeByteLength": len(round_trip),
                    "RoundTripUtf16LeSha256": hashlib.sha256(round_trip).hexdigest().upper(),
                    "XmlTextCharacterLength": len(xml_text),
                }
            elif "WScript.Shell" in script:
                link_bytes = path.read_bytes()
                link = parse_shell_link(link_bytes)
                value = {
                    "ApiSequence": "WScript.Shell.CreateShortcut-read-only",
                    "Arguments": "",
                    "Description": link.name_string,
                    "Hotkey": "",
                    "IconLocation": "",
                    "InputByteLength": len(link_bytes),
                    "InputSha256": hashlib.sha256(link_bytes).hexdigest().upper(),
                    "TargetPath": link.target_path,
                    "WindowStyle": 1,
                    "WorkingDirectory": "",
                }
            elif "Get-FileHash" in script:
                value = {
                    "Algorithm": "SHA256",
                    "Hash": hashlib.sha256(path.read_bytes()).hexdigest().upper(),
                }
            elif "Get-AuthenticodeSignature" in script:
                value = {
                    "Status": "NotSigned",
                    "StatusMessage": "not signed",
                    "SignerThumbprint": "",
                    "SignerSubject": "",
                    "SignerIssuer": "",
                    "SignatureType": "None",
                    "IsOSBinary": False,
                }
            elif "Get-Item" in script:
                value = {"Exists": stream.exists()}
            elif "Get-Content" in script:
                observed = stream.read_bytes()
                value = {
                    "Base64": base64.b64encode(observed).decode(),
                    "Length": len(observed),
                }
            else:
                raise AssertionError("unexpected PowerShell script")
            stdout = json.dumps(value, separators=(",", ":"))
        elif "/HEADERS" in command:
            stdout = "8664 machine\n1000 entry point\n20B magic\n.text name"
        else:
            raise AssertionError(f"unexpected native command: {command!r}")
        return {
            "argv": kwargs["recorded_argv"],
            "returncode": 0,
            "stderr": "",
            "stdout": stdout,
        }

    report = attest(
        windows_fixture,
        prerequisite,
        repository_root=tmp_path,
        command_runner=runner,
        prefetch_decompressor=_fake_prefetch_decompressor,
    )
    assert report["verdict"] == "pass", report["failures"]
    assert report["artifact_counts"] == {
        "default_stream_files": 14,
        "prefetch": 4,
        "scheduled_task_xml": 1,
        "shell_link": 1,
        "synthetic_pe": 5,
        "zone_identifier": 1,
    }
    assert report["claim_scope"]["emitted_pe_execution"] is False
    assert "post-size bits" in report["claim_scope"]["prefetch_scope"]
    assert len(report["artifacts"]["prefetch"]) == 4
    assert report["prefetch_positive_control"]["verdict"] == "pass"
    assert len(report["artifacts"]["scheduled_task_xml"]) == 1
    assert len(report["artifacts"]["shell_link"]) == 1
    task = report["artifacts"]["scheduled_task_xml"][0]
    link = report["artifacts"]["shell_link"][0]
    assert task["target"]["path"] in {item["path"] for item in report["artifacts"]["pe"]}
    assert link["target"]["path"] in {item["path"] for item in report["artifacts"]["pe"]}
    assert report["fixture"]["post_observation"]["unchanged"] is True
    assert report["private_scene"]["post_observation"]["unchanged"] is True
    assert report["tools"]["post_observation"]["unchanged"] is True
    assert report["positive_control"]["post_observation"]["unchanged"] is True
    assert observed_commands
    assert all(command[0] in tools.values() for command in observed_commands)
    assert json.loads(_canonical_json_bytes(report)) == report
    mutated = json.loads(_canonical_json_bytes(report))
    mutated["tools"]["initial"]["powershell"]["version_stdout"] = "PowerShell 7.6.2"
    with pytest.raises(RuntimeError, match="PowerShell version evidence"):
        _validate_native_report(mutated)

    mutated = json.loads(_canonical_json_bytes(report))
    mutated["artifacts"]["pe"][0]["get_file_hash"]["observation"]["argv"][-4] = "-Command"
    with pytest.raises(RuntimeError, match="Get-FileHash observation"):
        _validate_native_report(mutated)

    mutated = json.loads(_canonical_json_bytes(report))
    mutated["portable_prerequisite"]["post_observation"]["sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="prerequisite post-state"):
        _validate_native_report(mutated)

    mutated = json.loads(_canonical_json_bytes(report))
    mutated["portable_prerequisite"]["record"]["claim_scope"]["cross_host_boundary"] += (
        " unbound mutation"
    )
    with pytest.raises(RuntimeError, match="prerequisite post-state"):
        _validate_native_report(mutated)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["pe"][0]["sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="does not bind PE"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["pe"][0]["byte_profile"]["zero_padding_bytes"] = 510
    with pytest.raises(RuntimeError, match="byte profile"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["pe"][0]["dumpbin_headers"]["markers"]["amd64_machine"] = False
    with pytest.raises(RuntimeError, match="dumpbin markers"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    dumpbin = hostile["artifacts"]["pe"][0]["dumpbin_headers"]["observation"]
    dumpbin["stdout"] = "invented passing dumpbin output"
    dumpbin["stdout_size"] = len(dumpbin["stdout"].encode())
    dumpbin["stdout_sha256"] = hashlib.sha256(dumpbin["stdout"].encode()).hexdigest()
    with pytest.raises(RuntimeError, match="dumpbin output"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["pe"][0]["signature"]["result"]["Status"] = "Valid"
    with pytest.raises(RuntimeError, match="signature"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["pe"][0]["get_file_hash"]["observation"]["result_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="Get-FileHash observation"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["prefetch"][0]["wrapper"]["declared_uncompressed_size"] += 1
    with pytest.raises(RuntimeError, match="Prefetch.*wrapper"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["prefetch"][0]["native_decompression"]["output_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="non-exact Prefetch"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["prefetch"][0]["inner_header"]["version"] = 17
    with pytest.raises(RuntimeError, match="Prefetch.*inner header"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["prefetch_positive_control"]["mutation"]["payload_offset"] += 1
    with pytest.raises(RuntimeError, match="control mutation"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    control_native = hostile["prefetch_positive_control"]["native_decompression"]
    control_native["decompress_ntstatus"] = "0x00000000"
    control_native["final_uncompressed_size"] = hostile["artifacts"]["prefetch"][0]["wrapper"][
        "declared_uncompressed_size"
    ]
    control_native["returned_output_size"] = control_native["final_uncompressed_size"]
    control_native["output_sha256"] = hostile["prefetch_positive_control"]["expected_output_sha256"]
    hostile["prefetch_positive_control"]["outcome"] = "nonmatching-exact-output"
    with pytest.raises(RuntimeError, match="red Prefetch corruption control"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["zone_identifier"][0]["logical_stream"]["sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="does not bind stream"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["zone_identifier"][0]["readback"]["result"]["Base64"] = ""
    with pytest.raises(RuntimeError, match="ADS readback"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["zone_identifier"][0]["default_stream_postcondition"]["native_sha256"] = (
        "0" * 64
    )
    with pytest.raises(RuntimeError, match="default stream"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["scheduled_task_xml"][0]["native_parse"]["result"]["Accepted"] = False
    with pytest.raises(RuntimeError, match="Task Scheduler returned"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["scheduled_task_xml"][0]["target"]["sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="scheduled task.*PE join"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["scheduled_task_xml"][0]["portable_assurance"]["profile"]["command"] = (
        r"C:\Windows\invented.exe"
    )
    with pytest.raises(RuntimeError, match="scheduled task.*portable profile"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["scheduled_task_xml"][0]["portable_assurance"]["profile"]["enabled"] = 0
    with pytest.raises(RuntimeError, match="scheduled task.*portable profile"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["scheduled_task_xml"][0]["portable_assurance"]["bytes_base64"] = "!"
    with pytest.raises(RuntimeError, match="scheduled task.*portable bytes"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["shell_link"][0]["native_parse"]["result"]["TargetPath"] = (
        r"C:\Windows\invented.exe"
    )
    with pytest.raises(RuntimeError, match="WScript.Shell returned"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["shell_link"][0]["target"]["size"] += 1
    with pytest.raises(RuntimeError, match="Shell Link.*PE join"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["shell_link"][0]["portable_assurance"]["profile"]["target_size"] += 1
    with pytest.raises(RuntimeError, match="Shell Link.*portable profile"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["shell_link"][0]["target"] = hostile["artifacts"]["scheduled_task_xml"][0][
        "target"
    ]
    with pytest.raises(RuntimeError, match="distinct"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["claim_scope"]["activation_scope"] = "weakened"
    with pytest.raises(RuntimeError, match="claim scope"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["portable_prerequisite"]["record"]["fixture"]["carrier"]["files"][0]["sha256"] = (
        "0" * 64
    )
    hostile["fixture"]["carrier"] = hostile["portable_prerequisite"]["record"]["fixture"]["carrier"]
    hostile["private_scene"]["initial"] = hostile["fixture"]["carrier"]
    hostile["private_scene"]["post_observation"] = {
        **hostile["fixture"]["carrier"],
        "unchanged": True,
    }
    mutated_prerequisite = _canonical_json_bytes(hostile["portable_prerequisite"]["record"])
    for identity_name in ("identity", "local_initial", "post_observation"):
        identity = hostile["portable_prerequisite"][identity_name]
        identity["sha256"] = hashlib.sha256(mutated_prerequisite).hexdigest()
        identity["size"] = len(mutated_prerequisite)
    with pytest.raises(RuntimeError, match="fixture carrier"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["artifacts"]["pe"][0] = "not an evidence object"
    with pytest.raises(RuntimeError, match="invalid artifact evidence"):
        _validate_native_report(hostile)

    hostile = json.loads(_canonical_json_bytes(report))
    hostile["tools"]["initial"]["powershell"]["authenticode"]["result"]["SignerThumbprint"] = (
        "B" * 40
    )
    with pytest.raises(RuntimeError, match="valid Microsoft-signed"):
        _validate_native_report(hostile)


def test_fixture_mutation_is_rejected_before_any_native_tool(
    windows_fixture, tmp_path, monkeypatch
):
    fixture = tmp_path / "fixture"
    shutil.copytree(windows_fixture, fixture)
    _patch_source(monkeypatch)
    portable = prepare(fixture, repository_root=tmp_path)
    prerequisite = tmp_path / "portable.json"
    prerequisite.write_bytes(_canonical_json_bytes(portable))
    _state, captured = _fixture_state(fixture)
    relative = next(iter(captured))
    artifact = fixture / "artifacts" / Path(*relative.split("/"))
    data = bytearray(artifact.read_bytes())
    data[-1] ^= 1
    artifact.write_bytes(data)
    monkeypatch.setattr(attest.__globals__["sys"], "platform", "win32")
    _mock_windows_reader_on_posix(monkeypatch)
    called = False

    def native(_runner):
        nonlocal called
        called = True
        raise AssertionError("must not run")

    monkeypatch.setitem(attest.__globals__, "_native_tools", native)
    with pytest.raises(
        RuntimeError,
        match="default streams disagree|do not exactly match",
    ):
        attest(fixture, prerequisite, repository_root=tmp_path)
    assert called is False


def test_output_creation_is_exclusive_and_outside_protected_roots(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    destination = outside / "record.json"
    assert _write_new_output(destination, b"{}\n", forbidden_roots=(protected,)) == destination
    with pytest.raises(FileExistsError):
        _write_new_output(destination, b"replace\n", forbidden_roots=(protected,))
    with pytest.raises(RuntimeError, match="protected"):
        _write_new_output(protected / "record.json", b"{}\n", forbidden_roots=(protected,))
    with pytest.raises(RuntimeError, match="alternate data stream"):
        _write_new_output(
            outside / "record.json:Zone.Identifier",
            b"{}\n",
            forbidden_roots=(protected,),
        )


@pytest.mark.parametrize(
    ("message", "expected_failure"),
    [
        ("sentinel native postcondition", "sentinel native postcondition"),
        ("", "RuntimeError"),
    ],
)
def test_observe_main_preserves_a_native_failure_in_a_v5_envelope(
    tmp_path,
    monkeypatch,
    capsys,
    message,
    expected_failure,
):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    prerequisite = tmp_path / "portable.json"
    output = tmp_path / "native.json"
    captured = {}

    def failing_attest(_fixture, _prerequisite):
        raise RuntimeError(message)

    def capture_output(destination, data, *, forbidden_roots):
        captured["data"] = data
        captured["destination"] = destination
        captured["forbidden_roots"] = forbidden_roots
        return destination

    monkeypatch.setitem(main.__globals__, "attest", failing_attest)
    monkeypatch.setitem(main.__globals__, "_write_new_output", capture_output)
    monkeypatch.setitem(
        main.__globals__,
        "_timestamp",
        lambda _now=None: "2026-08-04T13:08:13Z",
    )
    monkeypatch.setattr(
        main.__globals__["sys"],
        "argv",
        [
            str(_SCRIPT),
            "observe",
            "--fixture",
            str(fixture),
            "--prerequisite",
            str(prerequisite),
            "--out",
            str(output),
        ],
    )

    assert main() == 1
    report = json.loads(captured["data"])
    assert report == {
        "canonicalization": main.__globals__["CANONICALIZATION"],
        "failures": [expected_failure],
        "generated_at_utc": "2026-08-04T13:08:13Z",
        "schema": main.__globals__["SCHEMA_ID"],
        "schema_version": 5,
        "verdict": "fail",
    }
    assert captured["destination"] == output
    assert len(captured["forbidden_roots"]) == 2
    output_text = capsys.readouterr()
    assert "wrote" in output_text.out
    assert f"FAIL: {expected_failure}" in output_text.err
    assert "invalid envelope" not in output_text.err
    assert "cannot safely write" not in output_text.err
