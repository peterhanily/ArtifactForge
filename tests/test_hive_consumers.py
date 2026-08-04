# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Responder-facing registry consumers must recognise and extract the emitted records."""
from __future__ import annotations

from pathlib import Path
import struct

import pytest

from artifactforge.artifacts.hive import build_amcache_hive, build_run_hive
from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME
from artifactforge.gates import inertness, validity

regipy = pytest.importorskip("regipy")
pyregf = pytest.importorskip("pyregf")

from regipy.plugins.amcache.amcache import AmCachePlugin  # noqa: E402
from regipy.plugins.software.persistence import SoftwarePersistencePlugin  # noqa: E402
from regipy.registry import RegistryHive  # noqa: E402


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _rewrite_base_name(data: bytes, name: str) -> bytes:
    encoded = name.encode("utf-16-le")
    assert len(encoded) <= 64
    changed = bytearray(data)
    changed[48:112] = b"\x00" * 64
    changed[48:48 + len(encoded)] = encoded
    checksum = 0
    for offset in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", changed, offset)[0]
    if checksum in (0, 0xFFFFFFFF):
        checksum ^= 1
    struct.pack_into("<I", changed, 508, checksum & 0xFFFFFFFF)
    return bytes(changed)


def _libregf_text_values(path: Path, key_path: str) -> dict[str, str]:
    hive = pyregf.file()
    hive.open(str(path))
    try:
        key = hive.get_key_by_path(key_path)
        assert key is not None
        return {
            value.name: value.data.decode("utf-16-le").rstrip("\x00")
            for value in key.values
        }
    finally:
        hive.close()


def test_regipy_amcache_plugin_recognises_and_extracts_emitted_records(tmp_path):
    rows = [
        ("a" * 40, r"c:\program files\windrow\updater.exe", "updater.exe", 2729),
        ("b" * 40, r"c:\programdata\stonewell\relay.exe", "relay.exe", 4096),
    ]
    path = _write(tmp_path / "Amcache.hve", build_amcache_hive(rows))

    hive = RegistryHive(str(path))
    plugin = AmCachePlugin(hive, as_json=True)
    assert hive.header.file_name == "Amcache.hve"
    assert hive.hive_type == "amcache"
    assert plugin.can_run() is True
    plugin.run()
    assert {(entry["sha1"], entry["lower_case_long_path"], entry["name"], entry["size"])
            for entry in plugin.entries} == set(rows)


def test_amcache_profile_preserves_name_case_but_joins_lowercase_path(tmp_path):
    path = _write(
        tmp_path / "Amcache.hve",
        build_amcache_hive(
            [("a" * 40, r"c:\program files\7zfm.exe", "7zFM.exe", 2729)]
        ),
    )

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()
    plugin = AmCachePlugin(RegistryHive(str(path)), as_json=True)
    plugin.run()
    assert plugin.entries[0]["lower_case_long_path"].endswith(r"\7zfm.exe")
    assert plugin.entries[0]["name"] == "7zFM.exe"


def test_expected_regipy_legacy_probe_diagnostic_does_not_pollute_gate_output(
    tmp_path, caplog, capsys
):
    _write(
        tmp_path / "Amcache.hve",
        build_amcache_hive(
            [("a" * 40, r"c:\program files\7zfm.exe", "7zFM.exe", 2729)]
        ),
    )

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()
    assert "Could not find" not in capsys.readouterr().err
    assert not any("Could not find" in record.getMessage() for record in caplog.records)


def test_regipy_software_plugin_recognises_and_extracts_run_values(tmp_path):
    rows = [
        ("Windrow Updater", r"C:\Program Files\Windrow\updater.exe"),
        ("Stonewell Relay", r"C:\ProgramData\Stonewell\relay.exe"),
    ]
    path = _write(tmp_path / "SOFTWARE", build_run_hive(rows))

    hive = RegistryHive(str(path))
    plugin = SoftwarePersistencePlugin(hive, as_json=True)
    assert hive.header.file_name == r"\System32\config\SOFTWARE"
    assert hive.hive_type == "software"
    assert plugin.can_run() is True
    plugin.run()
    observed = plugin.entries[r"\Microsoft\Windows\CurrentVersion\Run"]["values"]
    assert {(entry["name"], entry["value"]) for entry in observed} == set(rows)


@pytest.mark.parametrize(
    "name,data",
    (
        ("Amcache.hve", build_amcache_hive([("a" * 40, r"c:\a.exe", "a.exe", 1)])),
        ("SOFTWARE", build_run_hive([("Updater", r"C:\Updater.exe")])),
    ),
)
def test_disclosure_is_a_normal_key_not_a_forged_hive_identity(tmp_path, name, data):
    path = _write(tmp_path / name, data)
    hive = RegistryHive(str(path))
    assert "ArtifactForgeHive" not in hive.header.file_name

    regipy_marker = hive.get_key(f"\\{RESERVED_NAME}")
    assert {value.name: value.value for value in regipy_marker.iter_values()} == {
        "marker": MARKER,
        "notice": NOTICE,
    }
    assert _libregf_text_values(path, RESERVED_NAME) == {
        "marker": MARKER,
        "notice": NOTICE,
    }


def test_unicode_registry_value_names_round_trip_both_readers(tmp_path):
    value_name = "München 自動更新"
    path = _write(
        tmp_path / "SOFTWARE",
        build_run_hive([(value_name, r"C:\Program Files\Windrow\updater.exe")]),
    )
    regipy_run = RegistryHive(str(path)).get_key(r"\Microsoft\Windows\CurrentVersion\Run")
    assert [value.name for value in regipy_run.iter_values()] == [value_name]

    hive = pyregf.file()
    hive.open(str(path))
    try:
        libregf_run = hive.get_key_by_path(r"Microsoft\Windows\CurrentVersion\Run")
        assert [value.name for value in libregf_run.values] == [value_name]
    finally:
        hive.close()


def test_gate1_records_typed_consensus_profiles_and_real_plugin_consumers(tmp_path):
    _write(
        tmp_path / "Amcache.hve",
        build_amcache_hive([("a" * 40, r"c:\windrow\updater.exe", "updater.exe", 2729)]),
    )
    _write(
        tmp_path / "Software.run.hive",
        build_run_hive([("Windrow Updater", r"C:\Windrow\updater.exe")]),
    )
    report = validity.run(str(tmp_path))
    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 4
    assert report.metrics["semantic_checks_passed"] == 6


def test_gate1_accepts_both_hive_profiles_at_the_64_row_boundary(tmp_path):
    _write(
        tmp_path / "Amcache.hve",
        build_amcache_hive(
            [
                (
                    f"{index + 1:040x}",
                    rf"c:\programdata\artifactforge\agent{index:02d}.exe",
                    f"Agent{index:02d}.exe",
                    index,
                    f"{index + 1:016x}",
                )
                for index in range(64)
            ]
        ),
    )
    _write(
        tmp_path / "Software.run.hive",
        build_run_hive(
            [
                (
                    f"ArtifactForge Updater {index:02d}",
                    rf"C:\ProgramData\ArtifactForge\agent{index:02d}.exe",
                )
                for index in range(64)
            ]
        ),
    )

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 4
    assert report.metrics["semantic_checks_passed"] == 6


def test_parseable_base_identity_mutation_breaks_profile_and_plugin_gate(tmp_path):
    path = _write(
        tmp_path / "Amcache.hve",
        build_amcache_hive([("a" * 40, r"c:\windrow\updater.exe", "updater.exe", 2729)]),
    )
    before = validity.run(str(tmp_path))
    assert before.ok, before.render()
    path.write_bytes(_rewrite_base_name(path.read_bytes(), "OrdinaryHive"))

    # Both generic readers still agree on every typed key and value. Only the artifact-aware
    # profile and consumer applicability have been destroyed.
    assert validity._read_regipy(str(path)) == validity._read_libregf(str(path))
    after = validity.run(str(tmp_path))
    new = [failure for failure in after.fails if failure not in before.fails]
    assert any("windows-hive-profile" in failure for failure in new), new
    assert any("regipy-artifact-consumer" in failure for failure in new), new


def test_parseable_marker_value_mutation_breaks_gate1_and_gate3(tmp_path):
    path = _write(
        tmp_path / "Amcache.hve",
        build_amcache_hive([("a" * 40, r"c:\windrow\updater.exe", "updater.exe", 2729)]),
    )
    before_validity = validity.run(str(tmp_path))
    before_inertness = inertness.run(str(tmp_path))
    assert before_validity.ok and before_inertness.ok

    data = path.read_bytes()
    original = MARKER.encode("utf-16-le")
    replacement = "ARTIFACTF0RGE".encode("utf-16-le")
    assert len(original) == len(replacement) and data.count(original) == 1
    path.write_bytes(data.replace(original, replacement))

    assert validity._read_regipy(str(path)) == validity._read_libregf(str(path))
    after_validity = validity.run(str(tmp_path))
    after_inertness = inertness.run(str(tmp_path))
    assert any("windows-hive-profile" in failure for failure in after_validity.fails)
    assert any("synthetic marker" in failure for failure in after_inertness.fails)
