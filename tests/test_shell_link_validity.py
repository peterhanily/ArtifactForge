# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 requires external and bounded-reader consensus for Windows Shell Links."""
from __future__ import annotations

from dataclasses import replace
import struct

import pytest

from artifactforge.artifacts.shell_link import (
    MIN_PORTABLE_FILETIME,
    ShellLinkTimestamps,
    build_shell_link,
)
from artifactforge.content import build_pe_stub
from artifactforge.gates import validity


TARGET = r"C:\Users\v\AppData\Local\ArtifactForge\updater.exe"
TIMESTAMPS = ShellLinkTimestamps(
    creation_filetime=133_497_684_000_000_000,
    access_filetime=133_497_690_000_000_000,
    write_filetime=133_497_687_000_000_000,
)


def _link() -> bytes:
    return build_shell_link(
        TARGET,
        "Updater reference",
        2729,
        timestamps=TIMESTAMPS,
        volume_serial=0x1234ABCD,
        volume_label="TRAINING",
    )


def _scene(tmp_path, *, link_data: bytes | None = None, link_name: str = "Updater.lnk"):
    (tmp_path / "updater.exe").write_bytes(build_pe_stub(b"s" * 32))
    (tmp_path / link_name).write_bytes(_link() if link_data is None else link_data)


def test_shell_link_gate_runs_three_readers_consensus_and_profile(tmp_path):
    _scene(tmp_path)
    payload = (tmp_path / "Updater.lnk").read_bytes()

    liblnk = validity.READERS["liblnk"](payload)
    lnkparse3 = validity.READERS["LnkParse3"](payload)
    raw = validity.READERS["shell-link-raw"](payload)
    assert liblnk == lnkparse3 == raw

    report = validity.run(str(tmp_path))
    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 5
    assert report.metrics["oracle_reads_total"] == 5
    assert report.metrics["semantic_checks_passed"] == 3
    assert report.metrics["semantic_checks_total"] == 3
    assert report.metrics["claim_scopes"]["independent_consensus"] == {
        "passed": 2,
        "total": 2,
    }
    assert report.metrics["claim_scopes"]["declared_profile_conformance"] == {
        "passed": 1,
        "total": 1,
    }


def test_shell_link_magic_classifies_a_renamed_file_and_suffix_classifies_corruption(tmp_path):
    data = _link()
    assert validity.classify_bytes(data, "renamed.bin") == "shell-link"
    assert validity.classify_bytes(b"not a link", "claimed.LNK") == "shell-link"

    _scene(tmp_path, link_name="renamed.bin")
    report = validity.run(str(tmp_path))
    assert report.ok, report.render()


def test_shell_link_gate_rejects_payload_after_the_terminal_block(tmp_path):
    _scene(tmp_path, link_data=_link() + b"PAYLOAD")
    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any(
        "LnkParse3" in failure or "shell-link-raw" in failure
        for failure in report.fails
    )


def test_shell_link_gate_rejects_nonrepresentable_filetime_consensus(tmp_path):
    data = bytearray(_link())
    creation = struct.unpack_from("<Q", data, 28)[0]
    struct.pack_into("<Q", data, 28, creation + 1)
    _scene(tmp_path, link_data=bytes(data))

    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any("shell-link-consensus" in failure for failure in report.fails)


def test_shell_link_gate_rejects_consensus_timestamp_outside_writer_profile(tmp_path):
    data = bytearray(_link())
    for offset in (28, 36, 44):
        struct.pack_into("<Q", data, offset, MIN_PORTABLE_FILETIME - 10)
    _scene(tmp_path, link_data=bytes(data))

    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any("shell-link-profile" in failure for failure in report.fails)


def test_shell_link_gate_rejects_typed_reader_disagreement(tmp_path, monkeypatch):
    _scene(tmp_path)
    original = validity.READERS["LnkParse3"]

    def altered(data):
        return replace(original(data), target_size=2730)

    monkeypatch.setitem(validity.READERS, "LnkParse3", altered)
    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any("shell-link-consensus" in failure for failure in report.fails)


@pytest.mark.parametrize("oracle", ("liblnk", "LnkParse3"))
def test_shell_link_missing_external_oracle_is_failure(tmp_path, monkeypatch, oracle):
    _scene(tmp_path)

    def missing(_data):
        module = "pylnk" if oracle == "liblnk" else "LnkParse3"
        error = ModuleNotFoundError(f"No module named {module!r}")
        error.name = module
        raise error

    monkeypatch.setitem(validity.READERS, oracle, missing)
    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any(f"oracle '{oracle}' is not installed" in failure for failure in report.fails)


def test_shell_link_snapshot_bound_precedes_external_parsers(tmp_path, monkeypatch):
    _scene(tmp_path, link_data=b"L\0\0\0" + b"X" * 4093)

    def forbidden(_data):
        raise AssertionError("external parser must not run beyond the snapshot bound")

    monkeypatch.setitem(validity.READERS, "liblnk", forbidden)
    monkeypatch.setitem(validity.READERS, "LnkParse3", forbidden)
    report = validity.run(str(tmp_path))
    assert not report.ok
    assert any("exceeds the 4096-byte snapshot limit" in failure for failure in report.fails)
