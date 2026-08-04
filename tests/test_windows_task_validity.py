# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 consensus, profile, and consumer checks for disabled Scheduled Task XML."""
from __future__ import annotations

import dataclasses
from xml.etree import ElementTree

import pytest

from artifactforge.artifacts.windows_task import (
    MAX_SCHEDULED_TASK_XML_BYTES,
    build_scheduled_task_xml,
)
from artifactforge.content import build_pe_stub
from artifactforge.gates import validity


TASK_NAME = "WindrowCache"
COMMAND = r"C:\Users\v\AppData\Local\Temp\windrow-helper.exe"
DECOY_COMMAND = r"C:\Users\v\AppData\Local\Temp\decoy-helper.exe"
TASK_FILENAME = f"{TASK_NAME}.task.xml"


def _decode(data: bytes) -> str:
    assert data.startswith(b"\xff\xfe")
    return data[2:].decode("utf-16-le")


def _encode(text: str) -> bytes:
    return b"\xff\xfe" + text.encode("utf-16-le")


def _replace(data: bytes, old: str, new: str) -> bytes:
    text = _decode(data)
    assert text.count(old) == 1
    return _encode(text.replace(old, new))


def _task() -> bytes:
    return build_scheduled_task_xml(
        TASK_NAME,
        COMMAND,
        resident_pe_paths=(COMMAND,),
    )


def _write_pe(path, *, seed: int = 1) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_pe_stub(bytes((seed,)) * 32))


def _write_scene(tmp_path, task_data: bytes, *, task_filename: str = TASK_FILENAME):
    _write_pe(tmp_path / "windrow-helper.exe")
    task_path = tmp_path / task_filename
    task_path.parent.mkdir(parents=True, exist_ok=True)
    task_path.write_bytes(task_data)
    return task_path


def test_task_gate_separates_consensus_profile_and_dissect_consumer(tmp_path):
    task_path = _write_scene(tmp_path, _task())

    elementtree = validity._read_elementtree_task_xml(task_path.read_bytes())
    raw = validity._read_task_xml_raw(task_path.read_bytes())
    dissect = validity._read_dissect_task_xml(task_path.read_bytes())
    assert elementtree == raw
    assert dissect.version == "1.2"
    assert dissect.uri == elementtree.uri
    assert dissect.description == elementtree.description
    assert dissect.command == elementtree.command
    assert dissect.enabled is False
    assert dissect.allow_start_on_demand is False
    assert dissect.hidden is False
    assert dissect.arguments is None
    assert dissect.working_directory is None
    assert dissect.action_context is None
    assert dissect.trigger_count == dissect.principal_count == 0
    assert dissect.action_count == 1

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 5
    assert report.metrics["oracle_reads_total"] == 5
    assert report.metrics["semantic_checks_passed"] == 4
    assert report.metrics["semantic_checks_total"] == 4
    assert report.metrics["claim_scopes"]["downstream_consumer_compatibility"] == {
        "passed": 1,
        "total": 1,
    }


@pytest.mark.parametrize(
    "mutate",
    (
        lambda data: _replace(data, "<Enabled>false</Enabled>", "<Enabled>true</Enabled>"),
        lambda data: _replace(
            data,
            "<AllowStartOnDemand>false</AllowStartOnDemand>",
            "<AllowStartOnDemand>true</AllowStartOnDemand>",
        ),
        lambda data: _replace(data, "<Hidden>false</Hidden>", "<Hidden>true</Hidden>"),
        lambda data: _replace(
            data,
            "  <Settings>",
            "  <Triggers><LogonTrigger /></Triggers>\r\n  <Settings>",
        ),
        lambda data: _replace(
            data,
            "  <Settings>",
            "  <Principals><Principal id=\"Synthetic\"><UserId>S-1-5-18</UserId>"
            "</Principal></Principals>\r\n  <Settings>",
        ),
        lambda data: _replace(
            data,
            f"      <Command>{COMMAND}</Command>",
            f"      <Command>{COMMAND}</Command>\r\n      <Arguments>--run</Arguments>",
        ),
        lambda data: _replace(
            data,
            "    </Exec>",
            "      <WorkingDirectory>C:\\Temp</WorkingDirectory>\r\n    </Exec>",
        ),
        lambda data: _replace(data, "  <Actions>", '  <Actions Context="Synthetic">'),
        lambda data: _replace(
            data,
            "    </Exec>",
            f"    </Exec>\r\n    <Exec><Command>{COMMAND}</Command></Exec>",
        ),
        lambda data: _replace(data, 'version="1.2"', 'version="1.4"'),
        lambda data: _replace(
            data,
            'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"',
            'xmlns="https://artifactforge.invalid/not-task-scheduler"',
        ),
        lambda data: _replace(
            data,
            "ARTIFACTFORGE synthetic inert scheduled-task artifact",
            "ALTERED synthetic inert scheduled-task artifact",
        ),
        lambda data: _decode(data)
        .replace('encoding="UTF-16"', 'encoding="UTF-8"')
        .encode("utf-8"),
    ),
    ids=(
        "enabled",
        "demand-start",
        "hidden",
        "trigger",
        "principal",
        "arguments",
        "working-directory",
        "action-context",
        "second-action",
        "version",
        "namespace",
        "marker",
        "utf8-wire-encoding",
    ),
)
def test_parser_valid_activation_and_profile_mutations_turn_gate_red(tmp_path, mutate):
    mutated = mutate(_task())
    ElementTree.fromstring(mutated)
    _write_scene(tmp_path, mutated)

    report = validity.run(str(tmp_path))

    assert not report.ok
    assert any(TASK_FILENAME in failure or "task-xml:" in failure for failure in report.fails)


def test_safe_nonresident_command_passes_all_readers_but_fails_profile_join(tmp_path):
    mutated = _replace(_task(), COMMAND, DECOY_COMMAND)
    task_path = _write_scene(tmp_path, mutated)
    assert validity._read_elementtree_task_xml(task_path.read_bytes()).command == DECOY_COMMAND
    assert validity._read_task_xml_raw(task_path.read_bytes()).command == DECOY_COMMAND
    assert validity._read_dissect_task_xml(task_path.read_bytes()).command == DECOY_COMMAND

    report = validity.run(str(tmp_path))

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == report.metrics["oracle_reads_total"] == 5
    assert report.metrics["semantic_checks_passed"] == 3
    assert report.metrics["semantic_checks_total"] == 4
    assert any("scheduled-task-xml-profile" in failure for failure in report.fails)
    assert any("exactly one resident PE" in failure for failure in report.fails)


def test_loose_task_filename_is_transport_and_need_not_duplicate_the_uri_name(tmp_path):
    _write_scene(tmp_path, _task(), task_filename="OtherName.task.xml")

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()


def test_extensionless_native_task_store_content_is_recognised_and_valid(tmp_path):
    native_path = f"C/Windows/System32/Tasks/ArtifactForge/{TASK_NAME}"
    task_path = _write_scene(tmp_path, _task(), task_filename=native_path)

    assert validity.classify(str(task_path)) == "task-xml"
    report = validity.run(str(tmp_path))

    assert report.ok, report.render()


def test_renamed_task_content_is_classified_but_rejected_outside_owned_paths(tmp_path):
    task_path = _write_scene(tmp_path, _task(), task_filename="renamed-task-content.bin")

    assert validity.classify(str(task_path)) == "task-xml"
    report = validity.run(str(tmp_path))

    assert not report.ok
    assert not any("no format recognised" in failure for failure in report.fails)
    assert any("exact native Task-store served path" in failure for failure in report.fails)


def test_utf16_xml_declaration_with_non_task_root_is_classified_then_rejected(tmp_path):
    _write_pe(tmp_path / "windrow-helper.exe")
    data = _encode(
        '<?xml version="1.0" encoding="UTF-16"?>\r\n'
        '<NotTask xmlns="https://artifactforge.invalid/not-task">value</NotTask>\r\n'
    )
    path = tmp_path / "extensionless-xml"
    path.write_bytes(data)

    assert validity.classify(str(path)) == "task-xml"
    report = validity.run(str(tmp_path))

    assert not report.ok
    assert not any("no format recognised" in failure for failure in report.fails)
    assert any("task-xml:" in failure for failure in report.fails)
    assert any("scheduled-task-xml-profile" in failure for failure in report.fails)


def test_command_basename_uses_windows_case_insensitive_resident_matching(tmp_path):
    _write_pe(tmp_path / "WINDROW-HELPER.EXE")
    (tmp_path / TASK_FILENAME).write_bytes(_task())

    report = validity.run(str(tmp_path))

    assert report.ok, report.render()


def test_casefold_ambiguous_resident_pe_basenames_turn_profile_red(tmp_path):
    _write_pe(tmp_path / "first" / "windrow-helper.exe", seed=1)
    _write_pe(tmp_path / "second" / "WINDROW-HELPER.EXE", seed=2)
    (tmp_path / TASK_FILENAME).write_bytes(_task())

    report = validity.run(str(tmp_path))

    assert not report.ok
    assert any("exactly one resident PE" in failure for failure in report.fails)


def test_task_consensus_is_type_exact(tmp_path, monkeypatch):
    _write_scene(tmp_path, _task())
    original = validity.READERS["task-xml-raw"]

    def altered(data):
        return dataclasses.replace(original(data), enabled=0)

    monkeypatch.setitem(validity.READERS, "task-xml-raw", altered)
    report = validity.run(str(tmp_path))

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == report.metrics["oracle_reads_total"]
    assert any("scheduled-task-xml-consensus" in failure for failure in report.fails)
    assert any("non-exact scheduled-task field type" in failure for failure in report.fails)


def test_dissect_consumer_disagreement_is_a_separate_failure(tmp_path, monkeypatch):
    _write_scene(tmp_path, _task())
    original = validity.READERS["dissect.target-tasks"]

    def altered(data):
        return dataclasses.replace(original(data), command=DECOY_COMMAND)

    monkeypatch.setitem(validity.READERS, "dissect.target-tasks", altered)
    report = validity.run(str(tmp_path))

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == report.metrics["oracle_reads_total"]
    assert any("dissect-scheduled-task-consumer" in failure for failure in report.fails)
    assert not any("scheduled-task-xml-consensus" in failure for failure in report.fails)


def test_task_snapshot_bound_prevents_all_three_readers_from_running(tmp_path, monkeypatch):
    _write_pe(tmp_path / "windrow-helper.exe")
    (tmp_path / TASK_FILENAME).write_bytes(b"X" * (MAX_SCHEDULED_TASK_XML_BYTES + 1))
    called: list[str] = []

    def forbidden(_source):
        called.append("called")
        raise AssertionError("bounded snapshot must reject before parser invocation")

    for oracle in ("elementtree", "task-xml-raw", "dissect.target-tasks"):
        monkeypatch.setitem(validity.READERS, oracle, forbidden)

    report = validity.run(str(tmp_path))

    assert not called
    assert report.metrics["oracle_reads_total"] == 5
    assert report.metrics["oracle_reads_passed"] == 2
    assert sum("snapshot limit" in failure for failure in report.fails) == 3
