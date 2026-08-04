# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Scheduled Task XML is deterministic, inert, bounded, and independently observed."""
from __future__ import annotations

from xml.etree import ElementTree

import pytest

from artifactforge.artifacts.windows_task import (
    MAX_SCHEDULED_TASK_RESIDENTS,
    MAX_SCHEDULED_TASK_XML_BYTES,
    TASK_DESCRIPTION,
    TASK_NAMESPACE,
    ScheduledTaskXmlValue,
    ScheduledTaskXmlWireValue,
    build_scheduled_task_xml,
    parse_scheduled_task_xml,
    read_scheduled_task_xml_wire,
    validate_scheduled_task_xml,
)
from artifactforge.disclosure import MARKER


COMMAND = r"C:\Users\v\AppData\Local\Temp\windrow-helper.exe"
DECOY = r"C:\Program Files\Stonewell\stonewell-helper.exe"


def _decode(data: bytes) -> str:
    assert data.startswith(b"\xff\xfe")
    return data[2:].decode("utf-16-le")


def _encode(text: str) -> bytes:
    return b"\xff\xfe" + text.encode("utf-16-le")


def _replace(data: bytes, old: str, new: str) -> bytes:
    text = _decode(data)
    assert text.count(old) == 1
    return _encode(text.replace(old, new))


def _generic_xml_parse(data: bytes) -> None:
    ElementTree.fromstring(data)


def test_task_writer_is_byte_exact_deterministic_disabled_and_trigger_free():
    first = build_scheduled_task_xml(
        "WindrowCache",
        COMMAND,
        resident_pe_paths=(COMMAND, DECOY),
    )
    second = build_scheduled_task_xml(
        "WindrowCache",
        COMMAND,
        resident_pe_paths=iter((COMMAND, DECOY)),
    )
    assert first == second
    assert first.startswith(b"\xff\xfe")
    assert len(first) <= MAX_SCHEDULED_TASK_XML_BYTES
    expected = "\r\n".join(
        (
            '<?xml version="1.0" encoding="UTF-16"?>',
            f'<Task version="1.2" xmlns="{TASK_NAMESPACE}">',
            "  <RegistrationInfo>",
            f"    <URI>\\ArtifactForge\\{MARKER}-WindrowCache</URI>",
            f"    <Description>{TASK_DESCRIPTION}</Description>",
            "  </RegistrationInfo>",
            "  <Settings>",
            "    <AllowStartOnDemand>false</AllowStartOnDemand>",
            "    <Enabled>false</Enabled>",
            "    <Hidden>false</Hidden>",
            "  </Settings>",
            "  <Actions>",
            "    <Exec>",
            f"      <Command>{COMMAND}</Command>",
            "    </Exec>",
            "  </Actions>",
            "</Task>",
            "",
        )
    )
    assert first == _encode(expected)
    decoded = _decode(first)
    assert "<Triggers" not in decoded
    assert "<Arguments" not in decoded
    assert "<WorkingDirectory" not in decoded


@pytest.mark.parametrize("version", ("1.2", "1.3"))
def test_elementtree_and_wire_readers_agree_on_both_owned_versions(version):
    data = build_scheduled_task_xml(
        "WindrowCache",
        COMMAND,
        resident_pe_paths=(COMMAND,),
        version=version,
    )
    parsed = parse_scheduled_task_xml(data)
    wire = read_scheduled_task_xml_wire(data)
    validated = validate_scheduled_task_xml(data, resident_pe_paths=(COMMAND,))

    assert isinstance(parsed, ScheduledTaskXmlValue)
    assert isinstance(wire, ScheduledTaskXmlWireValue)
    assert validated == parsed
    assert parsed.namespace == TASK_NAMESPACE
    assert parsed.version == wire.version == version
    assert parsed.task_name == wire.task_name == "WindrowCache"
    assert parsed.uri == wire.uri == rf"\ArtifactForge\{MARKER}-WindrowCache"
    assert parsed.description == wire.description == TASK_DESCRIPTION
    assert parsed.command == wire.command == COMMAND
    assert type(parsed.enabled) is bool and parsed.enabled is False
    assert type(parsed.allow_start_on_demand) is bool
    assert parsed.allow_start_on_demand is False
    assert type(parsed.hidden) is bool and parsed.hidden is False
    assert parsed.trigger_count == wire.trigger_count == 0
    assert parsed.action_count == wire.action_count == 1
    assert wire.encoding == "UTF-16LE+BOM"
    assert wire.line_count == 17
    assert wire.marker_count == 2
    _generic_xml_parse(data)


def test_resident_join_uses_windows_case_semantics_but_requires_the_exact_path():
    uppercase_resident = r"C:\USERS\V\APPDATA\LOCAL\TEMP\WINDROW-HELPER.EXE"
    data = build_scheduled_task_xml(
        "WindrowCache",
        COMMAND,
        resident_pe_paths=(uppercase_resident,),
    )

    assert validate_scheduled_task_xml(
        data,
        resident_pe_paths=(uppercase_resident,),
    ).command == COMMAND
    with pytest.raises(ValueError, match="not an exact resident"):
        validate_scheduled_task_xml(
            data,
            resident_pe_paths=(r"C:\Other\windrow-helper.exe",),
        )


def test_command_xml_escaping_round_trips_without_becoming_task_syntax():
    command = r"C:\Program Files\Research & Development\helper.exe"
    data = build_scheduled_task_xml(
        "AmpersandPath",
        command,
        resident_pe_paths=(command,),
    )
    assert "Research &amp; Development" in _decode(data)
    assert parse_scheduled_task_xml(data).command == command
    assert read_scheduled_task_xml_wire(data).command == command


@pytest.mark.parametrize(
    ("kwargs", "match"),
    (
        ({"task_name": ""}, "1..64"),
        ({"task_name": " leading"}, "1..64"),
        ({"task_name": "bad/name"}, "1..64"),
        ({"task_name": "x" * 65}, "1..64"),
        ({"task_name": "Café"}, "1..64"),
        ({"task_name": "Windrow."}, "valid Windows name"),
        ({"task_name": "CON"}, "valid Windows name"),
        ({"version": "1.1"}, "'1.2' or '1.3'"),
        ({"version": "1.4"}, "'1.2' or '1.3'"),
        ({"version": 1.2}, "'1.2' or '1.3'"),
        ({"command": r"relative\helper.exe"}, "normalized absolute"),
        ({"command": r"\\server\share\helper.exe"}, "normalized absolute"),
        ({"command": r"c:\Temp\helper.exe"}, "normalized absolute"),
        ({"command": r"C:/Temp/helper.exe"}, "normalized absolute"),
        ({"command": r"C:\Temp\..\helper.exe"}, "normalized absolute"),
        ({"command": r"C:\Temp\\helper.exe"}, "normalized absolute"),
        ({"command": "C:\\Temp\\helper.exe\n"}, "control character"),
        ({"command": r"C:\Temp\helper.exe --flag"}, "one .exe"),
        ({"command": r"C:\Temp\helper.cmd"}, "one .exe"),
        ({"command": r"C:\Temp\cmd.exe"}, "forbidden"),
        ({"command": r"C:\Temp\powershell.exe"}, "forbidden"),
        ({"command": r"C:\Temp\NUL.exe"}, "invalid Windows"),
        ({"command": "C:\\Temp\\trailing .exe"}, "not an exact resident"),
        ({"command": r"C:\Temp\%PROGRAMDATA%\helper.exe"}, "invalid Windows"),
        ({"command": "C:\\Temp\\café.exe"}, "strict ASCII"),
        ({"command": "C:\\" + "a" * 252 + ".exe"}, "invalid Windows"),
        (
            {"command": "C:\\" + "a" * 130 + "\\" + "b" * 123 + ".exe"},
            "exceeds 260",
        ),
    ),
)
def test_task_writer_rejects_values_outside_the_inert_exec_profile(kwargs, match):
    values = {
        "task_name": "WindrowCache",
        "command": COMMAND,
        "resident_pe_paths": (COMMAND,),
        "version": "1.2",
    }
    values.update(kwargs)
    if "command" in kwargs:
        candidate = kwargs["command"]
        if isinstance(candidate, str) and "trailing .exe" not in candidate:
            values["resident_pe_paths"] = (candidate,)
    with pytest.raises(ValueError, match=match):
        build_scheduled_task_xml(**values)


@pytest.mark.parametrize(
    ("residents", "match"),
    (
        ((), "1..128"),
        (COMMAND, "iterable"),
        ({COMMAND: b"bytes"}, "iterable"),
        ((COMMAND, r"C:\users\v\appdata\local\temp\windrow-helper.exe"),
         "case-insensitive duplicates"),
        ((DECOY,), "not an exact resident"),
        ((r"C:\Temp\cmd.exe",), "forbidden"),
    ),
)
def test_task_writer_requires_a_bounded_unambiguous_resident_pe_allowlist(
    residents, match
):
    with pytest.raises(ValueError, match=match):
        build_scheduled_task_xml(
            "WindrowCache",
            COMMAND,
            resident_pe_paths=residents,
        )


def test_resident_allowlist_bound_is_checked_with_bounded_iteration():
    paths = tuple(
        rf"C:\Temp\helper-{index:03d}.exe"
        for index in range(MAX_SCHEDULED_TASK_RESIDENTS + 1)
    )
    with pytest.raises(ValueError, match="1..128"):
        build_scheduled_task_xml(
            "WindrowCache",
            paths[0],
            resident_pe_paths=iter(paths),
        )


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (
            lambda data: _replace(
                data,
                "<Enabled>false</Enabled>",
                "<Enabled>true</Enabled>",
            ),
            "lowercase false",
        ),
        (
            lambda data: _replace(
                data,
                "      <Command>",
                "      <Arguments>--run</Arguments>\r\n      <Command>",
            ),
            "outside the closed",
        ),
        (
            lambda data: _replace(
                data,
                "    </Exec>",
                "      <WorkingDirectory>C:\\Temp</WorkingDirectory>\r\n    </Exec>",
            ),
            "outside the closed",
        ),
        (
            lambda data: _replace(
                data,
                "  <Settings>",
                "  <Triggers><LogonTrigger /></Triggers>\r\n  <Settings>",
            ),
            "outside the closed",
        ),
        (
            lambda data: _replace(
                data,
                "  <Settings>",
                "  <!-- parser-valid but outside the canonical profile -->\r\n  <Settings>",
            ),
            "outside the closed",
        ),
        (
            lambda data: _replace(
                data,
                f'xmlns="{TASK_NAMESPACE}"',
                'xmlns="https://artifactforge.invalid/task"',
            ),
            "Microsoft Task root",
        ),
        (
            lambda data: _replace(
                data,
                rf"\{MARKER}-WindrowCache",
                r"\ALTERED-WindrowCache",
            ),
            "marked task-store profile",
        ),
        (
            lambda data: _replace(
                data,
                "<Actions>",
                '<Actions Context="SyntheticPrincipal">',
            ),
            "attributes",
        ),
        (
            lambda data: _replace(data, 'version="1.2"', 'version="1.4"'),
            "'1.2' or '1.3'",
        ),
    ),
    ids=(
        "enabled",
        "arguments",
        "working-directory",
        "trigger",
        "comment",
        "namespace",
        "marker",
        "action-context",
        "version",
    ),
)
def test_elementtree_reader_rejects_well_formed_parser_valid_profile_mutations(
    mutate, match
):
    data = build_scheduled_task_xml(
        "WindrowCache", COMMAND, resident_pe_paths=(COMMAND,)
    )
    mutated = mutate(data)
    _generic_xml_parse(mutated)
    with pytest.raises(ValueError, match=match):
        parse_scheduled_task_xml(mutated)


def test_resident_join_rejects_a_safe_but_nonresident_parser_valid_command():
    data = build_scheduled_task_xml(
        "WindrowCache", COMMAND, resident_pe_paths=(COMMAND, DECOY)
    )
    mutated = _replace(data, COMMAND, DECOY)
    assert parse_scheduled_task_xml(mutated).command == DECOY
    assert read_scheduled_task_xml_wire(mutated).command == DECOY
    with pytest.raises(ValueError, match="not an exact resident"):
        validate_scheduled_task_xml(mutated, resident_pe_paths=(COMMAND,))


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (lambda data: data[2:], "UTF-16LE BOM"),
        (lambda data: b"\xfe\xff" + data[2:], "UTF-16LE BOM"),
        (lambda data: data[:-1], "complete code units"),
        (
            lambda data: _encode(_decode(data).replace("\r\n", "\n")),
            "end with CRLF",
        ),
        (
            lambda data: _replace(data, "ARTIFACTFORGE-", "&#65;RTIFACTFORGE-"),
            "non-canonical XML escaping",
        ),
        (
            lambda data: _encode(_decode(data).replace("  <Settings>", " <Settings>")),
            "canonical structure",
        ),
    ),
    ids=("no-bom", "big-endian-bom", "odd", "lf", "numeric-reference", "indent"),
)
def test_wire_reader_rejects_noncanonical_bytes_that_remain_well_formed_when_applicable(
    mutate, match
):
    data = build_scheduled_task_xml(
        "WindrowCache", COMMAND, resident_pe_paths=(COMMAND,)
    )
    mutated = mutate(data)
    if not mutated.startswith(b"\xfe\xff") and len(mutated) % 2 == 0:
        _generic_xml_parse(mutated)
    with pytest.raises(ValueError, match=match):
        read_scheduled_task_xml_wire(mutated)


def test_xml_reader_accepts_semantically_identical_utf8_but_consensus_rejects_wire():
    data = build_scheduled_task_xml(
        "WindrowCache", COMMAND, resident_pe_paths=(COMMAND,)
    )
    utf8 = _decode(data).replace('encoding="UTF-16"', 'encoding="UTF-8"').encode()
    assert parse_scheduled_task_xml(utf8).command == COMMAND
    with pytest.raises(ValueError, match="UTF-16LE BOM"):
        validate_scheduled_task_xml(utf8, resident_pe_paths=(COMMAND,))


def test_readers_bound_input_before_parsing_or_scanning(monkeypatch):
    oversized = b"X" * (MAX_SCHEDULED_TASK_XML_BYTES + 1)

    def forbidden(_data):
        raise AssertionError("ElementTree must not run beyond the snapshot bound")

    monkeypatch.setattr(ElementTree, "fromstring", forbidden)
    with pytest.raises(ValueError, match="1..16384"):
        parse_scheduled_task_xml(oversized)
    with pytest.raises(ValueError, match="1..16384"):
        read_scheduled_task_xml_wire(oversized)


def test_xml_reader_rejects_doctype_before_elementtree_entity_processing():
    data = build_scheduled_task_xml(
        "WindrowCache", COMMAND, resident_pe_paths=(COMMAND,)
    )
    text = _decode(data).replace(
        '<Task version="1.2"',
        '<!DOCTYPE Task [<!ENTITY x "WindrowCache">]>\r\n<Task version="1.2"',
    )
    mutated = _encode(text.replace("ARTIFACTFORGE-WindrowCache", "ARTIFACTFORGE-&x;"))
    with pytest.raises(ValueError, match="declarations or entities"):
        parse_scheduled_task_xml(mutated)
