# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic, disabled Windows Task Scheduler XML artifacts.

This module owns one deliberately small Task Scheduler 1.2/1.3 profile.  It is XML data
only: the writer never registers a task, contacts the Task Scheduler service, or executes
the command it records.  The profile has no triggers or principal, contains exactly one
argument-free ``Exec`` action naming an allowlisted resident PE, and sets both ``Enabled``
and ``AllowStartOnDemand`` to ``false``.

The standard-library ElementTree reader and the byte-oriented canonical reader are
separately implemented.  Their agreement is a useful local gate, not a claim that this
bounded reader implements the complete Microsoft schema.

Primary format references (retrieved 2026-08-03):

* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/0d6383e4-de92-43e7-b0bb-a60cfa36379f
* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/4b178ab9-afd9-46e1-88c6-fa3bda613121
* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/2e1de7c6-804e-40db-8aeb-9e0df2b9bb02
* https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-exectype-complextype
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
import ntpath
import re
from xml.etree import ElementTree

from artifactforge.disclosure import MARKER


TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
TASK_DESCRIPTION = (
    f"{MARKER} synthetic inert scheduled-task artifact; disabled and trigger-free."
)
SCHEDULED_TASK_XML_PROFILE = "windows-task-scheduler-disabled-exec-v1"
TASK_VERSIONS = frozenset({"1.2", "1.3"})
MAX_SCHEDULED_TASK_XML_BYTES = 16 * 1024
MAX_SCHEDULED_TASK_NAME_BYTES = 64
MAX_SCHEDULED_TASK_COMMAND_CODE_UNITS = 260
MAX_SCHEDULED_TASK_COMPONENT_CODE_UNITS = 255
MAX_SCHEDULED_TASK_RESIDENTS = 128

_TASK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_TASK_URI = re.compile(
    rf"\\ArtifactForge\\{re.escape(MARKER)}-([A-Za-z0-9][A-Za-z0-9._-]{{0,63}})"
)
_DRIVE = re.compile(r"[A-Z]:")
_INVALID_WINDOWS_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*%')
_RESERVED_WINDOWS_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
_FORBIDDEN_EXECUTABLES = frozenset(
    {
        "bash.exe",
        "bitsadmin.exe",
        "certutil.exe",
        "cmd.exe",
        "cscript.exe",
        "curl.exe",
        "forfiles.exe",
        "installutil.exe",
        "msbuild.exe",
        "mshta.exe",
        "msiexec.exe",
        "node.exe",
        "pcalua.exe",
        "perl.exe",
        "powershell.exe",
        "pwsh.exe",
        "python.exe",
        "python3.exe",
        "reg.exe",
        "regasm.exe",
        "regsvcs.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "ruby.exe",
        "schtasks.exe",
        "wscript.exe",
        "wsl.exe",
    }
)


@dataclass(frozen=True)
class ScheduledTaskXmlValue:
    """Typed observation from the ElementTree implementation."""

    namespace: str
    version: str
    task_name: str
    uri: str
    description: str
    command: str
    enabled: bool
    allow_start_on_demand: bool
    hidden: bool
    trigger_count: int
    action_count: int


@dataclass(frozen=True)
class ScheduledTaskXmlWireValue:
    """Canonical wire observation produced without an XML parser."""

    encoding: str
    line_count: int
    marker_count: int
    version: str
    task_name: str
    uri: str
    description: str
    command: str
    enabled: bool
    allow_start_on_demand: bool
    hidden: bool
    trigger_count: int
    action_count: int


def _task_name(value: object, *, where: str = "scheduled task name") -> str:
    if (
        type(value) is not str
        or _TASK_NAME.fullmatch(value) is None
        or value.endswith(".")
        or value.split(".", 1)[0].upper() in _RESERVED_WINDOWS_STEMS
    ):
        raise ValueError(
            f"{where} must be 1..{MAX_SCHEDULED_TASK_NAME_BYTES} printable ASCII "
            "letters, digits, dot, underscore, or hyphen forming a valid Windows name"
        )
    return value


def _task_version(value: object) -> str:
    if type(value) is not str or value not in TASK_VERSIONS:
        raise ValueError("scheduled task version must be exact text '1.2' or '1.3'")
    return value


def _windows_pe_path(value: object, *, where: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{where} must be a non-empty Windows PE path")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must be strict ASCII") from exc
    if len(encoded) > MAX_SCHEDULED_TASK_COMMAND_CODE_UNITS:
        raise ValueError(
            f"{where} exceeds {MAX_SCHEDULED_TASK_COMMAND_CODE_UNITS} UTF-16 code units"
        )
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError(f"{where} contains a control character")

    drive, tail = ntpath.splitdrive(value)
    if (
        _DRIVE.fullmatch(drive) is None
        or not tail.startswith("\\")
        or tail.startswith("\\\\")
        or ntpath.normpath(value) != value
    ):
        raise ValueError(f"{where} must be a normalized absolute drive-letter Windows path")
    components = tail[1:].split("\\")
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ValueError(f"{where} must not contain empty or dot path components")
    for component in components:
        if (
            len(component) > MAX_SCHEDULED_TASK_COMPONENT_CODE_UNITS
            or component[-1] in {" ", "."}
            or any(character in _INVALID_WINDOWS_COMPONENT_CHARACTERS for character in component)
            or component.split(".", 1)[0].upper() in _RESERVED_WINDOWS_STEMS
        ):
            raise ValueError(f"{where} contains an invalid Windows path component")
    basename = components[-1].casefold()
    if not basename.endswith(".exe"):
        raise ValueError(f"{where} must name one .exe resident")
    if basename in _FORBIDDEN_EXECUTABLES:
        raise ValueError(f"{where} names a forbidden interpreter or command utility")
    return value


def _resident_allowlist(values) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray, dict)):
        raise ValueError("resident_pe_paths must be an iterable of Windows PE paths")
    try:
        materialised = tuple(islice(iter(values), MAX_SCHEDULED_TASK_RESIDENTS + 1))
    except TypeError as exc:
        raise ValueError("resident_pe_paths must be iterable") from exc
    if not 1 <= len(materialised) <= MAX_SCHEDULED_TASK_RESIDENTS:
        raise ValueError(
            f"resident_pe_paths requires 1..{MAX_SCHEDULED_TASK_RESIDENTS} paths"
        )
    paths = tuple(
        _windows_pe_path(value, where=f"resident_pe_paths item {index}")
        for index, value in enumerate(materialised)
    )
    if len({path.casefold() for path in paths}) != len(paths):
        raise ValueError("resident_pe_paths cannot contain case-insensitive duplicates")
    return paths


def _is_resident_path(command: str, residents: tuple[str, ...]) -> bool:
    """Compare a complete Windows path with Windows case semantics."""
    folded_command = command.casefold()
    return any(folded_command == resident.casefold() for resident in residents)


def _xml_text(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _qualified(name: str) -> str:
    return f"{{{TASK_NAMESPACE}}}{name}"


def _no_attributes(element: ElementTree.Element, *, where: str) -> None:
    if element.attrib:
        raise ValueError(f"{where} must not carry XML attributes")


def _container_children(
    element: ElementTree.Element,
    expected: tuple[str, ...],
    *,
    where: str,
    root_version_attribute: bool = False,
) -> tuple[ElementTree.Element, ...]:
    if not root_version_attribute:
        _no_attributes(element, where=where)
    if element.text and element.text.strip():
        raise ValueError(f"{where} must not contain mixed text")
    children = tuple(element)
    if tuple(child.tag for child in children) != tuple(_qualified(name) for name in expected):
        raise ValueError(f"{where} has elements outside the closed scheduled-task profile")
    if any(child.tail and child.tail.strip() for child in children):
        raise ValueError(f"{where} must not contain mixed child tails")
    return children


def _leaf_text(element: ElementTree.Element, *, where: str) -> str:
    _no_attributes(element, where=where)
    if len(element):
        raise ValueError(f"{where} must contain text only")
    if type(element.text) is not str or not element.text:
        raise ValueError(f"{where} must contain non-empty text")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in element.text):
        raise ValueError(f"{where} contains a control character")
    return element.text


def _false_text(element: ElementTree.Element, *, where: str) -> bool:
    if _leaf_text(element, where=where) != "false":
        raise ValueError(f"{where} must be exact lowercase false")
    return False


def parse_scheduled_task_xml(data: bytes) -> ScheduledTaskXmlValue:
    """Parse the closed task profile with the standard-library XML implementation.

    This view intentionally does not own serialization details such as BOM and CRLF.  The
    separately implemented wire reader owns those facts, and
    :func:`validate_scheduled_task_xml` requires the two observations to agree.
    """
    if type(data) is not bytes:
        raise ValueError("scheduled task XML must be immutable bytes")
    if not 1 <= len(data) <= MAX_SCHEDULED_TASK_XML_BYTES:
        raise ValueError(
            f"scheduled task XML must contain 1..{MAX_SCHEDULED_TASK_XML_BYTES} bytes"
        )
    for token in (b"<!DOCTYPE", b"<!ENTITY"):
        if (
            token in data
            or b"".join(bytes((byte, 0)) for byte in token) in data
            or b"".join(bytes((0, byte)) for byte in token) in data
        ):
            raise ValueError("scheduled task XML must not contain declarations or entities")
    try:
        parser = ElementTree.XMLParser(
            target=ElementTree.TreeBuilder(insert_comments=True, insert_pis=True)
        )
        root = ElementTree.fromstring(data, parser=parser)
    except (ElementTree.ParseError, UnicodeError) as exc:
        raise ValueError(f"scheduled task XML is not well-formed: {exc}") from exc

    if root.tag != _qualified("Task") or set(root.attrib) != {"version"}:
        raise ValueError("scheduled task XML requires the exact Microsoft Task root")
    version = _task_version(root.attrib["version"])
    registration, settings, actions = _container_children(
        root,
        ("RegistrationInfo", "Settings", "Actions"),
        where="Task",
        root_version_attribute=True,
    )

    uri_element, description_element = _container_children(
        registration,
        ("URI", "Description"),
        where="RegistrationInfo",
    )
    uri = _leaf_text(uri_element, where="RegistrationInfo/URI")
    uri_match = _TASK_URI.fullmatch(uri)
    if uri_match is None:
        raise ValueError("RegistrationInfo/URI is outside the marked task-store profile")
    task_name = _task_name(uri_match.group(1), where="RegistrationInfo/URI task name")
    description = _leaf_text(description_element, where="RegistrationInfo/Description")
    if description != TASK_DESCRIPTION:
        raise ValueError("RegistrationInfo/Description lacks the exact synthetic notice")

    allow_start, enabled, hidden = _container_children(
        settings,
        ("AllowStartOnDemand", "Enabled", "Hidden"),
        where="Settings",
    )
    allow_start_on_demand = _false_text(
        allow_start, where="Settings/AllowStartOnDemand"
    )
    enabled_value = _false_text(enabled, where="Settings/Enabled")
    hidden_value = _false_text(hidden, where="Settings/Hidden")

    (exec_element,) = _container_children(actions, ("Exec",), where="Actions")
    (command_element,) = _container_children(exec_element, ("Command",), where="Actions/Exec")
    command = _windows_pe_path(
        _leaf_text(command_element, where="Actions/Exec/Command"),
        where="Actions/Exec/Command",
    )
    return ScheduledTaskXmlValue(
        namespace=TASK_NAMESPACE,
        version=version,
        task_name=task_name,
        uri=uri,
        description=description,
        command=command,
        enabled=enabled_value,
        allow_start_on_demand=allow_start_on_demand,
        hidden=hidden_value,
        trigger_count=0,
        action_count=1,
    )


def _unescape_wire_text(value: str, *, where: str) -> str:
    if "<" in value or ">" in value:
        raise ValueError(f"{where} contains raw XML markup")
    output: list[str] = []
    cursor = 0
    while cursor < len(value):
        if value[cursor] != "&":
            output.append(value[cursor])
            cursor += 1
            continue
        if not value.startswith("&amp;", cursor):
            raise ValueError(f"{where} uses non-canonical XML escaping")
        output.append("&")
        cursor += 5
    return "".join(output)


def read_scheduled_task_xml_wire(data: bytes) -> ScheduledTaskXmlWireValue:
    """Read the exact UTF-16LE+BOM/CRLF serialization without using an XML parser."""
    if type(data) is not bytes:
        raise ValueError("scheduled task XML wire value must be immutable bytes")
    if not 1 <= len(data) <= MAX_SCHEDULED_TASK_XML_BYTES:
        raise ValueError(
            f"scheduled task XML wire value must contain 1..{MAX_SCHEDULED_TASK_XML_BYTES} bytes"
        )
    if not data.startswith(b"\xff\xfe"):
        raise ValueError("scheduled task XML wire value requires a UTF-16LE BOM")
    body = data[2:]
    if not body or len(body) % 2:
        raise ValueError("scheduled task XML UTF-16LE body must contain complete code units")
    if any(body[high_index] for high_index in range(1, len(body), 2)):
        raise ValueError("scheduled task XML wire profile is printable ASCII in UTF-16LE")
    try:
        text = body.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("scheduled task XML wire value is not strict UTF-16LE") from exc
    if not text.endswith("\r\n"):
        raise ValueError("scheduled task XML wire value must end with CRLF")
    without_crlf = text.replace("\r\n", "")
    if "\r" in without_crlf or "\n" in without_crlf:
        raise ValueError("scheduled task XML wire value must use CRLF exclusively")
    if any(
        ord(character) < 0x20 or ord(character) > 0x7E
        for character in without_crlf
    ):
        raise ValueError("scheduled task XML wire value must contain printable ASCII")

    lines = text.split("\r\n")
    if len(lines) != 18 or lines[-1] != "":
        raise ValueError("scheduled task XML wire value has a non-canonical line count")
    if lines[0] != '<?xml version="1.0" encoding="UTF-16"?>':
        raise ValueError("scheduled task XML wire value has a non-canonical declaration")
    root_match = re.fullmatch(
        rf'<Task version="(1\.[23])" xmlns="{re.escape(TASK_NAMESPACE)}">',
        lines[1],
    )
    if root_match is None:
        raise ValueError("scheduled task XML wire value has a non-canonical Task root")
    exact_lines = {
        2: "  <RegistrationInfo>",
        5: "  </RegistrationInfo>",
        6: "  <Settings>",
        7: "    <AllowStartOnDemand>false</AllowStartOnDemand>",
        8: "    <Enabled>false</Enabled>",
        9: "    <Hidden>false</Hidden>",
        10: "  </Settings>",
        11: "  <Actions>",
        12: "    <Exec>",
        14: "    </Exec>",
        15: "  </Actions>",
        16: "</Task>",
    }
    if any(lines[index] != expected for index, expected in exact_lines.items()):
        raise ValueError("scheduled task XML wire value is outside the canonical structure")

    uri_match = re.fullmatch(r"    <URI>([^<>]*)</URI>", lines[3])
    description_match = re.fullmatch(
        r"    <Description>([^<>]*)</Description>", lines[4]
    )
    command_match = re.fullmatch(r"      <Command>([^<>]*)</Command>", lines[13])
    if uri_match is None or description_match is None or command_match is None:
        raise ValueError("scheduled task XML wire value has a malformed text leaf")
    uri = _unescape_wire_text(uri_match.group(1), where="wire URI")
    description = _unescape_wire_text(
        description_match.group(1), where="wire Description"
    )
    command = _unescape_wire_text(command_match.group(1), where="wire Command")
    marked_uri = _TASK_URI.fullmatch(uri)
    if marked_uri is None:
        raise ValueError("scheduled task XML wire URI is outside the marked profile")
    task_name = _task_name(marked_uri.group(1), where="wire URI task name")
    if description != TASK_DESCRIPTION:
        raise ValueError("scheduled task XML wire Description lacks the exact notice")
    command = _windows_pe_path(command, where="wire Command")
    return ScheduledTaskXmlWireValue(
        encoding="UTF-16LE+BOM",
        line_count=17,
        marker_count=text.count(MARKER),
        version=_task_version(root_match.group(1)),
        task_name=task_name,
        uri=uri,
        description=description,
        command=command,
        enabled=False,
        allow_start_on_demand=False,
        hidden=False,
        trigger_count=0,
        action_count=1,
    )


def validate_scheduled_task_xml(
    data: bytes, *, resident_pe_paths
) -> ScheduledTaskXmlValue:
    """Require XML/wire consensus and an exact resident command-path join."""
    residents = _resident_allowlist(resident_pe_paths)
    parsed = parse_scheduled_task_xml(data)
    wire = read_scheduled_task_xml_wire(data)
    for name in (
        "version",
        "task_name",
        "uri",
        "description",
        "command",
        "enabled",
        "allow_start_on_demand",
        "hidden",
        "trigger_count",
        "action_count",
    ):
        parsed_value = getattr(parsed, name)
        wire_value = getattr(wire, name)
        if type(parsed_value) is not type(wire_value) or parsed_value != wire_value:
            raise ValueError(f"scheduled task XML readers disagree on {name}")
    if not _is_resident_path(parsed.command, residents):
        raise ValueError("scheduled task command is not an exact resident PE path")
    return parsed


def build_scheduled_task_xml(
    task_name: str,
    command: str,
    *,
    resident_pe_paths,
    version: str = "1.2",
) -> bytes:
    """Emit one deterministic, disabled and trigger-free Task Scheduler XML document."""
    task_name = _task_name(task_name)
    version = _task_version(version)
    command = _windows_pe_path(command, where="scheduled task command")
    residents = _resident_allowlist(resident_pe_paths)
    if not _is_resident_path(command, residents):
        raise ValueError("scheduled task command is not an exact resident PE path")
    uri = f"\\ArtifactForge\\{MARKER}-{task_name}"
    text = "\r\n".join(
        (
            '<?xml version="1.0" encoding="UTF-16"?>',
            f'<Task version="{version}" xmlns="{TASK_NAMESPACE}">',
            "  <RegistrationInfo>",
            f"    <URI>{_xml_text(uri)}</URI>",
            f"    <Description>{_xml_text(TASK_DESCRIPTION)}</Description>",
            "  </RegistrationInfo>",
            "  <Settings>",
            "    <AllowStartOnDemand>false</AllowStartOnDemand>",
            "    <Enabled>false</Enabled>",
            "    <Hidden>false</Hidden>",
            "  </Settings>",
            "  <Actions>",
            "    <Exec>",
            f"      <Command>{_xml_text(command)}</Command>",
            "    </Exec>",
            "  </Actions>",
            "</Task>",
            "",
        )
    )
    data = b"\xff\xfe" + text.encode("utf-16-le", errors="strict")
    validate_scheduled_task_xml(data, resident_pe_paths=residents)
    return data


__all__ = [
    "MAX_SCHEDULED_TASK_COMMAND_CODE_UNITS",
    "MAX_SCHEDULED_TASK_COMPONENT_CODE_UNITS",
    "MAX_SCHEDULED_TASK_NAME_BYTES",
    "MAX_SCHEDULED_TASK_RESIDENTS",
    "MAX_SCHEDULED_TASK_XML_BYTES",
    "ScheduledTaskXmlValue",
    "ScheduledTaskXmlWireValue",
    "SCHEDULED_TASK_XML_PROFILE",
    "TASK_DESCRIPTION",
    "TASK_NAMESPACE",
    "TASK_VERSIONS",
    "build_scheduled_task_xml",
    "parse_scheduled_task_xml",
    "read_scheduled_task_xml_wire",
    "validate_scheduled_task_xml",
]
