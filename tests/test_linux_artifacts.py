# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Linux loose artifacts are deterministic, inert data with independent bounded readers."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import pytest

from artifactforge.artifacts.linux import build_bash_history, build_desktop_entry
from artifactforge.gates.oracles.bash_history_subset import (
    BashHistoryEntry,
    BashHistoryLimits,
    BashHistorySubsetError,
    load_bash_history,
    loads_bash_history,
)
from artifactforge.gates.oracles.desktop_entry_subset import (
    DesktopEntry,
    DesktopEntryLimits,
    DesktopEntrySubsetError,
    load_desktop_entry,
    loads_desktop_entry,
)


RESIDENTS = (
    "/home/alex/.local/bin/cache-helper",
    "/home/alex/.local/bin/sync-helper",
)
DESKTOP_BYTES = (
    b"[Desktop Entry]\n"
    b"Version=1.5\n"
    b"Type=Application\n"
    b"Name=ArtifactForge Sync Helper\n"
    b"Comment=Synthetic autostart evidence; inert resident\n"
    b"Exec=/home/alex/.local/bin/sync-helper\n"
    b"Terminal=false\n"
    b"Hidden=false\n"
    b"DBusActivatable=false\n"
    b"X-ArtifactForge-Synthetic=ARTIFACTFORGE\n"
)
HISTORY_ROWS = (
    (1_705_294_800, RESIDENTS[0]),
    (1_705_294_860, ": 'ARTIFACTFORGE-SYNTHETIC-HISTORY-NO-OP'"),
    (1_705_294_920, RESIDENTS[1]),
)
HISTORY_BYTES = (
    b"#1705294800\n"
    b"/home/alex/.local/bin/cache-helper\n"
    b"#1705294860\n"
    b": 'ARTIFACTFORGE-SYNTHETIC-HISTORY-NO-OP'\n"
    b"#1705294920\n"
    b"/home/alex/.local/bin/sync-helper\n"
)


def _desktop_bytes(**replacements: str) -> bytes:
    values = {
        "Version": "1.5",
        "Type": "Application",
        "Name": "ArtifactForge Sync Helper",
        "Comment": "Synthetic autostart evidence; inert resident",
        "Exec": RESIDENTS[1],
        "Terminal": "false",
        "Hidden": "false",
        "DBusActivatable": "false",
        "X-ArtifactForge-Synthetic": "ARTIFACTFORGE",
    }
    values.update(replacements)
    return (
        "[Desktop Entry]\n"
        + "\n".join(f"{key}={value}" for key, value in values.items())
        + "\n"
    ).encode()


def test_desktop_writer_is_byte_exact_deterministic_and_raw_reader_is_type_exact(tmp_path):
    first = build_desktop_entry(
        "ArtifactForge Sync Helper",
        "Synthetic autostart evidence; inert resident",
        RESIDENTS[1],
    )
    second = build_desktop_entry(
        "ArtifactForge Sync Helper",
        "Synthetic autostart evidence; inert resident",
        RESIDENTS[1],
    )
    assert first == second == DESKTOP_BYTES

    expected = DesktopEntry(
        version="1.5",
        entry_type="Application",
        name="ArtifactForge Sync Helper",
        comment="Synthetic autostart evidence; inert resident",
        exec_path=RESIDENTS[1],
        terminal=False,
        hidden=False,
        dbus_activatable=False,
        synthetic_marker="ARTIFACTFORGE",
    )
    assert loads_desktop_entry(first) == expected
    assert loads_desktop_entry(bytearray(first)) == expected
    assert loads_desktop_entry(memoryview(first)) == expected
    path = tmp_path / "sync.desktop"
    path.write_bytes(first)
    assert load_desktop_entry(path) == expected
    assert type(expected.terminal) is bool
    assert type(expected.hidden) is bool
    assert type(expected.dbus_activatable) is bool


def test_desktop_utf8_values_and_value_punctuation_round_trip_without_becoming_syntax():
    data = build_desktop_entry("Café]", "Synthetic key=value]", RESIDENTS[0])
    parsed = loads_desktop_entry(data)
    assert parsed.name == "Café]"
    assert parsed.comment == "Synthetic key=value]"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"name": ""}, "non-empty"),
        ({"name": " surrounding "}, "surrounding"),
        ({"comment": "line\nfeed"}, "control"),
        ({"comment": "escaped\\svalue"}, "escape"),
        ({"exec_path": "relative/helper"}, "normalized absolute"),
        ({"exec_path": "/home/alex/helper --flag"}, "normalized absolute"),
        ({"exec_path": "/home/alex/helper%u"}, "normalized absolute"),
        ({"exec_path": "/home/alex/helper;touch"}, "normalized absolute"),
        ({"exec_path": "/home/alex/../helper"}, "normalized absolute"),
        ({"exec_path": "/home//alex/helper"}, "normalized absolute"),
    ],
)
def test_desktop_writer_rejects_values_outside_the_no_shell_profile(kwargs, match):
    values = {
        "name": "Name",
        "comment": "Synthetic inert entry",
        "exec_path": RESIDENTS[0],
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=match):
        build_desktop_entry(**values)


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (DESKTOP_BYTES.replace(b"Version=1.5\n", b""), "missing keys"),
        (DESKTOP_BYTES + b"Name=Again\n", "duplicated"),
        (DESKTOP_BYTES + b"[Desktop Action Run]\n", "additional group"),
        (DESKTOP_BYTES.replace(b"Name=", b"Name[fr]="), "localized"),
        (DESKTOP_BYTES + b"Actions=Run;\n", "unsupported keys"),
        (_desktop_bytes(Version="1.4"), "Version"),
        (_desktop_bytes(Type="Link"), "Type"),
        (_desktop_bytes(Terminal="False"), "lowercase false"),
        (_desktop_bytes(Hidden="true"), "lowercase false"),
        (_desktop_bytes(DBusActivatable="true"), "lowercase false"),
        (_desktop_bytes(Exec=f"{RESIDENTS[0]} --flag"), "without arguments"),
        (_desktop_bytes(Exec=f"{RESIDENTS[0]} %u"), "field codes"),
        (_desktop_bytes(Exec=f"{RESIDENTS[0]};id"), "shell syntax"),
        (_desktop_bytes(**{"X-ArtifactForge-Synthetic": "ALTERED"}), "marker"),
        (DESKTOP_BYTES.replace(b"\n", b"\r\n"), "LF rather than"),
        (DESKTOP_BYTES[:-1], "end with LF"),
        (b"\xef\xbb\xbf" + DESKTOP_BYTES, "BOM"),
        (DESKTOP_BYTES.replace(b"Name=A", b"Name=\xffA"), "valid UTF-8"),
        (DESKTOP_BYTES.replace(b"Comment=Synthetic", b"Comment= Synthetic"), "whitespace"),
    ],
)
def test_desktop_raw_reader_rejects_malformed_duplicate_or_active_shapes(raw, match):
    with pytest.raises(DesktopEntrySubsetError, match=match):
        loads_desktop_entry(raw)


def test_desktop_raw_reader_bounds_before_parsing():
    with pytest.raises(DesktopEntrySubsetError, match="8-byte"):
        loads_desktop_entry(DESKTOP_BYTES, limits=DesktopEntryLimits(max_bytes=8))
    with pytest.raises(DesktopEntrySubsetError, match="line limit"):
        loads_desktop_entry(DESKTOP_BYTES, limits=DesktopEntryLimits(max_lines=2))
    with pytest.raises(DesktopEntrySubsetError, match="value limit"):
        loads_desktop_entry(DESKTOP_BYTES, limits=DesktopEntryLimits(max_value_bytes=8))


def test_bash_history_writer_is_byte_exact_deterministic_and_reader_is_type_exact(tmp_path):
    first = build_bash_history(HISTORY_ROWS, resident_paths=RESIDENTS)
    second = build_bash_history(iter(HISTORY_ROWS), resident_paths=iter(RESIDENTS))
    assert first == second == HISTORY_BYTES
    expected = tuple(BashHistoryEntry(*row) for row in HISTORY_ROWS)
    assert loads_bash_history(first, resident_paths=RESIDENTS) == expected
    assert loads_bash_history(bytearray(first), resident_paths=RESIDENTS) == expected
    assert loads_bash_history(memoryview(first), resident_paths=RESIDENTS) == expected
    path = tmp_path / ".bash_history"
    path.write_bytes(first)
    assert load_bash_history(path, resident_paths=RESIDENTS) == expected
    assert all(type(entry.epoch) is int for entry in expected)


@pytest.mark.parametrize(
    ("entries", "residents", "match"),
    [
        ([], RESIDENTS, "1..1024"),
        ([(0, RESIDENTS[0])], RESIDENTS, "positive int64"),
        ([(True, RESIDENTS[0])], RESIDENTS, "positive int64"),
        ([(2, RESIDENTS[0]), (1, RESIDENTS[1])], RESIDENTS, "strictly increasing"),
        ([(1, "/home/alex/.local/bin/not-resident")], RESIDENTS, "exact resident"),
        ([(1, f"{RESIDENTS[0]} --flag")], RESIDENTS, "normalized absolute"),
        ([(1, "eval")], RESIDENTS, "normalized absolute"),
        ([(1, ": 'ARTIFACTFORGE-SYNTHETIC-X'; rm")], RESIDENTS, "normalized absolute"),
        ([(1, ": 'ARTIFACTFORGE-SYNTHETIC-'\n")], RESIDENTS, "normalized absolute"),
        ([(1, RESIDENTS[0])], ("/usr/bin/curl",), "forbidden command"),
        ([(1, RESIDENTS[0])], (RESIDENTS[0], RESIDENTS[0]), "duplicates"),
        ([(1, RESIDENTS[0])], (), "1..128"),
    ],
)
def test_bash_writer_rejects_unsafe_ambiguous_and_unbounded_inputs(entries, residents, match):
    with pytest.raises(ValueError, match=match):
        build_bash_history(entries, resident_paths=residents)


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (b"", "empty"),
        (b"#1705294800\n", "orphan"),
        (b"/home/alex/.local/bin/cache-helper\n#1705294800\n", "#epoch"),
        (b"#0\n/home/alex/.local/bin/cache-helper\n", "#epoch"),
        (b"#01\n/home/alex/.local/bin/cache-helper\n", "#epoch"),
        (
            b"#1705294800\n/home/alex/.local/bin/cache-helper\n"
            b"#1705294800\n/home/alex/.local/bin/sync-helper\n",
            "strictly increasing",
        ),
        (HISTORY_BYTES.replace(b"\n", b"\r\n"), "LF rather than"),
        (HISTORY_BYTES[:-1], "end with LF"),
        (HISTORY_BYTES.replace(b"cache-helper", b"cache-\xffhelper"), "ASCII"),
        (HISTORY_BYTES.replace(b"cache-helper\n", b"cache-helper\n\n"), "blank"),
        (
            b"#1705294800\n/home/alex/.local/bin/cache-helper;id\n",
            "without shell syntax",
        ),
        (b"#1705294800\n/home/alex/.local/bin/cache-helper >x\n", "without shell syntax"),
        (b"#1705294800\n$(id)\n", "without shell syntax"),
        (b"#1705294800\neval\n", "without shell syntax"),
        (b"#1705294800\n/usr/bin/curl\n", "forbidden command"),
        (b"#1705294800\n/home/alex/.local/bin/other\n", "exact resident"),
        (b"#1705294800\n: 'ARTIFACTFORGE-SYNTHETIC-'\n", "without shell syntax"),
    ],
)
def test_bash_raw_reader_rejects_orphans_multiline_operators_and_forbidden_verbs(raw, match):
    residents = RESIDENTS + (("/usr/bin/curl",) if b"/usr/bin/curl" in raw else ())
    with pytest.raises(BashHistorySubsetError, match=match):
        loads_bash_history(raw, resident_paths=residents)


def test_bash_raw_reader_bounds_before_expansion():
    with pytest.raises(BashHistorySubsetError, match="8-byte"):
        loads_bash_history(
            HISTORY_BYTES,
            resident_paths=RESIDENTS,
            limits=BashHistoryLimits(max_bytes=8),
        )
    with pytest.raises(BashHistorySubsetError, match="1..1 records"):
        loads_bash_history(
            HISTORY_BYTES,
            resident_paths=RESIDENTS,
            limits=BashHistoryLimits(max_records=1),
        )
    with pytest.raises(BashHistorySubsetError, match="line limit"):
        loads_bash_history(
            HISTORY_BYTES,
            resident_paths=RESIDENTS,
            limits=BashHistoryLimits(max_line_bytes=8),
        )


def test_raw_readers_do_not_import_writers_or_external_parsers():
    import artifactforge.gates.oracles.bash_history_subset as bash_module
    import artifactforge.gates.oracles.desktop_entry_subset as desktop_module

    for module in (bash_module, desktop_module):
        tree = ast.parse(Path(module.__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not [name for name in imported if name.startswith("artifactforge.artifacts")]
        assert "xdg" not in imported
        assert "dissect" not in imported


def test_pyxdg_consensus_when_the_optional_external_parser_is_installed(tmp_path):
    desktop_module = pytest.importorskip("xdg.DesktopEntry", reason="PyXDG is CI-optional")
    path = tmp_path / "sync.desktop"
    path.write_bytes(DESKTOP_BYTES)
    external = desktop_module.DesktopEntry(str(path))
    internal = loads_desktop_entry(DESKTOP_BYTES)

    # PyXDG's getVersion() coerces to float; the string API preserves the file's typed value.
    assert external.getVersionString() == internal.version
    assert external.getType() == internal.entry_type
    assert external.getName() == internal.name
    assert external.getComment() == internal.comment
    assert external.getExec() == internal.exec_path
    assert external.getTerminal() is internal.terminal
    assert external.getHidden() is internal.hidden
    assert external.get("DBusActivatable", type="boolean") is internal.dbus_activatable
    assert external.get("X-ArtifactForge-Synthetic") == internal.synthetic_marker


def test_dissect_target_consensus_when_the_optional_external_parser_is_installed(tmp_path):
    target_module = pytest.importorskip("dissect.target", reason="dissect.target is CI-optional")
    filesystem_module = pytest.importorskip(
        "dissect.target.filesystem", reason="dissect.target is CI-optional"
    )
    filesystem = filesystem_module.VirtualFilesystem()
    filesystem.map_file_fh("/home/alex/.bash_history", BytesIO(HISTORY_BYTES))
    filesystem.map_file_fh(
        "/etc/passwd",
        BytesIO(b"alex:x:1000:1000:ArtifactForge:/home/alex:/bin/bash\n"),
    )
    filesystem.map_file_fh("/etc/os-release", BytesIO(b"ID=artifactforge\n"))
    filesystem.makedirs("/var")
    filesystem.makedirs("/run")
    target = target_module.Target()
    target.filesystems.add(filesystem)
    target.apply()
    external = list(target.bashhistory())
    internal = loads_bash_history(HISTORY_BYTES, resident_paths=RESIDENTS)

    assert [record.command for record in external] == [record.command for record in internal]
    assert [record.shell for record in external] == ["bash"] * len(internal)
    assert [record.order for record in external] == list(range(len(internal)))
    assert [record.ts for record in external] == [
        datetime.fromtimestamp(record.epoch, timezone.utc) for record in internal
    ]
