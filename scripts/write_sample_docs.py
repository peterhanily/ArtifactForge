# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Write each sample's answer key and README, with real parser output pasted in.

The key is called ARTIFACT_ANSWERS.json rather than GROUND_TRUTH.json on purpose.
EvidenceForge's evaluator checks its evaluation directory and that directory's direct parent
for a file named exactly `GROUND_TRUTH.json`, selecting the first existing candidate before it
validates the schema. An invalid child candidate can therefore shadow a valid parent candidate;
EvidenceForge emits visible warning logs, continues without parsed ground truth, and its
ground-truth-dependent causality components can score lower. Avoiding the reserved filename
costs nothing and prevents the collision.

The parser output is the part that matters. A gallery showing only what the generator says
about its own files is a brochure; these pages quote concrete reader output, and the Linux
page quotes both members of all three declared parser pairs, including the bounded first-party
readers. If a pair ever stops agreeing, regenerating the gallery makes it obvious.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import timezone
from io import BytesIO

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from artifactforge import suite  # noqa: E402
from artifactforge.disclosure import NOTICE  # noqa: E402
from artifactforge.gates.oracles import load_bash_history, load_desktop_entry  # noqa: E402
from artifactforge.inventory import InventoryFile, inventory_regular_files  # noqa: E402

BANNER = {
    "synthetic": True,
    "notice": NOTICE,
    "generator": "ArtifactForge",
}
# Deliberately NOT recorded here: the sqlite3 version. It is environment-dependent, and
# putting it in a generated file makes that file environment-dependent too. That is how the
# answer key briefly stopped being byte-identical across platforms, defeating the very diff
# that had just been narrowed to exclude the databases. Provenance belongs in prose that a
# person maintains; `samples/README.md` carries it, and fidelity-scorecard.json records the
# version the gates ran under.


def _markdown_table(headers, rows) -> str:
    """Render compact GitHub Markdown while escaping data-owned table separators."""

    def cell(value: object) -> str:
        return str(value).replace("|", r"\|").replace("\n", "<br>")

    normalized = [tuple(cell(value) for value in row) for row in rows]
    if any(len(row) != len(headers) for row in normalized):
        raise ValueError("sample Markdown table row has the wrong number of cells")
    return "\n".join(
        (
            "| " + " | ".join(cell(header) for header in headers) + " |",
            "| " + " | ".join("---" for _header in headers) + " |",
            *("| " + " | ".join(row) + " |" for row in normalized),
        )
    )


def _named(files: tuple[InventoryFile, ...], name: str) -> InventoryFile:
    matches = [file for file in files if file.name == name]
    if len(matches) != 1:
        raise ValueError(
            f"sample artifact basename {name!r} resolves to "
            f"{[file.relative_path for file in matches]}"
        )
    return matches[0]


def _one_with_suffix(files: tuple[InventoryFile, ...], suffix: str, *, where: str) -> InventoryFile:
    matches = [file for file in files if file.relative_path.casefold().endswith(suffix.casefold())]
    if len(matches) != 1:
        raise ValueError(
            f"Windows gallery requires exactly one {where}; found "
            f"{[file.relative_path for file in matches]}"
        )
    return matches[0]


def _windows_prefetch_view(file: InventoryFile):
    """Read one copied v30 Prefetch through both parsers and the strict byte profile."""
    from artifactforge.gates.oracles.prefetch_profile import (
        dissect_prefetch_v30_view,
        parse_mam_prefetch_v30_variant1,
        pyscca_prefetch_v30_view,
        require_prefetch_v30_consensus,
        validate_artifactforge_prefetch_v30_profile,
    )

    if file.data is None:
        raise ValueError(f"{file.relative_path}: Prefetch inventory did not capture bytes")
    strict = parse_mam_prefetch_v30_variant1(file.data)
    consensus = require_prefetch_v30_consensus(
        {
            "pyscca": pyscca_prefetch_v30_view(file.data),
            "dissect.target-prefetch": dissect_prefetch_v30_view(file.data),
        }
    )
    profile = validate_artifactforge_prefetch_v30_profile(strict, consensus)
    expected_name = f"{strict.executable_name}-{strict.prefetch_hash:08X}.pf"
    if file.name != expected_name:
        raise ValueError(
            f"{file.relative_path}: Prefetch filename does not bind its Vista path hash"
        )
    return strict, profile


def _windows_prefetch_guest_paths(
    files: tuple[InventoryFile, ...], binaries: dict[str, bytes]
) -> dict[str, str]:
    """Map executed resident basenames to profile guest paths through Prefetch bytes."""
    paths: dict[str, str] = {}
    for file in files:
        if not file.name.casefold().endswith(".pf"):
            continue
        parsed, _profile = _windows_prefetch_view(file)
        candidate = parsed.executable_name.casefold()
        if candidate not in binaries:
            continue
        recorded = parsed.metric_filenames[0]
        volume = parsed.volume_device_path
        if not recorded.casefold().startswith((volume + "\\").casefold()):
            raise ValueError("Windows gallery Prefetch path is outside its sole volume")
        # The loose Windows profile declares the sole modeled volume as C:. Its opaque token
        # is bound to the independently parsed creation time and serial number.
        guest_path = "C:" + recorded[len(volume) :]
        if guest_path.rsplit("\\", 1)[-1].casefold() != candidate:
            raise ValueError("Windows gallery Prefetch path and executable name disagree")
        if candidate in paths:
            raise ValueError("Windows gallery Prefetch resident path mapping is ambiguous")
        paths[candidate] = guest_path
    return paths


def _windows_reference_surfaces(
    files: tuple[InventoryFile, ...],
    binaries: dict[str, bytes],
    *,
    persisted_path: str,
    persistence_paths: tuple[str, ...],
    browser_target_paths: tuple[str, ...],
) -> dict:
    """Read Task/LNK bytes through independent implementations and resolve their PEs.

    This helper deliberately receives only the copied gallery inventory and paths already
    re-derived from the Run hive and Chromium database. Exact resident guest paths are joined
    independently through the modeled Prefetch device path and fixed system-volume mapping
    before either reference is parsed. It never reads a suite key, private scene join or
    generator object.
    """
    from artifactforge.artifacts.shell_link import parse_shell_link
    from artifactforge.artifacts.windows_task import (
        parse_scheduled_task_xml,
        read_scheduled_task_xml_wire,
        validate_scheduled_task_xml,
    )
    from artifactforge.gates import validity
    from artifactforge.gates.oracles.shell_link_profile import (
        liblnk_shell_link_view,
        lnkparse3_shell_link_view,
        require_shell_link_consensus,
        validate_artifactforge_shell_link_profile,
    )

    def data_of(file: InventoryFile) -> bytes:
        if file.data is None:
            raise ValueError(f"{file.relative_path}: gallery inventory did not capture bytes")
        return file.data

    resident_guest_paths = _windows_prefetch_guest_paths(files, binaries)

    def resident_at(target_path: str, *, where: str) -> tuple[str, bytes]:
        basename = target_path.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        target = binaries.get(basename)
        if target is None:
            raise ValueError(f"{where} target {target_path!r} does not resolve to a resident PE")
        expected_path = resident_guest_paths.get(basename)
        if expected_path is None or target_path.casefold() != expected_path.casefold():
            raise ValueError(
                f"{where} target {target_path!r} does not match the independent Prefetch path"
            )
        return basename, target

    task_file = _one_with_suffix(files, ".task.xml", where="Scheduled Task XML")
    task_data = data_of(task_file)
    task_elementtree = parse_scheduled_task_xml(task_data)
    task_wire = read_scheduled_task_xml_wire(task_data)
    task_target_name, task_target_data = resident_at(
        task_elementtree.command, where="Scheduled Task"
    )
    task_validated = validate_scheduled_task_xml(
        task_data,
        resident_pe_paths=(task_elementtree.command,),
    )
    task_dissect = validity._read_dissect_task_xml(task_data)
    if task_validated != task_elementtree:
        raise ValueError("Windows gallery Task validation changed the ElementTree observation")
    task_shared = (
        task_elementtree.version,
        task_elementtree.uri,
        task_elementtree.description,
        task_elementtree.command,
        task_elementtree.enabled,
        task_elementtree.allow_start_on_demand,
        task_elementtree.hidden,
        task_elementtree.trigger_count,
        task_elementtree.action_count,
    )
    if task_shared != (
        task_wire.version,
        task_wire.uri,
        task_wire.description,
        task_wire.command,
        task_wire.enabled,
        task_wire.allow_start_on_demand,
        task_wire.hidden,
        task_wire.trigger_count,
        task_wire.action_count,
    ):
        raise ValueError("Windows gallery Task ElementTree and wire observations disagree")
    if task_shared != (
        task_dissect.version,
        task_dissect.uri,
        task_dissect.description,
        task_dissect.command,
        task_dissect.enabled,
        task_dissect.allow_start_on_demand,
        task_dissect.hidden,
        task_dissect.trigger_count,
        task_dissect.action_count,
    ):
        raise ValueError("Windows gallery Task readers and Dissect consumer disagree")
    if (
        task_elementtree.enabled,
        task_elementtree.allow_start_on_demand,
        task_elementtree.hidden,
        task_elementtree.trigger_count,
        task_elementtree.action_count,
        task_dissect.principal_count,
        task_dissect.arguments,
        task_dissect.working_directory,
        task_dissect.action_context,
    ) != (False, False, False, 0, 1, 0, None, None, None):
        raise ValueError("Windows gallery Task is outside the disabled trigger-free profile")

    shell_file = _one_with_suffix(files, ".lnk", where="Shell Link")
    shell_data = data_of(shell_file)
    shell_raw = parse_shell_link(shell_data)
    shell_liblnk = liblnk_shell_link_view(shell_data)
    shell_lnkparse3 = lnkparse3_shell_link_view(shell_data)
    shell_consensus = require_shell_link_consensus(
        {"liblnk": shell_liblnk, "LnkParse3": shell_lnkparse3}
    )
    shell_profile = validate_artifactforge_shell_link_profile(shell_consensus)
    if (
        shell_consensus.target_path,
        shell_consensus.description,
        shell_consensus.target_size,
        shell_consensus.creation_filetime,
        shell_consensus.access_filetime,
        shell_consensus.write_filetime,
        shell_consensus.volume_serial,
        shell_consensus.volume_label,
    ) != (
        shell_raw.target_path,
        shell_raw.name_string,
        shell_raw.target_size,
        shell_raw.creation_filetime,
        shell_raw.access_filetime,
        shell_raw.write_filetime,
        shell_raw.volume_serial,
        shell_raw.volume_label,
    ):
        raise ValueError("Windows gallery Shell Link external/raw observations disagree")
    shell_target_name, shell_target_data = resident_at(shell_raw.target_path, where="Shell Link")
    if shell_raw.target_size != len(shell_target_data):
        raise ValueError("Windows gallery Shell Link size does not match resident PE bytes")

    excluded_paths = {path.casefold() for path in (*persistence_paths, *browser_target_paths)}
    excluded_names = {
        path.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        for path in (*persistence_paths, *browser_target_paths)
    }
    reference_paths = {
        task_elementtree.command.casefold(),
        shell_raw.target_path.casefold(),
    }
    reference_names = {task_target_name, shell_target_name}
    if len(reference_paths) != 2:
        raise ValueError("Windows gallery Task and Shell Link must target distinct resident PEs")
    if not reference_paths.isdisjoint(excluded_paths) or not reference_names.isdisjoint(
        excluded_names
    ):
        raise ValueError(
            "Windows gallery Task/Shell Link targets must exclude all persistence/browser rows"
        )

    user_match = re.fullmatch(
        r"C:\\Users\\([^\\]+)\\AppData\\Local\\Temp\\[^\\]+",
        persisted_path,
        flags=re.IGNORECASE,
    )
    if user_match is None:
        raise ValueError("Windows gallery persisted path does not expose one canonical user")
    user = user_match.group(1)

    task_sha256 = hashlib.sha256(task_target_data).hexdigest()
    shell_sha256 = hashlib.sha256(shell_target_data).hexdigest()
    return {
        "user": user,
        "scheduled_task": {
            "source": task_file.relative_path,
            "guest_path": (
                rf"C:\Windows\System32\Tasks\ArtifactForge\{task_elementtree.task_name}"
            ),
            "task_name": task_elementtree.task_name,
            "target_name": task_target_name,
            "target_path": task_elementtree.command,
            "target_role": "disabled-task-reference-target",
            "target_size": len(task_target_data),
            "target_sha256": task_sha256,
        },
        "shell_link": {
            "source": shell_file.relative_path,
            "guest_path": (
                f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\"
                f"Start Menu\\Programs\\{shell_file.relative_path}"
            ),
            "target_name": shell_target_name,
            "target_path": shell_raw.target_path,
            "target_role": "shell-link-reference-target",
            "target_size": len(shell_target_data),
            "target_sha256": shell_sha256,
            "creation_filetime": shell_raw.creation_filetime,
            "access_filetime": shell_raw.access_filetime,
            "write_filetime": shell_raw.write_filetime,
            "volume_serial": shell_raw.volume_serial,
        },
        "readings": [
            (
                "Task XML: ElementTree, wire reader and Dissect",
                "ElementTree and the bounded wire reader agree on the closed Task profile. "
                "Dissect is a separate consumer observation.\n\n"
                + _markdown_table(
                    ("Field", "Observed value"),
                    (
                        ("Artifact", f"`{task_file.relative_path}`"),
                        ("Task", f"`{task_elementtree.task_name}`"),
                        ("Command", f"`{task_elementtree.command}`"),
                        (
                            "Profile",
                            "enabled=false; demand_start=false; triggers=0; actions=1",
                        ),
                        (
                            "Wire",
                            f"encoding={task_wire.encoding}; lines={task_wire.line_count}; "
                            f"marker_count={task_wire.marker_count}",
                        ),
                        (
                            "Dissect-only surfaces",
                            f"principals={task_dissect.principal_count}; arguments=None; "
                            "working_directory=None; action_context=None",
                        ),
                        (
                            "Resident join",
                            f"`{task_target_name}`; size={len(task_target_data)}; "
                            f"sha256=`{task_sha256[:16]}...`; path source=Prefetch",
                        ),
                    ),
                ),
            ),
            (
                "Shell Link: liblnk, LnkParse3 and raw reader",
                "liblnk and LnkParse3 agree on their typed semantic intersection. The bounded "
                "raw reader owns the exact wire profile.\n\n"
                + _markdown_table(
                    ("Field", "Observed value"),
                    (
                        ("Artifact", f"`{shell_file.relative_path}`"),
                        ("Target", f"`{shell_raw.target_path}`"),
                        ("External consensus", shell_liblnk.detail()),
                        ("Raw description", shell_raw.name_string),
                        ("Profile", shell_profile),
                        (
                            "Resident join",
                            f"`{shell_target_name}`; size={len(shell_target_data)}; "
                            f"sha256=`{shell_sha256[:16]}...`; path source=Prefetch",
                        ),
                        (
                            "Relation",
                            "distinct Task/Link targets; neither is a persistence/browser target",
                        ),
                    ),
                ),
            ),
        ],
    }


def _windows_readings(d: str) -> list:
    import pefile
    from regipy.registry import RegistryHive

    out = []
    files = inventory_regular_files(d, capture_bytes=True)

    binaries = {}
    binary_names = set()
    for file in files:
        data = file.data
        assert data is not None
        if data[:2] == b"MZ":
            binaries[file.relative_path] = data
            binary_names.add(file.name.lower())

    out.append(
        (
            "PE files: pefile",
            _markdown_table(
                ("File", "SHA-256", "IMPHASH"),
                (
                    (
                        f"`{name}`",
                        f"`{hashlib.sha256(data).hexdigest()[:16]}...`",
                        f"`{pefile.PE(data=data).get_imphash()}`",
                    )
                    for name, data in binaries.items()
                ),
            ),
        )
    )

    run = RegistryHive(os.fspath(_named(files, "Software.run.hive").path)).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    run_values = tuple(run.get_values())

    def windows_basename(path: str) -> str:
        return path.replace("/", "\\").rsplit("\\", 1)[-1]

    out.append(
        (
            "Run key: regipy",
            _markdown_table(
                ("Value", "Command", "Resident PE"),
                (
                    (
                        f"`{value.name}`",
                        f"`{value.value}`",
                        (
                            f"`{windows_basename(value.value)}`"
                            if windows_basename(value.value).lower() in binary_names
                            else "none"
                        ),
                    )
                    for value in run_values
                ),
            ),
        )
    )

    by_sha1 = {hashlib.sha1(x).hexdigest(): n for n, x in binaries.items()}  # noqa: S324
    iaf = RegistryHive(os.fspath(_named(files, "Amcache.hve").path)).get_key(
        "\\Root\\InventoryApplicationFile"
    )
    rows = []
    for sub in iaf.iter_subkeys():
        v = {x.name: x.value for x in sub.get_values()}
        sha1 = v["FileId"][4:]
        rows.append(
            (
                f"`{v['Name']}`",
                f"`0000{sha1[:16]}...`",
                f"`{by_sha1[sha1]}`" if sha1 in by_sha1 else "none",
            )
        )
    out.append(
        (
            "Amcache: regipy",
            "Five of eight FileId SHA-1 values join to resident bytes.\n\n"
            + _markdown_table(("Recorded name", "FileId", "Resident match"), rows),
        )
    )

    prefetch_rows = []
    volume_tokens = set()
    for file in files:
        if not file.name.endswith(".pf"):
            continue
        parsed, _profile = _windows_prefetch_view(file)
        volume_tokens.add(parsed.volume_device_path)
        prefetch_rows.append(
            (
                f"`{parsed.executable_name}`",
                str(parsed.version),
                str(parsed.run_count),
                f"`0x{parsed.prefetch_hash:08x}`",
                "yes" if parsed.executable_name.lower() in binary_names else "no",
            )
        )
    if len(volume_tokens) != 1:
        raise ValueError("Windows gallery Prefetch records do not share one volume token")
    volume_token = next(iter(volume_tokens))
    out.append(
        (
            "Compressed Prefetch v30: raw MAM reader, pyscca and Dissect",
            "All four records pass expected-size MAM framing, the closed v30 profile, pyscca "
            "acceptance and typed pyscca/Dissect semantic consensus. Their shared volume token "
            f"is `{volume_token}`; each marker is bound to that token.\n\n"
            + _markdown_table(
                ("Executable", "Version", "Run count", "Vista hash", "On disk"),
                prefetch_rows,
            ),
        )
    )

    connection = sqlite3.connect(os.fspath(_named(files, "History").path))
    try:
        downloads = connection.execute(
            "SELECT d.target_path,d.received_bytes,d.hash,d.referrer,u.url "
            "FROM downloads AS d JOIN downloads_url_chains AS u ON u.id=d.id "
            "ORDER BY d.id,u.chain_index"
        ).fetchall()
    finally:
        connection.close()
    binary_sha256 = {hashlib.sha256(data).hexdigest(): name for name, data in binaries.items()}
    download_rows = []
    resident_browser_targets = []
    for target, size, stored_hash, _referrer, source_url in downloads:
        match = re.fullmatch(r".+/sha256/([0-9a-f]{64})/([^/]+)", source_url)
        digest = match.group(1) if match else ""
        resident = binary_sha256.get(digest)
        if resident is not None:
            resident_browser_targets.append(target)
        download_rows.append(
            (
                f"`{target}`",
                str(size),
                f"`{stored_hash.hex()}`" if stored_hash else "empty BLOB",
                f"`{digest[:16]}...`",
                f"`{resident}`" if resident is not None else "none",
            )
        )
    out.append(
        (
            "Chromium completed downloads: sqlite3",
            _markdown_table(
                ("Target", "Bytes", "Database hash", "URL SHA-256", "Resident match"),
                download_rows,
            ),
        )
    )
    resident_run_paths = [
        value.value for value in run_values if windows_basename(value.value).lower() in binary_names
    ]
    if len(resident_run_paths) != 1 or len(resident_browser_targets) != 1:
        raise ValueError(
            "Windows gallery readings require one resident Run target and browser target"
        )
    binary_by_basename = {
        file.name.casefold(): file.data
        for file in files
        if file.data is not None and file.data[:2] == b"MZ"
    }
    references = _windows_reference_surfaces(
        files,
        binary_by_basename,
        persisted_path=resident_run_paths[0],
        persistence_paths=tuple(value.value for value in run_values),
        browser_target_paths=tuple(row[0] for row in downloads),
    )
    out.extend(references["readings"])
    return out


def _macos_readings(d: str) -> list:
    import lief
    import plistlib

    out = []
    files = inventory_regular_files(d, capture_bytes=True)

    binaries = []
    for file in files:
        data = file.data
        assert data is not None
        if data[:4] != b"\xcf\xfa\xed\xfe":
            continue
        b = lief.parse(os.fspath(file.path))
        undefined = sorted(
            s.name
            for s in b.symbols
            if s.is_external and not s.has_export_info and s.name.startswith("_")
        )
        binaries.append(
            (
                f"`{file.relative_path}`",
                str(b.header.cpu_type).split(".")[-1],
                str(b.header.nb_cmds),
                f"`{hashlib.md5(','.join(undefined).encode()).hexdigest()}`",  # noqa: S324
            )
        )
    out.append(
        (
            "Mach-O files: LIEF",
            "The symhash is recomputed from each binary's undefined symbols.\n\n"
            + _markdown_table(("File", "CPU", "Load commands", "Symhash"), binaries),
        )
    )

    def q(name, sql):
        con = sqlite3.connect(os.fspath(_named(files, name).path))
        try:
            return con.execute(sql).fetchall()
        finally:
            con.close()

    out.append(
        (
            "TCC records: sqlite3",
            _markdown_table(
                ("Client", "Service", "Auth value"),
                (
                    (f"`{client}`", f"`{service}`", str(auth_value))
                    for client, service, auth_value in q(
                        "TCC.db", "SELECT client, service, auth_value FROM access"
                    )
                ),
            ),
        )
    )
    out.append(
        (
            "Modeled in-focus records: sqlite3",
            _markdown_table(
                ("knowledgeC client",),
                (
                    (f"`{row[0]}`",)
                    for row in q(
                        "knowledgeC.db",
                        "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME = '/app/inFocus'",
                    )
                ),
            ),
        )
    )
    out.append(
        (
            "QuarantineEventsV2: sqlite3",
            "Each UUID is joined to the corresponding serialized quarantine-xattr sidecar.\n\n"
            + _markdown_table(
                ("UUID", "Agent", "Download URL"),
                (
                    (f"`{uuid}`", agent, f"`{url}`")
                    for uuid, agent, url in q(
                        "QuarantineEventsV2",
                        "SELECT LSQuarantineEventIdentifier, LSQuarantineAgentName, "
                        "LSQuarantineDataURLString FROM LSQuarantineEvent",
                    )
                ),
            ),
        )
    )

    lines = []
    for file in files:
        if not file.name.endswith(".plist"):
            continue
        data = file.data
        assert data is not None
        pl = plistlib.loads(data)
        lines.append((f"`{pl['Label']}`", f"`{pl['ProgramArguments'][0]}`"))
    out.append(
        (
            "LaunchAgents: plistlib",
            _markdown_table(("Label", "Program"), lines),
        )
    )
    return out


def _windows_evidence(d: str) -> dict:
    """Build the gallery's Gate-2 claims only from the copied Windows bytes."""
    import pefile
    from regipy.registry import RegistryHive

    files = inventory_regular_files(d, capture_bytes=True)
    binaries = {
        file.name.lower(): file.data
        for file in files
        if file.data is not None and file.data[:2] == b"MZ"
    }
    if len(binaries) != 5:
        raise ValueError("Windows gallery requires exactly five resident PE files")
    resident_guest_paths = _windows_prefetch_guest_paths(files, binaries)

    run = RegistryHive(os.fspath(_named(files, "Software.run.hive").path)).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    resident_run_values = [
        value.value
        for value in run.get_values()
        if value.value.replace("/", "\\").rsplit("\\", 1)[-1].lower() in binaries
    ]
    if len(resident_run_values) != 1:
        raise ValueError("Windows gallery requires one Run value naming a resident PE")
    persisted_path = resident_run_values[0]
    persisted_name = persisted_path.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    persisted_prefetch_path = resident_guest_paths.get(persisted_name)
    if persisted_prefetch_path is None:
        raise ValueError("Windows gallery persisted PE has no independent Prefetch path")
    if persisted_prefetch_path.casefold() != persisted_path.casefold():
        raise ValueError("Windows gallery Run path disagrees with independent Prefetch path")

    prefetches = {}
    for file in files:
        if file.name.endswith(".pf"):
            parsed, _profile = _windows_prefetch_view(file)
            prefetches[parsed.executable_name.lower()] = parsed.run_count
    if persisted_name not in prefetches:
        raise ValueError("Windows gallery persisted PE has no prefetch record")
    orphans = sorted(name for name in prefetches if name not in binaries)
    if len(orphans) != 1:
        raise ValueError("Windows gallery requires exactly one absent prefetch executable")

    resident_claims = []
    sha1_to_name = {}
    for name, data in sorted(binaries.items()):
        assert data is not None
        sha1 = hashlib.sha1(data).hexdigest()  # noqa: S324 - forensic identity
        sha1_to_name[sha1] = name
        claim = {
            "role": "persisted" if name == persisted_name else "resident-candidate",
            "name": name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": sha1,
            "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identity
            "imphash": pefile.PE(data=data).get_imphash(),
        }
        if name in resident_guest_paths:
            claim["path"] = resident_guest_paths[name]
        resident_claims.append(claim)

    amcache = RegistryHive(os.fspath(_named(files, "Amcache.hve").path)).get_key(
        "\\Root\\InventoryApplicationFile"
    )
    relations = []
    for subkey in amcache.iter_subkeys():
        row = {value.name: value.value for value in subkey.get_values()}
        file_id = row.get("FileId")
        if not isinstance(file_id, str) or not file_id.startswith("0000"):
            continue
        link_value = file_id[4:]
        candidate = sha1_to_name.get(link_value)
        if candidate is None:
            continue
        data = binaries[candidate]
        assert data is not None
        relations.append(
            {
                "selector": {"lower_case_long_path": row["LowerCaseLongPath"]},
                "link_value": link_value,
                "candidate": candidate,
                "expected": hashlib.sha256(data).hexdigest(),
            }
        )
    relations.sort(key=lambda relation: relation["selector"]["lower_case_long_path"])
    if len(relations) != 5:
        raise ValueError("Windows gallery requires five Amcache-to-resident relations")

    history = sqlite3.connect(os.fspath(_named(files, "History").path))
    try:
        download_rows = history.execute(
            "SELECT d.target_path,d.received_bytes,d.total_bytes,d.hash,d.state,d.referrer,"
            "u.url FROM downloads AS d JOIN downloads_url_chains AS u ON u.id=d.id "
            "ORDER BY d.id,u.chain_index"
        ).fetchall()
    finally:
        history.close()
    if len(download_rows) != 3:
        raise ValueError("Windows gallery requires three completed browser downloads")
    resident_sha256 = {
        hashlib.sha256(data).hexdigest(): name
        for name, data in binaries.items()
        if data is not None
    }
    browser_matches = []
    for target, received, total, stored_hash, state, referrer, source_url in download_rows:
        match = re.fullmatch(r".+/sha256/([0-9a-f]{64})/([^/]+)", source_url)
        if match is None:
            raise ValueError("Windows gallery browser URL lacks content-addressed identity")
        digest, basename = match.groups()
        if basename.casefold() != target.rsplit("\\", 1)[-1].casefold():
            raise ValueError("Windows gallery browser target and URL basename disagree")
        candidate = resident_sha256.get(digest)
        if candidate is None:
            continue
        data = binaries[candidate]
        assert data is not None
        if (received, total, stored_hash, state) != (len(data), len(data), b"", 1):
            raise ValueError("Windows gallery browser row disagrees with resident bytes")
        browser_matches.append(
            {
                "target_path": target,
                "candidate": candidate,
                "size": len(data),
                "sha256": digest,
                "source_url": source_url,
                "referrer_url": referrer,
                "database_hash": "empty BLOB (Chromium semantics)",
            }
        )
    if len(browser_matches) != 1 or browser_matches[0]["target_path"] != persisted_path:
        raise ValueError(
            "Windows gallery requires one browser download naming the persisted resident PE"
        )

    references = _windows_reference_surfaces(
        files,
        binaries,
        persisted_path=persisted_path,
        persistence_paths=tuple(value.value for value in run.get_values()),
        browser_target_paths=tuple(row[0] for row in download_rows),
    )
    reference_roles = {
        references["scheduled_task"]["target_name"]: (
            references["scheduled_task"]["target_role"],
            references["scheduled_task"]["target_path"],
        ),
        references["shell_link"]["target_name"]: (
            references["shell_link"]["target_role"],
            references["shell_link"]["target_path"],
        ),
    }
    for claim in resident_claims:
        if claim["name"] in reference_roles:
            role, parsed_path = reference_roles[claim["name"]]
            if parsed_path.casefold() != str(claim.get("path", "")).casefold():
                raise ValueError(
                    "Windows gallery reference path disagrees with independent Prefetch path"
                )
            claim["role"] = role

    return {
        "family": "windows",
        "user": references["user"],
        "residents": resident_claims,
        "persisted": {
            "name": persisted_name,
            "path": persisted_path,
            "run_count": prefetches[persisted_name],
        },
        "orphan_execution": orphans[0],
        "prefetch": {
            "artifact_count": len(prefetches),
            "execution_names": sorted(prefetches),
        },
        "browser_download": browser_matches[0],
        "scheduled_task": references["scheduled_task"],
        "shell_link": references["shell_link"],
        "benchmark_relations": relations,
        "benchmark_candidates": [
            {"candidate": name, "value": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(binaries.items())
            if data is not None
        ],
        "derivation": "re-derived from committed gallery bytes; not evaluator construction state",
    }


def _macos_evidence(d: str) -> dict:
    """Build the gallery's Gate-2 claims only from the copied macOS bytes."""
    import lief
    import plistlib

    from artifactforge.artifacts.macos import parse_quarantine_xattr
    from artifactforge.content.macho import cdhash_of_file

    files = inventory_regular_files(d, capture_bytes=True)
    machos = {
        file.name: file.data
        for file in files
        if file.data is not None and file.data[:4] == b"\xcf\xfa\xed\xfe"
    }
    if len(machos) != 5:
        raise ValueError("macOS gallery requires exactly five resident Mach-O files")

    binary_claims = []
    for bundle_id, data in sorted(machos.items()):
        assert data is not None
        parsed = lief.parse(os.fspath(_named(files, bundle_id).path))
        undefined = sorted(
            symbol.name
            for symbol in parsed.symbols
            if symbol.is_external and not symbol.has_export_info and symbol.name.startswith("_")
        )
        binary_claims.append(
            {
                "bundle_id": bundle_id,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic identity
                "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identity
                "cdhash": cdhash_of_file(data),
                "symhash": hashlib.md5(",".join(undefined).encode()).hexdigest(),  # noqa: S324 - structural identity
            }
        )

    def query(name: str, sql: str):
        connection = sqlite3.connect(os.fspath(_named(files, name).path))
        try:
            return connection.execute(sql).fetchall()
        finally:
            connection.close()

    granted = {row[0] for row in query("TCC.db", "SELECT client FROM access WHERE auth_value = 2")}
    used = {
        row[0]
        for row in query(
            "knowledgeC.db",
            "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME = '/app/inFocus'",
        )
    }
    subjects = sorted(granted & used)
    if len(subjects) != 1 or subjects[0] not in machos:
        raise ValueError("macOS gallery requires one used client with an allowed TCC grant")
    subject_bundle = subjects[0]
    subject_plist = plistlib.loads(_named(files, f"{subject_bundle}.plist").data)

    quarantine_rows = {
        row[0]: row
        for row in query(
            "QuarantineEventsV2",
            "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
            "LSQuarantineAgentName, LSQuarantineTimeStamp FROM LSQuarantineEvent",
        )
    }
    if len(quarantine_rows) != 5:
        raise ValueError("macOS gallery requires five unique quarantine rows")
    relations = []
    for file in files:
        if not file.name.endswith(".quarantine.xattr") or file.data is None:
            continue
        parsed = parse_quarantine_xattr(file.data)
        row = quarantine_rows.get(parsed.event_uuid)
        if row is None:
            raise ValueError(f"{file.relative_path}: quarantine UUID has no database row")
        bundle_id = file.name.removesuffix(".quarantine.xattr")
        if bundle_id not in machos:
            raise ValueError(f"{file.relative_path}: xattr has no resident Mach-O candidate")
        relations.append(
            {
                "selector": {"xattr_relative_path": file.relative_path},
                "link_value": parsed.event_uuid,
                "candidate": bundle_id,
                "expected": row[1],
            }
        )
    relations.sort(key=lambda relation: relation["selector"]["xattr_relative_path"])
    if len(relations) != 5:
        raise ValueError("macOS gallery requires five xattr-to-quarantine relations")

    return {
        "family": "macos",
        "binaries": binary_claims,
        "subject": {
            "bundle_id": subject_bundle,
            "app_path": subject_plist["ProgramArguments"][0],
        },
        "benchmark_relations": relations,
        "benchmark_candidates": [
            {"candidate": relation["candidate"], "value": relation["expected"]}
            for relation in relations
        ],
        "derivation": "re-derived from committed gallery bytes; not evaluator construction state",
    }


def _linux_evidence(d: str, fixture_dir: str) -> tuple[dict, dict]:
    """Re-derive the public Linux answer record from the copied artifact bytes.

    Fixture Core intentionally discards a scene's private construction-time join.  A sample
    should not smuggle that private record back out, so this derives the one shared XDG/history
    subject and every content digest from the same loose files a reader receives.
    """
    manifest_path = os.path.join(fixture_dir, "fixture.json")
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    recipe = manifest["recipe"]
    profile = recipe["profile"]
    if recipe["family"] != "linux" or profile["id"] != "linux-glibc-x86_64-loose-v2":
        raise ValueError("Linux sample requires the exact glibc/x86-64 loose fixture profile")

    files = inventory_regular_files(d, capture_bytes=True)
    elf_files = [file for file in files if file.data is not None and file.data[:4] == b"\x7fELF"]
    desktop_files = [file for file in files if file.relative_path.endswith(".desktop")]
    history_files = [file for file in files if file.name == ".bash_history"]
    if (len(elf_files), len(desktop_files), len(history_files), len(files)) != (5, 3, 1, 9):
        raise ValueError("Linux gallery profile requires exactly 5 ELF + 3 XDG + 1 history")

    home_dir = f"/home/{profile['username']}"
    guest_by_served = {file.relative_path: "/" + file.relative_path for file in elf_files}
    guest_paths = sorted(guest_by_served.values())
    desktop_records = []
    desktop_targets = set()
    for file in desktop_files:
        parsed = load_desktop_entry(file.path)
        desktop_targets.add(parsed.exec_path)
        desktop_records.append(
            {
                "guest_path": "/" + file.relative_path,
                "served_relpath": file.relative_path,
                "exec_guest_path": parsed.exec_path,
            }
        )

    history_file = history_files[0]
    history = load_bash_history(history_file.path, resident_paths=guest_paths)
    history_targets = {entry.command for entry in history if entry.command.startswith("/")}
    subject_paths = desktop_targets & history_targets
    if (
        len(subject_paths) != 1
        or len(desktop_targets) != 3
        or len(history_targets) != 3
        or not desktop_targets <= set(guest_paths)
        or not history_targets <= set(guest_paths)
    ):
        raise ValueError("Linux sample does not have the exact 3-by-3 unique-intersection join")
    subject_path = next(iter(subject_paths))

    role_by_guest = {subject_path: "subject"}
    for index, path in enumerate(sorted(desktop_targets - subject_paths), start=1):
        role_by_guest[path] = f"autostart-decoy-{index}"
    for index, path in enumerate(sorted(history_targets - subject_paths), start=1):
        role_by_guest[path] = f"history-decoy-{index}"

    residents = []
    for file in elf_files:
        data = file.data
        assert data is not None
        guest_path = guest_by_served[file.relative_path]
        marker_matches = re.findall(rb"ARTIFACTFORGE-SYNTHETIC-[0-9a-f]{16}", data)
        if len(marker_matches) != 1:
            raise ValueError(f"{file.relative_path}: expected one exact ELF disclosure marker")
        residents.append(
            {
                "role": role_by_guest[guest_path],
                "name": file.name,
                "guest_path": guest_path,
                "served_relpath": file.relative_path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic identity
                "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identity
                "marker": marker_matches[0].decode("ascii"),
            }
        )
    residents.sort(key=lambda resident: resident["served_relpath"])
    subject = next(resident for resident in residents if resident["guest_path"] == subject_path)
    desktop_records.sort(key=lambda record: record["served_relpath"])

    join = {
        "family": "linux",
        "profile": profile["id"],
        "os": "linux glibc-x86_64",
        "host": profile["hostname"],
        "user": profile["username"],
        "home_dir": home_dir,
        "residents": residents,
        "subject": subject,
        "autostart": desktop_records,
        "bash_history": {
            "guest_path": "/" + history_file.relative_path,
            "served_relpath": history_file.relative_path,
            "direct_exec_guest_paths": sorted(history_targets),
        },
        "decoys": {
            "resident_elfs": 5,
            "autostart_entries": 3,
            "history_direct_execs": 3,
        },
        "pivots": {
            "subject": "the one resident named by both XDG autostart Exec and Bash history",
            "digest": "guest path -> exact served relative path -> resident ELF bytes",
        },
    }
    answers = {
        "shared_guest_path": subject_path,
        "shared_served_relpath": subject["served_relpath"],
        "shared_sha256": subject["sha256"],
    }
    return answers, join


def _linux_readings(d: str, join: dict) -> list:
    import lief
    from dissect.target import Target
    from dissect.target.filesystem import VirtualFilesystem
    from elftools.elf.elffile import ELFFile
    from xdg.DesktopEntry import DesktopEntry as XDGDesktopEntry

    out = []
    files = inventory_regular_files(d, capture_bytes=True)
    elf_files = [file for file in files if file.data is not None and file.data[:4] == b"\x7fELF"]
    desktop_files = [file for file in files if file.relative_path.endswith(".desktop")]
    history_file = next(file for file in files if file.name == ".bash_history")
    resident_paths = [resident["guest_path"] for resident in join["residents"]]

    elf_rows = []
    elf_invariants = set()
    for file in elf_files:
        data = file.data
        assert data is not None
        binary = lief.parse(os.fspath(file.path))
        if binary is None:
            raise ValueError(f"LIEF returned no binary for {file.relative_path}")
        with open(file.path, "rb") as stream:
            elf = ELFFile(stream)
            interpreter = (
                next(
                    segment
                    for segment in elf.iter_segments()
                    if segment.header.p_type == "PT_INTERP"
                )
                .data()
                .rstrip(b"\x00")
                .decode("ascii")
            )
            dynamic = next(
                segment for segment in elf.iter_segments() if segment.header.p_type == "PT_DYNAMIC"
            )
            needed = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_NEEDED"]
            text_bytes = elf.get_section_by_name(".text").data().hex()
            if binary.interpreter != interpreter or binary.libraries != needed:
                raise ValueError(f"{file.relative_path}: LIEF and pyelftools disagree")
            imported = len(list(binary.imported_symbols))
            elf_invariants.add((interpreter, tuple(needed), imported, text_bytes))
            elf_rows.append(
                (
                    f"`{file.relative_path}`",
                    f"`{hashlib.sha256(data).hexdigest()[:16]}...`",
                    str(binary.header.file_type).split(".")[-1],
                    str(elf.header["e_type"]),
                )
            )
    if len(elf_invariants) != 1:
        raise ValueError("Linux gallery ELF files do not share the declared closed profile")
    interpreter, needed, imported, text_bytes = next(iter(elf_invariants))
    out.append(
        (
            "ELF files: LIEF and pyelftools",
            f"Both readers report interpreter `{interpreter}` and dependency "
            f"`{','.join(needed)}` for every file. LIEF reports {imported} imported symbols; "
            f"pyelftools reads the nine-byte entry as `{text_bytes}`.\n\n"
            + _markdown_table(
                ("File", "SHA-256", "LIEF type", "pyelftools type"),
                elf_rows,
            ),
        )
    )

    desktop_rows = []
    for file in desktop_files:
        external = XDGDesktopEntry(os.fspath(file.path))
        raw = load_desktop_entry(file.path)
        if (external.getType(), external.getExec(), external.getHidden()) != (
            raw.entry_type,
            raw.exec_path,
            raw.hidden,
        ):
            raise ValueError(f"{file.relative_path}: PyXDG and raw reader disagree")
        desktop_rows.append(
            (
                f"`{file.relative_path}`",
                f"`{raw.exec_path}`",
                str(raw.hidden).lower(),
                f"`{raw.synthetic_marker}`",
            )
        )
    out.append(
        (
            "XDG autostart: PyXDG and raw reader",
            "Both readers agree on Type, Exec and Hidden. The raw reader also checks the exact "
            "synthetic marker.\n\n"
            + _markdown_table(("File", "Exec", "Hidden", "Marker"), desktop_rows),
        )
    )

    filesystem = VirtualFilesystem()
    history_guest_path = join["bash_history"]["guest_path"]
    filesystem.map_file_fh(history_guest_path, BytesIO(history_file.data))
    filesystem.map_file_fh(
        "/etc/passwd",
        BytesIO(
            f"{join['user']}:x:1000:1000:ArtifactForge:{join['home_dir']}:/bin/bash\n".encode()
        ),
    )
    filesystem.map_file_fh("/etc/os-release", BytesIO(b"ID=artifactforge\n"))
    filesystem.makedirs("/var")
    filesystem.makedirs("/run")
    target = Target()
    target.filesystems.add(filesystem)
    target.apply()
    external_history = list(target.bashhistory())
    raw_history = load_bash_history(history_file.path, resident_paths=resident_paths)
    history_rows = []
    for external, raw in zip(external_history, raw_history, strict=True):
        observed_epoch = int(external.ts.timestamp())
        if (observed_epoch, external.command) != (raw.epoch, raw.command):
            raise ValueError("Linux gallery Dissect and raw Bash-history readers disagree")
        history_rows.append(
            (
                str(external.order),
                external.ts.astimezone(timezone.utc).isoformat(),
                str(raw.epoch),
                f"`{raw.command}`",
            )
        )
    out.append(
        (
            "Bash history: dissect.target and raw reader",
            f"Both readers agree on the records in `{history_file.relative_path}`. They read "
            "history as data; neither executes a command.\n\n"
            + _markdown_table(
                ("Order", "UTC timestamp", "Epoch", "Command"),
                history_rows,
            ),
        )
    )
    return out


def write(
    sample_dir: str,
    title: str,
    story: str,
    answers: dict,
    readings,
    *,
    scope: str,
    derived_evidence: dict | None = None,
) -> None:
    document = {**BANNER, "answers": answers}
    if derived_evidence is not None:
        document["derived_evidence"] = derived_evidence
    with open(os.path.join(sample_dir, "ARTIFACT_ANSWERS.json"), "w") as f:
        json.dump(document, f, indent=2)
        f.write("\n")

    body = [
        f"# {title}",
        "",
        "> **Synthetic sample.** Nothing here was collected from a real host or incident. "
        "Do not submit these values to a blocklist or threat-intelligence platform. See "
        "[`../../SECURITY.md`](../../SECURITY.md).",
        "",
        "## Scenario",
        "",
        story,
        "",
        "## Scope",
        "",
        scope,
        "",
        "## Reproduce",
        "",
        "From the repository root, run `scripts/make-samples.sh`. A byte difference means the "
        "generator or its declared inputs changed.",
        "",
        "## Reader results",
        "",
    ]
    for heading, output in readings:
        body += [f"### {heading}", "", output, ""]
    body += [
        "## Answer key",
        "",
        "Byte-derived answers are in [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each "
        "answer joins at least two artifacts.",
        "",
    ]
    with open(os.path.join(sample_dir, "README.md"), "w") as f:
        f.write("\n".join(body))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True)
    ap.add_argument("--windows", required=True)
    ap.add_argument("--macos", required=True)
    ap.add_argument("--linux-fixture", required=True)
    args = ap.parse_args()

    win_dir = "samples/01-windows-dropper"
    mac_dir = "samples/02-macos-quarantined-app"
    linux_dir = "samples/03-linux-autostart-history"
    win = suite.read_answers(args.suite, args.windows)
    mac = suite.read_answers(args.suite, args.macos)
    windows_evidence = _windows_evidence(win_dir)
    macos_evidence = _macos_evidence(mac_dir)
    if sorted(win["answers"].values()) != sorted(
        relation["expected"] for relation in windows_evidence["benchmark_relations"]
    ):
        raise ValueError("Windows evaluator answers disagree with byte-derived gallery evidence")
    if sorted(mac["answers"].values()) != sorted(
        relation["expected"] for relation in macos_evidence["benchmark_relations"]
    ):
        raise ValueError("macOS evaluator answers disagree with byte-derived gallery evidence")

    write(
        win_dir,
        "Windows: five historical hashes resolved against resident bytes",
        "Five resident PEs are joined to five of eight Amcache FileId SHA-1 values. The answer "
        "map records SHA-256 values recomputed from those PE bytes.\n\n"
        + _markdown_table(
            ("Surface", "Byte-derived relation", "Role"),
            (
                ("Run key", "path to resident PE and Prefetch record", "persistence context"),
                ("Chromium History", "reserved-URL SHA-256 to persisted PE", "download context"),
                ("Task XML", "path, size and SHA-256 to another PE", "configuration reference"),
                ("Shell Link", "path, size and SHA-256 to another PE", "file reference"),
                ("Prefetch", "executable path and run count", "execution context"),
            ),
        ),
        win["answers"],
        _windows_readings(win_dir),
        scope=(
            "The Task is disabled and trigger-free. The Shell Link has no arguments, network "
            "target or activation evidence. Their parser agreement and byte joins do not prove "
            "Task registration, shortcut activation or target execution."
        ),
        derived_evidence=windows_evidence,
    )

    write(
        mac_dir,
        "macOS: five quarantine UUIDs resolved to download events",
        "Five applications each have a real Mach-O binary and a strict serialized "
        "`com.apple.quarantine` xattr sidecar. Each xattr UUID resolves to exactly one "
        "`QuarantineEventsV2` URL; the answer map is re-derived from those emitted records. "
        "TCC, knowledgeC and LaunchAgent records provide separate modeled context.",
        mac["answers"],
        _macos_readings(mac_dir),
        scope=(
            "The records model grants, in-focus observations, downloads and persistence "
            "configuration. They are synthetic records, not proof that a real application was "
            "allowed, used, downloaded or launched."
        ),
        derived_evidence=macos_evidence,
    )

    linux_answers, linux_join = _linux_evidence(linux_dir, args.linux_fixture)
    write(
        linux_dir,
        "Linux: one resident named by XDG autostart and Bash history",
        "Five nested ELF files are resident. Three XDG autostart records name one set of "
        "three paths; a timestamped Bash history names another set of three. Their unique "
        "shared path identifies the subject, and that exact guest path maps to one recursive "
        "served path whose SHA-256 is computed from the committed ELF bytes.",
        linux_answers,
        _linux_readings(linux_dir, linux_join),
        scope=(
            "This is naming evidence, not activation evidence. Fixture ABI v2 binds logical "
            "guest modes, but this gallery contains only the copied artifact bytes and is not "
            "an activation-ready filesystem. Each ELF declares the glibc loader and `libc.so.6`; "
            "the loader would run before the nine-byte direct-exit entry. Do not execute the "
            "files, run `ldd`, launch the desktop entries or evaluate the history."
        ),
        derived_evidence=linux_join,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
