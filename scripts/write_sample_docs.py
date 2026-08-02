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
# putting it in a generated file makes that file environment-dependent too — which is how the
# answer key briefly stopped being byte-identical across platforms, defeating the very diff
# that had just been narrowed to exclude the databases. Provenance belongs in prose that a
# person maintains; `samples/README.md` carries it, and fidelity-scorecard.json records the
# version the gates ran under.


def _named(files: tuple[InventoryFile, ...], name: str) -> InventoryFile:
    matches = [file for file in files if file.name == name]
    if len(matches) != 1:
        raise ValueError(
            f"sample artifact basename {name!r} resolves to "
            f"{[file.relative_path for file in matches]}"
        )
    return matches[0]


def _windows_readings(d: str) -> list:
    import pefile
    import pyscca
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
            "pefile — every binary present",
            "\n".join(
                f"{name:24s} sha256={hashlib.sha256(data).hexdigest()[:16]}...  "
                f"imphash={pefile.PE(data=data).get_imphash()}"
                for name, data in binaries.items()
            ),
        )
    )

    run = RegistryHive(os.fspath(_named(files, "Software.run.hive").path)).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    out.append(
        (
            "regipy — Run key: three autostarts, one naming a program that is here",
            "\n".join(f"{v.name:24s} {v.value}" for v in run.get_values()),
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
        row = f"{v['Name']:24s} FileId=0000{sha1[:16]}..."
        if sha1 in by_sha1:
            row += f"  <-- matches {by_sha1[sha1]} on disk"
        rows.append(row)
    out.append(
        (
            "regipy — Amcache: eight records, five whose hashes belong to resident files",
            "\n".join(rows),
        )
    )

    lines = []
    for file in files:
        if not file.name.endswith(".pf"):
            continue
        f = pyscca.file()
        f.open(os.fspath(file.path))
        try:
            resident = (
                "" if f.get_executable_filename().lower() in binary_names else "  <-- not on disk"
            )
            lines.append(
                f"{f.get_executable_filename():24s} run_count={f.get_run_count()}  "
                f"hash=0x{f.get_prefetch_hash():08x}{resident}"
            )
        finally:
            f.close()
    out.append(("libscca (what plaso uses) — prefetch", "\n".join(lines)))
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
            f"{file.relative_path:26s} {str(b.header.cpu_type).split('.')[-1]:8s} "
            f"cmds={b.header.nb_cmds}  symhash="
            f"{hashlib.md5(','.join(undefined).encode()).hexdigest()}"
        )  # noqa: S324
    out.append(
        (
            "LIEF — every Mach-O present, with the symhash recomputed from its symbol table",
            "\n".join(binaries),
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
            "sqlite3 — TCC: two clients allowed, two refused",
            "\n".join(
                f"{c:26s} {s:34s} auth_value={a}"
                for c, s, a in q("TCC.db", "SELECT client, service, auth_value FROM access")
            ),
        )
    )
    out.append(
        (
            "sqlite3 — knowledgeC: which of them was actually used",
            "\n".join(
                r[0]
                for r in q(
                    "knowledgeC.db",
                    "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME = '/app/inFocus'",
                )
            ),
        )
    )
    out.append(
        (
            "sqlite3 — QuarantineEventsV2: five downloads, joined by the xattr UUID",
            "\n".join(
                f"{u}  {a:16s} {url}"
                for u, a, url in q(
                    "QuarantineEventsV2",
                    "SELECT LSQuarantineEventIdentifier, LSQuarantineAgentName, "
                    "LSQuarantineDataURLString FROM LSQuarantineEvent",
                )
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
        lines.append(f"{pl['Label']:26s} {pl['ProgramArguments'][0]}")
    out.append(("plistlib — LaunchAgents", "\n".join(lines)))
    return out


def _windows_evidence(d: str) -> dict:
    """Build the gallery's Gate-2 claims only from the copied Windows bytes."""
    import pefile
    from regipy.registry import RegistryHive
    from windowsprefetch import Prefetch

    files = inventory_regular_files(d, capture_bytes=True)
    binaries = {
        file.name.lower(): file.data
        for file in files
        if file.data is not None and file.data[:2] == b"MZ"
    }
    if len(binaries) != 5:
        raise ValueError("Windows gallery requires exactly five resident PE files")

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

    prefetches = {}
    for file in files:
        if file.name.endswith(".pf"):
            parsed = Prefetch(os.fspath(file.path))
            prefetches[parsed.executableName.lower()] = parsed.runCount
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
        resident_claims.append(
            {
                "role": "persisted" if name == persisted_name else "resident-candidate",
                "name": name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "sha1": sha1,
                "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identity
                "imphash": pefile.PE(data=data).get_imphash(),
            }
        )

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

    return {
        "family": "windows",
        "residents": resident_claims,
        "persisted": {
            "name": persisted_name,
            "path": persisted_path,
            "run_count": prefetches[persisted_name],
        },
        "orphan_execution": orphans[0],
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
    if recipe["family"] != "linux" or profile["id"] != "linux-glibc-x86_64-loose-v1":
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

    lines = []
    for file in elf_files:
        data = file.data
        assert data is not None
        binary = lief.parse(os.fspath(file.path))
        if binary is None:
            raise ValueError(f"LIEF returned no binary for {file.relative_path}")
        lines.append(
            f"{file.relative_path}  type={str(binary.header.file_type).split('.')[-1]} "
            f"machine={str(binary.header.machine_type).split('.')[-1]} "
            f"interp={binary.interpreter} needed={','.join(binary.libraries)} "
            f"imports={len(list(binary.imported_symbols))} "
            f"sha256={hashlib.sha256(data).hexdigest()[:16]}..."
        )
    out.append(
        (
            "LIEF — five ELF64 PIE files declare glibc but import no functions",
            "\n".join(lines),
        )
    )

    lines = []
    for file in elf_files:
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
            lines.append(
                f"{file.relative_path}  type={elf.header['e_type']} "
                f"machine={elf.header['e_machine']} interp={interpreter} "
                f"needed={','.join(needed)} .text={text_bytes}"
            )
    out.append(
        (
            "pyelftools — independently reads the same loader, dependency and nine-byte entry",
            "\n".join(lines),
        )
    )

    external_lines = []
    raw_lines = []
    for file in desktop_files:
        external = XDGDesktopEntry(os.fspath(file.path))
        raw = load_desktop_entry(file.path)
        external_lines.append(
            f"{file.relative_path}  Type={external.getType()} Exec={external.getExec()} "
            f"Hidden={str(external.getHidden()).lower()}"
        )
        raw_lines.append(
            f"{file.relative_path}  Type={raw.entry_type} Exec={raw.exec_path} "
            f"Hidden={str(raw.hidden).lower()} marker={raw.synthetic_marker}"
        )
    out.append(("PyXDG — three XDG desktop-entry records", "\n".join(external_lines)))
    out.append(("bounded raw reader — the same XDG values and exact marker", "\n".join(raw_lines)))

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
    out.append(
        (
            "dissect.target — timestamped Bash-history records read as data",
            "\n".join(
                f"{history_file.relative_path}  {record.ts.astimezone(timezone.utc).isoformat()} "
                f"order={record.order} command={record.command}"
                for record in external_history
            ),
        )
    )
    out.append(
        (
            "bounded raw reader — the same Bash epochs and command strings",
            "\n".join(
                f"{history_file.relative_path}  epoch={record.epoch} command={record.command}"
                for record in raw_history
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
        "> **Synthetic.** Every byte here was generated. No hash, UUID, URL or path in "
        "this directory identifies anything real, and none should be submitted to a "
        "blocklist or a threat-intelligence platform. See [`../../SECURITY.md`]"
        "(../../SECURITY.md).",
        "",
        story,
        "",
        "Regenerate with `scripts/make-samples.sh`. The bytes are deterministic, so a "
        "regeneration that differs is a change in the generator, not in the weather.",
        "",
        "## What the declared readers see",
        "",
    ]
    for heading, output in readings:
        body += [f"### {heading}", "", "```", output, "```", ""]
    body += [
        "## The answers",
        "",
        "In [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each one requires reading at least "
        "two of the files above together.",
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
        "Five binaries are resident. Five of eight Amcache rows carry `FileId` SHA-1 values "
        "that each resolve to exactly one of those binaries, while stale rows remain noise. "
        "The answer map records the resident SHA-256 values re-derived from the loose bytes. "
        "Run-key and prefetch evidence provide separate persistence/execution context without "
        "selecting the hash answers by filename or stored order.",
        win["answers"],
        _windows_readings(win_dir),
        derived_evidence=windows_evidence,
    )

    write(
        mac_dir,
        "macOS: five quarantine UUIDs resolved to download events",
        "Five applications each have a real Mach-O binary and a strict serialized "
        "`com.apple.quarantine` xattr sidecar. Each xattr UUID resolves to exactly one "
        "`QuarantineEventsV2` URL; the answer map is re-derived from those emitted records. "
        "TCC, knowledgeC and LaunchAgent records remain independent incident context.",
        mac["answers"],
        _macos_readings(mac_dir),
        derived_evidence=macos_evidence,
    )

    linux_answers, linux_join = _linux_evidence(linux_dir, args.linux_fixture)
    write(
        linux_dir,
        "Linux: one resident named by XDG autostart and Bash history",
        "Five nested ELF files are resident. Three XDG autostart records name one set of "
        "three paths; a timestamped Bash history names another set of three. Their unique "
        "shared path identifies the subject, and that exact guest path maps to one recursive "
        "served path whose SHA-256 is computed from the committed ELF bytes.\n\n"
        "This is naming evidence, not an activation claim: parser acceptance does not prove "
        "that a desktop session launched an entry, and shell history is not proof that a "
        "command ran. Fixture Core v1 does not bind executable modes, so the released files "
        "are normalized to 0644 and are not an activation-ready filesystem. The ELF declares "
        "the glibc loader and `libc.so.6`, while the main object imports and calls no libc "
        "function; external loader/dependency code is out of scope and on a real "
        "execution attempt the dynamic loader would run before its nine-byte direct-exit "
        "entry. The files are deliberately minimal, not compiler-shaped. Do not execute "
        "them, run `ldd`, launch the desktop entries, or source/evaluate the history.",
        linux_answers,
        _linux_readings(linux_dir, linux_join),
        derived_evidence=linux_join,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
