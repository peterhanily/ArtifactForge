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

The parser output is the part that matters. A gallery showing what the generator says about
its own files is a brochure; a gallery showing what pefile, regipy, libscca and LIEF say about
them is evidence — and if any of those tools ever stop agreeing, regenerating the gallery
makes it obvious.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "src"))

from artifactforge import suite  # noqa: E402
from artifactforge.disclosure import NOTICE  # noqa: E402
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

    out.append(("pefile — every binary present", "\n".join(
        f"{name:24s} sha256={hashlib.sha256(data).hexdigest()[:16]}...  "
        f"imphash={pefile.PE(data=data).get_imphash()}"
        for name, data in binaries.items())))

    run = RegistryHive(os.fspath(_named(files, "Software.run.hive").path)).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run")
    out.append(("regipy — Run key: three autostarts, one naming a program that is here",
                "\n".join(f"{v.name:24s} {v.value}" for v in run.get_values())))

    by_sha1 = {hashlib.sha1(x).hexdigest(): n for n, x in binaries.items()}   # noqa: S324
    iaf = RegistryHive(os.fspath(_named(files, "Amcache.hve").path)).get_key(
        "\\Root\\InventoryApplicationFile")
    rows = []
    for sub in iaf.iter_subkeys():
        v = {x.name: x.value for x in sub.get_values()}
        sha1 = v["FileId"][4:]
        rows.append(f"{v['Name']:24s} FileId=0000{sha1[:16]}...  "
                    f"{'<-- matches ' + by_sha1[sha1] + ' on disk' if sha1 in by_sha1 else ''}")
    out.append(("regipy — Amcache: eight records, one whose hash belongs to a resident file",
                "\n".join(rows)))

    lines = []
    for file in files:
        if not file.name.endswith(".pf"):
            continue
        f = pyscca.file()
        f.open(os.fspath(file.path))
        try:
            resident = "" if f.get_executable_filename().lower() in binary_names else \
                "  <-- not on disk"
            lines.append(f"{f.get_executable_filename():24s} run_count={f.get_run_count()}  "
                         f"hash=0x{f.get_prefetch_hash():08x}{resident}")
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
        undefined = sorted(s.name for s in b.symbols
                           if s.is_external and not s.has_export_info
                           and s.name.startswith("_"))
        binaries.append(
            f"{file.relative_path:26s} {str(b.header.cpu_type).split('.')[-1]:8s} "
            f"cmds={b.header.nb_cmds}  symhash="
            f"{hashlib.md5(','.join(undefined).encode()).hexdigest()}")     # noqa: S324
    out.append(("LIEF — every Mach-O present, with the symhash recomputed from its symbol "
                "table", "\n".join(binaries)))

    def q(name, sql):
        con = sqlite3.connect(os.fspath(_named(files, name).path))
        try:
            return con.execute(sql).fetchall()
        finally:
            con.close()

    out.append(("sqlite3 — TCC: two clients allowed, two refused", "\n".join(
        f"{c:26s} {s:34s} auth_value={a}"
        for c, s, a in q("TCC.db", "SELECT client, service, auth_value FROM access"))))
    out.append(("sqlite3 — knowledgeC: which of them was actually used", "\n".join(
        r[0] for r in q("knowledgeC.db",
                        "SELECT ZVALUESTRING FROM ZOBJECT "
                        "WHERE ZSTREAMNAME = '/app/inFocus'"))))
    out.append(("sqlite3 — QuarantineEventsV2: five downloads, joined by the xattr UUID",
                "\n".join(f"{u}  {a:16s} {url}" for u, a, url in q(
                    "QuarantineEventsV2",
                    "SELECT LSQuarantineEventIdentifier, LSQuarantineAgentName, "
                    "LSQuarantineDataURLString FROM LSQuarantineEvent"))))

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


def write(sample_dir: str, title: str, story: str, answers: dict, join: dict, readings) -> None:
    with open(os.path.join(sample_dir, "ARTIFACT_ANSWERS.json"), "w") as f:
        json.dump({**BANNER, "answers": answers, "join": join}, f, indent=2)
        f.write("\n")

    body = [f"# {title}", "",
            "> **Synthetic.** Every byte here was generated. No hash, UUID, URL or path in "
            "this directory identifies anything real, and none should be submitted to a "
            "blocklist or a threat-intelligence platform. See [`../../SECURITY.md`]"
            "(../../SECURITY.md).", "",
            story, "",
            "Regenerate with `scripts/make-samples.sh`. The bytes are deterministic, so a "
            "regeneration that differs is a change in the generator, not in the weather.", "",
            "## What real tools see", ""]
    for heading, output in readings:
        body += [f"### {heading}", "", "```", output, "```", ""]
    body += ["## The answers", "",
             "In [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each one requires reading at least "
             "two of the files above together.", ""]
    with open(os.path.join(sample_dir, "README.md"), "w") as f:
        f.write("\n".join(body))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True)
    ap.add_argument("--windows", required=True)
    ap.add_argument("--macos", required=True)
    args = ap.parse_args()

    win_dir = "samples/01-windows-dropper"
    mac_dir = "samples/02-macos-quarantined-app"
    win = suite.read_answers(args.suite, args.windows)
    mac = suite.read_answers(args.suite, args.macos)

    write(win_dir, "Windows: a persisted binary, and a hash that points elsewhere",
          "Five binaries. One Run-key value names a program that is present; Amcache's "
          "recorded hashes match a *different* one, while the persisted binary is recorded "
          "under a deliberately stale value whose historical bytes are not retained. One "
          "prefetch record names a program "
          "that is no longer on disk. Following names and following hashes lead to different "
          "files, which is what makes each of them a pivot rather than a lookup.",
          win["answers"], win["join"], _windows_readings(win_dir))

    write(mac_dir, "macOS: a quarantined app that was granted access, and used",
          "Five applications, each with a real Mach-O binary and a quarantine record. Two "
          "hold an allowed TCC grant; only one of those also appears in knowledgeC as having "
          "been used. Everything after that hangs off the quarantine UUID in that app's "
          "serialized `com.apple.quarantine` xattr value, emitted here as a sidecar file; the "
          "UUID is the join macOS gives a responder.",
          mac["answers"], mac["join"], _macos_readings(mac_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
