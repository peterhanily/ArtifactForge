# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Write each sample's answer key and README, with real parser output pasted in.

The key is called ARTIFACT_ANSWERS.json rather than GROUND_TRUTH.json on purpose.
EvidenceForge's loader searches an output directory AND its parent for a file named exactly
`GROUND_TRUTH.json`, and degrades to a single `logger.warning` when one does not match its
schema — so an ArtifactForge scene sitting anywhere near an EvidenceForge run would make that
tool report a wrong number quietly. Not colliding costs nothing.

The parser output is the part that matters. A gallery showing what the generator says about
its own files is a brochure; a gallery showing what pefile, regipy, libscca and LIEF say about
them is evidence — and if any of those tools ever stop agreeing, regenerating the gallery
makes it obvious.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "src"))

from artifactforge import suite  # noqa: E402
from artifactforge.disclosure import NOTICE  # noqa: E402

BANNER = {
    "synthetic": True,
    "notice": NOTICE,
    "generator": "ArtifactForge",
    # A SQLite header embeds the writing library's version, so the macOS databases here are
    # byte-identical only to a rebuild using the same one. Recorded so a difference is
    # explicable rather than alarming; every other artifact is byte-identical anywhere.
    "sqlite_version": sqlite3.sqlite_version,
}


def _windows_readings(d: str) -> list:
    import pefile
    import pyscca
    from regipy.registry import RegistryHive
    out = []

    binaries = {}
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        with open(path, "rb") as f:
            head = f.read(2)
        if head == b"MZ":
            with open(path, "rb") as f:
                binaries[name] = f.read()

    out.append(("pefile — every binary present", "\n".join(
        f"{name:24s} sha256={hashlib.sha256(data).hexdigest()[:16]}...  "
        f"imphash={pefile.PE(data=data).get_imphash()}"
        for name, data in binaries.items())))

    run = RegistryHive(os.path.join(d, "Software.run.hive")).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run")
    out.append(("regipy — Run key: three autostarts, one naming a program that is here",
                "\n".join(f"{v.name:24s} {v.value}" for v in run.get_values())))

    by_sha1 = {hashlib.sha1(x).hexdigest(): n for n, x in binaries.items()}   # noqa: S324
    iaf = RegistryHive(os.path.join(d, "Amcache.hve")).get_key(
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
    for pf_path in sorted(glob.glob(os.path.join(d, "*.pf"))):
        f = pyscca.file()
        f.open(pf_path)
        try:
            resident = "" if f.get_executable_filename().lower() in binaries else \
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

    binaries = []
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        with open(path, "rb") as f:
            if f.read(4) != b"\xcf\xfa\xed\xfe":
                continue
        b = lief.parse(path)
        undefined = sorted(s.name for s in b.symbols
                           if s.is_external and not s.has_export_info
                           and s.name.startswith("_"))
        binaries.append(
            f"{name:26s} {str(b.header.cpu_type).split('.')[-1]:8s} "
            f"cmds={b.header.nb_cmds}  symhash="
            f"{hashlib.md5(','.join(undefined).encode()).hexdigest()}")     # noqa: S324
    out.append(("LIEF — every Mach-O present, with the symhash recomputed from its symbol "
                "table", "\n".join(binaries)))

    def q(name, sql):
        con = sqlite3.connect(os.path.join(d, name))
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
    for path in sorted(glob.glob(os.path.join(d, "*.plist"))):
        with open(path, "rb") as f:
            pl = plistlib.load(f)
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
          "recorded hashes match a *different* one, because the persisted binary is recorded "
          "under the hash of the version Amcache saw. One prefetch record names a program "
          "that is no longer on disk. Following names and following hashes lead to different "
          "files, which is what makes each of them a pivot rather than a lookup.",
          win["answers"], win["join"], _windows_readings(win_dir))

    write(mac_dir, "macOS: a quarantined app that was granted access, and used",
          "Five applications, each with a real Mach-O binary and a quarantine record. Two "
          "hold an allowed TCC grant; only one of those also appears in knowledgeC as having "
          "been used. Everything after that hangs off the quarantine UUID in that app's "
          "`com.apple.quarantine` xattr, which is the join macOS actually gives a responder.",
          mac["answers"], mac["join"], _macos_readings(mac_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
