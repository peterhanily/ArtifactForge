# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Scan a corpus with a YARA rule set, with a positive control first.

A rule set that matches nothing because it failed to compile looks exactly like a clean
result. So before reporting anything, this crafts a file that satisfies one rule in the set
exactly, and a near-miss that satisfies it one condition short, and requires the first to hit
and the second not to. Only then is a zero worth printing.

Community rule sets are largely *descriptive* rather than accusatory — `IsPE64` says a file is
a 64-bit PE, `win_registry` says it imports registry APIs. Those firing is expected and says
nothing about whether a file is malicious, so hits are grouped by whether the rule names a
threat or describes a characteristic, and only the first group is treated as a finding.
"""
from __future__ import annotations

import argparse
import collections
import glob
import os
import sys
import tempfile

XPROTECT = ("/Library/Apple/System/Library/CoreServices/XProtect.bundle"
            "/Contents/Resources/XProtect.yara")

#: Rules whose meaning is "this file has property X", not "this file is malicious". A hit is
#: expected and carries no verdict — a genuine artifact of the same kind fires them too.
DESCRIPTIVE = {
    "domain", "url", "contains_base64", "IsPE64", "IsPE32", "IsConsole", "IsWindowsGUI",
    "HasOverlay", "HasModified_DOS_Message", "HasRichSignature", "IsNET_EXE", "IsDLL",
    "win_registry", "win_files_operation", "win_token", "win_mutex", "network_tcp_socket",
    "network_dns", "network_http", "Str_Win32_Winsock2_Library", "Str_Win32_Wininet_Library",
    "Str_Win32_Internet_API", "with_sqlite", "Big_Numbers0", "Big_Numbers1", "Big_Numbers2",
    "Browsers", "Misc_Suspicious_Strings", "escalate_priv", "screenshot", "keylogger",
    "anti_dbg", "win_hook", "inject_thread", "create_process", "ldpreload",
}


def _load(paths, externals):
    import yara
    compiled, failed = {}, 0
    for p in paths:
        try:
            compiled[p] = yara.compile(filepath=p, externals=externals)
        except Exception:                       # noqa: BLE001 — unsupported module or syntax
            failed += 1
    return compiled, failed


def _control(compiled) -> bool:
    """Craft a file satisfying XProtect_MACOS_71915a8 and a near-miss one condition short."""
    import yara                                 # noqa: F401 — imported for the error type
    body = "#!" + "/bin/zsh\n" + "\\U00000" * 16 + "${" * 101 + "rev)"
    with tempfile.TemporaryDirectory() as d:
        hit_path = os.path.join(d, "control")
        miss_path = os.path.join(d, "near")
        with open(hit_path, "w") as f:
            f.write(body)
        with open(miss_path, "w") as f:
            f.write(body.replace("${" * 101, "${" * 100))
        hit = any(rules.match(hit_path) for rules in compiled.values())
        miss = any(rules.match(miss_path) for rules in compiled.values())
    return hit and not miss


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", help="a directory of .yar files")
    ap.add_argument("--xprotect", action="store_true", help="use Apple's shipped signatures")
    ap.add_argument("--corpus", required=True)
    args = ap.parse_args()

    externals = {"filename": "", "filepath": "", "extension": "", "filetype": "", "md5": ""}
    if args.xprotect:
        if not os.path.exists(XPROTECT):
            print("   SKIPPED: XProtect.yara not present (not macOS)")
            return 0
        compiled, failed = _load([XPROTECT], externals)
        if not compiled:
            print("   SKIPPED: XProtect.yara did not compile with this yara build")
            return 0
        if not _control(compiled):
            print("   SKIPPED: the control did not fire, so a clean result would mean nothing")
            return 0
        print("   control: a crafted file matches XProtect_MACOS_71915a8, a near-miss does "
              "not — the rules work")
    else:
        paths = [p for p in sorted(glob.glob(os.path.join(args.rules, "**", "*.yar"),
                                             recursive=True))
                 if "/deprecated/" not in p and not os.path.basename(p).endswith("_index.yar")]
        compiled, failed = _load(paths, externals)
        total = sum(sum(1 for _ in r) for r in compiled.values())
        print(f"   {len(compiled)}/{len(paths)} rule files compiled ({failed} unsupported by "
              f"this yara build), {total} rules")

    corpus = sorted(p for p in glob.glob(os.path.join(args.corpus, "*")) if os.path.isfile(p))
    named, descriptive = collections.Counter(), collections.Counter()
    for path in corpus:
        for rules in compiled.values():
            for m in rules.match(path):
                (descriptive if m.rule in DESCRIPTIVE else named)[m.rule] += 1

    print(f"   scanned {len(corpus)} files")
    if descriptive:
        print(f"   descriptive hits (expected — a real artifact fires these too): "
              f"{sum(descriptive.values())} across {len(descriptive)} rules")
        for rule, n in descriptive.most_common(8):
            print(f"      {n:5d}x {rule}")
    if named:
        print(f"   THREAT-NAMING RULES FIRED: {sum(named.values())} across {len(named)}")
        for rule, n in named.most_common(20):
            print(f"      {n:5d}x {rule}")
        return 1
    print("   no threat-naming rule fired")
    return 0


if __name__ == "__main__":
    sys.exit(main())
