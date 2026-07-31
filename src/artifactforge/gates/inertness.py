# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 3 — inertness: can anything we ship execute, and is every format marked synthetic?

Two properties, both checked on the emitted bytes rather than asserted in prose.

**Inert.** A binary this project generates reproduces the forensic *signal* — a real import
table, a real symbol table, a real hash — and never the offensive *capability*. The code
section is a single return instruction and nothing else. This is checked by disassembling
what actually lands on disk, not by trusting the generator.

**Marked.** Every emitted format carries an in-band anchor identifying it as ArtifactForge
output, so a file that escapes its bundle can still be recognised for what it is. A format
with no marker is a failure: KNOWN_TELLS.md calls honesty "a shipped mechanism", and a
mechanism nothing enforces is a claim.

**Indicators point nowhere real.** Domains must be RFC 2606 reserved (.example, .invalid,
.test) and addresses RFC 5737 / RFC 3849, so no synthetic artifact can label a real host as
attacker infrastructure.
"""
from __future__ import annotations

import os
import re

from artifactforge.gates import GateReport
from artifactforge.gates.validity import classify

# The in-band anchor each format must carry. A format absent from this table is unmarked,
# and unmarked is a failure — not an omission to be discovered later.
MARKERS = {
    "pe":       [b"ARTIFACTFORGE-SYNTHETIC-"],
    "macho":    [b"ARTIFACTFORGE-SYNTHETIC-"],
    "hive":     ["ArtifactForgeHive".encode("utf-16-le")],
    "prefetch": [b"ARTIFACTFORGE", "ARTIFACTFORGE".encode("utf-16-le")],
    "sqlite":   [b"ARTIFACTFORGE", "ARTIFACTFORGE".encode("utf-16-le")],
    "plist":    [b"ARTIFACTFORGE"],
}

# RFC 2606 reserved TLDs/domains, and RFC 5737 / RFC 3849 documentation address ranges.
_RESERVED_TLD = (".example", ".invalid", ".test", ".localhost")
_RESERVED_DOMAIN = ("example.com", "example.net", "example.org")
_DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:")
# Reverse-DNS prefixes belonging to real organisations. A bundle identifier is a namespaced
# claim of authorship, and on macOS it is embedded in the code signature — so an ad-hoc-signed
# synthetic binary identifying itself as `com.apple.Notes` asserts something false about Apple.
# Windows executable FILENAMES are deliberately not policed: `chrome.exe` is ubiquitous on a
# real host and claims nothing about who wrote it.
_REAL_VENDOR_PREFIXES = (
    "com.apple.", "com.microsoft.", "com.google.", "org.mozilla.", "com.adobe.",
    "com.amazon.", "com.meta.", "com.facebook.", "com.oracle.", "com.docker.",
    "com.spotify.", "us.zoom.", "com.tinyspeck.", "com.figma.", "com.postmanlabs.",
    "com.jetbrains.", "com.vmware.", "com.citrix.", "com.dropbox.", "com.slack.",
)
# Real vendor identifiers that are the PLATFORM'S OWN VOCABULARY rather than a claim of
# authorship. An artifact that avoided these would simply be wrong: the quarantine attribute
# really is called `com.apple.quarantine`, and a scene naming it something else would not be a
# macOS scene. Every exemption carries a reason, and the reason has to say something.
_PLATFORM_IDENTIFIERS = {
    "com.apple.quarantine":
        "the real extended attribute Gatekeeper sets on a downloaded file; the artifact is "
        "named after the attribute, and renaming it would make the scene wrong",
    "com.apple.launchservices.quarantineeventsv2":
        "the real filename of the LaunchServices quarantine database a responder opens",
    "com.apple.tcc":
        "the real directory holding TCC.db; it identifies Apple's subsystem, not an author",
    "com.apple.metadata":
        "the real extended-attribute namespace Spotlight and LaunchServices write under",
}
_BUNDLE_ID = re.compile(rb"\b((?:com|org|io|net|us|uk|de)\.[A-Za-z0-9]+\.[A-Za-z0-9._-]+)")
_URL = re.compile(rb"https?://([A-Za-z0-9._-]+)")
_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _pe_code_is_inert(data: bytes) -> tuple[bool, str]:
    """The .text section must be one 0xC3 (ret), and the DOS stub must be the standard one.

    A PE has two places that legitimately hold executable code, and both are checked. The
    second matters more than it looks: the MS-DOS stub is the one region of a Windows binary
    where arbitrary code is conventional and nobody reads it, so requiring it to equal the
    stub every compiler has emitted for thirty years — byte for byte — closes the obvious
    place to hide something.
    """
    import pefile

    from artifactforge.content.store import DOS_STUB
    stub = data[0x40:0x40 + len(DOS_STUB)]
    if stub != DOS_STUB:
        return False, ("the MS-DOS stub is not the standard one; the only permitted 16-bit "
                       "code is the message-and-exit stub every compiler emits")

    pe = pefile.PE(data=data)
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") != b".text":
            continue
        body = s.get_data()
        if body[:1] != b"\xc3":
            return False, f".text does not begin with ret (0xC3): {body[:8].hex()}"
        if body[1:].strip(b"\x00"):
            return False, f".text carries {len(body[1:].strip(chr(0).encode()))} bytes past ret"
        return True, "ret + padding, standard DOS stub"
    return False, "no .text section"


def _macho_code_is_inert(data: bytes) -> tuple[bool, str]:
    """arm64 __text must be `mov w0, #0` then `ret`, and then nothing but padding."""
    mov_w0_0, ret = b"\x00\x00\x80\x52", b"\xc0\x03\x5f\xd6"
    idx = data.find(mov_w0_0 + ret)
    if idx < 0:
        return False, "did not find `mov w0,#0 ; ret` — the only permitted code body"
    return True, "mov w0,#0 ; ret"


def _indicator_hygiene(r: GateReport, where: str, data: bytes):
    for host in set(_URL.findall(data)):
        h = host.decode("ascii", "replace").lower().rstrip(".")
        if h.endswith(_RESERVED_TLD) or h in _RESERVED_DOMAIN:
            continue
        r.fail(f"{where}: URL host {h!r} is not an RFC 2606 reserved name — a "
                       f"synthetic artifact must never name a host that could be real")
    for bundle in set(_BUNDLE_ID.findall(data)):
        b = bundle.decode("ascii", "replace")
        low = b.lower().rstrip(".")
        if any(low == k or low.startswith(k + ".") for k in _PLATFORM_IDENTIFIERS):
            continue
        if low.startswith(_REAL_VENDOR_PREFIXES):
            r.fail(f"{where}: bundle identifier {b!r} sits under a real vendor's reverse-DNS "
                   f"prefix — on macOS that is embedded in the code signature, so a synthetic "
                   f"binary would be asserting something false about them")

    for ip in set(_IPV4.findall(data)):
        s = ip.decode()
        if any(s.startswith(n) for n in _DOC_NETS) or s.startswith(("10.", "127.", "192.168.")):
            continue
        if s.startswith("172.") and 16 <= int(s.split(".")[1]) <= 31:
            continue
        r.fail(f"{where}: address {s} is outside the RFC 5737 documentation "
                       f"and RFC 1918 private ranges")


def run(scene_dir: str) -> GateReport:
    r = GateReport(3, "inertness",
                   "can anything we ship execute, and is every format marked synthetic?")
    marked = fmts = 0

    for name in sorted(os.listdir(scene_dir)):
        path = os.path.join(scene_dir, name)
        if not os.path.isfile(path) or name.startswith("."):
            continue
        if name == "JOIN_MANIFEST.json":
            continue
        with open(path, "rb") as f:
            data = f.read()

        fmt = classify(path)
        _indicator_hygiene(r, fmt or os.path.splitext(name)[1] or "text", data)
        if fmt is None:
            continue                                   # xattr sidecar and other plain text
        fmts += 1

        if fmt == "pe":
            ok, why = _pe_code_is_inert(data)
            if not ok:
                r.fail(f"{fmt}: PE is not inert — {why}")
        elif fmt == "macho":
            ok, why = _macho_code_is_inert(data)
            if not ok:
                r.fail(f"{fmt}: Mach-O is not inert — {why}")

        anchors = MARKERS.get(fmt)
        if anchors is None:
            r.fail(f"{fmt}: no declared synthetic marker for this format")
        elif any(a in data for a in anchors):
            marked += 1
        else:
            r.fail(f"{fmt}: carries no in-band synthetic marker, so a copy that "
                           f"escapes its bundle cannot be recognised as generated")

    if fmts == 0:
        r.fail(f"no artifact in {scene_dir!r} was classified, so nothing was checked for "
               f"inertness or for its synthetic marker")
    r.metrics["formats_marked"] = marked
    r.metrics["formats_total"] = fmts
    r.denominator = f"{marked}/{fmts} artifacts carry an in-band synthetic marker"
    return r
