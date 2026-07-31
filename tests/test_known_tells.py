# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""KNOWN_TELLS.md must describe exactly the formats this project can emit.

The file used to open with "CI fails if a format ships without an entry here". Nothing read
it. Four of the six formats it was supposed to cover carried no disclosure at all, and the
sentence stayed true-looking for as long as nobody checked. This is that check.

It runs in both directions on purpose. A missing section means a format ships undisclosed. A
section with no corresponding format means the disclosure has outlived the code and is now
describing something that no longer exists — which is a different way of being untrue.
"""
import os
import re

from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME
from artifactforge.gates.inertness import MARKERS
from artifactforge.gates.validity import ORACLES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sections(rel="KNOWN_TELLS.md"):
    with open(os.path.join(ROOT, rel)) as f:
        text = f.read()
    return {m.group(1).strip(): m.start() for m in re.finditer(r"^## (.+)$", text, re.M)}, text


def test_every_emittable_format_is_disclosed():
    sections, _ = _sections()
    emittable = set(ORACLES) | set(MARKERS)
    missing = sorted(f for f in emittable if f not in sections)
    assert not missing, f"formats emitted with no Known Tells section: {missing}"


def test_no_section_describes_a_format_that_does_not_exist():
    sections, _ = _sections()
    emittable = set(ORACLES) | set(MARKERS)
    prose = {"Not emitted at all", "EvidenceForge coupling"}
    orphan = sorted(s for s in sections if s not in emittable and s not in prose)
    assert not orphan, f"Known Tells sections describing nothing the code emits: {orphan}"


def test_every_format_section_states_how_it_is_marked():
    """A disclosure that does not say where the anchor lives cannot be checked by a reader."""
    sections, text = _sections()
    ordered = sorted(sections.items(), key=lambda kv: kv[1])
    bodies = {}
    for i, (name, start) in enumerate(ordered):
        end = ordered[i + 1][1] if i + 1 < len(ordered) else len(text)
        bodies[name] = text[start:end]
    for fmt in sorted(set(MARKERS)):
        assert "**Marked.**" in bodies[fmt], f"'{fmt}' does not say where its marker is"


def test_the_disclosure_constants_are_ascii_and_unambiguous():
    """The anchor has to survive every container. A binary plist re-encodes any string with a
    non-ASCII character as UTF-16, which would hide it from `strings` and from Gate 3."""
    for value in (MARKER, NOTICE, RESERVED_NAME):
        assert value.isascii(), f"{value!r} is not ASCII and will not survive a binary plist"
    assert "not evidence" in NOTICE.lower()
    assert "blocklist" in NOTICE.lower()


def test_the_security_policy_and_inertness_doc_exist_and_link_up():
    security = _sections("SECURITY.md")[1]
    inert = _sections("docs/inert-by-construction.md")[1]
    assert "security@" in security, "a security policy with no address is a decoration"
    assert "docs/inert-by-construction.md" in security
    assert MARKER in inert and "SECURITY.md" in inert
