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
import ast
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


def _compact(rel="KNOWN_TELLS.md"):
    return " ".join(_sections(rel)[1].split())


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


def test_no_document_links_to_a_file_that_does_not_exist():
    """Relative links rot silently, and a README pointing at a deleted design doc is the
    cheapest possible way to look careless."""
    import glob
    docs = ([os.path.join(ROOT, n) for n in
             ("README.md", "SECURITY.md", "KNOWN_TELLS.md", "CHANGELOG.md", "CLAUDE.md")]
            + glob.glob(os.path.join(ROOT, "docs", "*.md"))
            + glob.glob(os.path.join(ROOT, "samples", "**", "*.md"), recursive=True)
            + glob.glob(os.path.join(ROOT, "integration", "**", "*.md"), recursive=True))
    broken = []
    for doc in docs:
        if not os.path.exists(doc):
            continue
        with open(doc) as f:
            body = f.read()
        for target in re.findall(r"\]\((?!https?://|#)([^)#]+)", body):
            resolved = os.path.normpath(os.path.join(os.path.dirname(doc), target))
            if not os.path.exists(resolved):
                broken.append(f"{os.path.relpath(doc, ROOT)} -> {target}")
    assert not broken, broken


def test_every_platform_identifier_exemption_carries_a_real_reason():
    """An allowlist entry without a justification is a hole somebody widened once and forgot.

    The reason has to be long enough to be an argument rather than a shrug — the same bar
    PacketForge applies to its own indicator exemptions.
    """
    from artifactforge.gates.inertness import _PLATFORM_IDENTIFIERS, _REAL_VENDOR_PREFIXES
    assert _PLATFORM_IDENTIFIERS, "the exemption list must be explicit, not implicit"
    for identifier, reason in _PLATFORM_IDENTIFIERS.items():
        assert identifier == identifier.lower(), identifier
        assert identifier.startswith(_REAL_VENDOR_PREFIXES), \
            f"{identifier!r} is exempted from a rule it would never have tripped"
        assert len(reason) > 40, f"{identifier!r}'s justification says nothing: {reason!r}"


def test_static_macho_checks_are_not_published_as_runtime_results():
    """No CI lane executes the Mach-O, so prose must stop at the emitted-byte profile."""
    documents = (
        "KNOWN_TELLS.md",
        "SECURITY.md",
        "docs/inert-by-construction.md",
        "integration/evidenceforge/MAINTAINER_NOTE_DRAFT.md",
    )
    forbidden = (
        "Running it returns zero",
        "It runs and returns zero",
        "Running it does exactly one thing",
    )
    for rel in documents:
        text = _sections(rel)[1]
        assert "does not execute" in text, f"{rel} does not disclose the runtime-test gap"
        for claim in forbidden:
            assert claim not in text, f"{rel} publishes unexecuted runtime claim {claim!r}"


def test_prefetch_acceptance_is_not_promoted_to_plaso_compatibility():
    readme = _compact("README.md")
    design = _compact("docs/DESIGN.md")
    note = _compact("integration/evidenceforge/MAINTAINER_NOTE_DRAFT.md")
    assert "which means plaso reads" not in readme.lower()
    assert "does not run a Plaso extraction" in readme
    assert "does not run a Plaso extraction" in design
    assert "I have not run a Plaso extraction" in note


def test_documented_sqlite_determinism_stops_at_the_current_producer_boundary():
    design = _compact("docs/DESIGN.md")
    fixture = _compact("docs/fixture-core.md")
    tells = _compact()
    note = _compact("integration/evidenceforge/MAINTAINER_NOTE_DRAFT.md")
    assert "regenerates byte-identical forever" not in design
    for rel, text, producer_gap in (
        ("docs/DESIGN.md", design, "Fixture ABI v1 does not bind that producer"),
        ("docs/fixture-core.md", fixture, "GeneratorIdentity v1 does not bind that release"),
        ("KNOWN_TELLS.md", tells, "Fixture ABI v1 does not bind it"),
        (
            "integration/evidenceforge/MAINTAINER_NOTE_DRAFT.md",
            note,
            "Fixture ABI v1 does not bind the SQLite producer",
        ),
    ):
        assert producer_gap in text, f"{rel} omits the SQLite-producer gap"
        assert "cross-runtime" in text, f"{rel} overstates SQLite byte determinism"


def test_source_docstrings_scope_determinism_to_a_declared_abi():
    modules = (
        "src/artifactforge/suite.py",
        "src/artifactforge/content/seed.py",
        "src/artifactforge/content/macho.py",
        "src/artifactforge/content/store.py",
    )
    for rel in modules:
        with open(os.path.join(ROOT, rel), encoding="utf-8") as source:
            docstring = ast.get_docstring(ast.parse(source.read())) or ""
        assert "ABI" in docstring, f"{rel} does not name its determinism compatibility axis"
        assert "forever" not in docstring.lower(), f"{rel} publishes an unbounded promise"


def test_parser_acceptance_and_gatekeeper_observations_keep_their_claim_boundaries():
    design = _compact("docs/DESIGN.md")
    tells = _compact()
    inert = _compact("docs/inert-by-construction.md")
    note = _compact("integration/evidenceforge/MAINTAINER_NOTE_DRAFT.md")
    assert "does not turn acceptance into realism" in design
    assert "inconclusive, not evidence of Gatekeeper rejection" in tells
    assert "Gatekeeper output is inconclusive rather than rejection evidence" in inert
    assert "Gatekeeper remains inapplicable to the loose target" in note


def test_macos_consumer_query_profile_is_versioned_and_bounded():
    tells = _compact()
    oracles = _compact("docs/macos-oracles.md")
    assert "macos-11-14-consumer-v1" in oracles
    assert "not a general macOS schema claim" in tells
    assert "not a captured or complete knowledgeC/TCC schema" in oracles


def test_hive_disclosure_and_consumer_claims_match_the_typed_profile():
    tells = _compact()
    design = _compact("docs/DESIGN.md")
    inert = _compact("docs/inert-by-construction.md")
    assert "regipy and libregf to agree on the complete typed modeled tree" in tells
    assert "Amcache and Software-persistence plugins to recognise and extract" in design
    assert "a root `artifactforge_synthetic` key" in inert
    assert "base block's hive name, `ArtifactForgeHive`" not in inert


def test_public_evidenceforge_comment_is_not_denied_by_local_status_prose():
    documents = (
        "README.md",
        "docs/ROADMAP.md",
        "integration/evidenceforge/README.md",
        "integration/evidenceforge/MAINTAINER_NOTE_DRAFT.md",
    )
    for rel in documents:
        text = _sections(rel)[1]
        assert "issuecomment-5152265897" in text, f"{rel} omits the existing public comment"
    combined = "\n".join(_sections(rel)[1].lower() for rel in documents)
    for false_claim in (
        "has not been posted or proposed to anyone",
        "nothing has been posted or pushed upstream",
        "nothing has been posted, pushed or proposed upstream",
        "nothing here has been proposed to the evidenceforge maintainers",
    ):
        assert false_claim not in combined


def test_scanner_prose_records_the_failed_unbound_diagnostic_without_calling_it_clean():
    inert = _sections("docs/inert-by-construction.md")[1]
    security = _sections("SECURITY.md")[1]
    for rel, text in (("docs/inert-by-construction.md", inert), ("SECURITY.md", security)):
        assert "unbound" in text, f"{rel} promotes an unbound diagnostic"
        assert "community-YARA matches" in text, f"{rel} hides the strict diagnostic matches"
        assert "rule-file load failures" in text, f"{rel} hides rule-load failures"
        marker = text.index("community-YARA matches")
        context = text[marker - 160 : marker + 300].lower()
        assert "red" in context and "clean" in context, f"{rel} mis-scopes the diagnostic"


def test_scorecard_source_record_is_not_called_signed_release_attestation():
    design = _sections("docs/DESIGN.md")[1]
    assert "A release scorecard is also a source attestation" not in design
    assert "measurement-source record" in design
    assert "not a signature" in design
