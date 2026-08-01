# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The isolation rule, enforced by walking the syntax tree rather than by discipline.

ArtifactForge stands alone. EvidenceForge is an optional development tool, and the coupling
to it — a transcription of a private seed construction that SemVer does not protect — is
allowed to exist in exactly two places and nowhere else.

Checked with an AST walk rather than a linter rule, for a specific reason: ruff's banned-api
check inspects import statements, and the form this repository actually used was
`pytest.importorskip("evidenceforge.generation.actions.file_transfer")` — a string argument to
a function call, which sails straight past it. A rule that misses the exact shape of the code
it is meant to govern is worse than no rule, because it reads like coverage.

The tiers:

  Tier 0  everything under src/artifactforge except ingest/ — must not touch EvidenceForge
          at all, in any form.
  Tier 1  src/artifactforge/ingest/ — may know EvidenceForge's FILE FORMAT and must still not
          import its code, so companion mode works whether or not it is installed.
  Tier 2  tests/ef_contract/ and integration/ — the only places the import is legal. Neither
          ships in the wheel.
"""
import ast
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "artifactforge")
FORBIDDEN = "evidenceforge"

#: The generation chain. None of it may reach for the companion adapter or the seed
#: transcription, or the coupling has leaked inward and standalone is no longer structural.
CHAIN = ("model", "pools", "suite", "disclosure", "scorecard",
         "content", "artifacts", "compose", "fixture", "bench", "gates")


def _python_files(directory):
    for dirpath, _dirnames, filenames in os.walk(directory):
        if "__pycache__" in dirpath:
            continue
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def _referenced_modules(path):
    """Every module this file reaches for — including via a string argument.

    Covers `import x`, `from x import y`, and any call taking a dotted-module string, which
    is how importlib.import_module and pytest.importorskip are written.
    """
    with open(path) as f:
        tree = ast.parse(f.read(), filename=path)
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif isinstance(node, ast.Call):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
    return found


def _rel(path):
    return os.path.relpath(path, ROOT)


TIER_1 = os.path.join(SRC, "ingest")


@pytest.mark.parametrize("path", sorted(_python_files(SRC)), ids=_rel)
def test_no_shipped_module_imports_evidenceforge(path):
    """Tier 0 and Tier 1 both: nothing in the wheel may import it, adapter included."""
    offenders = sorted(m for m in _referenced_modules(path)
                       if m == FORBIDDEN or m.startswith(FORBIDDEN + "."))
    assert not offenders, (
        f"{_rel(path)} reaches for {offenders} — EvidenceForge is a development tool, and "
        f"importing it from the package makes it a dependency of generating anything.")


@pytest.mark.parametrize("path", sorted(_python_files(SRC)), ids=_rel)
def test_the_generation_chain_never_reaches_for_the_companion_adapter(path):
    """The arrows point one way: ingest and ef_seeds depend on the chain, never the reverse."""
    top = os.path.relpath(path, SRC).split(os.sep)[0].removesuffix(".py")
    if top not in CHAIN:
        return
    reached = _referenced_modules(path)
    for banned in ("artifactforge.ingest", "artifactforge.ef_seeds"):
        offenders = sorted(m for m in reached if m == banned or m.startswith(banned + "."))
        assert not offenders, (
            f"{_rel(path)} is in the generation chain and reaches for {offenders}; the "
            f"companion adapter and the upstream seed transcription must stay downstream "
            f"of it, or standalone generation stops being structural.")


def test_the_upstream_seed_transcription_is_not_public_api():
    """Re-exporting it would make a private upstream surface part of ours."""
    import artifactforge
    assert not [n for n in artifactforge.__all__
                if "seed" in n.lower() or "sysmon" in n.lower()], artifactforge.__all__
    assert not hasattr(artifactforge, "ef_seeds") or "ef_seeds" not in artifactforge.__all__


def test_the_companion_adapter_works_without_evidenceforge_installed():
    """It reads files. Whether the tool that wrote them is importable is beside the point."""
    from artifactforge.ingest import evidenceforge as adapter
    assert adapter._EF_LAYOUT["sysmon_log"].endswith(".xml")
    with pytest.raises(FileNotFoundError, match="does not look like an EvidenceForge run"):
        adapter.read_run(ROOT)
