# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Adapters that read another tool's output. Outside the generation chain, deliberately.

ArtifactForge stands alone: `model`, `content`, `artifacts`, `compose` and `bench` never
import anything from here, and nothing here is needed to generate a single artifact. This
package exists so a companion mode is possible without the coupling leaking inward.

The rule is enforced mechanically by `tests/test_isolation.py`, in three tiers:

  Tier 0  everything under src/artifactforge except this package: `evidenceforge` may not be
          imported, named in an importlib call, or reached via pytest.importorskip.
  Tier 1  this package: may know another tool's FILE FORMAT — paths, filenames, field names —
          and nothing else. It never imports that tool's code, so it works whether or not the
          tool is installed.
  Tier 2  tests/ef_contract/ and integration/: the only places importing EvidenceForge is
          legal, and both are excluded from the wheel.
"""
