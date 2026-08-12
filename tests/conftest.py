# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Host capabilities that some checks depend on, declared rather than assumed."""

from __future__ import annotations

import pytest

from artifactforge.inventory import InventoryError, measure_change_visibility


@pytest.fixture
def requires_visible_rewrites(tmp_path):
    """Skip where this filesystem cannot show a same-size in-place rewrite.

    Change-and-restore detection compares stat tuples, so where file-time granularity is
    coarser than the mutation window these checks would go red for a property of the host
    rather than a defect in the code.  A red suite that is really a host-capability report
    hides both.  ``artifactforge scorecard`` declares the same shortfall as an honest gap.
    """
    try:
        visibility = measure_change_visibility(tmp_path)
    except InventoryError as exc:
        pytest.skip(f"cannot probe host change visibility: {exc}")
    if not visibility.complete:
        pytest.skip(f"host filesystem hides same-size rewrites: {visibility.describe()}")
