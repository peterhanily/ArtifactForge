# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Host capability contract for the live Benchmark v3 attempt ledger."""
from __future__ import annotations

import os

import pytest

from artifactforge.bench import attempt


def test_live_attempt_platform_contract_is_explicit_and_fail_closed():
    if os.name == "posix":
        assert attempt.ATTEMPT_PLATFORM_SUPPORTED is True
        assert attempt.require_attempt_platform() is None
        return

    assert attempt.ATTEMPT_PLATFORM_SUPPORTED is False
    with pytest.raises(attempt.AttemptPlatformError, match="POSIX directory-descriptor"):
        attempt.require_attempt_platform()


def test_detached_report_verifier_remains_available_on_every_platform():
    assert callable(attempt.verify_retired_report)
