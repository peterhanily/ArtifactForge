# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Seed derivation shared by every content writer.

Derived values are pure functions of a seed — no wall clock, no os.urandom, no PID — and remain
stable for the same domain and declared derivation ABI. Whole-scene byte identity additionally
depends on each artifact writer and its producer contract; this module does not promise
cross-version or cross-runtime identity by itself. Content writers draw from here rather than
rolling their own, because a writer reaching for entropy would silently break the scoped
determinism contract.
"""
from __future__ import annotations

import hashlib
import struct


def sub_seed(parent: bytes, domain: str) -> bytes:
    """A domain-separated child seed. Two domains can never collide on the same parent."""
    return hashlib.sha256(parent + b"|" + domain.encode()).digest()


def prng_bytes(seed: bytes, n: int) -> bytes:
    """`n` deterministic bytes from a seed — a counter-mode SHA256 stream."""
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(seed + struct.pack("<Q", ctr)).digest()
        ctr += 1
    return out[:n]
