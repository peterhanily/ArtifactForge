# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Seed derivation shared by every content writer.

Bytes are a pure function of a seed — no wall clock, no os.urandom, no PID — so the same
scenario regenerates byte-identical forever. Every writer draws from here rather than
rolling its own, because a single writer reaching for entropy would silently break the
property the whole project rests on.
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
